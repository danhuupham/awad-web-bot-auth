import { performance } from 'node:perf_hooks';
import { createBaselineIpUaVerifier } from './baseline-verifier.js';
import { DirectoryResolver } from './directory.js';
import { startOriginServer } from './origin-server.js';
import { createWebBotAuthVerifier } from './webbotauth-verifier.js';

/**
 * @typedef {{
 *   name: string,
 *   resetState: () => void,
 *   verifyRequest: (req: any) => Promise<any>
 * }} BotVerifier
 */

/** @type {DirectoryResolver | null} */
let resolver = null;
/** @type {BotVerifier | null} */
let baselineVerifier = null;
/** @type {BotVerifier | null} */
let changeVerifier = null;
/** @type {BotVerifier | null} */
let activeVerifier = null;
/** @type {Awaited<ReturnType<typeof startOriginServer>> | null} */
let originServer = null;
/** @type {NodeJS.CpuUsage | undefined} */
let cpuSnapshot;
/** @type {import('node:perf_hooks').EventLoopUtilization | undefined} */
let eluSnapshot;
let wallStartNs = 0n;

const delegatingVerifier = {
  async verifyRequest(req) {
    if (req.url === '/__warmup_socket') {
      return {
        allowed: true,
        statusCode: 200,
        category: 'warmup',
        botVerified: false,
        reason: 'socket_warmup',
        headers: {}
      };
    }
    if (!activeVerifier) {
      throw new Error('Origin worker verifier not initialized');
    }
    return activeVerifier.verifyRequest(req);
  }
};

process.on('message', async (/** @type {any} */ msg) => {
  try {
    if (msg.type === 'init') {
      const nextResolver = new DirectoryResolver({
        caCertPem: msg.tlsCredentials.cert,
        allowLoopbackForLocalStudy: true
      });
      const nextBaseline = createBaselineIpUaVerifier();
      const nextChange = createWebBotAuthVerifier({
        directoryResolver: nextResolver,
        trustedDirectoryUrls: msg.trustedDirectoryUrls
      });
      const srv = await startOriginServer({
        tlsCredentials: msg.tlsCredentials,
        verifier: delegatingVerifier
      });
      resolver = nextResolver;
      baselineVerifier = nextBaseline;
      changeVerifier = nextChange;
      activeVerifier = nextBaseline;
      originServer = srv;
      process.send?.({
        id: msg.id,
        ok: true,
        port: srv.port,
        authority: srv.authority,
        baseUrl: srv.baseUrl
      });
      return;
    }

    if (msg.type === 'prepare-mode') {
      activeVerifier = msg.mode === 'change' ? changeVerifier : baselineVerifier;
      activeVerifier?.resetState();
      process.send?.({ id: msg.id, ok: true });
      return;
    }

    if (msg.type === 'start-window') {
      await new Promise((r) => setImmediate(r));
      eluSnapshot = performance.eventLoopUtilization();
      cpuSnapshot = process.cpuUsage();
      wallStartNs = process.hrtime.bigint();
      process.send?.({ id: msg.id, ok: true });
      return;
    }

    if (msg.type === 'stop-window') {
      await new Promise((r) => setImmediate(r));
      const eluDiff = performance.eventLoopUtilization(eluSnapshot);
      const cpuDiff = process.cpuUsage(cpuSnapshot);
      const wallMs = Number(process.hrtime.bigint() - wallStartNs) / 1e6;
      const osUserMs = cpuDiff.user / 1000;
      const osSystemMs = cpuDiff.system / 1000;
      const osTotalCpuMs = osUserMs + osSystemMs;
      process.send?.({
        id: msg.id,
        ok: true,
        cpu: {
          eluActiveMs: eluDiff.active,
          eluIdleMs: eluDiff.idle,
          eluUtilizationPct: eluDiff.utilization * 100,
          osUserMs,
          osSystemMs,
          osTotalCpuMs,
          wallMs
        },
        resolverStats: {
          cacheHits: resolver?.stats.cacheHits ?? 0,
          networkFetches: resolver?.stats.networkFetches ?? 0,
          coldFetchDurationsMs: resolver?.stats.coldFetchDurationsMs ?? []
        }
      });
      return;
    }

    if (msg.type === 'shutdown') {
      resolver?.destroy();
      await originServer?.close();
      process.send?.({ id: msg.id, ok: true });
      process.exit(0);
    }
  } catch (err) {
    process.send?.({ id: msg.id, ok: false, error: err.message });
  }
});
