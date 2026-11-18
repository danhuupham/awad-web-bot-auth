import { performance } from 'node:perf_hooks';
import { createBaselineIpUaVerifier } from './baseline-verifier.js';
import { DirectoryResolver } from './directory.js';
import { startOriginServer } from './origin-server.js';
import { createWebBotAuthVerifier } from './webbotauth-verifier.js';

let resolver = null;
let baselineVerifier = null;
let changeVerifier = null;
let activeVerifier = null;
let originServer = null;
let cpuSnapshot = null;
let eluSnapshot = null;
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
    return activeVerifier.verifyRequest(req);
  }
};

process.on('message', async (msg) => {
  try {
    if (msg.type === 'init') {
      resolver = new DirectoryResolver({
        caCertPem: msg.tlsCredentials.cert,
        allowLoopbackForLocalStudy: true
      });
      baselineVerifier = createBaselineIpUaVerifier();
      changeVerifier = createWebBotAuthVerifier({
        directoryResolver: resolver,
        trustedDirectoryUrls: msg.trustedDirectoryUrls
      });
      activeVerifier = baselineVerifier;
      originServer = await startOriginServer({
        tlsCredentials: msg.tlsCredentials,
        verifier: delegatingVerifier
      });
      process.send({
        id: msg.id,
        ok: true,
        port: originServer.port,
        authority: originServer.authority,
        baseUrl: originServer.baseUrl
      });
      return;
    }

    if (msg.type === 'prepare-mode') {
      activeVerifier = msg.mode === 'change' ? changeVerifier : baselineVerifier;
      activeVerifier.resetState();
      process.send({ id: msg.id, ok: true });
      return;
    }

    if (msg.type === 'start-window') {
      await new Promise((r) => setImmediate(r));
      eluSnapshot = performance.eventLoopUtilization();
      cpuSnapshot = process.cpuUsage();
      wallStartNs = process.hrtime.bigint();
      process.send({ id: msg.id, ok: true });
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
      process.send({
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
          cacheHits: resolver.stats.cacheHits,
          networkFetches: resolver.stats.networkFetches,
          coldFetchDurationsMs: resolver.stats.coldFetchDurationsMs
        }
      });
      return;
    }

    if (msg.type === 'shutdown') {
      resolver?.destroy();
      await originServer?.close();
      process.send({ id: msg.id, ok: true });
      process.exit(0);
    }
  } catch (err) {
    process.send({ id: msg.id, ok: false, error: err.message });
  }
});
