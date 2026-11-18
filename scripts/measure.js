import { fork } from 'node:child_process';
import fs from 'node:fs/promises';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startDirectoryServer } from '../src/directory.js';
import { generateBotKeyPair } from '../src/rfc9421.js';
import { createLoopbackTlsCredentials } from '../src/tls.js';
import { generateMixedWorkload } from '../src/workload.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, '..');
const RESULTS_DIR = path.join(ROOT_DIR, 'results');

function parseCliArgs(argv) {
  let runs = 7;
  let concurrency = 16;
  let seed = 20261118;
  for (const arg of argv) {
    if (arg.startsWith('--runs=')) runs = Number.parseInt(arg.slice(7), 10);
    if (arg.startsWith('--concurrency=')) concurrency = Number.parseInt(arg.slice(14), 10);
    if (arg.startsWith('--seed=')) seed = Number.parseInt(arg.slice(7), 10);
  }
  if (!Number.isInteger(runs) || runs < 1) throw new Error('Invalid --runs value');
  if (!Number.isInteger(concurrency) || concurrency < 1) {
    throw new Error('Invalid --concurrency value');
  }
  return { runs, concurrency, seed };
}

function createWorkerRpc(workerPath) {
  const child = fork(workerPath, [], { stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
  let nextId = 1;
  const pending = new Map();

  child.on('message', (msg) => {
    const entry = pending.get(msg.id);
    if (!entry) return;
    pending.delete(msg.id);
    if (msg.ok) entry.resolve(msg);
    else entry.reject(new Error(msg.error ?? 'Worker RPC error'));
  });

  child.on('exit', (code) => {
    for (const [, entry] of pending) {
      entry.reject(new Error(`Origin worker exited unexpectedly with code ${code}`));
    }
    pending.clear();
  });

  return {
    call(type, payload = {}) {
      const id = nextId++;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        child.send({ id, type, ...payload });
      });
    }
  };
}

function sendHttpRequest(agent, baseUrl, item) {
  return new Promise((resolve, reject) => {
    const startNs = process.hrtime.bigint();
    const req = https.request(
      `${baseUrl}${item.url}`,
      {
        method: item.method,
        agent,
        headers: item.headers
      },
      (res) => {
        res.on('data', () => {});
        res.on('end', () => {
          const e2eLatencyMs = Number(process.hrtime.bigint() - startNs) / 1e6;
          const verifyLatencyMs = Number.parseFloat(
            String(res.headers['x-verify-latency-ms'] ?? '0')
          );
          resolve({
            id: item.id,
            kind: item.kind,
            attackSubkind: item.attackSubkind,
            statusCode: res.statusCode,
            botVerified: res.headers['x-bot-verified'] === '1',
            reason: String(res.headers['x-verify-reason'] ?? ''),
            verifyLatencyMs,
            e2eLatencyMs,
            sigHeaderBytes: item.sigHeaderBytes
          });
        });
      }
    );
    req.on('error', reject);
    req.end();
  });
}

async function runPool(items, concurrency, fn) {
  const results = new Array(items.length);
  let cursor = 0;

  async function worker() {
    while (true) {
      const idx = cursor++;
      if (idx >= items.length) return;
      results[idx] = await fn(items[idx]);
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, () => worker()));
  return results;
}

function quantile(sortedValues, q) {
  if (sortedValues.length === 0) return 0;
  const pos = (sortedValues.length - 1) * q;
  const base = Math.floor(pos);
  const rest = pos - base;
  if (sortedValues[base + 1] !== undefined) {
    return sortedValues[base] + rest * (sortedValues[base + 1] - sortedValues[base]);
  }
  return sortedValues[base];
}

function summarizeSeries(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const min = sorted[0] ?? 0;
  const max = sorted.at(-1) ?? 0;
  const p25 = quantile(sorted, 0.25);
  const median = quantile(sorted, 0.5);
  const p75 = quantile(sorted, 0.75);
  return {
    median: round6(median),
    iqr: round6(p75 - p25),
    p25: round6(p25),
    p75: round6(p75),
    min: round6(min),
    max: round6(max)
  };
}

function round6(num) {
  return Math.round(num * 1e6) / 1e6;
}

function round3(num) {
  return Math.round(num * 1e3) / 1e3;
}

function aggregateModeMetrics(records, cpu, resolverStats, directoryFetches) {
  const humans = records.filter((r) => r.kind === 'legit_human');
  const validBots = records.filter((r) => r.kind === 'legit_signed_bot');
  const spoofedBots = records.filter((r) => r.kind === 'spoofed_bot');
  const botClaiming = records.filter((r) => r.kind !== 'legit_human');

  const humansAllowed = humans.filter((r) => r.statusCode === 200 && !r.botVerified).length;
  const validBotsAccepted = validBots.filter((r) => r.statusCode === 200 && r.botVerified).length;
  const spoofedRejected = spoofedBots.filter((r) => r.statusCode >= 400 || !r.botVerified).length;

  const attackSubkinds = [
    'spoof_external_ip_ua',
    'spoof_shared_cloud_ip_ua',
    'forged_rogue_directory_sig',
    'tampered_target_path_sig',
    'expired_or_replayed_sig'
  ];
  const byAttack = {};
  for (const sub of attackSubkinds) {
    const subRows = spoofedBots.filter((r) => r.attackSubkind === sub);
    const rejected = subRows.filter((r) => r.statusCode >= 400 || !r.botVerified).length;
    byAttack[sub] = {
      total: subRows.length,
      rejected,
      rejectedPct: round3((rejected / subRows.length) * 100)
    };
  }

  const botVerifyLatencies = botClaiming.map((r) => r.verifyLatencyMs).sort((a, b) => a - b);
  const allVerifyLatencies = records.map((r) => r.verifyLatencyMs).sort((a, b) => a - b);
  const e2eLatencies = records.map((r) => r.e2eLatencyMs).sort((a, b) => a - b);
  const sigWireBytes = validBots.map((r) => r.sigHeaderBytes).sort((a, b) => a - b);

  return {
    totalRequests: records.length,
    humanPassThroughRatePct: round3((humansAllowed / humans.length) * 100),
    validBotAcceptanceRatePct: round3((validBotsAccepted / validBots.length) * 100),
    spoofedBotRejectionRatePct: round3((spoofedRejected / spoofedBots.length) * 100),
    spoofedRejectedCount: spoofedRejected,
    spoofedTotalCount: spoofedBots.length,
    validBotsAcceptedCount: validBotsAccepted,
    validBotsTotalCount: validBots.length,
    byAttack,
    verifyLatencyBotP50Ms: round6(quantile(botVerifyLatencies, 0.5)),
    verifyLatencyBotP95Ms: round6(quantile(botVerifyLatencies, 0.95)),
    verifyLatencyAllP50Ms: round6(quantile(allVerifyLatencies, 0.5)),
    verifyLatencyAllP95Ms: round6(quantile(allVerifyLatencies, 0.95)),
    e2eLatencyP50Ms: round6(quantile(e2eLatencies, 0.5)),
    e2eLatencyP95Ms: round6(quantile(e2eLatencies, 0.95)),
    coldDirectoryFetchMs: round6(resolverStats.coldFetchDurationsMs[0] ?? 0),
    directoryFetches,
    directoryCacheHits: resolverStats.cacheHits,
    originCpuActiveMs: round6(cpu.eluActiveMs),
    originCpuUsPerReq: round3((cpu.eluActiveMs * 1000) / records.length),
    originCpuUtilizationPct: round3(cpu.eluUtilizationPct),
    originOsCpuTicksMs: round6(cpu.osTotalCpuMs),
    originWallMs: round6(cpu.wallMs),
    throughputReqPerSec: round3(records.length / (cpu.wallMs / 1000)),
    signedHeaderBytesMedian: quantile(sigWireBytes, 0.5)
  };
}

async function executeModePass({
  originRpc,
  baseUrl,
  tlsCert,
  mode,
  workload,
  concurrency,
  trustedDirServer
}) {
  await originRpc.call('prepare-mode', { mode });
  trustedDirServer.resetFetchCount();

  const agent = new https.Agent({
    ca: tlsCert,
    keepAlive: true,
    maxSockets: concurrency
  });

  // Pre-warm TLS keep-alive sockets identically before starting CPU & latency measurement window
  const socketWarmupItems = Array.from({ length: concurrency }, (_, idx) => ({
    id: -idx - 1,
    kind: 'warmup',
    attackSubkind: null,
    method: 'GET',
    url: '/__warmup_socket',
    headers: { 'User-Agent': 'SocketWarmup/1.0' },
    sigHeaderBytes: 0
  }));
  await runPool(socketWarmupItems, concurrency, (it) => sendHttpRequest(agent, baseUrl, it));

  await originRpc.call('start-window');
  const records = await runPool(workload, concurrency, (it) => sendHttpRequest(agent, baseUrl, it));
  const stopInfo = await originRpc.call('stop-window');

  agent.destroy();

  return aggregateModeMetrics(
    records,
    stopInfo.cpu,
    stopInfo.resolverStats,
    trustedDirServer.getFetchCount()
  );
}

async function main() {
  const { runs, concurrency, seed } = parseCliArgs(process.argv.slice(2));
  await fs.mkdir(RESULTS_DIR, { recursive: true });

  // Clean stale run-*.json files if re-running with a different count
  const existing = await fs.readdir(RESULTS_DIR);
  for (const name of existing) {
    if (/^run-\d+\.json$/.test(name)) {
      await fs.unlink(path.join(RESULTS_DIR, name));
    }
  }

  const tlsCredentials = createLoopbackTlsCredentials();
  const trustedBotKeyPair = generateBotKeyPair();
  const rogueBotKeyPair = generateBotKeyPair();

  const trustedDirServer = await startDirectoryServer({
    tlsCredentials,
    botKeyPairs: [trustedBotKeyPair],
    maxAgeSec: 300
  });
  const rogueDirServer = await startDirectoryServer({
    tlsCredentials,
    botKeyPairs: [rogueBotKeyPair],
    maxAgeSec: 300
  });

  const originRpc = createWorkerRpc(path.join(ROOT_DIR, 'src', 'origin-worker.js'));
  const originInfo = await originRpc.call('init', {
    tlsCredentials,
    trustedDirectoryUrls: [trustedDirServer.url]
  });

  const workload = generateMixedWorkload({
    seed,
    originAuthority: originInfo.authority,
    trustedBotKeyPair,
    trustedDirectoryUrl: trustedDirServer.url,
    rogueBotKeyPair,
    rogueDirectoryUrl: rogueDirServer.url
  });

  // Equal V8 TurboFan JIT warm-up (1,000 requests each for baseline and change) before timed runs;
  // executeModePass resets JWKS cache and nonce state before every subsequent timed run.
  const warmupSlice = workload;
  await executeModePass({
    originRpc,
    baseUrl: originInfo.baseUrl,
    tlsCert: tlsCredentials.cert,
    mode: 'baseline',
    workload: warmupSlice,
    concurrency,
    trustedDirServer
  });
  await executeModePass({
    originRpc,
    baseUrl: originInfo.baseUrl,
    tlsCert: tlsCredentials.cert,
    mode: 'change',
    workload: warmupSlice,
    concurrency,
    trustedDirServer
  });

  const environment = {
    measuredAt: new Date().toISOString(),
    nodeVersion: process.version,
    platform: `${os.platform()} ${os.release()} (${os.arch()})`,
    cpuModel: os.cpus()[0]?.model?.trim() ?? 'unknown',
    logicalCores: os.cpus().length,
    totalMemoryGb: round3(os.totalmem() / 1024 ** 3),
    seed,
    runs,
    workloadSize: workload.length,
    concurrency
  };

  const runSummaries = [];
  const logLines = [];
  const log = (line = '') => {
    console.log(line);
    logLines.push(line);
  };

  log('========================================================================================');
  log('SEMINAR E1 — Web Bot Auth (RFC 9421 Ed25519) vs. User-Agent + IP Allowlist Benchmark');
  log('========================================================================================');
  log(
    `Environment : Node ${environment.nodeVersion} | ${environment.platform} | ${environment.cpuModel} (${environment.logicalCores} cores, ${environment.totalMemoryGb} GB RAM)`
  );
  log(
    `Fixed Setup : ${workload.length} HTTPS TLS 1.3 requests/run (300 human, 300 valid signed bot, 400 spoofed bot) | concurrency=${concurrency} | seed=${seed} | runs=${runs}`
  );
  log('----------------------------------------------------------------------------------------');

  for (let r = 1; r <= runs; r += 1) {
    // Alternate execution order (AB, BA, AB...) to eliminate within-run ordering bias
    const order = r % 2 === 1 ? ['baseline', 'change'] : ['change', 'baseline'];
    const pair = {};
    for (const mode of order) {
      pair[mode] = await executeModePass({
        originRpc,
        baseUrl: originInfo.baseUrl,
        tlsCert: tlsCredentials.cert,
        mode,
        workload,
        concurrency,
        trustedDirServer
      });
    }

    const addedVerifyP95Ms = round6(
      pair.change.verifyLatencyBotP95Ms - pair.baseline.verifyLatencyBotP95Ms
    );
    const addedVerifyAllP95Ms = round6(
      pair.change.verifyLatencyAllP95Ms - pair.baseline.verifyLatencyAllP95Ms
    );
    const addedE2eP95Ms = round6(pair.change.e2eLatencyP95Ms - pair.baseline.e2eLatencyP95Ms);
    const addedCpuActiveMs = round6(
      pair.change.originCpuActiveMs - pair.baseline.originCpuActiveMs
    );
    const addedCpuUsPerReq = round3(
      pair.change.originCpuUsPerReq - pair.baseline.originCpuUsPerReq
    );
    const addedCpuRelativePct =
      pair.baseline.originCpuActiveMs > 0
        ? round3(
            ((pair.change.originCpuActiveMs - pair.baseline.originCpuActiveMs) /
              pair.baseline.originCpuActiveMs) *
              100
          )
        : 0;

    const runData = {
      run: r,
      executionOrder: order,
      environment,
      baseline: pair.baseline,
      change: pair.change,
      deltas: {
        spoofedRejectionGainPctPoints: round3(
          pair.change.spoofedBotRejectionRatePct - pair.baseline.spoofedBotRejectionRatePct
        ),
        addedVerifyBotP95Ms: addedVerifyP95Ms,
        addedVerifyAllP95Ms,
        addedE2eP95Ms,
        addedOriginCpuActiveMs: addedCpuActiveMs,
        addedOriginCpuUsPerReq: addedCpuUsPerReq,
        addedOriginCpuRelativePct: addedCpuRelativePct
      }
    };

    const runFileName = `run-${String(r).padStart(2, '0')}.json`;
    await fs.writeFile(
      path.join(RESULTS_DIR, runFileName),
      `${JSON.stringify(runData, null, 2)}\n`,
      'utf8'
    );
    runSummaries.push(runData);

    log(
      `Run ${String(r).padStart(2, '0')} (${order.join('->')}) | ` +
        `Spoof Reject: ${pair.baseline.spoofedBotRejectionRatePct.toFixed(1)}% -> ${pair.change.spoofedBotRejectionRatePct.toFixed(1)}% | ` +
        `Bot Verify p95: ${pair.baseline.verifyLatencyBotP95Ms.toFixed(3)} -> ${pair.change.verifyLatencyBotP95Ms.toFixed(3)} ms (+${addedVerifyP95Ms.toFixed(3)} ms) | ` +
        `Origin CPU: ${pair.baseline.originCpuActiveMs.toFixed(2)} -> ${pair.change.originCpuActiveMs.toFixed(2)} ms (+${addedCpuRelativePct.toFixed(1)}%, +${addedCpuUsPerReq.toFixed(1)} us/req)`
    );
  }

  const summary = {
    environment,
    baseline: {
      spoofedBotRejectionRatePct: summarizeSeries(
        runSummaries.map((x) => x.baseline.spoofedBotRejectionRatePct)
      ),
      validBotAcceptanceRatePct: summarizeSeries(
        runSummaries.map((x) => x.baseline.validBotAcceptanceRatePct)
      ),
      humanPassThroughRatePct: summarizeSeries(
        runSummaries.map((x) => x.baseline.humanPassThroughRatePct)
      ),
      verifyLatencyBotP50Ms: summarizeSeries(
        runSummaries.map((x) => x.baseline.verifyLatencyBotP50Ms)
      ),
      verifyLatencyBotP95Ms: summarizeSeries(
        runSummaries.map((x) => x.baseline.verifyLatencyBotP95Ms)
      ),
      verifyLatencyAllP95Ms: summarizeSeries(
        runSummaries.map((x) => x.baseline.verifyLatencyAllP95Ms)
      ),
      e2eLatencyP50Ms: summarizeSeries(runSummaries.map((x) => x.baseline.e2eLatencyP50Ms)),
      e2eLatencyP95Ms: summarizeSeries(runSummaries.map((x) => x.baseline.e2eLatencyP95Ms)),
      originCpuActiveMs: summarizeSeries(runSummaries.map((x) => x.baseline.originCpuActiveMs)),
      originCpuUsPerReq: summarizeSeries(runSummaries.map((x) => x.baseline.originCpuUsPerReq)),
      originCpuUtilizationPct: summarizeSeries(
        runSummaries.map((x) => x.baseline.originCpuUtilizationPct)
      ),
      throughputReqPerSec: summarizeSeries(runSummaries.map((x) => x.baseline.throughputReqPerSec)),
      byAttack: runSummaries[0].baseline.byAttack
    },
    change: {
      spoofedBotRejectionRatePct: summarizeSeries(
        runSummaries.map((x) => x.change.spoofedBotRejectionRatePct)
      ),
      validBotAcceptanceRatePct: summarizeSeries(
        runSummaries.map((x) => x.change.validBotAcceptanceRatePct)
      ),
      humanPassThroughRatePct: summarizeSeries(
        runSummaries.map((x) => x.change.humanPassThroughRatePct)
      ),
      verifyLatencyBotP50Ms: summarizeSeries(
        runSummaries.map((x) => x.change.verifyLatencyBotP50Ms)
      ),
      verifyLatencyBotP95Ms: summarizeSeries(
        runSummaries.map((x) => x.change.verifyLatencyBotP95Ms)
      ),
      verifyLatencyAllP95Ms: summarizeSeries(
        runSummaries.map((x) => x.change.verifyLatencyAllP95Ms)
      ),
      e2eLatencyP50Ms: summarizeSeries(runSummaries.map((x) => x.change.e2eLatencyP50Ms)),
      e2eLatencyP95Ms: summarizeSeries(runSummaries.map((x) => x.change.e2eLatencyP95Ms)),
      coldDirectoryFetchMs: summarizeSeries(runSummaries.map((x) => x.change.coldDirectoryFetchMs)),
      directoryFetches: summarizeSeries(runSummaries.map((x) => x.change.directoryFetches)),
      originCpuActiveMs: summarizeSeries(runSummaries.map((x) => x.change.originCpuActiveMs)),
      originCpuUsPerReq: summarizeSeries(runSummaries.map((x) => x.change.originCpuUsPerReq)),
      originCpuUtilizationPct: summarizeSeries(
        runSummaries.map((x) => x.change.originCpuUtilizationPct)
      ),
      throughputReqPerSec: summarizeSeries(runSummaries.map((x) => x.change.throughputReqPerSec)),
      signedHeaderBytesMedian: runSummaries[0].change.signedHeaderBytesMedian,
      byAttack: runSummaries[0].change.byAttack
    },
    deltas: {
      spoofedRejectionGainPctPoints: summarizeSeries(
        runSummaries.map((x) => x.deltas.spoofedRejectionGainPctPoints)
      ),
      addedVerifyBotP95Ms: summarizeSeries(runSummaries.map((x) => x.deltas.addedVerifyBotP95Ms)),
      addedVerifyAllP95Ms: summarizeSeries(runSummaries.map((x) => x.deltas.addedVerifyAllP95Ms)),
      addedE2eP95Ms: summarizeSeries(runSummaries.map((x) => x.deltas.addedE2eP95Ms)),
      addedOriginCpuActiveMs: summarizeSeries(
        runSummaries.map((x) => x.deltas.addedOriginCpuActiveMs)
      ),
      addedOriginCpuUsPerReq: summarizeSeries(
        runSummaries.map((x) => x.deltas.addedOriginCpuUsPerReq)
      ),
      addedOriginCpuRelativePct: summarizeSeries(
        runSummaries.map((x) => x.deltas.addedOriginCpuRelativePct)
      )
    }
  };

  log('----------------------------------------------------------------------------------------');
  log(`SUMMARY ACROSS ${runs} RUNS (Median [Min .. Max] | IQR):`);
  log(
    `1. Spoofed Bot Rejection (%)    : Baseline ${summary.baseline.spoofedBotRejectionRatePct.median.toFixed(1)}% [${summary.baseline.spoofedBotRejectionRatePct.min.toFixed(1)}..${summary.baseline.spoofedBotRejectionRatePct.max.toFixed(1)}]  ->  Change ${summary.change.spoofedBotRejectionRatePct.median.toFixed(1)}% [${summary.change.spoofedBotRejectionRatePct.min.toFixed(1)}..${summary.change.spoofedBotRejectionRatePct.max.toFixed(1)}]  (+${summary.deltas.spoofedRejectionGainPctPoints.median.toFixed(1)} pp)`
  );
  log(
    `2. Valid Signed Bot Accept (%)  : Baseline ${summary.baseline.validBotAcceptanceRatePct.median.toFixed(1)}%  ->  Change ${summary.change.validBotAcceptanceRatePct.median.toFixed(1)}%  (Human pass-through: ${summary.change.humanPassThroughRatePct.median.toFixed(1)}%)`
  );
  log(
    `3. Bot Verify Latency p95 (ms)  : Baseline ${summary.baseline.verifyLatencyBotP95Ms.median.toFixed(3)} ms [${summary.baseline.verifyLatencyBotP95Ms.min.toFixed(3)}..${summary.baseline.verifyLatencyBotP95Ms.max.toFixed(3)}]  ->  Change ${summary.change.verifyLatencyBotP95Ms.median.toFixed(3)} ms [${summary.change.verifyLatencyBotP95Ms.min.toFixed(3)}..${summary.change.verifyLatencyBotP95Ms.max.toFixed(3)}]  (Added: +${summary.deltas.addedVerifyBotP95Ms.median.toFixed(3)} ms, IQR ${summary.deltas.addedVerifyBotP95Ms.iqr.toFixed(3)} ms)`
  );
  log(
    `4. End-to-End HTTPS p95 (ms)    : Baseline ${summary.baseline.e2eLatencyP95Ms.median.toFixed(3)} ms [${summary.baseline.e2eLatencyP95Ms.min.toFixed(3)}..${summary.baseline.e2eLatencyP95Ms.max.toFixed(3)}]  ->  Change ${summary.change.e2eLatencyP95Ms.median.toFixed(3)} ms [${summary.change.e2eLatencyP95Ms.min.toFixed(3)}..${summary.change.e2eLatencyP95Ms.max.toFixed(3)}]  (Added: +${summary.deltas.addedE2eP95Ms.median.toFixed(3)} ms)`
  );
  log(
    `5. Cold JWKS Directory Fetch    : ${summary.change.coldDirectoryFetchMs.median.toFixed(3)} ms [${summary.change.coldDirectoryFetchMs.min.toFixed(3)}..${summary.change.coldDirectoryFetchMs.max.toFixed(3)}] (${summary.change.directoryFetches.median} fetch/run via coalescing)`
  );
  log(
    `6. Origin Active CPU (1k reqs)  : Baseline ${summary.baseline.originCpuActiveMs.median.toFixed(2)} ms (${summary.baseline.originCpuUsPerReq.median.toFixed(1)} us/req)  ->  Change ${summary.change.originCpuActiveMs.median.toFixed(2)} ms (${summary.change.originCpuUsPerReq.median.toFixed(1)} us/req)  (Added: +${summary.deltas.addedOriginCpuRelativePct.median.toFixed(1)}% [${summary.deltas.addedOriginCpuRelativePct.min.toFixed(1)}%..${summary.deltas.addedOriginCpuRelativePct.max.toFixed(1)}%], IQR ${summary.deltas.addedOriginCpuRelativePct.iqr.toFixed(1)}%)`
  );
  log(
    `7. Wire Header Overhead         : +${summary.change.signedHeaderBytesMedian} bytes/signed request (Signature + Signature-Input + Signature-Agent)`
  );
  log('========================================================================================');

  await fs.writeFile(
    path.join(RESULTS_DIR, 'summary.json'),
    `${JSON.stringify(summary, null, 2)}\n`,
    'utf8'
  );
  await fs.writeFile(
    path.join(RESULTS_DIR, 'measure-log.txt'),
    `${logLines.join('\n')}\n`,
    'utf8'
  );

  await originRpc.call('shutdown');
  await trustedDirServer.close();
  await rogueDirServer.close();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
