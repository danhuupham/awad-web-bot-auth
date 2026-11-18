import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const SUMMARY_PATH = path.join(ROOT_DIR, 'results', 'summary.json');
const REPORT_PATH = path.join(ROOT_DIR, 'REPORT.md');
const SLIDES_HTML_PATH = path.join(ROOT_DIR, 'slides', 'slides.html');

const summary = JSON.parse(fs.readFileSync(SUMMARY_PATH, 'utf8'));
assert.ok(summary.environment.runs >= 5, 'Expected at least 5 recorded runs in summary.json');

for (let r = 1; r <= summary.environment.runs; r += 1) {
  const runPath = path.join(ROOT_DIR, 'results', `run-${String(r).padStart(2, '0')}.json`);
  assert.ok(fs.existsSync(runPath), `Missing raw run log ${runPath}`);
}

const reportText = fs.readFileSync(REPORT_PATH, 'utf8');
const slidesText = fs.readFileSync(SLIDES_HTML_PATH, 'utf8');

const expectedTokens = [
  `${summary.baseline.spoofedBotRejectionRatePct.median.toFixed(1)}%`,
  `${summary.change.spoofedBotRejectionRatePct.median.toFixed(1)}%`,
  `${summary.baseline.verifyLatencyBotP95Ms.median.toFixed(3)} ms`,
  `${summary.change.verifyLatencyBotP95Ms.median.toFixed(3)} ms`,
  `+${summary.deltas.addedVerifyBotP95Ms.median.toFixed(3)} ms`,
  `${summary.change.coldDirectoryFetchMs.median.toFixed(3)} ms`,
  `${summary.baseline.originCpuActiveMs.median.toFixed(2)} ms`,
  `${summary.change.originCpuActiveMs.median.toFixed(2)} ms`,
  `+${summary.deltas.addedOriginCpuRelativePct.median.toFixed(1)}%`,
  `${summary.change.signedHeaderBytesMedian} bytes`
];

for (const token of expectedTokens) {
  assert.ok(
    reportText.includes(token),
    `REPORT.md is missing logged metric "${token}" from results/summary.json`
  );
  assert.ok(
    slidesText.includes(token),
    `slides/slides.html is missing logged metric "${token}" from results/summary.json`
  );
}

const firstLine = reportText.split(/\r?\n/)[0];
assert.match(
  firstLine,
  /^Repository:\s+https:\/\/github\.com\//,
  'REPORT.md first line must contain the public GitHub repository URL'
);

console.log(
  `Claims verification passed: all ${expectedTokens.length} headline metrics in REPORT.md and slides match results/summary.json (${summary.environment.runs} raw logs verified).`
);
