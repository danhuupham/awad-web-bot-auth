import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const HTML_PATH = path.join(ROOT_DIR, 'slides', 'slides.html');
const PDF_PATH = path.join(ROOT_DIR, 'slides.pdf');

const CANDIDATE_BROWSERS = [
  process.env.BROWSER_BIN,
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium-browser',
  '/usr/bin/chromium',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
].filter((p) => typeof p === 'string');

const browserBin = CANDIDATE_BROWSERS.find((p) => fs.existsSync(p));
if (!browserBin) {
  console.error('No Chromium/Chrome/Edge binary found to render slides.pdf');
  process.exit(1);
}

const fileUrl = pathToFileURL(HTML_PATH).href;
execFileSync(
  browserBin,
  [
    '--headless',
    '--disable-gpu',
    '--virtual-time-budget=3000',
    '--no-pdf-header-footer',
    `--print-to-pdf=${PDF_PATH}`,
    fileUrl
  ],
  { stdio: 'inherit' }
);

const stat = fs.statSync(PDF_PATH);
console.log(`Generated ${PDF_PATH} (${(stat.size / 1024).toFixed(1)} KB) using ${browserBin}`);
