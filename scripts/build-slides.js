import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));

const DECKS = [
  {
    htmlPath: path.join(ROOT_DIR, 'slides', 'slides.html'),
    pdfPath: path.join(ROOT_DIR, 'slides.pdf')
  },
  {
    htmlPath: path.join(ROOT_DIR, 'slides', 'slides-vi.html'),
    pdfPath: path.join(ROOT_DIR, 'slides-vi.pdf')
  }
];

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
  console.error('No Chromium/Chrome/Edge binary found to render slide PDFs');
  process.exit(1);
}

for (const deck of DECKS) {
  if (!fs.existsSync(deck.htmlPath)) continue;
  const fileUrl = pathToFileURL(deck.htmlPath).href;
  execFileSync(
    browserBin,
    [
      '--headless',
      '--disable-gpu',
      '--virtual-time-budget=3000',
      '--no-pdf-header-footer',
      `--print-to-pdf=${deck.pdfPath}`,
      fileUrl
    ],
    { stdio: 'inherit' }
  );
  const stat = fs.statSync(deck.pdfPath);
  console.log(
    `Generated ${deck.pdfPath} (${(stat.size / 1024).toFixed(1)} KB) using ${browserBin}`
  );
}
