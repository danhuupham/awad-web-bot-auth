import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const PARENT_DIR = path.resolve(ROOT_DIR, '..');

const talkContent = fs.readFileSync(path.join(ROOT_DIR, 'TALK.md'), 'utf8');
if (talkContent.includes('TODO_BEFORE_SUBMISSION')) {
  console.error(
    '[BLOCKED] TALK.md still contains TODO_BEFORE_SUBMISSION. Paste your Unlisted YouTube or Google Drive link into TALK.md and commit first.'
  );
  process.exit(1);
}

const dirty = execSync('git status --porcelain', { cwd: ROOT_DIR, encoding: 'utf8' }).trim();
if (dirty) {
  console.error('[BLOCKED] Working tree has uncommitted changes. Commit all files before packing.');
  process.exit(1);
}

execSync('npm run check', { cwd: ROOT_DIR, stdio: 'inherit' });

const selfAssess = fs.readFileSync(path.join(ROOT_DIR, 'SELF_ASSESSMENT_REPORT.md'), 'utf8');
const match = /Total we claim:\s*(\d+)\s*\/\s*100/i.exec(selfAssess);
if (!match) {
  console.error(
    '[BLOCKED] Could not parse "Total we claim: XX / 100" from SELF_ASSESSMENT_REPORT.md'
  );
  process.exit(1);
}

const total = match[1];
const zipName = `20120450-21120595-23120256_${total}.zip`;
const outZipPath = path.join(PARENT_DIR, zipName);

if (fs.existsSync(outZipPath)) {
  fs.unlinkSync(outZipPath);
}

// Use tar -a -c -f (built into Windows 10/11 & macOS/Linux bsdtar) so hidden .git directory is included cleanly while excluding node_modules
execSync(`tar -a -c -f "${outZipPath}" --exclude=node_modules -C "${ROOT_DIR}" .`, {
  stdio: 'inherit'
});

const sizeKb = (fs.statSync(outZipPath).size / 1024).toFixed(1);
console.log(`Packed submission archive (including .git): ${outZipPath} (${sizeKb} KB)`);
