import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));

const SECRET_PATTERNS = [
  { name: 'PEM Private Key', regex: /-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/ },
  { name: 'GitHub Token', regex: /\bgh[pousr]_[A-Za-z0-9_]{30,}\b/ },
  { name: 'Google API Key', regex: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { name: 'OpenAI Key', regex: /\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b/ },
  { name: 'AWS Access Key', regex: /\bAKIA[0-9A-Z]{16}\b/ }
];

const IGNORED_DIRS = new Set(['.git', 'node_modules']);
const BINARY_EXTS = new Set(['.pdf', '.png', '.jpg', '.jpeg', '.zip', '.woff', '.woff2']);

function walkFiles(dir, list = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (IGNORED_DIRS.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkFiles(fullPath, list);
    } else if (!BINARY_EXTS.has(path.extname(entry.name).toLowerCase())) {
      list.push(fullPath);
    }
  }
  return list;
}

let findings = 0;

for (const filePath of walkFiles(ROOT_DIR)) {
  const rel = path.relative(ROOT_DIR, filePath);
  if (rel.replace(/\\/g, '/') === 'scripts/scan-secrets.js') continue;
  const content = fs.readFileSync(filePath, 'utf8');
  for (const pat of SECRET_PATTERNS) {
    if (pat.regex.test(content)) {
      console.error(`[FAIL] Secret pattern "${pat.name}" matched in ${rel}`);
      findings += 1;
    }
  }
}

if (fs.existsSync(path.join(ROOT_DIR, '.git'))) {
  try {
    const history = execSync('git log -p --all -- . ":!scripts/scan-secrets.js"', {
      cwd: ROOT_DIR,
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024
    });
    for (const pat of SECRET_PATTERNS) {
      if (pat.regex.test(history)) {
        console.error(`[FAIL] Secret pattern "${pat.name}" matched in git commit history`);
        findings += 1;
      }
    }
  } catch {
    // Empty git repo before initial commit
  }
}

if (findings > 0) {
  process.exit(1);
}
console.log('Secret scan passed: 0 findings across working tree and git history.');
