# Web Bot Auth Study — Project Rules (`AGENTS.md`)

## Stack

- Node.js `>=22.13.0` (`v26.13.1` Active LTS "Lithium", ESM, built-in `node:crypto`, `node:https`, `node:perf_hooks`, `node:child_process`, `node:test`), ESLint 10, Prettier 3.10, TypeScript 7 (`tsc --noEmit`).
- Zero runtime `dependencies` and `$0.00` external API cost: `npm test` and `npm run measure` run 100% offline over loopback TLS 1.3 (`127.0.0.1`).

## Commands

- `npm ci` · `npm run format` · `npm run format:check` · `npm run lint` · `npm run typecheck` · `npm test` · `npm run scan` · `npm run verify:claims` · `npm run check` · `npm run measure` · `npm run build:slides` · `npm run pack:submission`

## Conventions

- Run quality gates in strict order before every commit: **Format → Lint → Typecheck → Test → Scan → Verify Claims** (`npm run format && npm run check`).
- Hold everything fixed between Baseline (`src/baseline-verifier.js`) and Change (`src/webbotauth-verifier.js`): same `src/origin-server.js` inside isolated child process `src/origin-worker.js`, same TLS 1.3 socket pool (`concurrency = 16`), same `seed = 20261118` workload, equal 1,000-request V8 JIT warm-up, alternating `AB/BA` run order, and full JWKS/nonce wipe before every timed run.
- Measure origin active CPU via `perf_hooks.performance.eventLoopUtilization()` inside `src/origin-worker.js` rather than `process.cpuUsage()` to avoid Windows `15.625 ms` `GetProcessTimes` tick quantization (`AI-LOG.md` Entry 3).
- Index JWKS caches strictly on `(normalizedDirectoryUrl, keyid)` (`draft-ietf-webbotauth-httpsig-protocol-01` §5.4) and require `@method`, `@authority`, `@path`, `@query`, and Dictionary `"signature-agent";key="<label>"` coverage (`AI-LOG.md` Entries 1–2).
- Cite only primary specifications/docs with exact versions, publication dates, and access dates in `REPORT.md` §7.

## Never

- Never send traffic, crawls, or directory fetches outside `127.0.0.1` (`allowLoopbackForLocalStudy: false` blocks loopback, private, and link-local IPs by default per §6.7).
- Never commit PEM private keys, `.env`, or numbers in `REPORT.md` / `slides/slides.html` that do not exist in `results/summary.json`.
- Never hand-edit `results/*.json` or weaken `test/` / `scripts/verify-claims.js` to make checks pass; never silence gates with `|| true`, `.skip`, or `continue-on-error: true`.

## Permissions

- **Allowed:** Read tracked files; edit `src/`, `slides/`, and docs; run `npm run format`, `npm run check`, `npm run measure`, `npm run build:slides`, `git status`, `git diff`, `git log`.
- **Ask First:** Edit `test/`, `.github/workflows/`, `package.json`, or `scripts/verify-claims.js`; create/push public GitHub repositories or open PRs.
- **Never:** Commit secrets/private keys; send outbound traffic to external sites; fabricate benchmark logs or uncited version facts.
