# Seminar E1 — A Measured Look at Web Bot Auth (RFC 9421 HTTP Message Signatures)

**Course:** CSC13114 — Advanced Web Application Development (CQ2023/3)  
**Team:** `20120450` (Phạm Hữu Đan) · `21120595` (Nguyễn Thành Vinh) · `23120256` (Trần Đại Hiệp)

## Research Question

> _Compared with User-Agent and IP allowlist checks, what percentage of spoofed bot requests (%) does RFC 9421 HTTP Message Signature verification (Ed25519) reject on a 1,000-request mixed workload while accepting valid signed bots, and how much p95 verification latency (ms) and CPU overhead (%) does it add per request?_

---

## From a Fresh Clone to `npm run measure`

### Prerequisites

- **Node.js `>= 22.0.0`** (tested on Node `v22.x` LTS on Ubuntu Linux and Node `v26.13.1` on Windows 11 x64).
- **Zero external npm dependencies, zero API keys, and zero network calls outside `127.0.0.1`:** all Ed25519 cryptography, ephemeral TLS 1.3 X.509 certificates, HTTP Structured Field parsing, and benchmarking use Node.js built-in modules (`node:crypto`, `node:https`, `node:perf_hooks`, `node:child_process`, `node:test`).

### Step-by-Step Reproduction

```bash
git clone https://github.com/danhuupham/awad-web-bot-auth.git
cd awad-web-bot-auth
npm ci
npm run check
npm run measure
```

_(Because runtime `dependencies` are empty, `npm test` and `npm run measure` can also run directly without `npm ci` in offline environments; `npm ci` installs the pinned quality-gate toolchain: Prettier, ESLint, and TypeScript.)_

### What `npm run measure` Does

1. Generates ephemeral in-memory X.509 v3 Ed25519 TLS credentials for `127.0.0.1` (full CA verification enabled; no private keys on disk) and starts two local HTTPS JWKS key directories (`trusted` and `rogue`) serving `/.well-known/http-message-signatures-directory` per `draft-ietf-webbotauth-httpsig-protocol-01`.
2. Forks an isolated **Origin HTTPS Server worker process** (`src/origin-worker.js`) so Origin CPU utilization (`performance.eventLoopUtilization()`) is never contaminated by the HTTPS load-generator client or directory servers.
3. Generates a deterministic **1,000-request mixed workload** (`seed = 20261118`): `300` human browser requests, `300` valid Ed25519-signed bot requests, and `400` spoofed/adversarial bot requests across 5 attack vectors (`80` each).
4. Warms up V8 TurboFan JIT equally on both middlewares (`1,000` requests each), then runs **7 full iterations** alternating execution order (`baseline -> change`, `change -> baseline`, ...), resetting JWKS caches and nonce replay state before every timed run.
5. Prints per-run numbers and the 7-run **median, IQR, and min–max spread**, and writes raw artifacts into [`results/`](results/):
   - `results/run-01.json` … `results/run-07.json` — raw per-run metrics, attack breakdown, directory stats, and CPU measurements.
   - `results/summary.json` — aggregated median, IQR (`p75 - p25`), `p25`, `p75`, `min`, and `max` across all 7 runs.
   - `results/measure-log.txt` — exact stdout table printed by `npm run measure`.

### Quality Gate Commands (See [`AGENTS.md`](AGENTS.md))

| Command                                   | Purpose                                                                                                    |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `npm run format` / `npm run format:check` | Formats or checks formatting with Prettier 3 (`results/` and `slides.pdf` excluded)                        |
| `npm run lint`                            | Runs ESLint 9 across `src/`, `test/`, and `scripts/`                                                       |
| `npm run typecheck`                       | Runs TypeScript `tsc --noEmit` (`checkJs: true`, `strict: true`)                                           |
| `npm test`                                | Runs 10 unit, official IETF Appendix E.2 test-vector, SSRF/cache security, and HTTPS integration tests     |
| `npm run verify:claims`                   | Verifies every headline metric in `REPORT.md` and `slides/slides.html` matches `results/summary.json`      |
| `npm run scan`                            | Scans working tree and `git log -p --all` to ensure zero private keys or secrets are committed             |
| `npm run check`                           | Runs all six synchronous gates (`format:check` → `lint` → `typecheck` → `test` → `scan` → `verify:claims`) |

---

## Key Deliverable Files

- [`REPORT.md`](REPORT.md) — Short study report (≤ 3 pages) answering the research question with setup, numbers, trade-offs, limits, and primary IETF/Node.js sources.
- [`slides.pdf`](slides.pdf) — 10-slide presentation deck rendered from [`slides/slides.html`](slides/slides.html).
- [`TALK.md`](TALK.md) — Recorded presentation link and 3-member speaking breakdown.
- [`AI-LOG.md`](AI-LOG.md) — Transparent log of assistant usage, rejected drafts, and technical errors caught by the team.
- [`SELF_ASSESSMENT_REPORT.md`](SELF_ASSESSMENT_REPORT.md) — Criterion-by-criterion self-assessment with file and log evidence.
