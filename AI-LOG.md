# AI-LOG.md — Seminar E1: Web Bot Auth (RFC 9421 HTTP Message Signatures)

**Course:** CSC13114 — Advanced Web Application Development (CQ2023/3)  
**Team Members:**

- `20120450` — Phạm Hữu Đan
- `21120595` — Nguyễn Thành Vinh
- `23120256` — Trần Đại Hiệp

**Data & Cost Declaration:**

- This seminar study uses **zero paid LLM/cloud APIs** at runtime (`$0.00` API cost). All HTTP traffic, TLS 1.3 certificates, Ed25519 keys, and JWKS directory fetches run locally on `127.0.0.1` using Node.js built-in modules (`node:crypto`, `node:https`, `node:perf_hooks`, `node:child_process`, `node:test`). Anyone can re-run `npm test` and `npm run measure` offline without any API key.

---

## Entry 1 · 2026-11-18 — Topic registration and primary-source verification on IETF Datatracker

Tool: Antigravity (Gemini)
Asked for: Formulate a narrow, measurable research question for Topic E1 (_Web Bot Auth_) and summarize the current IETF specification status, headers, and key directory discovery format.
Kept:

- The controlled experimental framing comparing a `User-Agent` + IPv4 CIDR allowlist baseline (`203.0.113.0/24`) against RFC 9421 `Ed25519` HTTP Message Signature verification on a 1,000-request mixed workload (`300` human, `300` valid signed bots, `400` adversarial spoofed/tampered/replayed requests).
  Changed:
- Queried `https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/doc.json` and `https://www.ietf.org/archive/id/draft-ietf-webbotauth-httpsig-protocol-01.txt` directly on `2026-11-18` and updated all protocol citations and wire formats to **`draft-ietf-webbotauth-httpsig-protocol-01`** (published `2026-10-29` by T. Meunier & S. Major in the IETF `webbotauth` Working Group, expiring `2027-05-02`).
  Rejected:
- **Rejected outdated individual-draft names and bare-string `Signature-Agent` wire format:** Secondary blog posts and pre-October-2026 examples (including `web-bot-auth@0.2.0` targeting `-00` / `draft-meunier-web-bot-auth-architecture-03`) cite `draft-meunier-http-message-signatures-directory` and send `Signature-Agent: "https://..."` as a bare Structured Field String. Checking the official `2026-10-29` WG draft (`draft-ietf-webbotauth-httpsig-protocol-01` §5.2.1 & Changelog) revealed that those individual drafts were consolidated into `draft-ietf-webbotauth-httpsig-protocol` and signers **MUST** now send `Signature-Agent` as a **Dictionary Structured Header** (`Signature-Agent: sig1="https://..."`, covering `"signature-agent";key="sig1"`). We rejected generating bare-string headers in our signer and implemented the normative Dictionary format (while testing backward-compatible parsing against IETF Appendix E.2.2).
  By hand: Selected Topic `E1` on the class registration Google Sheet (`20120450-21120595-23120256`) and verified publication dates and statuses of RFC 9421 (Feb 2024), RFC 9651 (Sep 2024), RFC 7517, RFC 7638, RFC 8037, and RFC 9530 on `rfc-editor.org` / `datatracker.ietf.org`.

---

## Entry 2 · 2026-11-18 — Implementing RFC 9421 + Web Bot Auth verifier, SSRF guards, and IETF Appendix E.2 test vectors

Tool: Antigravity (Gemini)
Asked for: Implement Structured Field parsing (`src/structured-fields.js`), RFC 9421 Ed25519 signing/verification (`src/rfc9421.js`), JWKS directory server and cached resolver (`src/directory.js`), and the origin verifiers (`src/baseline-verifier.js`, `src/webbotauth-verifier.js`) with unit tests.
Kept:

- Ephemeral in-memory X.509 v3 Ed25519 TLS certificate generation (`src/tls.js`) so local HTTPS servers run with full CA verification (`rejectUnauthorized: true`) and zero private key PEM files on disk; byte-for-byte test suites (`test/ietf-vectors.test.js`, `test/security-guards.test.js`, `test/integration.test.js`) matching IETF Appendix E.2.1, E.2.2, and E.2.3.
  Changed:
- Enforced `(normalizedDirectoryUrl, keyid)` composite cache indexing in `DirectoryResolver` (`src/directory.js`) per §5.4 instead of indexing by `keyid` thumbprint alone, preventing cross-URL attribution spoofing, and added in-flight fetch coalescing (Appendix C.3) so 16 concurrent cold-start requests trigger only `1` directory HTTPS fetch per run.
  Rejected:
- **Rejected minimal `@authority`-only signature coverage in the benchmark (`src/rfc9421.js`, `src/webbotauth-verifier.js`):** An initial minimal signer following the Appendix E parsing example covered only `("@authority" "signature-agent";key="sig1")`. As `draft-ietf-webbotauth-httpsig-protocol-01` §5.2 and Appendix E explicitly warn, an `@authority`-only signature can be replayed by an attacker against **any path or query string** on the same origin until `expires`. We rejected `@authority`-only acceptance for origin protection, required `@method`, `@authority`, `@path`, and `@query` plus a bounded `nonce`, and added `80` `tampered_target_path_sig` requests plus a dedicated regression test in `test/security-guards.test.js`.
  By hand: Audited all five SSRF precautions in §6.7 (blocking `127.0.0.1`, `localhost`, `10.0.0.0/8`, `169.254.169.254`, HTTP redirects, `>64 KB` responses, and `>16` JWKs by default) and §6.8 rejection of RFC 9421 Appendix B.1.4 example key `poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U`.

---

## Entry 3 · 2026-11-18 — Catching and fixing two benchmark measurement flaws in `scripts/measure.js`

Tool: Antigravity (Gemini)
Asked for: Write `scripts/measure.js` (`npm run measure`) to run 7 controlled iterations comparing Baseline vs. Change and output raw JSON logs and median/spread summaries to `results/`.
Kept:

- Deterministic seeded 1,000-request workload (`seed = 20261118`), alternating run order (`AB`, `BA`, `AB`, ...), pre-warmed TLS keep-alive socket pools, and full state reset (`resetState()` clearing JWKS cache and nonce map) before every timed run so Runs 1–7 each measure a genuine cold directory start rather than carrying a warm JWKS cache across runs.
  Changed:
- **Fix 1 — Isolated Origin Server OS process (`src/origin-worker.js`):** Separated the Origin HTTPS Server into a child process via `child_process.fork()` so client HTTPS load generation and directory responses never pollute origin CPU measurements.
- **Fix 2 — Replaced quantized Windows `process.cpuUsage()` with `performance.eventLoopUtilization()`:** On our first 7-run execution on Windows 11 (`win32`), we inspected the raw output and caught that `process.cpuUsage()` reported `297.00 -> 312.00 ms (+5.1%)`, `250.00 -> 250.00 ms (+0.0%)`, and `172.00 -> 375.00 ms (+118.0%)` — every reading was quantized to multiples of **`15.625 ms` (`1/64 s` Windows `GetProcessTimes` clock tick)** across a `~200 ms` workload! We replaced `process.cpuUsage()` as the primary CPU metric with `perf_hooks.performance.eventLoopUtilization()` (backed by nanosecond `QueryPerformanceCounter` via `uv_hrtime`) and increased V8 TurboFan warm-up from `200` to `1,000` requests before Run 1 (still wiping all caches afterward).
  Rejected:
- **Rejected reporting the first quantized `process.cpuUsage()` run (`[0.0% .. 118.0%]` spread):** Reporting OS-tick-quantized numbers over a `~200 ms` window measured Windows kernel timer granularity rather than Ed25519 verification work. Switching to `eventLoopUtilization()` narrowed the 7-run CPU overhead IQR from `>50%` down to **`9.7%`** (`+69.7%` median, `[+58.7% .. +109.6%]`), while still logging `originOsCpuTicksMs` in `results/run-*.json` for transparency.
  By hand: Checked the mathematical multiples of `15.625 ms` in the initial console output, verified `eventLoopUtilization()` across async libuv ticks on Node `v26.13.1`, and confirmed pairwise delta calculation in `results/summary.json`.

---

## Entry 4 · 2026-11-18 — Writing `REPORT.md`, rendering `slides.pdf`, and automating log-to-slide verification

Tool: Antigravity (Gemini)
Asked for: Draft `REPORT.md` (≤ 3 pages), `slides/slides.html` → `slides.pdf`, `scripts/verify-claims.js`, `TALK.md`, and `SELF_ASSESSMENT_REPORT.md`.
Kept:

- `REPORT.md`, 10-slide 16:9 HTML/PDF deck (`slides.pdf`), `scripts/scan-secrets.js`, and `scripts/verify-claims.js` verifying that all 10 headline metrics in `REPORT.md` and `slides/slides.html` match `results/summary.json` verbatim.
  Changed:
- Visually inspected every page of the rendered `slides.pdf` and fixed three layout defects caught on inspection: (1) reduced vertical padding/card height on Slides 1 and 5 where `overflow: hidden` had clipped the bottom footer bar; (2) replaced literal Markdown backticks `` `403` `` inside HTML table cells on Slide 5 with `<code>403</code>`; and (3) adjusted `<pre>` font size on Slide 4 from `14.5px` to `12.6px` so all 7 run log lines render cleanly without wrapping.
  Rejected:
- Rejected putting any unlogged rounded approximations on the slides; every figure in `REPORT.md` and `slides.pdf` is asserted against `results/summary.json` by `npm run verify:claims`.
  By hand: Reviewed `REPORT.md` length (≤ 3 pages), verified speaker division across all three team members (`20120450`, `21120595`, `23120256`), and calibrated `SELF_ASSESSMENT_REPORT.md`.

---

## Entry 5 · 2026-11-18 — Adding `AGENTS.md` project rules and the full Format → Lint → Typecheck quality-gate harness

Tool: Antigravity (Gemini)
Asked for: Add `AGENTS.md`, Prettier, ESLint, and TypeScript (`tsc --noEmit`) quality gates matching the course harness conventions, and wire them into `npm run check` and `.github/workflows/ci.yml`.
Kept:

- `AGENTS.md` (30 lines covering **Stack**, **Commands**, **Conventions**, **Never**, and **Permissions**), `.prettierrc.json`, `.prettierignore` (protecting raw `results/` logs from reformatting), `eslint.config.js`, `tsconfig.json` (`checkJs: true`, `strict: true`), and `.github/workflows/ci.yml` (`npm ci` + `npm audit --audit-level=high` + `npm run check`).
  Changed:
- Updated `scripts/pack-submission.js` to pass `--exclude=node_modules` to `tar` so installing `devDependencies` locally never bloats the final `<StudentIDs>_<total>.zip` archive while still including `.git` and `package-lock.json`.
  Rejected:
- Rejected letting Prettier format `results/*.json` (`results/` added to `.prettierignore`) so raw outputs written by `npm run measure` remain untouched.
  By hand: Ran `npm run format` → `npm run lint` → `npm run typecheck` → `npm test` → `npm run scan` → `npm run verify:claims` in strict order before committing.
