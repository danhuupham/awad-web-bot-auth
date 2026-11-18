Repository: https://github.com/danhuupham/awad-web-bot-auth

# Web Bot Auth at the Origin: Measuring RFC 9421 HTTP Message Signatures Against User-Agent and IP Allowlists

**Course:** CSC13114 (CQ2023/3) · **Topic E1** · **Team:** `20120450` · `21120595` · `23120256`

## 1. Research Question

> _Compared with User-Agent and IP allowlist checks, what percentage of spoofed bot requests (%) does RFC 9421 HTTP Message Signature verification (Ed25519) reject on a 1,000-request mixed workload while accepting valid signed bots, and how much p95 verification latency (ms) and CPU overhead (%) does it add per request?_

## 2. Experimental Setup and What Was Held Fixed

All measurements were recorded locally against self-owned Node.js HTTPS services (`results/summary.json`, `results/run-01.json`–`run-07.json`):

- **Machine & Runtime:** AMD Ryzen 7 4800H (16 logical cores), 31.42 GB RAM, Windows 11 x64 (`win32 10.0.26300`), Node.js `v26.13.1` built-in `node:crypto`, `node:https`, and `node:perf_hooks` (verified compatible with Node.js `22.x` LTS in GitHub Actions CI).
- **Held Fixed Across Baseline and Change:**
  1. **Origin Server Process & Transport:** One isolated child worker process (`src/origin-worker.js`) serving a fixed 1 KB JSON payload over TLS 1.3 (`127.0.0.1`), using an identical keep-alive client pool (`concurrency = 16`, `maxSockets = 16`, pre-warmed on `/__warmup_socket` before each measurement window). Isolating the origin in a separate OS process keeps client TLS generation and directory serving out of origin CPU metrics.
  2. **Deterministic 1,000-Request Mixed Workload (`seed = 20261118`):** Identical URLs, headers, and arrival order:
     - `300` **Human browser requests** (`192.0.2.0/24`, standard browser `User-Agent`) → expected `200 OK` (`botVerified: false`).
     - `300` **Valid signed bot requests** (`ResearchCrawler/1.0` from shared cloud CIDR `203.0.113.0/24`, valid Ed25519 signature) → expected `200 OK` (`botVerified: true`).
     - `400` **Spoofed/adversarial bot requests** (`80` per class): (a) forged `User-Agent` from external IP `198.51.100.0/24`; (b) unsigned forged `User-Agent` from co-hosted cloud tenant IP `203.0.113.0/24`; (c) valid signature from an untrusted rogue directory on `203.0.113.0/24`; (d) valid signature captured for `/articles/public-teaser-*` replayed onto `/articles/premium-feed-*`; (e) `40` expired signatures (`expires < now`) plus `40` replayed nonces captured from earlier valid bot requests.
  3. **JIT Warm-Up & Cold-Cache Discipline:** Both modes receive an identical 1,000-request V8 TurboFan warm-up before Run 1. Across **7 timed runs**, execution order alternates (`baseline -> change`, `change -> baseline`) and `resetState()` clears both the JWKS directory cache and the nonce replay table before every run so Run 1 through Run 7 each incur a genuine cold directory fetch.

## 3. Baseline vs. Single Change

Only the `verifier` middleware injected into `startOriginServer()` (`src/origin-server.js`) changes:

- **Baseline (`src/baseline-verifier.js`):** Checks `User-Agent` (`ResearchCrawler/`) plus a compiled 32-bit IPv4 CIDR allowlist (`203.0.113.0/24`), representing traditional origin bot verification via published crawler IP ranges [2, §2].
- **Change (`src/webbotauth-verifier.js`):** Implements **RFC 9421** (`ed25519`) [1] profiled by **`draft-ietf-webbotauth-httpsig-protocol-01`** [2]: parses Structured Field headers (`Signature`, `Signature-Input`, and Dictionary `Signature-Agent` [2, §5.2.1; 3]); requires `tag="web-bot-auth"`, bounded `created`/`expires`, `nonce`, and narrow target components (`@method`, `@authority`, `@path`, `@query`, `"signature-agent";key="sig1"`); resolves the operator's `application/http-message-signatures-directory+json` JWKS at `/.well-known/http-message-signatures-directory` with SSRF guards, in-flight request coalescing, and `(URL, keyid)` cache binding [2, §5.4–§6.7]; verifies the Ed25519 signature (`kid` = RFC 7638 / RFC 8037 JWK SHA-256 thumbprint [5, 6]); and rejects duplicate nonces (`429`) or invalid/missing signatures (`403` with `Accept-Signature`). Byte-level compliance is verified against official IETF test vectors E.2.1–E.2.3 (`test/ietf-vectors.test.js`).

## 4. Measured Results (7 Runs — Median and Spread)

Pairwise deltas (`Change − Baseline`) are computed within each run before taking the 7-run median (`results/summary.json`):

| Metric (1,000 requests/run, `concurrency = 16`)   | Baseline: UA + IP CIDR (Median `[Min..Max]`, IQR) | Change: Web Bot Auth Ed25519 (Median `[Min..Max]`, IQR)               | Pairwise Delta (Median `[Min..Max]`, IQR)                       |
| ------------------------------------------------- | ------------------------------------------------- | --------------------------------------------------------------------- | --------------------------------------------------------------- |
| **Spoofed bot rejection (`%`, `n = 400`)**        | **`20.0%`** (`[20.0..20.0]`, IQR `0.0%`)          | **`100.0%`** (`[100.0..100.0]`, IQR `0.0%`)                           | **`+80.0 pp`** (`[+80.0..+80.0]`, IQR `0.0`)                    |
| **Valid signed bot acceptance (`%`, `n = 300`)**  | **`100.0%`** (`[100.0..100.0]`)                   | **`100.0%`** (`[100.0..100.0]`)                                       | **`0.0 pp`** (`100.0%` human pass-through)                      |
| **Bot verify middleware `p50` (`ms`, `n = 700`)** | **`0.017 ms`** (`[0.015..0.025]`, IQR `0.003`)    | **`0.221 ms`** (`[0.218..0.267]`, IQR `0.022`)                        | **`+0.204 ms`**                                                 |
| **Bot verify middleware `p95` (`ms`, `n = 700`)** | **`0.046 ms`** (`[0.040..0.055]`, IQR `0.008`)    | **`0.421 ms`** (`[0.396..0.523]`, IQR `0.085`)                        | **`+0.380 ms`** (`[+0.349..+0.468]`, IQR `0.080`)               |
| **All-request verify `p95` (`ms`, `n = 1,000`)**  | **`0.042 ms`** (`[0.039..0.053]`, IQR `0.007`)    | **`0.398 ms`** (`[0.373..0.487]`, IQR `0.080`)                        | **`+0.359 ms`** (`[+0.329..+0.433]`, IQR `0.074`)               |
| **End-to-end HTTPS `p95` (`ms`, `n = 1,000`)**    | **`4.600 ms`** (`[4.250..5.727]`, IQR `0.670`)    | **`6.043 ms`** (`[5.568..8.760]`, IQR `2.543`)                        | **`+1.794 ms`** (`[+1.036..+4.025]`, IQR `1.513`)               |
| **Cold JWKS directory fetch (`ms`)**              | `0` fetches                                       | **`2.822 ms`** (`[2.139..4.248]`, IQR `0.950`, **`1` fetch/run**)     | Coalesced across 16 concurrent sockets                          |
| **Origin active CPU (`ms` / 1,000 reqs)**         | **`170.27 ms`** (`[161.23..221.02]`, IQR `28.66`) | **`291.27 ms`** (`[277.80..382.88]`, IQR `60.21`)                     | **`+127.01 ms`** (**`+69.7%`** `[+58.7%..+109.6%]`, IQR `9.7%`) |
| **Signed request wire header overhead**           | `0 bytes`                                         | **`457 bytes`** (`Signature` + `Signature-Input` + `Signature-Agent`) | **`+457 bytes`** per signed request                             |

**Breakdown by Attack Class (`80` requests each):** Baseline blocks `100%` (`80/80`) of `spoof_external_ip_ua`, but blocks **`0%` (`0/320`)** of `spoof_shared_cloud_ip_ua`, `forged_rogue_directory_sig`, `tampered_target_path_sig`, and `expired_or_replayed_sig` because all four originate inside the shared cloud egress subnet `203.0.113.0/24`. Web Bot Auth blocks **`100%` (`400/400`)** across all five classes.

## 5. Findings, Trade-Offs, and Recommendation

- **What improves and what it costs:** Cryptographic verification raises spoofed-bot rejection from **`20.0%` to `100.0%`** while keeping **`100.0%`** valid-bot acceptance, adding **`+0.380 ms`** to `p95` bot-verification latency (`0.046 ms` → `0.421 ms`), **`+69.7%`** (`+127.0 µs/req`) in origin event-loop CPU time (reducing single-core peak throughput from `5,432` to `3,422 req/s`), and **`+457 bytes`** of uncompressed HTTP headers per signed request (which HPACK/QPACK cannot index across per-request signatures [2, Appendix C.7]).
- **Recommendation — Use Web Bot Auth when:** your origin grants elevated rate limits, paid-crawl access, or agent capabilities to automated clients hosted on shared cloud IP ranges (AWS, GCP, Cloudflare Workers), provided you cache JWKS directories with in-flight coalescing, cover `@method` + `@path` + `@query` (not `@authority` alone [2, §5.2]), and enforce strict SSRF bounds on `Signature-Agent` fetches [2, §6.7].
- **When NOT to use it at the origin:**
  1. **Public cacheable static assets or unthrottled L7 DDoS:** Flooding an origin with random invalid Ed25519 signatures forces `~0.22 ms` of asymmetric math per request; offload verification to an edge CDN or issue short-lived session tokens after the first verified request [2, §5.6, §6.2].
  2. **Instant revocation requirements:** Web Bot Auth defines **no revocation channel**; a compromised key stays valid at verifiers until `expires` or JWKS `Cache-Control` TTL expiry [2, §5.5.2, §6.3].
  3. **Privacy-sensitive user-owned agents:** `Signature-Agent` URLs enable cross-origin request correlation even across key rotations [2, §7.1].
  4. **Legacy crawler ecosystems:** `draft-ietf-webbotauth-httpsig-protocol-01` is an active IETF Working Group draft (expiring May 2027), not yet a finalized RFC; major crawlers still transitioning require fallback policies (`unverified` tier [2, Appendix C.1]).

## 6. Limits of This Measurement

1. **Loopback RTT vs. WAN Directory Discovery:** Our cold JWKS fetch (`2.822 ms`) ran over `127.0.0.1` TLS 1.3; cross-continent TLS + DNS discovery adds `50–250 ms` on cache misses or during directory outages.
2. **Process-Local Nonce Store:** Replay detection used an in-memory `Map`; multi-replica origins require a shared Redis/atomic store, adding `~0.3–1.5 ms` network RTT if per-request nonces are enforced globally [2, Appendix C.6].
3. **Algorithm & Payload Scope:** We measured `GET` requests with `ed25519`; `rsa-pss-sha512` [2, Appendix E.1] incurs higher verification CPU, and `POST` agents covering bodies via `Content-Digest` [7] pay additional hashing and buffering cost.

## 7. Sources (All Primary Specifications Verified on 2026-11-18)

1. A. Backman, J. Richer, M. Sporny, **RFC 9421: _HTTP Message Signatures_**, IETF Proposed Standard, Feb 2024. <https://www.rfc-editor.org/rfc/rfc9421> (accessed 2026-11-18).
2. T. Meunier, S. Major, **`draft-ietf-webbotauth-httpsig-protocol-01`: _HTTP Message Signatures for automated traffic_**, IETF `webbotauth` Working Group Internet-Draft (work in progress; published 29 Oct 2026, expires 2 May 2027). <https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/01/> (accessed 2026-11-18).
3. M. Nottingham, P.-H. Kamp, **RFC 9651: _Structured Field Values for HTTP_**, IETF Proposed Standard, Sep 2024. <https://www.rfc-editor.org/rfc/rfc9651> (accessed 2026-11-18).
4. M. Jones, **RFC 7517: _JSON Web Key (JWK)_**, IETF Proposed Standard, May 2015. <https://www.rfc-editor.org/rfc/rfc7517> (accessed 2026-11-18).
5. M. Jones, N. Sakimura, **RFC 7638: _JSON Web Key (JWK) Thumbprint_**, IETF Proposed Standard, Sep 2015. <https://www.rfc-editor.org/rfc/rfc7638> (accessed 2026-11-18).
6. I. Liusvaara, **RFC 8037: _CFRG ECDH and Signatures in JOSE_** (Appendix A.3: Ed25519 JWK Thumbprint), IETF Proposed Standard, Jan 2017. <https://www.rfc-editor.org/rfc/rfc8037> (accessed 2026-11-18).
7. R. Polli, L. Pardue, **RFC 9530: _Digest Fields_**, IETF Proposed Standard, Feb 2024. <https://www.rfc-editor.org/rfc/rfc9530> (accessed 2026-11-18).
8. Cloudflare Research, **`web-bot-auth` npm package `v0.2.0`** (modified 31 Aug 2026) & repository <https://github.com/cloudflare/web-bot-auth> (accessed 2026-11-18).
9. Node.js Documentation, **`node:crypto` & `node:perf_hooks` (`eventLoopUtilization`)**, Node.js `v26.13.1` / `v22.x` LTS. <https://nodejs.org/api/crypto.html>, <https://nodejs.org/api/perf_hooks.html> (accessed 2026-11-18).
