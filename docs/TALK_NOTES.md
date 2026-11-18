# Presentation Notes & Class Vote Post Template

## 1. Three-Speaker Script Outline (Target: 7m 30s, Limit: 8m 00s)

### Speaker 1 — Pham Huu Dan (`20120450`) · `00:00 – 02:30` (Slides 1–3)
- **Slide 1 (`00:00–00:45`):** State the research question, the workload size (`1,000` requests), and the three headline metrics (`20.0% -> 100.0%` spoofed-bot rejection, `+0.380 ms` `p95` verification latency, `+69.7%` origin active CPU).
- **Slide 2 (`00:45–01:35`):** Explain why `User-Agent` + IP CIDR allowlists fail on shared cloud egress subnets (`203.0.113.0/24`) and how RFC 9421 (`Ed25519`) + `draft-ietf-webbotauth-httpsig-protocol-01` (`Signature-Agent` Dictionary, `Signature-Input`, `Signature`, and `/.well-known/http-message-signatures-directory`) authenticate the bot cryptographically.
- **Slide 3 (`01:35–02:30`):** Walk through what was held fixed (isolated origin worker process, TLS 1.3 keep-alive `concurrency = 16`, deterministic `seed = 20261118` workload with 5 adversarial classes, 1,000-request V8 JIT warm-up, alternating `AB/BA` run order, and cold JWKS reset before each of the 7 runs).

### Speaker 2 — Nguyen Thanh Vinh (`21120595`) · `02:30 – 05:30` (Live Run + Slides 4–7)
- **Live Terminal + Slide 4 (`02:30–03:20`):** Run `npm test && npm run measure` live, showing the 10 passing tests (including IETF Appendix E.2.1–E.2.3 vectors) and the raw outputs written to `results/run-01.json`..`run-07.json` and `results/summary.json`.
- **Slide 5 (`03:20–04:05`):** Present security accuracy (`100.0%` valid bots accepted, `100.0%` humans passed, `20.0% -> 100.0%` spoofed bots rejected across all 5 attack vectors, IQR `0.0%`).
- **Slide 6 (`04:05–04:45`):** Present latency (`p50` `0.017 -> 0.221 ms`, `p95` `0.046 -> 0.421 ms`, pairwise delta `+0.380 ms`, IQR `0.080 ms`) and cold JWKS fetch (`2.822 ms`, `1` fetch/run via in-flight coalescing).
- **Slide 7 (`04:45–05:30`):** Present origin active CPU (`170.27 -> 291.27 ms` per 1,000 requests, `+69.7%`, IQR `9.7%`), single-core peak throughput (`5,432 -> 3,422 req/s`), and `+457 bytes` of HPACK/QPACK-incompressible headers per signed request.

### Speaker 3 — Tran Dai Hiep (`23120256`) · `05:30 – 07:40` (Slides 8–10)
- **Slide 8 (`05:30–06:25`):** Explain the four cases when **not** to use Web Bot Auth directly at the origin: unthrottled L7 DDoS / public static assets, instant key revocation requirements, privacy-sensitive personal agents, and deployments without SSRF bounds on `Signature-Agent` fetches.
- **Slide 9 (`06:25–07:05`):** Summarize measurement limits (loopback RTT vs. WAN discovery, single-process nonce map vs. Redis, `GET` + `Ed25519` scope) and the three real technical defects caught and logged in `AI-LOG.md`.
- **Slide 10 (`07:05–07:40`):** Close with the scenario-by-scenario deployment recommendation and verified primary sources (`2026-11-18`).

---

## 2. Facebook Group Vote Post (`AWAD FIT HCMUS`)

```text
#AWADSeminar23_3
Web Bot Auth at the Origin: Measuring RFC 9421 HTTP Message Signatures Against User-Agent and IP Allowlists

Question: Compared with User-Agent and IP allowlist checks, what percentage of spoofed bot requests (%) does RFC 9421 HTTP Message Signature verification (Ed25519) reject on a 1,000-request mixed workload while accepting valid signed bots, and how much p95 verification latency (ms) and CPU overhead (%) does it add per request?

Headline number: Web Bot Auth raises spoofed-bot rejection from 20.0% to 100.0% (+80.0 pp across 7 cold-reset runs; 100.0% valid bots accepted) while adding +0.380 ms to p95 verification latency (0.046 ms -> 0.421 ms, IQR 0.080 ms), +69.7% origin active CPU (+127.0 us/req, IQR 9.7%), and +457 bytes of HTTP headers per signed request.

Talk video: <PASTE_UNLISTED_YOUTUBE_OR_GOOGLE_DRIVE_LINK_HERE>
GitHub repo: https://github.com/danhuupham/awad-web-bot-auth
Team: 20120450 - 21120595 - 23120256
```
