# Recorded Talk — Seminar E1: Web Bot Auth (RFC 9421 HTTP Message Signatures)

- **Course:** CSC13114 — Advanced Web Application Development (CQ2023/3)
- **Team:** `20120450` (Phạm Hữu Đan) · `21120595` (Nguyễn Thành Vinh) · `23120256` (Trần Đại Hiệp)
- **Slides:** [`slides.pdf`](slides.pdf)
- **Recorded Talk Link (≤ 8 minutes, viewable by anyone with the link):**  
  `TODO_BEFORE_SUBMISSION: Paste your Unlisted YouTube or shared Google Drive video URL here`

---

## Speaker Breakdown (All 3 Team Members Present)

| Time Window     | Speaker                            | Slides / Demo Covered                                                                                                                                                                                                                                                                                                                      |
| --------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `00:00 – 02:30` | **Phạm Hữu Đan (`20120450`)**      | **Slides 1–3:** Research question, why `User-Agent` + IPv4 CIDR allowlists fail on shared cloud egress IPs, RFC 9421 + `draft-ietf-webbotauth-httpsig-protocol-01` wire mechanics, and controlled experimental setup (what was held fixed vs. single middleware change).                                                                   |
| `02:30 – 05:30` | **Nguyễn Thành Vinh (`21120595`)** | **Live Terminal Run + Slides 4–7:** Live execution of `npm test && npm run measure`, walkthrough of `results/summary.json`, spoofed-bot rejection (`20.0%` → `100.0%`), `p95` verification latency (`+0.380 ms`, IQR `0.080 ms`), coalesced cold JWKS fetch (`2.822 ms`), origin CPU (`+69.7%`, IQR `9.7%`), and `+457 bytes` header cost. |
| `05:30 – 07:40` | **Trần Đại Hiệp (`23120256`)**     | **Slides 8–10:** Four concrete cases when **not** to use Web Bot Auth at the origin (L7 DDoS CPU asymmetry, zero key revocation, cross-origin privacy correlation, SSRF without fetch bounds), measurement limits, assistant errors caught, and final deployment recommendation.                                                           |
