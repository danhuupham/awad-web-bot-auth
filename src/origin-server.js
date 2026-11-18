import https from 'node:https';

const FIXED_ARTICLE_BODY = 'x'.repeat(860);

/**
 * Shared HTTPS Origin Server used identically for Baseline and Change runs.
 * Only the injected `verifier` middleware differs between Baseline and Change.
 */
export async function startOriginServer({ tlsCredentials, verifier }) {
  const server = https.createServer(tlsCredentials, async (req, res) => {
    const verifyStartNs = process.hrtime.bigint();
    const decision = await verifier.verifyRequest(req);
    const verifyLatencyMs = Number(process.hrtime.bigint() - verifyStartNs) / 1e6;

    const commonHeaders = {
      'Content-Type': 'application/json; charset=utf-8',
      'X-Verify-Latency-Ms': verifyLatencyMs.toFixed(6),
      'X-Bot-Verified': decision.botVerified ? '1' : '0',
      'X-Verify-Reason': decision.reason,
      ...decision.headers
    };

    if (!decision.allowed) {
      const errPayload = JSON.stringify({
        status: decision.statusCode,
        allowed: false,
        botVerified: false,
        reason: decision.reason
      });
      res.writeHead(decision.statusCode, commonHeaders);
      res.end(errPayload);
      return;
    }

    const okPayload = JSON.stringify({
      status: 200,
      allowed: true,
      botVerified: decision.botVerified,
      category: decision.category,
      path: req.url,
      content: FIXED_ARTICLE_BODY
    });
    res.writeHead(200, commonHeaders);
    res.end(okPayload);
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  return {
    port,
    authority: `127.0.0.1:${port}`,
    baseUrl: `https://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => server.close(resolve))
  };
}
