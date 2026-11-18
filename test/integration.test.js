import assert from 'node:assert/strict';
import https from 'node:https';
import test from 'node:test';
import { createBaselineIpUaVerifier } from '../src/baseline-verifier.js';
import { DirectoryResolver, startDirectoryServer } from '../src/directory.js';
import { startOriginServer } from '../src/origin-server.js';
import { generateBotKeyPair, signBotRequest } from '../src/rfc9421.js';
import { createLoopbackTlsCredentials } from '../src/tls.js';
import { createWebBotAuthVerifier } from '../src/webbotauth-verifier.js';

function sendRequest(agent, baseUrl, method, path, headers) {
  return new Promise((resolve, reject) => {
    const req = https.request(`${baseUrl}${path}`, { method, agent, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: JSON.parse(Buffer.concat(chunks).toString('utf8'))
        });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

test('End-to-end Origin + Directory HTTPS integration: Baseline vs Web Bot Auth', async () => {
  const creds = createLoopbackTlsCredentials();
  const trustedBot = generateBotKeyPair();
  const dirServer = await startDirectoryServer({
    tlsCredentials: creds,
    botKeyPairs: [trustedBot]
  });

  const resolver = new DirectoryResolver({
    caCertPem: creds.cert,
    allowLoopbackForLocalStudy: true
  });

  const baselineOrigin = await startOriginServer({
    tlsCredentials: creds,
    verifier: createBaselineIpUaVerifier()
  });
  const changeOrigin = await startOriginServer({
    tlsCredentials: creds,
    verifier: createWebBotAuthVerifier({
      directoryResolver: resolver,
      trustedDirectoryUrls: [dirServer.url]
    })
  });

  const clientAgent = new https.Agent({ ca: creds.cert, keepAlive: true });

  // 1) Co-hosted cloud IP spoofing User-Agent passes Baseline (false accept) but fails Change (403 + Accept-Signature)
  const spoofHeaders = {
    'User-Agent': 'ResearchCrawler/1.0',
    'X-Simulated-Client-IP': '203.0.113.88'
  };
  const baseSpoof = await sendRequest(
    clientAgent,
    baselineOrigin.baseUrl,
    'GET',
    '/articles/1',
    spoofHeaders
  );
  assert.equal(baseSpoof.statusCode, 200);
  assert.equal(baseSpoof.body.botVerified, true);

  const changeSpoof = await sendRequest(
    clientAgent,
    changeOrigin.baseUrl,
    'GET',
    '/articles/1',
    spoofHeaders
  );
  assert.equal(changeSpoof.statusCode, 403);
  assert.ok(changeSpoof.headers['accept-signature']);

  // 2) Valid signed bot passes Change on first call (200) and fails nonce replay on second call (429)
  const signed = signBotRequest({
    method: 'GET',
    authority: changeOrigin.authority,
    url: '/articles/1?q=ok',
    headers: spoofHeaders,
    privateKey: trustedBot.privateKey,
    keyid: trustedBot.kid,
    agentDirectoryUrl: dirServer.url,
    nonce: 'unique-integration-nonce-001'
  });

  const firstOk = await sendRequest(
    clientAgent,
    changeOrigin.baseUrl,
    'GET',
    '/articles/1?q=ok',
    signed.headers
  );
  assert.equal(firstOk.statusCode, 200);
  assert.equal(firstOk.body.botVerified, true);
  assert.equal(dirServer.getFetchCount(), 1);

  const replayAttempt = await sendRequest(
    clientAgent,
    changeOrigin.baseUrl,
    'GET',
    '/articles/1?q=ok',
    signed.headers
  );
  assert.equal(replayAttempt.statusCode, 429);
  assert.equal(replayAttempt.body.reason, 'replayed_nonce');

  clientAgent.destroy();
  resolver.destroy();
  await baselineOrigin.close();
  await changeOrigin.close();
  await dirServer.close();
});
