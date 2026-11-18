import assert from 'node:assert/strict';
import https from 'node:https';
import test from 'node:test';
import {
  DIRECTORY_MEDIA_TYPE,
  DIRECTORY_WELL_KNOWN_PATH,
  DirectoryResolver,
  isRestrictedHostOrIp,
  normalizeSignatureAgentIdentifier
} from '../src/directory.js';
import { generateBotKeyPair, signBotRequest } from '../src/rfc9421.js';
import { createLoopbackTlsCredentials } from '../src/tls.js';
import { createWebBotAuthVerifier } from '../src/webbotauth-verifier.js';

test('Section 6.7 SSRF host and IP filter blocks private, loopback, and metadata addresses by default', async () => {
  assert.equal(isRestrictedHostOrIp('127.0.0.1'), true);
  assert.equal(isRestrictedHostOrIp('localhost'), true);
  assert.equal(isRestrictedHostOrIp('10.0.0.5'), true);
  assert.equal(isRestrictedHostOrIp('169.254.169.254'), true);
  assert.equal(isRestrictedHostOrIp('172.16.10.2'), true);
  assert.equal(isRestrictedHostOrIp('192.168.1.1'), true);
  assert.equal(isRestrictedHostOrIp('::1'), true);
  assert.equal(isRestrictedHostOrIp('93.184.216.34'), false);

  const resolver = new DirectoryResolver({ allowLoopbackForLocalStudy: false });
  const res = await resolver.resolveKey(
    'https://127.0.0.1:8443/.well-known/http-message-signatures-directory',
    'some-kid'
  );
  assert.equal(res.status, 'ssrf_blocked');
  resolver.destroy();
});

test('Section 5.5 URI normalization strips query parameters and enforces https scheme', () => {
  assert.throws(() => normalizeSignatureAgentIdentifier('http://example.com/jwks.json'));
  assert.equal(
    normalizeSignatureAgentIdentifier(
      'https://EXAMPLE.COM:443/.well-known/http-message-signatures-directory?tenant=123'
    ),
    'https://example.com/.well-known/http-message-signatures-directory'
  );
});

test('Section 6.8 rejects RFC 9421 example test key unless explicitly enabled', async () => {
  const resolver = new DirectoryResolver({
    allowLoopbackForLocalStudy: true,
    allowRfcTestKeys: false
  });
  const res = await resolver.resolveKey(
    'https://127.0.0.1:9999/.well-known/http-message-signatures-directory',
    'poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U'
  );
  assert.equal(res.status, 'test_key_rejected');
  resolver.destroy();
});

test('Section 5.4 indexes cached keys by (URL, keyid) pair rather than keyid alone, and Section 6.10 handles rotation/outage', async () => {
  const creds = createLoopbackTlsCredentials();
  let activeKeys = [generateBotKeyPair()];
  let failMode = false;

  const dirA = https.createServer(creds, (req, res) => {
    if (failMode) {
      res.writeHead(503);
      res.end('unavailable');
      return;
    }
    res.writeHead(200, {
      'Content-Type': DIRECTORY_MEDIA_TYPE,
      'Cache-Control': 'max-age=60'
    });
    res.end(JSON.stringify({ keys: activeKeys.map((k) => k.publicJwk) }));
  });
  const dirB = https.createServer(creds, (req, res) => {
    res.writeHead(200, {
      'Content-Type': DIRECTORY_MEDIA_TYPE,
      'Cache-Control': 'max-age=60'
    });
    res.end(JSON.stringify({ keys: [] }));
  });

  await new Promise((r) => dirA.listen({ port: 0, host: '127.0.0.1' }, () => r(null)));
  await new Promise((r) => dirB.listen({ port: 0, host: '127.0.0.1' }, () => r(null)));

  let fakeNowMs = 1_760_000_000_000;
  const resolver = new DirectoryResolver({
    caCertPem: creds.cert,
    allowLoopbackForLocalStudy: true,
    nowFn: () => fakeNowMs
  });

  const addrA = dirA.address();
  const addrB = dirB.address();
  if (!addrA || typeof addrA === 'string' || !addrB || typeof addrB === 'string') {
    throw new Error('Expected bound TCP ports');
  }
  const urlA = `https://127.0.0.1:${addrA.port}${DIRECTORY_WELL_KNOWN_PATH}`;
  const urlB = `https://127.0.0.1:${addrB.port}${DIRECTORY_WELL_KNOWN_PATH}`;
  const key1 = activeKeys[0];

  const hitA = await resolver.resolveKey(urlA, key1.kid);
  assert.equal(hitA.status, 'ok');

  // Asserting urlB with key1.kid MUST fail even though key1.kid is cached under urlA
  const crossUrlAttempt = await resolver.resolveKey(urlB, key1.kid);
  assert.equal(crossUrlAttempt.status, 'key_not_found');

  // Section 6.10: transient 503 after TTL expiry MUST NOT evict cached key
  fakeNowMs += 120_000;
  failMode = true;
  const duringOutage = await resolver.resolveKey(urlA, key1.kid);
  assert.equal(duringOutage.status, 'ok');

  // Section 5.5.2 & 6.10: valid 200 response rotating out key1 replaces cached entry
  failMode = false;
  const key2 = generateBotKeyPair();
  activeKeys = [key2];
  const rotatedOld = await resolver.resolveKey(urlA, key1.kid);
  assert.equal(rotatedOld.status, 'key_not_found');
  const rotatedNew = await resolver.resolveKey(urlA, key2.kid);
  assert.equal(rotatedNew.status, 'ok');

  resolver.destroy();
  await new Promise((r) => dirA.close(r));
  await new Promise((r) => dirB.close(r));
});

test('Verifier rejects @authority-only signatures when narrow target coverage is required', async () => {
  const creds = createLoopbackTlsCredentials();
  const botKey = generateBotKeyPair();
  const dir = https.createServer(creds, (req, res) => {
    res.writeHead(200, { 'Content-Type': DIRECTORY_MEDIA_TYPE });
    res.end(JSON.stringify({ keys: [botKey.publicJwk] }));
  });
  await new Promise((r) => dir.listen({ port: 0, host: '127.0.0.1' }, () => r(null)));
  const addr = dir.address();
  if (!addr || typeof addr === 'string') throw new Error('Expected bound TCP port');
  const dirUrl = `https://127.0.0.1:${addr.port}${DIRECTORY_WELL_KNOWN_PATH}`;

  const resolver = new DirectoryResolver({
    caCertPem: creds.cert,
    allowLoopbackForLocalStudy: true
  });
  const verifier = createWebBotAuthVerifier({
    directoryResolver: resolver,
    trustedDirectoryUrls: [dirUrl],
    requireRequestTargetCoverage: true
  });

  const nowSec = Math.floor(Date.now() / 1000);
  const wideSig = signBotRequest({
    method: 'GET',
    authority: 'origin.example',
    url: '/articles/secret',
    headers: { 'User-Agent': 'ResearchCrawler/1.0' },
    privateKey: botKey.privateKey,
    keyid: botKey.kid,
    agentDirectoryUrl: dirUrl,
    created: nowSec - 2,
    expires: nowSec + 60,
    coverMethodPathQuery: false
  });

  const decision = await verifier.verifyRequest({
    method: 'GET',
    url: '/articles/secret',
    headers: {
      host: 'origin.example',
      'user-agent': 'ResearchCrawler/1.0',
      'signature-agent': wideSig.headers['Signature-Agent'],
      'signature-input': wideSig.headers['Signature-Input'],
      signature: wideSig.headers.Signature
    }
  });
  assert.equal(decision.allowed, false);
  assert.equal(decision.statusCode, 403);
  assert.equal(decision.reason, 'narrow_target_components_missing');

  resolver.destroy();
  await new Promise((r) => dir.close(r));
});
