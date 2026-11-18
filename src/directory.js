import crypto from 'node:crypto';
import https from 'node:https';
import net from 'node:net';
import {
  KNOWN_TEST_KEY_THUMBPRINTS,
  buildSignatureBase,
  computeEd25519JwkThumbprint
} from './rfc9421.js';
import { serializeSignatureParamsValue } from './structured-fields.js';

export const DIRECTORY_WELL_KNOWN_PATH = '/.well-known/http-message-signatures-directory';
export const DIRECTORY_MEDIA_TYPE = 'application/http-message-signatures-directory+json';

/**
 * Normalizes a Signature-Agent URI per draft-ietf-webbotauth-httpsig-protocol-01 Section 5.5:
 * - Must be https
 * - Query component discarded from the identifier (though fetched as sent)
 * - Scheme and host lowercased, default port :443 stripped
 */
export function normalizeSignatureAgentIdentifier(rawUri) {
  let parsed;
  try {
    parsed = new URL(rawUri);
  } catch {
    throw new Error('Invalid Signature-Agent URI');
  }
  if (parsed.protocol !== 'https:') {
    throw new Error('Signature-Agent URI scheme MUST be https');
  }
  if (parsed.username || parsed.password || parsed.hash) {
    throw new Error('Signature-Agent URI must not contain credentials or fragment');
  }
  const host = parsed.hostname.toLowerCase();
  const portPart = parsed.port && parsed.port !== '443' ? `:${parsed.port}` : '';
  const pathname = parsed.pathname || '/';
  return `https://${host}${portPart}${pathname}`;
}

/**
 * Checks whether a hostname or IP literal falls in loopback, private, or link-local ranges
 * per draft-ietf-webbotauth-httpsig-protocol-01 Section 6.7 (SSRF).
 */
export function isRestrictedHostOrIp(hostname) {
  const lower = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (lower === 'localhost' || lower.endsWith('.localhost') || lower.endsWith('.internal')) {
    return true;
  }
  const ipVersion = net.isIP(lower);
  if (ipVersion === 4) {
    const parts = lower.split('.').map((x) => Number.parseInt(x, 10));
    const [a, b] = parts;
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 169 && b === 254) return true; // link-local / cloud metadata 169.254.169.254
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    return false;
  }
  if (ipVersion === 6) {
    if (lower === '::1' || lower === '::') return true;
    if (lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd')) return true;
    if (lower.startsWith('::ffff:')) {
      return isRestrictedHostOrIp(lower.slice(7));
    }
  }
  return false;
}

/**
 * Signs a directory JWKS JSON body per Appendix B & Appendix E.2.3 (tag="http-message-signatures-directory").
 */
export function signDirectoryResponse({
  requestAuthority,
  bodyString,
  signingKeyPair,
  created = Math.floor(Date.now() / 1000),
  expires = created + 3600
}) {
  const digestB64 = crypto.createHash('sha256').update(bodyString, 'utf8').digest('base64');
  const contentDigest = `sha-256=:${digestB64}:`;
  const components = [
    { name: '@authority', params: [{ key: 'req', value: true, type: 'boolean' }] },
    { name: 'content-digest', params: [] }
  ];
  const signatureParams = [
    { key: 'created', value: created, type: 'integer' },
    { key: 'expires', value: expires, type: 'integer' },
    { key: 'keyid', value: signingKeyPair.kid, type: 'string' },
    { key: 'tag', value: 'http-message-signatures-directory', type: 'string' }
  ];
  const serializedParams = serializeSignatureParamsValue(components, signatureParams);
  const signatureBase = buildSignatureBase({
    message: {
      status: 200,
      headers: { 'content-digest': contentDigest },
      request: { authority: requestAuthority, headers: { host: requestAuthority } }
    },
    components,
    serializedParams
  });
  const sig = crypto.sign(null, Buffer.from(signatureBase, 'utf8'), signingKeyPair.privateKey);
  return {
    'Content-Digest': contentDigest,
    'Signature-Input': `binding=${serializedParams}`,
    Signature: `binding=:${sig.toString('base64')}:`
  };
}

/**
 * Local HTTPS directory server serving /.well-known/http-message-signatures-directory.
 */
export async function startDirectoryServer({
  tlsCredentials,
  botKeyPairs,
  maxAgeSec = 300,
  artificialDelayMs = 0
}) {
  let fetchCount = 0;

  const server = https.createServer(tlsCredentials, async (req, res) => {
    fetchCount += 1;
    if (artificialDelayMs > 0) {
      await new Promise((r) => setTimeout(r, artificialDelayMs));
    }

    const urlObj = new URL(req.url ?? '/', `https://${req.headers.host ?? '127.0.0.1'}`);
    if (req.method !== 'GET' || urlObj.pathname !== DIRECTORY_WELL_KNOWN_PATH) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not_found' }));
      return;
    }

    const bodyString = JSON.stringify({
      keys: botKeyPairs.map((kp) => kp.publicJwk)
    });
    const bindingHeaders =
      botKeyPairs.length > 0
        ? signDirectoryResponse({
            requestAuthority: req.headers.host ?? '127.0.0.1',
            bodyString,
            signingKeyPair: botKeyPairs[0]
          })
        : {};

    res.writeHead(200, {
      'Content-Type': DIRECTORY_MEDIA_TYPE,
      'Cache-Control': `public, max-age=${maxAgeSec}`,
      ...bindingHeaders
    });
    res.end(bodyString);
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  return {
    port,
    url: `https://127.0.0.1:${port}${DIRECTORY_WELL_KNOWN_PATH}`,
    getFetchCount: () => fetchCount,
    resetFetchCount: () => {
      fetchCount = 0;
    },
    close: () => new Promise((resolve) => server.close(resolve))
  };
}

function parseMaxAgeSeconds(cacheControlHeader, fallbackSec) {
  if (!cacheControlHeader) return fallbackSec;
  const match = /max-age=(\d+)/i.exec(String(cacheControlHeader));
  return match ? Number.parseInt(match[1], 10) : fallbackSec;
}

/**
 * Bounded, SSRF-guarded, coalescing JWKS directory resolver keyed by (normalizedUrl, keyid)
 * per draft-ietf-webbotauth-httpsig-protocol-01 Sections 5.4, 5.5, 6.7, 6.8, 6.10, and Appendix C.3/C.4.
 */
export class DirectoryResolver {
  constructor({
    caCertPem,
    allowLoopbackForLocalStudy = false,
    allowRfcTestKeys = false,
    maxBytes = 65536,
    maxKeys = 16,
    timeoutMs = 2000,
    defaultTtlSec = 300,
    nowFn = () => Date.now()
  } = {}) {
    this.allowLoopbackForLocalStudy = allowLoopbackForLocalStudy;
    this.allowRfcTestKeys = allowRfcTestKeys;
    this.maxBytes = maxBytes;
    this.maxKeys = maxKeys;
    this.timeoutMs = timeoutMs;
    this.defaultTtlSec = defaultTtlSec;
    this.nowFn = nowFn;
    this.agent = new https.Agent({
      ca: caCertPem,
      keepAlive: true,
      maxSockets: 16
    });

    // Map<normalizedUrl, { expiresAtMs: number, keysByKid: Map<string, crypto.KeyObject> }>
    this.cache = new Map();
    // Map<normalizedUrl, Promise<Map<string, crypto.KeyObject>>>
    this.inFlight = new Map();
    this.stats = { cacheHits: 0, networkFetches: 0, coldFetchDurationsMs: [] };
  }

  clearCache() {
    this.cache.clear();
    this.inFlight.clear();
    this.stats = { cacheHits: 0, networkFetches: 0, coldFetchDurationsMs: [] };
  }

  destroy() {
    this.agent.destroy();
  }

  async resolveKey(rawAgentUrl, keyid) {
    const identifier = normalizeSignatureAgentIdentifier(rawAgentUrl);
    const parsedUrl = new URL(rawAgentUrl);

    if (!this.allowLoopbackForLocalStudy && isRestrictedHostOrIp(parsedUrl.hostname)) {
      return { status: 'ssrf_blocked', identifier, publicKey: null };
    }

    if (!this.allowRfcTestKeys && KNOWN_TEST_KEY_THUMBPRINTS.has(keyid)) {
      return { status: 'test_key_rejected', identifier, publicKey: null };
    }

    const nowMs = this.nowFn();
    const cached = this.cache.get(identifier);
    if (cached && cached.expiresAtMs > nowMs) {
      this.stats.cacheHits += 1;
      const keyObj = cached.keysByKid.get(keyid) ?? null;
      return {
        status: keyObj ? 'ok' : 'key_not_found',
        identifier,
        publicKey: keyObj,
        fromCache: true
      };
    }

    let fetchPromise = this.inFlight.get(identifier);
    if (!fetchPromise) {
      fetchPromise = this.#fetchDirectory(parsedUrl, identifier).finally(() => {
        this.inFlight.delete(identifier);
      });
      this.inFlight.set(identifier, fetchPromise);
    }

    try {
      const keysByKid = await fetchPromise;
      const keyObj = keysByKid.get(keyid) ?? null;
      return {
        status: keyObj ? 'ok' : 'key_not_found',
        identifier,
        publicKey: keyObj,
        fromCache: false
      };
    } catch {
      // Section 6.10: transient fetch failure MUST NOT evict an existing cached entry.
      if (cached) {
        const staleKey = cached.keysByKid.get(keyid) ?? null;
        if (staleKey) {
          return { status: 'ok', identifier, publicKey: staleKey, fromCache: true };
        }
      }
      return { status: 'discovery_failed', identifier, publicKey: null };
    }
  }

  async #fetchDirectory(parsedUrl, identifier) {
    const startNs = process.hrtime.bigint();
    this.stats.networkFetches += 1;

    const { statusCode, headers, bodyBuffer } = await new Promise((resolve, reject) => {
      const req = https.request(
        parsedUrl,
        {
          method: 'GET',
          agent: this.agent,
          headers: { Accept: `${DIRECTORY_MEDIA_TYPE}, application/json` },
          timeout: this.timeoutMs
        },
        (res) => {
          // Section 5.5: MUST be 200 OK; MUST NOT follow redirects.
          if (res.statusCode !== 200) {
            res.resume();
            reject(new Error(`Directory returned non-200 status ${res.statusCode}`));
            return;
          }
          const chunks = [];
          let totalBytes = 0;
          res.on('data', (chunk) => {
            totalBytes += chunk.length;
            if (totalBytes > this.maxBytes) {
              req.destroy(new Error('Directory response exceeded maxBytes limit'));
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', () => {
            resolve({
              statusCode: res.statusCode,
              headers: res.headers,
              bodyBuffer: Buffer.concat(chunks)
            });
          });
          res.on('error', reject);
        }
      );
      req.on('timeout', () => req.destroy(new Error('Directory fetch timed out')));
      req.on('error', reject);
      req.end();
    });

    if (statusCode !== 200) {
      throw new Error(`Unexpected status ${statusCode}`);
    }

    const durationMs = Number(process.hrtime.bigint() - startNs) / 1e6;
    this.stats.coldFetchDurationsMs.push(durationMs);

    const jwks = JSON.parse(bodyBuffer.toString('utf8'));
    if (!jwks || !Array.isArray(jwks.keys)) {
      throw new Error('Malformed JWKS directory payload');
    }
    if (jwks.keys.length > this.maxKeys) {
      throw new Error(`JWKS key count ${jwks.keys.length} exceeds maxKeys ${this.maxKeys}`);
    }

    const isWellKnown = parsedUrl.pathname === DIRECTORY_WELL_KNOWN_PATH;
    const keysByKid = new Map();
    const nowSec = Math.floor(this.nowFn() / 1000);

    for (const jwk of jwks.keys) {
      if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
        continue;
      }
      if (typeof jwk.nbf === 'number' && nowSec < jwk.nbf) continue;
      if (typeof jwk.exp === 'number' && nowSec >= jwk.exp) continue;

      const thumbprint = computeEd25519JwkThumbprint(jwk);
      if (!this.allowRfcTestKeys && KNOWN_TEST_KEY_THUMBPRINTS.has(thumbprint)) {
        continue;
      }
      // Section 5.5: at well-known URI, if kid is present it MUST equal the thumbprint.
      if (isWellKnown && jwk.kid !== undefined && jwk.kid !== thumbprint) {
        throw new Error('Well-known directory JWK kid does not match RFC 7638 thumbprint');
      }
      const lookupKid = jwk.kid ?? thumbprint;
      const keyObj = crypto.createPublicKey({
        key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x },
        format: 'jwk'
      });
      keysByKid.set(lookupKid, keyObj);
      keysByKid.set(thumbprint, keyObj);
    }

    const ttlSec = parseMaxAgeSeconds(headers['cache-control'], this.defaultTtlSec);
    // Section 6.10: valid 200 directory replaces cached entry for this URL (even if a key was removed).
    this.cache.set(identifier, {
      expiresAtMs: this.nowFn() + ttlSec * 1000,
      keysByKid
    });

    return keysByKid;
  }
}
