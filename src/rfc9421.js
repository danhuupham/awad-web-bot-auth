import crypto from 'node:crypto';
import {
  parseSignatureAgentHeader,
  parseSignatureHeader,
  parseSignatureInputHeader,
  serializeComponentIdentifier,
  serializeSfString,
  serializeSignatureParamsValue
} from './structured-fields.js';

/**
 * RFC 9421 Appendix B.1.4 example Ed25519 key thumbprint.
 * Rejected by default in verifiers per draft-ietf-webbotauth-httpsig-protocol-01 Section 6.8.
 */
export const KNOWN_TEST_KEY_THUMBPRINTS = new Set(['poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U']);

/**
 * Computes RFC 7638 / RFC 8037 Appendix A.3 base64url JWK SHA-256 Thumbprint for Ed25519 OKP keys.
 */
export function computeEd25519JwkThumbprint(jwk) {
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
    throw new TypeError('Expected an Ed25519 OKP JWK with kty="OKP", crv="Ed25519", and string x');
  }
  const canonicalJson = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x
  });
  return crypto.createHash('sha256').update(canonicalJson, 'utf8').digest('base64url');
}

export function generateBotKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicJwk = publicKey.export({ format: 'jwk' });
  const privateJwk = privateKey.export({ format: 'jwk' });
  const kid = computeEd25519JwkThumbprint(publicJwk);
  return {
    kid,
    publicKey,
    privateKey,
    publicJwk: {
      kty: 'OKP',
      crv: 'Ed25519',
      kid,
      x: publicJwk.x,
      use: 'sig'
    },
    privateJwk
  };
}

function getHeaderValue(headers, lowerName) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') {
    const v = headers.get(lowerName);
    return v === null ? undefined : v;
  }
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lowerName) {
      return Array.isArray(v) ? v.join(', ') : v;
    }
  }
  return undefined;
}

function canonicalizeHeaderFieldValue(raw) {
  return String(raw).trim().replace(/\s+/g, ' ');
}

function resolveDerivedComponent(name, msg) {
  switch (name) {
    case '@method':
      if (!msg.method) throw new Error('Missing method for @method component');
      return msg.method.toUpperCase();
    case '@authority': {
      const auth = msg.authority ?? getHeaderValue(msg.headers, 'host');
      if (!auth) throw new Error('Missing authority/Host for @authority component');
      return String(auth).toLowerCase();
    }
    case '@scheme':
      return (msg.scheme ?? 'https').toLowerCase();
    case '@target-uri': {
      const scheme = (msg.scheme ?? 'https').toLowerCase();
      const auth = (msg.authority ?? getHeaderValue(msg.headers, 'host') ?? '').toLowerCase();
      const pathAndQuery = msg.url ?? '/';
      return `${scheme}://${auth}${pathAndQuery}`;
    }
    case '@path': {
      const rawUrl = msg.url ?? '/';
      const qIdx = rawUrl.indexOf('?');
      const pathPart = qIdx === -1 ? rawUrl : rawUrl.slice(0, qIdx);
      return pathPart || '/';
    }
    case '@query': {
      const rawUrl = msg.url ?? '/';
      const qIdx = rawUrl.indexOf('?');
      return qIdx === -1 ? '?' : rawUrl.slice(qIdx);
    }
    case '@status':
      if (msg.status === undefined) throw new Error('Missing status for @status component');
      return String(msg.status);
    default:
      throw new Error(`Unsupported derived component "${name}"`);
  }
}

function resolveComponentValue(comp, message) {
  const params = comp.params ?? [];
  const hasReqParam = params.some((p) => p.key === 'req' && p.value === true);
  const keyParam = params.find((p) => p.key === 'key');

  const targetMsg = hasReqParam ? message.request : message;
  if (!targetMsg) {
    throw new Error(`Component "${comp.name}";req requires associated request context`);
  }

  if (comp.name.startsWith('@')) {
    if (keyParam) {
      throw new Error(`Derived component "${comp.name}" cannot carry ;key parameter`);
    }
    return resolveDerivedComponent(comp.name, targetMsg);
  }

  const rawHeader = getHeaderValue(targetMsg.headers, comp.name);
  if (rawHeader === undefined) {
    throw new Error(`Missing covered HTTP header "${comp.name}"`);
  }

  if (keyParam) {
    if (comp.name === 'signature-agent') {
      const parsed = parseSignatureAgentHeader(rawHeader, { allowLegacyString: false });
      const memberVal = parsed.members.get(keyParam.value);
      if (memberVal === undefined) {
        throw new Error(`Signature-Agent dictionary has no valid member "${keyParam.value}"`);
      }
      return serializeSfString(memberVal);
    }
    throw new Error(`Dictionary ;key lookup not supported for header "${comp.name}"`);
  }

  return canonicalizeHeaderFieldValue(rawHeader);
}

/**
 * Constructs the canonical RFC 9421 Section 2.5 signature base string.
 */
export function buildSignatureBase({ message, components, serializedParams }) {
  const seenIds = new Set();
  const lines = [];

  for (const comp of components) {
    const compId = serializeComponentIdentifier(comp);
    if (seenIds.has(compId)) {
      throw new Error(`Duplicate component identifier ${compId} in Signature-Input`);
    }
    seenIds.add(compId);
    const compValue = resolveComponentValue(comp, message);
    lines.push(`${compId}: ${compValue}`);
  }

  lines.push(`"@signature-params": ${serializedParams}`);
  return lines.join('\n');
}

/**
 * Signs an outbound HTTP request per RFC 9421 + draft-ietf-webbotauth-httpsig-protocol-01 Section 5.2.
 */
export function signBotRequest({
  method = 'GET',
  scheme = 'https',
  authority,
  url = '/',
  headers = {},
  privateKey,
  keyid,
  agentDirectoryUrl,
  label = 'sig1',
  created = Math.floor(Date.now() / 1000),
  expires = created + 300,
  nonce = crypto.randomBytes(16).toString('base64url'),
  tag = 'web-bot-auth',
  includeAlg = false,
  coverMethodPathQuery = true
}) {
  const signatureAgentHeader = `${label}=${serializeSfString(agentDirectoryUrl)}`;
  const mergedHeaders = {
    ...headers,
    host: authority,
    'signature-agent': signatureAgentHeader
  };

  const components = coverMethodPathQuery
    ? [
        { name: '@method', params: [] },
        { name: '@authority', params: [] },
        { name: '@path', params: [] },
        { name: '@query', params: [] },
        { name: 'signature-agent', params: [{ key: 'key', value: label, type: 'string' }] }
      ]
    : [
        { name: '@authority', params: [] },
        { name: 'signature-agent', params: [{ key: 'key', value: label, type: 'string' }] }
      ];

  const signatureParams = [
    { key: 'created', value: created, type: 'integer' },
    { key: 'expires', value: expires, type: 'integer' },
    { key: 'keyid', value: keyid, type: 'string' }
  ];
  if (includeAlg) {
    signatureParams.push({ key: 'alg', value: 'ed25519', type: 'string' });
  }
  if (nonce !== null && nonce !== undefined) {
    signatureParams.push({ key: 'nonce', value: nonce, type: 'string' });
  }
  signatureParams.push({ key: 'tag', value: tag, type: 'string' });

  const serializedParams = serializeSignatureParamsValue(components, signatureParams);
  const signatureBase = buildSignatureBase({
    message: { method, scheme, authority, url, headers: mergedHeaders },
    components,
    serializedParams
  });

  const sigBytes = crypto.sign(null, Buffer.from(signatureBase, 'utf8'), privateKey);
  const signatureInputHeader = `${label}=${serializedParams}`;
  const signatureHeader = `${label}=:${sigBytes.toString('base64')}:`;

  return {
    headers: {
      ...headers,
      'Signature-Agent': signatureAgentHeader,
      'Signature-Input': signatureInputHeader,
      Signature: signatureHeader
    },
    signatureBase,
    signatureBytes: sigBytes
  };
}

/**
 * Low-level RFC 9421 cryptographic verifier given parsed headers and a resolved Ed25519 KeyObject.
 */
export function verifySignatureBaseWithKey({ message, entry, signatureBytes, publicKey }) {
  const signatureBase = buildSignatureBase({
    message,
    components: entry.components,
    serializedParams: entry.serializedParams
  });
  const ok = crypto.verify(null, Buffer.from(signatureBase, 'utf8'), publicKey, signatureBytes);
  return { ok, signatureBase };
}

export { parseSignatureAgentHeader, parseSignatureHeader, parseSignatureInputHeader };
