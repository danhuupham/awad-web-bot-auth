import { normalizeSignatureAgentIdentifier } from './directory.js';
import {
  parseSignatureAgentHeader,
  parseSignatureHeader,
  parseSignatureInputHeader,
  verifySignatureBaseWithKey
} from './rfc9421.js';

const ACCEPT_SIGNATURE_CHALLENGE =
  'sig1=("@method" "@authority" "@path" "@query" "signature-agent";key="sig1");tag="web-bot-auth"';

/**
 * Change Bot Verifier: verifies RFC 9421 Ed25519 HTTP Message Signatures +
 * draft-ietf-webbotauth-httpsig-protocol-01 key discovery, (URL, keyid) binding,
 * covered request components, validity window, and bounded nonce replay cache.
 */
export function createWebBotAuthVerifier({
  directoryResolver,
  protectedBotUaTokens = ['ResearchCrawler/'],
  trustedDirectoryUrls = null,
  requireRequestTargetCoverage = true,
  requireNonce = true,
  maxValidityWindowSec = 3600,
  maxClockSkewSec = 30,
  maxNonceEntries = 20000,
  nowSecFn = () => Math.floor(Date.now() / 1000)
}) {
  const uaTokensLower = protectedBotUaTokens.map((t) => t.toLowerCase());
  const trustedSet = trustedDirectoryUrls
    ? new Set(trustedDirectoryUrls.map((u) => normalizeSignatureAgentIdentifier(u)))
    : null;

  // Map<replayKey, expiresEpochSec>
  const seenNonces = new Map();

  function pruneAndRecordNonce(replayKey, expiresSec, nowSec) {
    const existingExp = seenNonces.get(replayKey);
    if (existingExp !== undefined && existingExp >= nowSec) {
      return false;
    }
    if (seenNonces.size >= maxNonceEntries) {
      for (const [k, exp] of seenNonces) {
        if (exp < nowSec || seenNonces.size >= maxNonceEntries) {
          seenNonces.delete(k);
        }
        if (seenNonces.size < maxNonceEntries * 0.8) break;
      }
    }
    seenNonces.set(replayKey, expiresSec);
    return true;
  }

  return {
    name: 'web-bot-auth-rfc9421',
    resetState() {
      seenNonces.clear();
      directoryResolver.clearCache();
    },
    async verifyRequest(req) {
      const ua = String(req.headers['user-agent'] ?? '');
      const uaLower = ua.toLowerCase();
      const claimsProtectedBotUa = uaTokensLower.some((tok) => uaLower.includes(tok));

      const rawSig = req.headers.signature;
      const rawSigInput = req.headers['signature-input'];
      const rawSigAgent = req.headers['signature-agent'];
      const hasAnySigHeader = Boolean(rawSig || rawSigInput || rawSigAgent);

      if (!claimsProtectedBotUa && !hasAnySigHeader) {
        return {
          allowed: true,
          statusCode: 200,
          category: 'human',
          botVerified: false,
          reason: 'unsigned_human_traffic',
          headers: {}
        };
      }

      // Section 5.3: refuse unsigned bot-claiming requests with 403 + Accept-Signature.
      if (!rawSig || !rawSigInput || !rawSigAgent) {
        return {
          allowed: false,
          statusCode: 403,
          category: 'rejected_bot',
          botVerified: false,
          reason: 'missing_signature_headers',
          headers: { 'Accept-Signature': ACCEPT_SIGNATURE_CHALLENGE }
        };
      }

      let sigMap;
      let sigInputMap;
      let sigAgentParsed;
      try {
        sigMap = parseSignatureHeader(String(rawSig));
        sigInputMap = parseSignatureInputHeader(String(rawSigInput));
        sigAgentParsed = parseSignatureAgentHeader(String(rawSigAgent), {
          allowLegacyString: false
        });
      } catch {
        // Section 5.4 step 1-3: malformed signature headers -> 400 Bad Request.
        return {
          allowed: false,
          statusCode: 400,
          category: 'rejected_bot',
          botVerified: false,
          reason: 'malformed_signature_headers',
          headers: { 'Accept-Signature': ACCEPT_SIGNATURE_CHALLENGE }
        };
      }

      const nowSec = nowSecFn();
      let candidateFound = false;

      for (const [label, entry] of sigInputMap.entries()) {
        if (entry.params.tag !== 'web-bot-auth') continue;
        candidateFound = true;

        const sigBytes = sigMap.get(label);
        if (!sigBytes) {
          return {
            allowed: false,
            statusCode: 400,
            category: 'rejected_bot',
            botVerified: false,
            reason: 'missing_signature_for_label',
            headers: { 'Accept-Signature': ACCEPT_SIGNATURE_CHALLENGE }
          };
        }

        const { created, expires, keyid, nonce, alg } = entry.params;
        if (
          typeof created !== 'number' ||
          typeof expires !== 'number' ||
          typeof keyid !== 'string' ||
          keyid.length === 0
        ) {
          return {
            allowed: false,
            statusCode: 403,
            category: 'rejected_bot',
            botVerified: false,
            reason: 'missing_required_signature_params',
            headers: { 'Accept-Signature': ACCEPT_SIGNATURE_CHALLENGE }
          };
        }

        if (alg !== undefined && alg !== 'ed25519') {
          return {
            allowed: false,
            statusCode: 403,
            category: 'rejected_bot',
            botVerified: false,
            reason: 'unsupported_algorithm',
            headers: { 'Accept-Signature': ACCEPT_SIGNATURE_CHALLENGE }
          };
        }

        if (
          created > nowSec + maxClockSkewSec ||
          expires <= nowSec ||
          expires < created ||
          expires - created > maxValidityWindowSec
        ) {
          return {
            allowed: false,
            statusCode: 403,
            category: 'rejected_bot',
            botVerified: false,
            reason: 'expired_or_invalid_window',
            headers: { 'Accept-Signature': ACCEPT_SIGNATURE_CHALLENGE }
          };
        }

        // Section 5.2 & 5.2.1: must cover @authority (or @target-uri) and "signature-agent";key="<label>"
        const compNames = new Set(entry.components.map((c) => c.name));
        const coversAuthorityOrUri =
          compNames.has('@authority') || compNames.has('@target-uri');
        const coversAgentMember = entry.components.some(
          (c) =>
            c.name === 'signature-agent' &&
            c.params.some((p) => p.key === 'key' && p.value === label)
        );
        if (!coversAuthorityOrUri || !coversAgentMember) {
          return {
            allowed: false,
            statusCode: 403,
            category: 'rejected_bot',
            botVerified: false,
            reason: 'insufficient_mandatory_components',
            headers: { 'Accept-Signature': ACCEPT_SIGNATURE_CHALLENGE }
          };
        }

        if (requireRequestTargetCoverage) {
          const coversTarget =
            compNames.has('@target-uri') ||
            (compNames.has('@method') && compNames.has('@path') && compNames.has('@query'));
          if (!coversTarget) {
            return {
              allowed: false,
              statusCode: 403,
              category: 'rejected_bot',
              botVerified: false,
              reason: 'narrow_target_components_missing',
              headers: { 'Accept-Signature': ACCEPT_SIGNATURE_CHALLENGE }
            };
          }
        }

        if (requireNonce && (typeof nonce !== 'string' || nonce.length < 8)) {
          return {
            allowed: false,
            statusCode: 403,
            category: 'rejected_bot',
            botVerified: false,
            reason: 'missing_nonce',
            headers: { 'Accept-Signature': ACCEPT_SIGNATURE_CHALLENGE }
          };
        }

        const rawAgentUrl = sigAgentParsed.members.get(label);
        if (!rawAgentUrl) {
          return {
            allowed: false,
            statusCode: 403,
            category: 'rejected_bot',
            botVerified: false,
            reason: 'missing_signature_agent_member',
            headers: { 'Accept-Signature': ACCEPT_SIGNATURE_CHALLENGE }
          };
        }

        let normalizedAgentUrl;
        try {
          normalizedAgentUrl = normalizeSignatureAgentIdentifier(rawAgentUrl);
        } catch {
          return {
            allowed: false,
            statusCode: 400,
            category: 'rejected_bot',
            botVerified: false,
            reason: 'invalid_signature_agent_uri',
            headers: { 'Accept-Signature': ACCEPT_SIGNATURE_CHALLENGE }
          };
        }

        if (trustedSet && !trustedSet.has(normalizedAgentUrl)) {
          return {
            allowed: false,
            statusCode: 403,
            category: 'rejected_bot',
            botVerified: false,
            reason: 'untrusted_signature_agent_directory',
            headers: { 'Accept-Signature': ACCEPT_SIGNATURE_CHALLENGE }
          };
        }

        const resolved = await directoryResolver.resolveKey(rawAgentUrl, keyid);
        if (resolved.status !== 'ok' || !resolved.publicKey) {
          return {
            allowed: false,
            statusCode: 403,
            category: 'rejected_bot',
            botVerified: false,
            reason: `key_resolution_${resolved.status}`,
            headers: { 'Accept-Signature': ACCEPT_SIGNATURE_CHALLENGE }
          };
        }

        let verified = false;
        try {
          const check = verifySignatureBaseWithKey({
            message: {
              method: req.method,
              scheme: 'https',
              authority: req.headers.host,
              url: req.url,
              headers: req.headers
            },
            entry,
            signatureBytes: sigBytes,
            publicKey: resolved.publicKey
          });
          verified = check.ok;
        } catch {
          verified = false;
        }

        if (!verified) {
          return {
            allowed: false,
            statusCode: 403,
            category: 'rejected_bot',
            botVerified: false,
            reason: 'invalid_cryptographic_signature',
            headers: { 'Accept-Signature': ACCEPT_SIGNATURE_CHALLENGE }
          };
        }

        if (requireNonce) {
          const replayKey = `${normalizedAgentUrl}|${keyid}|${nonce}`;
          if (!pruneAndRecordNonce(replayKey, expires, nowSec)) {
            // Section 5.3: replay detected -> 429 Too Many Requests + Accept-Signature.
            return {
              allowed: false,
              statusCode: 429,
              category: 'rejected_bot',
              botVerified: false,
              reason: 'replayed_nonce',
              headers: { 'Accept-Signature': ACCEPT_SIGNATURE_CHALLENGE }
            };
          }
        }

        return {
          allowed: true,
          statusCode: 200,
          category: 'verified_bot',
          botVerified: true,
          operator: normalizedAgentUrl,
          reason: 'verified_rfc9421_signature',
          headers: {}
        };
      }

      return {
        allowed: false,
        statusCode: 403,
        category: 'rejected_bot',
        botVerified: false,
        reason: candidateFound ? 'verification_failed' : 'missing_web_bot_auth_tag',
        headers: { 'Accept-Signature': ACCEPT_SIGNATURE_CHALLENGE }
      };
    }
  };
}
