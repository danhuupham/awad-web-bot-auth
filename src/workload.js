import { signBotRequest } from './rfc9421.js';

function createMulberry32(seed) {
  let state = seed >>> 0;
  return function nextRandom() {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function deterministicShuffle(items, rng) {
  const arr = [...items];
  for (let i = arr.length - 1; i > 0; i -= 1) {
    const j = Math.floor(rng() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function deterministicNonce(rng, index, prefix) {
  const hex = Array.from({ length: 16 }, () =>
    Math.floor(rng() * 256)
      .toString(16)
      .padStart(2, '0')
  ).join('');
  return `${prefix}-${index}-${hex}`;
}

function headerWireBytes(headers) {
  let total = 0;
  for (const [k, v] of Object.entries(headers)) {
    total += Buffer.byteLength(`${k}: ${v}\r\n`, 'utf8');
  }
  return total;
}

/**
 * Generates the deterministic 1,000-request mixed workload:
 * - 300 legit_human: browser User-Agent from public client IPs (192.0.2.x)
 * - 300 legit_signed_bot: ResearchCrawler/1.0 from shared cloud CIDR (203.0.113.x) with valid Ed25519 signature
 * - 400 spoofed_bot (5 realistic attack classes x 80 requests):
 *     1. spoof_external_ip_ua (80): forged bot UA from unlisted IP 198.51.100.x, unsigned
 *     2. spoof_shared_cloud_ip_ua (80): forged bot UA from co-hosted cloud IP 203.0.113.x, unsigned
 *     3. forged_rogue_directory_sig (80): signed with attacker's own Ed25519 key & rogue directory on 203.0.113.x
 *     4. tampered_target_path_sig (80): valid bot signature over /articles/public-teaser replayed onto /articles/premium-feed
 *     5. expired_or_replayed_sig (80): 40 expired timestamps + 40 replayed nonces captured from earlier valid bot requests
 */
export function generateMixedWorkload({
  seed = 20261118,
  originAuthority,
  trustedBotKeyPair,
  trustedDirectoryUrl,
  rogueBotKeyPair,
  rogueDirectoryUrl,
  nowSec = Math.floor(Date.now() / 1000)
}) {
  const rng = createMulberry32(seed);
  const baseItems = [];
  const validSignedPool = [];

  const botUa = 'Mozilla/5.0 (compatible; ResearchCrawler/1.0; +https://crawler.example/bot)';
  const humanUas = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 Version/18.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0'
  ];

  // 1) 300 normal human browser requests
  for (let i = 0; i < 300; i += 1) {
    const ipHost = (i % 250) + 1;
    const ua = humanUas[i % humanUas.length];
    const url = `/articles/post-${(i % 50) + 1}?page=${(i % 5) + 1}`;
    const headers = {
      'User-Agent': ua,
      Accept: 'application/json',
      'X-Simulated-Client-IP': `192.0.2.${ipHost}`
    };
    baseItems.push({
      kind: 'legit_human',
      attackSubkind: null,
      expectedAllowed: true,
      expectedBotVerified: false,
      method: 'GET',
      url,
      headers,
      sigHeaderBytes: 0
    });
  }

  // 2) 300 valid signed bot requests
  for (let i = 0; i < 300; i += 1) {
    const ipHost = (i % 200) + 10;
    const url = `/articles/research-${(i % 60) + 1}?format=summary`;
    const baseHeaders = {
      'User-Agent': botUa,
      Accept: 'application/json',
      'X-Simulated-Client-IP': `203.0.113.${ipHost}`
    };
    const nonce = deterministicNonce(rng, i, 'legit');
    const signed = signBotRequest({
      method: 'GET',
      scheme: 'https',
      authority: originAuthority,
      url,
      headers: baseHeaders,
      privateKey: trustedBotKeyPair.privateKey,
      keyid: trustedBotKeyPair.kid,
      agentDirectoryUrl: trustedDirectoryUrl,
      label: 'sig1',
      created: nowSec - 5,
      expires: nowSec + 300,
      nonce
    });
    const sigOnlyHeaders = {
      'Signature-Agent': signed.headers['Signature-Agent'],
      'Signature-Input': signed.headers['Signature-Input'],
      Signature: signed.headers.Signature
    };
    const item = {
      kind: 'legit_signed_bot',
      attackSubkind: null,
      expectedAllowed: true,
      expectedBotVerified: true,
      method: 'GET',
      url,
      headers: signed.headers,
      sigHeaderBytes: headerWireBytes(sigOnlyHeaders)
    };
    baseItems.push(item);
    validSignedPool.push(item);
  }

  // 3a) 80 spoof_external_ip_ua (unsigned bot UA from unlisted IP 198.51.100.x)
  for (let i = 0; i < 80; i += 1) {
    baseItems.push({
      kind: 'spoofed_bot',
      attackSubkind: 'spoof_external_ip_ua',
      expectedAllowed: false,
      expectedBotVerified: false,
      method: 'GET',
      url: `/articles/scrape-${i + 1}?format=full`,
      headers: {
        'User-Agent': botUa,
        Accept: 'application/json',
        'X-Simulated-Client-IP': `198.51.100.${(i % 200) + 10}`
      },
      sigHeaderBytes: 0
    });
  }

  // 3b) 80 spoof_shared_cloud_ip_ua (unsigned bot UA from co-hosted cloud IP 203.0.113.x)
  for (let i = 0; i < 80; i += 1) {
    baseItems.push({
      kind: 'spoofed_bot',
      attackSubkind: 'spoof_shared_cloud_ip_ua',
      expectedAllowed: false,
      expectedBotVerified: false,
      method: 'GET',
      url: `/articles/cloud-scrape-${i + 1}?format=full`,
      headers: {
        'User-Agent': botUa,
        Accept: 'application/json',
        'X-Simulated-Client-IP': `203.0.113.${(i % 200) + 20}`
      },
      sigHeaderBytes: 0
    });
  }

  // 3c) 80 forged_rogue_directory_sig (signed with attacker's own key & untrusted directory on 203.0.113.x)
  for (let i = 0; i < 80; i += 1) {
    const url = `/articles/rogue-${i + 1}?format=full`;
    const baseHeaders = {
      'User-Agent': botUa,
      Accept: 'application/json',
      'X-Simulated-Client-IP': `203.0.113.${(i % 200) + 30}`
    };
    const signed = signBotRequest({
      method: 'GET',
      scheme: 'https',
      authority: originAuthority,
      url,
      headers: baseHeaders,
      privateKey: rogueBotKeyPair.privateKey,
      keyid: rogueBotKeyPair.kid,
      agentDirectoryUrl: rogueDirectoryUrl,
      label: 'sig1',
      created: nowSec - 5,
      expires: nowSec + 300,
      nonce: deterministicNonce(rng, i, 'rogue')
    });
    baseItems.push({
      kind: 'spoofed_bot',
      attackSubkind: 'forged_rogue_directory_sig',
      expectedAllowed: false,
      expectedBotVerified: false,
      method: 'GET',
      url,
      headers: signed.headers,
      sigHeaderBytes: 0
    });
  }

  // 3d) 80 tampered_target_path_sig (valid signature signed for /public-teaser replayed onto /premium-feed)
  for (let i = 0; i < 80; i += 1) {
    const signedUrl = `/articles/public-teaser-${i + 1}?tier=free`;
    const tamperedUrl = `/articles/premium-feed-${i + 1}?tier=full`;
    const baseHeaders = {
      'User-Agent': botUa,
      Accept: 'application/json',
      'X-Simulated-Client-IP': `203.0.113.${(i % 200) + 40}`
    };
    const signed = signBotRequest({
      method: 'GET',
      scheme: 'https',
      authority: originAuthority,
      url: signedUrl,
      headers: baseHeaders,
      privateKey: trustedBotKeyPair.privateKey,
      keyid: trustedBotKeyPair.kid,
      agentDirectoryUrl: trustedDirectoryUrl,
      label: 'sig1',
      created: nowSec - 5,
      expires: nowSec + 300,
      nonce: deterministicNonce(rng, i, 'tamper')
    });
    baseItems.push({
      kind: 'spoofed_bot',
      attackSubkind: 'tampered_target_path_sig',
      expectedAllowed: false,
      expectedBotVerified: false,
      method: 'GET',
      url: tamperedUrl,
      headers: signed.headers,
      sigHeaderBytes: 0
    });
  }

  // 3e-part1) 40 expired signatures on shared cloud IP
  for (let i = 0; i < 40; i += 1) {
    const url = `/articles/expired-${i + 1}?format=summary`;
    const baseHeaders = {
      'User-Agent': botUa,
      Accept: 'application/json',
      'X-Simulated-Client-IP': `203.0.113.${(i % 200) + 50}`
    };
    const signed = signBotRequest({
      method: 'GET',
      scheme: 'https',
      authority: originAuthority,
      url,
      headers: baseHeaders,
      privateKey: trustedBotKeyPair.privateKey,
      keyid: trustedBotKeyPair.kid,
      agentDirectoryUrl: trustedDirectoryUrl,
      label: 'sig1',
      created: nowSec - 900,
      expires: nowSec - 120,
      nonce: deterministicNonce(rng, i, 'expired')
    });
    baseItems.push({
      kind: 'spoofed_bot',
      attackSubkind: 'expired_or_replayed_sig',
      expectedAllowed: false,
      expectedBotVerified: false,
      method: 'GET',
      url,
      headers: signed.headers,
      sigHeaderBytes: 0
    });
  }

  // Shuffle the first 960 items deterministically, then place the 40 nonce-replay attacks
  // in the tail half copying early legit_signed_bot requests (at least 100 slots earlier)
  // so that under concurrency=16 the original request is guaranteed to land first.
  const first960 = deterministicShuffle(baseItems, rng);
  const earlyLegitBots = [];
  for (let idx = 0; idx < first960.length && earlyLegitBots.length < 40; idx += 1) {
    if (first960[idx].kind === 'legit_signed_bot' && idx < 450) {
      earlyLegitBots.push(first960[idx]);
    }
  }
  while (earlyLegitBots.length < 40) {
    earlyLegitBots.push(validSignedPool[earlyLegitBots.length]);
  }

  const replayItems = earlyLegitBots.map((orig, idx) => ({
    kind: 'spoofed_bot',
    attackSubkind: 'expired_or_replayed_sig',
    expectedAllowed: false,
    expectedBotVerified: false,
    method: orig.method,
    url: orig.url,
    headers: {
      ...orig.headers,
      'X-Simulated-Client-IP': `203.0.113.${(idx % 180) + 60}`
    },
    sigHeaderBytes: 0
  }));

  // Interleave the 40 replay items deterministically across indices 600..999
  const head = first960.slice(0, 600);
  const tail = deterministicShuffle([...first960.slice(600), ...replayItems], rng);
  return [...head, ...tail].map((item, idx) => ({ ...item, id: idx + 1 }));
}
