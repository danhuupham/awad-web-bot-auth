function ipv4ToUint32(ip) {
  const parts = String(ip).trim().split('.');
  if (parts.length !== 4) return null;
  let num = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const octet = Number.parseInt(part, 10);
    if (octet < 0 || octet > 255) return null;
    num = ((num << 8) | octet) >>> 0;
  }
  return num;
}

function parseCidrList(cidrs) {
  return cidrs.map((cidr) => {
    const [baseIp, prefixStr] = cidr.split('/');
    const base = ipv4ToUint32(baseIp);
    const prefix = Number.parseInt(prefixStr, 10);
    if (base === null || Number.isNaN(prefix) || prefix < 0 || prefix > 32) {
      throw new Error(`Invalid IPv4 CIDR "${cidr}"`);
    }
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    return { network: (base & mask) >>> 0, mask };
  });
}

/**
 * Baseline Bot Verifier: checks User-Agent substring + published IPv4 CIDR allowlist.
 * Represents conventional pre-RFC-9421 bot verification at an origin server.
 */
export function createBaselineIpUaVerifier({
  botRules = [
    {
      botName: 'ResearchCrawler',
      uaToken: 'ResearchCrawler/',
      allowedCidrs: ['203.0.113.0/24']
    }
  ]
} = {}) {
  const compiledRules = botRules.map((rule) => ({
    botName: rule.botName,
    uaTokenLower: rule.uaToken.toLowerCase(),
    ranges: parseCidrList(rule.allowedCidrs)
  }));

  return {
    name: 'baseline-ip-ua',
    resetState() {
      // Stateless IP + User-Agent allowlist check.
    },
    async verifyRequest(req) {
      const ua = String(req.headers['user-agent'] ?? '');
      const uaLower = ua.toLowerCase();
      const matchedRule = compiledRules.find((r) => uaLower.includes(r.uaTokenLower));

      if (!matchedRule) {
        return {
          allowed: true,
          statusCode: 200,
          category: 'human',
          botVerified: false,
          reason: 'non_bot_user_agent',
          headers: {}
        };
      }

      const clientIp = String(
        req.headers['x-simulated-client-ip'] ?? req.socket?.remoteAddress ?? '127.0.0.1'
      );
      const ipUint = ipv4ToUint32(clientIp);
      const inRange =
        ipUint !== null &&
        matchedRule.ranges.some((range) => ((ipUint & range.mask) >>> 0) === range.network);

      if (!inRange) {
        return {
          allowed: false,
          statusCode: 403,
          category: 'rejected_bot',
          botVerified: false,
          reason: 'ip_not_in_allowlist',
          headers: {}
        };
      }

      return {
        allowed: true,
        statusCode: 200,
        category: 'verified_bot',
        botVerified: true,
        operator: matchedRule.botName,
        reason: 'ua_and_ip_matched',
        headers: {}
      };
    }
  };
}
