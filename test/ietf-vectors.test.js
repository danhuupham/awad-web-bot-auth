import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { signDirectoryResponse } from '../src/directory.js';
import {
  buildSignatureBase,
  computeEd25519JwkThumbprint,
  parseSignatureAgentHeader,
  parseSignatureHeader,
  parseSignatureInputHeader,
  verifySignatureBaseWithKey
} from '../src/rfc9421.js';

// Official RFC 9421 Appendix B.1.4 Example Ed25519 Test Key
const RFC9421_ED25519_JWK = {
  kty: 'OKP',
  crv: 'Ed25519',
  d: 'n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU',
  x: 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs'
};

test('RFC 7638 / RFC 8037 Appendix A.3 JWK thumbprint matches IETF Appendix E.2 keyid', () => {
  const thumbprint = computeEd25519JwkThumbprint(RFC9421_ED25519_JWK);
  assert.equal(thumbprint, 'poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U');
});

test('draft-ietf-webbotauth-httpsig-protocol-01 Appendix E.2.1 vector (Dictionary Signature-Agent)', () => {
  const rawSigAgent = 'sig2="https://signature-agent.test"';
  const rawSigInput =
    'sig2=("@authority" "signature-agent";key="sig2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth"';
  const rawSig =
    'sig2=:CGokAoY/FrPpyuzTe1Fb2kLTAH9Idw6qSFd1+D77r1firsMRCxeuLu5e6O+ek3zQgDMAzjiXtLVfqE00xnABCQ==:';

  const sigMap = parseSignatureHeader(rawSig);
  const inputMap = parseSignatureInputHeader(rawSigInput);
  const agentParsed = parseSignatureAgentHeader(rawSigAgent, { allowLegacyString: false });

  assert.equal(agentParsed.isLegacyString, false);
  assert.equal(agentParsed.members.get('sig2'), 'https://signature-agent.test');

  const entry = inputMap.get('sig2');
  const publicKey = crypto.createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: RFC9421_ED25519_JWK.x },
    format: 'jwk'
  });
  const privateKey = crypto.createPrivateKey({ key: RFC9421_ED25519_JWK, format: 'jwk' });

  const message = {
    method: 'POST',
    scheme: 'https',
    authority: 'example.com',
    url: '/foo?param=Value&Pet=dog',
    headers: {
      host: 'example.com',
      'signature-agent': rawSigAgent
    }
  };

  const result = verifySignatureBaseWithKey({
    message,
    entry,
    signatureBytes: sigMap.get('sig2'),
    publicKey
  });
  assert.equal(result.ok, true);

  // Also verify signing produces exact byte-for-byte Base64 signature from Appendix E.2.1
  const recomputed = crypto
    .sign(null, Buffer.from(result.signatureBase, 'utf8'), privateKey)
    .toString('base64');
  assert.equal(
    recomputed,
    'CGokAoY/FrPpyuzTe1Fb2kLTAH9Idw6qSFd1+D77r1firsMRCxeuLu5e6O+ek3zQgDMAzjiXtLVfqE00xnABCQ=='
  );
});

test('draft-ietf-webbotauth-httpsig-protocol-01 Appendix E.2.2 vector (Legacy sf-string Signature-Agent)', () => {
  const rawSigAgent = '"https://signature-agent.test"';
  const rawSigInput =
    'sig2=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"';
  const rawSig =
    'sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:';

  const agentParsed = parseSignatureAgentHeader(rawSigAgent, { allowLegacyString: true });
  assert.equal(agentParsed.isLegacyString, true);
  assert.equal(agentParsed.legacyValue, 'https://signature-agent.test');

  const sigMap = parseSignatureHeader(rawSig);
  const entry = parseSignatureInputHeader(rawSigInput).get('sig2');
  const publicKey = crypto.createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: RFC9421_ED25519_JWK.x },
    format: 'jwk'
  });

  const result = verifySignatureBaseWithKey({
    message: {
      authority: 'example.com',
      headers: { host: 'example.com', 'signature-agent': rawSigAgent }
    },
    entry,
    signatureBytes: sigMap.get('sig2'),
    publicKey
  });
  assert.equal(result.ok, true);
});

test('draft-ietf-webbotauth-httpsig-protocol-01 Appendix E.2.3 vector (Signed Directory Response)', () => {
  const body =
    '{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","use":"sig"}]}';
  const privateKey = crypto.createPrivateKey({ key: RFC9421_ED25519_JWK, format: 'jwk' });
  const publicKey = crypto.createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: RFC9421_ED25519_JWK.x },
    format: 'jwk'
  });

  const headers = signDirectoryResponse({
    requestAuthority: 'signature-agent.test',
    bodyString: body,
    signingKeyPair: {
      kid: 'poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U',
      privateKey
    },
    created: 1735689600,
    expires: 4889289600
  });

  assert.equal(headers['Content-Digest'], 'sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:');
  assert.equal(
    headers.Signature,
    'binding=:l6P8R67tm3kujAxbHWio7ll01qrEZ0dKD/WWlGhNYEmTnFZM8Wt0VQ9zqGfvo7T/UMkBxsigzChM1Gpz7gOVBg==:'
  );

  const entry = parseSignatureInputHeader(headers['Signature-Input']).get('binding');
  const sigBytes = parseSignatureHeader(headers.Signature).get('binding');
  const base = buildSignatureBase({
    message: {
      status: 200,
      headers: { 'content-digest': headers['Content-Digest'] },
      request: { authority: 'signature-agent.test', headers: { host: 'signature-agent.test' } }
    },
    components: entry.components,
    serializedParams: entry.serializedParams
  });
  assert.equal(crypto.verify(null, Buffer.from(base, 'utf8'), publicKey, sigBytes), true);
});
