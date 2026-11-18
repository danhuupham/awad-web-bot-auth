import crypto from 'node:crypto';

function asn1Len(len) {
  if (len < 128) return Buffer.from([len]);
  const bytes = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function derTag(tagByte, ...buffers) {
  const body = Buffer.concat(buffers);
  return Buffer.concat([Buffer.from([tagByte]), asn1Len(body.length), body]);
}

const derSeq = (...b) => derTag(0x30, ...b);
const derSet = (...b) => derTag(0x31, ...b);
const derOid = (bytes) => derTag(0x06, Buffer.from(bytes));
const derUtf8 = (str) => derTag(0x0c, Buffer.from(str, 'utf8'));
const derUtcTime = (str) => derTag(0x17, Buffer.from(str, 'ascii'));
const derBitString = (buf) => derTag(0x03, Buffer.from([0x00]), buf);
const derOctetString = (buf) => derTag(0x04, buf);
const derExplicit = (num, ...b) => derTag(0xa0 | num, ...b);

function toPem(label, derBuffer) {
  const lines = derBuffer.toString('base64').match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

/**
 * Generates an in-memory X.509 v3 Ed25519 TLS certificate for 127.0.0.1 / localhost.
 * Avoids storing any private keys on disk while keeping full TLS 1.3 verification enabled.
 */
export function createLoopbackTlsCredentials() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });

  // OID 1.3.101.112 (id-Ed25519)
  const algEd25519 = derSeq(derOid([0x2b, 0x65, 0x70]));
  // Subject / Issuer: CN=localhost
  const subjectName = derSeq(derSet(derSeq(derOid([0x55, 0x04, 0x03]), derUtf8('localhost'))));
  const validity = derSeq(derUtcTime('250101000000Z'), derUtcTime('350101000000Z'));

  // SubjectAltName: DNS:localhost, IP:127.0.0.1
  const sanExtValue = derSeq(
    derTag(0x82, Buffer.from('localhost', 'ascii')),
    derTag(0x87, Buffer.from([127, 0, 0, 1]))
  );
  const extensions = derExplicit(
    3,
    derSeq(
      // basicConstraints (2.5.29.19) = CA:FALSE
      derSeq(derOid([0x55, 0x1d, 0x13]), derOctetString(derSeq())),
      // subjectAltName (2.5.29.17)
      derSeq(derOid([0x55, 0x1d, 0x11]), derOctetString(sanExtValue))
    )
  );

  const serial = derTag(0x02, Buffer.concat([Buffer.from([0x01]), crypto.randomBytes(8)]));
  const versionV3 = derExplicit(0, derTag(0x02, Buffer.from([0x02])));

  const tbsCertificate = derSeq(
    versionV3,
    serial,
    algEd25519,
    subjectName,
    validity,
    subjectName,
    spkiDer,
    extensions
  );

  const signature = crypto.sign(null, tbsCertificate, privateKey);
  const certDer = derSeq(tbsCertificate, algEd25519, derBitString(signature));

  return {
    cert: toPem('CERTIFICATE', certDer),
    key: privateKey.export({ type: 'pkcs8', format: 'pem' })
  };
}
