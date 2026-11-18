/**
 * Subset of RFC 9651 Structured Field Values required by RFC 9421 and
 * draft-ietf-webbotauth-httpsig-protocol-01 (Signature, Signature-Input, Signature-Agent).
 */

const KEY_RE = /^[a-z*][a-z0-9_\-.*]*$/;

export function serializeSfString(value) {
  if (typeof value !== 'string') {
    throw new TypeError('Structured Field String must be a string');
  }
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code <= 0x1f || code >= 0x7f) {
      throw new RangeError('Structured Field String contains non-printable ASCII');
    }
  }
  const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  return `"${escaped}"`;
}

function skipOws(input, pos) {
  let i = pos;
  while (i < input.length && (input[i] === ' ' || input[i] === '\t')) i += 1;
  return i;
}

function skipSp(input, pos) {
  let i = pos;
  while (i < input.length && input[i] === ' ') i += 1;
  return i;
}

function parseKey(input, pos) {
  let i = pos;
  while (i < input.length && /[a-z0-9_\-.*]/.test(input[i])) i += 1;
  const key = input.slice(pos, i);
  if (!KEY_RE.test(key)) {
    throw new SyntaxError(`Invalid Structured Field key near index ${pos}`);
  }
  return { key, nextPos: i };
}

function parseSfStringAt(input, pos) {
  if (input[pos] !== '"') {
    throw new SyntaxError(`Expected '"' at index ${pos}`);
  }
  let i = pos + 1;
  let out = '';
  while (i < input.length) {
    const ch = input[i];
    if (ch === '\\') {
      i += 1;
      if (i >= input.length || (input[i] !== '"' && input[i] !== '\\')) {
        throw new SyntaxError(`Invalid escape sequence at index ${i}`);
      }
      out += input[i];
      i += 1;
      continue;
    }
    if (ch === '"') {
      return { value: out, nextPos: i + 1 };
    }
    const code = ch.charCodeAt(0);
    if (code <= 0x1f || code >= 0x7f) {
      throw new SyntaxError(`Invalid character in sf-string at index ${i}`);
    }
    out += ch;
    i += 1;
  }
  throw new SyntaxError('Unterminated sf-string');
}

function parseByteSequenceAt(input, pos) {
  if (input[pos] !== ':') {
    throw new SyntaxError(`Expected ':' at index ${pos}`);
  }
  const end = input.indexOf(':', pos + 1);
  if (end === -1) {
    throw new SyntaxError('Unterminated sf-binary byte sequence');
  }
  const b64 = input.slice(pos + 1, end);
  if (!/^[A-Za-z0-9+/=]*$/.test(b64)) {
    throw new SyntaxError('Invalid base64 characters in sf-binary');
  }
  return { bytes: Buffer.from(b64, 'base64'), base64: b64, nextPos: end + 1 };
}

function parseBareItemAt(input, pos) {
  const ch = input[pos];
  if (ch === '"') {
    const parsed = parseSfStringAt(input, pos);
    return { type: 'string', value: parsed.value, nextPos: parsed.nextPos };
  }
  if (ch === ':') {
    const parsed = parseByteSequenceAt(input, pos);
    return { type: 'bytes', value: parsed.bytes, nextPos: parsed.nextPos };
  }
  if (ch === '?') {
    const bit = input[pos + 1];
    if (bit !== '0' && bit !== '1') {
      throw new SyntaxError(`Invalid sf-boolean at index ${pos}`);
    }
    return { type: 'boolean', value: bit === '1', nextPos: pos + 2 };
  }
  if (ch === '-' || (ch >= '0' && ch <= '9')) {
    let i = pos + (ch === '-' ? 1 : 0);
    while (i < input.length && input[i] >= '0' && input[i] <= '9') i += 1;
    const rawNum = input.slice(pos, i);
    if (rawNum === '-' || rawNum.length === 0) {
      throw new SyntaxError(`Invalid sf-integer at index ${pos}`);
    }
    return { type: 'integer', value: Number.parseInt(rawNum, 10), nextPos: i };
  }
  if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '*') {
    let i = pos + 1;
    while (i < input.length && /[A-Za-z0-9:/!#$%&'*+\-.^_`|~]/.test(input[i])) i += 1;
    return { type: 'token', value: input.slice(pos, i), nextPos: i };
  }
  throw new SyntaxError(`Unsupported Structured Field bare item at index ${pos}`);
}

function parseParametersAt(input, pos) {
  let i = pos;
  const params = [];
  while (i < input.length && input[i] === ';') {
    i = skipSp(input, i + 1);
    const { key, nextPos } = parseKey(input, i);
    i = nextPos;
    let paramValue = true;
    let paramType = 'boolean';
    if (i < input.length && input[i] === '=') {
      const bare = parseBareItemAt(input, i + 1);
      paramValue = bare.value;
      paramType = bare.type;
      i = bare.nextPos;
    }
    params.push({ key, value: paramValue, type: paramType });
  }
  return { params, nextPos: i };
}

/**
 * Parses Signature-Agent per draft-ietf-webbotauth-httpsig-protocol-01 Section 5.2.1.
 * Supports:
 * 1) Dictionary Structured Header: sig1="https://signer.example.com" (normative)
 *    Members carrying parameters MUST be ignored per Section 5.2.1.
 * 2) Legacy sf-string: "https://signer.example.com" (optional migration form, Appendix E.2.2)
 */
export function parseSignatureAgentHeader(rawHeader, { allowLegacyString = true } = {}) {
  if (typeof rawHeader !== 'string' || rawHeader.trim() === '') {
    throw new SyntaxError('Empty Signature-Agent header');
  }
  const trimmed = rawHeader.trim();

  if (trimmed.startsWith('"')) {
    if (!allowLegacyString) {
      throw new SyntaxError('Legacy bare sf-string Signature-Agent is disabled');
    }
    const { value, nextPos } = parseSfStringAt(trimmed, 0);
    const { params, nextPos: endPos } = parseParametersAt(trimmed, nextPos);
    if (skipOws(trimmed, endPos) !== trimmed.length || params.length > 0) {
      throw new SyntaxError('Invalid legacy sf-string Signature-Agent');
    }
    return { isLegacyString: true, legacyValue: value, members: new Map() };
  }

  let i = 0;
  const members = new Map();
  while (i < trimmed.length) {
    i = skipOws(trimmed, i);
    const { key, nextPos } = parseKey(trimmed, i);
    i = nextPos;
    if (trimmed[i] !== '=') {
      throw new SyntaxError(`Expected '=' after Signature-Agent key "${key}"`);
    }
    i += 1;
    const bare = parseBareItemAt(trimmed, i);
    i = bare.nextPos;
    const { params, nextPos: afterParams } = parseParametersAt(trimmed, i);
    i = skipOws(trimmed, afterParams);

    // Section 5.2.1: Dictionary members MUST be String Items with https URI and MUST NOT carry parameters.
    if (bare.type === 'string' && params.length === 0) {
      members.set(key, bare.value);
    }

    if (i < trimmed.length) {
      if (trimmed[i] !== ',') {
        throw new SyntaxError(`Expected ',' at index ${i} in Signature-Agent`);
      }
      i += 1;
      if (skipOws(trimmed, i) === trimmed.length) {
        throw new SyntaxError('Trailing comma in Signature-Agent dictionary');
      }
    }
  }

  return { isLegacyString: false, legacyValue: null, members };
}

/**
 * Parses Signature header dictionary: label=:base64:
 */
export function parseSignatureHeader(rawHeader) {
  if (typeof rawHeader !== 'string' || rawHeader.trim() === '') {
    throw new SyntaxError('Empty Signature header');
  }
  const trimmed = rawHeader.trim();
  let i = 0;
  const signatures = new Map();

  while (i < trimmed.length) {
    i = skipOws(trimmed, i);
    const { key: label, nextPos } = parseKey(trimmed, i);
    i = nextPos;
    if (trimmed[i] !== '=') {
      throw new SyntaxError(`Expected '=' for signature label "${label}"`);
    }
    const seq = parseByteSequenceAt(trimmed, i + 1);
    const { nextPos: afterParams } = parseParametersAt(trimmed, seq.nextPos);
    i = skipOws(trimmed, afterParams);
    signatures.set(label, seq.bytes);

    if (i < trimmed.length) {
      if (trimmed[i] !== ',') {
        throw new SyntaxError(`Expected ',' in Signature header at index ${i}`);
      }
      i += 1;
    }
  }

  return signatures;
}

export function serializeComponentIdentifier(comp) {
  let out = serializeSfString(comp.name);
  for (const param of comp.params ?? []) {
    if (param.value === true && param.type === 'boolean') {
      out += `;${param.key}`;
    } else if (param.type === 'string') {
      out += `;${param.key}=${serializeSfString(param.value)}`;
    } else {
      throw new SyntaxError(`Unsupported component parameter type "${param.type}"`);
    }
  }
  return out;
}

export function serializeSignatureParamsValue(components, signatureParams) {
  const inner = components.map(serializeComponentIdentifier).join(' ');
  let out = `(${inner})`;
  for (const param of signatureParams) {
    if (param.type === 'integer') {
      out += `;${param.key}=${param.value}`;
    } else if (param.type === 'string') {
      out += `;${param.key}=${serializeSfString(param.value)}`;
    } else if (param.type === 'token') {
      out += `;${param.key}=${param.value}`;
    } else if (param.type === 'boolean' && param.value === true) {
      out += `;${param.key}`;
    } else {
      throw new SyntaxError(`Unsupported signature parameter "${param.key}"`);
    }
  }
  return out;
}

/**
 * Parses Signature-Input dictionary:
 * sig1=("@authority" "signature-agent";key="sig1");created=1735689600;expires=...;keyid="...";tag="web-bot-auth"
 */
export function parseSignatureInputHeader(rawHeader) {
  if (typeof rawHeader !== 'string' || rawHeader.trim() === '') {
    throw new SyntaxError('Empty Signature-Input header');
  }
  const trimmed = rawHeader.trim();
  let i = 0;
  const entries = new Map();

  while (i < trimmed.length) {
    i = skipOws(trimmed, i);
    const { key: label, nextPos } = parseKey(trimmed, i);
    i = nextPos;
    if (trimmed[i] !== '=' || trimmed[i + 1] !== '(') {
      throw new SyntaxError(`Expected '=(' after Signature-Input label "${label}"`);
    }
    i += 2;
    const components = [];
    i = skipSp(trimmed, i);
    while (i < trimmed.length && trimmed[i] !== ')') {
      const strItem = parseSfStringAt(trimmed, i);
      const { params, nextPos: afterCompParams } = parseParametersAt(trimmed, strItem.nextPos);
      const compName = strItem.value;
      if (compName !== compName.toLowerCase()) {
        throw new SyntaxError(`Component identifier "${compName}" must be lowercase`);
      }
      components.push({ name: compName, params });
      i = afterCompParams;
      if (trimmed[i] === ' ') {
        i = skipSp(trimmed, i);
      } else if (trimmed[i] !== ')') {
        throw new SyntaxError(`Expected space or ')' in inner list at index ${i}`);
      }
    }
    if (trimmed[i] !== ')') {
      throw new SyntaxError('Unterminated inner list in Signature-Input');
    }
    const { params: signatureParams, nextPos: afterSigParams } = parseParametersAt(trimmed, i + 1);
    i = skipOws(trimmed, afterSigParams);

    const paramMap = Object.create(null);
    for (const p of signatureParams) {
      paramMap[p.key] = p.value;
    }

    entries.set(label, {
      label,
      components,
      signatureParams,
      params: paramMap,
      serializedParams: serializeSignatureParamsValue(components, signatureParams)
    });

    if (i < trimmed.length) {
      if (trimmed[i] !== ',') {
        throw new SyntaxError(`Expected ',' in Signature-Input at index ${i}`);
      }
      i += 1;
    }
  }

  return entries;
}
