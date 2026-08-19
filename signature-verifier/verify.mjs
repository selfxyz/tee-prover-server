// The JS parsing layer for the TEE prover's signature pre-check (Plan A,
// Task 1). Ports the semantics of src/verifier/chunks.rs,
// src/verifier/sha_padding.rs, and the certificate/key-matching pieces of
// src/verifier/passport.rs and src/verifier/dsc.rs -- not their syntax.
//
// Zero dependencies: node:crypto and node:buffer only. No @selfxyz/common, no
// forge, elliptic, pkijs, or asn1js.
//
// The governing asymmetry from the Rust modules still applies here: a
// function returns `null` (or `false`, for the boolean-returning check) on
// anything unparseable or non-matching, never throws. A thrown exception
// would become a server crash instead of a verdict -- see certPublicKey's
// doc comment in particular, since `X509Certificate`'s constructor is the
// one call in this module that throws on malformed input by default.

import crypto from 'node:crypto';

// ---------------------------------------------------------------------
// limbsToBigInt -- base-2^n reassembly, least-significant limb first.
// ---------------------------------------------------------------------

/**
 * Reassembles a big integer from little-endian base-`2^n` limbs (decimal
 * strings): `limbs[0] + limbs[1] * 2^n + limbs[2] * 2^(2n) + ...`.
 *
 * Mirrors chunks.rs's `bigint_from_limbs`, including its two rejections:
 * `n == 0`, and any limb outside `[0, 2^n)`. Both return `null`.
 *
 * Rejecting matters even though no legitimate input triggers it. An
 * out-of-range limb means the client sent a value the circuit's own
 * `Num2Bits` range check would refuse, and accumulating it with `|=` would
 * silently overlap the neighbouring limb's bits -- reassembling a *different*
 * key and failing verification for a reason no message would explain. Better
 * an explicit `null` the caller turns into a skip.
 *
 * `n` need not be a multiple of 8 -- secp521r1 uses `n = 66`, and limbs are
 * NOT byte-aligned there. This must stay genuine base-`2^n` arithmetic
 * (`acc |= BigInt(limb) << (BigInt(n) * BigInt(i))`); any byte-slicing
 * shortcut silently corrupts those keys while looking plausible on every
 * byte-aligned curve.
 *
 * @param {ReadonlyArray<string>} limbs decimal-string limbs, LSB-first.
 * @param {number} n limb width in bits (base is `2^n`).
 * @returns {bigint|null} null if `n == 0` or a limb is out of range.
 */
export function limbsToBigInt(limbs, n) {
  if (!Number.isInteger(n) || n <= 0) return null;
  const nBig = BigInt(n);
  const bound = 1n << nBig;
  let acc = 0n;
  for (let i = 0; i < limbs.length; i++) {
    // Validate the text before converting: BigInt('') is 0n rather than a
    // throw, so a try/catch alone lets an empty limb through as zero and
    // silently reassembles a different key. chunks.rs's parse::<BigUint>()
    // rejects it, so this must too.
    const text = String(limbs[i]);
    if (!/^[0-9]+$/.test(text)) return null;
    const limb = BigInt(text);
    if (limb < 0n || limb >= bound) return null;
    acc += limb << (nBig * BigInt(i));
  }
  return acc;
}

// ---------------------------------------------------------------------
// fieldAsStrings -- the string/number/array-of-either normalization that
// chunks.rs's field_as_strings performs. Not one of this task's four
// mandated exports, but ported for the same reason chunks.rs has it: two
// entire document families (Aadhaar, KYC) once verified nothing in
// production because their fields arrive as genuine JSON numbers, not the
// decimal strings every other family's builder emits.
// ---------------------------------------------------------------------

/**
 * Normalizes a raw JSON field value into an array of decimal strings.
 * Accepts a bare string, a bare number (Aadhaar's `qrDataPaddedLength`), or
 * an array whose elements are each a string or a number (the normal case,
 * and KYC's `data_padded`, respectively). Anything else -- `undefined`,
 * `null`, an object, a boolean, or an array containing any of those --
 * returns `null`.
 *
 * A JSON number is rendered with `String(n)`, matching Rust's
 * `Number::to_string()`: an integer like `1536` becomes `"1536"` and parses
 * downstream exactly as the stringified form would; a non-integer like
 * `5.0` becomes `"5"` in JS (unlike Rust's `"5.0"`) -- still fails a
 * strict `parse::<u8>()`-equivalent integer check downstream, so nothing
 * ambiguous is accepted, only the encoding gap is closed.
 *
 * @param {unknown} value
 * @returns {string[] | null}
 */
export function fieldAsStrings(value) {
  if (typeof value === 'string') {
    return [value];
  }
  if (typeof value === 'number') {
    return [String(value)];
  }
  if (Array.isArray(value)) {
    const out = [];
    for (const item of value) {
      if (typeof item === 'string') {
        out.push(item);
      } else if (typeof item === 'number') {
        out.push(String(item));
      } else {
        return null;
      }
    }
    return out;
  }
  return null;
}

// ---------------------------------------------------------------------
// recoverMessage -- strips ShaBytesDynamic-style SHA padding back off.
// ---------------------------------------------------------------------

/**
 * Recovers the original (unpadded) message from `bytes[..paddedLength]`,
 * which is assumed to be standard SHA padding: `message || 0x80 || zeros*
 * || be_uint64(message_len_in_bits)`, padded out to a whole number of
 * 64-byte blocks.
 *
 * Mirrors sha_padding.rs's `recover_message` exactly, including its
 * handling of the 384/512-bit shape (128-byte blocks, 16-byte length
 * field): this function only ever reads the trailing 8 bytes as the
 * bit-length, which is correct for both shapes for the same two reasons
 * the Rust doc comment gives --
 *
 * 1. 128 is a multiple of 64, so the `paddedLength % 64 !== 0` check never
 *    rejects a genuinely 128-byte-block-aligned buffer.
 * 2. The 128-bit length field is big-endian, so its trailing 8 bytes are
 *    the true bit-length's low 64 bits, and its leading 8 bytes -- zero
 *    for any message under 2^64 bits, i.e. every real document -- are
 *    covered by the same "every byte between the 0x80 marker and the
 *    length field must be zero" check as the ordinary zero padding.
 *
 * Returns `null` if: `paddedLength` exceeds `bytes.length`; `paddedLength`
 * is not a non-negative integer or is not a multiple of 64; the buffer is
 * too short to hold an 8-byte length field; the encoded bit-length is not
 * a whole number of bytes; the encoded length does not fit inside the
 * buffer (leaving no room for the `0x80` marker); the byte immediately
 * after the message is not `0x80`; or any byte between that marker and the
 * length field is not zero.
 *
 * @param {Uint8Array} bytes
 * @param {number} paddedLength
 * @returns {Uint8Array | null}
 */
export function recoverMessage(bytes, paddedLength) {
  if (!Number.isInteger(paddedLength) || paddedLength < 0) {
    return null;
  }
  if (paddedLength > bytes.length) {
    return null;
  }
  if (paddedLength % 64 !== 0) {
    return null;
  }
  const buf = bytes.subarray(0, paddedLength);
  if (buf.length < 8) {
    return null;
  }
  const msgAndPadLen = buf.length - 8;

  // Big-endian 64-bit bit-length from the trailing 8 bytes. BigInt keeps
  // this exact regardless of magnitude -- equivalent to Rust's
  // `u64::from_be_bytes`.
  let bitLen = 0n;
  for (let i = msgAndPadLen; i < buf.length; i++) {
    bitLen = (bitLen << 8n) | BigInt(buf[i]);
  }
  if (bitLen % 8n !== 0n) {
    return null;
  }
  const msgLenBig = bitLen / 8n;
  if (msgLenBig >= BigInt(msgAndPadLen)) {
    // No room left for the 0x80 marker (and, ordinarily, at least one zero
    // byte) before the length field.
    return null;
  }
  const msgLen = Number(msgLenBig);
  if (buf[msgLen] !== 0x80) {
    return null;
  }
  for (let i = msgLen + 1; i < msgAndPadLen; i++) {
    if (buf[i] !== 0) {
      return null;
    }
  }
  return buf.subarray(0, msgLen);
}

// ---------------------------------------------------------------------
// Minimal DER TLV reader -- used only to pull the raw EC point (x || y)
// back out of a SubjectPublicKeyInfo DER buffer, since node:crypto has no
// public API for that and JWK export throws for brainpool curves (Node
// supports `asymmetricKeyDetails.namedCurve` for brainpool, but
// `KeyObject.export({format:'jwk'})` does not recognize those curve names).
// This is a generic, few-line TLV walker -- not a general ASN.1/ DER
// library -- deliberately kept to exactly what SPKI parsing needs so it
// stays within the zero-dependency constraint without reaching for asn1js.
// ---------------------------------------------------------------------

/**
 * Reads one DER TLV (tag-length-value) at `offset`. Supports short-form and
 * long-form definite lengths only (every DER encoding node:crypto emits is
 * definite-length); returns `null` on indefinite length, a length that
 * overruns the buffer, or a truncated header.
 *
 * @param {Buffer} buf
 * @param {number} offset
 * @returns {{tag: number, content: Buffer, nextOffset: number} | null}
 */
function readDerTLV(buf, offset) {
  if (offset + 2 > buf.length) {
    return null;
  }
  const tag = buf[offset];
  const first = buf[offset + 1];
  let length;
  let headerLen;
  if (first & 0x80) {
    const numLenBytes = first & 0x7f;
    if (numLenBytes === 0 || offset + 2 + numLenBytes > buf.length) {
      return null; // indefinite length or truncated long-form length
    }
    let len = 0;
    for (let i = 0; i < numLenBytes; i++) {
      len = len * 256 + buf[offset + 2 + i];
    }
    length = len;
    headerLen = 2 + numLenBytes;
  } else {
    length = first;
    headerLen = 2;
  }
  const contentStart = offset + headerLen;
  const contentEnd = contentStart + length;
  if (contentEnd > buf.length) {
    return null;
  }
  return { tag, content: buf.subarray(contentStart, contentEnd), nextOffset: contentEnd };
}

/**
 * Extracts the raw uncompressed EC point (`x`, `y`, each a fixed-width
 * big-endian Buffer) from a SubjectPublicKeyInfo DER buffer:
 * `SEQUENCE { AlgorithmIdentifier, BIT STRING { 0x00, 0x04, x, y } }`.
 *
 * Returns `null` for anything else: a malformed outer structure, a
 * BIT STRING with nonzero unused-bits, or a point that is not the
 * uncompressed form (`0x04` prefix) with an even remaining length.
 *
 * @param {Buffer} spkiDer
 * @returns {{x: Buffer, y: Buffer} | null}
 */
function extractEcPoint(spkiDer) {
  const outer = readDerTLV(spkiDer, 0);
  if (!outer || outer.tag !== 0x30) {
    return null;
  }
  const alg = readDerTLV(outer.content, 0);
  if (!alg) {
    return null;
  }
  const bitstr = readDerTLV(outer.content, alg.nextOffset);
  if (!bitstr || bitstr.tag !== 0x03 || bitstr.content.length < 2) {
    return null;
  }
  const unusedBits = bitstr.content[0];
  if (unusedBits !== 0) {
    return null;
  }
  const point = bitstr.content.subarray(1);
  if (point.length < 3 || point[0] !== 0x04) {
    return null; // only the uncompressed point form is supported
  }
  const coordLen = (point.length - 1) / 2;
  if (!Number.isInteger(coordLen)) {
    return null;
  }
  return { x: point.subarray(1, 1 + coordLen), y: point.subarray(1 + coordLen) };
}

/**
 * Renders `value` as exactly `length` big-endian bytes, left-padding with
 * zeros. `null` if `value` is negative or its minimal encoding needs more
 * than `length` bytes -- mirrors dsc.rs's `to_fixed_bytes`.
 *
 * @param {bigint} value
 * @param {number} length
 * @returns {Buffer | null}
 */
function bigIntToFixedBytes(value, length) {
  // `null` reaches here when limbsToBigInt rejected its input. Guarding is not
  // decoration: `null < 0n` is false (null coerces to 0), so without this the
  // next line throws TypeError on null.toString(16) -- turning a verdict into
  // a crash.
  if (typeof value !== 'bigint' || value < 0n) {
    return null;
  }
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) {
    hex = `0${hex}`;
  }
  if (hex.length > length * 2) {
    return null;
  }
  return Buffer.from(hex.padStart(length * 2, '0'), 'hex');
}

// ---------------------------------------------------------------------
// certPublicKey -- parse a DER certificate, never throw.
// ---------------------------------------------------------------------

/**
 * Parses `derBytes` as an X.509 certificate and returns its public key.
 *
 * `new crypto.X509Certificate(...)` throws on malformed input -- an
 * escaping exception here would become a server crash instead of a
 * verdict, so this always catches and returns `null` rather than letting
 * anything propagate.
 *
 * `details` is the key's `asymmetricKeyDetails` (spread into a plain
 * object): for RSA this carries `modulusLength`; for EC keys -- including
 * brainpool curves, which node:crypto supports here even though its JWK
 * exporter rejects them -- this carries `namedCurve`.
 *
 * @param {Uint8Array | Buffer} derBytes
 * @returns {{key: import('node:crypto').KeyObject, details: object} | null}
 */
export function certPublicKey(derBytes) {
  try {
    const buf = Buffer.isBuffer(derBytes) ? derBytes : Buffer.from(derBytes);
    const cert = new crypto.X509Certificate(buf);
    const key = cert.publicKey;
    return { key, details: { ...key.asymmetricKeyDetails } };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------
// keyMatchesCert -- byte comparison between circuit-supplied limbs and a
// parsed certificate's own public key.
// ---------------------------------------------------------------------

/**
 * Checks that the circuit-supplied public key (`suppliedLimbs`, base-`2^n`
 * limbs) is byte-for-byte the same key `cert` (a `certPublicKey` result)
 * actually carries.
 *
 * `scheme` selects the limb layout: `'rsa'` (covers both RSA PKCS#1v15 and
 * RSASSA-PSS -- the key material and its layout are identical, only the
 * padding scheme used to verify a signature differs) reads `suppliedLimbs`
 * as a single `k`-limb modulus; `'ecdsa'` (covers both NIST and brainpool
 * curves -- same `x || y` layout, `getKLengthFactor(alg) == 2` for every
 * ECDSA algorithm id) reads it as `2k` limbs, `x = [0..k]`, `y = [k..2k]`.
 * Any other `scheme`, a limb-count mismatch, a `cert` that is `null` or
 * lacks a usable key, or a key whose type does not match `scheme` all
 * return `false` rather than throwing.
 *
 * @param {ReadonlyArray<string>} suppliedLimbs
 * @param {number} n limb width in bits.
 * @param {number} k limb count (RSA modulus limbs, or half the ECDSA limb count).
 * @param {{key: import('node:crypto').KeyObject, details: object} | null} cert
 * @param {'rsa' | 'ecdsa'} scheme
 * @returns {boolean}
 */
export function keyMatchesCert(suppliedLimbs, n, k, cert, scheme) {
  if (!cert || !cert.key) {
    return false;
  }
  try {
    if (scheme === 'rsa') {
      if (suppliedLimbs.length !== k) {
        return false;
      }
      const jwk = cert.key.export({ format: 'jwk' });
      if (jwk.kty !== 'RSA' || typeof jwk.n !== 'string') {
        return false;
      }
      const certModulus = Buffer.from(jwk.n, 'base64url');
      const suppliedModulus = bigIntToFixedBytes(limbsToBigInt(suppliedLimbs, n), certModulus.length);
      if (!suppliedModulus) {
        return false;
      }
      return Buffer.compare(suppliedModulus, certModulus) === 0;
    }
    if (scheme === 'ecdsa') {
      if (suppliedLimbs.length !== 2 * k) {
        return false;
      }
      const spkiDer = cert.key.export({ format: 'der', type: 'spki' });
      const point = extractEcPoint(spkiDer);
      if (!point) {
        return false;
      }
      const x = limbsToBigInt(suppliedLimbs.slice(0, k), n);
      const y = limbsToBigInt(suppliedLimbs.slice(k, 2 * k), n);
      const xBytes = bigIntToFixedBytes(x, point.x.length);
      const yBytes = bigIntToFixedBytes(y, point.y.length);
      if (!xBytes || !yBytes) {
        return false;
      }
      return Buffer.compare(xBytes, point.x) === 0 && Buffer.compare(yBytes, point.y) === 0;
    }
    return false;
  } catch {
    return false;
  }
}
