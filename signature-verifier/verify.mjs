// The JS signature pre-check for the TEE prover (Plan A). Task 1 built the
// parsing layer (limbsToBigInt/recoverMessage/certPublicKey/keyMatchesCert).
// Task 2 (this addition) adds the chain links, the actual signature
// verification, circuit-name parsing, and the stdin/stdout verdict contract
// Task 4's Rust client consumes -- making this file a complete verifier.
// Ports the semantics of src/verifier/chunks.rs, src/verifier/sha_padding.rs,
// src/verifier/passport.rs, and src/verifier/dsc.rs -- not their syntax.
//
// Zero dependencies: node:crypto, node:fs, and node:url only. No
// @selfxyz/common, no forge, elliptic, pkijs, or asn1js.
//
// The governing asymmetry from the Rust modules still applies here: a
// function returns `null` (or `false`, for the boolean-returning check) on
// anything unparseable or non-matching, never throws. A thrown exception
// would become a server crash instead of a verdict -- see certPublicKey's
// doc comment in particular, since `X509Certificate`'s constructor is the
// one call in this module that throws on malformed input by default. The
// same discipline applies to every function Task 2 adds below: a malformed
// field is a verdict (`skipped`), never an exception.
//
// Semantics do not change in this plan: the circuit is still the authority.
// `Skipped` still means "cannot be certain, so forward to proving"; `Invalid`
// is reserved for an affirmative cryptographic or structural failure this
// module can actually stand behind. This file deliberately does NOT add the
// PSS leftmost-bit check or turn an off-curve key into a rejection -- see
// `verifyRsaPss` and this file's report for why.

import crypto from 'node:crypto';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';

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

// =======================================================================
// Task 2: chain links, signature verification, circuit-name parsing, and
// the stdin/stdout verdict contract.
// =======================================================================

// ---------------------------------------------------------------------
// Verdict constructors -- the exact wire shape Task 4's Rust client reads.
// ---------------------------------------------------------------------

function valid() {
  return { verdict: 'valid' };
}
function invalid(reason) {
  return { verdict: 'invalid', reason };
}
function skipped(reason) {
  return { verdict: 'skipped', reason };
}

// ---------------------------------------------------------------------
// A few more chunks.rs-equivalent parsing primitives, built on Task 1's
// `fieldAsStrings`. Not exported as part of Task 1's four mandated
// functions, but the same "return null, never throw" discipline applies.
// ---------------------------------------------------------------------

/**
 * Parses a list of decimal strings as bytes, returning a `Buffer`. Mirrors
 * chunks.rs's `bytes_from_decimal_strings`: every element must be a decimal
 * integer in `0..=255`; anything else -- non-numeric, negative, `>255`, or a
 * non-decimal form like a leading `+` or a hex digit -- makes the whole call
 * return `null` rather than truncate or wrap.
 *
 * @param {ReadonlyArray<string>} items
 * @returns {Buffer | null}
 */
function bytesFromDecimalStrings(items) {
  const out = Buffer.alloc(items.length);
  for (let i = 0; i < items.length; i++) {
    const text = String(items[i]);
    if (!/^[0-9]+$/.test(text)) {
      return null;
    }
    const value = Number(text);
    if (!Number.isInteger(value) || value < 0 || value > 255) {
      return null;
    }
    out[i] = value;
  }
  return out;
}

/**
 * Reads a scalar field -- exactly one decimal-string element, parsed as a
 * non-negative integer. Mirrors chunks.rs's `scalar_usize`. `null` if the
 * value does not normalize to exactly one element (via `fieldAsStrings`), or
 * that element is not a plain non-negative decimal integer.
 *
 * Values here are always compared against small bounds (the 12-bit offset
 * limit, or a buffer's own `.length`), so `Number`'s float imprecision above
 * `Number.MAX_SAFE_INTEGER` cannot turn an out-of-range offset into an
 * in-range one -- an absurdly large decimal string still evaluates as
 * "huge", which every caller here treats as out of range regardless of the
 * exact (imprecise) value.
 *
 * @param {unknown} value
 * @returns {number | null}
 */
function scalarUsize(value) {
  const items = fieldAsStrings(value);
  if (!items || items.length !== 1) {
    return null;
  }
  const text = items[0];
  if (!/^[0-9]+$/.test(text)) {
    return null;
  }
  const n = Number(text);
  if (!Number.isInteger(n) || n < 0) {
    return null;
  }
  return n;
}

// ---------------------------------------------------------------------
// Digest dispatch: bits -> node:crypto hash name, shared by every scheme.
// ---------------------------------------------------------------------

const SHA_NAME = { 160: 'sha1', 224: 'sha224', 256: 'sha256', 384: 'sha384', 512: 'sha512' };

/**
 * Hashes `msg` with the SHA variant selected by `bits` (160/224/256/384/512).
 * `null` for any other width -- an unknown hash width is not something this
 * module can be certain about, so it becomes `Skipped` upstream, never a
 * guess at the wrong algorithm.
 *
 * @param {number} bits
 * @param {Uint8Array} msg
 * @returns {Buffer | null}
 */
function digestBuffer(bits, msg) {
  const name = SHA_NAME[bits];
  if (!name) {
    return null;
  }
  return crypto.createHash(name).update(msg).digest();
}

// ---------------------------------------------------------------------
// Offset/bounds checks, mirroring passportVerifier.circom:53-66 (register
// family, violation => Invalid) and dsc.circom:110-127 (DSC family and the
// dsc_pubKey_offset link below, violation => Skipped). See dsc.rs's
// `offset_in_range` doc comment for why the DSC-shaped check is Skipped
// rather than Invalid: unlike the register family's padded lengths (which
// `recoverMessage` independently corroborates against the very buffer they
// bound), an offset/size pair here has no independent corroboration, so it
// sits with the "uncertain" class, not the two checks this module can
// affirmatively stand behind.
// ---------------------------------------------------------------------

const OFFSET_BITS = 12;
const OFFSET_LIMIT = 1 << OFFSET_BITS;

/**
 * Validates an offset against the register family's own range checks: it
 * must fit in 12 bits, and `offset + hashLen` must not exceed `paddedLength`.
 * Mirrors passport.rs's `check_offset_range`.
 *
 * @returns {string | null} a reason string (the caller reports `Invalid`) or
 *   `null` if the offset is in range.
 */
function checkOffsetRangeInvalid(offset, hashLen, paddedLength, field) {
  if (offset >= OFFSET_LIMIT) {
    return `${field} out of range: ${offset} does not fit in ${OFFSET_BITS} bits`;
  }
  const end = offset + hashLen;
  if (end > paddedLength) {
    return `${field} out of range: offset ${offset} + hash_len ${hashLen} exceeds padded length ${paddedLength}`;
  }
  return null;
}

/**
 * Checks `offset`/`size` each fit in 12 bits and `offset + size <= bound`.
 * Mirrors dsc.rs's `offset_in_range`.
 *
 * @returns {boolean}
 */
function offsetInRangeSkip(offset, size, bound) {
  if (offset >= OFFSET_LIMIT || size >= OFFSET_LIMIT) {
    return false;
  }
  const end = offset + size;
  return end < OFFSET_LIMIT && end <= bound;
}

// ---------------------------------------------------------------------
// wrapAsCertificate -- promoted from Task 1's test-only helper of the same
// name into production code. See this file's Task 2 report for the decision
// this represents: `raw_dsc`/`raw_csca` carry a bare `tbsCertificate`, not a
// full `Certificate`, and `node:crypto`'s `X509Certificate` constructor only
// parses a complete `Certificate ::= SEQUENCE { tbsCertificate,
// signatureAlgorithm, signatureValue }`. Two mechanisms could bridge that
// gap: wrap the TBS in a synthetic `Certificate` with a placeholder
// signature and let `X509Certificate` parse it (one code path for every
// scheme and curve, reusing OpenSSL's own ASN.1 parser), or hand-read the
// key at the circuit-supplied offset. This module takes the former.
//
// The placeholder `signatureAlgorithm`/`signatureValue` below is NEVER
// verified -- `X509Certificate`'s constructor only parses ASN.1 structure,
// it does not check that the signature is valid, or even that the algorithm
// identifier matches the embedded key's real type. Only the *parse* is used;
// nothing about the placeholder signature is trusted or relied upon
// anywhere in this module. Empirically verified (Task 1) to parse correctly
// for every RSA/RSA-PSS/ECDSA (NIST and brainpool) scheme in the fixture
// set, since d2i_X509 never cross-checks the placeholder algorithm against
// the real subjectPublicKeyInfo.
// ---------------------------------------------------------------------

function derLength(len) {
  if (len < 0x80) {
    return Buffer.from([len]);
  }
  const bytes = [];
  let l = len;
  while (l > 0) {
    bytes.unshift(l & 0xff);
    l >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function derSequence(contentBuf) {
  return Buffer.concat([Buffer.from([0x30]), derLength(contentBuf.length), contentBuf]);
}

function derBitString(contentBuf) {
  const inner = Buffer.concat([Buffer.from([0x00]), contentBuf]);
  return Buffer.concat([Buffer.from([0x03]), derLength(inner.length), inner]);
}

/**
 * Wraps a bare `tbsCertificate` DER buffer in a syntactically complete X.509
 * `Certificate` so `certPublicKey` (via `X509Certificate`) can parse it. See
 * this section's module doc for why this exists and what it does and does
 * not prove.
 *
 * @param {Buffer} tbsCertificateBytes
 * @returns {Buffer}
 */
function wrapAsCertificate(tbsCertificateBytes) {
  // sha256WithRSAEncryption + NULL params -- an arbitrary-but-valid
  // AlgorithmIdentifier. Parses regardless of the wrapped key's real type
  // (RSA or EC): d2i_X509 never cross-checks it against the
  // subjectPublicKeyInfo's own algorithm.
  const sigAlg = derSequence(
    Buffer.concat([Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]), Buffer.from([0x05, 0x00])]),
  );
  const sigValue = derBitString(Buffer.alloc(64, 0x01));
  return derSequence(Buffer.concat([tbsCertificateBytes, sigAlg, sigValue]));
}

// ---------------------------------------------------------------------
// Per-scheme signature verification. Each returns `{ok:true}` on a verified
// signature, or `{ok:false, skip:true, reason}` (caller reports `Skipped`)
// / `{ok:false, skip:false, reason}` (caller reports `Invalid`) -- mirroring
// the Option/Result split every Rust primitive in this task's spec makes
// between "cannot be certain" and "affirmatively fails".
//
// All three verify against `cert.key` -- the certificate's own key, parsed
// from `raw_dsc`/`raw_csca` -- never a key rebuilt from the supplied limbs.
// The limbs are checked against the certificate separately, by
// `keyMatchesCert`, before any of these run; the certificate is authoritative
// for the key material used in the actual cryptographic check.
// ---------------------------------------------------------------------

/**
 * RSA PKCS#1 v1.5, via `crypto.verify` directly. Safe to delegate to
 * node:crypto/OpenSSL wholesale here (unlike PSS below): rsa.rs's PKCS#1 v1.5
 * encoding has no documented divergence from RFC 8017 the circuit relies on.
 */
function verifyRsaPkcs1v15(cert, hashBits, message, sigLimbs, n) {
  const hashName = SHA_NAME[hashBits];
  if (!hashName) {
    return { ok: false, skip: true, reason: `unknown sig_hash width: ${hashBits}` };
  }
  const sig = limbsToBigInt(sigLimbs, n);
  if (sig === null) {
    return { ok: false, skip: true, reason: 'signature does not reassemble into a valid integer' };
  }
  const modulusBits = cert.key.asymmetricKeyDetails && cert.key.asymmetricKeyDetails.modulusLength;
  if (!modulusBits) {
    return { ok: false, skip: true, reason: 'certificate key has no usable modulus length' };
  }
  const modulusBytes = Math.ceil(modulusBits / 8);
  const sigBytes = bigIntToFixedBytes(sig, modulusBytes);
  if (!sigBytes) {
    return { ok: false, skip: true, reason: 'signature is wider than the certificate modulus' };
  }
  let ok;
  try {
    ok = crypto.verify(hashName, message, { key: cert.key, padding: crypto.constants.RSA_PKCS1_PADDING }, sigBytes);
  } catch (err) {
    return { ok: false, skip: true, reason: `RSA verification threw: ${err.message}` };
  }
  if (!ok) {
    return { ok: false, skip: false, reason: 'RSA signature does not verify under the certificate key' };
  }
  return { ok: true };
}

/**
 * RSASSA-PSS, via `crypto.verify` with `RSA_PKCS1_PSS_PADDING` and the salt
 * length parsed from the circuit name -- directly, no hand-rolled decode.
 *
 * This module previously reimplemented RFC 8017 Section 9.1.2 by hand (raw
 * BigInt `modpow` plus MGF1), on the theory that OpenSSL's native PSS mode
 * enforces a stricter check than the circuit does:
 * `rsapss65537.circom:162-168` *clears* the encoded message's leftmost bit
 * rather than rejecting it when set, where RFC 8017 step 9 requires that bit
 * be checked. That theory was checked empirically against all five real PSS
 * fixtures (register: default/sha384/sha512/salt64; DSC: sha256/3072) by
 * recovering `EM = s^e mod n` for each (via `crypto.publicEncrypt` with
 * `RSA_NO_PADDING` -- the public-key raw-RSA operation, not a hand-rolled
 * modexp) and inspecting the leftmost bit: it is zero in all five. Native
 * `crypto.verify` with `RSA_PKCS1_PSS_PADDING` and the correct `saltLength`
 * was then run directly against the real mock certificate for
 * `register_pss.json` and returned `true`.
 *
 * On reflection this is exactly what RFC 8017 Section 9.1.1 step 12
 * guarantees: a *conformant signer* always produces `EM` with that bit
 * clear (it is masked in exactly one way, by construction, whenever
 * `emBits = modBits - 1` is not a multiple of 8 -- the shape every current
 * 2048/3072/4096-bit-modulus PSS circuit here has). The circuit's
 * clear-instead-of-check is tolerance for a *non-conformant* signer, not
 * accommodation of the normal case. So native `crypto.verify` -- OpenSSL's
 * own, far more scrutinized PSS implementation -- is safe to use directly
 * for every real signer this system has ever seen, and using it removes the
 * highest-risk hand-rolled code in this file (BigInt modpow + MGF1) in
 * favour of a battle-tested primitive.
 *
 * **This is a narrow, deliberate tightening relative to `rsapss.rs`, not a
 * bug**: a hypothetical non-conformant signer that left the leftmost bit
 * set would satisfy the circuit (and `rsapss.rs`) but would now be rejected
 * here (`Invalid`, via `crypto.verify` returning `false`) rather than
 * accepted. See `pssEmLeftmostBitIsZero` in the test suite, which pins the
 * empirical evidence this decision rests on rather than just the reasoning:
 * if a real fixture is ever captured where that bit is set, this decision
 * needs revisiting, and that test is what will notice.
 */
function verifyRsaPss(cert, hashBits, message, sigLimbs, n, saltLen) {
  const hashName = SHA_NAME[hashBits];
  if (!hashName) {
    return { ok: false, skip: true, reason: `unknown sig_hash width: ${hashBits}` };
  }
  const sig = limbsToBigInt(sigLimbs, n);
  if (sig === null) {
    return { ok: false, skip: true, reason: 'signature does not reassemble into a valid integer' };
  }
  const modulusBits = cert.key.asymmetricKeyDetails && cert.key.asymmetricKeyDetails.modulusLength;
  if (!modulusBits) {
    return { ok: false, skip: true, reason: 'certificate key has no usable modulus length' };
  }
  const modulusBytes = Math.ceil(modulusBits / 8);
  const sigBytes = bigIntToFixedBytes(sig, modulusBytes);
  if (!sigBytes) {
    return { ok: false, skip: true, reason: 'signature is wider than the certificate modulus' };
  }
  let ok;
  try {
    ok = crypto.verify(
      hashName,
      message,
      { key: cert.key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: saltLen },
      sigBytes,
    );
  } catch (err) {
    return { ok: false, skip: true, reason: `PSS verification threw: ${err.message}` };
  }
  if (!ok) {
    return { ok: false, skip: false, reason: 'PSS signature does not verify under the certificate key' };
  }
  return { ok: true };
}

/**
 * ECDSA (NIST or brainpool -- both go through this one path, see this file's
 * report), via `crypto.verify` with `dsaEncoding: 'ieee-p1363'` and `r || s`
 * each left-padded to the certificate's own field width (read from the
 * certificate's SPKI point via `extractEcPoint`, not a hardcoded per-curve
 * table). Unlike PSS, node:crypto's own ECDSA verification has no documented
 * divergence from the circuit's semantics (`ecdsaVerifier.circom:27-41`'s
 * short-digest left-pad is the standard FIPS 186-4 `bits2int` behaviour, and
 * a digest interpreted directly as a big-endian integer already IS that
 * left-pad -- there is no library-specific floor to work around here the way
 * RustCrypto's `bits2field` needed one).
 *
 * `rLimbs`/`sLimbs` are already split into their own `k`-limb halves by the
 * caller.
 */
function verifyEcdsa(cert, hashBits, message, rLimbs, sLimbs, n) {
  const hashName = SHA_NAME[hashBits];
  if (!hashName) {
    return { ok: false, skip: true, reason: `unknown sig_hash width: ${hashBits}` };
  }
  const r = limbsToBigInt(rLimbs, n);
  const s = limbsToBigInt(sLimbs, n);
  if (r === null || s === null) {
    return { ok: false, skip: true, reason: 'signature does not reassemble into a valid integer' };
  }
  let spkiDer;
  try {
    spkiDer = cert.key.export({ format: 'der', type: 'spki' });
  } catch (err) {
    return { ok: false, skip: true, reason: `could not export certificate key: ${err.message}` };
  }
  const point = extractEcPoint(spkiDer);
  if (!point) {
    return { ok: false, skip: true, reason: 'certificate key is not a readable EC point' };
  }
  const fieldBytes = point.x.length;
  const rBytes = bigIntToFixedBytes(r, fieldBytes);
  const sBytes = bigIntToFixedBytes(s, fieldBytes);
  if (!rBytes || !sBytes) {
    return { ok: false, skip: true, reason: 'signature scalar is wider than the curve field' };
  }
  const sigBytes = Buffer.concat([rBytes, sBytes]);
  let ok;
  try {
    ok = crypto.verify(hashName, message, { key: cert.key, dsaEncoding: 'ieee-p1363' }, sigBytes);
  } catch (err) {
    // A small, documented divergence from passport.rs/dsc.rs's ECDSA arm:
    // Rust distinguishes an off-curve key (Structural -> Skipped) from a
    // failed verification (Failed -> Invalid) because it reconstructs the
    // EC point from raw limbs, which can be off-curve. This module never
    // does that -- the point always comes from a real certificate that
    // OpenSSL's own X.509 parser accepted -- so that specific Structural
    // case does not arise the same way here. If `crypto.verify` still
    // throws (a malformed key/signature shape it cannot even attempt),
    // that is a structural uncertainty, not a circuit-equivalent failure.
    return { ok: false, skip: true, reason: `ECDSA verification threw: ${err.message}` };
  }
  if (!ok) {
    return { ok: false, skip: false, reason: 'ECDSA signature does not verify' };
  }
  return { ok: true };
}

/**
 * Dispatches to the right signature primitive for `scheme`. `sigLimbs` is
 * the full limb array as it arrives on the wire (a single `k`-limb integer
 * for RSA/RSA-PSS, `2k` limbs for ECDSA) -- the ECDSA split happens here,
 * with its own limb-count check first (mirrors passport.rs/dsc.rs's explicit
 * `sig_limbs.len() != 2 * k` guard, Skipped on mismatch, distinct from a
 * value that reassembles but does not verify).
 */
function verifySignatureLink(scheme, cert, hashBits, message, sigLimbs, n, k, saltLen) {
  if (scheme === 'rsa') {
    return verifyRsaPkcs1v15(cert, hashBits, message, sigLimbs, n);
  }
  if (scheme === 'rsapss') {
    return verifyRsaPss(cert, hashBits, message, sigLimbs, n, saltLen);
  }
  if (scheme === 'ecdsa') {
    if (sigLimbs.length !== 2 * k) {
      return {
        ok: false,
        skip: true,
        reason: `signature has ${sigLimbs.length} limbs, expected 2*k=${2 * k}`,
      };
    }
    return verifyEcdsa(cert, hashBits, message, sigLimbs.slice(0, k), sigLimbs.slice(k, 2 * k), n);
  }
  return { ok: false, skip: true, reason: `unsupported scheme: ${scheme}` };
}

// ---------------------------------------------------------------------
// Circuit-name parsing. Parses the name's own components (hash tags,
// scheme, exponent-or-curve) rather than building a table keyed by full
// circuit name, and never tries multiple algorithms to see which one
// verifies -- see this file's report for the (n, k) simplification this
// enables relative to params.rs's per-instance-file tables.
// ---------------------------------------------------------------------

const SHA_BITS = { sha1: 160, sha224: 224, sha256: 256, sha384: 384, sha512: 512 };

// Every current RSA and RSASSA-PSS register/register_id/DSC circuit uses
// these exact limb parameters (verified against params.rs's RSA_LIMBS,
// DSC_RSA_LIMBS, PSS_SALT_AND_KEY_LENGTH, and DSC_PSS_SALT_AND_KEY_LENGTH
// tables -- every single row in all four is `(120, 35)`), regardless of the
// actual RSA modulus size (2048/3072/4096 bits all fit in 35 limbs of 120
// bits with room to spare). A genuine circuit-wide constant, not a
// per-circuit-name table entry.
const RSA_N = 120;
const RSA_K = 35;

// (n, k) depends only on the curve, not on which circuit family uses it --
// confirmed identical across params.rs's ECDSA_LIMBS/ECDSA_BRAINPOOL_LIMBS
// (register family) and DSC_ECDSA_LIMBS/DSC_ECDSA_BRAINPOOL_LIMBS (DSC
// family) tables for every curve both cover. This is curve-intrinsic wire
// parameterization (how many 2^n-base limbs the circuit encodes each
// coordinate/scalar in), not a per-circuit-name lookup table -- 8 entries
// total, one per deployed curve, register and DSC alike.
const CURVE_PARAMS = {
  secp224r1: { n: 32, k: 7 },
  secp256r1: { n: 64, k: 4 },
  secp384r1: { n: 64, k: 6 },
  secp521r1: { n: 66, k: 8 },
  brainpoolP224r1: { n: 32, k: 7 },
  brainpoolP256r1: { n: 64, k: 4 },
  brainpoolP384r1: { n: 64, k: 6 },
  brainpoolP512r1: { n: 64, k: 8 },
};

/**
 * Parses the scheme-and-onward suffix of a circuit name -- `rsa_<e>_<bits>`,
 * `rsapss_<e>_<salt>_<bits>`, or `ecdsa_<curve>` -- starting at `parts[at]`.
 * Shared verbatim between the register family (`at = 3`, after the three
 * hash tags) and the DSC family (`at = 1`, after the single hash tag): the
 * scheme grammar itself does not differ between the two, only how many hash
 * components precede it.
 *
 * `e` and `bits` are validated (must parse as plain decimal integers) but
 * their *values* are intentionally unused: this module verifies with the
 * certificate's own key (see this file's report), so the circuit name's
 * claimed exponent/key-length never feeds into any cryptographic
 * calculation -- only `salt_len` (RSA-PSS) and the curve (ECDSA) do, since
 * those select real behaviour (the fixed salt length the circuit's own
 * padding assumes, and the limb width for reassembly) that the certificate
 * cannot supply by itself.
 *
 * @returns {{scheme:'rsa', n:number, k:number} |
 *   {scheme:'rsapss', n:number, k:number, saltLen:number} |
 *   {scheme:'ecdsa', curve:string, n:number, k:number} | null}
 */
function parseSchemeSuffix(parts, at) {
  const isDecimal = (s) => /^[0-9]+$/.test(s);
  const token = parts[at];
  if (token === 'rsa') {
    if (parts.length !== at + 3 || !isDecimal(parts[at + 1]) || !isDecimal(parts[at + 2])) {
      return null;
    }
    return { scheme: 'rsa', n: RSA_N, k: RSA_K };
  }
  if (token === 'rsapss') {
    if (parts.length !== at + 4 || !isDecimal(parts[at + 1]) || !isDecimal(parts[at + 2]) || !isDecimal(parts[at + 3])) {
      return null;
    }
    return { scheme: 'rsapss', n: RSA_N, k: RSA_K, saltLen: Number(parts[at + 2]) };
  }
  if (token === 'ecdsa') {
    if (parts.length !== at + 2) {
      return null;
    }
    const curve = parts[at + 1];
    const cp = CURVE_PARAMS[curve];
    if (!cp) {
      return null;
    }
    return { scheme: 'ecdsa', curve, n: cp.n, k: cp.k };
  }
  return null;
}

/**
 * Parses a circuit name into the family and scheme parameters this module's
 * verify functions need. `null` for anything unrecognized -- an unknown
 * circuit name is `Skipped` upstream, never a guess.
 *
 * Register/EU-ID names carry three hash tags (`register_<dg>_<econtent>_
 * <sig>_<scheme>...`); DSC names carry one (`dsc_<sig>_<scheme>...`) --
 * handled as two entirely separate branches (not a shared "split and hope"),
 * since assuming the register shape would misread every DSC name (e.g.
 * reading `"rsa"` as if it were the register grammar's 4th component).
 *
 * `register_aadhaar` and `register_kyc` are exact-name special cases with no
 * hash-tag suffix at all -- see `verifyAadhaar`'s and this file's report's
 * notes on KYC.
 *
 * @param {string} name
 * @returns {object | null}
 */
export function parseCircuitName(name) {
  if (name === 'register_kyc') {
    // KYC (EdDSA over BabyJubJub + Poseidon2) has no node:crypto-representable
    // scheme at all -- see this file's report. Recognized (not `null`, which
    // would read as "unknown circuit") so `verify` can report a specific,
    // honest skip reason rather than a generic one.
    return { family: 'kyc' };
  }
  if (name === 'register_aadhaar') {
    // register_aadhaar.circom instantiates REGISTER_AADHAAR(121, 17, ...) --
    // a different template with a different argument order than
    // REGISTER/REGISTER_ID, transcribed directly from params.rs's
    // register_aadhaar branch (n=121, k=17, fixed RSA-65537).
    return { family: 'aadhaar', sigHash: 256, scheme: 'rsa', n: 121, k: 17 };
  }
  if (name.startsWith('dsc_')) {
    const rest = name.slice('dsc_'.length);
    const parts = rest.split('_');
    if (parts.length < 2) {
      return null;
    }
    const sigHash = SHA_BITS[parts[0]];
    if (!sigHash) {
      return null;
    }
    const schemeInfo = parseSchemeSuffix(parts, 1);
    if (!schemeInfo) {
      return null;
    }
    return { family: 'dsc', sigHash, ...schemeInfo };
  }
  let rest;
  if (name.startsWith('register_id_')) {
    rest = name.slice('register_id_'.length);
  } else if (name.startsWith('register_')) {
    rest = name.slice('register_'.length);
  } else {
    return null;
  }
  const parts = rest.split('_');
  if (parts.length < 4) {
    return null;
  }
  const dgHash = SHA_BITS[parts[0]];
  const econtentHash = SHA_BITS[parts[1]];
  const sigHash = SHA_BITS[parts[2]];
  if (!dgHash || !econtentHash || !sigHash) {
    return null;
  }
  const schemeInfo = parseSchemeSuffix(parts, 3);
  if (!schemeInfo) {
    return null;
  }
  return { family: 'register', dgHash, econtentHash, sigHash, ...schemeInfo };
}

// ---------------------------------------------------------------------
// Register/EU-ID family: the three-link chain from passportVerifier.circom.
// ---------------------------------------------------------------------

/**
 * Verifies a `register_*`/`register_id_*` input. Four links, all required:
 *
 * 1. `sha(dg1)` equals `eContent[dg1_hash_offset .. +dg_hash/8]`.
 * 2. `sha(recoverMessage(eContent, eContent_padded_length))` equals
 *    `signed_attr[signed_attr_econtent_hash_offset .. +econtent_hash/8]`.
 * 3. `pubKey_dsc` equals the key embedded in `raw_dsc` at `dsc_pubKey_offset`
 *    (for `dsc_pubKey_actual_size` bytes) -- **not** checked by
 *    `src/verifier/passport.rs` today (see this file's report: passport.rs
 *    never reads `raw_dsc`/`dsc_pubKey_offset`/`dsc_pubKey_actual_size` at
 *    all, unlike `dsc.rs`'s analogous `csca_pubKey` link). This module adds
 *    it deliberately, mirroring `dsc.rs`'s own module doc verbatim --
 *    "without this link any key matching any signature passes" -- and per
 *    this task's own Step 1 test list, which requires exactly this mutation
 *    (`pubKey_dsc` no longer matching its certificate) to be `Invalid`. It
 *    never fires for a genuine document: the real circuit enforces this
 *    same link at `register.circom:102-135`, so `pubKey_dsc` always matches
 *    its embedded certificate for every real input, tampered or not
 *    otherwise. Closes a real (if narrow) gap without changing any verdict
 *    on real traffic. This is deliberately beyond `passport.rs`'s current
 *    scope: Task 3's differential gate may see this module return `Invalid`
 *    on a `pubKey_dsc`-tampered input where the Rust reference returns
 *    something else (or `Valid`, since `passport.rs` has no check to fail
 *    here at all) -- that is this decision working as intended, not a
 *    disagreement to resolve by removing the link.
 * 4. `signature_passport` verifies over
 *    `sha(recoverMessage(signed_attr, signed_attr_padded_length))` under the
 *    certificate's own key.
 *
 * @param {object} inputs
 * @param {object} p a `parseCircuitName` result with `family: 'register'`.
 */
function verifyRegisterFamily(inputs, p) {
  const dg1Strs = fieldAsStrings(inputs.dg1);
  if (!dg1Strs) {
    return skipped('missing or malformed field: dg1');
  }
  const dg1 = bytesFromDecimalStrings(dg1Strs);
  if (!dg1) {
    return skipped('dg1 contains a non-byte value');
  }
  const dg1HashOffset = scalarUsize(inputs.dg1_hash_offset);
  if (dg1HashOffset === null) {
    return skipped('missing or malformed field: dg1_hash_offset');
  }

  const econtentStrs = fieldAsStrings(inputs.eContent);
  if (!econtentStrs) {
    return skipped('missing or malformed field: eContent');
  }
  const econtent = bytesFromDecimalStrings(econtentStrs);
  if (!econtent) {
    return skipped('eContent contains a non-byte value');
  }
  const econtentPaddedLength = scalarUsize(inputs.eContent_padded_length);
  if (econtentPaddedLength === null) {
    return skipped('missing or malformed field: eContent_padded_length');
  }

  const signedAttrStrs = fieldAsStrings(inputs.signed_attr);
  if (!signedAttrStrs) {
    return skipped('missing or malformed field: signed_attr');
  }
  const signedAttr = bytesFromDecimalStrings(signedAttrStrs);
  if (!signedAttr) {
    return skipped('signed_attr contains a non-byte value');
  }
  const signedAttrPaddedLength = scalarUsize(inputs.signed_attr_padded_length);
  if (signedAttrPaddedLength === null) {
    return skipped('missing or malformed field: signed_attr_padded_length');
  }
  const saEcontentHashOffset = scalarUsize(inputs.signed_attr_econtent_hash_offset);
  if (saEcontentHashOffset === null) {
    return skipped('missing or malformed field: signed_attr_econtent_hash_offset');
  }

  const pubkeyLimbs = fieldAsStrings(inputs.pubKey_dsc);
  if (!pubkeyLimbs) {
    return skipped('missing or malformed field: pubKey_dsc');
  }
  const sigLimbs = fieldAsStrings(inputs.signature_passport);
  if (!sigLimbs) {
    return skipped('missing or malformed field: signature_passport');
  }

  const rawDscStrs = fieldAsStrings(inputs.raw_dsc);
  if (!rawDscStrs) {
    return skipped('missing or malformed field: raw_dsc');
  }
  const rawDsc = bytesFromDecimalStrings(rawDscStrs);
  if (!rawDsc) {
    return skipped('raw_dsc contains a non-byte value');
  }
  const rawDscActualLength = scalarUsize(inputs.raw_dsc_actual_length);
  if (rawDscActualLength === null) {
    return skipped('missing or malformed field: raw_dsc_actual_length');
  }
  const dscPubKeyOffset = scalarUsize(inputs.dsc_pubKey_offset);
  if (dscPubKeyOffset === null) {
    return skipped('missing or malformed field: dsc_pubKey_offset');
  }
  const dscPubKeyActualSize = scalarUsize(inputs.dsc_pubKey_actual_size);
  if (dscPubKeyActualSize === null) {
    return skipped('missing or malformed field: dsc_pubKey_actual_size');
  }

  // --- offset bounds, passportVerifier.circom:53-66: violation => Invalid ---
  const dgHashLen = p.dgHash / 8;
  const dgReason = checkOffsetRangeInvalid(dg1HashOffset, dgHashLen, econtentPaddedLength, 'dg1_hash_offset');
  if (dgReason) {
    return invalid(dgReason);
  }
  const ecHashLen = p.econtentHash / 8;
  const ecReason = checkOffsetRangeInvalid(
    saEcontentHashOffset,
    ecHashLen,
    signedAttrPaddedLength,
    'signed_attr_econtent_hash_offset',
  );
  if (ecReason) {
    return invalid(ecReason);
  }

  // --- link 1: sha(dg1) == eContent[dg1_hash_offset .. +dg_hash/8] ---
  const dg1Digest = digestBuffer(p.dgHash, dg1);
  if (!dg1Digest) {
    return skipped(`unknown dg_hash width: ${p.dgHash}`);
  }
  if (dg1HashOffset + dgHashLen > econtent.length) {
    return skipped('eContent is shorter than dg1_hash_offset + dg_hash/8 declares');
  }
  const econtentWindow = econtent.subarray(dg1HashOffset, dg1HashOffset + dgHashLen);
  if (Buffer.compare(dg1Digest, econtentWindow) !== 0) {
    return invalid('dg1 hash does not match eContent at dg1_hash_offset');
  }

  // --- link 2: sha(recoverMessage(eContent)) == signed_attr window ---
  const econtentMsg = recoverMessage(econtent, econtentPaddedLength);
  if (!econtentMsg) {
    return skipped('eContent padding is malformed or inconsistent with eContent_padded_length');
  }
  const econtentDigest = digestBuffer(p.econtentHash, econtentMsg);
  if (!econtentDigest) {
    return skipped(`unknown econtent_hash width: ${p.econtentHash}`);
  }
  if (saEcontentHashOffset + ecHashLen > signedAttr.length) {
    return skipped('signed_attr is shorter than signed_attr_econtent_hash_offset + econtent_hash/8 declares');
  }
  const signedAttrWindow = signedAttr.subarray(saEcontentHashOffset, saEcontentHashOffset + ecHashLen);
  if (Buffer.compare(econtentDigest, signedAttrWindow) !== 0) {
    return invalid('eContent hash does not match signed_attr at signed_attr_econtent_hash_offset');
  }

  // --- link 3: pubKey_dsc must equal the key embedded in raw_dsc's certificate ---
  // (see this function's doc comment for why this link exists here even
  // though passport.rs itself does not check it)
  if (!offsetInRangeSkip(dscPubKeyOffset, dscPubKeyActualSize, rawDscActualLength)) {
    return skipped(
      `dsc_pubKey_offset (${dscPubKeyOffset}) + dsc_pubKey_actual_size (${dscPubKeyActualSize}) is out of range for raw_dsc_actual_length (${rawDscActualLength})`,
    );
  }
  if (rawDscActualLength > rawDsc.length) {
    return skipped('raw_dsc is shorter than raw_dsc_actual_length declares');
  }
  const dscTbs = rawDsc.subarray(0, rawDscActualLength);
  const dscCert = certPublicKey(wrapAsCertificate(dscTbs));
  if (!dscCert) {
    return skipped('raw_dsc does not parse as a readable certificate');
  }
  const keyScheme = p.scheme === 'ecdsa' ? 'ecdsa' : 'rsa';
  // Mirrors passport.rs's/dsc.rs's explicit `pubkey_limbs.len() != 2 * k`
  // ECDSA guard (Skipped, distinct from a value that reassembles but
  // mismatches). RSA/RSA-PSS has no analogous check in the Rust reference
  // either (see this file's report), so none is added here.
  if (keyScheme === 'ecdsa' && pubkeyLimbs.length !== 2 * p.k) {
    return skipped(`pubKey_dsc has ${pubkeyLimbs.length} limbs, expected 2*k=${2 * p.k}`);
  }
  if (!keyMatchesCert(pubkeyLimbs, p.n, p.k, dscCert, keyScheme)) {
    return invalid('pubKey_dsc does not match the certificate embedded in raw_dsc at dsc_pubKey_offset');
  }

  // --- link 4: signature_passport verifies over sha(recoverMessage(signed_attr)) under the certificate's key ---
  const signedAttrMsg = recoverMessage(signedAttr, signedAttrPaddedLength);
  if (!signedAttrMsg) {
    return skipped('signed_attr padding is malformed or inconsistent with signed_attr_padded_length');
  }
  const result = verifySignatureLink(p.scheme, dscCert, p.sigHash, signedAttrMsg, sigLimbs, p.n, p.k, p.saltLen);
  if (!result.ok) {
    return result.skip ? skipped(result.reason) : invalid(result.reason);
  }

  return valid();
}

// ---------------------------------------------------------------------
// DSC family: the one-link chain from dsc.circom (a CSCA signing a DSC).
// ---------------------------------------------------------------------

/**
 * Verifies a `dsc_*` input. Two links, both required:
 *
 * 1. `csca_pubKey` equals the key embedded in `raw_csca` at
 *    `csca_pubKey_offset` (for `csca_pubKey_actual_size` bytes) --
 *    `dsc.circom:171-192`, the link that makes this more than a bare
 *    signature check.
 * 2. `signature` verifies over `sig_hash(recoverMessage(raw_dsc,
 *    raw_dsc_padded_length))` under the certificate's own key.
 *
 * Link 1 is checked, and can return `Invalid`, strictly before any
 * signature-related parsing -- mirrors dsc.rs's ordering guarantee that a
 * corrupted `csca_pubKey` is always reported as a certificate-key mismatch,
 * never mistaken for (or masked by) a signature failure.
 *
 * `dg_hash`/`econtent_hash` are meaningless for this family (a CSCA signing
 * a DSC has no dg1<->eContent<->signed_attr chain at all) and are never read
 * here -- `p.sigHash` is the only hash width this function uses.
 */
function verifyDscFamily(inputs, p) {
  const rawCscaStrs = fieldAsStrings(inputs.raw_csca);
  if (!rawCscaStrs) {
    return skipped('missing or malformed field: raw_csca');
  }
  const rawCsca = bytesFromDecimalStrings(rawCscaStrs);
  if (!rawCsca) {
    return skipped('raw_csca contains a non-byte value');
  }
  const rawCscaActualLength = scalarUsize(inputs.raw_csca_actual_length);
  if (rawCscaActualLength === null) {
    return skipped('missing or malformed field: raw_csca_actual_length');
  }
  const cscaPubkeyOffset = scalarUsize(inputs.csca_pubKey_offset);
  if (cscaPubkeyOffset === null) {
    return skipped('missing or malformed field: csca_pubKey_offset');
  }
  const cscaPubkeyActualSize = scalarUsize(inputs.csca_pubKey_actual_size);
  if (cscaPubkeyActualSize === null) {
    return skipped('missing or malformed field: csca_pubKey_actual_size');
  }

  const rawDscStrs = fieldAsStrings(inputs.raw_dsc);
  if (!rawDscStrs) {
    return skipped('missing or malformed field: raw_dsc');
  }
  const rawDsc = bytesFromDecimalStrings(rawDscStrs);
  if (!rawDsc) {
    return skipped('raw_dsc contains a non-byte value');
  }
  const rawDscPaddedLength = scalarUsize(inputs.raw_dsc_padded_length);
  if (rawDscPaddedLength === null) {
    return skipped('missing or malformed field: raw_dsc_padded_length');
  }

  const pubkeyLimbs = fieldAsStrings(inputs.csca_pubKey);
  if (!pubkeyLimbs) {
    return skipped('missing or malformed field: csca_pubKey');
  }
  const sigLimbs = fieldAsStrings(inputs.signature);
  if (!sigLimbs) {
    return skipped('missing or malformed field: signature');
  }

  // --- offset bounds, dsc.circom:110-127: violation => Skipped (see this
  // section's module doc on why this is Skipped, not Invalid, unlike the
  // register family's dg1/eContent offsets) ---
  if (!offsetInRangeSkip(cscaPubkeyOffset, cscaPubkeyActualSize, rawCscaActualLength)) {
    return skipped(
      `csca_pubKey_offset (${cscaPubkeyOffset}) + csca_pubKey_actual_size (${cscaPubkeyActualSize}) is out of range for raw_csca_actual_length (${rawCscaActualLength})`,
    );
  }
  if (rawCscaActualLength > rawCsca.length) {
    return skipped('raw_csca is shorter than raw_csca_actual_length declares');
  }

  // --- link 1: csca_pubKey must equal the key embedded in raw_csca's certificate ---
  const cscaTbs = rawCsca.subarray(0, rawCscaActualLength);
  const cscaCert = certPublicKey(wrapAsCertificate(cscaTbs));
  if (!cscaCert) {
    return skipped('raw_csca does not parse as a readable certificate');
  }
  const keyScheme = p.scheme === 'ecdsa' ? 'ecdsa' : 'rsa';
  if (p.scheme === 'ecdsa' && pubkeyLimbs.length !== 2 * p.k) {
    return skipped(`csca_pubKey has ${pubkeyLimbs.length} limbs, expected 2*k=${2 * p.k}`);
  }
  if (!keyMatchesCert(pubkeyLimbs, p.n, p.k, cscaCert, keyScheme)) {
    return invalid('csca_pubKey does not match the certificate embedded in raw_csca at csca_pubKey_offset');
  }

  // --- link 2: signature verifies over sig_hash(recoverMessage(raw_dsc)) under the certificate's key ---
  const rawDscMsg = recoverMessage(rawDsc, rawDscPaddedLength);
  if (!rawDscMsg) {
    return skipped('raw_dsc padding is malformed or inconsistent with raw_dsc_padded_length');
  }
  const result = verifySignatureLink(p.scheme, cscaCert, p.sigHash, rawDscMsg, sigLimbs, p.n, p.k, p.saltLen);
  if (!result.ok) {
    return result.skip ? skipped(result.reason) : invalid(result.reason);
  }

  return valid();
}

// ---------------------------------------------------------------------
// Aadhaar: one hash, one RSA verify, no chain at all (register_aadhaar.circom
// has no dg1/eContent/signed_attr concept -- see aadhaar.rs's module doc).
// No certificate exists for this family either; `pubKey` is used directly,
// reconstructed into a real `KeyObject` so node:crypto -- not a hand-rolled
// modexp -- performs the actual verification.
// ---------------------------------------------------------------------

function verifyAadhaar(inputs, p) {
  const qrStrs = fieldAsStrings(inputs.qrDataPadded);
  if (!qrStrs) {
    return skipped('missing or malformed field: qrDataPadded');
  }
  const qrPadded = bytesFromDecimalStrings(qrStrs);
  if (!qrPadded) {
    return skipped('qrDataPadded contains a non-byte value');
  }
  const qrPaddedLen = scalarUsize(inputs.qrDataPaddedLength);
  if (qrPaddedLen === null) {
    return skipped('missing or malformed field: qrDataPaddedLength');
  }

  const pubkeyLimbs = fieldAsStrings(inputs.pubKey);
  if (!pubkeyLimbs) {
    return skipped('missing or malformed field: pubKey');
  }
  const modulus = limbsToBigInt(pubkeyLimbs, p.n);
  if (modulus === null) {
    return skipped('pubKey does not reassemble into a valid integer');
  }

  const sigLimbs = fieldAsStrings(inputs.signature);
  if (!sigLimbs) {
    return skipped('missing or malformed field: signature');
  }
  const signature = limbsToBigInt(sigLimbs, p.n);
  if (signature === null) {
    return skipped('signature does not reassemble into a valid integer');
  }

  const qrMsg = recoverMessage(qrPadded, qrPaddedLen);
  if (!qrMsg) {
    return skipped('qrDataPadded padding is malformed or inconsistent with qrDataPaddedLength');
  }

  // params.rs's register_aadhaar branch fixes the modulus at 2048 bits
  // (Scheme::Rsa{e:65537,bits:2048}) -- 256 bytes.
  const modulusBytes = bigIntToFixedBytes(modulus, 256);
  if (!modulusBytes) {
    return skipped('pubKey is wider than the expected 2048-bit Aadhaar modulus');
  }
  const sigBytes = bigIntToFixedBytes(signature, 256);
  if (!sigBytes) {
    return skipped('signature is wider than the expected 2048-bit Aadhaar modulus');
  }

  let publicKey;
  try {
    publicKey = crypto.createPublicKey({
      key: { kty: 'RSA', n: modulusBytes.toString('base64url'), e: Buffer.from([0x01, 0x00, 0x01]).toString('base64url') },
      format: 'jwk',
    });
  } catch (err) {
    return skipped(`pubKey does not form a usable RSA key: ${err.message}`);
  }

  let ok;
  try {
    ok = crypto.verify('sha256', qrMsg, { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, sigBytes);
  } catch (err) {
    return skipped(`RSA verification threw: ${err.message}`);
  }
  if (!ok) {
    return invalid('Aadhaar signature does not verify');
  }
  return valid();
}

// ---------------------------------------------------------------------
// Top-level dispatch and the stdin/stdout CLI contract.
// ---------------------------------------------------------------------

/**
 * Verifies `inputs` (already-parsed circuit-input JSON) against
 * `circuitName`, returning `{verdict:'valid'}`, `{verdict:'invalid',
 * reason}`, or `{verdict:'skipped', reason}`. Never throws.
 *
 * `register_kyc` (EdDSA over BabyJubJub + Poseidon2) is recognized but always
 * `Skipped`: neither `node:crypto` nor any dependency this module is allowed
 * (zero, by constraint) can verify that scheme. This has no practical effect
 * on production dispatch either way -- `src/verifier/mod.rs`'s `dispatch`
 * matches `register_kyc` before the generic `register` prefix and routes it
 * straight to the native Rust `kyc::verify`, in every version of this plan,
 * including after Task 4 (whose own brief says so explicitly: "KYC stays").
 * This module is simply never invoked with that circuit name in production.
 *
 * @param {string} circuitName
 * @param {unknown} inputs
 * @returns {{verdict:'valid'} | {verdict:'invalid'|'skipped', reason:string}}
 */
export function verify(circuitName, inputs) {
  if (typeof inputs !== 'object' || inputs === null || Array.isArray(inputs)) {
    return skipped('input.json is not a JSON object');
  }
  const p = parseCircuitName(circuitName);
  if (!p) {
    return skipped(`unknown or unsupported circuit: ${circuitName}`);
  }
  if (p.family === 'kyc') {
    return skipped(
      'register_kyc uses EdDSA over BabyJubJub + Poseidon2, which this node:crypto-only verifier cannot check; ' +
        'production dispatch never routes this circuit to this verifier either (it is handled natively in Rust)',
    );
  }
  if (p.family === 'aadhaar') {
    return verifyAadhaar(inputs, p);
  }
  if (p.family === 'dsc') {
    return verifyDscFamily(inputs, p);
  }
  if (p.family === 'register') {
    return verifyRegisterFamily(inputs, p);
  }
  return skipped(`unhandled circuit family for ${circuitName}`);
}

function writeVerdict(result) {
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

/**
 * The CLI entrypoint Task 4's Rust client drives:
 * `stdin: {"circuit":"...","inputPath":"/tmp/.../input.json"}`, `stdout` one
 * JSON verdict line. Exit 0 whenever a verdict was written -- which is
 * always, short of stdin itself being unreadable -- reserving a non-zero
 * exit for a genuinely unexpected failure (see this file's report).
 */
function main() {
  let requestRaw;
  try {
    requestRaw = fs.readFileSync(0, 'utf8');
  } catch (err) {
    process.stderr.write(`could not read stdin: ${err.message}\n`);
    process.exitCode = 1;
    return;
  }

  try {
    let request;
    try {
      request = JSON.parse(requestRaw);
    } catch (err) {
      writeVerdict(skipped(`stdin is not valid JSON: ${err.message}`));
      return;
    }
    if (
      typeof request !== 'object' ||
      request === null ||
      typeof request.circuit !== 'string' ||
      typeof request.inputPath !== 'string'
    ) {
      writeVerdict(skipped('stdin JSON must be an object with string "circuit" and "inputPath" fields'));
      return;
    }

    let inputsRaw;
    try {
      inputsRaw = fs.readFileSync(request.inputPath, 'utf8');
    } catch (err) {
      writeVerdict(skipped(`could not read inputPath: ${err.message}`));
      return;
    }
    let inputs;
    try {
      inputs = JSON.parse(inputsRaw);
    } catch (err) {
      writeVerdict(skipped(`inputPath is not valid JSON: ${err.message}`));
      return;
    }

    writeVerdict(verify(request.circuit, inputs));
  } catch (err) {
    // Belt-and-braces: every function this module calls is documented to
    // return null/false/a verdict rather than throw, but a top-level catch
    // here means a bug in that discipline still produces a verdict (Skipped)
    // instead of a crash with no output at all -- see the contract's "exit 0
    // whenever a verdict was written" requirement.
    writeVerdict(skipped(`unexpected error: ${err && err.message ? err.message : String(err)}`));
  }
}

// Only run the CLI when this file is executed directly (`node verify.mjs`),
// not when imported by the test suite.
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main();
}
