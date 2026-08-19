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
// This module is RFC-strict rather than circuit-matching. Its verdict is
// authoritative: the enclave signs no proof for anything but `valid`, so a
// false accept and a false reject are both real costs, and where they
// conflict this module rejects. That is a deliberate change from an earlier
// design in which the verdict was only an optimization hint and this module
// was built to mirror the circuit's behaviour wherever the two differed.
// Two places where being RFC-strict rather than circuit-matching matters:
//
//   - RSA-PSS (`verifyRsaPss`): native `crypto.verify`/OpenSSL enforces RFC
//     8017 SS9.1.2 step 9 (maskedDB's leftmost bits must be zero), where
//     rsapss65537.circom:162 clears that bit instead of checking it. See
//     `verifyRsaPss`'s doc comment for why this needed no code change here
//     -- OpenSSL was already strict by construction -- and
//     `verify.test.mjs`'s "RFC 8017 leftmost-bit PSS forgery" suite for the
//     negative vector proving it. A reader tempted to "fix" this by
//     reintroducing a hand-rolled BigInt/MGF1 PSS decode should read
//     `verifyRsaPss`'s doc comment first -- that would undo a deliberate
//     simplification, not restore correctness.
//   - Off-curve ECDSA keys (`certPublicKeyOrInvalidReason`): ecdsa.circom
//     never checks the curve equation at all (ecdsa.circom:18-102), so an
//     off-curve point was previously `Skipped` (mirroring the circuit's
//     blind spot) rather than rejected. This module now reports `Invalid`,
//     naming the curve, when a certificate's ASN.1 structure parses but
//     OpenSSL refuses to build a `KeyObject` from its embedded key -- see
//     that function's doc comment and `verify.test.mjs`'s "an off-curve
//     embedded public key" suite.
//
// Every other check in this file continues to follow the discipline
// established above: `Skipped` means "cannot be certain, so forward to
// proving" (an honest coverage gap, not a rejection); `Invalid` is reserved
// for an affirmative cryptographic or structural failure this module can
// actually stand behind. What changed is which failures qualify as
// affirmative -- the RFC's definition, not the circuit's, going forward.

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
 * Extracts the RSA modulus (`n`, a big-endian `Buffer`, no leading-zero pad
 * byte) directly from a SubjectPublicKeyInfo DER buffer, without ever
 * calling `KeyObject.export({format:'jwk'})` -- which throws `Unsupported
 * JWK Key Type` for an `id-RSASSA-PSS` key (see this file's report and
 * `keyMatchesCert`'s RSA branch, which used to rely on JWK and so
 * false-rejected every real `id-RSASSA-PSS` SPKI certificate).
 * `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
 * lives inside the SPKI's `BIT STRING`, identically encoded regardless of
 * which SPKI `AlgorithmIdentifier` (`rsaEncryption` or `id-RSASSA-PSS`)
 * wraps it -- the two share one key format, differing only in which
 * signature scheme the private key is permitted to use.
 *
 * Returns `null` for anything unexpected: a malformed outer structure, a
 * BIT STRING with nonzero unused-bits, or a modulus that is not a DER
 * INTEGER.
 *
 * @param {Buffer} spkiDer
 * @returns {Buffer | null}
 */
function extractRsaModulus(spkiDer) {
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
  if (bitstr.content[0] !== 0) {
    return null; // nonzero unused-bits
  }
  const rsaPublicKey = readDerTLV(bitstr.content, 1);
  if (!rsaPublicKey || rsaPublicKey.tag !== 0x30) {
    return null;
  }
  const modulusTlv = readDerTLV(rsaPublicKey.content, 0);
  if (!modulusTlv || modulusTlv.tag !== 0x02) {
    return null;
  }
  // stripDerIntegerPad (defined further down, alongside the SPKI algorithm
  // classifier that also needs it) removes the leading 0x00 pad byte DER
  // INTEGER encoding adds only when needed to keep the value positive, so
  // the result is the plain unsigned big-endian modulus -- matching the
  // convention `bigIntToFixedBytes`/`Buffer.compare` below already expect
  // (the same convention the old JWK `n` field gave). Referencing it here,
  // before its declaration further down, is safe: this function is never
  // called until verify() runs, well after module evaluation completes.
  return stripDerIntegerPad(modulusTlv.content);
}

// ---------------------------------------------------------------------
// SPKI algorithm classification -- decides WHY OpenSSL refused to build a
// KeyObject for an embedded public key (certPublicKeyOrInvalidReason,
// below), never used to perform verification itself.
//
// `X509Certificate`'s constructor parses DER *structure* only.
// `cert.publicKey` is where OpenSSL actually builds an `EVP_PKEY`, and
// EVERYTHING semantic about the key -- including an algorithm identifier
// this OpenSSL build has no implementation for at all -- throws there,
// with the same generic `"decode error"` a genuinely invalid key produces.
// Verified empirically: flipping one byte of the SPKI `AlgorithmIdentifier`
// OID in a real `raw_dsc` (leaving the rest of the ASN.1 structure intact)
// makes `cert.publicKey` throw for both an RSA and an ECDSA fixture, with
// the exact same error OpenSSL gives for an off-curve point (this file's
// report). Distinguishing "we don't recognise this algorithm" from "we
// recognise it and the key is bad anyway" requires reading the SPKI's own
// `AlgorithmIdentifier` OID directly, independent of whatever OpenSSL made
// of it.
// ---------------------------------------------------------------------

const ID_EC_PUBLIC_KEY_OID = '1.2.840.10045.2.1';
const ID_RSA_ENCRYPTION_OID = '1.2.840.113549.1.1.1';
const PRIME_FIELD_OID = '1.2.840.10045.1.1'; // ANSI X9.62 prime-field fieldType

// OID -> curve name, matching node:crypto's own `namedCurve` strings (and
// `CURVE_PARAMS`'s keys, defined later in this file). Values verified
// empirically: generating a real key for each curve and inspecting its
// exported SPKI DER (this file's report).
const CURVE_OID_TO_NAME = {
  '1.3.132.0.33': 'secp224r1',
  '1.2.840.10045.3.1.7': 'secp256r1',
  '1.3.132.0.34': 'secp384r1',
  '1.3.132.0.35': 'secp521r1',
  '1.3.36.3.3.2.8.1.1.5': 'brainpoolP224r1',
  '1.3.36.3.3.2.8.1.1.7': 'brainpoolP256r1',
  '1.3.36.3.3.2.8.1.1.11': 'brainpoolP384r1',
  '1.3.36.3.3.2.8.1.1.13': 'brainpoolP512r1',
};

// Field prime (hex, no leading-zero pad byte) -> curve name, for EC keys
// that encode their domain parameters EXPLICITLY (`ECParameters`) rather
// than via the named-curve OID shortcut above. This is not a hypothetical:
// this repo's own `register_ecdsa_secp256r1.json` fixture's `raw_dsc` does
// exactly this for a perfectly valid, on-curve secp256r1 key (verified
// while building this fix -- its SPKI `AlgorithmIdentifier` parameters are
// an `ECParameters` SEQUENCE, not an OID), and this plan's own design doc
// flags explicit domain parameters as a real-world DSC pattern. Treating
// every explicit encoding as "unrecognized" would silently reopen the exact
// off-curve vulnerability this plan closes for any DSC using this fully
// standard, OpenSSL-supported encoding: an off-curve point behind explicit
// parameters would report Skipped (uncertain) rather than Invalid, and
// nothing else in this module checks curve membership either. The field
// prime is unique across our 8 supported curves, so matching it is a
// reliable fingerprint without needing to compare the full parameter set
// (generator point, order, cofactor). Values verified empirically via
// `openssl ecparam -name <curve> -param_enc explicit -text` for each of the
// 8 curves (this file's report).
const CURVE_PRIME_HEX_TO_NAME = {
  'ffffffffffffffffffffffffffffffff000000000000000000000001': 'secp224r1',
  'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff': 'secp256r1',
  'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff': 'secp384r1',
  '01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff':
    'secp521r1',
  'd7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff': 'brainpoolP224r1',
  'a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377': 'brainpoolP256r1',
  '8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53': 'brainpoolP384r1',
  'aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3':
    'brainpoolP512r1',
};

/**
 * Decodes a DER OBJECT IDENTIFIER's raw content bytes (no tag/length) into
 * its dotted-decimal string, e.g. `[0x2a,0x86,0x48,...]` -> `"1.2.840..."`.
 * The first byte encodes the first two arcs (`40*X + Y`); every byte after
 * that is a base-128 value, continued across bytes while the high bit is
 * set. A truncated trailing value (the final byte still has its
 * continuation bit set) is simply dropped rather than thrown on -- this is
 * only ever used to compare against a small fixed set of known-good
 * dotted strings (below), so a malformed encoding just fails to match any
 * of them, which is the correct (unrecognized) outcome either way.
 *
 * @param {Buffer} bytes
 * @returns {string | null} null for an empty input.
 */
function oidBytesToDotted(bytes) {
  if (!bytes || bytes.length === 0) {
    return null;
  }
  const first = bytes[0];
  const x = first < 80 ? Math.floor(first / 40) : 2;
  const parts = [x, first - 40 * x];
  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    value = value * 128 + (bytes[i] & 0x7f);
    if ((bytes[i] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

/**
 * Finds the `SubjectPublicKeyInfo` field inside an already-parsed
 * `TBSCertificate`'s content (the bytes inside its outer `SEQUENCE`, i.e.
 * `version`, `serialNumber`, `signature`, `issuer`, `validity`, `subject`,
 * `subjectPublicKeyInfo`, ...). Rather than counting fields (the `version`
 * field is `OPTIONAL` and context-tagged, so its presence shifts every
 * later field's index), this scans each top-level element for the one
 * whose *shape* is unambiguously `SubjectPublicKeyInfo ::= SEQUENCE {
 * AlgorithmIdentifier, BIT STRING }` -- a SEQUENCE containing exactly two
 * children, a nested SEQUENCE (`AlgorithmIdentifier`) whose own first
 * child is an OBJECT IDENTIFIER, followed immediately by a BIT STRING that
 * accounts for the rest of the outer SEQUENCE's content. No other
 * `TBSCertificate` field matches that shape: `issuer`/`subject` are
 * `SEQUENCE OF SET`, not `SEQUENCE OF SEQUENCE`; `validity` is a `SEQUENCE`
 * of two `Time` values (`UTCTime`/`GeneralizedTime`, tags `0x17`/`0x18`,
 * not `0x30`); `signature` (the TBS's own `AlgorithmIdentifier`) is a bare
 * `AlgorithmIdentifier`, not one wrapped in an outer `SEQUENCE` alongside a
 * `BIT STRING`.
 *
 * @param {Buffer} tbsContent
 * @returns {{algorithmContent: Buffer, oid: Buffer, afterOidOffset: number} | null}
 */
function findSubjectPublicKeyInfo(tbsContent) {
  let offset = 0;
  while (offset < tbsContent.length) {
    const tlv = readDerTLV(tbsContent, offset);
    if (!tlv) {
      return null;
    }
    if (tlv.tag === 0x30) {
      const alg = readDerTLV(tlv.content, 0);
      if (alg && alg.tag === 0x30) {
        const bitstr = readDerTLV(tlv.content, alg.nextOffset);
        if (bitstr && bitstr.tag === 0x03 && bitstr.nextOffset === tlv.content.length) {
          const oidTlv = readDerTLV(alg.content, 0);
          if (oidTlv && oidTlv.tag === 0x06) {
            return { algorithmContent: alg.content, oid: oidTlv.content, afterOidOffset: oidTlv.nextOffset };
          }
        }
      }
    }
    offset = tlv.nextOffset;
  }
  return null;
}

/**
 * Strips a DER INTEGER's leading `0x00` pad byte, if present. DER INTEGER
 * encoding prepends exactly one such byte only when needed to keep the
 * value positive (i.e. when the following byte's own high bit is set) --
 * removing it yields the plain unsigned big-endian value.
 *
 * @param {Buffer} bytes
 * @returns {Buffer}
 */
function stripDerIntegerPad(bytes) {
  if (bytes.length > 1 && bytes[0] === 0x00 && (bytes[1] & 0x80) !== 0) {
    return bytes.subarray(1);
  }
  return bytes;
}

/**
 * Matches an explicit `ECParameters` DER structure's field prime against
 * `CURVE_PRIME_HEX_TO_NAME`, returning the curve name if it matches one of
 * our 8 supported curves' prime exactly, `null` otherwise (a genuinely
 * unsupported/custom curve, a binary/char-2 field -- none of our curves use
 * one -- or a structure this reader cannot parse).
 *
 * `ECParameters ::= SEQUENCE { version INTEGER, fieldID SEQUENCE { fieldType
 * OBJECT IDENTIFIER, parameters ANY }, curve ..., base ..., order ...,
 * cofactor ... }` -- only `version` and `fieldID` are read; everything after
 * (the curve coefficients, generator point, order, cofactor) is unused,
 * since the field prime alone is already a unique fingerprint across our 8
 * supported curves.
 *
 * @param {Buffer} paramsContent the content of the explicit ECParameters SEQUENCE.
 * @returns {string | null}
 */
function matchExplicitPrimeFieldCurve(paramsContent) {
  const version = readDerTLV(paramsContent, 0);
  if (!version || version.tag !== 0x02) {
    return null;
  }
  const fieldId = readDerTLV(paramsContent, version.nextOffset);
  if (!fieldId || fieldId.tag !== 0x30) {
    return null;
  }
  const fieldType = readDerTLV(fieldId.content, 0);
  if (!fieldType || fieldType.tag !== 0x06 || oidBytesToDotted(fieldType.content) !== PRIME_FIELD_OID) {
    return null;
  }
  const primeTlv = readDerTLV(fieldId.content, fieldType.nextOffset);
  if (!primeTlv || primeTlv.tag !== 0x02) {
    return null;
  }
  const prime = stripDerIntegerPad(primeTlv.content);
  return CURVE_PRIME_HEX_TO_NAME[prime.toString('hex')] || null;
}

/**
 * Classifies the SPKI algorithm actually embedded in `certificateDer` (a
 * full DER `Certificate`, e.g. from `wrapAsCertificate`), independent of
 * whatever `cert.publicKey` made of it. Used only when the getter has
 * already thrown -- never to perform verification itself.
 *
 * `recognized: true` means this module has a working `crypto.verify` path
 * for the algorithm (`rsaEncryption`, or `id-ecPublicKey` with a curve this
 * file's `CURVE_PARAMS` table covers, named OR explicitly encoded) -- so if
 * OpenSSL still refuses the key, the key material itself is the problem,
 * not our coverage. `recognized: false` covers everything else: an
 * algorithm this build has no path for at all (`id-RSASSA-PSS` at the SPKI
 * level, DSA, GOST, ...), or a curve (named or explicit) this module does
 * not carry limb parameters for -- in every one of these cases OpenSSL's
 * throw tells us nothing about whether the key material itself is valid.
 *
 * @param {Buffer} certificateDer
 * @returns {{recognized: true, curve?: string, description: string} |
 *   {recognized: false, description: string}}
 */
function classifySpkiAlgorithm(certificateDer) {
  const outer = readDerTLV(certificateDer, 0);
  if (!outer || outer.tag !== 0x30) {
    return { recognized: false, description: 'certificate structure unreadable' };
  }
  const tbs = readDerTLV(outer.content, 0);
  if (!tbs || tbs.tag !== 0x30) {
    return { recognized: false, description: 'tbsCertificate unreadable' };
  }
  const spki = findSubjectPublicKeyInfo(tbs.content);
  if (!spki) {
    return { recognized: false, description: 'subjectPublicKeyInfo not found in tbsCertificate' };
  }
  const algOid = oidBytesToDotted(spki.oid);
  if (algOid === ID_RSA_ENCRYPTION_OID) {
    return { recognized: true, description: 'rsaEncryption' };
  }
  if (algOid === ID_EC_PUBLIC_KEY_OID) {
    const params = readDerTLV(spki.algorithmContent, spki.afterOidOffset);
    let curve;
    let unrecognizedDetail;
    if (params && params.tag === 0x06) {
      const curveOid = oidBytesToDotted(params.content);
      curve = CURVE_OID_TO_NAME[curveOid];
      unrecognizedDetail = curve ? null : `unrecognized curve OID ${curveOid}`;
    } else if (params && params.tag === 0x30) {
      // Explicit domain parameters, not the named-curve OID shortcut --
      // verified present in this repo's own register_ecdsa_secp256r1.json
      // fixture (see CURVE_PRIME_HEX_TO_NAME's doc comment). Matched by
      // field prime, not rejected outright.
      curve = matchExplicitPrimeFieldCurve(params.content);
      unrecognizedDetail = curve ? null : 'explicit curve parameters that do not match a supported curve';
    } else {
      unrecognizedDetail = 'curve parameters this reader cannot decode';
    }
    // CURVE_PARAMS is declared later in this file, but this function is
    // never invoked until verify() runs, well after module evaluation
    // completes, so this forward reference is safe.
    if (curve && CURVE_PARAMS[curve]) {
      return { recognized: true, curve, description: `id-ecPublicKey / ${curve}` };
    }
    return { recognized: false, description: `id-ecPublicKey with ${unrecognizedDetail}` };
  }
  return { recognized: false, description: `unsupported SPKI algorithm OID ${algOid || '(unreadable)'}` };
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
// certPublicKeyOrInvalidReason -- Task 1 (Plan B) addition. Same parse as
// certPublicKey, but distinguishes WHY no key came out, because the
// reasons now get different verdicts (RFC-strict, not circuit-mirroring):
// a structurally unparseable certificate is still Skipped (uncertain,
// unchanged from Plan A); a certificate that parses fine as ASN.1 and whose
// embedded SPKI names an algorithm this module supports (rsaEncryption, or
// id-ecPublicKey with a curve in CURVE_PARAMS) but whose key OpenSSL still
// refuses to build a KeyObject for -- the off-curve-point case, primarily
// -- is Invalid, an affirmative rejection, per this plan's design doc
// ("RFC-strict: ECDSA" section). A certificate whose SPKI names an
// algorithm this module does NOT support is Skipped instead, even though
// `cert.publicKey` throws there too: `X509Certificate`'s constructor
// parses ASN.1 *structure* only, so an algorithm OpenSSL cannot build an
// `EVP_PKEY` for throws at the SAME getter, with the SAME generic
// "decode error", as a genuinely bad key of a *supported* algorithm.
// Conflating the two used to make an unsupported-algorithm DSC (e.g. one
// this OpenSSL build has no implementation for) reject every document
// from that issuer as a forgery, one enforcement mode earlier than
// intended, with no skip-rate signal to warn of it -- see this file's
// report and classifySpkiAlgorithm's own doc comment.
//
// certPublicKey itself is left alone (Task 1's original contract, tested
// directly with its own "returns null on any failure" semantics) rather
// than widening its return shape -- this is a separate function used only
// by the two call sites that need the distinction.
// ---------------------------------------------------------------------

/**
 * Splits certPublicKey's single "parse the certificate" step into its two
 * distinct OpenSSL calls, so the two ways it can fail can get different
 * verdicts:
 *
 * 1. `new crypto.X509Certificate(buf)` parses DER/ASN.1 *structure* only. If
 *    this throws, the certificate itself is unparseable (a corrupted tag
 *    byte, truncated length, etc.) -- `{ok:false, invalid:false}`, callers
 *    report `Skipped`, unchanged from before.
 * 2. `cert.publicKey` is where OpenSSL actually builds an `EVP_PKEY` from the
 *    parsed `SubjectPublicKeyInfo` -- this is where curve-membership (and
 *    other key-validity) checks happen, but it is ALSO where an algorithm
 *    OpenSSL simply does not implement throws, with an indistinguishable
 *    generic error. Verified empirically (this file's report): a
 *    certificate carrying a syntactically well-formed but off-curve EC
 *    point parses fine at step 1, then throws only here (`"digital
 *    envelope routines::decode error"`), while a corrupted outer DER tag
 *    throws at step 1 instead -- AND flipping one byte of the SPKI's own
 *    `AlgorithmIdentifier` OID (leaving the rest of the ASN.1 untouched)
 *    also parses fine at step 1 and throws only here, with the exact same
 *    error text. So step 2 throwing is NOT by itself evidence the key
 *    material is bad -- `classifySpkiAlgorithm` (below) resolves that by
 *    reading the OID directly rather than trusting which OpenSSL call
 *    failed. If step 2 throws AND the algorithm is one this module
 *    supports, the key material itself was not valid -- `{ok:false,
 *    invalid:true, reason}`, callers report `Invalid`. If step 2 throws
 *    and the algorithm is unsupported, callers report `Skipped` instead --
 *    `{ok:false, invalid:false, reason}`, naming the unsupported algorithm.
 *
 * @param {Uint8Array | Buffer} derBytes
 * @returns {{ok:true, key: import('node:crypto').KeyObject, details: object} |
 *   {ok:false, invalid:true, reason:string} |
 *   {ok:false, invalid:false, reason?:string}}
 */
function certPublicKeyOrInvalidReason(derBytes) {
  const buf = Buffer.isBuffer(derBytes) ? derBytes : Buffer.from(derBytes);
  let cert;
  try {
    cert = new crypto.X509Certificate(buf);
  } catch {
    return { ok: false, invalid: false };
  }
  try {
    const key = cert.publicKey;
    return { ok: true, key, details: { ...key.asymmetricKeyDetails } };
  } catch (err) {
    const alg = classifySpkiAlgorithm(buf);
    if (alg.recognized) {
      return { ok: false, invalid: true, reason: err && err.message ? err.message : String(err), curve: alg.curve };
    }
    return {
      ok: false,
      invalid: false,
      reason: `SPKI uses an algorithm this build does not support (${alg.description}), so key validity cannot be checked`,
    };
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
      // DER SPKI export, not JWK: `KeyObject.export({format:'jwk'})` throws
      // `Unsupported JWK Key Type` for an `id-RSASSA-PSS` key, which used to
      // make this branch report a mismatch for every genuine RSASSA-PSS SPKI
      // certificate regardless of whether the modulus actually matched (this
      // file's report). `extractRsaModulus` reads the same DER `RSAPublicKey`
      // structure either SPKI algorithm identifier wraps, exactly as
      // `extractEcPoint` already does for the ECDSA branch below.
      const spkiDer = cert.key.export({ format: 'der', type: 'spki' });
      const certModulus = extractRsaModulus(spkiDer);
      if (!certModulus) {
        return false;
      }
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

/**
 * Compares `suppliedLimbs` byte-for-byte against `rawBuf[offset .. offset +
 * size]` DIRECTLY -- mirroring `dsc.circom:171-192`'s `CheckPubkeyPosition` +
 * `CheckPubkeysEqual` (and `dsc.rs`'s own byte-window comparison) verbatim,
 * not derived from the parsed certificate at all.
 *
 * This is independent of, and in addition to, `keyMatchesCert`'s
 * certificate-based comparison below -- the two are NOT redundant. A key
 * that genuinely matches the parsed certificate but sits at the wrong
 * DECLARED offset would pass a certificate-only check yet fail this one:
 * `keyMatchesCert` never reads `offset`/`size` at all, so nothing before
 * this function actually ties the supplied key to its *stated location* in
 * `raw_dsc`/`raw_csca`. Without this check, the offset/size fields are
 * bounds-checked (`offsetInRangeSkip`, above) but otherwise inert.
 *
 * @param {ReadonlyArray<string>} suppliedLimbs
 * @param {number} n limb width in bits.
 * @param {number} k limb count (RSA modulus limbs, or half the ECDSA count).
 * @param {'rsa'|'ecdsa'} scheme
 * @param {Buffer} rawBuf the full raw_dsc/raw_csca buffer.
 * @param {number} offset
 * @param {number} size
 * @param {string} keyField field name, for the reason string (e.g. `pubKey_dsc`).
 * @param {string} rawField field name, for the reason string (e.g. `raw_dsc`).
 * @param {string} offsetField field name, for the reason string (e.g. `dsc_pubKey_offset`).
 * @returns {{ok:true} | {ok:false, skip:boolean, reason:string}}
 */
function keyMatchesWindow(suppliedLimbs, n, k, scheme, rawBuf, offset, size, keyField, rawField, offsetField) {
  const window = rawBuf.subarray(offset, offset + size);
  const sizeField = offsetField.replace(/_offset$/, '_actual_size');
  if (scheme === 'ecdsa') {
    if (size % 2 !== 0) {
      return { ok: false, skip: true, reason: `${sizeField} is odd; an ECDSA x||y split must be even` };
    }
    if (suppliedLimbs.length !== 2 * k) {
      return { ok: false, skip: true, reason: `${keyField} has ${suppliedLimbs.length} limbs, expected 2*k=${2 * k}` };
    }
    const half = size / 2;
    const x = limbsToBigInt(suppliedLimbs.slice(0, k), n);
    const y = limbsToBigInt(suppliedLimbs.slice(k, 2 * k), n);
    if (x === null || y === null) {
      return { ok: false, skip: true, reason: `${keyField}'s x/y half does not reassemble into a valid integer` };
    }
    const xBytes = bigIntToFixedBytes(x, half);
    const yBytes = bigIntToFixedBytes(y, half);
    if (!xBytes || !yBytes) {
      return {
        ok: false,
        skip: false,
        reason: `${keyField} does not match ${rawField}: a coordinate is wider than half of ${sizeField}`,
      };
    }
    if (Buffer.compare(xBytes, window.subarray(0, half)) !== 0 || Buffer.compare(yBytes, window.subarray(half)) !== 0) {
      return { ok: false, skip: false, reason: `${keyField} does not match the bytes in ${rawField} at ${offsetField}` };
    }
    return { ok: true };
  }
  // rsa / rsapss -- the window is the bare modulus, no exponent involved
  // (same convention as keyMatchesCert's 'rsa' scheme).
  const modulus = limbsToBigInt(suppliedLimbs, n);
  if (modulus === null) {
    return { ok: false, skip: true, reason: `${keyField} does not reassemble into a valid integer` };
  }
  const modulusBytes = bigIntToFixedBytes(modulus, size);
  if (!modulusBytes) {
    return {
      ok: false,
      skip: false,
      reason: `${keyField} does not match ${rawField}: it is wider than ${sizeField}`,
    };
  }
  if (Buffer.compare(modulusBytes, window) !== 0) {
    return { ok: false, skip: false, reason: `${keyField} does not match the bytes in ${rawField} at ${offsetField}` };
  }
  return { ok: true };
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
    // does that -- `cert.key` here always comes from a real certificate
    // whose key `certPublicKeyOrInvalidReason` already confirmed OpenSSL
    // could build a KeyObject for, which (Plan B) is itself now the
    // off-curve check: an off-curve point is caught and reported `Invalid`
    // there, before a call ever reaches this function. So this catch is not
    // where off-curve-ness is caught (by design, not oversight) -- if
    // `crypto.verify` still throws here, it is over some OTHER malformed
    // key/signature shape it cannot even attempt, a structural uncertainty
    // distinct from both the off-curve case above and a normal failed
    // verification below.
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
 * `e` and `bits` are validated (must parse as plain decimal integers). `bits`
 * is otherwise unused: this module verifies with the certificate's own key
 * (see this file's report), so the circuit name's claimed key-length never
 * feeds into any cryptographic calculation -- only `salt_len` (RSA-PSS) and
 * the curve (ECDSA) do, since those select real behaviour (the fixed salt
 * length the circuit's own padding assumes, and the limb width for
 * reassembly) that the certificate cannot supply by itself.
 *
 * `e`, unlike `bits`, IS used: it is returned as a `BigInt` so the caller can
 * check it against the certificate's actual `publicExponent`
 * (`keyMatchesCert` only ever compares the modulus/point, never the
 * exponent). Before this check existed, a certificate whose real exponent
 * disagreed with the one the circuit name declared -- the extreme case
 * being `e = 1`, under which `s^1 mod n = s` and any PKCS#1-encoded digest
 * is trivially a "valid signature" -- verified as `Valid`. Harmless in
 * practice only because the circuit itself is compiled per-exponent and
 * still constrains `e`, so no proof results either way; this module should
 * not rely on that.
 *
 * @returns {{scheme:'rsa', n:number, k:number, e:bigint} |
 *   {scheme:'rsapss', n:number, k:number, e:bigint, saltLen:number} |
 *   {scheme:'ecdsa', curve:string, n:number, k:number} | null}
 */
function parseSchemeSuffix(parts, at) {
  const isDecimal = (s) => /^[0-9]+$/.test(s);
  const token = parts[at];
  if (token === 'rsa') {
    if (parts.length !== at + 3 || !isDecimal(parts[at + 1]) || !isDecimal(parts[at + 2])) {
      return null;
    }
    return { scheme: 'rsa', n: RSA_N, k: RSA_K, e: BigInt(parts[at + 1]) };
  }
  if (token === 'rsapss') {
    if (parts.length !== at + 4 || !isDecimal(parts[at + 1]) || !isDecimal(parts[at + 2]) || !isDecimal(parts[at + 3])) {
      return null;
    }
    return { scheme: 'rsapss', n: RSA_N, k: RSA_K, e: BigInt(parts[at + 1]), saltLen: Number(parts[at + 2]) };
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
  const keyScheme = p.scheme === 'ecdsa' ? 'ecdsa' : 'rsa';
  // Byte-window comparison against raw_dsc at the STATED offset, mirroring
  // dsc.circom's CheckPubkeyPosition+CheckPubkeysEqual (and dsc.rs's own
  // byte comparison) directly -- independent of certificate parsing. See
  // keyMatchesWindow's doc comment for why this is not redundant with the
  // certificate-based check below: without it, a genuine key that matches
  // the parsed certificate but sits at the wrong declared offset would pass.
  const windowResult = keyMatchesWindow(
    pubkeyLimbs,
    p.n,
    p.k,
    keyScheme,
    rawDsc,
    dscPubKeyOffset,
    dscPubKeyActualSize,
    'pubKey_dsc',
    'raw_dsc',
    'dsc_pubKey_offset',
  );
  if (!windowResult.ok) {
    return windowResult.skip ? skipped(windowResult.reason) : invalid(windowResult.reason);
  }
  const dscTbs = rawDsc.subarray(0, rawDscActualLength);
  const dscCertResult = certPublicKeyOrInvalidReason(wrapAsCertificate(dscTbs));
  if (!dscCertResult.ok) {
    if (dscCertResult.invalid) {
      // RFC-strict (Plan B): the certificate's ASN.1 structure parsed fine,
      // but OpenSSL refused to build a KeyObject from its embedded public
      // key -- an off-curve EC point, most commonly. The previous design
      // mirrored the circuit (ecdsa.circom never checks the curve equation)
      // by treating this identically to a structurally unparseable
      // certificate: Skipped. That is no longer correct -- this is an
      // affirmative "the embedded key is not valid," not a coverage gap.
      const keyKind = keyScheme === 'ecdsa' ? `a valid point on ${p.curve}` : 'a valid RSA public key';
      return invalid(
        `pubKey_dsc's certificate (raw_dsc at dsc_pubKey_offset) does not carry ${keyKind}: ` +
          `OpenSSL rejected the embedded key (${dscCertResult.reason})`,
      );
    }
    // Either raw_dsc's ASN.1 structure was itself unparseable (no `reason`),
    // or the SPKI names an algorithm this module does not support (a
    // `reason` naming it -- see certPublicKeyOrInvalidReason/
    // classifySpkiAlgorithm) -- both are honest coverage gaps, not evidence
    // of a bad key.
    return skipped(dscCertResult.reason || 'raw_dsc does not parse as a readable certificate');
  }
  const dscCert = { key: dscCertResult.key, details: dscCertResult.details };
  // Certificate-based comparison, kept alongside the window comparison
  // above (not replaced by it): this is what Task 1/Task 2 already
  // established, and it is what lets `verifySignatureLink` below use a real
  // `KeyObject` (`dscCert.key`) rather than a key rebuilt from limbs.
  if (!keyMatchesCert(pubkeyLimbs, p.n, p.k, dscCert, keyScheme)) {
    return invalid('pubKey_dsc does not match the certificate embedded in raw_dsc at dsc_pubKey_offset');
  }
  // keyMatchesCert only compares the modulus (RSA) or point (ECDSA); for RSA
  // and RSA-PSS the exponent the circuit name declares (`p.e`, parsed in
  // parseSchemeSuffix) must independently match what the certificate itself
  // carries -- see parseSchemeSuffix's doc comment for why this matters (the
  // `e = 1` forgeability case in particular).
  if (keyScheme === 'rsa' && dscCert.details.publicExponent !== p.e) {
    return invalid(
      `raw_dsc's certificate has RSA public exponent ${dscCert.details.publicExponent} but the circuit name declares e=${p.e}`,
    );
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
  const keyScheme = p.scheme === 'ecdsa' ? 'ecdsa' : 'rsa';
  // Byte-window comparison against raw_csca at the STATED offset, mirroring
  // dsc.circom:171-192's CheckPubkeyPosition+CheckPubkeysEqual (and dsc.rs's
  // own byte comparison, dsc.rs:198-262) directly -- independent of
  // certificate parsing. See keyMatchesWindow's doc comment for why this is
  // not redundant with the certificate-based check below.
  const windowResult = keyMatchesWindow(
    pubkeyLimbs,
    p.n,
    p.k,
    keyScheme,
    rawCsca,
    cscaPubkeyOffset,
    cscaPubkeyActualSize,
    'csca_pubKey',
    'raw_csca',
    'csca_pubKey_offset',
  );
  if (!windowResult.ok) {
    return windowResult.skip ? skipped(windowResult.reason) : invalid(windowResult.reason);
  }
  const cscaTbs = rawCsca.subarray(0, rawCscaActualLength);
  const cscaCertResult = certPublicKeyOrInvalidReason(wrapAsCertificate(cscaTbs));
  if (!cscaCertResult.ok) {
    if (cscaCertResult.invalid) {
      // See verifyRegisterFamily's identical branch for why this is Invalid,
      // not Skipped, under Plan B's RFC-strict rule.
      const keyKind = keyScheme === 'ecdsa' ? `a valid point on ${p.curve}` : 'a valid RSA public key';
      return invalid(
        `csca_pubKey's certificate (raw_csca at csca_pubKey_offset) does not carry ${keyKind}: ` +
          `OpenSSL rejected the embedded key (${cscaCertResult.reason})`,
      );
    }
    // See verifyRegisterFamily's identical branch for why an unsupported
    // SPKI algorithm gets its own named reason rather than the generic one.
    return skipped(cscaCertResult.reason || 'raw_csca does not parse as a readable certificate');
  }
  const cscaCert = { key: cscaCertResult.key, details: cscaCertResult.details };
  // Certificate-based comparison, kept alongside the window comparison
  // above (not replaced by it) -- see verifyRegisterFamily's identical
  // comment on why both are needed.
  if (!keyMatchesCert(pubkeyLimbs, p.n, p.k, cscaCert, keyScheme)) {
    return invalid('csca_pubKey does not match the certificate embedded in raw_csca at csca_pubKey_offset');
  }
  // See verifyRegisterFamily's identical exponent check for why this is
  // needed alongside keyMatchesCert (which never compares the exponent).
  if (keyScheme === 'rsa' && cscaCert.details.publicExponent !== p.e) {
    return invalid(
      `raw_csca's certificate has RSA public exponent ${cscaCert.details.publicExponent} but the circuit name declares e=${p.e}`,
    );
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
