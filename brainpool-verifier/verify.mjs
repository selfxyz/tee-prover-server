#!/usr/bin/env node
// Native ECDSA pre-check for the brainpoolP{224,256,384,512}r1 circuits.
//
// No usable Rust crate covers these curves (bp256/bp384 gate arithmetic
// behind an unstable feature; brainpoolP224r1/P512r1 have no crate at all in
// any version), so this sidecar leans on Node's OpenSSL binding instead.
//
// Contract (see task-1-brief.md):
//   stdin:  {"curve":"brainpoolP256r1","x":"<hex>","y":"<hex>",
//            "r":"<hex>","s":"<hex>","message":"<hex>","hash":"sha256"}
//   stdout: {"valid":true} | {"valid":false} | {"error":"<reason>"}
//   exit:   always 0 once a JSON object has been written. The Rust caller
//           distinguishes on the payload, not the exit code.
//
// The governing asymmetry: a false reject is a production outage, a false
// accept costs nothing (Groth16 still verifies afterward), and brainpool
// circuits already skip the pre-check today. So every failure path here must
// produce {"error":...}, never {"valid":false} -- Task 2 turns an error into
// a skip, which is exactly where we already are. {"valid":false} is reserved
// for a signature OpenSSL actually rejected, never for a structural problem
// with the input.
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';

// SPKI prefixes below are everything that precedes the 0x04 uncompressed
// point marker in a brainpool EC SubjectPublicKeyInfo. They were extracted
// empirically from OpenSSL 3.5.5 output (see task-1-brief.md's "Validated
// before planning" section) -- use verbatim, do not re-derive, no ASN.1
// encoder needed because this prefix is constant per curve.

// Hash names accepted on the wire, passed straight through to
// crypto.verify() as its OpenSSL digest name. The 20 brainpool circuits span
// all five widths (sha1/sha224 with brainpoolP224r1, sha1/sha256 with
// P256r1, sha256/sha384 with P384r1, sha384/sha512 with P512r1) -- there is
// no single hash this sidecar can assume. An unrecognized name is a
// structural problem, so it still yields {"error":...}, never {"valid":false}.
const SUPPORTED_HASHES = new Set(['sha1', 'sha224', 'sha256', 'sha384', 'sha512']);
const CURVES = {
  brainpoolP224r1: {
    fieldBytes: 28,
    prefix:
      '3052301406072a8648ce3d020106092b2403030208010105033a00',
  },
  brainpoolP256r1: {
    fieldBytes: 32,
    prefix:
      '305a301406072a8648ce3d020106092b2403030208010107034200',
  },
  brainpoolP384r1: {
    fieldBytes: 48,
    prefix:
      '307a301406072a8648ce3d020106092b240303020801010b036200',
  },
  brainpoolP512r1: {
    fieldBytes: 64,
    prefix:
      '30819b301406072a8648ce3d020106092b240303020801010d03818200',
  },
};

function isHex(value) {
  return typeof value === 'string' && /^([0-9a-fA-F]{2})+$/.test(value);
}

// Left-pad a hex string to exactly fieldBytes bytes. Returns null if the
// value is already wider than the field -- the caller must treat that as a
// structural error, never silently truncate (a truncated key would fail to
// verify and look indistinguishable from an honest signature failure).
function hexToFieldBuffer(hex, fieldBytes) {
  const byteLength = hex.length / 2;
  if (byteLength > fieldBytes) {
    return null;
  }
  return Buffer.from(hex.padStart(fieldBytes * 2, '0'), 'hex');
}

function writeResult(result) {
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

function verifyRequest(raw) {
  let request;
  try {
    request = JSON.parse(raw);
  } catch {
    return { error: 'malformed JSON input' };
  }

  if (typeof request !== 'object' || request === null) {
    return { error: 'input is not a JSON object' };
  }

  const { curve, x, y, r, s, message, hash } = request;

  const curveInfo = CURVES[curve];
  if (!curveInfo) {
    return { error: `unknown curve: ${JSON.stringify(curve)}` };
  }

  if (!SUPPORTED_HASHES.has(hash)) {
    return { error: `unsupported hash: ${JSON.stringify(hash)}` };
  }

  for (const [name, value] of [
    ['x', x],
    ['y', y],
    ['r', r],
    ['s', s],
    ['message', message],
  ]) {
    if (!isHex(value)) {
      return { error: `malformed hex for field "${name}"` };
    }
  }

  const { fieldBytes, prefix } = curveInfo;

  const xBuf = hexToFieldBuffer(x, fieldBytes);
  const yBuf = hexToFieldBuffer(y, fieldBytes);
  if (!xBuf || !yBuf) {
    return { error: 'public key coordinate wider than curve field' };
  }

  const rBuf = hexToFieldBuffer(r, fieldBytes);
  const sBuf = hexToFieldBuffer(s, fieldBytes);
  if (!rBuf || !sBuf) {
    return { error: 'signature component wider than curve field' };
  }

  // Keys build by concatenation: prefix || 0x04 || x || y. Everything before
  // the point marker is constant per curve, so no ASN.1 encoder is needed.
  const spkiDer = Buffer.concat([
    Buffer.from(prefix, 'hex'),
    Buffer.from([0x04]),
    xBuf,
    yBuf,
  ]);

  let publicKey;
  try {
    publicKey = createPublicKey({
      key: spkiDer,
      format: 'der',
      type: 'spki',
    });
  } catch (err) {
    return { error: `invalid public key: ${err.message}` };
  }

  let messageBuf;
  try {
    messageBuf = Buffer.from(message, 'hex');
  } catch (err) {
    return { error: `malformed message hex: ${err.message}` };
  }

  // ieee-p1363 signature is raw r||s, each already left-padded to field
  // width above -- this avoids DER INTEGER encoding, the classic source of
  // ECDSA interop bugs (the leading-zero-when-high-bit-set rule).
  const signature = Buffer.concat([rBuf, sBuf]);

  let valid;
  try {
    // `message`, not a digest: OpenSSL hashes and truncates it itself here,
    // which keeps ECDSA's bits2int truncation semantics out of this
    // interface rather than re-deriving them in a second language.
    valid = cryptoVerify(
      hash,
      messageBuf,
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      signature,
    );
  } catch (err) {
    // A throw here means OpenSSL rejected the request as structurally
    // invalid (bad signature length, bad key, etc.) -- not that it evaluated
    // the signature and found it wanting. That distinction is exactly
    // {"error":...} vs {"valid":false}.
    return { error: `verification failed: ${err.message}` };
  }

  return { valid };
}

const chunks = [];
process.stdin.on('data', (chunk) => chunks.push(chunk));
process.stdin.on('end', () => {
  const raw = Buffer.concat(chunks).toString('utf8');
  writeResult(verifyRequest(raw));
});
