// Tests for verify.mjs, the brainpoolP*r1 ECDSA signature pre-check sidecar.
//
// Known-good vectors are generated with the OpenSSL CLI (ecparam -genkey,
// dgst -sign), never with this script's own signing logic -- a verifier that
// only checks signatures it produced itself proves nothing but
// self-consistency.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const VERIFY_SCRIPT = fileURLToPath(new URL('./verify.mjs', import.meta.url));

const CURVES = {
  brainpoolP224r1: 28,
  brainpoolP256r1: 32,
  brainpoolP384r1: 48,
  brainpoolP512r1: 64,
};

const MESSAGE_HEX = Buffer.from(
  'the quick brown fox jumps over the lazy dog',
).toString('hex');

function runVerify(input) {
  const result = spawnSync(process.execPath, [VERIFY_SCRIPT], {
    input: JSON.stringify(input),
    encoding: 'utf8',
  });
  assert.equal(
    result.status,
    0,
    `expected exit 0 with a JSON payload, got status ${result.status}\nstderr: ${result.stderr}`,
  );
  return JSON.parse(result.stdout);
}

function tmpDir() {
  return mkdtempSync(join(tmpdir(), 'brainpool-verify-test-'));
}

function opensslKeygen(curve, dir) {
  const keyPath = join(dir, `${curve}.pem`);
  const r = spawnSync('openssl', [
    'ecparam',
    '-name',
    curve,
    '-genkey',
    '-noout',
    '-out',
    keyPath,
  ]);
  assert.equal(r.status, 0, r.stderr?.toString());
  return keyPath;
}

// Extract the raw (x, y) point from an OpenSSL-generated key by taking the
// tail of its DER SubjectPublicKeyInfo. The BIT STRING content in an EC SPKI
// is always `0x04 || X || Y` and always sits at the end of the structure, so
// no ASN.1 decoding is needed -- just slice the last N bytes.
function opensslPublicXY(keyPath, fieldBytes, dir) {
  const pubPath = join(dir, 'pub.der');
  const r = spawnSync('openssl', [
    'ec',
    '-in',
    keyPath,
    '-pubout',
    '-outform',
    'DER',
    '-out',
    pubPath,
  ]);
  assert.equal(r.status, 0, r.stderr?.toString());
  const der = readFileSync(pubPath);
  const tailLen = 1 + 2 * fieldBytes;
  const tail = der.subarray(der.length - tailLen);
  assert.equal(tail[0], 0x04, 'expected an uncompressed point marker');
  const x = tail.subarray(1, 1 + fieldBytes).toString('hex');
  const y = tail.subarray(1 + fieldBytes).toString('hex');
  return { x, y };
}

// Minimal DER TLV length reader -- short form and one-byte long form, which
// covers every signature length brainpoolP224r1..P512r1 can produce.
function readDerLength(buf, offset) {
  const first = buf[offset];
  if (first < 0x80) {
    return { length: first, next: offset + 1 };
  }
  const numBytes = first & 0x7f;
  let length = 0;
  for (let i = 0; i < numBytes; i++) {
    length = (length << 8) | buf[offset + 1 + i];
  }
  return { length, next: offset + 1 + numBytes };
}

// Split an OpenSSL DER ECDSA signature (SEQUENCE of two INTEGERs) into its
// raw r and s byte strings. This is plain TLV slicing, not general ASN.1
// decoding -- verify.mjs itself never does this; the wire format it accepts
// is already raw r||s, and this parsing only exists to build test fixtures
// from OpenSSL's DER output.
function parseDerEcdsaSignature(der) {
  assert.equal(der[0], 0x30, 'expected a SEQUENCE');
  const { next: seqNext } = readDerLength(der, 1);
  let offset = seqNext;
  const ints = [];
  for (let i = 0; i < 2; i++) {
    assert.equal(der[offset], 0x02, 'expected an INTEGER');
    const { length, next } = readDerLength(der, offset + 1);
    ints.push(der.subarray(next, next + length));
    offset = next + length;
  }
  return { r: ints[0], s: ints[1] };
}

// DER INTEGER encoding is minimal and prepends a 0x00 sign byte whenever the
// value's top bit is set, so a fieldBytes-wide scalar can appear as
// fieldBytes+1 bytes. Strip that artifact and left-pad back to field width --
// this is the field-width normalization the wire format expects, not a
// generic ASN.1 concern.
function derIntegerToFieldHex(bytes, fieldBytes) {
  let b = bytes;
  if (b.length > fieldBytes && b[0] === 0x00) {
    b = b.subarray(1);
  }
  assert.ok(
    b.length <= fieldBytes,
    `DER integer (${b.length} bytes) wider than field (${fieldBytes} bytes)`,
  );
  return Buffer.from(b).toString('hex').padStart(fieldBytes * 2, '0');
}

function opensslSign(keyPath, messageHex, fieldBytes, dir) {
  const msgPath = join(dir, 'msg.bin');
  writeFileSync(msgPath, Buffer.from(messageHex, 'hex'));
  const sigPath = join(dir, 'sig.der');
  const r = spawnSync('openssl', [
    'dgst',
    '-sha256',
    '-sign',
    keyPath,
    '-out',
    sigPath,
    msgPath,
  ]);
  assert.equal(r.status, 0, r.stderr?.toString());
  const der = readFileSync(sigPath);
  const { r: rBytes, s: sBytes } = parseDerEcdsaSignature(der);
  return {
    r: derIntegerToFieldHex(rBytes, fieldBytes),
    s: derIntegerToFieldHex(sBytes, fieldBytes),
  };
}

function flipLastNibble(hex) {
  const last = hex.slice(-1);
  const flipped = last === '0' ? '1' : '0';
  return hex.slice(0, -1) + flipped;
}

for (const [curve, fieldBytes] of Object.entries(CURVES)) {
  test(`${curve}: OpenSSL-produced signature verifies true`, () => {
    const dir = tmpDir();
    const keyPath = opensslKeygen(curve, dir);
    const { x, y } = opensslPublicXY(keyPath, fieldBytes, dir);
    const { r, s } = opensslSign(keyPath, MESSAGE_HEX, fieldBytes, dir);

    const out = runVerify({
      curve,
      x,
      y,
      r,
      s,
      message: MESSAGE_HEX,
      hash: 'sha256',
    });

    assert.deepEqual(out, { valid: true });
  });

  test(`${curve}: tampered signature verifies false (not error)`, () => {
    const dir = tmpDir();
    const keyPath = opensslKeygen(curve, dir);
    const { x, y } = opensslPublicXY(keyPath, fieldBytes, dir);
    const { r, s } = opensslSign(keyPath, MESSAGE_HEX, fieldBytes, dir);

    const out = runVerify({
      curve,
      x,
      y,
      r,
      s: flipLastNibble(s),
      message: MESSAGE_HEX,
      hash: 'sha256',
    });

    assert.deepEqual(out, { valid: false });
  });
}

test('unknown curve yields {"error":...}, not a thrown exit', () => {
  const out = runVerify({
    curve: 'secp256k1',
    x: '00',
    y: '00',
    r: '00',
    s: '00',
    message: '00',
    hash: 'sha256',
  });
  assert.equal(typeof out.error, 'string');
  assert.equal(out.valid, undefined);
});

test('malformed hex yields {"error":...}', () => {
  const dir = tmpDir();
  const keyPath = opensslKeygen('brainpoolP256r1', dir);
  const { y } = opensslPublicXY(keyPath, 32, dir);
  const { r, s } = opensslSign(keyPath, MESSAGE_HEX, 32, dir);

  const out = runVerify({
    curve: 'brainpoolP256r1',
    x: 'not-hex-zz',
    y,
    r,
    s,
    message: MESSAGE_HEX,
    hash: 'sha256',
  });

  assert.equal(typeof out.error, 'string');
  assert.equal(out.valid, undefined);
});

test('odd-length hex yields {"error":...}', () => {
  const out = runVerify({
    curve: 'brainpoolP256r1',
    x: 'abc',
    y: '00',
    r: '00',
    s: '00',
    message: '00',
    hash: 'sha256',
  });
  assert.equal(typeof out.error, 'string');
});

test('a coordinate wider than the curve field yields {"error":...}, never a truncated key', () => {
  const dir = tmpDir();
  const keyPath = opensslKeygen('brainpoolP256r1', dir);
  const { x, y } = opensslPublicXY(keyPath, 32, dir);
  const { r, s } = opensslSign(keyPath, MESSAGE_HEX, 32, dir);

  const overWideX = 'ff' + x; // 33 bytes for a 32-byte field

  const out = runVerify({
    curve: 'brainpoolP256r1',
    x: overWideX,
    y,
    r,
    s,
    message: MESSAGE_HEX,
    hash: 'sha256',
  });

  assert.equal(typeof out.error, 'string');
  assert.equal(out.valid, undefined);
});

test('an oversized r yields {"error":...}, never {"valid":false}', () => {
  const dir = tmpDir();
  const keyPath = opensslKeygen('brainpoolP256r1', dir);
  const { x, y } = opensslPublicXY(keyPath, 32, dir);
  const { r, s } = opensslSign(keyPath, MESSAGE_HEX, 32, dir);

  const out = runVerify({
    curve: 'brainpoolP256r1',
    x,
    y,
    r: 'ff' + r,
    s,
    message: MESSAGE_HEX,
    hash: 'sha256',
  });

  assert.equal(typeof out.error, 'string');
  assert.equal(out.valid, undefined);
});

test('malformed (non-JSON) stdin yields {"error":...} with exit 0', () => {
  const result = spawnSync(process.execPath, [VERIFY_SCRIPT], {
    input: 'not json at all',
    encoding: 'utf8',
  });
  assert.equal(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(typeof parsed.error, 'string');
});
