// Tests for verify.mjs (Plan A, Task 1: the parsing layer) against the 23
// real fixtures checked in under tests/fixtures/ -- captured from the
// sibling monorepo's own circuit-input generators, not hand-built, so a
// wire-format mismatch (like the Aadhaar/KYC Value::Number gap the Rust
// crate hit) would show up here rather than only in production.
//
// Run with: node --test signature-verifier/verify.test.mjs
// (not `node --test signature-verifier` -- that resolves the directory as
// a module and fails with MODULE_NOT_FOUND.)

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { spawnSync } from 'node:child_process';
import { limbsToBigInt, fieldAsStrings, recoverMessage, certPublicKey, keyMatchesCert, verify, parseCircuitName } from './verify.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = path.join(__dirname, '..', 'tests', 'fixtures');

// The sibling monorepo checkout that carries the mock certificates these
// fixtures were generated against (see real_fixtures.rs's module doc and
// this task's brief). Tests that need it skip cleanly if it is absent,
// mirroring params::table_matches_the_monorepo_instance_files's convention
// of never hard-failing on missing external state.
const MOCK_CERT_ROOT = '/Users/ayman/self/self/common/src/mock_certificates';
const MOCK_CERTS_AVAILABLE = fs.existsSync(MOCK_CERT_ROOT);

// ---------------------------------------------------------------------
// Fixture / DER plumbing shared by the tests below.
// ---------------------------------------------------------------------

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, name), 'utf8'));
}

/** A field's sole scalar value as a JS number, handling every shape
 * chunks.rs's field_as_strings normalizes: a bare string, a bare number, or
 * a single-element array of either. */
function scalarNumber(value) {
  const strs = fieldAsStrings(value);
  assert.equal(strs?.length, 1, `expected exactly one scalar element, got ${JSON.stringify(value)}`);
  return Number(strs[0]);
}

function bytesFromDecimalArray(value) {
  const strs = fieldAsStrings(value);
  assert.ok(strs, `expected a decimal-string/number array, got ${JSON.stringify(value)?.slice(0, 100)}`);
  return Buffer.from(strs.map((s) => Number(s)));
}

function mockCertPem(dir, file) {
  return fs.readFileSync(path.join(MOCK_CERT_ROOT, dir, file), 'utf8');
}

// --- Minimal DER encoders, test-only: wrap a bare tbsCertificate buffer
// (what raw_dsc/raw_csca actually carry on the wire -- see this task's
// report) into a syntactically complete X.509 "Certificate" DER so
// node:crypto's X509Certificate can parse it. X509Certificate's constructor
// only parses ASN.1 structure; it does not verify the signature, so a
// placeholder signatureAlgorithm/signatureValue is sufficient -- verified
// empirically against every scheme in the fixture set before relying on it
// here. ---

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

function wrapAsCertificate(tbsCertificateBytes) {
  // sha256WithRSAEncryption + NULL params -- an arbitrary-but-valid
  // AlgorithmIdentifier. d2i_X509 never cross-checks this against the
  // subjectPublicKeyInfo's own algorithm, so this placeholder parses fine
  // regardless of the wrapped tbsCertificate's real key type (RSA or EC).
  const sigAlg = derSequence(
    Buffer.concat([Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]), Buffer.from([0x05, 0x00])]),
  );
  const sigValue = derBitString(Buffer.alloc(64, 0x01));
  return derSequence(Buffer.concat([tbsCertificateBytes, sigAlg, sigValue]));
}

/** Extracts the tbsCertificate DER bytes from a full certificate's own DER
 * (`cert.raw`), for comparing recoverMessage's output against a known-good,
 * independently-sourced value rather than this test's own arithmetic. */
function tbsCertificateOf(certPem) {
  const cert = new crypto.X509Certificate(certPem);
  const der = cert.raw;
  const outerLenByte = der[1];
  const outerHeaderLen = outerLenByte & 0x80 ? 2 + (outerLenByte & 0x7f) : 2;
  const tbsLenByte = der[outerHeaderLen + 1];
  const tbsHeaderLen = tbsLenByte & 0x80 ? 2 + (tbsLenByte & 0x7f) : 2;
  let tbsLen;
  if (tbsLenByte & 0x80) {
    const n = tbsLenByte & 0x7f;
    tbsLen = 0;
    for (let i = 0; i < n; i++) tbsLen = tbsLen * 256 + der[outerHeaderLen + 2 + i];
  } else {
    tbsLen = tbsLenByte;
  }
  const tbsStart = outerHeaderLen;
  const tbsEnd = tbsStart + tbsHeaderLen + tbsLen;
  return der.subarray(tbsStart, tbsEnd);
}

// ---------------------------------------------------------------------
// The circuit-parameter table this task's brief pins values from
// (src/verifier/params.rs's RSA_LIMBS / ECDSA_LIMBS / ECDSA_BRAINPOOL_LIMBS
// / PSS_SALT_AND_KEY_LENGTH / DSC_* tables), joined with which mock
// certificate directory each fixture's keys were generated from (recorded
// in real_fixtures.rs's FIXTURES comments) and which fields carry what.
// ---------------------------------------------------------------------

// register_*/register_id_* (passport/EU-ID): the DSC's own key is
// pubKey_dsc/signature_passport, and the embedded certificate bytes are
// raw_dsc (a bare tbsCertificate, actual-length-delimited, no SHA padding).
const REGISTER_FAMILY = [
  { file: 'register_passport.json', circuit: 'register_sha256_sha256_sha256_rsa_3_4096', scheme: 'rsa', n: 120, k: 35, mockDir: 'sha256_rsa_3_4096' },
  { file: 'register_id.json', circuit: 'register_id_sha1_sha256_sha256_rsa_65537_4096', scheme: 'rsa', n: 120, k: 35, mockDir: 'sha256_rsa_65537_4096' },
  { file: 'register_pss.json', circuit: 'register_sha256_sha256_sha256_rsapss_65537_32_2048', scheme: 'rsa', n: 120, k: 35, mockDir: 'sha256_rsapss_32_65537_2048' },
  { file: 'register_pss_sha256_salt64.json', circuit: 'register_sha256_sha256_sha256_rsapss_65537_64_2048', scheme: 'rsa', n: 120, k: 35, mockDir: 'sha256_rsapss_64_65537_2048' },
  { file: 'register_pss_sha384.json', circuit: 'register_sha384_sha384_sha384_rsapss_65537_48_2048', scheme: 'rsa', n: 120, k: 35, mockDir: 'sha384_rsapss_48_65537_2048' },
  { file: 'register_pss_sha512.json', circuit: 'register_sha512_sha512_sha512_rsapss_65537_64_2048', scheme: 'rsa', n: 120, k: 35, mockDir: 'sha512_rsapss_64_65537_2048' },
  { file: 'register_ecdsa_brainpoolP224r1.json', circuit: 'register_sha1_sha1_sha1_ecdsa_brainpoolP224r1', scheme: 'ecdsa', curve: 'brainpoolP224r1', n: 32, k: 7, mockDir: 'sha1_ecdsa_brainpoolP224r1' },
  { file: 'register_ecdsa_brainpoolP256r1.json', circuit: 'register_sha256_sha256_sha256_ecdsa_brainpoolP256r1', scheme: 'ecdsa', curve: 'brainpoolP256r1', n: 64, k: 4, mockDir: 'sha256_ecdsa_brainpoolP256r1' },
  { file: 'register_ecdsa_brainpoolP384r1.json', circuit: 'register_sha384_sha384_sha384_ecdsa_brainpoolP384r1', scheme: 'ecdsa', curve: 'brainpoolP384r1', n: 64, k: 6, mockDir: 'sha384_ecdsa_brainpoolP384r1' },
  { file: 'register_ecdsa_brainpoolP512r1.json', circuit: 'register_sha512_sha512_sha512_ecdsa_brainpoolP512r1', scheme: 'ecdsa', curve: 'brainpoolP512r1', n: 64, k: 8, mockDir: 'sha512_ecdsa_brainpoolP512r1' },
  { file: 'register_ecdsa_secp224r1.json', circuit: 'register_sha256_sha224_sha224_ecdsa_secp224r1', scheme: 'ecdsa', curve: 'secp224r1', n: 32, k: 7, mockDir: 'sha224_ecdsa_secp224r1' },
  { file: 'register_ecdsa_secp256r1.json', circuit: 'register_sha256_sha256_sha256_ecdsa_secp256r1', scheme: 'ecdsa', curve: 'secp256r1', n: 64, k: 4, mockDir: 'sha256_ecdsa_secp256r1' },
  { file: 'register_ecdsa_secp256r1_sha1.json', circuit: 'register_sha1_sha1_sha1_ecdsa_secp256r1', scheme: 'ecdsa', curve: 'secp256r1', n: 64, k: 4, mockDir: 'sha1_ecdsa_secp256r1' },
  { file: 'register_ecdsa_secp384r1.json', circuit: 'register_sha384_sha384_sha384_ecdsa_secp384r1', scheme: 'ecdsa', curve: 'secp384r1', n: 64, k: 6, mockDir: 'sha384_ecdsa_secp384r1' },
  { file: 'register_ecdsa_secp384r1_sha256.json', circuit: 'register_sha256_sha256_sha256_ecdsa_secp384r1', scheme: 'ecdsa', curve: 'secp384r1', n: 64, k: 6, mockDir: 'sha256_ecdsa_secp384r1' },
  { file: 'register_ecdsa_secp521r1.json', circuit: 'register_sha512_sha512_sha512_ecdsa_secp521r1', scheme: 'ecdsa', curve: 'secp521r1', n: 66, k: 8, mockDir: 'sha512_ecdsa_secp521r1' },
].map((row) => ({
  ...row,
  keyField: 'pubKey_dsc',
  sigField: 'signature_passport',
  rawCertField: 'raw_dsc',
  rawLenField: 'raw_dsc_actual_length',
  mockCertFile: 'mock_dsc.pem',
}));

// dsc_* (CSCA signs DSC): the key under test is csca_pubKey/signature, and
// the embedded certificate bytes are raw_csca (also a bare tbsCertificate,
// actual-length-delimited). raw_dsc here is the *message* CSCA's signature
// covers (SHA-padded, hence raw_dsc_padded_length) -- exercised separately
// below via recoverMessage, not via certPublicKey/keyMatchesCert.
const DSC_FAMILY = [
  { file: 'dsc_sha256_rsa_65537_4096.json', circuit: 'dsc_sha256_rsa_65537_4096', scheme: 'rsa', n: 120, k: 35, mockDir: 'sha256_rsa_65537_4096' },
  { file: 'dsc_sha256_rsapss_65537_32_3072.json', circuit: 'dsc_sha256_rsapss_65537_32_3072', scheme: 'rsa', n: 120, k: 35, mockDir: 'sha256_rsapss_32_65537_3072' },
  { file: 'dsc_sha256_ecdsa_secp521r1.json', circuit: 'dsc_sha256_ecdsa_secp521r1', scheme: 'ecdsa', curve: 'secp521r1', n: 66, k: 8, mockDir: 'sha256_ecdsa_secp521r1' },
  { file: 'dsc_sha512_ecdsa_secp521r1.json', circuit: 'dsc_sha512_ecdsa_secp521r1', scheme: 'ecdsa', curve: 'secp521r1', n: 66, k: 8, mockDir: 'sha512_ecdsa_secp521r1' },
  { file: 'dsc_sha256_ecdsa_brainpoolP256r1.json', circuit: 'dsc_sha256_ecdsa_brainpoolP256r1', scheme: 'ecdsa', curve: 'brainpoolP256r1', n: 64, k: 4, mockDir: 'sha256_ecdsa_brainpoolP256r1' },
].map((row) => ({
  ...row,
  keyField: 'csca_pubKey',
  sigField: 'signature',
  rawCertField: 'raw_csca',
  rawLenField: 'raw_csca_actual_length',
  mockCertFile: 'mock_csca.pem',
}));

const ALL_CERT_FIXTURES = [...REGISTER_FAMILY, ...DSC_FAMILY];
assert.equal(ALL_CERT_FIXTURES.length, 21, 'expected 21 of the 23 fixtures to carry a raw_dsc/raw_csca certificate window (Aadhaar and KYC do not)');

function tbsBytesOf(row, fixture) {
  const raw = bytesFromDecimalArray(fixture[row.rawCertField]);
  const len = scalarNumber(fixture[row.rawLenField]);
  return raw.subarray(0, len);
}

// ---------------------------------------------------------------------
// limbsToBigInt
// ---------------------------------------------------------------------

describe('limbsToBigInt', () => {
  test('35 limbs, n=120 (RSA modulus) matches the mock cert\'s own key -- not our own arithmetic', { skip: !MOCK_CERTS_AVAILABLE }, () => {
    const fixture = loadFixture('register_passport.json');
    const modulus = limbsToBigInt(fixture.pubKey_dsc, 120);
    assert.equal(fixture.pubKey_dsc.length, 35);

    const cert = new crypto.X509Certificate(mockCertPem('sha256_rsa_3_4096', 'mock_dsc.pem'));
    const jwk = cert.publicKey.export({ format: 'jwk' });
    const certModulus = BigInt(`0x${Buffer.from(jwk.n, 'base64url').toString('hex')}`);

    assert.equal(modulus, certModulus);
    assert.equal(jwk.e, 'Aw'); // base64url(0x03) -- e=3, matching the fixture's circuit name
  });

  test('16 limbs (2k), n=66, k=8 (secp521r1 -- NOT byte-aligned) matches the mock CSCA cert\'s own key', { skip: !MOCK_CERTS_AVAILABLE }, () => {
    const fixture = loadFixture('dsc_sha256_ecdsa_secp521r1.json');
    assert.equal(fixture.csca_pubKey.length, 16);
    const n = 66;
    const k = 8;
    const x = limbsToBigInt(fixture.csca_pubKey.slice(0, k), n);
    const y = limbsToBigInt(fixture.csca_pubKey.slice(k, 2 * k), n);

    const cert = new crypto.X509Certificate(mockCertPem('sha256_ecdsa_secp521r1', 'mock_csca.pem'));
    assert.equal(cert.publicKey.asymmetricKeyDetails.namedCurve, 'secp521r1');
    const jwk = cert.publicKey.export({ format: 'jwk' });
    const certX = BigInt(`0x${Buffer.from(jwk.x, 'base64url').toString('hex')}`);
    const certY = BigInt(`0x${Buffer.from(jwk.y, 'base64url').toString('hex')}`);

    assert.equal(x, certX, 'x coordinate: a byte-slicing shortcut would corrupt this (n=66 is not a multiple of 8)');
    assert.equal(y, certY, 'y coordinate: a byte-slicing shortcut would corrupt this (n=66 is not a multiple of 8)');
  });

  test('a second secp521r1 fixture (sha512 sig hash, still n=66/k=8) also matches independently', { skip: !MOCK_CERTS_AVAILABLE }, () => {
    const fixture = loadFixture('dsc_sha512_ecdsa_secp521r1.json');
    const n = 66;
    const k = 8;
    const x = limbsToBigInt(fixture.csca_pubKey.slice(0, k), n);
    const y = limbsToBigInt(fixture.csca_pubKey.slice(k, 2 * k), n);

    const cert = new crypto.X509Certificate(mockCertPem('sha512_ecdsa_secp521r1', 'mock_csca.pem'));
    const jwk = cert.publicKey.export({ format: 'jwk' });
    assert.equal(x, BigInt(`0x${Buffer.from(jwk.x, 'base64url').toString('hex')}`));
    assert.equal(y, BigInt(`0x${Buffer.from(jwk.y, 'base64url').toString('hex')}`));
  });

  test('a brainpool fixture (n=64, byte-aligned but a different curve family) matches its mock cert', { skip: !MOCK_CERTS_AVAILABLE }, () => {
    const fixture = loadFixture('register_ecdsa_brainpoolP256r1.json');
    const n = 64;
    const k = 4;
    const x = limbsToBigInt(fixture.pubKey_dsc.slice(0, k), n);
    const y = limbsToBigInt(fixture.pubKey_dsc.slice(k, 2 * k), n);

    const cert = new crypto.X509Certificate(mockCertPem('sha256_ecdsa_brainpoolP256r1', 'mock_dsc.pem'));
    // JWK export throws for brainpool curves in node:crypto -- exercised
    // directly via the SPKI DER point instead (same path keyMatchesCert
    // uses internally for every ECDSA scheme, brainpool included). The
    // coordinate byte width is the curve's field size, k*n/8 (32 bytes for
    // P-256) -- NOT n/8 (n is the limb width, 64 bits here, not the curve
    // field width).
    const spki = cert.publicKey.export({ format: 'der', type: 'spki' });
    const half = (k * n) / 8;
    const point = spki.subarray(spki.length - (2 * half + 1));
    assert.equal(point[0], 0x04);
    const certX = BigInt(`0x${point.subarray(1, 1 + half).toString('hex')}`);
    const certY = BigInt(`0x${point.subarray(1 + half).toString('hex')}`);
    assert.equal(x, certX);
    assert.equal(y, certY);
  });

  test('little-endian base-2^n fold: limbs [1, 2] at n=8 is 1 + 2*256 = 513', () => {
    assert.equal(limbsToBigInt(['1', '2'], 8), 513n);
  });
});

// ---------------------------------------------------------------------
// fieldAsStrings -- the string/number/array-of-either normalization.
// ---------------------------------------------------------------------

describe('fieldAsStrings', () => {
  test('Aadhaar\'s qrDataPaddedLength arrives as a bare JSON number', () => {
    const fixture = loadFixture('register_aadhaar.json');
    assert.equal(typeof fixture.qrDataPaddedLength, 'number');
    assert.deepEqual(fieldAsStrings(fixture.qrDataPaddedLength), [String(fixture.qrDataPaddedLength)]);
  });

  test('KYC\'s data_padded arrives as an array of JSON numbers', () => {
    const fixture = loadFixture('register_kyc.json');
    assert.ok(Array.isArray(fixture.data_padded) && typeof fixture.data_padded[0] === 'number');
    const strs = fieldAsStrings(fixture.data_padded);
    assert.equal(strs.length, fixture.data_padded.length);
    assert.equal(strs[0], String(fixture.data_padded[0]));
  });

  test('a DSC fixture\'s raw_dsc_padded_length arrives as a bare string', () => {
    const fixture = loadFixture('dsc_sha256_ecdsa_secp521r1.json');
    assert.equal(typeof fixture.raw_dsc_padded_length, 'string');
    assert.deepEqual(fieldAsStrings(fixture.raw_dsc_padded_length), [fixture.raw_dsc_padded_length]);
  });

  test('a register fixture\'s scalar fields arrive array-wrapped', () => {
    const fixture = loadFixture('register_passport.json');
    assert.ok(Array.isArray(fixture.signed_attr_padded_length));
    assert.deepEqual(fieldAsStrings(fixture.signed_attr_padded_length), fixture.signed_attr_padded_length);
  });

  test('anything else -- object, boolean, null, missing -- is null', () => {
    assert.equal(fieldAsStrings(null), null);
    assert.equal(fieldAsStrings(undefined), null);
    assert.equal(fieldAsStrings(true), null);
    assert.equal(fieldAsStrings({}), null);
    assert.equal(fieldAsStrings([1, {}]), null);
  });
});

// ---------------------------------------------------------------------
// recoverMessage
// ---------------------------------------------------------------------

function buildSha256Padded(msg) {
  const padded = [...msg];
  padded.push(0x80);
  while ((padded.length + 8) % 64 !== 0) padded.push(0);
  const bitLen = BigInt(msg.length) * 8n;
  const lenBytes = Buffer.alloc(8);
  lenBytes.writeBigUInt64BE(bitLen);
  return Buffer.concat([Buffer.from(padded), lenBytes]);
}

function buildSha384512Padded(msg) {
  // 128-byte blocks, 16-byte big-endian length field (high 64 bits zero for
  // any real-sized message) -- sha_padding.rs's documented coincidence that
  // reading only the trailing 8 bytes still recovers the right value.
  const padded = [...msg];
  padded.push(0x80);
  while ((padded.length + 16) % 128 !== 0) padded.push(0);
  const bitLen = BigInt(msg.length) * 8n;
  const lenBytes = Buffer.alloc(16);
  lenBytes.writeBigUInt64BE(bitLen, 8);
  return Buffer.concat([Buffer.from(padded), lenBytes]);
}

describe('recoverMessage', () => {
  test('recovers a message from ordinary SHA-256-style (64-byte block) padding', () => {
    const msg = Buffer.from('hello world');
    const padded = buildSha256Padded(msg);
    assert.equal(padded.length % 64, 0);
    const recovered = recoverMessage(padded, padded.length);
    assert.ok(recovered);
    assert.equal(Buffer.compare(recovered, msg), 0);
  });

  test('recovers a message from SHA-384/512-style (128-byte block) padding', () => {
    const msg = Buffer.from(
      'a message long enough to span more than one 128-byte block boundary, to make sure the block-alignment and bounds checks both see real data',
    );
    const padded = buildSha384512Padded(msg);
    assert.equal(padded.length % 128, 0);
    assert.equal(padded.length % 64, 0); // the %64 check must not reject a genuinely 128-aligned buffer
    const recovered = recoverMessage(padded, padded.length);
    assert.ok(recovered);
    assert.equal(Buffer.compare(recovered, msg), 0);
  });

  test('returns null when the 0x80 marker is missing', () => {
    const msg = Buffer.from('hello');
    const padded = buildSha256Padded(msg);
    const corrupted = Buffer.from(padded);
    corrupted[msg.length] = 0x00; // was 0x80
    assert.equal(recoverMessage(corrupted, corrupted.length), null);
  });

  test('returns null when a byte between the marker and the length field is nonzero', () => {
    const msg = Buffer.from('hello world');
    const padded = buildSha256Padded(msg);
    const corrupted = Buffer.from(padded);
    corrupted[msg.length + 3] = 0x01;
    assert.equal(recoverMessage(corrupted, corrupted.length), null);
  });

  test('returns null when paddedLength is not block-aligned', () => {
    const msg = Buffer.from('hello world');
    const padded = buildSha256Padded(msg);
    assert.equal(recoverMessage(padded, padded.length - 1), null);
  });

  test('returns null when paddedLength exceeds the buffer', () => {
    const padded = buildSha256Padded(Buffer.from('hi'));
    assert.equal(recoverMessage(padded, padded.length + 64), null);
  });

  test('returns null for a too-short buffer', () => {
    assert.equal(recoverMessage(Buffer.alloc(0), 0), null);
  });

  test('returns null when the encoded bit-length is not a multiple of 8', () => {
    const padded = Buffer.alloc(64);
    padded[0] = 0x80;
    padded.writeBigUInt64BE(0xffffffffffffffffn, 56);
    assert.equal(recoverMessage(padded, 64), null);
  });

  test('returns null when the encoded length legitimately exceeds the buffer', () => {
    const padded = Buffer.alloc(64);
    padded[0] = 0x80;
    padded.writeBigUInt64BE(8000n, 56); // 1000 bytes -- far more than one 64-byte block can hold
    assert.equal(recoverMessage(padded, 64), null);
  });

  test('real fixture: recoverMessage(signed_attr, signed_attr_padded_length) round-trips through an actual RSA signature verification (RSA family)', () => {
    const fixture = loadFixture('register_passport.json');
    const signedAttrBytes = bytesFromDecimalArray(fixture.signed_attr);
    const paddedLength = scalarNumber(fixture.signed_attr_padded_length);
    const recovered = recoverMessage(signedAttrBytes, paddedLength);
    assert.ok(recovered, 'signed_attr must recover cleanly from a real fixture');

    // Independent check: build the DSC's real public key from pubKey_dsc's
    // own limbs and verify signature_passport over the recovered message
    // with node:crypto's own RSA verifier -- not this module's arithmetic.
    const n = 120;
    const k = 35;
    const modulus = limbsToBigInt(fixture.pubKey_dsc, n);
    const signature = limbsToBigInt(fixture.signature_passport, n);
    const modulusBytes = bigIntToBytesForTest(modulus, 512);
    const sigBytes = bigIntToBytesForTest(signature, 512);
    const publicKey = crypto.createPublicKey({
      key: { kty: 'RSA', n: modulusBytes.toString('base64url'), e: Buffer.from([3]).toString('base64url') },
      format: 'jwk',
    });
    const ok = crypto.verify('sha256', recovered, { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, sigBytes);
    assert.equal(ok, true, 'signature_passport must verify over recoverMessage\'s output under pubKey_dsc');
  });

  test('real fixture: recoverMessage(signed_attr, signed_attr_padded_length) round-trips through an actual ECDSA signature verification (secp521r1)', () => {
    const fixture = loadFixture('register_ecdsa_secp521r1.json');
    const signedAttrBytes = bytesFromDecimalArray(fixture.signed_attr);
    const paddedLength = scalarNumber(fixture.signed_attr_padded_length);
    const recovered = recoverMessage(signedAttrBytes, paddedLength);
    assert.ok(recovered);

    const n = 66;
    const k = 8;
    const x = limbsToBigInt(fixture.pubKey_dsc.slice(0, k), n);
    const y = limbsToBigInt(fixture.pubKey_dsc.slice(k, 2 * k), n);
    const r = limbsToBigInt(fixture.signature_passport.slice(0, k), n);
    const s = limbsToBigInt(fixture.signature_passport.slice(k, 2 * k), n);

    const fieldBytes = 66;
    const publicKey = crypto.createPublicKey({
      key: { kty: 'EC', crv: 'P-521', x: bigIntToBytesForTest(x, fieldBytes).toString('base64url'), y: bigIntToBytesForTest(y, fieldBytes).toString('base64url') },
      format: 'jwk',
    });
    const rawSig = Buffer.concat([bigIntToBytesForTest(r, fieldBytes), bigIntToBytesForTest(s, fieldBytes)]);
    const ok = crypto.verify('sha512', recovered, { key: publicKey, dsaEncoding: 'ieee-p1363' }, rawSig);
    assert.equal(ok, true, 'signature_passport must verify over recoverMessage\'s output under pubKey_dsc (ECDSA/secp521r1)');
  });

  test('real fixture: recoverMessage(raw_dsc, raw_dsc_padded_length) on a DSC fixture recovers exactly the DSC\'s own tbsCertificate bytes', { skip: !MOCK_CERTS_AVAILABLE }, () => {
    const fixture = loadFixture('dsc_sha256_ecdsa_secp521r1.json');
    const rawDsc = bytesFromDecimalArray(fixture.raw_dsc);
    const paddedLength = scalarNumber(fixture.raw_dsc_padded_length);
    const recovered = recoverMessage(rawDsc, paddedLength);
    assert.ok(recovered);

    const expectedTbs = tbsCertificateOf(mockCertPem('sha256_ecdsa_secp521r1', 'mock_dsc.pem'));
    assert.equal(Buffer.compare(recovered, expectedTbs), 0, 'recovered raw_dsc bytes must equal the real DSC certificate\'s own tbsCertificate, byte for byte');
  });
});

function bigIntToBytesForTest(value, length) {
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) hex = `0${hex}`;
  return Buffer.from(hex.padStart(length * 2, '0'), 'hex');
}

// ---------------------------------------------------------------------
// certPublicKey
// ---------------------------------------------------------------------

describe('certPublicKey', () => {
  test('returns null rather than throwing on malformed DER', () => {
    assert.equal(certPublicKey(Buffer.from([0x30, 0xff, 0x00])), null);
    assert.equal(certPublicKey(Buffer.alloc(0)), null);
    assert.equal(certPublicKey(Buffer.from('not a certificate at all')), null);
  });

  test('returns null (not a throw) for garbage that merely starts with a plausible tag', () => {
    const garbage = Buffer.alloc(200, 0x41);
    garbage[0] = 0x30;
    garbage[1] = 0x82;
    assert.equal(certPublicKey(garbage), null);
  });

  for (const row of ALL_CERT_FIXTURES) {
    test(`parses ${row.rawCertField} from ${row.file} and returns a usable key`, { skip: !MOCK_CERTS_AVAILABLE }, () => {
      const fixture = loadFixture(row.file);
      const tbs = tbsBytesOf(row, fixture);
      const wrapped = wrapAsCertificate(tbs);
      const result = certPublicKey(wrapped);
      assert.ok(result, `${row.file}: certPublicKey must not return null for a real, correctly-wrapped fixture certificate`);
      assert.ok(result.key);

      if (row.scheme === 'ecdsa') {
        // node:crypto/OpenSSL reports secp256r1 under its OpenSSL name,
        // 'prime256v1' -- the same curve, an alias node does not normalize.
        // Every other curve name it reports matches the circuit name
        // verbatim (spot-checked: secp224r1/384r1/521r1, all four
        // brainpool curves).
        const expectedCurve = row.curve === 'secp256r1' ? 'prime256v1' : row.curve;
        assert.equal(result.details.namedCurve, expectedCurve, `${row.file}: details.namedCurve must match the curve in the circuit name`);
      } else {
        assert.equal(result.key.asymmetricKeyType, 'rsa');
      }
    });
  }
});

// ---------------------------------------------------------------------
// keyMatchesCert
// ---------------------------------------------------------------------

describe('keyMatchesCert', () => {
  for (const row of ALL_CERT_FIXTURES) {
    test(`${row.file}: ${row.keyField} matches the certificate embedded in ${row.rawCertField}`, { skip: !MOCK_CERTS_AVAILABLE }, () => {
      const fixture = loadFixture(row.file);
      const tbs = tbsBytesOf(row, fixture);
      const cert = certPublicKey(wrapAsCertificate(tbs));
      assert.ok(cert);

      const suppliedLimbs = fixture[row.keyField];
      assert.equal(keyMatchesCert(suppliedLimbs, row.n, row.k, cert, row.scheme), true);
    });

    test(`${row.file}: flipping one limb of ${row.keyField} makes keyMatchesCert return false`, { skip: !MOCK_CERTS_AVAILABLE }, () => {
      const fixture = loadFixture(row.file);
      const tbs = tbsBytesOf(row, fixture);
      const cert = certPublicKey(wrapAsCertificate(tbs));
      assert.ok(cert);

      const suppliedLimbs = [...fixture[row.keyField]];
      const original = BigInt(suppliedLimbs[0]);
      suppliedLimbs[0] = String(original ^ 1n);

      assert.equal(keyMatchesCert(suppliedLimbs, row.n, row.k, cert, row.scheme), false);
    });
  }

  test('returns false (not a throw) when cert is null', () => {
    assert.equal(keyMatchesCert(['1', '2'], 64, 1, null, 'rsa'), false);
  });

  test('returns false for a limb-count mismatch', { skip: !MOCK_CERTS_AVAILABLE }, () => {
    const fixture = loadFixture('register_passport.json');
    const tbs = tbsBytesOf(REGISTER_FAMILY[0], fixture);
    const cert = certPublicKey(wrapAsCertificate(tbs));
    assert.equal(keyMatchesCert(fixture.pubKey_dsc.slice(0, 34), 120, 35, cert, 'rsa'), false);
  });

  test('returns false for an unknown scheme', { skip: !MOCK_CERTS_AVAILABLE }, () => {
    const fixture = loadFixture('register_passport.json');
    const tbs = tbsBytesOf(REGISTER_FAMILY[0], fixture);
    const cert = certPublicKey(wrapAsCertificate(tbs));
    assert.equal(keyMatchesCert(fixture.pubKey_dsc, 120, 35, cert, 'eddsa'), false);
  });
});

describe('limbsToBigInt rejects what chunks.rs rejects', () => {
  // chunks.rs's bigint_from_limbs returns None for n == 0 and for any limb
  // outside [0, 2^n). Accepting them would accumulate overlapping bits and
  // reassemble a DIFFERENT key -- verification would then fail with no message
  // explaining why, which is the confusing-failure mode worth spending a guard
  // on even though no legitimate input triggers it.
  test('rejects n == 0', () => {
    assert.equal(limbsToBigInt(['1', '2'], 0), null);
  });

  test('rejects a negative or non-integer n', () => {
    assert.equal(limbsToBigInt(['1'], -8), null);
    assert.equal(limbsToBigInt(['1'], 1.5), null);
  });

  test('rejects a limb that does not fit in n bits', () => {
    assert.equal(limbsToBigInt(['255'], 8), 255n); // 2^8 - 1 fits
    assert.equal(limbsToBigInt(['256'], 8), null); // 2^8 does not
    assert.equal(limbsToBigInt(['1', '999'], 8), null); // second limb overflows
  });

  test('rejects a negative limb', () => {
    assert.equal(limbsToBigInt(['-1'], 8), null);
  });

  test('rejects a limb that is not a decimal integer', () => {
    assert.equal(limbsToBigInt(['deadbeef'], 8), null);
    assert.equal(limbsToBigInt([''], 8), null);
  });

  test('still reassembles the non-byte-aligned n=66 case', () => {
    // Guards against a regression where the range check is computed with a
    // byte-aligned bound; 2^66 is not a whole number of bytes.
    const limb = (1n << 66n) - 1n;
    assert.equal(limbsToBigInt([limb.toString(), '1'], 66), limb | (1n << 66n));
    assert.equal(limbsToBigInt([(1n << 66n).toString()], 66), null);
  });
});

// =======================================================================
// Task 2: chain links, signature verification, and the verdict contract.
// None of this needs MOCK_CERTS_AVAILABLE -- unlike Task 1's independence
// checks (which cross-check against the sibling monorepo's own mock PEMs),
// `verify()` parses raw_dsc/raw_csca as a certificate using only the
// fixture's own bytes, so every test below runs on a bare checkout of this
// repo alone.
// =======================================================================

const AADHAAR_CIRCUIT = 'register_aadhaar';
const KYC_CIRCUIT = 'register_kyc';

/**
 * Every fixture this verifier is expected to actually handle: the 16
 * register-family + 5 DSC-family rows already defined above (reused, not
 * duplicated), plus Aadhaar. 22 of the 23 checked-in fixtures --
 * `register_kyc` is the one deliberate exception; see the describe block
 * below for why.
 */
const ALL_FIXTURE_CIRCUITS = [
  ...REGISTER_FAMILY.map((r) => ({ file: r.file, circuit: r.circuit, sigField: r.sigField, keyField: r.keyField, scheme: r.scheme, family: 'register' })),
  ...DSC_FAMILY.map((r) => ({ file: r.file, circuit: r.circuit, sigField: r.sigField, keyField: r.keyField, scheme: r.scheme, family: 'dsc' })),
  { file: 'register_aadhaar.json', circuit: AADHAAR_CIRCUIT, sigField: 'signature', keyField: 'pubKey', scheme: 'rsa', family: 'aadhaar' },
];

assert.equal(
  ALL_FIXTURE_CIRCUITS.length,
  22,
  'expected 22 of the 23 fixtures to be handled by this verifier -- register_kyc is the deliberate exception',
);

// Reason-text fragments used to assert a mutation failed for its OWN reason
// and no other -- six tests in this project have passed for the wrong
// reason, per this task's brief.
const DG1_LINK_PHRASE = 'dg1 hash does not match';
const ECONTENT_LINK_PHRASE = 'eContent hash does not match';
// A tampered key limb now fails the byte-window comparison
// (keyMatchesWindow, checked first -- mirrors dsc.rs's ordering) before it
// ever reaches the certificate-based comparison, so the reason names the
// window, not "the certificate". Both raw_dsc and raw_csca share this
// prefix, so one constant covers both families.
const CERT_LINK_PHRASE = 'does not match the bytes in raw_';
const SIGNATURE_PHRASES = ['RSA signature does not verify', 'PSS signature does not verify', 'ECDSA signature does not verify', 'Aadhaar signature does not verify'];

function assertReasonNamesOnly(reason, allowedPhrase, label) {
  assert.ok(reason.includes(allowedPhrase), `${label}: reason must contain "${allowedPhrase}", got: ${reason}`);
  const allOtherPhrases = [DG1_LINK_PHRASE, ECONTENT_LINK_PHRASE, CERT_LINK_PHRASE, ...SIGNATURE_PHRASES].filter((p) => p !== allowedPhrase);
  for (const other of allOtherPhrases) {
    assert.ok(!reason.includes(other), `${label}: reason must NOT mention "${other}", got: ${reason}`);
  }
}

function tamperedLimb(original) {
  return String(original) === '1' ? '2' : '1';
}

function signatureReasonPhrase(scheme) {
  if (scheme === 'rsa') return 'RSA signature does not verify';
  if (scheme === 'rsapss') return 'PSS signature does not verify';
  if (scheme === 'ecdsa') return 'ECDSA signature does not verify';
  return null;
}

describe("verify -- RSA-PSS uses native crypto.verify, pinned against the empirical evidence that licenses it", () => {
  // This module's PSS path uses native crypto.verify(RSA_PKCS1_PSS_PADDING)
  // directly, on the empirical claim (see verifyRsaPss's doc comment) that
  // every real PSS fixture's recovered EM (= signature^e mod n -- the
  // public-key raw RSA operation, computed here via crypto.publicEncrypt
  // with RSA_NO_PADDING, NOT a hand-rolled modexp) has its leftmost bit
  // clear, exactly what RFC 8017 step 12 guarantees for a conformant
  // signer. This test pins that EVIDENCE, not just the reasoning: if a
  // fixture is ever captured where this fails, a non-conformant issuer has
  // appeared in real traffic and the native-crypto.verify decision for PSS
  // needs revisiting -- see verifyRsaPss's doc comment in verify.mjs.
  const pssRows = ALL_FIXTURE_CIRCUITS.filter((r) => r.circuit.includes('_rsapss_'));
  assert.equal(pssRows.length, 5, 'expected all 5 PSS fixtures (4 register + 1 DSC)');

  for (const row of pssRows) {
    test(`${row.file}: recovered EM has a clear leftmost bit (RFC 8017 step 12's conformant-signer guarantee)`, () => {
      const fixture = loadFixture(row.file);
      const certRow = [...REGISTER_FAMILY, ...DSC_FAMILY].find((r) => r.file === row.file);
      assert.ok(certRow, `${row.file}: expected a REGISTER_FAMILY/DSC_FAMILY row for certificate parsing`);
      const tbs = tbsBytesOf(certRow, fixture);
      const cert = certPublicKey(wrapAsCertificate(tbs));
      assert.ok(cert, `${row.file}: certificate must parse`);

      const modulusBits = cert.key.asymmetricKeyDetails.modulusLength;
      const modulusBytes = Math.ceil(modulusBits / 8);
      const sig = limbsToBigInt(fixture[row.sigField], 120);
      assert.ok(sig !== null, `${row.file}: signature must reassemble`);
      const sigBytes = bigIntToBytesForTest(sig, modulusBytes);

      // s^e mod n via node:crypto's own raw RSA public-key operation.
      const em = crypto.publicEncrypt({ key: cert.key, padding: crypto.constants.RSA_NO_PADDING }, sigBytes);
      assert.equal(em.length, modulusBytes);
      assert.equal(
        em[0] & 0x80,
        0,
        `${row.file}: EM's leftmost bit must be clear -- if this fails, a non-conformant signer has ` +
          'appeared in real traffic and verifyRsaPss\'s native crypto.verify decision needs revisiting',
      );
    });
  }
});


describe('verify -- every non-KYC fixture is valid', () => {
  // THE test that matters most in this task: a verifier that checked nothing
  // would also pass a test that merely tolerated `skipped`, which has
  // happened twice in this project already -- so this asserts the verdict
  // is exactly `{verdict:'valid'}`, nothing looser.
  for (const row of ALL_FIXTURE_CIRCUITS) {
    test(`${row.file} (${row.circuit}) is valid`, () => {
      const fixture = loadFixture(row.file);
      assert.deepEqual(verify(row.circuit, fixture), { verdict: 'valid' });
    });
  }
});

describe('verify -- register_kyc is a deliberate, documented exception, not silently skipped coverage', () => {
  test('register_kyc is skipped, not valid', () => {
    const fixture = loadFixture('register_kyc.json');
    const result = verify(KYC_CIRCUIT, fixture);
    assert.equal(result.verdict, 'skipped');
    assert.match(
      result.reason,
      /BabyJubJub/,
      'the skip reason must name why -- EdDSA-BabyJubJub has no node:crypto-representable scheme',
    );
  });
});

describe('verify -- tampering the signature is invalid, naming the signature check and nothing else', () => {
  for (const row of ALL_FIXTURE_CIRCUITS) {
    test(`${row.file}: flipping one limb of ${row.sigField} is invalid for the signature check`, () => {
      const fixture = loadFixture(row.file);
      const tampered = structuredClone(fixture);
      const limbs = [...tampered[row.sigField]];
      limbs[0] = tamperedLimb(limbs[0]);
      tampered[row.sigField] = limbs;

      const result = verify(row.circuit, tampered);
      assert.equal(result.verdict, 'invalid', `${row.file}: got ${JSON.stringify(result)}`);
      // row.scheme (borrowed from REGISTER_FAMILY/DSC_FAMILY) is the
      // key-MATCHING scheme ('rsa'|'ecdsa' -- PSS shares RSA's key layout),
      // not the signature scheme, so it cannot distinguish plain RSA from
      // RSA-PSS here. Re-derive the real scheme from the circuit name.
      const realScheme = row.family === 'aadhaar' ? 'aadhaar' : parseCircuitName(row.circuit).scheme;
      const phrase = signatureReasonPhrase(realScheme);
      if (phrase) {
        assertReasonNamesOnly(result.reason, phrase, row.file);
      } else {
        // Aadhaar's own phrase isn't in the shared SIGNATURE_PHRASES set
        // (different family, no chain links to cross-check against), so it
        // gets its own direct assertion instead of the shared helper.
        assert.match(result.reason, /Aadhaar signature does not verify/, `${row.file}: got ${result.reason}`);
      }
    });
  }
});

describe('verify -- tampering dg1 is invalid, naming the dg1 link and nothing else (register family only)', () => {
  for (const row of REGISTER_FAMILY) {
    test(`${row.file}: flipping one byte of dg1 is invalid for the dg1 link`, () => {
      const fixture = loadFixture(row.file);
      const tampered = structuredClone(fixture);
      const dg1 = [...tampered.dg1];
      dg1[0] = String((Number(dg1[0]) ^ 1) & 0xff);
      tampered.dg1 = dg1;

      const result = verify(row.circuit, tampered);
      assert.equal(result.verdict, 'invalid', `${row.file}: got ${JSON.stringify(result)}`);
      assertReasonNamesOnly(result.reason, DG1_LINK_PHRASE, row.file);
    });
  }
});

describe('verify -- tampering eContent is invalid, naming the eContent link and nothing else (register family only)', () => {
  for (const row of REGISTER_FAMILY) {
    test(`${row.file}: flipping eContent[0] (outside the dg1_hash_offset=70 window) is invalid for the eContent link`, () => {
      const fixture = loadFixture(row.file);
      // dg1_hash_offset is 70 for every register-family fixture (verified
      // against every checked-in fixture before writing this test), so
      // index 0 lies outside the dg1-hash window and link 1 stays intact --
      // only link 2 (the eContent<->signed_attr hash) can break here.
      assert.equal(Number([].concat(fixture.dg1_hash_offset)[0]), 70, `${row.file}: dg1_hash_offset assumption changed`);
      const tampered = structuredClone(fixture);
      const econtent = [...tampered.eContent];
      econtent[0] = String((Number(econtent[0]) ^ 1) & 0xff);
      tampered.eContent = econtent;

      const result = verify(row.circuit, tampered);
      assert.equal(result.verdict, 'invalid', `${row.file}: got ${JSON.stringify(result)}`);
      assertReasonNamesOnly(result.reason, ECONTENT_LINK_PHRASE, row.file);
    });
  }
});

describe('verify -- tampering the certificate-embedded key limb is invalid, naming the key/certificate link and nothing else', () => {
  // Covers both families: pubKey_dsc (register, checked against raw_dsc --
  // this module's own added link, see verifyRegisterFamily's doc comment)
  // and csca_pubKey (DSC, checked against raw_csca -- dsc.circom's own
  // link). Without this link, any key matching any signature would pass.
  for (const row of [...REGISTER_FAMILY, ...DSC_FAMILY]) {
    test(`${row.file}: flipping one limb of ${row.keyField} is invalid for the key/certificate link`, () => {
      const fixture = loadFixture(row.file);
      const tampered = structuredClone(fixture);
      const limbs = [...tampered[row.keyField]];
      limbs[0] = tamperedLimb(limbs[0]);
      tampered[row.keyField] = limbs;

      const result = verify(row.circuit, tampered);
      assert.equal(result.verdict, 'invalid', `${row.file}: got ${JSON.stringify(result)}`);
      assertReasonNamesOnly(result.reason, CERT_LINK_PHRASE, row.file);
    });
  }
});

describe("verify -- a genuine key at the WRONG declared offset is invalid, not valid (the certificate-only check would have missed this)", () => {
  // The scenario this closes: pubKey_dsc/csca_pubKey are left untouched --
  // still the real key, still matching the parsed certificate -- but the
  // declared offset is shifted a few bytes within bounds. keyMatchesCert
  // alone (certificate-based, never reads offset/size) would have said
  // Valid here; keyMatchesWindow (byte-window comparison against the
  // STATED offset, mirroring dsc.rs) is what actually ties the key to its
  // claimed location and must say Invalid.
  test("register family: shifting dsc_pubKey_offset by 8 bytes (still in-bounds) is invalid", () => {
    const fixture = loadFixture("register_passport.json");
    const tampered = structuredClone(fixture);
    const shifted = Number([].concat(fixture.dsc_pubKey_offset)[0]) + 8;
    tampered.dsc_pubKey_offset = [String(shifted)];
    const result = verify("register_sha256_sha256_sha256_rsa_3_4096", tampered);
    assert.equal(result.verdict, "invalid", `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /does not match the bytes in raw_dsc/);
  });

  test("DSC family: shifting csca_pubKey_offset by 8 bytes (still in-bounds) is invalid", () => {
    const fixture = loadFixture("dsc_sha256_rsa_65537_4096.json");
    const tampered = structuredClone(fixture);
    const shifted = Number(fixture.csca_pubKey_offset) + 8;
    tampered.csca_pubKey_offset = String(shifted);
    const result = verify("dsc_sha256_rsa_65537_4096", tampered);
    assert.equal(result.verdict, "invalid", `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /does not match the bytes in raw_csca/);
  });
});

describe('verify -- skip paths', () => {
  test('an unknown circuit name is skipped', () => {
    const result = verify('totally_not_a_real_circuit', {});
    assert.equal(result.verdict, 'skipped');
  });

  test('a non-object input.json is skipped, not a thrown exception', () => {
    assert.equal(verify('register_sha256_sha256_sha256_rsa_3_4096', null).verdict, 'skipped');
    assert.equal(verify('register_sha256_sha256_sha256_rsa_3_4096', 'not an object').verdict, 'skipped');
    assert.equal(verify('register_sha256_sha256_sha256_rsa_3_4096', [1, 2, 3]).verdict, 'skipped');
  });

  test('a missing field is skipped, not invalid (register family)', () => {
    const fixture = loadFixture('register_passport.json');
    const tampered = structuredClone(fixture);
    delete tampered.pubKey_dsc;
    const result = verify('register_sha256_sha256_sha256_rsa_3_4096', tampered);
    assert.equal(result.verdict, 'skipped');
  });

  test('a missing field is skipped, not invalid (DSC family)', () => {
    const fixture = loadFixture('dsc_sha256_rsa_65537_4096.json');
    const tampered = structuredClone(fixture);
    delete tampered.csca_pubKey;
    const result = verify('dsc_sha256_rsa_65537_4096', tampered);
    assert.equal(result.verdict, 'skipped');
  });

  test('malformed eContent padding is skipped, not invalid (register family)', () => {
    const fixture = loadFixture('register_passport.json');
    const tampered = structuredClone(fixture);
    // Not a multiple of 64: recoverMessage's block-alignment check rejects
    // this unconditionally, regardless of the real fixture's own byte
    // content -- unlike a padded length that IS block-aligned (e.g. 64),
    // which this real fixture's actual bytes might still happen to parse as
    // a differently-recovered (but structurally valid) message, breaking
    // link 2 (Invalid) rather than the padding parse itself (Skipped). Still
    // >= dg1_hash_offset(70) + dg_hash/8(32) = 102, so link 1's own offset
    // bound check (checked first) does not trip instead.
    tampered.eContent_padded_length = ['447'];
    const result = verify('register_sha256_sha256_sha256_rsa_3_4096', tampered);
    assert.equal(result.verdict, 'skipped', `got ${JSON.stringify(result)}`);
  });

  test('malformed raw_dsc padding is skipped, not invalid (DSC family)', () => {
    const fixture = loadFixture('dsc_sha256_rsa_65537_4096.json');
    const tampered = structuredClone(fixture);
    // Not a multiple of 64 -- see the eContent test above for why this is
    // the deterministic choice rather than a block-aligned length.
    tampered.raw_dsc_padded_length = '703';
    const result = verify('dsc_sha256_rsa_65537_4096', tampered);
    assert.equal(result.verdict, 'skipped', `got ${JSON.stringify(result)}`);
  });

  test('an unreadable certificate is skipped (register family: raw_dsc\'s outer DER tag corrupted)', () => {
    const fixture = loadFixture('register_passport.json');
    const tampered = structuredClone(fixture);
    const rawDsc = [...tampered.raw_dsc];
    rawDsc[0] = '0'; // corrupt the tbsCertificate's own outer SEQUENCE tag byte
    tampered.raw_dsc = rawDsc;
    const result = verify('register_sha256_sha256_sha256_rsa_3_4096', tampered);
    assert.equal(result.verdict, 'skipped', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /certificate/);
  });

  test('an unreadable certificate is skipped (DSC family: raw_csca\'s outer DER tag corrupted)', () => {
    const fixture = loadFixture('dsc_sha256_rsa_65537_4096.json');
    const tampered = structuredClone(fixture);
    const rawCsca = [...tampered.raw_csca];
    rawCsca[0] = '0';
    tampered.raw_csca = rawCsca;
    const result = verify('dsc_sha256_rsa_65537_4096', tampered);
    assert.equal(result.verdict, 'skipped', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /certificate/);
  });

  test('an out-of-range dg1_hash_offset is invalid (register family, passportVerifier.circom:53-66)', () => {
    const fixture = loadFixture('register_passport.json');
    const tampered = structuredClone(fixture);
    tampered.dg1_hash_offset = ['100000'];
    const result = verify('register_sha256_sha256_sha256_rsa_3_4096', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
  });

  test('an out-of-range csca_pubKey_offset is skipped, not invalid (DSC family, dsc.circom:110-127)', () => {
    const fixture = loadFixture('dsc_sha256_rsa_65537_4096.json');
    const tampered = structuredClone(fixture);
    tampered.csca_pubKey_offset = '100000';
    const result = verify('dsc_sha256_rsa_65537_4096', tampered);
    assert.equal(result.verdict, 'skipped', `got ${JSON.stringify(result)}`);
  });

  test('an out-of-range dsc_pubKey_offset is skipped, not invalid (register family -- this module\'s own added link)', () => {
    const fixture = loadFixture('register_passport.json');
    const tampered = structuredClone(fixture);
    tampered.dsc_pubKey_offset = ['100000'];
    const result = verify('register_sha256_sha256_sha256_rsa_3_4096', tampered);
    assert.equal(result.verdict, 'skipped', `got ${JSON.stringify(result)}`);
  });
});

describe('parseCircuitName', () => {
  test('a DSC name (one hash tag) is not misread as a register name (three hash tags)', () => {
    const dsc = parseCircuitName('dsc_sha256_rsa_65537_4096');
    assert.equal(dsc.family, 'dsc');
    assert.equal(dsc.sigHash, 256);
    assert.equal(dsc.scheme, 'rsa');

    const reg = parseCircuitName('register_sha1_sha256_sha256_rsa_65537_4096');
    assert.equal(reg.family, 'register');
    assert.deepEqual([reg.dgHash, reg.econtentHash, reg.sigHash], [160, 256, 256]);
  });

  test('register_kyc and register_aadhaar are their own families', () => {
    assert.equal(parseCircuitName('register_kyc').family, 'kyc');
    assert.equal(parseCircuitName('register_aadhaar').family, 'aadhaar');
  });

  test('an unknown or malformed circuit name is null', () => {
    assert.equal(parseCircuitName('totally_unknown'), null);
    assert.equal(parseCircuitName('register_sha256_sha256_sha256_rsa_65537'), null); // missing the bits component
    assert.equal(parseCircuitName('register_sha256_sha256_sha256_ecdsa_not_a_curve'), null);
    assert.equal(parseCircuitName('dsc_sha256_ecdsa_not_a_curve'), null);
  });

  test('an ECDSA curve absent from CURVE_PARAMS is null, not a guess', () => {
    assert.equal(parseCircuitName('register_sha256_sha256_sha256_ecdsa_secp192r1'), null);
  });
});

describe('CLI contract: stdin {circuit, inputPath} JSON -> one stdout verdict JSON line, exit 0', () => {
  const scriptPath = path.join(__dirname, 'verify.mjs');

  function runCli(input) {
    return spawnSync(process.execPath, [scriptPath], { input, encoding: 'utf8' });
  }

  test('a valid fixture piped through the CLI prints {"verdict":"valid"} and exits 0', () => {
    const inputPath = path.join(FIXTURES_DIR, 'register_passport.json');
    const request = JSON.stringify({ circuit: 'register_sha256_sha256_sha256_rsa_3_4096', inputPath });
    const result = runCli(request);
    assert.equal(result.status, 0, `stderr: ${result.stderr}`);
    assert.deepEqual(JSON.parse(result.stdout.trim()), { verdict: 'valid' });
  });

  test('an unknown circuit prints a skipped verdict and still exits 0', () => {
    const inputPath = path.join(FIXTURES_DIR, 'register_passport.json');
    const request = JSON.stringify({ circuit: 'not_a_real_circuit', inputPath });
    const result = runCli(request);
    assert.equal(result.status, 0, `stderr: ${result.stderr}`);
    assert.equal(JSON.parse(result.stdout.trim()).verdict, 'skipped');
  });

  test('malformed stdin JSON prints a skipped verdict and still exits 0', () => {
    const result = runCli('this is not json');
    assert.equal(result.status, 0, `stderr: ${result.stderr}`);
    assert.equal(JSON.parse(result.stdout.trim()).verdict, 'skipped');
  });

  test('stdin JSON missing the required fields prints a skipped verdict and still exits 0', () => {
    const result = runCli(JSON.stringify({ circuit: 'register_sha256_sha256_sha256_rsa_3_4096' }));
    assert.equal(result.status, 0, `stderr: ${result.stderr}`);
    assert.equal(JSON.parse(result.stdout.trim()).verdict, 'skipped');
  });

  test('a missing inputPath file prints a skipped verdict and still exits 0', () => {
    const request = JSON.stringify({
      circuit: 'register_sha256_sha256_sha256_rsa_3_4096',
      inputPath: '/nonexistent/path/does/not/exist/input.json',
    });
    const result = runCli(request);
    assert.equal(result.status, 0, `stderr: ${result.stderr}`);
    assert.equal(JSON.parse(result.stdout.trim()).verdict, 'skipped');
  });

  test('an inputPath file that is not valid JSON prints a skipped verdict and still exits 0', () => {
    const badPath = path.join(FIXTURES_DIR, '..', '..', 'signature-verifier', 'verify.mjs');
    const request = JSON.stringify({ circuit: 'register_sha256_sha256_sha256_rsa_3_4096', inputPath: badPath });
    const result = runCli(request);
    assert.equal(result.status, 0, `stderr: ${result.stderr}`);
    assert.equal(JSON.parse(result.stdout.trim()).verdict, 'skipped');
  });
});
