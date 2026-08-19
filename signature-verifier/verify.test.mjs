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

// Mirrors real_fixtures.rs's `all_real_fixtures_are_present`: that Rust test
// reads the directory itself (`std::fs::read_dir`) and asserts the on-disk
// `.json` count against its `FIXTURES` table, so a fixture checked in
// without a row fails loudly instead of silently going unchecked. The JS
// suite below used to assert two bare integer literals (21, 22) instead --
// numbers that stayed correct only because nobody added a fixture without
// remembering to update them by hand. Deriving from an actual directory
// scan here means an added-but-unlisted fixture now fails in *both*
// languages, not just Rust's.
const ON_DISK_FIXTURE_COUNT = fs.readdirSync(FIXTURES_DIR).filter((f) => f.endsWith('.json')).length;

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
assert.equal(
  ALL_CERT_FIXTURES.length,
  ON_DISK_FIXTURE_COUNT - 2,
  `expected all but 2 (register_aadhaar.json, register_kyc.json -- neither carries a raw_dsc/raw_csca ` +
    `certificate window) of the ${ON_DISK_FIXTURE_COUNT} on-disk tests/fixtures/*.json files to be listed ` +
    'in REGISTER_FAMILY/DSC_FAMILY',
);

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

/** Inverse of limbsToBigInt: splits `value` into `k` base-`2^n` limbs,
 * least-significant limb first, as decimal strings -- for tests that need
 * to construct a wire-shaped limb array from a value they picked (an
 * off-curve point's coordinates, an out-of-range scalar), rather than one
 * read out of a real fixture. */
function limbsFromBigInt(value, n, k) {
  const mask = (1n << BigInt(n)) - 1n;
  const limbs = [];
  let v = value;
  for (let i = 0; i < k; i++) {
    limbs.push(String(v & mask));
    v >>= BigInt(n);
  }
  return limbs;
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

// ---------------------------------------------------------------------
// An independent (test-only, not imported from verify.mjs) DER reader for
// RSAPublicKey's modulus, used solely to build the "known correct" expected
// value for the RSASSA-PSS tests below without relying on the very
// extraction code (`extractRsaModulus`) those tests exist to pin -- reusing
// the fix's own code to build its own input would not actually prove
// anything. Validated against `KeyObject.export({format:'jwk'})` for a
// plain RSA key (where JWK export works) before being trusted for the one
// case JWK export cannot handle (RSASSA-PSS).
// ---------------------------------------------------------------------

function readTlv(buf, offset) {
  const tag = buf[offset];
  const first = buf[offset + 1];
  let length;
  let headerLen;
  if (first & 0x80) {
    const numLenBytes = first & 0x7f;
    let len = 0;
    for (let i = 0; i < numLenBytes; i++) len = len * 256 + buf[offset + 2 + i];
    length = len;
    headerLen = 2 + numLenBytes;
  } else {
    length = first;
    headerLen = 2;
  }
  const contentStart = offset + headerLen;
  return { tag, contentStart, content: buf.subarray(contentStart, contentStart + length), nextOffset: contentStart + length };
}

function rsaModulusFromSpkiDerIndependently(spkiDer) {
  const outer = readTlv(spkiDer, 0);
  const alg = readTlv(outer.content, 0);
  const bitstr = readTlv(outer.content, alg.nextOffset);
  const rsaPublicKey = readTlv(bitstr.content, 1); // skip the leading unused-bits byte
  const modulusTlv = readTlv(rsaPublicKey.content, 0);
  let modulus = modulusTlv.content;
  if (modulus.length > 1 && modulus[0] === 0x00 && (modulus[1] & 0x80) !== 0) {
    modulus = modulus.subarray(1);
  }
  return modulus;
}

describe('keyMatchesCert -- id-RSASSA-PSS SPKI certificates', () => {
  // Real DSCs can carry an id-RSASSA-PSS SPKI algorithm identifier (this
  // plan's design doc). keyMatchesCert's RSA branch used to call
  // `cert.key.export({format:'jwk'})`, which throws `Unsupported JWK Key
  // Type` for an rsa-pss KeyObject -- caught by the branch's own try/catch
  // and reported as "does not match", even when the supplied modulus was
  // correct. This pins the fix.

  test("sanity check: this test file's own independent DER reader agrees with JWK export for a plain (non-PSS) RSA key", () => {
    const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwkModulus = Buffer.from(publicKey.export({ format: 'jwk' }).n, 'base64url');
    const derModulus = rsaModulusFromSpkiDerIndependently(publicKey.export({ format: 'der', type: 'spki' }));
    assert.equal(Buffer.compare(jwkModulus, derModulus), 0);
  });

  test('the correct modulus for an id-RSASSA-PSS SPKI key is reported as a match, not a mismatch', () => {
    const { publicKey } = crypto.generateKeyPairSync('rsa-pss', {
      modulusLength: 3072,
      hashAlgorithm: 'sha256',
      mgf1HashAlgorithm: 'sha256',
      saltLength: 32,
    });
    assert.equal(publicKey.asymmetricKeyType, 'rsa-pss');
    // Confirms the premise this test rests on: JWK export genuinely throws
    // for this key, so a test that passed without this fix would not
    // actually be exercising the bug.
    assert.throws(() => publicKey.export({ format: 'jwk' }), /Unsupported JWK Key Type/);

    const modulus = rsaModulusFromSpkiDerIndependently(publicKey.export({ format: 'der', type: 'spki' }));
    const n = 120;
    const k = 35; // this file's fixed RSA limb parameters (register/DSC alike)
    const suppliedLimbs = limbsFromBigInt(BigInt(`0x${modulus.toString('hex')}`), n, k);

    const cert = { key: publicKey, details: { ...publicKey.asymmetricKeyDetails } };
    assert.equal(
      keyMatchesCert(suppliedLimbs, n, k, cert, 'rsa'),
      true,
      'the correct modulus must match even though the SPKI algorithm is id-RSASSA-PSS, not rsaEncryption',
    );
  });

  test('a WRONG modulus for an id-RSASSA-PSS SPKI key is still reported as a mismatch', () => {
    // Confirms the fix does not overcorrect into "always matches" for PSS
    // keys -- it must still genuinely compare the modulus.
    const { publicKey } = crypto.generateKeyPairSync('rsa-pss', {
      modulusLength: 2048,
      hashAlgorithm: 'sha256',
      mgf1HashAlgorithm: 'sha256',
      saltLength: 32,
    });
    const cert = { key: publicKey, details: { ...publicKey.asymmetricKeyDetails } };
    const wrongLimbs = limbsFromBigInt(12345n, 120, 35);
    assert.equal(keyMatchesCert(wrongLimbs, 120, 35, cert, 'rsa'), false);
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
  ON_DISK_FIXTURE_COUNT - 1,
  `expected all but 1 (register_kyc.json, the deliberate exception) of the ${ON_DISK_FIXTURE_COUNT} on-disk ` +
    'tests/fixtures/*.json files to be handled by this verifier',
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

describe('verify -- the certificate\'s RSA public exponent must match the one the circuit name declares', () => {
  // keyMatchesCert only ever compares the modulus (RSA) or point (ECDSA),
  // never the exponent -- so without a dedicated check, a certificate whose
  // real exponent disagrees with the circuit name's declared `e` verifies as
  // Valid anyway. Reusing real fixtures (rather than a hand-built cert) for
  // this: register_passport.json's DSC certificate genuinely has e=3
  // (register_sha256_sha256_sha256_rsa_3_4096), and
  // dsc_sha256_rsa_65537_4096.json's CSCA certificate genuinely has
  // e=65537. Feeding either fixture's own inputs to the OTHER exponent's
  // circuit name changes nothing else reachable before this check (same
  // hash tags, same modulus, same signature bytes -- `bits` in the circuit
  // name is otherwise unused) -- so a regression that dropped this check
  // would make either of these Valid again, not just Invalid-for-some-other-
  // reason.
  test('register_passport.json (real e=3) claimed as e=65537 is invalid, naming the exponent mismatch', () => {
    const fixture = loadFixture('register_passport.json');
    const result = verify('register_sha256_sha256_sha256_rsa_65537_4096', fixture);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /RSA public exponent/, `got ${result.reason}`);
  });

  test('dsc_sha256_rsa_65537_4096.json (real e=65537) claimed as e=3 is invalid, naming the exponent mismatch', () => {
    const fixture = loadFixture('dsc_sha256_rsa_65537_4096.json');
    const result = verify('dsc_sha256_rsa_3_4096', fixture);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /RSA public exponent/, `got ${result.reason}`);
  });
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

  test('a missing field is invalid, not skipped (register family)', () => {
    // Plan B, Task 2: pubKey_dsc is a fixed-size signal array in the circuit
    // (register.circom:87); a JSON payload missing it entirely cannot even
    // produce a witness, which is a stronger rejection than a failed
    // constraint, not a coverage gap.
    const fixture = loadFixture('register_passport.json');
    const tampered = structuredClone(fixture);
    delete tampered.pubKey_dsc;
    const result = verify('register_sha256_sha256_sha256_rsa_3_4096', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
  });

  test('a missing field is invalid, not skipped (DSC family)', () => {
    // Same reasoning as the register-family case above: csca_pubKey is a
    // fixed-size signal array (dsc.circom:65).
    const fixture = loadFixture('dsc_sha256_rsa_65537_4096.json');
    const tampered = structuredClone(fixture);
    delete tampered.csca_pubKey;
    const result = verify('dsc_sha256_rsa_65537_4096', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
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

  test('an out-of-range csca_pubKey_offset is invalid, not skipped (DSC family, dsc.circom:110-127 hard-asserts this range)', () => {
    // dsc.circom:111-127 Num2Bits(12)s the offset, the size, and their sum,
    // then asserts `csca_pubKey_offset_in_range === 1` -- an unsatisfiable
    // constraint for an out-of-range offset, so the circuit itself could
    // never produce a proof for this input. Treating it as Skipped (an
    // earlier version of this module did) was looser than both the RFC and
    // the circuit, and inflated the skip-rate metric the fail-closed
    // rollout depends on to gate enforcement.
    const fixture = loadFixture('dsc_sha256_rsa_65537_4096.json');
    const tampered = structuredClone(fixture);
    tampered.csca_pubKey_offset = '100000';
    const result = verify('dsc_sha256_rsa_65537_4096', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
  });

  test('an out-of-range dsc_pubKey_offset is invalid, not skipped (register family -- this module\'s own added link, register.circom:102-123 hard-asserts this range)', () => {
    const fixture = loadFixture('register_passport.json');
    const tampered = structuredClone(fixture);
    tampered.dsc_pubKey_offset = ['100000'];
    const result = verify('register_sha256_sha256_sha256_rsa_3_4096', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
  });
});

// =======================================================================
// Plan B, Task 2: malformed input is invalid, not skipped.
//
// The premise: `Skipped` used to mean two different things -- "cannot be
// certain" and "this input is broken" -- and nearly every site below was
// the second, reported as the first. Each of these mutations produces an
// input the sibling monorepo's own circuit could never turn into a proof
// (a missing/wrong-count fixed-size signal, a byte-range violation, an
// offset/size relationship the circuit also range-checks, or a limb that
// cannot satisfy the circuit's own Num2Bits/BigLessThan constraints) -- see
// this task's report for the exact circuit citation backing each case.
// Where a case is NOT here (RSA-scheme modulus reassembly, the four
// SHA-padding-shape checks, three Aadhaar-specific width checks), that is
// deliberate: this task's report explains why those stay Skipped rather
// than being promoted on a guess.
// =======================================================================

function outOfRangeLimb() {
  // >= 2^120 (the widest `n` any RSA/RSA-PSS circuit here uses) and
  // >= 2^121 (Aadhaar's `n`) alike -- comfortably out of range for every
  // scheme's limb width, so `limbsToBigInt` returns null regardless of
  // which field it lands in.
  return (1n << 400n).toString();
}

describe('verify -- Plan B Task 2: byte-range violations are invalid, not skipped', () => {
  test('dg1 contains a non-byte value is invalid (register family, passportVerifier.circom:68 BytesToBitsArray -> Num2Bits(8))', () => {
    const fixture = loadFixture('register_passport.json');
    const tampered = structuredClone(fixture);
    const dg1 = [...tampered.dg1];
    dg1[0] = '256';
    tampered.dg1 = dg1;
    const result = verify('register_sha256_sha256_sha256_rsa_3_4096', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /dg1 contains a non-byte value/);
  });

  test('eContent contains a non-byte value is invalid (register family, passportVerifier.circom:79 ShaBytesDynamic -> Num2Bits(8))', () => {
    const fixture = loadFixture('register_passport.json');
    const tampered = structuredClone(fixture);
    const econtent = [...tampered.eContent];
    econtent[econtent.length - 1] = '999';
    tampered.eContent = econtent;
    const result = verify('register_sha256_sha256_sha256_rsa_3_4096', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /eContent contains a non-byte value/);
  });

  test('signed_attr contains a non-byte value is invalid (register family, passportVerifier.circom:89 ShaBytesDynamic -> Num2Bits(8))', () => {
    const fixture = loadFixture('register_passport.json');
    const tampered = structuredClone(fixture);
    const sa = [...tampered.signed_attr];
    sa[sa.length - 1] = '999';
    tampered.signed_attr = sa;
    const result = verify('register_sha256_sha256_sha256_rsa_3_4096', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /signed_attr contains a non-byte value/);
  });

  test('raw_dsc contains a non-byte value is invalid (register family, register.circom:100 explicit AssertBytes)', () => {
    const fixture = loadFixture('register_passport.json');
    const tampered = structuredClone(fixture);
    const rawDsc = [...tampered.raw_dsc];
    rawDsc[rawDsc.length - 1] = '300';
    tampered.raw_dsc = rawDsc;
    const result = verify('register_sha256_sha256_sha256_rsa_3_4096', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /raw_dsc contains a non-byte value/);
  });

  test('raw_csca contains a non-byte value is invalid (DSC family, dsc.circom:73 explicit AssertBytes)', () => {
    const fixture = loadFixture('dsc_sha256_rsa_65537_4096.json');
    const tampered = structuredClone(fixture);
    const rawCsca = [...tampered.raw_csca];
    rawCsca[rawCsca.length - 1] = '300';
    tampered.raw_csca = rawCsca;
    const result = verify('dsc_sha256_rsa_65537_4096', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /raw_csca contains a non-byte value/);
  });

  test('raw_dsc contains a non-byte value is invalid (DSC family, dsc.circom:203 PackBytesAndPoseidon -> AssertBytes)', () => {
    const fixture = loadFixture('dsc_sha256_rsa_65537_4096.json');
    const tampered = structuredClone(fixture);
    const rawDsc = [...tampered.raw_dsc];
    rawDsc[rawDsc.length - 1] = '300';
    tampered.raw_dsc = rawDsc;
    const result = verify('dsc_sha256_rsa_65537_4096', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /raw_dsc contains a non-byte value/);
  });

  test('qrDataPadded contains a non-byte value is invalid (Aadhaar, register_aadhaar.circom:46 Sha256Bytes -> Num2Bits(8))', () => {
    const fixture = loadFixture('register_aadhaar.json');
    const tampered = structuredClone(fixture);
    const qr = [...tampered.qrDataPadded];
    qr[qr.length - 1] = '400';
    tampered.qrDataPadded = qr;
    const result = verify(AADHAAR_CIRCUIT, tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /qrDataPadded contains a non-byte value/);
  });
});

describe('verify -- Plan B Task 2: a missing or wrong-count fixed-size field is invalid, not skipped', () => {
  test('a missing field is invalid (Aadhaar family)', () => {
    const fixture = loadFixture('register_aadhaar.json');
    const tampered = structuredClone(fixture);
    delete tampered.pubKey;
    const result = verify(AADHAAR_CIRCUIT, tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /missing or malformed field: pubKey/);
  });

  test('a wrong-count pubKey_dsc (ECDSA) is invalid, not skipped (fixed-size kScaled signal array)', () => {
    const fixture = loadFixture('register_ecdsa_secp256r1.json');
    const tampered = structuredClone(fixture);
    tampered.pubKey_dsc = tampered.pubKey_dsc.slice(0, -1);
    const result = verify('register_sha256_sha256_sha256_ecdsa_secp256r1', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /expected 2\*k=/);
  });

  test('a wrong-count signature_passport (ECDSA) is invalid, not skipped (fixed-size kScaled signal array)', () => {
    const fixture = loadFixture('register_ecdsa_secp256r1.json');
    const tampered = structuredClone(fixture);
    tampered.signature_passport = tampered.signature_passport.slice(0, -1);
    const result = verify('register_sha256_sha256_sha256_ecdsa_secp256r1', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /signature has \d+ limbs, expected 2\*k=/);
  });
});

describe('verify -- Plan B Task 2: a fixed-size array shorter than its own declared length is invalid, not skipped', () => {
  test('eContent shorter than dg1_hash_offset + dg_hash/8 declares is invalid (register family)', () => {
    const fixture = loadFixture('register_passport.json');
    const tampered = structuredClone(fixture);
    // dg1_hash_offset=70, dg_hash=256 bits -> window ends at byte 102;
    // truncate eContent to 100 bytes so the (already in-range) offset+len
    // exceeds the array actually supplied.
    tampered.eContent = tampered.eContent.slice(0, 100);
    const result = verify('register_sha256_sha256_sha256_rsa_3_4096', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /eContent is shorter than dg1_hash_offset/);
  });

  test('raw_csca shorter than raw_csca_actual_length declares is invalid (DSC family)', () => {
    const fixture = loadFixture('dsc_sha256_rsa_65537_4096.json');
    const tampered = structuredClone(fixture);
    tampered.raw_csca = tampered.raw_csca.slice(0, 10);
    const result = verify('dsc_sha256_rsa_65537_4096', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /raw_csca is shorter than raw_csca_actual_length declares/);
  });
});

describe('verify -- Plan B Task 2: ECDSA-scheme limb reassembly and shape failures are invalid (ecdsaVerifier.circom Num2Bits(n), checkPubkeyPosition.circom key_length_ok)', () => {
  test('an odd dsc_pubKey_actual_size is invalid, not skipped (register family ECDSA -- checkPubkeyPosition.circom:73-77 + signatureAlgorithm.circom:548-551, every valid ECDSA key length is even)', () => {
    const fixture = loadFixture('register_ecdsa_secp256r1.json');
    const tampered = structuredClone(fixture);
    assert.deepEqual(tampered.dsc_pubKey_actual_size, ['64']);
    tampered.dsc_pubKey_actual_size = ['63'];
    const result = verify('register_sha256_sha256_sha256_ecdsa_secp256r1', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /is odd; an ECDSA x\|\|y split must be even/);
  });

  test('an odd csca_pubKey_actual_size is invalid, not skipped (DSC family ECDSA)', () => {
    const fixture = loadFixture('dsc_sha256_ecdsa_secp521r1.json');
    const tampered = structuredClone(fixture);
    assert.equal(tampered.csca_pubKey_actual_size, '132');
    tampered.csca_pubKey_actual_size = '131';
    const result = verify('dsc_sha256_ecdsa_secp521r1', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /is odd; an ECDSA x\|\|y split must be even/);
  });

  test('pubKey_dsc x/y half out of range is invalid, not skipped (register family ECDSA -- ecdsaVerifier.circom:68-69,73-74)', () => {
    const fixture = loadFixture('register_ecdsa_secp256r1.json');
    const tampered = structuredClone(fixture);
    const limbs = [...tampered.pubKey_dsc];
    limbs[0] = outOfRangeLimb();
    tampered.pubKey_dsc = limbs;
    const result = verify('register_sha256_sha256_sha256_ecdsa_secp256r1', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /x\/y half does not reassemble into a valid integer/);
  });

  test('signature_passport (r/s) out of range is invalid, not skipped (register family ECDSA -- ecdsaVerifier.circom:66-67,71-72)', () => {
    const fixture = loadFixture('register_ecdsa_secp256r1.json');
    const tampered = structuredClone(fixture);
    const limbs = [...tampered.signature_passport];
    limbs[0] = outOfRangeLimb();
    tampered.signature_passport = limbs;
    const result = verify('register_sha256_sha256_sha256_ecdsa_secp256r1', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /signature does not reassemble into a valid integer/);
  });
});

describe('verify -- Plan B Task 2: RSA-PSS-scheme limb reassembly is invalid (validate.circom Num2Bits(CHUNK_SIZE) on BOTH signature[i] and pubkey[i])', () => {
  test('pubKey_dsc modulus out of range is invalid for RSA-PSS, not skipped (register family -- validate.circom:22-27)', () => {
    const fixture = loadFixture('register_pss.json');
    const tampered = structuredClone(fixture);
    const limbs = [...tampered.pubKey_dsc];
    limbs[0] = outOfRangeLimb();
    tampered.pubKey_dsc = limbs;
    const result = verify('register_sha256_sha256_sha256_rsapss_65537_32_2048', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /pubKey_dsc does not reassemble into a valid integer/);
  });

  test('signature_passport out of range is invalid for RSA-PSS, not skipped (register family -- validate.circom:22-27)', () => {
    const fixture = loadFixture('register_pss.json');
    const tampered = structuredClone(fixture);
    const limbs = [...tampered.signature_passport];
    limbs[0] = outOfRangeLimb();
    tampered.signature_passport = limbs;
    const result = verify('register_sha256_sha256_sha256_rsapss_65537_32_2048', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /signature does not reassemble into a valid integer/);
  });

  test('a signature reassembling wider than the certificate modulus is invalid for RSA-PSS (validate.circom:41-44 BigLessThan(signature, pubkey) === 1)', () => {
    const fixture = loadFixture('register_pss.json');
    const tampered = structuredClone(fixture);
    const limbs = [...tampered.signature_passport];
    limbs[limbs.length - 1] = '100000000000000000000000000000000000'; // in-range per-limb, but pushes the reassembled integer far past the 2048-bit modulus
    tampered.signature_passport = limbs;
    const result = verify('register_sha256_sha256_sha256_rsapss_65537_32_2048', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /signature is wider than the certificate modulus/);
  });
});

describe('verify -- Plan B Task 2: plain-RSA-scheme SIGNATURE reassembly is invalid (verifyRsa65537Pkcs1v1_5.circom:33-34 Num2Bits(CHUNK_SIZE) on signature[i] only)', () => {
  test('signature_passport out of range is invalid for plain RSA, not skipped (register family)', () => {
    const fixture = loadFixture('register_passport.json');
    const tampered = structuredClone(fixture);
    const limbs = [...tampered.signature_passport];
    limbs[0] = outOfRangeLimb();
    tampered.signature_passport = limbs;
    const result = verify('register_sha256_sha256_sha256_rsa_3_4096', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /signature does not reassemble into a valid integer/);
  });

  test('a signature reassembling wider than the certificate modulus is invalid for plain RSA (BigLessThan(signature, modulus) === 1)', () => {
    const fixture = loadFixture('register_passport.json');
    const tampered = structuredClone(fixture);
    const limbs = [...tampered.signature_passport];
    limbs[limbs.length - 1] = '100000000000000000000000000000000000';
    tampered.signature_passport = limbs;
    const result = verify('register_sha256_sha256_sha256_rsa_3_4096', tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /signature is wider than the certificate modulus/);
  });

  test('signature out of range is invalid for Aadhaar (register_aadhaar.circom -> SignatureVerifier(1,n,k) -> VerifyRsa65537Pkcs1v1_5, signature only)', () => {
    const fixture = loadFixture('register_aadhaar.json');
    const tampered = structuredClone(fixture);
    const limbs = [...tampered.signature];
    limbs[0] = outOfRangeLimb();
    tampered.signature = limbs;
    const result = verify(AADHAAR_CIRCUIT, tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /signature does not reassemble into a valid integer/);
  });
});

describe('verify -- Plan B Task 2: left as skipped -- no confirmed circuit citation, so no promotion on a guess (see this task\'s report)', () => {
  test('pubKey_dsc modulus out of range STAYS skipped for plain RSA (register family -- only the signature, not the modulus, is range-checked by verifyRsa65537Pkcs1v1_5.circom)', () => {
    const fixture = loadFixture('register_passport.json');
    const tampered = structuredClone(fixture);
    const limbs = [...tampered.pubKey_dsc];
    limbs[0] = outOfRangeLimb();
    tampered.pubKey_dsc = limbs;
    const result = verify('register_sha256_sha256_sha256_rsa_3_4096', tampered);
    assert.equal(result.verdict, 'skipped', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /pubKey_dsc does not reassemble into a valid integer/);
  });

  test('pubKey out of range STAYS skipped for Aadhaar (same reasoning -- Aadhaar dispatches through the same plain-PKCS1v1.5 verifier, modulus unchecked)', () => {
    const fixture = loadFixture('register_aadhaar.json');
    const tampered = structuredClone(fixture);
    const limbs = [...tampered.pubKey];
    limbs[0] = outOfRangeLimb();
    tampered.pubKey = limbs;
    const result = verify(AADHAAR_CIRCUIT, tampered);
    assert.equal(result.verdict, 'skipped', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /pubKey does not reassemble into a valid integer/);
  });

  test('pubKey reassembling wider than the fixed 2048-bit Aadhaar modulus STAYS skipped (no confirmed circuit assertion of that exact bound)', () => {
    const fixture = loadFixture('register_aadhaar.json');
    const tampered = structuredClone(fixture);
    const limbs = [...tampered.pubKey];
    // n=121, k=17: the top limb (index 16) is scaled by 2^(121*16)=2^1936.
    // 2^113 is still a valid in-range limb (< 2^121), but 2^113 * 2^1936 =
    // 2^2049 needs 257 bytes -- one more than the fixed 256-byte modulus.
    limbs[limbs.length - 1] = (1n << 113n).toString();
    tampered.pubKey = limbs;
    const result = verify(AADHAAR_CIRCUIT, tampered);
    assert.equal(result.verdict, 'skipped', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /pubKey is wider than the expected 2048-bit Aadhaar modulus/);
  });

  test('signature reassembling wider than the fixed 2048-bit Aadhaar modulus STAYS skipped', () => {
    const fixture = loadFixture('register_aadhaar.json');
    const tampered = structuredClone(fixture);
    const limbs = [...tampered.signature];
    limbs[limbs.length - 1] = (1n << 113n).toString();
    tampered.signature = limbs;
    const result = verify(AADHAAR_CIRCUIT, tampered);
    assert.equal(result.verdict, 'skipped', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /signature is wider than the expected 2048-bit Aadhaar modulus/);
  });

  test('malformed signed_attr padding STAYS skipped (register family, link 4 -- see report: only block-alignment is a confirmed circuit constraint, not the marker/zero-run/bit-length shape)', () => {
    const fixture = loadFixture('register_passport.json');
    const tampered = structuredClone(fixture);
    const original = Number([].concat(fixture.signed_attr_padded_length)[0]);
    tampered.signed_attr_padded_length = [String(original + 1)]; // no longer a multiple of 64
    const result = verify('register_sha256_sha256_sha256_rsa_3_4096', tampered);
    assert.equal(result.verdict, 'skipped', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /signed_attr padding is malformed/);
  });

  test('malformed qrDataPadded padding STAYS skipped (Aadhaar, same Sha256Bytes/Sha256General mechanics as the other padding checks)', () => {
    const fixture = loadFixture('register_aadhaar.json');
    const tampered = structuredClone(fixture);
    tampered.qrDataPaddedLength = Number(fixture.qrDataPaddedLength) + 1;
    const result = verify(AADHAAR_CIRCUIT, tampered);
    assert.equal(result.verdict, 'skipped', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /qrDataPadded padding is malformed/);
  });
});

// =======================================================================
// Plan B, Task 1: RFC-strict negative vectors.
//
// The premise these pin: a false accept is a forged credential, not a free
// optimization, so this module must be RFC-strict on its own terms rather
// than lenient anywhere. Two cases these vectors cover: a malleable PSS EM,
// and an off-curve key, both of which must be rejections rather than
// coverage gaps. Each block below first establishes
// current behaviour by running it (not by assuming the design doc), then
// pins whatever that behaviour turns out to be -- see this task's report
// for which of these four required an implementation change and which
// were already true after Plan A.
// =======================================================================

describe('verify -- RFC 8017 leftmost-bit PSS forgery is invalid (RFC-strict, not circuit-mirrored)', () => {
  // rsapss65537.circom:162 CLEARS the leftmost bit of the recovered DB
  // rather than checking it (RFC 8017 SS9.1.2 step 9), and the pre-Plan-B
  // design deliberately matched that: a signature whose EM has the
  // leftmost bit genuinely set verified as Valid. This test constructs
  // exactly such a signature -- using a real mock DSC's own private key,
  // so the rest of the chain (dg1/eContent/signed_attr links, the
  // certificate) is completely real and only the forged EM under test is
  // synthetic -- and confirms it is now Invalid.
  //
  // Constructing the EM is the fiddly part the task brief warns about:
  // forcing the leftmost bit can (a) push EM above the modulus, breaking
  // the RSA round-trip, or (b) land on a byte where the bit was already
  // going to end up set anyway, which would prove nothing about the
  // clear-vs-check divergence. `rsapss.rs`'s deleted
  // `sign_pss_with_high_bit_set` test helper (git history: commit 40ba9f7's
  // parent, src/verifier/primitives/rsapss.rs) searches salt bytes for a
  // candidate clearing both hurdles at once; this port follows the same
  // two-gate acceptance test.
  function mgf1(seed, outLen) {
    const blocks = [];
    let counter = 0;
    while (blocks.length * 32 < outLen) {
      const block = Buffer.concat([seed, Buffer.from([(counter >>> 24) & 0xff, (counter >>> 16) & 0xff, (counter >>> 8) & 0xff, counter & 0xff])]);
      blocks.push(crypto.createHash('sha256').update(block).digest());
      counter += 1;
    }
    return Buffer.concat(blocks).subarray(0, outLen);
  }

  /** Mirrors rsapss.rs's sign_pss_with_high_bit_set: searches candidate
   * salts (varying only the last two bytes) for one where forcing
   * maskedDB's leftmost bit BOTH keeps EM < n AND leaves the bit `verify_pss`
   * (here, crypto.verify) will actually recover genuinely set -- not merely
   * a bit that was going to be 1 regardless of forcing. Returns raw RSA
   * signature bytes for BOTH the forced-bit EM under test and (for the same
   * candidate salt/db/mask) the conformant, bit-clear EM a real signer would
   * have produced -- the latter is the control this task's brief asks for:
   * disabling the "force the bit" step on this exact candidate must leave a
   * signature that verifies, proving the forced bit is what the rejection
   * test below actually exercises, not some other broken parameter. Both are
   * `EM^d mod n` via crypto.privateEncrypt/RSA_NO_PADDING -- the private-key
   * raw operation, not a hand-rolled modexp. */
  function signPssWithAndWithoutHighBit(privateKey, n, mHash, saltLenBytes, emLenBytes) {
    const hLen = mHash.length;
    const dbLen = emLenBytes - hLen - 1;
    const salt = Buffer.alloc(saltLenBytes, 7);
    for (let attempt = 0; attempt <= 0xffff; attempt++) {
      salt[saltLenBytes - 1] = attempt & 0xff;
      salt[saltLenBytes - 2] = (attempt >> 8) & 0xff;
      const mPrime = Buffer.concat([Buffer.alloc(8, 0), mHash, salt]);
      const h = crypto.createHash('sha256').update(mPrime).digest();
      const db = Buffer.alloc(dbLen, 0);
      db[dbLen - saltLenBytes - 1] = 0x01;
      salt.copy(db, dbLen - saltLenBytes);
      const mask = mgf1(h, dbLen);
      const maskedConformant = Buffer.alloc(dbLen);
      for (let i = 0; i < dbLen; i++) maskedConformant[i] = db[i] ^ mask[i];
      const maskedForced = Buffer.from(maskedConformant);
      maskedForced[0] |= 0x80;
      const recoveredTopBitGenuinelySet = (maskedForced[0] ^ mask[0]) & 0x80;
      const emForced = Buffer.concat([maskedForced, h, Buffer.from([0xbc])]);
      const emForcedInt = BigInt(`0x${emForced.toString('hex')}`);
      if (recoveredTopBitGenuinelySet && emForcedInt < n) {
        const emConformant = Buffer.concat([maskedConformant, h, Buffer.from([0xbc])]);
        return {
          forgedSig: crypto.privateEncrypt({ key: privateKey, padding: crypto.constants.RSA_NO_PADDING }, emForced),
          conformantSig: crypto.privateEncrypt({ key: privateKey, padding: crypto.constants.RSA_NO_PADDING }, emConformant),
        };
      }
    }
    throw new Error('no candidate salt produced both EM < n and a genuinely-set recovered top bit in 65536 attempts');
  }

  test('a forged PSS signature with a genuinely-set leftmost EM bit is invalid, not valid -- and the SAME candidate without the forced bit is valid (isolates the forced bit as the cause)', { skip: !MOCK_CERTS_AVAILABLE }, () => {
    const row = REGISTER_FAMILY.find((r) => r.file === 'register_pss.json');
    const fixture = loadFixture('register_pss.json');
    const privateKey = crypto.createPrivateKey(fs.readFileSync(path.join(MOCK_CERT_ROOT, row.mockDir, 'mock_dsc.key'), 'utf8'));

    // The real message this signature must cover -- link 4 verifies over
    // sha256(recoverMessage(signed_attr)), and crypto.verify hashes the
    // message it is given internally, so `message` (not its hash) is what
    // must match what verify.mjs will feed crypto.verify.
    const signedAttr = bytesFromDecimalArray(fixture.signed_attr);
    const signedAttrPaddedLength = scalarNumber(fixture.signed_attr_padded_length);
    const message = recoverMessage(signedAttr, signedAttrPaddedLength);
    assert.ok(message, 'register_pss.json\'s own signed_attr must recover cleanly');
    const mHash = crypto.createHash('sha256').update(message).digest();

    const n = BigInt(`0x${Buffer.from(privateKey.export({ format: 'jwk' }).n, 'base64url').toString('hex')}`);
    const { forgedSig, conformantSig } = signPssWithAndWithoutHighBit(privateKey, n, mHash, 32, 256);

    const forgedLimbs = limbsFromBigInt(BigInt(`0x${forgedSig.toString('hex')}`), 120, 35);
    const forged = structuredClone(fixture);
    forged.signature_passport = forgedLimbs;
    const forgedResult = verify(row.circuit, forged);
    assert.equal(forgedResult.verdict, 'invalid', `got ${JSON.stringify(forgedResult)}`);
    assert.match(forgedResult.reason, /PSS signature does not verify/, `got ${forgedResult.reason}`);

    // Control: same candidate salt, same db, same mask, same message -- only
    // the forced leftmost bit differs. If this were also invalid, the
    // rejection above would not be attributable to the forced bit at all
    // (it would prove this test's construction is broken some other way).
    const conformantLimbs = limbsFromBigInt(BigInt(`0x${conformantSig.toString('hex')}`), 120, 35);
    const conformant = structuredClone(fixture);
    conformant.signature_passport = conformantLimbs;
    const conformantResult = verify(row.circuit, conformant);
    assert.deepEqual(conformantResult, { verdict: 'valid' }, `control (bit not forced) must verify: got ${JSON.stringify(conformantResult)}`);
  });
});

describe('verify -- an off-curve embedded public key is invalid, not skipped (RFC-strict)', () => {
  // ecdsa.circom never checks the curve equation (ecdsa.circom:18-102), and
  // the shipped design mirrored that by treating an off-curve point the
  // same as any other certificate-parse failure: Skipped. Running this
  // (rather than assuming it) shows the CURRENT pre-implementation
  // behaviour is exactly that -- see this task's report. This test
  // replaces the real embedded EC point's bytes (both in raw_dsc AND in
  // pubKey_dsc, so the byte-window comparison still passes and this
  // exercises certificate parsing specifically, not keyMatchesWindow) with
  // an all-0x01 point, which is vanishingly unlikely to satisfy any real
  // curve equation, and confirms the result is Invalid and names the curve.
  test('register family: an off-curve point in raw_dsc is invalid and names the curve', () => {
    const fixture = loadFixture('register_ecdsa_secp256r1.json');
    const circuit = 'register_sha256_sha256_sha256_ecdsa_secp256r1';
    const tampered = structuredClone(fixture);

    const rawDsc = bytesFromDecimalArray(tampered.raw_dsc);
    const offset = scalarNumber(tampered.dsc_pubKey_offset);
    const size = scalarNumber(tampered.dsc_pubKey_actual_size);
    const half = size / 2;
    Buffer.alloc(half, 0x01).copy(rawDsc, offset);
    Buffer.alloc(half, 0x01).copy(rawDsc, offset + half);
    tampered.raw_dsc = [...rawDsc].map(String);

    const n = 64;
    const k = 4;
    const onesLimbs = limbsFromBigInt(BigInt(`0x${Buffer.alloc(half, 0x01).toString('hex')}`), n, k);
    tampered.pubKey_dsc = [...onesLimbs, ...onesLimbs];

    const result = verify(circuit, tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /not carry a valid point on secp256r1/, `got ${result.reason}`);
  });

  test('DSC family: an off-curve point in raw_csca is invalid and names the curve', () => {
    const fixture = loadFixture('dsc_sha256_ecdsa_secp521r1.json');
    const circuit = 'dsc_sha256_ecdsa_secp521r1';
    const tampered = structuredClone(fixture);

    const rawCsca = bytesFromDecimalArray(tampered.raw_csca);
    const offset = scalarNumber(tampered.csca_pubKey_offset);
    const size = scalarNumber(tampered.csca_pubKey_actual_size);
    const half = size / 2;
    Buffer.alloc(half, 0x01).copy(rawCsca, offset);
    Buffer.alloc(half, 0x01).copy(rawCsca, offset + half);
    tampered.raw_csca = [...rawCsca].map(String);

    const n = 66;
    const k = 8;
    const onesLimbs = limbsFromBigInt(BigInt(`0x${Buffer.alloc(half, 0x01).toString('hex')}`), n, k);
    tampered.csca_pubKey = [...onesLimbs, ...onesLimbs];

    const result = verify(circuit, tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /not carry a valid point on secp521r1/, `got ${result.reason}`);
  });

  test('disabling the check: without it, the off-curve point would only be Skipped (proves this is not caught downstream by something else)', () => {
    // Same construction as the register-family test above, but calling the
    // OLD certPublicKey (Task 1's parse-or-null primitive, which does not
    // distinguish a structurally-fine-but-off-curve key from any other
    // unparseable certificate) directly through the same wrapAsCertificate
    // path this test file already uses elsewhere. This is the "disable the
    // specific check" proof the task brief asks for: with the distinguishing
    // check removed, the off-curve certificate is merely unparseable to
    // certPublicKey, which is exactly the Skipped outcome this task's
    // change moves away from.
    const fixture = loadFixture('register_ecdsa_secp256r1.json');
    const row = REGISTER_FAMILY.find((r) => r.file === 'register_ecdsa_secp256r1.json');
    const tbs = tbsBytesOf(row, fixture);
    const corrupted = Buffer.from(tbs);
    const offset = scalarNumber(fixture.dsc_pubKey_offset);
    const size = scalarNumber(fixture.dsc_pubKey_actual_size);
    const half = size / 2;
    Buffer.alloc(half, 0x01).copy(corrupted, offset);
    Buffer.alloc(half, 0x01).copy(corrupted, offset + half);

    assert.equal(certPublicKey(wrapAsCertificate(corrupted)), null, 'the pre-existing certPublicKey primitive must not itself distinguish off-curve from any other parse failure -- that distinction is what verify.mjs\'s new certPublicKeyOrInvalidReason adds');
  });
});

// ---------------------------------------------------------------------
// A minimal, test-local DER TLV reader used only to locate the SPKI's
// AlgorithmIdentifier OID inside a raw_dsc/raw_csca tbsCertificate buffer,
// so the tests below can flip one of its bytes -- mirroring verify.mjs's
// own readDerTLV/findSubjectPublicKeyInfo (neither is exported, since
// they're internal to the fix under test, not part of its public surface).
// ---------------------------------------------------------------------

function readDerTlvForOidLocation(buf, offset) {
  const tag = buf[offset];
  const first = buf[offset + 1];
  let length;
  let headerLen;
  if (first & 0x80) {
    const numLenBytes = first & 0x7f;
    let len = 0;
    for (let i = 0; i < numLenBytes; i++) len = len * 256 + buf[offset + 2 + i];
    length = len;
    headerLen = 2 + numLenBytes;
  } else {
    length = first;
    headerLen = 2;
  }
  const contentStart = offset + headerLen;
  return { tag, contentStart, content: buf.subarray(contentStart, contentStart + length), nextOffset: contentStart + length };
}

/** Locates the SPKI `AlgorithmIdentifier` OID inside `tbsBuf` (a raw_dsc/
 * raw_csca buffer already truncated to its actual length) and flips its
 * last byte in place -- leaving every other byte, and the ASN.1 structure
 * itself, untouched. */
function flipSpkiAlgorithmOidByte(tbsBuf) {
  const outer = readDerTlvForOidLocation(tbsBuf, 0);
  let offset = 0;
  let oidAbsOffset = null;
  let oidLen = null;
  while (offset < outer.content.length) {
    const tlv = readDerTlvForOidLocation(outer.content, offset);
    if (tlv.tag === 0x30) {
      const alg = readDerTlvForOidLocation(tlv.content, 0);
      if (alg.tag === 0x30) {
        const bitstr = readDerTlvForOidLocation(tlv.content, alg.nextOffset);
        if (bitstr.tag === 0x03 && bitstr.nextOffset === tlv.content.length) {
          const oidTlv = readDerTlvForOidLocation(alg.content, 0);
          if (oidTlv.tag === 0x06) {
            oidAbsOffset = outer.contentStart + tlv.contentStart + oidTlv.contentStart;
            oidLen = oidTlv.content.length;
            break;
          }
        }
      }
    }
    offset = tlv.nextOffset;
  }
  assert.ok(oidAbsOffset !== null, 'expected to find the SPKI AlgorithmIdentifier OID in tbsBuf');
  tbsBuf[oidAbsOffset + oidLen - 1] ^= 0xff;
}

describe('verify -- an unsupported SPKI algorithm is skipped, not invalid (the OID-flip case)', () => {
  // certPublicKeyOrInvalidReason's earlier version treated ANY cert.publicKey
  // throw as Invalid, reasoning that an off-curve point throws there while a
  // structurally-corrupt certificate throws at the X509Certificate
  // constructor instead. The first half is right; the conclusion was too
  // broad: the constructor only parses ASN.1 *structure* -- cert.publicKey is
  // where OpenSSL actually builds an EVP_PKEY, and EVERYTHING semantic about
  // the SPKI throws there, including an algorithm OID this OpenSSL build
  // does not implement, with the SAME generic "decode error" an off-curve
  // point produces. Flipping one byte of the SPKI algorithm OID -- leaving
  // the rest of the certificate's ASN.1 structure completely untouched --
  // demonstrates this: the certificate still parses fine at step 1, and
  // still throws only at step 2, indistinguishable BY WHICH CALL THREW from
  // a genuine off-curve key. This must be Skipped ("we don't recognise this
  // algorithm"), not Invalid ("we know this algorithm and the key is still
  // bad") -- otherwise a DSC whose SPKI uses an algorithm this build lacks
  // gets every document from that issuer rejected as a forgery, one
  // enforcement mode earlier than intended (mode 2 already rejects Invalid;
  // only mode 3 rejects Skipped), with no skip-rate signal to warn of it.

  test('register family (ECDSA): flipping the SPKI algorithm OID in raw_dsc is skipped, naming the unsupported algorithm', () => {
    const fixture = loadFixture('register_ecdsa_secp256r1.json');
    const circuit = 'register_sha256_sha256_sha256_ecdsa_secp256r1';
    const tampered = structuredClone(fixture);

    const rawDsc = bytesFromDecimalArray(tampered.raw_dsc);
    const rawDscActualLength = scalarNumber(tampered.raw_dsc_actual_length);
    flipSpkiAlgorithmOidByte(rawDsc.subarray(0, rawDscActualLength));
    tampered.raw_dsc = [...rawDsc].map(String);

    const result = verify(circuit, tampered);
    assert.equal(result.verdict, 'skipped', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /algorithm this build does not support/, `got ${result.reason}`);
  });

  test('register family (RSA): flipping the SPKI algorithm OID in raw_dsc is skipped, naming the unsupported algorithm', () => {
    const fixture = loadFixture('register_passport.json');
    const circuit = 'register_sha256_sha256_sha256_rsa_3_4096';
    const tampered = structuredClone(fixture);

    const rawDsc = bytesFromDecimalArray(tampered.raw_dsc);
    const rawDscActualLength = scalarNumber(tampered.raw_dsc_actual_length);
    flipSpkiAlgorithmOidByte(rawDsc.subarray(0, rawDscActualLength));
    tampered.raw_dsc = [...rawDsc].map(String);

    const result = verify(circuit, tampered);
    assert.equal(result.verdict, 'skipped', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /algorithm this build does not support/, `got ${result.reason}`);
  });

  test('DSC family: flipping the SPKI algorithm OID in raw_csca is skipped, naming the unsupported algorithm', () => {
    const fixture = loadFixture('dsc_sha256_rsa_65537_4096.json');
    const circuit = 'dsc_sha256_rsa_65537_4096';
    const tampered = structuredClone(fixture);

    const rawCsca = bytesFromDecimalArray(tampered.raw_csca);
    const rawCscaActualLength = scalarNumber(tampered.raw_csca_actual_length);
    flipSpkiAlgorithmOidByte(rawCsca.subarray(0, rawCscaActualLength));
    tampered.raw_csca = [...rawCsca].map(String);

    const result = verify(circuit, tampered);
    assert.equal(result.verdict, 'skipped', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /algorithm this build does not support/, `got ${result.reason}`);
  });

  test('the other direction still holds: a RECOGNIZED algorithm with a genuinely bad key is still invalid, not skipped', () => {
    // Cross-check so the two directions cannot silently collapse into one
    // outcome: an off-curve point (recognized algorithm, bad key material)
    // must stay Invalid even after this fix -- re-asserted here, beside the
    // OID-flip verdict above, so a regression that made classifySpkiAlgorithm
    // over-eager (treating everything as unrecognized) would be caught in
    // the same place as the fix it is meant to pin. Uses the exact
    // construction the "off-curve embedded public key" suite above already
    // establishes.
    const fixture = loadFixture('register_ecdsa_secp256r1.json');
    const circuit = 'register_sha256_sha256_sha256_ecdsa_secp256r1';
    const tampered = structuredClone(fixture);

    const rawDsc = bytesFromDecimalArray(tampered.raw_dsc);
    const offset = scalarNumber(tampered.dsc_pubKey_offset);
    const size = scalarNumber(tampered.dsc_pubKey_actual_size);
    const half = size / 2;
    Buffer.alloc(half, 0x01).copy(rawDsc, offset);
    Buffer.alloc(half, 0x01).copy(rawDsc, offset + half);
    tampered.raw_dsc = [...rawDsc].map(String);
    const onesLimbs = limbsFromBigInt(BigInt(`0x${Buffer.alloc(half, 0x01).toString('hex')}`), 64, 4);
    tampered.pubKey_dsc = [...onesLimbs, ...onesLimbs];

    const result = verify(circuit, tampered);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /not carry a valid point on secp256r1/, `got ${result.reason}`);
  });
});

describe('verify -- an out-of-range ECDSA scalar (r >= curve order) is invalid', () => {
  // node:crypto/OpenSSL's own ECDSA verification already rejects a
  // component outside [1, n-1] (n = the curve order) -- there is no
  // circuit-mirroring divergence to remove here, unlike PSS and off-curve
  // above. This pins that behaviour with evidence rather than assuming it:
  // setting every limb of the signature's r half to its maximum
  // representable value (2^n - 1, n = the limb width) yields a value that
  // is provably >= every deployed curve's order (Hasse's theorem bounds the
  // order strictly below the field size, which is itself what the limb
  // width encodes) -- curve-agnostic, no per-curve order constant needed.
  for (const row of REGISTER_FAMILY.filter((r) => r.scheme === 'ecdsa')) {
    test(`${row.file}: r forced to the maximum representable value (>= ${row.curve}'s order) is invalid`, () => {
      const fixture = loadFixture(row.file);
      const tampered = structuredClone(fixture);
      const maxLimb = String((1n << BigInt(row.n)) - 1n);
      const sigLimbs = [...tampered.signature_passport];
      for (let i = 0; i < row.k; i++) {
        sigLimbs[i] = maxLimb; // the r half occupies limbs [0, k)
      }
      tampered.signature_passport = sigLimbs;

      const result = verify(row.circuit, tampered);
      assert.equal(result.verdict, 'invalid', `${row.file}: got ${JSON.stringify(result)}`);
      assert.match(result.reason, /ECDSA signature does not verify/, `${row.file}: got ${result.reason}`);
    });
  }

  test('disabling the check: an in-range but merely-wrong r fails for the SAME reason, not a different one -- OpenSSL does not distinguish "out of range" as its own error class', () => {
    // This is the closest this item comes to a "disable the check and
    // confirm it is not caught downstream" proof: there is no separate,
    // disable-able range check in this codebase for ECDSA scalars (unlike
    // PSS's leftmost bit or the off-curve certificate case) -- the range
    // check lives entirely inside OpenSSL's own ECDSA_verify. An ordinary
    // tampered-but-in-range r fails via the exact same code path and the
    // exact same reason string, confirming there is no separate downstream
    // catch this test could be accidentally exercising instead.
    const fixture = loadFixture('register_ecdsa_secp256r1.json');
    const tampered = structuredClone(fixture);
    const sigLimbs = [...tampered.signature_passport];
    sigLimbs[0] = tamperedLimb(sigLimbs[0]);
    tampered.signature_passport = sigLimbs;
    const result = verify('register_sha256_sha256_sha256_ecdsa_secp256r1', tampered);
    assert.equal(result.verdict, 'invalid');
    assert.match(result.reason, /ECDSA signature does not verify/);
  });
});

describe('verify -- the signature algorithm (hash) is pinned to the circuit name, never discovered', () => {
  // Never infer the algorithm by trying candidates (this plan's design
  // doc, "RFC-strict" section): a real signature, valid under the hash its
  // circuit name actually declares, must NOT verify under a DIFFERENT
  // declared hash -- proving verify.mjs uses exactly the hash the name
  // says rather than brute-forcing until something matches. Only the
  // SIGNATURE hash tag is changed (the last of the three register-family
  // tags); dg_hash/econtent_hash are left alone so this isolates the
  // signature-hash pin from the dg1/eContent chain checks, which use their
  // own hash tags and would otherwise fail first for an unrelated reason.
  test('ECDSA: a real sha256 signature presented against a circuit declaring sha512 is invalid, not valid', () => {
    const fixture = loadFixture('register_ecdsa_secp256r1.json');
    // Real circuit: register_sha256_sha256_sha256_ecdsa_secp256r1 (dg,
    // econtent, AND sig hash all sha256). Only the sig hash tag changes.
    const result = verify('register_sha256_sha256_sha512_ecdsa_secp256r1', fixture);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /ECDSA signature does not verify/, `got ${result.reason}`);
  });

  test('RSA PKCS#1 v1.5: a real sha256 signature presented against a circuit declaring sha512 is invalid, not valid', () => {
    const fixture = loadFixture('register_passport.json');
    // Real circuit: register_sha256_sha256_sha256_rsa_3_4096.
    const result = verify('register_sha256_sha256_sha512_rsa_3_4096', fixture);
    assert.equal(result.verdict, 'invalid', `got ${JSON.stringify(result)}`);
    assert.match(result.reason, /RSA signature does not verify/, `got ${result.reason}`);
  });

  test('sanity: the real fixture with its own real circuit name is still valid (the hash-pin tests above are not vacuously passing on a fixture that never verifies)', () => {
    const fixture = loadFixture('register_ecdsa_secp256r1.json');
    assert.deepEqual(verify('register_sha256_sha256_sha256_ecdsa_secp256r1', fixture), { verdict: 'valid' });
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

// =======================================================================
// Drift guard -- ports params.rs's (pre-Plan-A) `table_matches_the_
// monorepo_instance_files` test, which parsed the sibling monorepo's own
// circuit instance files and asserted the checked-in table agreed with
// them on (n, k), hash widths, and exponents. That guard caught a real
// instance-count error and was proven load-bearing by mutation four
// separate times; deleting params.rs's tables (Plan A, Task 4) deleted the
// guard along with them. verify.mjs derives the same values from the
// circuit NAME instead of a transcribed table, so what needs re-proving
// here is narrower -- just that the name-derived (dg_hash, econtent_hash,
// sig_hash, n, k) for every register/register_id/DSC instance file still
// agrees with what that file's own REGISTER(...)/REGISTER_ID(...)/DSC(...)
// template arguments (and signatureAlgorithm.circom's own getHashLength
// table) say -- but the failure shape is the same bad one: a changed limb
// width upstream produces a wrong reassembly -> Invalid -> the request is
// rejected in production (main.rs's cleanup path).
//
// Self-skips, exactly as the Rust version did, when the sibling monorepo
// is not checked out at ../self -- printing an unmistakable SKIP line so a
// skipped guard is never mistaken for a passing one (a bare TAP "ok #
// SKIP" line is easy to miss scrolling past 200+ other "ok" lines).
// =======================================================================

const SIBLING_CIRCUITS_ROOT = path.join(__dirname, '..', '..', 'self', 'circuits', 'circuits');
const SIBLING_AVAILABLE = fs.existsSync(SIBLING_CIRCUITS_ROOT);

/**
 * Extracts the comma-separated argument list following `marker` (e.g.
 * `'REGISTER('`) in `src`, up to the matching close-paren. Mirrors the old
 * params.rs `extract_args` helper. Returns `null` if `marker` is absent.
 */
function extractTemplateArgs(src, marker) {
  const idx = src.indexOf(marker);
  if (idx === -1) {
    return null;
  }
  const start = idx + marker.length;
  const end = src.indexOf(')', start);
  if (end === -1) {
    return null;
  }
  return src
    .slice(start, end)
    .split(',')
    .map((s) => s.trim());
}

/**
 * Parses `getHashLength(signatureAlgorithm)`'s own `if (signatureAlgorithm
 * == N) { return H; }` branches directly out of signatureAlgorithm.circom's
 * source, building the id -> hash-bit-width map this guard checks
 * `sig_hash` against. Read from the file's own function body, not
 * transcribed by hand into a second table that could itself drift.
 * Returns `null` if the function cannot be located at all (a signal to fail
 * loudly, not to guess).
 */
function parseHashLengthTable(src) {
  const fnMatch = src.match(/function getHashLength\(signatureAlgorithm\)\s*\{([\s\S]*?)\n\}/);
  if (!fnMatch) {
    return null;
  }
  const body = fnMatch[1];
  const table = new Map();
  const re = /signatureAlgorithm\s*==\s*(\d+)\s*\)\s*\{\s*return\s+(\d+)\s*;/g;
  let m;
  while ((m = re.exec(body)) !== null) {
    table.set(Number(m[1]), Number(m[2]));
  }
  return table.size > 0 ? table : null;
}


/**
 * The PSS salt length the circuit itself uses, derived from the signature
 * algorithm id rather than from the circuit name.
 *
 * signatureVerifier.circom:95 -- `SALT_LEN = signatureAlgorithm == 46 ? 64 :
 * HASH_LEN_BITS / 8`. Algorithm 46 is the reason this rule cannot be inferred:
 * it is SHA-256 with a 64-byte salt, breaking the otherwise-universal
 * `hash / 8`. verify.mjs reads the salt out of the circuit NAME, which agrees
 * with the id-derived value for all 20 PSS circuits deployed today -- so this
 * assertion exists to catch the day that stops being true. A wrong salt makes
 * OpenSSL reject a genuine signature, which the pipeline turns into a rejected
 * request, so the failure direction is an outage rather than a lost fast path.
 */
function saltLenFromAlgorithmId(sigAlgoId, hashBits) {
  return sigAlgoId === 46 ? 64 : hashBits / 8;
}

describe("drift guard: verify.mjs's circuit-name-derived (n, k, hash widths) match the sibling monorepo's instance files", () => {
  if (!SIBLING_AVAILABLE) {
    const msg = `SKIP: sibling monorepo not present at ${SIBLING_CIRCUITS_ROOT} -- drift guard did NOT run`;
    console.log(msg);
    test('sibling monorepo not present -- this whole guard is SKIPPED, not passing', { skip: msg }, () => {});
    return;
  }

  const hashLengthPath = path.join(SIBLING_CIRCUITS_ROOT, 'utils', 'passport', 'signatureAlgorithm.circom');
  const HASH_LENGTH_TABLE = parseHashLengthTable(fs.readFileSync(hashLengthPath, 'utf8'));

  test('getHashLength(...) parses out of signatureAlgorithm.circom', () => {
    assert.ok(HASH_LENGTH_TABLE, `could not parse getHashLength(...) out of ${hashLengthPath}`);
  });

  /**
   * Register/register_id instance files: `<TEMPLATE>(dg_hash, econtent_hash,
   * sig_algo_id, n, k, ...)`, except `register_aadhaar.circom`
   * (`REGISTER_AADHAAR(n, k, maxDataLength)` -- a different argument order
   * entirely) and `register_kyc.circom` (`REGISTER_KYC()`, no template
   * arguments at all -- EdDSA-BabyJubJub has no limb layout to drift-check).
   */
  function checkRegisterFamily(familyDir, templateName) {
    const dir = path.join(SIBLING_CIRCUITS_ROOT, familyDir, 'instances');
    const files = fs.readdirSync(dir).filter((f) => f.endsWith('.circom')).sort();
    for (const file of files) {
      const stem = file.slice(0, -'.circom'.length);
      if (stem === 'register_kyc') {
        continue;
      }
      test(`${familyDir}/instances/${file}`, () => {
        const src = fs.readFileSync(path.join(dir, file), 'utf8');
        const parsed = parseCircuitName(stem);
        assert.ok(parsed, `${stem}: parseCircuitName does not recognize this on-disk instance name at all`);

        if (stem === 'register_aadhaar') {
          const args = extractTemplateArgs(src, 'REGISTER_AADHAAR(');
          assert.ok(args, `${file}: could not find REGISTER_AADHAAR(...) in ${file}`);
          assert.equal(parsed.n, Number(args[0]), `${stem}: n drift (verify.mjs says ${parsed.n}, instance file says ${args[0]})`);
          assert.equal(parsed.k, Number(args[1]), `${stem}: k drift (verify.mjs says ${parsed.k}, instance file says ${args[1]})`);
          return;
        }

        const args = extractTemplateArgs(src, `${templateName}(`);
        assert.ok(args, `${file}: could not find ${templateName}(...) in ${file}`);
        const [dgHashArg, econtentHashArg, sigAlgoId, nArg, kArg] = args.map(Number);

        assert.equal(
          parsed.dgHash,
          dgHashArg,
          `${stem}: dg_hash drift (verify.mjs says ${parsed.dgHash}, instance file's 1st ${templateName} arg says ${dgHashArg})`,
        );
        assert.equal(
          parsed.econtentHash,
          econtentHashArg,
          `${stem}: econtent_hash drift (verify.mjs says ${parsed.econtentHash}, instance file's 2nd ${templateName} arg says ${econtentHashArg})`,
        );

        const expectedSigHash = HASH_LENGTH_TABLE.get(sigAlgoId);
        assert.ok(
          expectedSigHash !== undefined,
          `${stem}: signatureAlgorithm id ${sigAlgoId} (instance file's 3rd ${templateName} arg) has no entry in ` +
            `getHashLength -- add it by reading signatureAlgorithm.circom, do not guess`,
        );
        assert.equal(
          parsed.sigHash,
          expectedSigHash,
          `${stem}: sig_hash drift (verify.mjs says ${parsed.sigHash}, but signatureAlgorithm id ${sigAlgoId} implies ${expectedSigHash} via getHashLength)`,
        );

        assert.equal(parsed.n, nArg, `${stem}: n drift (verify.mjs says ${parsed.n}, instance file says ${nArg})`);
        assert.equal(parsed.k, kArg, `${stem}: k drift (verify.mjs says ${parsed.k}, instance file says ${kArg})`);

        if (parsed.scheme === 'rsapss') {
          const expectedSalt = saltLenFromAlgorithmId(sigAlgoId, expectedSigHash);
          assert.equal(
            parsed.saltLen,
            expectedSalt,
            `${stem}: PSS salt drift (verify.mjs reads ${parsed.saltLen} from the circuit name, but ` +
              `signatureAlgorithm id ${sigAlgoId} implies ${expectedSalt} via signatureVerifier.circom:95)`,
          );
        }
      });
    }
  }

  checkRegisterFamily('register', 'REGISTER');
  checkRegisterFamily('register_id', 'REGISTER_ID');

  // DSC instance files: `DSC(sig_algo_id, n, k)` -- a different template
  // from REGISTER(...)/REGISTER_ID(...) in both shape and argument order
  // (no dg_hash/econtent_hash pair at all; `sig_algo_id` is 1st here, not
  // 3rd).
  const dscDir = path.join(SIBLING_CIRCUITS_ROOT, 'dsc', 'instances');
  const dscFiles = fs.readdirSync(dscDir).filter((f) => f.endsWith('.circom')).sort();
  for (const file of dscFiles) {
    const stem = file.slice(0, -'.circom'.length);
    test(`dsc/instances/${file}`, () => {
      const src = fs.readFileSync(path.join(dscDir, file), 'utf8');
      const parsed = parseCircuitName(stem);
      assert.ok(parsed, `${stem}: parseCircuitName does not recognize this on-disk instance name at all`);

      const args = extractTemplateArgs(src, 'DSC(');
      assert.ok(args, `${file}: could not find DSC(...) in ${file}`);
      const [sigAlgoId, nArg, kArg] = args.map(Number);

      const expectedSigHash = HASH_LENGTH_TABLE.get(sigAlgoId);
      assert.ok(
        expectedSigHash !== undefined,
        `${stem}: signatureAlgorithm id ${sigAlgoId} (instance file's 1st DSC arg) has no entry in getHashLength -- ` +
          `add it by reading signatureAlgorithm.circom, do not guess`,
      );
      assert.equal(
        parsed.sigHash,
        expectedSigHash,
        `${stem}: sig_hash drift (verify.mjs says ${parsed.sigHash}, but signatureAlgorithm id ${sigAlgoId} implies ${expectedSigHash} via getHashLength)`,
      );
      assert.equal(parsed.n, nArg, `${stem}: n drift (verify.mjs says ${parsed.n}, instance file says ${nArg})`);
      assert.equal(parsed.k, kArg, `${stem}: k drift (verify.mjs says ${parsed.k}, instance file says ${kArg})`);

      if (parsed.scheme === 'rsapss') {
        const expectedSalt = saltLenFromAlgorithmId(sigAlgoId, expectedSigHash);
        assert.equal(
          parsed.saltLen,
          expectedSalt,
          `${stem}: PSS salt drift (verify.mjs reads ${parsed.saltLen} from the circuit name, but ` +
            `signatureAlgorithm id ${sigAlgoId} implies ${expectedSalt} via signatureVerifier.circom:95)`,
        );
      }
    });
  }
});
