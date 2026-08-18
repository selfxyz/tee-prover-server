import { execFileSync } from 'node:child_process';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert';

// Run the tsx that npm installed, never `npx tsx`: npx silently downloads and
// executes the package when it is absent locally, which is exactly the behaviour
// src/attestation/bootstrap.rs was changed to avoid inside the enclave.
const TSX = join('node_modules', '.bin', 'tsx');

// The synthetic fixture's address is written by fixtures/make_synthetic_jwt.mjs;
// read it rather than hardcoding it, so regenerating the fixture cannot desync
// this test from the token it verifies.
const ADDR = readFileSync('fixtures/synthetic_jwt.address.txt', 'utf8').trim();
const OTHER_ADDR = '0x1111111111111111111111111111111111111111';
const out = join(mkdtempSync(join(tmpdir(), 'jwtgen-')), 'inputs.json');

// --- Happy path: well-formed fixture whose eat_nonce attests THIS address ---

execFileSync(TSX, ['index.ts', ADDR, out], {
  env: { ...process.env, JWT_FIXTURE: 'fixtures/synthetic_jwt.txt' },
  stdio: 'inherit',
});

const inputs = JSON.parse(readFileSync(out, 'utf8'));
for (const k of ['message', 'messageLength', 'leaf_cert', 'intermediate_cert',
                 'leaf_pubkey', 'intermediate_pubkey', 'root_pubkey',
                 'jwt_signature', 'current_date', 'eat_nonce_0_b64_length']) {
  assert.ok(k in inputs, `missing input key: ${k}`);
}
// image_digest_length is emitted as a decimal string, matching the didit-tee
// generator's output format verbatim (output parity, not a type we get to pick).
assert.strictEqual(Number(inputs.image_digest_length), 71, 'image_digest_length must be 71');
// The nonce the circuit is handed must be the bare 40-character hex address (no
// `0x`), not the 42-character argv form or something else of a plausible length.
assert.strictEqual(Number(inputs.eat_nonce_0_b64_length), ADDR.length - 2,
  'eat_nonce_0_b64_length must be the bare (0x-stripped) enclave address length');
console.log('OK');

// --- Rejection cases: the generator must exit non-zero on any failure, since
// a later Rust caller treats a non-zero exit as fatal. ---

function assertRejected(env, argv, label) {
  let threw = false;
  let output = '';
  try {
    execFileSync(TSX, ['index.ts', ...argv], { env: { ...process.env, ...env }, stdio: 'pipe' });
  } catch (e) {
    threw = true;
    // The generator logs progress on stdout and failures on stderr; callers assert
    // against both, so return them concatenated.
    output = `${(e.stdout ?? '').toString()}${(e.stderr ?? '').toString()}`;
  }
  assert.ok(threw, `${label} must be rejected with a non-zero exit`);
  console.log(`OK (${label})`);
  return output;
}

// The central claim: a token that does not attest THIS enclave's address must be
// rejected, however well-formed and however validly signed it is. Both real captured
// fixtures are exactly that — validly signed GCP attestation tokens minted for other
// keys (example_jwt.txt's nonce is a didit-tee EdDSA pubkey; example_jwt_fail.txt's is
// a raw hex nonce) — so they double as this check's negative fixtures while still
// exercising real certificate-chain parsing and real RSA signature verification, both
// of which run before the nonce comparison.
for (const fixture of ['fixtures/example_jwt.txt', 'fixtures/example_jwt_fail.txt']) {
  const output = assertRejected({ JWT_FIXTURE: fixture }, [ADDR, out],
    `${fixture} does not attest our address`);
  assert.match(output, /eat_nonce does not bind this enclave key/,
    `${fixture} must be rejected for nonce binding specifically, not some earlier error`);
  assert.match(output, /JWT signature verified/,
    `${fixture} must reach the nonce check with its real chain parsed and signature verified`);
}

// Same token, different requested address: the fixture attests ADDR, so asking about
// OTHER_ADDR must fail. Pins that the comparison is against argv, not a constant.
assertRejected({ JWT_FIXTURE: 'fixtures/synthetic_jwt.txt' }, [OTHER_ADDR, out],
  'valid token minted for a different address');

// x5c has fewer than 3 certificates (chain-of-trust requires exactly 3).
assertRejected({ JWT_FIXTURE: 'fixtures/example_jwt_short_chain.txt' }, [ADDR, out],
  'x5c with fewer than 3 certificates');

// Truncated / non-JWT garbage token (fails base64url/JSON parsing).
assertRejected({ JWT_FIXTURE: 'fixtures/example_jwt_truncated.txt' }, [ADDR, out],
  'truncated/garbage token');

// Malformed argv[2]: not an address at all.
assertRejected({ JWT_FIXTURE: 'fixtures/synthetic_jwt.txt' }, ['notanaddress', out],
  'non-address argv[2]');

// Malformed argv[2]: checksummed (mixed-case) address -- contract is lowercase-only.
assertRejected({ JWT_FIXTURE: 'fixtures/synthetic_jwt.txt' },
  ['0xAbCdEf1234567890AbCdEf1234567890AbCdEf12', out],
  'checksummed (non-lowercase) argv[2]');
