import { execFileSync } from 'node:child_process';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert';

const ADDR = '0x1111111111111111111111111111111111111111';
const out = join(mkdtempSync(join(tmpdir(), 'jwtgen-')), 'inputs.json');

// --- Happy path: well-formed fixture, valid address -> inputs.json written ---

execFileSync('npx', ['tsx', 'index.ts', ADDR, out], {
  env: { ...process.env, JWT_FIXTURE: 'fixtures/example_jwt.txt' },
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
console.log('OK');

// --- Rejection cases: the generator must exit non-zero on any failure, since
// a later Rust caller treats a non-zero exit as fatal. ---
//
// Note: fixtures/example_jwt_fail.txt is NOT used here. It is a validly-signed
// real GCP attestation JWT whose only difference from example_jwt.txt is its
// eat_nonce content/encoding, which is a circuit-level nonce-binding check
// (comparing eat_nonce against the enclave address once the circuit actually
// runs) -- not something this field-extraction generator can or should
// evaluate. It parses successfully like any other well-formed JWT, so it is
// kept in the repo, unused by this test, reserved for circuit-level negative
// testing in a later task.

function assertRejected(env, argv, label) {
  let threw = false;
  try {
    execFileSync('npx', ['tsx', 'index.ts', ...argv], { env: { ...process.env, ...env }, stdio: 'pipe' });
  } catch {
    threw = true;
  }
  assert.ok(threw, `${label} must be rejected with a non-zero exit`);
  console.log(`OK (${label})`);
}

// x5c has fewer than 3 certificates (chain-of-trust requires exactly 3).
assertRejected({ JWT_FIXTURE: 'fixtures/example_jwt_short_chain.txt' }, [ 'index.ts', ADDR, out ],
  'x5c with fewer than 3 certificates');

// Truncated / non-JWT garbage token (fails base64url/JSON parsing).
assertRejected({ JWT_FIXTURE: 'fixtures/example_jwt_truncated.txt' }, [ 'index.ts', ADDR, out ],
  'truncated/garbage token');

// Malformed argv[2]: not an address at all.
assertRejected({ JWT_FIXTURE: 'fixtures/example_jwt.txt' }, [ 'index.ts', 'notanaddress', out ],
  'non-address argv[2]');

// Malformed argv[2]: checksummed (mixed-case) address -- contract is lowercase-only.
assertRejected({ JWT_FIXTURE: 'fixtures/example_jwt.txt' },
  [ 'index.ts', '0xAbCdEf1234567890AbCdEf1234567890AbCdEf12', out ],
  'checksummed (non-lowercase) argv[2]');
