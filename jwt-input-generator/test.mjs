import { execFileSync } from 'node:child_process';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert';

const ADDR = '0x1111111111111111111111111111111111111111';
const out = join(mkdtempSync(join(tmpdir(), 'jwtgen-')), 'inputs.json');

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
assert.strictEqual(inputs.image_digest_length, 71, 'image_digest_length must be 71');
console.log('OK');

let threw = false;
try {
  execFileSync('npx', ['tsx', 'index.ts', ADDR, out],
    { env: { ...process.env, JWT_FIXTURE: 'fixtures/example_jwt_fail.txt' }, stdio: 'pipe' });
} catch { threw = true; }
assert.ok(threw, 'example_jwt_fail.txt must be rejected with a non-zero exit');
console.log('OK (rejection)');
