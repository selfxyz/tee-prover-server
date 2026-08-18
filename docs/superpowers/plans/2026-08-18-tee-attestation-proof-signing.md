# TEE Attestation + Proof Signing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `tee-prover-server` a secp256k1 identity minted inside the enclave, attested by Google via the Confidential Space token nonce and proven with the `gcp_jwt_verifier` circuit, and sign every proof output with it.

**Architecture:** At boot, `bootstrap` mints a k256 key in memory, derives its Ethereum address, and spawns the vendored Node sidecar with that address. The sidecar requests a PKI attestation token carrying the address in its nonce, parses the x5c chain, and writes circuit inputs. Bootstrap then drives the attestation proof through the server's existing `WitnessGenerator`/`ProofGenerator`. Afterwards each request-path proof is signed with the same key before it lands in Postgres. On-chain registration is written but compiled out by default.

**Tech Stack:** Rust (tokio, jsonrpsee, sqlx/Postgres), `k256` for signing, `alloy-primitives`/`alloy-sol-types` for ABI encoding, `alloy` (feature-gated) for chain submission, Node/tsx sidecar, circom + rapidsnark.

**Spec:** `docs/superpowers/specs/2026-08-18-tee-attestation-signing-design.md`

## Global Constraints

- The signing key is **secp256k1**, minted in Rust, held in memory only. It is never written to disk, never sent to Secret Manager, and never passed to the Node sidecar.
- Signed digest is pinned: `keccak256(abi.encode(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[] publicInputs))`, signature is 65-byte recoverable `(r, s, v)`.
- The attestation nonce is the enclave's Ethereum address as a lowercase `0x`-prefixed hex string. Second nonce entry is the literal `"self_protocol"`.
- Bootstrap failure is **fatal**. The server must never serve proofs it cannot sign.
- On-chain submission lives behind a `chain` cargo feature, **off by default**.
- Nothing in this plan modifies the KYC attestation path or `RegisterProofVerifierLib`.
- Existing pipeline stages report errors via `crate::utils::cleanup(uuid, &pool, reason)`. Follow that pattern; do not introduce a second error convention.

## File Structure

| File | Responsibility |
|---|---|
| `jwt-input-generator/index.ts` | Vendored from didit-tee. Takes an address, returns circuit inputs. No key material. |
| `src/attestation/mod.rs` | Module root; re-exports `EnclaveKey`, `bootstrap`. |
| `src/attestation/key.rs` | k256 keygen, address derivation, digest signing. |
| `src/attestation/digest.rs` | Proof → 32-byte digest, ABI-encoded to match Solidity. |
| `src/attestation/bootstrap.rs` | Orchestrates key → sidecar → witness → proof. |
| `src/attestation/chain.rs` | `registerProverKey` submission, `chain` feature only. |

---

### Task 1: Vendor the JWT input generator, address-driven and fixture-testable

**Files:**
- Create: `jwt-input-generator/` (copied from `../didit-tee/jwt-input-generator/`)
- Modify: `jwt-input-generator/index.ts`
- Create: `jwt-input-generator/fixtures/example_jwt.txt`

**Interfaces:**
- Consumes: nothing.
- Produces: CLI contract `tsx index.ts <enclaveAddress> <outputFile>`, plus `JWT_FIXTURE` env var. Writes a JSON object of circuit inputs. Exits non-zero on any failure.

- [ ] **Step 1: Copy the generator and its fixture**

```bash
cp -R ../didit-tee/jwt-input-generator ./jwt-input-generator
rm -rf jwt-input-generator/node_modules
mkdir -p jwt-input-generator/fixtures
cp ../self/circuits/circuits/gcp_jwt_verifier/example_jwt.txt jwt-input-generator/fixtures/
cp ../self/circuits/circuits/gcp_jwt_verifier/example_jwt_fail.txt jwt-input-generator/fixtures/
cd jwt-input-generator && npm install && cd ..
```

- [ ] **Step 2: Write the failing test**

Create `jwt-input-generator/test.mjs`:

```javascript
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
```

- [ ] **Step 3: Run it to confirm it fails**

Run: `cd jwt-input-generator && node test.mjs`
Expected: FAIL — the current `main()` ignores argv, mints an EdDSA key, and reads from the TEE socket.

- [ ] **Step 4: Replace keygen and token fetch in `index.ts`**

Delete the `EdDSAPoseidon`/`poseidon2` imports and the `key.txt` write. Replace `getCustomTokenBytes` and the head of `main()`:

```typescript
export function getCustomTokenBytes(enclaveAddress: string): Promise<Buffer> {
  const fixture = process.env.JWT_FIXTURE;
  if (fixture) {
    return Promise.resolve(Buffer.from(fs.readFileSync(fixture, 'utf8').trim(), 'utf8'));
  }
  return new Promise((resolve, reject) => {
    const requestBody: TokenRequest = {
      audience: "USER",
      token_type: "PKI",
      nonces: [enclaveAddress, "self_protocol"],
    };
    const bodyStr = JSON.stringify(requestBody);
    const options: http.RequestOptions = {
      socketPath: "/run/container_launcher/teeserver.sock",
      path: "/v1/token",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(bodyStr),
      },
    };
    const req = http.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c) => chunks.push(Buffer.from(c)));
      res.on("error", reject);
      res.on("end", () => resolve(Buffer.concat(chunks)));
    });
    req.on("error", reject);
    req.write(bodyStr);
    req.end();
  });
}

async function main() {
  const enclaveAddress = process.argv[2];
  const outputFile = process.argv[3] ?? '/zk/inputs.json';
  if (!/^0x[0-9a-f]{40}$/.test(enclaveAddress ?? '')) {
    console.error('usage: tsx index.ts <lowercase 0x address> <outputFile>');
    process.exit(1);
  }
  const rawJWT = (await getCustomTokenBytes(enclaveAddress)).toString('utf8').trim();
  // ...existing x5c parsing and input building, writing to `outputFile`...
}

main().catch((e) => { console.error(e); process.exit(1); });
```

Leave every other function (`parseCertificate`, `pubkeyToChunks`, `signatureToChunks`, `rechunkSignatureToK35`, `bufferToByteArray`, `getCurrentDateDigitsYYMMDDHHMMSS`) untouched — that is the proven code we are here to reuse.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd jwt-input-generator && node test.mjs`
Expected: `OK`

- [ ] **Step 6: Add the rejection test**

Append to `test.mjs`:

```javascript
let threw = false;
try {
  execFileSync('npx', ['tsx', 'index.ts', ADDR, out],
    { env: { ...process.env, JWT_FIXTURE: 'fixtures/example_jwt_fail.txt' }, stdio: 'pipe' });
} catch { threw = true; }
assert.ok(threw, 'example_jwt_fail.txt must be rejected with a non-zero exit');
console.log('OK (rejection)');
```

- [ ] **Step 7: Run both tests**

Run: `cd jwt-input-generator && node test.mjs`
Expected: `OK` then `OK (rejection)`

- [ ] **Step 8: Commit**

```bash
git add jwt-input-generator
git commit -m "feat: vendor JWT input generator, address-driven with fixture mode"
```

---

### Task 2: Enclave k256 key

**Files:**
- Create: `src/attestation/mod.rs`
- Create: `src/attestation/key.rs`
- Modify: `Cargo.toml`
- Modify: `src/main.rs:1-7` (add `mod attestation;`)

**Interfaces:**
- Consumes: nothing.
- Produces: `EnclaveKey::generate() -> EnclaveKey`, `EnclaveKey::address(&self) -> String` (lowercase `0x` hex), `EnclaveKey::sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 65], String>`. `EnclaveKey` is `Clone` and `Send + Sync` so it can move into the pipeline task.

- [ ] **Step 1: Add dependencies**

In `Cargo.toml` under `[dependencies]`:

```toml
k256 = { version = "0.13", features = ["ecdsa"] }
alloy-primitives = "0.8"
alloy-sol-types = "0.8"
rand = "0.8"
hex = "0.4"
```

- [ ] **Step 2: Write the failing test**

Create `src/attestation/key.rs` containing only:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_is_lowercase_hex_of_twenty_bytes() {
        let key = EnclaveKey::generate();
        let addr = key.address();
        assert!(addr.starts_with("0x"), "address must be 0x-prefixed: {addr}");
        assert_eq!(addr.len(), 42, "address must be 42 chars: {addr}");
        assert_eq!(addr, addr.to_lowercase(), "address must be lowercase");
    }

    #[test]
    fn signature_recovers_to_the_signing_address() {
        let key = EnclaveKey::generate();
        let digest = [7u8; 32];
        let sig = key.sign_digest(&digest).expect("signing failed");
        assert_eq!(sig.len(), 65);
        assert_eq!(recover_address(&digest, &sig).unwrap(), key.address());
    }
}
```

- [ ] **Step 3: Run it to confirm it fails**

Run: `cargo test --lib attestation::key`
Expected: FAIL — `cannot find type EnclaveKey in this scope`.

- [ ] **Step 4: Implement**

Prepend to `src/attestation/key.rs`:

```rust
use alloy_primitives::keccak256;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};

#[derive(Clone)]
pub struct EnclaveKey {
    signing_key: SigningKey,
}

impl EnclaveKey {
    pub fn generate() -> Self {
        EnclaveKey { signing_key: SigningKey::random(&mut rand::thread_rng()) }
    }

    pub fn address(&self) -> String {
        address_from_verifying_key(self.signing_key.verifying_key())
    }

    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 65], String> {
        let (sig, recid) = self
            .signing_key
            .sign_prehash_recoverable(digest)
            .map_err(|e| e.to_string())?;
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        // Solidity's ecrecover expects v in {27, 28}
        out[64] = recid.to_byte() + 27;
        Ok(out)
    }
}

fn address_from_verifying_key(vk: &VerifyingKey) -> String {
    let uncompressed = vk.to_encoded_point(false);
    // skip the 0x04 SEC1 prefix; address is the last 20 bytes of keccak(pubkey)
    let hash = keccak256(&uncompressed.as_bytes()[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

pub fn recover_address(digest: &[u8; 32], sig: &[u8; 65]) -> Result<String, String> {
    let signature = Signature::from_slice(&sig[..64]).map_err(|e| e.to_string())?;
    let recid = RecoveryId::from_byte(sig[64].saturating_sub(27))
        .ok_or_else(|| "invalid recovery id".to_string())?;
    let vk = VerifyingKey::recover_from_prehash(digest, &signature, recid)
        .map_err(|e| e.to_string())?;
    Ok(address_from_verifying_key(&vk))
}
```

Create `src/attestation/mod.rs`:

```rust
pub mod key;

pub use key::EnclaveKey;
```

Add `mod attestation;` to the module list at the top of `src/main.rs`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib attestation::key`
Expected: 2 passed.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/attestation src/main.rs
git commit -m "feat: k256 enclave signing key with ecrecover-compatible signatures"
```

---

### Task 3: Proof digest

**Files:**
- Create: `src/attestation/digest.rs`
- Modify: `src/attestation/mod.rs`
- Modify: `src/db/mod.rs:158-164` (make `Proof` public)

**Interfaces:**
- Consumes: `crate::db::Proof`.
- Produces: `proof_digest(proof: &Proof, public_inputs: &[String]) -> Result<[u8; 32], String>`.

- [ ] **Step 1: Make `Proof` reachable**

In `src/db/mod.rs`, change `struct Proof` to `pub struct Proof` and each of its fields to `pub`. It is currently private to the module.

- [ ] **Step 2: Write the failing test**

Create `src/attestation/digest.rs` containing only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Proof;

    fn sample() -> (Proof, Vec<String>) {
        (
            Proof {
                pi_a: vec!["1".into(), "2".into()],
                pi_b: vec![vec!["3".into(), "4".into()], vec!["5".into(), "6".into()]],
                pi_c: vec!["7".into(), "8".into()],
                protocol: "groth16".into(),
            },
            vec!["9".into(), "10".into()],
        )
    }

    #[test]
    fn digest_is_stable() {
        let (p, pi) = sample();
        let a = proof_digest(&p, &pi).unwrap();
        let b = proof_digest(&p, &pi).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn digest_changes_with_public_inputs() {
        let (p, pi) = sample();
        let mut other = pi.clone();
        other[0] = "11".into();
        assert_ne!(proof_digest(&p, &pi).unwrap(), proof_digest(&p, &other).unwrap());
    }

    #[test]
    fn rejects_malformed_proof() {
        let (mut p, pi) = sample();
        p.pi_a = vec!["1".into()]; // must be exactly 2 elements
        assert!(proof_digest(&p, &pi).is_err());
    }
}
```

- [ ] **Step 3: Run it to confirm it fails**

Run: `cargo test --lib attestation::digest`
Expected: FAIL — `cannot find function proof_digest`.

- [ ] **Step 4: Implement**

Prepend to `src/attestation/digest.rs`:

```rust
use alloy_primitives::{keccak256, U256};
use alloy_sol_types::SolValue;

use crate::db::Proof;

fn parse(values: &[String]) -> Result<Vec<U256>, String> {
    values
        .iter()
        .map(|v| U256::from_str_radix(v, 10).map_err(|e| format!("bad field element {v}: {e}")))
        .collect()
}

fn fixed2(values: &[String], what: &str) -> Result<[U256; 2], String> {
    let parsed = parse(values)?;
    if parsed.len() != 2 {
        return Err(format!("{what} must have exactly 2 elements, got {}", parsed.len()));
    }
    Ok([parsed[0], parsed[1]])
}

/// keccak256(abi.encode(uint256[2], uint256[2][2], uint256[2], uint256[]))
///
/// Matches what a Solidity verifier reconstructs from the proof it already receives,
/// so `ecrecover(digest, sig)` on-chain yields the enclave address.
pub fn proof_digest(proof: &Proof, public_inputs: &[String]) -> Result<[u8; 32], String> {
    let a = fixed2(&proof.pi_a, "pi_a")?;
    if proof.pi_b.len() != 2 {
        return Err(format!("pi_b must have exactly 2 rows, got {}", proof.pi_b.len()));
    }
    let b = [fixed2(&proof.pi_b[0], "pi_b[0]")?, fixed2(&proof.pi_b[1], "pi_b[1]")?];
    let c = fixed2(&proof.pi_c, "pi_c")?;
    let inputs = parse(public_inputs)?;

    let encoded = (a, b, c, inputs).abi_encode_params();
    Ok(*keccak256(encoded))
}
```

Add `pub mod digest;` to `src/attestation/mod.rs`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib attestation::digest`
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add src/attestation src/db/mod.rs
git commit -m "feat: ABI-encoded proof digest matching on-chain ecrecover"
```

---

### Task 4: Bootstrap

**Files:**
- Create: `src/attestation/bootstrap.rs`
- Modify: `src/attestation/mod.rs`

**Interfaces:**
- Consumes: `EnclaveKey`, `crate::generator::witness_generator::WitnessGenerator`, `crate::generator::proof_generator::ProofGenerator`, `crate::utils::get_tmp_folder_path`.
- Produces: `bootstrap(circuit_folder: &str, zkey_path: &str, rapidsnark_path: &str) -> Result<(EnclaveKey, AttestationProof), String>` and `pub struct AttestationProof { pub proof: crate::db::Proof, pub public_inputs: Vec<String> }`.

- [ ] **Step 1: Write the failing test**

Create `src/attestation/bootstrap.rs` containing only:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sidecar_receives_the_enclave_address() {
        let key = EnclaveKey::generate();
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("inputs.json");

        run_input_generator(&key.address(), out.to_str().unwrap(), Some("fixtures/example_jwt.txt"))
            .await
            .expect("sidecar failed");

        let inputs: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert!(inputs.get("message").is_some());
    }

    #[tokio::test]
    async fn sidecar_failure_is_an_error() {
        let key = EnclaveKey::generate();
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("inputs.json");
        assert!(run_input_generator(&key.address(), out.to_str().unwrap(),
                                    Some("fixtures/example_jwt_fail.txt")).await.is_err());
    }
}
```

Add `tempfile = "3"` to `[dev-dependencies]` in `Cargo.toml`.

- [ ] **Step 2: Run it to confirm it fails**

Run: `cargo test --lib attestation::bootstrap`
Expected: FAIL — `cannot find function run_input_generator`.

- [ ] **Step 3: Implement**

Prepend to `src/attestation/bootstrap.rs`:

```rust
use core::str;
use std::path;

use crate::attestation::digest::proof_digest;
use crate::attestation::EnclaveKey;
use crate::db::Proof;
use crate::generator::{proof_generator::ProofGenerator, witness_generator::WitnessGenerator};
use crate::utils::get_tmp_folder_path;
use serde::Deserialize;

pub const ATTESTATION_CIRCUIT: &str = "gcp_jwt_verifier";
const GENERATOR_DIR: &str = "/jwt/jwt-input-generator";

pub struct AttestationProof {
    pub proof: Proof,
    pub public_inputs: Vec<String>,
}

/// Spawns the Node sidecar. `fixture` is only set by tests; in the enclave the
/// sidecar fetches a live token from the Confidential Space socket.
pub async fn run_input_generator(
    enclave_address: &str,
    output_file: &str,
    fixture: Option<&str>,
) -> Result<(), String> {
    // Tests run with CWD = crate root; in the enclave the sidecar lives at /jwt.
    let dir = if fixture.is_some() { "jwt-input-generator" } else { GENERATOR_DIR };
    let mut cmd = tokio::process::Command::new("npx");
    cmd.current_dir(dir)
        .arg("tsx")
        .arg("index.ts")
        .arg(enclave_address)
        .arg(output_file);
    if let Some(f) = fixture {
        cmd.env("JWT_FIXTURE", f);
    }
    let output = cmd.output().await.map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "jwt-input-generator failed: {}",
            str::from_utf8(&output.stderr).unwrap_or("unknown error")
        ));
    }
    Ok(())
}

/// Mints the enclave key, has Google attest to it, and proves that attestation.
/// Any failure here must abort startup — the server may not serve proofs it cannot sign.
pub async fn bootstrap(
    circuit_folder: &str,
    zkey_path: &str,
    rapidsnark_path: &str,
) -> Result<(EnclaveKey, AttestationProof), String> {
    let key = EnclaveKey::generate();
    let uuid = uuid::Uuid::new_v4();
    let tmp = get_tmp_folder_path(&uuid.to_string());
    tokio::fs::create_dir_all(&tmp).await.map_err(|e| e.to_string())?;

    let input_file = path::Path::new(&tmp).join("input.json");
    run_input_generator(&key.address(), input_file.to_str().unwrap(), None).await?;

    WitnessGenerator::new(uuid, ATTESTATION_CIRCUIT.to_string())
        .run(circuit_folder)
        .await?;
    ProofGenerator::new(uuid, zkey_path.to_string())
        .run(&rapidsnark_path.to_string())
        .await?;

    let proof_str = std::fs::read_to_string(path::Path::new(&tmp).join("proof.json"))
        .map_err(|e| e.to_string())?;
    let inputs_str = std::fs::read_to_string(path::Path::new(&tmp).join("public_inputs.json"))
        .map_err(|e| e.to_string())?;

    let proof = Proof::deserialize(&mut serde_json::de::Deserializer::from_str(&proof_str))
        .map_err(|e| e.to_string())?;
    let public_inputs =
        Vec::<String>::deserialize(&mut serde_json::de::Deserializer::from_str(&inputs_str))
            .map_err(|e| e.to_string())?;

    // Fail fast if the digest encoding cannot handle our own proof shape.
    proof_digest(&proof, &public_inputs)?;

    let _ = tokio::fs::remove_dir_all(&tmp).await;
    Ok((key, AttestationProof { proof, public_inputs }))
}
```

Add `pub mod bootstrap;` to `src/attestation/mod.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib attestation::bootstrap`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/attestation
git commit -m "feat: attestation bootstrap driving the existing prover pipeline"
```

---

### Task 5: Persist signatures

**Files:**
- Modify: `setup.sql`
- Modify: `src/db/mod.rs:71-137` (`update_proof`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `update_proof(uuid: uuid::Uuid, db: &sqlx::Pool<sqlx::Postgres>, signature: &str) -> Result<(), String>` — signature is a `0x`-prefixed 132-char hex string.

**Note:** `setup.sql` is already behind the code — `create_proof_status` binds `version`, `user_defined_data`, and `self_defined_data`, which the table definition lacks. Add those alongside `signature` so the file matches reality.

- [ ] **Step 1: Update the schema**

In `setup.sql`, inside `CREATE TABLE IF NOT EXISTS proofs`, add after `identifier VARCHAR(255)`:

```sql
    ,version INTEGER
    ,user_defined_data TEXT
    ,self_defined_data TEXT
    ,signature VARCHAR(132)
```

And add to the `json_build_object` in `status_update_notify()`, after `'identifier', NEW.identifier`:

```sql
      ,'signature', NEW.signature
```

Add a migration for existing deployments at the end of the file:

```sql
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS version INTEGER;
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS user_defined_data TEXT;
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS self_defined_data TEXT;
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS signature VARCHAR(132);
```

- [ ] **Step 2: Change the `update_proof` signature**

In `src/db/mod.rs`, change the function signature and the SQL:

```rust
pub async fn update_proof(
    uuid: uuid::Uuid,
    db: &sqlx::Pool<sqlx::Postgres>,
    signature: &str,
) -> Result<(), String> {
```

and

```rust
    match sqlx::query(
        "UPDATE proofs SET proof = $1, status = $2, proof_generated_at = $3, public_inputs = $4, signature = $5 WHERE request_id = $6",
    )
    .bind(sqlx::types::Json(proof))
    .bind(status)
    .bind(now)
    .bind(public_inputs)
    .bind(signature)
    .bind(sqlx::types::uuid::Uuid::from(uuid))
```

- [ ] **Step 3: Confirm the build breaks at the call site**

Run: `cargo build`
Expected: FAIL — `update_proof` called with 2 arguments in `src/main.rs`. Task 6 fixes it.

- [ ] **Step 4: Commit**

```bash
git add setup.sql src/db/mod.rs
git commit -m "feat: persist proof signatures and sync setup.sql with the code"
```

---

### Task 6: Sign in the request pipeline

**Files:**
- Modify: `src/main.rs:22-31` (imports), `src/main.rs:44-100` (startup), `src/main.rs:186-205` (proof loop)

**Interfaces:**
- Consumes: `bootstrap()`, `EnclaveKey`, `proof_digest()`, `update_proof(.., signature)`.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Run bootstrap before the server starts**

After the `rapid_snark_path` binding and before `tokio::select!`, insert:

```rust
    let attestation_zkey = path::Path::new(&zkey_folder)
        .join(format!("{}.zkey", attestation::bootstrap::ATTESTATION_CIRCUIT));
    if !attestation_zkey.exists() {
        panic!("attestation zkey {} does not exist!", attestation_zkey.display());
    }

    // Fatal by design: the server must never serve proofs it cannot sign.
    let (enclave_key, attestation_proof) = match attestation::bootstrap::bootstrap(
        &circuit_folder,
        attestation_zkey.to_str().unwrap(),
        &rapid_snark_path,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => panic!("TEE attestation bootstrap failed: {e}"),
    };
    println!("Enclave attested. Signing address: {}", enclave_key.address());

    #[cfg(feature = "chain")]
    if let Err(e) = attestation::chain::register_prover_key(&enclave_key, &attestation_proof).await {
        panic!("prover key registration failed: {e}");
    }
    #[cfg(not(feature = "chain"))]
    let _ = &attestation_proof;
```

- [ ] **Step 2: Sign in the proof-generator loop**

Replace the body of the third `tokio::select!` arm:

```rust
    _ = async {
        while let Some(proof_generator) = proof_generator_receiver.recv().await {
            let uuid = proof_generator.uuid();

            if let Err(e) = proof_generator.run(&rapid_snark_path).await {
                dbg!(&e);
                cleanup(uuid.clone(), &pool, e.to_string()).await;
                continue;
            }

            let signature = match attestation::sign_proof_output(&enclave_key, &uuid) {
                Ok(sig) => sig,
                Err(e) => {
                    dbg!(&e);
                    cleanup(uuid.clone(), &pool, e).await;
                    continue;
                }
            };

            if let Err(e) = update_proof(uuid.clone(), &pool, &signature).await {
                dbg!(&e);
                cleanup(uuid.clone(), &pool, e.to_string()).await;
                continue;
            }
            let tmp_folder = get_tmp_folder_path(&uuid.to_string());
            let _ = tokio::fs::remove_dir_all(tmp_folder).await;
        }
    } => {}
```

- [ ] **Step 3: Add the helper**

Append to `src/attestation/mod.rs`:

```rust
use serde::Deserialize;

/// Reads the proof this request just produced and signs it. Returns a
/// 0x-prefixed 132-character hex string.
pub fn sign_proof_output(key: &EnclaveKey, uuid: &uuid::Uuid) -> Result<String, String> {
    let tmp = crate::utils::get_tmp_folder_path(&uuid.to_string());
    let proof_str = std::fs::read_to_string(std::path::Path::new(&tmp).join("proof.json"))
        .map_err(|e| e.to_string())?;
    let inputs_str =
        std::fs::read_to_string(std::path::Path::new(&tmp).join("public_inputs.json"))
            .map_err(|e| e.to_string())?;

    let proof = crate::db::Proof::deserialize(
        &mut serde_json::de::Deserializer::from_str(&proof_str),
    )
    .map_err(|e| e.to_string())?;
    let public_inputs = Vec::<String>::deserialize(
        &mut serde_json::de::Deserializer::from_str(&inputs_str),
    )
    .map_err(|e| e.to_string())?;

    let d = digest::proof_digest(&proof, &public_inputs)?;
    Ok(format!("0x{}", hex::encode(key.sign_digest(&d)?)))
}
```

- [ ] **Step 4: Verify the build and the full suite**

Run: `cargo build && cargo test --lib`
Expected: build succeeds, all tests pass.

Note: Step 1 references `attestation::chain::register_prover_key`, which Task 7 creates.
It is behind `#[cfg(feature = "chain")]`, so the default build used here is unaffected.
Do not run `cargo build --features chain` until Task 7 is complete.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs src/attestation
git commit -m "feat: sign proof outputs with the attested enclave key"
```

---

### Task 7: On-chain registration behind the `chain` feature

**Files:**
- Create: `src/attestation/chain.rs`
- Modify: `Cargo.toml`, `src/attestation/mod.rs`

**Interfaces:**
- Consumes: `EnclaveKey`, `AttestationProof`.
- Produces: `register_prover_key(key: &EnclaveKey, attestation: &AttestationProof) -> Result<(), String>`, compiled only with `--features chain`.

**Note:** `registerProverKey` does not exist on-chain yet — that is deferred contract work. This task writes the client against the agreed signature so the flag can simply be flipped later. It is never exercised in CI.

- [ ] **Step 1: Add the feature and dependency**

In `Cargo.toml`:

```toml
[features]
register = []
dsc = []
disclose = []
cherrypick = []
chain = ["dep:alloy"]

[dependencies]
alloy = { version = "1.5.2", features = ["essentials", "sol-types"], optional = true }
```

- [ ] **Step 2: Implement**

Create `src/attestation/chain.rs`:

```rust
use std::str::FromStr;

use alloy::{
    network::EthereumWallet, primitives::Address, providers::ProviderBuilder,
    signers::local::PrivateKeySigner, sol,
};

use crate::attestation::{bootstrap::AttestationProof, EnclaveKey};

sol! {
    #[sol(rpc)]
    interface IdentityRegistryKycImplV1 {
        function registerProverKey(uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256[20] pubSignals) external;
    }
}

fn to_u256_array<const N: usize>(values: &[String], what: &str) -> Result<[alloy::primitives::U256; N], String> {
    if values.len() != N {
        return Err(format!("{what} must have {N} elements, got {}", values.len()));
    }
    let mut out = [alloy::primitives::U256::ZERO; N];
    for (i, v) in values.iter().enumerate() {
        out[i] = alloy::primitives::U256::from_str_radix(v, 10)
            .map_err(|e| format!("bad {what}[{i}]: {e}"))?;
    }
    Ok(out)
}

pub async fn register_prover_key(
    _key: &EnclaveKey,
    attestation: &AttestationProof,
) -> Result<(), String> {
    // The submitter key only pays gas and satisfies onlyProofTEE. It is deliberately
    // distinct from the attested signing key, which never leaves memory.
    let submitter_pk = std::env::var("PROOF_TEE_PRIVATE_KEY")
        .map_err(|_| "PROOF_TEE_PRIVATE_KEY is not set".to_string())?;
    let rpc_url = std::env::var("RPC_URL").map_err(|_| "RPC_URL is not set".to_string())?;
    let contract_address = std::env::var("KYC_REGISTRY_ADDRESS")
        .map_err(|_| "KYC_REGISTRY_ADDRESS is not set".to_string())?;

    let signer = PrivateKeySigner::from_str(&submitter_pk).map_err(|e| e.to_string())?;
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect(&rpc_url)
        .await
        .map_err(|e| e.to_string())?;

    let addr = Address::from_str(&contract_address).map_err(|e| e.to_string())?;
    let contract = IdentityRegistryKycImplV1::new(addr, provider);

    let a = to_u256_array::<2>(&attestation.proof.pi_a, "pi_a")?;
    let b = [
        to_u256_array::<2>(&attestation.proof.pi_b[0], "pi_b[0]")?,
        to_u256_array::<2>(&attestation.proof.pi_b[1], "pi_b[1]")?,
    ];
    let c = to_u256_array::<2>(&attestation.proof.pi_c, "pi_c")?;
    let pub_signals = to_u256_array::<20>(&attestation.public_inputs, "public_inputs")?;

    contract
        .registerProverKey(a, b, c, pub_signals)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .watch()
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}
```

Add to `src/attestation/mod.rs`:

```rust
#[cfg(feature = "chain")]
pub mod chain;
```

- [ ] **Step 3: Verify both compile paths**

Run: `cargo build && cargo build --features chain`
Expected: both succeed.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock src/attestation
git commit -m "feat: prover key registration behind the chain feature, off by default"
```

---

### Task 8: Enclave image and circuit provisioning

**Files:**
- Modify: `Dockerfile.tee:35-60`
- Modify: `download_zkeys.sh`, `check_circuits.sh`, `constants.sh`

**Interfaces:**
- Consumes: `jwt-input-generator/` from Task 1.
- Produces: an image containing Node, the sidecar, and the `gcp_jwt_verifier` circuit + zkey.

**Note:** `build_docker.sh` builds **7 image variants** (register×3, dsc×3, disclose×1) and each gets its own PCR0 digest. All 7 must be registered in `PCR0Manager` before the `chain` flag is turned on — not one.

- [ ] **Step 1: Add Node and the sidecar to the image**

In `Dockerfile.tee`, after the `apt-get install` line:

```dockerfile
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y nodejs

WORKDIR /jwt/jwt-input-generator
COPY jwt-input-generator/package*.json ./
RUN npm ci --omit=dev
COPY jwt-input-generator/ ./
```

- [ ] **Step 2: Ship the attestation circuit unconditionally**

The existing lines filter circuits by proof type and size. The attestation circuit is needed by **every** variant, so add after them:

```dockerfile
COPY ./circuits/gcp_jwt_verifier_cpp /circuits/gcp_jwt_verifier_cpp
COPY ./zkeys/gcp_jwt_verifier.zkey /zkeys/gcp_jwt_verifier.zkey
RUN chmod +x /circuits/gcp_jwt_verifier_cpp/gcp_jwt_verifier
```

- [ ] **Step 3: Add it to the artifact scripts**

In `constants.sh`, add a variable listing the always-present circuit so the download and check scripts share one source of truth:

```bash
ALWAYS_CIRCUITS=(
  "gcp_jwt_verifier"
)
```

Then in `download_zkeys.sh` and `check_circuits.sh`, iterate `ALWAYS_CIRCUITS` in addition to the size-filtered lists, using the same download and existence-check logic those scripts already apply to the other circuits.

- [ ] **Step 4: Verify the image builds**

Run: `docker build --build-arg PROOFTYPE=disclose --build-arg SIZE_FILTER=small -f Dockerfile.tee -t tee-server-attestation-check .`
Expected: build succeeds. Bootstrap is not exercised — it needs a Confidential Space VM.

- [ ] **Step 5: Confirm the sidecar is present and runnable in the image**

Run: `docker run --rm tee-server-attestation-check sh -c "cd /jwt/jwt-input-generator && JWT_FIXTURE=fixtures/example_jwt.txt npx tsx index.ts 0x1111111111111111111111111111111111111111 /tmp/inputs.json && head -c 80 /tmp/inputs.json"`
Expected: prints the start of a JSON object.

- [ ] **Step 6: Commit**

```bash
git add Dockerfile.tee download_zkeys.sh check_circuits.sh constants.sh
git commit -m "build: ship Node sidecar and attestation circuit in the enclave image"
```

---

## Deferred (not this plan)

1. `registerProverKey` on `IdentityRegistryKycImplV1` — `mapping(address => bool) _isRegisteredProverKey` and `_proofTee` appended after `_prevNameAndYobOfacRoot`, `onlyProofTEE` mirroring `onlyTEE`, shared verification extracted to `_verifyGcpJwtAttestation`, an `isRegisteredProverKey` view, and a revoke path.
2. Deploy the registry upgrade.
3. Register all 7 image digests in `PCR0Manager`; set `_proofTee`.
4. Build with `--features chain`.
