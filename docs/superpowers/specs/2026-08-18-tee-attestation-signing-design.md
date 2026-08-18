# TEE Attestation + Proof Signing for tee-prover-server

**Date:** 2026-08-18
**Status:** Approved design, not yet implemented
**Target branch:** `staging`

## Problem

`tee-prover-server` runs inside GCP Confidential Space and generates Groth16 proofs, but it
has no cryptographic identity of its own. Clients receive a raw attestation token from
`hello()` and must verify it themselves; the proofs the server returns carry nothing that
ties them to an attested enclave. A consumer holding a proof cannot tell whether it came
from a genuine enclave or was fabricated.

`didit-tee` already solves this shape of problem for KYC: it mints an identity keypair at
boot, has Google attest to that key via the attestation token nonce, proves the attestation
in zero knowledge with the `gcp_jwt_verifier` circuit, and registers the pubkey commitment
on-chain. We want the same guarantee for proof outputs.

## Goals

- The prover holds an identity key that provably exists only inside a measured enclave.
- Every proof output is signed with that key.
- The key's provenance is anchored on-chain so consumers can verify it independently.

## Non-goals

- Replacing the existing ECDH/attestation handshake in `hello()`. It stays as-is.
- Verifying prover signatures on-chain. Nothing in the hub consults them; the registry is
  a public record for off-chain consumers.
- Changing the KYC attestation path in any way.

## Background: how didit-tee does it

```
start.sh
 └─ jwt-input-generator (Node)
     ├─ mints EdDSA-BabyJubJub keypair
     ├─ writes /zk/key.txt
     ├─ requests PKI token, nonces = [eddsaPubkey, "self_protocol"]
     ├─ parses the x5c chain, builds circuit inputs
     └─ writes /zk/inputs.json
 └─ didit-tee (Rust)
     ├─ witness → rapidsnark → proof
     └─ registerPubkeyCommitment() on IdentityRegistryKycImplV1
```

The nonce is the load-bearing part: Google signs an attestation that includes the enclave's
freshly minted public key, so the JWT itself binds "this key" to "this measured image".

## Architecture

```
start.sh
 ├─ update_creds.sh                      (existing) WIF attestation credentials
 ├─ jwt-input-generator (Node sidecar)   NEW
 │     mint EdDSA key -> PKI token (nonces = [pubkey, "self_protocol"])
 │     -> /zk/key.txt (tmpfs) + /zk/inputs.json
 └─ exec tee-server
       ├─ bootstrap        NEW  attestation proof via existing generators; load key; unlink
       ├─ chain            NEW  registerPubkeyCommitmentForProofs()  [feature-flagged OFF]
       └─ pipeline         MOD  ... -> ProofGenerator -> sign() -> Postgres
```

### Why a Node sidecar rather than a Rust port

The generator is a thin wrapper over four published libraries
(`@zk-email/jwt-tx-builder-helpers`, `@zk-kit/eddsa-poseidon`, `node-forge`,
`poseidon-lite`). The genuinely fiddly parts — x5c parsing and locating the RSA modulus
offset inside the TBS by hex substring search — are already solved and in production in
`didit-tee`. A Rust reimplementation would be ~450 lines of ASN.1 offset arithmetic whose
only correctness gate is byte-parity with the TypeScript it replaces.

Accepted cost: Node enters the measured image, enlarging the attack surface and changing
the PCR0 digest. The digest must be registered in `PCR0Manager` before the chain flag can
be turned on, which is already part of the deferred sequence.

## Components

| Component | Responsibility | Depends on |
|---|---|---|
| `jwt-input-generator/` (Node) | Mint EdDSA key; fetch PKI token with pubkey in nonce; emit circuit inputs | Confidential Space socket; the four npm libs above |
| `src/attestation/bootstrap.rs` | Read sidecar outputs; drive attestation proof through existing generators; load and unlink key | `generator::{WitnessGenerator, ProofGenerator}` |
| `src/attestation/signing.rs` | Sign `proof ‖ public_inputs` with the enclave key | key from bootstrap |
| `src/attestation/chain.rs` | Submit `registerPubkeyCommitmentForProofs` | `alloy`, behind `chain` feature |

`bootstrap.rs` runs to completion before the RPC server binds. A failure to attest is
fatal — the server must not serve proofs it cannot sign.

## Key lifecycle

The signing key is minted in-enclave at boot, written to `/zk/key.txt` on **tmpfs**, read
once by the Rust process, and then unlinked. It is never persisted and never leaves the
enclave.

Persisting it — including to GCP Secret Manager — was considered and rejected. Anyone able
to read the secret could sign proof outputs indistinguishably from a genuine enclave,
which defeats the attestation entirely. Note that this repo's Secret Manager access is
already attestation-gated via Workload Identity Federation (`update_creds.sh` builds an
`external_account` credential sourced from
`/run/container_launcher/attestation_verifier_claims_token`), but that protection is only
as strong as the attribute condition configured on the `attestation-verifier` provider. If
that condition does not pin the image digest, any workload in the pool can read the
secret. A signing key's security should not rest on IAM configuration outside this repo.

Consequences, accepted deliberately:

1. **Every restart mints a new key and needs a new registration transaction.** Acceptable
   at current scale. Each horizontally scaled instance registers its own key.
2. **There is no revocation path.** The deferred `_isRegisteredProofPubkeyCommitment`
   mapping follows the existing KYC pattern, where the flag is set to `true` and never
   unset. Every key an enclave has ever minted would stay valid forever, and a compromised
   key could not be retired. A revoke method should be added in the deferred contract work
   rather than inheriting this property by default.

## Signature scheme

EdDSA-BabyJubJub with Poseidon, mirroring `didit-tee`. This is dictated by the
registration path: the commitment is `poseidon2([pk[0], pk[1]])`, and
`GCPJWTHelper.unpackAndDecodeHexPubkey` reads the pubkey out of the attestation's
`eat_nonce` public signals. Choosing secp256k1 would ease Solidity verification but
requires a different commitment format and helper.

## Data flow for a signed proof

`submit_request` -> decrypt -> FileGenerator -> WitnessGenerator -> ProofGenerator ->
**sign** -> Postgres.

Results reach consumers through the existing `pg_notify('status_update', ...)` trigger,
which publishes the whole `proofs` row. There is no result RPC, so the signature must be
stored as a column and added to the trigger's `json_build_object` payload, or consumers
will not see it.

## Feature flags

`chain` (default off) gates the `alloy` dependency and the on-chain submission, matching
the existing `prod`-style gating in `didit-tee`. With the flag off, bootstrap still mints
the key, fetches the token, generates the attestation proof, and signs proof outputs —
only the registration transaction is skipped. This keeps the PR self-contained and
reviewable before the contract method exists.

## Files touched

- `jwt-input-generator/` — new, copied from `didit-tee`
- `src/attestation/{mod,bootstrap,signing,chain}.rs` — new
- `src/main.rs` — invoke bootstrap before serving
- `src/generator/mod.rs` — signing hook after `ProofGenerator`
- `src/db/` — persist the signature
- `Cargo.toml` — eddsa/poseidon; `alloy` behind `chain`
- `setup.sql` — `signature` column + include it in the notify payload
- `Dockerfile.tee` — Node + `npm install`; tmpfs mount for `/zk`
- `start.sh` — run the sidecar before `tee-server`
- `download_zkeys.sh`, `check_circuits.sh`, `constants.sh` — carry `gcp_jwt_verifier`

## Error handling

- Sidecar failure (no token, malformed x5c) — non-zero exit, `start.sh` aborts under
  `set -e`; the server never starts.
- Attestation proof failure — fatal in bootstrap, same reasoning.
- Chain submission failure with the flag on — fatal. A prover whose key is not registered
  produces signatures nobody can verify.
- Signing failure mid-pipeline — mark the row failed with a reason, matching how existing
  pipeline stages report errors.

## Testing

Real end-to-end proving requires a Confidential Space VM, so two seams are needed:
`bootstrap.rs` must accept a token from a fixture instead of the socket, and the sidecar
needs a fixture mode. The sidecar as copied from `didit-tee` always fetches a live token
from `/run/container_launcher/teeserver.sock`; it must gain an argument or env var that
reads a JWT from a file instead, mirroring how `prepare.ts` already takes a JWT path. This
is a required change to the copied code, not an optional test affordance.

1. **Sidecar smoke test** against `self/circuits/circuits/gcp_jwt_verifier/example_jwt.txt`
   via that fixture mode — produces inputs that generate a valid witness.
2. **Negative fixture** — `example_jwt_fail.txt` must be rejected.
3. **Handoff contract** — Rust-side tests asserting the expected file paths and JSON
   schema from the sidecar, so a generator change cannot silently break the consumer.
4. **Signature round-trip** — sign and verify with a known key; assert the commitment
   matches `poseidon2([pk[0], pk[1]])`.
5. **Migration** — `setup.sql` applies cleanly to an existing `proofs` table and the
   notify payload contains the new field.

## Out of scope (deferred, in order)

1. `registerPubkeyCommitmentForProofs` on `IdentityRegistryKycImplV1`: a new
   `_isRegisteredProofPubkeyCommitment` mapping and `_proofTee` address appended after
   `_prevNameAndYobOfacRoot`; an `onlyProofTEE` modifier mirroring `onlyTEE`; the shared
   verification body extracted to `_verifyGcpJwtAttestation`; an
   `isRegisteredProofPubkeyCommitment` view; plus a revoke path per the note above.
   `RegisterProofVerifierLib` is deliberately left untouched so a prover key can never
   satisfy the KYC attestor check at `RegisterProofVerifierLib.sol:101-108`.
2. Deploy the registry upgrade.
3. Register the prover's image digest in `PCR0Manager`; set `_proofTee`.
4. Turn the `chain` flag on.

## Risks

- **Node in the enclave image.** Larger measured surface and a new dependency tree inside
  the TEE. Mitigated only by the fact that the sidecar exits before the server starts.
- **PCR0 churn.** Any change to the image — including npm dependency updates — changes the
  digest and requires re-registration in `PCR0Manager` before registrations succeed.
- **Sidecar/consumer coupling.** The handoff is untyped files on disk. Test 3 exists
  specifically to catch drift.
