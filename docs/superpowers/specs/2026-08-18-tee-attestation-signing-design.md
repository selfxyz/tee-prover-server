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
 └─ exec tee-server
       (bootstrap spawns the Node sidecar as a subprocess, passing the enclave address)
       jwt-input-generator: PKI token (nonces = [enclaveAddress, "self_protocol"])
                            -> /zk/inputs.json   (no key file)
       ├─ bootstrap        NEW  mint k256 key; spawn sidecar; attestation proof via existing generators
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

The signing key is a **secp256k1 (k256) ECDSA** key minted in-enclave at boot by the Rust
process and held only in memory. It is never written to disk and never leaves the enclave.
`bootstrap.rs` derives the Ethereum address, spawns the Node sidecar with that address as
an argument, and the sidecar places it in the attestation token's nonce. There is no
`key.txt`; the earlier tmpfs design is superseded because Rust owns the key directly.

Persisting the key — including to GCP Secret Manager — was considered and rejected. Anyone
able to read the secret could sign proof outputs indistinguishably from a genuine enclave,
which defeats the attestation entirely. Note that this repo's Secret Manager access is
already attestation-gated via Workload Identity Federation (`update_creds.sh` builds an
`external_account` credential sourced from
`/run/container_launcher/attestation_verifier_claims_token`), but that protection is only
as strong as the attribute condition configured on the `attestation-verifier` provider. If
that condition does not pin the image digest, any workload in the pool can read the
secret. A signing key's security should not rest on IAM configuration outside this repo.

The Ethereum key used to *submit* the registration transaction is separate from the
attested signing key, mirroring `didit-tee` (which uses `only_tee_pk` for submission). The
submitter only pays gas and satisfies `onlyProofTEE`; compromising it cannot forge
signatures.

Consequences, accepted deliberately:

1. **Every restart mints a new key and needs a new registration transaction.** Acceptable
   at current scale. Each horizontally scaled instance registers its own key.
2. **There is no revocation path.** The deferred registry mapping follows the existing KYC
   pattern, where the flag is set to `true` and never unset. Every key an enclave has ever
   minted would stay valid forever, and a compromised key could not be retired. A revoke
   method should be added in the deferred contract work rather than inheriting this
   property by default.

## Signature scheme

secp256k1 ECDSA, producing a 65-byte recoverable `(r, s, v)` signature. Chosen so proof
signatures can be verified **on-chain** with `ecrecover`, which is a single opcode;
verifying EdDSA-BabyJubJub in Solidity is substantially more expensive and complex.

This diverges from `didit-tee`, which uses EdDSA-BabyJubJub because its signatures are
verified inside a circuit rather than on-chain. The consequence here is that no Poseidon
commitment is needed: the attestation nonce carries the enclave's Ethereum address
directly (42 characters, well inside the 99-character `eat_nonce` limit), and the deferred
registry is a `mapping(address => bool)` rather than a commitment mapping. No
`unpackAndDecodeHexPubkey`-style helper is required.

**Signed digest — pinned.** Changing this later invalidates every stored signature:

```
digest = keccak256(abi.encode(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[] publicInputs))
```

This is reconstructible in Solidity from the proof a verifier already receives, so an
on-chain verifier needs no additional input beyond the signature itself.

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
- `Cargo.toml` — `k256` (signing, always on); `alloy` behind `chain`
- `setup.sql` — `signature` column + include it in the notify payload
- `Dockerfile.tee` — Node + `npm install`; vendored sidecar at `/jwt`
- `start.sh` — unchanged; `bootstrap.rs` spawns the sidecar as a subprocess
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
4. **Signature round-trip** — sign a known digest with a known key, recover the signer,
   and assert it equals the derived enclave address. Includes a fixed-vector test against
   a known `(digest, key) -> signature` pair so the encoding cannot drift from what an
   on-chain `ecrecover` verifier would compute.
5. **Migration** — `setup.sql` applies cleanly to an existing `proofs` table and the
   notify payload contains the new field.

## Out of scope (deferred, in order)

1. `registerProverKey` on the **hub** (`IdentityVerificationHubImplV2`), not on
   `IdentityRegistryKycImplV1`: a `mapping(address => bool) _isRegisteredProverKey`, an
   authorized submitter, and an `isRegisteredProverKey` view. The prover address is read
   from the `eat_nonce` public signals rather than unpacked as a Poseidon commitment.

   **Why the hub.** An earlier draft of this spec targeted the KYC registry, because that
   is the only contract that currently holds the GCP JWT verification plumbing
   (`_gcpJwtVerifier`, `_gcpRootCAPubkeyHash`, `_PCR0Manager`, `_tee`) — the hub has none
   of it. That was expedience, not design. A prover key is orthogonal to attestation type:
   this server produces passport, EU ID, Aadhaar and KYC proofs alike. Registering it in a
   KYC-specific contract also places it one mapping away from `checkPubkeyCommitment`,
   which `RegisterProofVerifierLib.sol:101-108` treats as KYC-attestor authority — the
   tension that forced the earlier draft to invent a separate mapping and a separate
   `_proofTee` purely to keep the two apart. On the hub that tension does not exist.

   **Open decision, not settled here:** whether the hub gets its own
   `_gcpJwtVerifier`/`_gcpRootCAPubkeyHash`/`_PCR0Manager` storage, or reads them through
   the registry it already holds. Note the verification body (verifier + root-CA + PCR0 +
   timestamp window) is *already* duplicated twice inside
   `IdentityRegistryKycImplV1` (`:503-510` and `:556-563`), so extracting it is preferable
   to adding a third copy wherever it lands.

   Also add a revoke path per the note above; the KYC pattern sets its flag to `true` and
   never unsets it.

2. Deploy the hub upgrade.
3. Register the prover's image digest in `PCR0Manager`; set `_proofTee`.
4. Turn the `chain` flag on.

## Risks

- **Node in the enclave image.** Larger measured surface and a new dependency tree inside
  the TEE. Mitigated only by the fact that the sidecar exits before the server starts.
- **PCR0 churn.** Any change to the image — including npm dependency updates — changes the
  digest and requires re-registration in `PCR0Manager` before registrations succeed.
- **Sidecar/consumer coupling.** The handoff is untyped files on disk. Test 3 exists
  specifically to catch drift.
