# Self TEE Prover Server

A zero-knowledge proof generation server that runs inside a Trusted Execution Environment (TEE). It generates Groth16 proofs for passport and identity verification as part of the [Self](https://self.xyz) protocol, using Google Cloud Confidential Space to provide cryptographic attestation that all computation happens in a secure, tamper-proof enclave.

## Architecture

The server implements a 3-stage async pipeline connected by Tokio mpsc channels:

```
Client
  │
  │  JSON-RPC 2.0 (TCP :8888)
  │
[Confidential Space VM]
  │
  ├── hello()           → ECDH handshake + TEE attestation token
  ├── submit_request()  → AES-GCM decrypt → pipeline ↓
  │
  ├── FileGenerator     → writes input.json to tmp directory
  ├── WitnessGenerator  → runs circom C++ witness binary
  └── ProofGenerator    → runs rapidsnark Groth16 prover
                              │
                         PostgreSQL (proof + public inputs stored)
```

### Encryption & Attestation Flow

1. Client sends their P-256 public key via `hello`
2. Server generates an ephemeral P-256 key pair and computes a shared secret (ECDH)
3. Server requests an attestation token from the Confidential Space TEE, binding both public keys to the enclave identity
4. Client verifies the attestation, confirming the server is a genuine enclave
5. Client encrypts proof inputs with AES-256-GCM using the shared secret and submits via `submit_request`
6. Server decrypts, generates the ZK proof, and stores results in PostgreSQL

This ensures proof inputs are **never transmitted in plaintext** and the server can cryptographically prove it runs inside a legitimate TEE.

## Proof Types

| Type | Description |
|---|---|
| `register` | Registers a passport in the on-chain merkle tree (proves passport validity + cryptographic chain) |
| `dsc` | Proves the Document Signing Certificate chain from the Country Signing CA |
| `disclose` | Selectively discloses passport attributes (age, nationality, etc.) without revealing the full document |

Each type also supports ID-card and Aadhaar variants (`register_id`, `dsc_id`, `disclose_id`, `register_aadhaar`, `disclose_aadhaar`).

## Build

### Prerequisites

- Docker
- Git submodules (circom circuits, rapidsnark)

### Setup

```sh
git submodule update --init --recursive
cd self/circuits && yarn && cd ../..
```

### Building Docker Images

```sh
docker build \
  --build-arg PROOFTYPE=<register|dsc|disclose> \
  --build-arg SIZE_FILTER=<small|medium|large> \
  -f Dockerfile.tee \
  -t <IMAGE_NAME> .
```

A `Dockerfile.cherrypick` variant bundles all circuit types into a single image (compiled with `--features cherrypick`).

## Running

### CLI Options

```
Options:
  -s, --server-address <SERVER_ADDRESS>    Web server bind address [default: 0.0.0.0:3001]
  -d, --project-id <PROJECT_ID>           GCP project ID (for Secret Manager)
      --secret-id <SECRET_ID>             Secret Manager secret name for DB URL
  -c, --circuit-folder <CIRCUIT_FOLDER>   Circuit folder path [default: /circuits]
  -k, --zkey-folder <ZKEY_FOLDER>         ZKey folder path [default: /zkeys]
  -r, --rapidsnark-path <RAPIDSNARK_PATH> Rapidsnark binary path [default: /rapidsnark]
      --precheck-mode <PRECHECK_MODE>      Signature pre-check enforcement mode: shadow|enforce [default: enforce]
  -h, --help                              Print help
```

### Environment Variables

| Variable | Description |
|---|---|
| `PROJECT_ID` | GCP project ID |
| `SECRET_ID` | Secret Manager secret name (contains the PostgreSQL connection URL) |
| `PROJECT_NUMBER` | GCP project number (for Workload Identity Federation) |
| `POOL_NAME` | GCP Workload Identity Pool name |
| `PRECHECK_MODE` | `shadow` or `enforce` (default `enforce`); see [Operations](#operations) |

The database URL is fetched at runtime from GCP Secret Manager using TEE attestation credentials — it is never passed as an environment variable or CLI argument.

### Container Startup

Inside the TEE, `start.sh` handles initialization:

1. Generates GCP Workload Identity Federation credentials via attestation
2. Sets `ulimit -s 500000` (required for ZK witness generation)
3. Launches the server on port 8888

## API

The API follows **JSON-RPC 2.0** under the `openpassport` namespace.

### `openpassport_health`

Liveness check.

### `openpassport_hello`

Initiates an ECDH handshake with TEE attestation.

**Parameters:**
- `user_pubkey` (`Vec<u8>`): Client's compressed P-256 public key (33 bytes, SEC1)
- `uuid` (`String`): Unique session identifier

**Returns:** `HelloResponse` containing the UUID and attestation token (verify before proceeding).

### `openpassport_submit_request`

Submits an encrypted proof request.

**Parameters:**
- `uuid` (`String`): Session identifier from `hello`
- `nonce` (`Vec<u8>`): AES-GCM nonce
- `cipher_text` (`Vec<u8>`): Encrypted `SubmitRequest` payload
- `auth_tag` (`Vec<u8>`): AES-GCM authentication tag

**Returns:** The UUID. Poll the database for proof status updates.

### `openpassport_attestation`

Requests a raw attestation token.

**Parameters:**
- `user_data` (`Option<Vec<u8>>`): Optional user data
- `nonce` (`Option<Vec<u8>>`): Optional nonce
- `public_key` (`Option<Vec<u8>>`): Optional public key

**Returns:** Attestation data as bytes.

### Example

```json
// Request
{
  "jsonrpc": "2.0",
  "method": "openpassport_hello",
  "params": {
    "user_pubkey": [3, 12, 45, ...],
    "uuid": "550e8400-e29b-41d4-a716-446655440000"
  },
  "id": 1
}

// Response
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "uuid": "550e8400-e29b-41d4-a716-446655440000",
    "attestation": [...]
  }
}
```

## Database

The `proofs` table tracks proof lifecycle with PostgreSQL LISTEN/NOTIFY for real-time status updates:

| Status | Value | Description |
|---|---|---|
| Pending | 0 | Request received, queued |
| WitnessGenerated | 1 | Circom witness computed |
| ProofGenerated | 2 | Groth16 proof complete |
| Failed | 3 | Error (reason stored) |

Every row also carries the signature pre-check's own verdict, independent of `status`/`reason`:

| `precheck_verdict` | Value | Description |
|---|---|---|
| Valid | 0 | Signature verified |
| Invalid | 1 | An affirmative cryptographic or structural failure |
| Unavailable | 2 | The check itself could not be completed (sidecar failure, or a residual certificate-parseability gap) |

`precheck_verdict`/`precheck_reason` are nullable and written on every request that reaches the pre-check, whatever the outcome — including `valid` and including requests that go on to reject or succeed. A circuit that received no requests has no rows at all, which is what keeps "no traffic" distinguishable from "everything unavailable". Promotion/monitoring query:

```sql
SELECT circuit_name, precheck_verdict, count(*)
FROM proofs WHERE created_at > now() - interval '7 days'
GROUP BY 1, 2 ORDER BY 1;
```

Schema is defined in [`setup.sql`](./setup.sql).

## Operations

### Signature pre-check enforcement

The server verifies a document's signature before Groth16 proving (`signature-verifier/` + `src/verifier/`). `--precheck-mode` (env `PRECHECK_MODE`) controls what happens to that verdict:

| mode | `invalid` | `unavailable` |
|---|---|---|
| `shadow` | forward | forward |
| `enforce` | reject | reject |

`register_kyc` is exempt in both modes: it is verified by the native Rust path (`src/verifier/kyc.rs`), not the JS sidecar, and its own circuit has no unrelated authority to move — see `precheck_rejection` in `src/verifier/mod.rs`.

**Default is `enforce`, in the image itself** (`start.sh` passes `--precheck-mode=${PRECHECK_MODE:-enforce}`). It is still overridable per-deployment without a rebuild:

- **To flip to `shadow` in an incident**: set `PRECHECK_MODE=shadow` on the Cloud Run / Confidential Space revision and deploy that revision. This is a config change and a revision bump — not an image rebuild, and not a re-attestation of a new measured image. It takes effect for requests handled by the new revision; in-flight requests on the old revision are unaffected.
- **Known residual risk**: a certificate whose ASN.1 encoding OpenSSL's parser refuses to parse is the one remaining way a genuine document can fail this pre-check. Under `enforce` that becomes a rejection for every document from the affected issuer. It cannot be detected in advance from this repo's own fixtures — the encoding comes from that issuer's real government PKI, not from anything the client controls — so watch the `precheck_verdict`/`precheck_reason` data (query above) per circuit family for a family whose `Unavailable` rate is not near zero, rather than assuming the fixture suite covers it.
- **Sidecar health is a production dependency under `enforce`, not an optimization.** An `unavailable` verdict rejects, so if the `signature-verifier` Node sidecar is down or failing, `enforce` mode produces **no proofs at all** for the affected circuits until it recovers — monitor it accordingly. `shadow` mode does not have this exposure, which is the fast mitigation described above.

## Tech Stack

| Component | Technology |
|---|---|
| Language | Rust (2021 edition) |
| Async runtime | Tokio |
| RPC | jsonrpsee (JSON-RPC 2.0) |
| Database | PostgreSQL (sqlx) |
| Encryption | AES-256-GCM, P-256 ECDH |
| TEE | Google Cloud Confidential Space |
| Secrets | GCP Secret Manager |
| ZK proofs | Groth16 (circom + rapidsnark) |
| CI/CD | GitHub Actions → GCP Artifact Registry |

## CI/CD

Pushes to `main` deploy to production (tag `latest`), pushes to `staging` deploy with tag `stg`. The pipeline:

1. Downloads pre-compiled circuit artifacts and `.zkey` files from S3 / GCP Buckets
2. Builds Docker images per proof type and size tier
3. Pushes to Google Artifact Registry
4. Notifies a GCP Cloud Function with build metadata
