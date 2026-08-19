//! Signature primitives used by the verifier chains.
//!
//! Plan A, Task 4: `rsa`, `rsapss`, `ecdsa`, and `brainpool` are gone -- every
//! scheme they covered (RSA PKCS#1 v1.5, RSASSA-PSS, and ECDSA over both NIST
//! and brainpool curves) is now checked by the JS `signature-verifier`
//! sidecar (see `verifier::sidecar`), which reaches all of them through
//! `node:crypto`'s single `crypto.verify` entry point. `eddsa` (EdDSA over
//! BabyJubJub) is the one scheme with no `node:crypto` representation, so it
//! stays as a native Rust primitive backing `kyc::verify`.

pub mod eddsa;
