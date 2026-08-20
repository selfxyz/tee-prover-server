use std::str::FromStr;

use alloy::{
    network::EthereumWallet, primitives::Address, providers::ProviderBuilder,
    signers::local::PrivateKeySigner, sol,
};

use crate::attestation::{bootstrap::AttestationProof, EnclaveKey};

// Registration targets the HUB, not IdentityRegistryKycImplV1.
//
// The GCP JWT verification plumbing (verifier address, root-CA hash, PCR0Manager,
// authorized TEE) currently lives only on the KYC registry, which is why an earlier
// draft aimed here. But a prover key is orthogonal to attestation type — this server
// produces passport, EU ID, Aadhaar and KYC proofs alike — and registering it in a
// KYC-specific contract puts it one mapping away from checkPubkeyCommitment, which
// RegisterProofVerifierLib treats as KYC-attestor authority. The hub is the
// attestation-agnostic entry point and has nothing a prover key can be confused with.
//
// registerProverKey does not exist yet; this is written against the agreed signature
// so the feature can be enabled by flipping the `chain` flag. Regenerate this
// interface from the deployed ABI at switch-on rather than trusting the hand-written
// selector, and note the `20` is the gcp_jwt_verifier circuit's public-signal count
// (1 root-CA hash + 4 eat_nonce chunks + 3 image-hash chunks + 12 current_date).
sol! {
    #[sol(rpc)]
    interface IIdentityVerificationHubV2 {
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

/// Registers the enclave's attested signing key on-chain by submitting the
/// attestation proof to `IIdentityVerificationHubV2.registerProverKey`.
///
/// `key` identifies the attested signing key (its address is what gets
/// registered) but its private material never leaves enclave memory and is
/// never used here. The transaction itself is signed and paid for by
/// `submitter_pk`, a separate key that only exists to satisfy the contract's
/// `onlyProverTEE` check and pay gas — it is deliberately distinct from the
/// attested key and must never be conflated with or derived from it.
///
/// Every input is a parameter; this function reads no environment at all.
///
/// Under Confidential Space an env var is an instance-metadata value, readable
/// by anyone holding `compute.instances.get` on the project. None of these
/// three can travel that way: `submitter_pk` is a funded private key, and a
/// provider RPC URL routinely embeds an API key in its path. `main.rs` fetches
/// all three from Secret Manager — the same path the database URL already
/// takes — and passes them in. Taking them as arguments rather than reading
/// them here is what keeps that decision enforceable: an env read inside this
/// function would silently reinstate the metadata route for whichever value
/// it read.
pub async fn register_prover_key(
    _key: &EnclaveKey,
    attestation: &AttestationProof,
    rpc_url: &str,
    hub_address: &str,
    submitter_pk: &str,
) -> Result<(), String> {
    // Validate the attestation's shape before touching env vars or the network.
    // `AttestationProof`'s fields are `pub` and this fn is public, so nothing
    // upstream guarantees `pi_b` has two rows the way `proof_digest` does on
    // its only current call path — index it only after checking.
    if attestation.proof.pi_b.len() != 2 {
        return Err(format!("pi_b must have exactly 2 rows, got {}", attestation.proof.pi_b.len()));
    }
    let a = to_u256_array::<2>(&attestation.proof.pi_a, "pi_a")?;
    let b = [
        to_u256_array::<2>(&attestation.proof.pi_b[0], "pi_b[0]")?,
        to_u256_array::<2>(&attestation.proof.pi_b[1], "pi_b[1]")?,
    ];
    let c = to_u256_array::<2>(&attestation.proof.pi_c, "pi_c")?;
    let pub_signals = to_u256_array::<20>(&attestation.public_inputs, "public_inputs")?;

    // Checked before any network access so a missing or blank secret reports
    // itself, rather than surfacing later as an RPC timeout or an opaque
    // address-parse failure.
    if submitter_pk.trim().is_empty() {
        return Err("submitter key is empty".to_string());
    }
    if rpc_url.trim().is_empty() {
        return Err("rpc url is empty".to_string());
    }
    if hub_address.trim().is_empty() {
        return Err("hub address is empty".to_string());
    }
    let contract_address = hub_address.trim();

    // The error deliberately does not interpolate the key material.
    let signer = PrivateKeySigner::from_str(submitter_pk.trim())
        .map_err(|_| "submitter key is not a valid secp256k1 private key".to_string())?;
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect(rpc_url.trim())
        .await
        .map_err(|e| format!("failed to connect to RPC_URL: {e}"))?;

    let addr = Address::from_str(contract_address)
        .map_err(|e| format!("invalid hub address: {e}"))?;
    let contract = IIdentityVerificationHubV2::new(addr, provider);

    contract
        .registerProverKey(a, b, c, pub_signals)
        .send()
        .await
        .map_err(|e| format!("registerProverKey transaction failed to send: {e}"))?
        .watch()
        .await
        .map_err(|e| format!("registerProverKey transaction failed to confirm: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_u256_array_rejects_short_input() {
        let values = vec!["1".to_string()];
        let err = to_u256_array::<2>(&values, "pi_a").unwrap_err();
        assert_eq!(err, "pi_a must have 2 elements, got 1");
    }

    #[test]
    fn to_u256_array_rejects_long_input() {
        let values = vec!["1".to_string(), "2".to_string(), "3".to_string()];
        let err = to_u256_array::<2>(&values, "pi_a").unwrap_err();
        assert_eq!(err, "pi_a must have 2 elements, got 3");
    }

    #[test]
    fn to_u256_array_rejects_non_decimal_string() {
        let values = vec!["not_a_number".to_string(), "2".to_string()];
        let err = to_u256_array::<2>(&values, "pi_a").unwrap_err();
        assert!(err.starts_with("bad pi_a[0]:"), "unexpected error message: {err}");
    }

    #[test]
    fn to_u256_array_accepts_exact_length_decimal_strings() {
        let values = vec!["1".to_string(), "2".to_string()];
        let out = to_u256_array::<2>(&values, "pi_a").unwrap();
        assert_eq!(out[0], alloy::primitives::U256::from(1u64));
        assert_eq!(out[1], alloy::primitives::U256::from(2u64));
    }

    fn sample_proof() -> crate::db::Proof {
        crate::db::Proof {
            pi_a: vec!["1".into(), "2".into()],
            pi_b: vec![vec!["3".into(), "4".into()], vec!["5".into(), "6".into()]],
            pi_c: vec!["7".into(), "8".into()],
            protocol: "groth16".into(),
        }
    }

    /// `AttestationProof`'s fields are `pub` and `register_prover_key` is a public
    /// async fn, so nothing stops a future caller from constructing one with a
    /// malformed `pi_b` directly (bypassing the shape checks `proof_digest`
    /// already runs on the only current call path). This pins the guard added
    /// to `register_prover_key` so a bad `pi_b` produces a clean `Err` instead
    /// of an index-out-of-bounds panic.
    #[tokio::test]
    async fn register_prover_key_rejects_malformed_pi_b_before_indexing() {
        let mut proof = sample_proof();
        proof.pi_b = vec![vec!["3".into(), "4".into()]]; // only one row, must be 2

        let attestation = AttestationProof {
            proof,
            public_inputs: vec!["0".to_string(); 20],
        };
        let key = EnclaveKey::generate();

        let err = register_prover_key(&key, &attestation, "http://rpc.invalid", "0x0000000000000000000000000000000000000001", "0xdeadbeef").await.unwrap_err();
        assert_eq!(err, "pi_b must have exactly 2 rows, got 1");
    }

    /// The submitter key arrives as an argument, not as `PROOF_TEE_PRIVATE_KEY`
    /// in the process environment.
    ///
    /// Confidential Space delivers `tee-env-*` values through instance
    /// metadata, which is readable by anyone holding `compute.instances.get` on
    /// the project -- so a funded private key must never travel that way. It is
    /// fetched from Secret Manager by `main.rs`, exactly as the database URL is,
    /// and handed here. Passing it explicitly is what keeps that decision
    /// visible: an env-var read inside this function would silently accept a
    /// metadata-delivered key again.
    #[tokio::test]
    async fn register_prover_key_rejects_an_empty_submitter_key() {
        let attestation = AttestationProof {
            proof: sample_proof(),
            public_inputs: vec!["0".to_string(); 20],
        };
        let key = EnclaveKey::generate();

        let err = register_prover_key(&key, &attestation, "http://rpc.invalid", "0x0000000000000000000000000000000000000001", "   ").await.unwrap_err();
        assert_eq!(err, "submitter key is empty");
    }

    /// Every blank input is named specifically, before any network access.
    ///
    /// All three arrive from Secret Manager, so a blank one means a secret that
    /// is missing, empty, or wrong -- the single most likely way this is
    /// misconfigured on first deploy. Naming which one is blank turns that into
    /// a one-line diagnosis; without these guards an empty rpc url surfaces as
    /// a connection error and an empty hub address as an opaque parse failure,
    /// neither of which points at the secret.
    #[tokio::test]
    async fn each_blank_input_is_rejected_by_name() {
        let attestation = AttestationProof {
            proof: sample_proof(),
            public_inputs: vec!["0".to_string(); 20],
        };
        let key = EnclaveKey::generate();
        const RPC: &str = "http://rpc.invalid";
        const HUB: &str = "0x0000000000000000000000000000000000000001";
        const PK: &str = "0xdeadbeef";

        let cases = [
            ((RPC, HUB, "  "), "submitter key is empty"),
            (("", HUB, PK), "rpc url is empty"),
            ((RPC, " \t ", PK), "hub address is empty"),
        ];
        for ((rpc, hub, pk), expected) in cases {
            let err = register_prover_key(&key, &attestation, rpc, hub, pk).await.unwrap_err();
            assert_eq!(err, expected, "for inputs ({rpc:?}, {hub:?}, {pk:?})");
        }
    }

    /// A malformed submitter key must not put key material in the error.
    ///
    /// The error is logged and, on the boot path, becomes a panic message. Both
    /// destinations outlive the process, so interpolating the key would leak it
    /// on exactly the failure most likely to be pasted into a bug report.
    #[tokio::test]
    async fn an_invalid_submitter_key_is_not_echoed_in_the_error() {
        let attestation = AttestationProof {
            proof: sample_proof(),
            public_inputs: vec!["0".to_string(); 20],
        };
        let key = EnclaveKey::generate();
        let secret = "totally-not-a-valid-private-key-but-secret";

        let err = register_prover_key(
            &key,
            &attestation,
            "http://rpc.invalid",
            "0x0000000000000000000000000000000000000001",
            secret,
        )
        .await
        .unwrap_err();

        assert!(!err.contains(secret), "error must not echo the key material: {err}");
        assert_eq!(err, "submitter key is not a valid secp256k1 private key");
    }
}
