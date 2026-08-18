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

/// Registers the enclave's attested signing key on-chain by submitting the
/// attestation proof to `IdentityRegistryKycImplV1.registerProverKey`.
///
/// `key` identifies the attested signing key (its address is what gets
/// registered) but its private material never leaves enclave memory and is
/// never used here. The transaction itself is signed and paid for by a
/// separate submitter key (`PROOF_TEE_PRIVATE_KEY`) that only exists to
/// satisfy the contract's `onlyProofTEE` check and pay gas — it is
/// deliberately distinct from the attested key and must never be conflated
/// with or derived from it.
pub async fn register_prover_key(
    _key: &EnclaveKey,
    attestation: &AttestationProof,
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

    // The submitter key only pays gas and satisfies onlyProofTEE. It is deliberately
    // distinct from the attested signing key, which never leaves memory.
    let submitter_pk = std::env::var("PROOF_TEE_PRIVATE_KEY")
        .map_err(|_| "PROOF_TEE_PRIVATE_KEY is not set".to_string())?;
    let rpc_url = std::env::var("RPC_URL").map_err(|_| "RPC_URL is not set".to_string())?;
    let contract_address = std::env::var("KYC_REGISTRY_ADDRESS")
        .map_err(|_| "KYC_REGISTRY_ADDRESS is not set".to_string())?;

    let signer = PrivateKeySigner::from_str(&submitter_pk)
        .map_err(|e| format!("invalid PROOF_TEE_PRIVATE_KEY: {e}"))?;
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect(&rpc_url)
        .await
        .map_err(|e| format!("failed to connect to RPC_URL: {e}"))?;

    let addr = Address::from_str(&contract_address)
        .map_err(|e| format!("invalid KYC_REGISTRY_ADDRESS: {e}"))?;
    let contract = IdentityRegistryKycImplV1::new(addr, provider);

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

        let err = register_prover_key(&key, &attestation).await.unwrap_err();
        assert_eq!(err, "pi_b must have exactly 2 rows, got 1");
    }
}
