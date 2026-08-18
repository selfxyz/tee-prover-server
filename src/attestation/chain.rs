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
