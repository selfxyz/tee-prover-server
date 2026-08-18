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
        // NOTE: the brief specified `example_jwt_fail.txt` here, but that fixture is a
        // validly-signed real attestation JWT built for circuit-level nonce-binding
        // rejection tests, not generator-level parsing failures — the sidecar accepts
        // it and exits 0 (verified manually; this is the same known issue documented in
        // Task 1's report/commit 4abe9a4). `example_jwt_short_chain.txt` is a fixture
        // with only 2 of the required 3 x5c certificates, which the sidecar's own
        // parsing genuinely rejects with a non-zero exit — confirmed manually before
        // wiring it in here.
        assert!(run_input_generator(&key.address(), out.to_str().unwrap(),
                                    Some("fixtures/example_jwt_short_chain.txt")).await.is_err());
    }
}
