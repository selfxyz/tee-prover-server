use core::str;
use std::path;

use crate::attestation::digest::proof_digest;
use crate::attestation::EnclaveKey;
use crate::db::{read_proof_output, Proof};
use crate::generator::{proof_generator::ProofGenerator, witness_generator::WitnessGenerator};
use crate::utils::get_tmp_folder_path;

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

    // Run the tsx that `npm ci` installed into the image, by absolute path, instead of
    // `npx tsx`: with `npx`, a missing `node_modules/.bin/tsx` is not an error — it
    // downloads the package from the registry and executes it. That would run
    // unmeasured code inside an enclave whose image digest is the entire security
    // anchor. Resolving the path ourselves means a missing runtime is a loud boot
    // failure (fatal by design) and never a network fetch. Canonicalized because a
    // relative program path is resolved against an unspecified working directory once
    // `current_dir` is also set.
    let tsx = std::fs::canonicalize(path::Path::new(dir).join("node_modules/.bin/tsx"))
        .map_err(|e| {
            format!("jwt-input-generator runtime not found at {dir}/node_modules/.bin/tsx: {e}")
        })?;

    let mut cmd = tokio::process::Command::new(tsx);
    cmd.current_dir(dir)
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

    // Everything fallible lives in this inner block so `tmp` is always cleaned up
    // afterward, on both the success and the failure path. Bootstrap failure is
    // fatal by design, which means the error paths here are precisely the ones
    // that fire in practice — leaving the JWT input and any partial witness/proof
    // artifacts behind in the enclave's filesystem is not an acceptable default.
    let result: Result<AttestationProof, String> = async {
        let input_file = path::Path::new(&tmp).join("input.json");
        run_input_generator(&key.address(), input_file.to_str().unwrap(), None).await?;

        WitnessGenerator::new(uuid, ATTESTATION_CIRCUIT.to_string())
            .run(circuit_folder)
            .await?;
        ProofGenerator::new(uuid, zkey_path.to_string())
            .run(&rapidsnark_path.to_string())
            .await?;

        // Single reader shared with the request pipeline (see
        // `crate::db::read_proof_output`), so bootstrap's own self-check reads
        // proof.json/public_inputs.json exactly the same way every other
        // caller does.
        let (proof, public_inputs) = read_proof_output(uuid).await?;

        // Fail fast if the digest encoding cannot handle our own proof shape.
        proof_digest(&proof, &public_inputs)?;

        Ok(AttestationProof { proof, public_inputs })
    }
    .await;

    if let Err(cleanup_err) = tokio::fs::remove_dir_all(&tmp).await {
        match &result {
            // The body succeeded: the attestation is valid and there's nothing
            // secret to lose (the key never touched disk, and the proof/public
            // inputs left behind are published on-chain anyway), so a failed rm
            // is a hygiene issue, not a reason to refuse to serve proofs. Log
            // and move on rather than turning a valid attestation into a fatal
            // boot error.
            Ok(_) => {
                eprintln!(
                    "bootstrap: succeeded but failed to clean up {tmp}: {cleanup_err}"
                );
            }
            // The body already failed: that error is the one that explains why
            // the enclave cannot attest and must reach the caller unmasked.
            // Surface the cleanup failure too, just not as the returned error.
            Err(body_err) => {
                eprintln!(
                    "bootstrap: cleanup of {tmp} failed ({cleanup_err}) after bootstrap error: {body_err}"
                );
            }
        }
    }

    result.map(|attestation| (key, attestation))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The address the synthetic fixture's `eat_nonce` attests. The sidecar now
    /// requires `eat_nonce` to be exactly the nonce list it asked Google to attest,
    /// so a happy-path test cannot use a freshly minted key: no key minted here can
    /// appear inside an already-signed token. `fixtures/make_synthetic_jwt.mjs`
    /// generates a self-signed chain and token for this address and writes it here;
    /// read it rather than hardcoding it so regenerating the fixture can't desync.
    fn synthetic_fixture_address() -> String {
        std::fs::read_to_string("jwt-input-generator/fixtures/synthetic_jwt.address.txt")
            .expect("missing synthetic fixture; regenerate with fixtures/make_synthetic_jwt.mjs")
            .trim()
            .to_string()
    }

    #[tokio::test]
    async fn sidecar_receives_the_enclave_address() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("inputs.json");

        run_input_generator(
            &synthetic_fixture_address(),
            out.to_str().unwrap(),
            Some("fixtures/synthetic_jwt.txt"),
        )
        .await
        .expect("sidecar failed");

        let inputs: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert!(inputs.get("message").is_some());
    }

    /// The spec's central claim, enforced at the seam that can actually break it: a
    /// real, validly-signed GCP attestation token that attests some *other* key must
    /// make the sidecar fail, so bootstrap cannot "succeed" and leave the enclave
    /// signing proofs with a key nothing attested. `fixtures/example_jwt.txt` is
    /// exactly that token (its nonce is a didit-tee EdDSA pubkey), so the failure
    /// happens only after its real 3-certificate chain and RSA signature verify.
    #[tokio::test]
    async fn sidecar_rejects_a_token_that_attests_another_key() {
        let key = EnclaveKey::generate();
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("inputs.json");

        let err = run_input_generator(
            &key.address(),
            out.to_str().unwrap(),
            Some("fixtures/example_jwt.txt"),
        )
        .await
        .expect_err("a token attesting a different key must be rejected");

        assert!(
            err.contains("eat_nonce does not bind this enclave key"),
            "expected a nonce-binding rejection, got: {err}"
        );
        assert!(!out.exists(), "no circuit inputs may be written for an unbound token");
    }

    #[tokio::test]
    async fn sidecar_failure_is_an_error() {
        let key = EnclaveKey::generate();
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("inputs.json");
        // A *parsing* failure, deliberately distinct from the nonce-binding failure
        // covered by `sidecar_rejects_a_token_that_attests_another_key`:
        // `example_jwt_short_chain.txt` carries only 2 of the required 3 x5c
        // certificates, so it is rejected before the nonce is ever looked at. Keeping
        // both means a regression in either check is attributable to one of them.
        // (`example_jwt_fail.txt` is now also rejected — but for nonce binding, which
        // is why the other test uses it and this one does not.)
        assert!(run_input_generator(&key.address(), out.to_str().unwrap(),
                                    Some("fixtures/example_jwt_short_chain.txt")).await.is_err());
    }

    /// `bootstrap` mints its own uuid internally (by design — its signature can't
    /// take one), so this test can't predict the exact `tmp_<uuid>` path up front.
    /// Instead it snapshots the set of `tmp_*` entries in the crate root before and
    /// after a failing call: since nothing else in this suite creates `tmp_*`
    /// directories (see `get_tmp_folder_path` in `src/utils.rs` for the shape),
    /// any directory bootstrap created for this call must be gone afterward, or
    /// the sets won't match.
    #[tokio::test]
    async fn cleanup_runs_after_a_failed_bootstrap() {
        // Shared with `attestation::tests`: see `crate::attestation::TMP_ROOT_LOCK`
        // for why this global crate-root directory scan must not interleave
        // with any other test that creates its own `tmp_*` directory.
        let _guard =
            crate::attestation::TMP_ROOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        fn tmp_dirs() -> std::collections::HashSet<String> {
            std::fs::read_dir(".")
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|name| name.starts_with("tmp_"))
                .collect()
        }

        let before = tmp_dirs();

        // No Confidential Space socket exists on this machine, so
        // `run_input_generator` (the first fallible step in the body) fails
        // immediately — a bad circuit_folder never even gets reached. Either
        // way this exercises the failure path the cleanup fix targets: some
        // step in the body errors out after the tmp dir was created.
        let result = bootstrap(
            "not-a-real-circuit-folder",
            "not-a-real-zkey",
            "not-a-real-rapidsnark",
        )
        .await;

        assert!(
            result.is_err(),
            "expected bootstrap to fail without a Confidential Space socket"
        );

        let after = tmp_dirs();
        assert_eq!(
            before, after,
            "bootstrap must not leave its tmp_<uuid> directory behind on failure"
        );
    }
}
