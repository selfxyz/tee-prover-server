//! Native pre-check of a document's signature, from the same circuit inputs the
//! prover is about to consume.
//!
//! The governing asymmetry: a false reject takes down proving for a valid
//! document, while a false accept costs nothing because the circuit still
//! verifies the signature properly. So this module skips whenever it cannot be
//! certain, and only an affirmative failure rejects.

use std::panic::AssertUnwindSafe;

use futures::FutureExt;

pub mod chunks;
pub mod params;
pub mod passport;
pub mod primitives;
pub mod sha_padding;
#[cfg(test)]
pub mod testkit;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Valid,
    /// An affirmative cryptographic or structural failure. Only this rejects.
    Invalid(String),
    /// Cannot check. Never a rejection.
    Skipped(String),
}

/// Runs a verifier body, converting any panic into `Skipped`.
///
/// A panic here must not fail the request: the circuit remains the authority,
/// so the worst outcome of a bug in this module is a lost optimisation.
pub(crate) async fn run_guarded<F>(f: F) -> Verdict
where
    F: FnOnce() -> Verdict,
{
    match AssertUnwindSafe(async move { f() }).catch_unwind().await {
        Ok(v) => v,
        Err(_) => Verdict::Skipped("verifier panicked".to_string()),
    }
}

pub async fn verify_inputs(uuid: uuid::Uuid, circuit_name: &str) -> Verdict {
    let dir = crate::utils::get_tmp_folder_path(&uuid.to_string());
    let path = std::path::Path::new(&dir).join("input.json");

    // Reading here rather than in a later task keeps the "missing file" test
    // honest: a stub that ignored the uuid would skip for the wrong reason.
    let raw = match tokio::fs::read_to_string(&path).await {
        Ok(raw) => raw,
        Err(e) => return Verdict::Skipped(format!("could not read input.json: {e}")),
    };
    let inputs: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => return Verdict::Skipped(format!("input.json is not valid JSON: {e}")),
    };

    let Some(p) = params::lookup(circuit_name) else {
        return Verdict::Skipped(format!("no circuit parameters known for circuit {circuit_name}"));
    };

    // register_* and register_id_* both carry the RSA passport / EU-ID
    // three-link chain (this also reaches register_aadhaar and register_kyc,
    // which passport::verify itself declines via their non-RSA-passport shape
    // or scheme, skipping rather than misapplying the chain).
    if circuit_name.starts_with("register") {
        return run_guarded(|| passport::verify(&inputs, &p)).await;
    }

    Verdict::Skipped(format!("no verifier wired for circuit {circuit_name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unknown_circuit_is_skipped_never_invalid() {
        let v = verify_inputs(uuid::Uuid::new_v4(), "not_a_real_circuit").await;
        match v {
            Verdict::Skipped(_) => {}
            other => panic!("expected Skipped for an unknown circuit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_input_file_is_skipped_for_that_reason() {
        // No tmp folder exists for this uuid, so input.json cannot be read.
        // Asserting the REASON matters: a stub that ignores the uuid and skips
        // unconditionally would pass a bare Skipped check while reading nothing.
        let v = verify_inputs(uuid::Uuid::new_v4(), "register_sha256_sha256_sha256_rsa_65537_4096").await;
        match v {
            Verdict::Skipped(reason) => assert!(
                reason.contains("input.json"),
                "expected the reason to name the unreadable input file, got: {reason}"
            ),
            other => panic!("a missing input file must skip, not reject: got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_readable_input_file_gets_past_the_read_step() {
        // Proves the read actually happens: with a real file present, the skip
        // reason must be about dispatch, not about reading.
        let uuid = uuid::Uuid::new_v4();
        let dir = crate::utils::get_tmp_folder_path(&uuid.to_string());
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(std::path::Path::new(&dir).join("input.json"), b"{}").await.unwrap();

        let v = verify_inputs(uuid, "register_sha256_sha256_sha256_rsa_65537_4096").await;
        let _ = tokio::fs::remove_dir_all(&dir).await;

        match v {
            Verdict::Skipped(reason) => assert!(
                !reason.contains("input.json"),
                "the file was readable, so the reason must not blame the file: {reason}"
            ),
            other => panic!("expected Skipped at this stage, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_panicking_verifier_surfaces_as_skipped() {
        let v = run_guarded(|| panic!("boom")).await;
        match v {
            Verdict::Skipped(reason) => assert!(reason.contains("panic")),
            other => panic!("a panic must become Skipped, got {other:?}"),
        }
    }
}
