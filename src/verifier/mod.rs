//! Native pre-check of a document's signature, from the same circuit inputs the
//! prover is about to consume.
//!
//! The governing asymmetry: a false reject takes down proving for a valid
//! document, while a false accept costs nothing because the circuit still
//! verifies the signature properly. So this module skips whenever it cannot be
//! certain, and only an affirmative failure rejects.

use std::panic::AssertUnwindSafe;

use futures::FutureExt;

pub mod aadhaar;
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

    // Aadhaar and KYC are exact-name circuit families with their own verifiers,
    // but both also start with "register" — the same prefix as the RSA
    // passport / EU-ID circuits handled below. They MUST be matched here,
    // before the prefix match, or their arms would be unreachable, shadowed by
    // the broader "register" prefix (the same class of bug the Task 2
    // reviewer caught in the parameter lookup's register_id_-before-register_
    // ordering).
    if circuit_name == "register_aadhaar" {
        return run_guarded(|| aadhaar::verify(&inputs, &p)).await;
    }
    if circuit_name == "register_kyc" {
        // Task 6 owns this verifier; until it lands, register_kyc must still
        // be excluded here rather than falling through to the prefix match.
        return Verdict::Skipped(format!("no verifier wired yet for circuit {circuit_name}"));
    }

    // Only genuine RSA passport / EU-ID circuits reach here: register_* and
    // register_id_* (register_id_* is itself a subset of the "register"
    // prefix, so a single prefix check covers both).
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

    /// Pins the dispatch routing itself, independent of *why* Aadhaar
    /// currently skips. The fixture below is deliberately a self-consistent
    /// RSA passport-shaped input built under register_aadhaar's own (n, k) =
    /// (121, 17) and all-SHA-256 hash widths — i.e. one passport::verify
    /// would call `Valid` on if the "register" prefix arm ever reached it
    /// before the exact-name exclusion.
    ///
    /// Now that the Aadhaar arm is wired (Task 5), the correctly-routed
    /// outcome is no longer "no verifier wired" — it is `Skipped` for
    /// Aadhaar's own missing fields, because this fixture uses passport field
    /// names (`dg1`, `pubKey_dsc`, `signature_passport`, ...), none of which
    /// is `qrDataPadded`. So the property under test is unchanged (this
    /// payload must not be verified by the passport chain), only the
    /// expected reason moves from a routing placeholder to Aadhaar's own
    /// field-parsing message. If a future edit reorders the dispatch so the
    /// prefix match runs first, this test observes `Valid`, not `Skipped`,
    /// and fails loudly rather than passing for the wrong reason.
    #[tokio::test]
    async fn register_aadhaar_is_never_routed_into_the_passport_verifier() {
        let key = testkit::TestRsaKey::generate(65537);
        let inputs = testkit::passport_inputs(&key, 121, 17);

        let uuid = uuid::Uuid::new_v4();
        let dir = crate::utils::get_tmp_folder_path(&uuid.to_string());
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(std::path::Path::new(&dir).join("input.json"), inputs.to_string())
            .await
            .unwrap();

        let v = verify_inputs(uuid, "register_aadhaar").await;
        let _ = tokio::fs::remove_dir_all(&dir).await;

        match v {
            Verdict::Skipped(reason) => assert!(
                reason.contains("qrDataPadded"),
                "register_aadhaar must be checked by the Aadhaar verifier against its own \
                 fields (this passport-shaped fixture has no qrDataPadded field, so the \
                 Aadhaar verifier must skip for that reason), not a passport-chain reason: \
                 {reason}"
            ),
            other => panic!(
                "register_aadhaar must never reach the passport verifier (it would have \
                 accepted this self-consistent fixture as Valid): got {other:?}"
            ),
        }
    }

    /// Same pin for KYC. Its scheme (EdDsaBabyJubJub, n = k = 0) has no
    /// RSA-style limb layout, so there is no way to build a fixture the
    /// passport chain would call `Valid` on the way the Aadhaar test above
    /// does. Instead this asserts on the reason string directly: if the
    /// "register" prefix arm were ever reached first, passport::verify's own
    /// scheme guard would produce a reason mentioning the RSA scheme mismatch
    /// rather than "no verifier wired".
    #[tokio::test]
    async fn register_kyc_is_never_routed_into_the_passport_verifier() {
        let uuid = uuid::Uuid::new_v4();
        let dir = crate::utils::get_tmp_folder_path(&uuid.to_string());
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(std::path::Path::new(&dir).join("input.json"), b"{}")
            .await
            .unwrap();

        let v = verify_inputs(uuid, "register_kyc").await;
        let _ = tokio::fs::remove_dir_all(&dir).await;

        match v {
            Verdict::Skipped(reason) => {
                assert!(
                    reason.contains("no verifier wired"),
                    "register_kyc must skip with a 'no verifier wired' reason (Task 6's                      arm doesn't exist yet), got: {reason}"
                );
                assert!(
                    !reason.to_lowercase().contains("scheme"),
                    "reason must not be the passport chain's scheme-mismatch message, which                      would mean routing fell through to the passport verifier: {reason}"
                );
            }
            other => panic!("register_kyc must never reach the passport verifier, got {other:?}"),
        }
    }
}
