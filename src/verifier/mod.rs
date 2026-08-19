//! Native pre-check of a document's signature, from the same circuit inputs the
//! prover is about to consume.
//!
//! The governing asymmetry, corrected under Plan B (`docs/superpowers/specs/
//! 2026-08-19-tee-signature-authority-design.md`): the circuit's own
//! signature check has a security bug and is retained only as defence in
//! depth, so a false accept here is a forged credential, not a free outcome
//! -- while a false reject is still a production outage. Neither is free.
//! Where the two conflict, this module rejects. It skips only when it
//! genuinely cannot be certain, since `Skipped` is what the fail-closed
//! rollout (shadow -> enforce-on-known -> enforce) ultimately turns into a
//! rejection too, once skip-rate evidence supports it per circuit family --
//! see the design doc's "Fail-closed, and how it ships" section. A stale
//! version of this comment previously argued the opposite (the pre-Plan-B
//! premise, "a false accept costs nothing"); a stale comment already argued
//! for reintroducing deleted code once in this project, so this one is
//! being corrected now rather than left to cause the same failure again.
//!
//! Plan A, Task 4: `dispatch` now has exactly two branches. `register_kyc`
//! (EdDSA over BabyJubJub + Poseidon2, no `node:crypto` representation) is
//! still verified natively, by `kyc.rs`. Every other circuit -- every RSA,
//! RSA-PSS, and ECDSA (NIST and brainpool curve alike) passport, EU-ID, DSC,
//! and Aadhaar circuit -- is verified by the JS `signature-verifier` sidecar
//! via `sidecar::verify`, which replaces the RSA/ECDSA-family Rust verifiers
//! (`passport.rs`, `dsc.rs`, `aadhaar.rs`) and their primitives entirely. See
//! this task's report for the ~4,700 lines that came out with them.

use std::panic::AssertUnwindSafe;

use futures::FutureExt;

pub mod chunks;
pub mod kyc;
pub mod metrics;
pub mod params;
pub mod primitives;
#[cfg(test)]
mod real_fixtures;
mod sidecar;
/// Test-only fixture builders for `kyc.rs`'s own tests.
///
/// Gated behind `cfg(test)` so it stays out of the release binary.
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
///
/// No longer `verify_inputs`'s own panic guard as of Task 3 (Plan 4) --
/// `dispatch` now runs inside `tokio::task::spawn_blocking`, whose `JoinError`
/// already reports a panic, so `verify_inputs` maps that directly instead of
/// wrapping this. Kept (not deleted) because its own test below,
/// `a_panicking_verifier_surfaces_as_skipped`, is this crate's pin on the
/// panic-containment behaviour itself; `cfg_attr` rather than a bare
/// `#[allow(dead_code)]` since a non-test build genuinely has no caller left.
#[cfg_attr(not(test), allow(dead_code))]
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
    // This also still gates the sidecar branch below, not just the native
    // register_kyc one: an unreadable or malformed input.json skips before
    // dispatch is ever reached, for either branch, exactly as before Task 4.
    let raw = match tokio::fs::read_to_string(&path).await {
        Ok(raw) => raw,
        Err(e) => return Verdict::Skipped(format!("could not read input.json: {e}")),
    };
    let inputs: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => return Verdict::Skipped(format!("input.json is not valid JSON: {e}")),
    };

    // dispatch is synchronous, but its generic (sidecar) branch reaches the
    // async Node/JS sidecar client via `tokio::runtime::Handle::current().
    // block_on(...)`. `block_on` panics if the calling thread is a normal
    // async worker thread, so `dispatch` is run inside `tokio::task::
    // spawn_blocking` here -- a blocking-pool thread, not a worker thread, so
    // `Handle::current()` still resolves and `block_on` does not panic
    // there. See `sidecar_dispatch_through_verify_inputs_does_not_deadlock`
    // below for the proof this does not hang.
    //
    // This also replaces `run_guarded`'s `catch_unwind` for this call site:
    // `spawn_blocking`'s `JoinError` already reports a panic, so a panic
    // inside `dispatch` still surfaces as `Skipped`, not a failed request --
    // the circuit remains the authority, so the worst outcome of a bug in
    // this module is a lost optimisation. `run_guarded` itself is unchanged
    // and still used by its own test below (`a_panicking_verifier_surfaces_
    // as_skipped`), which is this crate's pin on that panic-containment
    // behaviour.
    let circuit_name_owned = circuit_name.to_string();
    verdict_from_join(
        tokio::task::spawn_blocking(move || dispatch(&circuit_name_owned, &inputs, &path)).await,
    )
}

/// Maps a `spawn_blocking` result to a `Verdict`, converting a panic into
/// `Skipped`.
///
/// Split out so the production panic path is testable. `run_guarded`'s own test
/// pins `catch_unwind`, but `verify_inputs` no longer goes through
/// `run_guarded` -- so without this seam the spec's panic-containment
/// requirement would be asserted only about a function production does not
/// call, which is assurance pointing at the wrong code.
fn verdict_from_join(res: Result<Verdict, tokio::task::JoinError>) -> Verdict {
    match res {
        Ok(verdict) => verdict,
        Err(_join_error) => Verdict::Skipped("verifier panicked".to_string()),
    }
}

/// Routes already-parsed inputs to the family verifier.
///
/// Split out of `verify_inputs` so tests can exercise the real routing
/// against in-memory inputs. `verify_inputs` reads `input.json` from a
/// uuid-named temp directory, so a test that wanted to check routing would
/// otherwise have to either stage files on disk or reimplement this match —
/// and a reimplemented match drifts from the one production uses, which is
/// exactly the kind of divergence these verifiers exist to avoid.
///
/// `inputs` is only used by the `register_kyc` branch (`kyc::verify` takes
/// already-parsed JSON); the generic branch re-derives everything it needs
/// from `input_path` instead, since that is the sidecar's own wire contract
/// (`{"circuit":...,"inputPath":...}`) -- the sidecar reads and parses the
/// file itself, on its side of the process boundary.
pub(crate) fn dispatch(
    circuit_name: &str,
    inputs: &serde_json::Value,
    input_path: &std::path::Path,
) -> Verdict {
    // KYC is the one circuit with no node:crypto-representable scheme
    // (EdDSA over BabyJubJub + Poseidon2), so it is the one exception to the
    // generic sidecar branch below. This MUST be checked before falling
    // through, or register_kyc would silently lose its native verifier and
    // get the sidecar's own permanent, documented skip instead (see
    // `signature-verifier/verify.mjs`'s `verify()` doc comment) -- no false
    // accept either way, but a quiet loss of the one real check this
    // pre-check can still perform for that circuit.
    if circuit_name == "register_kyc" {
        let p = params::lookup(circuit_name)
            .expect("register_kyc has a fixed placeholder CircuitParams row");
        return kyc::verify(inputs, &p);
    }

    // Every other circuit -- register_*, register_id_*, register_aadhaar,
    // dsc_* -- is verified by the JS signature-verifier sidecar, which does
    // its own family routing (parseCircuitName) on its side of the wire.
    // Safe only because `verify_inputs` runs `dispatch` inside `tokio::
    // task::spawn_blocking`, a blocking-pool thread rather than a normal
    // async worker thread -- see `verify_inputs`'s own doc comment.
    tokio::runtime::Handle::current().block_on(sidecar::verify(circuit_name, input_path))
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
        // Proves the read actually happens: with a real (if empty) file
        // present, the sidecar is reached and skips for ITS OWN reason (a
        // missing field), not because Rust's own file read failed.
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

    /// The production panic path, as opposed to `run_guarded`'s.
    ///
    /// `verify_inputs` maps `spawn_blocking`'s `JoinError` rather than using
    /// `catch_unwind`, so this is the assertion that actually covers spec
    /// Testing item 5 for the code that runs in production. The `JoinError` is
    /// obtained from a real panicking blocking task, not constructed.
    #[tokio::test]
    async fn a_panic_inside_spawn_blocking_surfaces_as_skipped() {
        let join_err = tokio::task::spawn_blocking(|| -> Verdict { panic!("boom") })
            .await
            .expect_err("the task panicked, so this must be Err");
        assert!(join_err.is_panic(), "the JoinError must report a panic");
        match verdict_from_join(Err(join_err)) {
            Verdict::Skipped(reason) => assert!(reason.contains("panicked"), "{reason}"),
            other => panic!("a panic must be Skipped, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_completed_blocking_task_passes_its_verdict_through() {
        let ok = tokio::task::spawn_blocking(|| Verdict::Valid).await;
        assert_eq!(verdict_from_join(ok), Verdict::Valid);
    }

    /// Pins register_kyc's routing directly against `dispatch`: it must
    /// reach the native `kyc::verify`, not the generic sidecar branch. If
    /// this special case were ever dropped, register_kyc would still get a
    /// `Skipped` verdict (the sidecar documents its own permanent skip for
    /// this circuit -- see `signature-verifier/verify.mjs`), so a bare
    /// `Skipped` check would pass for the wrong reason; asserting the reason
    /// names `kyc.rs`'s own missing-field message (`data_padded`), not the
    /// sidecar's `BabyJubJub` skip message, is what actually pins the
    /// routing rather than merely the outcome class.
    #[test]
    fn register_kyc_is_routed_to_the_native_kyc_verifier() {
        let inputs = serde_json::json!({});
        let v = dispatch("register_kyc", &inputs, std::path::Path::new("/does/not/matter"));
        match v {
            Verdict::Skipped(reason) => assert!(
                reason.contains("data_padded"),
                "register_kyc must reach kyc::verify, which skips on its own missing \
                 data_padded field -- got a different reason, suggesting it was routed \
                 elsewhere: {reason}"
            ),
            other => panic!("expected Skipped for an empty KYC input, got {other:?}"),
        }
    }

    /// Proves the sync/async boundary this task's dispatch relies on does
    /// not deadlock: `dispatch` (sync) reaches the generic branch, which
    /// calls `tokio::runtime::Handle::current().block_on(sidecar::verify(...))`
    /// -- legitimate only because `verify_inputs` (not `dispatch` directly)
    /// runs `dispatch` inside `tokio::task::spawn_blocking`, a blocking-pool
    /// thread rather than a normal async worker thread. If that boundary
    /// were ever violated, `block_on` would panic there; a subtler violation
    /// could instead hang. This goes through the real `verify_inputs` entry
    /// point against the production sidecar path, wrapped in an explicit
    /// timeout so "does not hang" is asserted, not just hoped for.
    #[tokio::test]
    async fn sidecar_dispatch_through_verify_inputs_does_not_deadlock() {
        let uuid = uuid::Uuid::new_v4();
        let dir = crate::utils::get_tmp_folder_path(&uuid.to_string());
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(std::path::Path::new(&dir).join("input.json"), b"{}").await.unwrap();

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            verify_inputs(uuid, "register_sha256_sha256_sha256_rsa_65537_4096"),
        )
        .await;
        let _ = tokio::fs::remove_dir_all(&dir).await;

        let v = result.expect(
            "dispatch's generic (sidecar) branch must return, not hang -- a deadlock here \
             would mean block_on ran on a thread spawn_blocking did not actually give it",
        );
        match v {
            Verdict::Skipped(_) | Verdict::Invalid(_) => {}
            Verdict::Valid => panic!("did not expect an empty, non-cryptographic input to verify as Valid"),
        }
    }
}
