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
pub mod dsc;
pub mod kyc;
pub mod params;
pub mod passport;
pub mod metrics;
pub mod primitives;
#[cfg(test)]
mod real_fixtures;
pub mod sha_padding;
#[cfg(test)]
/// Test-only helpers, including a deterministic RSA key.
///
/// Gated behind `cfg(test)` so it stays out of the release binary. Its
/// `TestRsaKey` carries two hardcoded primes -- fine for a test key generated
/// for this purpose, but a hardcoded private key has no business inside a
/// confidential-computing image, and a scanner or auditor finding one there
/// would be right to object.
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

    // dispatch is synchronous, but its Scheme::EcdsaBrainpool arm (passport.rs
    // / dsc.rs) reaches the async Node/OpenSSL sidecar client via
    // `tokio::runtime::Handle::current().block_on(...)`. `block_on` panics if
    // the calling thread is a normal async worker thread, so `dispatch` is
    // run inside `tokio::task::spawn_blocking` here -- a blocking-pool
    // thread, not a worker thread, so `Handle::current()` still resolves and
    // `block_on` does not panic there. See `brainpool_dispatch_through_
    // verify_inputs_does_not_deadlock` below for the proof this does not
    // hang.
    //
    // This also replaces `run_guarded`'s `catch_unwind` for this call site:
    // `spawn_blocking`'s `JoinError` already reports a panic, so a panic
    // inside `dispatch` still surfaces as `Skipped`, not a failed request --
    // the circuit remains the authority, so the worst outcome of a bug in
    // this module is a lost optimisation. `run_guarded` itself is unchanged
    // and still used by its own test below (`a_panicking_verifier_surfaces_
    // as_skipped`), which is this crate's pin on that panic-containment
    // behaviour.
    let circuit_name = circuit_name.to_string();
    verdict_from_join(tokio::task::spawn_blocking(move || dispatch(&circuit_name, &inputs, &p)).await)
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
/// Split out of `verify_inputs` so tests can exercise the real routing against
/// in-memory inputs. `verify_inputs` reads `input.json` from a uuid-named
/// temp directory, so a test that wanted to check routing would otherwise have
/// to either stage files on disk or reimplement this match — and a
/// reimplemented match drifts from the one production uses, which is exactly
/// the kind of divergence these verifiers exist to avoid.
pub(crate) fn dispatch(
    circuit_name: &str,
    inputs: &serde_json::Value,
    p: &params::CircuitParams,
) -> Verdict {
    // Aadhaar and KYC are exact-name circuit families with their own verifiers,
    // but both also start with "register" — the same prefix as the RSA
    // passport / EU-ID circuits handled below. They MUST be matched here,
    // before the prefix match, or their arms would be unreachable, shadowed by
    // the broader "register" prefix (the same class of bug the Task 2
    // reviewer caught in the parameter lookup's register_id_-before-register_
    // ordering).
    if circuit_name == "register_aadhaar" {
        return aadhaar::verify(inputs, p);
    }
    if circuit_name == "register_kyc" {
        return kyc::verify(inputs, p);
    }

    // Only genuine RSA passport / EU-ID circuits reach here: register_* and
    // register_id_* (register_id_* is itself a subset of the "register"
    // prefix, so a single prefix check covers both).
    if circuit_name.starts_with("register") {
        return passport::verify(inputs, p);
    }

    // DSC circuits (a CSCA signing a DSC certificate). The "dsc" and
    // "register" prefixes are disjoint, so this arm's position relative to
    // the one above is not load-bearing -- but this file has already had two
    // prefix-shadowing bugs caught in review (see the Aadhaar/KYC comment
    // above), so it gets its own routing-pin test below rather than resting
    // on "the prefixes happen not to collide today".
    if circuit_name.starts_with("dsc") {
        return dsc::verify(inputs, p);
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
    /// scheme guard would produce a reason mentioning the RSA scheme mismatch.
    ///
    /// Now that the KYC arm is wired (Task 6), the correctly-routed outcome
    /// is no longer the "no verifier wired" placeholder — it is `Skipped` for
    /// KYC's own missing fields, because this fixture (`{}`) has none of
    /// `data_padded`/`s`/`R`/`pubKey`. So the property under test is
    /// unchanged (this payload must not be verified by the passport chain),
    /// only the expected reason moves from a routing placeholder to KYC's own
    /// field-parsing message. If a future edit reorders the dispatch so the
    /// prefix match runs first, this test observes a scheme-mismatch reason
    /// (or `Valid`), not this one, and fails loudly rather than passing for
    /// the wrong reason.
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
                    reason.contains("data_padded"),
                    "register_kyc must be checked by the KYC verifier against its own fields \
                     (this empty fixture has no data_padded field, so the KYC verifier must \
                     skip for that reason), not a passport-chain reason: {reason}"
                );
                assert!(
                    !reason.to_lowercase().contains("scheme"),
                    "reason must not be the passport chain's scheme-mismatch message, which \
                     would mean routing fell through to the passport verifier: {reason}"
                );
            }
            other => panic!(
                "register_kyc must never reach the passport verifier, got {other:?}"
            ),
        }
    }

    /// Pins DSC routing directly against `dispatch`, exercising the real
    /// routing table against in-memory inputs -- exactly what `dispatch`'s
    /// own doc comment says it was split out for. A self-consistent RSA DSC
    /// fixture only verifies `Valid` if it actually reached `dsc::verify`;
    /// passport::verify would reject it outright (no `dg1`/`pubKey_dsc`/
    /// `signature_passport` fields at all).
    #[test]
    fn dsc_prefixed_circuits_are_routed_to_the_dsc_verifier() {
        let p = params::lookup("dsc_sha256_rsa_65537_4096").expect("known circuit");
        let key = testkit::TestRsaKey::generate(65537);
        let inputs = testkit::dsc_inputs(&key, p.n, p.k as usize);

        let v = dispatch("dsc_sha256_rsa_65537_4096", &inputs, &p);
        assert_eq!(v, Verdict::Valid, "a self-consistent dsc_ fixture must reach dsc::verify, got {v:?}");
    }

    /// The other half of the pin: a `register_` name must still reach
    /// `passport::verify`, not be swallowed by a `dsc` arm matched too
    /// broadly (e.g. `contains("dsc")` instead of a `starts_with` prefix, or
    /// an ordering mistake). Reuses the existing passport fixture -- if
    /// dsc::verify ever ran on this instead, it would skip on a missing
    /// `raw_csca` field rather than verify `Valid` the way passport::verify
    /// does here.
    #[test]
    fn register_prefixed_circuits_are_never_routed_to_the_dsc_verifier() {
        let p = params::lookup("register_sha256_sha256_sha256_rsa_65537_4096").expect("known circuit");
        let key = testkit::TestRsaKey::generate(65537);
        let inputs = testkit::passport_inputs(&key, p.n, p.k as usize);

        let v = dispatch("register_sha256_sha256_sha256_rsa_65537_4096", &inputs, &p);
        assert_eq!(v, Verdict::Valid, "register_ names must still reach passport::verify, got {v:?}");
    }

    /// Proves the sync/async boundary from this task does not deadlock:
    /// `dispatch` (sync) reaches `Scheme::EcdsaBrainpool`'s arm in
    /// passport.rs, which calls `tokio::runtime::Handle::current().block_on
    /// (verify_brainpool(...))` -- legitimate only because `verify_inputs`
    /// (not `dispatch` directly) runs `dispatch` inside `tokio::task::
    /// spawn_blocking`, a blocking-pool thread rather than a normal async
    /// worker thread. If that boundary were ever violated (e.g. `dispatch`
    /// called directly from an async fn's own body instead of through
    /// `spawn_blocking`), `block_on` would panic there; a subtler violation
    /// could instead hang. This goes through the real `verify_inputs` entry
    /// point (not `verify_brainpool` directly, and not a stub) against the
    /// production `brainpool::verify_brainpool` path, and wraps it in an
    /// explicit timeout so "does not hang" is asserted, not just hoped for --
    /// a real deadlock here would be invisible to every test in Task 2's
    /// scope, since none of them go through `dispatch`.
    ///
    /// The brainpool sidecar itself is not on this machine's `DEFAULT_
    /// SIDECAR_SCRIPT` path outside the production container (see
    /// `primitives::brainpool`'s own `verify_brainpool_routes_through_the_
    /// documented_default_path` test), so the realistic outcome here is
    /// `Skipped` -- that is fine: the property under test is "returns
    /// promptly", not "the sidecar accepts this arbitrary, non-cryptographic
    /// fixture".
    #[tokio::test]
    async fn brainpool_dispatch_through_verify_inputs_does_not_deadlock() {
        let p = params::lookup("register_sha256_sha256_sha256_ecdsa_brainpoolP256r1")
            .expect("known circuit");
        let inputs = testkit::brainpool_passport_inputs(p.n, p.k as usize);

        let uuid = uuid::Uuid::new_v4();
        let dir = crate::utils::get_tmp_folder_path(&uuid.to_string());
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(std::path::Path::new(&dir).join("input.json"), inputs.to_string())
            .await
            .unwrap();

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            verify_inputs(uuid, "register_sha256_sha256_sha256_ecdsa_brainpoolP256r1"),
        )
        .await;
        let _ = tokio::fs::remove_dir_all(&dir).await;

        let v = result.expect(
            "dispatch's EcdsaBrainpool arm must return, not hang -- a deadlock here would mean \
             block_on ran on a thread spawn_blocking did not actually give it",
        );
        match v {
            Verdict::Skipped(_) | Verdict::Invalid(_) => {}
            Verdict::Valid => {
                panic!("did not expect an arbitrary, non-cryptographic fixture to verify as Valid")
            }
        }
    }
}
