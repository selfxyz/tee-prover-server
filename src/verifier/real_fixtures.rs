//! Tests against real `input.json` fixtures captured from the sibling
//! monorepo's *own* circuit-input generators — not hand-built.
//!
//! The spec's Testing item 1 requires asserting `Valid` against the mock
//! inputs the monorepo already generates, because a hand-built
//! self-consistent fixture (the kind every other test in this crate used to
//! use) can only prove a verifier agrees with itself; it cannot catch a
//! wire-format mismatch between what a real generator emits and what this
//! crate parses — which is exactly how Aadhaar and KYC once shipped skipping
//! 100% of real traffic.
//!
//! Plan A, Task 4: before this task, this file called `passport::verify`/
//! `dsc::verify`/`aadhaar::verify`/`kyc::verify` directly, one family at a
//! time. Those Rust family verifiers are gone now except `kyc::verify` --
//! every other circuit is checked by the JS `signature-verifier` sidecar
//! (`verifier::sidecar`), so per-family unit coverage of that crypto now
//! lives in `signature-verifier/verify.test.mjs` instead. What this file
//! keeps -- and must keep, per this task's own instructions -- is the
//! property the `FIXTURES` table enforces: every checked-in fixture is
//! listed, the listed count matches the on-disk `.json` count (so an
//! unlisted fixture fails the suite instead of silently going unchecked),
//! and tampering each fixture's signature field stops it from verifying.
//! Both checks now drive the real public entry point, `verify_inputs` --
//! writing the fixture to a uuid-named temp dir exactly as production does
//! -- rather than calling a family verifier directly, which is also the only
//! way left to prove the Rust -> sidecar wiring (spawn node, pass an
//! `inputPath`, parse the verdict) against real fixture data end to end, not
//! just against the stub scripts `sidecar.rs`'s own tests use.
//!
//! Fixtures are checked in under `tests/fixtures/`, so they are present in
//! this repo's own CI without the sibling monorepo.

use crate::verifier::Verdict;

/// Reads `tests/fixtures/<name>` relative to the crate root. Panics on an
/// absent, unreadable, or invalid-JSON fixture -- unlike the pre-Task-4
/// version of this function, absence is no longer tolerated: `run_fixture`'s
/// only caller loops over `FIXTURES`, and `all_real_fixtures_are_present`
/// already asserts every one of those files exists, so a genuinely missing
/// file here means that guard itself has a bug, not an expected condition to
/// skip past quietly.
fn read_fixture(name: &str) -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("fixture {} is not valid JSON: {e}", path.display()))
}

/// Writes `inputs` to a fresh uuid-named temp dir as `input.json` -- the same
/// layout `main.rs`'s real request path uses (`utils::get_tmp_folder_path`)
/// -- then runs the real `verify_inputs` entry point against it, cleaning up
/// afterwards. This is the only way to exercise `dispatch`'s generic branch
/// (the sidecar) the same way production does, rather than calling a family
/// verifier's `verify` function directly the way this file did before
/// Task 4.
async fn run_inputs(circuit: &str, inputs: serde_json::Value) -> Verdict {
    // Held for the whole body, per `crate::attestation::TMP_ROOT_LOCK`'s own
    // contract: `get_tmp_folder_path` puts this directory in the crate root
    // alongside every other `tmp_*`, and
    // `bootstrap::tests::cleanup_runs_after_a_failed_bootstrap` snapshots that
    // whole set before and after its call. A `tmp_<uuid>` of ours living for the
    // duration of a `verify_inputs` call looks exactly like a directory bootstrap
    // failed to clean up, so that test went red at random with an extra entry it
    // never created. This file was the one `tmp_*` producer not taking the lock.
    let _tmp_root = crate::attestation::TMP_ROOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let uuid = uuid::Uuid::new_v4();
    let dir = crate::utils::get_tmp_folder_path(&uuid.to_string());
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let serialised = inputs.to_string();
    let written = serialised.len();
    tokio::fs::write(std::path::Path::new(&dir).join("input.json"), &serialised)
        .await
        .unwrap();
    // The real byte count, as production passes it: this stands in for
    // FileGenerator::run's return value.
    let v = crate::verifier::verify_inputs(uuid, circuit, written).await;
    let _ = tokio::fs::remove_dir_all(&dir).await;
    v
}

async fn run_fixture(file: &str, circuit: &str) -> Verdict {
    run_inputs(circuit, read_fixture(file)).await
}

/// Absence is loud, not a per-test skip: deleting or moving a fixture (or
/// adding one without a `FIXTURES` row) fails this test directly, rather
/// than leaving every other test in this module passing while checking
/// nothing -- the same silent no-coverage shape that let Aadhaar and KYC
/// ship skipping all real traffic.
#[test]
fn all_real_fixtures_are_present() {
    // Keyed off FIXTURES so a fixture can never be listed for tampering but
    // missing from the presence check, or vice versa. Also asserts the count,
    // so a fixture checked into tests/fixtures/ without a FIXTURES row is
    // caught here rather than silently going untested.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for (name, _, _) in FIXTURES {
        let path = dir.join(name);
        assert!(path.exists(), "checked-in fixture missing: {}", path.display());
    }
    let on_disk = std::fs::read_dir(&dir)
        .expect("fixtures directory")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .count();
    assert_eq!(
        on_disk,
        FIXTURES.len(),
        "tests/fixtures/ holds {on_disk} .json files but FIXTURES lists {} -- \
         every fixture needs a row so the tamper test covers it",
        FIXTURES.len()
    );
}

/// Every checked-in fixture, paired with the circuit whose params it is
/// verified under, and the JSON field carrying its signature.
///
/// This table exists so the tamper test below covers *every* fixture rather
/// than a hand-picked subset. Add a row whenever a fixture is added;
/// `all_real_fixtures_are_present` and
/// `every_fixture_stops_verifying_when_its_signature_is_tampered` both key
/// off it, so a fixture that is checked in but not listed is caught by the
/// count assertion rather than silently going uncovered.
const FIXTURES: &[(&str, &str, &str)] = &[
    ("register_aadhaar.json", "register_aadhaar", "signature"),
    ("dsc_sha256_ecdsa_secp521r1.json", "dsc_sha256_ecdsa_secp521r1", "signature"),
    ("dsc_sha512_ecdsa_secp521r1.json", "dsc_sha512_ecdsa_secp521r1", "signature"),
    ("dsc_sha256_rsa_65537_4096.json", "dsc_sha256_rsa_65537_4096", "signature"),
    ("dsc_sha256_rsapss_65537_32_3072.json", "dsc_sha256_rsapss_65537_32_3072", "signature"),
    ("dsc_sha256_ecdsa_brainpoolP256r1.json", "dsc_sha256_ecdsa_brainpoolP256r1", "signature"),
    ("register_ecdsa_brainpoolP224r1.json", "register_sha1_sha1_sha1_ecdsa_brainpoolP224r1", "signature_passport"),
    ("register_ecdsa_brainpoolP256r1.json", "register_sha256_sha256_sha256_ecdsa_brainpoolP256r1", "signature_passport"),
    ("register_ecdsa_brainpoolP384r1.json", "register_sha384_sha384_sha384_ecdsa_brainpoolP384r1", "signature_passport"),
    ("register_ecdsa_brainpoolP512r1.json", "register_sha512_sha512_sha512_ecdsa_brainpoolP512r1", "signature_passport"),
    ("register_ecdsa_secp224r1.json", "register_sha256_sha224_sha224_ecdsa_secp224r1", "signature_passport"),
    ("register_ecdsa_secp256r1.json", "register_sha256_sha256_sha256_ecdsa_secp256r1", "signature_passport"),
    ("register_ecdsa_secp256r1_sha1.json", "register_sha1_sha1_sha1_ecdsa_secp256r1", "signature_passport"),
    ("register_ecdsa_secp384r1.json", "register_sha384_sha384_sha384_ecdsa_secp384r1", "signature_passport"),
    ("register_ecdsa_secp384r1_sha256.json", "register_sha256_sha256_sha256_ecdsa_secp384r1", "signature_passport"),
    ("register_ecdsa_secp521r1.json", "register_sha512_sha512_sha512_ecdsa_secp521r1", "signature_passport"),
    ("register_id.json", "register_id_sha1_sha256_sha256_rsa_65537_4096", "signature_passport"),
    ("register_kyc.json", "register_kyc", "s"),
    ("register_passport.json", "register_sha256_sha256_sha256_rsa_3_4096", "signature_passport"),
    ("register_pss.json", "register_sha256_sha256_sha256_rsapss_65537_32_2048", "signature_passport"),
    ("register_pss_sha256_salt64.json", "register_sha256_sha256_sha256_rsapss_65537_64_2048", "signature_passport"),
    ("register_pss_sha384.json", "register_sha384_sha384_sha384_rsapss_65537_48_2048", "signature_passport"),
    ("register_pss_sha512.json", "register_sha512_sha512_sha512_rsapss_65537_64_2048", "signature_passport"),
];

/// Every checked-in fixture must verify `Valid` through the real public
/// entry point, `verify_inputs` -- register_kyc included, since its native
/// `kyc::verify` path really does accept its own real fixture. This is the
/// end-to-end analogue of the 20+ individually-named `real_*_fixture_is_valid`
/// tests this file had before Task 4 (one per family/fixture); consolidated
/// into a loop now that there is a single non-KYC dispatch path (the
/// sidecar) rather than four separate family verifiers to name tests after.
#[tokio::test]
async fn every_real_fixture_verifies_as_valid() {
    for (file, circuit, _sig_field) in FIXTURES {
        let v = run_fixture(file, circuit).await;
        assert_eq!(v, Verdict::Valid, "{file} ({circuit}): expected Valid, got {v:?}");
    }
}

/// Corrupting the signature must stop every fixture from verifying.
///
/// Without this, `every_real_fixture_verifies_as_valid` only proves the
/// pipeline returned `Valid` -- not that it looked at the signature at all.
/// A verifier that ignored the signature entirely would pass that test for
/// every fixture. This covers all 23 rows, register_kyc included (its own
/// `s` field really does fail `kyc::verify`'s EdDSA check when tampered).
///
/// The assertion is `Invalid`, not merely "not `Valid`": a tampered limb of
/// "1" still parses, so a `Skipped` here would mean the signature failed to
/// *read* rather than failed to *verify*, which is a different and weaker
/// property than the one being claimed.
#[tokio::test]
async fn every_fixture_stops_verifying_when_its_signature_is_tampered() {
    for (file, circuit, sig_field) in FIXTURES {
        let mut inputs = read_fixture(file);

        let field = inputs
            .get_mut(*sig_field)
            .unwrap_or_else(|| panic!("{file} has no field {sig_field}"));
        match field {
            serde_json::Value::Array(limbs) => {
                let first = limbs.first_mut().expect("signature has no limbs");
                *first = serde_json::Value::String(tampered(first));
            }
            other => *other = serde_json::Value::String(tampered(other)),
        }

        let verdict = run_inputs(circuit, inputs).await;
        assert!(
            matches!(verdict, Verdict::Invalid(_)),
            "{file}: tampering {sig_field} must yield Invalid, got {verdict:?}"
        );
    }
}

/// A decimal string that differs from `v` whatever `v` currently holds.
fn tampered(v: &serde_json::Value) -> String {
    if v.as_str() == Some("1") {
        "2".to_string()
    } else {
        "1".to_string()
    }
}

/// The disclose circuits reach `verify_inputs` on a `disclose`-feature image
/// (and on a `cherrypick` one) exactly as any other circuit does: `main.rs`
/// calls it unconditionally, with no proof-type branch. They prove
/// identity-tree membership and selective disclosure and carry no document
/// signature, so the sidecar reports `Valid` for them -- a positive statement
/// about four named circuits.
///
/// Driven through the real `verify_inputs` entry point rather than
/// `verify`/`dispatch` directly, because the routing is the part worth
/// pinning: `dispatch` sends every non-`register_kyc` circuit to the sidecar,
/// so this asserts the whole Rust -> node -> verdict path agrees for a
/// disclose name, not just that the JS function returns the right object.
#[tokio::test]
async fn every_disclose_circuit_verifies_as_valid_through_the_real_entry_point() {
    for circuit in DISCLOSE_CIRCUITS {
        // Disclose inputs are not consulted, so the object's contents are
        // irrelevant -- but it must still be a JSON object, since that is
        // what a real circuit-input generator emits and what `verify_inputs`
        // parses before dispatching.
        let verdict = run_inputs(circuit, serde_json::json!({})).await;
        assert!(
            matches!(verdict, Verdict::Valid),
            "{circuit} must verify as Valid through verify_inputs, got {verdict:?}"
        );
    }
}

/// The four circuit names `main.rs` can be handed on a `disclose`-feature
/// image, per `server.rs`'s `ProofRequest::Disclose*` arms.
const DISCLOSE_CIRCUITS: [&str; 4] = [
    "vc_and_disclose",
    "vc_and_disclose_id",
    "vc_and_disclose_aadhaar",
    "vc_and_disclose_kyc",
];

/// A disclose request must reach witness generation under `enforce`.
///
/// `every_disclose_circuit_verifies_as_valid_through_the_real_entry_point`
/// pins the verdict; this pins what the verdict *does*. The two are separate
/// because `precheck_rejection` reaches its decision from the verdict alone
/// -- it takes `circuit_name` but never matches on it -- so a `Valid`
/// disclose verdict forwarding is a consequence of the verdict, and that
/// consequence is what a disclose image's availability actually depends on.
#[tokio::test]
async fn a_disclose_circuit_is_forwarded_under_enforce() {
    for circuit in DISCLOSE_CIRCUITS {
        let verdict = run_inputs(circuit, serde_json::json!({})).await;
        assert_eq!(
            crate::verifier::precheck_rejection(circuit, &verdict, crate::args::PrecheckMode::Enforce),
            None,
            "{circuit} must be forwarded under enforce, not rejected"
        );
    }
}

/// A circuit name that merely resembles a disclose one must still reject
/// under `enforce`.
///
/// The counterpart to `verify.test.mjs`'s near-miss block, asserted here on
/// the Rust side of the wire: the recognition is an exact-match list, so an
/// unrecognised name remains a coverage gap, and a coverage gap rejects. A
/// prefix match in the sidecar would forward these instead.
#[tokio::test]
async fn a_name_resembling_a_disclose_circuit_still_rejects_under_enforce() {
    for circuit in ["vc_and_disclose_typo", "vc_and_disclose_v2", "vc_and_disclosex"] {
        let verdict = run_inputs(circuit, serde_json::json!({})).await;
        assert!(
            matches!(verdict, Verdict::Skipped(_)),
            "{circuit} must not be recognised, got {verdict:?}"
        );
        assert!(
            crate::verifier::precheck_rejection(circuit, &verdict, crate::args::PrecheckMode::Enforce)
                .is_some(),
            "{circuit} must reject under enforce"
        );
    }
}
