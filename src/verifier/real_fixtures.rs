//! Tests against real `input.json` fixtures captured from the sibling
//! monorepo's *own* circuit-input generators — not hand-built.
//!
//! The spec's Testing item 1 requires asserting `Valid` against the mock
//! inputs the monorepo already generates, because a hand-built
//! self-consistent fixture (the kind every other test in this crate uses) can
//! only prove the verifier agrees with itself; it cannot catch a wire-format
//! mismatch between what a real generator emits and what this crate parses —
//! which is exactly how Aadhaar and KYC shipped skipping 100% of real
//! traffic (see `chunks::field_as_strings`'s `Value::Number` fix).
//!
//! Each fixture was produced by running the monorepo's own mock-data
//! generators (the same ones its `circuits/tests/register*` test suites use)
//! and capturing the exact JSON string `FileGenerator` would write to
//! `input.json` — i.e. `JSON.stringify(inputs, bigIntReplacer)`, matching
//! `new-common/src/blockchain/proving.ts`'s `getPayload`. No field was
//! hand-edited after capture.
//!
//! Fixtures are checked in under `tests/fixtures/`, so they are present in
//! this repo's own CI without the sibling monorepo. The skip-if-absent
//! fallback below exists only for a checkout where the file was deleted or
//! is otherwise missing, mirroring
//! `params::table_matches_the_monorepo_instance_files`'s pattern of never
//! hard-failing on missing external state.

use crate::verifier::{aadhaar, kyc, params, passport, Verdict};

/// Reads `tests/fixtures/<name>` relative to the crate root. `None` (with a
/// SKIP message) if the file is absent; panics on unreadable-but-present or
/// invalid JSON, since a present-but-corrupt checked-in fixture is a real
/// problem, not an absence.
fn read_fixture(name: &str) -> Option<serde_json::Value> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    if !path.exists() {
        eprintln!("SKIP: real fixture not present at {}", path.display());
        return None;
    }
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()));
    Some(
        serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("fixture {} is not valid JSON: {e}", path.display())),
    )
}

#[test]
fn real_passport_fixture_is_valid() {
    // Captured via genAndInitMockPassportData(sha256, sha256, rsa_3_4096, ...)
    // -> generator.generateRegisterInputs(..., { useTestPadding: true }),
    // circuit name confirmed as register_sha256_sha256_sha256_rsa_3_4096.
    let Some(inputs) = read_fixture("register_passport.json") else {
        return;
    };
    let p = params::lookup("register_sha256_sha256_sha256_rsa_3_4096").expect("known circuit");
    assert_eq!(passport::verify(&inputs, &p), Verdict::Valid);
}

#[test]
fn real_euid_fixture_is_valid() {
    // Captured via genMockIdDocAndInitDataParsing({ idType: mock_id_card,
    // sha1, sha256, rsa_sha256_65537_4096 }) -> the same
    // generateRegisterInputs path, circuit name confirmed as
    // register_id_sha1_sha256_sha256_rsa_65537_4096.
    let Some(inputs) = read_fixture("register_id.json") else {
        return;
    };
    let p =
        params::lookup("register_id_sha1_sha256_sha256_rsa_65537_4096").expect("known circuit");
    assert_eq!(passport::verify(&inputs, &p), Verdict::Valid);
}

#[test]
fn real_aadhaar_fixture_is_valid() {
    // Captured via genMockIdDoc({ idType: mock_aadhaar }) ->
    // generator.generateRegisterInputs(doc, secret, ''), the same path
    // circuits/tests/register/register_aadhaar.test.ts exercises. This is
    // the fixture that pins the exact bug this fix wave closes:
    // qrDataPaddedLength arrives as a bare JSON number here, not a
    // one-element string array.
    let Some(inputs) = read_fixture("register_aadhaar.json") else {
        return;
    };
    assert!(
        inputs["qrDataPaddedLength"].is_number(),
        "fixture capture regressed: expected qrDataPaddedLength to be a bare JSON number, \
         matching new-common/src/circuits/inputs/register-aadhaar.ts's production encoding"
    );
    let p = params::lookup("register_aadhaar").expect("known circuit");
    assert_eq!(aadhaar::verify(&inputs, &p), Verdict::Valid);
}

#[test]
fn real_kyc_fixture_is_valid() {
    // Captured via generateMockKycRegisterInputs(null, true, undefined), the
    // same generator circuits/tests/register/register_kyc.test.ts exercises.
    // This is the fixture that pins the other half of the encoding bug:
    // data_padded arrives as a plain JSON number array, not an array of
    // decimal strings.
    let Some(inputs) = read_fixture("register_kyc.json") else {
        return;
    };
    assert!(
        inputs["data_padded"]
            .as_array()
            .is_some_and(|a| a.iter().all(|v| v.is_number())),
        "fixture capture regressed: expected data_padded to be a plain JSON number array, \
         matching new-common/src/circuits/inputs/register-kyc.ts's production encoding \
         (common/src/utils/kyc/generateInputs.ts's older generator does the same)"
    );
    let p = params::lookup("register_kyc").expect("known circuit");
    assert_eq!(kyc::verify(&inputs, &p), Verdict::Valid);
}
