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

/// Absence is a SKIP per-test, so deleting or moving the fixtures would leave
/// every test in this module passing while checking nothing — the same silent
/// no-coverage shape that let Aadhaar and KYC ship skipping all real traffic.
/// This is the one place absence is loud instead.
#[test]
fn all_real_fixtures_are_present() {
    for name in [
        "register_passport.json",
        "register_id.json",
        "register_aadhaar.json",
        "register_kyc.json",
        "register_pss.json",
        "register_pss_sha384.json",
        "register_pss_sha512.json",
        "register_pss_sha256_salt64.json",
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        assert!(path.exists(), "checked-in fixture missing: {}", path.display());
    }
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
fn real_pss_fixture_is_valid() {
    // Captured via genAndInitMockPassportData('sha256', 'sha256',
    // 'rsapss_sha256_65537_2048_32', 'FRA', '000101', '300101') ->
    // generator.generateRegisterInputs(..., { useTestPadding: true }), the
    // same path circuits/tests/register/register.test.ts's RSAPSS rows
    // exercise. Circuit name confirmed via doc.getRegisterCircuitName() as
    // register_sha256_sha256_sha256_rsapss_65537_32_2048.
    let Some(inputs) = read_fixture("register_pss.json") else {
        return;
    };
    let p = params::lookup("register_sha256_sha256_sha256_rsapss_65537_32_2048")
        .expect("known circuit");
    assert_eq!(passport::verify(&inputs, &p), Verdict::Valid);
}

#[test]
fn real_pss_fixture_with_a_corrupted_signature_limb_is_invalid_for_the_pss_check() {
    // Corrupts only `signature_passport` -- dg1, eContent, and signed_attr
    // are untouched, so links 1 and 2 still pass. The reason must therefore
    // name the PSS signature check itself, not a dg1/eContent/signed_attr
    // chain link -- a mutation that failed for the wrong reason would prove
    // nothing (see this module's doc comment on wire-format mismatches).
    let Some(mut inputs) = read_fixture("register_pss.json") else {
        return;
    };
    let arr = inputs["signature_passport"].as_array_mut().unwrap();
    arr[0] = serde_json::Value::String("1".to_string());
    let p = params::lookup("register_sha256_sha256_sha256_rsapss_65537_32_2048")
        .expect("known circuit");
    let v = passport::verify(&inputs, &p);
    let Verdict::Invalid(reason) = &v else {
        panic!("corrupting signature_passport must be Invalid, got {v:?}");
    };
    assert!(
        reason.contains("PSS"),
        "the reason must name the PSS signature check, not a chain link, got: {reason}"
    );
}

#[test]
fn real_pss_sha384_fixture_is_valid() {
    // Captured via genAndInitMockPassportData('sha384', 'sha384',
    // 'rsapss_sha384_65537_2048', 'FRA', '000101', '300101') ->
    // generator.generateRegisterInputs(..., { useTestPadding: true }), the
    // same test_cases.ts row circuits/tests/register/register.test.ts's
    // SHA-384 RSAPSS case exercises (no explicit salt suffix in the
    // SignatureAlgorithm string: the switch in getMockDSC.ts has no
    // '..._2048_48' case, only the bare 'rsapss_sha384_65537_2048' one, and
    // that's what test_cases.ts's sha384 row itself produces since it has no
    // saltLength field). Circuit name confirmed via
    // doc.getRegisterCircuitName() as
    // register_sha384_sha384_sha384_rsapss_65537_48_2048 -- id 45, the sole
    // untested-until-now SHA-384 row.
    let Some(inputs) = read_fixture("register_pss_sha384.json") else {
        return;
    };
    let p = params::lookup("register_sha384_sha384_sha384_rsapss_65537_48_2048")
        .expect("known circuit");
    assert_eq!(passport::verify(&inputs, &p), Verdict::Valid);
}

#[test]
fn real_pss_sha512_fixture_is_valid() {
    // Captured via genAndInitMockPassportData('sha512', 'sha512',
    // 'rsapss_sha512_65537_2048', 'FRA', '000101', '300101') -> the same
    // path, mirroring test_cases.ts's SHA-512 RSAPSS row (also no explicit
    // salt suffix, for the same reason as the SHA-384 fixture above).
    // Circuit name confirmed as
    // register_sha512_sha512_sha512_rsapss_65537_64_2048 -- id 42, the sole
    // untested-until-now SHA-512 row.
    let Some(inputs) = read_fixture("register_pss_sha512.json") else {
        return;
    };
    let p = params::lookup("register_sha512_sha512_sha512_rsapss_65537_64_2048")
        .expect("known circuit");
    assert_eq!(passport::verify(&inputs, &p), Verdict::Valid);
}

#[test]
fn real_pss_sha256_salt64_fixture_is_valid() {
    // Captured via genAndInitMockPassportData('sha256', 'sha256',
    // 'rsapss_sha256_65537_2048_64', 'FRA', '000101', '300101') -- the
    // explicit-salt SignatureAlgorithm string, matching test_cases.ts's
    // "Denmark" SHA-256/salt-64 row and getMockDSC.ts's exact
    // 'rsapss_sha256_65537_2048_64' case. Circuit name confirmed as
    // register_sha256_sha256_sha256_rsapss_65537_64_2048 -- id 46, the
    // single exception to the salt = hash/8 rule and, until this fixture,
    // the one row nothing exercised end to end at all.
    let Some(inputs) = read_fixture("register_pss_sha256_salt64.json") else {
        return;
    };
    let p = params::lookup("register_sha256_sha256_sha256_rsapss_65537_64_2048")
        .expect("known circuit");
    assert_eq!(passport::verify(&inputs, &p), Verdict::Valid);
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
