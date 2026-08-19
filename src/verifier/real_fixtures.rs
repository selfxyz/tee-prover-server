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

use crate::verifier::{aadhaar, dsc, kyc, params, passport, Verdict};

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
/// than the two that happen to have a hand-written mutation test. Add a row
/// whenever a fixture is added; `all_real_fixtures_are_present` and
/// `every_fixture_stops_verifying_when_its_signature_is_tampered` both key off
/// it, so a fixture that is checked in but not listed is caught by the count
/// assertion rather than silently going uncovered.
///
/// **Formerly a known finding, now fixed: `dsc_sha256_ecdsa_secp521r1` (alg
/// 40).** A real fixture for it was captured via
/// `genAndInitMockPassportData('sha256', 'sha256', 'ecdsa_sha256_secp521r1_521',
/// ...)` (circuit name confirmed as `dsc_sha256_ecdsa_secp521r1` via
/// `doc.getDscCircuitName()`). It used to make `dsc::verify` return
/// `Invalid("ECDSA signature does not verify: signature error")` for a
/// signature that was, by construction of the capture, genuinely valid --
/// RustCrypto's `bits2field` (`ecdsa-0.16.9/src/hazmat.rs:185-205`)
/// hard-errors whenever a prehash is shorter than half the curve's field
/// width, and secp521r1's 66-byte field puts that floor at 33 bytes, one
/// byte over alg 40's 32-byte SHA-256 digest. `primitives::ecdsa::
/// verify_ecdsa` now left-pads the digest to the full field width before
/// calling `verify_prehash` (see `pad_digest_to_field_width`'s doc comment
/// there for why that is equivalent to `bits2field`'s own short-input
/// handling), so this floor can no longer trip for any digest at or above
/// half the field width, closing this false reject. The fixture is now
/// checked in and asserted `Valid` below, alongside its previous substitute
/// `dsc_sha512_ecdsa_secp521r1` (alg 41), which stays for its own
/// non-byte-aligned-limb coverage.
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

/// Corrupting the signature must stop every fixture from verifying.
///
/// Without this, a fixture test asserting `Valid` proves only that the verifier
/// returned `Valid` — not that it looked at the signature at all. A verifier
/// that ignored the signature entirely would pass all fourteen `*_is_valid`
/// tests. Two fixtures had hand-written mutation tests; this covers the rest,
/// and covers every fixture added later for free.
///
/// The assertion is `Invalid`, not merely "not `Valid`": a tampered limb of
/// "1" still parses, so a `Skipped` here would mean the signature failed to
/// *read* rather than failed to *verify*, which is a different and weaker
/// property than the one being claimed.
///
/// `#[tokio::test]` + `spawn_blocking` per row, not a plain `#[test]` calling
/// `dispatch` directly: `Scheme::EcdsaBrainpool`'s dispatch arm reaches the
/// Node/OpenSSL sidecar via `tokio::runtime::Handle::current().block_on(...)`,
/// which panics with no Tokio runtime at all (a plain `#[test]`) and panics
/// again on a normal async worker thread (a bare `#[tokio::test]` calling
/// `dispatch` in its own body) -- `block_on` requires a blocking-pool thread,
/// which only `spawn_blocking` provides. This mirrors exactly how production
/// runs it in `mod::verify_inputs`. Brainpool rows are NOT excluded from this
/// loop to sidestep that panic risk: an excluded row would be a fixture that
/// ships without its tamper guarantee ever being checked, the same
/// unchecked-row gap this whole gate exists to close.
#[tokio::test]
async fn every_fixture_stops_verifying_when_its_signature_is_tampered() {
    for (file, circuit, sig_field) in FIXTURES {
        let Some(mut inputs) = read_fixture(file) else {
            continue;
        };
        let p = params::lookup(circuit).unwrap_or_else(|| panic!("no params row for {circuit}"));

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

        let circuit_owned = circuit.to_string();
        let verdict = tokio::task::spawn_blocking(move || super::dispatch(&circuit_owned, &inputs, &p))
            .await
            .expect("dispatch must not panic");
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

#[test]
fn real_ecdsa_secp224r1_fixture_is_valid() {
    // Captured via genAndInitMockPassportData('sha256', 'sha224',
    // 'ecdsa_sha224_secp224r1_224', 'FRA', '000101', '300101') ->
    // generator.generateRegisterInputs(..., { useTestPadding: true }),
    // mirroring circuits/tests/register/test_cases.ts's sole secp224r1 row
    // (dgHashAlgo sha256, eContentHashAlgo sha224 -- the asymmetric-hash
    // algorithm 44 case). Circuit name confirmed via
    // doc.getRegisterCircuitName() as
    // register_sha256_sha224_sha224_ecdsa_secp224r1.
    let Some(inputs) = read_fixture("register_ecdsa_secp224r1.json") else {
        return;
    };
    let p = params::lookup("register_sha256_sha224_sha224_ecdsa_secp224r1").expect("known circuit");
    assert_eq!(passport::verify(&inputs, &p), Verdict::Valid);
}

#[test]
fn real_ecdsa_secp256r1_fixture_is_valid() {
    // Captured via genAndInitMockPassportData('sha256', 'sha256',
    // 'ecdsa_sha256_secp256r1_256', 'FRA', '000101', '300101'), mirroring
    // test_cases.ts's algorithm 8 row. Circuit name confirmed as
    // register_sha256_sha256_sha256_ecdsa_secp256r1.
    let Some(inputs) = read_fixture("register_ecdsa_secp256r1.json") else {
        return;
    };
    let p = params::lookup("register_sha256_sha256_sha256_ecdsa_secp256r1").expect("known circuit");
    assert_eq!(passport::verify(&inputs, &p), Verdict::Valid);
}

#[test]
fn real_ecdsa_secp384r1_fixture_is_valid() {
    // Captured via genAndInitMockPassportData('sha384', 'sha384',
    // 'ecdsa_sha384_secp384r1_384', 'FRA', '000101', '300101'), mirroring
    // test_cases.ts's algorithm 9 row. Circuit name confirmed as
    // register_sha384_sha384_sha384_ecdsa_secp384r1.
    let Some(inputs) = read_fixture("register_ecdsa_secp384r1.json") else {
        return;
    };
    let p = params::lookup("register_sha384_sha384_sha384_ecdsa_secp384r1").expect("known circuit");
    assert_eq!(passport::verify(&inputs, &p), Verdict::Valid);
}

#[test]
fn real_ecdsa_secp521r1_fixture_is_valid() {
    // Captured via genAndInitMockPassportData('sha512', 'sha512',
    // 'ecdsa_sha512_secp521r1_521', 'FRA', '000101', '300101'), mirroring
    // test_cases.ts's algorithm 41 row. Circuit name confirmed as
    // register_sha512_sha512_sha512_ecdsa_secp521r1.
    let Some(inputs) = read_fixture("register_ecdsa_secp521r1.json") else {
        return;
    };
    let p = params::lookup("register_sha512_sha512_sha512_ecdsa_secp521r1").expect("known circuit");
    assert_eq!(passport::verify(&inputs, &p), Verdict::Valid);
}

#[test]
fn real_ecdsa_secp256r1_sha1_fixture_is_valid() {
    // Fix-wave item 2: alg 7, the narrower-digest row -- SHA-1 (20 bytes)
    // under secp256r1's 32-byte field, exercising RustCrypto's bits2field
    // left-pad path (no other fixture here has hash width < field width).
    // Captured via genAndInitMockPassportData('sha1', 'sha1',
    // 'ecdsa_sha1_secp256r1_256', 'FRA', '000101', '300101'), mirroring
    // test_cases.ts's algorithm 7 row (the sole non-brainpool secp256r1/sha1
    // row). Circuit name confirmed via doc.getRegisterCircuitName() as
    // register_sha1_sha1_sha1_ecdsa_secp256r1.
    let Some(inputs) = read_fixture("register_ecdsa_secp256r1_sha1.json") else {
        return;
    };
    let p = params::lookup("register_sha1_sha1_sha1_ecdsa_secp256r1").expect("known circuit");
    assert_eq!(passport::verify(&inputs, &p), Verdict::Valid);
}

#[test]
fn real_ecdsa_secp384r1_sha256_fixture_is_valid() {
    // Fix-wave item 2: alg 23, the other narrower-digest row -- SHA-256 (32
    // bytes) under secp384r1's 48-byte field. Captured via
    // genAndInitMockPassportData('sha256', 'sha256',
    // 'ecdsa_sha256_secp384r1_384', 'FRA', '000101', '300101'), mirroring
    // test_cases.ts's algorithm 23 row. Circuit name confirmed as
    // register_sha256_sha256_sha256_ecdsa_secp384r1.
    let Some(inputs) = read_fixture("register_ecdsa_secp384r1_sha256.json") else {
        return;
    };
    let p = params::lookup("register_sha256_sha256_sha256_ecdsa_secp384r1").expect("known circuit");
    assert_eq!(passport::verify(&inputs, &p), Verdict::Valid);
}

#[test]
fn real_ecdsa_secp256r1_fixture_with_a_corrupted_signature_limb_is_invalid_for_the_ecdsa_check() {
    // Corrupts only `signature_passport` -- dg1, eContent, and signed_attr
    // are untouched, so links 1 and 2 still pass. The reason must therefore
    // name the ECDSA signature check itself, not a dg1/eContent/signed_attr
    // chain link -- a mutation that failed for the wrong reason would prove
    // nothing (see this module's doc comment on wire-format mismatches).
    let Some(mut inputs) = read_fixture("register_ecdsa_secp256r1.json") else {
        return;
    };
    let arr = inputs["signature_passport"].as_array_mut().unwrap();
    arr[0] = serde_json::Value::String("1".to_string());
    let p = params::lookup("register_sha256_sha256_sha256_ecdsa_secp256r1").expect("known circuit");
    let v = passport::verify(&inputs, &p);
    let Verdict::Invalid(reason) = &v else {
        panic!("corrupting signature_passport must be Invalid, got {v:?}");
    };
    assert!(
        reason.contains("ECDSA") || reason.contains("does not verify"),
        "the reason must name the ECDSA signature check, not a chain link, got: {reason}"
    );
}

#[test]
fn real_dsc_rsa_fixture_is_valid() {
    // Captured via genAndInitMockPassportData('sha256', 'sha256',
    // 'rsa_sha256_65537_2048', 'FRA', '000101', '300101') ->
    // createCircuitInputGenerator().generateDscInputs(doc,
    // serialized_csca_tree), mirroring circuits/tests/dsc/dsc.test.ts's RSA
    // row from test_cases.ts's fullSigAlgs (sigAlg: 'rsa', hashFunction:
    // 'sha256', domainParameter: '65537', keyLength: '2048'). Circuit name
    // confirmed via doc.getDscCircuitName() as dsc_sha256_rsa_65537_4096 --
    // the driver's keyLength '2048' describes the DSC's OWN key, not the CSCA
    // key that signs it -- reassembling this fixture's csca_pubKey from its 35
    // limbs gives a 4096-bit modulus, which is the key this verifier actually
    // checks against. adapter.ts's RSA branch names the circuit ..._4096
    // accordingly, since only the 4096 DSC-RSA circuit
    // exists.
    let Some(inputs) = read_fixture("dsc_sha256_rsa_65537_4096.json") else {
        return;
    };
    let p = params::lookup("dsc_sha256_rsa_65537_4096").expect("known circuit");
    assert_eq!(dsc::verify(&inputs, &p), Verdict::Valid);
}

#[test]
fn real_dsc_pss_3072_fixture_is_valid() {
    // Captured via genAndInitMockPassportData('sha256', 'sha256',
    // 'rsapss_sha256_65537_3072', 'FRA', '000101', '300101'), mirroring
    // fullSigAlgs's { sigAlg: 'rsapss', hashFunction: 'sha256', saltLen:
    // '32', domainParameter: '65537', keyLength: '3072' } row (no explicit
    // salt suffix in the SignatureAlgorithm string: 32 is the sha256/8
    // default, same as the register PSS fixtures' precedent). Circuit name
    // confirmed as dsc_sha256_rsapss_65537_32_3072 -- alg 19, the first
    // 3072-bit PSS fixture captured in this crate (every PSS fixture
    // captured before this task was 2048 or 4096). This and the fixture
    // below are the first coverage at all for dsc::verify's PSS and ECDSA
    // branches; Task 2 unit-tested only the RSA path.
    let Some(inputs) = read_fixture("dsc_sha256_rsapss_65537_32_3072.json") else {
        return;
    };
    let p = params::lookup("dsc_sha256_rsapss_65537_32_3072").expect("known circuit");
    assert_eq!(dsc::verify(&inputs, &p), Verdict::Valid);
}

#[test]
fn real_dsc_ecdsa_secp521r1_alg40_fixture_is_valid() {
    // Captured via genAndInitMockPassportData('sha256', 'sha256',
    // 'ecdsa_sha256_secp521r1_521', 'FRA', '000101', '300101'), mirroring
    // fullSigAlgs's { sigAlg: 'ecdsa', hashFunction: 'sha256',
    // domainParameter: 'secp521r1', keyLength: '521' } row (test_cases.ts
    // line 64). Circuit name confirmed as dsc_sha256_ecdsa_secp521r1 via
    // doc.getDscCircuitName() -- alg 40, the exact false-reject shape this
    // fix closes: a 32-byte SHA-256 digest under secp521r1's 66-byte field,
    // one byte under bits2field's 33-byte floor. Before the
    // pad_digest_to_field_width fix in primitives::ecdsa, dsc::verify
    // returned Invalid against this exact fixture for a genuinely valid
    // signature; see this file's module doc comment above FIXTURES for the
    // history. This test would fail again if that fix were reverted -- it
    // is not asserting anything the tamper test below couldn't also catch
    // for a wrong reason, since a verifier that ignored the signature
    // entirely would also report Valid here, which is exactly what
    // every_fixture_stops_verifying_when_its_signature_is_tampered rules
    // out for every row in FIXTURES, this one included.
    let Some(inputs) = read_fixture("dsc_sha256_ecdsa_secp521r1.json") else {
        return;
    };
    let p = params::lookup("dsc_sha256_ecdsa_secp521r1").expect("known circuit");
    assert_eq!(dsc::verify(&inputs, &p), Verdict::Valid);
}

#[test]
fn real_dsc_ecdsa_secp521r1_fixture_is_valid() {
    // Captured via genAndInitMockPassportData('sha512', 'sha512',
    // 'ecdsa_sha512_secp521r1_521', 'FRA', '000101', '300101'), mirroring
    // fullSigAlgs's { sigAlg: 'ecdsa', hashFunction: 'sha512',
    // domainParameter: 'secp521r1', keyLength: '521' } row. Circuit name
    // confirmed as dsc_sha512_ecdsa_secp521r1 -- alg 41: n=66, so its limbs
    // are still not byte-aligned, the same edge case alg 40 (above) also
    // exercises; kept alongside alg 40 rather than removed, since a SHA-512
    // digest (64 bytes) never touches the bits2field floor at all and this
    // was the first real-fixture coverage of dsc::verify's ECDSA branch
    // before alg 40 could be added.
    let Some(inputs) = read_fixture("dsc_sha512_ecdsa_secp521r1.json") else {
        return;
    };
    let p = params::lookup("dsc_sha512_ecdsa_secp521r1").expect("known circuit");
    assert_eq!(dsc::verify(&inputs, &p), Verdict::Valid);
}

// --- Brainpool (Plan 4, Task 4): real fixtures captured via genAndInit-
// MockPassportData against the sibling monorepo's own generators, exactly
// like every fixture above. `#[tokio::test]` + `spawn_blocking` here (not a
// plain #[test] calling passport::verify/dsc::verify directly): the
// EcdsaBrainpool dispatch arm calls the Node/OpenSSL sidecar via
// `tokio::runtime::Handle::current().block_on(...)`, which needs a
// blocking-pool thread, not a bare async worker thread or no runtime at all
// -- see this module's other tokio::test fixture tests and mod.rs's
// verify_inputs for the identical pattern production uses.

#[tokio::test]
async fn real_ecdsa_brainpoolp224r1_fixture_is_valid() {
    // Captured via genAndInitMockPassportData('sha1', 'sha1',
    // 'ecdsa_sha1_brainpoolP224r1_224', 'FRA', '000101', '300101') ->
    // generator.generateRegisterInputs(..., { useTestPadding: true }),
    // mirroring circuits/tests/register/test_cases.ts's brainpoolP224r1/
    // SHA-1 row (alg 27). Circuit name confirmed via
    // doc.getRegisterCircuitName() as
    // register_sha1_sha1_sha1_ecdsa_brainpoolP224r1. signature_passport/
    // pubKey_dsc both have 14 limbs (= 2*k for k=7), matching params.rs's
    // ECDSA_BRAINPOOL_LIMBS row.
    let Some(inputs) = read_fixture("register_ecdsa_brainpoolP224r1.json") else {
        return;
    };
    let p = params::lookup("register_sha1_sha1_sha1_ecdsa_brainpoolP224r1").expect("known circuit");
    let verdict = tokio::task::spawn_blocking(move || passport::verify(&inputs, &p))
        .await
        .expect("verifier must not panic");
    assert_eq!(verdict, Verdict::Valid);
}

#[tokio::test]
async fn real_ecdsa_brainpoolp256r1_fixture_is_valid() {
    // Captured via genAndInitMockPassportData('sha256', 'sha256',
    // 'ecdsa_sha256_brainpoolP256r1_256', 'FRA', '000101', '300101'),
    // mirroring test_cases.ts's brainpoolP256r1/SHA-256 row (alg 21).
    // Circuit name confirmed as
    // register_sha256_sha256_sha256_ecdsa_brainpoolP256r1.
    let Some(inputs) = read_fixture("register_ecdsa_brainpoolP256r1.json") else {
        return;
    };
    let p = params::lookup("register_sha256_sha256_sha256_ecdsa_brainpoolP256r1")
        .expect("known circuit");
    let verdict = tokio::task::spawn_blocking(move || passport::verify(&inputs, &p))
        .await
        .expect("verifier must not panic");
    assert_eq!(verdict, Verdict::Valid);
}

#[tokio::test]
async fn real_ecdsa_brainpoolp384r1_fixture_is_valid() {
    // Captured via genAndInitMockPassportData('sha384', 'sha384',
    // 'ecdsa_sha384_brainpoolP384r1_384', 'FRA', '000101', '300101'),
    // mirroring test_cases.ts's brainpoolP384r1/SHA-384 row (alg 22).
    // Circuit name confirmed as
    // register_sha384_sha384_sha384_ecdsa_brainpoolP384r1.
    let Some(inputs) = read_fixture("register_ecdsa_brainpoolP384r1.json") else {
        return;
    };
    let p = params::lookup("register_sha384_sha384_sha384_ecdsa_brainpoolP384r1")
        .expect("known circuit");
    let verdict = tokio::task::spawn_blocking(move || passport::verify(&inputs, &p))
        .await
        .expect("verifier must not panic");
    assert_eq!(verdict, Verdict::Valid);
}

#[tokio::test]
async fn real_ecdsa_brainpoolp512r1_fixture_is_valid() {
    // Captured via genAndInitMockPassportData('sha512', 'sha512',
    // 'ecdsa_sha512_brainpoolP512r1_512', 'FRA', '000101', '300101'),
    // mirroring test_cases.ts's brainpoolP512r1/SHA-512 row (alg 29).
    // Circuit name confirmed as
    // register_sha512_sha512_sha512_ecdsa_brainpoolP512r1.
    let Some(inputs) = read_fixture("register_ecdsa_brainpoolP512r1.json") else {
        return;
    };
    let p = params::lookup("register_sha512_sha512_sha512_ecdsa_brainpoolP512r1")
        .expect("known circuit");
    let verdict = tokio::task::spawn_blocking(move || passport::verify(&inputs, &p))
        .await
        .expect("verifier must not panic");
    assert_eq!(verdict, Verdict::Valid);
}

#[tokio::test]
async fn real_dsc_ecdsa_brainpoolp256r1_fixture_is_valid() {
    // Captured via genAndInitMockPassportData('sha256', 'sha256',
    // 'ecdsa_sha256_brainpoolP256r1_256', 'FRA', '000101', '300101') ->
    // createCircuitInputGenerator().generateDscInputs(doc,
    // serialized_csca_tree), mirroring circuits/tests/dsc/test_cases.ts's
    // fullSigAlgs brainpoolP256r1/SHA-256 row (alg 21). Circuit name
    // confirmed via doc.getDscCircuitName() as
    // dsc_sha256_ecdsa_brainpoolP256r1 -- this crate's one required DSC
    // brainpool fixture, per this task's brief.
    let Some(inputs) = read_fixture("dsc_sha256_ecdsa_brainpoolP256r1.json") else {
        return;
    };
    let p = params::lookup("dsc_sha256_ecdsa_brainpoolP256r1").expect("known circuit");
    let verdict = tokio::task::spawn_blocking(move || dsc::verify(&inputs, &p))
        .await
        .expect("verifier must not panic");
    assert_eq!(verdict, Verdict::Valid);
}
