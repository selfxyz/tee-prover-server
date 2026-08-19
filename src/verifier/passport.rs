//! The passport / EU-ID three-link verification chain, from
//! `passportVerifier.circom:52-93`.
//!
//! A bare signature verify only proves the DSC signed *something* — not that
//! it signed *this passport's data*. Three links, each required, tie the
//! signature back to `dg1`:
//!
//! 1. `sha_dg(dg1)` equals the `dg_hash/8` bytes of `eContent` at
//!    `dg1_hash_offset`.
//! 2. `sha_ec(recover_message(eContent, eContent_padded_length))` equals the
//!    `econtent_hash/8` bytes of `signed_attr` at
//!    `signed_attr_econtent_hash_offset`.
//! 3. `signature_passport` verifies over
//!    `sha_sig(recover_message(signed_attr, signed_attr_padded_length))` under
//!    `pubKey_dsc` -- RSA PKCS#1v15, RSASSA-PSS, or ECDSA over a NIST curve,
//!    depending on the circuit's `Scheme` (see `params.rs`). Only the final
//!    link's signature check differs by scheme; links 1 and 2 are identical
//!    for all three.
//!
//! The governing asymmetry still applies: anything unparseable is `Skipped`.
//! Only an affirmative failure — a present, parseable hash link that doesn't
//! match; a signature that fails; or an offset that violates the circuit's own
//! range checks (`passportVerifier.circom:53-66`) — is `Invalid`.

use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::verifier::chunks::{bigint_from_limbs, bytes_from_decimal_strings, field_as_strings, scalar_usize};
use crate::verifier::params::{CircuitParams, Scheme};
use crate::verifier::primitives::ecdsa::{self, Curve};
use crate::verifier::primitives::rsa::verify_pkcs1v15;
use crate::verifier::primitives::rsapss;
use crate::verifier::sha_padding::recover_message;
use crate::verifier::Verdict;

/// The maximum offset the circuit's range check permits: 12 bits
/// (`passportVerifier.circom:53-66`).
const OFFSET_BITS: u32 = 12;

/// Hashes `msg` with the SHA variant selected by `bits` (160/224/256/384/512).
/// `None` for any other width, which becomes `Skipped` upstream — an unknown
/// hash width is not something this module can be certain about.
fn digest(bits: u32, msg: &[u8]) -> Option<Vec<u8>> {
    Some(match bits {
        160 => Sha1::digest(msg).to_vec(),
        224 => {
            use sha2::Sha224;
            Sha224::digest(msg).to_vec()
        }
        256 => Sha256::digest(msg).to_vec(),
        384 => Sha384::digest(msg).to_vec(),
        512 => Sha512::digest(msg).to_vec(),
        _ => return None,
    })
}

/// Validates an offset against the circuit's own range checks: it must fit in
/// 12 bits, and `offset + hash_len` must not exceed `padded_length`. A
/// violation is `Invalid` (via `Err`), never `Skipped` — the circuit itself
/// certainly rejects an out-of-range offset, so this is an affirmative
/// structural failure, not an uncertainty.
fn check_offset_range(offset: usize, hash_len: usize, padded_length: usize, field: &str) -> Result<(), String> {
    if offset >= (1usize << OFFSET_BITS) {
        return Err(format!("{field} out of range: {offset} does not fit in {OFFSET_BITS} bits"));
    }
    match offset.checked_add(hash_len) {
        Some(end) if end <= padded_length => Ok(()),
        _ => Err(format!(
            "{field} out of range: offset {offset} + hash_len {hash_len} exceeds padded length {padded_length}"
        )),
    }
}

/// Extracts a byte slice `buf[offset..offset+len]`, returning `None` if it
/// does not fit — used only after the range check against the circuit's
/// declared padded length has already passed, but the underlying decimal-byte
/// array can still independently be shorter than declared.
fn slice_at<'a>(buf: &'a [u8], offset: usize, len: usize) -> Option<&'a [u8]> {
    buf.get(offset..offset + len)
}

pub fn verify(inputs: &serde_json::Value, p: &CircuitParams) -> Verdict {
    if !matches!(p.scheme, Scheme::Rsa { .. } | Scheme::RsaPss { .. } | Scheme::Ecdsa { .. }) {
        return Verdict::Skipped(format!(
            "passport::verify only handles the RSA PKCS#1v15, RSASSA-PSS, and ECDSA schemes, got {:?}",
            p.scheme
        ));
    }

    // --- 1. Parse every field. Any parse failure => Skipped. ---
    let Some(dg1_items) = field_as_strings(inputs, "dg1") else {
        return Verdict::Skipped("missing or malformed field: dg1".to_string());
    };
    let Some(dg1) = bytes_from_decimal_strings(&dg1_items) else {
        return Verdict::Skipped("dg1 contains a non-byte value".to_string());
    };
    let Some(dg1_hash_offset) = scalar_usize(inputs, "dg1_hash_offset") else {
        return Verdict::Skipped("missing or malformed field: dg1_hash_offset".to_string());
    };

    let Some(econtent_items) = field_as_strings(inputs, "eContent") else {
        return Verdict::Skipped("missing or malformed field: eContent".to_string());
    };
    let Some(econtent) = bytes_from_decimal_strings(&econtent_items) else {
        return Verdict::Skipped("eContent contains a non-byte value".to_string());
    };
    let Some(econtent_padded_length) = scalar_usize(inputs, "eContent_padded_length") else {
        return Verdict::Skipped("missing or malformed field: eContent_padded_length".to_string());
    };

    let Some(signed_attr_items) = field_as_strings(inputs, "signed_attr") else {
        return Verdict::Skipped("missing or malformed field: signed_attr".to_string());
    };
    let Some(signed_attr) = bytes_from_decimal_strings(&signed_attr_items) else {
        return Verdict::Skipped("signed_attr contains a non-byte value".to_string());
    };
    let Some(signed_attr_padded_length) = scalar_usize(inputs, "signed_attr_padded_length") else {
        return Verdict::Skipped("missing or malformed field: signed_attr_padded_length".to_string());
    };
    let Some(sa_econtent_hash_offset) = scalar_usize(inputs, "signed_attr_econtent_hash_offset") else {
        return Verdict::Skipped("missing or malformed field: signed_attr_econtent_hash_offset".to_string());
    };

    let Some(pubkey_limbs) = field_as_strings(inputs, "pubKey_dsc") else {
        return Verdict::Skipped("missing or malformed field: pubKey_dsc".to_string());
    };
    let Some(sig_limbs) = field_as_strings(inputs, "signature_passport") else {
        return Verdict::Skipped("missing or malformed field: signature_passport".to_string());
    };
    // RSA and RSASSA-PSS carry a single `k`-limb big integer in each of
    // `pubKey_dsc` (the modulus) and `signature_passport`. ECDSA instead
    // carries `2k` limbs in each -- two coordinates / two scalars -- per
    // `ecdsaVerifier.circom`'s `getKLengthFactor(alg) == 2`; that split
    // happens below, per-scheme, rather than here.

    // --- 2. Range checks the circuit itself enforces. Violation => Invalid. ---
    let dg_hash_len = (p.dg_hash / 8) as usize;
    if let Err(reason) = check_offset_range(dg1_hash_offset, dg_hash_len, econtent_padded_length, "dg1_hash_offset") {
        return Verdict::Invalid(reason);
    }
    let econtent_hash_len = (p.econtent_hash / 8) as usize;
    if let Err(reason) = check_offset_range(
        sa_econtent_hash_offset,
        econtent_hash_len,
        signed_attr_padded_length,
        "signed_attr_econtent_hash_offset",
    ) {
        return Verdict::Invalid(reason);
    }

    // --- 3. Link 1: sha_dg(dg1) == eContent[dg1_hash_offset..+dg_hash/8] ---
    let Some(dg1_digest) = digest(p.dg_hash, &dg1) else {
        return Verdict::Skipped(format!("unknown dg_hash width: {}", p.dg_hash));
    };
    let Some(econtent_window) = slice_at(&econtent, dg1_hash_offset, dg_hash_len) else {
        return Verdict::Skipped("eContent is shorter than dg1_hash_offset + dg_hash/8 declares".to_string());
    };
    if dg1_digest != econtent_window {
        return Verdict::Invalid("dg1 hash does not match eContent at dg1_hash_offset".to_string());
    }

    // --- 4. Link 2: sha_ec(recover_message(eContent, len)) == signed_attr window ---
    let Some(econtent_msg) = recover_message(&econtent, econtent_padded_length) else {
        return Verdict::Skipped("eContent padding is malformed or inconsistent with eContent_padded_length".to_string());
    };
    let Some(econtent_digest) = digest(p.econtent_hash, econtent_msg) else {
        return Verdict::Skipped(format!("unknown econtent_hash width: {}", p.econtent_hash));
    };
    let Some(signed_attr_window) = slice_at(&signed_attr, sa_econtent_hash_offset, econtent_hash_len) else {
        return Verdict::Skipped(
            "signed_attr is shorter than signed_attr_econtent_hash_offset + econtent_hash/8 declares".to_string(),
        );
    };
    if econtent_digest != signed_attr_window {
        return Verdict::Invalid("eContent hash does not match signed_attr at signed_attr_econtent_hash_offset".to_string());
    }

    // --- 5. Link 3: verify_pkcs1v15 over sha_sig(recover_message(signed_attr, len)) ---
    let Some(signed_attr_msg) = recover_message(&signed_attr, signed_attr_padded_length) else {
        return Verdict::Skipped(
            "signed_attr padding is malformed or inconsistent with signed_attr_padded_length".to_string(),
        );
    };
    let Some(sig_digest) = digest(p.sig_hash, signed_attr_msg) else {
        return Verdict::Skipped(format!("unknown sig_hash width: {}", p.sig_hash));
    };
    match &p.scheme {
        Scheme::Rsa { e, .. } => {
            let Some(modulus) = bigint_from_limbs(&pubkey_limbs, p.n) else {
                return Verdict::Skipped("pubKey_dsc does not reassemble into a valid integer".to_string());
            };
            let Some(signature) = bigint_from_limbs(&sig_limbs, p.n) else {
                return Verdict::Skipped("signature_passport does not reassemble into a valid integer".to_string());
            };
            if !verify_pkcs1v15(&signature, &modulus, *e, &sig_digest, p.sig_hash) {
                return Verdict::Invalid("signature does not verify under pubKey_dsc".to_string());
            }
        }
        Scheme::RsaPss { e, salt_len, bits } => {
            let Some(modulus) = bigint_from_limbs(&pubkey_limbs, p.n) else {
                return Verdict::Skipped("pubKey_dsc does not reassemble into a valid integer".to_string());
            };
            let Some(signature) = bigint_from_limbs(&sig_limbs, p.n) else {
                return Verdict::Skipped("signature_passport does not reassemble into a valid integer".to_string());
            };
            let hash = match p.sig_hash {
                160 => rsapss::PssHash::Sha1,
                256 => rsapss::PssHash::Sha256,
                384 => rsapss::PssHash::Sha384,
                512 => rsapss::PssHash::Sha512,
                other => return Verdict::Skipped(format!("unsupported PSS hash width {other}")),
            };
            if let Err(reason) = rsapss::verify_pss(&signature, &modulus, *e, &sig_digest, hash, *salt_len, *bits) {
                return Verdict::Invalid(format!("PSS signature does not verify: {reason}"));
            }
        }
        Scheme::Ecdsa { curve } => {
            let Some(curve) = Curve::from_name(curve) else {
                return Verdict::Skipped(format!("unknown ECDSA curve name: {curve}"));
            };
            // `pubKey_dsc` = x || y (each `k` limbs); `signature_passport` =
            // r || s (each `k` limbs) -- `ecdsaVerifier.circom:50-55`'s
            // `getKLengthFactor(alg) == 2` split, little-endian base-`2^n`
            // per half, exactly as `bigint_from_limbs` already reassembles.
            let k = p.k as usize;
            if pubkey_limbs.len() != 2 * k {
                return Verdict::Skipped(format!(
                    "pubKey_dsc has {} limbs, expected 2*k={}",
                    pubkey_limbs.len(),
                    2 * k
                ));
            }
            if sig_limbs.len() != 2 * k {
                return Verdict::Skipped(format!(
                    "signature_passport has {} limbs, expected 2*k={}",
                    sig_limbs.len(),
                    2 * k
                ));
            }
            let Some(x) = bigint_from_limbs(&pubkey_limbs[0..k], p.n) else {
                return Verdict::Skipped("pubKey_dsc's x half does not reassemble into a valid integer".to_string());
            };
            let Some(y) = bigint_from_limbs(&pubkey_limbs[k..2 * k], p.n) else {
                return Verdict::Skipped("pubKey_dsc's y half does not reassemble into a valid integer".to_string());
            };
            let Some(r) = bigint_from_limbs(&sig_limbs[0..k], p.n) else {
                return Verdict::Skipped("signature_passport's r half does not reassemble into a valid integer".to_string());
            };
            let Some(s) = bigint_from_limbs(&sig_limbs[k..2 * k], p.n) else {
                return Verdict::Skipped("signature_passport's s half does not reassemble into a valid integer".to_string());
            };
            if let Err(reason) = ecdsa::verify_ecdsa(curve, &x, &y, &r, &s, &sig_digest) {
                // `reason` is already self-describing -- verify_ecdsa prefixes
                // its own failures ("ECDSA signature does not verify: ...",
                // "public key is not on the curve: ...", "signature scalar out
                // of range: ..."). Wrapping it again produced a doubled prefix.
                return Verdict::Invalid(reason);
            }
        }
        // Guarded out at the top of this function -- unreachable here.
        _ => {
            return Verdict::Skipped(
                "passport::verify only handles the RSA PKCS#1v15, RSASSA-PSS, and ECDSA schemes".to_string(),
            )
        }
    }

    Verdict::Valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::testkit::*;

    fn params() -> crate::verifier::params::CircuitParams {
        crate::verifier::params::lookup("register_sha256_sha256_sha256_rsa_65537_4096")
            .expect("known circuit")
    }

    fn fixture() -> serde_json::Value {
        let p = params();
        let key = TestRsaKey::generate(65537);
        passport_inputs(&key, p.n, p.k as usize)
    }

    fn reason(v: &Verdict) -> String {
        match v {
            Verdict::Invalid(r) | Verdict::Skipped(r) => r.clone(),
            Verdict::Valid => String::new(),
        }
    }

    #[test]
    fn a_self_consistent_passport_input_is_valid() {
        assert_eq!(verify(&fixture(), &params()), Verdict::Valid);
    }

    #[test]
    fn flipping_a_dg1_byte_is_invalid_for_the_dg1_link() {
        // THE test that distinguishes this design from a bare signature check.
        let mut inputs = fixture();
        flip_byte(&mut inputs, "dg1", 5);
        let v = verify(&inputs, &params());
        assert!(matches!(v, Verdict::Invalid(_)), "got {v:?}");
        let r = reason(&v);
        assert!(r.contains("dg1"), "the reason must name the dg1 link, got: {r}");
    }

    #[test]
    fn flipping_an_econtent_byte_is_invalid_for_the_econtent_link() {
        let mut inputs = fixture();
        // Index 0 is outside the dg1-hash window, so only link 2 breaks.
        flip_byte(&mut inputs, "eContent", 0);
        let v = verify(&inputs, &params());
        assert!(matches!(v, Verdict::Invalid(_)), "got {v:?}");
        let r = reason(&v);
        assert!(r.contains("eContent"), "the reason must name the eContent link, got: {r}");
    }

    #[test]
    fn corrupting_the_signature_is_invalid_for_the_signature_check() {
        let mut inputs = fixture();
        let arr = inputs["signature_passport"].as_array_mut().unwrap();
        arr[0] = serde_json::Value::String("1".to_string());
        let v = verify(&inputs, &params());
        assert!(matches!(v, Verdict::Invalid(_)), "got {v:?}");
        let r = reason(&v);
        assert!(r.contains("signature"), "the reason must name the signature check, got: {r}");
    }

    #[test]
    fn an_offset_past_the_padded_length_is_invalid() {
        let mut inputs = fixture();
        inputs["dg1_hash_offset"] = serde_json::json!(["100000"]);
        assert!(matches!(verify(&inputs, &params()), Verdict::Invalid(_)));
    }

    #[test]
    fn an_offset_that_fits_in_12_bits_but_still_exceeds_the_padded_length_is_invalid() {
        // Distinct branch from the test above: offset=100000 there trips
        // check_offset_range's 12-bit range check and never reaches the
        // `offset + hash_len > padded_length` (LessEqThan) check -- the one
        // the design's prose emphasises and the branch most likely to be
        // mistakenly "tightened" later, since 100000 alone never exercises
        // it. offset=500 fits comfortably under 4096 (12 bits), but
        // 500 + 32 (sha256's hash_len) exceeds a claimed 512-byte padded
        // length.
        let mut inputs = fixture();
        inputs["dg1_hash_offset"] = serde_json::json!(["500"]);
        inputs["eContent_padded_length"] = serde_json::json!(["512"]);
        let v = verify(&inputs, &params());
        assert!(matches!(v, Verdict::Invalid(_)), "got {v:?}");
    }

    #[test]
    fn a_missing_field_is_skipped_not_invalid() {
        let mut inputs = fixture();
        inputs.as_object_mut().unwrap().remove("pubKey_dsc");
        let v = verify(&inputs, &params());
        assert!(matches!(v, Verdict::Skipped(_)), "a missing field must skip, got {v:?}");
    }

    #[test]
    fn malformed_econtent_padding_is_skipped_not_invalid() {
        let mut inputs = fixture();
        // Claim a padded length that the buffer's own length field contradicts.
        inputs["eContent_padded_length"] = serde_json::json!(["64"]);
        let v = verify(&inputs, &params());
        assert!(matches!(v, Verdict::Skipped(_)), "malformed padding must skip, got {v:?}");
    }
}
