//! Aadhaar signature pre-check, from `register_aadhaar.circom`.
//!
//! One hash, one RSA verify, no chain: `register_aadhaar.circom:46` uses
//! `Sha256Bytes` and `:51` calls `SignatureVerifier(1, n, k)` — signature
//! algorithm 1, which routes to `VerifyRsa65537Pkcs1v1_5`. So `signature`
//! verifies over `sha256(recover_message(qrDataPadded, qrDataPaddedLength))`
//! under `pubKey`, RSA-65537 PKCS#1 v1.5. `delimiterIndices` is
//! field-extraction metadata — it carries no signature material, and is not
//! read here.
//!
//! The governing asymmetry still applies: anything unparseable is `Skipped`.
//! Only a present, well-formed signature that fails to verify is `Invalid`.

use sha2::{Digest, Sha256};

use crate::verifier::chunks::{bigint_from_limbs, bytes_from_decimal_strings, field_as_strings, scalar_usize};
use crate::verifier::params::{CircuitParams, Scheme};
use crate::verifier::primitives::rsa::verify_pkcs1v15;
use crate::verifier::sha_padding::recover_message;
use crate::verifier::Verdict;

/// Hashes `msg` with the SHA variant selected by `bits`. `None` for anything
/// other than 256 — the only width `register_aadhaar` uses today — which
/// becomes `Skipped` upstream rather than a guess at the wrong algorithm.
fn digest(bits: u32, msg: &[u8]) -> Option<Vec<u8>> {
    match bits {
        256 => Some(Sha256::digest(msg).to_vec()),
        _ => None,
    }
}

pub fn verify(inputs: &serde_json::Value, p: &CircuitParams) -> Verdict {
    // The exponent is fixed by the circuit (`SignatureVerifier(1, n, k)` routes
    // to `VerifyRsa65537Pkcs1v1_5`), but it is read from `p.scheme` rather than
    // hardcoded, so a future parameter change cannot silently verify the wrong
    // thing — any scheme other than RSA-65537 skips.
    match &p.scheme {
        Scheme::Rsa { e: 65537, .. } => {}
        _ => {
            return Verdict::Skipped("aadhaar::verify only handles the RSA-65537 PKCS#1v15 scheme".to_string())
        }
    }

    // --- 1. Parse every field. Any parse failure => Skipped. ---
    let Some(qr_items) = field_as_strings(inputs, "qrDataPadded") else {
        return Verdict::Skipped("missing or malformed field: qrDataPadded".to_string());
    };
    let Some(qr_padded) = bytes_from_decimal_strings(&qr_items) else {
        return Verdict::Skipped("qrDataPadded contains a non-byte value".to_string());
    };
    let Some(qr_padded_len) = scalar_usize(inputs, "qrDataPaddedLength") else {
        return Verdict::Skipped("missing or malformed field: qrDataPaddedLength".to_string());
    };

    let Some(pubkey_limbs) = field_as_strings(inputs, "pubKey") else {
        return Verdict::Skipped("missing or malformed field: pubKey".to_string());
    };
    let Some(modulus) = bigint_from_limbs(&pubkey_limbs, p.n) else {
        return Verdict::Skipped("pubKey does not reassemble into a valid integer".to_string());
    };

    let Some(sig_limbs) = field_as_strings(inputs, "signature") else {
        return Verdict::Skipped("missing or malformed field: signature".to_string());
    };
    let Some(signature) = bigint_from_limbs(&sig_limbs, p.n) else {
        return Verdict::Skipped("signature does not reassemble into a valid integer".to_string());
    };

    // --- 2. Recover the message from the SHA-padded QR data. ---
    let Some(qr_msg) = recover_message(&qr_padded, qr_padded_len) else {
        return Verdict::Skipped(
            "qrDataPadded padding is malformed or inconsistent with qrDataPaddedLength".to_string(),
        );
    };

    // --- 3. Hash it, then verify the RSA-65537 PKCS#1 v1.5 signature. ---
    let Some(qr_digest) = digest(p.sig_hash, qr_msg) else {
        return Verdict::Skipped(format!("unknown sig_hash width: {}", p.sig_hash));
    };
    if !verify_pkcs1v15(&signature, &modulus, 65537, &qr_digest, p.sig_hash) {
        return Verdict::Invalid("Aadhaar signature does not verify".to_string());
    }

    Verdict::Valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::testkit::*;

    fn params() -> crate::verifier::params::CircuitParams {
        crate::verifier::params::lookup("register_aadhaar").expect("known circuit")
    }

    fn fixture() -> serde_json::Value {
        let p = params();
        aadhaar_inputs(&TestRsaKey::generate(65537), p.n, p.k as usize)
    }

    #[test]
    fn a_self_consistent_aadhaar_input_is_valid() {
        assert_eq!(verify(&fixture(), &params()), Verdict::Valid);
    }

    #[test]
    fn flipping_a_qr_data_byte_is_invalid() {
        let mut inputs = fixture();
        flip_byte(&mut inputs, "qrDataPadded", 3);
        let v = verify(&inputs, &params());
        assert!(matches!(v, Verdict::Invalid(_)), "got {v:?}");
    }

    #[test]
    fn corrupting_the_signature_is_invalid() {
        let mut inputs = fixture();
        inputs["signature"].as_array_mut().unwrap()[0] = serde_json::Value::String("1".to_string());
        assert!(matches!(verify(&inputs, &params()), Verdict::Invalid(_)));
    }

    #[test]
    fn a_missing_pubkey_field_is_skipped() {
        let mut inputs = fixture();
        inputs.as_object_mut().unwrap().remove("pubKey");
        let v = verify(&inputs, &params());
        assert!(matches!(v, Verdict::Skipped(_)), "a missing field must skip, got {v:?}");
    }

    #[test]
    fn malformed_padding_is_skipped_not_invalid() {
        let mut inputs = fixture();
        inputs["qrDataPaddedLength"] = serde_json::json!(["64"]);
        let v = verify(&inputs, &params());
        assert!(matches!(v, Verdict::Skipped(_)), "malformed padding must skip, got {v:?}");
    }

    /// Pins the actual production wire encoding, not just the testkit's own
    /// self-consistent form. `new-common/src/circuits/inputs/register-
    /// aadhaar.ts` sets `qrDataPaddedLength: processed.qrDataPaddedLen` — a
    /// bare JSON number, never wrapped in a one-element string array the way
    /// the hand-built fixture (and every other scalar field) encodes it. A
    /// verifier that only accepted `Value::String` would skip on every real
    /// Aadhaar request while still passing every other test in this file,
    /// which is exactly the gap that shipped. This test must fail if
    /// `field_as_strings` regresses to string-only.
    #[test]
    fn production_encoding_qr_data_padded_length_as_bare_json_number_is_valid() {
        let mut inputs = fixture();
        let len: u64 = inputs["qrDataPaddedLength"][0]
            .as_str()
            .expect("testkit encodes this as a one-element string array")
            .parse()
            .expect("decimal string");
        inputs["qrDataPaddedLength"] = serde_json::json!(len);
        assert_eq!(verify(&inputs, &params()), Verdict::Valid);
    }
}
