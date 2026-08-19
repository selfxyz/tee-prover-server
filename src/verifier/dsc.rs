//! The DSC verification chain -- a CSCA certificate signing a DSC
//! certificate -- from `dsc.circom`.
//!
//! A bare signature verify only proves the supplied key signed *something* --
//! not that the key is actually the CSCA's own key. One link, the analogue of
//! passport.rs's dg1 link, ties the signature back to the certificate:
//!
//! 1. `csca_pubKey`, reassembled from limbs, must equal the bytes in
//!    `raw_csca` at `csca_pubKey_offset`, for `csca_pubKey_actual_size` bytes
//!    (`dsc.circom:171-192`, via `CheckPubkeyPosition`+`CheckPubkeysEqual`).
//!    For RSA and RSASSA-PSS that window is the modulus; for ECDSA
//!    (`kLengthFactor == 2`) it is `x‖y`, each half of
//!    `csca_pubKey_actual_size`. **Without this link the whole check is
//!    worthless** -- a caller could supply any key that matches any
//!    signature, and the native pre-check would wave through a document
//!    whose CSCA key was simply invented.
//! 2. `signature` verifies over `sig_hash(recover_message(raw_dsc,
//!    raw_dsc_padded_length))` under `csca_pubKey` -- RSA PKCS#1v15,
//!    RSASSA-PSS, or ECDSA over a NIST curve, depending on the circuit's
//!    `Scheme` (see `params.rs`). `recover_message` implements exactly the
//!    padding shape `dsc.circom:88-108` asserts: the `0x80` marker and the
//!    trailing-zero check.
//!
//! Link 1 is checked, and can return `Invalid`, strictly before any code
//! touches signature verification -- so a corrupted `csca_pubKey` is always
//! reported as a certificate-key mismatch, never mistaken for (or masked by)
//! a signature failure.
//!
//! **Deliberately out of scope** (the circuit remains the sole authority on
//! these -- this is a decision, not an omission):
//! - The CSCA Merkle inclusion proof and the two Poseidon leaf computations
//!   (`dsc.circom:130-134, 200-203`). These are tree-membership and
//!   commitment properties, not signature properties.
//! - The ASN.1 prefix / RSA-exponent-suffix validation inside
//!   `CheckPubkeyPosition` (`dsc.circom:172-180`). A missing or malformed
//!   prefix is exactly the kind of thing the real circuit would also reject,
//!   so skipping it here only risks a false *accept*, never a false reject --
//!   and a false accept costs nothing, since the Groth16 circuit still
//!   verifies afterward.
//!
//! `dg_hash` and `econtent_hash` on `CircuitParams` are meaningless
//! placeholders for every DSC circuit -- see `params::lookup_dsc`'s doc
//! comment, which explains why a plausible-looking placeholder is safer than
//! an invented distinct value. This module must never read either field.
//!
//! The governing asymmetry still applies: anything uncertain is `Skipped`.
//! Only the two affirmative failures above -- a certificate-key mismatch, or
//! a signature that fails to verify -- are `Invalid`. Per this task's spec, an
//! out-of-range offset is *also* `Skipped` here, not `Invalid` (see
//! `offset_in_range`'s doc comment) -- a deliberate difference from
//! passport.rs's `dg1_hash_offset` handling, not an oversight.

use num_bigint::BigUint;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::verifier::chunks::{bigint_from_limbs, bytes_from_decimal_strings, field_as_strings, scalar_usize};
use crate::verifier::params::{CircuitParams, Scheme};
use crate::verifier::primitives::brainpool::{self, BrainpoolCurve};
use crate::verifier::primitives::ecdsa::{self, Curve};
use crate::verifier::primitives::rsa::verify_pkcs1v15;
use crate::verifier::primitives::rsapss;
use crate::verifier::sha_padding::recover_message;
use crate::verifier::Verdict;

/// The maximum offset the circuit's range checks permit: 12 bits
/// (`dsc.circom:110-127`).
const OFFSET_BITS: u32 = 12;

/// Hashes `msg` with the SHA variant selected by `bits` (160/224/256/384/512).
/// `None` for any other width, which becomes `Skipped` upstream -- an unknown
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

/// Checks `offset`/`size` each fit in 12 bits and `offset + size <= bound`
/// (`dsc.circom:110-127`, `bound` being `raw_csca_actual_length`).
///
/// Unlike passport.rs's `check_offset_range` (whose violation is `Invalid`),
/// a violation here is `Skipped`, per this task's spec. The difference is not
/// cosmetic: passport.rs's offset bounds (`eContent_padded_length`,
/// `signed_attr_padded_length`) are lengths this same module independently
/// corroborates by calling `recover_message` against the very buffers they
/// bound. `raw_csca_actual_length` has no such corroboration anywhere in this
/// function -- `raw_csca` is never SHA-padded input, so nothing here vouches
/// for it independently. An out-of-range offset therefore sits with the
/// "uncertain" class (missing fields, unparseable values, unsupported
/// schemes, malformed SHA padding), not with the two checks this module can
/// affirmatively stand behind: the certificate-key link and the signature.
fn offset_in_range(offset: usize, size: usize, bound: usize) -> bool {
    let limit = 1usize << OFFSET_BITS;
    if offset >= limit || size >= limit {
        return false;
    }
    match offset.checked_add(size) {
        Some(end) => end < limit && end <= bound,
        None => false,
    }
}

/// Extracts a byte slice `buf[offset..offset+len]`, returning `None` if it
/// does not fit -- used only after the range check against the declared
/// bound has already passed, but the underlying decimal-byte array can still
/// independently be shorter than declared.
fn slice_at<'a>(buf: &'a [u8], offset: usize, len: usize) -> Option<&'a [u8]> {
    buf.get(offset..offset + len)
}

/// Renders `v` as exactly `size` big-endian bytes, left-padding with zeros.
/// `None` if `v`'s natural (minimal) encoding needs more than `size` bytes --
/// it then cannot equal a `size`-byte window of `raw_csca` regardless of
/// padding, so there is nothing left to compare.
fn to_fixed_bytes(v: &BigUint, size: usize) -> Option<Vec<u8>> {
    let raw = v.to_bytes_be();
    if raw.len() > size {
        return None;
    }
    let mut out = vec![0u8; size - raw.len()];
    out.extend_from_slice(&raw);
    Some(out)
}

pub fn verify(inputs: &serde_json::Value, p: &CircuitParams) -> Verdict {
    if !matches!(
        p.scheme,
        Scheme::Rsa { .. } | Scheme::RsaPss { .. } | Scheme::Ecdsa { .. } | Scheme::EcdsaBrainpool { .. }
    ) {
        return Verdict::Skipped(format!(
            "dsc::verify only handles the RSA PKCS#1v15, RSASSA-PSS, ECDSA, and brainpool-ECDSA \
             schemes, got {:?}",
            p.scheme
        ));
    }

    // --- 1. Parse every field. Any parse failure => Skipped. ---
    let Some(raw_csca_items) = field_as_strings(inputs, "raw_csca") else {
        return Verdict::Skipped("missing or malformed field: raw_csca".to_string());
    };
    let Some(raw_csca) = bytes_from_decimal_strings(&raw_csca_items) else {
        return Verdict::Skipped("raw_csca contains a non-byte value".to_string());
    };
    let Some(raw_csca_actual_length) = scalar_usize(inputs, "raw_csca_actual_length") else {
        return Verdict::Skipped("missing or malformed field: raw_csca_actual_length".to_string());
    };
    let Some(csca_pubkey_offset) = scalar_usize(inputs, "csca_pubKey_offset") else {
        return Verdict::Skipped("missing or malformed field: csca_pubKey_offset".to_string());
    };
    let Some(csca_pubkey_actual_size) = scalar_usize(inputs, "csca_pubKey_actual_size") else {
        return Verdict::Skipped("missing or malformed field: csca_pubKey_actual_size".to_string());
    };

    let Some(raw_dsc_items) = field_as_strings(inputs, "raw_dsc") else {
        return Verdict::Skipped("missing or malformed field: raw_dsc".to_string());
    };
    let Some(raw_dsc) = bytes_from_decimal_strings(&raw_dsc_items) else {
        return Verdict::Skipped("raw_dsc contains a non-byte value".to_string());
    };
    let Some(raw_dsc_padded_length) = scalar_usize(inputs, "raw_dsc_padded_length") else {
        return Verdict::Skipped("missing or malformed field: raw_dsc_padded_length".to_string());
    };

    let Some(pubkey_limbs) = field_as_strings(inputs, "csca_pubKey") else {
        return Verdict::Skipped("missing or malformed field: csca_pubKey".to_string());
    };
    let Some(sig_limbs) = field_as_strings(inputs, "signature") else {
        return Verdict::Skipped("missing or malformed field: signature".to_string());
    };
    // RSA and RSASSA-PSS carry a single `k`-limb big integer in each of
    // `csca_pubKey` (the modulus) and `signature`. ECDSA instead carries `2k`
    // limbs in each -- x||y and r||s -- per `getKLengthFactor(alg) == 2`;
    // that split happens below, per-scheme.

    // --- 2. Offset range check (dsc.circom:110-127). Violation => Skipped. ---
    if !offset_in_range(csca_pubkey_offset, csca_pubkey_actual_size, raw_csca_actual_length) {
        return Verdict::Skipped(format!(
            "csca_pubKey_offset ({csca_pubkey_offset}) + csca_pubKey_actual_size \
             ({csca_pubkey_actual_size}) is out of range for raw_csca_actual_length \
             ({raw_csca_actual_length})"
        ));
    }

    // --- 3. Link 1: csca_pubKey (reassembled) == raw_csca[offset..+size] ---
    // (dsc.circom:171-192) -- THE link that makes this check meaningful.
    // Checked, and can return Invalid, before any signature-related parsing
    // below, so a corrupted csca_pubKey can never be reported as (or masked
    // by) a signature failure.
    let Some(csca_window) = slice_at(&raw_csca, csca_pubkey_offset, csca_pubkey_actual_size) else {
        return Verdict::Skipped(
            "raw_csca is shorter than csca_pubKey_offset + csca_pubKey_actual_size declares".to_string(),
        );
    };

    match &p.scheme {
        Scheme::Rsa { .. } | Scheme::RsaPss { .. } => {
            let Some(modulus) = bigint_from_limbs(&pubkey_limbs, p.n) else {
                return Verdict::Skipped("csca_pubKey does not reassemble into a valid integer".to_string());
            };
            let Some(modulus_bytes) = to_fixed_bytes(&modulus, csca_pubkey_actual_size) else {
                return Verdict::Invalid(
                    "csca_pubKey does not match the certificate: it is wider than csca_pubKey_actual_size"
                        .to_string(),
                );
            };
            if modulus_bytes.as_slice() != csca_window {
                return Verdict::Invalid(
                    "csca_pubKey does not match the bytes in raw_csca at csca_pubKey_offset".to_string(),
                );
            }
        }
        // Same x||y limb-layout check for both curve families -- this step is
        // about limb geometry (getKLengthFactor(alg) == 2), not curve math,
        // so Ecdsa and EcdsaBrainpool share it. The curve-specific signature
        // math happens below, in the link-2 match.
        Scheme::Ecdsa { .. } | Scheme::EcdsaBrainpool { .. } => {
            if csca_pubkey_actual_size % 2 != 0 {
                return Verdict::Skipped(
                    "csca_pubKey_actual_size is odd; an ECDSA x||y split must be even".to_string(),
                );
            }
            let half = csca_pubkey_actual_size / 2;
            let k = p.k as usize;
            if pubkey_limbs.len() != 2 * k {
                return Verdict::Skipped(format!(
                    "csca_pubKey has {} limbs, expected 2*k={}",
                    pubkey_limbs.len(),
                    2 * k
                ));
            }
            let Some(x) = bigint_from_limbs(&pubkey_limbs[0..k], p.n) else {
                return Verdict::Skipped("csca_pubKey's x half does not reassemble into a valid integer".to_string());
            };
            let Some(y) = bigint_from_limbs(&pubkey_limbs[k..2 * k], p.n) else {
                return Verdict::Skipped("csca_pubKey's y half does not reassemble into a valid integer".to_string());
            };
            let Some(x_bytes) = to_fixed_bytes(&x, half) else {
                return Verdict::Invalid(
                    "csca_pubKey does not match the certificate: its x coordinate is wider than half of \
                     csca_pubKey_actual_size"
                        .to_string(),
                );
            };
            let Some(y_bytes) = to_fixed_bytes(&y, half) else {
                return Verdict::Invalid(
                    "csca_pubKey does not match the certificate: its y coordinate is wider than half of \
                     csca_pubKey_actual_size"
                        .to_string(),
                );
            };
            if x_bytes.as_slice() != &csca_window[..half] || y_bytes.as_slice() != &csca_window[half..] {
                return Verdict::Invalid(
                    "csca_pubKey does not match the bytes in raw_csca at csca_pubKey_offset".to_string(),
                );
            }
        }
        // Guarded out at the top of this function -- unreachable here.
        _ => {
            return Verdict::Skipped(
                "dsc::verify only handles the RSA PKCS#1v15, RSASSA-PSS, ECDSA, and brainpool-ECDSA schemes"
                    .to_string(),
            )
        }
    }

    // --- 4. Link 2: signature verifies over sig_hash(recover_message(raw_dsc, len)) ---
    let Some(raw_dsc_msg) = recover_message(&raw_dsc, raw_dsc_padded_length) else {
        return Verdict::Skipped("raw_dsc padding is malformed or inconsistent with raw_dsc_padded_length".to_string());
    };
    let Some(sig_digest) = digest(p.sig_hash, raw_dsc_msg) else {
        return Verdict::Skipped(format!("unknown sig_hash width: {}", p.sig_hash));
    };

    match &p.scheme {
        Scheme::Rsa { e, .. } => {
            let Some(modulus) = bigint_from_limbs(&pubkey_limbs, p.n) else {
                return Verdict::Skipped("csca_pubKey does not reassemble into a valid integer".to_string());
            };
            let Some(signature) = bigint_from_limbs(&sig_limbs, p.n) else {
                return Verdict::Skipped("signature does not reassemble into a valid integer".to_string());
            };
            if !verify_pkcs1v15(&signature, &modulus, *e, &sig_digest, p.sig_hash) {
                return Verdict::Invalid("signature does not verify under csca_pubKey".to_string());
            }
        }
        Scheme::RsaPss { e, salt_len, bits } => {
            let Some(modulus) = bigint_from_limbs(&pubkey_limbs, p.n) else {
                return Verdict::Skipped("csca_pubKey does not reassemble into a valid integer".to_string());
            };
            let Some(signature) = bigint_from_limbs(&sig_limbs, p.n) else {
                return Verdict::Skipped("signature does not reassemble into a valid integer".to_string());
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
            let k = p.k as usize;
            let Some(x) = bigint_from_limbs(&pubkey_limbs[0..k], p.n) else {
                return Verdict::Skipped("csca_pubKey's x half does not reassemble into a valid integer".to_string());
            };
            let Some(y) = bigint_from_limbs(&pubkey_limbs[k..2 * k], p.n) else {
                return Verdict::Skipped("csca_pubKey's y half does not reassemble into a valid integer".to_string());
            };
            if sig_limbs.len() != 2 * k {
                return Verdict::Skipped(format!(
                    "signature has {} limbs, expected 2*k={}",
                    sig_limbs.len(),
                    2 * k
                ));
            }
            let Some(r) = bigint_from_limbs(&sig_limbs[0..k], p.n) else {
                return Verdict::Skipped("signature's r half does not reassemble into a valid integer".to_string());
            };
            let Some(s) = bigint_from_limbs(&sig_limbs[k..2 * k], p.n) else {
                return Verdict::Skipped("signature's s half does not reassemble into a valid integer".to_string());
            };
            match ecdsa::verify_ecdsa(curve, &x, &y, &r, &s, &sig_digest) {
                Ok(()) => {}
                // Structural: cannot show the circuit would reject this too
                // (see passport.rs's identical branch and ecdsa::EcdsaError's
                // doc comment). Skipped, not Invalid.
                Err(ecdsa::EcdsaError::Structural(reason)) => {
                    return Verdict::Skipped(format!(
                        "ECDSA public key or coordinate cannot be checked natively: {reason}"
                    ));
                }
                // Failed: an affirmative failure the circuit's own
                // constraints would also produce.
                Err(ecdsa::EcdsaError::Failed(reason)) => {
                    return Verdict::Invalid(reason);
                }
            }
        }
        Scheme::EcdsaBrainpool { curve } => {
            let Some(curve) = BrainpoolCurve::from_name(curve) else {
                return Verdict::Skipped(format!("unknown brainpool curve name: {curve}"));
            };
            let k = p.k as usize;
            let Some(x) = bigint_from_limbs(&pubkey_limbs[0..k], p.n) else {
                return Verdict::Skipped("csca_pubKey's x half does not reassemble into a valid integer".to_string());
            };
            let Some(y) = bigint_from_limbs(&pubkey_limbs[k..2 * k], p.n) else {
                return Verdict::Skipped("csca_pubKey's y half does not reassemble into a valid integer".to_string());
            };
            if sig_limbs.len() != 2 * k {
                return Verdict::Skipped(format!(
                    "signature has {} limbs, expected 2*k={}",
                    sig_limbs.len(),
                    2 * k
                ));
            }
            let Some(r) = bigint_from_limbs(&sig_limbs[0..k], p.n) else {
                return Verdict::Skipped("signature's r half does not reassemble into a valid integer".to_string());
            };
            let Some(s) = bigint_from_limbs(&sig_limbs[k..2 * k], p.n) else {
                return Verdict::Skipped("signature's s half does not reassemble into a valid integer".to_string());
            };

            // Same sync/async boundary as passport.rs's identical arm: dsc::
            // verify must stay sync too, and block_on is sound here for the
            // same reason -- this is only reached, in production, via
            // mod::dispatch running inside mod::verify_inputs's
            // spawn_blocking, never directly on an async worker thread. See
            // passport.rs's EcdsaBrainpool arm for the full reasoning.
            let handle = tokio::runtime::Handle::current();
            match handle.block_on(brainpool::verify_brainpool(curve, &x, &y, &r, &s, raw_dsc_msg, p.sig_hash)) {
                Ok(()) => {}
                Err(ecdsa::EcdsaError::Structural(reason)) => {
                    return Verdict::Skipped(format!(
                        "brainpool ECDSA public key or signature cannot be checked natively: {reason}"
                    ));
                }
                Err(ecdsa::EcdsaError::Failed(reason)) => {
                    return Verdict::Invalid(reason);
                }
            }
        }
        // Guarded out at the top of this function -- unreachable here.
        _ => {
            return Verdict::Skipped(
                "dsc::verify only handles the RSA PKCS#1v15, RSASSA-PSS, ECDSA, and brainpool-ECDSA schemes"
                    .to_string(),
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
        crate::verifier::params::lookup("dsc_sha256_rsa_65537_4096").expect("known circuit")
    }

    fn fixture() -> serde_json::Value {
        let p = params();
        let key = TestRsaKey::generate(65537);
        dsc_inputs(&key, p.n, p.k as usize)
    }

    fn reason(v: &Verdict) -> String {
        match v {
            Verdict::Invalid(r) | Verdict::Skipped(r) => r.clone(),
            Verdict::Valid => String::new(),
        }
    }

    #[test]
    fn a_self_consistent_dsc_input_is_valid() {
        assert_eq!(verify(&fixture(), &params()), Verdict::Valid);
    }

    #[test]
    fn corrupting_the_signature_is_invalid_for_the_signature_check() {
        let mut inputs = fixture();
        let arr = inputs["signature"].as_array_mut().unwrap();
        arr[0] = serde_json::Value::String("1".to_string());
        let v = verify(&inputs, &params());
        assert!(matches!(v, Verdict::Invalid(_)), "got {v:?}");
        let r = reason(&v);
        assert!(r.contains("signature"), "the reason must name the signature check, got: {r}");
    }

    #[test]
    fn corrupting_csca_pubkey_breaks_the_certificate_key_link_not_the_signature_check() {
        // THE test that distinguishes this design from a bare signature
        // check: without this link, a caller could supply any key that
        // matches any signature. `csca_pubKey` no longer matches the bytes
        // embedded in `raw_csca`, so this must be Invalid for that reason --
        // and, since link 1 is checked strictly before any signature-related
        // parsing, it is structurally impossible for this to instead surface
        // as (or be masked by) a signature failure. Assert both directions:
        // the reason must name the certificate-key link, and must not
        // mention the signature check at all.
        let mut inputs = fixture();
        flip_limb(&mut inputs, "csca_pubKey", 0);
        let v = verify(&inputs, &params());
        assert!(matches!(v, Verdict::Invalid(_)), "got {v:?}");
        let r = reason(&v);
        assert!(
            r.contains("csca_pubKey") && r.contains("raw_csca"),
            "the reason must name the certificate-key link, got: {r}"
        );
        assert!(
            !r.contains("signature does not verify") && !r.contains("PSS") && !r.contains("ECDSA"),
            "the reason must not be a signature-check failure -- link 1 must be checked \
             (and fail) before link 2 ever runs, got: {r}"
        );
    }

    #[test]
    fn an_offset_out_of_range_is_skipped_not_invalid() {
        // Per this task's spec (see offset_in_range's doc comment), an
        // out-of-range offset here is Skipped, not Invalid, unlike
        // passport.rs's dg1_hash_offset handling.
        let mut inputs = fixture();
        inputs["csca_pubKey_offset"] = serde_json::json!(["100000"]);
        let v = verify(&inputs, &params());
        assert!(matches!(v, Verdict::Skipped(_)), "got {v:?}");
    }

    #[test]
    fn malformed_raw_dsc_padding_is_skipped_not_invalid() {
        let mut inputs = fixture();
        // Claim a padded length that the buffer's own length field contradicts.
        inputs["raw_dsc_padded_length"] = serde_json::json!(["64"]);
        let v = verify(&inputs, &params());
        assert!(matches!(v, Verdict::Skipped(_)), "malformed padding must skip, got {v:?}");
    }

    #[test]
    fn a_missing_field_is_skipped_not_invalid() {
        let mut inputs = fixture();
        inputs.as_object_mut().unwrap().remove("csca_pubKey");
        let v = verify(&inputs, &params());
        assert!(matches!(v, Verdict::Skipped(_)), "a missing field must skip, got {v:?}");
    }
}
