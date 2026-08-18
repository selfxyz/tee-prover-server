//! KYC signature pre-check, from `register_kyc.circom`.
//!
//! `:36` builds the signed message via `PackBytesAndPoseidon(max_length)` over
//! `data_padded` — **not** a plain Poseidon over the raw bytes. Bytes are
//! first packed at `MAX_BYTES_IN_FIELD` (31) bytes per field element,
//! little-endian within each chunk, and only then Poseidon'd (in arity-16
//! batches with a final Poseidon over the per-batch hashes, when there are
//! more than 16 chunks). `:41-48` then calls circomlib's
//! `EdDSAPoseidonVerifier(S, M, Ax, Ay, R8x, R8y)` over that hash — EdDSA over
//! BabyJubJub. Getting the packing wrong produces a different message hash
//! and therefore a false reject, which is exactly the failure this pre-check
//! exists to avoid — see `pack_bytes_and_poseidon`, ported from the KYC
//! signer's own implementation rather than derived from the circuit.
//!
//! `:25-33` also runs circomlib's `BabyCheck` on both `R` and `pubKey` before
//! the signature check. Only `pubKey` failing that is treated as an
//! affirmative `Invalid` here — that is the caller's public identity, and an
//! off-curve one is a structural failure the circuit itself would reject.
//!
//! `secret` (`:23`) is a private nullifier/commitment input, not signature
//! material, and is not read here.
//!
//! The governing asymmetry still applies: anything unparseable is `Skipped`.
//! Only a present, well-formed signature (or pubkey) that fails its
//! affirmative check is `Invalid`.

use num_bigint::{BigInt, BigUint};

use crate::verifier::chunks::{bytes_from_decimal_strings, field_as_strings};
use crate::verifier::params::CircuitParams;
use crate::verifier::primitives::eddsa::{fr_from_biguint, point_on_curve};
use crate::verifier::Verdict;

/// Ported verbatim from didit-tee's `pack_bytes_and_poseidon`
/// (`../didit-tee/src/crypto/poseidon.rs`) — the KYC signer's own packing, so
/// it is the authority on how `data_padded` becomes the message EdDSA signs.
pub const MAX_BYTES_IN_FIELD: usize = 31;

/// How many `MAX_BYTES_IN_FIELD`-byte chunks `byte_len` bytes pack into.
fn compute_int_chunk_length(byte_len: usize) -> usize {
    let pack_size = MAX_BYTES_IN_FIELD;
    let remain = byte_len % pack_size;
    let mut num_chunks = (byte_len - remain) / pack_size;
    if remain > 0 {
        num_chunks += 1;
    }
    num_chunks
}

/// Packs bytes into field elements, little-endian within each
/// `MAX_BYTES_IN_FIELD`-byte chunk: `sum = b_0*256^0 + b_1*256^1 + ...`.
fn pack_bytes(bytes: &[u8]) -> Vec<BigInt> {
    use num_traits::{One, Zero};

    let pack_size = MAX_BYTES_IN_FIELD;
    let max_ints = compute_int_chunk_length(bytes.len());
    let mut out = Vec::with_capacity(max_ints);

    for chunk_idx in 0..max_ints {
        let mut acc = BigInt::zero();
        let mut factor = BigInt::one();

        for j in 0..pack_size {
            let idx = chunk_idx * pack_size + j;
            if idx >= bytes.len() {
                break;
            }
            acc += &factor * (bytes[idx] as u32);
            factor <<= 8;
        }

        out.push(acc);
    }

    out
}

/// Packs `bytes` and Poseidon-hashes the result, exactly as
/// `PackBytesAndPoseidon` does in the circuit. `None` on any of the
/// reference implementation's `Err` paths (an empty message, or more than 16
/// arity-16 rounds) rather than a `Result`, so callers route straight to
/// `Skipped` — the same "returns `Option`, never invents a value" discipline
/// as `verifier::chunks`.
///
/// Returns `BigInt` (not the reference's `BigUint`) because every caller —
/// `babyjubjub_rs::PrivateKey::sign` in the test fixture and
/// `babyjubjub_rs::verify` here — takes the message as `BigInt`.
pub fn pack_bytes_and_poseidon(bytes: &[u8]) -> Option<BigInt> {
    use ark_bn254::Fr;
    use light_poseidon::{Poseidon, PoseidonHasher};
    use num_traits::Zero;

    let packed: Vec<Fr> = pack_bytes(bytes)
        .iter()
        .map(|x| Fr::from(BigUint::from_bytes_le(x.to_bytes_le().1.as_slice())))
        .collect();

    let len = packed.len();

    let hash: Fr = if len < 16 {
        if len == 0 {
            return None;
        }
        Poseidon::<Fr>::new_circom(len).ok()?.hash(&packed).ok()?
    } else {
        let rounds = (len + 15) / 16; // ceil(len / 16)
        if rounds > 16 {
            return None;
        }

        let mut chunk_hashes: Vec<Fr> = Vec::with_capacity(rounds);
        for i in 0..rounds {
            let mut chunk: Vec<Fr> = vec![Fr::zero(); 16];
            for (j, slot) in chunk.iter_mut().enumerate() {
                let idx = i * 16 + j;
                if idx < len {
                    *slot = packed[idx];
                }
            }
            chunk_hashes.push(Poseidon::<Fr>::new_circom(16).ok()?.hash(&chunk).ok()?);
        }

        Poseidon::<Fr>::new_circom(chunk_hashes.len()).ok()?.hash(&chunk_hashes).ok()?
    };

    let biguint: BigUint = hash.into();
    Some(BigInt::from(biguint))
}

/// Reads a single-element field (`s`) as a field element. Not
/// `chunks::scalar_usize`: `s` can exceed `usize`, and it is a field element,
/// not a limb-reassembled integer (`p.n == 0` for KYC — see
/// `verifier::params::lookup`'s note on the `EdDsaBabyJubJub` placeholder).
fn single_field_element(inputs: &serde_json::Value, key: &str) -> Option<BigUint> {
    let items = field_as_strings(inputs, key)?;
    if items.len() != 1 {
        return None;
    }
    items[0].parse().ok()
}

/// Reads a two-element field (`R`, `pubKey`) as an `(x, y)` field-element
/// pair.
fn point_as_biguints(inputs: &serde_json::Value, key: &str) -> Option<(BigUint, BigUint)> {
    let items = field_as_strings(inputs, key)?;
    if items.len() != 2 {
        return None;
    }
    let x = items[0].parse().ok()?;
    let y = items[1].parse().ok()?;
    Some((x, y))
}

pub fn verify(inputs: &serde_json::Value, _p: &CircuitParams) -> Verdict {
    // --- 1. Parse every field. Any parse failure => Skipped. ---
    let Some(data_items) = field_as_strings(inputs, "data_padded") else {
        return Verdict::Skipped("missing or malformed field: data_padded".to_string());
    };
    let Some(data) = bytes_from_decimal_strings(&data_items) else {
        return Verdict::Skipped("data_padded contains a non-byte value".to_string());
    };

    let Some(s) = single_field_element(inputs, "s") else {
        return Verdict::Skipped("missing or malformed field: s".to_string());
    };
    let Some((r_x, r_y)) = point_as_biguints(inputs, "R") else {
        return Verdict::Skipped("missing or malformed field: R".to_string());
    };
    let Some((pk_x, pk_y)) = point_as_biguints(inputs, "pubKey") else {
        return Verdict::Skipped("missing or malformed field: pubKey".to_string());
    };

    let (Some(r_x_fr), Some(r_y_fr)) = (fr_from_biguint(&r_x), fr_from_biguint(&r_y)) else {
        return Verdict::Skipped("R does not parse into a field element".to_string());
    };
    let (Some(pk_x_fr), Some(pk_y_fr)) = (fr_from_biguint(&pk_x), fr_from_biguint(&pk_y)) else {
        return Verdict::Skipped("pubKey does not parse into a field element".to_string());
    };

    // --- 2. Hash the packed message. None => Skipped. ---
    let Some(msg) = pack_bytes_and_poseidon(&data) else {
        return Verdict::Skipped("data_padded could not be packed and hashed".to_string());
    };

    // --- 3. Build the Point/Signature. An off-curve pubKey => Invalid: the
    //    circuit's own BabyCheck rejects it too, so this is an affirmative
    //    structural failure rather than something merely unparseable. ---
    if !point_on_curve(&pk_x, &pk_y) {
        return Verdict::Invalid("KYC pubkey is not on the curve".to_string());
    }

    let pk = babyjubjub_rs::Point { x: pk_x_fr, y: pk_y_fr };
    let sig = babyjubjub_rs::Signature {
        r_b8: babyjubjub_rs::Point { x: r_x_fr, y: r_y_fr },
        s: BigInt::from(s),
    };

    // --- 4. Verify the EdDSA-Poseidon signature. ---
    if !babyjubjub_rs::verify(pk, sig, msg) {
        return Verdict::Invalid("KYC EdDSA signature does not verify".to_string());
    }

    Verdict::Valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::testkit::*;

    fn params() -> crate::verifier::params::CircuitParams {
        crate::verifier::params::lookup("register_kyc").expect("known circuit")
    }

    #[test]
    fn pack_bytes_and_poseidon_matches_the_reference_vector() {
        // Vector transcribed from ../didit-tee/src/crypto/poseidon.rs's own unit
        // test. If this fails, the packing has diverged from the signer and every
        // real signature would be falsely rejected.
        let (input, expected) = reference_packing_vector();
        assert_eq!(pack_bytes_and_poseidon(&input).unwrap().to_string(), expected);
    }

    #[test]
    fn a_self_consistent_kyc_input_is_valid() {
        let p = params();
        assert_eq!(verify(&kyc_inputs(), &p), Verdict::Valid);
    }

    #[test]
    fn flipping_a_data_byte_is_invalid() {
        let mut inputs = kyc_inputs();
        flip_byte(&mut inputs, "data_padded", 4);
        let v = verify(&inputs, &params());
        assert!(matches!(v, Verdict::Invalid(_)), "got {v:?}");
    }

    #[test]
    fn corrupting_s_is_invalid() {
        let mut inputs = kyc_inputs();
        inputs["s"] = serde_json::json!(["1"]);
        assert!(matches!(verify(&inputs, &params()), Verdict::Invalid(_)));
    }

    #[test]
    fn a_missing_r_field_is_skipped() {
        let mut inputs = kyc_inputs();
        inputs.as_object_mut().unwrap().remove("R");
        let v = verify(&inputs, &params());
        assert!(matches!(v, Verdict::Skipped(_)), "a missing field must skip, got {v:?}");
    }

    #[test]
    fn an_off_curve_pubkey_is_invalid() {
        let mut inputs = kyc_inputs();
        // (12345, 6789) is not a BabyJubJub point (see
        // primitives::eddsa::tests::arbitrary_coordinates_are_not_on_curve).
        inputs["pubKey"] = serde_json::json!(["12345", "6789"]);
        let v = verify(&inputs, &params());
        match v {
            Verdict::Invalid(reason) => assert!(
                reason.contains("curve"),
                "expected the reason to name the curve check, got: {reason}"
            ),
            other => panic!("an off-curve pubkey must be Invalid, got {other:?}"),
        }
    }
}
