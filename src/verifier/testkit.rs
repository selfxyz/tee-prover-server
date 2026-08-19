//! Fixture builders for `kyc.rs`'s own tests -- the one Rust verifier left
//! that still needs a hand-built, self-consistent input object rather than a
//! real checked-in fixture.
//!
//! Plan A, Task 4 removed every builder used only by the RSA/ECDSA family
//! verifiers and by `mod.rs`'s old routing-pin tests (`TestRsaKey`,
//! `passport_inputs`, `ecdsa_passport_inputs`, `brainpool_passport_inputs`,
//! `aadhaar_inputs`, `dsc_inputs`, `sha_pad`, `to_limbs`, `flip_limb`) --
//! their only callers were `passport.rs`/`dsc.rs`/`primitives::ecdsa`
//! (deleted) and `mod.rs`'s routing tests (rewritten to use real checked-in
//! fixtures instead, now that there is only one non-KYC dispatch path to
//! pin).

use serde_json::{json, Value};

pub fn bytes_to_decimal(b: &[u8]) -> Vec<String> {
    b.iter().map(|x| x.to_string()).collect()
}

/// Flips one byte of a decimal-string byte array field, in place.
pub fn flip_byte(v: &mut Value, key: &str, index: usize) {
    let arr = v[key].as_array_mut().expect("array field");
    let cur: u8 = arr[index].as_str().unwrap().parse().unwrap();
    arr[index] = Value::String((cur ^ 0x01).to_string());
}

/// The independent test vector transcribed from didit-tee's own unit test
/// (`../didit-tee/src/crypto/poseidon.rs:106-111`) — didit-tee is the KYC
/// signer, so this is evidence from the authority producing these signatures,
/// not something self-generated. The 43-byte input spans two 31-byte chunks,
/// exercising the multi-chunk path a shorter vector would not.
pub fn reference_packing_vector() -> (Vec<u8>, String) {
    (
        b"Hello, world! This is a really big world!!!".to_vec(),
        "6446139023319571694658613803604429404979765410698322161344351432504333128665".to_string(),
    )
}

/// Self-consistent KYC input: EdDSA-BabyJubJub over PackBytesAndPoseidon(data).
pub fn kyc_inputs() -> Value {
    use babyjubjub_rs::PrivateKey;

    use crate::verifier::primitives::eddsa::fr_to_decimal;

    let data: Vec<u8> = (0u8..255).cycle().take(295).collect();
    let msg = crate::verifier::kyc::pack_bytes_and_poseidon(&data).expect("packing");

    let sk = PrivateKey::import(vec![7u8; 32]).expect("test key");
    let pk = sk.public();
    let sig = sk.sign(msg).expect("sign");

    json!({
        "data_padded": bytes_to_decimal(&data),
        "s": [sig.s.to_string()],
        "R": [fr_to_decimal(&sig.r_b8.x), fr_to_decimal(&sig.r_b8.y)],
        "pubKey": [fr_to_decimal(&pk.x), fr_to_decimal(&pk.y)],
    })
}
