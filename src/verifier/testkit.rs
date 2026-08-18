//! Fixture builders for verifier tests. Each builds a *self-consistent* input
//! object, so a test asserting Valid is asserting agreement with the real
//! chain rather than with a hand-written expectation.

use num_bigint::BigUint;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Applies SHA padding the way the off-circuit input builders do.
pub fn sha_pad(msg: &[u8]) -> Vec<u8> {
    let mut p = msg.to_vec();
    p.push(0x80);
    while (p.len() + 8) % 64 != 0 {
        p.push(0);
    }
    p.extend_from_slice(&((msg.len() as u64) * 8).to_be_bytes());
    p
}

/// Splits a big integer into little-endian base-2^n limbs as decimal strings.
pub fn to_limbs(v: &BigUint, n: u32, k: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(k);
    let mask = (BigUint::from(1u32) << n) - BigUint::from(1u32);
    for i in 0..k {
        out.push(((v >> (n * i as u32)) & &mask).to_string());
    }
    out
}

pub fn bytes_to_decimal(b: &[u8]) -> Vec<String> {
    b.iter().map(|x| x.to_string()).collect()
}

/// A small deterministic RSA key with a chosen public exponent. Small primes are
/// fine here: we are testing the verifier's arithmetic and chain logic, not RSA.
pub struct TestRsaKey {
    pub n: BigUint,
    pub e: u64,
    pub d: BigUint,
    pub bits: u32,
}

impl TestRsaKey {
    /// `e` is a parameter because production carries 3, 65537, and five exotic
    /// exponents (56611, 64321, 107903, 122125, 130689).
    /// Two fixed 512-bit primes, giving a 1024-bit modulus — ample for even a
    /// SHA-512 DigestInfo encoding. Fixed rather than random so a failure is
    /// reproducible, and verified coprime with every exponent in production
    /// (3, 65537, 56611, 64321, 107903, 122125, 130689). Note e=3 is the fussy
    /// one: it requires p and q to be chosen so 3 does not divide (p-1)(q-1).
    pub fn generate(e: u64) -> Self {
        use num_integer::Integer;

        const P_HEX: &[u8] = b"b3e73c7cef0b1778e8b45aa7ca4bb776b7808353d95b3451377cd013366d0f5e\
92e00996322ec4a837aa208d947fca8c75d2763972352f439fa717f851b6ed7f";
        const Q_HEX: &[u8] = b"bdffb484611317f6aecf7d3f49c3ae6b51c47b26fa352dae85db3a4004d24bdb\
3b0c1cf8abb7ed96d202e976fcdcc6129dc2c4c0e3ea044054a8acd3fa31a5fb";

        let p = BigUint::parse_bytes(P_HEX, 16).expect("valid prime hex");
        let q = BigUint::parse_bytes(Q_HEX, 16).expect("valid prime hex");
        let n = &p * &q;
        let phi = (&p - 1u32) * (&q - 1u32);
        let e_big = BigUint::from(e);

        assert!(
            e_big.gcd(&phi) == BigUint::from(1u32),
            "the fixed test primes are not coprime with e={e}; pick different primes \
             rather than working around this, or every signature test will fail for \
             a confusing reason"
        );

        // d = e^-1 mod phi, via the extended Euclidean algorithm over signed ints.
        // `extended_gcd` is a method on `num_integer::Integer` (the return type
        // `ExtendedGcd` is just a plain struct, not itself a trait to import).
        let ext = num_bigint::BigInt::from(e_big.clone())
            .extended_gcd(&num_bigint::BigInt::from(phi.clone()));
        let phi_i = num_bigint::BigInt::from(phi);
        let d = ((ext.x % &phi_i) + &phi_i) % &phi_i;
        let d = d.to_biguint().expect("modular inverse is non-negative");

        Self { n, e, d, bits: 1024 }
    }

    pub fn sign_digest_pkcs1v15(&self, digest: &[u8], hash_bits: u32) -> BigUint {
        let em = crate::verifier::primitives::rsa::pkcs1v15_encode(
            digest, hash_bits, (self.bits / 8) as usize,
        )
        .expect("encode");
        BigUint::from_bytes_be(&em).modpow(&self.d, &self.n)
    }
}

/// Builds a self-consistent passport input: dg1 -> eContent -> signed_attr -> signature.
pub fn passport_inputs(key: &TestRsaKey, n: u32, k: usize) -> Value {
    let dg1: Vec<u8> = (0u8..93).collect();
    let dg1_hash = Sha256::digest(&dg1);

    let dg1_hash_offset = 32usize;
    let mut econtent = vec![0u8; 128];
    econtent[dg1_hash_offset..dg1_hash_offset + 32].copy_from_slice(&dg1_hash);
    let econtent_padded = sha_pad(&econtent);
    let econtent_hash = Sha256::digest(&econtent);

    let sa_offset = 16usize;
    let mut signed_attr = vec![0u8; 96];
    signed_attr[sa_offset..sa_offset + 32].copy_from_slice(&econtent_hash);
    let signed_attr_padded = sha_pad(&signed_attr);
    let signed_attr_hash = Sha256::digest(&signed_attr);

    let sig = key.sign_digest_pkcs1v15(&signed_attr_hash, 256);

    json!({
        "dg1": bytes_to_decimal(&dg1),
        "dg1_hash_offset": [dg1_hash_offset.to_string()],
        "eContent": bytes_to_decimal(&econtent_padded),
        "eContent_padded_length": [econtent_padded.len().to_string()],
        "signed_attr": bytes_to_decimal(&signed_attr_padded),
        "signed_attr_padded_length": [signed_attr_padded.len().to_string()],
        "signed_attr_econtent_hash_offset": [sa_offset.to_string()],
        "pubKey_dsc": to_limbs(&key.n, n, k),
        "signature_passport": to_limbs(&sig, n, k),
    })
}

/// Self-consistent Aadhaar input: one sha256 over padded QR data, one RSA-65537 signature.
pub fn aadhaar_inputs(key: &TestRsaKey, n: u32, k: usize) -> Value {
    let qr: Vec<u8> = (0u8..200).cycle().take(512).collect();
    let padded = sha_pad(&qr);
    let digest = Sha256::digest(&qr);
    let sig = key.sign_digest_pkcs1v15(&digest, 256);

    json!({
        "qrDataPadded": bytes_to_decimal(&padded),
        "qrDataPaddedLength": [padded.len().to_string()],
        "pubKey": to_limbs(&key.n, n, k),
        "signature": to_limbs(&sig, n, k),
    })
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
