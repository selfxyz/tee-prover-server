//! RSASSA-PSS verification (RFC 8017 §9.1.2), matching the *circuit's*
//! semantics where it diverges from the RFC. See this module's tests and the
//! plan's "circuit's PSS semantics" section.
//!
//! Nothing here is called from production code yet -- this plan's Task 2
//! wires `verify_pss` into `params.rs`'s scheme table and Task 3 into
//! `passport.rs`'s dispatch. The `#[allow(dead_code)]` attributes below come
//! off once those tasks land, same as `Scheme::RsaPss` in `params.rs`.

use num_bigint::BigUint;
use sha1::Digest as _;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PssHash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

#[allow(dead_code)]
impl PssHash {
    pub fn len(self) -> usize {
        match self {
            PssHash::Sha1 => 20,
            PssHash::Sha256 => 32,
            PssHash::Sha384 => 48,
            PssHash::Sha512 => 64,
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            PssHash::Sha1 => sha1::Sha1::digest(data).to_vec(),
            PssHash::Sha256 => sha2::Sha256::digest(data).to_vec(),
            PssHash::Sha384 => sha2::Sha384::digest(data).to_vec(),
            PssHash::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }
}

/// RFC 8017 §B.2.1: repeatedly hash `seed || counter` (counter as a 4-byte
/// big-endian block), concatenate, and truncate to `out_len`.
#[allow(dead_code)]
fn mgf1(seed: &[u8], out_len: usize, hash: PssHash) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len + hash.len());
    let mut counter: u32 = 0;
    while out.len() < out_len {
        let mut block = Vec::with_capacity(seed.len() + 4);
        block.extend_from_slice(seed);
        block.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&hash.digest(&block));
        counter += 1;
    }
    out.truncate(out_len);
    out
}

/// Verifies an RSASSA-PSS signature per RFC 8017 §9.1.2, with one deliberate
/// divergence: see the leftmost-bit comment below.
#[allow(dead_code)]
pub fn verify_pss(
    signature: &BigUint,
    modulus: &BigUint,
    exponent: u64,
    m_hash: &[u8],
    hash: PssHash,
    salt_len: usize,
    key_bits: u32,
) -> Result<(), String> {
    // validate.circom:41-44
    if signature >= modulus {
        return Err("signature is not less than modulus".into());
    }
    let em_len = (key_bits as usize) / 8;
    let h_len = hash.len();
    if m_hash.len() != h_len {
        return Err(format!(
            "message hash is {} bytes, expected {h_len}",
            m_hash.len()
        ));
    }
    if em_len < h_len + salt_len + 2 {
        return Err(format!(
            "EM length {em_len} too short for hash {h_len} + salt {salt_len}"
        ));
    }

    let em_int = signature.modpow(&BigUint::from(exponent), modulus);
    let raw = em_int.to_bytes_be();
    if raw.len() > em_len {
        return Err(format!("EM is {} bytes, exceeds {em_len}", raw.len()));
    }
    // Left-pad to exactly EM_LEN: the circuit renders into a fixed-width buffer.
    let mut em = vec![0u8; em_len - raw.len()];
    em.extend_from_slice(&raw);

    // rsapss65537.circom:119
    let Some(&trailer) = em.last() else {
        return Err("EM is empty".into());
    };
    if trailer != 0xbc {
        return Err(format!("EM does not end in 0xbc (found 0x{trailer:02x})"));
    }

    let db_len = em_len - h_len - 1;
    let (masked_db, rest) = em.split_at(db_len);
    let h = &rest[..h_len];

    let mask = mgf1(h, db_len, hash);
    let mut db: Vec<u8> = masked_db.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect();
    // rsapss65537.circom:162-168 CLEARS this bit rather than checking it, as
    // RFC 8017 step 9 would. Checking it would reject inputs the circuit
    // accepts -- a false reject -- so this primitive clears it too.
    if let Some(first) = db.first_mut() {
        *first &= 0x7f;
    }

    let zero_len = db_len - salt_len - 1;
    if db[..zero_len].iter().any(|b| *b != 0) {
        return Err("DB padding is not all zero".into());
    }
    if db[zero_len] != 0x01 {
        return Err(format!(
            "DB 0x01 separator missing (found 0x{:02x})",
            db[zero_len]
        ));
    }
    let salt = &db[zero_len + 1..];

    let mut m_prime = Vec::with_capacity(8 + h_len + salt_len);
    m_prime.extend_from_slice(&[0u8; 8]);
    m_prime.extend_from_slice(m_hash);
    m_prime.extend_from_slice(salt);
    if hash.digest(&m_prime) != h {
        return Err("H mismatch".into());
    }
    Ok(())
}

#[cfg(test)]
fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    sha2::Sha256::digest(data).to_vec()
}

#[cfg(test)]
mod tests_support {
    use super::{mgf1, sha256, PssHash};
    use num_bigint::BigUint;

    /// The signing-side test key: Plan 1's checked-in `TestRsaKey::generate`
    /// primes, exponent 65537. Its modulus is 1024 bits, not 2048 — PSS is
    /// indifferent to modulus size, since EM_LEN is a parameter and SHA-256
    /// with a 32-byte salt needs only 32+32+2 = 66 bytes against EM_LEN 128.
    pub fn test_key() -> (BigUint, BigUint) {
        let key = crate::verifier::testkit::TestRsaKey::generate(65537);
        (key.n, key.d)
    }

    /// Identical to the test module's `sign_pss`, except it sets rather than
    /// clears the leftmost bit of the masked DB before appending H and the
    /// trailer byte — used to prove the verifier clears that bit rather than
    /// rejecting it (rsapss65537.circom:162-168).
    ///
    /// Clearing that bit (as `sign_pss` does) is what guarantees EM, read as
    /// an integer, is less than the modulus: an EM_LEN-byte value with its
    /// top bit clear is always < 2^(8*EM_LEN - 1), and an EM_LEN-byte modulus
    /// is always >= that same bound. Setting the bit instead loses that
    /// guarantee -- EM may land above the modulus, and RSA's `s = EM^d mod n`
    /// then signs `EM mod n`, not `EM` itself, so recovery would not
    /// round-trip back to this EM. Since the starting `salt` here is a fixed
    /// test vector rather than something chosen to satisfy that bound, this
    /// searches nearby salts (varying only the last byte, so `salt_len` is
    /// unaffected) for one where forcing the bit still leaves EM < n.
    pub fn sign_pss_with_high_bit_set(
        m_hash: &[u8],
        salt: &[u8],
        key_bits: u32,
        n: &BigUint,
        d: &BigUint,
    ) -> BigUint {
        let em_len = (key_bits / 8) as usize;
        let h_len = m_hash.len();
        let mut salt = salt.to_vec();
        for attempt in 0u16..=u16::MAX {
            if let Some(last) = salt.last_mut() {
                *last = attempt as u8;
            }
            let mut m_prime = vec![0u8; 8];
            m_prime.extend_from_slice(m_hash);
            m_prime.extend_from_slice(&salt);
            let h = sha256(&m_prime);
            let db_len = em_len - h_len - 1;
            let mut db = vec![0u8; db_len];
            db[db_len - salt.len() - 1] = 0x01;
            db[db_len - salt.len()..].copy_from_slice(&salt);
            let mask = mgf1(&h, db_len, PssHash::Sha256);
            let mut masked: Vec<u8> = db.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect();
            masked[0] |= 0x80;
            let mut em = masked;
            em.extend_from_slice(&h);
            em.push(0xbc);
            let em_int = BigUint::from_bytes_be(&em);
            if &em_int < n {
                return em_int.modpow(d, n);
            }
        }
        unreachable!("no candidate salt produced an EM below the modulus in 65536 attempts");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Signs by constructing EM directly and raising to d, so the test proves
    // verify_pss agrees with a from-scratch EMSA-PSS-ENCODE — not with itself.
    fn sign_pss(m_hash: &[u8], salt: &[u8], key_bits: u32, n: &BigUint, d: &BigUint) -> BigUint {
        let em_len = (key_bits / 8) as usize;
        let h_len = m_hash.len();
        let mut m_prime = vec![0u8; 8];
        m_prime.extend_from_slice(m_hash);
        m_prime.extend_from_slice(salt);
        let h = sha256(&m_prime);
        let db_len = em_len - h_len - 1;
        let mut db = vec![0u8; db_len];
        db[db_len - salt.len() - 1] = 0x01;
        db[db_len - salt.len()..].copy_from_slice(salt);
        let mask = mgf1(&h, db_len, PssHash::Sha256);
        let mut masked: Vec<u8> = db.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect();
        masked[0] &= 0x7f; // clear the leftmost bit, as a conformant signer does
        let mut em = masked;
        em.extend_from_slice(&h);
        em.push(0xbc);
        BigUint::from_bytes_be(&em).modpow(d, n)
    }

    #[test]
    fn a_valid_pss_signature_verifies() {
        let (n, d) = tests_support::test_key();
        let m_hash = sha256(b"signed attributes");
        let salt = [7u8; 32];
        let sig = sign_pss(&m_hash, &salt, 1024, &n, &d);
        assert_eq!(
            verify_pss(&sig, &n, 65537, &m_hash, PssHash::Sha256, 32, 1024),
            Ok(())
        );
    }

    #[test]
    fn a_tampered_message_hash_fails() {
        let (n, d) = tests_support::test_key();
        let m_hash = sha256(b"signed attributes");
        let salt = [7u8; 32];
        let sig = sign_pss(&m_hash, &salt, 1024, &n, &d);
        let other = sha256(b"different attributes");
        let err = verify_pss(&sig, &n, 65537, &other, PssHash::Sha256, 32, 1024).unwrap_err();
        assert!(err.contains("H mismatch"), "wrong reason: {err}");
    }

    #[test]
    fn a_wrong_salt_length_fails_for_its_own_reason() {
        let (n, d) = tests_support::test_key();
        let m_hash = sha256(b"signed attributes");
        let sig = sign_pss(&m_hash, &[7u8; 32], 1024, &n, &d);
        // Verifying a salt-32 signature as salt-64 must fail on the DB
        // separator, not on H — asserting the reason is the point.
        let err = verify_pss(&sig, &n, 65537, &m_hash, PssHash::Sha256, 64, 1024).unwrap_err();
        assert!(err.contains("0x01 separator"), "wrong reason: {err}");
    }

    #[test]
    fn a_signature_not_less_than_the_modulus_fails() {
        let (n, _d) = tests_support::test_key();
        let err = verify_pss(&n, &n, 65537, &[0u8; 32], PssHash::Sha256, 32, 1024).unwrap_err();
        assert!(err.contains("not less than modulus"), "wrong reason: {err}");
    }

    #[test]
    fn the_leftmost_bit_is_cleared_not_checked() {
        // The circuit forces db[0] to zero (rsapss65537.circom:162-168) rather
        // than rejecting when it is set. A verifier that rejects here would
        // reject inputs the circuit accepts — a false reject. This test pins
        // that divergence deliberately.
        let (n, d) = tests_support::test_key();
        let m_hash = sha256(b"signed attributes");
        let salt = [7u8; 32];
        let sig = tests_support::sign_pss_with_high_bit_set(&m_hash, &salt, 1024, &n, &d);
        assert_eq!(
            verify_pss(&sig, &n, 65537, &m_hash, PssHash::Sha256, 32, 1024),
            Ok(())
        );
    }

    #[test]
    fn mgf1_first_block_is_hash_of_seed_and_counter() {
        // MGF1's first output block is Hash(seed || counter=0). Checked
        // directly against a from-scratch hash, not against verify_pss.
        let seed = sha256(b"");
        let out = mgf1(&seed, 32, PssHash::Sha256);
        let expect = sha256(&[seed.as_slice(), &[0, 0, 0, 0]].concat());
        assert_eq!(out, expect);

        // A length that is not a multiple of the hash size exercises the
        // truncation path -- MGF1 implementations most often go wrong here.
        let out_100 = mgf1(&seed, 100, PssHash::Sha256);
        assert_eq!(out_100.len(), 100);
        let mut expect_100 = sha256(&[seed.as_slice(), &[0, 0, 0, 0]].concat());
        expect_100.extend_from_slice(&sha256(&[seed.as_slice(), &[0, 0, 0, 1]].concat()));
        expect_100.extend_from_slice(&sha256(&[seed.as_slice(), &[0, 0, 0, 2]].concat()));
        expect_100.extend_from_slice(&sha256(&[seed.as_slice(), &[0, 0, 0, 3]].concat()));
        expect_100.truncate(100);
        assert_eq!(out_100, expect_100);
    }
}
