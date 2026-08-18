//! RSA PKCS#1 v1.5 signature verification via a raw modular exponentiation.
//!
//! Deliberately not a higher-level RSA crate: several of those reject unusual
//! public exponents, and production carries five exotic ones (56611, 64321,
//! 107903, 122125, 130689) alongside 3 and 65537. A raw `modpow` handles them
//! all identically.

use num_bigint::BigUint;

/// ASN.1 DigestInfo prefixes for the SHA family, per RFC 8017 §9.2.
fn digest_info_prefix(hash_bits: u32) -> Option<&'static [u8]> {
    Some(match hash_bits {
        160 => &[0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14],
        224 => &[0x30,0x2d,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x04,0x05,0x00,0x04,0x1c],
        256 => &[0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20],
        384 => &[0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30],
        512 => &[0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40],
        _ => return None,
    })
}

/// Builds the PKCS#1 v1.5 encoded message: 0x00 || 0x01 || 0xFF.. || 0x00 || DigestInfo.
pub fn pkcs1v15_encode(digest: &[u8], hash_bits: u32, k_bytes: usize) -> Option<Vec<u8>> {
    let prefix = digest_info_prefix(hash_bits)?;
    let t_len = prefix.len() + digest.len();
    if k_bytes < t_len + 11 {
        return None;
    }
    let mut em = Vec::with_capacity(k_bytes);
    em.push(0x00);
    em.push(0x01);
    em.extend(std::iter::repeat(0xff).take(k_bytes - t_len - 3));
    em.push(0x00);
    em.extend_from_slice(prefix);
    em.extend_from_slice(digest);
    Some(em)
}

/// Verifies an RSA PKCS#1 v1.5 signature.
///
/// Deliberately a raw modexp rather than a higher-level RSA crate: several of
/// those reject unusual public exponents, and production carries 56611, 64321,
/// 107903, 122125 and 130689 alongside 3 and 65537. One modexp handles them all.
pub fn verify_pkcs1v15(
    sig: &BigUint,
    modulus: &BigUint,
    e: u64,
    digest: &[u8],
    hash_bits: u32,
) -> bool {
    if sig >= modulus {
        return false;
    }
    let k_bytes = (modulus.bits() as usize + 7) / 8;
    let Some(expected) = pkcs1v15_encode(digest, hash_bits, k_bytes) else {
        return false;
    };
    let m = sig.modpow(&BigUint::from(e), modulus);
    let mut got = m.to_bytes_be();
    // to_bytes_be drops the leading zero the encoding starts with.
    while got.len() < k_bytes {
        got.insert(0, 0x00);
    }
    got == expected
}
