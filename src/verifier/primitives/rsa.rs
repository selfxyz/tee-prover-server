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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::testkit::TestRsaKey;
    use sha1::Digest as _;

    /// The five DigestInfo prefixes, taken from OpenSSL rather than from
    /// RFC 8017's text.
    ///
    /// Each value was produced by signing a message with `openssl dgst -<alg>
    /// -sign`, undoing the RSA operation with the public exponent, stripping
    /// `00 01 FF.. 00`, and removing the trailing digest — i.e. read back out
    /// of a real OpenSSL signature. That matters: asserting our encoder against
    /// our own decoder proves only self-consistency, and every RSA fixture in
    /// this repo has a SHA-256 signature hash, so before this test four of the
    /// five prefixes were exercised by nothing at all while live circuits
    /// depended on them (algs 3/11/33 at 160, alg 34 at 384, algs 15/31 at 512,
    /// plus DSC algs 11 and 15).
    const OPENSSL_PREFIXES: &[(u32, &str)] = &[
        (160, "3021300906052b0e03021a05000414"),
        (224, "302d300d06096086480165030402040500041c"),
        (256, "3031300d060960864801650304020105000420"),
        (384, "3041300d060960864801650304020205000430"),
        (512, "3051300d060960864801650304020305000440"),
    ];

    #[test]
    fn digest_info_prefixes_match_openssl() {
        for (bits, expect) in OPENSSL_PREFIXES {
            let got = digest_info_prefix(*bits)
                .unwrap_or_else(|| panic!("no prefix for {bits}"));
            assert_eq!(hex(got), *expect, "DigestInfo prefix for SHA-{bits}");
        }
    }

    #[test]
    fn an_unknown_hash_width_has_no_prefix() {
        assert!(digest_info_prefix(0).is_none());
        assert!(digest_info_prefix(128).is_none());
        assert!(digest_info_prefix(255).is_none());
    }

    /// Round-trips every width a live circuit uses, not just the one every
    /// fixture happens to use.
    #[test]
    fn every_hash_width_round_trips() {
        let key = TestRsaKey::generate(65537);
        for (bits, _) in OPENSSL_PREFIXES {
            let digest = digest_of(*bits, b"self dsc precheck");
            let sig = key.sign_digest_pkcs1v15(&digest, *bits);
            assert!(
                verify_pkcs1v15(&sig, &key.n, key.e, &digest, *bits),
                "SHA-{bits} should verify"
            );
            let mut wrong = digest.clone();
            wrong[0] ^= 1;
            assert!(
                !verify_pkcs1v15(&sig, &key.n, key.e, &wrong, *bits),
                "SHA-{bits} must reject a tampered digest"
            );
        }
    }

    /// A signature made under one hash width must not verify under another --
    /// this is what the prefix bytes are for, and a table with two identical
    /// rows would pass every other test in this module.
    #[test]
    fn a_signature_does_not_verify_under_a_different_hash_width() {
        let key = TestRsaKey::generate(65537);
        let d256 = digest_of(256, b"self dsc precheck");
        let sig = key.sign_digest_pkcs1v15(&d256, 256);
        let d512 = digest_of(512, b"self dsc precheck");
        assert!(!verify_pkcs1v15(&sig, &key.n, key.e, &d512, 512));
    }

    fn digest_of(bits: u32, msg: &[u8]) -> Vec<u8> {
        match bits {
            160 => sha1::Sha1::digest(msg).to_vec(),
            224 => sha2::Sha224::digest(msg).to_vec(),
            256 => sha2::Sha256::digest(msg).to_vec(),
            384 => sha2::Sha384::digest(msg).to_vec(),
            512 => sha2::Sha512::digest(msg).to_vec(),
            other => panic!("no digest for {other}"),
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
