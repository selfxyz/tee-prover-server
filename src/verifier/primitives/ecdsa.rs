//! ECDSA verification for the NIST curves used by the passport signature
//! chains, matching the *circuit's* semantics. See this module's tests and
//! the plan's "circuit's ECDSA semantics" section.
//!
//! Source: `ecdsaVerifier.circom` (in the `self/circuits` repo).
//! `getKLengthFactor(alg) == 2` for every ECDSA algorithm, so both
//! `pubKey_dsc` and `signature_passport` carry `2k` limbs
//! (`ecdsaVerifier.circom:50-55`): `r = signature[0..k]`, `s =
//! signature[k..2k]`, `x = pubKey[0..k]`, `y = pubKey[k..2k]`, each base-`2^n`
//! and least-significant-limb-first -- exactly what `chunks::bigint_from_limbs`
//! already reassembles into the `x`, `y`, `r`, `s` big integers this module
//! takes as input. Reassembly into those big integers happens in Task 3's
//! caller, not here.
//!
//! The message scalar: `ecdsaVerifier.circom:27-41` truncates the digest to
//! the leftmost `n*k` bits when `HASH_LEN_BITS >= n*k`, and otherwise
//! left-pads with zeros to `n*k` bits. The truncation branch is dead for
//! every deployed instance -- all 14 have `HASH_LEN_BITS <= n*k` (the
//! tightest is secp224r1 + SHA-224, both exactly 224 bits) -- so this module
//! does not implement it. Left-padding does not change the integer value, so
//! the circuit's `z` is simply the digest read as a big-endian integer,
//! which is exactly what RustCrypto's `bits2field` produces for a digest no
//! longer than the field. Task 2 adds a drift assertion over the instance
//! set that would catch a future instance needing the truncation branch;
//! this primitive intentionally does not guess at it.
//!
//! Wired into production via `passport.rs`'s dispatch arm for
//! `Scheme::Ecdsa` (Task 3); no longer test-only.

use num_bigint::BigUint;
// The `signature` crate is only a transitive dependency (re-exported by each
// `pXXX::ecdsa` module); this trait is the same type regardless of which
// curve crate's re-export it is imported through, so one import covers all
// four `match` arms below.
use p256::ecdsa::signature::hazmat::PrehashVerifier;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    Secp224r1,
    Secp256r1,
    Secp384r1,
    Secp521r1,
}

impl Curve {
    pub fn from_name(s: &str) -> Option<Curve> {
        Some(match s {
            "secp224r1" => Curve::Secp224r1,
            "secp256r1" => Curve::Secp256r1,
            "secp384r1" => Curve::Secp384r1,
            "secp521r1" => Curve::Secp521r1,
            _ => return None,
        })
    }

    /// Field width in bytes: 28 / 32 / 48 / 66. secp521r1's 66 does not
    /// divide evenly into 8-byte words -- see the module doc's note on
    /// `n = 66` limbs not being byte-aligned. This function only deals in
    /// bytes (the SEC1 point / signature scalar encoding width), not limbs,
    /// so that misalignment does not appear here.
    pub fn field_bytes(self) -> usize {
        match self {
            Curve::Secp224r1 => 28,
            Curve::Secp256r1 => 32,
            Curve::Secp384r1 => 48,
            Curve::Secp521r1 => 66,
        }
    }
}

/// Left-pads `v` to exactly `width` bytes, big-endian. `Err` if `v` needs
/// more than `width` bytes -- silently truncating instead would let an
/// oversized coordinate masquerade as a valid, different one. Unreachable in
/// practice from real reassembled input: `bigint_from_limbs` (the caller's
/// caller) already rejects any limb `>= 2^n`, and `n*k` equals the field
/// width in bits exactly for all four curves, so a value it produces can
/// never need more than `width` bytes. Classified `Structural` below rather
/// than `Failed` anyway, since this branch is not a circuit constraint
/// either way and the safer default for an unreachable path is the one that
/// cannot false-reject.
fn coord_bytes(v: &BigUint, width: usize) -> Result<Vec<u8>, String> {
    let raw = v.to_bytes_be();
    if raw.len() > width {
        return Err(format!(
            "coordinate is {} bytes, wider than the field ({width})",
            raw.len()
        ));
    }
    let mut out = vec![0u8; width - raw.len()];
    out.extend_from_slice(&raw);
    Ok(out)
}

/// The two ways `verify_ecdsa` can fail, distinguished by whether the
/// *circuit* would also reject the input:
///
/// - `Structural`: the circuit cannot be shown to reject this. Right now
///   the only case is an off-curve public key -- `verifyECDSABits`
///   (`../self/circuits/circuits/utils/crypto/signature/ecdsa/ecdsa.circom:
///   18-102`) never checks that the point satisfies the curve equation, only
///   `1 <= r,s < order` (`:44-57`) and limb widths. An off-curve key paired
///   with a signature crafted against the point's *twist* can satisfy those
///   checks and pass the circuit, so natively rejecting it here would be a
///   false reject -- a production outage, per this module's governing
///   asymmetry. The caller must map this to `Verdict::Skipped`, not
///   `Invalid`.
/// - `Failed`: the circuit's own constraints would also reject this --
///   `r`/`s` out of `1..order` (a real `verifyECDSABits` range check), or the
///   signature affirmatively fails to verify. The caller maps this to
///   `Verdict::Invalid`.
///
/// A typed distinction rather than matching on `reason`'s text: the
/// underlying `signature`/`elliptic-curve` crate error strings are not a
/// stable API contract, so string-matching them would be one dependency
/// bump away from silently falling back to the wrong variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EcdsaError {
    Structural(String),
    Failed(String),
}

impl EcdsaError {
    /// The human-readable reason, regardless of variant. `passport.rs`
    /// matches on the variant directly rather than calling this (it needs to
    /// route `Structural` to `Skipped` and `Failed` to `Invalid`, not just
    /// read the message), so this has no caller outside `#[cfg(test)]` --
    /// used by this module's own tests to assert on the reason text without
    /// duplicating the `Structural(s) | Failed(s) => s` match at each call
    /// site.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn message(&self) -> &str {
        match self {
            EcdsaError::Structural(s) | EcdsaError::Failed(s) => s,
        }
    }
}

/// Verifies an ECDSA signature over one of the four NIST curves the
/// deployed circuits use, given the limb-reassembled coordinates and
/// scalars and the signed-attribute digest. `Err` is either a `Structural`
/// failure (cannot determine what the circuit would do -- the caller must
/// map this to `Skipped`) or a `Failed` one (the circuit's own constraints
/// would also reject this -- the caller maps this to `Invalid`); see
/// `EcdsaError`'s doc comment for which is which and why. A false reject
/// here is a production outage; a false accept costs nothing, since the
/// circuit still verifies afterward.
pub fn verify_ecdsa(
    curve: Curve,
    x: &BigUint,
    y: &BigUint,
    r: &BigUint,
    s: &BigUint,
    m_hash: &[u8],
) -> Result<(), EcdsaError> {
    let width = curve.field_bytes();
    let x_bytes = coord_bytes(x, width).map_err(EcdsaError::Structural)?;
    let y_bytes = coord_bytes(y, width).map_err(EcdsaError::Structural)?;
    let r_bytes = coord_bytes(r, width).map_err(EcdsaError::Structural)?;
    let s_bytes = coord_bytes(s, width).map_err(EcdsaError::Structural)?;

    // SEC1 uncompressed point encoding: 0x04 || x || y.
    let mut point = Vec::with_capacity(1 + 2 * width);
    point.push(0x04);
    point.extend_from_slice(&x_bytes);
    point.extend_from_slice(&y_bytes);

    // Concatenated r||s, fed to `Signature::from_slice`. Deliberately not
    // `Signature::from_scalars(r_arr, s_arr)` with fixed-size `[u8; N]`
    // arrays: that requires `[u8; N]: Into<FieldBytes<C>>`, and
    // `generic-array`'s array conversions only cover a fixed list of lengths
    // (..64, 70, 80, ...) that skips 66 -- secp521r1's field width -- so an
    // array-based version would need a curve-specific carve-out just for
    // secp521r1. `from_slice` validates the same "r, s in 1..n" range from a
    // plain byte slice, for any width, uniformly across all four curves.
    let mut rs_bytes = Vec::with_capacity(2 * width);
    rs_bytes.extend_from_slice(&r_bytes);
    rs_bytes.extend_from_slice(&s_bytes);

    match curve {
        Curve::Secp224r1 => {
            let vk = p224::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                .map_err(|e| EcdsaError::Structural(format!("public key is not on the curve: {e}")))?;
            let sig = p224::ecdsa::Signature::from_slice(&rs_bytes)
                .map_err(|e| EcdsaError::Failed(format!("signature scalar out of range: {e}")))?;
            vk.verify_prehash(m_hash, &sig)
                .map_err(|e| EcdsaError::Failed(format!("ECDSA signature does not verify: {e}")))
        }
        Curve::Secp256r1 => {
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                .map_err(|e| EcdsaError::Structural(format!("public key is not on the curve: {e}")))?;
            let sig = p256::ecdsa::Signature::from_slice(&rs_bytes)
                .map_err(|e| EcdsaError::Failed(format!("signature scalar out of range: {e}")))?;
            vk.verify_prehash(m_hash, &sig)
                .map_err(|e| EcdsaError::Failed(format!("ECDSA signature does not verify: {e}")))
        }
        Curve::Secp384r1 => {
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                .map_err(|e| EcdsaError::Structural(format!("public key is not on the curve: {e}")))?;
            let sig = p384::ecdsa::Signature::from_slice(&rs_bytes)
                .map_err(|e| EcdsaError::Failed(format!("signature scalar out of range: {e}")))?;
            vk.verify_prehash(m_hash, &sig)
                .map_err(|e| EcdsaError::Failed(format!("ECDSA signature does not verify: {e}")))
        }
        Curve::Secp521r1 => {
            let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                .map_err(|e| EcdsaError::Structural(format!("public key is not on the curve: {e}")))?;
            let sig = p521::ecdsa::Signature::from_slice(&rs_bytes)
                .map_err(|e| EcdsaError::Failed(format!("signature scalar out of range: {e}")))?;
            vk.verify_prehash(m_hash, &sig)
                .map_err(|e| EcdsaError::Failed(format!("ECDSA signature does not verify: {e}")))
        }
    }
}

#[cfg(test)]
fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    sha2::Sha256::digest(data).to_vec()
}

#[cfg(test)]
fn sha224(data: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    sha2::Sha224::digest(data).to_vec()
}

#[cfg(test)]
fn sha384(data: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    sha2::Sha384::digest(data).to_vec()
}

#[cfg(test)]
fn sha512(data: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    sha2::Sha512::digest(data).to_vec()
}

#[cfg(test)]
fn sha1(data: &[u8]) -> Vec<u8> {
    use sha1::Digest as _;
    sha1::Sha1::digest(data).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    // Signs with the crate's own signer so the test proves verify_ecdsa
    // agrees with an independent implementation of the same standard, then
    // feeds it through the limb representation the circuit actually uses.
    #[test]
    fn a_valid_p256_signature_verifies() {
        use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
        let sk = SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let m_hash = sha256(b"signed attributes");
        let (sig, _): (p256::ecdsa::Signature, _) = sk.sign_prehash(&m_hash).unwrap();
        let pt = sk.verifying_key().to_encoded_point(false);
        let x = BigUint::from_bytes_be(pt.x().unwrap());
        let y = BigUint::from_bytes_be(pt.y().unwrap());
        let r = BigUint::from_bytes_be(&sig.r().to_bytes());
        let s = BigUint::from_bytes_be(&sig.s().to_bytes());
        assert_eq!(verify_ecdsa(Curve::Secp256r1, &x, &y, &r, &s, &m_hash), Ok(()));
    }

    /// Returns (x, y, r, s, m_hash) for a freshly signed P-256 message, in the
    /// big-integer form the circuit's limbs reassemble into.
    fn p256_case() -> (BigUint, BigUint, BigUint, BigUint, Vec<u8>) {
        use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
        let sk = SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let m_hash = sha256(b"signed attributes").to_vec();
        let (sig, _): (p256::ecdsa::Signature, _) = sk.sign_prehash(&m_hash).unwrap();
        let pt = sk.verifying_key().to_encoded_point(false);
        (
            BigUint::from_bytes_be(pt.x().unwrap()),
            BigUint::from_bytes_be(pt.y().unwrap()),
            BigUint::from_bytes_be(&sig.r().to_bytes()),
            BigUint::from_bytes_be(&sig.s().to_bytes()),
            m_hash,
        )
    }

    #[test]
    fn a_tampered_hash_fails() {
        let (x, y, r, s, _) = p256_case();
        let other = sha256(b"different attributes").to_vec();
        let err = verify_ecdsa(Curve::Secp256r1, &x, &y, &r, &s, &other).unwrap_err();
        assert!(
            matches!(err, EcdsaError::Failed(_)),
            "a signature that fails to verify is a Failed error (the circuit rejects it \
             too), not Structural: got {err:?}"
        );
        assert!(err.message().contains("does not verify"), "wrong reason: {err:?}");
    }

    #[test]
    fn a_point_not_on_the_curve_is_skipped_not_failed() {
        // y+1 is not on the curve: must be Err, and specifically Structural --
        // the circuit's own verifyECDSABits never checks curve membership
        // (ecdsa.circom:18-102), so an off-curve key is not something this
        // primitive can prove the circuit would also reject. The caller
        // (passport.rs) maps Structural to Skipped, not Invalid -- this is
        // the fix for the false-reject this fix wave's item 1 closes.
        let (x, y, r, s, m_hash) = p256_case();
        let err = verify_ecdsa(Curve::Secp256r1, &x, &(y + 1u32), &r, &s, &m_hash).unwrap_err();
        assert!(
            matches!(err, EcdsaError::Structural(_)),
            "an off-curve point must be Structural (-> Skipped upstream), not Failed \
             (-> Invalid): got {err:?}"
        );
        assert!(err.message().contains("not on the curve"), "wrong reason: {err:?}");
    }

    #[test]
    fn a_coordinate_wider_than_the_field_is_rejected() {
        // Guards the left-pad in coord_bytes: a value needing more than
        // field_bytes must not be silently truncated into a valid-looking key.
        // Unreachable from real reassembled limbs (see coord_bytes's doc
        // comment) but exercised directly here with a synthetic oversized
        // value, which is exactly why this test can still fail: feed
        // coord_bytes a value under `width` bytes and this assertion breaks.
        let (_, y, r, s, m_hash) = p256_case();
        let too_big = BigUint::from(1u32) << 300;
        let err = verify_ecdsa(Curve::Secp256r1, &too_big, &y, &r, &s, &m_hash).unwrap_err();
        assert!(
            matches!(err, EcdsaError::Structural(_)),
            "an oversized coordinate is Structural, same safe-default reasoning as an \
             off-curve point: got {err:?}"
        );
        assert!(err.message().contains("wider than the field"), "wrong reason: {err:?}");
    }

    // One test per curve, so a curve listed in the params table without a
    // working code path fails here rather than in production. Written out
    // rather than looped: each uses its own crate's signer, and the field
    // widths differ (28 / 32 / 48 / 66 bytes).
    #[test]
    fn p224_round_trips() {
        use p224::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
        let sk = SigningKey::from_slice(&[0x37u8; 28]).unwrap();
        let m_hash = sha224(b"signed attributes").to_vec();
        let (sig, _): (p224::ecdsa::Signature, _) = sk.sign_prehash(&m_hash).unwrap();
        let pt = sk.verifying_key().to_encoded_point(false);
        assert_eq!(
            verify_ecdsa(
                Curve::Secp224r1,
                &BigUint::from_bytes_be(pt.x().unwrap()),
                &BigUint::from_bytes_be(pt.y().unwrap()),
                &BigUint::from_bytes_be(&sig.r().to_bytes()),
                &BigUint::from_bytes_be(&sig.s().to_bytes()),
                &m_hash,
            ),
            Ok(())
        );
    }

    #[test]
    fn p384_round_trips() {
        use p384::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
        let sk = SigningKey::from_slice(&[0x37u8; 48]).unwrap();
        let m_hash = sha384(b"signed attributes").to_vec();
        let (sig, _): (p384::ecdsa::Signature, _) = sk.sign_prehash(&m_hash).unwrap();
        let pt = sk.verifying_key().to_encoded_point(false);
        assert_eq!(
            verify_ecdsa(
                Curve::Secp384r1,
                &BigUint::from_bytes_be(pt.x().unwrap()),
                &BigUint::from_bytes_be(pt.y().unwrap()),
                &BigUint::from_bytes_be(&sig.r().to_bytes()),
                &BigUint::from_bytes_be(&sig.s().to_bytes()),
                &m_hash,
            ),
            Ok(())
        );
    }

    // The two live rows below feed a digest narrower than the curve's field,
    // which routes through RustCrypto's `bits2field` left-pad path (`prehash.
    // len() < FieldBytesSize / 2` is the only case it errors on) -- no
    // fixture or other test exercised this before this fix wave's item 2.
    // Both are comfortably inside the safe range today (20 >= 16, 32 >= 24),
    // but nothing proved that before these two tests.

    #[test]
    fn a_sha1_prehash_verifies_under_p256_alg_7() {
        // alg 7: SHA-1 (20 bytes) under secp256r1's 32-byte field.
        use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
        let sk = SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let m_hash = sha1(b"signed attributes");
        let (sig, _): (p256::ecdsa::Signature, _) = sk.sign_prehash(&m_hash).unwrap();
        let pt = sk.verifying_key().to_encoded_point(false);
        assert_eq!(
            verify_ecdsa(
                Curve::Secp256r1,
                &BigUint::from_bytes_be(pt.x().unwrap()),
                &BigUint::from_bytes_be(pt.y().unwrap()),
                &BigUint::from_bytes_be(&sig.r().to_bytes()),
                &BigUint::from_bytes_be(&sig.s().to_bytes()),
                &m_hash,
            ),
            Ok(())
        );
    }

    #[test]
    fn a_sha256_prehash_verifies_under_p384_alg_23() {
        // alg 23: SHA-256 (32 bytes) under secp384r1's 48-byte field.
        use p384::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
        let sk = SigningKey::from_slice(&[0x37u8; 48]).unwrap();
        let m_hash = sha256(b"signed attributes");
        let (sig, _): (p384::ecdsa::Signature, _) = sk.sign_prehash(&m_hash).unwrap();
        let pt = sk.verifying_key().to_encoded_point(false);
        assert_eq!(
            verify_ecdsa(
                Curve::Secp384r1,
                &BigUint::from_bytes_be(pt.x().unwrap()),
                &BigUint::from_bytes_be(pt.y().unwrap()),
                &BigUint::from_bytes_be(&sig.r().to_bytes()),
                &BigUint::from_bytes_be(&sig.s().to_bytes()),
                &m_hash,
            ),
            Ok(())
        );
    }

    #[test]
    fn p521_round_trips() {
        // p521's `SigningKey`/`VerifyingKey` are hand-rolled wrapper types in
        // the `p521` crate (unlike p224/p256/p384, which are plain aliases
        // over the generic `ecdsa_core` types), so this shape differs in two
        // small ways: `sign_prehash` returns a bare `Signature` rather than
        // the recoverable `(Signature, RecoveryId)` tuple the other three
        // curves support, and the verifying key comes from `VerifyingKey::
        // from(&sk)` rather than a `sk.verifying_key()` method.
        use p521::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};
        // secp521r1's order is a 521-bit number, 7 bits short of this curve's
        // 66-byte (528-bit) field width -- unlike p224/p256/p384, where the
        // field width lines up with the order's bit length exactly. A
        // uniform-looking `[0x37u8; 66]` seed (as the other three curves use)
        // would read as a 526-bit integer, larger than the order, and
        // `from_slice` would reject it as out of range. Zeroing the leading
        // byte keeps the seed under 2^520, comfortably inside the order.
        let mut seed = [0x37u8; 66];
        seed[0] = 0x00;
        let sk = SigningKey::from_slice(&seed).unwrap();
        let m_hash = sha512(b"signed attributes").to_vec();
        let sig: Signature = sk.sign_prehash(&m_hash).unwrap();
        let vk = VerifyingKey::from(&sk);
        let pt = vk.to_encoded_point(false);
        assert_eq!(
            verify_ecdsa(
                Curve::Secp521r1,
                &BigUint::from_bytes_be(pt.x().unwrap()),
                &BigUint::from_bytes_be(pt.y().unwrap()),
                &BigUint::from_bytes_be(&sig.r().to_bytes()),
                &BigUint::from_bytes_be(&sig.s().to_bytes()),
                &m_hash,
            ),
            Ok(())
        );
    }

    #[test]
    fn from_name_maps_the_four_deployed_curves_and_rejects_the_rest() {
        // The params rows Task 2 adds (and the drift assertion over the
        // instance set) key off these exact strings, so a typo here would
        // silently route a deployed algorithm to `None` -- checked against
        // all four, not just one, plus an explicit unknown-name case so this
        // can't pass by only ever exercising the `Some` arm.
        assert_eq!(Curve::from_name("secp224r1"), Some(Curve::Secp224r1));
        assert_eq!(Curve::from_name("secp256r1"), Some(Curve::Secp256r1));
        assert_eq!(Curve::from_name("secp384r1"), Some(Curve::Secp384r1));
        assert_eq!(Curve::from_name("secp521r1"), Some(Curve::Secp521r1));
        assert_eq!(Curve::from_name("brainpoolP256r1"), None);
    }
}
