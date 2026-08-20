//! EdDSA-over-BabyJubJub verification, circomlib-compatible via
//! `babyjubjub_rs::verify`.
//!
//! Two details this module exists to get right:
//!
//! - `s`, `R`, `pubKey` arrive from the circuit's witness JSON as plain
//!   decimal strings — field elements, not RSA-style limbs and not bytes.
//!   `babyjubjub_rs::Fr` (an alias for `poseidon_rs::Fr`) does *not* round-trip
//!   through `Display`/`FromStr`/`.to_string()`: its `Display` impl renders as
//!   `Fr(0x...)`, not plain decimal digits, so `.to_string()` does not give
//!   `Fr::from_str` the digits it needs. The correct round-trip is the crate's
//!   own `ff_ce::{to_hex, from_hex}` pair — the same one `babyjubjub_rs` uses
//!   internally (see its `Point::compress` and free `verify` function, both of
//!   which go through `to_hex`, never `Display`).
//! - `babyjubjub-rs` exposes no on-curve check. `register_kyc.circom:25-33`
//!   runs circomlib's `BabyCheck` on both `R` and `pubKey` before verifying
//!   the signature; `point_on_curve` below is that same equation
//!   (`a*x^2 + y^2 == 1 + d*x^2*y^2 (mod p)`, `a = 168700`, `d = 168696`)
//!   implemented directly over `BigUint`, needing no dependency beyond
//!   `num-bigint`, already in use throughout this crate.

use num_bigint::BigUint;
use num_traits::One;

/// BabyJubJub's base field modulus — the same BN254 scalar-field order
/// `light-poseidon`/`ark-bn254` and `babyjubjub-rs` both use.
fn modulus() -> BigUint {
    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
        .parse()
        .expect("valid modulus literal")
}

/// Converts an already-parsed field element into `babyjubjub_rs::Fr`, via
/// hex — `Fr::from_repr` (which `from_hex` calls) rejects anything at or
/// above the field modulus, so an out-of-range value returns `None` here
/// rather than silently wrapping.
pub fn fr_from_biguint(v: &BigUint) -> Option<babyjubjub_rs::Fr> {
    let mut hex = v.to_str_radix(16);
    if hex.len() % 2 != 0 {
        hex.insert(0, '0');
    }
    ff_ce::from_hex::<babyjubjub_rs::Fr>(&hex).ok()
}

/// Inverse of `fr_from_biguint`, for building self-consistent test fixtures
/// that need to serialize a signed `Fr` back into the decimal-string form the
/// circuit input JSON uses.
///
/// Used only by `verifier::testkit` (`#[cfg(test)]`), so a non-test build
/// has no caller for it.
#[cfg_attr(not(test), allow(dead_code))]
pub fn fr_to_decimal(fr: &babyjubjub_rs::Fr) -> String {
    let hex = ff_ce::to_hex(fr);
    BigUint::parse_bytes(hex.as_bytes(), 16)
        .expect("ff_ce::to_hex always produces valid hex")
        .to_string()
}

/// circomlib's `BabyCheck`: true iff `(x, y)` lies on the twisted-Edwards
/// BabyJubJub curve, `a*x^2 + y^2 == 1 + d*x^2*y^2 (mod p)`.
pub fn point_on_curve(x: &BigUint, y: &BigUint) -> bool {
    let p = modulus();
    let a = BigUint::from(168700u32);
    let d = BigUint::from(168696u32);
    let x2 = (x * x) % &p;
    let y2 = (y * y) % &p;
    let lhs = (&a * &x2 + &y2) % &p;
    let rhs = (BigUint::one() + (&d * &x2 * &y2) % &p) % &p;
    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generator_point_is_on_curve() {
        // babyjubjub-rs's own B8 base point.
        let x: BigUint = "5299619240641551281634865583518297030282874472190772894086521144482721001553"
            .parse()
            .unwrap();
        let y: BigUint = "16950150798460657717958625567821834550301663161624707787222815936182638968203"
            .parse()
            .unwrap();
        assert!(point_on_curve(&x, &y));
    }

    #[test]
    fn arbitrary_coordinates_are_not_on_curve() {
        assert!(!point_on_curve(&BigUint::from(12345u32), &BigUint::from(6789u32)));
    }

    #[test]
    fn fr_round_trips_through_decimal() {
        let v: BigUint = "14422859473778768188622151430526693594403470008420308922992775064941455773685"
            .parse()
            .unwrap();
        let fr = fr_from_biguint(&v).expect("in-range field element");
        assert_eq!(fr_to_decimal(&fr), v.to_string());
    }

    #[test]
    fn a_value_at_or_above_the_modulus_does_not_parse() {
        assert!(fr_from_biguint(&modulus()).is_none());
    }
}
