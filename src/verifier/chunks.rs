//! Parsing primitives for the input JSON's peculiar encoding: every field
//! (including scalars) is emitted as an array of decimal strings, and
//! multi-limb big integers are encoded little-endian in base `2^n`.
//!
//! The governing asymmetry applies here too: every function returns `None` on
//! anything ambiguous, never a best-effort guess. A `None` becomes `Skipped`
//! upstream, never a rejection — so there is no reason to be clever about
//! recovering from malformed input.

use num_bigint::BigUint;

/// Reads `v[key]` and returns it as a `Vec<String>`, accepting either a JSON
/// array of strings (the normal case — even scalars arrive this way, e.g.
/// `"dg1_hash_offset": ["12"]`) or a bare string (returned as a one-element
/// vec). Anything else — missing key, non-string array elements, numbers,
/// objects — returns `None`.
pub fn field_as_strings(v: &serde_json::Value, key: &str) -> Option<Vec<String>> {
    match v.get(key)? {
        serde_json::Value::String(s) => Some(vec![s.clone()]),
        serde_json::Value::Array(arr) => arr
            .iter()
            .map(|item| match item {
                serde_json::Value::String(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

/// Reads a scalar field: exactly one decimal-string element, parsed as a
/// `usize`. `None` if the field is absent, has more than one element, or
/// doesn't parse.
pub fn scalar_usize(v: &serde_json::Value, key: &str) -> Option<usize> {
    let items = field_as_strings(v, key)?;
    if items.len() != 1 {
        return None;
    }
    items[0].parse::<usize>().ok()
}

/// Parses a list of decimal strings as bytes. Every element must be a valid
/// decimal number in `0..=255`; anything else (non-numeric, negative, or
/// `>255`) makes the whole call return `None` rather than truncate or wrap.
pub fn bytes_from_decimal_strings(items: &[String]) -> Option<Vec<u8>> {
    items
        .iter()
        .map(|s| s.parse::<u32>().ok().and_then(|v| u8::try_from(v).ok()))
        .collect()
}

/// Reassembles a big integer from little-endian base-`2^n` limbs (decimal
/// strings): `limbs[0] + limbs[1] * 2^n + limbs[2] * 2^(2n) + ...`.
///
/// `n == 0` is rejected explicitly rather than relying on the mask/modulus
/// arithmetic to happen to reject every nonzero limb. `n == 0` has no
/// meaningful limb layout — it is the placeholder `CircuitParams` carries for
/// `register_kyc` (EdDSA over BabyJubJub has no RSA-style limb decomposition;
/// its fields are parsed as field elements directly, never through this
/// function). If a caller ever passes it here anyway, this must fail loudly
/// and on purpose, not by accident.
///
/// Any limb at or above `2^n`, or that fails to parse as an unsigned decimal
/// integer, makes the whole call return `None`.
pub fn bigint_from_limbs(limbs: &[String], n: u32) -> Option<BigUint> {
    if n == 0 {
        return None;
    }
    let modulus = BigUint::from(2u32).pow(n);
    let mut result = BigUint::from(0u32);
    let mut multiplier = BigUint::from(1u32);
    for limb in limbs {
        let val: BigUint = limb.parse().ok()?;
        if val >= modulus {
            return None;
        }
        result += &val * &multiplier;
        multiplier *= &modulus;
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_fields_arrive_as_single_element_arrays() {
        let v: serde_json::Value = serde_json::from_str(r#"{"dg1_hash_offset":["12"]}"#).unwrap();
        assert_eq!(scalar_usize(&v, "dg1_hash_offset"), Some(12));
    }

    #[test]
    fn a_bare_scalar_is_also_accepted() {
        let v: serde_json::Value = serde_json::from_str(r#"{"x":"7"}"#).unwrap();
        assert_eq!(scalar_usize(&v, "x"), Some(7));
    }

    #[test]
    fn byte_arrays_parse_from_decimal_not_hex() {
        let items = vec!["255".to_string(), "16".to_string(), "0".to_string()];
        assert_eq!(bytes_from_decimal_strings(&items), Some(vec![0xff, 0x10, 0x00]));
    }

    #[test]
    fn a_value_above_255_is_not_a_byte() {
        assert_eq!(bytes_from_decimal_strings(&["256".to_string()]), None);
    }

    #[test]
    fn limbs_reassemble_little_endian_base_2n() {
        // n = 8, limbs [1, 2] => 1 + 2*256 = 513
        let limbs = vec!["1".to_string(), "2".to_string()];
        assert_eq!(bigint_from_limbs(&limbs, 8), Some(num_bigint::BigUint::from(513u32)));
    }

    #[test]
    fn a_limb_at_or_above_2n_is_rejected() {
        assert_eq!(bigint_from_limbs(&["256".to_string()], 8), None);
    }

    #[test]
    fn n_equal_zero_is_explicitly_rejected() {
        // register_kyc's (0, 0) placeholder has no limb layout at all. This must
        // fail on purpose, not by lucky accident of the modulus arithmetic.
        assert_eq!(bigint_from_limbs(&["0".to_string()], 0), None);
    }
}
