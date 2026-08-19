//! Parsing primitives for the input JSON's peculiar encoding: every field
//! (including scalars) is emitted as an array of decimal strings.
//!
//! The governing asymmetry applies here too: every function returns `None` on
//! anything ambiguous, never a best-effort guess. A `None` becomes `Skipped`
//! upstream, never a rejection — so there is no reason to be clever about
//! recovering from malformed input.
//!
//! Plan A, Task 4: `scalar_usize` and `bigint_from_limbs` are gone along with
//! the RSA/ECDSA verifiers that were their only callers (`passport.rs`,
//! `dsc.rs`, `aadhaar.rs`, `primitives::ecdsa`) -- the JS `signature-verifier`
//! sidecar (`verifier::sidecar`) does that parsing now, on its own side of
//! the wire. `field_as_strings` and `bytes_from_decimal_strings` survive
//! because `kyc.rs` still calls them directly.

/// Reads `v[key]` and returns it as a `Vec<String>`, accepting a JSON array of
/// strings (the normal case — even scalars arrive this way, e.g.
/// `"dg1_hash_offset": ["12"]`), a bare string, or a JSON number/array of
/// numbers rendered via `Number::to_string()`.
///
/// The number cases exist because not every real input generator stringifies
/// every field: Aadhaar's `qrDataPaddedLength` and KYC's `data_padded` arrive
/// as genuine JSON numbers (see `new-common/src/documents/aadhaar/qr.ts` and
/// `common/src/utils/kyc/generateInputs.ts`), while passport/EU-ID's builder
/// routes every field through `formatInput`, which stringifies. Without this,
/// those two families skip on every real request.
///
/// Rendering a number via `to_string()` is not lossy leniency: an integer
/// like `1536` becomes `"1536"` and parses downstream exactly as the
/// stringified form would; a non-integer like `5.0` becomes `"5.0"`, which
/// still fails the downstream `parse::<usize>()` / `u8::try_from` — so
/// nothing ambiguous is accepted, only the encoding gap is closed.
///
/// Anything else — missing key, non-string/non-number array elements,
/// objects, bools, null — returns `None`.
pub fn field_as_strings(v: &serde_json::Value, key: &str) -> Option<Vec<String>> {
    match v.get(key)? {
        serde_json::Value::String(s) => Some(vec![s.clone()]),
        serde_json::Value::Number(n) => Some(vec![n.to_string()]),
        serde_json::Value::Array(arr) => arr
            .iter()
            .map(|item| match item {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .collect(),
        _ => None,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_scalar_is_also_accepted() {
        let v: serde_json::Value = serde_json::from_str(r#"{"x":"7"}"#).unwrap();
        assert_eq!(field_as_strings(&v, "x"), Some(vec!["7".to_string()]));
    }

    #[test]
    fn a_bare_json_number_scalar_is_accepted() {
        // Aadhaar's qrDataPaddedLength arrives this way in production: a
        // genuine JSON number, not a string.
        let v: serde_json::Value = serde_json::from_str(r#"{"qrDataPaddedLength":1536}"#).unwrap();
        assert_eq!(field_as_strings(&v, "qrDataPaddedLength"), Some(vec!["1536".to_string()]));
    }

    #[test]
    fn an_array_of_json_numbers_is_accepted() {
        // KYC's data_padded arrives this way in production: a plain
        // number[], not an array of decimal strings.
        let v: serde_json::Value = serde_json::from_str(r#"{"data_padded":[1,2,255]}"#).unwrap();
        assert_eq!(
            field_as_strings(&v, "data_padded"),
            Some(vec!["1".to_string(), "2".to_string(), "255".to_string()])
        );
    }

    #[test]
    fn a_non_integer_json_number_still_fails_the_downstream_byte_parse() {
        // field_as_strings widens what parses, but a float like 5.0 renders
        // as "5.0" and must still fail bytes_from_decimal_strings's
        // parse::<u32>() — nothing ambiguous becomes valid.
        let v: serde_json::Value = serde_json::from_str(r#"{"data_padded":[5.0]}"#).unwrap();
        let items = field_as_strings(&v, "data_padded").expect("number parses to a string form");
        assert_eq!(items, vec!["5.0".to_string()]);
        assert_eq!(bytes_from_decimal_strings(&items), None);
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
    fn missing_key_is_none() {
        let v: serde_json::Value = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(field_as_strings(&v, "nope"), None);
    }
}
