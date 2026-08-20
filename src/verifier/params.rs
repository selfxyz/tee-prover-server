//! Circuit parameters for `register_kyc` -- the one circuit `dispatch` still
//! routes to a native Rust verifier.
//!
//! Before Plan A, Task 4, this module was a ~1600-line table covering every
//! RSA/RSA-PSS/ECDSA (NIST and brainpool) passport, EU-ID, and DSC circuit,
//! transcribed from the sibling monorepo's own circuit instance files. All of
//! that is gone: `dispatch` no longer needs a `CircuitParams` for any of
//! those circuits at all, since it now hands the circuit name and the raw
//! `input.json` path straight to the JS `signature-verifier` sidecar
//! (`verifier::sidecar`), which does its own parsing on its side of the wire.
//!
//! `register_kyc` is the exception: `kyc.rs` takes a `&CircuitParams` in its
//! `verify` signature (unused inside -- see `kyc::verify`'s `_p` parameter),
//! and `kyc.rs`'s own tests call `lookup("register_kyc")` directly to build
//! one. Both of those call sites are why this module -- and not just its one
//! `register_kyc` row -- survived Task 4's deletion list; see this task's
//! report for the full reasoning.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scheme {
    // KYC signs with EdDSA over BabyJubJub field elements, which has no
    // RSA/ECDSA-style big-integer limb decomposition at all -- see this
    // struct's own `n`/`k` fields' doc comment. This is the only variant
    // left; every other scheme this enum used to carry (`Rsa`, `RsaPss`,
    // `Ecdsa`, `EcdsaBrainpool`) went with the Rust verifiers that
    // constructed them.
    EdDsaBabyJubJub,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitParams {
    pub dg_hash: u32,
    pub econtent_hash: u32,
    pub sig_hash: u32,
    pub scheme: Scheme,
    pub n: u32,
    pub k: u32,
}

/// `register_kyc` is the only name this ever returns `Some` for post-Task 4:
/// `dispatch` calls this once, for its one remaining native-Rust branch, and
/// nothing else in production calls `lookup` at all anymore. Every other
/// circuit name is `None` -- not because it is unknown, but because nothing
/// needs a `CircuitParams` for it any longer.
pub fn lookup(name: &str) -> Option<CircuitParams> {
    // register_kyc.circom instantiates REGISTER_KYC() -- no template
    // arguments at all, so there is no (n, k) to transcribe. 0/0 is an
    // explicit "not applicable" placeholder, not an invented value:
    // kyc::verify never reads dg_hash/econtent_hash/sig_hash/n/k, only
    // `scheme` (indirectly, via the type itself never being constructed
    // for any other scheme here).
    if name == "register_kyc" {
        return Some(CircuitParams {
            dg_hash: 0,
            econtent_hash: 0,
            sig_hash: 0,
            scheme: Scheme::EdDsaBabyJubJub,
            n: 0,
            k: 0,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_kyc_has_a_fixed_placeholder_params_row() {
        let p = lookup("register_kyc").expect("register_kyc must be known");
        assert_eq!(p.scheme, Scheme::EdDsaBabyJubJub);
        assert_eq!(p.n, 0);
        assert_eq!(p.k, 0);
    }

    #[test]
    fn every_other_circuit_name_is_none() {
        // These used to have rows here; now nothing calls lookup for them,
        // since dispatch routes them straight to the sidecar without ever
        // constructing a CircuitParams.
        for name in [
            "register_sha256_sha256_sha256_rsa_65537_4096",
            "register_id_sha1_sha256_sha256_rsa_65537_4096",
            "register_sha256_sha256_sha256_ecdsa_brainpoolP256r1",
            "dsc_sha256_rsa_65537_4096",
            "register_aadhaar",
            "",
            "not_a_real_circuit",
        ] {
            assert_eq!(lookup(name), None, "{name}: expected no CircuitParams row");
        }
    }
}
