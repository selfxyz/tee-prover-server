use alloy_primitives::{keccak256, U256};
use alloy_sol_types::SolValue;

use crate::db::Proof;

fn parse(values: &[String]) -> Result<Vec<U256>, String> {
    values
        .iter()
        .map(|v| {
            // `U256::from_str_radix` delegates to ruint's `from_base_be`, which folds
            // over the input's digits and therefore returns ZERO for an empty digit
            // iterator. An empty (or whitespace-only) field element would otherwise
            // parse to 0 and produce a wrong-but-plausible digest instead of an error
            // — the one outcome this encoder must never have, since the digest is
            // pinned and a bad one yields a signature nothing can verify.
            if v.trim().is_empty() {
                return Err(format!("bad field element {v:?}: empty"));
            }
            U256::from_str_radix(v, 10).map_err(|e| format!("bad field element {v}: {e}"))
        })
        .collect()
}

fn fixed2(values: &[String], what: &str) -> Result<[U256; 2], String> {
    let parsed = parse(values)?;
    if parsed.len() != 2 {
        return Err(format!("{what} must have exactly 2 elements, got {}", parsed.len()));
    }
    Ok([parsed[0], parsed[1]])
}

/// abi.encode(uint256[2], uint256[2][2], uint256[2], uint256[])
///
/// Split out from `proof_digest` so tests can assert the intermediate ABI-encoded bytes
/// directly against `cast abi-encode` output, localizing any future break to the encoder
/// rather than leaving it ambiguous between encoder and hasher.
fn encode(proof: &Proof, public_inputs: &[String]) -> Result<Vec<u8>, String> {
    let a = fixed2(&proof.pi_a, "pi_a")?;
    if proof.pi_b.len() != 2 {
        return Err(format!("pi_b must have exactly 2 rows, got {}", proof.pi_b.len()));
    }
    let b = [fixed2(&proof.pi_b[0], "pi_b[0]")?, fixed2(&proof.pi_b[1], "pi_b[1]")?];
    let c = fixed2(&proof.pi_c, "pi_c")?;
    let inputs = parse(public_inputs)?;

    Ok((a, b, c, inputs).abi_encode_params())
}

/// keccak256(abi.encode(uint256[2], uint256[2][2], uint256[2], uint256[]))
///
/// Matches what a Solidity verifier reconstructs from the proof it already receives,
/// so `ecrecover(digest, sig)` on-chain yields the enclave address.
pub fn proof_digest(proof: &Proof, public_inputs: &[String]) -> Result<[u8; 32], String> {
    Ok(*keccak256(encode(proof, public_inputs)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Proof;

    fn sample() -> (Proof, Vec<String>) {
        (
            Proof {
                pi_a: vec!["1".into(), "2".into()],
                pi_b: vec![vec!["3".into(), "4".into()], vec!["5".into(), "6".into()]],
                pi_c: vec!["7".into(), "8".into()],
                protocol: "groth16".into(),
            },
            vec!["9".into(), "10".into()],
        )
    }

    #[test]
    fn digest_is_stable() {
        let (p, pi) = sample();
        let a = proof_digest(&p, &pi).unwrap();
        let b = proof_digest(&p, &pi).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn digest_changes_with_public_inputs() {
        let (p, pi) = sample();
        let mut other = pi.clone();
        other[0] = "11".into();
        assert_ne!(proof_digest(&p, &pi).unwrap(), proof_digest(&p, &other).unwrap());
    }

    /// An empty field element must be an error, not a silent 0. Without the
    /// explicit guard in `parse`, ruint's `from_base_be` returns ZERO over an
    /// empty digit iterator, so `""` would encode as 0 and yield a digest that
    /// looks valid but signs the wrong object.
    #[test]
    fn rejects_empty_field_elements() {
        for blank in ["", " ", "\t", "\n"] {
            let (mut p, pi) = sample();
            p.pi_a = vec![blank.into(), "2".into()];
            assert!(
                proof_digest(&p, &pi).is_err(),
                "empty pi_a element {blank:?} must be rejected, not parsed as 0"
            );

            let (mut p, pi) = sample();
            p.pi_b[1] = vec!["5".into(), blank.into()];
            assert!(
                proof_digest(&p, &pi).is_err(),
                "empty pi_b element {blank:?} must be rejected, not parsed as 0"
            );

            let (p, mut pi) = sample();
            pi[0] = blank.into();
            assert!(
                proof_digest(&p, &pi).is_err(),
                "empty public input {blank:?} must be rejected, not parsed as 0"
            );
        }
    }

    /// Pins the reason the guard exists: an empty element must NOT hash to the
    /// same digest as an explicit "0", which is what the unguarded parse did.
    #[test]
    fn empty_field_element_does_not_alias_zero() {
        let (mut p, pi) = sample();
        p.pi_a = vec!["0".into(), "2".into()];
        let zero_digest = proof_digest(&p, &pi).expect("explicit 0 is a valid field element");

        let (mut q, pi2) = sample();
        q.pi_a = vec!["".into(), "2".into()];
        match proof_digest(&q, &pi2) {
            Ok(d) => panic!("empty element produced digest {d:?} (aliasing {zero_digest:?})"),
            Err(e) => assert!(e.contains("empty"), "unexpected error: {e}"),
        }
    }

    #[test]
    fn rejects_malformed_proof() {
        let (mut p, pi) = sample();
        p.pi_a = vec!["1".into()]; // must be exactly 2 elements
        assert!(proof_digest(&p, &pi).is_err());
    }

    // Ground truth generated with Foundry's `cast` against the exact `sample()` vector above
    // (pi_a = [1,2], pi_b = [[3,4],[5,6]], pi_c = [7,8], public_inputs = [9,10]):
    //
    //   cast abi-encode "f(uint256[2],uint256[2][2],uint256[2],uint256[])" \
    //     "[1,2]" "[[3,4],[5,6]]" "[7,8]" "[9,10]"
    //   # => 0x0000...0001 0000...0002 0000...0003 0000...0004 0000...0005 0000...0006
    //   #    0000...0007 0000...0008 0000...0120 0000...0002 0000...0009 000...000a
    //   # (8 static head words, then the dynamic tail's offset/length/elements)
    //
    //   cast keccak <that encoding>
    //   # => 0x5696f3225b77a4372d8d3d26e9c8beda1239a2be61d8e50c15f00494c73aa745
    //
    // Regenerate both commands to refresh these constants if this test ever needs updating.
    //
    // THIS VALUE IS PINNED. It is the exact preimage/digest a Solidity verifier reconstructs
    // and feeds to `ecrecover`. Changing the encoding (and therefore this constant) invalidates
    // every attestation signature ever stored — do not "fix" a failing assertion here without
    // first confirming Solidity's `abi.encode` semantics actually changed.
    #[test]
    fn matches_solidity_abi_encode_ground_truth() {
        let (p, pi) = sample();

        let expected_encoded = hex::decode(concat!(
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "0000000000000000000000000000000000000000000000000000000000000004",
            "0000000000000000000000000000000000000000000000000000000000000005",
            "0000000000000000000000000000000000000000000000000000000000000006",
            "0000000000000000000000000000000000000000000000000000000000000007",
            "0000000000000000000000000000000000000000000000000000000000000008",
            "0000000000000000000000000000000000000000000000000000000000000120",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000009",
            "000000000000000000000000000000000000000000000000000000000000000a",
        ))
        .unwrap();

        let actual_encoded = encode(&p, &pi).unwrap();
        assert_eq!(
            actual_encoded, expected_encoded,
            "ABI encoding diverged from Solidity's abi.encode ground truth"
        );

        let expected_digest =
            hex::decode("5696f3225b77a4372d8d3d26e9c8beda1239a2be61d8e50c15f00494c73aa745")
                .unwrap();
        let actual_digest = proof_digest(&p, &pi).unwrap();
        assert_eq!(
            actual_digest.as_slice(),
            expected_digest.as_slice(),
            "digest diverged from Solidity ecrecover ground truth (pinned — see comment above)"
        );
    }
}
