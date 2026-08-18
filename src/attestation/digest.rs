use alloy_primitives::{keccak256, U256};
use alloy_sol_types::SolValue;

use crate::db::Proof;

fn parse(values: &[String]) -> Result<Vec<U256>, String> {
    values
        .iter()
        .map(|v| U256::from_str_radix(v, 10).map_err(|e| format!("bad field element {v}: {e}")))
        .collect()
}

fn fixed2(values: &[String], what: &str) -> Result<[U256; 2], String> {
    let parsed = parse(values)?;
    if parsed.len() != 2 {
        return Err(format!("{what} must have exactly 2 elements, got {}", parsed.len()));
    }
    Ok([parsed[0], parsed[1]])
}

/// keccak256(abi.encode(uint256[2], uint256[2][2], uint256[2], uint256[]))
///
/// Matches what a Solidity verifier reconstructs from the proof it already receives,
/// so `ecrecover(digest, sig)` on-chain yields the enclave address.
pub fn proof_digest(proof: &Proof, public_inputs: &[String]) -> Result<[u8; 32], String> {
    let a = fixed2(&proof.pi_a, "pi_a")?;
    if proof.pi_b.len() != 2 {
        return Err(format!("pi_b must have exactly 2 rows, got {}", proof.pi_b.len()));
    }
    let b = [fixed2(&proof.pi_b[0], "pi_b[0]")?, fixed2(&proof.pi_b[1], "pi_b[1]")?];
    let c = fixed2(&proof.pi_c, "pi_c")?;
    let inputs = parse(public_inputs)?;

    let encoded = (a, b, c, inputs).abi_encode_params();
    Ok(*keccak256(encoded))
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

    #[test]
    fn rejects_malformed_proof() {
        let (mut p, pi) = sample();
        p.pi_a = vec!["1".into()]; // must be exactly 2 elements
        assert!(proof_digest(&p, &pi).is_err());
    }
}
