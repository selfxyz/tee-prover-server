use serde::{Deserialize, Serialize};
use sqlx::types::chrono::Utc;

use crate::{
    types::{EndpointType, ProofType},
    utils::get_tmp_folder_path,
};
pub mod types;

type PublicInputs = Vec<String>;

pub async fn create_proof_status(
    uuid: uuid::Uuid,
    proof_type: &ProofType,
    circuit_name: &str,
    on_chain: bool,
    db: &sqlx::Pool<sqlx::Postgres>,
    endpoint_type: Option<&EndpointType>,
    endpoint: Option<&String>,
    version: i32,
    user_defined_data: &str,
    self_defined_data: &str,
) -> Result<(), String> {
    let proof_type_id: i32 = proof_type.into();
    let now = Utc::now();

    let status: i32 = types::Status::Pending.into();

    let _ = sqlx::query(
        "INSERT INTO proofs (proof_type, request_id, status, created_at, circuit_name, onchain, endpoint_type, endpoint, version, user_defined_data, self_defined_data) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(proof_type_id)
    .bind(sqlx::types::Uuid::from(uuid))
    .bind(status)
    .bind(now)
    .bind(circuit_name)
    .bind(on_chain)
    .bind(endpoint_type.map(|e| serde_plain::to_string(e).unwrap()))
    .bind(endpoint)
    .bind(version)
    .bind(user_defined_data)
    .bind(self_defined_data)
    .execute(db)
    .await.map_err(|e| {
        dbg!(e);
        return "Could not create the record";
    })?;

    Ok(())
}

pub async fn set_witness_generated(
    uuid: uuid::Uuid,
    db: &sqlx::Pool<sqlx::Postgres>,
) -> Result<(), sqlx::Error> {
    let status: i32 = types::Status::WitnessGenerated.into();
    let now = Utc::now();

    match sqlx::query(&format!(
        "UPDATE proofs SET status = $1, witness_generated_at = $2 WHERE request_id = $3",
    ))
    .bind(status)
    .bind(now)
    .bind(sqlx::types::Uuid::from(uuid))
    .execute(db)
    .await
    {
        Ok(_) => Ok(()),
        Err(e) => {
            dbg!(&e);
            return Err(e);
        }
    }
}

/// Reads and parses the `proof.json`/`public_inputs.json` this request's
/// rapidsnark run produced. This is the single reader for those two files:
/// every caller that needs the parsed proof output (attestation bootstrap,
/// enclave signing, and this row's own persistence) must go through this
/// function rather than re-reading the files independently. A client-supplied
/// uuid means the tmp folder is not guaranteed exclusive to one in-flight
/// request; two independent reads of the same folder can observe different
/// bytes if a second pipeline's output lands between them. Reading once and
/// threading the parsed values through the caller closes that gap.
pub async fn read_proof_output(uuid: uuid::Uuid) -> Result<(Proof, PublicInputs), String> {
    let tmp = get_tmp_folder_path(&uuid.to_string());
    let proof_file_path = std::path::Path::new(&tmp).join("proof.json");
    let public_inputs_file_path = std::path::Path::new(&tmp).join("public_inputs.json");

    let proof_string = match tokio::fs::read_to_string(&proof_file_path).await {
        Ok(proof_string) => proof_string,
        Err(e) => {
            dbg!(&e);
            return Err(format!(
                "Could not read proof from path: {}",
                proof_file_path.display(),
            ));
        }
    };

    let public_inputs_string = match tokio::fs::read_to_string(&public_inputs_file_path).await {
        Ok(public_inputs_string) => public_inputs_string,
        Err(e) => {
            dbg!(&e);
            return Err(format!(
                "Could not read public inputs from path: {}",
                public_inputs_file_path.display(),
            ));
        }
    };

    let mut proof_reader = serde_json::de::Deserializer::from_str(&proof_string);

    let proof = match Proof::deserialize(&mut proof_reader) {
        Ok(proof) => proof,
        Err(e) => {
            return Err(format!("Could not deserialize proof: {}", e));
        }
    };

    let mut public_inputs_reader = serde_json::de::Deserializer::from_str(&public_inputs_string);

    let public_inputs = match PublicInputs::deserialize(&mut public_inputs_reader) {
        Ok(public_inputs) => public_inputs,
        Err(e) => {
            return Err(format!("Could not deserialize public inputs: {}", e));
        }
    };

    // Normalised here, at the single reader both the attestation bootstrap and the
    // proof pipeline share, so no consumer has to know the prover's wire shape.
    let proof = to_affine(proof)?;

    Ok((proof, public_inputs))
}

/// Drops the projective coordinate rapidsnark and snarkjs append to a Groth16
/// proof, leaving the affine form every consumer here expects.
///
/// A prover writes `pi_a`/`pi_c` as `[x, y, "1"]` and `pi_b` as
/// `[[..], [..], ["1", "0"]]` -- the trailing entry is the homogeneous
/// coordinate, not part of the point. Solidity verifiers take
/// `uint256[2]` / `uint256[2][2]`, and `attestation::digest::proof_digest`
/// encodes exactly those shapes, so the extra element made every real proof
/// fail with `pi_a must have exactly 2 elements, got 3` -- on the attestation
/// self-check in `bootstrap` and, identically, on `sign_proof` for every proof
/// the server produces.
///
/// The trailing values are asserted rather than blindly truncated. A proof
/// whose third coordinate is anything but the identity is not a proof this
/// code has understood, and silently discarding it would sign a point that
/// differs from the one the prover computed.
fn to_affine(proof: Proof) -> Result<Proof, String> {
    fn affine_point(mut v: Vec<String>, what: &str) -> Result<Vec<String>, String> {
        match v.len() {
            2 => Ok(v),
            3 => {
                let z = v.pop().expect("length checked");
                if z != "1" {
                    return Err(format!(
                        "{what} has a non-identity projective coordinate {z:?}; expected \"1\""
                    ));
                }
                Ok(v)
            }
            n => Err(format!("{what} must have 2 or 3 elements, got {n}")),
        }
    }

    let pi_a = affine_point(proof.pi_a, "pi_a")?;
    let pi_c = affine_point(proof.pi_c, "pi_c")?;

    let mut pi_b = proof.pi_b;
    match pi_b.len() {
        2 => {}
        3 => {
            let z = pi_b.pop().expect("length checked");
            if z != ["1".to_string(), "0".to_string()] {
                return Err(format!(
                    "pi_b has a non-identity projective row {z:?}; expected [\"1\", \"0\"]"
                ));
            }
        }
        n => return Err(format!("pi_b must have 2 or 3 rows, got {n}")),
    }
    for (i, row) in pi_b.iter().enumerate() {
        if row.len() != 2 {
            return Err(format!("pi_b[{i}] must have 2 elements, got {}", row.len()));
        }
    }

    Ok(Proof { pi_a, pi_b, pi_c, protocol: proof.protocol })
}

pub async fn update_proof(
    uuid: uuid::Uuid,
    db: &sqlx::Pool<sqlx::Postgres>,
    proof: &Proof,
    public_inputs: &PublicInputs,
    signature: &str,
) -> Result<(), String> {
    let status: i32 = types::Status::ProofGenererated.into();

    let now = Utc::now();
    match sqlx::query(
        "UPDATE proofs SET proof = $1, status = $2, proof_generated_at = $3, public_inputs = $4, signature = $5 WHERE request_id = $6",
    )
    .bind(sqlx::types::Json(proof))
    .bind(status)
    .bind(now)
    .bind(public_inputs)
    .bind(signature)
    .bind(sqlx::types::uuid::Uuid::from(uuid))
    .execute(db)
    .await
    {
        Ok(_) => Ok(()),
        Err(e) => {
            return Err(format!("Could not update proof: {}", e));
        }
    }
}

/// The exact query `record_precheck` runs. Pulled out to a constant so
/// `record_precheck_never_inserts` can assert directly on the SQL text
/// without a live database: an `UPDATE` keyed on `request_id` can only ever
/// touch a row `create_proof_status` already inserted for real traffic, so a
/// circuit that received no requests can never acquire a row through this
/// path -- "no traffic" and "everything skipped" stay distinguishable by
/// construction, not by a query-time filter.
const RECORD_PRECHECK_QUERY: &str =
    "UPDATE proofs SET precheck_verdict = $1, precheck_reason = $2 WHERE request_id = $3";

/// Persists the signature pre-check's verdict to the request's existing
/// `proofs` row. Written on every path `verify_inputs` can return, including
/// a `valid` verdict and a rejection -- there is no branch that leaves this
/// unset for a request that actually reached the pre-check.
///
/// Deliberately off the critical path: the caller in `main.rs` logs and
/// continues on `Err`, exactly like every other DB write in this module. A
/// database blip must never turn a `valid` verdict into a rejection --
/// that matters more, not less, once a verdict can gate enforcement.
pub async fn record_precheck(
    uuid: uuid::Uuid,
    verdict: &crate::verifier::Verdict,
    db: &sqlx::Pool<sqlx::Postgres>,
) -> Result<(), sqlx::Error> {
    let code: i32 = types::PrecheckVerdict::from(verdict).into();
    let reason: Option<String> = match verdict {
        crate::verifier::Verdict::Valid => None,
        crate::verifier::Verdict::Invalid(reason) | crate::verifier::Verdict::Skipped(reason) => {
            Some(reason.clone())
        }
    };

    match sqlx::query(RECORD_PRECHECK_QUERY)
        .bind(code)
        .bind(reason)
        .bind(sqlx::types::Uuid::from(uuid))
        .execute(db)
        .await
    {
        Ok(_) => Ok(()),
        Err(e) => {
            dbg!(&e);
            Err(e)
        }
    }
}

pub async fn fail_proof(
    uuid: uuid::Uuid,
    db: &sqlx::Pool<sqlx::Postgres>,
    reason: String,
) -> Result<(), sqlx::Error> {
    let status: i32 = types::Status::Failed.into();
    match sqlx::query("UPDATE proofs SET status = $1, reason = $2 WHERE request_id = $3")
        .bind(status)
        .bind(reason)
        .bind(sqlx::types::Uuid::from(uuid))
        .execute(db)
        .await
    {
        Ok(_) => Ok(()),
        Err(e) => {
            dbg!(&e);
            return Err(e);
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Proof {
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
    pub protocol: String,
}

#[cfg(test)]
mod affine_tests {
    use super::*;

    fn snarkjs_shaped() -> Proof {
        // Exactly what rapidsnark/snarkjs write: a trailing projective coordinate
        // on pi_a and pi_c, and a trailing ["1","0"] row on pi_b.
        Proof {
            pi_a: vec!["11".into(), "22".into(), "1".into()],
            pi_b: vec![
                vec!["31".into(), "32".into()],
                vec!["41".into(), "42".into()],
                vec!["1".into(), "0".into()],
            ],
            pi_c: vec!["51".into(), "52".into(), "1".into()],
            protocol: "groth16".into(),
        }
    }

    #[test]
    fn a_prover_shaped_proof_becomes_affine() {
        let p = to_affine(snarkjs_shaped()).expect("must normalise");
        assert_eq!(p.pi_a, vec!["11".to_string(), "22".to_string()]);
        assert_eq!(p.pi_c, vec!["51".to_string(), "52".to_string()]);
        assert_eq!(p.pi_b.len(), 2);
        assert_eq!(p.pi_b[1], vec!["41".to_string(), "42".to_string()]);
    }

    #[test]
    fn an_already_affine_proof_is_unchanged() {
        let mut p = snarkjs_shaped();
        p.pi_a.pop();
        p.pi_c.pop();
        p.pi_b.pop();
        let (a, b, c) = (p.pi_a.clone(), p.pi_b.clone(), p.pi_c.clone());
        let out = to_affine(p).expect("must accept affine input");
        assert_eq!(out.pi_a, a);
        assert_eq!(out.pi_b, b);
        assert_eq!(out.pi_c, c);
    }

    /// The trailing coordinate is asserted, not assumed. A point whose third
    /// coordinate is not the identity has not been understood, and truncating it
    /// would sign a different point than the prover computed.
    #[test]
    fn a_non_identity_projective_coordinate_is_rejected() {
        let mut p = snarkjs_shaped();
        p.pi_a = vec!["11".into(), "22".into(), "7".into()];
        let err = to_affine(p).unwrap_err();
        assert!(err.contains("non-identity projective coordinate"), "got: {err}");

        let mut q = snarkjs_shaped();
        q.pi_b[2] = vec!["9".into(), "0".into()];
        let err = to_affine(q).unwrap_err();
        assert!(err.contains("non-identity projective row"), "got: {err}");
    }

    #[test]
    fn a_wrong_length_point_is_rejected() {
        let mut p = snarkjs_shaped();
        p.pi_a = vec!["11".into()];
        assert!(to_affine(p).unwrap_err().contains("must have 2 or 3 elements"));

        let mut q = snarkjs_shaped();
        q.pi_b = vec![vec!["1".into(), "2".into()]];
        assert!(to_affine(q).unwrap_err().contains("must have 2 or 3 rows"));
    }

    /// The end-to-end point: a prover-shaped proof must survive the digest that
    /// bootstrap and sign_proof both run. Before normalisation this failed with
    /// "pi_a must have exactly 2 elements, got 3", which is what crash-looped the
    /// enclave on every boot.
    #[test]
    fn a_normalised_proof_digests_cleanly() {
        let p = to_affine(snarkjs_shaped()).expect("must normalise");
        crate::attestation::digest::proof_digest(&p, &vec!["7".to_string()])
            .expect("digest must accept a normalised prover proof");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// There is no live Postgres in this crate's test environment (CI's
    /// `cargo test --bin tee-server` runs with no database service, and
    /// there is no test harness elsewhere in this module that stands one
    /// up), so "a circuit with no traffic has no rows" cannot be exercised
    /// as a live round trip here. What CAN be pinned without a database is
    /// the property that actually guarantees it: `record_precheck` only
    /// ever executes an `UPDATE ... WHERE request_id = $3`, never an
    /// `INSERT`. The only statement that inserts a `proofs` row at all is
    /// `create_proof_status`, called once per submitted request -- so a
    /// circuit that received zero requests has zero rows to update, and
    /// this query cannot manufacture one. If this ever became an upsert
    /// (`INSERT ... ON CONFLICT`) or a bare `INSERT`, that guarantee would
    /// silently break; this test fails loudly if it does.
    #[test]
    fn record_precheck_never_inserts() {
        let normalized = RECORD_PRECHECK_QUERY.to_uppercase();
        assert!(
            normalized.trim_start().starts_with("UPDATE"),
            "record_precheck's query must be an UPDATE, not: {RECORD_PRECHECK_QUERY}"
        );
        assert!(
            !normalized.contains("INSERT"),
            "record_precheck's query must never insert a row -- a circuit with \
             no traffic must have no rows, and only create_proof_status may \
             insert one: {RECORD_PRECHECK_QUERY}"
        );
        assert!(
            normalized.contains("WHERE REQUEST_ID"),
            "record_precheck must be keyed on request_id, the same key \
             create_proof_status inserts under: {RECORD_PRECHECK_QUERY}"
        );
    }
}
