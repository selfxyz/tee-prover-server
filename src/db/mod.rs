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

pub async fn update_proof(uuid: uuid::Uuid, db: &sqlx::Pool<sqlx::Postgres>) -> Result<(), String> {
    let proof_file_path =
        std::path::Path::new(&get_tmp_folder_path(&uuid.to_string())).join("proof.json");
    let public_inputs_file_path =
        std::path::Path::new(&get_tmp_folder_path(&uuid.to_string())).join("public_inputs.json");

    //remove the unwrap here later
    let proof_string = match std::fs::read_to_string(&proof_file_path) {
        Ok(proof_string) => proof_string,
        Err(e) => {
            dbg!(&e);
            return Err(format!(
                "Could not read proof from path: {}",
                proof_file_path.display(),
            ));
        }
    };

    let public_inputs_string = match std::fs::read_to_string(&public_inputs_file_path) {
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

    let status: i32 = types::Status::ProofGenererated.into();

    let now = Utc::now();
    match sqlx::query(
        "UPDATE proofs SET proof = $1, status = $2, proof_generated_at = $3, public_inputs = $4  WHERE request_id = $5",
    )
    .bind(sqlx::types::Json(proof))
    .bind(status)
    .bind(now)
    .bind(public_inputs)
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
struct Proof {
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
    protocol: String,
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
