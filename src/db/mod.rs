use alloy_primitives::keccak256;
use alloy_signer::{Signature, SignerSync};
use alloy_signer_local::PrivateKeySigner;
use num_bigint::BigUint;
use num_traits::Num;

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
) -> Result<(), String> {
    let proof_type_id: i32 = proof_type.into();
    let now = Utc::now();

    let status: i32 = types::Status::Pending.into();

    let _ = sqlx::query(
        "INSERT INTO proofs (proof_type, request_id, status, created_at, circuit_name, onchain, endpoint_type, endpoint) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(proof_type_id)
    .bind(sqlx::types::Uuid::from(uuid))
    .bind(status)
    .bind(now)
    .bind(circuit_name)
    .bind(on_chain)
    .bind(endpoint_type.map(|e| serde_plain::to_string(e).unwrap()))
    .bind(endpoint)
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

pub async fn update_proof(
    uuid: uuid::Uuid,
    db: &sqlx::Pool<sqlx::Postgres>,
    signer: &PrivateKeySigner,
) -> Result<(), String> {
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

    let proof_msg = proof.to_bytes();
    let message_hash = keccak256(&&proof_msg);
    let alloy_signature: Signature = signer.sign_hash_sync(&message_hash).unwrap();

    let parity = if alloy_signature.recid().is_y_odd() {
        1
    } else {
        0
    } + 27;
    let r: [u8; 32] = alloy_signature.r().to_be_bytes();
    let s: [u8; 32] = alloy_signature.s().to_be_bytes();

    let mut signature = hex::encode(r);
    signature.push_str(&hex::encode(s));
    signature.push_str(&format!("{:x}", parity));

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
        "UPDATE proofs SET proof = $1, status = $2, proof_generated_at = $3, public_inputs = $4, signature=$5 WHERE request_id = $6",
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

impl Proof {
    fn to_bytes32(value: &String) -> Option<[u8; 32]> {
        let num = BigUint::from_str_radix(value, 10).ok()?;
        let bytes = num.to_bytes_be();

        if bytes.len() > 32 {
            return None;
        }

        let mut bytes32 = [0u8; 32];
        bytes32[(32 - bytes.len())..].copy_from_slice(&bytes);

        Some(bytes32)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut final_bytes: Vec<u8> = vec![];

        for i in 0..self.pi_a.len() - 1 {
            let bytes32 = match Self::to_bytes32(&self.pi_a[i]) {
                Some(bytes32) => bytes32.to_vec(),
                None => return final_bytes, //this branch should never be triggered
            };

            final_bytes.extend(bytes32);
        }

        for i in 0..self.pi_b.len() - 1 {
            for j in 0..self.pi_b[i].len() {
                let bytes32 = match Self::to_bytes32(&self.pi_b[i][j]) {
                    Some(bytes32) => bytes32.to_vec(),
                    None => return final_bytes, //this branch should never be triggered
                };

                final_bytes.extend(bytes32)
            }
        }

        for i in 0..self.pi_c.len() - 1 {
            let bytes32 = match Self::to_bytes32(&self.pi_c[i]) {
                Some(bytes32) => bytes32.to_vec(),
                None => return final_bytes, //this branch should never be triggered
            };

            final_bytes.extend(bytes32);
        }

        return final_bytes;
    }
}
