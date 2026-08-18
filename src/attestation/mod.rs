pub mod bootstrap;
pub mod digest;
pub mod key;

pub use key::EnclaveKey;

use serde::Deserialize;

/// Reads the proof this request just produced and signs it. Returns a
/// 0x-prefixed 132-character hex string.
pub fn sign_proof_output(key: &EnclaveKey, uuid: &uuid::Uuid) -> Result<String, String> {
    let tmp = crate::utils::get_tmp_folder_path(&uuid.to_string());
    let proof_str = std::fs::read_to_string(std::path::Path::new(&tmp).join("proof.json"))
        .map_err(|e| e.to_string())?;
    let inputs_str =
        std::fs::read_to_string(std::path::Path::new(&tmp).join("public_inputs.json"))
            .map_err(|e| e.to_string())?;

    let proof = crate::db::Proof::deserialize(
        &mut serde_json::de::Deserializer::from_str(&proof_str),
    )
    .map_err(|e| e.to_string())?;
    let public_inputs = Vec::<String>::deserialize(
        &mut serde_json::de::Deserializer::from_str(&inputs_str),
    )
    .map_err(|e| e.to_string())?;

    let d = digest::proof_digest(&proof, &public_inputs)?;
    Ok(format!("0x{}", hex::encode(key.sign_digest(&d)?)))
}
