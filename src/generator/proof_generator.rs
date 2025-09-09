use core::str;
use std::path;

use crate::utils::get_tmp_folder_path;

pub struct ProofGenerator {
    uuid: uuid::Uuid,
    zkey_file_path: String,
}

impl ProofGenerator {
    pub fn new(uuid: uuid::Uuid, zkey_file_path: String) -> Self {
        ProofGenerator {
            uuid,
            zkey_file_path,
        }
    }

    pub fn uuid(&self) -> uuid::Uuid {
        self.uuid.clone()
    }

    pub async fn run(&self, rapid_snark_path_exe: &String) -> Result<(), String> {
        // let witness_file_path_str = get_tmp_folder_path(&self.uuid.to_string());
        let tmp_folder_path = get_tmp_folder_path(&self.uuid.to_string());
        let witness_file_path = path::Path::new(&tmp_folder_path).join("output.wtns");

        if !witness_file_path.exists() {
            return Err("Witness file does not exist".to_string());
        }

        // let proof_file_path_str = get_tmp_folder_path(&self.uuid.to_string());
        let proof_file_path = path::Path::new(&tmp_folder_path).join("proof.json");

        // let public_inputs = get_tmp_folder_path(&self.uuid);
        let public_inputs = path::Path::new(&tmp_folder_path).join("public_inputs.json");

        match tokio::process::Command::new(format!("{}", rapid_snark_path_exe))
            .arg(&self.zkey_file_path)
            .arg(witness_file_path)
            .arg(proof_file_path)
            .arg(public_inputs.into_os_string().into_string().unwrap())
            .output()
            .await
        {
            Ok(output) => {
                if !output.status.success() || output.stderr.len() > 0 {
                    return Err(str::from_utf8(&output.stderr)
                        .unwrap_or("Proof failed")
                        .to_string());
                }
            }
            Err(err) => {
                return Err(err.to_string());
            }
        };

        Ok(())
    }
}
