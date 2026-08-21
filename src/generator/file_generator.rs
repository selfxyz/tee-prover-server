use std::path;

use crate::utils::get_tmp_folder_path;

use crate::types::{ProofRequest, ProofType};
use tokio::io::AsyncWriteExt;

pub struct FileGenerator {
    uuid: uuid::Uuid,
    pub proof_request: ProofRequest,
}

impl FileGenerator {
    pub fn new(uuid: uuid::Uuid, proof_request: ProofRequest) -> Self {
        Self {
            uuid,
            proof_request,
        }
    }

    pub fn uuid(&self) -> uuid::Uuid {
        self.uuid.clone()
    }

    pub fn proof_type(&self) -> ProofType {
        (&self.proof_request).into()
    }

    //create the tmp folder
    //create the inputs file
    pub async fn run(&self) -> Result<(uuid::Uuid, String), std::io::Error> {
        let path_str = get_tmp_folder_path(&self.uuid.to_string());
        let path = path::Path::new(&path_str);
        tokio::fs::create_dir_all(path).await?;

        let mut input_file = tokio::fs::File::create(path.join("input.json")).await?;

        // write_all, not write: `write` issues one operation and returns how many
        // bytes it took, capped at tokio's 2 MiB DEFAULT_MAX_BUF_SIZE. That count
        // was discarded, so any input over 2 MiB -- every -large register and dsc
        // request -- was silently truncated to exactly 2 MiB.
        input_file
            .write_all(self.proof_request.circuit().inputs.as_bytes())
            .await?;

        // tokio::fs::File buffers, and dropping it does not flush. The precheck
        // opens input.json immediately after this returns, so an unflushed write
        // reaches it as an empty file. Both truncation and emptiness surface
        // identically -- Verdict::Skipped("input.json is not valid JSON") -- which
        // --precheck-mode=enforce rejects before witness generation.
        //
        // flush, not sync_all: the reader is another process going through the
        // page cache, not a crash-durability requirement, so there is no reason
        // to pay for an fsync on a tmp file.
        input_file.flush().await?;

        Ok((self.uuid.clone(), self.proof_request.circuit().name.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ProofRequest;

    /// A JSON object larger than tokio's `DEFAULT_MAX_BUF_SIZE` (2 MiB), which is
    /// the most a single `tokio::fs::File` write will take. Past that, `write`
    /// necessarily returns a short count -- deterministically, no race needed.
    ///
    /// This is not a contrived size: the -large register and dsc workloads exist
    /// precisely because their inputs are big.
    fn oversized_inputs() -> String {
        let limbs: Vec<String> = (0..400_000).map(|i| format!("\"{i}\"")).collect();
        let s = format!("{{\"signature\":[{}]}}", limbs.join(","));
        assert!(
            s.len() > 2 * 1024 * 1024,
            "fixture must exceed tokio's 2 MiB max write, got {}",
            s.len()
        );
        s
    }

    fn request(inputs: String) -> ProofRequest {
        ProofRequest::Register {
            circuit: crate::generator::Circuit {
                name: "register_sha256_sha256_sha256_rsa_65537_4096".to_string(),
                inputs,
            },
            endpoint_type: None,
            endpoint: None,
        }
    }

    /// The precheck reads input.json immediately after this runs, then parses it.
    /// Anything short of the whole payload landing on disk reaches it as
    /// `Verdict::Skipped("input.json is not valid JSON: ...")`, which
    /// `--precheck-mode=enforce` rejects before witness generation.
    #[tokio::test]
    async fn input_json_lands_on_disk_whole() {
        let _guard = crate::attestation::TMP_ROOT_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let inputs = oversized_inputs();
        let uuid = uuid::Uuid::new_v4();
        let generator = FileGenerator::new(uuid, request(inputs.clone()));

        generator.run().await.expect("run failed");

        let dir = get_tmp_folder_path(&uuid.to_string());
        let written = tokio::fs::read_to_string(path::Path::new(&dir).join("input.json"))
            .await
            .expect("input.json unreadable");
        let _ = tokio::fs::remove_dir_all(&dir).await;

        assert_eq!(
            written.len(),
            inputs.len(),
            "input.json is {} bytes, payload was {}",
            written.len(),
            inputs.len()
        );
        serde_json::from_str::<serde_json::Value>(&written)
            .expect("input.json is not valid JSON");
    }
}
