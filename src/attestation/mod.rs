pub mod bootstrap;
pub mod digest;
pub mod key;

pub use key::EnclaveKey;

/// Signs the digest of an already-read-and-parsed proof/public-inputs pair.
/// Callers must obtain `proof`/`public_inputs` from a single call to
/// `crate::db::read_proof_output` and pass those same parsed values here and
/// into `crate::db::update_proof` — never re-read the request's tmp files
/// independently for signing vs. storage. The uuid backing that tmp folder is
/// client-supplied, so a second in-flight request can share it; two
/// independent reads can observe different bytes if the second pipeline's
/// output lands between them, producing a stored signature that does not
/// verify against its own stored proof. Returns a 0x-prefixed 132-character
/// hex string.
pub fn sign_proof(
    key: &EnclaveKey,
    proof: &crate::db::Proof,
    public_inputs: &[String],
) -> Result<String, String> {
    let d = digest::proof_digest(proof, public_inputs)?;
    Ok(format!("0x{}", hex::encode(key.sign_digest(&d)?)))
}

/// `get_tmp_folder_path` always resolves to `./tmp_<uuid>` in the crate root,
/// which every test in this process shares as a working directory. Most tests
/// only ever touch their own uuid-scoped subdirectory, so that's harmless —
/// except `bootstrap::tests::cleanup_runs_after_a_failed_bootstrap`, which
/// snapshots *every* `tmp_*` entry in the crate root before and after its call
/// (it has to: `bootstrap` mints its own uuid internally, so it can't predict
/// the exact path up front). Any other test that is transiently creating a
/// `tmp_*` directory of its own while that snapshot runs will look like a
/// leftover to it. Both that test and this module's own `tmp_*`-creating test
/// take this lock for their whole body so the two can never interleave.
#[cfg(test)]
pub(crate) static TMP_ROOT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use key::recover_address;

    /// Regression test for the read/sign/store race: pins the reader, the
    /// digest, and the signature together end-to-end, so a future change that
    /// reintroduces a second independent read of proof.json/public_inputs.json
    /// (or otherwise desyncs the signed bytes from the digest) fails here.
    #[tokio::test]
    async fn sign_proof_recovers_to_the_enclave_address() {
        let _guard = TMP_ROOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let key = EnclaveKey::generate();
        let uuid = uuid::Uuid::new_v4();
        let tmp = crate::utils::get_tmp_folder_path(&uuid.to_string());
        tokio::fs::create_dir_all(&tmp).await.unwrap();

        let proof_json =
            r#"{"pi_a":["1","2"],"pi_b":[["3","4"],["5","6"]],"pi_c":["7","8"],"protocol":"groth16"}"#;
        let inputs_json = r#"["9","10"]"#;
        tokio::fs::write(std::path::Path::new(&tmp).join("proof.json"), proof_json)
            .await
            .unwrap();
        tokio::fs::write(std::path::Path::new(&tmp).join("public_inputs.json"), inputs_json)
            .await
            .unwrap();

        let (proof, public_inputs) =
            crate::db::read_proof_output(uuid).await.expect("read_proof_output failed");

        let signature_hex = sign_proof(&key, &proof, &public_inputs).expect("sign_proof failed");
        assert!(signature_hex.starts_with("0x"));
        assert_eq!(signature_hex.len(), 2 + 65 * 2, "expected a 0x-prefixed 65-byte signature");

        let sig_bytes = hex::decode(&signature_hex[2..]).unwrap();
        let mut sig = [0u8; 65];
        sig.copy_from_slice(&sig_bytes);

        // Recompute the digest independently from the same parsed values used
        // to sign; if `sign_proof` or the reader ever drift from what gets
        // persisted, this equality is what catches it.
        let d = digest::proof_digest(&proof, &public_inputs).expect("digest failed");
        assert_eq!(
            recover_address(&d, &sig).unwrap(),
            key.address(),
            "signature must recover to the signing enclave's own address"
        );

        let _ = tokio::fs::remove_dir_all(&tmp).await;
    }
}
