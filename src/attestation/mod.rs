pub mod bootstrap;
#[cfg(feature = "chain")]
pub mod chain;
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
    // Signed over the SUBMITTED coordinate order, not the prover's. The hub
    // digests the calldata it receives, and a relaying client transposes each
    // pi_b pair on the way -- see `digest::to_submitted_order`. Signing the
    // prover's order yields a digest the hub can never reproduce, so every
    // register and disclose call reverts UnauthorizedProverSigner.
    let submitted = digest::to_submitted_order(proof)?;
    let d = digest::proof_digest(&submitted, public_inputs)?;
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

    /// sign_proof must sign the digest of the SUBMITTED order, which is what the
    /// hub reconstructs from calldata. Pinned end to end rather than by
    /// inspection: recover the signer from both candidate digests and assert
    /// only the submitted one yields the enclave's address.
    #[test]
    fn sign_proof_signs_the_submitted_coordinate_order() {
        use key::recover_address;

        let key = EnclaveKey::generate();
        let proof = crate::db::Proof {
            pi_a: vec!["1".into(), "2".into()],
            pi_b: vec![vec!["3".into(), "4".into()], vec!["5".into(), "6".into()]],
            pi_c: vec!["7".into(), "8".into()],
            protocol: "groth16".into(),
        };
        let public_inputs = vec!["9".to_string(), "10".to_string()];

        let sig_hex = sign_proof(&key, &proof, &public_inputs).expect("sign_proof failed");
        let sig: [u8; 65] = hex::decode(sig_hex.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap();

        let submitted = digest::to_submitted_order(&proof).unwrap();
        let d_submitted = digest::proof_digest(&submitted, &public_inputs).unwrap();
        let d_prover = digest::proof_digest(&proof, &public_inputs).unwrap();

        assert_eq!(
            recover_address(&d_submitted, &sig).unwrap().to_lowercase(),
            key.address().to_lowercase(),
            "signature must recover to the enclave over the SUBMITTED order"
        );
        assert_ne!(
            recover_address(&d_prover, &sig).unwrap().to_lowercase(),
            key.address().to_lowercase(),
            "the prover's order must NOT recover -- that is the bug this pins"
        );
    }

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
        //
        // Over the SUBMITTED coordinate order, because that is what sign_proof
        // signs and what the hub reconstructs from calldata. This assertion used
        // the prover's order and passed, which is precisely why the mismatch
        // survived: the enclave agreed with itself while disagreeing with the
        // contract.
        let submitted = digest::to_submitted_order(&proof).expect("reorder failed");
        let d = digest::proof_digest(&submitted, &public_inputs).expect("digest failed");
        assert_eq!(
            recover_address(&d, &sig).unwrap(),
            key.address(),
            "signature must recover to the signing enclave's own address"
        );

        let _ = tokio::fs::remove_dir_all(&tmp).await;
    }
}
