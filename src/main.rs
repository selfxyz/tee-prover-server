mod args;
mod attestation;
mod db;
mod generator;
mod server;
mod store;
mod types;
mod utils;
mod verifier;

use std::collections::HashMap;
use std::path;
use std::sync::Arc;

use clap::Parser;
use db::{read_proof_output, record_precheck, set_witness_generated, update_proof};
use generator::{proof_generator::ProofGenerator, witness_generator::WitnessGenerator};
use google_cloud_secretmanager_v1::client::SecretManagerService;
use jsonrpsee::server::Server;
use server::RpcServer;
use sqlx::postgres::PgPoolOptions;
use utils::{cleanup, get_tmp_folder_path};

/// Enumerates `<circuit_folder>/*_cpp` into the `circuit_name -> zkey_path` map the
/// request pipeline is allowed to prove against, panicking if any circuit is missing
/// its zkey (a fail-fast boot check, unchanged).
///
/// The attestation circuit (`attestation::bootstrap::ATTESTATION_CIRCUIT`) is
/// deliberately EXCLUDED. `Circuit { name, inputs }` on a `submit_request` is entirely
/// client-supplied and the only validation performed is a lookup in this map, so leaving
/// the attestation circuit in it lets any client run the attestation circuit on
/// attacker-chosen inputs and receive the resulting proof *signed with the attested
/// enclave key*. `root_pubkey` is a circuit input rather than a pinned constant, so a
/// self-signed 3-certificate chain carrying an arbitrary `eat_nonce` and `image_digest`
/// would yield a valid proof — forged attestation evidence for any off-chain consumer
/// that treats an enclave-signed `gcp_jwt_verifier` proof as genuine.
///
/// Excluding it cannot affect the enclave's own attestation: `attestation::bootstrap`
/// is handed the circuit folder and the zkey path directly and never consults this map.
fn build_circuit_zkey_map(circuit_folder: &str, zkey_folder: &str) -> HashMap<String, String> {
    let mut circuit_zkey_map = HashMap::new();

    let entries = std::fs::read_dir(std::path::Path::new(circuit_folder)).unwrap();

    for entry in entries {
        let entry = entry.unwrap().path();
        let dir_name = entry.file_name().unwrap();
        let cpp_folder = dir_name.to_str().unwrap();
        //assuming that the folder ends with "_cpp"
        let circuit_name = cpp_folder[0..cpp_folder.len() - 4].to_string();

        // Never reachable from a client request: see this function's doc comment.
        if circuit_name == attestation::bootstrap::ATTESTATION_CIRCUIT {
            continue;
        }

        let zkey_path = path::Path::new(zkey_folder).join(format!("{}.zkey", circuit_name));
        let zkey_path_str = zkey_path.to_str().unwrap();

        if !zkey_path.exists() {
            panic!("zkey {zkey_path_str} does not exist!");
        }

        circuit_zkey_map.insert(circuit_name, zkey_path_str.to_string());
    }

    // The `continue` above already guarantees this; asserting makes a regression a
    // loud startup failure instead of a silently client-reachable attestation circuit.
    assert!(
        !circuit_zkey_map.contains_key(attestation::bootstrap::ATTESTATION_CIRCUIT),
        "the attestation circuit must never be reachable from a client request"
    );

    circuit_zkey_map
}

#[tokio::main]
async fn main() {
    let client = SecretManagerService::builder().build().await.unwrap();

    let project = std::env::var("PROJECT_ID").unwrap();
    let secret = std::env::var("SECRET_ID").unwrap();
    let name = format!("projects/{}/secrets/{}/versions/latest", project, secret);

    let resp = client
        .access_secret_version()
        .set_name(name)
        .send()
        .await
        .unwrap();

    let payload = resp.payload.unwrap().data.to_vec();
    //creds is a plain string with the db url
    let database_url = String::from_utf8(payload).unwrap();

    let config = args::Config::parse();
    let server_url = config.server_address;
    let precheck_mode = config.precheck_mode;

    let server = Server::builder().build(server_url).await.unwrap();

    let (file_generator_sender, mut file_generator_receiver) = tokio::sync::mpsc::channel(10);
    let (witness_generator_sender, mut witness_generator_receiver) = tokio::sync::mpsc::channel(10);
    let (proof_generator_sender, mut proof_generator_receiver) = tokio::sync::mpsc::channel(10);

    let server_addr = server.local_addr().unwrap();

    let pool = match PgPoolOptions::new()
        .max_connections(20)
        .connect(&database_url)
        .await
    {
        Ok(pool) => pool,
        Err(e) => {
            panic!("Error: {:?}", e);
        }
    };

    let circuit_folder = config.circuit_folder;
    let zkey_folder = config.zkey_folder;

    let circuit_zkey_map_arc = Arc::new(build_circuit_zkey_map(&circuit_folder, &zkey_folder));

    let rapid_snark_path_exe = path::Path::new(&config.rapidsnark_path)
        .join("package")
        .join("bin")
        .join("prover");

    if !rapid_snark_path_exe.exists() {
        panic!("rapid snark path does not exist!");
    }
    let rapid_snark_path = rapid_snark_path_exe.into_os_string().into_string().unwrap();

    let attestation_zkey = path::Path::new(&zkey_folder)
        .join(format!("{}.zkey", attestation::bootstrap::ATTESTATION_CIRCUIT));
    if !attestation_zkey.exists() {
        panic!("attestation zkey {} does not exist!", attestation_zkey.display());
    }

    // Fatal by design: the server must never serve proofs it cannot sign. This
    // runs — and either succeeds or panics — before `server.start(...)` below,
    // so no request (not even `hello()`/`submit_request()`) is ever accepted
    // by a server whose enclave attestation hasn't been proven yet.
    let (enclave_key, attestation_proof) = match attestation::bootstrap::bootstrap(
        &circuit_folder,
        attestation_zkey.to_str().unwrap(),
        &rapid_snark_path,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => panic!("TEE attestation bootstrap failed: {e}"),
    };
    println!("Enclave attested. Signing address: {}", enclave_key.address());

    // Fetched from Secret Manager, never from an env var: under Confidential
    // Space an env var is an instance-metadata value, readable by anyone with
    // `compute.instances.get` on the project, and this key is funded. Same
    // path the database URL above already takes.
    //
    // Fatal like the bootstrap before it. With signature enforcement live on
    // the hub, an enclave whose key was never registered produces proofs that
    // every register call rejects -- so failing to register is failing to
    // serve, and it is better to not start than to serve rejected proofs.
    #[cfg(feature = "chain")]
    {
        // One prefix, three secrets: `<prefix>RPC_URL`, `<prefix>HUB_ADDRESS`,
        // `<prefix>TEE_PRIVATE_KEY`. Staging and production share the
        // `self-protocol` project, so the prefix is what keeps their prover
        // config apart in a single Secret Manager namespace -- a staging
        // instance reading production's funded key is the failure this naming
        // exists to make impossible.
        //
        // The prefix itself is the only part that travels as metadata; it names
        // secrets rather than containing any.
        let prefix = std::env::var("PROVER_SECRET_PREFIX")
            .expect("PROVER_SECRET_PREFIX is not set");

        let mut prover_config = Vec::new();
        for suffix in ["RPC_URL", "HUB_ADDRESS", "TEE_PRIVATE_KEY"] {
            let secret_id = format!("{prefix}{suffix}");
            let name = format!("projects/{}/secrets/{}/versions/latest", project, secret_id);
            let resp = client
                .access_secret_version()
                .set_name(name)
                .send()
                .await
                .unwrap_or_else(|e| {
                    // Names the secret, never its contents.
                    panic!("failed to read secret {secret_id} from Secret Manager: {e}")
                });
            let value = String::from_utf8(
                resp.payload
                    .unwrap_or_else(|| panic!("secret {secret_id} has no payload"))
                    .data
                    .to_vec(),
            )
            .unwrap_or_else(|_| panic!("secret {secret_id} is not valid UTF-8"));
            prover_config.push(value);
        }

        if let Err(e) = attestation::chain::register_prover_key(
            &enclave_key,
            &attestation_proof,
            &prover_config[0],
            &prover_config[1],
            &prover_config[2],
        )
        .await
        {
            panic!("prover key registration failed: {e}");
        }
    }
    #[cfg(not(feature = "chain"))]
    let _ = &attestation_proof;

    let handle = server.start(
        server::RpcServerImpl::new(
            store::LruStore::new(1000),
            file_generator_sender,
            Arc::clone(&circuit_zkey_map_arc),
            pool.clone(),
        )
        .into_rpc(),
    );

    // Printed only once the server is actually accepting connections — i.e.
    // after attestation bootstrap has succeeded and `start()` has been called.
    println!("Server running on: http://{}", server_addr);

    tokio::select! {
        _ = handle.stopped() => {
            println!("Server stopped");
        }

    _ = async {
        while let Some(file_generator) = file_generator_receiver.recv().await {
            let uuid = file_generator.uuid();

            let pool_clone = pool.clone();
            let witness_generator_clone = witness_generator_sender.clone();
            tokio::spawn(async move {
                let (uuid, circuit_name, bytes_written) = match file_generator.run().await {
                    Ok(v) => v,
                    Err(e) => {
                        dbg!(&e);
                        cleanup(uuid.clone(), &pool_clone, e.to_string()).await;
                        return;
                    }
                };

                let verdict = crate::verifier::verify_inputs(uuid, &circuit_name, bytes_written).await;
                crate::verifier::metrics::record(&verdict);

                // Off the critical path by design: a DB error here must
                // never turn a `valid` verdict into a failed request, so it
                // is logged and the pipeline continues regardless of the
                // result. This matters more under enforcement, where a DB
                // blip would otherwise become a user-visible rejection.
                if let Err(e) = record_precheck(uuid, &verdict, &pool_clone).await {
                    dbg!(&e);
                }

                match &verdict {
                    crate::verifier::Verdict::Valid => {
                        println!("precheck valid for {circuit_name}");
                    }
                    crate::verifier::Verdict::Skipped(reason) => {
                        println!("precheck unavailable for {circuit_name}: {reason}");
                    }
                    crate::verifier::Verdict::Invalid(reason) => {
                        println!("precheck invalid for {circuit_name}: {reason}");
                    }
                }

                // Reject before witness generation: no proof is produced,
                // therefore none is signed, which is how the verdict gates
                // on-chain trust without touching the attestation work.
                if let Some(reason) =
                    crate::verifier::precheck_rejection(&circuit_name, &verdict, precheck_mode)
                {
                    cleanup(uuid, &pool_clone, reason).await;
                    return;
                }

                if let Err(e) = witness_generator_clone.send(WitnessGenerator::new(
                    uuid.clone(),
                    circuit_name
                )).await {
                    dbg!(&e);
                    cleanup(uuid, &pool_clone, e.to_string()).await;
                    return;
                }
            });
        }
    } => {}

    _ = async {
        while let Some(witness_generator) = witness_generator_receiver.recv().await {
            let circuit_zkey_map_arc_clone = Arc::clone(&circuit_zkey_map_arc);
            let proof_generator_sender_clone = proof_generator_sender.clone();

            let circuit_folder = circuit_folder.clone();
            let zkey_folder = zkey_folder.clone();

            let uuid = witness_generator.uuid.clone();

            let pool_clone = pool.clone();
            tokio::spawn(async move {
                match witness_generator
                    .run(&circuit_folder)
                    .await {
                    Ok((uuid, circuit_name)) => {
                        let zkey_file = circuit_zkey_map_arc_clone.get(circuit_name.as_str()).unwrap();
                        let zkey_file_path = path::Path::new(&zkey_folder).join(zkey_file).to_str().unwrap().to_string();

                        if let Err(e) = set_witness_generated(uuid.clone(), &pool_clone).await {
                            dbg!(&e);
                            cleanup(uuid.clone(), &pool_clone, e.to_string()).await;
                            return;
                        }

                        if let Err(e) = proof_generator_sender_clone.send(ProofGenerator::new(
                            uuid.clone(),
                            zkey_file_path,
                        )).await {
                            dbg!(&e);
                            cleanup(uuid.clone(), &pool_clone, e.to_string()).await;
                            return;
                        }
                    },
                    Err(e) => {
                        dbg!(&e);
                        cleanup(uuid.clone(), &pool_clone, e.to_string()).await;
                        return;
                    }
                }
            });
        }
    } => {}

    _ = async {
        while let Some(proof_generator) = proof_generator_receiver.recv().await {
            let uuid = proof_generator.uuid();

            if let Err(e) = proof_generator.run(&rapid_snark_path).await {
                dbg!(&e);
                cleanup(uuid.clone(), &pool, e.to_string()).await;
                continue;
            }

            // Read proof.json/public_inputs.json exactly once: the uuid is
            // client-supplied, so a second in-flight request can share this
            // tmp folder, and a second independent read (one for signing, one
            // for storage) could observe different bytes. Sign and persist
            // these same parsed values so the signed object and the stored
            // object are identical.
            let (proof, public_inputs) = match read_proof_output(uuid).await {
                Ok(result) => result,
                Err(e) => {
                    dbg!(&e);
                    cleanup(uuid.clone(), &pool, e).await;
                    continue;
                }
            };

            let signature = match attestation::sign_proof(&enclave_key, &proof, &public_inputs) {
                Ok(sig) => sig,
                Err(e) => {
                    dbg!(&e);
                    cleanup(uuid.clone(), &pool, e).await;
                    continue;
                }
            };

            if let Err(e) =
                update_proof(uuid.clone(), &pool, &proof, &public_inputs, &signature).await
            {
                dbg!(&e);
                cleanup(uuid.clone(), &pool, e.to_string()).await;
                continue;
            }
            let tmp_folder = get_tmp_folder_path(&uuid.to_string());
            let _ = tokio::fs::remove_dir_all(tmp_folder).await;
        }
    } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C2 regression: the attestation circuit ships in `/circuits` alongside every
    /// other circuit (every image variant needs it at boot), and this map is the ONLY
    /// gate on the client-supplied `circuit.name` in `submit_request`. If it ever
    /// reappears here, a client can have the enclave prove the attestation circuit on
    /// inputs it chose and sign the result with the attested key.
    #[test]
    fn attestation_circuit_is_not_client_reachable() {
        let dir = tempfile::tempdir().unwrap();
        let circuits = dir.path().join("circuits");
        let zkeys = dir.path().join("zkeys");
        std::fs::create_dir_all(&circuits).unwrap();
        std::fs::create_dir_all(&zkeys).unwrap();

        for name in [attestation::bootstrap::ATTESTATION_CIRCUIT, "vc_and_disclose"] {
            std::fs::create_dir_all(circuits.join(format!("{name}_cpp"))).unwrap();
            std::fs::write(zkeys.join(format!("{name}.zkey")), b"x").unwrap();
        }

        let map =
            build_circuit_zkey_map(circuits.to_str().unwrap(), zkeys.to_str().unwrap());

        assert!(
            !map.contains_key(attestation::bootstrap::ATTESTATION_CIRCUIT),
            "attestation circuit must be excluded from the client-reachable circuit map"
        );
        // The exclusion must be surgical: everything else still has to be provable.
        assert!(map.contains_key("vc_and_disclose"), "ordinary circuits must stay in the map");
        assert_eq!(map.len(), 1);
    }

    /// The exclusion must not depend on the attestation circuit having a zkey next to
    /// the others: it is skipped before the per-circuit zkey existence check, so a
    /// layout where only its zkey is missing must still build a map rather than panic.
    /// (`main` checks the attestation zkey separately, by full path.)
    #[test]
    fn attestation_circuit_is_skipped_before_its_zkey_is_required() {
        let dir = tempfile::tempdir().unwrap();
        let circuits = dir.path().join("circuits");
        let zkeys = dir.path().join("zkeys");
        std::fs::create_dir_all(circuits.join(format!(
            "{}_cpp",
            attestation::bootstrap::ATTESTATION_CIRCUIT
        )))
        .unwrap();
        std::fs::create_dir_all(&zkeys).unwrap();

        let map =
            build_circuit_zkey_map(circuits.to_str().unwrap(), zkeys.to_str().unwrap());
        assert!(map.is_empty());
    }
}
