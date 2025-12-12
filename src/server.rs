use base64::engine::{general_purpose, Engine};
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types;
use jsonrpsee::{types::ErrorObjectOwned, ResponsePayload};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::PublicKey;
use rand_core::OsRng;
use sqlx::Pool;
use std::collections::HashMap;
use std::sync::Arc;

use crate::db::create_proof_status;
use crate::store::{KeyMaterial, LruStore};
use crate::types::{ProofRequest, SubmitRequest};
use crate::utils;
use crate::{generator::file_generator::FileGenerator, types::HelloResponse};

// PQXDH imports
use hkdf::Hkdf;
use ml_kem::kem::Decapsulate;
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret as X25519Secret, PublicKey as X25519PublicKey};

#[rpc(server, namespace = "openpassport")]
pub trait Rpc {
    #[method(name = "health")]
    async fn health(&self) -> ResponsePayload<'static, String>;

    /// Initiates a cryptographic handshake with the client.
    /// Negotiates suite (PQXDH or legacy P-256), generates keypairs, computes shared secrets,
    /// and returns attestation with public keys. For PQXDH, stores pending state awaiting key_exchange.
    #[method(name = "hello")]
    async fn hello(
        &self,
        user_pubkey: Vec<u8>,
        uuid: uuid::Uuid,
        supported_suites: Vec<String>,
    ) -> ResponsePayload<'static, HelloResponse>;

    /// Completes the PQXDH handshake by decapsulating the Kyber ciphertext.
    /// Derives the final session key using HKDF per Signal PQXDH spec.
    /// Only valid for UUIDs in PqxdhPending state after hello.
    #[method(name = "key_exchange")]
    async fn key_exchange(
        &self,
        uuid: uuid::Uuid,
        kyber_ciphertext: Vec<u8>,
    ) -> ResponsePayload<'static, String>;

    #[method(name = "submit_request")]
    async fn submit_request(
        &self,
        uuid: uuid::Uuid,
        nonce: Vec<u8>,
        cipher_text: Vec<u8>,
        auth_tag: Vec<u8>,
    ) -> ResponsePayload<'static, String>;
}

pub struct RpcServerImpl {
    store: LruStore,
    file_generator_sender: tokio::sync::mpsc::Sender<FileGenerator>,
    circuit_zkey_map: Arc<HashMap<String, String>>,
    db: Pool<sqlx::Postgres>,
}

impl RpcServerImpl {
    pub fn new(
        store: LruStore,
        file_generator_sender: tokio::sync::mpsc::Sender<FileGenerator>,
        circuit_zkey_map: Arc<HashMap<String, String>>,
        db: Pool<sqlx::Postgres>,
    ) -> Self {
        Self {
            store,
            file_generator_sender,
            circuit_zkey_map,
            db,
        }
    }
}

#[async_trait]
impl RpcServer for RpcServerImpl {
    async fn health(&self) -> ResponsePayload<'static, String> {
        ResponsePayload::success("OK".to_string())
    }

    async fn hello(
        &self,
        user_pubkey: Vec<u8>,
        uuid: uuid::Uuid,
        supported_suites: Vec<String>,
    ) -> ResponsePayload<'static, HelloResponse> {
        // negotiating suite: prefer PQXDH, fallback to legacy
        let selected_suite = if supported_suites.contains(&"Self-PQXDH-1".to_string()) {
            "Self-PQXDH-1"
        } else if supported_suites.contains(&"legacy-p256".to_string()) {
            "legacy-p256"
        } else {
            return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                types::ErrorCode::InvalidParams.code(),
                "No supported cryptographic suite found",
                None,
            ));
        };

        if selected_suite == "Self-PQXDH-1" {
            // PQXDH flow: X25519 + Kyber ML-KEM-768
            if user_pubkey.len() != 32 {
                return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                    types::ErrorCode::InvalidRequest.code(),
                    "X25519 public key must be 32 bytes",
                    None,
                ));
            }

            // generating X25519 keypair
            let mut rng = OsRng;
            let x25519_secret = X25519Secret::random_from_rng(&mut rng);
            let x25519_public = X25519PublicKey::from(&x25519_secret);

            // parsing client's X25519 public key
            let client_x25519_public = {
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&user_pubkey);
                X25519PublicKey::from(key_bytes)
            };

            // computing X25519 shared secret
            let x25519_shared = x25519_secret.diffie_hellman(&client_x25519_public);

            // generating Kyber ML-KEM-768 keypair (using system RNG)
            let (decapsulation_key, encapsulation_key) = MlKem768::generate(&mut rand::rng());

            // storing X25519 shared secret and Kyber secret key (waiting for key_exchange)
            let key_material = KeyMaterial::PqxdhPending {
                x25519_shared: x25519_shared.as_bytes().to_vec(),
                kyber_secret: decapsulation_key.as_bytes().to_vec(),
            };

            match self.store.insert_new_agreement(uuid, key_material).await {
                Ok(_) => (),
                Err(_) => {
                    return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                        types::ErrorCode::InvalidRequest.code(),
                        "UUID already exists",
                        None,
                    ));
                }
            }

            // encoding public keys for attestation
            let x25519_public_b64 = general_purpose::STANDARD.encode(x25519_public.as_bytes());
            let kyber_public_b64 = general_purpose::STANDARD.encode(encapsulation_key.as_bytes());

            // creating attestation JWT with suite and public keys
            let attestation_result = utils::attestation::get_custom_token_bytes(vec![
                &x25519_public_b64,
                &kyber_public_b64,
                selected_suite,
            ])
            .await
            .map_err(|e| format!("{:?}", e));

            let attestation = match attestation_result {
                Ok(attestation) => attestation,
                Err(err_string) => {
                    self.store.remove_agreement(&uuid).await;
                    return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                        types::ErrorCode::InternalError.code(),
                        err_string,
                        None,
                    ));
                }
            };

            ResponsePayload::success(
                HelloResponse::new(
                    uuid,
                    attestation,
                    selected_suite.to_string(),
                    Some(x25519_public.as_bytes().to_vec()),
                    Some(encapsulation_key.as_bytes().to_vec()),
                )
                .into(),
            )
        } else {
            // legacy P-256 ECDH flow
            if user_pubkey.len() != 33 {
                return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                    types::ErrorCode::InvalidRequest.code(),
                    "P-256 public key must be 33 bytes",
                    None,
                ));
            }

            let mut rng = OsRng;
            let my_private_key = EphemeralSecret::random(&mut rng);
            let my_public_key = PublicKey::from(&my_private_key);

            let their_public_key = match PublicKey::from_sec1_bytes(&user_pubkey) {
                Ok(pubkey) => pubkey,
                Err(err) => {
                    return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                        types::ErrorCode::InvalidParams.code(),
                        format!("{:?}", err),
                        None,
                    ));
                }
            };

            let their_public_key_compressed =
                their_public_key.to_encoded_point(true).to_bytes().to_vec();
            let my_public_key_compressed = my_public_key.to_encoded_point(true).to_bytes().to_vec();

            let their_public_key_string =
                general_purpose::STANDARD.encode(&their_public_key_compressed);
            let my_public_key_string = general_purpose::STANDARD.encode(&my_public_key_compressed);

            let attestation = match utils::attestation::get_custom_token_bytes(vec![
                &their_public_key_string,
                &my_public_key_string,
            ])
            .await
            {
                Ok(attestation) => attestation,
                Err(err) => {
                    return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                        types::ErrorCode::InternalError.code(),
                        format!("{:?}", err),
                        None,
                    ));
                }
            };

            let derived_key_result = my_private_key
                .diffie_hellman(&their_public_key)
                .raw_secret_bytes()
                .to_vec();

            let key_material = KeyMaterial::LegacyP256(derived_key_result);

            match self.store.insert_new_agreement(uuid, key_material).await {
                Ok(_) => (),
                Err(_) => {
                    return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                        types::ErrorCode::InvalidRequest.code(),
                        "UUID already exists",
                        None,
                    ));
                }
            }

            ResponsePayload::success(
                HelloResponse::new(uuid, attestation, selected_suite.to_string(), None, None)
                    .into(),
            )
        }
    }

    async fn key_exchange(
        &self,
        uuid: uuid::Uuid,
        kyber_ciphertext: Vec<u8>,
    ) -> ResponsePayload<'static, String> {
        // validating Kyber ciphertext length (ML-KEM-768 = 1088 bytes)
        const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;
        if kyber_ciphertext.len() != ML_KEM_768_CIPHERTEXT_SIZE {
            return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                types::ErrorCode::InvalidRequest.code(),
                format!(
                    "Invalid Kyber ciphertext length: expected {}, got {}",
                    ML_KEM_768_CIPHERTEXT_SIZE,
                    kyber_ciphertext.len()
                ),
                None,
            ));
        }

        // retrieving pending PQXDH key material from store
        let key_material = match self.store.get_key_material(&uuid).await {
            Some(material) => material,
            None => {
                return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                    types::ErrorCode::InvalidRequest.code(),
                    "UUID not found",
                    None,
                ));
            }
        };

        let (x25519_shared, kyber_secret) = match key_material {
            KeyMaterial::PqxdhPending {
                x25519_shared,
                kyber_secret,
            } => (x25519_shared, kyber_secret),
            _ => {
                self.store.remove_agreement(&uuid).await;
                return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                    types::ErrorCode::InvalidRequest.code(),
                    "UUID is not in PQXDH pending state",
                    None,
                ));
            }
        };

        // decapsulating Kyber ciphertext to get Kyber shared secret
        // converting stored secret key bytes back to DecapsulationKey
        type DecapKey = <MlKem768 as KemCore>::DecapsulationKey;
        let decaps_key_bytes: &Encoded<DecapKey> = kyber_secret[..].try_into().map_err(|_| {
            "Invalid decapsulation key length"
        }).unwrap();
        let decaps_key = DecapKey::from_bytes(decaps_key_bytes);

        // converting ciphertext bytes to Ciphertext type
        let ct: ml_kem::Ciphertext<MlKem768> = kyber_ciphertext[..].try_into().map_err(|_| {
            "Invalid ciphertext length"
        }).unwrap();

        // decapsulating to get shared secret
        let kyber_shared = decaps_key.decapsulate(&ct).map_err(|e| {
            format!("Decapsulation failed: {:?}", e)
        }).unwrap();
        let kyber_shared_bytes: &[u8] = kyber_shared.as_ref();

        // deriving final session key using HKDF matching Signal PQXDH spec
        // F prefix (32 0xFF bytes) per Signal spec
        let f_prefix = vec![0xff; 32];

        // IKM = F || X25519_shared || Kyber_shared
        let mut ikm = Vec::with_capacity(f_prefix.len() + x25519_shared.len() + kyber_shared_bytes.len());
        ikm.extend_from_slice(&f_prefix);
        ikm.extend_from_slice(&x25519_shared);
        ikm.extend_from_slice(&kyber_shared_bytes);

        // zero-filled salt (32 bytes for SHA-256 output length) per Signal spec
        let salt = vec![0u8; 32];

        // info parameter following Signal pattern: "protocol_curve_hash_pqkem"
        let info = b"Self-PQXDH-1_X25519_SHA-256_ML-KEM-768";

        // deriving 32-byte session key using HKDF-SHA256
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut session_key = vec![0u8; 32];
        if let Err(e) = hkdf.expand(info, &mut session_key) {
            self.store.remove_agreement(&uuid).await;
            return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                types::ErrorCode::InternalError.code(),
                format!("HKDF expansion failed: {:?}", e),
                None,
            ));
        }

        // updating store with final session key
        let final_material = KeyMaterial::PqxdhComplete(session_key);
        if let Err(e) = self.store.update_key_material(&uuid, final_material).await {
            self.store.remove_agreement(&uuid).await;
            return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                types::ErrorCode::InternalError.code(),
                format!("Failed to update key material: {}", e),
                None,
            ));
        }

        ResponsePayload::success("key_exchange_complete".to_string())
    }

    //TODO: check if circuit exists
    async fn submit_request(
        &self,
        uuid: uuid::Uuid,
        nonce: Vec<u8>,
        cipher_text: Vec<u8>,
        auth_tag: Vec<u8>,
    ) -> ResponsePayload<'static, String> {
        let nonce = nonce.as_slice();
        let auth_tag = auth_tag.as_slice();
        let key = {
            let key = match self.store.get_shared_secret(&uuid).await {
                Some(shared_secret) => shared_secret,
                None => {
                    self.store.remove_agreement(&uuid).await;
                    return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                        types::ErrorCode::InvalidRequest.code(),
                        "UUID not found",
                        None,
                    ));
                }
            };
            key
        };

        let key: [u8; 32] = match key.try_into() {
            Ok(key) => key,
            Err(_) => {
                self.store.remove_agreement(&uuid).await;
                return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                    types::ErrorCode::InternalError.code(), //INTERNAL_SERVER_ERROR
                    "Failed to store ephemeral key",
                    None,
                ));
            }
        };

        let decrypted_text: String = match utils::decrypt(key, cipher_text, auth_tag, nonce) {
            Ok(text) => text,
            Err(_) => {
                self.store.remove_agreement(&uuid).await;
                return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                    types::ErrorCode::InvalidRequest.code(),
                    "Failed to decrypt text",
                    None,
                ));
            }
        };

        let submit_request = match serde_json::from_str::<SubmitRequest>(&decrypted_text) {
            Ok(submit_request) => {
                let mut allowed_proof_type = "";
                if cfg!(feature = "register") {
                    allowed_proof_type = "register";
                } else if cfg!(feature = "dsc") {
                    allowed_proof_type = "dsc";
                } else {
                    allowed_proof_type = "disclose";
                }

                let invalid_proof_type_response =
                    ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                        types::ErrorCode::InvalidRequest.code(), //BAD REQUEST
                        format!("This endpoint only allows {} inputs", allowed_proof_type),
                        None,
                    ));

                match submit_request.proof_request_type {
                    ProofRequest::Register { .. }
                    | ProofRequest::RegisterId { .. }
                    | ProofRequest::RegisterAadhaar { .. } => {
                        if !cfg!(feature = "register") && !cfg!(feature = "cherrypick") {
                            self.store.remove_agreement(&uuid).await;
                            return invalid_proof_type_response;
                        }
                    }
                    ProofRequest::Dsc { .. } | ProofRequest::DscId { .. } => {
                        if !cfg!(feature = "dsc") && !cfg!(feature = "cherrypick") {
                            self.store.remove_agreement(&uuid).await;
                            return invalid_proof_type_response;
                        }
                    }
                    ProofRequest::Disclose { .. }
                    | ProofRequest::DiscloseId { .. }
                    | ProofRequest::DiscloseAadhaar { .. } => {
                        if !cfg!(feature = "disclose") && !cfg!(feature = "cherrypick") {
                            self.store.remove_agreement(&uuid).await;
                            return invalid_proof_type_response;
                        }
                    }
                };

                let circuit_name = submit_request.proof_request_type.circuit().name.clone();
                if !self.circuit_zkey_map.contains_key(&circuit_name) {
                    self.store.remove_agreement(&uuid).await;
                    return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                        types::ErrorCode::InvalidRequest.code(),
                        format!("Could not find the given circuit name: {}", &circuit_name),
                        None,
                    ));
                }
                submit_request
            }
            Err(_) => {
                self.store.remove_agreement(&uuid).await;
                return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                    types::ErrorCode::InvalidRequest.code(),
                    "Failed to parse proof request",
                    None,
                ));
            }
        };

        let (endpoint_type, endpoint, user_defined_data, self_defined_data, version) =
            match &submit_request.proof_request_type {
                ProofRequest::Register {
                    endpoint_type,
                    endpoint,
                    ..
                } => (endpoint_type.as_ref(), endpoint.as_ref(), "", "", 1 as i32),
                ProofRequest::Dsc {
                    endpoint_type,
                    endpoint,
                    ..
                } => (endpoint_type.as_ref(), endpoint.as_ref(), "", "", 1),
                ProofRequest::Disclose {
                    endpoint_type,
                    endpoint,
                    user_defined_data,
                    self_defined_data,
                    version,
                    ..
                } => {
                    (
                        Some(endpoint_type),
                        Some(endpoint),
                        user_defined_data.as_str(),
                        self_defined_data.as_str(),
                        *version as i32,
                    )
                }
                ProofRequest::RegisterId {
                    endpoint_type,
                    endpoint,
                    ..
                } => (endpoint_type.as_ref(), endpoint.as_ref(), "", "", 1),
                ProofRequest::DscId {
                    endpoint_type,
                    endpoint,
                    ..
                } => (endpoint_type.as_ref(), endpoint.as_ref(), "", "", 1),
                ProofRequest::DiscloseId {
                    endpoint_type,
                    endpoint,
                    user_defined_data,
                    self_defined_data,
                    version,
                    ..
                } => (
                    Some(endpoint_type),
                    Some(endpoint),
                    user_defined_data.as_str(),
                    self_defined_data.as_str(),
                    *version as i32,
                ),
                ProofRequest::RegisterAadhaar {
                    endpoint_type,
                    endpoint,
                    ..
                } => (endpoint_type.as_ref(), endpoint.as_ref(), "", "", 1),
                ProofRequest::DiscloseAadhaar {
                    endpoint_type,
                    endpoint,
                    user_defined_data,
                    self_defined_data,
                    version,
                    ..
                } => (
                    Some(endpoint_type),
                    Some(endpoint),
                    user_defined_data.as_str(),
                    self_defined_data.as_str(),
                    *version as i32,
                ),
            };

        if let Err(e) = create_proof_status(
            uuid,
            &(&submit_request.proof_request_type).into(),
            &submit_request.proof_request_type.circuit().name,
            submit_request.onchain,
            &self.db,
            endpoint_type,
            endpoint,
            version,
            user_defined_data,
            self_defined_data,
        )
        .await
        {
            self.store.remove_agreement(&uuid).await;
            return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                types::ErrorCode::InternalError.code(), //INTERNAL_SERVER_ERROR
                e,
                None,
            ));
        }

        let file_generator = FileGenerator::new(uuid.clone(), submit_request.proof_request_type);
        match self.file_generator_sender.send(file_generator).await {
            Ok(()) => (),
            Err(e) => {
                self.store.remove_agreement(&uuid).await;
                return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                    types::ErrorCode::InternalError.code(), //INTERNAL_SERVER_ERROR
                    e.to_string(),
                    None,
                ));
            }
        }

        self.store.remove_agreement(&uuid).await;
        ResponsePayload::success(uuid.to_string())
    }
}
