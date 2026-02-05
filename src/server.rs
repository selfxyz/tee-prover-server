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
use crate::store::LruStore;
use crate::types::{ProofRequest, SubmitRequest};
use crate::utils;
use crate::{generator::file_generator::FileGenerator, types::HelloResponse};

#[rpc(server, namespace = "openpassport")]
pub trait Rpc {
    #[method(name = "health")]
    async fn health(&self) -> ResponsePayload<'static, String>;
    #[method(name = "hello")]
    async fn hello(
        &self,
        user_pubkey: Vec<u8>,
        uuid: uuid::Uuid,
    ) -> ResponsePayload<'static, HelloResponse>;
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
    ) -> ResponsePayload<'static, HelloResponse> {
        if user_pubkey.len() != 33 {
            return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                types::ErrorCode::InvalidRequest.code(), //BAD_REQUEST
                "Public key must be 33 bytes",
                None,
            ));
        };

        let mut rng = OsRng;
        let my_private_key = EphemeralSecret::random(&mut rng);
        let my_public_key = PublicKey::from(&my_private_key);

        let their_public_key = match PublicKey::from_sec1_bytes(&user_pubkey) {
            Ok(pubkey) => pubkey,
            Err(err) => {
                return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                    types::ErrorCode::InvalidParams.code(), //INVALID_PARAMS
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
                    types::ErrorCode::InternalError.code(), //INTERNAL_SERVER_ERROR
                    format!("{:?}", err),
                    None,
                ));
            }
        };

        let derived_key_result = my_private_key
            .diffie_hellman(&their_public_key)
            .raw_secret_bytes()
            .to_vec();

        match self
            .store
            .insert_new_agreement(uuid, derived_key_result)
            .await
        {
            Ok(_) => (),
            Err(_) => {
                return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                    types::ErrorCode::InvalidRequest.code(), //INTERNAL_SERVER_ERROR
                    "UUID already exists",
                    None,
                ));
            }
        }

        ResponsePayload::success(HelloResponse::new(uuid, attestation).into())
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
                    | ProofRequest::RegisterAadhaar { .. }
                    | ProofRequest::RegisterKyc { .. } => {
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
                    | ProofRequest::DiscloseAadhaar { .. }
                    | ProofRequest::DiscloseKyc { .. } => {
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
                ProofRequest::RegisterKyc {
                    endpoint_type,
                    endpoint,
                    ..
                } => (endpoint_type.as_ref(), endpoint.as_ref(), "", "", 1),
                ProofRequest::DiscloseKyc {
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
