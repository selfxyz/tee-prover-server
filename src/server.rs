use aws_nitro_enclaves_nsm_api::api::ErrorCode;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types;
use jsonrpsee::{types::ErrorObjectOwned, ResponsePayload};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::PublicKey;
use rand_core::{CryptoRng, RngCore};
use sqlx::Pool;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use crate::db::create_proof_status;
use crate::store::LruStore;
use crate::types::{ProofRequest, SubmitRequest};
use crate::utils::{self, nsm_get_random};
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
    fd: i32,
    store: LruStore,
    file_generator_sender: tokio::sync::mpsc::Sender<FileGenerator>,
    circuit_zkey_map: Arc<HashMap<String, String>>,
    db: Pool<sqlx::Postgres>,
}

impl RpcServerImpl {
    pub fn new(
        fd: i32,
        store: LruStore,
        file_generator_sender: tokio::sync::mpsc::Sender<FileGenerator>,
        circuit_zkey_map: Arc<HashMap<String, String>>,
        db: Pool<sqlx::Postgres>,
    ) -> Self {
        Self {
            fd,
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
        if user_pubkey.len() != 65 {
            return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                types::ErrorCode::InvalidRequest.code(), //BAD_REQUEST
                "Public key must be 65 bytes",
                None,
            ));
        };

        let mut nitro_rng = NitroRng::new(self.fd);

        let my_private_key = EphemeralSecret::random(&mut nitro_rng);
        let my_public_key = PublicKey::from(&my_private_key).to_sec1_bytes().to_vec();

        let attestation = match utils::get_attestation(
            self.fd,
            Some(user_pubkey.clone()),
            None,
            Some(my_public_key.clone()),
        ) {
            Ok(attestation) => attestation,
            Err(err) => {
                return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                    types::ErrorCode::InternalError.code(), //INTERNAL_SERVER_ERROR
                    format!("{:?}", err),
                    None,
                ));
            }
        };

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
                    ProofRequest::Register { .. } | ProofRequest::RegisterId { .. } => {
                        if !cfg!(feature = "register") {
                            self.store.remove_agreement(&uuid).await;
                            return invalid_proof_type_response;
                        }
                    }
                    ProofRequest::Dsc { .. } | ProofRequest::DscId { .. } => {
                        if !cfg!(feature = "dsc") {
                            self.store.remove_agreement(&uuid).await;
                            return invalid_proof_type_response;
                        }
                    }
                    ProofRequest::Disclose { .. } | ProofRequest::DiscloseId { .. } => {
                        if !cfg!(feature = "disclose") {
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

        let (endpoint_type, endpoint, user_defined_data, version) =
            match &submit_request.proof_request_type {
                ProofRequest::Register {
                    endpoint_type,
                    endpoint,
                    ..
                } => (endpoint_type.as_ref(), endpoint.as_ref(), "", 1 as i32),
                ProofRequest::Dsc {
                    endpoint_type,
                    endpoint,
                    ..
                } => (endpoint_type.as_ref(), endpoint.as_ref(), "", 1),
                ProofRequest::Disclose {
                    endpoint_type,
                    endpoint,
                    user_defined_data,
                    version,
                    ..
                } => {
                    dbg!(&version);
                    (
                        Some(endpoint_type),
                        Some(endpoint),
                        user_defined_data.as_str(),
                        *version as i32,
                    )
                }
                ProofRequest::RegisterId {
                    endpoint_type,
                    endpoint,
                    ..
                } => (endpoint_type.as_ref(), endpoint.as_ref(), "", 1),
                ProofRequest::DscId {
                    endpoint_type,
                    endpoint,
                    ..
                } => (endpoint_type.as_ref(), endpoint.as_ref(), "", 1),
                ProofRequest::DiscloseId {
                    endpoint_type,
                    endpoint,
                    user_defined_data,
                    version,
                    ..
                } => (
                    Some(endpoint_type),
                    Some(endpoint),
                    user_defined_data.as_str(),
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

pub struct NitroRng {
    fd: i32, // File descriptor for NitroSecureModule
}

impl NitroRng {
    pub fn new(fd: i32) -> Self {
        Self { fd }
    }
}

impl RngCore for NitroRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        unsafe {
            let mut buf_len = dest.len();
            let res = nsm_get_random(self.fd, dest.as_mut_ptr(), &mut buf_len);
            match res {
                ErrorCode::Success => (),
                _ => panic!("Failed to get random bytes: {:?}", res),
            }
        }
    }

    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        unsafe {
            let mut buf_len = dest.len();
            let res = nsm_get_random(self.fd, dest.as_mut_ptr(), &mut buf_len);
            match res {
                ErrorCode::Success => Ok(()),
                _ => Err(rand_core::Error::new(io::Error::new(
                    io::ErrorKind::Other,
                    "Could not generate random data",
                ))),
            }
        }
    }
}

impl CryptoRng for NitroRng {}
