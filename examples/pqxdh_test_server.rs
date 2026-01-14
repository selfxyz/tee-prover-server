/// Minimal TEE server for PQXDH handshake testing.
/// This server only implements hello and key_exchange methods without requiring:
/// - TEE attestation service (mocked)
/// - PostgreSQL database
/// - Circuit/zkey files
/// - Proof generation
///
/// Run with: cargo run --example pqxdh_test_server --features test_mode
///
/// The server will listen on http://127.0.0.1:9944 by default.

use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::types;
use jsonrpsee::{types::ErrorObjectOwned, ResponsePayload};
use std::sync::Arc;

use tee_server::store::{KeyMaterial, LruStore};
use tee_server::types::HelloResponse;

// importing PQXDH dependencies
use base64::engine::{general_purpose, Engine};
use hkdf::Hkdf;
use ml_kem::kem::Decapsulate;
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::PublicKey;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret as X25519Secret, PublicKey as X25519PublicKey};

// mock attestation function for test mode
async fn get_mock_attestation(nonces: Vec<&str>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mock_header = r#"{"alg":"RS256","typ":"JWT"}"#;
    let mock_payload = format!(
        r#"{{"nonces":[{}],"iat":{},"exp":{}}}"#,
        nonces
            .iter()
            .map(|n| format!("\"{}\"", n))
            .collect::<Vec<_>>()
            .join(","),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600,
    );

    let encoded_header = general_purpose::URL_SAFE_NO_PAD.encode(mock_header);
    let encoded_payload = general_purpose::URL_SAFE_NO_PAD.encode(mock_payload);
    let mock_signature = general_purpose::URL_SAFE_NO_PAD.encode("mock_sig");

    let mock_jwt = format!("{}.{}.{}", encoded_header, encoded_payload, mock_signature);
    Ok(mock_jwt.into_bytes())
}

#[rpc(server, namespace = "openpassport")]
pub trait TestRpc {
    #[method(name = "health")]
    async fn health(&self) -> ResponsePayload<'static, String>;

    #[method(name = "hello")]
    async fn hello(
        &self,
        user_pubkey: Vec<u8>,
        uuid: uuid::Uuid,
        supported_suites: Vec<String>,
    ) -> ResponsePayload<'static, HelloResponse>;

    #[method(name = "key_exchange")]
    async fn key_exchange(
        &self,
        uuid: uuid::Uuid,
        kyber_ciphertext: Vec<u8>,
    ) -> ResponsePayload<'static, String>;

    /// DEBUG ONLY: Returns the derived session key for testing.
    /// DO NOT use in production, as keys should never be exposed!
    #[method(name = "debug_get_session_key")]
    async fn debug_get_session_key(&self, uuid: uuid::Uuid) -> ResponsePayload<'static, Vec<u8>>;
}

pub struct TestRpcServerImpl {
    store: Arc<LruStore>,
}

impl TestRpcServerImpl {
    pub fn new(store: Arc<LruStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl TestRpcServer for TestRpcServerImpl {
    async fn health(&self) -> ResponsePayload<'static, String> {
        ResponsePayload::success("OK".to_string())
    }

    async fn hello(
        &self,
        user_pubkey: Vec<u8>,
        uuid: uuid::Uuid,
        supported_suites: Vec<String>,
    ) -> ResponsePayload<'static, HelloResponse> {
        println!("Received hello from UUID: {}", uuid);
        println!("Supported suites: {:?}", supported_suites);

        // negotiating suite
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

        println!("Selected suite: {}", selected_suite);

        if selected_suite == "Self-PQXDH-1" {
            // PQXDH flow
            if user_pubkey.len() != 32 {
                return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                    types::ErrorCode::InvalidRequest.code(),
                    format!("X25519 public key must be 32 bytes, got {}", user_pubkey.len()),
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

            // storing pending state
            let key_material = KeyMaterial::PqxdhPending {
                x25519_shared: x25519_shared.as_bytes().to_vec(),
                kyber_secret: decapsulation_key.as_bytes().to_vec(),
            };

            match self.store.insert_new_agreement(uuid, key_material).await {
                Ok(_) => println!("Stored pending PQXDH state for UUID: {}", uuid),
                Err(e) => {
                    return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                        types::ErrorCode::InvalidRequest.code(),
                        format!("UUID already exists: {}", e),
                        None,
                    ));
                }
            }

            // encoding public keys
            let x25519_b64 = general_purpose::STANDARD.encode(x25519_public.as_bytes());
            let kyber_b64 = general_purpose::STANDARD.encode(encapsulation_key.as_bytes());

            // generating mock attestation
            let attestation_result =
                get_mock_attestation(vec![&x25519_b64, &kyber_b64, selected_suite])
                    .await
                    .map_err(|e| format!("{:?}", e));

            let attestation = match attestation_result {
                Ok(att) => att,
                Err(e) => {
                    self.store.remove_agreement(&uuid).await;
                    return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                        types::ErrorCode::InternalError.code(),
                        format!("Attestation failed: {}", e),
                        None,
                    ));
                }
            };

            let encaps_key_bytes = encapsulation_key.as_bytes();
            println!(
                "Returning PQXDH response: X25519 pubkey {} bytes, Kyber pubkey {} bytes",
                x25519_public.as_bytes().len(),
                encaps_key_bytes.len()
            );
            println!("Server Kyber public key (first 16 bytes): {:02x?}", &encaps_key_bytes[..16]);

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
            // legacy P-256 flow
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
                Err(e) => {
                    return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                        types::ErrorCode::InvalidParams.code(),
                        format!("{:?}", e),
                        None,
                    ));
                }
            };

            let their_key_b64 = general_purpose::STANDARD
                .encode(&their_public_key.to_encoded_point(true).to_bytes());
            let my_key_b64 =
                general_purpose::STANDARD.encode(&my_public_key.to_encoded_point(true).to_bytes());

            let attestation_result = get_mock_attestation(vec![&their_key_b64, &my_key_b64])
                .await
                .map_err(|e| format!("{:?}", e));

            let attestation = match attestation_result {
                Ok(att) => att,
                Err(e) => {
                    return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                        types::ErrorCode::InternalError.code(),
                        format!("Attestation failed: {}", e),
                        None,
                    ));
                }
            };

            let shared_secret = my_private_key
                .diffie_hellman(&their_public_key)
                .raw_secret_bytes()
                .to_vec();

            let key_material = KeyMaterial::LegacyP256(shared_secret);

            match self.store.insert_new_agreement(uuid, key_material).await {
                Ok(_) => println!("Stored legacy P-256 key for UUID: {}", uuid),
                Err(e) => {
                    return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                        types::ErrorCode::InvalidRequest.code(),
                        format!("UUID already exists: {}", e),
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
        println!("Received key_exchange from UUID: {}", uuid);
        println!("Kyber ciphertext length: {}", kyber_ciphertext.len());

        // validating ciphertext length
        const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;
        if kyber_ciphertext.len() != ML_KEM_768_CIPHERTEXT_SIZE {
            return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                types::ErrorCode::InvalidRequest.code(),
                format!(
                    "Invalid Kyber ciphertext: expected {} bytes, got {}",
                    ML_KEM_768_CIPHERTEXT_SIZE,
                    kyber_ciphertext.len()
                ),
                None,
            ));
        }

        // retrieving pending state
        let key_material = match self.store.get_key_material(&uuid).await {
            Some(m) => m,
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

        // decapsulating
        type DecapKey = <MlKem768 as KemCore>::DecapsulationKey;
        let decaps_key_bytes: &Encoded<DecapKey> = kyber_secret[..].try_into().map_err(|_| {
            "Invalid decapsulation key length"
        }).unwrap();
        let decaps_key = DecapKey::from_bytes(decaps_key_bytes);

        // parsing ciphertext from bytes
        let ct: ml_kem::Ciphertext<MlKem768> = kyber_ciphertext[..].try_into().map_err(|_| {
            "Invalid ciphertext length"
        }).unwrap();

        let kyber_shared = decaps_key.decapsulate(&ct).map_err(|e| {
            format!("Decapsulation failed: {:?}", e)
        }).unwrap();
        let kyber_shared_bytes: &[u8] = kyber_shared.as_ref();

        println!("Server X25519 shared secret (first 8 bytes): {:02x?}", &x25519_shared[..8]);
        println!("Server Kyber shared secret (first 8 bytes): {:02x?}", &kyber_shared_bytes[..8]);

        // deriving session key using Signal PQXDH spec
        let f_prefix = vec![0xff; 32];
        let mut ikm = Vec::with_capacity(f_prefix.len() + x25519_shared.len() + kyber_shared_bytes.len());
        ikm.extend_from_slice(&f_prefix);
        ikm.extend_from_slice(&x25519_shared);
        ikm.extend_from_slice(&kyber_shared_bytes);

        let salt = vec![0u8; 32];
        let info = b"Self-PQXDH-1_X25519_SHA-256_ML-KEM-768";

        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut session_key = vec![0u8; 32];
        if let Err(e) = hkdf.expand(info, &mut session_key) {
            self.store.remove_agreement(&uuid).await;
            return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                types::ErrorCode::InternalError.code(),
                format!("HKDF failed: {:?}", e),
                None,
            ));
        }

        println!("Derived session key (first 8 bytes): {:02x?}", &session_key[..8]);

        // updating store
        let complete_material = KeyMaterial::PqxdhComplete(session_key);
        if let Err(e) = self.store.update_key_material(&uuid, complete_material).await {
            self.store.remove_agreement(&uuid).await;
            return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                types::ErrorCode::InternalError.code(),
                format!("Failed to update key material: {}", e),
                None,
            ));
        }

        println!("✅ Key exchange complete for UUID: {}", uuid);
        ResponsePayload::success("key_exchange_complete".to_string())
    }

    async fn debug_get_session_key(&self, uuid: uuid::Uuid) -> ResponsePayload<'static, Vec<u8>> {
        match self.store.get_shared_secret(&uuid).await {
            Some(key) => {
                println!("DEBUG: Returning session key for UUID: {}", uuid);
                ResponsePayload::success(key)
            }
            None => ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                types::ErrorCode::InvalidRequest.code(),
                "UUID not found or not in complete state",
                None,
            )),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:9944";
    println!("🚀 Starting PQXDH test server on {}", addr);
    println!("📝 This server is for testing PQXDH handshake only");
    println!("   - Attestation is mocked (not cryptographically valid)");
    println!("   - No database required");
    println!("   - Only hello and key_exchange methods available\n");

    let server = Server::builder().build(addr).await?;
    let store = Arc::new(LruStore::new(1000));

    let handle = server.start(TestRpcServerImpl::new(store).into_rpc());

    println!("✅ Server ready at ws://{}\n", addr);
    println!("Press Ctrl+C to stop\n");

    handle.stopped().await;
    Ok(())
}
