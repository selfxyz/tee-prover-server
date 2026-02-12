use crate::db::fail_proof;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};

pub fn decrypt(
    key: [u8; 32],
    cipher_text: Vec<u8>,
    auth_tag: &[u8],
    nonce: &[u8],
) -> Result<String, String> {
    let key: &Key<Aes256Gcm> = (&key).into();

    let cipher = Aes256Gcm::new(key);

    let mut ciphertext_with_tag = cipher_text;
    ciphertext_with_tag.extend_from_slice(auth_tag);

    let plaintext_bytes =
        match cipher.decrypt(Nonce::from_slice(nonce), ciphertext_with_tag.as_ref()) {
            Ok(plaintext) => plaintext,
            Err(e) => return Err(e.to_string()),
        };

    match String::from_utf8(plaintext_bytes) {
        Ok(plaintext) => Ok(plaintext),
        Err(e) => Err(e.to_string()),
    }
}

pub fn get_tmp_folder_path(uuid: &String) -> String {
    format!("./tmp_{}", uuid)
}

pub async fn cleanup(uuid: uuid::Uuid, pool: &sqlx::Pool<sqlx::Postgres>, reason: String) {
    let tmp_folder = get_tmp_folder_path(&uuid.to_string());
    let _ = fail_proof(uuid, &pool, reason).await;
    let _ = tokio::fs::remove_dir_all(tmp_folder).await;
}

pub mod attestation {
    use std::error::Error;

    #[cfg(feature = "test_mode")]
    use base64::{engine::general_purpose, Engine};

    #[cfg(not(feature = "test_mode"))]
    use hyper::body::Buf;
    #[cfg(not(feature = "test_mode"))]
    use hyper::{Body, Client, Request};
    #[cfg(not(feature = "test_mode"))]
    use hyperlocal::{UnixClientExt, Uri as HyperlocalUri};
    #[cfg(not(feature = "test_mode"))]
    use serde::Serialize;

    #[cfg(not(feature = "test_mode"))]
    #[derive(Serialize)]
    struct TokenRequest<'a> {
        audience: &'a str,
        token_type: &'a str,
        nonces: Vec<&'a str>,
    }

    /// Generates a mock attestation token for local testing (test_mode feature only).
    /// Returns a JWT-like structure with base64url-encoded header, payload, and signature.
    /// NOT cryptographically valid - for development and testing purposes only.
    #[cfg(feature = "test_mode")]
    pub async fn get_custom_token_bytes(nonces: Vec<&str>) -> Result<Vec<u8>, Box<dyn Error>> {
        // creating mock JWT header
        let mock_header = r#"{"alg":"RS256","typ":"JWT"}"#;

        // creating mock JWT payload with nonces and timestamps
        let mock_payload = format!(
            r#"{{"nonces":[{}],"iat":{},"exp":{}}}"#,
            nonces.iter().map(|n| format!("\"{}\"", n)).collect::<Vec<_>>().join(","),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600,
        );

        // encoding header and payload using base64url (not crypto-safe, just for structure)
        let encoded_header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mock_header);
        let encoded_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mock_payload);
        let mock_signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("mock_signature_for_testing");

        // assembling JWT structure: header.payload.signature
        let mock_jwt = format!("{}.{}.{}", encoded_header, encoded_payload, mock_signature);

        println!("Mock attestation token generated for nonces: {:?}", nonces);
        Ok(mock_jwt.into_bytes())
    }

    #[cfg(not(feature = "test_mode"))]
    pub async fn get_custom_token_bytes(nonces: Vec<&str>) -> Result<Vec<u8>, Box<dyn Error>> {
        let request_body = TokenRequest {
            audience: "USER",
            token_type: "PKI",
            nonces,
        };
        let json = serde_json::to_string(&request_body)?;

        let client = Client::unix();
        let socket_path = "/run/container_launcher/teeserver.sock";

        // Fix: explicit type for URI
        let uri: hyper::Uri = HyperlocalUri::new(socket_path, "/v1/token").into();

        let req = Request::post(uri)
            .header("Content-Type", "application/json")
            .body(Body::from(json))?;

        let res = client.request(req).await?;
        let mut bytes = hyper::body::aggregate(res).await?;
        let token_bytes = bytes.copy_to_bytes(bytes.remaining()).to_vec();

        println!("Token Response: {}", String::from_utf8_lossy(&token_bytes));
        Ok(token_bytes)
    }
}
