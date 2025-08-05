use crate::db::fail_proof;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use serde_bytes::ByteBuf;

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

    use hyper::body::Buf;
    use hyper::{Body, Client, Request};
    use hyperlocal::{UnixClientExt, Uri as HyperlocalUri};
    use serde::Serialize;

    #[derive(Serialize)]
    struct TokenRequest<'a> {
        audience: &'a str,
        token_type: &'a str,
        nonces: Vec<&'a str>,
    }

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
