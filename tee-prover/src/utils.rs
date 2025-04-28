use crate::db::fail_proof;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use aws_nitro_enclaves_nsm_api::api::{ErrorCode, Request, Response};
use aws_nitro_enclaves_nsm_api::driver::nsm_process_request;
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

pub fn get_attestation(
    fd: i32,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
) -> Result<Vec<u8>, ErrorCode> {
    let request = Request::Attestation {
        user_data: user_data.map(|buf| ByteBuf::from(buf)),
        nonce: nonce.map(|buf| ByteBuf::from(buf)),
        public_key: public_key.map(|buf| ByteBuf::from(buf)),
    };

    match nsm_process_request(fd, request) {
        Response::Attestation { document } => Ok(document),
        Response::Error(err) => Err(err),
        _ => Err(ErrorCode::InvalidResponse), //shouldn't get triggered
    }
}

pub async fn cleanup(uuid: uuid::Uuid, pool: &sqlx::Pool<sqlx::Postgres>, reason: String) {
    let tmp_folder = get_tmp_folder_path(&uuid.to_string());
    let _ = fail_proof(uuid, &pool, reason).await;
    let _ = tokio::fs::remove_dir_all(tmp_folder).await;
}

pub unsafe fn nsm_get_random(fd: i32, buf: *mut u8, buf_len: &mut usize) -> ErrorCode {
    if fd < 0 || buf.is_null() || buf_len == &0 {
        return ErrorCode::InvalidArgument;
    }
    match nsm_process_request(fd, Request::GetRandom) {
        Response::GetRandom { random } => {
            *buf_len = std::cmp::min(*buf_len, random.len());
            std::ptr::copy_nonoverlapping(random.as_ptr(), buf, *buf_len);
            ErrorCode::Success
        }
        Response::Error(err) => err,
        _ => ErrorCode::InvalidResponse,
    }
}
