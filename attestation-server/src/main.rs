mod nitro_rng;

use aws_nitro_enclaves_nsm_api::{
    api::{ErrorCode, Request, Response},
    driver::{nsm_init, nsm_process_request},
};
use jsonrpsee::ResponsePayload;
use jsonrpsee::{proc_macros::rpc, types::ErrorObjectOwned};
use jsonrpsee::{server::ServerBuilder, types};
use p256::{ecdh::EphemeralSecret, elliptic_curve::PublicKey};
use serde_bytes::ByteBuf;
use std::net::SocketAddr;

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
        _ => Err(ErrorCode::InvalidResponse),
    }
}

#[rpc(server)]
pub trait Attestation {
    #[method(name = "attestation")]
    fn get_attestation(&self, user_pubkey: Vec<u8>)
    -> ResponsePayload<'static, (Vec<u8>, Vec<u8>)>;
}

pub struct AttestationServerImpl {
    fd: i32,
}

impl AttestationServerImpl {
    pub fn new(fd: i32) -> Self {
        Self { fd }
    }
}

impl AttestationServer for AttestationServerImpl {
    fn get_attestation(
        &self,
        user_pubkey: Vec<u8>,
    ) -> ResponsePayload<'static, (Vec<u8>, Vec<u8>)> {
        let mut nitro_rng = nitro_rng::NitroRng::new(self.fd);

        let my_private_key = EphemeralSecret::random(&mut nitro_rng);
        let my_public_key = PublicKey::from(&my_private_key).to_sec1_bytes().to_vec();

        let attestation = match get_attestation(
            self.fd,
            Some(user_pubkey.clone()),
            None,
            Some(my_public_key.clone()),
        ) {
            Ok(attestation) => attestation,
            Err(err) => {
                return ResponsePayload::error(ErrorObjectOwned::owned::<String>(
                    types::ErrorCode::InternalError.code(),
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

        let shared_secret = my_private_key
            .diffie_hellman(&their_public_key)
            .raw_secret_bytes()
            .to_vec();

        ResponsePayload::success((attestation, shared_secret))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr: SocketAddr = "172.17.0.1:3001".parse()?;

    let server = ServerBuilder::default().build(addr).await?;

    let fd = nsm_init();
    let api = AttestationServerImpl { fd };

    let module = api.into_rpc();

    let handle = server.start(module);
    handle.stopped().await;

    Ok(())
}
