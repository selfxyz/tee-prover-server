use alloy_primitives::keccak256;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};

#[derive(Clone)]
pub struct EnclaveKey {
    signing_key: SigningKey,
}

impl EnclaveKey {
    pub fn generate() -> Self {
        EnclaveKey {
            signing_key: SigningKey::random(&mut rand::thread_rng()),
        }
    }

    pub fn address(&self) -> String {
        address_from_verifying_key(self.signing_key.verifying_key())
    }

    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 65], String> {
        let (sig, recid) = self
            .signing_key
            .sign_prehash_recoverable(digest)
            .map_err(|e| e.to_string())?;
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        // Solidity's ecrecover expects v in {27, 28}
        out[64] = recid.to_byte() + 27;
        Ok(out)
    }
}

// Compile-time guarantee: EnclaveKey must be movable into a long-lived tokio
// task and cloned across concurrent signing calls.
const _: fn() = || {
    fn assert_clone_send_sync<T: Clone + Send + Sync>() {}
    assert_clone_send_sync::<EnclaveKey>();
};

fn address_from_verifying_key(vk: &VerifyingKey) -> String {
    let uncompressed = vk.to_encoded_point(false);
    // skip the 0x04 SEC1 prefix; address is the last 20 bytes of keccak(pubkey)
    let hash = keccak256(&uncompressed.as_bytes()[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

pub fn recover_address(digest: &[u8; 32], sig: &[u8; 65]) -> Result<String, String> {
    let signature = Signature::from_slice(&sig[..64]).map_err(|e| e.to_string())?;
    let recid = RecoveryId::from_byte(sig[64].saturating_sub(27))
        .ok_or_else(|| "invalid recovery id".to_string())?;
    let vk = VerifyingKey::recover_from_prehash(digest, &signature, recid)
        .map_err(|e| e.to_string())?;
    Ok(address_from_verifying_key(&vk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_is_lowercase_hex_of_twenty_bytes() {
        let key = EnclaveKey::generate();
        let addr = key.address();
        assert!(addr.starts_with("0x"), "address must be 0x-prefixed: {addr}");
        assert_eq!(addr.len(), 42, "address must be 42 chars: {addr}");
        assert_eq!(addr, addr.to_lowercase(), "address must be lowercase");
    }

    #[test]
    fn signature_recovers_to_the_signing_address() {
        let key = EnclaveKey::generate();
        let digest = [7u8; 32];
        let sig = key.sign_digest(&digest).expect("signing failed");
        assert_eq!(sig.len(), 65);
        assert_eq!(recover_address(&digest, &sig).unwrap(), key.address());
    }
}
