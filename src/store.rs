use std::num::NonZeroUsize;

// use std::collections::HashMap;
use lru::LruCache;
use tokio::sync::Mutex;

/// Key material stored in the LRU cache during handshake.
#[derive(Clone)]
pub enum KeyMaterial {
    /// Legacy P-256 ECDH shared secret (final session key).
    LegacyP256(Vec<u8>),
    /// PQXDH pending state: X25519 shared secret and Kyber secret key.
    /// Waiting for client to send Kyber ciphertext in key_exchange call.
    PqxdhPending {
        x25519_shared: Vec<u8>,
        kyber_secret: Vec<u8>,
    },
    /// PQXDH complete: final session key derived via HKDF.
    PqxdhComplete(Vec<u8>),
}

pub struct LruStore {
    ecdh_store: Mutex<LruCache<String, KeyMaterial>>,
}

impl LruStore {
    pub fn new(size: usize) -> Self {
        Self {
            ecdh_store: Mutex::new(LruCache::new(NonZeroUsize::new(size).unwrap())),
        }
    }
}

impl LruStore {
    /// Inserts new key material for a UUID, returning an error if UUID already exists.
    /// Used during initial handshake to store either legacy P-256 keys or PQXDH pending state.
    pub async fn insert_new_agreement(
        &self,
        uuid: uuid::Uuid,
        key_material: KeyMaterial,
    ) -> Result<(), String> {
        let mut cache = self.ecdh_store.lock().await;

        if cache.contains(&uuid.to_string()) {
            return Err("Duplicate uuid".to_string());
        } else {
            cache.put(uuid.to_string(), key_material);
        }

        return Ok(());
    }

    /// Retrieves key material for a UUID without removing it from the store.
    /// Returns None if UUID not found. Used to check handshake state.
    pub async fn get_key_material(&self, uuid: &uuid::Uuid) -> Option<KeyMaterial> {
        let mut cache = self.ecdh_store.lock().await;
        cache.get(&uuid.to_string()).map(|x| x.clone())
    }

    /// Updates existing key material for a UUID, typically transitioning from pending to complete state.
    /// Returns an error if UUID not found. Used during PQXDH key_exchange to finalize session key.
    pub async fn update_key_material(
        &self,
        uuid: &uuid::Uuid,
        key_material: KeyMaterial,
    ) -> Result<(), String> {
        let mut cache = self.ecdh_store.lock().await;
        if cache.contains(&uuid.to_string()) {
            cache.put(uuid.to_string(), key_material);
            Ok(())
        } else {
            Err("UUID not found".to_string())
        }
    }

    /// Retrieves the final session key for a UUID if handshake is complete.
    /// Returns None if UUID not found or still in pending state.
    /// Used by submit_request to decrypt client payloads.
    pub async fn get_shared_secret(&self, uuid: &uuid::Uuid) -> Option<Vec<u8>> {
        let mut cache = self.ecdh_store.lock().await;
        cache.get(&uuid.to_string()).and_then(|material| match material {
            KeyMaterial::LegacyP256(key) => Some(key.clone()),
            KeyMaterial::PqxdhComplete(key) => Some(key.clone()),
            KeyMaterial::PqxdhPending { .. } => None,
        })
    }

    /// Removes key material for a UUID from the store.
    /// Used for cleanup on errors or after proof submission.
    pub async fn remove_agreement(&self, uuid: &uuid::Uuid) {
        let mut cache = self.ecdh_store.lock().await;
        cache.pop(&uuid.to_string());
    }
}
