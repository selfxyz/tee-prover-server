use std::num::NonZeroUsize;

// use std::collections::HashMap;
use lru::LruCache;
use tokio::sync::Mutex;

pub struct LruStore {
    ecdh_store: Mutex<LruCache<String, Vec<u8>>>,
}

impl LruStore {
    pub fn new(size: usize) -> Self {
        Self {
            ecdh_store: Mutex::new(LruCache::new(NonZeroUsize::new(size).unwrap())),
        }
    }
}

impl LruStore {
    pub async fn insert_new_agreement(
        &self,
        uuid: uuid::Uuid,
        shared_secret: Vec<u8>,
    ) -> Result<(), String> {
        let mut cache = self.ecdh_store.lock().await;

        if cache.contains(&uuid.to_string()) {
            return Err("Duplicate uuid".to_string());
        } else {
            cache.put(uuid.to_string(), shared_secret);
        }

        return Ok(());
    }

    pub async fn get_shared_secret(&self, uuid: &uuid::Uuid) -> Option<Vec<u8>> {
        let mut cache = self.ecdh_store.lock().await;
        cache.get(&uuid.to_string()).map(|x| x.clone())
    }

    pub async fn remove_agreement(&self, uuid: &uuid::Uuid) {
        let mut cache = self.ecdh_store.lock().await;
        cache.pop(&uuid.to_string());
    }
}
