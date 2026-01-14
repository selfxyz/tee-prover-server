use tee_server::store::{KeyMaterial, LruStore};
use uuid::Uuid;

/// Tests basic LruStore insert and retrieve operations with legacy P-256 key material.
/// Verifies that stored shared secrets can be successfully retrieved.
#[tokio::test]
async fn test_store_insert_and_retrieve_legacy() {
    let store = LruStore::new(100);
    let uuid = Uuid::new_v4();
    let shared_secret = vec![0x42; 32];

    let material = KeyMaterial::LegacyP256(shared_secret.clone());

    // inserting key material
    store
        .insert_new_agreement(uuid, material)
        .await
        .expect("Insert should succeed");

    // retrieving shared secret
    let retrieved = store.get_shared_secret(&uuid).await;
    assert!(retrieved.is_some(), "Should retrieve shared secret");
    assert_eq!(retrieved.unwrap(), shared_secret, "Shared secrets should match");
}

/// Tests LruStore with PQXDH pending state insertion and retrieval.
/// Verifies that pending state does not return session keys until completion.
#[tokio::test]
async fn test_store_pqxdh_pending() {
    let store = LruStore::new(100);
    let uuid = Uuid::new_v4();

    let x25519_shared = vec![0x01; 32];
    let kyber_secret = vec![0x02; 2400];

    let material = KeyMaterial::PqxdhPending {
        x25519_shared: x25519_shared.clone(),
        kyber_secret: kyber_secret.clone(),
    };

    // inserting pending material
    store
        .insert_new_agreement(uuid, material)
        .await
        .expect("Insert should succeed");

    // get_shared_secret should return None for pending state
    let retrieved = store.get_shared_secret(&uuid).await;
    assert!(retrieved.is_none(), "Should not return shared secret for pending state");

    // get_key_material should return the pending state
    let material_retrieved = store.get_key_material(&uuid).await;
    assert!(material_retrieved.is_some(), "Should retrieve key material");

    match material_retrieved.unwrap() {
        KeyMaterial::PqxdhPending {
            x25519_shared: x,
            kyber_secret: k,
        } => {
            assert_eq!(x, x25519_shared, "X25519 shared secrets should match");
            assert_eq!(k, kyber_secret, "Kyber secret keys should match");
        }
        _ => panic!("Expected PqxdhPending state"),
    }
}

/// Tests updating PQXDH state from pending to complete via update_key_material.
/// Simulates the transition that occurs during key_exchange RPC call.
#[tokio::test]
async fn test_store_pqxdh_update_to_complete() {
    let store = LruStore::new(100);
    let uuid = Uuid::new_v4();

    // inserting pending state
    let material = KeyMaterial::PqxdhPending {
        x25519_shared: vec![0x01; 32],
        kyber_secret: vec![0x02; 2400],
    };

    store
        .insert_new_agreement(uuid, material)
        .await
        .expect("Insert should succeed");

    // updating to complete state
    let session_key = vec![0x99; 32];
    let complete_material = KeyMaterial::PqxdhComplete(session_key.clone());

    store
        .update_key_material(&uuid, complete_material)
        .await
        .expect("Update should succeed");

    // verifying update
    let retrieved = store.get_shared_secret(&uuid).await;
    assert!(retrieved.is_some(), "Should retrieve shared secret after completion");
    assert_eq!(retrieved.unwrap(), session_key, "Session keys should match");
}

/// Tests that duplicate UUID insertion fails with an error.
/// Ensures each UUID can only be used once per handshake session.
#[tokio::test]
async fn test_store_duplicate_uuid_fails() {
    let store = LruStore::new(100);
    let uuid = Uuid::new_v4();

    let material1 = KeyMaterial::LegacyP256(vec![0x01; 32]);
    let material2 = KeyMaterial::LegacyP256(vec![0x02; 32]);

    // first insert should succeed
    store
        .insert_new_agreement(uuid, material1)
        .await
        .expect("First insert should succeed");

    // second insert with same UUID should fail
    let result = store.insert_new_agreement(uuid, material2).await;
    assert!(result.is_err(), "Duplicate UUID should fail");
}

/// Tests updating non-existent UUID fails with an error.
/// Prevents invalid state transitions for uninitialized sessions.
#[tokio::test]
async fn test_store_update_nonexistent_fails() {
    let store = LruStore::new(100);
    let uuid = Uuid::new_v4();

    let material = KeyMaterial::PqxdhComplete(vec![0x99; 32]);

    // updating non-existent UUID should fail
    let result = store.update_key_material(&uuid, material).await;
    assert!(result.is_err(), "Update of non-existent UUID should fail");
}

/// Tests removing key material from store via remove_agreement.
/// Used for cleanup on errors or after successful proof submission.
#[tokio::test]
async fn test_store_remove_agreement() {
    let store = LruStore::new(100);
    let uuid = Uuid::new_v4();

    let material = KeyMaterial::LegacyP256(vec![0x42; 32]);

    store
        .insert_new_agreement(uuid, material)
        .await
        .expect("Insert should succeed");

    // verifying key material exists
    assert!(store.get_key_material(&uuid).await.is_some(), "Key material should exist");

    // removing key material
    store.remove_agreement(&uuid).await;

    // verifying key material is gone
    assert!(store.get_key_material(&uuid).await.is_none(), "Key material should be removed");
}

/// Tests LRU eviction policy when cache reaches capacity.
/// Verifies that least recently used entries are evicted when cache is full.
#[tokio::test]
async fn test_store_lru_eviction() {
    let store = LruStore::new(2); // small cache size
    let uuid1 = Uuid::new_v4();
    let uuid2 = Uuid::new_v4();
    let uuid3 = Uuid::new_v4();

    let material1 = KeyMaterial::LegacyP256(vec![0x01; 32]);
    let material2 = KeyMaterial::LegacyP256(vec![0x02; 32]);
    let material3 = KeyMaterial::LegacyP256(vec![0x03; 32]);

    // inserting first two entries
    store.insert_new_agreement(uuid1, material1).await.unwrap();
    store.insert_new_agreement(uuid2, material2).await.unwrap();

    // both should be retrievable
    assert!(store.get_key_material(&uuid1).await.is_some());
    assert!(store.get_key_material(&uuid2).await.is_some());

    // inserting third entry should evict the least recently used (uuid1)
    store.insert_new_agreement(uuid3, material3).await.unwrap();

    // uuid1 should be evicted
    assert!(store.get_key_material(&uuid1).await.is_none(), "First UUID should be evicted");
    assert!(store.get_key_material(&uuid2).await.is_some(), "Second UUID should still exist");
    assert!(store.get_key_material(&uuid3).await.is_some(), "Third UUID should exist");
}

/// Tests that get_shared_secret returns correct values for all KeyMaterial variants.
/// Legacy and Complete return keys, Pending returns None until handshake completes.
#[tokio::test]
async fn test_store_get_shared_secret_variants() {
    let store = LruStore::new(100);

    // legacy P-256 should return the shared secret
    let uuid1 = Uuid::new_v4();
    let legacy_key = vec![0x42; 32];
    store
        .insert_new_agreement(uuid1, KeyMaterial::LegacyP256(legacy_key.clone()))
        .await
        .unwrap();
    assert_eq!(store.get_shared_secret(&uuid1).await.unwrap(), legacy_key);

    // PQXDH pending should return None
    let uuid2 = Uuid::new_v4();
    store
        .insert_new_agreement(
            uuid2,
            KeyMaterial::PqxdhPending {
                x25519_shared: vec![0x01; 32],
                kyber_secret: vec![0x02; 2400],
            },
        )
        .await
        .unwrap();
    assert!(store.get_shared_secret(&uuid2).await.is_none());

    // PQXDH complete should return the session key
    let uuid3 = Uuid::new_v4();
    let session_key = vec![0x99; 32];
    store
        .insert_new_agreement(uuid3, KeyMaterial::PqxdhComplete(session_key.clone()))
        .await
        .unwrap();
    assert_eq!(store.get_shared_secret(&uuid3).await.unwrap(), session_key);
}
