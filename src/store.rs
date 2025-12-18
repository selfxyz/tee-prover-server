use base64::Engine;
use redis::{AsyncCommands, aio::ConnectionManager};

pub struct UuidManager {
    connection_manager: ConnectionManager,
}

impl UuidManager {
    pub fn new(connection_manager: ConnectionManager) -> Self {
        Self {
            connection_manager,
        }
    }
}

impl UuidManager {
    pub async fn insert_new_agreement(
        &self,
        uuid: uuid::Uuid,
        shared_secret: Vec<u8>,
    ) -> Result<(), String> {
        let mut connection = self.connection_manager.clone();
        let uuid_str = uuid.to_string();
        if connection.exists(uuid_str).await.map_err(|e| e.to_string())? {
            return Err("UUID already exists".to_string());
        }
        let shared_secret_base64 = base64::engine::general_purpose::STANDARD.encode(shared_secret);
        connection.set_ex::<String, String, ()>(uuid.to_string(), shared_secret_base64, 60 * 2).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn get_shared_secret(&self, uuid: &uuid::Uuid) -> Option<Vec<u8>> {
        let mut connection = self.connection_manager.clone();
        let uuid_str = uuid.to_string();
        let shared_secret_base64 = connection.get::<String, String>(uuid_str).await.ok();
        shared_secret_base64.map(|x| base64::engine::general_purpose::STANDARD.decode::<&str>(x.as_ref()).ok()).flatten()
    }

    pub async fn remove_agreement(&self, uuid: &uuid::Uuid) {
        let mut connection = self.connection_manager.clone();
        connection.del::<String, ()>(uuid.to_string()).await.ok();
    }
}
