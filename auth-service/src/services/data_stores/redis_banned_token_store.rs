use std::sync::Arc;

use redis::Connection;
use tokio::sync::RwLock;

use crate::{
    domain::{BannedTokenStore, BannedTokenStoreError},
    utils::auth::TOKEN_TTL_SECONDS,
};

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn add_banned_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        let key = get_key(&token);

        let mut conn = self.conn.write().await;

        redis::Cmd::set_ex(&key, true, TOKEN_TTL_SECONDS as u64)
            .query(&mut conn)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn is_banned_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        let key = get_key(token);

        let mut conn = self.conn.write().await;

        let is_banned: bool = redis::cmd("EXISTS")
            .arg(&key)
            .query(&mut conn)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)?;

        Ok(is_banned)
    }
}

const BANNED_TOKENS_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKENS_KEY_PREFIX, token)
}
