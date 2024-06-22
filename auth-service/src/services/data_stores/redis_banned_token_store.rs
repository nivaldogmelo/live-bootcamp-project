use std::sync::Arc;

use color_eyre::eyre::Context;
use redis::{Commands, Connection};
use secrecy::{ExposeSecret, Secret};
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
    #[tracing::instrument(name = "Adding token to banned tokens", skip_all)]
    async fn add_banned_token(
	&mut self,
	token: Secret<String>,
    ) -> Result<(), BannedTokenStoreError> {
	let key = get_key(&token);

	let ttl: u64 = TOKEN_TTL_SECONDS
	    .try_into()
	    .wrap_err("failed to convert TTL to u64")
	    .map_err(BannedTokenStoreError::UnexpectedError)?;

	let mut conn = self.conn.write().await;

	conn.set_ex(key.expose_secret(), true, ttl)
	    .wrap_err("failed to set banned token in Redis")
	    .map_err(BannedTokenStoreError::UnexpectedError)?;

	Ok(())
    }

    #[tracing::instrument(name = "Checking if token is banned", skip_all)]
    async fn is_banned_token(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError> {
	let key = get_key(token);

	let mut conn = self.conn.write().await;

	let is_banned: bool = conn
	    .exists(key.expose_secret())
	    .wrap_err("failed to check if token exists in Redis")
	    .map_err(BannedTokenStoreError::UnexpectedError)?;

	Ok(is_banned)
    }
}

const BANNED_TOKENS_KEY_PREFIX: &str = "banned_token:";

#[tracing::instrument(name = "Building key format for redis", skip_all)]
fn get_key(token: &Secret<String>) -> Secret<String> {
    Secret::new(format!(
	"{}{}",
	BANNED_TOKENS_KEY_PREFIX,
	token.expose_secret()
    ))
}
