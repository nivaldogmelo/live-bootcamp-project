use std::sync::Arc;

use color_eyre::eyre::Context;
use redis::{Commands, Connection};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError};

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisTwoFACodeStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
	Self { conn }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    #[tracing::instrument(name = "Adding 2FA code", skip_all)]
    async fn add_code(
	&mut self,
	email: Email,
	login_attempt_id: LoginAttemptId,
	code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
	let key = get_key(&email);

	let value = TwoFATuple(
	    login_attempt_id.as_ref().expose_secret().to_string(),
	    code.as_ref().expose_secret().to_string(),
	);

	let value = serde_json::to_string(&value)
	    .wrap_err("failed to serialize 2FA tuple")
	    .map_err(TwoFACodeStoreError::UnexpectedError)?;
	let mut conn = self.conn.write().await;

	conn.set_ex(&key, value, TEN_MINUTES)
	    .wrap_err("failed to set 2FA code")
	    .map_err(TwoFACodeStoreError::UnexpectedError)?;

	Ok(())
    }

    #[tracing::instrument(name = "Getting 2FA code", skip_all)]
    async fn get_code(
	&self,
	email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
	let key = get_key(email);

	let mut conn = self.conn.write().await;

	let value: String = redis::Cmd::get(&key)
	    .query(&mut conn)
	    .wrap_err("failed to deserialize 2FA tuple")
	    .map_err(TwoFACodeStoreError::UnexpectedError)?;

	let TwoFATuple(login_attempt_id, code) = serde_json::from_str(&value)
	    .wrap_err("failed to deserialize 2FA tuple")
	    .map_err(TwoFACodeStoreError::UnexpectedError)?;

	let login_attempt_id = LoginAttemptId::parse(Secret::new(login_attempt_id))
	    .map_err(TwoFACodeStoreError::UnexpectedError)?;
	let code =
	    TwoFACode::parse(Secret::new(code)).map_err(TwoFACodeStoreError::UnexpectedError)?;

	Ok((login_attempt_id, code))
    }

    #[tracing::instrument(name = "Removing 2FA code", skip_all)]
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
	let key = get_key(email);

	let mut conn = self.conn.write().await;

	conn.del(&key)
	    .wrap_err("failed to remove 2FA code")
	    .map_err(TwoFACodeStoreError::UnexpectedError)?;

	Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES: u64 = 10 * 60;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

#[tracing::instrument(name = "Building key format for redis", skip_all)]
fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref().expose_secret())
}
