use std::sync::Arc;

use redis::Connection;
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
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);

        let value = TwoFATuple(
            login_attempt_id.as_ref().to_string(),
            code.as_ref().to_string(),
        );

        let value =
            serde_json::to_string(&value).map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        let mut conn = self.conn.write().await;

        redis::Cmd::set_ex(&key, value, TEN_MINUTES)
            .query(&mut conn)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = get_key(email);

        let mut conn = self.conn.write().await;

        let value: String = redis::Cmd::get(&key)
            .query(&mut conn)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        let TwoFATuple(login_attempt_id, code) =
            serde_json::from_str(&value).map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        let login_attempt_id = LoginAttemptId::parse(login_attempt_id)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        let code = TwoFACode::parse(code).map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        Ok((login_attempt_id, code))
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(email);

        let mut conn = self.conn.write().await;

        redis::Cmd::del(&key)
            .query(&mut conn)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES: u64 = 10 * 60;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref())
}
