use std::collections::HashSet;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default, Clone)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_banned_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        self.tokens.insert(token);
        Ok(())
    }

    async fn is_banned_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.contains(token))
    }
}

#[tokio::test]
async fn test_add_banned_token() {
    let mut store = HashsetBannedTokenStore::default();

    let token = "token".to_owned();

    let result = store.add_banned_token(token.clone()).await;

    assert!(result.is_ok());
    assert!(store.tokens.contains(&token));
}

#[tokio::test]
async fn test_is_banned_token() {
    let mut store = HashsetBannedTokenStore::default();

    let token = "token".to_owned();
    store.tokens.insert(token.clone());

    let result = store.is_banned_token(&token).await;

    assert!(result.unwrap());
}
