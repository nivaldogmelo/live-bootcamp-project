use std::collections::HashSet;

use secrecy::{ExposeSecret, Secret};

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default, Clone)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_banned_token(
        &mut self,
        token: Secret<String>,
    ) -> Result<(), BannedTokenStoreError> {
        self.tokens.insert(token.expose_secret().to_owned());
        Ok(())
    }

    async fn is_banned_token(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.contains(token.expose_secret()))
    }
}

#[tokio::test]
async fn test_add_banned_token() {
    let mut store = HashsetBannedTokenStore::default();

    let token = "token".to_owned();
    let token = Secret::new(token);

    let result = store.add_banned_token(token.clone()).await;

    assert!(result.is_ok());
    assert!(store.tokens.contains(token.expose_secret()));
}

#[tokio::test]
async fn test_is_banned_token() {
    let mut store = HashsetBannedTokenStore::default();

    let token = "token".to_owned();
    let token = Secret::new(token);
    store.tokens.insert(token.expose_secret().to_owned());

    let result = store.is_banned_token(&token).await;

    assert!(result.unwrap());
}
