use std::collections::HashMap;

use crate::domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError};

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
	&mut self,
	email: Email,
	login_attempt: LoginAttemptId,
	code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
	self.codes.insert(email, (login_attempt, code));
	Ok(())
    }

    async fn get_code(
	&self,
	email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
	match self.codes.get(email) {
	    Some((login_attempt, code)) => Ok((login_attempt.clone(), code.clone())),
	    None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
	}
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
	match self.codes.remove(email) {
	    Some(_) => Ok(()),
	    None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
	}
    }
}

#[tokio::test]
async fn test_add_code() {
    let mut store = HashmapTwoFACodeStore::default();
    let email = Email::parse("johndoe@example.com".to_owned()).unwrap();
    let login_attempt = LoginAttemptId::default();
    let code = TwoFACode::default();

    let response = store
	.add_code(email.clone(), login_attempt.clone(), code.clone())
	.await;

    assert!(response.is_ok());

    let (stored_login_attempt, stored_code) = store.codes.get(&email).unwrap();
    assert_eq!(&login_attempt, stored_login_attempt);
    assert_eq!(&code, stored_code);
}

#[tokio::test]
async fn test_get_code() {
    let mut store = HashmapTwoFACodeStore::default();
    let email = Email::parse("johndoe@example.com".to_owned()).unwrap();
    let login_attempt = LoginAttemptId::default();
    let code = TwoFACode::default();

    store
	.codes
	.insert(email.clone(), (login_attempt.clone(), code.clone()));

    let response = store.get_code(&email).await;

    assert!(response.is_ok());

    let (stored_login_attempt, stored_code) = response.unwrap();
    assert_eq!(login_attempt, stored_login_attempt);
    assert_eq!(code, stored_code);
}

#[tokio::test]
async fn test_remove_code() {
    let mut store = HashmapTwoFACodeStore::default();
    let email = Email::parse("johndoe@example.com".to_owned()).unwrap();
    let login_attempt = LoginAttemptId::default();
    let code = TwoFACode::default();

    store
	.codes
	.insert(email.clone(), (login_attempt.clone(), code.clone()));

    let response = store.remove_code(&email).await;

    assert!(response.is_ok());
    assert!(store.codes.get(&email).is_none());
}
