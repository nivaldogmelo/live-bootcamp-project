use std::collections::HashMap;

use crate::domain::Email;
use crate::domain::Password;
use crate::domain::User;
use crate::domain::UserStore;
use crate::domain::UserStoreError;

#[derive(Default, Clone)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
	if self.users.contains_key(&user.email) {
	    return Err(UserStoreError::UserAlreadyExists);
	}

	self.users.insert(user.email.clone(), user);
	Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
	match self.users.get(email) {
	    Some(user) => Ok(user.clone()),
	    None => Err(UserStoreError::UserNotFound),
	}
    }

    async fn validate_user(
	&self,
	email: &Email,
	password: &Password,
    ) -> Result<(), UserStoreError> {
	match self.users.get(email) {
	    Some(user) => {
		if user.password.eq(password) {
		    Ok(())
		} else {
		    Err(UserStoreError::InvalidCredentials)
		}
	    }
	    None => Err(UserStoreError::UserNotFound),
	}
    }
}

#[tokio::test]
async fn test_add_user() {
    let mut users = HashmapUserStore::default();
    let user1 = User {
	email: Email::parse("johndoe@example.com".to_owned()).unwrap(),
	password: Password::parse("password".to_owned()).unwrap(),
	requires_2fa: true,
    };

    // Ok scenario ////////////////////////////////////////////////////////
    assert_eq!(users.add_user(user1.clone()).await, Ok(()));
    // User already exists ////////////////////////////////////////////////
    assert_eq!(
	users.add_user(user1).await,
	Err(UserStoreError::UserAlreadyExists)
    );
}

#[tokio::test]
async fn test_get_user() {
    let mut users = HashmapUserStore::default();
    let user = User {
	email: Email::parse("johndoe@example.com".to_owned()).unwrap(),
	password: Password::parse("password".to_owned()).unwrap(),
	requires_2fa: true,
    };
    users.users.insert(user.email.clone(), user.clone());
    // Ok scenario ////////////////////////////////////////////////////////
    let result = users.get_user(&user.email).await;
    assert_eq!(result, Ok(user));

    // UserNotfound ///////////////////////////////////////////////////////
    assert_eq!(
	users
	    .get_user(&Email::parse("marydoe@example.com".to_owned()).unwrap())
	    .await,
	Err(UserStoreError::UserNotFound)
    );
}

#[tokio::test]
async fn test_validate_user() {
    let mut users = HashmapUserStore::default();
    let user = User {
	email: Email::parse("johndoe@example.com".to_owned()).unwrap(),
	password: Password::parse("password".to_owned()).unwrap(),
	requires_2fa: true,
    };

    let _ = users.add_user(user.clone()).await;

    // Ok scenario ////////////////////////////////////////////////////////
    assert_eq!(
	users
	    .validate_user(&user.email.clone(), &user.password.clone())
	    .await,
	Ok(())
    );

    // UserNotfound ///////////////////////////////////////////////////////
    assert_eq!(
	users
	    .validate_user(
		&Email::parse("marydoe@example.com".to_owned()).unwrap(),
		&Password::parse("password".to_owned()).unwrap()
	    )
	    .await,
	Err(UserStoreError::UserNotFound)
    );

    // InvalidCredentials /////////////////////////////////////////////////
    assert_eq!(
	users
	    .validate_user(
		&user.email.clone(),
		&Password::parse("wrong_password".to_owned()).unwrap()
	    )
	    .await,
	Err(UserStoreError::InvalidCredentials)
    );
}
