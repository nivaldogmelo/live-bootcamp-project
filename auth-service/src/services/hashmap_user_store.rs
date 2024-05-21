use std::collections::HashMap;

use crate::domain::User;
use crate::domain::UserStore;
use crate::domain::UserStoreError;

#[derive(Default, Clone)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
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

    async fn get_user(&self, email: &str) -> Result<&User, UserStoreError> {
	match self.users.get(email) {
	    Some(user) => Ok(user),
	    None => Err(UserStoreError::UserNotFound),
	}
    }

    async fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
	match self.users.get(email) {
	    Some(user) => {
		if user.password == password {
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
	email: "johndoe@example.com".to_string(),
	password: "password".to_string(),
	requires_2fa: true,
    };

    let user2 = User {
	email: "johndoe@example.com".to_string(),
	password: "password".to_string(),
	requires_2fa: true,
    };

    // Ok scenario ////////////////////////////////////////////////////////
    assert_eq!(users.add_user(user1).await, Ok(()));
    // User already exists ////////////////////////////////////////////////
    assert_eq!(
	users.add_user(user2).await,
	Err(UserStoreError::UserAlreadyExists)
    );
}

#[tokio::test]
async fn test_get_user() {
    let mut users = HashmapUserStore::default();
    let user_found = User {
	email: "johndoe@example.com".to_string(),
	password: "password".to_string(),
	requires_2fa: true,
    };
    let _ = users.add_user(user_found).await;
    // Ok scenario ////////////////////////////////////////////////////////
    assert_eq!(
	users.get_user("johndoe@example.com").await.unwrap().email,
	"johndoe@example.com"
    );

    // UserNotfound ///////////////////////////////////////////////////////
    assert_eq!(
	users.get_user("marydoe@example.com").await,
	Err(UserStoreError::UserNotFound)
    );
}

#[tokio::test]
async fn test_validate_user() {
    let mut users = HashmapUserStore::default();
    let user_found = User {
	email: "johndoe@example.com".to_string(),
	password: "password".to_string(),
	requires_2fa: true,
    };

    let _ = users.add_user(user_found).await;

    // Ok scenario ////////////////////////////////////////////////////////
    assert_eq!(
	users.validate_user("johndoe@example.com", "password").await,
	Ok(())
    );

    // UserNotfound ///////////////////////////////////////////////////////
    assert_eq!(
	users.validate_user("marydoe@example.com", "password").await,
	Err(UserStoreError::UserNotFound)
    );

    // InvalidCredentials /////////////////////////////////////////////////
    assert_eq!(
	users
	    .validate_user("johndoe@example.com", "other_password")
	    .await,
	Err(UserStoreError::InvalidCredentials)
    );
}
