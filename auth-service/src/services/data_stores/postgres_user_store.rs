use color_eyre::eyre::{eyre, Context, Result};

use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier, Version,
};
use sqlx::PgPool;
use tokio::task;

use crate::domain::{Email, Password, User, UserStore, UserStoreError};

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
	Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    #[tracing::instrument(name = "Adding user to PostgreSQL", skip_all)]
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
	let password_hash = compute_password_hash(user.password.as_ref().to_owned())
	    .await
	    .map_err(UserStoreError::UnexpectedError)?;

	sqlx::query!(
	    r#"INSERT INTO users (email, password_hash, requires_2fa)
	       VALUES ($1, $2, $3)
	       "#,
	    user.email.as_ref(),
	    &password_hash,
	    user.requires_2fa,
	)
	.execute(&self.pool)
	.await
	.map_err(|e| UserStoreError::UnexpectedError(e.into()))?;

	Ok(())
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)]
    async fn get_user(&self, username: &Email) -> Result<User, UserStoreError> {
	sqlx::query!(
	    r#"SELECT email, password_hash, requires_2fa
	       FROM users
	       WHERE email = $1"#,
	    username.as_ref()
	)
	.fetch_optional(&self.pool)
	.await
	.map_err(|e| UserStoreError::UnexpectedError(e.into()))?
	.map(|row| {
	    Ok(User {
		email: Email::parse(row.email)
		    .map_err(|e| UserStoreError::UnexpectedError(eyre!(e)))?,
		password: Password::parse(row.password_hash)
		    .map_err(|e| UserStoreError::UnexpectedError(eyre!(e)))?,
		requires_2fa: row.requires_2fa,
	    })
	})
	.ok_or(UserStoreError::UserNotFound)?
    }

    #[tracing::instrument(name = "Validating user credentials in PostgreSQL", skip_all)]
    async fn validate_user(
	&self,
	username: &Email,
	password: &Password,
    ) -> Result<(), UserStoreError> {
	let user = self.get_user(username).await?;

	if verify_password_hash(
	    user.password.as_ref().to_string(),
	    password.as_ref().to_string(),
	)
	.await
	.is_err()
	{
	    return Err(UserStoreError::InvalidCredentials);
	}

	Ok(())
    }
}

#[tracing::instrument(name = "Verify password hash", skip_all)]
async fn verify_password_hash(
    expected_password_hash: String,
    password_candidate: String,
) -> Result<()> {
    let current_span: tracing::Span = tracing::Span::current();
    let hash_result = task::spawn_blocking(move || {
	current_span.in_scope(|| {
	    let expected_password_hash: PasswordHash<'_> =
		PasswordHash::new(&expected_password_hash)?;

	    Argon2::default()
		.verify_password(password_candidate.as_bytes(), &expected_password_hash)
		.map_err(|e| e.into())
	})
    })
    .await;

    hash_result?
}

#[tracing::instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(password: String) -> Result<String> {
    let current_span: tracing::Span = tracing::Span::current();
    let compute_result = task::spawn_blocking(move || {
	current_span.in_scope(|| {
	    let salt: SaltString = SaltString::generate(&mut rand::thread_rng());
	    let password_hash = Argon2::new(
		Algorithm::Argon2id,
		Version::V0x13,
		Params::new(1500, 2, 1, None)?,
	    )
	    .hash_password(password.as_bytes(), &salt)?
	    .to_string();

	    Ok(password_hash)
	})
    })
    .await;

    compute_result?
}
