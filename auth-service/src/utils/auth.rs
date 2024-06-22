use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use color_eyre::eyre::{eyre, Context, ContextCompat, Result};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Validation};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::domain::Email;

use super::constants::{JWT_COOKIE_NAME, JWT_SECRET};

pub const TOKEN_TTL_SECONDS: i64 = 600; // 10 minutes

#[derive(Debug)]
pub enum GenerateTokenError {
    TokenError(jsonwebtoken::errors::Error),
    UnexpectedError,
}

#[tracing::instrument(name = "Generate Auth Cookie", skip_all)]
pub fn generate_auth_cookie(email: &Email) -> Result<Cookie<'static>> {
    let token = generate_auth_token(email)?;
    Ok(create_auth_cookie(token))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    exp: usize,
}

#[tracing::instrument(name = "Generate Auth Token", skip_all)]
fn generate_auth_token(email: &Email) -> Result<String> {
    let delta = chrono::Duration::try_seconds(TOKEN_TTL_SECONDS)
	.wrap_err("failed to create 10 minute time delta")?;

    let exp = Utc::now()
	.checked_add_signed(delta)
	.ok_or(eyre!("failed to add 10 minutes to current time"))?
	.timestamp();

    let exp: usize = exp.try_into().wrap_err(format!(
	"failed to convert expiration time to usize. exp time: {}",
	exp
    ))?;

    let sub = email.as_ref().expose_secret().to_owned();

    let claims = Claims { sub, exp };

    create_token(&claims)
}

#[tracing::instrument(name = "Create Token", skip_all)]
fn create_token(claims: &Claims) -> Result<String> {
    encode(
	&jsonwebtoken::Header::default(),
	&claims,
	&EncodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
    )
    .wrap_err("failed to create token")
}

#[tracing::instrument(name = "Create Auth Cookie", skip_all)]
fn create_auth_cookie(token: String) -> Cookie<'static> {
    let cookie = Cookie::build((JWT_COOKIE_NAME, token))
	.path("/") // apply cookie to all URLs on the server //////////////////
	.http_only(true) // prevent JavaScript from accessing the cookie //////
	.same_site(SameSite::Lax)
	.build();
    cookie
}

#[tracing::instrument(name = "Validate Token", skip(token))]
pub async fn validate_token(token: &str) -> Result<Claims> {
    decode::<Claims>(
	token,
	&DecodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
	&Validation::default(),
    )
    .map(|data| data.claims)
    .wrap_err("failed to decode token")
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;

    use super::*;

    #[tokio::test]
    async fn test_generate_auth_cookie() {
	let email = Email::parse(Secret::new("test@example.com".to_owned())).unwrap();
	let cookie = generate_auth_cookie(&email).unwrap();
	assert_eq!(cookie.name(), JWT_COOKIE_NAME);
	assert_eq!(cookie.value().split('.').count(), 3);
	assert_eq!(cookie.path(), Some("/"));
	assert_eq!(cookie.http_only(), Some(true));
	assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
	let token = "test_token".to_owned();
	let cookie = create_auth_cookie(token.clone());
	assert_eq!(cookie.name(), JWT_COOKIE_NAME);
	assert_eq!(cookie.value(), token);
	assert_eq!(cookie.path(), Some("/"));
	assert_eq!(cookie.http_only(), Some(true));
	assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
	let email = Email::parse(Secret::new("test@example.com".to_owned())).unwrap();
	let result = generate_auth_token(&email).unwrap();
	assert_eq!(result.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
	let email = Email::parse(Secret::new("test@example.com".to_owned())).unwrap();
	let token = generate_auth_token(&email).unwrap();
	let result = validate_token(&token).await.unwrap();
	assert_eq!(result.sub, "test@example.com");

	let exp = Utc::now()
	    .checked_add_signed(chrono::Duration::try_minutes(9).expect("valid duration"))
	    .expect("valid timestamp")
	    .timestamp();

	assert!(result.exp > exp as usize);
    }

    #[tokio::test]
    async fn test_validate_token_with_invalid_token() {
	let token = "invalid token".to_owned();
	let result = validate_token(&token).await;
	assert!(result.is_err());
    }
}
