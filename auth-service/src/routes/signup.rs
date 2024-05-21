use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, User},
    services::UserStoreError,
};

pub async fn signup(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = request.email.clone();
    let password = request.password.clone();

    if !email.contains('@') || password.len() < 8 {
	return Err(AuthAPIError::InvalidCredentials);
    }

    let user = request.into_user();
    let mut user_store = state.user_store.write().await;
    match user_store.add_user(user) {
	Ok(_) => (),
	Err(UserStoreError::UserAlreadyExists) => return Err(AuthAPIError::UserAlreadyExists),
	Err(_) => return Err(AuthAPIError::UnexpectedError),
    };

    let response = Json(SignupResponse {
	message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

#[derive(Serialize)]
pub struct SignupResponse {
    pub message: String,
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

impl SignupRequest {
    fn into_user(self) -> User {
	User::new(self.email.clone(), self.password.clone(), self.requires_2fa)
    }
}
