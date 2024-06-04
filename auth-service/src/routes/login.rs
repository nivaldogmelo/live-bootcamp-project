use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, UserStore, UserStoreError},
    services::HashmapUserStore,
};

pub async fn login(
    State(state): State<AppState<HashmapUserStore>>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email =
        Email::parse(request.email.clone()).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password =
        Password::parse(request.password.clone()).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user_store = state.user_store.read().await;

    if let Err(UserStoreError::InvalidCredentials) =
        user_store.validate_user(&email, &password).await
    {
        return Err(AuthAPIError::IncorrectCredentials);
    };

    if let Err(UserStoreError::UserNotFound) = user_store.get_user(&email).await {
        println!("User not found");
        return Err(AuthAPIError::IncorrectCredentials);
    };

    Ok(StatusCode::OK.into_response())
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub message: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}
