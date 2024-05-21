use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{app_state::AppState, domain::User};

pub async fn signup(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SignupRequest>,
) -> impl IntoResponse {
    let user = request.into_user();
    let mut user_store = state.user_store.write().await;
    let _ = user_store.add_user(user);

    let response = Json(SignupResponse {
	message: "User created successfully!".to_string(),
    });

    (StatusCode::CREATED, response)
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
    fn into_user(&self) -> User {
	User::new(self.email.clone(), self.password.clone(), self.requires_2fa)
    }
}
