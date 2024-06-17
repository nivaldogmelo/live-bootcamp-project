use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, User, UserStoreError},
    AuthRequest,
};

pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let user = request.into_user()?;

    let mut user_store = state.user_store.write().await;

    match user_store.add_user(user).await {
	Ok(_) => (),
	Err(UserStoreError::UserAlreadyExists) => return Err(AuthAPIError::UserAlreadyExists),
	Err(e) => {
	    println!("Error: {:?}", e);
	    return Err(AuthAPIError::UnexpectedError);
	}
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

impl AuthRequest for SignupRequest {
    fn into_user(self) -> Result<User, AuthAPIError> {
	let email =
	    Email::parse(self.email.clone()).map_err(|_| AuthAPIError::InvalidCredentials)?;
	let password =
	    Password::parse(self.password.clone()).map_err(|_| AuthAPIError::InvalidCredentials)?;

	Ok(User::new(email, password, self.requires_2fa))
    }
}
