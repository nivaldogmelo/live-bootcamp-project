use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use secrecy::Secret;
use serde::Deserialize;

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode},
    utils::auth::generate_auth_cookie,
};

#[tracing::instrument(name = "Verify 2FA", skip_all)]
pub async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email = match Email::parse(request.email) {
        Ok(email) => email,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let login_attempt_id = match LoginAttemptId::parse(Secret::new(request.login_attempt_id)) {
        Ok(login_attempt_id) => login_attempt_id,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let two_fa_code = match TwoFACode::parse(Secret::new(request.two_fa_code)) {
        Ok(two_fa_code) => two_fa_code,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let mut two_fa_code_store = state.two_fa_code_store.write().await;

    let code_tuple = match two_fa_code_store.get_code(&email).await {
        Ok(tuple) => tuple,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };

    if !(code_tuple.1 == two_fa_code && code_tuple.0 == login_attempt_id) {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    let jwt_cookie = match generate_auth_cookie(&email) {
        Ok(cookie) => cookie,
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e))),
    };

    let updated_jar = jar.add(jwt_cookie);

    match two_fa_code_store.remove_code(&email).await {
        Ok(_) => {}
        Err(e) => return (updated_jar, Err(AuthAPIError::UnexpectedError(e.into()))),
    }

    (updated_jar, Ok(StatusCode::OK))
}

#[derive(Deserialize)]
pub struct Verify2FARequest {
    pub email: Secret<String>,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub two_fa_code: String,
}
