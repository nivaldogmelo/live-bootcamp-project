use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{cookie, CookieJar};
use secrecy::{ExposeSecret, Secret};

use crate::{
    app_state::AppState,
    domain::AuthAPIError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
};

#[tracing::instrument(name = "Logout", skip_all)]
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let cookie = match jar.get(JWT_COOKIE_NAME) {
        Some(cookie) => cookie,
        None => return (jar, Err(AuthAPIError::MissingToken)),
    };

    let token = cookie.value().to_owned();
    let token = Secret::new(token);

    if (validate_token(token.expose_secret()).await).is_err() {
        return (jar, Err(AuthAPIError::InvalidToken));
    }

    match state
        .banned_token_store
        .write()
        .await
        .add_banned_token(token.to_owned())
        .await
    {
        Ok(_) => (),
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e.into()))),
    }

    let jar = jar.remove(cookie::Cookie::from(JWT_COOKIE_NAME));

    (jar, Ok(StatusCode::OK))
}
