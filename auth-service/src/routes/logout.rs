use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{cookie, CookieJar};

use crate::{
    app_state::AppState,
    domain::AuthAPIError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
};

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let cookie = match jar.get(JWT_COOKIE_NAME) {
	Some(cookie) => cookie,
	None => return (jar, Err(AuthAPIError::MissingToken)),
    };

    let token = cookie.value().to_owned();

    if (validate_token(&token).await).is_err() {
	return (jar, Err(AuthAPIError::InvalidToken));
    }

    if state
	.banned_token_store
	.write()
	.await
	.add_banned_token(token.to_owned())
	.await
	.is_err()
    {
	return (jar, Err(AuthAPIError::UnexpectedError));
    }

    let jar = jar.remove(cookie::Cookie::from(JWT_COOKIE_NAME));

    (jar, Ok(StatusCode::OK))
}
