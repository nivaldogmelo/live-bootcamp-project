use auth_service::domain::BannedTokenStore;
use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};
use macros::test_and_cleanup;
use reqwest::Url;

use crate::helpers::{get_random_email, TestApp};

#[test_and_cleanup]
async fn should_return_200_if_valid_jwt_cookie() {
    let random_email = get_random_email();

    let signup_body = serde_json::json!({
    "email": random_email,
    "password": "password123",
    "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
    "email": random_email,
    "password": "password123"
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No JWT cookie found");

    assert!(!auth_cookie.value().is_empty());

    let token = auth_cookie.value();

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 200);

    let banned_token_store = app.banned_token_store.read().await;

    let contains_token = banned_token_store
        .is_banned_token(token)
        .await
        .expect("Failed to check if token is banned");

    assert!(contains_token);
}

#[test_and_cleanup]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let random_email = get_random_email();

    let signup_body = serde_json::json!({
    "email": random_email,
    "password": "password123",
    "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
    "email": random_email,
    "password": "password123"
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No JWT cookie found");

    assert!(!auth_cookie.value().is_empty());

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No JWT cookie found");

    assert!(auth_cookie.value().is_empty());

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 400);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Missing auth token".to_owned()
    );
}

#[test_and_cleanup]
async fn should_return_400_if_jwt_cookie_missing() {
    let response = app.post_logout().await;

    assert_eq!(
        response.status().as_u16(),
        400,
        "Response: {:?} failed",
        response
    );

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Missing auth token".to_owned()
    );
}

#[test_and_cleanup]
async fn should_return_401_if_invalid_token() {
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Response: {:?} failed",
        response
    );

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "JWT is not valid".to_owned()
    );
}
