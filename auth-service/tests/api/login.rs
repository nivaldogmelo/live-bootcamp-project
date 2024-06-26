use auth_service::domain::{Email, TwoFACodeStore};
use auth_service::{
    routes::TwoFactorAuthResponse, utils::constants::JWT_COOKIE_NAME, ErrorResponse,
};
use secrecy::Secret;

use crate::helpers::{get_random_email, TestApp};
use macros::test_and_cleanup;

#[test_and_cleanup]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let random_email = get_random_email();

    let signup_body = serde_json::json!({"email": random_email.clone(), "password": "password123", "requires2FA": false});

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({"email": random_email, "password": "password123"});

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}

#[test_and_cleanup]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let random_email = get_random_email();

    let signup_body = serde_json::json!({"email": random_email.clone(), "password": "password123", "requires2FA": true});

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({"email": random_email, "password": "password123"});

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(json_body.message, "2FA required".to_owned());

    let store = app.two_fa_code_store.read().await;

    let email = Email::parse(Secret::new(random_email)).expect("Could not parse email");

    assert!(store.get_code(&email).await.is_ok());
}

#[test_and_cleanup]
async fn should_return_400_if_invalid_input() {
    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({"email": "invalid-email", "password": "password123"}),
        serde_json::json!({"email": random_email, "password": "pass"}),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Test case failed: {:?}",
            test_case
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }
}

#[test_and_cleanup]
async fn should_return_401_if_incorrect_credentials() {
    let random_email = get_random_email();

    let test_cases = [serde_json::json!({"email": random_email, "password": "password123"})];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            401,
            "Test case failed: {:?}",
            test_case
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Incorrect Credentials".to_owned()
        );
    }
}

#[test_and_cleanup]
async fn should_return_422_if_malformed_credentials() {
    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({"password": "password123"}),
        serde_json::json!({"email": random_email}),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;

        assert_eq!(response.status().as_u16(), 422);
    }
}
