use auth_service::domain::BannedTokenStore;
use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};
use macros::test_and_cleanup;

use crate::helpers::{get_random_email, TestApp};

#[test_and_cleanup]
async fn should_return_200_valid_token() {
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

    let verify_token_body = serde_json::json!({
    "token": &token
    });

    let response = app.post_verify_token(&verify_token_body).await;

    assert_eq!(response.status().as_u16(), 200);
}

#[test_and_cleanup]
async fn should_return_401_if_valid_token() {
    let test_cases = [serde_json::json!({"token": ""})];

    for test_case in test_cases.iter() {
	let response = app.post_verify_token(&test_case).await;

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
	    "JWT is not valid".to_owned()
	);
    }
}

#[test_and_cleanup]
async fn should_return_401_if_banned_token() {
    let token = "banned_token".to_owned();

    if app
	.banned_token_store
	.write()
	.await
	.add_banned_token(token.clone())
	.await
	.is_err()
    {
	panic!("Could not add banned token to store");
    }

    let test_case = serde_json::json!({"token": "banned_token"});

    let response = app.post_verify_token(&test_case).await;

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
	"JWT is not valid".to_owned()
    );
}

#[test_and_cleanup]
async fn should_return_422_if_malformed_input() {
    let test_cases = [
	serde_json::json!({"password": "password123"}),
	serde_json::json!({"email": ""}),
	serde_json::json!({"toke": "fiudosagfbn34"}),
    ];

    for test_case in test_cases.iter() {
	let response = app.post_verify_token(&test_case).await;

	assert_eq!(response.status().as_u16(), 422);
    }
}
