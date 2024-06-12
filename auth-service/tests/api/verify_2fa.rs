use auth_service::{
    domain::{Email, LoginAttemptId, TwoFACodeStore},
    routes::TwoFactorAuthResponse,
    utils::constants::JWT_COOKIE_NAME,
};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_200_if_correct_code() {
    let app = TestApp::new().await;

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

    let login_attempt_id = json_body.login_attempt_id;

    let two_fa_code = app
	.two_fa_code_store
	.read()
	.await
	.get_code(&Email::parse(random_email.clone()).unwrap())
	.await
	.unwrap();

    let two_fa_code = two_fa_code.1.as_ref();

    let test_cases = [
	serde_json::json!({"email": random_email, "loginAttemptId": login_attempt_id, "2FACode": two_fa_code}),
    ];

    for test_case in test_cases.iter() {
	let response = app.post_verify_2fa(test_case).await;

	assert_eq!(response.status().as_u16(), 200);

	let auth_cookie = response
	    .cookies()
	    .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
	    .expect("No auth cookie found");

	assert!(!auth_cookie.value().is_empty());
    }
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();
    let random_uuid = uuid::Uuid::new_v4().to_string();

    let test_cases = [
	serde_json::json!({"email": random_email, "loginAttemptId": random_uuid, "2FACode": "12F456"}),
	serde_json::json!({"email": random_email, "loginAttemptId": "454325433455432", "2FACode": "12F456"}),
	serde_json::json!({"email": "invalid-email", "loginAttemptId": random_uuid, "2FACode": "12F456"}),
    ];

    for test_case in test_cases.iter() {
	let response = app.post_verify_2fa(test_case).await;

	assert_eq!(response.status().as_u16(), 400);
    }
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;

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

    let login_attempt_id = json_body.login_attempt_id;

    let two_fa_code = app
	.two_fa_code_store
	.read()
	.await
	.get_code(&Email::parse(random_email.clone()).unwrap())
	.await
	.unwrap();

    let two_fa_code = two_fa_code.1.as_ref();

    let incorrect_login_attempt_id = uuid::Uuid::new_v4().to_string();

    let test_cases = [
	serde_json::json!({"email": "test@example.com", "loginAttemptId": login_attempt_id, "2FACode": two_fa_code}),
	serde_json::json!({"email": random_email, "loginAttemptId": login_attempt_id, "2FACode": "123456"}),
	serde_json::json!({"email": random_email, "loginAttemptId": incorrect_login_attempt_id, "2FACode": two_fa_code}),
    ];

    for test_case in test_cases.iter() {
	let response = app.post_verify_2fa(test_case).await;

	assert_eq!(response.status().as_u16(), 401);
    }
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    let app = TestApp::new().await;

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

    let login_attempt_id = json_body.login_attempt_id;

    let two_fa_code = app
	.two_fa_code_store
	.read()
	.await
	.get_code(&Email::parse(random_email.clone()).unwrap())
	.await
	.unwrap();

    let two_fa_code = two_fa_code.1.as_ref();

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let json_body = response
	.json::<TwoFactorAuthResponse>()
	.await
	.expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(json_body.message, "2FA required".to_owned());

    let test_cases = [
	serde_json::json!({"email": random_email, "loginAttemptId": login_attempt_id, "2FACode": two_fa_code}),
    ];

    for test_case in test_cases.iter() {
	let response = app.post_verify_2fa(test_case).await;

	assert_eq!(response.status().as_u16(), 401);
    }
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {
    let app = TestApp::new().await;

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

    let login_attempt_id = json_body.login_attempt_id;

    let two_fa_code = app
	.two_fa_code_store
	.read()
	.await
	.get_code(&Email::parse(random_email.clone()).unwrap())
	.await
	.unwrap();

    let two_fa_code = two_fa_code.1.as_ref();

    let test_case = serde_json::json!({"email": random_email, "loginAttemptId": login_attempt_id, "2FACode": two_fa_code});

    let response = app.post_verify_2fa(&test_case).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
	.cookies()
	.find(|cookie| cookie.name() == JWT_COOKIE_NAME)
	.expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    let response = app.post_verify_2fa(&test_case).await;

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();
    let random_uuid = LoginAttemptId::default().as_ref().to_owned();

    let test_cases = [
	serde_json::json!({"loginAttemptId": random_uuid, "2FACode": "12F456"}),
	serde_json::json!({"email": random_email, "2FACode": "12F456"}),
	serde_json::json!({"email": random_email, "loginAttemptId": random_uuid}),
    ];

    for test_case in test_cases {
	let response = app.post_verify_2fa(&test_case).await;

	assert_eq!(
	    response.status().as_u16(),
	    422,
	    "Failed for input: {:?}",
	    test_case
	);
    }
}
