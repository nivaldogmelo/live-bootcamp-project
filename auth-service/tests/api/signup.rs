use auth_service::ErrorResponse;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_201_if_valid_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
	serde_json::json!({"email": random_email, "password": "password123", "requires2FA": true}),
    ];

    for test_case in test_cases.iter() {
	let response = app.post_signup(test_case).await;

	assert_eq!(
	    response.status().as_u16(),
	    201,
	    "Test case failed: {:?}",
	    test_case
	);
    }
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
	serde_json::json!({"email": "invalid-email", "password": "password123", "requires2FA": true}),
	serde_json::json!({"email": random_email, "password": "pass", "requires2FA": true}),
    ];

    for test_case in test_cases.iter() {
	let response = app.post_signup(test_case).await;

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

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    let app = TestApp::new().await;

    let email1 = get_random_email();

    let test_body =
	serde_json::json!({"email": email1, "password": "password123", "requires2FA": true});

    app.post_signup(&test_body).await;

    let response = app.post_signup(&test_body).await;

    assert_eq!(response.status().as_u16(), 201);

    app.post_signup(&test_body).await;

    let response = app.post_signup(&test_body).await;

    assert_eq!(
	response.status().as_u16(),
	409,
	"Test case failed: {:?}",
	test_body
    );

    assert_eq!(
	response
	    .json::<ErrorResponse>()
	    .await
	    .expect("Could not deserialize response body to ErrorResponse")
	    .error,
	"User already exists".to_owned()
    );
}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
	serde_json::json!({"password": "password123", "requires2FA": true}),
	serde_json::json!({"email": random_email, "requires2FA": true}),
    ];

    for test_case in test_cases.iter() {
	let response = app.post_signup(test_case).await;

	assert_eq!(
	    response.status().as_u16(),
	    422,
	    "Test case failed: {:?}",
	    test_case
	);
    }
}
