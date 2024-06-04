use auth_service::ErrorResponse;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

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

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;

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

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;

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
