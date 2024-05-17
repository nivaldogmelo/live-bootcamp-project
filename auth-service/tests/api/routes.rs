use crate::helpers::TestApp;

#[tokio::test]
async fn root_returns_auth_ui() {
    let app = TestApp::new().await;

    let response = app.get_root().await;

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
}

#[tokio::test]
async fn signup() {
    let app = TestApp::new().await;

    let response = app.post_signup("fake_email", "fake_pass").await;

    assert_eq!(response.status().as_u16(), 201);
}

#[tokio::test]
async fn login() {
    let app = TestApp::new().await;

    let response = app.post_login("fake_email", "fake_pass").await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn verify_2fa() {
    let app = TestApp::new().await;

    let response = app
	.post_verify_2fa("fake_email", "login_attempt_id", "code")
	.await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn logout() {
    let app = TestApp::new().await;

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn verify_token() {
    let app = TestApp::new().await;

    let response = app.post_verify_token("token").await;

    assert_eq!(response.status().as_u16(), 200);
}
