use crate::helpers::TestApp;

#[tokio::test]
async fn verify_2fa() {
    let app = TestApp::new().await;

    let response = app
	.post_verify_2fa("fake_email", "login_attempt_id", "code")
	.await;

    assert_eq!(response.status().as_u16(), 200);
}
