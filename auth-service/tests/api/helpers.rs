use auth_service::Application;

pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> TestApp {
	let app = Application::build("127.0.0.1:0")
	    .await
	    .expect("Failed to build app");

	let address = format!("http://{}", app.address.clone());

	// Run the auth service in a separate async task to avoid blocking ////
	// to avoid blocking the main test thread. ////////////////////////////
	#[allow(clippy::let_underscore_future)]
	let _ = tokio::spawn(app.run());

	let http_client = reqwest::Client::new();

	TestApp {
	    address,
	    http_client,
	}
    }

    pub async fn get_root(&self) -> reqwest::Response {
	self.http_client
	    .get(&format!("{}/", self.address))
	    .send()
	    .await
	    .expect("Failed to send request.")
    }

    pub async fn post_signup(&self, email: &str, password: &str) -> reqwest::Response {
	let var_name = serde_json::json!({
	"email": email,
	"password": password,
	});

	self.http_client
	    .post(&format!("{}/signup", self.address))
	    .json(&var_name)
	    .send()
	    .await
	    .expect("Failed to send request.")
    }

    pub async fn post_login(&self, email: &str, password: &str) -> reqwest::Response {
	let var_name = serde_json::json!({
	"email": email,
	"password": password,
	});

	self.http_client
	    .post(&format!("{}/login", self.address))
	    .json(&var_name)
	    .send()
	    .await
	    .expect("Failed to send request.")
    }

    pub async fn post_verify_2fa(
	&self,
	email: &str,
	login_attempt_id: &str,
	code: &str,
    ) -> reqwest::Response {
	let var_name = serde_json::json!({
	"email": email,
	"loginAttemptId": login_attempt_id,
	"2FACODE": code,
	});

	self.http_client
	    .post(&format!("{}/verify-2fa", self.address))
	    .json(&var_name)
	    .send()
	    .await
	    .expect("Failed to send request.")
    }

    pub async fn post_logout(&self) -> reqwest::Response {
	self.http_client
	    .post(&format!("{}/logout", self.address))
	    .send()
	    .await
	    .expect("Failed to send request.")
    }

    pub async fn post_verify_token(&self, token: &str) -> reqwest::Response {
	let var_name = serde_json::json!({
	"token": token,
	});

	self.http_client
	    .post(&format!("{}/verify-token", self.address))
	    .json(&var_name)
	    .send()
	    .await
	    .expect("Failed to send request.")
    }
}
