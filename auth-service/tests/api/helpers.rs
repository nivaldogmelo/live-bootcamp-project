use std::sync::Arc;

use auth_service::{
    app_state::AppState,
    get_postgres_pool,
    services::{
	HashmapTwoFACodeStore, HashsetBannedTokenStore, MockEmailClient, PostgresUserStore,
    },
    utils::constants::{test, DATABASE_URL},
    Application,
};
use reqwest::cookie::Jar;
use sqlx::{postgres::PgPoolOptions, Executor};
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub banned_token_store: Arc<RwLock<HashsetBannedTokenStore>>,
    pub two_fa_code_store: Arc<RwLock<HashmapTwoFACodeStore>>,
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> TestApp {
	let pg_pool = configure_postgresql().await;

	let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
	let banned_token_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));
	let two_fa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));
	let email_client = Arc::new(MockEmailClient);
	let app_state = AppState::new(
	    user_store,
	    banned_token_store.clone(),
	    two_fa_code_store.clone(),
	    email_client,
	);

	let app = Application::build(app_state, test::APP_ADDRESS)
	    .await
	    .expect("Failed to build app");

	let address = format!("http://{}", app.address.clone());

	// Run the auth service in a separate async task to avoid blocking ////
	// to avoid blocking the main test thread. ////////////////////////////
	#[allow(clippy::let_underscore_future)]
	let _ = tokio::spawn(app.run());

	let cookie_jar = Arc::new(Jar::default());
	let http_client = reqwest::Client::builder()
	    .cookie_provider(cookie_jar.clone())
	    .build()
	    .unwrap();

	Self {
	    address,
	    cookie_jar,
	    banned_token_store,
	    two_fa_code_store,
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

    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
	Body: serde::Serialize,
    {
	self.http_client
	    .post(&format!("{}/signup", &self.address))
	    .json(body)
	    .send()
	    .await
	    .expect("Failed to execute request.")
    }

    pub async fn post_login<Body>(&self, body: &Body) -> reqwest::Response
    where
	Body: serde::Serialize,
    {
	self.http_client
	    .post(&format!("{}/login", self.address))
	    .json(body)
	    .send()
	    .await
	    .expect("Failed to execute request.")
    }

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> reqwest::Response
    where
	Body: serde::Serialize,
    {
	self.http_client
	    .post(&format!("{}/verify-2fa", self.address))
	    .json(&body)
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

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response
    where
	Body: serde::Serialize,
    {
	self.http_client
	    .post(&format!("{}/verify-token", &self.address))
	    .json(body)
	    .send()
	    .await
	    .expect("Failed to execute request.")
    }
}

async fn configure_postgresql() -> sqlx::Pool<sqlx::Postgres> {
    let postgres_conn_url = DATABASE_URL.to_owned();

    let db_name = Uuid::new_v4().to_string();

    configure_database(&postgres_conn_url, &db_name).await;

    let postgres_conn_url_with_db = format!("{}/{}", postgres_conn_url, db_name);

    get_postgres_pool(&postgres_conn_url_with_db)
	.await
	.expect("Failed to create Postgres connection pool!")
}

async fn configure_database(db_conn_url: &str, db_name: &str) {
    let connection = PgPoolOptions::new()
	.connect(db_conn_url)
	.await
	.expect("Failed to connect to Postgres.");

    connection
	.execute(format!(r#"CREATE DATABASE "{}";"#, db_name).as_str())
	.await
	.expect("Failed to create database.");

    let db_conn_string = format!("{}/{}", db_conn_url, db_name);

    let connection = PgPoolOptions::new()
	.connect(&db_conn_string)
	.await
	.expect("Failed to connect to Postgres.");

    sqlx::migrate!()
	.run(&connection)
	.await
	.expect("Failed to run migrations.");
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}
