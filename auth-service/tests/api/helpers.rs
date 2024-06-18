use std::{str::FromStr, sync::Arc};

use auth_service::{
    app_state::AppState,
    get_postgres_pool, get_redis_client,
    services::{HashmapTwoFACodeStore, MockEmailClient, PostgresUserStore, RedisBannedTokenStore},
    utils::constants::{test, DATABASE_URL, REDIS_HOST_NAME},
    Application,
};
use reqwest::cookie::Jar;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    Connection, Executor, PgConnection,
};
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub banned_token_store: Arc<RwLock<RedisBannedTokenStore>>,
    pub two_fa_code_store: Arc<RwLock<HashmapTwoFACodeStore>>,
    pub http_client: reqwest::Client,
    pub db_name: String,
    pub cleaned_up: bool,
}

impl TestApp {
    pub async fn new() -> TestApp {
	let db_name = Uuid::new_v4().to_string();
	let pg_pool = configure_postgresql(&db_name).await;
	let redis_conn = Arc::new(RwLock::new(configure_redis()));

	let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
	let banned_token_store = Arc::new(RwLock::new(RedisBannedTokenStore::new(redis_conn)));
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
	    db_name,
	    cleaned_up: false,
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

    pub async fn clean_up(&mut self) {
	if self.cleaned_up {
	    return;
	}

	delete_database(&self.db_name).await;

	self.cleaned_up = true;
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
	if !self.cleaned_up {
	    panic!("TestApp::clean_up was not called before dropping.");
	}
    }
}

async fn configure_postgresql(db_name: &str) -> sqlx::Pool<sqlx::Postgres> {
    let postgres_conn_url = DATABASE_URL.to_owned();

    configure_database(&postgres_conn_url, db_name).await;

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

async fn delete_database(db_name: &str) {
    let postgres_conn_url: String = DATABASE_URL.to_owned();

    let connection_options =
	PgConnectOptions::from_str(&postgres_conn_url).expect("Failed to parse connection string.");

    let mut connection = PgConnection::connect_with(&connection_options)
	.await
	.expect("Failed to connect to Postgres.");

    connection
	.execute(
	    format!(
		r#"SELECT pg_terminate_backend(pg_stat_activity.pid)
		   FROM pg_stat_activity
		   WHERE pg_stat_activity.datname = '{}'
		     AND pid <> pg_backend_pid();
	"#,
		db_name
	    )
	    .as_str(),
	)
	.await
	.expect("Failed to terminate connections.");

    connection
	.execute(format!(r#"DROP DATABASE "{}";"#, db_name).as_str())
	.await
	.expect("Failed to drop database.");
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.to_owned())
	.expect("Failed to get Redis client!")
	.get_connection()
	.expect("Failed to get Redis connection!")
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}
