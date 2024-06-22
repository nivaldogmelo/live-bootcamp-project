#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

use app_state::AppState;
use axum::{
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    serve::Serve,
    Json, Router,
};
use domain::{AuthAPIError, User};
use redis::{Client, RedisResult};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::error::Error;
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};
use utils::tracing::{make_span_with_request_id, on_request, on_response};

use routes::*;

pub mod app_state;
pub mod domain;
pub mod routes;
pub mod services;
pub mod utils;

pub struct Application {
    server: Serve<Router, Router>,

    pub address: String,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
	let allowed_origins = [
	    "http://localhost:3000".parse()?,
	    "http://192.241.129.202:8000".parse()?,
	];

	let cors = CorsLayer::new()
	    .allow_methods([Method::GET, Method::POST])
	    .allow_credentials(true)
	    .allow_origin(allowed_origins);

	let router = Router::new()
	    .nest_service("/", ServeDir::new("assets"))
	    .route("/signup", post(signup))
	    .route("/login", post(login))
	    .route("/verify-2fa", post(verify_2fa))
	    .route("/logout", post(logout))
	    .route("/verify-token", post(verify_token))
	    .with_state(app_state)
	    .layer(cors)
	    .layer(
		TraceLayer::new_for_http()
		    .make_span_with(make_span_with_request_id)
		    .on_request(on_request)
		    .on_response(on_response),
	    );

	let listener = tokio::net::TcpListener::bind(address).await?;
	let address = listener.local_addr()?.to_string();
	let server = axum::serve(listener, router);

	Ok(Self { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
	tracing::info!("Listening on http://{}", &self.address);
	self.server.await
    }
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
	log_error_chain(&self);

	let (status, error_message) = match self {
	    AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
	    AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
	    AuthAPIError::IncorrectCredentials => {
		(StatusCode::UNAUTHORIZED, "Incorrect Credentials")
	    }
	    AuthAPIError::UnexpectedError(_) => {
		(StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
	    }
	    AuthAPIError::MissingToken => (StatusCode::BAD_REQUEST, "Missing auth token"),
	    AuthAPIError::InvalidToken => (StatusCode::UNAUTHORIZED, "JWT is not valid"),
	};

	let body = Json(ErrorResponse {
	    error: error_message.to_string(),
	});

	(status, body).into_response()
    }
}

fn log_error_chain(e: &(dyn Error + 'static)) {
    let separator =
	"\n-----------------------------------------------------------------------------------\n";
    let mut report = format!("{}{:?}", separator, e);
    let mut current = e.source();
    while let Some(cause) = current {
	let str = format!("Caused by:\n\n{:?}", cause);
	report = format!("{}\n{}", report, str);
	current = cause.source();
    }
    report = format!("{}\n{}", report, separator);
    tracing::error!("{}", report);
}

pub trait AuthRequest {
    fn into_user(self) -> Result<User, AuthAPIError>;
}

pub async fn get_postgres_pool(url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new().max_connections(5).connect(url).await
}

pub fn get_redis_client(redis_hostname: String) -> RedisResult<Client> {
    let redis_url = format!("redis://{}", redis_hostname);
    redis::Client::open(redis_url)
}
