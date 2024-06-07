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
use serde::{Deserialize, Serialize};
use services::HashmapUserStore;
use std::error::Error;
use tower_http::{cors::CorsLayer, services::ServeDir};

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
    pub async fn build(
	app_state: AppState<HashmapUserStore>,
	address: &str,
    ) -> Result<Self, Box<dyn Error>> {
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
	    .layer(cors);

	let listener = tokio::net::TcpListener::bind(address).await?;
	let address = listener.local_addr()?.to_string();
	let server = axum::serve(listener, router);

	Ok(Self { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
	println!("Listening on http://{}", &self.address);
	self.server.await
    }
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
	let (status, error_message) = match self {
	    AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
	    AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
	    AuthAPIError::IncorrectCredentials => {
		(StatusCode::UNAUTHORIZED, "Incorrect Credentials")
	    }
	    AuthAPIError::UnexpectedError => {
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

pub trait AuthRequest {
    fn into_user(self) -> Result<User, AuthAPIError>;
}
