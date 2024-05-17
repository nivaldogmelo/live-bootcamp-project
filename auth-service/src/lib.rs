use axum::{routing::post, serve::Serve, Router};
use std::error::Error;
use tower_http::services::ServeDir;

use routes::*;

pub mod routes;

pub struct Application {
    server: Serve<Router, Router>,

    pub address: String,
}

impl Application {
    pub async fn build(address: &str) -> Result<Self, Box<dyn Error>> {
	let router = Router::new()
	    .nest_service("/", ServeDir::new("assets"))
	    .route("/signup", post(signup))
	    .route("/login", post(login))
	    .route("/verify-2fa", post(verify_2fa))
	    .route("/logout", post(logout))
	    .route("/verify-token", post(verify_token));

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
