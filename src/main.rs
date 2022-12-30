#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::similar_names
)]
#![feature(is_some_and)]

#[macro_use]
extern crate dotenv_codegen;

pub mod extract;
pub mod ratelimit;
pub mod response;
pub mod routes;

pub(crate) use ratelimit::ratelimit;
pub use response::Response;

use axum::{http::StatusCode, routing::get, Router, Server};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    essence::db::connect(dotenv!(
        "DATABASE_URL",
        "missing DATABASE_URL environment variable"
    ))
    .await?;
    essence::auth::configure_hasher(include_bytes!("../secret.key")).await;

    let router = Router::new()
        .route("/", get(|| async { (StatusCode::OK, "Hello from Adapt") }))
        .route("/teapot", get(|| async { StatusCode::IM_A_TEAPOT }))
        .merge(routes::auth::router())
        .merge(routes::guilds::router())
        .merge(routes::users::router());

    let addr = SocketAddr::from(([127, 0, 0, 1], 8077));
    Server::bind(&addr)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to install CTRL+C signal handler");
        })
        .await?;

    Ok(())
}
