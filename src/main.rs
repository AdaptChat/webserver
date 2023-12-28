#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::similar_names
)]
#![cfg_attr(not(feature = "ws"), allow(unused_variables, unused_imports))]
// #![feature(never_type)]
#![feature(try_blocks)]
#![feature(lazy_cell)]
#![feature(maybe_uninit_uninit_array)]
#![feature(maybe_uninit_array_assume_init)]

#[macro_use]
extern crate dotenv_codegen;

#[macro_use]
extern crate log;

#[cfg(feature = "ws")]
pub mod amqp;
pub mod cdn;
pub mod extract;
pub mod notification;
mod openapi;
pub mod ratelimit;
pub mod response;
pub mod routes;

pub(crate) use ratelimit::ratelimit;
pub use response::Response;

use axum::{http::StatusCode, routing::get, Router, Server};
use essence::utoipa::OpenApi;
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;
use utoipa_swagger_ui::SwaggerUi;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().expect("failed to load dotenv");
    env_logger::init();

    essence::connect(
        dotenv!("DATABASE_URL", "missing DATABASE_URL environment variable"),
        dotenv!("REDIS_URL", "missing REDIS_URL environment variable"),
    )
    .await?;
    essence::auth::configure_hasher(include_bytes!("../secret.key")).await;
    cdn::setup()?;
    notification::start_workers::<5>();
    #[cfg(feature = "ws")]
    amqp::connect().await?;

    // Generate OpenAPI spec
    let mut spec = openapi::ApiSpec::openapi();
    spec.info.title = "Adapt REST API".to_string();
    spec.info.description = Some("Public REST API for the Adapt chat platform".to_string());

    if std::env::args()
        .nth(1)
        .is_some_and(|arg| arg == "--openapi")
    {
        tokio::fs::write("openapi.yml", spec.to_yaml()?).await?;

        return Ok(());
    }

    let router = Router::new()
        .route("/", get(|| async { (StatusCode::OK, "Hello from Adapt") }))
        .route("/teapot", get(|| async { StatusCode::IM_A_TEAPOT }))
        .merge(routes::auth::router())
        .merge(routes::channels::router())
        // TODO: Add emojis router when ready.
        .merge(routes::guilds::router())
        .merge(routes::internal::router())
        .merge(routes::invites::router())
        .merge(routes::members::router())
        .merge(routes::messages::router())
        .merge(routes::roles::router())
        .merge(routes::users::router())
        .merge(SwaggerUi::new("/docs").url("/openapi.json", spec))
        .layer(CorsLayer::permissive());

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
