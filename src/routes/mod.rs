use crate::Response;
use axum::http::StatusCode;
use essence::Error;

pub type RouteResult<T> = Result<Response<T>, Response<Error>>;
pub type NoContentResult = Result<StatusCode, Response<Error>>;

pub mod auth;
pub mod channels;
pub mod emojis;
pub mod guilds;
pub mod internal;
pub mod invites;
pub mod members;
pub mod messages;
pub mod roles;
pub mod users;
