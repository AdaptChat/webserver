use crate::Response;
use axum::http::StatusCode;
use essence::Error;

pub type RouteResult<T> = Result<Response<T>, Response<Error>>;
pub type NoContentResult = Result<StatusCode, Response<Error>>;

pub mod users;