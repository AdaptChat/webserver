use crate::Response;
use essence::Error;

pub type RouteResult<T> = Result<Response<T>, Response<Error>>;

pub mod users;
