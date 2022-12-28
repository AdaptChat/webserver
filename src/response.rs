use axum::{
    http::{header::CONTENT_TYPE, StatusCode},
    response::{IntoResponse, Response as AxumResponse},
};
use essence::Error;
use serde::Serialize;

/// A response to an endpoint.
#[derive(Clone, Debug)]
pub struct Response<T: Serialize>(
    /// The status code of the response.
    pub StatusCode,
    /// The body of the response. Should be serializable.
    pub T,
);

impl<T: Serialize> Response<T> {
    /// Creates a new successful response (200 OK) with the given body.
    #[inline]
    #[must_use]
    pub const fn ok(body: T) -> Self {
        Self(StatusCode::OK, body)
    }

    /// Creates a new created response (201 Created) with the given body.
    #[inline]
    #[must_use]
    pub const fn created(body: T) -> Self {
        Self(StatusCode::CREATED, body)
    }
}

impl<T: Into<Error>> From<T> for Response<Error> {
    fn from(err: T) -> Self {
        let err = err.into();
        Self(
            StatusCode::from_u16(err.http_status_code().unwrap_or(0))
                .expect("error does not have an HTTP status code"),
            err,
        )
    }
}

impl<T: Serialize> IntoResponse for Response<T> {
    fn into_response(self) -> AxumResponse {
        let bytes = match simd_json::to_vec(&self.1) {
            Ok(bytes) => bytes,
            // TODO: this could become infinite recursion
            Err(err) => {
                return serialization_error(&err);
            }
        };

        axum::http::Response::builder()
            .status(self.0)
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Full::from(bytes))
            .expect("invalid http status code received")
            .into_response()
    }
}

#[inline]
fn serialization_error(err: &(impl ToString + std::fmt::Debug)) -> AxumResponse {
    Response::from(Error::InternalError {
        what: Some("serialization"),
        message: err.to_string(),
        debug: Some(format!("{err:?}")),
    })
    .into_response()
}
