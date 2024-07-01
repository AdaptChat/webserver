use axum::{
    extract::Request,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        StatusCode,
    },
    middleware::Next,
    response::{IntoResponse, Response as AxumResponse},
};
use erased_serde::Serialize;
use essence::Error;
use std::sync::Arc;

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

type ResponseHandle = (StatusCode, Arc<dyn Serialize + Send + Sync>);

pub(crate) async fn handle_accept_header(request: Request, next: Next) -> AxumResponse {
    let accept = request.headers().get(ACCEPT).map(|v| v.as_ref().to_owned());

    let mut response = next.run(request).await;

    if let Some(handle) = response.extensions_mut().remove::<ResponseHandle>() {
        let (status, body) = handle;
        #[allow(clippy::single_match_else)]
        let (mimetype, body) = match accept.as_deref() {
            Some(b"msgpack" | b"application/msgpack" | b"application/x-msgpack") => {
                let bytes = match rmp_serde::to_vec(&body) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        return serialization_error(&err);
                    }
                };
                ("application/msgpack", bytes)
            }
            _ => {
                let bytes = match simd_json::to_vec(&body) {
                    Ok(bytes) => bytes,
                    // TODO: this could become infinite recursion
                    Err(err) => {
                        return serialization_error(&err);
                    }
                };
                ("application/json", bytes)
            }
        };
        axum::http::Response::builder()
            .status(status)
            .header(CONTENT_TYPE, mimetype)
            .body(axum::body::Body::from(body))
            .expect("invalid http status code received")
            .into_response()
    } else {
        response
    }
}

impl<T: Serialize + Send + Sync + 'static> IntoResponse for Response<T> {
    fn into_response(self) -> AxumResponse {
        let mut response = StatusCode::NOT_IMPLEMENTED.into_response();
        response
            .extensions_mut()
            .insert::<ResponseHandle>((self.0, Arc::new(self.1)));
        response
    }
}

#[inline]
pub fn serialization_error(err: &(impl ToString + std::fmt::Debug)) -> AxumResponse {
    Response::from(Error::InternalError {
        what: Some("serialization".to_string()),
        message: err.to_string(),
        debug: Some(format!("{err:?}")),
    })
    .into_response()
}
