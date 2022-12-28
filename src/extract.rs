use crate::Response;
use axum::{
    body::Bytes,
    body::HttpBody,
    extract::FromRequest,
    http::{header, Request},
};
use bytes::Buf;
use essence::Error;
use serde::de::DeserializeOwned;

/// A JSON request body.
#[derive(Clone, Debug)]
pub struct Json<T>(pub T);

#[inline]
fn is_json_content_type<B>(req: &Request<B>) -> bool {
    req.headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|content_type| content_type.to_str().is_ok_and(|s| s == "application/json"))
}

#[axum::async_trait]
impl<T, B, S> FromRequest<S, B> for Json<T>
where
    T: DeserializeOwned,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<axum::BoxError>,
    S: Send + Sync,
{
    type Rejection = Response<Error>;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        let malformed = Response::from(Error::MalformedBody);

        if !is_json_content_type(&req) {
            return Err(malformed.clone());
        }

        // Deserialize the body using simd_json
        let body = Bytes::from_request(req, state)
            .await
            .map_err(|_| malformed.clone())?;
        simd_json::from_reader(body.reader())
            .map(Json)
            .map_err(|_| malformed)
    }
}
