use crate::Response;
use axum::{
    body::{Bytes, HttpBody},
    extract::FromRequest,
    http::{header, Request},
};
use bytes::Buf;
use essence::error::{Error, MalformedBodyErrorType};
use serde::de::DeserializeOwned;

/// A JSON request body.
#[derive(Clone, Debug)]
pub struct Json<T>(pub T);

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
        let content_type = req.headers().get(header::CONTENT_TYPE);

        if let Some(c) = content_type {
            match c.to_str() {
                Ok("application/json") => (),
                Ok(c) => {
                    return Err(Response::from(Error::MalformedBody {
                        error_type: MalformedBodyErrorType::InvalidContentType,
                        message: format!("expected content type application/json, got {c} instead"),
                    }));
                }
                Err(_) => {
                    return Err(Response::from(Error::MalformedBody {
                        error_type: MalformedBodyErrorType::InvalidContentType,
                        message: "expected content type application/json".to_string(),
                    }));
                }
            }
        } else {
            return Err(Response::from(Error::MalformedBody {
                error_type: MalformedBodyErrorType::InvalidContentType,
                message: "expected content type header to be \"application/json\", but the header \
                    was not present"
                    .to_string(),
            }));
        }

        // Deserialize the body using simd_json
        let body = Bytes::from_request(req, state)
            .await
            .map_err(|err| Error::InternalError {
                what: Some("deserialization"),
                message: "failed to buffer request body".to_string(),
                debug: Some(format!("{err:?}")),
            })?;

        simd_json::from_reader(body.reader())
            .map(Json)
            .map_err(|err| Error::MalformedBody {
                error_type: MalformedBodyErrorType::InvalidJson,
                message: err.to_string(),
            })
            .map_err(Response::from)
    }
}
