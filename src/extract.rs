use crate::Response;
use axum::{
    body::{Bytes, HttpBody},
    extract::{FromRequest, FromRequestParts},
    http::{header, request::Parts, Request},
};
use bytes::Buf;
use essence::{
    db::{get_pool, AuthDbExt},
    error::{Error, MalformedBodyErrorType},
    models::UserFlags,
};
use serde::de::DeserializeOwned;

/// Extracts authentication information (the token) from request headers.
#[derive(Copy, Clone, Debug)]
pub struct Auth(pub u64, pub UserFlags);

#[axum::async_trait]
impl<S> FromRequestParts<S> for Auth
where
    S: Send + Sync,
{
    type Rejection = Response<Error>;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get("Authorization")
            .ok_or(Error::InvalidToken {
                message: "missing `Authorization` header, which should contain the token",
            })?
            .to_str()
            .map_err(|_| Error::InvalidToken {
                message: "Invalid Authorization header",
            })?;

        let (id, flags) =
            get_pool()
                .fetch_user_info_by_token(token)
                .await?
                .ok_or(Error::InvalidToken {
                    message: "Invalid authorization token",
                })?;

        Ok(Self(id, flags))
    }
}

/// A JSON request body. This consumes the request body, it must be used as the last extractor.
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
