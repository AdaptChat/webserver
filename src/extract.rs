use crate::Response;
use axum::{
    body::{Bytes, HttpBody},
    extract::{
        multipart::{MultipartError, MultipartRejection},
        FromRequest, FromRequestParts, Multipart,
    },
    http::{header, request::Parts, Request},
};
use bytes::Buf;
use essence::{
    db::{get_pool, AuthDbExt},
    error::{Error, MalformedBodyErrorType},
    models::UserFlags,
};
use serde::de::DeserializeOwned;

pub trait MultipartIntoErrExt<T> {
    fn multipart_into_err(self) -> Result<T, Error>;
}

impl<T> MultipartIntoErrExt<T> for Result<T, MultipartError> {
    fn multipart_into_err(self) -> Result<T, Error> {
        self.map_err(|e| Error::MalformedBody {
            error_type: MalformedBodyErrorType::InvalidMultipart,
            message: e.to_string(),
        })
    }
}

impl<T> MultipartIntoErrExt<T> for Result<T, MultipartRejection> {
    fn multipart_into_err(self) -> Result<T, Error> {
        self.map_err(|e| Error::MalformedBody {
            error_type: MalformedBodyErrorType::InvalidMultipart,
            message: e.to_string(),
        })
    }
}

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
                message: String::from(
                    "missing `Authorization` header, which should contain the token",
                ),
            })?
            .to_str()
            .map_err(|_| Error::InvalidToken {
                message: "Invalid Authorization header".to_string(),
            })?;

        let (id, flags) =
            get_pool()
                .fetch_user_info_by_token(token)
                .await?
                .ok_or(Error::InvalidToken {
                    message: "Invalid authorization token".to_string(),
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
                what: Some("deserialization".to_string()),
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

#[derive(Debug)]
pub struct CreateMessageData<T>(pub T, pub Option<Multipart>);

#[axum::async_trait]
impl<T, B, S> FromRequest<S, B> for CreateMessageData<T>
where
    T: DeserializeOwned,
    B: HttpBody + Send + 'static,
    B::Data: Into<Bytes> + Send,
    B::Error: Into<axum::BoxError>,
    S: Send + Sync,
{
    type Rejection = Response<Error>;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        if req
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|ct| ct.to_str().is_ok_and(|ct| ct == "application/json"))
        {
            let Json(json) = Json::from_request(req, state).await?;

            return Ok(Self(json, None));
        }

        let mut multipart: Multipart = Multipart::from_request(req, state)
            .await
            .multipart_into_err()?;

        let field = multipart
            .next_field()
            .await
            .multipart_into_err()?
            .ok_or_else(|| Error::MissingField {
                field: "json".to_string(),
                message: "`json` field is required when using multipart body".to_string(),
            })?;

        if let Some(name) = field.name() {
            if name == "json" {
                simd_json::from_reader(field.bytes().await.multipart_into_err()?.reader())
                    .map_err(|err| {
                        Error::MalformedBody {
                            error_type: MalformedBodyErrorType::InvalidJson,
                            message: err.to_string(),
                        }
                        .into()
                    })
                    .map(|json| Self(json, Some(multipart)))
            } else {
                Err(Error::InvalidField {
                    field: name.to_string(),
                    message: "the first field must be named `json`".to_string(),
                }
                .into())
            }
        } else {
            Err(Error::MissingField {
                field: "json".to_string(),
                message: "`json` field is required when using multipart body".to_string(),
            }
            .into())
        }
    }
}
