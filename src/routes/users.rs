use crate::{extract::Json, ratelimit, routes::RouteResult, Response};
use axum::{routing::post, Router};
use essence::{
    auth::generate_token,
    db::{get_pool, AuthDbExt, UserDbExt},
    http::user::{CreateUserPayload, CreateUserResponse},
    models::ModelType,
    snowflake::generate_snowflake,
    Error,
};

fn validate_username(username: impl AsRef<str>) -> Result<(), Error> {
    let username = username.as_ref();
    let length = username.chars().count();

    if length < 2 {
        return Err(Error::InvalidField {
            field: "username",
            message: "Username must be at least 2 characters long".to_string(),
        });
    }

    if length > 32 {
        return Err(Error::InvalidField {
            field: "username",
            message: "Username cannot be longer than 32 characters".to_string(),
        });
    }

    for forbidden in ['\n', '\r', '#', '@'] {
        if username.contains(forbidden) {
            return Err(Error::InvalidField {
                field: "username",
                message: format!("Username cannot contain {forbidden:?}"),
            });
        }
    }

    Ok(())
}

/// POST /users
pub async fn create_user(
    Json(CreateUserPayload {
        username,
        email,
        password,
    }): Json<CreateUserPayload>,
) -> RouteResult<CreateUserResponse> {
    validate_username(&username)?;

    let db = get_pool();
    if db.is_email_taken(&email).await? {
        return Err(Response::from(Error::AlreadyTaken {
            what: "email",
            message: "Email is already taken".to_string(),
        }));
    }

    let mut transaction = db.begin().await?;

    // TODO: node id
    let id = generate_snowflake(ModelType::User, 0);
    transaction
        .register_user(id, &username, &email, &password)
        .await?;

    let token = generate_token(id);
    transaction.create_token(id, &token).await?;
    transaction.commit().await?;

    Ok(Response::created(CreateUserResponse { id, token }))
}

#[inline]
pub fn router() -> Router {
    Router::new().route("/users", post(create_user).layer(ratelimit!(3, 15)))
}
