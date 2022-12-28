use crate::{
    extract::{Auth, Json},
    ratelimit,
    routes::{NoContentResult, RouteResult},
    Response,
};
use axum::{
    extract::Path,
    handler::Handler,
    http::StatusCode,
    routing::{get, post},
    Router,
};
use essence::models::User;
use essence::{
    auth::generate_token,
    db::{get_pool, AuthDbExt, UserDbExt},
    http::user::{CreateUserPayload, CreateUserResponse, DeleteUserPayload},
    models::{ClientUser, ModelType, UserFlags},
    snowflake::generate_snowflake,
    Error, NotFoundExt,
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

/// GET /users/me
pub async fn get_client_user(Auth(id, _): Auth) -> RouteResult<ClientUser> {
    let db = get_pool();
    let user = db
        .fetch_client_user_by_id(id)
        .await?
        .ok_or_not_found("user", "client user not found")?;

    Ok(Response::ok(user))
}

/// DELETE /users/me
pub async fn delete_user(
    Auth(id, flags): Auth,
    Json(DeleteUserPayload { password }): Json<DeleteUserPayload>,
) -> NoContentResult {
    let mut db = get_pool();

    if flags.contains(UserFlags::BOT) {
        return Err(Response::from(Error::UnsupportedAuthMethod {
            message: "This user is a bot account, but this endpoint can only delete user \
                accounts. To delete bot accounts, see the DELETE /bots/:id endpoint.",
        }));
    }

    if !db.verify_password(id, password).await? {
        return Err(Response::from(Error::InvalidCredentials {
            what: "password",
            message: "Invalid password",
        }));
    }

    db.delete_user(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /users/:id
pub async fn get_user(_: Auth, Path(id): Path<u64>) -> RouteResult<User> {
    let user = get_pool()
        .fetch_user_by_id(id)
        .await?
        .ok_or_not_found("user", "user not found")?;

    Ok(Response::ok(user))
}

#[inline]
pub fn router() -> Router {
    Router::new()
        .route("/users", post(create_user.layer(ratelimit!(3, 15))))
        .route(
            "/users/me",
            get(get_client_user.layer(ratelimit!(3, 5)))
                .delete(delete_user.layer(ratelimit!(2, 40))),
        )
        .route("/users/:id", get(get_user.layer(ratelimit!(3, 5))))
}
