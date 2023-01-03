use crate::{
    cdn::upload_user_avatar,
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
use essence::{
    auth::generate_token,
    db::{get_pool, AuthDbExt, UserDbExt},
    http::user::{CreateUserPayload, CreateUserResponse, DeleteUserPayload, EditUserPayload},
    models::{ClientUser, ModelType, User, UserFlags},
    snowflake::generate_snowflake,
    Error, Maybe, NotFoundExt,
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

/// Create User
///
/// Registers a new user account with the given payload.
#[utoipa::path(
    post,
    path = "/users",
    request_body = CreateUserPayload,
    responses(
        (status = CREATED, description = "User ID and token", body = CreateUserResponse),
        (status = BAD_REQUEST, description = "Invalid payload", body = Error),
        (status = CONFLICT, description = "Username or email is already taken", body = Error),
    ),
)]
pub async fn create_user(payload: Json<CreateUserPayload>) -> RouteResult<CreateUserResponse> {
    let Json(CreateUserPayload {
        username,
        email,
        password,
    }) = payload;
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

/// Get Authenticated User
///
/// Fetches information about the logged in user.
#[utoipa::path(
    get,
    path = "/users/me",
    responses(
        (status = OK, description = "User object", body = ClientUser),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn get_client_user(Auth(id, _): Auth) -> RouteResult<ClientUser> {
    let db = get_pool();
    let user = db
        .fetch_client_user_by_id(id)
        .await?
        .ok_or_not_found("user", "client user not found")?;

    Ok(Response::ok(user))
}

/// Edit User
///
/// Modifies information about the logged in user.
#[utoipa::path(
    patch,
    path = "/users/me",
    request_body = EditUserPayload,
    responses(
        (status = OK, description = "User object after modification", body = User),
        (status = BAD_REQUEST, description = "Invalid payload", body = Error),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = CONFLICT, description = "Username is already taken", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn edit_user(
    Auth(id, _): Auth,
    Json(mut payload): Json<EditUserPayload>,
) -> RouteResult<User> {
    if let Some(ref username) = payload.username {
        validate_username(username)?;
    }
    if let Maybe::Value(ref mut avatar) = payload.avatar {
        *avatar = upload_user_avatar(id, avatar).await?;
    }

    get_pool()
        .edit_user(id, payload)
        .await
        .map(Response::ok)
        .map_err(Response::from)
}

/// Delete User
///
/// Deletes the user account of the authenticated user. This is irreversible.
#[utoipa::path(
    delete,
    path = "/users/me",
    request_body = DeleteUserPayload,
    responses(
        (status = NO_CONTENT, description = "User was successfully d4eleted"),
        (status = UNAUTHORIZED, description = "Invalid token/credentials", body = Error),
        (status = BAD_REQUEST, description = "Invalid payload", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn delete_user(
    Auth(id, flags): Auth,
    Json(payload): Json<DeleteUserPayload>,
) -> NoContentResult {
    let DeleteUserPayload { password } = payload;
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

/// Get User
///
/// Fetches information about a user by their ID.
#[utoipa::path(
    get,
    path = "/users/{user_id}",
    responses(
        (status = OK, description = "User object", body = User),
        (status = NOT_FOUND, description = "User not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn get_user(_auth: Auth, Path(user_id): Path<u64>) -> RouteResult<User> {
    let user = get_pool()
        .fetch_user_by_id(user_id)
        .await?
        .ok_or_not_found("user", "user not found")?;

    Ok(Response::ok(user))
}

pub fn router() -> Router {
    Router::new()
        .route("/users", post(create_user.layer(ratelimit!(3, 15))))
        .route(
            "/users/me",
            get(get_client_user.layer(ratelimit!(3, 5)))
                .patch(edit_user.layer(ratelimit!(3, 15)))
                .delete(delete_user.layer(ratelimit!(2, 30))),
        )
        .route("/users/:user_id", get(get_user.layer(ratelimit!(3, 5))))
}
