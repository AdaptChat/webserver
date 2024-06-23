use crate::{
    extract::Json,
    ratelimit::ratelimit,
    routes::{assert_not_bot_account, RouteResult},
    Response,
};
use axum::{handler::Handler, routing::post, Router};
use essence::{
    auth::{generate_token, verify_password},
    db::{get_pool, AuthDbExt, UserDbExt},
    http::auth::{LoginRequest, LoginResponse, TokenRetrievalMethod},
    utoipa, Error, NotFoundExt,
};

/// Generate Token (Login)
///
/// Login to the API with your email and password to retrieve an authentication token.
#[utoipa::path(
    post,
    path = "/login",
    request_body = LoginRequest,
    responses(
        (status = OK, description = "Login successful", body = LoginResponse),
        (status = UNAUTHORIZED, description = "Invalid credentials", body = Error),
    )
)]
pub async fn login(json: Json<LoginRequest>) -> RouteResult<LoginResponse> {
    // utoipa does not support parameter destructuring for structs, so we have to do it here instead
    let Json(LoginRequest {
        email,
        password,
        method,
    }) = json;

    let db = get_pool();
    let mut user = db
        .fetch_client_user_by_email(&email)
        .await?
        .ok_or_not_found("user", "user with the given email not found")?;

    assert_not_bot_account(
        user.flags,
        "Bots cannot login with this method, use a bot token instead",
    )?;

    if !verify_password(password, user.password.take().unwrap_or_default()).await? {
        return Err(Response::from(Error::InvalidCredentials {
            what: "password".to_string(),
            message: "Invalid password".to_string(),
        }));
    }

    if method == TokenRetrievalMethod::Reuse {
        if let Some(token) = db.fetch_token(user.id).await? {
            return Ok(Response::ok(LoginResponse {
                user_id: user.id,
                token,
            }));
        }
    }

    let mut transaction = db.begin().await?;
    if method == TokenRetrievalMethod::Revoke {
        transaction.delete_all_tokens(user.id).await?;
    }

    let token = generate_token(user.id);
    transaction.register_token(user.id, &token).await?;
    transaction.commit().await?;

    Ok(Response::ok(LoginResponse {
        user_id: user.id,
        token,
    }))
}

pub fn router() -> Router {
    Router::new().route("/login", post(login.layer(ratelimit!(3, 10))))
}
