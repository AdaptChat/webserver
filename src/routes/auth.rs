use crate::{extract::Json, ratelimit::ratelimit, routes::RouteResult, Response};
use axum::{handler::Handler, routing::post, Router};
use essence::{
    auth::{generate_token, verify_password},
    db::{get_pool, AuthDbExt, UserDbExt},
    http::auth::{LoginRequest, LoginResponse, TokenRetrievalMethod},
    models::UserFlags,
    Error, NotFoundExt,
};

/// POST /login
pub async fn login(
    Json(LoginRequest {
        email,
        password,
        method,
    }): Json<LoginRequest>,
) -> RouteResult<LoginResponse> {
    let db = get_pool();
    let mut user = db
        .fetch_client_user_by_email(&email)
        .await?
        .ok_or_not_found("user", "user with the given email not found")?;

    if user.flags.contains(UserFlags::BOT) {
        return Err(Response::from(Error::UnsupportedAuthMethod {
            message: "Bots cannot login with this method, use a bot token instead",
        }));
    }

    if !verify_password(password, user.password.take().unwrap_or_default()).await? {
        return Err(Response::from(Error::InvalidCredentials {
            what: "password",
            message: "Invalid password",
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
    transaction.create_token(user.id, &token).await?;
    transaction.commit().await?;

    Ok(Response::ok(LoginResponse {
        user_id: user.id,
        token,
    }))
}

pub fn router() -> Router {
    Router::new().route("/login", post(login.layer(ratelimit!(3, 10))))
}
