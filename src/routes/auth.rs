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

#[cfg(feature = "email")]
use crate::{
    email::{parse_and_validate_email, EmailMessage},
    extract::Auth,
    routes::NoContentResult,
};
#[cfg(feature = "email")]
use ::{
    axum::http::StatusCode,
    essence::{
        cache::{delete_email_verification, get_email_verification, store_email_verification},
        http::auth::{EmailVerificationFollowup, RequestEmailVerification},
        models::UserFlags,
    },
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

/// Request Email Verification
///
/// Initiates an email verification flow. If `new_email` is provided, the email is validated and
/// checked for uniqueness; a verification code is then sent to that address. If omitted, the code
/// is sent to the email already associated with the account. Returns an error if the payload is
/// absent and the account's email is already verified.
#[cfg(feature = "email")]
#[utoipa::path(
    post,
    path = "/auth/verify",
    request_body(content = Option<RequestEmailVerification>),
    responses(
        (status = NO_CONTENT, description = "Verification email sent"),
        (status = BAD_REQUEST, description = "Invalid or already-verified email", body = Error),
        (status = CONFLICT, description = "Email already taken", body = Error),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn request_email_verification(
    Auth(user_id, flags): Auth,
    payload: Option<Json<RequestEmailVerification>>,
) -> NoContentResult {
    assert_not_bot_account(flags, "Bot accounts cannot verify an email address")?;

    let db = get_pool();
    let user = db
        .fetch_client_user_by_id(user_id)
        .await?
        .ok_or_not_found("user", "user not found")?;

    let (new_email, password) = payload
        .map(|Json(p)| (p.new_email, p.password))
        .unwrap_or_default();
    let is_verified = user.flags.contains(UserFlags::VERIFIED);

    let target_email: String = if let Some(ref email) = new_email {
        if is_verified {
            let password = password.ok_or_else(|| Error::MissingField {
                field: "password".to_string(),
                message: "A password is required to change your email address.".to_string(),
            })?;
            if !db.verify_password(user_id, password).await? {
                return Err(Response::from(Error::InvalidCredentials {
                    what: "password".to_string(),
                    message: "Invalid password".to_string(),
                }));
            }
        }
        if db.is_email_taken(email).await? {
            return Err(Response::from(Error::AlreadyTaken {
                what: "email".to_string(),
                message: "Email is already taken".to_string(),
            }));
        }
        email.clone()
    } else {
        if user.flags.contains(UserFlags::VERIFIED) {
            return Err(Response::from(Error::InvalidField {
                field: "email".to_string(),
                message: "Your email address is already verified.".to_string(),
            }));
        }
        user.email.clone().ok_or_else(|| Error::InternalError {
            what: Some("email".to_string()),
            message: "Account has no associated email address.".to_string(),
            debug: None,
        })?
    };

    // NOTE: rand is not cryptographically secure, should this be changed?
    let code = format!("{:06}", rand::random::<u32>() % 1_000_000);
    store_email_verification(user_id, &code, new_email.as_deref()).await?;

    EmailMessage::VerifyEmail {
        username: &user.username,
        code: &code,
    }
    .send(parse_and_validate_email(&target_email)?)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Complete Email Verification
///
/// Completes an email verification flow by submitting the code that was sent. On success, the
/// account is marked as verified and, if a new email was supplied in the initiation step, the
/// email address is updated.
#[cfg(feature = "email")]
#[utoipa::path(
    post,
    path = "/auth/verify/followup",
    request_body = EmailVerificationFollowup,
    responses(
        (status = NO_CONTENT, description = "Verification successful"),
        (status = BAD_REQUEST, description = "Invalid or expired code", body = Error),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn verify_email_followup(
    Auth(user_id, flags): Auth,
    Json(EmailVerificationFollowup { code }): Json<EmailVerificationFollowup>,
) -> NoContentResult {
    assert_not_bot_account(flags, "Bot accounts cannot verify an email address")?;

    let (expected_code, pending_email) =
        get_email_verification(user_id).await?.ok_or_else(|| {
            Response::from(Error::InvalidField {
                field: "code".to_string(),
                message: "No email verification is pending for your account.".to_string(),
            })
        })?;

    if code != expected_code {
        return Err(Response::from(Error::InvalidField {
            field: "code".to_string(),
            message: "Incorrect verification code.".to_string(),
        }));
    }

    let db = get_pool();
    let mut transaction = db.begin().await?;

    if let Some(ref email) = pending_email {
        transaction.update_user_email(user_id, email).await?;
    }

    let mut user_flags = db
        .fetch_user_flags_by_id(user_id)
        .await?
        .ok_or_not_found("user", "user not found")?;
    user_flags.insert(UserFlags::VERIFIED);
    transaction
        .set_user_flags_by_id(user_id, user_flags)
        .await?;

    transaction.commit().await?;
    delete_email_verification(user_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub fn router() -> Router {
    let r = Router::new().route("/login", post(login.layer(ratelimit!(3, 10))));

    #[cfg(feature = "email")]
    let r = r
        .route(
            "/auth/verify",
            post(request_email_verification.layer(ratelimit!(1, 60))),
        )
        .route(
            "/auth/verify/followup",
            post(verify_email_followup.layer(ratelimit!(5, 60))),
        );

    r
}
