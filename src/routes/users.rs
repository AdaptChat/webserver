use std::sync::LazyLock;

#[cfg(feature = "ws")]
use crate::amqp::prelude::*;
#[cfg(feature = "email")]
use crate::email::parse_and_validate_email;
use crate::{
    cdn::{get_client, upload_user_avatar},
    extract::{Auth, Json},
    ratelimit,
    routes::{assert_not_bot_account, NoContentResult, RouteResult},
    Response,
};
use axum::{
    extract::Path,
    handler::Handler,
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post, put},
    Router,
};
use essence::{
    auth::generate_token,
    db::{get_pool, AuthDbExt, GuildDbExt, UserDbExt},
    http::{
        auth::LoginResponse,
        user::{
            CreateBotPayload, CreateBotResponse, CreateUserPayload, CreateUserResponse,
            DeleteBotPayload, DeleteUserPayload, EditBotPayload, EditUserPayload,
            RegenerateBotTokenPayload, SendFriendRequestPayload,
        },
    },
    models::{
        Bot, BotFlags, ClientUser, ModelType, Relationship, RelationshipType, User, UserFlags,
    },
    snowflake::generate_snowflake,
    utoipa, Error, Maybe, NotFoundExt,
};
use serde::{Deserialize, Serialize};

static TURNSTILE_SECRET_KEY: LazyLock<Option<String>> =
    LazyLock::new(|| std::env::var("TURNSTILE_SECRET_KEY").ok());

fn validate_username_esque(username: &str, field: &str) -> Result<(), Error> {
    let length = username.chars().count();

    if length < 2 {
        return Err(Error::InvalidField {
            field: field.to_string(),
            message: "Username must be at least 2 characters long".to_string(),
        });
    }

    if length > 32 {
        return Err(Error::InvalidField {
            field: field.to_string(),
            message: "Username cannot be longer than 32 characters".to_string(),
        });
    }

    Ok(())
}

fn validate_username(username: impl AsRef<str>) -> Result<(), Error> {
    const SPECIAL: [char; 3] = ['-', '.', '_'];

    let username = username.as_ref();
    validate_username_esque(username, "username")?;

    if let Some(forbidden) = username
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && !SPECIAL.contains(c))
    {
        return Err(Error::InvalidField {
            field: "username".to_string(),
            message: format!("Username cannot contain {forbidden:?}"),
        });
    }

    if username.starts_with(SPECIAL) || username.ends_with(SPECIAL) {
        return Err(Error::InvalidField {
            field: "username".to_string(),
            message: "First and last character of username must be alphanumeric".to_string(),
        });
    }

    Ok(())
}

fn validate_display_name(display_name: impl AsRef<str>) -> Result<(), Error> {
    let display_name = display_name.as_ref();
    validate_username_esque(display_name, "display_name")?;

    for forbidden in ['\n', '\r', '#', '@'] {
        if display_name.contains(forbidden) {
            return Err(Error::InvalidField {
                field: "display_name".to_string(),
                message: format!("Display name cannot contain {forbidden:?}"),
            });
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct TurnstileVerifyRequest {
    secret: &'static str,
    response: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    remoteip: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TurnstileVerifyResponse {
    success: bool,
    #[serde(rename = "error-codes")]
    error_codes: Vec<String>,
    // Ignore other fields
}

/// Check Username Availability
///
/// Checks if a username is available.
#[utoipa::path(
    get,
    path = "/users/check/{username}",
    responses(
        (status = OK, description = "Username is available"),
        (status = BAD_REQUEST, description = "Invalid username", body = Error),
        (status = CONFLICT, description = "Username is taken", body = Error),
    ),
)]
pub async fn check_username(Path(username): Path<String>) -> RouteResult<()> {
    validate_username(&username)?;
    if get_pool().is_username_taken(&username).await? {
        return Err(Response::from(Error::AlreadyTaken {
            what: "username".to_string(),
            message: "Username is already taken".to_string(),
        }));
    }
    Ok(Response::ok(()))
}

async fn validate_captcha(token: String, ip: Option<String>) -> Result<(), Error> {
    let Some(key) = TURNSTILE_SECRET_KEY.as_deref() else {
        warn!("TURNSTILE_SECRET_KEY not provided in env, captchas will not be validated!");
        return Ok(());
    };
    let resp = get_client()
        .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .json(&TurnstileVerifyRequest {
            secret: key,
            response: token,
            remoteip: ip,
        })
        .send()
        .await
        .map_err(|e| Error::InternalError {
            what: Some("error when trying to verify turnstile request".to_string()),
            message: e.to_string(),
            debug: Some(format!("{e:?}")),
        })?
        .json::<TurnstileVerifyResponse>()
        .await
        .map_err(|e| Error::InternalError {
            what: Some("invalid resp from cloudflare".to_string()),
            message: e.to_string(),
            debug: Some(format!("{e:?}")),
        })?;

    resp.success
        .then_some(())
        .ok_or_else(|| Error::InvalidCaptcha {
            message: resp.error_codes.join(", "),
        })
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
pub async fn create_user(
    headers: HeaderMap,
    payload: Json<CreateUserPayload>,
) -> RouteResult<CreateUserResponse> {
    let Json(CreateUserPayload {
        username,
        display_name,
        email,
        password,
        captcha_token,
    }) = payload;
    validate_username(&username)?;
    if let Some(ref display_name) = display_name {
        validate_display_name(display_name)?;
    }

    validate_captcha(
        captcha_token,
        headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok().map(ToString::to_string)),
    )
    .await?;

    #[cfg(feature = "email")]
    parse_and_validate_email(&email)?;

    let db = get_pool();
    if db.is_email_taken(&email).await? {
        return Err(Response::from(Error::AlreadyTaken {
            what: "email".to_string(),
            message: "Email is already taken".to_string(),
        }));
    }
    if db.is_username_taken(&username).await? {
        return Err(Response::from(Error::AlreadyTaken {
            what: "username".to_string(),
            message: "Username is already taken".to_string(),
        }));
    }

    let mut transaction = db.begin().await?;

    // TODO: node id
    let id = generate_snowflake(ModelType::User, 0);
    transaction
        .register_user(id, &username, display_name.as_ref(), &email, &password)
        .await?;

    let token = generate_token(id);
    transaction.register_token(id, &token).await?;
    transaction.commit().await?;

    Ok(Response::created(CreateUserResponse { id, token }))
}

/// Get Authenticated User
///
/// Fetches information about the logged-in user.
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

async fn raw_edit_user<'a, D>(
    db: &mut D,
    id: u64,
    mut payload: EditUserPayload,
) -> Result<User, Response<Error>>
where
    D: UserDbExt<'a> + Sync,
{
    if let Some(ref username) = payload.username {
        validate_username(username)?;

        if db.is_username_taken_excluding(username, id).await? {
            return Err(Response::from(Error::AlreadyTaken {
                what: "username".to_string(),
                message: "Username is already taken".to_string(),
            }));
        }
    }
    if let Maybe::Value(ref display_name) = payload.display_name {
        validate_display_name(display_name)?;
    }
    if let Maybe::Value(ref mut avatar) = payload.avatar {
        *avatar = upload_user_avatar(id, avatar).await?;
    }

    let (before, after) = db.edit_user(id, payload).await?;

    // TODO: this should publish to everyone who can see this user
    #[cfg(feature = "ws")]
    amqp::publish_user_event(
        id,
        OutboundMessage::UserUpdate {
            before,
            after: after.clone(),
        },
    )
    .await?;

    Ok(after)
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
    Auth(id, flags): Auth,
    Json(payload): Json<EditUserPayload>,
) -> RouteResult<User> {
    assert_not_bot_account(
        flags,
        "Bot accounts cannot edit user information. \
        The bot owner can access this function through the Edit Bot endpoint (PATCH /bots/:id).",
    )?;

    let mut db = get_pool();
    let after = raw_edit_user(&mut db, id, payload).await?;
    Ok(Response::ok(after))
}

/// Delete User
///
/// Deletes the user account of the authenticated user. This is irreversible.
#[utoipa::path(
    delete,
    path = "/users/me",
    request_body = DeleteUserPayload,
    responses(
        (status = NO_CONTENT, description = "User was successfully deleted"),
        (status = UNAUTHORIZED, description = "Invalid token/credentials", body = Error),
        (status = BAD_REQUEST, description = "Invalid payload", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn delete_user(
    Auth(id, flags): Auth,
    Json(payload): Json<DeleteUserPayload>,
) -> NoContentResult {
    assert_not_bot_account(
        flags,
        "This user is a bot account, but this endpoint can only delete user accounts. \
       To delete bot accounts, see the DELETE /bots/:id endpoint.",
    )?;

    let DeleteUserPayload { password } = payload;
    let mut db = get_pool();

    if !db.verify_password(id, password).await? {
        return Err(Response::from(Error::InvalidCredentials {
            what: "password".to_string(),
            message: "Invalid password".to_string(),
        }));
    }

    db.delete_user(id).await?;

    #[cfg(feature = "ws")]
    amqp::publish_user_event(id, OutboundMessage::UserDelete { user_id: id }).await?;

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

/// Get Relationships
///
/// Fetches all relationships of the authenticated user.
#[utoipa::path(
    get,
    path = "/relationships",
    responses(
        (status = OK, description = "List of relationships", body = Vec<Relationship>),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn get_relationships(Auth(user_id, _): Auth) -> RouteResult<Vec<Relationship>> {
    let relationships = get_pool().fetch_relationships(user_id).await?;

    Ok(Response::ok(relationships))
}

#[cfg(feature = "ws")]
async fn publish_relationship_events(
    user_id: u64,
    target_id: u64,
    outgoing: Relationship,
    incoming: Option<Relationship>,
) -> essence::Result<()> {
    let outgoing = amqp::publish_user_event(
        user_id,
        OutboundMessage::RelationshipCreate {
            relationship: outgoing,
        },
    );
    if let Some(incoming) = incoming {
        let incoming = amqp::publish_user_event(
            target_id,
            OutboundMessage::RelationshipCreate {
                relationship: incoming,
            },
        );
        tokio::try_join!(outgoing, incoming)?;
    } else {
        outgoing.await?;
    }
    Ok(())
}

/// Send Friend Request
///
/// Requests to add a user as a friend by their username and discriminator.
#[utoipa::path(
    post,
    path = "/relationships/friends",
    request_body = SendFriendRequestPayload,
    responses(
        (status = OK, description = "Relationship object", body = Relationship),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = BAD_REQUEST, description = "Invalid payload", body = Error),
        (status = NOT_FOUND, description = "User not found", body = Error),
        (status = CONFLICT, description = "Cannot act on self", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn add_friend(
    Auth(user_id, flags): Auth,
    Json(payload): Json<SendFriendRequestPayload>,
) -> RouteResult<Relationship> {
    assert_not_bot_account(flags, "Bot accounts cannot send friend requests")?;

    let db = get_pool();
    let target = db
        .fetch_user_by_username(&payload.username)
        .await?
        .ok_or_not_found("user", format!("User @{} does not exist", payload.username))?;

    if target.id == user_id {
        return Err(Response::from(Error::CannotActOnSelf {
            message: "You cannot send friend requests to yourself.".to_string(),
        }));
    }
    if target.flags.contains(UserFlags::BOT) {
        return Err(Response::from(Error::CannotFriendBots {
            target_id: target.id,
            message: "You cannot send friend requests to bot accounts.".to_string(),
        }));
    }

    match db.fetch_relationship_type(user_id, target.id).await? {
        Some(RelationshipType::Friend) => Err("You are already friends with this user."),
        Some(RelationshipType::OutgoingRequest) => {
            Err("You have already sent a friend request to this user.")
        }
        Some(RelationshipType::IncomingRequest) => {
            return accept_friend_request(Auth(user_id, flags), Path(target.id)).await;
        }
        Some(RelationshipType::Blocked) => Err(
            "You have blocked this user, you should unblock them before adding them as a friend.",
        ),
        None => Ok(()),
    }
    .map_err(|message| Error::AlreadyExists {
        what: "relationship".to_string(),
        message: message.to_string(),
    })?;

    let mut transaction = db.begin().await?;
    let (outgoing, incoming) = transaction
        .create_relationship(user_id, target.id, RelationshipType::OutgoingRequest)
        .await
        .map_err(Response::from)?;

    transaction.commit().await?;

    #[cfg(feature = "ws")]
    publish_relationship_events(user_id, target.id, outgoing.clone(), incoming).await?;

    Ok(Response::ok(outgoing))
}

/// Accept Friend Request
///
/// Accepts an incoming friend request.
#[utoipa::path(
    put,
    path = "/relationships/friends/{target_id}",
    responses(
        (status = OK, description = "Relationship object", body = Relationship),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = NOT_FOUND, description = "Relationship not found", body = Error),
        (status = CONFLICT, description = "Cannot act on self", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn accept_friend_request(
    Auth(user_id, _): Auth,
    Path(target_id): Path<u64>,
) -> RouteResult<Relationship> {
    let db = get_pool();
    match db.fetch_relationship_type(user_id, target_id).await? {
        Some(RelationshipType::IncomingRequest) => Ok(()),
        Some(RelationshipType::Friend) => Err(Response::from(Error::AlreadyExists {
            what: "relationship".to_string(),
            message: "You are already friends with this user.".to_string(),
        })),
        _ => Err(Response::from(Error::NotFound {
            entity: "relationship".to_string(),
            message: "You do not have an incoming friend request from this user.".to_string(),
        })),
    }?;

    let mut transaction = db.begin().await?;
    let (outgoing, incoming) = transaction
        .create_relationship(user_id, target_id, RelationshipType::Friend)
        .await?;

    transaction.commit().await?;

    #[cfg(feature = "ws")]
    publish_relationship_events(user_id, target_id, outgoing.clone(), incoming).await?;

    Ok(Response::ok(outgoing))
}

/// Block User
///
/// Blocks a user.
#[utoipa::path(
    put,
    path = "/relationships/blocks/{target_id}",
    responses(
        (status = OK, description = "Relationship object", body = Relationship),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = NOT_FOUND, description = "Relationship not found", body = Error),
        (status = CONFLICT, description = "Cannot act on self", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn block_user(
    Auth(user_id, _): Auth,
    Path(target_id): Path<u64>,
) -> RouteResult<Relationship> {
    let db = get_pool();
    if db.fetch_relationship_type(user_id, target_id).await? == Some(RelationshipType::Blocked) {
        return Err(Response::from(Error::AlreadyExists {
            what: "relationship".to_string(),
            message: "You have already blocked this user.".to_string(),
        }));
    }

    let mut transaction = db.begin().await?;
    let (outgoing, incoming) = transaction
        .create_relationship(user_id, target_id, RelationshipType::Blocked)
        .await?;

    transaction.commit().await?;

    #[cfg(feature = "ws")]
    publish_relationship_events(user_id, target_id, outgoing.clone(), incoming).await?;

    Ok(Response::ok(outgoing))
}

/// Delete Relationship
///
/// Deletes a relationship with a user. This includes:
/// * Revoking outgoing friend requests
/// * Declining incoming friend requests
/// * Unfriending users
/// * Unblocking users (unidirectional)
#[utoipa::path(
    delete,
    path = "/relationships/{target_id}",
    responses(
        (status = NO_CONTENT, description = "Relationship deleted"),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = NOT_FOUND, description = "Relationship not found", body = Error),
        (status = CONFLICT, description = "Cannot act on self", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn delete_relationship(
    Auth(user_id, _): Auth,
    Path(target_id): Path<u64>,
) -> NoContentResult {
    let db = get_pool();
    let mut transaction = db.begin().await?;

    let affected = transaction.delete_relationship(user_id, target_id).await?;
    if affected == 0 {
        return Err(Response::from(Error::NotFound {
            entity: "relationship".to_string(),
            message: "You do not have a relationship with this user.".to_string(),
        }));
    }

    #[cfg(feature = "ws")]
    {
        let outgoing = amqp::publish_user_event(
            user_id,
            OutboundMessage::RelationshipRemove { user_id: target_id },
        );
        if affected > 1 {
            let incoming = amqp::publish_user_event(
                target_id,
                OutboundMessage::RelationshipRemove { user_id },
            );
            tokio::try_join!(outgoing, incoming)?;
        } else {
            outgoing.await?;
        }
    }

    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct RegistrationKeyJson {
    pub key: String,
}

async fn add_registration_key(
    Auth(user_id, _): Auth,
    Json(RegistrationKeyJson { key }): Json<RegistrationKeyJson>,
) -> NoContentResult {
    get_pool().insert_push_key(user_id, key).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Create Bot
///
/// Registers a new bot account with the given payload.
#[utoipa::path(
    post,
    path = "/bots",
    request_body = CreateBotPayload,
    responses(
        (status = CREATED, description = "Bot ID and token", body = CreateBotResponse),
        (status = BAD_REQUEST, description = "Invalid payload", body = Error),
        (status = CONFLICT, description = "Username is already taken", body = Error),
    ),
    security(("token" = [])),
)]
async fn create_bot(
    Auth(user_id, flags): Auth,
    Json(payload): Json<CreateBotPayload>,
) -> RouteResult<CreateBotResponse> {
    assert_not_bot_account(flags, "Bot accounts cannot create bots")?;

    validate_username(&payload.username)?;
    if let Some(ref display_name) = payload.display_name {
        validate_display_name(display_name)?;
    }

    let db = get_pool();
    let qualified_name = format!("{user_id}/{}", payload.username);
    if db.is_username_taken(&qualified_name).await? {
        return Err(Response::from(Error::AlreadyTaken {
            what: "username".to_string(),
            message: "Username is already taken".to_string(),
        }));
    }

    let mut transaction = db.begin().await?;

    let id = generate_snowflake(ModelType::User, 0);
    let mut bot_flags = BotFlags::empty();
    if payload.public {
        bot_flags.insert(BotFlags::PUBLIC);
    }
    let bot = transaction
        .create_bot(
            id,
            user_id,
            &qualified_name,
            payload.display_name.as_deref(),
            bot_flags,
        )
        .await?;

    let token = generate_token(id);
    transaction.register_token(id, &token).await?;
    transaction.commit().await?;

    Ok(Response::created(CreateBotResponse { bot, token }))
}

/// Get Bot
///
/// Fetches information about a bot account by its ID.
#[utoipa::path(
    get,
    path = "/bots/{bot_id}",
    responses(
        (status = OK, description = "Bot object", body = Bot),
        (status = NOT_FOUND, description = "Bot not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn get_bot(_auth: Auth, Path(bot_id): Path<u64>) -> RouteResult<Bot> {
    let bot = get_pool()
        .fetch_bot(bot_id)
        .await?
        .ok_or_not_found("bot", "bot not found")?;

    Ok(Response::ok(bot))
}

/// Get All Bots
///
/// Fetches all bot accounts owned by the authenticated user.
#[utoipa::path(
    get,
    path = "/bots",
    responses(
        (status = OK, description = "List of bots", body = Vec<Bot>),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn get_bots(Auth(user_id, flags): Auth) -> RouteResult<Vec<Bot>> {
    assert_not_bot_account(flags, "Bot accounts cannot own other bots")?;
    let bots = get_pool().fetch_all_bots_by_user(user_id).await?;
    Ok(Response::ok(bots))
}

/// Edit Bot
///
/// Modifies information about a bot account.
#[utoipa::path(
    patch,
    path = "/bots/{bot_id}",
    request_body = EditBotPayload,
    responses(
        (status = OK, description = "Bot object after modification", body = Bot),
        (status = BAD_REQUEST, description = "Invalid payload", body = Error),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = CONFLICT, description = "Username is already taken", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn edit_bot(
    Auth(user_id, flags): Auth,
    Path(bot_id): Path<u64>,
    Json(mut payload): Json<EditBotPayload>,
) -> RouteResult<Bot> {
    assert_not_bot_account(flags, "Bots cannot edit their own bot information; this endpoint must be called by the bot owner.")?;
    payload.user_payload.username = None;

    let db = get_pool();
    db.assert_user_owns_bot(user_id, bot_id).await?;

    let mut transaction = db.begin().await?;
    let user = raw_edit_user(&mut transaction, bot_id, payload.user_payload.clone()).await?;
    let after = transaction.edit_bot(user, payload).await?;
    transaction.commit().await?;

    Ok(Response::ok(after))
}

async fn validate_optional_password<'t, D: AuthDbExt<'t> + GuildDbExt<'t> + Sync>(
    db: &D,
    guild_count_threshold: u64,
    user_id: u64,
    bot_id: u64,
    password: Option<String>,
    message: &'static str,
) -> Result<(), Response<Error>> {
    if db.fetch_guild_count(bot_id).await? > guild_count_threshold {
        if let Some(p) = password {
            if !db.verify_password(user_id, p.clone()).await? {
                return Err(Response::from(Error::InvalidCredentials {
                    what: "password".to_string(),
                    message: "Invalid password".to_string(),
                }));
            }
        } else {
            return Err(Response::from(Error::MissingField {
                field: "password".to_string(),
                message: String::from(message),
            }));
        }
    }
    Ok(())
}

/// Delete Bot
///
/// Deletes a bot account. Requires the bot owner's password if the bot is in over 20 guilds.
#[utoipa::path(
    delete,
    path = "/bots/{bot_id}",
    request_body = Option<DeleteBotPayload>,
    responses(
        (status = NO_CONTENT, description = "Bot was successfully deleted"),
        (status = UNAUTHORIZED, description = "Invalid token/credentials", body = Error),
        (status = BAD_REQUEST, description = "Invalid payload", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn delete_bot(
    Auth(user_id, flags): Auth,
    Path(bot_id): Path<u64>,
    payload: Option<Json<DeleteBotPayload>>,
) -> NoContentResult {
    assert_not_bot_account(
        flags,
        "Bots cannot delete other bots; this endpoint can only be accessed by user accounts.",
    )?;

    let db = get_pool();
    db.assert_user_owns_bot(user_id, bot_id).await?;

    validate_optional_password(
        &db,
        20,
        user_id,
        bot_id,
        payload.map(|Json(DeleteBotPayload { password })| password),
        "This bot is in over 20 guilds and requires a password to delete.",
    )
    .await?;

    let mut transaction = db.begin().await?;
    transaction.delete_user(bot_id).await?;
    transaction.delete_bot(bot_id).await?;
    transaction.commit().await?;

    #[cfg(feature = "ws")]
    amqp::publish_user_event(bot_id, OutboundMessage::UserDelete { user_id: bot_id }).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Regenerate Bot Token
///
/// Regenerates a token for a bot you own. If the bot is in over 20 guilds, you must provide the bot
/// owner's password.
#[utoipa::path(
    post,
    path = "/bots/{bot_id}/tokens",
    request_body = Option<RegenerateBotTokenPayload>,
    responses(
        (status = OK, description = "Token regenerated", body = LoginResponse),
        (status = UNAUTHORIZED, description = "Invalid token/credentials", body = Error),
        (status = BAD_REQUEST, description = "Invalid payload", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn regenerate_bot_token(
    Auth(user_id, flags): Auth,
    Path(bot_id): Path<u64>,
    payload: Option<Json<RegenerateBotTokenPayload>>,
) -> RouteResult<LoginResponse> {
    assert_not_bot_account(
        flags,
        "Bots cannot regenerate their own tokens, this endpoint must be called by the bot owner.",
    )?;

    let db = get_pool();
    db.assert_user_owns_bot(user_id, bot_id).await?;

    validate_optional_password(
        &db,
        20,
        user_id,
        bot_id,
        payload.map(|Json(RegenerateBotTokenPayload { password })| password),
        "This bot is in over 20 guilds and requires a password to regenerate its token.",
    )
    .await?;

    let mut transaction = db.begin().await?;
    let token = generate_token(bot_id);
    transaction.delete_all_tokens(bot_id).await?;
    transaction.register_token(bot_id, &token).await?;
    transaction.commit().await?;

    Ok(Response::ok(LoginResponse {
        user_id: bot_id,
        token,
    }))
}

pub fn router() -> Router {
    Router::new()
        .route("/users", post(create_user.layer(ratelimit!(3, 120))))
        .route(
            "/users/check/:username",
            get(check_username.layer(ratelimit!(5, 5))),
        )
        .route(
            "/users/me",
            get(get_client_user.layer(ratelimit!(3, 5)))
                .patch(edit_user.layer(ratelimit!(3, 15)))
                .delete(delete_user.layer(ratelimit!(2, 30))),
        )
        .route(
            "/users/me/notifications",
            post(add_registration_key.layer(ratelimit!(3, 5))),
        )
        .route("/users/:user_id", get(get_user.layer(ratelimit!(3, 5))))
        .route(
            "/relationships",
            get(get_relationships.layer(ratelimit!(3, 6))),
        )
        .route(
            "/relationships/friends",
            post(add_friend.layer(ratelimit!(3, 10))),
        )
        .route(
            "/relationships/friends/:target_id",
            put(accept_friend_request.layer(ratelimit!(5, 5))),
        )
        .route(
            "/relationships/blocks/:target_id",
            put(block_user.layer(ratelimit!(3, 10))),
        )
        .route(
            "/relationships/:target_id",
            delete(delete_relationship.layer(ratelimit!(5, 5))),
        )
        .route(
            "/bots",
            get(get_bots.layer(ratelimit!(3, 5))).post(create_bot.layer(ratelimit!(3, 120))),
        )
        .route(
            "/bots/:bot_id",
            get(get_bot.layer(ratelimit!(3, 5)))
                .patch(edit_bot.layer(ratelimit!(3, 15)))
                .delete(delete_bot.layer(ratelimit!(2, 30))),
        )
        .route(
            "/bots/:bot_id/tokens",
            post(regenerate_bot_token.layer(ratelimit!(3, 300))),
        )
}
