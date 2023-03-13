#[cfg(feature = "ws")]
use crate::amqp::prelude::*;
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
    routing::{delete, get, post, put},
    Router,
};
use essence::{
    auth::generate_token,
    db::{get_pool, AuthDbExt, UserDbExt},
    http::{
        user::SendFriendRequestPayload,
        user::{CreateUserPayload, CreateUserResponse, DeleteUserPayload, EditUserPayload},
    },
    models::{ClientUser, ModelType, Relationship, RelationshipType, User, UserFlags},
    snowflake::generate_snowflake,
    utoipa, Error, Maybe, NotFoundExt,
};

fn validate_username(username: impl AsRef<str>) -> Result<(), Error> {
    let username = username.as_ref();
    let length = username.chars().count();

    if length < 2 {
        return Err(Error::InvalidField {
            field: "username".to_string(),
            message: "Username must be at least 2 characters long".to_string(),
        });
    }

    if length > 32 {
        return Err(Error::InvalidField {
            field: "username".to_string(),
            message: "Username cannot be longer than 32 characters".to_string(),
        });
    }

    for forbidden in ['\n', '\r', '#', '@'] {
        if username.contains(forbidden) {
            return Err(Error::InvalidField {
                field: "username".to_string(),
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
            what: "email".to_string(),
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

    let (before, after) = get_pool().edit_user(id, payload).await?;

    #[cfg(feature = "ws")]
    amqp::publish_user_event(
        id,
        OutboundMessage::UserUpdate {
            before,
            after: after.clone(),
        },
    )
    .await?;

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
            message: String::from(
                "This user is a bot account, but this endpoint can only delete user \
                accounts. To delete bot accounts, see the DELETE /bots/:id endpoint.",
            ),
        }));
    }

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
    if flags.contains(UserFlags::BOT) {
        return Err(Response::from(Error::UnsupportedAuthMethod {
            message: String::from(
                "This user is a bot account, but this endpoint can only be used by user accounts.",
            ),
        }));
    }

    let db = get_pool();
    let target = db
        .fetch_user_by_tag(&payload.username, payload.discriminator)
        .await?
        .ok_or_not_found(
            "user",
            format!(
                "User with tag {}#{} does not exist",
                payload.username, payload.discriminator
            ),
        )?;
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
}
