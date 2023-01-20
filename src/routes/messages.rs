#[cfg(feature = "ws")]
use crate::amqp::prelude::*;
use crate::{
    extract::{Auth, Json},
    ratelimit::ratelimit,
    routes::{NoContentResult, RouteResult},
    Response,
};
use axum::{
    extract::{Path, Query},
    handler::Handler,
    http::StatusCode,
    routing::get,
    Router,
};
use essence::db::{MemberDbExt, UserDbExt};
use essence::models::MemberOrUser;
use essence::{
    db::{get_pool, ChannelDbExt, GuildDbExt, MessageDbExt, RoleDbExt},
    http::message::{CreateMessagePayload, EditMessagePayload, MessageHistoryQuery},
    models::{Embed, Message, ModelType, Permissions},
    snowflake::generate_snowflake,
    Error, Maybe, NotFoundExt,
};

async fn maybe_assert_permissions(
    channel_id: u64,
    user_id: u64,
    permissions: Permissions,
) -> essence::Result<Option<u64>> {
    let db = get_pool();
    let guild_id = db
        .inspect_channel(channel_id)
        .await?
        .ok_or_not_found("channel", format!("Channel with ID {channel_id} not found"))?
        .0;

    if let Some(guild_id) = guild_id {
        db.assert_member_has_permissions(guild_id, user_id, Some(channel_id), permissions)
            .await?;
    }

    Ok(guild_id)
}

fn validate_message_content(content: &str) -> essence::Result<()> {
    if content.len() > 4000 {
        return Err(Error::InvalidField {
            field: "content".to_string(),
            message: "Message content can be at most 4 KB in size".to_string(),
        });
    }

    Ok(())
}

fn validate_message_embeds(embeds: &[Embed]) -> essence::Result<()> {
    if embeds.len() > 10 {
        return Err(Error::InvalidField {
            field: "embeds".to_string(),
            message: "Message can have at most 10 embeds".to_string(),
        });
    }

    for (i, embed) in embeds.iter().enumerate() {
        if let Some(ref title) = embed.title {
            if title.len() > 256 {
                return Err(Error::InvalidField {
                    field: format!("embeds[{i}].title"),
                    message: "Embed title can be at most 256 bytes in size".to_string(),
                });
            }
        }

        if let Some(ref description) = embed.description {
            if description.len() > 4096 {
                return Err(Error::InvalidField {
                    field: format!("embeds[{i}].description"),
                    message: "Embed description can be at most 4096 bytes in size".to_string(),
                });
            }
        }

        // TODO check other fields, maybe this would be done better through a derive on the struct
    }

    Ok(())
}

/// Get Message
///
/// Gets a message in the given channel with the given ID.
/// If in a guild, you must have the `VIEW_MESSAGE_HISTORY` permission to use this endpoint.
#[utoipa::path(
    get,
    path = "/channels/{channel_id}/messages/{message_id}",
    responses(
        (status = OK, description = "Message object", body = Message),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Channel or message not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn get_message(
    Auth(user_id, _): Auth,
    Path((channel_id, message_id)): Path<(u64, u64)>,
) -> RouteResult<Message> {
    maybe_assert_permissions(
        channel_id,
        user_id,
        Permissions::VIEW_CHANNEL | Permissions::VIEW_MESSAGE_HISTORY,
    )
    .await?;

    let message = get_pool()
        .fetch_message(channel_id, message_id)
        .await?
        .ok_or_not_found("message", format!("Message with ID {message_id} not found"))?;
    Ok(Response::ok(message))
}

/// Get Message History
///
/// Fetches multiple messages from the channel's message history in bulk.
/// If in a guild, you must have the `VIEW_MESSAGE_HISTORY` permission to use this endpoint.
#[utoipa::path(
    get,
    path = "/channels/{channel_id}/messages",
    params(MessageHistoryQuery),
    responses(
        (status = OK, description = "Array of message objects", body = Vec<Message>),
        (status = BAD_REQUEST, description = "Invalid query", body = Error),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Channel not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn get_message_history(
    Auth(user_id, _): Auth,
    Path(channel_id): Path<u64>,
    Query(query): Query<MessageHistoryQuery>,
) -> RouteResult<Vec<Message>> {
    if query.limit > 200 {
        return Err(Response::from(Error::InvalidField {
            field: "limit".to_string(),
            message: "Limit must be less than or equal to 200".to_string(),
        }));
    }
    maybe_assert_permissions(
        channel_id,
        user_id,
        Permissions::VIEW_CHANNEL | Permissions::VIEW_MESSAGE_HISTORY,
    )
    .await?;

    let messages = get_pool().fetch_message_history(channel_id, query).await?;
    Ok(Response::ok(messages))
}

/// Create Message
///
/// Sends a message in the given channel. You must have both the `VIEW_CHANNEL` and `SEND_MESSAGES`
/// permissions in that channel if this message is being sent in a guild.
#[utoipa::path(
    post,
    path = "/channels/{channel_id}/messages",
    request_body = CreateMessagePayload,
    responses(
        (status = CREATED, description = "Message object", body = Message),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Channel not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn create_message(
    Auth(user_id, _): Auth,
    Path(channel_id): Path<u64>,
    Json(payload): Json<CreateMessagePayload>,
) -> RouteResult<Message> {
    if let Some(ref content) = payload.content {
        validate_message_content(content)?;
    }
    validate_message_embeds(&payload.embeds)?;
    let guild_id = maybe_assert_permissions(
        channel_id,
        user_id,
        Permissions::VIEW_CHANNEL | Permissions::SEND_MESSAGES,
    )
    .await?;

    let mut db = get_pool();
    let message_id = generate_snowflake(ModelType::Message, 0); // TODO: node id
    let message = db
        .create_message(channel_id, message_id, user_id, payload)
        .await?;

    #[cfg(feature = "ws")]
    let message_clone = message.clone();

    #[cfg(feature = "ws")]
    tokio::spawn(async move {
        let mut message = message_clone;

        // TODO: this should be cached
        message.author = if let Some(guild_id) = guild_id {
            db.fetch_member_by_id(guild_id, user_id)
                .await?
                .map(MemberOrUser::Member)
        } else {
            db.fetch_user_by_id(user_id).await?.map(MemberOrUser::User)
        };

        amqp::publish_event(
            guild_id,
            user_id,
            OutboundMessage::MessageCreate {
                message: message.clone(),
            },
        )
        .await?;

        Ok::<_, Error>(())
    });

    Ok(Response::created(message))
}

/// Edit Message
///
/// Edits a message in the given channel. You must have the `VIEW_CHANNEL` and `SEND_MESSAGES`
/// permissions in that channel if the target message is in a guild.
#[utoipa::path(
    patch,
    path = "/channels/{channel_id}/messages/{message_id}",
    request_body = EditMessagePayload,
    responses(
        (status = OK, description = "Message object", body = Message),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Channel or message not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn edit_message(
    Auth(user_id, _): Auth,
    Path((channel_id, message_id)): Path<(u64, u64)>,
    Json(payload): Json<EditMessagePayload>,
) -> RouteResult<Message> {
    if let Maybe::Value(ref content) = payload.content {
        validate_message_content(content)?;
    }
    if let Maybe::Value(ref embeds) = payload.embeds {
        validate_message_embeds(embeds)?;
    }
    let guild_id = maybe_assert_permissions(
        channel_id,
        user_id,
        Permissions::VIEW_CHANNEL | Permissions::SEND_MESSAGES,
    )
    .await?;

    let (before, after) = get_pool()
        .edit_message(channel_id, message_id, user_id, payload)
        .await?;

    #[cfg(feature = "ws")]
    amqp::publish_event(
        guild_id,
        user_id,
        OutboundMessage::MessageUpdate {
            before,
            after: after.clone(),
        },
    )
    .await?;

    Ok(Response::ok(after))
}

/// Delete Message
///
/// Deletes a message in the given channel. In a guild, you must have the `VIEW_CHANNEL` permission
/// to delete your own messages, with addition to the `MANAGE_MESSAGES` permission if you want to
/// delete messages sent by other members. If you have this permission, you are only able to delete
/// any messages sent by members who have either left the guild or are ranked lower than you in the
/// role hierarchy.
#[utoipa::path(
    delete,
    path = "/channels/{channel_id}/messages/{message_id}",
    responses(
        (status = NO_CONTENT, description = "Message deleted"),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Channel or message not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn delete_message(
    Auth(user_id, _): Auth,
    Path((channel_id, message_id)): Path<(u64, u64)>,
) -> NoContentResult {
    let db = get_pool();
    let guild_id = db
        .inspect_channel(channel_id)
        .await?
        .ok_or_not_found("channel", format!("Channel with ID {channel_id} not found"))?
        .0;

    if let Some(guild_id) = guild_id {
        let perms = db
            .fetch_member_permissions(guild_id, user_id, Some(channel_id))
            .await?;

        db.assert_member_has_permissions_with(guild_id, perms, Permissions::VIEW_CHANNEL)
            .await?;
        if let Some(author_id) = db
            .inspect_message(message_id)
            .await?
            .ok_or_not_found("message", format!("Message with ID {message_id} not found"))?
        {
            if author_id != user_id {
                db.assert_member_has_permissions_with(
                    guild_id,
                    perms,
                    Permissions::MANAGE_MESSAGES,
                )
                .await?;
            }

            db.assert_top_role_higher_than_target(guild_id, user_id, author_id)
                .await?;
        }
    }

    get_pool().delete_message(channel_id, message_id).await?;

    #[cfg(feature = "ws")]
    amqp::publish_event(
        guild_id,
        user_id,
        OutboundMessage::MessageDelete { message_id },
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[must_use]
pub fn router() -> Router {
    Router::new()
        .route(
            "/channels/:channel_id/messages",
            get(get_message_history.layer(ratelimit!(3, 7)))
                .post(create_message.layer(ratelimit!(5, 5))),
        )
        .route(
            "/channels/:channel_id/messages/:message_id",
            get(get_message.layer(ratelimit!(5, 5)))
                .patch(edit_message.layer(ratelimit!(5, 5)))
                .delete(delete_message.layer(ratelimit!(5, 5))),
        )
}
