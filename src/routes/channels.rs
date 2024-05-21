#[cfg(feature = "ws")]
use crate::amqp::prelude::*;
use crate::{
    extract::{Auth, Json},
    ratelimit::ratelimit,
    routes::{NoContentResult, RouteResult},
    Response,
};
use axum::{
    extract::Path,
    handler::Handler,
    http::StatusCode,
    routing::{get, put},
    Router,
};
use essence::{
    cache::ChannelInspection,
    db::{get_pool, ChannelDbExt, GuildDbExt, MessageDbExt, UserDbExt},
    error::UserInteractionType,
    http::channel::{
        CreateDmChannelPayload, CreateGuildChannelInfo, CreateGuildChannelPayload,
        EditChannelPayload,
    },
    models::{Channel, ChannelType, DmChannel, GuildChannel, ModelType, Permissions, UserFlags},
    snowflake::generate_snowflake,
    utoipa, Error, Maybe, NotFoundExt,
};
use futures_util::future::TryJoinAll;

#[inline]
fn validate_channel_name(name: &str) -> essence::Result<()> {
    if !(1..=32).contains(&name.chars().count()) {
        return Err(Error::InvalidField {
            field: "name".to_string(),
            message: "Channel name must be between 1 and 32 characters long".to_string(),
        });
    }

    if name.chars().any(|c| c == '\n' || c == '\r') {
        return Err(Error::InvalidField {
            field: "name".to_string(),
            message: "Channel name cannot contain newlines".to_string(),
        });
    }

    Ok(())
}

#[inline]
fn validate_channel_topic(topic: &str) -> essence::Result<()> {
    if topic.len() > 1024 {
        return Err(Error::InvalidField {
            field: "topic".to_string(),
            message: "Channel topic must be at most 1 KB in size".to_string(),
        });
    }

    Ok(())
}

/// Get DM Channels
///
/// Fetches all DM and group DM channels that the current user is a part of.
#[utoipa::path(
    get,
    path = "/users/me/channels",
    responses(
        (status = OK, description = "DM channels were successfully fetched", body = Vec<DmChannel>),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn get_dm_channels(Auth(user_id, _): Auth) -> RouteResult<Vec<DmChannel>> {
    Ok(Response::ok(
        get_pool().fetch_all_dm_channels_for_user(user_id).await?,
    ))
}

/// Open DM Channel / Create Group DM Channel
///
/// Opens a DM channel with the given user, or creates a group DM channel with the given users.
///
/// # For standard DM channels
/// You may only open DM channels with users that are your friends, share a mutual guild, and
/// do not have you blocked. If a DM channel already exists, the existing channel is returned.
///
/// # For group DM channels
/// You may only create group DM channels with users that are your friends and do not have you
/// blocked.
#[utoipa::path(
    post,
    path = "/users/me/channels",
    request_body = CreateDmChannelPayload,
    responses(
        (status = CREATED, description = "Channel was successfully created", body = DmChannel),
        (status = BAD_REQUEST, description = "Invalid payload", body = Error),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = NOT_FOUND, description = "User not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn create_dm_channel(
    Auth(user_id, _): Auth,
    Json(mut payload): Json<CreateDmChannelPayload>,
) -> RouteResult<DmChannel> {
    let mut db = get_pool();
    let recipients = match payload {
        CreateDmChannelPayload::Dm { recipient_id } => {
            db.assert_user_can_interact_with(user_id, recipient_id, UserInteractionType::Dm)
                .await?;
            vec![user_id, recipient_id]
        }
        CreateDmChannelPayload::Group {
            ref name,
            ref mut recipient_ids,
        } => {
            validate_channel_name(name)?;
            if recipient_ids.len() >= 20 {
                return Err(Response::from(Error::InvalidField {
                    field: "recipient_ids".to_string(),
                    message: "Group DMs cannot have more than 20 recipients".to_string(),
                }));
            }

            // TODO: this can be done in bulk
            for &recipient_id in recipient_ids.iter() {
                if recipient_id == user_id {
                    continue;
                }
                db.assert_user_can_interact_with(
                    user_id,
                    recipient_id,
                    UserInteractionType::GroupDm,
                )
                .await?;
            }

            if !recipient_ids.contains(&user_id) {
                recipient_ids.push(user_id);
            }
            recipient_ids.clone()
        }
    };

    let channel_id = generate_snowflake(ModelType::Channel, 0); // TODO: node ID
    let channel = db.create_dm_channel(user_id, channel_id, payload).await?;

    #[cfg(feature = "ws")]
    recipients
        .into_iter()
        .map(|recipient| {
            amqp::publish_user_event(
                recipient,
                OutboundMessage::ChannelCreate {
                    channel: Channel::Dm(channel.clone()),
                    nonce: None,
                },
            )
        })
        .collect::<TryJoinAll<_>>()
        .await?;

    Ok(Response::created(channel))
}

/// Get Guild Channels
///
/// Returns a list of all channels in the guild.
#[utoipa::path(
    get,
    path = "/guilds/{guild_id}/channels",
    responses(
        (status = OK, description = "Array of guild channels", body = [GuildChannel]),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = NOT_FOUND, description = "Guild not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn get_guild_channels(
    Auth(user_id, _): Auth,
    Path(guild_id): Path<u64>,
) -> RouteResult<Vec<GuildChannel>> {
    let db = get_pool();
    db.assert_invoker_in_guild(guild_id, user_id).await?;

    let channels = db.fetch_all_channels_in_guild(guild_id).await?;
    Ok(Response::ok(channels))
}

/// Create Guild Channel
///
/// Creates a new channel in the guild with the given payload. You must have the `MANAGE_CHANNELS`
/// permission to use this endpoint.
#[utoipa::path(
    post,
    path = "/guilds/{guild_id}/channels",
    request_body = CreateGuildChannelPayload,
    responses(
        (status = CREATED, description = "Channel was successfully created", body = Channel),
        (status = BAD_REQUEST, description = "Invalid payload", body = Error),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Guild not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn create_guild_channel(
    Auth(user_id, _): Auth,
    Path(guild_id): Path<u64>,
    Json(payload): Json<CreateGuildChannelPayload>,
) -> RouteResult<GuildChannel> {
    validate_channel_name(&payload.name)?;
    if let CreateGuildChannelInfo::Text {
        topic: Some(topic), ..
    }
    | CreateGuildChannelInfo::Announcement {
        topic: Some(topic), ..
    } = &payload.info
    {
        validate_channel_topic(topic)?;
    }

    let mut db = get_pool();

    if let Some(parent_id) = payload.parent_id {
        db.assert_channel_is_type(guild_id, parent_id, ChannelType::Category)
            .await?;
    }
    db.assert_member_has_permissions(
        guild_id,
        user_id,
        payload.parent_id,
        Permissions::MANAGE_CHANNELS,
    )
    .await?;

    #[cfg(feature = "ws")]
    let nonce = payload.nonce.take();

    let channel_id = generate_snowflake(ModelType::Channel, 0); // TODO: node ID
    let channel = db
        .create_guild_channel(guild_id, channel_id, payload)
        .await?;

    #[cfg(feature = "ws")]
    amqp::publish_bulk_event(
        guild_id,
        OutboundMessage::ChannelCreate {
            channel: Channel::Guild(channel.clone()),
            nonce,
        },
    )
    .await?;

    Ok(Response::created(channel))
}

/// Get Channel
///
/// Gets information about a channel given its ID. This includes guild channels, DM channels, and
/// group DM channels.
#[utoipa::path(
    get,
    path = "/channels/{channel_id}",
    responses(
        (status = OK, description = "Channel information", body = Channel),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = NOT_FOUND, description = "Channel not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn get_channel(
    Auth(user_id, _): Auth,
    Path(channel_id): Path<u64>,
) -> RouteResult<Channel> {
    let db = get_pool();
    if let Some(guild_id) = db
        .inspect_channel(channel_id)
        .await?
        .ok_or_not_found("channel", format!("Channel with ID {channel_id} not found"))?
        .guild_id
    {
        db.assert_invoker_in_guild(guild_id, user_id).await?;
    }

    let channel = db.fetch_channel(channel_id).await?.unwrap();
    Ok(Response::ok(channel))
}

/// Edit Channel
///
/// Edits a channel with the given payload.
/// For guild channels, you must have the `MODIFY_CHANNELS` permission to use this endpoint.
#[utoipa::path(
    patch,
    path = "/channels/{channel_id}",
    request_body = EditChannelPayload,
    responses(
        (status = OK, description = "Channel with updated details", body = Channel),
        (status = BAD_REQUEST, description = "Invalid payload", body = Error),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Channel not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn edit_channel(
    Auth(user_id, _): Auth,
    Path(channel_id): Path<u64>,
    Json(payload): Json<EditChannelPayload>,
) -> RouteResult<Channel> {
    if let Some(ref name) = payload.name {
        validate_channel_name(name)?;
    }
    if let Maybe::Value(ref topic) = payload.topic {
        validate_channel_topic(topic)?;
    }

    let mut db = get_pool();
    let ChannelInspection {
        guild_id,
        channel_type: kind,
        ..
    } = db
        .inspect_channel(channel_id)
        .await?
        .ok_or_not_found("channel", format!("Channel with ID {channel_id} not found"))?;

    if kind.is_guild() {
        db.assert_member_has_permissions(
            guild_id.unwrap(),
            user_id,
            Some(channel_id),
            Permissions::MODIFY_CHANNELS,
        )
        .await?;
    } else {
        db.assert_user_is_recipient(channel_id, user_id).await?;
    }

    let (before, channel) = db.edit_channel(channel_id, payload).await?;

    #[cfg(feature = "ws")]
    amqp::publish_bulk_event(
        guild_id.unwrap_or(channel_id),
        OutboundMessage::ChannelUpdate {
            before,
            after: channel.clone(),
        },
    )
    .await?;

    Ok(Response::ok(channel))
}

/// Delete Channel
///
/// Deletes a channel. For guild channels, you must have the `MANAGE_CHANNELS` permission to use
/// this endpoint. For standard DM channels, you must be a recipient of the DM. For group DM
/// channels, you must be the owner of the group DM.
#[utoipa::path(
    delete,
    path = "/channels/{channel_id}",
    responses(
        (status = NO_CONTENT, description = "Channel deleted"),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Channel not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn delete_channel(
    Auth(user_id, _): Auth,
    Path(channel_id): Path<u64>,
) -> NoContentResult {
    let mut db = get_pool();
    let ChannelInspection {
        guild_id,
        channel_type: kind,
        ..
    } = db
        .inspect_channel(channel_id)
        .await?
        .ok_or_not_found("channel", format!("Channel with ID {channel_id} not found"))?;

    match kind {
        _ if kind.is_guild() => {
            db.assert_member_has_permissions(
                guild_id.unwrap(),
                user_id,
                Some(channel_id),
                Permissions::MANAGE_CHANNELS,
            )
            .await?;
        }
        ChannelType::Dm => db.assert_user_is_recipient(channel_id, user_id).await?,
        ChannelType::Group => db.assert_user_is_group_owner(channel_id, user_id).await?,
        _ => unimplemented!(),
    }

    db.delete_channel(channel_id).await?;

    #[cfg(feature = "ws")]
    amqp::publish_bulk_event(
        guild_id.unwrap_or(channel_id),
        OutboundMessage::ChannelDelete {
            channel_id,
            guild_id,
        },
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn send_typing(
    user_id: u64,
    channel_id: u64,
    #[cfg(feature = "ws")] outbound: OutboundMessage,
) -> NoContentResult {
    let db = get_pool();
    let ChannelInspection {
        guild_id,
        channel_type: kind,
        ..
    } = db
        .inspect_channel(channel_id)
        .await?
        .ok_or_not_found("channel", format!("Channel with ID {channel_id} not found"))?;

    if kind.is_guild() {
        db.assert_member_has_permissions(
            guild_id.unwrap(),
            user_id,
            Some(channel_id),
            Permissions::SEND_MESSAGES,
        )
        .await?;
    } else {
        db.assert_user_is_recipient(channel_id, user_id).await?;
    }

    #[cfg(feature = "ws")]
    amqp::publish_bulk_event(guild_id.unwrap_or(channel_id), outbound).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Start Typing
///
/// Triggers a typing indicator for the specified channel. The typing indicator should last until
/// one of the following events occur:
///
/// * 10 seconds have passed since the typing indicator was triggered
/// * The user sends a message in the channel
/// * A `TypingStop` event is received for the channel
#[utoipa::path(
    put,
    path = "/channels/{channel_id}/typing",
    responses(
        (status = NO_CONTENT, description = "Typing indicator sent"),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Channel not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn start_typing(Auth(user_id, _): Auth, Path(channel_id): Path<u64>) -> NoContentResult {
    send_typing(
        user_id,
        channel_id,
        #[cfg(feature = "ws")]
        OutboundMessage::TypingStart {
            channel_id,
            user_id,
        },
    )
    .await
}

/// Stop Typing
///
/// Stops a typing indicator forcefully for the specified channel. Typing indicators should be
/// automatically stopped when a message is sent or when 10 seconds have passed since the typing
/// indicator was triggered.
#[utoipa::path(
    delete,
    path = "/channels/{channel_id}/typing",
    responses(
        (status = NO_CONTENT, description = "Typing indicator sent"),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Channel not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn stop_typing(Auth(user_id, _): Auth, Path(channel_id): Path<u64>) -> NoContentResult {
    send_typing(
        user_id,
        channel_id,
        #[cfg(feature = "ws")]
        OutboundMessage::TypingStop {
            channel_id,
            user_id,
        },
    )
    .await
}

/// Acknowledge Channel
///
/// Acknowledges a channel up to the given message ID, marking the message and all messages before
/// it as read.
#[utoipa::path(
    put,
    path = "/channels/{channel_id}/ack/{message_id}",
    responses(
        (status = NO_CONTENT, description = "Channel acknowledged"),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Channel not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn acknowledge_channel(
    Auth(user_id, flags): Auth,
    Path((channel_id, message_id)): Path<(u64, u64)>,
) -> NoContentResult {
    if flags.contains(UserFlags::BOT) {
        // we silently fail for bots for now, this could change to a hard error later
        return Ok(StatusCode::NO_CONTENT);
    }

    let mut db = get_pool();
    let ChannelInspection { guild_id, .. } = db
        .inspect_channel(channel_id)
        .await?
        .ok_or_not_found("channel", format!("Channel with ID {channel_id} not found"))?;

    if let Some(guild_id) = guild_id {
        db.assert_member_has_permissions(
            guild_id,
            user_id,
            Some(channel_id),
            Permissions::VIEW_CHANNEL | Permissions::VIEW_MESSAGE_HISTORY,
        )
        .await?;
    } else {
        db.assert_user_is_recipient(channel_id, user_id).await?;
    }

    // assert that this message actually exists
    db.fetch_message(channel_id, message_id)
        .await?
        .ok_or_not_found("message", format!("Message with ID {message_id} not found"))?;

    db.ack(user_id, channel_id, message_id).await?;

    #[cfg(feature = "ws")]
    amqp::publish_user_event(
        user_id,
        OutboundMessage::ChannelAck {
            channel_id,
            last_message_id: message_id,
        },
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub fn router() -> Router {
    Router::new()
        .route(
            "/guilds/:guild_id/channels",
            get(get_guild_channels.layer(ratelimit!(5, 5)))
                .post(create_guild_channel.layer(ratelimit!(5, 5))),
        )
        .route(
            "/users/me/channels",
            get(get_dm_channels.layer(ratelimit!(5, 5)))
                .post(create_dm_channel.layer(ratelimit!(5, 5))),
        )
        .route(
            "/channels/:channel_id",
            get(get_channel.layer(ratelimit!(5, 5)))
                .patch(edit_channel.layer(ratelimit!(5, 5)))
                .delete(delete_channel.layer(ratelimit!(5, 6))),
        )
        .route(
            "/channels/:channel_id/typing",
            put(start_typing.layer(ratelimit!(10, 5))).delete(stop_typing.layer(ratelimit!(10, 5))),
        )
        .route(
            "/channels/:channel_id/ack/:message_id",
            put(acknowledge_channel.layer(ratelimit!(10, 5))),
        )
}
