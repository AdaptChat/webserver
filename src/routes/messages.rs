#[cfg(feature = "ws")]
use crate::amqp::prelude::*;
use crate::{
    cdn,
    extract::{Auth, CreateMessageData, Json, MultipartIntoErrExt},
    notification::{self, Notification},
    ratelimit::ratelimit,
    routes::{NoContentResult, RouteResult},
    unicode::get_emoji_lookup,
    Response,
};
use axum::{
    extract::{Path, Query},
    handler::Handler,
    http::StatusCode,
    routing::{delete, get, put},
    Router,
};
use essence::{
    db::{
        get_pool, ChannelDbExt, EmojiDbExt, GuildDbExt, MemberDbExt, MessageDbExt, RoleDbExt,
        UserDbExt,
    },
    http::message::{CreateMessagePayload, EditMessagePayload, MessageHistoryQuery},
    models::{
        Attachment, Channel, DmChannelInfo, Embed, MemberOrUser, Message, MessageFlags,
        MessageInfo, ModelType, PartialEmoji, Permissions, Reaction,
    },
    snowflake::generate_snowflake,
    utoipa, Error, Maybe, NotFoundExt,
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
        .guild_id;

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
#[allow(clippy::too_many_lines)]
pub async fn create_message(
    Auth(user_id, _): Auth,
    Path(channel_id): Path<u64>,
    CreateMessageData(mut payload, multipart): CreateMessageData<CreateMessagePayload>,
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

    if payload.references.len() > 10 {
        return Err(Error::InvalidField {
            field: "references".to_string(),
            message: "Message can have at most 10 references".to_string(),
        }
        .into());
    }

    let attachment = if let Some(mut multipart) = multipart {
        let field = multipart.next_field().await.multipart_into_err()?;

        if let Some(field) = field {
            let filename = field
                .file_name()
                .ok_or_else(|| Error::InvalidField {
                    field: field.name().unwrap_or("unknown").to_string(),
                    message: "missing file name for field".to_string(),
                })?
                .to_string();

            let buffer = field.bytes().await.multipart_into_err()?;
            let size = buffer.len();

            let id = cdn::upload_attachment(filename.clone(), buffer.to_vec()).await?;

            Some(Attachment {
                id,
                filename,
                alt: None,
                size: size as u64,
            })
        } else {
            return Err(Error::MissingField {
                field: "file".to_string(),
                message: "missing attachment field".to_string(),
            }
            .into());
        }
    } else {
        None
    };

    let db = get_pool();
    let nonce = payload.nonce.take();

    let mut transaction = db.begin().await?;
    let message_id = generate_snowflake(ModelType::Message, 0); // TODO: node id
    let mut message = transaction
        .create_message(channel_id, message_id, user_id, payload)
        .await?;

    if let Some(attachment) = attachment {
        transaction
            .create_attachment(message_id, attachment.clone())
            .await?;
        message.attachments.push(attachment);
    }
    transaction.commit().await?;

    #[cfg(feature = "ws")]
    let message_clone = message.clone();
    let notification_message_clone = message.clone();

    tokio::spawn(async move {
        let channel = db
            .fetch_channel(channel_id)
            .await?
            .expect("channel not found");
        let user = db.fetch_user_by_id(user_id).await?.expect("user not found");

        let mut notif = match channel {
            Channel::Guild(c) => {
                let guild = db
                    .fetch_partial_guild(c.guild_id)
                    .await?
                    .expect("guild not found");

                Notification {
                    title: Some(format!("{} (#{}, {})", user.username, c.name, guild.name)),
                    link_to: Some(format!(
                        "https://app.adapt.chat/guilds/{}/{}",
                        guild.id, c.id
                    )),
                    ..Default::default()
                }
            }
            Channel::Dm(c) => match c.info {
                DmChannelInfo::Dm { .. } => Notification {
                    title: Some(user.username.clone()),
                    link_to: Some(format!("https://app.adapt.chat/dms/{}", c.id)),
                    ..Default::default()
                },
                DmChannelInfo::Group { name, icon, .. } => Notification {
                    title: Some(format!("{} ({name})", user.username)),
                    icon,
                    link_to: Some(format!("https://app.adapt.chat/dms/{}", c.id)),
                    ..Default::default()
                },
            },
        };

        notif.body = notification_message_clone
            .content
            .or_else(|| Some("New Message".to_string()));

        notif.icon = Some(notif.icon.or(user.avatar).unwrap_or_else(|| {
            format!("https://convey.adapt.chat/avatars/{user_id}/default.png?theme=dark&width=96")
        }));

        notification::push_to_users(db.fetch_channel_recipients(channel_id).await?, notif).await?;

        Ok::<_, Error>(())
    });

    #[cfg(feature = "ws")]
    tokio::spawn(async move {
        // auto-ack the message
        get_pool().ack(user_id, channel_id, message_id).await?;

        let mut message = message_clone;
        // TODO: this should be cached
        message.author = if let Some(guild_id) = guild_id {
            db.fetch_member_by_id(guild_id, user_id)
                .await?
                .map(MemberOrUser::Member)
        } else {
            db.fetch_user_by_id(user_id).await?.map(MemberOrUser::User)
        };

        amqp::publish_bulk_event(
            guild_id.unwrap_or(channel_id),
            OutboundMessage::MessageCreate {
                message: message.clone(),
                nonce,
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
        .edit_message(channel_id, message_id, Some(user_id), payload)
        .await?;

    #[cfg(feature = "ws")]
    amqp::publish_bulk_event(
        guild_id.unwrap_or(channel_id),
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
        .guild_id;

    if let Some(guild_id) = guild_id {
        let perms = db
            .fetch_member_permissions(guild_id, user_id, Some(channel_id))
            .await?;

        db.assert_member_has_permissions_with(guild_id, perms, Permissions::VIEW_CHANNEL)?;
        // TODO: #[feature(let_chains)], when stabilized, will make this much cleaner
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
                )?;

                db.assert_top_role_higher_than_target(guild_id, user_id, author_id)
                    .await?;
            }
        }
    }

    get_pool().delete_message(channel_id, message_id).await?;

    #[cfg(feature = "ws")]
    amqp::publish_bulk_event(
        guild_id.unwrap_or(channel_id),
        OutboundMessage::MessageDelete {
            channel_id,
            message_id,
        },
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn modify_message_flags(
    channel_id: u64,
    message_id: u64,
    user_id: u64,
    permissions: Permissions,
    enable: MessageFlags,
    disable: MessageFlags,
    system_message: Option<MessageInfo>,
) -> essence::Result<()> {
    let db = get_pool();
    let guild_id = db
        .inspect_channel(channel_id)
        .await?
        .ok_or_not_found("channel", format!("Channel with ID {channel_id} not found"))?
        .guild_id;

    if let Some(guild_id) = guild_id {
        db.assert_member_has_permissions_with(
            guild_id,
            db.fetch_member_permissions(guild_id, user_id, Some(channel_id))
                .await?,
            permissions,
        )?;
    }

    let mut transaction = db.begin().await?;
    transaction
        .edit_message_flags(channel_id, message_id, enable, disable)
        .await?;

    if let Some(system_message) = system_message {
        let system_message = transaction
            .send_system_message(
                channel_id,
                generate_snowflake(ModelType::Message, 0), // TODO: node id
                system_message,
            )
            .await?;

        #[cfg(feature = "ws")]
        amqp::publish_bulk_event(
            guild_id.unwrap_or(channel_id),
            OutboundMessage::MessageCreate {
                message: system_message,
                nonce: None,
            },
        )
        .await?;
    }

    transaction.commit().await?;
    Ok(())
}

/// Pin Message
///
/// Pins a message to its given channel. You must have the `PIN_MESSAGES` permission in the
/// channel, or be in a DM-type channel. This endpoint is idempotent.
#[utoipa::path(
    put,
    path = "/channels/{channel_id}/messages/{message_id}/pin",
    responses(
        (status = NO_CONTENT, description = "Message pinned"),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Channel or message not found", body = Error),
    ),
    security(("token" = [])),
)]
async fn pin_message(
    Auth(user_id, _): Auth,
    Path((channel_id, message_id)): Path<(u64, u64)>,
) -> NoContentResult {
    modify_message_flags(
        channel_id,
        message_id,
        user_id,
        Permissions::PIN_MESSAGES,
        MessageFlags::PINNED,
        MessageFlags::empty(),
        Some(MessageInfo::Pin {
            pinned_message_id: message_id,
            pinned_by: user_id,
        }),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Unpin Message
///
/// Unpins a message from its given channel. You must have the `PIN_MESSAGES` permission in the
/// channel, or be in a DM-type channel. This endpoint is idempotent, so it may still return
/// success even if the message wasn't originally pinned.
#[utoipa::path(
    delete,
    path = "/channels/{channel_id}/messages/{message_id}/pin",
    responses(
        (status = NO_CONTENT, description = "Message unpinned"),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Channel or message not found", body = Error),
    ),
    security(("token" = [])),
)]
async fn unpin_message(
    Auth(user_id, _): Auth,
    Path((channel_id, message_id)): Path<(u64, u64)>,
) -> NoContentResult {
    modify_message_flags(
        channel_id,
        message_id,
        user_id,
        Permissions::PIN_MESSAGES,
        MessageFlags::empty(),
        MessageFlags::PINNED,
        None,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get Message Reactions
///
/// Fetches all reactions for a message. The reaction objects returned in the response will include
/// the `created_at` field. If in a guild, this requires the `VIEW_CHANNEL` permission.
#[utoipa::path(
    get,
    path = "/channels/{channel_id}/messages/{message_id}/reactions",
    responses(
        (status = OK, description = "Array of reaction objects", body = Vec<Reaction>),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Channel or message not found", body = Error),
    ),
    security(("token" = [])),
)]
async fn get_message_reactions(
    Auth(user_id, _): Auth,
    Path((channel_id, message_id)): Path<(u64, u64)>,
) -> RouteResult<Vec<Reaction>> {
    maybe_assert_permissions(channel_id, user_id, Permissions::VIEW_CHANNEL).await?;

    let reactions = get_pool().fetch_reactions(message_id).await?;
    Ok(Response::ok(reactions))
}

async fn resolve_emoji(user_id: u64, emoji: String) -> essence::Result<PartialEmoji> {
    if let Ok(id) = emoji.parse::<u64>() {
        let db = get_pool();
        let emoji = db
            .fetch_emoji(id)
            .await?
            .ok_or_not_found("emoji", "emoji not found")?;
        db.assert_member_in_guild(user_id, emoji.guild_id).await?;
        Ok(emoji.into())
    } else if get_emoji_lookup().contains_key(&emoji) {
        Ok(PartialEmoji {
            id: None,
            name: emoji,
        })
    } else {
        Err(Error::NotFound {
            entity: "emoji".to_string(),
            message: "emoji is malformed or this unicode emoji is not supported".to_string(),
        })
    }
}

/// Add Reaction
///
/// Adds a reaction to a message. If in a guild and the reaction does not exist, this will require
/// the `ADD_REACTIONS` permission.
///
/// This endpoint is idempotent: if you have already reacted to this message with this emoji,
/// nothing will happen.
///
/// The emoji path parameter should be either a literal unicode emoji or the ID of a custom emoji.
#[utoipa::path(
    put,
    path = "/channels/{channel_id}/messages/{message_id}/reactions/{emoji}/me",
    responses(
        (status = NO_CONTENT, description = "Reaction added"),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Channel, message, or emoji not found", body = Error),
    ),
    security(("token" = [])),
)]
async fn add_reaction(
    Auth(user_id, _): Auth,
    Path((channel_id, message_id, emoji)): Path<(u64, u64, String)>,
) -> NoContentResult {
    let emoji = resolve_emoji(user_id, emoji).await?;

    let mut db = get_pool();
    // If reaction already exists, fetch guild ID normally, otherwise fetch guild ID via asserting
    // permissions
    let guild_id = if db.reaction_exists(message_id, None, &emoji).await? {
        db.inspect_channel(channel_id)
            .await?
            .ok_or_not_found("channel", "channel not found")?
            .guild_id
    } else {
        maybe_assert_permissions(channel_id, user_id, Permissions::ADD_REACTIONS).await?
    };

    let added = db.add_reaction(message_id, user_id, &emoji).await?;
    #[cfg(feature = "ws")]
    if added {
        amqp::publish_bulk_event(
            guild_id.unwrap_or(channel_id),
            OutboundMessage::ReactionAdd {
                channel_id,
                message_id,
                user_id,
                emoji,
            },
        )
        .await?;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Remove Own Reaction
///
/// Removes your own reaction from a message. This method is idempotent: if you try to remove a
/// reaction that you haven't added, nothing will happen.
///
/// The emoji path parameter should be either a literal unicode emoji or the ID of a custom emoji.
#[utoipa::path(
    delete,
    path = "/channels/{channel_id}/messages/{message_id}/reactions/{emoji}/me",
    responses(
        (status = NO_CONTENT, description = "Reaction removed"),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = NOT_FOUND, description = "Channel, message, or emoji not found", body = Error),
    ),
    security(("token" = [])),
)]
async fn remove_reaction(
    Auth(user_id, _): Auth,
    Path((channel_id, message_id, emoji)): Path<(u64, u64, String)>,
) -> NoContentResult {
    let emoji = resolve_emoji(user_id, emoji).await?;

    let mut db = get_pool();
    let removed = db.remove_reaction(message_id, user_id, &emoji).await?;

    #[cfg(feature = "ws")]
    if removed {
        let guild_id = db
            .inspect_channel(channel_id)
            .await?
            .ok_or_not_found("channel", "channel not found")?
            .guild_id;

        amqp::publish_bulk_event(
            guild_id.unwrap_or(channel_id),
            OutboundMessage::ReactionRemove {
                channel_id,
                message_id,
                user_id,
                moderator_id: None,
                emoji,
            },
        )
        .await?;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Remove User Reaction
///
/// Forcibly removes a reaction by another user from a message. This requires the `MANAGE_MESSAGES`
/// permission in the guild.
///
/// This method is idempotent: if you try to remove a reaction that doesn't exist, nothing will
/// happen.
///
/// The emoji path parameter should be either a literal unicode emoji or the ID of a custom emoji.
#[utoipa::path(
    delete,
    path = "/channels/{channel_id}/messages/{message_id}/reactions/{emoji}/{user_id}",
    responses(
        (status = NO_CONTENT, description = "Reaction removed"),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Channel, message, or emoji not found", body = Error),
    ),
    security(("token" = [])),
)]
async fn remove_user_reaction(
    Auth(user_id, _): Auth,
    Path((channel_id, message_id, emoji, target_user_id)): Path<(u64, u64, String, u64)>,
) -> NoContentResult {
    let emoji = resolve_emoji(user_id, emoji).await?;

    let mut db = get_pool();
    let guild_id = maybe_assert_permissions(channel_id, user_id, Permissions::MANAGE_MESSAGES)
        .await?
        .ok_or_else(|| Error::GuildOnly {
            message: String::from("Channel must be in a guild"),
        })?;

    let removed = db
        .remove_reaction(message_id, target_user_id, &emoji)
        .await?;

    #[cfg(feature = "ws")]
    if removed {
        amqp::publish_bulk_event(
            guild_id,
            OutboundMessage::ReactionRemove {
                channel_id,
                message_id,
                user_id: target_user_id,
                moderator_id: Some(user_id),
                emoji,
            },
        )
        .await?;
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn bulk_remove_reactions(
    user_id: u64,
    channel_id: u64,
    message_id: u64,
    emoji: Option<PartialEmoji>,
) -> essence::Result<()> {
    let mut db = get_pool();
    let guild_id = maybe_assert_permissions(channel_id, user_id, Permissions::MANAGE_MESSAGES)
        .await?
        .ok_or_else(|| Error::GuildOnly {
            message: String::from("Channel must be in a guild"),
        })?;

    db.bulk_remove_reactions(message_id, emoji.as_ref()).await?;

    #[cfg(feature = "ws")]
    amqp::publish_bulk_event(
        guild_id,
        OutboundMessage::ReactionRemoveBulk {
            channel_id,
            message_id,
            moderator_id: user_id,
            emoji,
        },
    )
    .await?;

    Ok(())
}

/// Remove All Reactions for Emoji
///
/// Removes all reactions for a given emoji from a message. This requires the `MANAGE_MESSAGES`
/// permission in the guild.
///
/// The emoji path parameter should be either a literal unicode emoji or the ID of a custom emoji.
#[utoipa::path(
    delete,
    path = "/channels/{channel_id}/messages/{message_id}/reactions/{emoji}",
    responses(
        (status = NO_CONTENT, description = "Reactions removed"),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Channel, message, or emoji not found", body = Error),
    ),
    security(("token" = [])),
)]
async fn remove_all_reactions_for_emoji(
    Auth(user_id, _): Auth,
    Path((channel_id, message_id, emoji)): Path<(u64, u64, String)>,
) -> NoContentResult {
    let emoji = resolve_emoji(user_id, emoji).await?;
    bulk_remove_reactions(user_id, channel_id, message_id, Some(emoji)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Clear Reactions
///
/// Removes all reactions from a message. This requires the `MANAGE_MESSAGES` permission in the
/// guild.
///
/// This method is idempotent: if you try to remove reactions from a message that has no reactions,
/// nothing will happen.
#[utoipa::path(
    delete,
    path = "/channels/{channel_id}/messages/{message_id}/reactions",
    responses(
        (status = NO_CONTENT, description = "Reactions removed"),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Channel or message not found", body = Error),
    ),
    security(("token" = [])),
)]
async fn clear_reactions(
    Auth(user_id, _): Auth,
    Path((channel_id, message_id)): Path<(u64, u64)>,
) -> NoContentResult {
    bulk_remove_reactions(user_id, channel_id, message_id, None).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn router() -> Router {
    Router::new()
        .route(
            "/channels/:channel_id/messages",
            get(get_message_history.layer(ratelimit!(5, 5)))
                .post(create_message.layer(ratelimit!(5, 5))),
        )
        .route(
            "/channels/:channel_id/messages/:message_id",
            get(get_message.layer(ratelimit!(5, 5)))
                .patch(edit_message.layer(ratelimit!(5, 5)))
                .delete(delete_message.layer(ratelimit!(5, 5))),
        )
        .route(
            "/channels/:channel_id/messages/:message_id/pin",
            put(pin_message.layer(ratelimit!(5, 5))).delete(unpin_message.layer(ratelimit!(5, 5))),
        )
        .route(
            "/channels/:channel_id/messages/:message_id/reactions",
            get(get_message_reactions.layer(ratelimit!(5, 5)))
                .delete(clear_reactions.layer(ratelimit!(5, 5))),
        )
        .route(
            "/channels/:channel_id/messages/:message_id/reactions/:emoji",
            delete(remove_all_reactions_for_emoji.layer(ratelimit!(5, 5))),
        )
        .route(
            "/channels/:channel_id/messages/:message_id/reactions/:emoji/me",
            put(add_reaction.layer(ratelimit!(10, 10)))
                .delete(remove_reaction.layer(ratelimit!(10, 10))),
        )
        .route(
            "/channels/:channel_id/messages/:message_id/reactions/:emoji/:user_id",
            delete(remove_user_reaction.layer(ratelimit!(10, 10))),
        )
}
