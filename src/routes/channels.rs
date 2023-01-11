#[cfg(feature = "ws")]
use crate::amqp::prelude::*;
use crate::{
    extract::{Auth, Json},
    ratelimit::ratelimit,
    routes::{NoContentResult, RouteResult},
    Response,
};
use axum::{extract::Path, handler::Handler, http::StatusCode, routing::get, Router};
use essence::{
    db::{get_pool, ChannelDbExt, GuildDbExt},
    http::channel::{CreateGuildChannelInfo, CreateGuildChannelPayload, EditChannelPayload},
    models::{Channel, ChannelType, GuildChannel, ModelType, Permissions},
    snowflake::generate_snowflake,
    Error, Maybe, NotFoundExt,
};

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
    if topic.len() < 1024 {
        return Err(Error::InvalidField {
            field: "topic".to_string(),
            message: "Channel topic must be at most 1 KB in size".to_string(),
        });
    }

    Ok(())
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

    let channel_id = generate_snowflake(ModelType::Channel, 0); // TODO: node ID
    let channel = db
        .create_guild_channel(guild_id, channel_id, payload)
        .await?;

    #[cfg(feature = "ws")]
    amqp::publish(
        &amqp::create_channel().await?,
        Some(guild_id),
        OutboundMessage::GuildChannelCreate {
            channel: channel.clone(),
        },
    )
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
        .0
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
    let (guild_id, _, kind) = db
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

    let channel = db.edit_channel(channel_id, payload).await?;
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
)]
pub async fn delete_channel(
    Auth(user_id, _): Auth,
    Path(channel_id): Path<u64>,
) -> NoContentResult {
    let mut db = get_pool();
    let (guild_id, _, kind) = db
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
    Ok(StatusCode::NO_CONTENT)
}

pub fn router() -> Router {
    Router::new()
        .route(
            "/guilds/:guild_id/channels",
            get(get_guild_channels.layer(ratelimit!(3, 6)))
                .post(create_guild_channel.layer(ratelimit!(3, 10))),
        )
        .route(
            "/channels/:channel_id",
            get(get_channel.layer(ratelimit!(4, 6)))
                .patch(edit_channel.layer(ratelimit!(3, 10)))
                .delete(delete_channel.layer(ratelimit!(3, 10))),
        )
}
