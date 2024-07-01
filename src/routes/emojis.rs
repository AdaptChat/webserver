use axum::{extract::Path, handler::Handler, http::StatusCode, routing::get, Router};
use essence::{
    db::{get_pool, EmojiDbExt, GuildDbExt},
    http::{
        emoji::{CreateEmojiPayload, EditEmojiPayload},
        guild::GetGuildQuery,
    },
    models::{CustomEmoji, GuildFlags, ModelType, Permissions},
    snowflake::generate_snowflake,
    utoipa, Error, NotFoundExt,
};

use super::{NoContentResult, RouteResult};
use crate::{
    cdn::upload_custom_emoji,
    extract::{Auth, Json},
    ratelimit::ratelimit,
    Response,
};

/// Create Custom Emoji
///
/// Creates a new custom emoji in the guild. You must have the `MANAGE_EMOJIS` permission for the
/// guild to use this endpoint.
#[utoipa::path(
    post,
    path = "/guilds/{guild_id}/emojis",
    request_body = CreateEmojiPayload,
    responses(
        (status = CREATED, description = "Custom emoji object", body = Role),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = BAD_REQUEST, description = "Invalid payload or name length", body = Error),
        (
            status = FORBIDDEN,
            description = "\
                You are forbidden from creating the emoji. This can be because:\n\
                * You are not a member of the guild.\n\
                * You do not have the `MANAGE_EMOJIS` permission in the guild.\
            ",
            body = Error,
        ),
        (status = NOT_FOUND, description = "Guild not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn create_emoji(
    Auth(user_id, _): Auth,
    Path(guild_id): Path<u64>,
    Json(CreateEmojiPayload { name, image }): Json<CreateEmojiPayload>,
) -> RouteResult<CustomEmoji> {
    if name.len() > 100 {
        return Err(Error::InvalidField {
            field: "name".to_string(),
            message: "emoji name must be between 2 to 100 characters long".to_string(),
        }
        .into());
    }
    let mut db = get_pool();
    db.assert_member_has_permissions(guild_id, user_id, None, Permissions::MANAGE_EMOJIS)
        .await?;

    let id = generate_snowflake(ModelType::Emoji, 0);

    upload_custom_emoji(id, &image).await?;
    let emoji = db.create_emoji(id, guild_id, name, user_id).await?;

    Ok(Response::created(emoji))
}

/// List Custom Emojis
///
/// Lists all custom emojis in the guild. If the guild is not public, you must be a member of the
/// guild to use this endpoint.
#[utoipa::path(
    get,
    path = "/guilds/{guild_id}/emojis",
    responses(
        (status = OK, description = "List of custom emojis", body = Vec<CustomEmoji>),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (
            status = FORBIDDEN,
            description = "The guild is not public and you are not a member of the guild.",
            body = Error,
        ),
        (status = NOT_FOUND, description = "Guild not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn list_guild_emojis(
    Auth(user_id, _): Auth,
    Path(guild_id): Path<u64>,
) -> RouteResult<Vec<CustomEmoji>> {
    let db = get_pool();

    let guild = db
        .fetch_guild(guild_id, GetGuildQuery::default())
        .await?
        .ok_or_not_found("guild", "guild not found")?;
    if !guild.partial.flags.contains(GuildFlags::PUBLIC) {
        db.assert_invoker_in_guild(guild_id, user_id).await?;
    }

    let emojis = db.fetch_all_emojis_in_guild(guild_id).await?;
    Ok(Response::ok(emojis))
}

/// Get Emoji
///
/// Gets information about a custom emoji.
#[utoipa::path(
    get,
    path = "/emojis/{emoji_id}",
    responses(
        (status = OK, description = "Custom emoji object", body = CustomEmoji),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = NOT_FOUND, description = "Emoji not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn get_emoji(_: Auth, Path(emoji_id): Path<u64>) -> RouteResult<CustomEmoji> {
    let emoji = get_pool()
        .fetch_emoji(emoji_id)
        .await?
        .ok_or_not_found("emoji", "emoji not found")?;

    Ok(Response::ok(emoji))
}

/// Edit Emoji
///
/// Modifies a custom emoji. You must have the `MANAGE_EMOJIS` permission for the guild to use this
/// endpoint.
#[utoipa::path(
    patch,
    path = "/guilds/{guild_id}/emojis/{emoji_id}",
    request_body = UpdateEmojiPayload,
    responses(
        (status = OK, description = "Custom emoji object", body = CustomEmoji),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = BAD_REQUEST, description = "Invalid payload or name length", body = Error),
        (status = FORBIDDEN, description = "Missing Manage Emojis permission", body = Error),
        (status = NOT_FOUND, description = "Emoji not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn edit_emoji(
    Auth(user_id, _): Auth,
    Path((guild_id, emoji_id)): Path<(u64, u64)>,
    Json(EditEmojiPayload { name }): Json<EditEmojiPayload>,
) -> RouteResult<CustomEmoji> {
    let mut db = get_pool();
    db.assert_member_has_permissions(guild_id, user_id, None, Permissions::MANAGE_EMOJIS)
        .await?;

    let updated = db.edit_emoji(emoji_id, name).await?;
    Ok(Response::ok(updated))
}

/// Delete Emoji
///
/// Deletes a custom emoji. You must have the `MANAGE_EMOJIS` permission for the guild to use this
/// endpoint.
#[utoipa::path(
    delete,
    path = "/guilds/{guild_id}/emojis/{emoji_id}",
    responses(
        (status = NO_CONTENT, description = "Emoji deleted", body = ()),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing Manage Emojis permission", body = Error),
        (status = NOT_FOUND, description = "Emoji not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn delete_emoji(
    Auth(user_id, _): Auth,
    Path((guild_id, emoji_id)): Path<(u64, u64)>,
) -> NoContentResult {
    let mut db = get_pool();
    db.assert_member_has_permissions(guild_id, user_id, None, Permissions::MANAGE_EMOJIS)
        .await?;

    db.delete_emoji(emoji_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn router() -> Router {
    Router::new()
        .route(
            "/guilds/:guild_id/emojis",
            get(list_guild_emojis.layer(ratelimit!(5, 5)))
                .post(create_emoji.layer(ratelimit!(5, 5))),
        )
        .route(
            "/guilds/:guild_id/emojis/:emoji_id",
            get(get_emoji).patch(edit_emoji).delete(delete_emoji),
        )
        .route("/emojis/:emoji_id", get(get_emoji))
}
