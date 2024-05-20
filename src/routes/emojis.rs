use axum::http::StatusCode;
use axum::routing::get;
use axum::{extract::Path, Router};
use essence::{
    db::{get_pool, EmojiDbExt, GuildDbExt},
    http::emoji::{CreateEmojiPayload, UpdateEmojiPayload},
    models::{Emoji, ModelType, Permissions},
    snowflake::generate_snowflake,
    Error, NotFoundExt,
};

use crate::{
    cdn::upload_custom_emoji,
    extract::{Auth, Json},
    Response,
};

use super::{NoContentResult, RouteResult};

pub async fn create_emoji(
    Auth(user_id, _): Auth,
    Path(guild_id): Path<u64>,
    Json(CreateEmojiPayload { name, image }): Json<CreateEmojiPayload>,
) -> RouteResult<Emoji> {
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
    let emoji = db.create_emoji(id, guild_id, name, user_id).await?;

    upload_custom_emoji(id, &image).await?;

    Ok(Response::created(emoji))
}

pub async fn list_guild_emojis(
    Auth(user_id, _): Auth,
    Path(guild_id): Path<u64>,
) -> RouteResult<Vec<Emoji>> {
    let db = get_pool();
    db.assert_invoker_in_guild(guild_id, user_id).await?;

    let emojis = db.fetch_all_emojis_in_guild(guild_id).await?;

    Ok(Response::ok(emojis))
}

pub async fn get_emoji(_: Auth, Path((_, emoji_id)): Path<(u64, u64)>) -> RouteResult<Emoji> {
    let emoji = get_pool()
        .fetch_emoji(emoji_id)
        .await?
        .ok_or_not_found("emoji", "emoji not found")?;

    Ok(Response::ok(emoji))
}

pub async fn update_emoji(
    Auth(user_id, _): Auth,
    Path((guild_id, emoji_id)): Path<(u64, u64)>,
    Json(UpdateEmojiPayload { name }): Json<UpdateEmojiPayload>,
) -> RouteResult<Emoji> {
    let mut db = get_pool();
    db.assert_member_has_permissions(guild_id, user_id, None, Permissions::MANAGE_EMOJIS)
        .await?;

    let updated = db.edit_emoji(emoji_id, name).await?;

    Ok(Response::ok(updated))
}

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
            get(list_guild_emojis).post(create_emoji),
        )
        .route(
            "/guilds/:guild_id/emojis/:emoji_id",
            get(get_emoji).patch(update_emoji).delete(delete_emoji),
        )
}
