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
use essence::{
    db::{get_pool, AuthDbExt, GuildDbExt},
    http::guild::{CreateGuildPayload, DeleteGuildPayload, EditGuildPayload, GetGuildQuery},
    models::{Guild, ModelType, PartialGuild, Permissions, UserFlags},
    snowflake::{generate_snowflake, with_model_type},
    Error, Maybe, NotFoundExt,
};

#[inline]
pub fn validate_guild_name(name: &str) -> Result<(), Error> {
    if !(2..=100).contains(&name.chars().count()) {
        return Err(Error::InvalidField {
            field: "name",
            message: "Guild name must be between 2 and 100 characters long".to_string(),
        });
    }

    Ok(())
}

#[inline]
pub fn validate_guild_description(description: &str) -> Result<(), Error> {
    if description.len() > 1024 {
        return Err(Error::InvalidField {
            field: "description",
            message: "Guild description must be at most 1 KB in size".to_string(),
        });
    }

    Ok(())
}

/// Create Guild
///
/// Creates a new guild with the given payload.
#[utoipa::path(
    post,
    path = "/guilds",
    request_body = CreateGuildPayload,
    responses(
        (status = CREATED, description = "Guild was successfully created", body = Guild),
        (status = BAD_REQUEST, description = "Invalid payload", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn create_guild(
    Auth(owner_id, _): Auth,
    Json(payload): Json<CreateGuildPayload>,
) -> RouteResult<Guild> {
    validate_guild_name(&payload.name)?;
    if let Some(ref desc) = payload.description {
        validate_guild_description(desc)?;
    }

    let db = get_pool();
    let mut transaction = db.begin().await?;

    let guild_id = generate_snowflake(ModelType::Guild, 0);
    let channel_id = with_model_type(guild_id, ModelType::Channel);
    let role_id = with_model_type(guild_id, ModelType::Role);

    let guild = transaction
        .create_guild(guild_id, channel_id, role_id, owner_id, payload)
        .await?;
    transaction.commit().await?;

    Ok(Response::created(guild))
}

/// Get All Guilds
///
/// Fetches information for all guilds the user is a member of, abiding by the given query.
#[utoipa::path(
    get,
    path = "/guilds",
    params(GetGuildQuery),
    responses(
        (status = OK, description = "Array of guild objects", body = [Guild]),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn get_all_guilds(
    Auth(user_id, _): Auth,
    Query(query): Query<GetGuildQuery>,
) -> RouteResult<Vec<Guild>> {
    let db = get_pool();
    let guilds = db.fetch_all_guilds_for_user(user_id, query).await?;

    Ok(Response::ok(guilds))
}

/// Get Guild
///
/// Fetches information for the guild with the given ID. You must be a member of the guild to fetch
/// it.
#[utoipa::path(
    get,
    path = "/guilds/{id}",
    responses(
        (status = OK, description = "Guild object", body = Guild),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "You are not a member of the guild", body = Error),
        (status = NOT_FOUND, description = "Guild not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn get_guild(
    Auth(user_id, _): Auth,
    Path(guild_id): Path<u64>,
    Query(query): Query<GetGuildQuery>,
) -> RouteResult<Guild> {
    let db = get_pool();
    db.assert_member_in_guild(guild_id, user_id).await?;

    let guild = db
        .fetch_guild(guild_id, query)
        .await?
        .ok_or_not_found("guild", "Guild not found")?;

    Ok(Response::ok(guild))
}

/// Edit Guild
///
/// Modifies details of the guild with the given ID. You must have `MANAGE_GUILD` permissions to
/// modify the guild. Returns the modified guild as a partial guild on success.
#[utoipa::path(
    patch,
    path = "/guilds/{id}",
    request_body = EditGuildPayload,
    responses(
        (status = OK, description = "Modified guild", body = PartialGuild),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "You do not have permission to modify the guild", body = Error),
        (status = NOT_FOUND, description = "Guild not found", body = Error),
        (status = BAD_REQUEST, description = "Invalid payload", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn edit_guild(
    Auth(user_id, _): Auth,
    Path(guild_id): Path<u64>,
    Json(payload): Json<EditGuildPayload>,
) -> RouteResult<PartialGuild> {
    if let Some(ref name) = payload.name {
        validate_guild_name(name)?;
    }
    if let Maybe::Value(ref desc) = payload.description {
        validate_guild_description(desc)?;
    }

    let mut db = get_pool();
    db.assert_member_has_permissions(guild_id, user_id, None, Permissions::MANAGE_GUILD)
        .await?;

    let guild = db.edit_guild(guild_id, payload).await?;
    Ok(Response::ok(guild))
}

/// Delete Guild
///
/// Deletes the guild with the given ID. You must be the owner of the guild to delete it.
#[utoipa::path(
    delete,
    path = "/guilds/{id}",
    request_body = Option<DeleteGuildPayload>,
    responses(
        (status = NO_CONTENT, description = "Guild was successfully deleted"),
        (status = UNAUTHORIZED, description = "Invalid token or password", body = Error),
        (status = FORBIDDEN, description = "You are not the owner of the guild", body = Error),
        (status = NOT_FOUND, description = "Guild not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn delete_guild(
    Auth(user_id, flags): Auth,
    Path(guild_id): Path<u64>,
    payload: Option<Json<DeleteGuildPayload>>,
) -> NoContentResult {
    let mut db = get_pool();
    db.assert_member_is_owner(guild_id, user_id).await?;

    if !flags.contains(UserFlags::BOT) {
        let Json(DeleteGuildPayload { password }) = payload.ok_or_else(|| {
            Response::from(Error::MissingBody {
                message: "Missing request body to delete guild",
            })
        })?;

        if !db.verify_password(user_id, password).await? {
            return Err(Response::from(Error::InvalidCredentials {
                what: "password",
                message: "Invalid password",
            }));
        }
    }

    db.delete_guild(guild_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn router() -> Router {
    Router::new()
        .route(
            "/guilds",
            get(get_all_guilds.layer(ratelimit!(1, 5))).post(create_guild.layer(ratelimit!(2, 15))),
        )
        .route(
            "/guilds/:id",
            get(get_guild.layer(ratelimit!(3, 12)))
                .patch(edit_guild.layer(ratelimit!(3, 12)))
                .delete(delete_guild.layer(ratelimit!(2, 20))),
        )
}
