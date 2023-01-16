use crate::ratelimit::ratelimit;
use crate::routes::NoContentResult;
use crate::{
    extract::{Auth, Json},
    routes::RouteResult,
    Response,
};
use axum::handler::Handler;
use axum::http::StatusCode;
use axum::{extract::Path, routing::get, Router};
use essence::models::Member;
use essence::{
    db::{get_pool, GuildDbExt, InviteDbExt},
    http::invite::CreateInvitePayload,
    models::{invite::Invite, Permissions, UserFlags},
    Error, NotFoundExt,
};
use rand::distributions::{Alphanumeric, DistString};

/// Create Invite to Guild
///
/// Creates an invite that leads to the homepage of the given guild.
/// You must have the `CREATE_INVITES` permission for the guild to use this endpoint.
#[utoipa::path(
    post,
    path = "/guilds/{guild_id}/invites",
    request_body = CreateInvitePayload,
    responses(
        (status = CREATED, description = "Invite was successfully created", body = Invite),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = BAD_REQUEST, description = "Bot account or invalid payload", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Guild not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn create_guild_invite(
    Auth(user_id, flags): Auth,
    Path(guild_id): Path<u64>,
    Json(payload): Json<CreateInvitePayload>,
) -> RouteResult<Invite> {
    if flags.contains(UserFlags::BOT) {
        return Err(Response::from(Error::UnsupportedAuthMethod {
            message: "Bots cannot create invites".to_string(),
        }));
    }

    let mut db = get_pool();
    db.assert_member_has_permissions(guild_id, user_id, None, Permissions::CREATE_INVITES)
        .await?;

    // TODO: this could be moved into essence or generated in the database. this should also check
    //       for duplicates.
    let code = Alphanumeric.sample_string(&mut rand::thread_rng(), 8);
    let invite = db.create_invite(guild_id, user_id, code, payload).await?;

    Ok(Response::created(invite))
}

/// Get Guild Invites
///
/// Gets a list of invites for the given guild. You must have the `MANAGE_INVITES` permission for
/// the guild to use this endpoint.
#[utoipa::path(
    get,
    path = "/guilds/{guild_id}/invites",
    responses(
        (status = OK, description = "List of invites", body = [Invite]),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Guild not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn get_guild_invites(
    Auth(user_id, _): Auth,
    Path(guild_id): Path<u64>,
) -> RouteResult<Vec<Invite>> {
    let db = get_pool();
    db.assert_member_has_permissions(guild_id, user_id, None, Permissions::MANAGE_INVITES)
        .await?;

    let invites = db.fetch_all_invites_in_guild(guild_id).await?;
    Ok(Response::ok(invites))
}

/// Get Invite
///
/// Gets an invite by its code. This endpoint does not require authentication, but is rate limited
/// by IP.
#[utoipa::path(
    get,
    path = "/invites/{code}",
    responses(
        (status = OK, description = "Invite", body = Invite),
        (status = NOT_FOUND, description = "Invite not found", body = Error),
    ),
)]
pub async fn get_invite(Path(code): Path<String>) -> RouteResult<Invite> {
    let db = get_pool();
    let invite = db
        .fetch_invite(&code)
        .await?
        .ok_or_not_found("invite", format!("Invite with code {code} not found"))?;

    Ok(Response::ok(invite))
}

/// Delete Invite
///
/// Deletes (revokes) an invite given its guild ID and code.
/// You must have the `MANAGE_INVITES` permission for the guild to use this endpoint.
#[utoipa::path(
    delete,
    path = "/guilds/{guild_id}/invites/{code}",
    responses(
        (status = NO_CONTENT, description = "Invite was successfully deleted"),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "Missing permissions", body = Error),
        (status = NOT_FOUND, description = "Guild or invite not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn delete_guild_invite(
    Auth(user_id, _): Auth,
    Path((guild_id, code)): Path<(u64, String)>,
) -> NoContentResult {
    let mut db = get_pool();
    db.assert_member_has_permissions(guild_id, user_id, None, Permissions::MANAGE_INVITES)
        .await?;

    db.delete_invite(&code).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Use Invite
///
/// Joins a guild using an invite.
#[utoipa::path(
    post,
    path = "/invites/{code}",
    responses(
        (status = OK, description = "Member object for the joined guild", body = Member),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = BAD_REQUEST, description = "Bot account", body = Error),
        (status = NOT_FOUND, description = "Invite not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn use_invite(
    Auth(user_id, flags): Auth,
    Path(code): Path<String>,
) -> RouteResult<Member> {
    if flags.contains(UserFlags::BOT) {
        return Err(Response::from(Error::UnsupportedAuthMethod {
            message: "Bots cannot use invites".to_string(),
        }));
    }

    let member = get_pool().use_invite(user_id, code).await?;
    Ok(Response::ok(member))
}

#[must_use]
pub fn router() -> Router {
    Router::new()
        .route(
            "/guilds/:guild_id/invites",
            get(get_guild_invites.layer(ratelimit!(4, 8)))
                .post(create_guild_invite.layer(ratelimit!(3, 8)))
                .delete(delete_guild_invite.layer(ratelimit!(3, 8))),
        )
        .route(
            "/invites/:code",
            get(get_invite.layer(ratelimit!(4, 8))).post(use_invite.layer(ratelimit!(3, 8))),
        )
}
