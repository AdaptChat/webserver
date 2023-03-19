#[cfg(feature = "ws")]
use crate::amqp::prelude::*;
use crate::{
    extract::{Auth, Json},
    ratelimit::ratelimit,
    routes::{NoContentResult, RouteResult},
    Response,
};
use axum::{extract::Path, handler::Handler, routing::get, Router};
use essence::{
    db::{get_pool, GuildDbExt, MemberDbExt, RoleDbExt},
    http::member::{EditClientMemberPayload, EditMemberPayload},
    models::{Member, Permissions},
    utoipa, Error, Maybe, NotFoundExt,
};
use reqwest::StatusCode;

fn validate_nick(nick: &str) -> essence::Result<()> {
    if !(1..=32).contains(&nick.chars().count()) {
        return Err(Error::InvalidField {
            field: "nick".to_string(),
            message: "Nickname must be between 1 and 32 characters long".to_string(),
        });
    }

    Ok(())
}

/// Get Member
///
/// Gets information of a member in a guild. You must be a member of the guild.
#[utoipa::path(
    get,
    path = "/guilds/{guild_id}/members/{member_id}",
    responses(
        (status = OK, description = "Member object", body = Member),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "You are not a member of the guild", body = Error),
        (status = NOT_FOUND, description = "Guild or member not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn get_member(
    Auth(user_id, _): Auth,
    Path((guild_id, member_id)): Path<(u64, u64)>,
) -> RouteResult<Member> {
    let db = get_pool();
    db.assert_invoker_in_guild(guild_id, user_id).await?;

    let member = db
        .fetch_member_by_id(guild_id, member_id)
        .await?
        .ok_or_not_found("member", format!("Member with ID {member_id} not found"))?;

    Ok(Response::ok(member))
}

/// Get Authenticated User as Member
///
/// Gets information of the authenticated user as a member of a guild. You must be a member of the
/// guild.
#[utoipa::path(
    get,
    path = "/guilds/{guild_id}/members/me",
    responses(
        (status = OK, description = "Member object", body = Member),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "You are not a member of the guild", body = Error),
        (status = NOT_FOUND, description = "Guild not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn get_client_member(
    Auth(user_id, _): Auth,
    Path(guild_id): Path<u64>,
) -> RouteResult<Member> {
    let db = get_pool();
    let member = db
        .fetch_member_by_id(guild_id, user_id)
        .await?
        .ok_or_not_found("member", "You are not a member of this guild")?;

    Ok(Response::ok(member))
}

/// Get All Members
///
/// Gets information of all members in a guild. You must be a member of the guild.
#[utoipa::path(
    get,
    path = "/guilds/{guild_id}/members",
    responses(
        (status = OK, description = "Array of member objects", body = [Member]),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "You are not a member of the guild", body = Error),
        (status = NOT_FOUND, description = "Guild not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn get_members(
    Auth(user_id, _): Auth,
    Path(guild_id): Path<u64>,
) -> RouteResult<Vec<Member>> {
    let db = get_pool();
    db.assert_invoker_in_guild(guild_id, user_id).await?;

    let members = db.fetch_all_members_in_guild(guild_id).await?;
    Ok(Response::ok(members))
}

/// Edit Authenticated User as Member
///
/// Edits the authenticated user as a member of the given guild. You must be a member of the guild.
/// Parts of the payload require different permissions:
/// * The `nick` field requires the `CHANGE_NICKNAME` permission.
#[utoipa::path(
    patch,
    path = "/guilds/{guild_id}/members/me",
    request_body = EditClientMemberPayload,
    responses(
        (status = OK, description = "Member object after modifications", body = Member),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "You are not a member of the guild", body = Error),
        (status = NOT_FOUND, description = "Guild not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn edit_client_member(
    Auth(user_id, _): Auth,
    Path(guild_id): Path<u64>,
    Json(payload): Json<EditClientMemberPayload>,
) -> RouteResult<Member> {
    let mut db = get_pool();
    db.assert_invoker_in_guild(guild_id, user_id).await?;
    let perms = db.fetch_member_permissions(guild_id, user_id, None).await?;

    if let Maybe::Value(ref nick) = payload.nick {
        validate_nick(nick)?;
        db.assert_member_has_permissions_with(guild_id, perms, Permissions::CHANGE_NICKNAME)
            .await?;
    }

    let member = db.edit_client_member(guild_id, user_id, payload).await?;
    Ok(Response::ok(member))
}

/// Edit Member
///
/// Edits information of a member in a guild. Parts of the payload require different permissions:
/// * The `nick` field requires the `MANAGE_NICKNAMES` permission.
/// * The `roles` field requires the `MANAGE_ROLES` permission.
///
/// Returns the modified member object on success.
#[utoipa::path(
    patch,
    path = "/guilds/{guild_id}/members/{member_id}",
    request_body = EditMemberPayload,
    responses(
        (status = OK, description = "Member object after modifications", body = Member),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (
            status = FORBIDDEN,
            description = "\
                You are forbidden from editing the member. This can be because:\n\
                * You are not a member of the guild.\n\
                * You are missing permissions.\
            ",
            body = Error,
        ),
        (status = NOT_FOUND, description = "Guild or member not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn edit_member(
    Auth(user_id, _): Auth,
    Path((guild_id, member_id)): Path<(u64, u64)>,
    Json(payload): Json<EditMemberPayload>,
) -> RouteResult<Member> {
    let mut db = get_pool();
    db.assert_invoker_in_guild(guild_id, user_id).await?;
    db.assert_member_in_guild(guild_id, member_id).await?;
    let perms = db.fetch_member_permissions(guild_id, user_id, None).await?;

    if let Maybe::Value(ref nick) = payload.nick {
        validate_nick(nick)?;
        db.assert_member_has_permissions_with(guild_id, perms, Permissions::MANAGE_NICKNAMES)
            .await?;
    }

    if let Some(ref roles) = payload.roles {
        db.assert_member_has_permissions_with(guild_id, perms, Permissions::MANAGE_ROLES)
            .await?;

        let (top_role_id, top_role_position) = db.fetch_top_role(guild_id, user_id).await?;
        let target_position = db.fetch_highest_position_in(guild_id, roles).await?;

        if target_position >= top_role_position {
            return Err(Response::from(Error::RoleTooLow {
                guild_id,
                top_role_id,
                top_role_position,
                desired_position: target_position,
                message: "You cannot assign roles higher than your top role".to_string(),
            }));
        }
    }

    let member = db.edit_member(guild_id, member_id, payload).await?;
    Ok(Response::ok(member))
}

/// Kick Member
///
/// Kicks a member from a guild. You must be a member of the guild and have the `KICK_MEMBERS`
/// permission, and their highest role must be lower than yours.
#[utoipa::path(
    delete,
    path = "/guilds/{guild_id}/members/{member_id}",
    responses(
        (status = NO_CONTENT, description = "Member was kicked"),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (
            status = FORBIDDEN,
            description = "\
                You are forbidden from editing the member. This can be because:\n\
                * You are not a member of the guild.\n\
                * You are missing permissions.\
            ",
            body = Error,
        ),
        (status = NOT_FOUND, description = "Guild or member not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn kick_member(
    Auth(user_id, _): Auth,
    Path((guild_id, member_id)): Path<(u64, u64)>,
) -> NoContentResult {
    let mut db = get_pool();
    db.assert_member_has_permissions(guild_id, user_id, None, Permissions::KICK_MEMBERS)
        .await?;
    db.assert_top_role_higher_than_target(guild_id, user_id, member_id)
        .await?;

    db.delete_member(guild_id, member_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Leave Guild
///
/// Leaves a guild. You must be a member of the guild beforehand. If you are the owner of the guild,
/// you must transfer ownership to another member before leaving.
#[utoipa::path(
    delete,
    path = "/guilds/{guild_id}/members/me",
    responses(
        (status = NO_CONTENT, description = "Success left the guild"),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "You are the owner of the guild", body = Error),
        (status = NOT_FOUND, description = "Guild not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn leave_guild(Auth(user_id, _): Auth, Path(guild_id): Path<u64>) -> NoContentResult {
    let mut db = get_pool();
    db.assert_invoker_in_guild(guild_id, user_id).await?;

    if db.fetch_partial_guild(guild_id).await?.unwrap().owner_id == user_id {
        return Err(Response::from(Error::CannotLeaveAsOwner {
            id: guild_id,
            message: String::from(
                "You cannot leave guilds that you own, please transfer ownership of the guild \
                to another member before leaving.",
            ),
        }));
    }

    db.delete_member(guild_id, user_id).await?;

    #[cfg(feature = "ws")]
    {
        let user_event = amqp::publish_user_event(
            user_id,
            OutboundMessage::GuildRemove {
                guild_id,
                info: MemberRemoveInfo::Leave,
            },
        );
        let guild_event = amqp::publish_bulk_event(
            guild_id,
            OutboundMessage::MemberRemove {
                guild_id,
                user_id,
                info: MemberRemoveInfo::Leave,
            },
        );
        tokio::try_join!(user_event, guild_event)?;
    }

    Ok(StatusCode::NO_CONTENT)
}

pub fn router() -> Router {
    Router::new()
        .route(
            "/guilds/:guild_id/members",
            get(get_members.layer(ratelimit!(3, 8))),
        )
        .route(
            "/guilds/:guild_id/members/me",
            get(get_client_member.layer(ratelimit!(5, 7)))
                .patch(edit_client_member.layer(ratelimit!(4, 7)))
                .delete(leave_guild.layer(ratelimit!(4, 8))),
        )
        .route(
            "/guilds/:guild_id/members/:member_id",
            get(get_member.layer(ratelimit!(5, 7)))
                .patch(edit_member.layer(ratelimit!(4, 7)))
                .delete(kick_member.layer(ratelimit!(4, 8))),
        )
}
