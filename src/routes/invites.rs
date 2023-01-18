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
    db::{get_pool, GuildDbExt, InviteDbExt, MemberDbExt},
    http::{guild::GetGuildQuery, invite::CreateInvitePayload},
    models::{Invite, Member, Permissions, UserFlags},
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
/// Joins a guild using an invite. If the guild was successfully joined, the created member object
/// is returned. If the user is already in the guild, the existing member object is returned.
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

    let mut db = get_pool();
    let (invite, member) = db.use_invite(user_id, code).await?;
    let member = if let Some(member) = member {
        #[cfg(feature = "ws")]
        let member_clone = member.clone();

        #[cfg(feature = "ws")]
        tokio::spawn(async move {
            let channel = amqp::create_channel().await?;
            let member = member_clone;
            let user_id = member.user_id();
            let guild_id = member.guild_id;

            amqp::publish_guild_event(
                &channel,
                guild_id,
                OutboundMessage::MemberJoin {
                    member,
                    invite: Some(invite),
                },
            )
            .await?;

            amqp::publish_user_event(
                &channel,
                user_id,
                OutboundMessage::GuildCreate {
                    guild: db
                        .fetch_guild(guild_id, GetGuildQuery::all())
                        .await?
                        .ok_or_else(|| Error::InternalError {
                            what: None,
                            message: String::from(
                                "Guild registered for invite but could not be fetched",
                            ),
                            debug: None,
                        })?,
                },
            )
            .await?;

            Ok::<_, Error>(())
        });

        member
    } else {
        db.fetch_member_by_id(invite.guild_id, user_id)
            .await?
            .ok_or_else(|| Error::InternalError {
                what: None,
                message: String::from(
                    "Member is already in guild, but no member could be fetched from guild",
                ),
                debug: None,
            })?
    };

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
