use crate::{extract::Auth, ratelimit::ratelimit, routes::RouteResult, Response};
use axum::{extract::Path, handler::Handler, routing::get, Router};
use essence::{
    db::{get_pool, GuildDbExt, RoleDbExt},
    models::Role,
    NotFoundExt,
};

/// Get All Roles
///
/// Fetches information for all roles in the guild with the given ID.
/// You must be a member of the guild.
#[utoipa::path(
    get,
    path = "/guilds/{guild_id}/roles",
    responses(
        (status = OK, description = "Array of role objects", body = [Role]),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "You are not a member of the guild", body = Error),
        (status = NOT_FOUND, description = "Guild not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn get_roles(
    Auth(user_id, _): Auth,
    Path(guild_id): Path<u64>,
) -> RouteResult<Vec<Role>> {
    let db = get_pool();
    db.assert_member_in_guild(guild_id, user_id).await?;

    let roles = db.fetch_all_roles_in_guild(guild_id).await?;
    Ok(Response::ok(roles))
}

/// Get Role
///
/// Fetches information for the role with the given ID in the given guild. You must be a member of
/// the guild the role belongs to.
#[utoipa::path(
    get,
    path = "/guilds/{guild_id}/roles/{role_id}",
    responses(
        (status = OK, description = "Role object", body = Role),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (status = FORBIDDEN, description = "You are not a member of the guild", body = Error),
        (status = NOT_FOUND, description = "Guild or role not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn get_role(
    Auth(user_id, _): Auth,
    Path((guild_id, role_id)): Path<(u64, u64)>,
) -> RouteResult<Role> {
    let db = get_pool();
    db.assert_member_in_guild(guild_id, user_id).await?;

    let role = db
        .fetch_role(guild_id, role_id)
        .await?
        .ok_or_not_found("role", "Role not found")?;

    Ok(Response::ok(role))
}

pub fn router() -> Router {
    Router::new()
        .route(
            "/guilds/:guild_id/roles",
            get(get_roles.layer(ratelimit!(3, 6))),
        )
        .route(
            "/guilds/:guild_id/roles/:role_id",
            get(get_role.layer(ratelimit!(5, 8))),
        )
}
