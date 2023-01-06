use crate::extract::Json;
use crate::routes::NoContentResult;
use crate::{extract::Auth, ratelimit::ratelimit, routes::RouteResult, Response};
use axum::http::StatusCode;
use axum::{extract::Path, handler::Handler, routing::get, Router};
use essence::http::role::{CreateRolePayload, EditRolePayload};
use essence::models::{ModelType, Permissions};
use essence::snowflake::generate_snowflake;
use essence::Error;
use essence::{
    db::{get_pool, GuildDbExt, RoleDbExt},
    models::Role,
    NotFoundExt,
};

fn validate_role_name(name: &str) -> Result<(), Error> {
    if !(1..=32).contains(&name.chars().count()) {
        return Err(Error::InvalidField {
            field: "name".to_string(),
            message: "Role name must be between 1 and 32 characters long".to_string(),
        });
    }

    Ok(())
}

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

/// Create Role
///
/// Creates a role in the guild with the given guild ID. You must have the `MANAGE_ROLES` permission
/// to create roles.
#[utoipa::path(
    post,
    path = "/guilds/{guild_id}/roles",
    request_body = CreateRolePayload,
    responses(
        (status = CREATED, description = "Role object", body = Role),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (
            status = FORBIDDEN,
            description = "\
                You are forbidden from creating the roles. This can be because:\n\
                * You are not a member of the guild.\n\
                * You do not have the `MANAGE_ROLES` permission in the guild.\n\
                * You are creating a role that allows or denies permissions you do not have.\
            ",
            body = Error,
        ),
        (status = NOT_FOUND, description = "Guild not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn create_role(
    Auth(user_id, _): Auth,
    Path(guild_id): Path<u64>,
    Json(payload): Json<CreateRolePayload>,
) -> RouteResult<Role> {
    validate_role_name(&payload.name)?;
    let mut db = get_pool();

    let member_permissions = db.fetch_member_permissions(guild_id, user_id, None).await?;
    db.assert_member_has_permissions_with(guild_id, member_permissions, Permissions::MANAGE_ROLES)
        .await?;

    if !payload.permissions.allow.contains(member_permissions)
        || !payload.permissions.deny.contains(member_permissions)
    {
        return Err(Response::from(Error::MissingPermissions {
            guild_id,
            permissions: payload.permissions.allow.difference(member_permissions)
                | payload.permissions.deny.difference(member_permissions),
            message: String::from(
                "You cannot create a role that allows or denies permissions you do not have",
            ),
        }));
    }

    let role_id = generate_snowflake(ModelType::Role, 0); // TODO: node id
    let role = db.create_role(guild_id, role_id, payload).await?;
    Ok(Response::ok(role))
}

/// Edit Role
///
/// Modifies the role with the given ID in the given guild. You must have the `MANAGE_ROLES`
/// permission, and the role must be lower than your highest role.
#[utoipa::path(
    patch,
    path = "/guilds/{guild_id}/roles/{role_id}",
    request_body = EditRolePayload,
    responses(
        (status = OK, description = "Modified role object", body = Role),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (
            status = FORBIDDEN,
            description = "\
                You are forbidden from editing the role. This can be because:\n\
                * You are not a member of the guild.\n\
                * You do not have the `MANAGE_ROLES` permission in the guild.\n\
                * You are editing a role that allows or denies permissions you do not have.\n\
                * You are editing a role that is higher than your highest role.\n\
            ",
            body = Error,
        ),
        (status = NOT_FOUND, description = "Guild or role not found", body = Error),
    ),
    security(("token" = [])),
)]
pub async fn edit_role(
    Auth(user_id, _): Auth,
    Path((guild_id, role_id)): Path<(u64, u64)>,
    Json(payload): Json<EditRolePayload>,
) -> RouteResult<Role> {
    if let Some(ref name) = payload.name {
        validate_role_name(name)?;
    }

    let mut db = get_pool();
    let member_permissions = db.fetch_member_permissions(guild_id, user_id, None).await?;
    db.assert_member_has_permissions_with(guild_id, member_permissions, Permissions::MANAGE_ROLES)
        .await?;
    db.assert_top_role_higher_than(guild_id, user_id, role_id)
        .await?;

    if let Some(permissions) = payload.permissions {
        if !permissions.allow.contains(member_permissions)
            || !permissions.deny.contains(member_permissions)
        {
            return Err(Response::from(Error::MissingPermissions {
                guild_id,
                permissions: permissions.allow.difference(member_permissions)
                    | permissions.deny.difference(member_permissions),
                message: String::from(
                    "You cannot edit a role to allow or deny permissions you do not have",
                ),
            }));
        }
    }

    let role = db.edit_role(guild_id, role_id, payload).await?;
    Ok(Response::ok(role))
}

/// Delete Role
///
/// Deletes the role with the given ID in the given guild. You must have the `MANAGE_ROLES`
/// permission, the role cannot be managed, and the role must be lower than your highest role.
#[utoipa::path(
    delete,
    path = "/guilds/{guild_id}/roles/{role_id}",
    responses(
        (status = NO_CONTENT, description = "Role deleted"),
        (status = UNAUTHORIZED, description = "Invalid token", body = Error),
        (
            status = FORBIDDEN,
            description = "\
                You are forbidden from deleting the role. This can be because:\n\
                * You are not a member of the guild.\n\
                * You do not have the `MANAGE_ROLES` permission in the guild.\n\
                * The role is managed.\n\
                * The role is higher than your highest role.\
            ",
            body = Error,
        ),
    ),
    security(("token" = [])),
)]
pub async fn delete_role(
    Auth(user_id, _): Auth,
    Path((guild_id, role_id)): Path<(u64, u64)>,
) -> NoContentResult {
    let mut db = get_pool();

    db.assert_role_is_not_managed(guild_id, role_id).await?;
    db.assert_member_has_permissions(guild_id, user_id, None, Permissions::MANAGE_ROLES)
        .await?;
    db.assert_top_role_higher_than(guild_id, user_id, role_id)
        .await?;
    db.delete_role(guild_id, role_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub fn router() -> Router {
    Router::new()
        .route(
            "/guilds/:guild_id/roles",
            get(get_roles.layer(ratelimit!(3, 6))).post(create_role.layer(ratelimit!(3, 8))),
        )
        .route(
            "/guilds/:guild_id/roles/:role_id",
            get(get_role.layer(ratelimit!(5, 8)))
                .patch(edit_role.layer(ratelimit!(3, 8)))
                .delete(delete_role.layer(ratelimit!(3, 10))),
        )
}
