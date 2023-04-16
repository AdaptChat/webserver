use crate::{
    extract::{Auth, Json},
    routes::RouteResult,
    Response,
};
use axum::{extract::Path, routing::put, Router};
use essence::{
    db::{get_pool, UserDbExt},
    models::UserFlags,
    Error, NotFoundExt,
};
use serde::{Deserialize, Serialize};

#[inline]
fn assert_user_is_privileged(flags: UserFlags) -> essence::Result<()> {
    if flags.contains(UserFlags::PRIVILEGED) {
        Ok(())
    } else {
        Err(Error::NotFound {
            entity: "_internal".to_string(),
            message: "Internal endpoint cannot be used".to_string(),
        })
    }
}

#[derive(Deserialize)]
struct SetUserFlagsPayload {
    #[serde(default)]
    add: UserFlags,
    #[serde(default)]
    remove: UserFlags,
    r#override: Option<UserFlags>,
}

#[derive(Serialize)]
struct UserFlagsInfo {
    flags: UserFlags,
}

/// PUT /_internal/flags/:user_id
async fn set_flags(
    Auth(_, user_flags): Auth,
    Path(target_id): Path<u64>,
    Json(payload): Json<SetUserFlagsPayload>,
) -> RouteResult<UserFlagsInfo> {
    assert_user_is_privileged(user_flags)?;
    let mut db = get_pool();

    let new_flags = if let Some(flags) = payload.r#override {
        flags
    } else {
        let base_flags = db
            .fetch_user_flags_by_id(target_id)
            .await?
            .ok_or_not_found("User", "User does not exist")?;

        base_flags | payload.add & !payload.remove
    };
    db.set_user_flags_by_id(target_id, new_flags).await?;

    Ok(Response::ok(UserFlagsInfo { flags: new_flags }))
}

pub fn router() -> Router {
    Router::new().route("/_internal/flags/:user_id", put(set_flags))
}
