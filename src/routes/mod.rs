use crate::Response;
use axum::http::StatusCode;
use essence::{models::UserFlags, Error};

pub type RouteResult<T> = Result<Response<T>, Response<Error>>;
pub type NoContentResult = Result<StatusCode, Response<Error>>;

pub mod auth;
pub mod channels;
pub mod emojis;
pub mod guilds;
pub mod internal;
pub mod invites;
pub mod members;
pub mod messages;
pub mod roles;
pub mod users;

pub fn assert_not_bot_account(
    flags: UserFlags,
    message: &(impl ToString + ?Sized),
) -> Result<(), Response<Error>> {
    if flags.contains(UserFlags::BOT) {
        return Err(Response::from(Error::UnsupportedAuthMethod {
            message: message.to_string(),
        }));
    }

    Ok(())
}
