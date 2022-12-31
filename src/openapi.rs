use crate::routes::{auth, guilds, users};
use essence::{http, models};
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi};

#[derive(OpenApi)]
#[openapi(
    paths(
        auth::login,
        guilds::create_guild,
        guilds::get_all_guilds,
        guilds::get_guild,
        users::create_user,
        users::get_client_user,
        users::get_user,
        users::edit_user,
        users::delete_user,
    ),
    components(schemas(
        http::auth::LoginRequest,
        http::auth::LoginResponse,
        http::auth::TokenRetrievalMethod,
        http::guild::CreateGuildPayload,
        http::guild::EditGuildPayload,
        http::guild::DeleteGuildPayload,
        http::user::CreateUserPayload,
        http::user::CreateUserResponse,
        http::user::EditUserPayload,
        http::user::DeleteUserPayload,
        http::user::ChangeEmailPayload,
        http::user::ChangePasswordPayload,
        models::TextBasedGuildChannelInfo,
        models::ChannelType,
        models::GuildChannelInfo,
        models::PermissionOverwrite,
        models::GuildChannel,
        models::DmChannelInfo,
        models::DmChannel,
        models::Channel,
        models::MaybePartialUser,
        models::Member,
        models::GuildMemberCount,
        models::PartialGuild,
        models::Guild,
        models::EmbedType,
        models::EmbedAuthor,
        models::EmbedFooter,
        models::MessageEmbedFieldAlignment,
        models::EmbedField,
        models::Embed,
        models::Attachment,
        models::MessageInfo,
        models::MemberOrUser,
        models::Message,
        models::PermissionPair,
        models::Role,
        models::User,
        models::GuildFolderInfo,
        models::GuildFolder,
        models::ClientUser,
        models::RelationshipType,
        models::Relationship,
        essence::Error,
    )),
    modifiers(&Security),
    tags(
        (name = "Adapt REST API", description = "Public REST API for the Adapt chat platform")
    ),
)]
pub struct ApiSpec;

pub struct Security;

impl Modify for Security {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(ref mut components) = openapi.components {
            components.add_security_scheme(
                "token",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("Authorization"))),
            );
        }
    }
}
