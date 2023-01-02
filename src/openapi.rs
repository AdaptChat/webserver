use crate::routes::{auth, channels, guilds, users};
use essence::{http, models};
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi};

#[derive(OpenApi)]
#[openapi(
    paths(
        auth::login,
        users::create_user,
        users::get_client_user,
        users::get_user,
        users::edit_user,
        users::delete_user,
        guilds::create_guild,
        guilds::get_all_guilds,
        guilds::get_guild,
        guilds::edit_guild,
        guilds::delete_guild,
        channels::create_guild_channel,
        channels::get_guild_channels,
        channels::get_channel,
        channels::edit_channel,
        channels::delete_channel,
    ),
    components(schemas(
        http::auth::LoginRequest,
        http::auth::LoginResponse,
        http::channel::CreateGuildChannelPayload,
        http::channel::CreateGuildChannelInfo,
        http::channel::EditChannelPayload,
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
        models::Permissions,
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
        models::GuildFlags,
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
        models::MessageFlags,
        models::PermissionPair,
        models::Role,
        models::RoleFlags,
        models::User,
        models::UserFlags,
        models::GuildFolderInfo,
        models::GuildFolder,
        models::ClientUser,
        models::RelationshipType,
        models::Relationship,
        essence::Error,
        essence::error::MalformedBodyErrorType,
    )),
    modifiers(&Security),
    servers(
        (description = "Production", url = "https://adapt.lambdabot.cf"),
        (description = "Local", url = "http://127.0.0.1:8077"),
    )
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
