use crate::{
    routes::{auth, channels, emojis, guilds, invites, members, messages, roles, users},
    unicode::EmojiData,
};
use essence::{
    http, models,
    utoipa::{
        self,
        openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
        Modify, OpenApi,
    },
};

#[derive(OpenApi)]
#[openapi(
    paths(
        auth::login,
        users::check_username,
        users::create_user,
        users::get_client_user,
        users::get_user,
        users::edit_user,
        users::delete_user,
        users::get_relationships,
        users::add_friend,
        users::accept_friend_request,
        users::block_user,
        users::delete_relationship,
        users::create_bot,
        users::get_bot,
        users::get_bots,
        users::edit_bot,
        users::delete_bot,
        users::regenerate_bot_token,
        guilds::create_guild,
        guilds::get_all_guilds,
        guilds::get_guild,
        guilds::edit_guild,
        guilds::delete_guild,
        channels::get_dm_channels,
        channels::create_dm_channel,
        channels::get_guild_channels,
        channels::create_guild_channel,
        channels::get_channel,
        channels::edit_channel,
        channels::delete_channel,
        channels::acknowledge_channel,
        roles::get_roles,
        roles::get_role,
        roles::create_role,
        roles::edit_role,
        roles::edit_role_positions,
        roles::delete_role,
        members::get_client_member,
        members::get_member,
        members::get_members,
        members::edit_client_member,
        members::edit_member,
        members::kick_member,
        members::leave_guild,
        members::add_bot_to_guild,
        invites::get_guild_invites,
        invites::create_guild_invite,
        invites::delete_guild_invite,
        invites::get_invite,
        invites::use_invite,
        messages::get_message_history,
        messages::get_message,
        messages::create_message,
        messages::edit_message,
        messages::delete_message,
        messages::pin_message,
        messages::unpin_message,
        messages::get_message_reactions,
        messages::clear_reactions,
        messages::remove_all_reactions_for_emoji,
        messages::add_reaction,
        messages::remove_reaction,
        messages::remove_user_reaction,
        emojis::list_unicode_emojis,
        emojis::get_emoji,
        emojis::list_guild_emojis,
        emojis::create_emoji,
        emojis::edit_emoji,
        emojis::delete_emoji,
    ),
    components(schemas(
        http::auth::LoginRequest,
        http::auth::LoginResponse,
        http::auth::TokenRetrievalMethod,
        http::channel::CreateGuildChannelPayload,
        http::channel::CreateGuildChannelInfo,
        http::channel::CreateDmChannelPayload,
        http::channel::EditChannelPayload,
        http::emoji::CreateEmojiPayload,
        http::emoji::EditEmojiPayload,
        http::guild::CreateGuildPayload,
        http::guild::EditGuildPayload,
        http::guild::DeleteGuildPayload,
        http::invite::CreateInvitePayload,
        http::member::EditClientMemberPayload,
        http::member::EditMemberPayload,
        http::member::AddBotPayload,
        http::message::CreateMessagePayload,
        http::message::EditMessagePayload,
        http::role::CreateRolePayload,
        http::role::EditRolePayload,
        http::user::CreateUserPayload,
        http::user::CreateUserResponse,
        http::user::EditUserPayload,
        http::user::DeleteUserPayload,
        http::user::ChangeEmailPayload,
        http::user::ChangePasswordPayload,
        http::user::SendFriendRequestPayload,
        http::user::CreateBotPayload,
        http::user::CreateBotResponse,
        http::user::EditBotPayload,
        http::user::DeleteBotPayload,
        http::user::RegenerateBotTokenPayload,
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
        models::MessageReference,
        models::MaybePartialMessage,
        models::MessageFlags,
        models::PermissionPair,
        models::CustomEmoji,
        models::PartialEmoji,
        EmojiData,
        models::Reaction,
        models::Role,
        models::RoleFlags,
        models::User,
        models::UserFlags,
        models::UserOnboardingFlags,
        models::Settings,
        models::GuildFolderInfo,
        models::GuildFolder,
        models::ClientUser,
        models::Bot,
        models::BotFlags,
        models::NotificationFlags,
        models::RelationshipType,
        models::Relationship,
        models::PrivacyConfiguration,
        models::Invite,
        models::ExtendedColor,
        models::Gradient,
        models::GradientStop,
        essence::Error,
        essence::error::MalformedBodyErrorType,
        essence::error::UserInteractionType,
    )),
    modifiers(&Security),
    servers(
        (description = "Production", url = "https://api.adapt.chat"),
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
