//! Handles email validation and verification.

use essence::{Error, Result};
use lettre::{
    address::Address,
    message::{header::ContentType, Mailbox},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use std::{
    collections::HashSet,
    env::var,
    fs::File,
    io::{BufRead, BufReader},
    sync::LazyLock,
};

#[derive(Clone)]
pub struct SmtpConfig {
    pub sender: Mailbox,
    pub host: String,
    pub port: Option<u16>,
    pub credentials: Option<Credentials>,
}

impl SmtpConfig {
    #[must_use]
    pub fn from_env() -> Self {
        let from_name = var("SMTP_FROM_NAME").unwrap_or_else(|_| "Adapt".to_string());
        let from_email = var("SMTP_FROM_EMAIL").expect("missing SMTP_FROM_EMAIL env var");
        Self {
            sender: format!("{from_name} <{from_email}>")
                .parse()
                .expect("could not parse SMTP_FROM name/email pair"),
            host: var("SMTP_HOST").expect("missing SMTP_HOST env var"),
            port: var("SMTP_PORT")
                .map(|p| p.parse().expect("SMTP_PORT should be u16"))
                .ok(),
            credentials: var("SMTP_USER")
                .and_then(|user| var("SMTP_PASSWORD").map(|pass| Credentials::new(user, pass)))
                .ok(),
        }
    }
}

/// Ensures that the email is properly formatted and is not known to be disposable,
/// then parses it into a [`Address`].
///
/// The blocklist of disposable email domains is configured by passing the filename of
/// a newline-separated list to the ``EMAIL_BLOCKLIST`` environment variable.
///
/// # Errors
/// * if the email is malformed
/// * if the email is part of the blocklist
pub fn parse_and_validate_email(email: &str) -> Result<Address> {
    static DOMAIN_BLOCKLIST: LazyLock<HashSet<String>> = LazyLock::new(|| {
        let Ok(blocklist_filename) = var("EMAIL_DOMAIN_BLOCKLIST") else {
            return HashSet::new();
        };
        let file = File::open(&blocklist_filename)
            .expect("could not access blocklist specified in EMAIL_DOMAIN_BLOCKLIST");
        BufReader::new(file)
            .lines()
            .map_while(std::result::Result::ok)
            .collect()
    });

    let Ok(address) = email.parse::<Address>() else {
        return Err(Error::InvalidField {
            field: "email".to_string(),
            message: "Email address is malformed.".to_string(),
        });
    };

    if DOMAIN_BLOCKLIST.contains(&address.domain().to_lowercase()) {
        return Err(Error::InvalidField {
            field: "email".to_string(),
            message: "Email domain is not allowed.".to_string(),
        });
    }

    Ok(address)
}

/// The message to send via email.
#[derive(Clone, Debug)]
pub enum EmailMessage<'a> {
    /// An email verification request.
    VerifyEmail {
        /// The username of the requesting user.
        username: &'a str,
        /// The verification code, which should be a string of six numerical digits.
        code: &'a str,
    },
    /// A verification request for a login attempt into an MFA-enabled account.
    Mfa {
        /// The username of the requesting user.
        username: &'a str,
        /// The verification code, which should be a string of six numerical digits.
        code: &'a str,
    },
    /// A password reset request with a reset token.
    ResetPassword {
        /// The username of the requesting user.
        username: &'a str,
        /// The verification token.
        token: &'a str,
    },
}

impl EmailMessage<'_> {
    /// The subject of the email.
    fn subject(&self) -> String {
        match self {
            Self::VerifyEmail { code, .. } | Self::Mfa { code, .. } => {
                format!("{code} is your Adapt verification code")
            }
            Self::ResetPassword { .. } => String::from("Reset your Adapt password"),
        }
    }

    /// Generates the HTML body of the email.
    fn body(&self) -> String {
        match self {
            Self::VerifyEmail { username, code } => format!(
                include_str!("templates/verify.html"),
                username = username,
                code = code
            ),
            Self::Mfa { username, code } => format!(
                include_str!("templates/mfa.html"),
                username = username,
                code = code
            ),
            Self::ResetPassword { username, token } => {
                let url = format!("https://app.adapt.chat/reset?token={token}");
                format!(
                    include_str!("templates/reset_password.html"),
                    username = username,
                    reset_url = url
                )
            }
        }
    }

    /// Sends this message to the provided email.
    ///
    /// Note: this method does not perform any formal validation of the provided email.
    pub async fn send(&self, recipient: Address) -> Result<()> {
        static SMTP_CONFIG: LazyLock<SmtpConfig> = LazyLock::new(SmtpConfig::from_env);

        let SmtpConfig {
            sender,
            host,
            port,
            credentials,
        } = &*SMTP_CONFIG;

        let to = Mailbox::new(None, recipient);
        let email = Message::builder()
            .from(sender.clone())
            .to(to)
            .subject(self.subject())
            .header(ContentType::TEXT_HTML)
            .body(self.body())
            .map_err(|e| Error::InternalError {
                what: Some("smtp".to_string()),
                message: "Failed to build email message".to_string(),
                debug: Some(format!("{e:?}")),
            })?;

        let mut transport = AsyncSmtpTransport::<Tokio1Executor>::relay(host).map_err(|e| {
            Error::InternalError {
                what: Some("smtp".to_string()),
                message: "Failed to create SMTP transport".to_string(),
                debug: Some(format!("{e:?}")),
            }
        })?;
        if let Some(port) = port {
            transport = transport.port(*port);
        }
        if let Some(credentials) = credentials {
            transport = transport.credentials(credentials.clone());
        }

        transport
            .build()
            .send(email)
            .await
            .map_err(|e| Error::InternalError {
                what: Some("smtp".to_string()),
                message: "Failed to send email".to_string(),
                debug: Some(format!("{e:?}")),
            })?;

        Ok(())
    }
}
