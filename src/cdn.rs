use data_url::DataUrl;
use essence::Error;
use reqwest::{
    multipart::{Form, Part},
    Client,
};
use serde::Deserialize;
use std::sync::OnceLock;

const CDN_URL: &str = dotenv!("CDN_URL", "missing CDN_URL environment variable");
const CDN_AUTHORIZATION: &str = dotenv!(
    "CDN_AUTHORIZATION",
    "missing CDN_AUTHORIZATION environment variable"
);
static CLIENT: OnceLock<Client> = OnceLock::new();

#[derive(Deserialize)]
struct CdnUploadResponse {
    path: String,
}

fn humanize_size(mut len: usize) -> String {
    const SIZES: [&str; 6] = ["B", "kB", "MB", "GB", "TB", "PB"];
    let mut index = 0;

    while len > 1000 {
        len /= 1000;
        index += 1;
    }
    format!("{len} {}", SIZES[index])
}

/// Initializes the reqwest client.
pub fn setup() -> reqwest::Result<()> {
    let client = Client::builder()
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()?;

    CLIENT.set(client).expect("failed to initialize CDN client");

    Ok(())
}

/// Gets a reference to the reqwest client.
pub fn get_client() -> &'static Client {
    CLIENT.get().expect("CDN client not initialized")
}

/// Turns a data URI scheme into a tuple `(bytes, extension)`.
fn data_scheme_to_bytes(
    field: Option<&'static str>,
    image_data: &str,
    accept_gifs: bool,
    max_size: usize,
) -> essence::Result<(Vec<u8>, String)> {
    let field = field.unwrap_or("unknown");
    let url = DataUrl::process(image_data).map_err(|_| Error::InvalidField {
        field: field.to_string(),
        message: "Invalid data scheme".to_string(),
    })?;

    let allowed = if accept_gifs {
        ["png", "jpeg", "jpg", "gif"].as_slice()
    } else {
        ["png", "jpeg", "jpg"].as_slice()
    };
    let mut ext = &*url.mime_type().subtype;
    if url.mime_type().type_ != "image" || !allowed.contains(&ext) {
        return Err(Error::InvalidField {
            field: field.to_string(),
            message: format!(
                "Data scheme must be one of [image/png, image/jpeg{}]",
                if accept_gifs { ", image/gif" } else { "" }
            ),
        });
    }
    if ext == "jpeg" {
        ext = "jpg";
    }

    let bytes = url
        .decode_to_vec()
        .map_err(|_| Error::InvalidField {
            field: field.to_string(),
            message: "Invalid image data".to_string(),
        })?
        .0;

    let size = bytes.len();
    if size > max_size {
        return Err(Error::InvalidField {
            field: field.to_string(),
            message: format!(
                "Provided image is too large ({} > {})",
                humanize_size(size),
                humanize_size(max_size)
            ),
        });
    }

    Ok((bytes, ext.to_string()))
}

async fn upload(
    endpoint: &str,
    bytes: Vec<u8>,
    filename: String,
) -> essence::Result<CdnUploadResponse> {
    let response = get_client()
        .post([CDN_URL, endpoint].concat())
        .header("Authorization", ["Bearer ", CDN_AUTHORIZATION].concat())
        .multipart(Form::new().part("file", Part::bytes(bytes).file_name(filename)))
        .send()
        .await
        .map_err(|e| Error::InternalError {
            what: Some("cdn".to_string()),
            message: format!("Failed to upload image to CDN: {e}"),
            debug: Some(format!("{e:?}")),
        })?;

    let status_code = response.status().as_u16();
    if status_code > 399 {
        let text = response.text().await.unwrap_or_default();

        return Err(Error::InternalError {
            what: Some("cdn".to_string()),
            message: format!("CDN responded with a {status_code} status code: {text}"),
            debug: None,
        });
    }

    response.json().await.map_err(|e| Error::InternalError {
        what: Some("cdn".to_string()),
        message: format!("Failed to deserialize CDN response: {e}"),
        debug: Some(format!("{e:?}")),
    })
}

/// Uploads a user avatar to the CDN and returns its URL.
pub async fn upload_user_avatar(user_id: u64, image_data: &str) -> essence::Result<String> {
    const CHARSET: &[u8] = b"0123456789abdcdef";
    let (bytes, ext) = data_scheme_to_bytes(Some("avatar"), image_data, true, 4_000_000)?;

    let url = upload(
        &format!("/avatars/{user_id}"),
        bytes,
        format!("avatar.{ext}"),
    )
    .await?
    .path;

    Ok([CDN_URL, &url].concat())
}
