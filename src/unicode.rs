use crate::cdn::get_client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;

pub const EMOJI_DB: &str = "https://raw.githubusercontent.com/github/gemoji/master/db/emoji.json";
pub const CACHE_PATH: &str = "emoji_cache.json";

pub static EMOJI_LOOKUP: OnceLock<HashMap<String, EmojiData>> = OnceLock::new();

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmojiData {
    pub emoji: String,
    pub description: String,
    pub category: String,
    pub aliases: Vec<String>,
    pub tags: Vec<String>,
    pub unicode_version: String,
    pub ios_version: String,
    pub skin_tones: Option<bool>,
}

async fn get_cached() -> Option<HashMap<String, EmojiData>> {
    let mut file = tokio::fs::read(CACHE_PATH).await.ok()?;
    simd_json::from_slice(&mut file).ok()
}

/// Makes an initial request to the emoji database to cache the emoji data.
pub async fn setup() -> reqwest::Result<()> {
    if let Some(map) = get_cached().await {
        EMOJI_LOOKUP
            .set(map)
            .expect("failed to initialize emoji lookup");
        return Ok(());
    }

    let client = get_client();
    let response: Vec<EmojiData> = client.get(EMOJI_DB).send().await?.json().await?;
    let map = response
        .into_iter()
        .map(|data| (data.emoji.clone(), data))
        .collect();

    if let Err(why) = tokio::fs::write(CACHE_PATH, simd_json::to_vec(&map).unwrap()).await {
        log::warn!("failed to write emoji cache: {why}");
    }
    EMOJI_LOOKUP
        .set(map)
        .expect("failed to initialize emoji lookup");
    Ok(())
}

/// Retrieves a reference to the emoji lookup map.
pub fn get_emoji_lookup() -> &'static HashMap<String, EmojiData> {
    EMOJI_LOOKUP.get().expect("emoji lookup not initialized")
}
