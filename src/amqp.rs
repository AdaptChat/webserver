use bincode::Encode;
use deadpool_lapin::{
    lapin::{options::BasicPublishOptions, BasicProperties, Channel},
    Object, Pool, Runtime,
};
use essence::Error;
use std::sync::OnceLock;

pub mod prelude {
    pub use crate::amqp;
    pub use essence::ws::OutboundMessage;
}

/// AMQP connection pool
pub static POOL: OnceLock<Pool> = OnceLock::new();

/// Connects to the amqp server and registers the pool.
pub fn connect() -> Result<(), deadpool_lapin::CreatePoolError> {
    let pool = deadpool_lapin::Config {
        url: Some("amqp://127.0.0.1:5672".to_string()),
        ..Default::default()
    }
    .create_pool(Some(Runtime::Tokio1))?;

    POOL.set(pool).expect("amqp pool called more than once");
    Ok(())
}

/// Retrieves the amqp pool; panics if it has not been initialized.
pub async fn get_pool() -> Object {
    POOL.get()
        .expect("amqp pool not initialized")
        .get()
        .await
        .expect("unable to get amqp pool")
}

/// Creates an amqp channel; panics if the amqp pool is not initialized.
pub async fn create_channel() -> essence::Result<Channel> {
    get_pool()
        .await
        .create_channel()
        .await
        .map_err(|err| Error::InternalError {
            what: Some("amqp (ws downstream)".to_string()),
            message: format!("unable to create amqp channel: {err}"),
            debug: Some(format!("{err:?}")),
        })
}

/// Sends a message to the amqp server.
pub async fn publish<T: Encode + Send>(
    channel: &Channel,
    exchange: &str,
    routing_key: &str,
    data: T,
) -> essence::Result<()> {
    let bytes = bincode::encode_to_vec(&data, bincode::config::standard()).map_err(|err| {
        Error::InternalError {
            what: Some("amqp (serialization)".to_string()),
            message: err.to_string(),
            debug: Some(format!("{err:?}")),
        }
    })?;

    channel
        .basic_publish(
            exchange,
            routing_key,
            BasicPublishOptions::default(),
            &bytes,
            BasicProperties::default(),
        )
        .await
        .map_err(|err| Error::InternalError {
            what: Some("amqp (ws downstream)".to_string()),
            message: format!("unable to publish message: {err}"),
            debug: Some(format!("{err:?}")),
        })?;

    Ok(())
}

/// Sends a guild-related event to the amqp server.
pub async fn publish_guild_event<T: Encode + Send>(
    channel: &Channel,
    guild_id: u64,
    event: T,
) -> essence::Result<()> {
    publish(channel, &guild_id.to_string(), "*", event).await
}

/// Sends a user-related event to the amqp server.
pub async fn publish_user_event<T: Encode + Send>(
    channel: &Channel,
    user_id: u64,
    event: T,
) -> essence::Result<()> {
    publish(channel, "events", &user_id.to_string(), event).await
}
