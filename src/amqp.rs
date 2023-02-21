use bincode::Encode;
use deadpool_lapin::{
    lapin::{
        options::BasicPublishOptions, publisher_confirm::PublisherConfirm, BasicProperties,
        Channel, Error::InvalidChannelState,
    },
    Object, Pool, Runtime,
};
use essence::Error;
use std::sync::OnceLock;
use tokio::sync::RwLock;

pub mod prelude {
    pub use crate::amqp;
    pub use essence::ws::OutboundMessage;
}

/// AMQP connection pool
pub static POOL: OnceLock<Pool> = OnceLock::new();
/// AMQP mono-channel (might change in the future)
pub static CHANNEL: OnceLock<RwLock<Channel>> = OnceLock::new();

/// Connects to the amqp server and registers the pool.
pub async fn connect() -> Result<(), Box<dyn std::error::Error>> {
    let pool = deadpool_lapin::Config {
        url: Some("amqp://127.0.0.1:5672".to_string()),
        ..Default::default()
    }
    .create_pool(Some(Runtime::Tokio1))?;

    CHANNEL
        .set(RwLock::new(pool.get().await?.create_channel().await?))
        .unwrap();
    POOL.set(pool).expect("amqp pool called more than once");
    Ok(())
}

/// Retrieves the amqp channel; panics if it has not been initialized.
pub async fn get_pool() -> Object {
    POOL.get()
        .expect("amqp pool not initialized")
        .get()
        .await
        .expect("unable to get amqp pool")
}

async fn _publish<'a>(
    channel: &'a Channel,
    exchange: &str,
    routing_key: &str,
    payload: &[u8],
) -> Result<PublisherConfirm, deadpool_lapin::lapin::Error> {
    channel
        .basic_publish(
            exchange,
            routing_key,
            BasicPublishOptions::default(),
            payload,
            BasicProperties::default(),
        )
        .await
}

/// Sends a message to the amqp server.
pub async fn publish<T: Encode + Send>(
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

    let shared = CHANNEL.get().expect("amqp channel not initialized");
    let channel = shared.read().await;

    if let Err(mut err) = _publish(&channel, exchange, routing_key, &bytes).await {
        drop(channel);

        if matches!(err, InvalidChannelState(_)) {
            match try {
                let channel = get_pool().await.create_channel().await?;
                _publish(&channel, exchange, routing_key, &bytes).await?;

                *shared.write().await = channel;
                Ok::<_, deadpool_lapin::lapin::Error>(())
            } {
                Ok(_) => return Ok(()),
                Err(why) => err = why,
            }
        }

        return Err(Error::InternalError {
            what: Some("amqp (ws downstream)".to_string()),
            message: format!("unable to publish message: {err}"),
            debug: Some(format!("{err:?}")),
        });
    }

    Ok(())
}

/// Sends a guild-related event to the amqp server.
pub async fn publish_guild_event<T: Encode + Send>(guild_id: u64, event: T) -> essence::Result<()> {
    publish(&guild_id.to_string(), "*", event).await
}

/// Sends a user-related event to the amqp server.
pub async fn publish_user_event<T: Encode + Send>(user_id: u64, event: T) -> essence::Result<()> {
    publish("events", &user_id.to_string(), event).await
}

/// Sends a guild-related event if `guild_id` is `Some`, otherwise fallsback to a user-related
/// event.
pub async fn publish_event<T: Encode + Send>(
    guild_id: Option<u64>,
    user_id: u64,
    event: T,
) -> essence::Result<()> {
    if let Some(guild_id) = guild_id {
        publish_guild_event(guild_id, event).await
    } else {
        publish_user_event(user_id, event).await
    }
}
