use deadpool_lapin::lapin::options::BasicPublishOptions;
use deadpool_lapin::lapin::BasicProperties;
use deadpool_lapin::{lapin::Channel, Object, Pool, Runtime};
use essence::Error;
use serde::Serialize;
use std::sync::OnceLock;

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
pub async fn publish<T: Serialize + Send>(
    channel: &Channel,
    guild_id: Option<u64>,
    data: T,
) -> essence::Result<()> {
    let bytes = rmp_serde::to_vec(&data).map_err(|err| Error::InternalError {
        what: Some("amqp (serialization)".to_string()),
        message: err.to_string(),
        debug: Some(format!("{err:?}")),
    })?;

    channel
        .basic_publish(
            &guild_id
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
            "*",
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
