#![allow(clippy::used_underscore_items)]

use bincode::Encode;
use deadpool_lapin::{
    lapin::{
        options::{BasicPublishOptions, ExchangeDeclareOptions},
        publisher_confirm::PublisherConfirm,
        types::FieldTable,
        BasicProperties, Channel,
        Error::{self as LapinError, InvalidChannelState},
        ExchangeKind,
    },
    Object, Pool, Runtime,
};
use essence::Error;
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use tokio::sync::RwLock;

pub mod prelude {
    pub use crate::amqp;
    pub use essence::ws::{MemberRemoveInfo, OutboundMessage};
}

/// AMQP connection pool
pub static POOL: OnceLock<Pool> = OnceLock::new();
/// AMQP mono-channel (might change in the future)
pub static CHANNEL: OnceLock<RwLock<Channel>> = OnceLock::new();
/// Exchanges which have already been declared.
static DECLARED_EXCHANGES: Mutex<Option<HashSet<String>>> = Mutex::new(None);

/// Connects to the amqp server and registers the pool.
pub async fn connect() -> Result<(), Box<dyn std::error::Error>> {
    let pool = deadpool_lapin::Config {
        url: std::env::var("AMQP_URL").ok(),
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

fn is_exchange_declared(exchange: &str) -> bool {
    let mut guard = DECLARED_EXCHANGES.lock().unwrap();
    let set = guard.get_or_insert_with(HashSet::new);
    !set.insert(exchange.to_string())
}

async fn ensure_exchange_declared(
    channel: &Channel,
    exchange: &str,
    kind: ExchangeKind,
) -> Result<(), LapinError> {
    if !is_exchange_declared(exchange) {
        channel
            .exchange_declare(
                exchange,
                kind,
                ExchangeDeclareOptions {
                    auto_delete: false,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await?;
    }
    Ok(())
}

async fn _publish(
    channel: &Channel,
    exchange: &str,
    kind: ExchangeKind,
    routing_key: &str,
    payload: &[u8],
) -> Result<PublisherConfirm, LapinError> {
    ensure_exchange_declared(channel, exchange, kind).await?;

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
    kind: ExchangeKind,
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

    macro_rules! publish {
        ($channel:expr) => {
            _publish($channel, exchange, kind.clone(), routing_key, &bytes).await
        };
    }

    if let Err(mut err) = publish!(&channel) {
        drop(channel);

        if matches!(err, InvalidChannelState(_)) {
            // channel died, reset exchanges
            {
                let mut guard = DECLARED_EXCHANGES.lock().unwrap();
                if let Some(set) = guard.as_mut() {
                    set.clear();
                }
            }
            match try {
                let channel = get_pool().await.create_channel().await?;
                publish!(&channel)?;

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

/// Sends a guild-related or DM channel-related event to the amqp server.
pub async fn publish_bulk_event<T: Encode + Send>(
    exchange_id: u64,
    event: T,
) -> essence::Result<()> {
    publish(&exchange_id.to_string(), ExchangeKind::Topic, "all", event).await
}

/// Sends a user-related event to the amqp server.
pub async fn publish_user_event<T: Encode + Send>(user_id: u64, event: T) -> essence::Result<()> {
    publish("events", ExchangeKind::Topic, &user_id.to_string(), event).await
}

/// Sends a bulk event if `exchange_id` is `Some`, otherwise fallsback to a user-related event.
pub async fn publish_event<T: Encode + Send>(
    exchange_id: Option<u64>,
    user_id: u64,
    event: T,
) -> essence::Result<()> {
    if let Some(exchange_id) = exchange_id {
        publish_bulk_event(exchange_id, event).await
    } else {
        publish_user_event(user_id, event).await
    }
}
