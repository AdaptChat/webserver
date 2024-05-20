use std::{collections::HashMap, mem::MaybeUninit, sync::LazyLock, time::Duration};

use deadqueue::unlimited::Queue;
use essence::{
    db::{get_pool, AuthDbExt},
    Result,
};
use fcm_v1::{
    android::{AndroidConfig, AndroidMessagePriority},
    auth::Authenticator,
    message::{Message, Notification as FCMNotification},
    webpush::{WebpushConfig, WebpushFcmOptions},
    Client, Error,
};
use tokio::{sync::OnceCell, task::JoinHandle};

static FCM_CLIENT: OnceCell<Client> = OnceCell::const_new();
static QUEUE: LazyLock<Queue<NotificationTask>> = LazyLock::new(Queue::new);

#[derive(Debug, Clone, Default)]
pub struct Notification {
    pub title: Option<String>,
    pub body: Option<String>,
    pub icon: Option<String>,
    pub link_to: Option<String>,
}

impl Into<FCMNotification> for Notification {
    fn into(self) -> FCMNotification {
        FCMNotification {
            title: self.title,
            body: self.body,
            image: self.icon,
        }
    }
}

impl Into<Message> for Notification {
    fn into(self) -> Message {
        let icon = self.icon.clone();
        let link_to = self.link_to.clone();

        Message {
            notification: Some(self.into()),
            android: Some(AndroidConfig {
                priority: Some(AndroidMessagePriority::High),
                ..Default::default()
            }),
            webpush: Some(WebpushConfig {
                fcm_options: WebpushFcmOptions {
                    link: link_to,
                    ..Default::default()
                },
                notification: icon.map(|v| HashMap::from([("icon".to_string(), v.into())])),
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

#[derive(Debug)]
struct NotificationTask {
    recipients: Vec<String>,
    msg: Notification,
}

async fn get_client() -> &'static Client {
    FCM_CLIENT
        .get_or_init(|| async {
            let auth = Authenticator::service_account_from_file(
                std::env::var("GOOGLE_APPLICATION_CREDENTIALS")
                    .expect("missing google application credentials"),
            )
            .await
            .expect("failed auth");

            Client::new(auth, "adapt-chat", false, Duration::from_secs(5))
        })
        .await
}

#[allow(clippy::must_use_candidate)]
pub fn start_workers<const N: usize>() -> [JoinHandle<()>; N] {
    let mut handles = MaybeUninit::uninit_array::<N>();
    for handle in &mut handles {
        handle.write(tokio::spawn(worker()));
    }
    // SAFETY: Already wrote to every index.
    unsafe { MaybeUninit::array_assume_init(handles) }
}

pub async fn push_to_user(user_id: u64, notif: Notification) -> Result<()> {
    let keys = get_pool().fetch_push_keys(user_id).await?;

    if !keys.is_empty() {
        QUEUE.push(NotificationTask {
            recipients: keys,
            msg: notif,
        });
    }

    Ok(())
}

pub async fn push_to_users(users: impl AsRef<[u64]> + Send, notif: Notification) -> Result<()> {
    for user_id in users.as_ref() {
        push_to_user(*user_id, notif.clone()).await?;
    }

    Ok(())
}

async fn worker() {
    loop {
        let notif = QUEUE.pop().await;
        info!("pushing notification: {notif:?}");

        let mut message: Message = notif.msg.into();

        for token in notif.recipients {
            message.token = Some(token);

            for tries in 0..=5 {
                if tries != 0 {
                    tokio::time::sleep(Duration::from_millis(tries * 125)).await;
                }
                match get_client().await.send(&message).await {
                    Err(Error::FCM { status_code, body }) => match status_code {
                        400 | 404 => {
                            info!("expired registration key, deleting.");
                            // UNWRAP: message.token is the token variable in this iteration
                            let token = message.token.unwrap();
                            let _ = get_pool().delete_push_key(token).await;
                            break;
                        }
                        429 | 500 | 503 => {
                            warn!("abnormal status {status_code}: {body}, retrying");
                            continue;
                        }
                        _ => {
                            info!("unknown status code {status_code}: {body}, ignoring.");
                            break;
                        }
                    },
                    Err(Error::Timeout) => continue,
                    _ => break,
                }
            }
        }
    }
}
