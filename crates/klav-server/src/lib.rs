//! Klav sync server.
//!
//! Zero-knowledge storage for encrypted vaults: the server stores opaque
//! blobs produced by `klav-core` on the clients plus the minimum metadata
//! needed to synchronise them (IDs, versions, revisions, sizes, timestamps).
//! It never decrypts anything and never implements cryptography itself.
//!
//! The HTTP API is documented in `docs/api.md`; deployment in
//! `docs/self-hosting.md`.

use std::future::Future;
use std::net::SocketAddr;

use axum::Router;
use tokio::net::TcpListener;

mod agentauth;
mod audit;
mod config;
mod db;
mod deletion;
mod error;
pub mod hosted_proxy;
mod http;
pub mod invites;
mod keys;
mod logins;
mod pause;
mod purge;
mod push;
mod quota;
mod ratelimit;
mod routes;
mod session;
mod state;
mod storage;
pub mod telemetry;
mod validate;
mod vaultdb;

pub use config::{
    ApnsConfig, Config, ConfigError, HostedProxyConfig, InvitesConfig, Limits, LogConfig,
    LogFormat, MIN_AUTO_INVITE_TOKEN_BYTES, PushConfig, RateLimitConfig, RetentionConfig,
    SessionConfig,
};
pub use db::{AdminDbError, DbError};
pub use keys::KeysError;
pub use purge::PurgeReport;
pub use push::PushError;

use crate::state::AppState;

/// Version of this server.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Error raised while starting the server.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// Database connection or migration failed.
    #[error(transparent)]
    Db(#[from] DbError),
    /// Server keys could not be loaded or created.
    #[error(transparent)]
    Keys(#[from] KeysError),
    /// The data directory could not be created.
    #[error("cannot create data directory: {0}")]
    DataDir(#[source] std::io::Error),
    /// The APNs key could not be loaded.
    #[error(transparent)]
    Push(#[from] PushError),
}

/// A configured server, connected to its database. Clones share the same
/// state.
#[derive(Clone)]
pub struct Server {
    state: AppState,
}

impl Server {
    /// Creates the data directory, connects to the database and runs the
    /// pending migrations.
    pub async fn new(mut config: Config) -> Result<Self, StartupError> {
        std::fs::create_dir_all(&config.data_dir).map_err(StartupError::DataDir)?;
        let pusher = push::Pusher::new(config.push.apns.as_ref())?;
        // The pusher holds the parsed key; the PEM does not stay in the
        // configuration every handler can reach for the life of the process.
        // (The process environment still has `KLAV_APNS_KEY`, if it came
        // from there: docs/self-hosting.md §2.4.)
        if let Some(apns) = config.push.apns.as_mut() {
            apns.key = None;
        }
        let db = db::Db::connect(&config.database_url).await?;
        let keys = keys::load_or_create(&db).await?;
        if pusher.enabled() {
            tracing::info!("APNs push notifications are on");
        }
        Ok(Self {
            state: AppState::new(config, db, keys, pusher),
        })
    }

    /// The HTTP application. Serve it with client addresses
    /// (`into_make_service_with_connect_info::<SocketAddr>`) so per-IP rate
    /// limiting works; [`Server::serve`] does that.
    pub fn router(&self) -> Router {
        http::router(self.state.clone())
    }

    /// Runs one retention pass as if the time were `now_ms` (Unix ms):
    /// deletes the accounts whose deletion is due (ADR 0037), purges items
    /// trashed and vaults deleted more than `retention.trash_days` ago, and
    /// drops dead sessions.
    pub async fn purge_expired(&self, now_ms: i64) -> Result<PurgeReport, PurgeError> {
        purge::purge_expired(&self.state, now_ms)
            .await
            .map_err(|e| PurgeError(format!("{e:?}")))
    }

    /// The purge's step for one account whose deletion it already listed
    /// as due (ADR 0037 §5.2): deletes it if, under its lock, the deletion
    /// is still asked for and due at `now_ms`. `false` when a cancel came
    /// first. For tests that put a cancel between the listing and the
    /// step; [`Server::purge_expired`] is what runs in production.
    #[doc(hidden)]
    pub async fn purge_account(
        &self,
        account: klav_core::ids::AccountId,
        now_ms: i64,
    ) -> Result<bool, PurgeError> {
        deletion::delete_account(&self.state, account, now_ms)
            .await
            .map_err(|e| PurgeError(format!("{e:?}")))
    }

    /// Serves on `listener` until `shutdown` completes. Also runs the
    /// retention purge every `retention.purge_interval_secs`.
    pub async fn serve(
        self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> std::io::Result<()> {
        let app = self.router();
        let purger = tokio::spawn(purge_loop(self.state.clone()));
        let result = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown)
        .await;
        purger.abort();
        result
    }
}

/// A retention pass failed (details are in the log).
#[derive(Debug, thiserror::Error)]
#[error("purge failed: {0}")]
pub struct PurgeError(String);

async fn purge_loop(state: AppState) {
    let period = std::time::Duration::from_secs(state.config().retention.purge_interval_secs);
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        if let Err(e) = purge::purge_expired(&state, db::now_ms()).await {
            tracing::error!(error = ?e, "purge failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
    use data_encoding::BASE64;
    use secrecy::SecretString;

    use super::*;

    #[tokio::test]
    async fn the_apns_key_does_not_stay_in_the_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            BASE64.encode(pkcs8.as_ref())
        );
        let config = Config {
            database_url: format!("sqlite://{}", dir.path().join("klav.db").display()),
            data_dir: dir.path().join("data"),
            push: PushConfig {
                apns: Some(ApnsConfig {
                    key_path: None,
                    key: Some(SecretString::from(pem)),
                    key_id: "KEY1234567".into(),
                    team_id: "TEAM123456".into(),
                    topic: "dev.klav.ios".into(),
                    endpoint_override: None,
                }),
            },
            ..Config::default()
        };
        let server = Server::new(config).await.unwrap();
        assert!(
            server
                .state
                .config()
                .push
                .apns
                .as_ref()
                .unwrap()
                .key
                .is_none()
        );
    }
}
