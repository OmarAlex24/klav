//! Server configuration: an optional TOML file plus `KLAV_*` environment
//! overrides. Every field has a safe default for self-hosting with SQLite.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use klav_core::crypto::hosted::HostedServicePublic;
use klav_proto::RegistrationMode;
use secrecy::SecretString;
use serde::{Deserialize, Deserializer};
use thiserror::Error;

/// Error while loading the configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The TOML file could not be read.
    #[error("cannot read config file {path}: {source}")]
    Read {
        /// Path of the file.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The TOML file is invalid.
    #[error("invalid config file: {0}")]
    Parse(String),
    /// An environment variable has an invalid value.
    #[error("invalid value for {name}")]
    Env {
        /// Variable name.
        name: &'static str,
    },
    /// A value is out of range.
    #[error("invalid configuration: {0}")]
    Invalid(&'static str),
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// One JSON object per line (default; for production).
    Json,
    /// Human-readable lines (for development).
    Pretty,
}

/// Logging settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// Output format.
    pub format: LogFormat,
    /// `tracing` filter directive, e.g. `info` or `klav_server=debug`.
    pub filter: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Json,
            filter: "info".into(),
        }
    }
}

/// Size limits.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Maximum size of a JSON request body, in bytes.
    pub max_json_body_bytes: usize,
    /// Maximum size of encrypted vault or project metadata, in bytes.
    pub max_meta_bytes: usize,
    /// Maximum size of an item overview section, in bytes.
    pub max_overview_bytes: usize,
    /// Maximum size of an item details section, in bytes.
    pub max_details_bytes: usize,
    /// Previous versions kept per item (older ones are dropped).
    pub max_item_versions: u32,
    /// Maximum size of one encrypted attachment, in bytes.
    pub max_attachment_bytes: u64,
    /// Maximum size of one upload chunk (request body), in bytes.
    pub max_attachment_chunk_bytes: usize,
    /// Declared bytes of unfinished uploads allowed at once in the vaults
    /// of one account (uploads idle for a day are removed).
    pub max_pending_upload_bytes: u64,
    /// Declared bytes of every attachment in the vaults an account owns
    /// that is not purged: finished, pending and those of trashed items
    /// (ADR 0048 §3.1). `0` means unlimited.
    pub max_account_attachment_bytes: u64,
    /// Encrypted bytes in the vaults an account owns, attachments aside:
    /// `overview`, `details` and `wrapped_key` of every item that is not
    /// purged and of its kept versions, plus the `meta` of every vault and
    /// project. `0` means unlimited.
    pub max_account_vault_bytes: u64,
    /// Items that are not purged (trashed ones count) in the vaults an
    /// account owns. `0` means unlimited.
    pub max_items_per_account: u64,
    /// Vaults an account owns, deleted ones too until they are purged.
    /// `0` means unlimited.
    pub max_vaults_per_account: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_json_body_bytes: 4 * 1024 * 1024,
            max_meta_bytes: 64 * 1024,
            max_overview_bytes: 64 * 1024,
            max_details_bytes: 1024 * 1024,
            max_item_versions: 50,
            max_attachment_bytes: 100 * 1024 * 1024,
            max_attachment_chunk_bytes: 8 * 1024 * 1024,
            max_pending_upload_bytes: 1024 * 1024 * 1024,
            // Generous but finite (ADR 0048 §3.1): a server left open by
            // mistake gets a ceiling nobody with a normal vault reaches.
            max_account_attachment_bytes: 10 * 1024 * 1024 * 1024,
            max_account_vault_bytes: 1024 * 1024 * 1024,
            max_items_per_account: 100_000,
            max_vaults_per_account: 1_000,
        }
    }
}

/// How long deleted things are kept before they are purged.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetentionConfig {
    /// Days an item stays in the trash (and a deleted vault stays
    /// restorable) before it is purged for good.
    pub trash_days: u32,
    /// Seconds between purge runs.
    pub purge_interval_secs: u64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            trash_days: 30,
            purge_interval_secs: 3600,
        }
    }
}

/// Rate limits (token buckets; `per_minute` is the refill rate and `burst`
/// the bucket size).
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Every request, per client IP.
    pub ip_per_minute: u32,
    /// Burst allowance per client IP.
    pub ip_burst: u32,
    /// Authentication endpoints (pre-login, sign-up, login, refresh), per IP.
    pub auth_ip_per_minute: u32,
    /// Burst for authentication endpoints, per IP.
    pub auth_ip_burst: u32,
    /// Authentication attempts per account e-mail (any IP).
    pub auth_email_per_minute: u32,
    /// Burst of authentication attempts per account e-mail.
    pub auth_email_burst: u32,
    /// Authenticated requests per account (all devices together).
    pub account_per_minute: u32,
    /// Burst of authenticated requests per account.
    pub account_burst: u32,
    /// Invite attempts per client IP: every `invite/check`, and every
    /// invite failure in `register/start` and `register/finish` (ADR 0048
    /// §1.3). On top of the `auth_*` limits.
    pub invite_ip_per_minute: u32,
    /// Burst of invite attempts per client IP.
    pub invite_ip_burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            ip_per_minute: 600,
            ip_burst: 120,
            auth_ip_per_minute: 30,
            auth_ip_burst: 10,
            auth_email_per_minute: 10,
            auth_email_burst: 5,
            account_per_minute: 1200,
            account_burst: 300,
            invite_ip_per_minute: 1,
            invite_ip_burst: 10,
        }
    }
}

/// Session lifetimes.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionConfig {
    /// Lifetime of an access token, in seconds.
    pub access_ttl_secs: u64,
    /// Lifetime of a refresh token, in seconds (sliding: every refresh
    /// starts a new period).
    pub refresh_ttl_secs: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            access_ttl_secs: 15 * 60,
            refresh_ttl_secs: 30 * 24 * 60 * 60,
        }
    }
}

/// Auto-issued beta invites (ADR 0050): the internal route the site calls
/// to issue a bound, single-use invite for a waitlist email, up to a cap.
///
/// Off unless `auto_max > 0`, `auto_token` is set and the server is in
/// `invite` mode. `Debug` is written by hand: the token prints redacted.
#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InvitesConfig {
    /// The shared bearer secret of `POST /v1/internal/invites/auto`, at
    /// least [`MIN_AUTO_INVITE_TOKEN_BYTES`] bytes (`KLAV_AUTO_INVITE_TOKEN`).
    /// Never logged.
    #[serde(deserialize_with = "secret_string")]
    pub auto_token: Option<SecretString>,
    /// How many auto-issued invites may exist at once, not counting revoked
    /// ones (`KLAV_AUTO_INVITE_MAX`). `0`, the default, turns the route off.
    pub auto_max: u64,
}

/// Shortest accepted auto-invite token, in bytes (ADR 0050 §2.1).
pub const MIN_AUTO_INVITE_TOKEN_BYTES: usize = 32;

impl InvitesConfig {
    /// The token, if auto-issued invites can be on at all.
    pub fn auto_enabled(&self) -> bool {
        self.auto_max > 0 && self.auto_token.is_some()
    }
}

impl std::fmt::Debug for InvitesConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvitesConfig")
            .field(
                "auto_token",
                &self.auto_token.as_ref().map(|_| "[redacted]"),
            )
            .field("auto_max", &self.auto_max)
            .finish()
    }
}

/// Klav Cloud's hosted proxy (ADR 0051 §8). Unset, the default and what
/// every self-hosted server keeps, refuses every hosted registration and
/// changes nothing else.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostedProxyConfig {
    /// The Ed25519 public key of the enclave's service key, as 64 hex
    /// digits (`KLAV_HOSTED_PROXY_SERVICE_KEY`). Not a secret.
    pub service_key: Option<String>,
}

impl HostedProxyConfig {
    /// The service key, if one is configured and valid ([`Config::load`]
    /// refuses an invalid one).
    pub fn key(&self) -> Option<HostedServicePublic> {
        self.service_key
            .as_deref()
            .and_then(|k| HostedServicePublic::from_hex(k).ok())
    }
}

/// Push notifications for approvals (ADR 0018 §5). Without `apns`, the
/// server sends nothing and everything else works as before.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PushConfig {
    /// Apple Push Notification service (token-based, `.p8`).
    pub apns: Option<ApnsConfig>,
}

/// APNs with a token signing key (`.p8`) from the Apple Developer account.
///
/// The key comes from exactly one of `key_path` (a file) or `key` (its PEM
/// contents, for hosts without file secrets). `Debug` is safe: `key` is a
/// [`SecretString`] and prints redacted.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApnsConfig {
    /// The `.p8` file (PKCS#8 P-256 key). Read once at start-up; its
    /// contents are never logged.
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    /// The `.p8` contents (PEM), instead of `key_path`. Never logged.
    #[serde(default, deserialize_with = "secret_string")]
    pub key: Option<SecretString>,
    /// Its key ID (10 characters, shown next to the key in the account).
    pub key_id: String,
    /// The Apple team ID.
    pub team_id: String,
    /// The app's bundle ID (`apns-topic`).
    pub topic: String,
    /// Sends every push to this base URL instead of Apple's (mock APNs in
    /// in-process tests). Not settable from the file or the environment.
    #[doc(hidden)]
    #[serde(skip)]
    pub endpoint_override: Option<String>,
}

/// Full server configuration.
///
/// `Debug` is written by hand: `database_url` can carry the database
/// password (`postgres://user:password@host/db`) and prints redacted.
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Address to listen on.
    pub listen: SocketAddr,
    /// `sqlite://…` or `postgres://…`.
    pub database_url: String,
    /// Directory for server data (attachments; the SQLite file by default).
    pub data_dir: PathBuf,
    /// Use the rightmost `X-Forwarded-For` address as the client IP. Enable
    /// only behind a reverse proxy that sets the header.
    pub trust_forwarded_for: bool,
    /// Take the client IP from this header (e.g. `x-real-ip` on Railway),
    /// which the reverse proxy in front sets to the client address,
    /// replacing whatever the client sent. Off by default: no header is
    /// trusted. Excludes `trust_forwarded_for`.
    pub trusted_ip_header: Option<String>,
    /// The old switch for new accounts: `true` is `open` and `false` is
    /// `closed`. Set with `registration_mode`, the two must agree, and
    /// `false` agrees with `invite` too (ADR 0048 §1.1). Read the
    /// effective mode with [`Config::registration_mode`].
    pub allow_registration: Option<bool>,
    /// How new accounts are taken: `open`, `invite` or `closed` (ADR 0048
    /// §1.1). Unset, it follows `allow_registration`, and with neither
    /// set it is `open`.
    pub registration_mode: Option<RegistrationMode>,
    /// Session lifetimes.
    pub sessions: SessionConfig,
    /// Trash and purge.
    pub retention: RetentionConfig,
    /// Logging.
    pub log: LogConfig,
    /// Size limits.
    pub limits: Limits,
    /// Rate limits.
    pub rate_limit: RateLimitConfig,
    /// Push notifications.
    pub push: PushConfig,
    /// Auto-issued beta invites (ADR 0050).
    pub invites: InvitesConfig,
    /// Klav Cloud's hosted proxy (ADR 0051 §8).
    pub hosted_proxy: HostedProxyConfig,
    /// Accept Argon2id parameters below the production floor at sign-up.
    ///
    /// **Only for in-process test suites**, which use reduced parameters to
    /// stay fast. It cannot be set from the TOML file or the environment, so
    /// a deployed server always enforces the floor (ADR 0010).
    #[doc(hidden)]
    #[serde(skip)]
    pub insecure_accept_weak_kdf: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            database_url: "sqlite://data/klav.db".into(),
            data_dir: PathBuf::from("data"),
            trust_forwarded_for: false,
            trusted_ip_header: None,
            allow_registration: None,
            registration_mode: None,
            sessions: SessionConfig::default(),
            retention: RetentionConfig::default(),
            log: LogConfig::default(),
            limits: Limits::default(),
            rate_limit: RateLimitConfig::default(),
            push: PushConfig::default(),
            invites: InvitesConfig::default(),
            hosted_proxy: HostedProxyConfig::default(),
            insecure_accept_weak_kdf: false,
        }
    }
}

impl Config {
    /// Loads the configuration: defaults, then the TOML file at `path` (if
    /// any), then overrides from `env` (`KLAV_*` variables).
    ///
    /// `env` is passed in (normally `std::env::vars()`) so tests never have to
    /// mutate the process environment.
    pub fn load(
        path: Option<&Path>,
        env: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ConfigError> {
        let mut config = match path {
            Some(path) => {
                let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
                    path: path.to_path_buf(),
                    source,
                })?;
                Self::from_toml(&text)?
            }
            None => Self::default(),
        };
        config.apply_env(env)?;
        config.validate()?;
        Ok(config)
    }

    /// Parses a TOML document (missing keys take their defaults).
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|e| ConfigError::Parse(e.message().to_owned()))
    }

    fn apply_env(
        &mut self,
        env: impl IntoIterator<Item = (String, String)>,
    ) -> Result<(), ConfigError> {
        let mut apns: [Option<String>; 4] = Default::default();
        let mut apns_key: Option<SecretString> = None;
        for (key, value) in env {
            match key.as_str() {
                "KLAV_LISTEN" => self.listen = parse(&value, "KLAV_LISTEN")?,
                "KLAV_DATABASE_URL" => self.database_url = value,
                "KLAV_DATA_DIR" => self.data_dir = PathBuf::from(value),
                "KLAV_TRUST_FORWARDED_FOR" => {
                    self.trust_forwarded_for = parse_bool(&value, "KLAV_TRUST_FORWARDED_FOR")?
                }
                "KLAV_TRUSTED_IP_HEADER" => {
                    // Empty means "none", so a template can leave it blank.
                    self.trusted_ip_header = Some(value).filter(|v| !v.trim().is_empty());
                }
                "KLAV_ALLOW_REGISTRATION" => {
                    self.allow_registration = Some(parse_bool(&value, "KLAV_ALLOW_REGISTRATION")?)
                }
                "KLAV_REGISTRATION_MODE" => {
                    // Empty means "unset", so a template can leave it blank.
                    self.registration_mode = match value.trim() {
                        "" => None,
                        "open" => Some(RegistrationMode::Open),
                        "invite" => Some(RegistrationMode::Invite),
                        "closed" => Some(RegistrationMode::Closed),
                        _ => {
                            return Err(ConfigError::Env {
                                name: "KLAV_REGISTRATION_MODE",
                            });
                        }
                    }
                }
                "KLAV_MAX_ACCOUNT_ATTACHMENT_BYTES" => {
                    self.limits.max_account_attachment_bytes =
                        parse(&value, "KLAV_MAX_ACCOUNT_ATTACHMENT_BYTES")?
                }
                "KLAV_MAX_ACCOUNT_VAULT_BYTES" => {
                    self.limits.max_account_vault_bytes =
                        parse(&value, "KLAV_MAX_ACCOUNT_VAULT_BYTES")?
                }
                "KLAV_MAX_ITEMS_PER_ACCOUNT" => {
                    self.limits.max_items_per_account = parse(&value, "KLAV_MAX_ITEMS_PER_ACCOUNT")?
                }
                "KLAV_MAX_VAULTS_PER_ACCOUNT" => {
                    self.limits.max_vaults_per_account =
                        parse(&value, "KLAV_MAX_VAULTS_PER_ACCOUNT")?
                }
                "KLAV_AUTO_INVITE_TOKEN" => {
                    // Empty means "unset", so a template can leave it blank.
                    self.invites.auto_token = Some(value)
                        .filter(|v| !v.is_empty())
                        .map(SecretString::from);
                }
                "KLAV_AUTO_INVITE_MAX" => {
                    self.invites.auto_max = if value.trim().is_empty() {
                        0
                    } else {
                        parse(value.trim(), "KLAV_AUTO_INVITE_MAX")?
                    }
                }
                "KLAV_HOSTED_PROXY_SERVICE_KEY" => {
                    // Empty means "unset", so a template can leave it blank.
                    self.hosted_proxy.service_key =
                        Some(value.trim().to_owned()).filter(|v| !v.is_empty());
                }
                "KLAV_LOG_FORMAT" => {
                    self.log.format = match value.as_str() {
                        "json" => LogFormat::Json,
                        "pretty" => LogFormat::Pretty,
                        _ => {
                            return Err(ConfigError::Env {
                                name: "KLAV_LOG_FORMAT",
                            });
                        }
                    }
                }
                "KLAV_LOG" => self.log.filter = value,
                "KLAV_APNS_KEY_PATH" => apns[0] = Some(value),
                "KLAV_APNS_KEY" => apns_key = Some(SecretString::from(value)),
                "KLAV_APNS_KEY_ID" => apns[1] = Some(value),
                "KLAV_APNS_TEAM_ID" => apns[2] = Some(value),
                "KLAV_APNS_TOPIC" => apns[3] = Some(value),
                _ => {}
            }
        }
        if apns.iter().any(Option::is_some) || apns_key.is_some() {
            let [key_path, key_id, team_id, topic] = apns;
            let base = self.push.apns.take();
            if key_path.is_some() && apns_key.is_some() {
                return Err(ConfigError::Invalid(
                    "APNs: set KLAV_APNS_KEY_PATH or KLAV_APNS_KEY, not both",
                ));
            }
            // A key source from the environment replaces the file's.
            let (key_path, key) = match (key_path, apns_key) {
                (None, None) => base
                    .as_ref()
                    .map(|b| (b.key_path.clone(), b.key.clone()))
                    .unwrap_or_default(),
                (path, key) => (path.map(PathBuf::from), key),
            };
            let pick = |env: Option<String>, file: Option<String>| env.or(file);
            let (Some(key_id), Some(team_id), Some(topic), true) = (
                pick(key_id, base.as_ref().map(|b| b.key_id.clone())),
                pick(team_id, base.as_ref().map(|b| b.team_id.clone())),
                pick(topic, base.as_ref().map(|b| b.topic.clone())),
                key_path.is_some() || key.is_some(),
            ) else {
                return Err(ConfigError::Invalid(
                    "APNs needs KLAV_APNS_KEY_PATH or KLAV_APNS_KEY, KLAV_APNS_KEY_ID, KLAV_APNS_TEAM_ID and KLAV_APNS_TOPIC",
                ));
            };
            self.push.apns = Some(ApnsConfig {
                key_path,
                key,
                key_id,
                team_id,
                topic,
                endpoint_override: None,
            });
        }
        Ok(())
    }

    /// The registration mode in effect (ADR 0048 §1.1): `registration_mode`
    /// if set, else `allow_registration` (`true` is `open`, `false` is
    /// `closed`), else `open`. [`Config::load`] has already refused a pair
    /// that disagrees.
    pub fn registration_mode(&self) -> RegistrationMode {
        match (self.registration_mode, self.allow_registration) {
            (Some(RegistrationMode::Unknown), _) => RegistrationMode::Closed,
            (Some(mode), _) => mode,
            (None, Some(false)) => RegistrationMode::Closed,
            (None, _) => RegistrationMode::Open,
        }
    }

    fn validate(&mut self) -> Result<(), ConfigError> {
        match (self.registration_mode, self.allow_registration) {
            (Some(RegistrationMode::Unknown), _) => {
                return Err(ConfigError::Invalid(
                    "registration_mode (KLAV_REGISTRATION_MODE) must be open, invite or closed",
                ));
            }
            (Some(RegistrationMode::Open), Some(false))
            | (Some(RegistrationMode::Invite | RegistrationMode::Closed), Some(true)) => {
                return Err(ConfigError::Invalid(
                    "registration_mode (KLAV_REGISTRATION_MODE) and allow_registration \
                     (KLAV_ALLOW_REGISTRATION) disagree: allow_registration = true goes only \
                     with registration_mode = open, and false with closed or invite",
                ));
            }
            _ => {}
        }
        if let Some(name) = &self.trusted_ip_header {
            let name = name.trim().to_ascii_lowercase();
            if axum::http::HeaderName::from_bytes(name.as_bytes()).is_err() {
                return Err(ConfigError::Invalid(
                    "trusted_ip_header (KLAV_TRUSTED_IP_HEADER) is not a valid header name",
                ));
            }
            if self.trust_forwarded_for {
                return Err(ConfigError::Invalid(
                    "set trusted_ip_header (KLAV_TRUSTED_IP_HEADER) or trust_forwarded_for (KLAV_TRUST_FORWARDED_FOR), not both",
                ));
            }
            self.trusted_ip_header = Some(name);
        }
        if let Some(key) = &self.hosted_proxy.service_key
            && HostedServicePublic::from_hex(key).is_err()
        {
            return Err(ConfigError::Invalid(
                "hosted_proxy.service_key (KLAV_HOSTED_PROXY_SERVICE_KEY) must be an Ed25519 \
                 public key as 64 hex digits",
            ));
        }
        let l = &self.limits;
        if l.max_json_body_bytes < 1024 {
            return Err(ConfigError::Invalid("limits.max_json_body_bytes < 1024"));
        }
        if l.max_overview_bytes < 64 || l.max_details_bytes < 64 || l.max_meta_bytes < 64 {
            return Err(ConfigError::Invalid(
                "limits: blob limits must be at least 64 bytes",
            ));
        }
        if l.max_attachment_chunk_bytes < 1024 || l.max_attachment_bytes < 1024 {
            return Err(ConfigError::Invalid(
                "limits: attachment limits must be at least 1 KiB",
            ));
        }
        if l.max_pending_upload_bytes < l.max_attachment_bytes {
            return Err(ConfigError::Invalid(
                "limits.max_pending_upload_bytes must be at least max_attachment_bytes",
            ));
        }
        if l.max_account_attachment_bytes != 0
            && l.max_account_attachment_bytes < l.max_attachment_bytes
        {
            return Err(ConfigError::Invalid(
                "limits.max_account_attachment_bytes (KLAV_MAX_ACCOUNT_ATTACHMENT_BYTES) must be 0 \
                 (unlimited) or at least max_attachment_bytes",
            ));
        }
        if self.retention.purge_interval_secs == 0 {
            return Err(ConfigError::Invalid(
                "retention.purge_interval_secs must be positive",
            ));
        }
        let r = &self.rate_limit;
        if [
            r.ip_per_minute,
            r.ip_burst,
            r.auth_ip_per_minute,
            r.auth_ip_burst,
            r.auth_email_per_minute,
            r.auth_email_burst,
            r.account_per_minute,
            r.account_burst,
            r.invite_ip_per_minute,
            r.invite_ip_burst,
        ]
        .contains(&0)
        {
            return Err(ConfigError::Invalid("rate limits must be positive"));
        }
        if let Some(apns) = &self.push.apns {
            if apns.key_path.is_some() == apns.key.is_some() {
                return Err(ConfigError::Invalid(
                    "push.apns: set exactly one of key_path (KLAV_APNS_KEY_PATH) or key (KLAV_APNS_KEY)",
                ));
            }
            let ok = |s: &str, max: usize| {
                !s.is_empty() && s.len() <= max && s.chars().all(|c| c.is_ascii_graphic())
            };
            if !ok(&apns.key_id, 32) || !ok(&apns.team_id, 32) || !ok(&apns.topic, 255) {
                return Err(ConfigError::Invalid(
                    "push.apns: key_id, team_id and topic must be short printable ASCII",
                ));
            }
        }
        if let Some(token) = &self.invites.auto_token {
            use secrecy::ExposeSecret as _;
            if token.expose_secret().len() < MIN_AUTO_INVITE_TOKEN_BYTES {
                return Err(ConfigError::Invalid(
                    "invites.auto_token (KLAV_AUTO_INVITE_TOKEN) must be at least 32 bytes",
                ));
            }
        }
        if self.invites.auto_max > 0 && self.invites.auto_token.is_none() {
            return Err(ConfigError::Invalid(
                "invites.auto_max (KLAV_AUTO_INVITE_MAX) above 0 needs invites.auto_token \
                 (KLAV_AUTO_INVITE_TOKEN)",
            ));
        }
        if self.sessions.access_ttl_secs == 0
            || self.sessions.refresh_ttl_secs < self.sessions.access_ttl_secs
        {
            return Err(ConfigError::Invalid(
                "sessions: access_ttl_secs > 0 and refresh_ttl_secs >= access_ttl_secs",
            ));
        }
        Ok(())
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("listen", &self.listen)
            .field("database_url", &redacted_url(&self.database_url))
            .field("data_dir", &self.data_dir)
            .field("trust_forwarded_for", &self.trust_forwarded_for)
            .field("trusted_ip_header", &self.trusted_ip_header)
            .field("allow_registration", &self.allow_registration)
            .field("registration_mode", &self.registration_mode)
            .field("sessions", &self.sessions)
            .field("retention", &self.retention)
            .field("log", &self.log)
            .field("limits", &self.limits)
            .field("rate_limit", &self.rate_limit)
            .field("push", &self.push)
            .field("invites", &self.invites)
            .field("insecure_accept_weak_kdf", &self.insecure_accept_weak_kdf)
            .finish()
    }
}

/// A database URL without its credentials and query (which can carry a
/// password too): `postgres://[redacted]@host:5432/db`.
fn redacted_url(url: &str) -> String {
    let url = url.split_once('?').map_or(url, |(base, _)| base);
    match url.split_once("://") {
        Some((scheme, rest)) => match rest.rsplit_once('@') {
            Some((_, host)) => format!("{scheme}://[redacted]@{host}"),
            None => format!("{scheme}://{rest}"),
        },
        None => "[redacted]".into(),
    }
}

/// Deserializes an optional string straight into a [`SecretString`].
fn secret_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<SecretString>, D::Error> {
    Ok(Option::<String>::deserialize(d)?.map(SecretString::from))
}

fn parse<T: std::str::FromStr>(value: &str, name: &'static str) -> Result<T, ConfigError> {
    value.parse().map_err(|_| ConfigError::Env { name })
}

fn parse_bool(value: &str, name: &'static str) -> Result<bool, ConfigError> {
    match value {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => Err(ConfigError::Env { name }),
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn hosted_proxy_service_key_is_optional_and_checked() {
        use klav_core::crypto::identity::IdentityKeyPair;

        // Unset by default and when blank: every hosted registration is
        // refused, nothing else changes.
        assert!(
            Config::load(None, env(&[]))
                .unwrap()
                .hosted_proxy
                .key()
                .is_none()
        );
        let c = Config::load(None, env(&[("KLAV_HOSTED_PROXY_SERVICE_KEY", " ")])).unwrap();
        assert!(c.hosted_proxy.key().is_none());
        let public = HostedServicePublic::of(IdentityKeyPair::generate().public()).unwrap();
        let text = data_encoding::HEXLOWER.encode(&public.to_bytes());
        let c = Config::load(None, env(&[("KLAV_HOSTED_PROXY_SERVICE_KEY", &text)])).unwrap();
        assert_eq!(c.hosted_proxy.key(), Some(public));
        // A malformed key is refused at start-up, never taken as unset.
        for bad in [&text[..62], "zz", &format!("{text}00")] {
            assert!(
                Config::load(None, env(&[("KLAV_HOSTED_PROXY_SERVICE_KEY", bad)])).is_err(),
                "{bad}"
            );
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.toml");
        std::fs::write(&path, format!("[hosted_proxy]\nservice_key = \"{text}\"\n")).unwrap();
        let c = Config::load(Some(&path), env(&[])).unwrap();
        assert_eq!(c.hosted_proxy.key(), Some(public));
        std::fs::write(&path, "[hosted_proxy]\nservice_key = \"00\"\n").unwrap();
        assert!(Config::load(Some(&path), env(&[])).is_err());
    }

    #[test]
    fn defaults_are_valid() {
        let config = Config::load(None, env(&[])).unwrap();
        assert_eq!(config.listen.port(), 8080);
        assert!(config.database_url.starts_with("sqlite:"));
        assert_eq!(config.log.format, LogFormat::Json);
    }

    #[test]
    fn toml_then_env_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("klav.toml");
        std::fs::write(
            &path,
            "listen = \"0.0.0.0:9000\"\n[limits]\nmax_json_body_bytes = 2048\n[log]\nformat = \"pretty\"\n",
        )
        .unwrap();
        let config = Config::load(
            Some(&path),
            env(&[
                ("KLAV_DATABASE_URL", "postgres://db/klav"),
                ("KLAV_TRUST_FORWARDED_FOR", "true"),
                ("KLAV_ALLOW_REGISTRATION", "0"),
                ("UNRELATED", "x"),
            ]),
        )
        .unwrap();
        assert_eq!(config.listen.port(), 9000);
        assert_eq!(config.limits.max_json_body_bytes, 2048);
        assert_eq!(config.log.format, LogFormat::Pretty);
        assert_eq!(config.database_url, "postgres://db/klav");
        assert!(config.trust_forwarded_for);
        assert_eq!(config.registration_mode(), RegistrationMode::Closed);
    }

    #[test]
    fn apns_comes_from_the_file_or_the_environment() {
        assert!(Config::default().push.apns.is_none());
        let config = Config::load(
            None,
            env(&[
                ("KLAV_APNS_KEY_PATH", "/run/secrets/AuthKey.p8"),
                ("KLAV_APNS_KEY_ID", "ABC123DEFG"),
                ("KLAV_APNS_TEAM_ID", "SZ3F58F8LX"),
                ("KLAV_APNS_TOPIC", "dev.klav.ios"),
            ]),
        )
        .unwrap();
        let apns = config.push.apns.unwrap();
        assert_eq!(apns.key_id, "ABC123DEFG");
        assert_eq!(apns.topic, "dev.klav.ios");
        assert!(apns.endpoint_override.is_none());
        // Half a configuration is an error, not a silent "no pushes".
        assert!(Config::load(None, env(&[("KLAV_APNS_KEY_ID", "ABC123DEFG")])).is_err());
        // The file can hold it and the environment override one value.
        let file = Config::from_toml(
            "[push.apns]\nkey_path = \"k.p8\"\nkey_id = \"K\"\nteam_id = \"T\"\ntopic = \"a.b\"\n",
        )
        .unwrap();
        assert_eq!(file.push.apns.unwrap().team_id, "T");
        assert!(Config::from_toml("[push.apns]\nendpoint_override = \"http://x\"\n").is_err());
    }

    #[test]
    fn the_apns_key_can_come_from_a_variable_but_not_from_two_places() {
        let pem = "-----BEGIN PRIVATE KEY-----\nS3NTINELpemBODY\n-----END PRIVATE KEY-----\n";
        let rest = [
            ("KLAV_APNS_KEY_ID", "ABC123DEFG"),
            ("KLAV_APNS_TEAM_ID", "SZ3F58F8LX"),
            ("KLAV_APNS_TOPIC", "dev.klav.ios"),
        ];
        let mut vars = rest.to_vec();
        vars.push(("KLAV_APNS_KEY", pem));
        let config = Config::load(None, env(&vars)).unwrap();
        let apns = config.push.apns.as_ref().unwrap();
        assert!(apns.key_path.is_none());
        assert_eq!(apns.key.as_ref().unwrap().expose_secret(), pem);
        // `Debug` of the whole configuration never shows the key.
        assert!(!format!("{config:?}").contains("S3NTINEL"));

        // Both sources at once is an error, from the environment or the file.
        vars.push(("KLAV_APNS_KEY_PATH", "/run/secrets/AuthKey.p8"));
        let err = Config::load(None, env(&vars)).unwrap_err().to_string();
        assert!(err.contains("not both"), "{err}");
        assert!(!err.contains("S3NTINEL"));
        let both = "[push.apns]\nkey_path = \"k.p8\"\nkey = \"x\"\nkey_id = \"K\"\nteam_id = \"T\"\ntopic = \"a.b\"\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("klav.toml");
        std::fs::write(&path, both).unwrap();
        assert!(Config::load(Some(&path), env(&[])).is_err());
        // Neither: the three other values alone are half a configuration.
        assert!(Config::load(None, env(&rest)).is_err());

        // A key source in the environment replaces the file's.
        std::fs::write(
            &path,
            "[push.apns]\nkey_path = \"k.p8\"\nkey_id = \"K\"\nteam_id = \"T\"\ntopic = \"a.b\"\n",
        )
        .unwrap();
        let config = Config::load(Some(&path), env(&[("KLAV_APNS_KEY", pem)])).unwrap();
        let apns = config.push.apns.unwrap();
        assert!(apns.key_path.is_none() && apns.key.is_some());
        assert_eq!(apns.key_id, "K");
        // And the file can hold the contents too.
        std::fs::write(
            &path,
            "[push.apns]\nkey = \"x\"\nkey_id = \"K\"\nteam_id = \"T\"\ntopic = \"a.b\"\n",
        )
        .unwrap();
        assert!(
            Config::load(Some(&path), env(&[]))
                .unwrap()
                .push
                .apns
                .unwrap()
                .key
                .is_some()
        );
    }

    #[test]
    fn debug_never_shows_the_database_password() {
        let config = Config::load(
            None,
            env(&[(
                "KLAV_DATABASE_URL",
                "postgres://klav:S3NTINEL-pw@db.internal:5432/klav?password=S3NTINEL-q",
            )]),
        )
        .unwrap();
        let shown = format!("{config:?}");
        assert!(!shown.contains("S3NTINEL"), "{shown}");
        assert!(shown.contains("db.internal:5432/klav"), "{shown}");
        assert_eq!(
            redacted_url("sqlite:///data/klav.db"),
            "sqlite:///data/klav.db"
        );
        assert_eq!(redacted_url("garbage"), "[redacted]");
    }

    #[test]
    fn a_trusted_ip_header_is_opt_in_and_exclusive() {
        assert!(Config::default().trusted_ip_header.is_none());
        let config = Config::load(None, env(&[("KLAV_TRUSTED_IP_HEADER", "X-Real-IP")])).unwrap();
        assert_eq!(config.trusted_ip_header.as_deref(), Some("x-real-ip"));
        // Blank is "none" (a template can leave it empty).
        let config = Config::load(None, env(&[("KLAV_TRUSTED_IP_HEADER", " ")])).unwrap();
        assert!(config.trusted_ip_header.is_none());
        assert!(Config::load(None, env(&[("KLAV_TRUSTED_IP_HEADER", "bad header")])).is_err());
        let err = Config::load(
            None,
            env(&[
                ("KLAV_TRUSTED_IP_HEADER", "x-real-ip"),
                ("KLAV_TRUST_FORWARDED_FOR", "true"),
            ]),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not both"), "{err}");
        assert_eq!(
            Config::from_toml("trusted_ip_header = \"x-real-ip\"")
                .unwrap()
                .trusted_ip_header
                .as_deref(),
            Some("x-real-ip")
        );
    }

    #[test]
    fn the_kdf_floor_cannot_be_disabled_by_configuration() {
        assert!(!Config::default().insecure_accept_weak_kdf);
        assert!(Config::from_toml("insecure_accept_weak_kdf = true").is_err());
        let config = Config::load(None, env(&[("KLAV_INSECURE_ACCEPT_WEAK_KDF", "true")])).unwrap();
        assert!(!config.insecure_accept_weak_kdf);
    }

    #[test]
    fn auto_invites_are_off_by_default_and_need_a_long_token() {
        let token = "t".repeat(MIN_AUTO_INVITE_TOKEN_BYTES);
        let c = Config::load(None, env(&[])).unwrap();
        assert_eq!(c.invites.auto_max, 0);
        assert!(c.invites.auto_token.is_none());
        assert!(!c.invites.auto_enabled());
        // Blank values are unset, as a template leaves them.
        let c = Config::load(
            None,
            env(&[("KLAV_AUTO_INVITE_TOKEN", ""), ("KLAV_AUTO_INVITE_MAX", "")]),
        )
        .unwrap();
        assert!(!c.invites.auto_enabled());
        let c = Config::load(
            None,
            env(&[
                ("KLAV_AUTO_INVITE_TOKEN", &token),
                ("KLAV_AUTO_INVITE_MAX", "50"),
            ]),
        )
        .unwrap();
        assert_eq!(c.invites.auto_max, 50);
        assert!(c.invites.auto_enabled());
        assert_eq!(
            c.invites.auto_token.as_ref().unwrap().expose_secret(),
            token
        );
        // The token never prints.
        assert!(!format!("{c:?}").contains(&token));
        // A token alone (max 0) is allowed and stays off.
        let c = Config::load(None, env(&[("KLAV_AUTO_INVITE_TOKEN", &token)])).unwrap();
        assert!(!c.invites.auto_enabled());
        // Too short, a cap without a token, a cap that isn't a number.
        let short = "t".repeat(MIN_AUTO_INVITE_TOKEN_BYTES - 1);
        assert!(Config::load(None, env(&[("KLAV_AUTO_INVITE_TOKEN", &short)])).is_err());
        assert!(Config::load(None, env(&[("KLAV_AUTO_INVITE_MAX", "1")])).is_err());
        assert!(
            Config::load(
                None,
                env(&[
                    ("KLAV_AUTO_INVITE_TOKEN", &token),
                    ("KLAV_AUTO_INVITE_MAX", "-1")
                ])
            )
            .is_err()
        );
        // And from the file.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.toml");
        std::fs::write(
            &path,
            format!("[invites]\nauto_token = \"{token}\"\nauto_max = 3\n"),
        )
        .unwrap();
        let c = Config::load(Some(&path), env(&[])).unwrap();
        assert_eq!(c.invites.auto_max, 3);
        std::fs::write(&path, "[invites]\nauto_max = 3\n").unwrap();
        assert!(Config::load(Some(&path), env(&[])).is_err());
    }

    #[test]
    fn registration_mode_and_allow_registration_must_agree() {
        use RegistrationMode::{Closed, Invite, Open};
        let mode =
            |pairs: &[(&str, &str)]| Config::load(None, env(pairs)).map(|c| c.registration_mode());
        // The bare binary stays open, as before this setting existed.
        assert_eq!(mode(&[]).unwrap(), Open);
        // Today's production variable alone keeps its meaning.
        assert_eq!(
            mode(&[("KLAV_ALLOW_REGISTRATION", "false")]).unwrap(),
            Closed
        );
        assert_eq!(mode(&[("KLAV_ALLOW_REGISTRATION", "true")]).unwrap(), Open);
        // The mode alone.
        for (text, want) in [("open", Open), ("invite", Invite), ("closed", Closed)] {
            assert_eq!(mode(&[("KLAV_REGISTRATION_MODE", text)]).unwrap(), want);
        }
        assert_eq!(mode(&[("KLAV_REGISTRATION_MODE", " ")]).unwrap(), Open);
        assert!(mode(&[("KLAV_REGISTRATION_MODE", "Invite")]).is_err());
        assert!(mode(&[("KLAV_REGISTRATION_MODE", "waitlist")]).is_err());
        // Both: true only with open; false with closed and with invite.
        let both = |allow: &str, m: &str| {
            mode(&[
                ("KLAV_ALLOW_REGISTRATION", allow),
                ("KLAV_REGISTRATION_MODE", m),
            ])
        };
        assert_eq!(both("true", "open").unwrap(), Open);
        assert_eq!(both("false", "closed").unwrap(), Closed);
        assert_eq!(both("false", "invite").unwrap(), Invite);
        for (allow, m) in [("true", "invite"), ("true", "closed"), ("false", "open")] {
            let err = both(allow, m).unwrap_err().to_string();
            assert!(
                err.contains("KLAV_REGISTRATION_MODE") && err.contains("KLAV_ALLOW_REGISTRATION"),
                "{allow} + {m}: {err}"
            );
        }
        // The same rules across the file and the environment (the
        // environment wins key by key, then the pair is checked).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("klav.toml");
        std::fs::write(
            &path,
            "allow_registration = false\nregistration_mode = \"invite\"\n",
        )
        .unwrap();
        assert_eq!(
            Config::load(Some(&path), env(&[]))
                .unwrap()
                .registration_mode(),
            Invite
        );
        assert!(Config::load(Some(&path), env(&[("KLAV_ALLOW_REGISTRATION", "true")])).is_err());
        assert_eq!(
            Config::load(Some(&path), env(&[("KLAV_REGISTRATION_MODE", "closed")]))
                .unwrap()
                .registration_mode(),
            Closed
        );
        std::fs::write(&path, "registration_mode = \"maybe\"\n").unwrap();
        assert!(Config::load(Some(&path), env(&[])).is_err());
    }

    #[test]
    fn quotas_come_from_the_file_or_the_environment() {
        let d = Config::default().limits;
        assert_eq!(d.max_account_attachment_bytes, 10 << 30);
        assert_eq!(d.max_account_vault_bytes, 1 << 30);
        assert_eq!(d.max_items_per_account, 100_000);
        assert_eq!(d.max_vaults_per_account, 1_000);
        let config = Config::load(
            None,
            env(&[
                ("KLAV_MAX_ACCOUNT_ATTACHMENT_BYTES", "262144000"),
                ("KLAV_MAX_ACCOUNT_VAULT_BYTES", "67108864"),
                ("KLAV_MAX_ITEMS_PER_ACCOUNT", "5000"),
                ("KLAV_MAX_VAULTS_PER_ACCOUNT", "0"),
            ]),
        )
        .unwrap();
        assert_eq!(config.limits.max_account_attachment_bytes, 250 << 20);
        assert_eq!(config.limits.max_account_vault_bytes, 64 << 20);
        assert_eq!(config.limits.max_items_per_account, 5_000);
        assert_eq!(config.limits.max_vaults_per_account, 0);
        // 0 is unlimited; otherwise one allowed attachment must fit.
        assert!(Config::load(None, env(&[("KLAV_MAX_ACCOUNT_ATTACHMENT_BYTES", "0")])).is_ok());
        let err = Config::load(
            None,
            env(&[("KLAV_MAX_ACCOUNT_ATTACHMENT_BYTES", "1048576")]),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("max_attachment_bytes"), "{err}");
        assert!(Config::load(None, env(&[("KLAV_MAX_ITEMS_PER_ACCOUNT", "-1")])).is_err());
        let file = Config::from_toml("[limits]\nmax_vaults_per_account = 20\n").unwrap();
        assert_eq!(file.limits.max_vaults_per_account, 20);
        // The invite bucket has defaults and must be positive.
        let r = Config::default().rate_limit;
        assert_eq!((r.invite_ip_per_minute, r.invite_ip_burst), (1, 10));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("klav.toml");
        std::fs::write(&path, "[rate_limit]\ninvite_ip_burst = 0\n").unwrap();
        assert!(Config::load(Some(&path), env(&[])).is_err());
    }

    #[test]
    fn rejects_unknown_keys_and_bad_values() {
        assert!(Config::from_toml("lisen = \"x\"").is_err());
        assert!(Config::load(None, env(&[("KLAV_LISTEN", "nope")])).is_err());
        assert!(Config::load(None, env(&[("KLAV_LOG_FORMAT", "xml")])).is_err());
        assert!(Config::load(None, env(&[("KLAV_TRUST_FORWARDED_FOR", "maybe")])).is_err());
    }
}
