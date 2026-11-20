//! Push notifications for approvals (ADR 0018 §5).
//!
//! When an agent asks for something the policy sets to `ask`, asks for a
//! task (ADR 0021 §8), or a new agent asks to register, the server tells the account's phones through
//! APNs. The payload carries **no text and no secrets**: a localisation key
//! the app turns into its own words, the kind of request and its ID. The
//! app fetches the details from this server when the person opens it.
//!
//! The deletion of the account (ADR 0037 §5.4) is told the same way, with
//! three keys (asked, canceled, done) and `type: "account"` without an ID.
//!
//! APNs uses token-based authentication: a JWT signed with ES256 by the
//! team's `.p8` key. The signature uses `aws-lc-rs`, the provider already
//! approved for TLS (ADR 0011): this is transport authentication, not vault
//! cryptography, and stays out of `klav-core`.
//!
//! Tokens are never logged (only device IDs), and failures never reach
//! the request that caused the push: sending runs in its own task.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use data_encoding::{BASE64, BASE64URL_NOPAD};
use klav_core::ids::AccountId;
use klav_proto::auth::PushEnvironment;
use klav_proto::task::TASK_DECIDE_TTL_MS;
use secrecy::ExposeSecret;
use serde_json::json;
use sqlx::Row;

use crate::config::ApnsConfig;
use crate::db::{Db, now_ms};
use crate::routes::agent_access::APPROVAL_TTL_MS;
use crate::routes::agents::PENDING_TTL_MS;

/// Apple's endpoints.
const PRODUCTION: &str = "https://api.push.apple.com";
const SANDBOX: &str = "https://api.sandbox.push.apple.com";
/// A provider token is reused for this long (Apple: 20 to 60 minutes).
const JWT_LIFETIME_SECS: i64 = 40 * 60;
/// At most this many registration pushes per account and hour: anyone who
/// knows the e-mail can ask to register an agent.
const REGISTRATION_PUSHES_PER_HOUR: usize = 5;
/// At most this many approval pushes per account and hour (each agent
/// already has at most 10 pending requests; this bounds several agents).
const APPROVAL_PUSHES_PER_HOUR: usize = 60;
/// At most this many task pushes per account and hour.
const TASK_PUSHES_PER_HOUR: usize = 30;
/// At most this many pushes of each account-deletion kind per account and
/// hour (asking is already limited to 3 a week; canceling is not).
const ACCOUNT_PUSHES_PER_HOUR: usize = 10;
/// Account notices stay in APNs for the deletion's delay: a phone that was
/// off for days still learns that its account is going.
const ACCOUNT_PUSH_TTL_SECS: i64 = crate::deletion::DELETION_DELAY_MS / 1000;

/// Why the push is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PushKind {
    /// An `ask` approval is waiting (the ID is the approval's).
    Approval,
    /// An agent asks to register (the ID is the agent's).
    Agent,
    /// An agent asks for a task (ADR 0021 §8; the ID is the task's).
    Task,
    /// The person asked to delete the account (ADR 0037 §5.4; no ID).
    AccountDeletion,
    /// The deletion was canceled (no ID).
    AccountCanceled,
    /// The account was deleted (no ID). Sent to the tokens read before the
    /// deletion, which removes them.
    AccountDeleted,
}

impl PushKind {
    fn name(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::Agent => "agent",
            Self::Task => "task",
            Self::AccountDeletion | Self::AccountCanceled | Self::AccountDeleted => "account",
        }
    }

    /// Whether the push is about the account itself (no ID).
    fn is_account(self) -> bool {
        matches!(
            self,
            Self::AccountDeletion | Self::AccountCanceled | Self::AccountDeleted
        )
    }

    /// Pushes of this kind each account may get per hour.
    fn hourly_budget(self) -> usize {
        match self {
            Self::Approval => APPROVAL_PUSHES_PER_HOUR,
            Self::Agent => REGISTRATION_PUSHES_PER_HOUR,
            Self::Task => TASK_PUSHES_PER_HOUR,
            Self::AccountDeletion | Self::AccountCanceled | Self::AccountDeleted => {
                ACCOUNT_PUSHES_PER_HOUR
            }
        }
    }

    fn loc_keys(self) -> (&'static str, &'static str) {
        match self {
            Self::Approval => ("PUSH_APPROVAL_TITLE", "PUSH_APPROVAL_BODY"),
            Self::Agent => ("PUSH_AGENT_TITLE", "PUSH_AGENT_BODY"),
            Self::Task => ("PUSH_TASK_TITLE", "PUSH_TASK_BODY"),
            Self::AccountDeletion => ("PUSH_ACCOUNT_DELETION_TITLE", "PUSH_ACCOUNT_DELETION_BODY"),
            Self::AccountCanceled => ("PUSH_ACCOUNT_CANCELED_TITLE", "PUSH_ACCOUNT_CANCELED_BODY"),
            Self::AccountDeleted => ("PUSH_ACCOUNT_DELETED_TITLE", "PUSH_ACCOUNT_DELETED_BODY"),
        }
    }
}

/// The JSON payload of a push: localisation keys, kind and ID only (no
/// ID for the account's own notices).
pub(crate) fn payload(kind: PushKind, id: &str) -> serde_json::Value {
    let (title, body) = kind.loc_keys();
    let klav = if kind.is_account() {
        json!({ "type": kind.name() })
    } else {
        json!({ "type": kind.name(), "id": id })
    };
    json!({
        "aps": {
            "alert": { "title-loc-key": title, "loc-key": body },
            "sound": "default",
            "thread-id": kind.name(),
        },
        "klav": klav,
    })
}

/// A phone to tell: its device, APNs token and environment. The token is
/// a delivery address, never logged (so no `Debug`).
pub(crate) struct Phone {
    device: String,
    token: String,
    environment: PushEnvironment,
}

/// The phones of `account`'s devices that are not revoked.
pub(crate) async fn phones<'e, E>(exec: E, account: AccountId) -> Result<Vec<Phone>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    let rows = sqlx::query(
        "SELECT p.device_id, p.token, p.environment FROM push_tokens p \
         JOIN devices d ON d.id = p.device_id \
         WHERE p.account_id = $1 AND d.revoked_at IS NULL",
    )
    .bind(account.to_string())
    .fetch_all(exec)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(Phone {
                device: row.try_get("device_id")?,
                token: row.try_get("token")?,
                environment: PushEnvironment::parse(&row.try_get::<String, _>("environment")?)
                    .unwrap_or(PushEnvironment::Production),
            })
        })
        .collect()
}

/// Error loading the APNs key.
#[derive(Debug, thiserror::Error)]
pub enum PushError {
    /// The `.p8` file could not be read.
    #[error("cannot read the APNs key file {0}")]
    Read(String),
    /// The key (file or `KLAV_APNS_KEY`) is not a PKCS#8 P-256 key.
    #[error("the APNs key is not a PKCS#8 P-256 private key (.p8)")]
    Key,
    /// The HTTP client for APNs could not start (e.g. no CA roots).
    #[error("cannot start the APNs HTTP client: {0}")]
    Http(String),
}

/// Signs APNs provider tokens (JWT, ES256) and caches the current one.
struct Signer {
    key: EcdsaKeyPair,
    key_id: String,
    team_id: String,
    rng: SystemRandom,
    current: Mutex<Option<(String, i64)>>,
}

impl Signer {
    fn token(&self, now_s: i64) -> Result<String, String> {
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((token, iat)) = current.as_ref()
            && now_s - iat < JWT_LIFETIME_SECS
        {
            return Ok(token.clone());
        }
        let header = json!({ "alg": "ES256", "kid": self.key_id }).to_string();
        let claims = json!({ "iss": self.team_id, "iat": now_s }).to_string();
        let input = format!(
            "{}.{}",
            BASE64URL_NOPAD.encode(header.as_bytes()),
            BASE64URL_NOPAD.encode(claims.as_bytes())
        );
        let signature = self
            .key
            .sign(&self.rng, input.as_bytes())
            .map_err(|_| "cannot sign the APNs token".to_owned())?;
        let token = format!("{input}.{}", BASE64URL_NOPAD.encode(signature.as_ref()));
        *current = Some((token.clone(), now_s));
        Ok(token)
    }

    fn forget(&self) {
        *self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

/// Reads the team key: the `.p8` file at `key_path` or the PEM in `key`.
fn load_key(config: &ApnsConfig) -> Result<EcdsaKeyPair, PushError> {
    let bytes = match (&config.key_path, &config.key) {
        (Some(path), None) => zeroize::Zeroizing::new(
            std::fs::read(path).map_err(|_| PushError::Read(path.display().to_string()))?,
        ),
        (None, Some(key)) => zeroize::Zeroizing::new(key.expose_secret().as_bytes().to_vec()),
        // `Config::validate` allows exactly one source.
        _ => return Err(PushError::Key),
    };
    parse_key(&bytes)
}

/// Parses a `.p8` key: PEM (`-----BEGIN PRIVATE KEY-----`) or raw DER.
///
/// A PEM pasted into a single-line variable may carry literal `\n`
/// escapes; they are read as line breaks.
fn parse_key(bytes: &[u8]) -> Result<EcdsaKeyPair, PushError> {
    let der = match std::str::from_utf8(bytes) {
        Ok(text) if text.contains("-----BEGIN") => {
            let text = zeroize::Zeroizing::new(text.replace("\\n", "\n"));
            let body: String = text
                .lines()
                .filter(|l| !l.trim_start().starts_with("-----"))
                .flat_map(|l| l.trim().chars())
                .collect();
            let body = zeroize::Zeroizing::new(body);
            zeroize::Zeroizing::new(BASE64.decode(body.as_bytes()).map_err(|_| PushError::Key)?)
        }
        _ => zeroize::Zeroizing::new(bytes.to_vec()),
    };
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der).map_err(|_| PushError::Key)
}

struct Apns {
    signer: Signer,
    topic: String,
    endpoint_override: Option<String>,
    http: reqwest::Client,
}

/// Sends pushes, if APNs is configured.
pub(crate) struct Pusher {
    apns: Option<Arc<Apns>>,
    /// Recent pushes per account and kind (hourly budget).
    sent: Mutex<HashMap<(AccountId, PushKind), Vec<i64>>>,
}

impl Pusher {
    /// A pusher for `config` (`None`: pushes are off).
    pub(crate) fn new(config: Option<&ApnsConfig>) -> Result<Self, PushError> {
        let apns = match config {
            None => None,
            Some(c) => {
                let key = load_key(c)?;
                let http = reqwest::Client::builder()
                    .timeout(Duration::from_secs(15))
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .map_err(|e| {
                        // reqwest's own message is only "builder error";
                        // the cause («No CA certificates…») is the source.
                        let cause = std::error::Error::source(&e)
                            .map_or_else(|| e.to_string(), ToString::to_string);
                        PushError::Http(cause)
                    })?;
                Some(Arc::new(Apns {
                    signer: Signer {
                        key,
                        key_id: c.key_id.clone(),
                        team_id: c.team_id.clone(),
                        rng: SystemRandom::new(),
                        current: Mutex::new(None),
                    },
                    topic: c.topic.clone(),
                    endpoint_override: c.endpoint_override.clone(),
                    http,
                }))
            }
        };
        Ok(Self {
            apns,
            sent: Mutex::new(HashMap::new()),
        })
    }

    /// Whether pushes are on.
    pub(crate) fn enabled(&self) -> bool {
        self.apns.is_some()
    }

    /// Tells the account's phones about `kind`/`id`, in the background.
    pub(crate) fn notify(&self, db: &Db, account: AccountId, kind: PushKind, id: String) {
        let Some(apns) = self.apns.clone() else {
            return;
        };
        if !self.allow_push(account, kind, now_ms()) {
            tracing::info!(%account, kind = kind.name(), "push skipped (hourly limit)");
            return;
        }
        let db = db.clone();
        tokio::spawn(async move {
            let phones = match phones(&db.pool, account).await {
                Ok(phones) => phones,
                Err(e) => {
                    tracing::warn!(%account, error = %format!("database: {e}"), "push notification failed");
                    return;
                }
            };
            send_all(&apns, &db, account, kind, &id, phones).await;
        });
    }

    /// Tells `phones` (read earlier) about `kind`, in the background: the
    /// final notice of a deletion, whose tokens are already gone.
    pub(crate) fn notify_phones(
        &self,
        db: &Db,
        account: AccountId,
        kind: PushKind,
        phones: Vec<Phone>,
    ) {
        let Some(apns) = self.apns.clone() else {
            return;
        };
        if phones.is_empty() {
            return;
        }
        if !self.allow_push(account, kind, now_ms()) {
            tracing::info!(%account, kind = kind.name(), "push skipped (hourly limit)");
            return;
        }
        let db = db.clone();
        tokio::spawn(async move {
            send_all(&apns, &db, account, kind, "", phones).await;
        });
    }

    /// Takes one push of `kind` from the account's hourly budget. Agents
    /// trigger approval and task pushes, and anyone who knows the e-mail
    /// triggers registration pushes: none of them may flood the phone.
    fn allow_push(&self, account: AccountId, kind: PushKind, now: i64) -> bool {
        let mut map = self
            .sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let sent = map.entry((account, kind)).or_default();
        sent.retain(|t| now - t < 3_600_000);
        if sent.len() >= kind.hourly_budget() {
            return false;
        }
        sent.push(now);
        true
    }
}

async fn send_all(
    apns: &Apns,
    db: &Db,
    account: AccountId,
    kind: PushKind,
    id: &str,
    phones: Vec<Phone>,
) {
    let body = payload(kind, id).to_string();
    for Phone {
        device,
        token,
        environment,
    } in phones
    {
        match send_one(apns, &token, environment, &body, kind, id).await {
            Ok(()) => tracing::info!(%account, %device, kind = kind.name(), "push sent"),
            Err(Rejected::Gone(reason)) => {
                tracing::info!(%account, %device, %reason, "push token no longer valid; removed");
                let _ = sqlx::query("DELETE FROM push_tokens WHERE device_id = $1 AND token = $2")
                    .bind(&device)
                    .bind(&token)
                    .execute(&db.pool)
                    .await;
            }
            Err(Rejected::Other(reason)) => {
                tracing::warn!(%account, %device, %reason, "push rejected");
            }
        }
    }
}

enum Rejected {
    /// The token is dead: forget it.
    Gone(String),
    /// Anything else (the reason Apple gave, or a network error).
    Other(String),
}

async fn send_one(
    apns: &Apns,
    token: &str,
    environment: PushEnvironment,
    body: &str,
    kind: PushKind,
    id: &str,
) -> Result<(), Rejected> {
    let base = apns
        .endpoint_override
        .as_deref()
        .unwrap_or(match environment {
            PushEnvironment::Production => PRODUCTION,
            PushEnvironment::Sandbox => SANDBOX,
        });
    let now_s = now_ms() / 1000;
    let jwt = apns.signer.token(now_s).map_err(Rejected::Other)?;
    let mut req = apns
        .http
        .post(format!("{base}/3/device/{token}"))
        .header("authorization", format!("bearer {jwt}"))
        .header("apns-topic", &apns.topic)
        .header("apns-push-type", "alert")
        .header("apns-priority", "10")
        // Approvals and tasks must be decided within 10 minutes,
        // registrations within an hour; the account's notices last as long
        // as the deletion's delay.
        .header(
            "apns-expiration",
            (now_s
                + match kind {
                    PushKind::Approval => APPROVAL_TTL_MS / 1000,
                    PushKind::Task => TASK_DECIDE_TTL_MS / 1000,
                    PushKind::Agent => PENDING_TTL_MS / 1000,
                    PushKind::AccountDeletion
                    | PushKind::AccountCanceled
                    | PushKind::AccountDeleted => ACCOUNT_PUSH_TTL_SECS,
                })
            .to_string(),
        )
        .header("content-type", "application/json")
        .body(body.to_owned());
    // Notices about one request replace each other; the account's own
    // notices never do (the person must see that a deletion was asked).
    if !id.is_empty() {
        req = req.header("apns-collapse-id", id);
    }
    let res = req
        .send()
        .await
        // Without the URL: it holds the token.
        .map_err(|e| Rejected::Other(format!("network: {}", e.without_url())))?;
    let status = res.status().as_u16();
    if status == 200 {
        return Ok(());
    }
    let reason = res
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|v| v.get("reason").and_then(|r| r.as_str()).map(str::to_owned))
        .unwrap_or_else(|| format!("HTTP {status}"));
    match (status, reason.as_str()) {
        (410, _) | (400, "BadDeviceToken" | "DeviceTokenNotForTopic") => {
            Err(Rejected::Gone(reason))
        }
        (403, "ExpiredProviderToken" | "InvalidProviderToken") => {
            apns.signer.forget();
            Err(Rejected::Other(reason))
        }
        _ => Err(Rejected::Other(reason)),
    }
}

/// Whether `token` looks like an APNs device token (hex, 32 to 200
/// characters; today they are 64).
pub(crate) fn valid_token(token: &str) -> bool {
    (32..=200).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_carry_no_text_from_the_server() {
        let p = payload(PushKind::Approval, "0193-id");
        assert_eq!(p["klav"]["type"], "approval");
        assert_eq!(p["klav"]["id"], "0193-id");
        assert_eq!(p["aps"]["alert"]["loc-key"], "PUSH_APPROVAL_BODY");
        assert!(p["aps"]["alert"].get("body").is_none());
        assert!(p["aps"]["alert"].get("title").is_none());
        assert_eq!(payload(PushKind::Agent, "x")["klav"]["type"], "agent");
        let task = payload(PushKind::Task, "0194-task");
        assert_eq!(task["klav"], json!({ "type": "task", "id": "0194-task" }));
        assert_eq!(task["aps"]["thread-id"], "task");
        assert_eq!(task["aps"]["alert"]["title-loc-key"], "PUSH_TASK_TITLE");
        assert_eq!(task["aps"]["alert"]["loc-key"], "PUSH_TASK_BODY");
        assert!(task["aps"]["alert"].get("body").is_none());
        assert!(task["aps"]["alert"].get("title").is_none());
        for (kind, title, body) in [
            (
                PushKind::AccountDeletion,
                "PUSH_ACCOUNT_DELETION_TITLE",
                "PUSH_ACCOUNT_DELETION_BODY",
            ),
            (
                PushKind::AccountCanceled,
                "PUSH_ACCOUNT_CANCELED_TITLE",
                "PUSH_ACCOUNT_CANCELED_BODY",
            ),
            (
                PushKind::AccountDeleted,
                "PUSH_ACCOUNT_DELETED_TITLE",
                "PUSH_ACCOUNT_DELETED_BODY",
            ),
        ] {
            // No ID, even if one is passed by mistake.
            let p = payload(kind, "0195-id");
            assert_eq!(p["klav"], json!({ "type": "account" }));
            assert_eq!(p["aps"]["thread-id"], "account");
            assert_eq!(p["aps"]["alert"]["title-loc-key"], title);
            assert_eq!(p["aps"]["alert"]["loc-key"], body);
            assert!(p["aps"]["alert"].get("body").is_none());
            assert!(p["aps"]["alert"].get("title").is_none());
        }
    }

    #[test]
    fn tokens_must_be_hex() {
        assert!(valid_token(&"ab".repeat(32)));
        assert!(!valid_token("abc"));
        assert!(!valid_token(&"zz".repeat(32)));
        assert!(!valid_token(&format!("{}/../x", "ab".repeat(32))));
    }

    #[test]
    fn pushes_are_limited_per_account_and_kind() {
        let pusher = Pusher::new(None).unwrap();
        let account = AccountId::generate();
        let other = AccountId::generate();
        let now = 1_000_000_000;
        for kind in [
            PushKind::Agent,
            PushKind::Approval,
            PushKind::Task,
            PushKind::AccountDeletion,
            PushKind::AccountCanceled,
            PushKind::AccountDeleted,
        ] {
            for _ in 0..kind.hourly_budget() {
                assert!(pusher.allow_push(account, kind, now));
            }
            assert!(!pusher.allow_push(account, kind, now + 1000), "{kind:?}");
            assert!(pusher.allow_push(other, kind, now));
            assert!(pusher.allow_push(account, kind, now + 3_600_001));
        }
        assert_eq!(REGISTRATION_PUSHES_PER_HOUR, 5);
    }

    #[test]
    fn provider_tokens_are_es256_jwts_and_reused() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("AuthKey.p8");
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            BASE64.encode(pkcs8.as_ref())
        );
        std::fs::write(&path, pem).unwrap();
        let key = load_key(&apns(Some(&path), None)).unwrap();
        let public = aws_lc_rs::signature::KeyPair::public_key(&key)
            .as_ref()
            .to_vec();
        let signer = Signer {
            key,
            key_id: "KEY1234567".into(),
            team_id: "TEAM123456".into(),
            rng,
            current: Mutex::new(None),
        };
        let jwt = signer.token(1_000).unwrap();
        assert_eq!(signer.token(1_000 + JWT_LIFETIME_SECS - 1).unwrap(), jwt);
        assert_ne!(signer.token(1_000 + JWT_LIFETIME_SECS).unwrap(), jwt);
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value =
            serde_json::from_slice(&BASE64URL_NOPAD.decode(parts[0].as_bytes()).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEY1234567");
        let claims: serde_json::Value =
            serde_json::from_slice(&BASE64URL_NOPAD.decode(parts[1].as_bytes()).unwrap()).unwrap();
        assert_eq!(claims["iss"], "TEAM123456");
        assert_eq!(claims["iat"], 1_000);
        let signature = BASE64URL_NOPAD.decode(parts[2].as_bytes()).unwrap();
        assert_eq!(signature.len(), 64);
        aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED,
            public,
        )
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .unwrap();
        std::fs::write(&path, "not a key").unwrap();
        assert!(matches!(
            load_key(&apns(Some(&path), None)),
            Err(PushError::Key)
        ));
    }

    fn apns(path: Option<&std::path::Path>, key: Option<&str>) -> ApnsConfig {
        ApnsConfig {
            key_path: path.map(std::path::Path::to_path_buf),
            key: key.map(secrecy::SecretString::from),
            key_id: "KEY1234567".into(),
            team_id: "TEAM123456".into(),
            topic: "dev.klav.ios".into(),
            endpoint_override: None,
        }
    }

    #[test]
    fn the_key_can_come_from_its_contents() {
        use aws_lc_rs::signature::KeyPair;

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let body = BASE64.encode(pkcs8.as_ref());
        let expected = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
            .unwrap()
            .public_key()
            .as_ref()
            .to_vec();
        // As pasted into a multi-line variable, wrapped at 64 columns.
        let wrapped: Vec<&str> = body
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            wrapped.join("\n")
        );
        let key = load_key(&apns(None, Some(&pem))).unwrap();
        assert_eq!(key.public_key().as_ref(), expected.as_slice());
        // On one line with literal `\n` escapes.
        let escaped = pem.replace('\n', "\\n");
        assert!(!escaped.contains('\n'));
        let key = load_key(&apns(None, Some(&escaped))).unwrap();
        assert_eq!(key.public_key().as_ref(), expected.as_slice());
    }

    #[test]
    fn a_bad_key_in_the_variable_is_rejected_without_echoing_it() {
        let sentinel = "S3NTINELb64AAAA";
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{sentinel}\n-----END PRIVATE KEY-----\n");
        let err = load_key(&apns(None, Some(&pem))).expect_err("rejected");
        assert!(matches!(err, PushError::Key));
        assert!(!err.to_string().contains(sentinel));
        assert!(!format!("{err:?}").contains(sentinel));
        // Neither source, or both, never reach this far (`Config::validate`),
        // and still fail closed.
        assert!(matches!(load_key(&apns(None, None)), Err(PushError::Key)));
    }
}
