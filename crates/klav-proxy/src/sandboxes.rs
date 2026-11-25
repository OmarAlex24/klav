//! Sandboxes (ADR 0036 §4, E3.3; layer 5): the issuer's API on the
//! proxy's loopback listener, the store, and the sweeper.
//!
//! - **The API** (`/_klav/sandboxes`): `POST` starts a sandbox, `GET`
//!   lists the caller's live ones, `POST /_klav/sandboxes/{id}/stop` ends
//!   one. Every request is signed by the issuer like a request to the Klav
//!   server (spec §13.3: the same headers and message). The proxy checks
//!   the signature with the issuer's identity in **its own grant**, signed
//!   by the account (`issuers[].public_identity`), never one it fetched
//!   elsewhere.
//! - **Start:** the proxy logs `sandbox.issued` on the Klav server before
//!   it answers. If the server refuses or does not answer, there is no
//!   sandbox and no secret. The answer carries the one-time secret; the
//!   issuer builds the `ksb1_` package from it and its own grant (D4).
//! - **The store** keeps each live sandbox with the SHA-256 of its secret
//!   (`klav_core::crypto::sandbox::secret_digest`), never the secret, in
//!   a 0600 file next to the proxy's registration, replaced atomically,
//!   plus the `sandbox.revoked` events the server has not taken yet, in
//!   order.
//! - **The sweeper** ends a sandbox when it expires (`ttl`), when it was
//!   never claimed within an hour of its start (`inactivity`), and when its
//!   issuer left the proxy's grant, lost one of the sandbox's profiles, or
//!   is one the server says is gone (`gone_issuers`: revoked, or its grant
//!   names no proxy or another one), all with `issuer_removed`.
//! - **The store lock** is held only to read or change the store, never
//!   across a call to the Klav server: a `stop` takes effect at once, even
//!   while a start waits for the server. A start reserves its place (and
//!   its pending end) under the lock, calls the server without it, and
//!   takes the lock again to keep or drop the sandbox. Ends are sent by one
//!   flush at a time, also without the lock.
//! - **Limits:** each issuer starts at most [`MAX_STARTS_PER_MINUTE`]
//!   sandboxes a minute and holds at most [`MAX_NONCES_PER_AGENT`] nonces;
//!   with [`MAX_OUTBOX`] ends waiting for the server, no sandbox starts.
//!
//! The secret is in the answer to `start` only: never in the store, a log
//! line, an error or a `Debug`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Path as UrlPath, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, request::Parts};
use axum::response::{IntoResponse, Response};
use klav_client::ClientError;
use klav_core::crypto::agent::{self as agent_crypto, NONCE_LEN, SignedRequest};
use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::sandbox::{SandboxSecret, secret_digest};
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::ids::{AgentId, SandboxId};
use klav_proto::Blob;
use klav_proto::ErrorCode;
use klav_proto::agent::{
    HEADER_AGENT, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP, SandboxIssuer,
};
use klav_proto::sandbox::{
    PATH_SANDBOXES, SUFFIX_REVOKED, SandboxEnd, SandboxIssue, SandboxRevoked, sandbox_path,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use crate::errors::KLAV_ERROR;
use crate::proxy::ProxyState;

/// Where the issuer's API lives on the loopback listener. A profile name
/// starts with a lower-case letter, so no profile can take it.
pub const API: &str = "/_klav/sandboxes";
/// Largest body the API reads: a start request is a label and six names.
pub const MAX_API_BODY: usize = 4 * 1024;
/// A sandbox never claimed this long after its start ends with
/// `inactivity` (ADR 0036 §4; D10). Until layer 6's forwarder claims
/// sandboxes, every sandbox ends this way at the latest.
pub const INACTIVITY_MS: i64 = 60 * 60 * 1000;
/// How often the sweeper runs.
pub const SWEEP_EVERY: Duration = Duration::from_secs(30);
/// How far an issuer's clock may be from the proxy's (spec §13.3).
pub const CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;
/// Nonces remembered at once; past it, signed requests wait (`429`).
const MAX_NONCES: usize = 4096;
/// Nonces of one issuer remembered at once, so one issuer cannot fill the
/// cache for the others (`429`).
pub const MAX_NONCES_PER_AGENT: usize = 1024;
/// Sandbox starts one issuer may ask for in a minute (`429`).
pub const MAX_STARTS_PER_MINUTE: usize = 30;
/// Ends waiting for the server past which no sandbox starts (`503`): ends
/// are never dropped to make room, so this bounds the ends of starts whose
/// outcome the proxy could not learn.
pub const MAX_OUTBOX: usize = 256;
/// The store's file extension, next to the agents' `.json` and `.key`.
pub const STORE_EXTENSION: &str = "sandbox-store";
/// Version of the store file.
pub const STORE_VERSION: u8 = 1;

/// The time, so tests can move it.
pub trait Clock: Send + Sync {
    /// Unix milliseconds.
    fn now_ms(&self) -> i64;
}

/// The system clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
    }
}

/// A live sandbox as the proxy keeps it: the digest of its secret, never
/// the secret.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Stored {
    pub(crate) sandbox_id: SandboxId,
    pub(crate) issuer_id: AgentId,
    pub(crate) label: String,
    pub(crate) profiles: Vec<String>,
    pub(crate) issued_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) secret_sha256: Blob,
    /// When the server logged its claim (`sandbox.claimed`). The channel
    /// key it is bound to is in the channels file ([`crate::claims`]), so
    /// this file keeps the format a proxy from before layer 6 reads.
    #[serde(default)]
    pub(crate) claimed_at: Option<i64>,
}

/// A live sandbox as `klav-proxy status` shows it.
#[derive(Debug, Clone, Serialize)]
pub struct SandboxView {
    /// Its ID.
    pub sandbox_id: SandboxId,
    /// The agent that started it.
    pub issuer_id: AgentId,
    /// The label its issuer gave it.
    pub label: String,
    /// Its profiles.
    pub profiles: Vec<String>,
    /// When it started (Unix ms).
    pub issued_at: i64,
    /// When it ends (Unix ms).
    pub expires_at: i64,
    /// Whether its forwarder claimed it.
    pub claimed: bool,
}

/// A `sandbox.revoked` the server has not taken yet.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Outgoing {
    pub(crate) sandbox_id: SandboxId,
    pub(crate) reason: SandboxEnd,
    /// With `person`: the `at` of the person's revocation it answers.
    /// Absent otherwise, so the file is what an older proxy wrote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) at: Option<i64>,
}

/// The store file.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoreFile {
    v: u8,
    pub(crate) sandboxes: Vec<Stored>,
    pub(crate) outbox: Vec<Outgoing>,
    /// Starts waiting for the server, with their issuer: they count toward
    /// `max_live`, and their pending end is not sent while they wait.
    /// Never saved: after a restart, the pending end is just an end.
    #[serde(skip)]
    starting: Vec<(SandboxId, AgentId)>,
    /// The channel keys of claimed sandboxes, and of claims the server may
    /// have logged: saved in their own file ([`crate::claims`]).
    #[serde(skip)]
    pub(crate) channels: Vec<crate::claims::Channel>,
    /// Thefts the proxy could not confirm the server logged: saved with
    /// the channels.
    #[serde(skip)]
    pub(crate) unconfirmed_thefts: Vec<crate::claims::UnconfirmedTheft>,
    /// Claims waiting for the server: a second one for the same sandbox
    /// waits (`429`). Never saved.
    #[serde(skip)]
    pub(crate) claiming: Vec<SandboxId>,
    /// The last call over its channel of each claimed sandbox (proxy
    /// clock). Never saved: after a restart, the proxy's start counts.
    #[serde(skip)]
    pub(crate) last_seen: HashMap<SandboxId, i64>,
    /// Channel keys bound to a sandbox at some point since the proxy
    /// started (one per claimed sandbox): a connection of such a key whose
    /// sandbox is no longer live is closed. Never saved.
    #[serde(skip)]
    pub(crate) ever_bound: std::collections::HashSet<[u8; 32]>,
    /// Why the sandbox of each channel key ended, newest last, at most
    /// [`MAX_ENDED_KEYS`]: that key alone is told the reason (papercut 4).
    /// Never saved: after a restart, an ended sandbox's key gets the
    /// general answer again.
    #[serde(skip)]
    pub(crate) ended_keys: std::collections::VecDeque<([u8; 32], SandboxEnd)>,
}

/// How many ended sandboxes' keys the proxy remembers the reason for.
pub(crate) const MAX_ENDED_KEYS: usize = 1024;

impl StoreFile {
    /// Notes why `sandbox` ended, for each channel key on record for it:
    /// called where it ends, while its keys are still on record. Each such
    /// place also cuts its calls in flight (`ProxyState::cuts`).
    pub(crate) fn note_end(&mut self, sandbox: SandboxId, reason: SandboxEnd) {
        let keys: Vec<[u8; 32]> = self
            .channels
            .iter()
            .filter(|c| c.sandbox_id == sandbox)
            .filter_map(|c| <[u8; 32]>::try_from(c.channel_key_sha256.as_bytes()).ok())
            .collect();
        for key in keys {
            self.ended_keys.retain(|(k, _)| *k != key);
            self.ended_keys.push_back((key, reason));
        }
        while self.ended_keys.len() > MAX_ENDED_KEYS {
            self.ended_keys.pop_front();
        }
    }

    /// Why the sandbox `key` was bound to ended, if the proxy remembers.
    pub(crate) fn end_of(&self, key: &[u8; 32]) -> Option<SandboxEnd> {
        self.ended_keys
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, reason)| *reason)
    }
}

/// The proxy's sandboxes: the store, the nonces it has seen, its clock.
pub struct Sandboxes {
    path: Option<PathBuf>,
    clock: Arc<dyn Clock>,
    pub(crate) started_at: i64,
    /// Held to read or change the store and the channels, never across a
    /// call to the server: one change at a time.
    pub(crate) store: tokio::sync::Mutex<StoreFile>,
    /// One flush at a time, so no end is sent twice at once.
    flushing: tokio::sync::Mutex<()>,
    nonces: Mutex<HashMap<(AgentId, [u8; NONCE_LEN]), i64>>,
    /// Each issuer's starts in the last minute.
    starts: Mutex<HashMap<AgentId, std::collections::VecDeque<i64>>>,
}

impl Sandboxes {
    /// The store at `path`, created empty when missing. Refuses a store it
    /// cannot read, of another version, or not a regular 0600 file of this
    /// user: starting over would forget live sandboxes it must still end.
    pub fn open(path: PathBuf, clock: Arc<dyn Clock>) -> Result<Self, String> {
        let file = match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StoreFile {
                v: STORE_VERSION,
                ..StoreFile::default()
            },
            Err(e) => return Err(format!("sandbox store {}: {e}", path.display())),
            Ok(_) => {
                crate::app::check_key_file(&path).map_err(|e| {
                    e.to_string()
                        .replace("key file", "sandbox store")
                        .replace("the key", "the store")
                })?;
                let bytes = std::fs::read(&path)
                    .map_err(|e| format!("sandbox store {}: {e}", path.display()))?;
                let file: StoreFile = serde_json::from_slice(&bytes).map_err(|_| {
                    format!(
                        "sandbox store {} cannot be read; klav-proxy does not start over on its own, since it would forget sandboxes it still has to end. Move the file away to start with none",
                        path.display()
                    )
                })?;
                if file.v != STORE_VERSION {
                    return Err(format!(
                        "sandbox store {} is version {}, and this klav-proxy reads version {STORE_VERSION}",
                        path.display(),
                        file.v
                    ));
                }
                file
            }
        };
        let mut file = file;
        let on_disk = crate::claims::load(&crate::claims::path_of(&path))?;
        file.channels = on_disk.channels;
        file.unconfirmed_thefts = on_disk.unconfirmed_thefts;
        let started_at = clock.now_ms();
        Ok(Self {
            path: Some(path),
            clock,
            started_at,
            store: tokio::sync::Mutex::new(file),
            flushing: tokio::sync::Mutex::new(()),
            nonces: Mutex::new(HashMap::new()),
            starts: Mutex::new(HashMap::new()),
        })
    }

    /// A store that lives in memory only (tests of other parts).
    pub fn in_memory(clock: Arc<dyn Clock>) -> Self {
        let started_at = clock.now_ms();
        Self {
            path: None,
            clock,
            started_at,
            store: tokio::sync::Mutex::new(StoreFile {
                v: STORE_VERSION,
                ..StoreFile::default()
            }),
            flushing: tokio::sync::Mutex::new(()),
            nonces: Mutex::new(HashMap::new()),
            starts: Mutex::new(HashMap::new()),
        }
    }

    /// The store file of the proxy named `name` in `home`. Not a `.json`:
    /// the agents' directory lists every `*.json` as an agent
    /// (`klav_sdk::config::list`).
    pub fn path_in(home: &klav_client::Home, name: &str) -> PathBuf {
        home.dir()
            .join("agents")
            .join(format!("{name}.{STORE_EXTENSION}"))
    }

    pub(crate) fn now(&self) -> i64 {
        self.clock.now_ms()
    }

    pub(crate) fn save(&self, file: &StoreFile) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let bytes = serde_json::to_vec(file).map_err(|e| e.to_string())?;
        klav_client::home::write_private(path, &bytes).map_err(|e| e.to_string())
    }

    /// Saves the channels file, next to the store.
    pub(crate) fn save_channels(&self, file: &StoreFile) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        crate::claims::save(
            &crate::claims::path_of(path),
            &file.channels,
            &file.unconfirmed_thefts,
        )
    }

    /// The thefts the proxy could not confirm the server logged (for
    /// `status`).
    pub async fn unconfirmed_thefts(&self) -> Vec<crate::claims::UnconfirmedTheft> {
        self.store.lock().await.unconfirmed_thefts.clone()
    }

    /// How many sandboxes are live (for `status`).
    pub async fn live(&self) -> usize {
        self.store.lock().await.sandboxes.len()
    }

    /// The live sandboxes, for `klav-proxy status`: never the digest of a
    /// secret.
    pub async fn views(&self) -> Vec<SandboxView> {
        self.store
            .lock()
            .await
            .sandboxes
            .iter()
            .map(|s| SandboxView {
                sandbox_id: s.sandbox_id,
                issuer_id: s.issuer_id,
                label: s.label.clone(),
                profiles: s.profiles.clone(),
                issued_at: s.issued_at,
                expires_at: s.expires_at,
                claimed: s.claimed_at.is_some(),
            })
            .collect()
    }

    /// How many ends wait for the server.
    pub async fn unsent(&self) -> usize {
        self.store.lock().await.outbox.len()
    }

    /// Puts `n` ends of sandboxes the server never had in the outbox.
    #[cfg(test)]
    pub(crate) async fn fill_outbox(&self, n: usize) {
        let mut store = self.store.lock().await;
        for _ in 0..n {
            store.outbox.push(Outgoing {
                sandbox_id: SandboxId::generate(),
                reason: SandboxEnd::Stop,
                at: None,
            });
        }
    }

    /// Counts a start of `agent` if it has one left this minute.
    fn take_start(&self, agent: AgentId) -> Result<(), IssuerError> {
        let now = self.now();
        let mut starts = self.starts.lock().unwrap_or_else(|e| e.into_inner());
        starts.retain(|_, seen| {
            while seen
                .front()
                .is_some_and(|t| now.saturating_sub(*t) >= 60_000)
            {
                seen.pop_front();
            }
            !seen.is_empty()
        });
        let seen = starts.entry(agent).or_default();
        if seen.len() >= MAX_STARTS_PER_MINUTE {
            return Err(IssuerError::Busy);
        }
        seen.push_back(now);
        Ok(())
    }

    /// Takes a nonce once, after the signature checked out. Forgets the
    /// ones past the clock window.
    fn take_nonce(&self, agent: AgentId, nonce: [u8; NONCE_LEN]) -> Result<(), IssuerError> {
        let now = self.now();
        let mut seen = self.nonces.lock().unwrap_or_else(|e| e.into_inner());
        seen.retain(|_, until| *until > now);
        if seen.contains_key(&(agent, nonce)) {
            return Err(IssuerError::BadSignature);
        }
        if seen.len() >= MAX_NONCES
            || seen.keys().filter(|(a, _)| *a == agent).count() >= MAX_NONCES_PER_AGENT
        {
            return Err(IssuerError::Busy);
        }
        seen.insert((agent, nonce), now + 2 * CLOCK_SKEW_MS + 1000);
        Ok(())
    }
}

/// What the API answers instead of a result: an HTTP status, a
/// `Klav-Error` header and `{error, message, next}`, with fixed texts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerError {
    /// Missing or bad signature headers, a signature that does not check
    /// out, a replayed nonce, or a time outside the window.
    BadSignature,
    /// The signer is not an issuer in the proxy's grant (or the server
    /// says it no longer is one).
    NotIssuer,
    /// A profile the issuer may not give, or that the proxy does not hold.
    ProfileNotAllowed,
    /// The issuer has as many live sandboxes as it may.
    TooMany,
    /// A TTL past the issuer's limit, a label or profile list out of
    /// format, or a body that is not the request.
    BadRequest(String),
    /// The person paused the agents.
    AgentsPaused,
    /// The proxy cannot reach the Klav server.
    ServerUnreachable,
    /// The Klav server refused the proxy (revoked).
    ServerDenied,
    /// The person asked Klav to delete the account: every agent stops.
    AccountDeleting,
    /// No live sandbox of this issuer with that ID.
    NotFound,
    /// Too many signed requests at once.
    Busy,
    /// The proxy could not keep the sandbox (its store). Nothing was
    /// handed out.
    Store,
    /// Not from this machine (a web page, or another host name).
    NotLocal,
    /// Signed for a proxy on another port (`?port=`): a request relayed
    /// by whatever listened on the port the issuer meant.
    OtherPort,
    /// A `stop` the proxy could not save: the sandbox is still live.
    StopNotSaved,
    /// [`MAX_OUTBOX`] ends wait for the server: no sandbox starts until it
    /// takes them.
    Backlog,
}

impl IssuerError {
    /// The `error` code (ADR 0036 E1.3).
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadSignature | Self::NotLocal | Self::OtherPort => "klav_not_allowed",
            Self::NotIssuer => "klav_not_issuer",
            Self::ProfileNotAllowed => "klav_profile_not_allowed",
            Self::TooMany => "klav_too_many_sandboxes",
            Self::BadRequest(_) => "klav_bad_request",
            Self::AgentsPaused => "klav_agents_paused",
            Self::ServerUnreachable => "klav_server_unreachable",
            Self::Backlog => "klav_proxy_backlog",
            Self::ServerDenied => "klav_not_allowed",
            Self::AccountDeleting => "klav_account_deleting",
            Self::NotFound => "klav_sandbox_not_found",
            Self::Busy => "klav_rate_limited",
            Self::Store | Self::StopNotSaved => "klav_proxy_store",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::BadSignature => StatusCode::UNAUTHORIZED,
            Self::NotIssuer
            | Self::ProfileNotAllowed
            | Self::ServerDenied
            | Self::NotLocal
            | Self::OtherPort => StatusCode::FORBIDDEN,
            Self::TooMany => StatusCode::CONFLICT,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::AgentsPaused | Self::AccountDeleting => StatusCode::LOCKED,
            Self::ServerUnreachable | Self::Backlog => StatusCode::SERVICE_UNAVAILABLE,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Busy => StatusCode::TOO_MANY_REQUESTS,
            Self::Store | Self::StopNotSaved => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn message(&self) -> String {
        match self {
            Self::BadSignature => "Klav's credential proxy did not accept this request: a missing or wrong signature, an agent that is not one of its sandbox issuers, a repeated request, or a clock off by more than 5 minutes.".into(),
            Self::OtherPort => "This request was signed for a Klav credential proxy on another port, so this one does not take it.".into(),
            Self::StopNotSaved => "Klav's credential proxy could not save the end of this sandbox, so the sandbox is still live.".into(),
            Self::NotLocal => "Klav's credential proxy only takes sandbox requests from programs on its own machine, addressed to 127.0.0.1 or localhost.".into(),
            Self::NotIssuer => "This agent may not start sandboxes at this credential proxy.".into(),
            Self::ProfileNotAllowed => "This agent may not give a sandbox one of these profiles.".into(),
            Self::TooMany => "This agent already has as many live sandboxes as the person allowed.".into(),
            Self::BadRequest(why) => format!("Klav's credential proxy refused this sandbox request: {why}."),
            Self::AgentsPaused => "The person paused Klav's agents: no sandbox starts until they resume them.".into(),
            Self::ServerUnreachable => "Klav's credential proxy could not reach the Klav server, so it cannot log a new sandbox.".into(),
            Self::Backlog => "Klav's credential proxy has too many sandbox ends the Klav server has not taken yet, so it starts no new sandbox until the server takes them.".into(),
            Self::ServerDenied => "The Klav server refused the credential proxy: the person may have revoked it.".into(),
            Self::AccountDeleting => "The person asked Klav to delete this account, so no sandbox starts.".into(),
            Self::NotFound => "No live sandbox of this agent has that ID.".into(),
            Self::Busy => "Klav's credential proxy is handling too many sandbox requests right now.".into(),
            Self::Store => "Klav's credential proxy could not save the sandbox, so it did not start it.".into(),
        }
    }

    fn next(&self) -> &'static str {
        match self {
            Self::NotIssuer => {
                "Tell the person they can let this agent start sandboxes with `klav proxy issuer add <agent>` in their own terminal, or in the Klav app. Do not run it yourself."
            }
            Self::ProfileNotAllowed | Self::TooMany => {
                "Tell the person this message. Stop a sandbox you no longer need with `klav sandbox stop <id>`, or ask the person to change what this agent may do with `klav proxy issuer add`. Do not copy keys into the sandbox."
            }
            Self::Busy | Self::StopNotSaved => {
                "Wait a few seconds and try once more. Do not retry in a loop."
            }
            Self::OtherPort => {
                "Something else answered on the proxy's port. Tell the person this exact message and stop."
            }
            Self::BadRequest(_) => "Fix the request as the message says.",
            _ => {
                "Tell the person this exact message and stop. Do not retry in a loop and do not copy keys into the sandbox."
            }
        }
    }
}

impl IntoResponse for IssuerError {
    fn into_response(self) -> Response {
        let body = json!({
            "error": self.code(),
            "message": self.message(),
            "next": self.next(),
        });
        let mut res = (self.status(), Json(body)).into_response();
        res.headers_mut()
            .insert(KLAV_ERROR, HeaderValue::from_static(self.code()));
        res
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, IssuerError> {
    let mut all = headers.get_all(name).iter();
    match (all.next(), all.next()) {
        (Some(v), None) => v.to_str().map_err(|_| IssuerError::BadSignature),
        _ => Err(IssuerError::BadSignature),
    }
}

fn fixed<const N: usize>(text: &str) -> Result<[u8; N], IssuerError> {
    Blob::from_text(text)
        .and_then(|b| b.into_bytes().try_into().ok())
        .ok_or(IssuerError::BadSignature)
}

/// Checks a signed request and returns its issuer, as the proxy's current
/// grant lists it.
async fn authenticate(
    state: &ProxyState,
    parts: &Parts,
    body: &[u8],
) -> Result<SandboxIssuer, IssuerError> {
    let sandboxes = state.sandboxes();
    let agent: AgentId = header(&parts.headers, HEADER_AGENT)?
        .parse()
        .map_err(|_| IssuerError::BadSignature)?;
    let timestamp: i64 = header(&parts.headers, HEADER_TIMESTAMP)?
        .parse()
        .map_err(|_| IssuerError::BadSignature)?;
    let nonce: [u8; NONCE_LEN] = fixed(header(&parts.headers, HEADER_NONCE)?)?;
    let signature = Signature::from_bytes(fixed::<SIGNATURE_LEN>(header(
        &parts.headers,
        HEADER_SIGNATURE,
    )?)?);
    let now = sandboxes.now();
    // The window, and nothing signed before this proxy started: its nonces
    // from before are gone, so an older request could be replayed.
    if now.abs_diff(timestamp) > CLOCK_SKEW_MS.unsigned_abs() || timestamp < sandboxes.started_at {
        return Err(IssuerError::BadSignature);
    }
    // Not in the grant reads as a bad signature: without a key that
    // verifies, nobody learns which agents are issuers.
    let issuer = state.issuer(agent).await.ok_or(IssuerError::BadSignature)?;
    let public = PublicIdentity::decode(issuer.public_identity.as_bytes())
        .map_err(|_| IssuerError::BadSignature)?;
    let path = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.path().to_owned(), |pq| pq.as_str().to_owned());
    let digest = agent_crypto::body_digest(body);
    agent_crypto::verify_request(
        &public,
        &SignedRequest {
            agent,
            method: parts.method.as_str(),
            path: &path,
            timestamp_ms: u64::try_from(timestamp).map_err(|_| IssuerError::BadSignature)?,
            nonce: &nonce,
            body_digest: &digest,
        },
        &signature,
    )
    .map_err(|_| IssuerError::BadSignature)?;
    // The signed query names the port the issuer meant: a process that
    // listened there cannot relay the request to a proxy on another one.
    if parts.uri.query() != Some(format!("port={}", state.local_port()).as_str()) {
        return Err(IssuerError::OtherPort);
    }
    sandboxes.take_nonce(agent, nonce)?;
    Ok(issuer)
}

/// The parts and the body (up to [`MAX_API_BODY`]) of a request from this
/// machine.
async fn local_request(state: &ProxyState, req: Request) -> Result<(Parts, Bytes), IssuerError> {
    let (parts, body) = req.into_parts();
    if crate::proxy::not_local(&parts.headers, state.local_port()) {
        return Err(IssuerError::NotLocal);
    }
    let body = axum::body::to_bytes(body, MAX_API_BODY)
        .await
        .map_err(|_| IssuerError::BadRequest(format!("a body over {MAX_API_BODY} bytes")))?;
    Ok((parts, body))
}

/// What an issuer asks for.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartBody {
    label: String,
    profiles: Vec<String>,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

/// One of the issuer's live sandboxes, as `GET` lists it.
#[derive(Serialize)]
struct Listed<'a> {
    sandbox_id: SandboxId,
    label: &'a str,
    profiles: &'a [String],
    issued_at: i64,
    expires_at: i64,
    claimed: bool,
}

/// Whether the server may have done what it was asked: a network error,
/// a 5xx or a 429 says nothing about it, a refusal does.
pub(crate) fn outcome_unknown(e: &ClientError) -> bool {
    match e {
        ClientError::Network(_) => true,
        ClientError::Api { status, .. } => *status >= 500 || *status == 429,
        ClientError::Paused(_)
        | ClientError::Denied(_)
        | ClientError::AccountDeleting(_)
        | ClientError::Conflict(_) => false,
        _ => true,
    }
}

/// Whether a waiting end is done with: the server has it already
/// (`sandbox_revoked`), never had the sandbox (`sandbox_not_found`, never
/// a plain `404`, which a server without these routes or a wrong address
/// also gives), or will never take this reason (`409`). Anything else keeps
/// it.
pub(crate) fn end_settled(e: &ClientError) -> bool {
    matches!(
        e,
        ClientError::Api {
            code: Some(ErrorCode::SandboxRevoked | ErrorCode::SandboxNotFound),
            ..
        } | ClientError::Api { status: 409, .. }
    )
}

/// Whether a kept end should stop the flush: the server is out of reach,
/// busy, paused or refusing the proxy's signature, so the next ends would
/// fail the same way. A refusal of this one end (a plain `404` from an
/// older server, a `400`) keeps it and goes on to the next.
fn stops_flush(e: &ClientError) -> bool {
    match e {
        ClientError::Api { status, code, .. } => {
            *status >= 500
                || *status == 429
                || *status == 401
                || *code == Some(ErrorCode::Forbidden)
        }
        _ => true,
    }
}

fn map_server_error(e: &ClientError) -> IssuerError {
    match e {
        ClientError::Network(_) => IssuerError::ServerUnreachable,
        ClientError::Api { status, .. } if *status >= 500 || *status == 429 => {
            IssuerError::ServerUnreachable
        }
        ClientError::Paused(_) => IssuerError::AgentsPaused,
        ClientError::AccountDeleting(_) => IssuerError::AccountDeleting,
        ClientError::Api {
            code: Some(ErrorCode::NotIssuer),
            ..
        } => IssuerError::NotIssuer,
        ClientError::Api {
            code: Some(ErrorCode::ProfileNotAllowed),
            ..
        } => IssuerError::ProfileNotAllowed,
        ClientError::Api {
            code: Some(ErrorCode::TooManySandboxes),
            ..
        } => IssuerError::TooMany,
        _ => IssuerError::ServerDenied,
    }
}

/// `POST /_klav/sandboxes`.
pub async fn start(State(state): State<Arc<ProxyState>>, req: Request) -> Response {
    match start_inner(&state, req).await {
        Ok(res) => res,
        Err(e) => {
            tracing::info!(error = e.code(), "sandbox start refused");
            e.into_response()
        }
    }
}

async fn start_inner(state: &ProxyState, req: Request) -> Result<Response, IssuerError> {
    let (parts, body) = local_request(state, req).await?;
    let issuer = authenticate(state, &parts, &body).await?;
    let asked: StartBody = serde_json::from_slice(&body)
        .map_err(|_| IssuerError::BadRequest("the body is not a sandbox request".into()))?;
    let held = state.profile_names();
    if asked
        .profiles
        .iter()
        .any(|p| !issuer.profiles.contains(p) || !held.contains(p))
    {
        return Err(IssuerError::ProfileNotAllowed);
    }
    let ttl = issuer
        .ttl_secs(asked.ttl_secs)
        .map_err(IssuerError::BadRequest)?;
    if state.gone_issuers().contains(&issuer.agent_id) {
        return Err(IssuerError::NotIssuer);
    }
    let sandboxes = state.sandboxes();
    // Counted once the signature checked out and before anything is
    // written: a flood of starts never reaches the store or the server.
    sandboxes.take_start(issuer.agent_id)?;
    let proxy_id = state.proxy_id().await;
    let secret = SandboxSecret::generate();
    let mut store = sandboxes.store.lock().await;
    let now = sandboxes.now();
    if store.outbox.len() >= MAX_OUTBOX {
        return Err(IssuerError::Backlog);
    }
    let live = store
        .sandboxes
        .iter()
        .filter(|s| s.issuer_id == issuer.agent_id && s.expires_at > now)
        .count()
        + store
            .starting
            .iter()
            .filter(|(_, i)| *i == issuer.agent_id)
            .count();
    if live >= usize::try_from(issuer.max_live).unwrap_or(usize::MAX) {
        return Err(IssuerError::TooMany);
    }
    let ttl_ms = i64::try_from(ttl.saturating_mul(1000)).unwrap_or(i64::MAX);
    let issue = SandboxIssue {
        sandbox_id: SandboxId::generate(),
        issuer_id: issuer.agent_id,
        label: asked.label,
        profiles: asked.profiles,
        expires_at: now.saturating_add(ttl_ms),
    };
    issue
        .check_format(proxy_id)
        .map_err(IssuerError::BadRequest)?;
    let digest = secret_digest(issue.sandbox_id, &secret);
    // Its end is written down before the server hears of it: if the
    // server records the issue and the answer is lost, or this process
    // dies before saving, a later flush ends it there (a server that never
    // had it answers `sandbox_not_found`, which drops the end). While the
    // start waits, its place counts toward `max_live` and its end is not
    // sent.
    let pending = Outgoing {
        sandbox_id: issue.sandbox_id,
        reason: SandboxEnd::Stop,
        at: None,
    };
    store.outbox.push(pending);
    if let Err(e) = sandboxes.save(&store) {
        tracing::error!(error = %e, "could not save the sandbox store");
        store.outbox.retain(|o| o.sandbox_id != issue.sandbox_id);
        return Err(IssuerError::Store);
    }
    store.starting.push((issue.sandbox_id, issue.issuer_id));
    drop(store);
    // Logged before anything is handed out (E3.3): no `sandbox.issued`, no
    // sandbox. The store is free meanwhile.
    let logged = state.post_signed(PATH_SANDBOXES, &issue).await;
    let mut store = sandboxes.store.lock().await;
    store.starting.retain(|(id, _)| *id != issue.sandbox_id);
    if let Err(e) = logged {
        if !outcome_unknown(&e) {
            // A refusal: the server has nothing to end.
            store.outbox.retain(|o| o.sandbox_id != issue.sandbox_id);
            if let Err(e) = sandboxes.save(&store) {
                tracing::error!(error = %e, "could not save the sandbox store");
            }
        }
        return Err(map_server_error(&e));
    }
    store.outbox.retain(|o| o.sandbox_id != issue.sandbox_id);
    store.sandboxes.push(Stored {
        sandbox_id: issue.sandbox_id,
        issuer_id: issue.issuer_id,
        label: issue.label.clone(),
        profiles: issue.profiles.clone(),
        issued_at: now,
        expires_at: issue.expires_at,
        secret_sha256: Blob::new(digest.to_vec()),
        claimed_at: None,
    });
    if let Err(e) = sandboxes.save(&store) {
        // The server has it as issued: end it there, and hand out nothing.
        // The file still holds the pending end saved above.
        tracing::error!(error = %e, "could not save the sandbox store");
        store.sandboxes.retain(|s| s.sandbox_id != issue.sandbox_id);
        store.outbox.push(pending);
        drop(store);
        flush(state).await;
        return Err(IssuerError::Store);
    }
    drop(store);
    tracing::info!(sandbox = %issue.sandbox_id, issuer = %issue.issuer_id, "sandbox started");
    // Every copy of the secret here is wiped on drop: the bytes, their
    // text, and the JSON, written by hand into a buffer sized up front so
    // it never reallocates. The buffer is then moved into the answer, and
    // that one copy, in the HTTP stack, is not wiped.
    let blob = Blob::new(secret.expose().to_vec());
    let secret_text = Zeroizing::new(blob.to_text());
    drop(Zeroizing::new(blob.into_bytes()));
    drop(secret);
    let id_json = serde_json::to_string(&issue.sandbox_id).map_err(|_| IssuerError::Store)?;
    let expires = issue.expires_at.to_string();
    let mut body = Zeroizing::new(String::with_capacity(
        64 + id_json.len() + secret_text.len() + expires.len(),
    ));
    body.push_str("{\"sandbox_id\":");
    body.push_str(&id_json);
    body.push_str(",\"secret\":\"");
    body.push_str(&secret_text);
    body.push_str("\",\"expires_at\":");
    body.push_str(&expires);
    body.push('}');
    drop(secret_text);
    let mut res = Response::new(Body::from(std::mem::take(&mut *body)));
    res.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    res.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    Ok(res)
}

/// `GET /_klav/sandboxes`: the caller's live sandboxes, never another
/// issuer's.
pub async fn list(State(state): State<Arc<ProxyState>>, req: Request) -> Response {
    let run = async {
        let (parts, body) = local_request(&state, req).await?;
        let issuer = authenticate(&state, &parts, &body).await?;
        let sandboxes = state.sandboxes();
        let store = sandboxes.store.lock().await;
        let now = sandboxes.now();
        let mine: Vec<Listed<'_>> = store
            .sandboxes
            .iter()
            .filter(|s| s.issuer_id == issuer.agent_id && s.expires_at > now)
            .map(|s| Listed {
                sandbox_id: s.sandbox_id,
                label: &s.label,
                profiles: &s.profiles,
                issued_at: s.issued_at,
                expires_at: s.expires_at,
                claimed: s.claimed_at.is_some(),
            })
            .collect();
        // The MCP profiles this issuer's sandboxes may use, with their
        // endpoints (ADR 0049, layer 5): `klav sandbox start` writes their
        // client setup lines from it. A field an older `klav` ignores.
        let mcp: Vec<serde_json::Value> = state
            .profiles()
            .all()
            .into_iter()
            .filter(|p| issuer.profiles.contains(&p.name))
            .filter_map(|p| {
                p.mcp
                    .as_ref()
                    .map(|m| json!({ "profile": p.name, "endpoint": m.endpoint }))
            })
            .collect();
        Ok::<_, IssuerError>(Json(json!({ "sandboxes": mine, "mcp": mcp })).into_response())
    };
    run.await.unwrap_or_else(IntoResponse::into_response)
}

/// `POST /_klav/sandboxes/{id}/stop`: ends one of the caller's sandboxes
/// at once. Another issuer's, or one that does not exist, gets the same
/// `404`. `logged` says whether the server already has the end.
pub async fn stop(
    State(state): State<Arc<ProxyState>>,
    UrlPath(id): UrlPath<String>,
    req: Request,
) -> Response {
    let run = async {
        let (parts, body) = local_request(&state, req).await?;
        let issuer = authenticate(&state, &parts, &body).await?;
        let id: SandboxId = id.parse().map_err(|_| IssuerError::NotFound)?;
        let sandboxes = state.sandboxes();
        let mut store = sandboxes.store.lock().await;
        let Some(at) = store
            .sandboxes
            .iter()
            .position(|s| s.sandbox_id == id && s.issuer_id == issuer.agent_id)
        else {
            return Err(IssuerError::NotFound);
        };
        let stopped = store.sandboxes.remove(at);
        store.outbox.push(Outgoing {
            sandbox_id: id,
            reason: SandboxEnd::Stop,
            at: None,
        });
        if let Err(e) = sandboxes.save(&store) {
            // Back as it was: the file still has it live, and so must this
            // process, or a restart would bring it back with no end sent.
            tracing::error!(error = %e, "could not save the sandbox store");
            store.outbox.pop();
            store.sandboxes.insert(at, stopped);
            return Err(IssuerError::StopNotSaved);
        }
        store.note_end(id, SandboxEnd::Stop);
        // Ended here at once, with its calls in flight; the server hears
        // of it now or later.
        drop(store);
        state.cuts().cut_sandboxes(&[id]);
        flush(&state).await;
        let logged = !sandboxes
            .store
            .lock()
            .await
            .outbox
            .iter()
            .any(|o| o.sandbox_id == id);
        tracing::info!(sandbox = %id, logged, "sandbox stopped");
        Ok::<_, IssuerError>(Json(json!({ "logged": logged })).into_response())
    };
    run.await.unwrap_or_else(IntoResponse::into_response)
}

/// Most pages of the person's revocations one sweep reads.
const MAX_REVOCATION_PAGES: usize = 10;

/// What one read of the person's revocations found.
pub(crate) struct Revocations {
    /// The live sandboxes they cover, with the `at` each one's `person`
    /// end answers.
    pub(crate) covered: HashMap<SandboxId, i64>,
    /// The cursor the read started from.
    pub(crate) from: u64,
    /// The cursor to commit once `covered` has ended
    /// ([`end_revoked_and_due`]), and not before.
    pub(crate) to: u64,
}

/// Reads the person's revocations after the proxy's cursor (ADR 0036
/// E3.3), each checked against the account's identity, and returns the
/// live sandboxes they cover and the cursor to commit after ending them.
/// It does not move the cursor itself: a read cut short (the first sweep's
/// time limit) must leave it where it was, or the revocations it read
/// would be skipped with their sandboxes still live (review of #348).
///
/// The new cursor passes a revocation only once its sandboxes are
/// settled here: one that covers a sandbox whose start still waits for
/// the server stops the read until the next sweep, so a sandbox the
/// server logged before the revocation is never left live. An error
/// (the server out of reach, the proxy paused, a revocation that does not
/// check) stops the read there and ends nothing more.
///
/// Not asked while the proxy keeps no sandbox and starts none: no
/// revocation can cover one then.
pub(crate) async fn read_revocations(state: &ProxyState) -> Revocations {
    let mut covered = HashMap::new();
    let from = state.revocation_cursor();
    let mut since = from;
    for _ in 0..MAX_REVOCATION_PAGES {
        {
            let store = state.sandboxes().store.lock().await;
            if store.sandboxes.is_empty() && store.starting.is_empty() {
                break;
            }
        }
        let page = match state.sandbox_revocations(since).await {
            Ok(page) => page,
            // A page that does not check: no text of it, ever.
            Err(ClientError::Security(_)) => {
                tracing::error!(
                    "a revocation the server sent does not check against the account; none \
                     after it is applied, and the next sweep asks again"
                );
                break;
            }
            Err(e) => {
                tracing::warn!(
                    kind = crate::proxy::redacted_kind(&e),
                    "could not read the person's revocations; the next sweep asks again"
                );
                break;
            }
        };
        let store = state.sandboxes().store.lock().await;
        let (cursor, waiting) = take_revocations(&store, since, &page.revocations, &mut covered);
        drop(store);
        since = cursor;
        if waiting || !page.more || page.revocations.is_empty() {
            break;
        }
    }
    Revocations {
        covered,
        from,
        to: since,
    }
}

/// Adds to `covered` the live sandboxes of `revocations` (in log order),
/// with the `at` of the first one that covers each, and returns the cursor
/// past the last one taken and whether it stopped at one that covers a
/// start still waiting for the server. That one's live sandboxes are
/// covered too; only the cursor stays before it, so the next sweep reads
/// it again for the start.
fn take_revocations(
    store: &StoreFile,
    since: u64,
    revocations: &[klav_sdk::revocations::CheckedRevocation],
    covered: &mut HashMap<SandboxId, i64>,
) -> (u64, bool) {
    let mut cursor = since;
    for r in revocations {
        // The live ones it covers end now, even if it also covers a start
        // still waiting: only the cursor waits for that one.
        for id in &r.sandbox_ids {
            if store.sandboxes.iter().any(|s| s.sandbox_id == *id) {
                covered.entry(*id).or_insert(r.at);
            }
        }
        if r.sandbox_ids
            .iter()
            .any(|id| store.starting.iter().any(|(s, _)| s == id))
        {
            return (cursor, true);
        }
        cursor = r.seq;
    }
    (cursor, false)
}

/// Ends the sandboxes the person revoked ([`read_revocations`]), that
/// expired, were never claimed within [`INACTIVITY_MS`], or whose issuer
/// left the proxy's grant, lost one of their profiles, or is gone for the
/// server, then sends what the server has not taken yet. Returns how many
/// it ended.
pub async fn sweep(state: &ProxyState) -> usize {
    let count = end_revoked_and_due(state).await;
    flush(state).await;
    count
}

/// [`sweep`] without the send: reads the revocations, ends what is due,
/// and only then commits the cursor. Cancelled at any point, it commits
/// both or neither: [`end_due`] does not wait once it holds the store, and
/// nothing waits between it and the commit. The commit moves the cursor
/// only from where this read started, so a sweep that overlaps another
/// never sets it back over the other's (it reads those again next time;
/// [`end_due`] ends only what is still live, so nothing ends twice).
pub(crate) async fn end_revoked_and_due(state: &ProxyState) -> usize {
    let read = read_revocations(state).await;
    let count = end_due(state, &read.covered).await;
    state.commit_revocation_cursor(read.from, read.to);
    count
}

/// The ending half of [`sweep`]: takes out of the live set, and puts in the
/// outbox, the sandboxes `revoked` covers (with the `at` each `person` end
/// answers) and those due for another reason. From here on the proxy serves
/// none of them, whether or not the server has taken the end yet.
pub(crate) async fn end_due(state: &ProxyState, revoked: &HashMap<SandboxId, i64>) -> usize {
    let sandboxes = state.sandboxes();
    let issuers = state.issuers().await;
    let gone = state.gone_issuers();
    let mut store = sandboxes.store.lock().await;
    let now = sandboxes.now();
    let started_at = sandboxes.started_at;
    let mut ended = Vec::new();
    let StoreFile {
        sandboxes: live,
        last_seen,
        ..
    } = &mut *store;
    let last_seen = &*last_seen;
    live.retain(|s| {
        let still = issuers.iter().find(|i| i.agent_id == s.issuer_id);
        let person = revoked.get(&s.sandbox_id).copied();
        let reason = if person.is_some() {
            Some(SandboxEnd::Person)
        } else if s.expires_at <= now {
            Some(SandboxEnd::Ttl)
        } else if now.saturating_sub(last_activity(s, last_seen, started_at)) >= INACTIVITY_MS {
            Some(SandboxEnd::Inactivity)
        } else if still.is_none_or(|i| s.profiles.iter().any(|p| !i.profiles.contains(p)))
            || gone.contains(&s.issuer_id)
        {
            Some(SandboxEnd::IssuerRemoved)
        } else {
            None
        };
        if let Some(reason) = reason {
            ended.push(Outgoing {
                sandbox_id: s.sandbox_id,
                reason,
                at: person,
            });
        }
        reason.is_none()
    });
    let count = ended.len();
    for o in &ended {
        store.note_end(o.sandbox_id, o.reason);
        store.last_seen.remove(&o.sandbox_id);
        tracing::info!(sandbox = %o.sandbox_id, reason = o.reason.as_str(), "sandbox ended");
    }
    // Its calls in flight end with it, a stream above all (ADR 0036 §7,
    // note of 2026-11-19).
    let ids: Vec<SandboxId> = ended.iter().map(|o| o.sandbox_id).collect();
    state.cuts().cut_sandboxes(&ids);
    store.outbox.extend(ended);
    if count > 0
        && let Err(e) = sandboxes.save(&store)
    {
        tracing::error!(error = %e, "could not save the sandbox store");
    }
    count
}

/// When a sandbox was last used: its issue while unclaimed; once claimed,
/// its last call over the channel, its claim or this proxy's start,
/// whichever is latest (ADR 0036 §5: an hour without a connection ends
/// it).
fn last_activity(s: &Stored, last_seen: &HashMap<SandboxId, i64>, started_at: i64) -> i64 {
    match s.claimed_at {
        None => s.issued_at,
        Some(claimed) => claimed
            .max(started_at)
            .max(last_seen.get(&s.sandbox_id).copied().unwrap_or(0)),
    }
}

/// Sends the waiting ends in order, without holding the store, one flush
/// at a time. Drops one the server already has, never had, or will never
/// take ([`end_settled`]); keeps one it refused for itself and goes on;
/// stops at an error that would fail the rest too ([`stops_flush`]). The
/// pending end of a start still waiting for the server is not sent.
pub(crate) async fn flush(state: &ProxyState) {
    let sandboxes = state.sandboxes();
    let _one = sandboxes.flushing.lock().await;
    let waiting: Vec<Outgoing> = {
        let store = sandboxes.store.lock().await;
        store
            .outbox
            .iter()
            .filter(|o| !store.starting.iter().any(|(id, _)| *id == o.sandbox_id))
            .copied()
            .collect()
    };
    let mut done = Vec::new();
    // `theft` ends that leave the outbox without the server's OK.
    let mut lost = Vec::new();
    for next in waiting {
        // `theft` and `released` need the claim logged first: send a claim
        // the server may not have yet, with the key it was made with.
        match crate::claims::log_pending_claim(state, next.sandbox_id).await {
            Ok(()) => {}
            Err(e) if end_settled(&e) => {
                tracing::info!(sandbox = %next.sandbox_id, kind = crate::proxy::redacted_kind(&e), "the server already has this sandbox's end");
                done.push(next.sandbox_id);
                if next.reason == SandboxEnd::Theft {
                    lost.push(next.sandbox_id);
                }
                continue;
            }
            Err(e) if stops_flush(&e) => {
                tracing::warn!(sandbox = %next.sandbox_id, kind = crate::proxy::redacted_kind(&e), "the server did not take a sandbox's claim; its end is kept for the next sweep");
                break;
            }
            Err(e) => {
                tracing::warn!(sandbox = %next.sandbox_id, kind = crate::proxy::redacted_kind(&e), "the server refused a sandbox's claim; its end is kept, and the next ones are sent");
                continue;
            }
        }
        let path = sandbox_path(next.sandbox_id, SUFFIX_REVOKED);
        match state
            .post_signed(
                &path,
                &SandboxRevoked {
                    reason: next.reason,
                    at: next.at,
                },
            )
            .await
        {
            Ok(()) => done.push(next.sandbox_id),
            Err(e) if end_settled(&e) => {
                tracing::info!(sandbox = %next.sandbox_id, kind = crate::proxy::redacted_kind(&e), "the server already has this sandbox's end, or never had the sandbox");
                done.push(next.sandbox_id);
                if next.reason == SandboxEnd::Theft {
                    lost.push(next.sandbox_id);
                }
            }
            Err(e) if stops_flush(&e) => {
                tracing::warn!(sandbox = %next.sandbox_id, kind = crate::proxy::redacted_kind(&e), "the server did not take a sandbox's end; kept for the next sweep");
                break;
            }
            Err(e) => {
                tracing::warn!(sandbox = %next.sandbox_id, kind = crate::proxy::redacted_kind(&e), "the server refused a sandbox's end; kept, and the next ones are sent");
            }
        }
    }
    if done.is_empty() {
        return;
    }
    let mut store = sandboxes.store.lock().await;
    store.outbox.retain(|o| !done.contains(&o.sandbox_id));
    if let Err(e) = sandboxes.save(&store) {
        tracing::error!(error = %e, "could not save the sandbox store");
    }
    for sandbox_id in &lost {
        tracing::warn!(sandbox = %sandbox_id, "the proxy could not confirm that the Klav server logged this sandbox's theft signal (the server counts the sandbox as over): check the person's log; `klav-proxy status` lists it");
        store
            .unconfirmed_thefts
            .push(crate::claims::UnconfirmedTheft {
                sandbox_id: *sandbox_id,
                dropped_at: sandboxes.now(),
            });
    }
    let excess = store
        .unconfirmed_thefts
        .len()
        .saturating_sub(crate::claims::MAX_UNCONFIRMED_THEFTS);
    store.unconfirmed_thefts.drain(..excess);
    // A channel key is kept while its sandbox lives or its end waits.
    let before = store.channels.len();
    let StoreFile {
        sandboxes: live,
        outbox,
        channels,
        ..
    } = &mut *store;
    channels.retain(|c| {
        live.iter().any(|s| s.sandbox_id == c.sandbox_id)
            || outbox.iter().any(|o| o.sandbox_id == c.sandbox_id)
    });
    if (store.channels.len() != before || !lost.is_empty())
        && let Err(e) = sandboxes.save_channels(&store)
    {
        tracing::error!(error = %e, "could not save the sandbox channels");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(i64);

    impl Clock for Fixed {
        fn now_ms(&self) -> i64 {
            self.0
        }
    }

    fn clock() -> Arc<dyn Clock> {
        Arc::new(Fixed(1_800_000_000_000))
    }

    fn live(id: SandboxId) -> Stored {
        Stored {
            sandbox_id: id,
            issuer_id: AgentId::generate(),
            label: "chat".into(),
            profiles: vec!["northflank".into()],
            issued_at: 1,
            expires_at: i64::MAX,
            secret_sha256: Blob::new(vec![0; 32]),
            claimed_at: None,
        }
    }

    fn revocation(
        seq: u64,
        at: i64,
        ids: &[SandboxId],
    ) -> klav_sdk::revocations::CheckedRevocation {
        klav_sdk::revocations::CheckedRevocation {
            seq,
            at,
            sandbox_ids: ids.to_vec(),
        }
    }

    /// The person's revocations end the live sandboxes they cover, with
    /// the first one's `at`; a sandbox already gone is skipped; one whose
    /// start still waits for the server stops the read, with the cursor
    /// before that revocation.
    #[test]
    fn revocations_cover_live_sandboxes_and_wait_for_a_start() {
        let [a, b, gone, waiting] = [(); 4].map(|()| SandboxId::generate());
        let mut store = StoreFile {
            v: STORE_VERSION,
            sandboxes: vec![live(a), live(b)],
            ..StoreFile::default()
        };
        let mut covered = HashMap::new();
        let page = [
            revocation(4, 100, &[a]),
            revocation(6, 200, &[a, b, gone]),
            revocation(9, 300, &[b]),
        ];
        assert_eq!(take_revocations(&store, 2, &page, &mut covered), (9, false));
        assert_eq!(covered, HashMap::from([(a, 100), (b, 200)]));

        // A start the server may have logged before the revocation: wait.
        store.starting.push((waiting, AgentId::generate()));
        let mut covered = HashMap::new();
        let page = [
            revocation(10, 400, &[a]),
            revocation(12, 500, &[waiting, b]),
        ];
        assert_eq!(take_revocations(&store, 9, &page, &mut covered), (10, true));
        // The live sandbox the waiting one covers ends now (review of
        // #348, 1); the cursor stays before it, so it is read again.
        assert_eq!(covered, HashMap::from([(a, 400), (b, 500)]));
        // Nothing new: the cursor stays.
        assert_eq!(
            take_revocations(&store, 12, &[], &mut HashMap::new()),
            (12, false)
        );
    }

    fn api(status: u16, code: Option<ErrorCode>) -> ClientError {
        ClientError::Api {
            status,
            code,
            message: String::new(),
            current_version: None,
        }
    }

    /// A waiting end survives what a redeploy, a clock jump, a server
    /// without these routes or a wrong address looks like, and goes only
    /// once the server has it, says it never had the sandbox, or will never
    /// take the reason.
    #[test]
    fn an_end_is_dropped_only_when_the_server_settled_it() {
        for kept in [
            ClientError::Network("down".into()),
            ClientError::Paused(None),
            ClientError::Denied("clock".into()),
            api(500, None),
            api(502, None),
            api(503, None),
            api(429, None),
            api(400, None),
            // A route the server does not have, or an older server.
            api(404, None),
            api(404, Some(ErrorCode::NotFound)),
        ] {
            assert!(!end_settled(&kept), "{kept:?}");
        }
        for settled in [
            api(403, Some(ErrorCode::SandboxRevoked)),
            api(404, Some(ErrorCode::SandboxNotFound)),
            api(409, None),
        ] {
            assert!(end_settled(&settled), "{settled:?}");
        }
    }

    /// An end the server cannot take now stops the flush; one it refused
    /// for itself is kept and the next ones still go.
    #[test]
    fn only_an_error_for_every_end_stops_the_flush() {
        for stops in [
            ClientError::Network("down".into()),
            ClientError::Paused(None),
            ClientError::Denied("clock".into()),
            api(500, None),
            api(429, None),
            api(401, None),
            api(403, Some(ErrorCode::Forbidden)),
        ] {
            assert!(stops_flush(&stops), "{stops:?}");
        }
        for goes_on in [
            api(404, None),
            api(404, Some(ErrorCode::NotFound)),
            api(400, None),
        ] {
            assert!(!stops_flush(&goes_on), "{goes_on:?}");
        }
    }

    #[test]
    fn an_issuer_has_its_own_starts_and_nonces() {
        let s = Sandboxes::in_memory(clock());
        let (a, b) = (AgentId::generate(), AgentId::generate());
        for _ in 0..MAX_STARTS_PER_MINUTE {
            s.take_start(a).expect("room");
        }
        assert_eq!(s.take_start(a), Err(IssuerError::Busy));
        s.take_start(b).expect("another issuer counts on its own");
        for n in 0..MAX_NONCES_PER_AGENT {
            let mut nonce = [0; NONCE_LEN];
            nonce[..8].copy_from_slice(&(n as u64).to_be_bytes());
            s.take_nonce(a, nonce).expect("room");
        }
        assert_eq!(
            s.take_nonce(a, [0xff; NONCE_LEN]),
            Err(IssuerError::Busy),
            "one issuer cannot fill the cache"
        );
        s.take_nonce(b, [0xff; NONCE_LEN])
            .expect("the others still get theirs");
    }

    /// A start whose answer says nothing about the server keeps its end;
    /// a refusal does not, and a 5xx reads as the server out of reach.
    #[test]
    fn a_start_keeps_its_end_unless_the_server_refused() {
        for unknown in [
            ClientError::Network("lost".into()),
            api(502, None),
            api(429, None),
        ] {
            assert!(outcome_unknown(&unknown), "{unknown:?}");
            assert_eq!(map_server_error(&unknown), IssuerError::ServerUnreachable);
        }
        for refused in [
            ClientError::Paused(None),
            ClientError::Denied("no".into()),
            api(403, Some(ErrorCode::NotIssuer)),
            api(403, Some(ErrorCode::ProfileNotAllowed)),
            api(409, Some(ErrorCode::TooManySandboxes)),
            api(400, None),
        ] {
            assert!(!outcome_unknown(&refused), "{refused:?}");
        }
    }

    #[test]
    fn a_store_it_cannot_trust_is_refused_not_started_over() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("p.sandboxes.json");
        // Missing: empty.
        Sandboxes::open(path.clone(), clock()).expect("new store");
        for (bytes, why) in [
            (&b"{not json"[..], "cannot be read"),
            (br#"{"v":2,"sandboxes":[],"outbox":[]}"#, "version 2"),
            (
                br#"{"v":1,"sandboxes":[],"outbox":[],"x":1}"#,
                "cannot be read",
            ),
        ] {
            klav_client::home::write_private(&path, bytes).expect("write");
            let err = Sandboxes::open(path.clone(), clock())
                .err()
                .expect("refused");
            assert!(err.contains(why), "{err}");
        }
        klav_client::home::write_private(&path, br#"{"v":1,"sandboxes":[],"outbox":[]}"#)
            .expect("write");
        Sandboxes::open(path.clone(), clock()).expect("a good store");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
            let err = Sandboxes::open(path, clock()).err().expect("too wide");
            assert!(
                err.contains("sandbox store") && err.contains("644"),
                "{err}"
            );
        }
    }

    #[test]
    fn a_nonce_is_taken_once_and_the_cache_is_bounded() {
        let s = Sandboxes::in_memory(clock());
        let agent = AgentId::generate();
        s.take_nonce(agent, [1; NONCE_LEN]).expect("first");
        assert_eq!(
            s.take_nonce(agent, [1; NONCE_LEN]),
            Err(IssuerError::BadSignature)
        );
        // Another agent's same nonce is its own.
        s.take_nonce(AgentId::generate(), [1; NONCE_LEN])
            .expect("another agent");
        // Many issuers fill it, each under its own cap.
        let others: Vec<AgentId> = (0..8).map(|_| AgentId::generate()).collect();
        for n in 0..MAX_NONCES - 2 {
            let mut nonce = [0; NONCE_LEN];
            nonce[..8].copy_from_slice(&(n as u64).to_be_bytes());
            nonce[15] = 9;
            s.take_nonce(others[n % others.len()], nonce).expect("room");
        }
        assert_eq!(
            s.take_nonce(agent, [2; NONCE_LEN]),
            Err(IssuerError::Busy),
            "full: wait, never forget one early"
        );
    }

    #[test]
    fn every_issuer_error_carries_its_code_and_says_nothing_secret() {
        let all = [
            (IssuerError::BadSignature, 401, "klav_not_allowed"),
            (IssuerError::NotLocal, 403, "klav_not_allowed"),
            (IssuerError::NotIssuer, 403, "klav_not_issuer"),
            (
                IssuerError::ProfileNotAllowed,
                403,
                "klav_profile_not_allowed",
            ),
            (IssuerError::TooMany, 409, "klav_too_many_sandboxes"),
            (IssuerError::BadRequest("x".into()), 400, "klav_bad_request"),
            (IssuerError::AgentsPaused, 423, "klav_agents_paused"),
            (
                IssuerError::ServerUnreachable,
                503,
                "klav_server_unreachable",
            ),
            (IssuerError::ServerDenied, 403, "klav_not_allowed"),
            (IssuerError::NotFound, 404, "klav_sandbox_not_found"),
            (IssuerError::Busy, 429, "klav_rate_limited"),
            (IssuerError::Backlog, 503, "klav_proxy_backlog"),
            (IssuerError::Store, 500, "klav_proxy_store"),
        ];
        for (e, status, code) in all {
            assert_eq!(e.code(), code);
            let res = e.into_response();
            assert_eq!(res.status().as_u16(), status, "{code}");
            assert_eq!(res.headers()[KLAV_ERROR], code);
        }
    }
}
