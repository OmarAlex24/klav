//! Mode (a), the base URL (ADR 0036 §7): a tool sends plain HTTP to
//! `http://127.0.0.1:PORT/<profile>/<path>`, and the proxy sends it to the
//! profile's upstream over HTTPS with the credential in the profile's
//! header.
//!
//! For each request, in this order: the profile by name; the method and
//! path as received, checked to be ones the policy can judge and the URL
//! parser will not re-encode; the profile's rate; the body, up to a limit;
//! the Klav server, asked for the item for this one request (never
//! cached); the credential into the profile's header after every header
//! that could carry another one is dropped; no redirects, no compressed
//! answers; and the answer with the value redacted from its headers and
//! from its body as it streams.
//!
//! A `text/event-stream` answer is a stream (ADR 0036 §7, note of
//! 2026-11-19, the MCP gate): the request timeout covers only its headers,
//! it may stay open [`STREAM_MAX`] at most and [`STREAM_IDLE`] without a
//! piece, its redactor emits through each line end, and it is cut when its
//! sandbox ends or the person pauses the agents.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::stream;
use klav_client::ClientError;
use klav_core::ids::{ApprovalId, ItemId};
use klav_proto::agent::ApprovalStatus;
use klav_sdk::{ProxyAccess, Redactor, Session, StreamRedactor};
use tokio::sync::RwLock;

use crate::errors::{Blocked, NotAllowed, ProxyError};
use crate::net::RefusedAddress;
use crate::profiles::{self, Profile, Profiles};
use crate::rate::RateLimits;

/// Largest request body the proxy forwards (it is read whole first).
pub const DEFAULT_MAX_BODY: usize = 10 * 1024 * 1024;
/// Longest a call to the provider may take, answer included. For a stream
/// (`text/event-stream`), only until its headers: then [`STREAM_MAX`].
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
/// Longest a stream (`text/event-stream`) may stay open, counted from when
/// its redactor took the value (ADR 0036 §7, note of 2026-11-19). It never
/// outlives its sandbox either.
pub const STREAM_MAX: Duration = Duration::from_secs(15 * 60);
/// Longest a stream waits for the provider's next piece, and for the
/// caller to take the previous one: [`BODY_IDLE`] for a stream.
pub const STREAM_IDLE: Duration = Duration::from_secs(2 * 60);
/// Requests handled at once. Each may hold a request body of up to
/// `--max-body` in memory, and a redactor with the value until its answer
/// ends (the request timeout, or [`STREAM_MAX`] for a stream); one over
/// the limit gets `429 klav_rate_limited`.
pub const MAX_IN_FLIGHT: usize = 16;
/// Connections open at once on the local listener; one more waits until
/// another closes.
pub const MAX_CONNECTIONS: usize = 64;
/// Longest the proxy waits for the provider's next piece of an answer, and
/// for the caller to take the previous one. Past it the answer is cut and
/// the redactor, which holds the value, is dropped. A stream has
/// [`STREAM_IDLE`] instead.
pub const BODY_IDLE: Duration = Duration::from_secs(60);
/// Calls a minute from one sandbox, over all its profiles (ADR 0036 §8).
pub const SANDBOX_RATE_PER_MINUTE: u32 = 60;
/// Of the [`MAX_IN_FLIGHT`] requests, how many one sandbox may hold at
/// once: a sandbox never takes every slot.
pub const SANDBOX_IN_FLIGHT: usize = 4;
/// Longest the proxy waits for the caller's next piece of a request body.
/// The whole body also has to arrive within the request timeout.
pub const REQUEST_BODY_IDLE: Duration = Duration::from_secs(10);
/// Approvals the proxy remembers at most (each until it expires).
const MAX_PENDING: usize = 256;
/// Query parameter names that carry a method in some frameworks: a request
/// with one is refused, since the policy judges the request's own method.
const METHOD_QUERY_NAMES: [&str; 4] = [
    "_method",
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];
/// How often the proxy looks for a newer grant (new profiles, new item
/// keys after a revocation elsewhere).
pub const GRANT_REFRESH: Duration = Duration::from_secs(30);

/// Headers the caller's request never passes upstream: framing and
/// hop-by-hop, anything that carries a credential or overrides the
/// method, and the proxy's own. The profile's header is dropped too.
const DROPPED_REQUEST_HEADERS: [&str; 32] = [
    "x-original-url",
    "x-rewrite-url",
    "x-original-uri",
    "x-original-host",
    "x-host",
    "x-forwarded",
    "via",
    "client-ip",
    "x-client-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "fastly-client-ip",
    "x-cluster-client-ip",
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
    "expect",
    "accept-encoding",
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
    "forwarded",
    "x-real-ip",
];

/// Headers the provider's answer never passes back: framing (the body is
/// re-streamed) and hop-by-hop.
const DROPPED_RESPONSE_HEADERS: [&str; 8] = [
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
];

/// Headers a sandbox never gets back from the provider: they set a
/// credential of the provider's own (a session cookie), or start a sign-in
/// that would end in one (`WWW-Authenticate`: an MCP client would begin
/// an OAuth flow with the provider, and get a token that works without the
/// proxy; ADR 0036 §7, note of 2026-11-19, T148).
const SANDBOX_DROPPED_RESPONSE_HEADERS: [&str; 3] =
    ["set-cookie", "set-cookie2", "www-authenticate"];

/// What the proxy remembers of an item between calls: never its value.
#[derive(Default, Clone)]
struct Seen {
    version: u64,
    tags: Vec<String>,
}

/// Everything a request needs.
pub struct ProxyState {
    session: RwLock<Session>,
    profiles: std::sync::RwLock<Profiles>,
    client: reqwest::Client,
    limits: RateLimits,
    seen: Mutex<HashMap<ItemId, Seen>>,
    /// Approvals asked for and not yet used, by request (query included),
    /// with when they expire: a retry of the same request checks it instead
    /// of asking the person again.
    pending: Mutex<HashMap<String, (ApprovalId, i64)>>,
    max_body: usize,
    request_timeout: Duration,
    /// [`STREAM_MAX`] and [`STREAM_IDLE`] (tests shorten them).
    stream_limits: std::sync::RwLock<(Duration, Duration)>,
    /// The calls in flight, to cut when their sandbox ends or the person
    /// pauses the agents.
    cuts: Arc<crate::cuts::Cuts>,
    /// The port the listener is bound to: the only one a request's `Host`
    /// may name.
    local_port: u16,
    /// `--no-local-calls` (ADR 0042 §3): every profile call on the
    /// loopback listener is refused; the issuer API and the channel stay.
    no_local_calls: bool,
    in_flight: Arc<tokio::sync::Semaphore>,
    /// Each sandbox's own share of `in_flight` ([`SANDBOX_IN_FLIGHT`]).
    sandbox_in_flight: Mutex<HashMap<klav_core::ids::SandboxId, Arc<tokio::sync::Semaphore>>>,
    /// [`REQUEST_BODY_IDLE`], in ms (tests shorten it).
    request_body_idle_ms: std::sync::atomic::AtomicU64,
    /// Where the next call waits after its access (tests).
    #[cfg(test)]
    access_gate: Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
    /// Where the next claim waits before the server logs it (tests).
    #[cfg(test)]
    claim_gate: Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
    /// What the redactor counted per profile since start (only numbers).
    counts: Arc<crate::counts::Counts>,
    /// The sandboxes its issuers started (ADR 0036 §4).
    sandboxes: crate::sandboxes::Sandboxes,
    /// Issuers of its grant the server no longer counts as issuers
    /// (`gone_issuers` of `GET /v1/agent/me`, ADR 0036 E3.3): their
    /// sandboxes end with `issuer_removed`.
    gone_issuers: Mutex<Vec<klav_core::ids::AgentId>>,
    /// The position in the account's log of the last revocation by the
    /// person it acted on (ADR 0036 E3.3). In memory only: after a start
    /// it reads them all again, and skips those of sandboxes it no longer
    /// keeps.
    revocation_cursor: Mutex<u64>,
    /// Tests: how many more reads of the revocations answer before the
    /// next one never does (`None`: all of them).
    #[cfg(test)]
    revocation_reads: Mutex<Option<usize>>,
    /// Its store's epoch and heartbeat (ADR 0036 E3.3).
    heartbeats: std::sync::RwLock<Arc<crate::heartbeat::Heartbeats>>,
    /// Who holds the sandbox channel's connections: which channel keys are
    /// connected, for the heartbeat.
    channel_admission: Arc<crate::channel::Admission>,
    /// Whether the server's last answer to the grant's refresh (every
    /// [`GRANT_REFRESH`]) said the person paused this proxy (`403
    /// agents_paused`). Only that request sets and clears it: it names no
    /// issuer, so a pause of one issuer, which the server gives that
    /// issuer's sandboxes on their calls, never reads as the whole proxy's.
    /// A sandbox's `GET /_klav/status` answers with the pause while it is
    /// set.
    paused: std::sync::atomic::AtomicBool,
    /// Tests: every signed `POST` and `PUT` answers `409` without reaching
    /// the server, and is counted (a server that refuses every epoch).
    #[cfg(test)]
    always_conflict: Mutex<Option<usize>>,
    /// The MCP gateway's sessions, pending requests and tool definitions
    /// (ADR 0049 §5.2), in memory only.
    mcp: Arc<crate::mcp::McpState>,
    /// Whether the server's last `GET /v1/agent/me` advertised the
    /// account's `mcp_gateway` switch (ADR 0049 §9). Off until it does:
    /// then MCP profiles serve in "no tool claims" mode.
    mcp_gateway: std::sync::atomic::AtomicBool,
    /// Klav Cloud's hosted proxy: the account's live sandboxes, whatever
    /// their issuer (ADR 0051 §3.3). `None` for every other proxy.
    account_live_cap: Option<usize>,
    /// Klav Cloud's hosted proxy: the account's budget for calls and
    /// request bodies (ADR 0051 §3.3). `None` for every other proxy.
    account_budget: Option<AccountBudget>,
}

/// Klav Cloud's per-account budget (ADR 0051 §3.3), apart from the quotas
/// the enclave's middleware counts:
/// - **calls to providers at once:** [`ProxyState`]'s `in_flight` is sized
///   to it, and a call over it waits its turn for `queue_wait`, then gets
///   `503 klav_proxy_backlog`;
/// - **bytes of request bodies held at once:** each piece of a body takes
///   its bytes from `buffer` as it arrives, and a body that does not fit
///   gets `503 klav_proxy_backlog`.
///
/// Both are taken only once the call is known to come from a sandbox bound
/// to its key, and are given back when the call's answer ends, or when the
/// caller goes away first.
struct AccountBudget {
    buffer: Arc<tokio::sync::Semaphore>,
    queue_wait: Duration,
}

/// Why a request body was not read whole ([`read_body`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyError {
    /// Over the body limit, whether it said its length or not.
    TooLarge,
    /// The account's budget for bodies held at once is full.
    Budget,
    /// It stalled, broke, or took longer than the request may.
    Broken,
}

impl ProxyState {
    /// The state for `session` behind a listener on `local_port`, reaching
    /// providers through `client` ([`crate::net::upstream_client`] in a
    /// release build).
    pub fn new(session: Session, client: reqwest::Client, local_port: u16) -> Self {
        let profiles = profiles::of(&session);
        Self {
            session: RwLock::new(session),
            profiles: std::sync::RwLock::new(profiles),
            client,
            limits: RateLimits::default(),
            seen: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            max_body: DEFAULT_MAX_BODY,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            stream_limits: std::sync::RwLock::new((STREAM_MAX, STREAM_IDLE)),
            cuts: Arc::new(crate::cuts::Cuts::default()),
            local_port,
            no_local_calls: false,
            in_flight: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT)),
            sandbox_in_flight: Mutex::new(HashMap::new()),
            #[cfg(test)]
            access_gate: Mutex::new(None),
            #[cfg(test)]
            claim_gate: Mutex::new(None),
            request_body_idle_ms: std::sync::atomic::AtomicU64::new(
                u64::try_from(REQUEST_BODY_IDLE.as_millis()).unwrap_or(u64::MAX),
            ),
            counts: Arc::new(crate::counts::Counts::in_memory()),
            sandboxes: crate::sandboxes::Sandboxes::in_memory(Arc::new(
                crate::sandboxes::SystemClock,
            )),
            gone_issuers: Mutex::new(Vec::new()),
            revocation_cursor: Mutex::new(0),
            #[cfg(test)]
            revocation_reads: Mutex::new(None),
            heartbeats: std::sync::RwLock::new(Arc::new(crate::heartbeat::Heartbeats::in_memory())),
            channel_admission: Arc::new(crate::channel::Admission::default()),
            paused: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            always_conflict: Mutex::new(None),
            mcp: Arc::new(crate::mcp::McpState::default()),
            mcp_gateway: std::sync::atomic::AtomicBool::new(false),
            account_live_cap: None,
            account_budget: None,
        }
    }

    /// The MCP gateway's tables.
    pub(crate) fn mcp(&self) -> &Arc<crate::mcp::McpState> {
        &self.mcp
    }

    /// Whether the account's `mcp_gateway` switch was on at the last
    /// refresh (ADR 0049 §9).
    pub(crate) fn mcp_gateway(&self) -> bool {
        self.mcp_gateway.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The session, read.
    pub(crate) async fn session(&self) -> tokio::sync::RwLockReadGuard<'_, Session> {
        self.session.read().await
    }

    /// The tags of `item` as last delivered (empty before the first call).
    pub(crate) fn seen_tags(&self, item: ItemId) -> Vec<String> {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&item)
            .map(|s| s.tags.clone())
            .unwrap_or_default()
    }

    /// The wait for each piece of a request body, and for the whole of it.
    pub(crate) fn body_waits(&self) -> (Duration, Duration) {
        (
            Duration::from_millis(
                self.request_body_idle_ms
                    .load(std::sync::atomic::Ordering::Relaxed),
            ),
            self.request_timeout,
        )
    }

    /// The profile's rate and, for a sandbox, its own (ADR 0036 §8): both
    /// checked before either is charged, so a sandbox over its own rate
    /// never spends the profile's, which other callers share.
    pub(crate) fn check_rates(
        &self,
        profile: &Profile,
        sandbox: Option<klav_core::ids::SandboxId>,
    ) -> Result<(), ProxyError> {
        let sandbox_rate = sandbox.map(|id| (format!("sandbox:{id}"), SANDBOX_RATE_PER_MINUTE));
        let mut rates = vec![(profile.name.clone(), profile.rate_per_minute)];
        rates.extend(sandbox_rate);
        self.limits
            .check_all(&rates, Instant::now())
            .map_err(|retry_after| ProxyError::RateLimited { retry_after })
    }

    /// Whether the server's last answer said the person paused this proxy.
    pub(crate) fn paused(&self) -> bool {
        self.paused.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Takes what the grant's refresh says of a pause: `403 agents_paused`
    /// sets it, a success clears it, any other error (the server out of
    /// reach, say) leaves it as it was.
    fn note_pause<T>(&self, outcome: &Result<T, ClientError>) {
        let paused = match outcome {
            Ok(_) => false,
            Err(ClientError::Paused(_)) => true,
            Err(_) => return,
        };
        self.paused
            .store(paused, std::sync::atomic::Ordering::SeqCst);
        // Every call in flight, a stream above all, ends with the pause
        // (ADR 0036 §7, note of 2026-11-19): a new one is refused anyway.
        if paused {
            self.cuts.cut_all_paused();
        }
    }

    /// The calls in flight.
    pub(crate) fn cuts(&self) -> &crate::cuts::Cuts {
        &self.cuts
    }

    /// Registers a call in flight, to cut when its sandbox ends or the
    /// person pauses the agents.
    pub(crate) fn register_cut(
        &self,
        sandbox: Option<klav_core::ids::SandboxId>,
    ) -> crate::cuts::CutHandle {
        self.cuts.register(sandbox)
    }

    /// Shortens [`STREAM_MAX`] and [`STREAM_IDLE`] (tests).
    #[cfg(test)]
    pub(crate) fn set_stream_limits(&self, max: Duration, idle: Duration) {
        *self
            .stream_limits
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = (max, idle);
    }

    fn stream_limits(&self) -> (Duration, Duration) {
        *self
            .stream_limits
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Cuts the calls in flight that a refusal of the server says are over:
    /// a sandbox the server bars, or one whose issuer it paused (then every
    /// live sandbox of that issuer, which the server refuses alike).
    async fn cut_for(&self, sandbox: Option<klav_core::ids::SandboxId>, e: &ProxyError) {
        let Some(sandbox) = sandbox else {
            return;
        };
        match e {
            ProxyError::SandboxRevoked => self.cuts.cut_sandboxes(&[sandbox]),
            ProxyError::AgentsPaused => {
                let store = self.sandboxes.store.lock().await;
                let issuer = store
                    .sandboxes
                    .iter()
                    .find(|s| s.sandbox_id == sandbox)
                    .map(|s| s.issuer_id);
                let mut of_issuer: Vec<_> = store
                    .sandboxes
                    .iter()
                    .filter(|s| Some(s.issuer_id) == issuer)
                    .map(|s| s.sandbox_id)
                    .collect();
                drop(store);
                of_issuer.push(sandbox);
                self.cuts.pause_sandboxes(&of_issuer);
            }
            _ => {}
        }
    }

    /// Keeps its store's epoch and heartbeat in `heartbeats` (its file),
    /// instead of in memory.
    pub fn with_heartbeats(self, heartbeats: crate::heartbeat::Heartbeats) -> Self {
        *self
            .heartbeats
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(heartbeats);
        self
    }

    /// Its store's epoch and heartbeat.
    pub(crate) fn heartbeats(&self) -> Arc<crate::heartbeat::Heartbeats> {
        Arc::clone(
            &self
                .heartbeats
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Replaces the heartbeat state, as a restart that reads the file again
    /// would (tests).
    #[cfg(test)]
    pub(crate) fn set_heartbeats(&self, heartbeats: crate::heartbeat::Heartbeats) {
        *self
            .heartbeats
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(heartbeats);
    }

    /// The sandbox channel's admission.
    pub(crate) fn channel_admission(&self) -> Arc<crate::channel::Admission> {
        Arc::clone(&self.channel_admission)
    }

    /// The channel keys (SHA-256 of the SPKI) that hold a connection now.
    pub(crate) fn connected_channel_keys(&self) -> std::collections::HashSet<[u8; 32]> {
        self.channel_admission.connected_keys()
    }

    /// Keeps the sandboxes in `sandboxes` (its store), instead of in
    /// memory.
    pub fn with_sandboxes(mut self, sandboxes: crate::sandboxes::Sandboxes) -> Self {
        self.sandboxes = sandboxes;
        self
    }

    /// The sandboxes.
    pub fn sandboxes(&self) -> &crate::sandboxes::Sandboxes {
        &self.sandboxes
    }

    /// Whether it serves profile calls on its loopback listener (not with
    /// `--no-local-calls`).
    pub(crate) fn serves_local_calls(&self) -> bool {
        !self.no_local_calls
    }

    /// The port of the local listener.
    pub(crate) fn local_port(&self) -> u16 {
        self.local_port
    }

    /// The issuer `agent` as the proxy's current grant lists it.
    pub(crate) async fn issuer(
        &self,
        agent: klav_core::ids::AgentId,
    ) -> Option<klav_proto::agent::SandboxIssuer> {
        self.session
            .read()
            .await
            .grant()
            .payload
            .issuers
            .iter()
            .find(|i| i.agent_id == agent)
            .cloned()
    }

    /// The issuers of the proxy's current grant.
    pub(crate) async fn issuers(&self) -> Vec<klav_proto::agent::SandboxIssuer> {
        self.session.read().await.grant().payload.issuers.clone()
    }

    /// Sets the list of gone issuers (tests).
    #[cfg(test)]
    pub(crate) fn set_gone_issuers(&self, gone: Vec<klav_core::ids::AgentId>) {
        *self.gone_issuers.lock().unwrap_or_else(|e| e.into_inner()) = gone;
    }

    /// Where the next read of the person's revocations starts.
    pub(crate) fn revocation_cursor(&self) -> u64 {
        *self
            .revocation_cursor
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Moves the cursor of the person's revocations to `seq` (tests: as
    /// after a restart; Klav Cloud's enclave: where the holder of a
    /// hand-off left it).
    #[cfg_attr(not(any(test, feature = "enclave")), allow(dead_code))]
    pub(crate) fn set_revocation_cursor(&self, seq: u64) {
        *self
            .revocation_cursor
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = seq;
    }

    /// Moves the cursor of the person's revocations from `from` to `to`,
    /// only if no other sweep moved it since `from` was read.
    pub(crate) fn commit_revocation_cursor(&self, from: u64, to: u64) {
        let mut cursor = self
            .revocation_cursor
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if *cursor == from {
            *cursor = to;
        }
    }

    /// Tests: from now on every signed `POST` and `PUT` answers `409`
    /// without reaching the server ([`Self::conflicts`] counts them), or,
    /// with `false`, they reach it again.
    #[cfg(test)]
    pub(crate) fn always_conflict(&self, on: bool) {
        *self
            .always_conflict
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = on.then_some(0);
    }

    /// Tests: how many requests got the `409` of [`Self::always_conflict`].
    #[cfg(test)]
    pub(crate) fn conflicts(&self) -> usize {
        self.always_conflict
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .unwrap_or(0)
    }

    /// Tests: after `reads` more reads of the revocations, the next one
    /// stalls for good, as a server that stops answering mid-read.
    #[cfg(test)]
    pub(crate) fn stall_revocations_after(&self, reads: Option<usize>) {
        *self
            .revocation_reads
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = reads;
    }

    /// The person's revocations of this proxy's sandboxes after `since`,
    /// each checked against the account's identity, under the session's
    /// read lock.
    pub(crate) async fn sandbox_revocations(
        &self,
        since: u64,
    ) -> Result<klav_sdk::revocations::RevocationPage, ClientError> {
        #[cfg(test)]
        {
            let stall = {
                let mut left = self
                    .revocation_reads
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                match left.as_mut() {
                    Some(0) => true,
                    Some(n) => {
                        *n -= 1;
                        false
                    }
                    None => false,
                }
            };
            if stall {
                std::future::pending::<()>().await;
            }
        }
        let session = self.session.read().await;
        session.agent().sandbox_revocations(since).await
    }

    /// The issuers the server last said are gone.
    pub(crate) fn gone_issuers(&self) -> Vec<klav_core::ids::AgentId> {
        self.gone_issuers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The names of the profiles it holds.
    pub(crate) fn profile_names(&self) -> Vec<String> {
        self.profiles()
            .all()
            .into_iter()
            .map(|p| p.name.clone())
            .collect()
    }

    /// The proxy's own agent ID.
    pub(crate) async fn proxy_id(&self) -> klav_core::ids::AgentId {
        self.session.read().await.agent().id()
    }

    /// A signed `POST` of `body` to the Klav server that must answer with
    /// success and no body.
    pub(crate) async fn post_signed<B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<(), ClientError> {
        self.send_signed(reqwest::Method::POST, path, body).await
    }

    /// A signed `PUT` of `body`, like [`Self::post_signed`].
    pub(crate) async fn put_signed<B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<(), ClientError> {
        self.send_signed(reqwest::Method::PUT, path, body).await
    }

    async fn send_signed<B: serde::Serialize>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: &B,
    ) -> Result<(), ClientError> {
        #[cfg(test)]
        if let Some(count) = self
            .always_conflict
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
        {
            *count += 1;
            return Err(ClientError::Api {
                status: 409,
                code: None,
                message: format!("{method} {path}: refused (test)"),
                current_version: None,
            });
        }
        let bytes = serde_json::to_vec(body)
            .map_err(|e| ClientError::Invalid(format!("request body: {e}")))?;
        let session = self.session.read().await;
        let sent = match session.agent().send(method, path, Some(&bytes)).await {
            Ok(res) => klav_client::api::empty(res).await,
            Err(e) => Err(e),
        };
        drop(session);
        sent
    }

    /// Caps the account's live sandboxes, whatever their issuer: Klav
    /// Cloud's per-account quota (ADR 0051 §3.3). A start over it is
    /// refused with `klav_rate_limited`.
    pub fn with_account_live_cap(mut self, cap: usize) -> Self {
        self.account_live_cap = Some(cap);
        self
    }

    /// [`ProxyState::with_account_live_cap`], if set.
    pub(crate) fn account_live_cap(&self) -> Option<usize> {
        self.account_live_cap
    }

    /// Klav Cloud's per-account budget (ADR 0051 §3.3): at most `calls`
    /// calls to providers at once, a call over it waiting `queue_wait` for
    /// its turn, and at most `buffer_bytes` bytes of request bodies held at
    /// once. Over either: `503 klav_proxy_backlog`. A body over the limit
    /// then gets `413 klav_upstream_blocked` instead of the self-hosted
    /// proxy's `403`.
    pub fn with_account_budget(
        mut self,
        calls: usize,
        buffer_bytes: usize,
        queue_wait: Duration,
    ) -> Self {
        self.in_flight = Arc::new(tokio::sync::Semaphore::new(calls.max(1)));
        self.account_budget = Some(AccountBudget {
            buffer: Arc::new(tokio::sync::Semaphore::new(
                buffer_bytes.min(tokio::sync::Semaphore::MAX_PERMITS),
            )),
            queue_wait,
        });
        self
    }

    /// The account's budget for request bodies, when there is one.
    pub(crate) fn body_budget(&self) -> Option<&Arc<tokio::sync::Semaphore>> {
        self.account_budget.as_ref().map(|b| &b.buffer)
    }

    /// Bytes of the account's body budget not held now (tests).
    #[cfg(all(test, feature = "enclave-testkit"))]
    pub(crate) fn free_buffer(&self) -> usize {
        self.body_budget().map_or(0, |b| b.available_permits())
    }

    /// What a body that was not read whole gets: Klav Cloud's proxy says
    /// which limit; a self-hosted one answers as it always did.
    pub(crate) fn body_refusal(&self, e: BodyError) -> ProxyError {
        match (e, self.account_budget.is_some()) {
            (BodyError::TooLarge, true) => ProxyError::BodyTooLarge,
            (BodyError::Budget, _) => ProxyError::Backlog {
                retry_after: 1,
                why: crate::errors::Backlog::Memory,
            },
            _ => ProxyError::NotAllowed(NotAllowed::Malformed),
        }
    }

    /// Sets the request body limit.
    pub fn with_max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
    }

    /// Sets the upstream timeout.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Refuses every profile call on the loopback listener
    /// (`--no-local-calls`, ADR 0042 §3).
    pub fn without_local_calls(mut self) -> Self {
        self.no_local_calls = true;
        self
    }

    /// Makes the next call stop right after its access: `reached` is
    /// notified there, and it goes on when `go` is (tests).
    #[cfg(test)]
    pub(crate) fn hold_after_access(
        &self,
        reached: Arc<tokio::sync::Notify>,
        go: Arc<tokio::sync::Notify>,
    ) {
        *self.access_gate.lock().unwrap_or_else(|e| e.into_inner()) = Some((reached, go));
    }

    #[cfg(test)]
    async fn after_access(&self) {
        let gate = self
            .access_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some((reached, go)) = gate {
            reached.notify_one();
            go.notified().await;
        }
    }

    /// Makes the next claim stop before the server logs it: `reached` is
    /// notified there, and it goes on when `go` is (tests).
    #[cfg(test)]
    pub(crate) fn hold_before_claim_log(
        &self,
        reached: Arc<tokio::sync::Notify>,
        go: Arc<tokio::sync::Notify>,
    ) {
        *self.claim_gate.lock().unwrap_or_else(|e| e.into_inner()) = Some((reached, go));
    }

    #[cfg(test)]
    pub(crate) async fn before_claim_log(&self) {
        let gate = self
            .claim_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some((reached, go)) = gate {
            reached.notify_one();
            go.notified().await;
        }
    }

    /// Another wait for each piece of a request body (tests).
    #[cfg(test)]
    pub(crate) fn set_request_body_idle(&self, idle: Duration) {
        self.request_body_idle_ms.store(
            u64::try_from(idle.as_millis()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Free request slots (tests).
    #[cfg(test)]
    pub(crate) fn free_slots(&self) -> usize {
        self.in_flight.available_permits()
    }

    /// The slots a request holds until its answer ends: one of all, and
    /// for a sandbox one of its own. A full share of the sandbox, or a full
    /// proxy, is `429 klav_rate_limited` at once; on Klav Cloud's proxy a
    /// call waits its turn among the account's for a while first, then
    /// gets `503 klav_proxy_backlog` ([`ProxyState::with_account_budget`]).
    pub(crate) async fn take_slots(
        &self,
        sandbox: Option<klav_core::ids::SandboxId>,
    ) -> Result<Slots, ProxyError> {
        let busy = ProxyError::RateLimited { retry_after: 1 };
        let own = self.take_own_slot(sandbox).ok_or_else(|| busy.clone())?;
        let all = match &self.account_budget {
            Some(budget) => tokio::time::timeout(
                budget.queue_wait,
                Arc::clone(&self.in_flight).acquire_owned(),
            )
            .await
            .ok()
            .and_then(Result::ok)
            .ok_or(ProxyError::Backlog {
                retry_after: 1,
                why: crate::errors::Backlog::Calls,
            })?,
            None => Arc::clone(&self.in_flight)
                .try_acquire_owned()
                .map_err(|_| busy)?,
        };
        Ok(Slots {
            _all: all,
            _own: own,
            _buffer: None,
        })
    }

    /// The sandbox's own slot: `Some(None)` for a call that is not a
    /// sandbox's, `None` when the sandbox's share is full.
    fn take_own_slot(
        &self,
        sandbox: Option<klav_core::ids::SandboxId>,
    ) -> Option<Option<tokio::sync::OwnedSemaphorePermit>> {
        Some(match sandbox {
            Some(id) => {
                let mut shares = self
                    .sandbox_in_flight
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                // Forget the shares nobody holds (ended sandboxes, idle
                // ones): each held slot keeps a clone of its share.
                shares.retain(|_, s| Arc::strong_count(s) > 1);
                let share = shares
                    .entry(id)
                    .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(SANDBOX_IN_FLIGHT)));
                Some(Arc::clone(share).try_acquire_owned().ok()?)
            }
            None => None,
        })
    }

    /// The profiles in force.
    pub fn profiles(&self) -> Profiles {
        self.profiles
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Whole values replaced for `profile` since start.
    pub fn redactions(&self, profile: &str) -> u64 {
        self.counts.get(profile).redacted
    }

    /// Pieces of `profile`'s value found and left as they are since start
    /// (T149): only the person sees this number.
    pub fn partial_matches(&self, profile: &str) -> u64 {
        self.counts.get(profile).partial
    }

    /// Its counts (for the task that saves them).
    pub fn counts(&self) -> Arc<crate::counts::Counts> {
        Arc::clone(&self.counts)
    }

    /// Keeps the counts in `counts` (a file `status` reads).
    pub fn with_counts(mut self, counts: crate::counts::Counts) -> Self {
        self.counts = Arc::new(counts);
        self
    }

    /// Looks for a newer grant and takes its profiles and keys, then asks
    /// which issuers are gone. Only the grant can fail it: a failed `me`
    /// leaves the last list of gone issuers as it was (logged), and no
    /// sandbox ends because of it.
    pub async fn refresh(&self) -> Result<(), ClientError> {
        let refreshed = self.refresh_grant().await;
        self.note_pause(&refreshed);
        refreshed?;
        if let Err(e) = self.refresh_gone_issuers().await {
            tracing::warn!(
                kind = redacted_kind(&e),
                "could not ask the server which issuers are gone; the last list stays"
            );
        }
        Ok(())
    }

    /// Looks for a newer grant and takes its profiles and keys.
    pub(crate) async fn refresh_grant(&self) -> Result<(), ClientError> {
        let mut session = self.session.write().await;
        session.refresh().await?;
        *self.profiles.write().unwrap_or_else(|e| e.into_inner()) = profiles::of(&session);
        Ok(())
    }

    /// Why the server refused a call, as far as the proxy's own copy of
    /// the grant tells: the method or the path, when its rules for this
    /// credential and host allow others and never this one
    /// ([`outside_rules`]); otherwise the server's wide reason.
    async fn why_denied(&self, profile: &Profile, method: &str, path: &str) -> NotAllowed {
        let session = self.session.read().await;
        let now = u64::try_from(klav_core_now_ms() / 1000).unwrap_or(0);
        outside_rules(
            &session.grant().payload.policy,
            profile.item,
            &profile.upstream.host,
            method,
            path,
            now,
        )
        .unwrap_or(NotAllowed::ServerDenied)
    }

    /// Which issuers the server no longer counts (ADR 0036 E3.3), and
    /// whether the account's `mcp_gateway` switch is on (ADR 0049 §9):
    /// asked only while the grant names issuers or MCP profiles, under the
    /// session's read lock. On an error the last answers stay.
    pub(crate) async fn refresh_gone_issuers(&self) -> Result<(), ClientError> {
        let session = self.session.read().await;
        let issuers = !session.grant().payload.issuers.is_empty();
        let mcp = session
            .grant()
            .payload
            .profiles
            .iter()
            .any(|p| p.mcp.is_some());
        let (gone, gateway) = if !issuers && !mcp {
            (Vec::new(), false)
        } else {
            let res = session
                .agent()
                .send(reqwest::Method::GET, "/v1/agent/me", None)
                .await?;
            let me: klav_proto::agent::AgentMe = klav_client::api::json(res).await?;
            if me.id != session.agent().id() {
                return Err(ClientError::Security(
                    "the server answered for another agent".into(),
                ));
            }
            (
                if issuers { me.gone_issuers } else { Vec::new() },
                me.mcp_gateway == Some(true),
            )
        };
        drop(session);
        *self.gone_issuers.lock().unwrap_or_else(|e| e.into_inner()) = gone;
        self.mcp_gateway
            .store(gateway, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

/// The router: every path goes to the forwarder.
pub fn router(state: Arc<ProxyState>) -> Router {
    use crate::sandboxes;
    use axum::routing::post;
    Router::new()
        .route(sandboxes::API, post(sandboxes::start).get(sandboxes::list))
        .route(
            &format!("{}/{{id}}/stop", sandboxes::API),
            post(sandboxes::stop),
        )
        .fallback(handle)
        .with_state(state)
}

/// Who a call comes from.
#[derive(Clone)]
pub(crate) enum Caller {
    /// A program on this machine, through the loopback listener.
    Local,
    /// A sandbox, through the pinned channel: the sandbox its key is bound
    /// to (ADR 0036 §6), and that key.
    Sandbox {
        bound: crate::claims::Bound,
        key: [u8; 32],
    },
}

impl Caller {
    pub(crate) fn sandbox(&self) -> Option<klav_core::ids::SandboxId> {
        match self {
            Self::Local => None,
            Self::Sandbox { bound, .. } => Some(bound.sandbox_id),
        }
    }
}

async fn handle(State(state): State<Arc<ProxyState>>, req: Request) -> Response {
    serve_call(&state, req, Caller::Local).await
}

/// A call to a profile, from this machine or from a sandbox, with its log
/// line.
pub(crate) async fn serve_call(state: &ProxyState, req: Request, caller: Caller) -> Response {
    let started = Instant::now();
    let method = req.method().clone();
    let sandbox = caller.sandbox();
    let result = forward(state, req, caller).await;
    let (status, error) = match &result {
        Ok(res) => (res.status().as_u16(), ""),
        Err(e) => (e.status().as_u16(), e.code()),
    };
    // Never the path, the query, a header or a body: the server's audit
    // log has the method, host and path of every call it allowed.
    tracing::info!(
        method = %method,
        status,
        error,
        sandbox = sandbox.map(|s| s.to_string()),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "proxied call"
    );
    result.unwrap_or_else(IntoResponse::into_response)
}

/// The profile name and the upstream path of a local path:
/// `/railway/graphql/v2` is `railway` and `/graphql/v2`; `/railway` alone
/// is `/`.
pub(crate) fn split_profile(raw: &str) -> Option<(&str, &str)> {
    let rest = raw.strip_prefix('/')?;
    match rest.find('/') {
        Some(i) => Some((&rest[..i], &rest[i..])),
        None => Some((rest, "/")),
    }
}

/// Whether the policy can judge this method: upper-case, 1 to 16
/// letters, and not `CONNECT` or `TRACE` (spec §13.4). The path is
/// checked apart, with an explanation ([`crate::paths::path_problem`]).
fn judgeable_method(method: &str) -> bool {
    (1..=16).contains(&method.len())
        && method.bytes().all(|b| b.is_ascii_uppercase())
        && !klav_core::policy::PROXY_REFUSED_METHODS.contains(&method)
}

/// The key of a request for the approvals it waits on: the fields of the
/// server's approval key for `proxy` and the exact query, so a remembered
/// approval is never checked for a request with another query. (The
/// server's own key has no query: see `api.md` §8.7.)
fn approval_key(
    profile: &Profile,
    method: &str,
    path: &str,
    query: Option<&str>,
    sandbox: Option<klav_core::ids::SandboxId>,
    mcp: Option<McpClaims<'_>>,
) -> String {
    let mcp = mcp.map(|m| (m.tool, m.args, m.local_client));
    format!(
        "{}\n{}\n{}\n{}\n{:?}\n{:?}\n{:?}",
        profile.item, profile.upstream.host, method, path, query, sandbox, mcp
    )
}

/// What an MCP message adds to its access (ADR 0049 §5.4, §3.2): the tool
/// and its argument digest for a `tools/call`, and the local client while
/// the account's switch is on.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct McpClaims<'a> {
    pub(crate) tool: Option<&'a str>,
    pub(crate) args: Option<&'a str>,
    pub(crate) local_client: Option<&'a str>,
}

/// Whether a request comes from a web page or names another host: it
/// carries a browser's `Origin` or `Sec-Fetch-Site`, or its `Host` is not
/// exactly `127.0.0.1:<port>` or `localhost:<port>` (a page that rebinds
/// its own name to 127.0.0.1 still sends that name).
///
/// Only `Sec-Fetch-Site` of the Fetch Metadata headers: browsers that send
/// them always send it, while Node's built-in `fetch` sends
/// `Sec-Fetch-Mode` alone, and tools on this machine use that. A browser
/// older than Fetch Metadata sends neither on a top-level or `<img>` GET
/// (threat model T149's row); the page cannot read the answer.
pub(crate) fn not_local(headers: &HeaderMap, port: u16) -> bool {
    not_loopback(headers, |p| p == port.to_string().as_bytes())
}

/// [`not_local`] for a sandbox's call through the pinned channel: the
/// same headers checked on every request, since the forwarder relays
/// bytes and checks nothing (ADR 0036 §5). The proxy does not know the
/// port the forwarder listens on in the sandbox (`klav-forward up
/// --port`), so any port is accepted with `127.0.0.1` or `localhost`: a
/// page that rebinds its own name still sends that name. Refused: no
/// `Host`, more than one, a `Host` without a port, and `[::1]` (the
/// forwarder listens on `127.0.0.1` only, so no client reaches it there).
pub(crate) fn not_sandbox_local(headers: &HeaderMap) -> bool {
    not_loopback(headers, |p| {
        !p.is_empty()
            && p.len() <= 5
            && p.iter().all(u8::is_ascii_digit)
            && std::str::from_utf8(p)
                .ok()
                .and_then(|p| p.parse::<u16>().ok())
                .is_some_and(|p| p != 0)
    })
}

/// The `Host` the forwarder's own requests carry (`klav_forward`'s
/// `status`, `claim` and `klav-forward status`).
pub(crate) const FORWARDER_HOST: &[u8] = b"klav-proxy";

/// [`not_sandbox_local`] for the channel's own routes, `GET /_klav/status`
/// and `POST /_klav/release` (ADR 0036 §5): the same browser headers are
/// refused, and the `Host` may also be exactly `klav-proxy`, what the
/// forwarder and `klav-forward status` send. A page that rebinds its own
/// name to `127.0.0.1` still sends that name (with the port, which a
/// browser always adds when it is not 80), so a rebinding page is refused
/// here even in an engine that leaves out `Origin` on a same-origin `GET`.
pub(crate) fn not_forwarder_own(headers: &HeaderMap) -> bool {
    let mut hosts = headers.get_all(header::HOST).iter();
    match (hosts.next(), hosts.next()) {
        (Some(host), None) if host.as_bytes().eq_ignore_ascii_case(FORWARDER_HOST) => {
            headers.contains_key(header::ORIGIN) || headers.contains_key("sec-fetch-site")
        }
        _ => not_sandbox_local(headers),
    }
}

/// A browser's headers, or a `Host` other than one `127.0.0.1:<port>` or
/// `localhost:<port>` whose port `port_ok` accepts.
fn not_loopback(headers: &HeaderMap, port_ok: impl Fn(&[u8]) -> bool) -> bool {
    if headers.contains_key(header::ORIGIN) || headers.contains_key("sec-fetch-site") {
        return true;
    }
    let mut hosts = headers.get_all(header::HOST).iter();
    let (Some(host), None) = (hosts.next(), hosts.next()) else {
        return true;
    };
    let host = host.as_bytes();
    let Some(colon) = host.iter().rposition(|b| *b == b':') else {
        return true;
    };
    let (name, port) = (&host[..colon], &host[colon + 1..]);
    !((name.eq_ignore_ascii_case(b"127.0.0.1") || name.eq_ignore_ascii_case(b"localhost"))
        && port_ok(port))
}

/// Whether a query may name a method: a parameter whose name,
/// percent-decoded up to three times, is one of [`METHOD_QUERY_NAMES`], or
/// has one as its base before `[` (`_method[]`) or as its last bracketed
/// key (`a[_method]`, the nested form of Rails and PHP). A name still
/// escaped after three decodings counts too: it cannot be judged. Only for
/// this check: the query is forwarded as received. A body
/// (`application/x-www-form-urlencoded`) is not inspected.
fn query_names_method(query: &str) -> bool {
    query.split(['&', ';']).any(|pair| {
        let raw = pair.split('=').next().unwrap_or_default();
        let mut name = raw.as_bytes().to_vec();
        for _ in 0..3 {
            name = percent_decode(&name);
        }
        if name.contains(&b'%') {
            return true;
        }
        let name = String::from_utf8_lossy(&name).trim().to_ascii_lowercase();
        let base = name.split('[').next().unwrap_or_default().trim();
        let last_key = name
            .rsplit_once('[')
            .and_then(|(_, rest)| rest.split(']').next())
            .map(str::trim);
        [Some(name.as_str()), Some(base), last_key]
            .into_iter()
            .flatten()
            .any(|n| METHOD_QUERY_NAMES.contains(&n))
    })
}

fn percent_decode(bytes: &[u8]) -> Vec<u8> {
    let hex = |b: u8| (b as char).to_digit(16).and_then(|d| u8::try_from(d).ok());
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match (
            bytes[i],
            bytes.get(i + 1).copied().and_then(hex),
            bytes.get(i + 2).copied().and_then(hex),
        ) {
            (b'%', Some(h), Some(l)) => {
                out.push(h << 4 | l);
                i += 3;
            }
            (b'+', _, _) => {
                out.push(b' ');
                i += 1;
            }
            (b, _, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// What a refused call is outside of, by the `proxy` rules that allow or
/// ask for `item` on `host`: the path when some allow this method and none
/// this path, the method in the opposite case, and the two together when
/// neither alone is the reason. `None` when no such rule exists, or one of
/// them covers this method on this path: then something else refused it (a
/// `deny` rule, the hours, a revoked proxy), and the server's wide message
/// stays. Never a value from the rules.
pub(crate) fn outside_rules(
    policy: &klav_core::policy::Policy,
    item: klav_core::ids::ItemId,
    host: &str,
    method: &str,
    path: &str,
    now_secs: u64,
) -> Option<NotAllowed> {
    use klav_core::policy::{Effect, Permission};
    let rules: Vec<_> = policy
        .rules
        .iter()
        .filter(|r| {
            r.permission == Permission::Proxy
                && r.effect != Effect::Deny
                && r.expires_at.is_none_or(|t| now_secs < t)
                && r.scope.items.contains(&item)
                && r.scope.domains.iter().any(|d| d.matches(host))
        })
        .collect();
    if rules.is_empty() {
        return None;
    }
    let method_in = |r: &&klav_core::policy::Rule| {
        r.scope.methods.is_empty() || r.scope.methods.iter().any(|m| m.as_str() == method)
    };
    let path_in = |r: &&klav_core::policy::Rule| {
        r.scope.path_prefixes.is_empty() || r.scope.path_prefixes.iter().any(|p| p.matches(path))
    };
    if rules.iter().any(|r| method_in(r) && path_in(r)) {
        return None;
    }
    let method_somewhere = rules.iter().any(method_in);
    let path_somewhere = rules.iter().any(path_in);
    Some(match (method_somewhere, path_somewhere) {
        (true, false) => NotAllowed::OutsidePath,
        (false, true) => NotAllowed::OutsideMethod,
        _ => NotAllowed::OutsideMethodOnPath,
    })
}

fn map_client_error(e: &ClientError) -> ProxyError {
    match e {
        ClientError::Network(_) => ProxyError::ServerUnreachable,
        ClientError::Paused(_) => ProxyError::AgentsPaused,
        // A sandbox's call the server bars (ADR 0036 E3.3).
        ClientError::Api {
            code: Some(klav_proto::ErrorCode::SandboxRevoked),
            ..
        } => ProxyError::SandboxRevoked,
        // The server refused the proxy's own signature (`klav_sdk::proxy`
        // passes its `401` through as it is).
        ClientError::Api { status: 401, .. } => ProxyError::NotAllowed(NotAllowed::ProxyRefused),
        ClientError::Denied(_) | ClientError::NotFound(_) | ClientError::AccountDeleting(_) => {
            ProxyError::NotAllowed(NotAllowed::ServerDenied)
        }
        _ => ProxyError::NotAllowed(NotAllowed::Unverifiable),
    }
}

async fn forward(state: &ProxyState, req: Request, caller: Caller) -> Result<Response, ProxyError> {
    // `--no-local-calls`: no local call goes further, whatever its path,
    // method or headers. Nothing is read, asked of the server or charged.
    if state.no_local_calls && matches!(caller, Caller::Local) {
        return Err(ProxyError::NotAllowed(NotAllowed::LocalCallsOff));
    }
    let (parts, body) = req.into_parts();
    // Before anything else, and before the server is asked: only
    // programs, never a web page. On the loopback listener, programs of
    // this machine. Through the channel, the key the handshake proved says
    // which sandbox calls, and the same headers say it is not a page in
    // that sandbox: the forwarder relays bytes and checks nothing, so this
    // runs here, on every request of a kept-alive connection.
    let foreign = match &caller {
        Caller::Local => not_local(&parts.headers, state.local_port),
        Caller::Sandbox { .. } => not_sandbox_local(&parts.headers),
    };
    if foreign {
        return Err(ProxyError::NotAllowed(NotAllowed::NotLocal));
    }
    // Origin-form only: an absolute URI (or a Host header) never chooses
    // where the request goes; the profile does.
    if parts.uri.scheme().is_some() || parts.uri.authority().is_some() {
        return Err(ProxyError::NotAllowed(NotAllowed::Malformed));
    }
    let (name, path) =
        split_profile(parts.uri.path()).ok_or(ProxyError::NotAllowed(NotAllowed::Malformed))?;
    let profile = state
        .profiles()
        .get(name)
        .cloned()
        .ok_or(ProxyError::NotAllowed(NotAllowed::UnknownProfile))?;
    // A sandbox only uses the profiles it was started with: any other
    // one is, for it, a profile the proxy does not have.
    if let Caller::Sandbox { bound, .. } = &caller
        && !bound.profiles.iter().any(|p| p == name)
    {
        return Err(ProxyError::NotAllowed(NotAllowed::UnknownProfile));
    }
    if profile.mcp.is_some() {
        return crate::mcp::forward(state, parts, body, caller, profile).await;
    }
    let method = parts.method.as_str().to_owned();
    if !judgeable_method(&method) {
        return Err(ProxyError::NotAllowed(NotAllowed::Policy));
    }
    // The same rule as `klav_core::policy::is_canonical_path`, plus the
    // server's refusal of `"`, refused here with the reason, before the
    // server is asked.
    if let Some(why) = crate::paths::path_problem(path) {
        return Err(ProxyError::PathRefused(why));
    }
    // The bytes checked are the bytes sent: refuse a request the URL
    // parser would spell differently. The query is not part of the policy
    // (spec §13.4) and goes as received.
    let query = parts.uri.query();
    if query.is_some_and(query_names_method) {
        return Err(ProxyError::NotAllowed(NotAllowed::MethodInQuery));
    }
    let target = match query {
        Some(q) => format!("{}{path}?{q}", profile.upstream.origin()),
        None => format!("{}{path}", profile.upstream.origin()),
    };
    let url =
        reqwest::Url::parse(&target).map_err(|_| ProxyError::NotAllowed(NotAllowed::Malformed))?;
    if url.path() != path
        || url.query() != query
        || url.host_str() != Some(profile.upstream.host.as_str())
    {
        return Err(ProxyError::NotAllowed(NotAllowed::Malformed));
    }
    // Held until the answer ends: they bound the bodies in memory and the
    // redactors holding the value. Taken, and the body read, before the
    // rates: a call refused for a slot, or for a body that stalls, never
    // spends a rate (review of #306, N3).
    let mut permit = state.take_slots(caller.sandbox()).await?;
    // Registered before the server is asked for the item: an end of the
    // sandbox or a pause from here on cuts this call, its answer included
    // (ADR 0036 §7, note of 2026-11-19). One that came before is the
    // server's refusal, or the check of the sandbox after the access.
    let cut = state.cuts.register(caller.sandbox());
    let idle = Duration::from_millis(
        state
            .request_body_idle_ms
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    let (body, held) = read_body(
        body,
        state.max_body,
        idle,
        state.request_timeout,
        state.body_budget(),
    )
    .await
    .map_err(|e| state.body_refusal(e))?;
    permit.hold(held);
    state.check_rates(&profile, caller.sandbox())?;
    let sent = send_upstream(
        state,
        &profile,
        &caller,
        Outgoing {
            method: &method,
            path,
            query,
            url,
            headers: forwarded_headers(&parts.headers, &profile.header),
            body,
            mcp: None,
        },
        permit,
        cut,
    )
    .await?;
    respond(sent, caller.sandbox().is_some(), None)
}

/// A request ready for the upstream, once its checks passed.
pub(crate) struct Outgoing<'a> {
    pub(crate) method: &'a str,
    pub(crate) path: &'a str,
    pub(crate) query: Option<&'a str>,
    pub(crate) url: reqwest::Url,
    /// The caller's headers that may go ([`forwarded_headers`]), and any
    /// the profile adds; the credential and `Accept-Encoding` are set here.
    pub(crate) headers: HeaderMap,
    pub(crate) body: Bytes,
    pub(crate) mcp: Option<McpClaims<'a>>,
}

/// The upstream's answer, with what its body needs.
pub(crate) struct Sent {
    pub(crate) res: reqwest::Response,
    redactor: Redactor,
    tally: Tally,
    held: Held,
}

/// The server asked for the item (never cached), the sandbox checked
/// again, the credential put in the profile's header, and the request
/// sent; the answer's headers are back.
pub(crate) async fn send_upstream(
    state: &ProxyState,
    profile: &Profile,
    caller: &Caller,
    out: Outgoing<'_>,
    permit: Slots,
    cut: crate::cuts::CutHandle,
) -> Result<Sent, ProxyError> {
    let Outgoing {
        method,
        path,
        query,
        url,
        mut headers,
        body,
        mcp,
    } = out;
    // A refusal comes back narrowed to the path or the method by
    // [`refused`], which logs the same decision it returns.
    let item = match access(state, profile, method, path, query, caller.sandbox(), mcp).await {
        Ok(item) => item,
        Err(e) => {
            state.cut_for(caller.sandbox(), &e).await;
            return Err(e);
        }
    };
    #[cfg(test)]
    state.after_access().await;
    // The sandbox may have ended while the server answered: it is checked
    // again before the value goes anywhere (review of #306, N2).
    // It must still be the same sandbox: a key is bound to one, and the
    // server authorised this call for that one (follow-up 1 of the
    // review of #304/#306).
    // Its end, as a deadline no answer outlives.
    let mut expiry = None;
    if let Caller::Sandbox { bound, key } = caller {
        let found = crate::claims::bound(state, key)
            .await
            .map_err(|e| match e {
                crate::claims::ChannelError::Expired => ProxyError::SandboxExpired,
                crate::claims::ChannelError::Ended(reason) => ProxyError::SandboxEnded(reason),
                _ => ProxyError::SandboxRevoked,
            })?;
        if found.sandbox_id != bound.sandbox_id {
            return Err(ProxyError::SandboxRevoked);
        }
        let left = found.expires_at.saturating_sub(state.sandboxes().now());
        expiry = Some(
            tokio::time::Instant::now() + Duration::from_millis(u64::try_from(left).unwrap_or(0)),
        );
    }
    if let Some(reason) = cut.reason() {
        return Err(cut_error(reason));
    }
    // From here the value is in memory: the deadlines count from now.
    let started = tokio::time::Instant::now();
    let (credential, secret) = profile
        .credential(&item)
        .map_err(|_| ProxyError::NotAllowed(NotAllowed::Policy))?;
    drop(item);
    // Only the whole value, never a piece (T149, ADR 0036 E9).
    let redactor = Redactor::whole_values([secret.as_str()]);
    drop(secret);

    headers.insert(
        header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    headers.insert(profile.header.clone(), credential);
    let upstream_method = Method::from_bytes(method.as_bytes())
        .map_err(|_| ProxyError::NotAllowed(NotAllowed::Malformed))?;
    // The request timeout covers the headers here, and the body in
    // [`respond`] unless the answer is a stream.
    let request = state
        .client
        .request(upstream_method, url)
        .headers(headers)
        .body(body)
        .send();
    let mut cut = cut;
    let sent = tokio::select! {
        biased;
        reason = cut.cut() => return Err(cut_error(reason)),
        () = sleep_until_or_never(expiry) => return Err(ProxyError::SandboxExpired),
        sent = tokio::time::timeout_at(started + state.request_timeout, request) => sent,
    };
    let res = match sent {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => return Err(ProxyError::UpstreamBlocked(send_error(&e))),
        Err(_) => return Err(ProxyError::UpstreamBlocked(Blocked::Unreachable)),
    };
    let tally = Tally {
        profile: profile.name.clone(),
        count: 0,
        partial: 0,
        counts: Arc::clone(&state.counts),
    };
    let (stream_max, stream_idle) = state.stream_limits();
    let held = Held {
        permit,
        cut,
        started,
        expiry,
        request_timeout: state.request_timeout,
        stream_max,
        stream_idle,
    };
    Ok(Sent {
        res,
        redactor,
        tally,
        held,
    })
}

/// What a call in flight answers when it is cut before its answer starts.
fn cut_error(reason: crate::cuts::CutReason) -> ProxyError {
    match reason {
        crate::cuts::CutReason::SandboxEnded => ProxyError::SandboxRevoked,
        crate::cuts::CutReason::Paused => ProxyError::AgentsPaused,
    }
}

/// Sleeps until `at`, or forever without one.
async fn sleep_until_or_never(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// What a call holds until its answer ends, and the limits of that answer.
pub(crate) struct Held {
    permit: Slots,
    cut: crate::cuts::CutHandle,
    /// When the redactor took the value.
    started: tokio::time::Instant,
    /// When its sandbox ends (a call from this machine has none).
    expiry: Option<tokio::time::Instant>,
    request_timeout: Duration,
    stream_max: Duration,
    stream_idle: Duration,
}

/// How long an answer's body may take, and how it is cut.
pub(crate) struct BodyLimits {
    /// Longest wait for the provider's next piece, and for the caller to
    /// take the previous one.
    idle: Duration,
    /// When the answer is cut, whatever it is doing.
    deadline: tokio::time::Instant,
    /// Cuts it when its sandbox ends or the person pauses the agents.
    cut: Option<crate::cuts::CutHandle>,
}

/// Whether the answer is a stream: `Content-Type: text/event-stream`, with
/// or without parameters.
pub(crate) fn is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("text/event-stream"))
}

/// What a request holds until its answer ends.
pub(crate) struct Slots {
    _all: tokio::sync::OwnedSemaphorePermit,
    _own: Option<tokio::sync::OwnedSemaphorePermit>,
    /// The bytes of the account's body budget the request's body holds.
    _buffer: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl Slots {
    /// Keeps the body's share of the account's budget until the answer
    /// ends.
    pub(crate) fn hold(&mut self, buffer: Option<tokio::sync::OwnedSemaphorePermit>) {
        self._buffer = buffer;
    }

    /// A slot of its own (tests).
    #[cfg(test)]
    pub(crate) fn single() -> Self {
        Self {
            _all: Arc::new(tokio::sync::Semaphore::new(1))
                .try_acquire_owned()
                .expect("permit"),
            _own: None,
            _buffer: None,
        }
    }
}

/// The caller's body, at most `max` bytes, each piece within `idle` and the
/// whole within `total`. A caller that stops in the middle of a body never
/// holds its slots for long. With `budget` (Klav Cloud's proxy), each piece
/// takes its bytes from it as it arrives; the permit returned holds them
/// until it is dropped, and a body that stops on the way gives them back
/// at once.
pub(crate) async fn read_body(
    body: Body,
    max: usize,
    idle: Duration,
    total: Duration,
    budget: Option<&Arc<tokio::sync::Semaphore>>,
) -> Result<(Bytes, Option<tokio::sync::OwnedSemaphorePermit>), BodyError> {
    use futures_util::StreamExt;
    let read = async {
        let mut stream = body.into_data_stream();
        let mut out = Vec::new();
        let mut held: Option<tokio::sync::OwnedSemaphorePermit> = None;
        loop {
            match tokio::time::timeout(idle, stream.next()).await {
                Err(_) | Ok(Some(Err(_))) => return Err(BodyError::Broken),
                Ok(None) => return Ok((Bytes::from(out), held)),
                Ok(Some(Ok(piece))) => {
                    if out.len().saturating_add(piece.len()) > max {
                        return Err(BodyError::TooLarge);
                    }
                    if let Some(budget) = budget
                        && !piece.is_empty()
                    {
                        let n = u32::try_from(piece.len()).map_err(|_| BodyError::Budget)?;
                        let taken = Arc::clone(budget)
                            .try_acquire_many_owned(n)
                            .map_err(|_| BodyError::Budget)?;
                        match held.as_mut() {
                            Some(h) => h.merge(taken),
                            None => held = Some(taken),
                        }
                    }
                    out.extend_from_slice(&piece);
                }
            }
        }
    };
    tokio::time::timeout(total, read)
        .await
        .unwrap_or(Err(BodyError::Broken))
}

/// Asks the server for the profile's item for this request and opens it,
/// reusing an approval this same request already waits on. A key that no
/// longer opens the item (the person changed it) makes the proxy take its
/// newer grant and ask once more.
async fn access(
    state: &ProxyState,
    profile: &Profile,
    method: &str,
    path: &str,
    query: Option<&str>,
    sandbox: Option<klav_core::ids::SandboxId>,
    mcp: Option<McpClaims<'_>>,
) -> Result<Box<klav_core::model::Item>, ProxyError> {
    let key = approval_key(profile, method, path, query, sandbox, mcp);
    let waiting = state
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .map(|(id, _)| *id);
    if let Some(id) = waiting {
        // The read guard ends with the block: [`refused`] reads the
        // session again.
        let waited = {
            let session = state.session.read().await;
            session.wait_decision(id, Duration::ZERO).await
        };
        let info = match waited {
            Ok(info) => info,
            Err(e) => {
                return Err(
                    refused(state, profile, method, path, sandbox, &e, Origin::Asked).await,
                );
            }
        };
        let forget = || {
            state
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
        };
        match info.status {
            ApprovalStatus::Denied => {
                forget();
                return Err(ProxyError::ApprovalDenied);
            }
            ApprovalStatus::Pending if info.expires_at > klav_core_now_ms() => {
                return Err(ProxyError::ApprovalPending {
                    approval_id: id,
                    expires_at: info.expires_at,
                });
            }
            // Approved: the server uses it for this same request (and this
            // runtime verifies it); expired: ask again.
            _ => forget(),
        }
    }
    let mut retried = false;
    loop {
        let seen = state
            .seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&profile.item)
            .cloned()
            .unwrap_or_default();
        let (got, in_grant) = {
            let session = state.session.read().await;
            // `proxy_access` refuses an item its grant does not have
            // before the server is asked: read under the same guard, for
            // the log.
            let in_grant = session.grant().items.contains_key(&profile.item);
            let mut call = profile.call(method, path, &seen.tags, sandbox);
            if let Some(m) = mcp {
                call.mcp_tool = m.tool;
                call.mcp_args = m.args;
                call.local_client = m.local_client;
            }
            (session.proxy_access(&call, seen.version).await, in_grant)
        };
        match got {
            Ok(ProxyAccess::Granted { item, version, .. }) => {
                state.seen.lock().unwrap_or_else(|e| e.into_inner()).insert(
                    profile.item,
                    Seen {
                        version,
                        tags: item.tags().to_vec(),
                    },
                );
                return Ok(item);
            }
            Ok(ProxyAccess::Pending {
                approval_id,
                expires_at,
            }) => {
                remember(
                    &mut state.pending.lock().unwrap_or_else(|e| e.into_inner()),
                    key,
                    approval_id,
                    expires_at,
                );
                return Err(ProxyError::ApprovalPending {
                    approval_id,
                    expires_at,
                });
            }
            Err(ClientError::Crypto(_)) if !retried => {
                retried = true;
                // Only the grant: a call never waits for, or fails on, the
                // list of gone issuers.
                if let Err(e) = state.refresh_grant().await {
                    return Err(
                        refused(state, profile, method, path, sandbox, &e, Origin::Asked).await,
                    );
                }
            }
            Err(e) => {
                let origin = if in_grant {
                    Origin::Asked
                } else {
                    Origin::NotInGrant
                };
                return Err(refused(state, profile, method, path, sandbox, &e, origin).await);
            }
        }
    }
}

/// Remembers an approval for a request, dropping the expired ones and, past
/// [`MAX_PENDING`], the ones that expire first.
fn remember(
    pending: &mut HashMap<String, (ApprovalId, i64)>,
    key: String,
    id: ApprovalId,
    expires_at: i64,
) {
    let now = klav_core_now_ms();
    pending.retain(|_, (_, until)| *until > now);
    while pending.len() >= MAX_PENDING {
        let Some(first) = pending
            .iter()
            .min_by_key(|(_, (_, until))| *until)
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        pending.remove(&first);
    }
    pending.insert(key, (id, expires_at));
}

fn klav_core_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// The kind of a client error, for the log: its variant, not its text
/// (which may quote the server).
pub(crate) fn redacted_kind(e: &ClientError) -> &'static str {
    match e {
        ClientError::Network(_) => "network",
        ClientError::Denied(_) => "denied",
        ClientError::Paused(_) => "paused",
        ClientError::NotFound(_) => "not_found",
        ClientError::Rollback(_) => "rollback",
        ClientError::Security(_) => "security",
        ClientError::Crypto(_) => "crypto",
        ClientError::Corrupt(_) => "corrupt",
        _ => "other",
    }
}

/// Where an error of [`access`] was decided, for its log line.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// The server was asked (or the proxy checked its answer).
    Asked,
    /// The proxy's grant does not have the profile's item, so
    /// `Session::proxy_access` refused before asking the server.
    NotInGrant,
}

/// What the sandbox is told when the server's answer is an error, with
/// its log line ([`log_refused`]): a refusal the proxy's copy of the grant
/// explains is said to be for the path or the method
/// ([`ProxyState::why_denied`]). The only place this narrowing happens, so
/// the line and the answer are one decision.
async fn refused(
    state: &ProxyState,
    profile: &Profile,
    method: &str,
    path: &str,
    sandbox: Option<klav_core::ids::SandboxId>,
    e: &ClientError,
    origin: Origin,
) -> ProxyError {
    let answer = match map_client_error(e) {
        ProxyError::NotAllowed(NotAllowed::ServerDenied) => {
            ProxyError::NotAllowed(state.why_denied(profile, method, path).await)
        }
        other => other,
    };
    log_refused(&profile.name, method, sandbox, e, origin, &answer);
    answer
}

/// One line for each kind of error, so that a call outside the profile, an
/// item the proxy's grant does not have, a refusal for another reason, a
/// server that could not be reached and an answer that could not be
/// verified read apart. The same fields as `proxied call` (the method, the
/// sandbox) plus the profile's name, the error's kind ([`redacted_kind`])
/// and fixed words: never the path (its segments can name a project, a
/// person or a token), the query, a header, a body or the error's text
/// (which may quote the server).
///
/// For a reader of the log:
/// - "Refused" is the server's refusal, or the proxy's own copy of the
///   policy refusing what the server let through; `error` says which kind
///   (`denied`, `not_found`, …) even when the line says "outside".
/// - `the server could not be reached` is any network error of
///   `klav-client`'s API layer: no connection, but also a TLS or
///   certificate failure and an answer it could not read (invalid JSON,
///   too large). Those are WARN, not the ERROR of an unverifiable answer.
/// - One honest case reaches the ERROR line: for up to [`GRANT_REFRESH`]
///   after the person changes a rule from ask to allow, the proxy's copy
///   of the grant still asks, and `klav_sdk`'s check that an ask was
///   approved refuses the server's "allowed" with a security error.
fn log_refused(
    profile: &str,
    method: &str,
    sandbox: Option<klav_core::ids::SandboxId>,
    e: &ClientError,
    origin: Origin,
    answer: &ProxyError,
) {
    let sandbox = sandbox.map(|s| s.to_string());
    let error = redacted_kind(e);
    match answer {
        // Before the outside lines: the proxy's own reason, not the rules.
        _ if origin == Origin::NotInGrant && matches!(e, ClientError::NotFound(_)) => {
            tracing::warn!(
                method = %method,
                sandbox,
                profile,
                error,
                reason = "not_in_grant",
                "the proxy's grant does not have this profile's credential"
            );
        }
        ProxyError::NotAllowed(
            n @ (NotAllowed::OutsidePath
            | NotAllowed::OutsideMethod
            | NotAllowed::OutsideMethodOnPath),
        ) => {
            let outside = match n {
                NotAllowed::OutsidePath => "path",
                NotAllowed::OutsideMethod => "method",
                _ => "method_on_path",
            };
            tracing::warn!(
                method = %method,
                sandbox,
                profile,
                error,
                outside,
                "a call outside its profile was refused"
            );
        }
        ProxyError::ServerUnreachable => {
            tracing::warn!(method = %method, sandbox, profile, error, "the server could not be reached");
        }
        // Signs that the server, or something between, answered with what
        // it should not have: louder than the rest.
        ProxyError::NotAllowed(NotAllowed::Unverifiable)
            if matches!(
                e,
                ClientError::Rollback(_)
                    | ClientError::Security(_)
                    | ClientError::Crypto(_)
                    | ClientError::Corrupt(_)
            ) =>
        {
            tracing::error!(method = %method, sandbox, profile, error, "the server's answer could not be verified");
        }
        ProxyError::NotAllowed(NotAllowed::Unverifiable) => {
            tracing::warn!(method = %method, sandbox, profile, error, "the server's answer could not be used");
        }
        other => {
            let reason = match other {
                ProxyError::AgentsPaused => "agents_paused",
                ProxyError::SandboxRevoked => "sandbox_revoked",
                ProxyError::NotAllowed(NotAllowed::ProxyRefused) => "proxy_refused",
                _ => "server_denied",
            };
            tracing::warn!(method = %method, sandbox, profile, error, reason, "the server refused the call");
        }
    }
}

/// The caller's headers that may go upstream: none of
/// [`DROPPED_REQUEST_HEADERS`], none named in `Connection`, none of the
/// proxy's or Klav's own, and not the profile's header.
pub(crate) fn forwarded_headers(from: &HeaderMap, profile_header: &HeaderName) -> HeaderMap {
    let named: Vec<String> = from
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();
    let mut out = HeaderMap::new();
    for (name, value) in from {
        let n = name.as_str();
        if DROPPED_REQUEST_HEADERS.contains(&n)
            || n.starts_with("x-forwarded-")
            || n.starts_with("x-envoy-")
            || n.starts_with("klav-")
            || n.starts_with("proxy-")
            || name == profile_header
            || named.iter().any(|c| c == n)
        {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

/// Why a call to the provider failed, without its URL or anything else
/// from the request.
fn send_error(e: &reqwest::Error) -> Blocked {
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
    while let Some(err) = source {
        if err.downcast_ref::<RefusedAddress>().is_some() {
            return Blocked::Address;
        }
        source = err.source();
    }
    Blocked::Unreachable
}

/// Counts, in one answer, the whole values replaced and the pieces left as
/// they are, and when it is dropped (after the caller has the end of the
/// answer, or the answer was cut) adds them to the profile's counts and
/// logs a line for each kind: the profile and the numbers, never what
/// matched. Pieces in a row can be a caller probing for the value (T149);
/// only the person sees them, in this log and in `klav-proxy status`.
struct Tally {
    profile: String,
    count: u64,
    partial: u64,
    counts: Arc<crate::counts::Counts>,
}

impl Drop for Tally {
    fn drop(&mut self) {
        if self.count == 0 && self.partial == 0 {
            return;
        }
        let total = self.counts.add(&self.profile, self.count, self.partial);
        if self.count > 0 {
            tracing::warn!(
                profile = %self.profile,
                replaced = self.count,
                total = total.redacted,
                "redacted the injected value from a provider's answer"
            );
        }
        if self.partial > 0 {
            tracing::warn!(
                profile = %self.profile,
                pieces = self.partial,
                total = total.partial,
                "a provider's answer held a piece of the injected value, left as it is: a caller may be probing for it (see klav-proxy status)"
            );
        }
    }
}

/// Whether a `Transfer-Encoding` asks for anything but one plain `chunked`
/// framing, across all its lines: hyper's client takes one layer of chunks
/// apart, so `gzip, chunked` would reach the redactor still compressed and
/// `chunked, chunked` with inner chunk sizes that can split the value.
fn transfer_encoded(headers: &HeaderMap) -> bool {
    let mut codings = 0;
    for value in headers.get_all(header::TRANSFER_ENCODING) {
        for coding in value.as_bytes().split(|b| *b == b',') {
            let coding = coding.trim_ascii();
            if coding.is_empty() {
                continue;
            }
            if !coding.eq_ignore_ascii_case(b"chunked") {
                return true;
            }
            codings += 1;
        }
    }
    codings > 1
}

/// What reads an answer's body after the redactor, for an MCP profile
/// (ADR 0049 §5.2): it may hold, drop or rewrite what the redactor emits,
/// and `Err` cuts the answer (never a clean end). It only ever sees
/// redacted bytes, so it cannot undo a redaction.
pub(crate) trait BodyTransform: Send + 'static {
    /// What to emit for the next redacted bytes.
    fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, ()>;
    /// What to emit at the end of the body.
    fn finish(&mut self) -> Result<Vec<u8>, ()>;
}

/// How an MCP profile's answer is read: given its status and headers, the
/// transform for its body ([`crate::mcp`]), or an error that replaces it.
pub(crate) type McpAnswer = Box<
    dyn FnOnce(reqwest::StatusCode, &HeaderMap) -> Result<Box<dyn BodyTransform>, ProxyError>
        + Send,
>;

/// The provider's answer, checked and redacted. A `304` passes with its
/// headers and no body; any other redirect is blocked. A stream
/// (`text/event-stream`) gets the stream's limits and goes out line by
/// line. An MCP profile's answer never carries `WWW-Authenticate`, for any
/// caller (ADR 0049 §2.4, T265), and its body goes through `mcp`.
pub(crate) fn respond(
    sent: Sent,
    for_sandbox: bool,
    mcp: Option<McpAnswer>,
) -> Result<Response, ProxyError> {
    let Sent {
        res,
        redactor,
        mut tally,
        held,
    } = sent;
    let status = res.status();
    if status.is_redirection() && status != reqwest::StatusCode::NOT_MODIFIED {
        return Err(ProxyError::UpstreamBlocked(Blocked::Redirect));
    }
    let encoded = res
        .headers()
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"));
    if encoded || transfer_encoded(res.headers()) {
        return Err(ProxyError::UpstreamBlocked(Blocked::Encoded));
    }
    let is_mcp = mcp.is_some();
    let mut headers = HeaderMap::new();
    for (name, value) in res.headers() {
        let n = name.as_str();
        if DROPPED_RESPONSE_HEADERS.contains(&n)
            || n.starts_with("klav-")
            || n.starts_with("access-control-")
            // A cookie the provider sets is a credential of its own, usable
            // without the proxy and after the sandbox ends: a sandbox gets
            // actions, not values.
            || (for_sandbox && SANDBOX_DROPPED_RESPONSE_HEADERS.contains(&n))
            // No MCP client starts its own sign-in with the provider.
            || (is_mcp && n == "www-authenticate")
        {
            continue;
        }
        let (redacted, replaced, partial) = redactor.scan_bytes(value.as_bytes());
        tally.partial += partial as u64;
        let value = if replaced == 0 {
            value.clone()
        } else {
            tally.count += replaced as u64;
            HeaderValue::from_bytes(&redacted)
                .unwrap_or_else(|_| HeaderValue::from_static(klav_sdk::actions::REDACTED))
        };
        headers.append(name.clone(), value);
    }
    let transform = match mcp {
        Some(read) => Some(read(status, &headers)?),
        None => None,
    };
    let body = if status == reqwest::StatusCode::NOT_MODIFIED {
        drop((res, redactor, held));
        // Counted and logged apart, never on the way of the answer.
        tokio::spawn(async move { drop(tally) });
        Body::empty()
    } else {
        let stream = is_event_stream(res.headers());
        let (redactor, idle, longest) = if stream {
            // Each event goes out with the chunk that ends it (step M2).
            (
                StreamRedactor::by_lines(redactor),
                held.stream_idle,
                held.stream_max,
            )
        } else {
            (
                StreamRedactor::new(redactor),
                BODY_IDLE,
                held.request_timeout,
            )
        };
        let mut deadline = held.started + longest;
        if let Some(expiry) = held.expiry {
            deadline = deadline.min(expiry);
        }
        let limits = BodyLimits {
            idle,
            deadline,
            cut: Some(held.cut),
        };
        redacted_body(res, redactor, tally, held.permit, limits, transform)
    };
    let mut out = Response::new(body);
    *out.status_mut() = StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    *out.headers_mut() = headers;
    Ok(out)
}

/// The body, chunk by chunk through the redactor, in a task of its own: it
/// waits at most `limits.idle` ([`BODY_IDLE`], or [`STREAM_IDLE`] for a
/// stream) for the provider's next chunk and for the caller to take the
/// last one, then cuts the answer and drops the redactor (which holds the
/// value). It is also cut at `limits.deadline`, when its sandbox ends or
/// the person pauses the agents, and as soon as the proxy sees the caller
/// went away (its slots come back then): through the channel, which takes
/// a half-close, that is when a write to it fails. A body the redactor cannot hold, one that
/// breaks, one the caller does not take in time, or one cut for any
/// reason ends with an error, never a clean end: hyper then does not
/// finish the chunked body, so the caller sees a broken transfer, never a
/// short answer that looks whole, and never an unredacted piece.
fn redacted_body(
    mut res: reqwest::Response,
    mut redactor: StreamRedactor,
    tally: Tally,
    permit: Slots,
    limits: BodyLimits,
    mut transform: Option<Box<dyn BodyTransform>>,
) -> Body {
    let BodyLimits {
        idle,
        deadline,
        cut: mut cut_handle,
    } = limits;
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(1);
    // Set only once the last piece is in the channel: a channel that
    // closes without it is a cut answer, whatever was or was not queued.
    let complete = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done = Arc::clone(&complete);
    tokio::spawn(async move {
        // The whole tally moves in (not just its count): it logs when the
        // task ends. `tx` is bound after it, so it drops first: the caller
        // has the end of the answer before the tally counts or logs, and
        // the timing of the end never depends on what was counted.
        let mut tally = tally;
        let _permit = permit;
        let tx = tx;
        let until = tokio::time::sleep_until(deadline);
        tokio::pin!(until);
        loop {
            // `None`: cut (the deadline, the sandbox's end, a pause) or the
            // caller went away. The channel then closes without its last
            // piece, which the caller reads as a broken answer.
            let got = tokio::select! {
                biased;
                _ = cut_or_never(&mut cut_handle) => None,
                () = &mut until => None,
                () = tx.closed() => None,
                got = tokio::time::timeout(idle, res.chunk()) => Some(got),
            };
            let piece = match got {
                None => Err(None),
                Some(Ok(Ok(Some(chunk)))) => match redactor.push(&chunk) {
                    Ok(out) => match transform.as_mut() {
                        None => Ok(Bytes::from(out)),
                        Some(t) => t.push(&out).map(Bytes::from).map_err(|()| Some(cut())),
                    },
                    Err(_) => Err(Some(cut())),
                },
                Some(Ok(Ok(None))) => {
                    let (mut last, replaced, partial) = redactor.finish_all();
                    tally.count += replaced as u64;
                    tally.partial += partial as u64;
                    if let Some(t) = transform.as_mut() {
                        // What the transform holds, then its end: a body it
                        // cannot read to the end is cut, never ended.
                        // The channel then closes without its last piece.
                        let Ok(mut held) = t.push(&last) else {
                            return;
                        };
                        let Ok(end) = t.finish() else {
                            return;
                        };
                        held.extend_from_slice(&end);
                        last = held;
                    }
                    let sent = tokio::select! {
                        biased;
                        _ = cut_or_never(&mut cut_handle) => false,
                        () = &mut until => false,
                        sent = tx.send_timeout(Ok(Bytes::from(last)), idle) => sent.is_ok(),
                    };
                    if sent {
                        done.store(true, std::sync::atomic::Ordering::Release);
                    }
                    return;
                }
                Some(_) => Err(Some(cut())),
            };
            let (piece, end) = match piece {
                // Nothing to emit yet (a line not ended, a held tail).
                Ok(bytes) if bytes.is_empty() => continue,
                Ok(bytes) => (Ok(bytes), false),
                Err(Some(e)) => (Err(e), true),
                Err(None) => {
                    tally.count += redactor.replaced() as u64;
                    tally.partial += redactor.partial() as u64;
                    return;
                }
            };
            let sent = tokio::select! {
                biased;
                _ = cut_or_never(&mut cut_handle) => false,
                () = &mut until => false,
                sent = tx.send_timeout(piece, idle) => sent.is_ok(),
            };
            if !sent || end {
                tally.count += redactor.replaced() as u64;
                tally.partial += redactor.partial() as u64;
                return;
            }
        }
    });
    Body::from_stream(stream::unfold(Some(rx), move |state| {
        let complete = Arc::clone(&complete);
        async move {
            let mut rx = state?;
            match rx.recv().await {
                Some(Err(e)) => Some((Err(e), None)),
                Some(piece) => Some((piece, Some(rx))),
                None if complete.load(std::sync::atomic::Ordering::Acquire) => None,
                None => Some((Err(cut()), None)),
            }
        }
    }))
}

/// Waits until `cut` says the call is cut, or forever without one.
async fn cut_or_never(cut: &mut Option<crate::cuts::CutHandle>) {
    match cut {
        Some(c) => {
            c.cut().await;
        }
        None => std::future::pending().await,
    }
}

fn cut() -> std::io::Error {
    std::io::Error::other("klav-proxy cut the provider's answer")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn the_profile_is_the_first_segment() {
        assert_eq!(
            split_profile("/railway/graphql/v2"),
            Some(("railway", "/graphql/v2"))
        );
        assert_eq!(split_profile("/railway"), Some(("railway", "/")));
        assert_eq!(split_profile("/railway/"), Some(("railway", "/")));
        assert_eq!(split_profile("railway"), None);
    }

    #[test]
    fn only_methods_the_policy_can_judge_go_on() {
        assert!(judgeable_method("GET"));
        assert!(!judgeable_method("get"));
        assert!(!judgeable_method("CONNECT"));
        assert!(!judgeable_method("TRACE"));
        assert!(!judgeable_method("M-SEARCH"));
        assert!(!judgeable_method("ABCDEFGHIJKLMNOPQ"));
    }

    #[test]
    fn credentials_and_overrides_never_pass_upstream() {
        let mut from = HeaderMap::new();
        for (n, v) in [
            ("authorization", "Bearer klav-placeholder"),
            ("cookie", "a=b"),
            ("x-api-key", "placeholder"),
            ("x-http-method-override", "DELETE"),
            ("x-method-override", "DELETE"),
            ("x-http-method", "DELETE"),
            ("host", "evil.test"),
            ("connection", "x-secret-hop"),
            ("x-secret-hop", "1"),
            ("klav-error", "spoof"),
            ("accept-encoding", "gzip"),
            ("content-type", "application/json"),
        ] {
            from.append(HeaderName::from_static(n), HeaderValue::from_static(v));
        }
        let out = forwarded_headers(&from, &HeaderName::from_static("x-api-key"));
        let names: Vec<&str> = out.keys().map(HeaderName::as_str).collect();
        assert_eq!(names, vec!["content-type"]);
        let mut from = HeaderMap::new();
        for n in [
            "x-forwarded-for",
            "x-forwarded-port",
            "x-forwarded-prefix",
            "forwarded",
            "x-original-url",
            "x-rewrite-url",
            "x-real-ip",
            "x-forwarded",
            "x-original-host",
            "x-host",
            "x-original-uri",
            "via",
            "client-ip",
            "x-client-ip",
            "true-client-ip",
            "cf-connecting-ip",
            "fastly-client-ip",
            "x-cluster-client-ip",
            "x-envoy-original-path",
            "x-envoy-external-address",
            "accept",
        ] {
            from.append(HeaderName::from_static(n), HeaderValue::from_static("1"));
        }
        let out = forwarded_headers(&from, &HeaderName::from_static("authorization"));
        let names: Vec<&str> = out.keys().map(HeaderName::as_str).collect();
        assert_eq!(names, vec!["accept"]);
    }

    #[test]
    fn only_programs_of_this_machine_may_call() {
        let headers = |pairs: &[(&'static str, &'static str)]| {
            let mut h = HeaderMap::new();
            for (n, v) in pairs {
                h.append(HeaderName::from_static(n), HeaderValue::from_static(v));
            }
            h
        };
        assert!(!not_local(&headers(&[("host", "127.0.0.1:8790")]), 8790));
        assert!(!not_local(&headers(&[("host", "LOCALHOST:8790")]), 8790));
        // Node's built-in `fetch` sends `Sec-Fetch-Mode` alone (no `Origin`,
        // no `Sec-Fetch-Site`): a program of this machine, let through.
        assert!(!not_local(
            &headers(&[
                ("host", "127.0.0.1:8790"),
                ("sec-fetch-mode", "cors"),
                ("sec-fetch-dest", "empty"),
                ("sec-fetch-user", "?1"),
            ]),
            8790
        ));
        for bad in [
            &[][..],
            &[("host", "127.0.0.1")][..],
            &[("host", "127.0.0.1:8791")][..],
            &[("host", "evil.test:8790")][..],
            &[("host", "[::1]:8790")][..],
            &[("host", "127.0.0.1:8790"), ("host", "127.0.0.1:8790")][..],
            &[("host", "127.0.0.1:8790"), ("origin", "null")][..],
            &[("host", "127.0.0.1:8790"), ("sec-fetch-site", "cross-site")][..],
            &[("host", "127.0.0.1:8790"), ("sec-fetch-site", "none")][..],
        ] {
            assert!(not_local(&headers(bad), 8790), "{bad:?}");
        }
    }

    fn header_map(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (n, v) in pairs {
            h.append(HeaderName::from_static(n), HeaderValue::from_static(v));
        }
        h
    }

    /// The `Host` edge cases of the loopback check, for a sandbox's call
    /// through the channel (any port) and for the channel's own routes
    /// (also `klav-proxy`, the forwarder's own `Host`).
    #[test]
    fn the_sandbox_host_check_takes_one_plain_loopback_host() {
        for good in [
            "127.0.0.1:8790",
            "127.0.0.1:1",
            "localhost:65535",
            "LocalHost:8790",
        ] {
            let h = header_map(&[("host", good)]);
            assert!(!not_sandbox_local(&h), "{good}");
            assert!(!not_forwarder_own(&h), "{good}");
        }
        for bad in [
            // A trailing dot names the same host to DNS, but it is not the
            // spelling the forwarder's callers use.
            "localhost.:8790",
            "127.0.0.1.:8790",
            // Userinfo is never part of a `Host`.
            "user@127.0.0.1:8790",
            "127.0.0.1:8790@evil.example:8790",
            // Ports out of range, empty, signed or too long.
            "127.0.0.1:0",
            "127.0.0.1:65536",
            "localhost:99999",
            "127.0.0.1:",
            "127.0.0.1:+80",
            "127.0.0.1:008790",
            // The forwarder listens on `127.0.0.1` only.
            "[::1]:8790",
            "[::1]",
            "127.0.0.2:8790",
            "evil.example:8790",
            "127.0.0.1",
        ] {
            let h = header_map(&[("host", bad)]);
            assert!(not_sandbox_local(&h), "{bad}");
            assert!(not_forwarder_own(&h), "{bad}");
        }
        // Two `Host` headers, even both loopback.
        let two = header_map(&[("host", "127.0.0.1:8790"), ("host", "127.0.0.1:8790")]);
        assert!(not_sandbox_local(&two));
        assert!(not_forwarder_own(&two));
        let two = header_map(&[("host", "klav-proxy"), ("host", "klav-proxy")]);
        assert!(not_forwarder_own(&two));
        assert!(not_sandbox_local(&HeaderMap::new()));
        assert!(not_forwarder_own(&HeaderMap::new()));

        // `klav-proxy` only for the channel's own routes, never with a
        // port or a browser's header.
        for own in ["klav-proxy", "KLAV-PROXY"] {
            let h = header_map(&[("host", own)]);
            assert!(!not_forwarder_own(&h), "{own}");
            assert!(not_sandbox_local(&h), "{own}");
        }
        for bad in ["klav-proxy:8790", "klav-proxy.", "x.klav-proxy"] {
            assert!(not_forwarder_own(&header_map(&[("host", bad)])), "{bad}");
        }
        for browser in [("origin", "null"), ("sec-fetch-site", "same-origin")] {
            for host in ["klav-proxy", "127.0.0.1:8790"] {
                let h = header_map(&[("host", host), browser]);
                assert!(not_forwarder_own(&h), "{host} {browser:?}");
                assert!(not_sandbox_local(&h), "{host} {browser:?}");
            }
        }
    }

    #[test]
    fn a_query_that_names_the_method_is_seen_in_its_spellings() {
        for q in [
            "_method=DELETE",
            "a=1&_Method=PUT",
            "%5Fmethod=DELETE",
            "%5fmethod=x",
            "%255Fmethod=x",
            "a;_method=x",
            "_method",
            "x-http-method-override=DELETE",
            "+_method=x",
            // Arrays and nested keys (Rails, PHP).
            "_method[]=DELETE",
            "%5Fmethod%5B%5D=DELETE",
            "a[_method]=x",
            "a[b][_method]=x",
            "a%5B_method%5D=x",
            // Escaped four times: still escaped after three, refused.
            "%2525255Fmethod=x",
        ] {
            assert!(query_names_method(q), "{q}");
        }
        for q in [
            "method=x",
            "a=_method",
            "my_method=x",
            "q=%5Fmethod",
            "",
            "a[method]=x",
            "_method_x[]=1",
            "a[_method]x[y]=1",
        ] {
            assert!(!query_names_method(q), "{q}");
        }
    }

    #[test]
    fn the_server_refusing_the_signature_is_told_by_its_status() {
        let refused = ClientError::Api {
            status: 401,
            code: None,
            message: "anything".into(),
            current_version: None,
        };
        assert_eq!(
            map_client_error(&refused),
            ProxyError::NotAllowed(NotAllowed::ProxyRefused)
        );
        // Words in a denial (a path that says "signature") change nothing.
        let denied = ClientError::Denied("the server refused it; /v1/signature".into());
        assert_eq!(
            map_client_error(&denied),
            ProxyError::NotAllowed(NotAllowed::ServerDenied)
        );
    }

    /// A refused call says whether its method or its path is outside the
    /// rules, from the proxy's own grant, and only when no rule covers
    /// both; otherwise the server's wide reason stays.
    #[test]
    fn a_refused_call_says_which_part_is_outside_the_rules() {
        use klav_core::policy::{
            DomainPattern, Effect, HttpMethod, PathPrefix, Permission, Policy, Rule, Scope,
        };
        let item = klav_core::ids::ItemId::generate();
        let rule = |effect, methods: &[&str], prefix: &str| Rule {
            permission: Permission::Proxy,
            effect,
            scope: Scope {
                items: vec![item],
                domains: vec![DomainPattern::parse("api.example.com").expect("host")],
                methods: methods
                    .iter()
                    .map(|m| HttpMethod::parse(m).expect("method"))
                    .collect(),
                path_prefixes: vec![PathPrefix::parse(prefix).expect("prefix")],
                ..Scope::default()
            },
            expires_at: None,
            once: false,
            origin: None,
        };
        let policy = Policy {
            rules: vec![rule(Effect::Allow, &["GET"], "/v1")],
            expires_at: None,
        };
        let why = |policy: &Policy, method: &str, path: &str| {
            outside_rules(policy, item, "api.example.com", method, path, 1)
        };
        assert_eq!(
            why(&policy, "GET", "/v2/projects"),
            Some(NotAllowed::OutsidePath)
        );
        assert_eq!(
            why(&policy, "POST", "/v1/projects"),
            Some(NotAllowed::OutsideMethod)
        );
        assert_eq!(
            why(&policy, "POST", "/v2"),
            Some(NotAllowed::OutsideMethodOnPath)
        );
        // Inside the rules: refused for another reason, said widely.
        assert_eq!(why(&policy, "GET", "/v1/projects"), None);
        // Another item or host, or only `deny` rules: nothing to say.
        let other = klav_core::ids::ItemId::generate();
        assert_eq!(
            outside_rules(&policy, other, "api.example.com", "GET", "/v2", 1),
            None
        );
        assert_eq!(
            outside_rules(&policy, item, "evil.example", "GET", "/v2", 1),
            None
        );
        let denies = Policy {
            rules: vec![rule(Effect::Deny, &["GET"], "/v1")],
            expires_at: None,
        };
        assert_eq!(why(&denies, "GET", "/v2"), None);
        // One rule has the method, another the path: the two together.
        let split = Policy {
            rules: vec![
                rule(Effect::Allow, &["GET"], "/v1"),
                rule(Effect::Ask, &["POST"], "/v2"),
            ],
            expires_at: None,
        };
        assert_eq!(
            why(&split, "POST", "/v1/x"),
            Some(NotAllowed::OutsideMethodOnPath)
        );
        assert_eq!(why(&split, "POST", "/v2/x"), None);
        // An expired rule counts for nothing.
        let mut lapsed = rule(Effect::Allow, &["GET"], "/v1");
        lapsed.expires_at = Some(1);
        let lapsed = Policy {
            rules: vec![lapsed],
            expires_at: None,
        };
        assert_eq!(why(&lapsed, "GET", "/v2"), None);
        // The messages name the part, and nothing of the rules.
        for (part, said) in [
            (NotAllowed::OutsidePath, "path is outside"),
            (NotAllowed::OutsideMethod, "method is outside"),
            (
                NotAllowed::OutsideMethodOnPath,
                "method on this path is outside",
            ),
        ] {
            let res = ProxyError::NotAllowed(part).into_response();
            assert_eq!(res.status(), StatusCode::FORBIDDEN);
            assert_eq!(res.headers()[crate::errors::KLAV_ERROR], "klav_not_allowed");
            let text = ProxyError::NotAllowed(part).message();
            assert!(text.contains(said), "{text}");
            assert!(!text.contains("/v1") && !text.contains("GET"), "{text}");
        }
    }

    /// A provider's answer in `pieces`; `Err` breaks the body there.
    fn upstream(pieces: Vec<Result<&'static [u8], &'static str>>) -> reqwest::Response {
        let frames = pieces.into_iter().map(|p| {
            p.map(|b| http_body::Frame::data(Bytes::from_static(b)))
                .map_err(std::io::Error::other)
        });
        let body = http_body_util::StreamBody::new(futures_util::stream::iter(frames));
        reqwest::Response::from(axum::http::Response::new(reqwest::Body::wrap(body)))
    }

    fn body_of(res: reqwest::Response, idle: Duration) -> Body {
        let limits = BodyLimits {
            idle,
            deadline: tokio::time::Instant::now() + Duration::from_secs(3600),
            cut: None,
        };
        body_with(res, StreamRedactor::new(Redactor::new([SECRET])), limits)
    }

    const SECRET: &str = "secret-value-0123456789";

    fn body_with(res: reqwest::Response, redactor: StreamRedactor, limits: BodyLimits) -> Body {
        let tally = Tally {
            profile: "p".into(),
            count: 0,
            partial: 0,
            counts: Arc::new(crate::counts::Counts::in_memory()),
        };
        redacted_body(res, redactor, tally, Slots::single(), limits, None)
    }

    /// A provider's answer fed piece by piece through the sender, as a
    /// stream that stays open until the sender drops.
    fn live_upstream() -> (
        tokio::sync::mpsc::UnboundedSender<&'static [u8]>,
        reqwest::Response,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<&'static [u8]>();
        let frames = futures_util::stream::unfold(rx, |mut rx| async move {
            let piece = rx.recv().await?;
            Some((
                Ok::<_, std::io::Error>(http_body::Frame::data(Bytes::from_static(piece))),
                rx,
            ))
        });
        let body = http_body_util::StreamBody::new(frames);
        let res = reqwest::Response::from(axum::http::Response::new(reqwest::Body::wrap(body)));
        (tx, res)
    }

    /// The next piece of `body` within `wait`: `None` when none came,
    /// `Some(Err)` when it broke, `Some(Ok(empty))` when it ended.
    async fn next_piece(body: &mut Body, wait: Duration) -> Option<Result<Bytes, ()>> {
        use http_body_util::BodyExt;
        match tokio::time::timeout(wait, body.frame()).await {
            Err(_) => None,
            Ok(None) => Some(Ok(Bytes::new())),
            Ok(Some(Err(_))) => Some(Err(())),
            Ok(Some(Ok(frame))) => Some(Ok(frame.into_data().unwrap_or_default())),
        }
    }

    fn stream_limits(deadline: Duration, cut: Option<crate::cuts::CutHandle>) -> BodyLimits {
        BodyLimits {
            idle: Duration::from_secs(5),
            deadline: tokio::time::Instant::now() + deadline,
            cut,
        }
    }

    const SHORT: Duration = Duration::from_millis(300);

    /// A stream's event goes out with the chunk that ends it, redacted,
    /// even with the value split across two chunks of one line; the default
    /// rule would hold the line's end until the next chunk.
    #[tokio::test]
    async fn a_stream_emits_each_line_with_the_chunk_that_ends_it() {
        let (feed, res) = live_upstream();
        let redactor = StreamRedactor::by_lines(Redactor::whole_values([SECRET]));
        let mut body = body_with(res, redactor, stream_limits(Duration::from_secs(30), None));
        feed.send(b"data: {\"token\":\"secret-val").expect("feed");
        assert!(
            next_piece(&mut body, SHORT).await.is_none(),
            "half a line waits"
        );
        feed.send(b"ue-0123456789\"}\n\n").expect("feed");
        let got = next_piece(&mut body, Duration::from_secs(5))
            .await
            .expect("the event")
            .expect("not broken");
        assert_eq!(
            String::from_utf8_lossy(&got),
            format!(
                "data: {{\"token\":\"{}\"}}\n\n",
                klav_sdk::actions::REDACTED
            )
        );
        feed.send(b"data: two\r\n\r\n").expect("feed");
        let got = next_piece(&mut body, Duration::from_secs(5))
            .await
            .expect("the second event")
            .expect("not broken");
        assert_eq!(&got[..], b"data: two\r\n\r\n");
        drop(feed);
        let mut rest = Vec::new();
        loop {
            match next_piece(&mut body, Duration::from_secs(5)).await {
                Some(Ok(b)) if b.is_empty() => break,
                Some(Ok(b)) => rest.extend_from_slice(&b),
                other => panic!("{other:?}"),
            }
        }
        assert!(rest.is_empty(), "nothing held back: {rest:?}");
    }

    /// A stream line longer than the 1 MiB hold is cut as an error.
    #[tokio::test]
    async fn a_stream_line_over_the_hold_cap_is_cut() {
        static HALF: [u8; klav_sdk::actions::MAX_STREAM_HOLD / 2 + 1] =
            [b'x'; klav_sdk::actions::MAX_STREAM_HOLD / 2 + 1];
        let (feed, res) = live_upstream();
        let redactor = StreamRedactor::by_lines(Redactor::whole_values([SECRET]));
        let mut body = body_with(res, redactor, stream_limits(Duration::from_secs(30), None));
        feed.send(b"data: ok\n").expect("feed");
        assert_eq!(
            next_piece(&mut body, Duration::from_secs(5)).await,
            Some(Ok(Bytes::from_static(b"data: ok\n")))
        );
        feed.send(&HALF).expect("feed");
        feed.send(&HALF).expect("feed");
        assert_eq!(
            next_piece(&mut body, Duration::from_secs(5)).await,
            Some(Err(()))
        );
    }

    /// The deadline cuts a stream that is still sending, with an error.
    #[tokio::test]
    async fn the_deadline_cuts_a_live_stream() {
        let (feed, res) = live_upstream();
        let redactor = StreamRedactor::by_lines(Redactor::whole_values([SECRET]));
        let mut body = body_with(
            res,
            redactor,
            stream_limits(Duration::from_millis(400), None),
        );
        let begun = std::time::Instant::now();
        let mut broke = false;
        for _ in 0..40 {
            let _ = feed.send(b"data: tick\n");
            match next_piece(&mut body, Duration::from_secs(5)).await {
                Some(Ok(b)) if b.is_empty() => panic!("a clean end"),
                Some(Ok(_)) => tokio::time::sleep(Duration::from_millis(50)).await,
                Some(Err(())) => {
                    broke = true;
                    break;
                }
                None => panic!("stalled"),
            }
        }
        assert!(broke, "never cut");
        let took = begun.elapsed();
        assert!(
            took >= Duration::from_millis(350) && took < Duration::from_secs(2),
            "{took:?}"
        );
    }

    /// A cut (the sandbox ended, a pause) breaks the answer at once, and
    /// its slot comes back.
    #[tokio::test]
    async fn a_cut_breaks_the_answer_at_once() {
        let cuts = Arc::new(crate::cuts::Cuts::default());
        let sandbox = klav_core::ids::SandboxId::generate();
        let (feed, res) = live_upstream();
        let redactor = StreamRedactor::by_lines(Redactor::whole_values([SECRET]));
        let limits = stream_limits(Duration::from_secs(60), Some(cuts.register(Some(sandbox))));
        let mut body = body_with(res, redactor, limits);
        feed.send(b"data: one\n").expect("feed");
        assert!(matches!(
            next_piece(&mut body, Duration::from_secs(5)).await,
            Some(Ok(_))
        ));
        assert_eq!(cuts.open(), 1);
        cuts.cut_sandboxes(&[sandbox]);
        assert_eq!(
            next_piece(&mut body, Duration::from_secs(1)).await,
            Some(Err(()))
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(cuts.open(), 0, "the task ended and dropped its handle");
    }

    /// A caller that goes away frees the answer's slot without waiting for
    /// the idle limit, even while the provider sends nothing.
    #[tokio::test]
    async fn a_caller_that_leaves_frees_the_slot_at_once() {
        let cuts = Arc::new(crate::cuts::Cuts::default());
        let (_feed, res) = live_upstream();
        let redactor = StreamRedactor::by_lines(Redactor::whole_values([SECRET]));
        let limits = BodyLimits {
            idle: Duration::from_secs(600),
            deadline: tokio::time::Instant::now() + Duration::from_secs(600),
            cut: Some(cuts.register(None)),
        };
        let body = body_with(res, redactor, limits);
        drop(body);
        let begun = std::time::Instant::now();
        while cuts.open() > 0 && begun.elapsed() < Duration::from_secs(2) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(cuts.open(), 0);
    }

    #[test]
    fn a_stream_is_told_by_its_content_type() {
        let ct = |v: &'static str| {
            let mut h = HeaderMap::new();
            h.insert(header::CONTENT_TYPE, HeaderValue::from_static(v));
            h
        };
        assert!(is_event_stream(&ct("text/event-stream")));
        assert!(is_event_stream(&ct("Text/Event-Stream; charset=utf-8")));
        assert!(!is_event_stream(&ct("application/json")));
        assert!(!is_event_stream(&ct("text/event-streams")));
        assert!(!is_event_stream(&HeaderMap::new()));
    }

    const PIECE: &[u8] = &[b'a'; 4096];

    #[tokio::test]
    async fn a_whole_answer_ends_cleanly() {
        let body = body_of(
            upstream(vec![Ok(PIECE), Ok(PIECE), Ok(b"end")]),
            Duration::from_secs(5),
        );
        let got = axum::body::to_bytes(body, usize::MAX).await.expect("whole");
        assert_eq!(got.len(), 2 * PIECE.len() + 3);
    }

    #[tokio::test]
    async fn a_caller_too_slow_gets_a_broken_answer_not_a_short_one() {
        let body = body_of(
            upstream(vec![Ok(PIECE), Ok(PIECE), Ok(PIECE), Ok(b"end")]),
            Duration::from_millis(50),
        );
        // The caller does not read: the second piece waits for the slot
        // past the idle limit and the task gives up.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(axum::body::to_bytes(body, usize::MAX).await.is_err());
    }

    #[tokio::test]
    async fn a_body_that_breaks_upstream_ends_in_an_error() {
        let body = body_of(
            upstream(vec![Ok(PIECE), Err("reset")]),
            Duration::from_secs(5),
        );
        assert!(axum::body::to_bytes(body, usize::MAX).await.is_err());
    }

    #[test]
    fn only_plain_chunked_framing_passes() {
        let te = |v: &'static str| {
            let mut h = HeaderMap::new();
            h.append(header::TRANSFER_ENCODING, HeaderValue::from_static(v));
            h
        };
        assert!(!transfer_encoded(&HeaderMap::new()));
        assert!(!transfer_encoded(&te("chunked")));
        assert!(!transfer_encoded(&te("Chunked")));
        assert!(!transfer_encoded(&te("chunked, ")));
        // Two layers of chunks, on one line or two: hyper takes one apart.
        let mut twice = te("chunked");
        twice.append(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        assert!(transfer_encoded(&twice));
        for v in [
            "chunked, chunked",
            "chunked,Chunked",
            "gzip, chunked",
            "deflate",
            "chunked, gzip",
            "identity",
            "br,chunked",
        ] {
            assert!(transfer_encoded(&te(v)), "{v}");
        }
    }

    #[test]
    fn a_remembered_approval_is_keyed_by_the_exact_query() {
        let profile = Profile {
            name: "p".into(),
            item: ItemId::generate(),
            field: None,
            header: HeaderName::from_static("authorization"),
            prefix: String::new(),
            upstream: crate::profiles::Upstream {
                host: "api.example.com".into(),
                port: 443,
            },
            rate_per_minute: 60,
            mcp: None,
        };
        // A sandbox never reuses another's (or this machine's) approval.
        let one = klav_core::ids::SandboxId::generate();
        let two = klav_core::ids::SandboxId::generate();
        let keys = [
            approval_key(&profile, "DELETE", "/v1/items/1", None, None, None),
            approval_key(&profile, "DELETE", "/v1/items/1", Some(""), None, None),
            approval_key(&profile, "DELETE", "/v1/items/1", Some("a=1"), None, None),
            approval_key(&profile, "DELETE", "/v1/items/1", Some("a=2"), None, None),
            approval_key(&profile, "DELETE", "/v1/items/1", None, Some(one), None),
            approval_key(&profile, "DELETE", "/v1/items/1", None, Some(two), None),
        ];
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn remembered_approvals_are_capped_and_expire() {
        let now = klav_core_now_ms();
        let mut pending = HashMap::new();
        remember(&mut pending, "old".into(), ApprovalId::generate(), now - 1);
        remember(
            &mut pending,
            "live".into(),
            ApprovalId::generate(),
            now + 60_000,
        );
        assert!(!pending.contains_key("old"), "expired ones go");
        for i in 0..(MAX_PENDING + 10) {
            let until = now + 120_000 + i64::try_from(i).unwrap();
            remember(&mut pending, format!("k{i}"), ApprovalId::generate(), until);
        }
        assert_eq!(pending.len(), MAX_PENDING);
        assert!(
            !pending.contains_key("live"),
            "the first to expire goes first"
        );
        assert!(pending.contains_key(&format!("k{}", MAX_PENDING + 9)));
    }

    /// A log in memory, written as `klav-proxy` writes its log without
    /// `KLAV_LOG_FORMAT=json` (and without colors).
    #[derive(Clone, Default)]
    pub(crate) struct LogBuffer(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for LogBuffer {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl LogBuffer {
        pub(crate) fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync + 'static {
            let writer = self.clone();
            tracing_subscriber::fmt()
                .with_writer(move || writer.clone())
                .with_ansi(false)
                .with_max_level(tracing::Level::INFO)
                .finish()
        }

        /// [`LogBuffer::subscriber`] at TRACE for Klav's own crates (INFO
        /// for the rest): the zero-logging tests read every line Klav
        /// writes, debug and trace included.
        pub(crate) fn verbose_subscriber(
            &self,
        ) -> impl tracing::Subscriber + Send + Sync + 'static {
            let writer = self.clone();
            tracing_subscriber::fmt()
                .with_writer(move || writer.clone())
                .with_ansi(false)
                .with_env_filter(tracing_subscriber::EnvFilter::new(
                    "info,klav_proxy=trace,klav_sdk=trace,klav_client=trace,klav_forward=trace,klav_core=trace",
                ))
                .finish()
        }

        pub(crate) fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap_or_else(|e| e.into_inner())).into_owned()
        }
    }

    /// The log lines `f` writes on this thread.
    fn logged(f: impl FnOnce()) -> String {
        let log = LogBuffer::default();
        tracing::subscriber::with_default(log.subscriber(), f);
        log.text()
    }

    /// What no line about a refused call may hold: the error's text (the
    /// server's words), and nothing of the request.
    const MARKER: &str = "MARKER-refused-0123456789";

    /// The one line `log_refused` writes for `e`, after the narrowing
    /// [`refused`] does, checked for what it must not hold.
    fn line_for(e: &ClientError, answer: ProxyError) -> String {
        let sandbox = klav_core::ids::SandboxId::generate();
        let out = logged(|| {
            log_refused(
                "northflank",
                "DELETE",
                Some(sandbox),
                e,
                Origin::Asked,
                &answer,
            )
        });
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(!out.contains(MARKER), "{out}");
        assert!(out.contains(&format!("sandbox=\"{sandbox}\"")), "{out}");
        assert!(out.contains(" method=DELETE "), "{out}");
        assert!(out.contains(" profile=\"northflank\""), "{out}");
        out.trim_end().to_owned()
    }

    #[test]
    fn a_call_outside_the_profile_has_its_own_line() {
        let denied = ClientError::Denied(MARKER.into());
        for (why, outside) in [
            (NotAllowed::OutsidePath, "path"),
            (NotAllowed::OutsideMethod, "method"),
            (NotAllowed::OutsideMethodOnPath, "method_on_path"),
        ] {
            let line = line_for(&denied, ProxyError::NotAllowed(why));
            assert!(line.contains(" WARN "), "{line}");
            assert!(
                line.contains("a call outside its profile was refused"),
                "{line}"
            );
            assert!(
                line.ends_with(&format!(" error=\"denied\" outside=\"{outside}\"")),
                "{line}"
            );
        }
        // The server's own kind stays on the line when the rules narrow
        // another refusal to "outside".
        for (e, error) in [
            (ClientError::NotFound(MARKER.into()), "not_found"),
            (ClientError::AccountDeleting(None), "other"),
        ] {
            let line = line_for(&e, ProxyError::NotAllowed(NotAllowed::OutsidePath));
            assert!(
                line.ends_with(&format!(" error=\"{error}\" outside=\"path\"")),
                "{line}"
            );
        }
        // Without the sandbox, from this machine, it says so too.
        let out = logged(|| {
            log_refused(
                "northflank",
                "GET",
                None,
                &denied,
                Origin::Asked,
                &ProxyError::NotAllowed(NotAllowed::OutsidePath),
            );
        });
        assert!(
            out.contains("a call outside its profile was refused"),
            "{out}"
        );
        assert!(!out.contains("sandbox="), "{out}");
    }

    #[test]
    fn a_refusal_for_another_reason_says_which() {
        let api = |status, code| ClientError::Api {
            status,
            code,
            message: MARKER.into(),
            current_version: None,
        };
        for (e, error, reason) in [
            (
                ClientError::Denied(MARKER.into()),
                "denied",
                "server_denied",
            ),
            (
                ClientError::NotFound(MARKER.into()),
                "not_found",
                "server_denied",
            ),
            (ClientError::AccountDeleting(None), "other", "server_denied"),
            (ClientError::Paused(None), "paused", "agents_paused"),
            (
                api(403, Some(klav_proto::ErrorCode::SandboxRevoked)),
                "other",
                "sandbox_revoked",
            ),
            (api(401, None), "other", "proxy_refused"),
        ] {
            // A refusal the grant does not explain stays `ServerDenied`.
            let line = line_for(&e, map_client_error(&e));
            assert!(line.contains(" WARN "), "{line}");
            assert!(line.contains("the server refused the call"), "{line}");
            assert!(
                line.ends_with(&format!(" error=\"{error}\" reason=\"{reason}\"")),
                "{line}"
            );
            assert!(!line.contains("outside"), "{line}");
        }
    }

    /// An item the proxy's grant does not have is the proxy's own
    /// refusal, before the server is asked: never "the server refused",
    /// and never "outside", whatever the rules narrow it to.
    #[test]
    fn an_item_not_in_the_grant_is_the_proxys_own_refusal() {
        let e = ClientError::NotFound(MARKER.into());
        for answer in [
            ProxyError::NotAllowed(NotAllowed::ServerDenied),
            ProxyError::NotAllowed(NotAllowed::OutsidePath),
        ] {
            let sandbox = klav_core::ids::SandboxId::generate();
            let out = logged(|| {
                log_refused(
                    "northflank",
                    "DELETE",
                    Some(sandbox),
                    &e,
                    Origin::NotInGrant,
                    &answer,
                );
            });
            let line = out.trim_end();
            assert_eq!(out.lines().count(), 1, "{out}");
            assert!(!out.contains(MARKER), "{out}");
            assert!(line.contains(" WARN "), "{line}");
            assert!(
                line.contains("the proxy's grant does not have this profile's credential"),
                "{line}"
            );
            assert!(!line.contains("server"), "{line}");
            assert!(!line.contains("outside"), "{line}");
            assert!(line.contains(&format!("sandbox=\"{sandbox}\"")), "{line}");
            assert!(
                line.ends_with(" error=\"not_found\" reason=\"not_in_grant\""),
                "{line}"
            );
        }
    }

    #[test]
    fn an_answer_that_could_not_be_verified_is_an_error() {
        for (e, error) in [
            (ClientError::Rollback(MARKER.into()), "rollback"),
            (ClientError::Security(MARKER.into()), "security"),
            (
                ClientError::Crypto(klav_core::crypto::CryptoError::Decryption),
                "crypto",
            ),
            (ClientError::Corrupt(MARKER.into()), "corrupt"),
        ] {
            let line = line_for(&e, map_client_error(&e));
            assert!(line.contains(" ERROR "), "{line}");
            assert!(
                line.contains("the server's answer could not be verified"),
                "{line}"
            );
            assert!(line.ends_with(&format!(" error=\"{error}\"")), "{line}");
        }
    }

    #[test]
    fn an_answer_that_could_not_be_used_says_so() {
        let e = ClientError::Api {
            status: 500,
            code: None,
            message: MARKER.into(),
            current_version: None,
        };
        let line = line_for(&e, map_client_error(&e));
        assert!(line.contains(" WARN "), "{line}");
        assert!(
            line.contains("the server's answer could not be used"),
            "{line}"
        );
        assert!(!line.contains("verified"), "{line}");
        assert!(line.ends_with(" error=\"other\""), "{line}");
    }

    #[test]
    fn a_server_that_could_not_be_reached_says_so() {
        let e = ClientError::Network(MARKER.into());
        let line = line_for(&e, map_client_error(&e));
        assert!(line.contains(" WARN "), "{line}");
        assert!(line.contains("the server could not be reached"), "{line}");
        assert!(line.ends_with(" error=\"network\""), "{line}");
    }
}
