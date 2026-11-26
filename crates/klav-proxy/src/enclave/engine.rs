//! The enclave (ADR 0051 §2–§4, §6.1, §6.4): one seed, many accounts.
//!
//! - **Seed** (§3.1, §4): 32 bytes in memory only ([`HostedSeed`]), from the
//!   OS RNG mixed with the NSM's entropy ([`Enclave::start_fresh`]), or
//!   from a live peer through the attested hand-off ([`Enclave::join`]).
//! - **Accounts** (§3.1, §3.4): each enrollment derives the account's agent
//!   keys from the seed; its channel key answers only to
//!   `a<agent_id hex>.<endpoint>` (SNI), and each account has its own
//!   [`ProxyState`] (its own agent, grant, sandboxes and quotas). A
//!   connection reaches only the state of the account its SNI named, whose
//!   key it was shown: account A's channel holds none of B's keys, grants or
//!   credentials.
//! - **API** (§6.4): `GET`/`POST /v1/manifest`, `GET /v1/attest`, `POST
//!   /v1/enroll`, the hand-off (`POST /v1/handoff/hello` and `/seal`),
//!   `GET /v1/status` (the service key's public half, §18) and `GET
//!   /healthz`. Every answer is self-authenticating or signed by the
//!   account, so the API's transport is not trusted.
//! - **Hand-off** (§4.2): the holder checks the joiner's attestation
//!   against a manifest the release authority signed **and** published in
//!   the repository, its PCR3 against `parent_roles`, and refuses an older
//!   image; the joiner checks the holder the same way; then the seed, the
//!   enrollments and each account's live sandbox state (its store, channel
//!   keys, heartbeat epoch and `seq`) move sealed to the joiner's attested
//!   key (kind `0x28`). A claimed sandbox goes on through the joiner with
//!   the same channel key, without a new claim, enrollment or grant.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use klav_client::ClientError;
use klav_core::crypto::channel::TlsSigner;
use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::sign::Signature;
use klav_core::ids::{AccountId, AgentId};
use klav_core::nitro::{
    HandoffKey, HostedSeed, Measurement, VerifiedManifest, derive_account_keys, enclave_binding,
    handoff_info, hosted_service_keys, open_handoff, seal_handoff, sign_hosted_registration,
    verify_enroll,
};
use klav_forward::channel::{KeysByName, peer_key, server_config_by_name};
use klav_proto::Blob;
use klav_proto::agent::HostedRegistrationProof;
use klav_sdk::{Agent, MemoryAgent, Session};
use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;

use super::attest::{AttestRequest, AttestationProvider};
use super::quota::{self, QuotaLimits, Quotas};
use super::registry::{AccountState, Enrollment, STATE_VERSION, SharedState};
use super::trust::{Anchors, ManifestSource, SignedManifest, is_published};
use super::{channel_name, now_ms, refuse};
use crate::channel::{Accepted, ChannelLimits, ChannelListener, Peer};
use crate::proxy::ProxyState;
use crate::transport::{BoxIo, Listener};

/// How far an enroll request's `at_ms` may be from the enclave's clock.
pub const ENROLL_SKEW_MS: u64 = 5 * 60 * 1000;
/// How long a hand-off session lives between hello and seal.
pub const HANDOFF_SESSION_TTL: Duration = Duration::from_secs(60);
/// Hand-off sessions open at once.
pub const MAX_PENDING_HANDOFFS: usize = 16;
/// The name the hosted agent registers under, shown to the person.
pub const AGENT_NAME: &str = "klav-cloud-proxy";
/// Enroll requests per account per minute.
pub const ENROLLS_PER_MINUTE: u32 = 6;
/// Attestations per account per minute.
pub const ATTESTS_PER_MINUTE: u32 = 60;
/// Largest nonce an asker may send.
pub const MAX_NONCE: usize = 64;
/// Largest API body.
pub const MAX_API_BODY: usize = 64 * 1024;
/// TLS handshakes at once on the channel.
const HANDSHAKES: usize = 256;

/// How the enclave is set up.
pub struct EnclaveConfig {
    /// The Klav server every account lives on (Q6: `https://api.klav.dev`).
    pub server: String,
    /// The proxy's DNS name (`proxy.klav.dev`): accounts are
    /// `a<agent_id hex>.<endpoint>`.
    pub endpoint: String,
    /// How the agents reach the server (inside the enclave, through the
    /// parent's egress).
    pub server_http: reqwest::Client,
    /// How the proxies reach providers.
    pub upstream: reqwest::Client,
    /// Each account's quotas.
    pub limits: QuotaLimits,
    /// Each account's channel limits.
    pub channel_limits: ChannelLimits,
}

/// The manifest the enclave serves, verified.
struct CurrentManifest {
    signed: SignedManifest,
    verified: VerifiedManifest,
}

/// One account the enclave serves.
struct Account {
    enrollment: Enrollment,
    name: String,
    quotas: Arc<Quotas>,
    serving: tokio::sync::Mutex<Option<Arc<Serving>>>,
    /// Whether its agent ever opened a session (it was approved), here or,
    /// before a hand-off, on the holder.
    served: AtomicBool,
    /// The live sandbox state a holder handed over, until the account's
    /// proxy starts from it; handed on as it is if it never does.
    carried: Mutex<Option<AccountState>>,
}

impl Account {
    fn carried(&self) -> Option<AccountState> {
        self.carried
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// An account's running proxy.
struct Serving {
    /// Also held by its tasks; the tests read it.
    #[cfg_attr(not(all(test, feature = "enclave-testkit")), allow(dead_code))]
    state: Arc<ProxyState>,
    tx: mpsc::Sender<(Accepted, Peer)>,
    slots: Arc<Semaphore>,
    /// The issuer API's loopback port; the tests read it.
    #[cfg_attr(not(all(test, feature = "enclave-testkit")), allow(dead_code))]
    local_port: u16,
    tasks: Vec<tokio::task::AbortHandle>,
}

impl Drop for Serving {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// A hand-off between hello and seal.
struct PendingHandoff {
    /// The nonce the joiner's document must carry.
    holder_nonce: [u8; 32],
    /// The nonce the holder's document carried (the joiner's).
    joiner_nonce: Vec<u8>,
    expires: Instant,
}

/// Klav Cloud's enclave.
pub struct Enclave {
    config: EnclaveConfig,
    nsm: Arc<dyn AttestationProvider>,
    anchors: Anchors,
    published: Arc<dyn ManifestSource>,
    /// This enclave's own image, from its own attestation.
    own: Measurement,
    seed: RwLock<Option<Arc<HostedSeed>>>,
    /// The Ed25519 public half of the service key, as 64 lowercase hex
    /// digits: set with the seed, served by `GET /v1/status` and logged
    /// once, so the operator can set `KLAV_HOSTED_PROXY_SERVICE_KEY` on
    /// the server (ADR 0051 §15, §18). Public; the private half is never
    /// kept, only derived when a registration is marked.
    service_key: OnceLock<String>,
    manifest: RwLock<Option<Arc<CurrentManifest>>>,
    accounts: RwLock<HashMap<AccountId, Arc<Account>>>,
    by_name: RwLock<HashMap<String, AccountId>>,
    keys: Arc<KeysByName>,
    handoffs: Mutex<HashMap<[u8; 16], PendingHandoff>>,
    rates: crate::rate::RateLimits,
}

fn read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Enclave {
    /// An enclave with no seed yet: it attests itself once to learn its
    /// own image (refused when its PCRs are zero, a debug enclave).
    pub fn new(
        config: EnclaveConfig,
        nsm: Arc<dyn AttestationProvider>,
        anchors: Anchors,
        published: Arc<dyn ManifestSource>,
    ) -> Result<Arc<Self>, String> {
        let nonce = klav_core::crypto::random::array::<32>();
        let document = nsm.attest(&AttestRequest {
            nonce: Some(&nonce),
            ..AttestRequest::default()
        })?;
        let own = anchors
            .document(&document, now_ms())
            .and_then(|d| d.measurement())
            .map_err(|e| format!("this enclave's own attestation: {}", e.code()))?;
        Ok(Arc::new(Self {
            config,
            nsm,
            anchors,
            published,
            own,
            seed: RwLock::new(None),
            service_key: OnceLock::new(),
            manifest: RwLock::new(None),
            accounts: RwLock::new(HashMap::new()),
            by_name: RwLock::new(HashMap::new()),
            keys: Arc::new(KeysByName::default()),
            handoffs: Mutex::new(HashMap::new()),
            rates: crate::rate::RateLimits::default(),
        }))
    }

    /// This enclave's image.
    pub fn measurement(&self) -> &Measurement {
        &self.own
    }

    /// Whether it holds a seed.
    pub fn has_seed(&self) -> bool {
        read(&self.seed).is_some()
    }

    fn seed(&self) -> Option<Arc<HostedSeed>> {
        read(&self.seed).clone()
    }

    fn set_seed(&self, seed: HostedSeed) -> Result<(), String> {
        let mut slot = write(&self.seed);
        if slot.is_some() {
            return Err("this enclave already holds a seed".into());
        }
        // Only the public half leaves this function; the key pair is
        // dropped (and zeroized) here.
        let service_key =
            data_encoding::HEXLOWER.encode(hosted_service_keys(&seed).public().ed25519());
        *slot = Some(Arc::new(seed));
        drop(slot);
        tracing::info!(
            service_key = %service_key,
            "service key: KLAV_HOSTED_PROXY_SERVICE_KEY on the server must be this public key"
        );
        let _ = self.service_key.set(service_key);
        Ok(())
    }

    /// The Ed25519 public half of the service key, as 64 lowercase hex
    /// digits, once the enclave holds a seed (genesis or a hand-off: the
    /// same seed, so the same key on every enclave that holds it).
    pub fn service_key(&self) -> Option<&str> {
        self.service_key.get().map(String::as_str)
    }

    /// The first enclave, or the first after a total loss (§4.4): a new
    /// seed from the OS RNG and the NSM's entropy. It knows no account.
    pub fn start_fresh(&self) -> Result<(), String> {
        let entropy = self.nsm.entropy()?;
        self.set_seed(HostedSeed::generate_with_entropy(&entropy))?;
        tracing::info!("new seed: no account is enrolled until each sets the hosted proxy up");
        Ok(())
    }

    fn manifest(&self) -> Option<Arc<CurrentManifest>> {
        read(&self.manifest).clone()
    }

    /// Serves `signed` from now on: signed by the release authority, not
    /// older than the one it serves, not expired, and listing this
    /// enclave's own image as `current` or `draining`. Returns its `seq`.
    pub fn load_manifest(&self, signed: SignedManifest) -> Result<u64, &'static str> {
        let highest = self.manifest().map(|m| m.verified.seq());
        let verified = self
            .anchors
            .manifest(&signed, highest, now_ms())
            .map_err(|e| e.code())?;
        verified.image_for(&self.own).map_err(|e| e.code())?;
        let seq = verified.seq();
        *write(&self.manifest) = Some(Arc::new(CurrentManifest { signed, verified }));
        Ok(seq)
    }

    /// What a hand-off carries besides the seed: the enrollments and each
    /// account's live sandbox state, read under each store's lock (the
    /// state of one account is consistent; accounts are read one by one).
    async fn shared_state(&self) -> SharedState {
        let mut accounts: Vec<Arc<Account>> = read(&self.accounts).values().cloned().collect();
        accounts.sort_by_key(|a| a.enrollment.account_id);
        let mut state = SharedState {
            v: STATE_VERSION,
            enrollments: Vec::with_capacity(accounts.len()),
            accounts: Vec::with_capacity(accounts.len()),
        };
        for account in accounts {
            state.enrollments.push(account.enrollment.clone());
            // A proxy being started right now has no sandbox yet: what it
            // starts from is still `carried`.
            let serving = account
                .serving
                .try_lock()
                .ok()
                .and_then(|slot| slot.as_ref().map(Arc::clone));
            let served = account.served.load(Ordering::SeqCst);
            let carried = match serving {
                Some(serving) => Some(AccountState {
                    account_id: account.enrollment.account_id,
                    served,
                    store: serving.state.sandboxes().snapshot().await,
                    heartbeat: Some(serving.state.heartbeats().snapshot().await),
                    revocation_cursor: serving.state.revocation_cursor(),
                }),
                None => account.carried().map(|mut c| {
                    c.served |= served;
                    c
                }),
            };
            if let Some(carried) = carried {
                state.accounts.push(carried);
            } else if served {
                state.accounts.push(AccountState {
                    account_id: account.enrollment.account_id,
                    served,
                    store: crate::sandboxes::StoreSnapshot::default(),
                    heartbeat: None,
                    revocation_cursor: 0,
                });
            }
        }
        state
    }

    /// Serves `enrollment` from now on, under keys derived from `seed`,
    /// starting from `carried` when a holder handed its live sandbox state
    /// over. An earlier enrollment of the same account is dropped, its
    /// channel name with it.
    fn add_account(
        &self,
        seed: &HostedSeed,
        enrollment: Enrollment,
        carried: Option<AccountState>,
    ) -> Result<String, String> {
        let keys = derive_account_keys(seed, enrollment.account_id, enrollment.generation);
        let name = channel_name(enrollment.agent_id, &self.config.endpoint);
        self.keys
            .insert(&name, TlsSigner::server(&keys))
            .map_err(|e| format!("channel key: {e}"))?;
        let account = enrollment.account_id;
        let previous = write(&self.accounts).insert(
            account,
            Arc::new(Account {
                enrollment,
                name: name.clone(),
                quotas: Arc::new(Quotas::new(self.config.limits)),
                serving: tokio::sync::Mutex::new(None),
                served: AtomicBool::new(carried.as_ref().is_some_and(|c| c.served)),
                carried: Mutex::new(carried),
            }),
        );
        let mut by_name = write(&self.by_name);
        if let Some(previous) = previous
            && previous.name != name
        {
            self.keys.remove(&previous.name);
            by_name.remove(&previous.name);
        }
        by_name.insert(name.clone(), account);
        Ok(name)
    }

    fn account(&self, id: AccountId) -> Option<Arc<Account>> {
        read(&self.accounts).get(&id).cloned()
    }

    fn account_named(&self, name: &str) -> Option<Arc<Account>> {
        let id = *read(&self.by_name).get(name)?;
        self.account(id)
    }

    /// The account's running proxy, started the first time a connection
    /// needs it: its agent (in memory, pinned to the enrolled account
    /// identity), its session, an in-memory sandbox store, its quotas and
    /// its background loops. Refused while the person has not approved the
    /// agent.
    async fn serving(self: &Arc<Self>, account: &Arc<Account>) -> Result<Arc<Serving>, String> {
        let mut slot = account.serving.lock().await;
        if let Some(serving) = slot.as_ref() {
            return Ok(Arc::clone(serving));
        }
        let seed = self.seed().ok_or("no seed")?;
        let e = &account.enrollment;
        let keys = derive_account_keys(&seed, e.account_id, e.generation);
        let agent = Agent::in_memory(self.memory_agent(e), keys).map_err(|e| e.to_string())?;
        let session = Session::open(agent).await.map_err(|e| e.to_string())?;
        // The issuer API (ADR 0036 §4) on the enclave's own loopback.
        let local = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|e| format!("loopback: {e}"))?;
        let local_port = local
            .local_addr()
            .map_err(|e| format!("loopback: {e}"))?
            .port();
        let limits = *account.quotas.limits();
        // After a hand-off, the holder's store, channel keys and heartbeat:
        // a claimed sandbox's forwarder goes on with the same channel key.
        let carried = account.carried();
        let clock: Arc<dyn crate::sandboxes::Clock> = Arc::new(crate::sandboxes::SystemClock);
        let (sandboxes, heartbeats, cursor) = match carried {
            Some(c) => (
                crate::sandboxes::Sandboxes::restored(clock, c.store),
                c.heartbeat.map(crate::heartbeat::Heartbeats::restored),
                c.revocation_cursor,
            ),
            None => (crate::sandboxes::Sandboxes::in_memory(clock), None, 0),
        };
        let state = ProxyState::new(session, self.config.upstream.clone(), local_port);
        let state = match heartbeats {
            Some(heartbeats) => state.with_heartbeats(heartbeats),
            None => state,
        };
        state.set_revocation_cursor(cursor);
        let state = Arc::new(
            state
                .with_sandboxes(sandboxes)
                .with_max_body(limits.max_body)
                .with_account_live_cap(limits.live_sandboxes)
                .with_account_budget(
                    limits.upstream_calls,
                    limits.buffer_bytes,
                    limits.queue_wait,
                ),
        );
        let (tx, rx) = mpsc::channel(16);
        let listener = ChannelListener::from_receiver(
            rx,
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            self.config.channel_limits,
        );
        let routes = crate::channel::router(Arc::clone(&state)).layer(
            axum::middleware::from_fn_with_state(Arc::clone(&account.quotas), quota::enforce),
        );
        let mut tasks = Vec::new();
        tasks.push(
            tokio::spawn(crate::channel::serve_routes(
                listener,
                Arc::clone(&state),
                routes,
                std::future::pending(),
            ))
            .abort_handle(),
        );
        let api = crate::proxy::router(Arc::clone(&state));
        tasks.push(
            tokio::spawn(async move {
                let _ = axum::serve(local, api).await;
            })
            .abort_handle(),
        );
        let s = Arc::clone(&state);
        tasks.push(
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(crate::proxy::GRANT_REFRESH);
                tick.tick().await;
                loop {
                    tick.tick().await;
                    if let Err(e) = s.refresh().await {
                        tracing::warn!(
                            kind = crate::proxy::redacted_kind(&e),
                            "could not refresh an account's grant"
                        );
                    }
                }
            })
            .abort_handle(),
        );
        let s = Arc::clone(&state);
        tasks.push(
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(crate::sandboxes::SWEEP_EVERY);
                loop {
                    tick.tick().await;
                    crate::sandboxes::sweep(&s).await;
                }
            })
            .abort_handle(),
        );
        let s = Arc::clone(&state);
        tasks.push(
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(crate::heartbeat::LOOK_EVERY);
                loop {
                    tick.tick().await;
                    crate::heartbeat::beat(&s, false).await;
                }
            })
            .abort_handle(),
        );
        account.served.store(true, Ordering::SeqCst);
        *account
            .carried
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        let serving = Arc::new(Serving {
            state,
            tx,
            slots: Arc::new(Semaphore::new(crate::channel::MAX_CHANNEL_CONNECTIONS)),
            local_port,
            tasks,
        });
        *slot = Some(Arc::clone(&serving));
        Ok(serving)
    }

    fn memory_agent(&self, e: &Enrollment) -> MemoryAgent {
        MemoryAgent {
            name: AGENT_NAME.into(),
            agent_id: e.agent_id,
            server: self.config.server.clone(),
            email: e.email.clone(),
            account_id: e.account_id,
            account_public_identity: e.account_public_identity.clone(),
            http: self.config.server_http.clone(),
        }
    }

    /// Accepts channel connections: finishes each TLS handshake with the
    /// key its SNI names, then hands it to that account's proxy. An
    /// unknown name, no name (an IP literal) or the fixed name of an
    /// older forwarder gets no key, and the handshake fails (§3.4).
    pub async fn serve_channel(self: Arc<Self>, listener: Box<dyn Listener>) {
        let config = match server_config_by_name(Arc::clone(&self.keys)) {
            Ok(config) => config,
            Err(e) => {
                tracing::error!(error = %e, "channel TLS");
                return;
            }
        };
        let acceptor = TlsAcceptor::from(config);
        let handshakes = Arc::new(Semaphore::new(HANDSHAKES));
        loop {
            let Ok(slot) = Arc::clone(&handshakes).acquire_owned().await else {
                return;
            };
            let io = match listener.accept().await {
                Ok(io) => io,
                Err(e) => {
                    tracing::warn!(error = %e, "channel accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let this = Arc::clone(&self);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let shaken =
                    tokio::time::timeout(this.config.channel_limits.handshake, acceptor.accept(io))
                        .await;
                drop(slot);
                let Ok(Ok(tls)) = shaken else {
                    tracing::debug!("channel handshake refused or timed out");
                    return;
                };
                let (name, key) = {
                    let conn = tls.get_ref().1;
                    (
                        conn.server_name().map(str::to_ascii_lowercase),
                        peer_key(conn),
                    )
                };
                let (Some(name), Some(key)) = (name, key) else {
                    return;
                };
                let Some(account) = this.account_named(&name) else {
                    return;
                };
                let serving = match this.serving(&account).await {
                    Ok(serving) => serving,
                    Err(_) => {
                        tracing::debug!("an account's proxy is not serving yet");
                        return;
                    }
                };
                let tls: tokio_rustls::server::TlsStream<BoxIo> = tls;
                let Some(accepted) = Accepted::routed(Box::new(tls), &serving.slots) else {
                    return;
                };
                let peer = Peer {
                    addr: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                    key,
                };
                let _ = serving.tx.send((accepted, peer)).await;
            });
        }
    }

    /// The public API (§6.4), and the hand-off with `handoff`.
    pub fn api_router(self: &Arc<Self>, handoff: bool) -> Router {
        let router = Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route("/v1/status", get(status))
            .route("/v1/manifest", get(get_manifest).post(post_manifest))
            .route("/v1/attest", get(attest))
            .route("/v1/enroll", post(enroll));
        let router = if handoff {
            router.merge(Self::handoff_routes())
        } else {
            router
        };
        router
            .layer(DefaultBodyLimit::max(MAX_API_BODY))
            .with_state(Arc::clone(self))
    }

    /// The hand-off alone (§4.2), for a peer port of its own.
    pub fn peer_router(self: &Arc<Self>) -> Router {
        Self::handoff_routes()
            .route("/healthz", get(|| async { "ok" }))
            .layer(DefaultBodyLimit::max(MAX_API_BODY))
            .with_state(Arc::clone(self))
    }

    fn handoff_routes() -> Router<Arc<Self>> {
        Router::new()
            .route("/v1/handoff/hello", post(handoff_hello))
            .route("/v1/handoff/seal", post(handoff_seal))
    }

    /// Serves the API with the hand-off on `listener` until it fails.
    pub async fn serve_api(self: Arc<Self>, listener: Box<dyn Listener>) -> std::io::Result<()> {
        self.serve_router(listener, true).await
    }

    /// Serves the API on `listener`, with the hand-off or without it.
    pub async fn serve_router(
        self: Arc<Self>,
        listener: Box<dyn Listener>,
        handoff: bool,
    ) -> std::io::Result<()> {
        let router = self.api_router(handoff);
        axum::serve(ApiListener(listener), router).await
    }

    /// Serves the hand-off alone on `listener` until it fails.
    pub async fn serve_peer(self: Arc<Self>, listener: Box<dyn Listener>) -> std::io::Result<()> {
        let router = self.peer_router();
        axum::serve(ApiListener(listener), router).await
    }

    /// Joins a live holder at `holder` (its API's base URL): ADR 0051 §4.2
    /// from the joiner's side. On success this enclave holds the seed and
    /// serves every account the holder did.
    pub async fn join(&self, holder: &str, client: &reqwest::Client) -> Result<(), String> {
        if self.has_seed() {
            return Err("this enclave already holds a seed".into());
        }
        let holder = holder.trim_end_matches('/');
        let joiner_nonce = klav_core::crypto::random::array::<32>();
        let hello: HelloAnswer = post_json(
            client,
            &format!("{holder}/v1/handoff/hello"),
            &HelloRequest {
                nonce: Blob::new(joiner_nonce.to_vec()),
            },
        )
        .await?;
        let signed = parse_manifest_wire(&hello.manifest)?;
        let highest = self.manifest().map(|m| m.verified.seq());
        let now = now_ms();
        let verified = self
            .anchors
            .manifest(&signed, highest, now)
            .map_err(|e| format!("the holder's manifest: {}", e.code()))?;
        is_published(self.published.as_ref(), verified.seq(), &signed).await?;
        let own = verified
            .image_for(&self.own)
            .map_err(|e| format!("this enclave's image in the manifest: {}", e.code()))?
            .clone();
        let holder_check = self
            .anchors
            .holder(hello.document.as_bytes(), &verified, &joiner_nonce, now)
            .map_err(|e| format!("the holder: {}", e.code()))?;
        let key = HandoffKey::generate();
        let public = key.public();
        let document = self.nsm.attest(&AttestRequest {
            nonce: Some(hello.nonce.as_bytes()),
            public_key: Some(&public),
            user_data: None,
        })?;
        let sealed: SealAnswer = post_json(
            client,
            &format!("{holder}/v1/handoff/seal"),
            &SealRequest {
                session: hello.session,
                document: Blob::new(document),
                manifest: hello.manifest,
            },
        )
        .await?;
        let info = handoff_info(
            &holder_check.measurement.pcr0,
            &self.own.pcr0,
            &joiner_nonce,
            hello.nonce.as_bytes(),
        );
        let (seed, state) = open_handoff(&key, sealed.sealed.as_bytes(), &info)
            .map_err(|_| "the sealed hand-off does not open".to_owned())?;
        let mut state = SharedState::decode(&state)?;
        let holder_version = holder_check.image.version_text().to_owned();
        let accounts = state.enrollments.len();
        let mut sandboxes = 0;
        for enrollment in std::mem::take(&mut state.enrollments) {
            let carried = state.take_account(enrollment.account_id);
            sandboxes += carried.as_ref().map_or(0, |c| c.store.live());
            self.add_account(&seed, enrollment, carried)?;
        }
        *write(&self.manifest) = Some(Arc::new(CurrentManifest { signed, verified }));
        self.set_seed(seed)?;
        tracing::info!(
            holder = %holder_version,
            joiner = %own.version_text(),
            accounts,
            sandboxes,
            "hand-off received"
        );
        Ok(())
    }

    #[cfg(all(test, feature = "enclave-testkit"))]
    pub(crate) fn seed_for_test(&self) -> Option<Arc<HostedSeed>> {
        self.seed()
    }

    /// Serves `enrollment` without asking the server (hand-off tests).
    #[cfg(all(test, feature = "enclave-testkit"))]
    pub(crate) fn enroll_for_test(&self, enrollment: Enrollment) -> Result<String, String> {
        let seed = self.seed().ok_or("no seed")?;
        self.add_account(&seed, enrollment, None)
    }

    /// Stops serving every account, as an enclave that goes away does:
    /// each account's proxy and its loops end (tests of the hand-off).
    #[cfg(all(test, feature = "enclave-testkit"))]
    pub(crate) async fn stop_for_test(&self) {
        let accounts: Vec<Arc<Account>> = read(&self.accounts).values().cloned().collect();
        for account in accounts {
            account.serving.lock().await.take();
        }
        write(&self.accounts).clear();
        let names: Vec<String> = write(&self.by_name).drain().map(|(n, _)| n).collect();
        for name in names {
            self.keys.remove(&name);
        }
    }

    #[cfg(all(test, feature = "enclave-testkit"))]
    pub(crate) fn channel_names(&self) -> Vec<String> {
        read(&self.by_name).keys().cloned().collect()
    }

    #[cfg(all(test, feature = "enclave-testkit"))]
    pub(crate) async fn issuer_port(self: &Arc<Self>, account: AccountId) -> Result<u16, String> {
        let account = self.account(account).ok_or("no such account")?;
        Ok(self.serving(&account).await?.local_port)
    }

    #[cfg(all(test, feature = "enclave-testkit"))]
    pub(crate) async fn state_of(
        self: &Arc<Self>,
        account: AccountId,
    ) -> Result<Arc<ProxyState>, String> {
        let account = self.account(account).ok_or("no such account")?;
        Ok(Arc::clone(&self.serving(&account).await?.state))
    }

    #[cfg(all(test, feature = "enclave-testkit"))]
    pub(crate) fn egress_today(&self, account: AccountId) -> u64 {
        self.account(account)
            .map(|a| a.quotas.egress_today())
            .unwrap_or(0)
    }
}

/// `axum::serve` over a transport [`Listener`].
struct ApiListener(Box<dyn Listener>);

impl axum::serve::Listener for ApiListener {
    type Io = BoxIo;
    type Addr = ();

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.0.accept().await {
                Ok(io) => return (io, ()),
                Err(e) => {
                    tracing::warn!(error = %e, "API accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(())
    }
}

async fn post_json<B: Serialize, R: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    body: &B,
) -> Result<R, String> {
    let res = client
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(|_| "the holder did not answer".to_owned())?;
    if !res.status().is_success() {
        let status = res.status().as_u16();
        let refused: serde_json::Value = res.json().await.unwrap_or_default();
        return Err(format!(
            "the holder refused ({status}): {} {}",
            refused["error"].as_str().unwrap_or("?"),
            refused["reason"].as_str().unwrap_or("")
        ));
    }
    res.json()
        .await
        .map_err(|_| "the holder's answer is malformed".to_owned())
}

// ----------------------------------------------------------------- wire --

pub use klav_proto::hosted::{AttestAnswer, EnrollAnswer, EnrollRequest, ManifestWire};

/// A manifest of this enclave on the wire.
fn manifest_wire(signed: &SignedManifest) -> ManifestWire {
    ManifestWire {
        manifest: String::from_utf8_lossy(&signed.bytes).into_owned(),
        signature: signed.signature_hex(),
    }
}

/// A manifest from the wire, its signature parsed.
fn parse_manifest_wire(wire: &ManifestWire) -> Result<SignedManifest, String> {
    Ok(SignedManifest {
        bytes: wire.manifest.as_bytes().to_vec(),
        signature: SignedManifest::parse_signature(&wire.signature)
            .ok_or("the manifest's signature is not 128 hex characters")?,
    })
}

/// `GET /v1/attest` query.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestQuery {
    /// The account.
    pub account: AccountId,
    /// The device's nonce, base64url without padding.
    pub nonce: String,
}

/// `POST /v1/handoff/hello`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloRequest {
    /// The joiner's nonce for the holder's document.
    pub nonce: Blob,
}

/// `POST /v1/handoff/hello` answer.
#[derive(Serialize, Deserialize)]
pub struct HelloAnswer {
    /// The session to name in the seal.
    pub session: Blob,
    /// The holder's nonce for the joiner's document.
    pub nonce: Blob,
    /// The holder's document, with the joiner's nonce.
    pub document: Blob,
    /// The holder's manifest.
    pub manifest: ManifestWire,
}

/// `POST /v1/handoff/seal`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealRequest {
    /// From the hello.
    pub session: Blob,
    /// The joiner's document: the holder's nonce, and its one-time X25519
    /// key in `public_key`.
    pub document: Blob,
    /// The manifest the joiner relies on.
    pub manifest: ManifestWire,
}

/// `POST /v1/handoff/seal` answer.
#[derive(Serialize, Deserialize)]
pub struct SealAnswer {
    /// Kind `0x28`.
    pub sealed: Blob,
}

/// What `GET /v1/status` answers.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StatusAnswer {
    /// The service key's Ed25519 public half (64 lowercase hex digits),
    /// what `KLAV_HOSTED_PROXY_SERVICE_KEY` takes; `null` with no seed.
    pub service_key: Option<String>,
}

// --------------------------------------------------------------- routes --

fn starting() -> Response {
    refuse(
        StatusCode::SERVICE_UNAVAILABLE,
        "klav_hosted_starting",
        "Klav Cloud's proxy is starting.",
        "Retry in a minute.",
        Some(30),
    )
}

fn bad_request(message: &'static str) -> Response {
    refuse(
        StatusCode::BAD_REQUEST,
        "klav_bad_request",
        message,
        "Fix the request; do not retry it as is.",
        None,
    )
}

fn handoff_refused(reason: &'static str) -> Response {
    let mut res = (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "klav_handoff_refused",
            "reason": reason,
            "message": "This enclave does not hand its seed to the asker.",
        })),
    )
        .into_response();
    res.headers_mut().insert(
        crate::errors::KLAV_ERROR,
        HeaderValue::from_static("klav_handoff_refused"),
    );
    res
}

/// `GET /v1/status`: always `200`, with the service key's public half once
/// the enclave holds a seed and `null` before. Nothing else: no account,
/// no count, no private key.
async fn status(State(e): State<Arc<Enclave>>) -> Response {
    Json(StatusAnswer {
        service_key: e.service_key().map(str::to_owned),
    })
    .into_response()
}

async fn get_manifest(State(e): State<Arc<Enclave>>) -> Response {
    match e.manifest() {
        Some(m) => Json(manifest_wire(&m.signed)).into_response(),
        None => starting(),
    }
}

async fn post_manifest(State(e): State<Arc<Enclave>>, Json(wire): Json<ManifestWire>) -> Response {
    let Ok(signed) = parse_manifest_wire(&wire) else {
        return bad_request("The manifest's signature is not 128 hex characters.");
    };
    match e.load_manifest(signed) {
        Ok(seq) => Json(serde_json::json!({ "seq": seq })).into_response(),
        Err(code) => {
            let mut res = (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "klav_manifest_refused",
                    "reason": code,
                    "message": "This enclave does not serve that manifest.",
                })),
            )
                .into_response();
            res.headers_mut().insert(
                crate::errors::KLAV_ERROR,
                HeaderValue::from_static("klav_manifest_refused"),
            );
            res
        }
    }
}

async fn attest(State(e): State<Arc<Enclave>>, Query(q): Query<AttestQuery>) -> Response {
    let (Some(seed), Some(manifest)) = (e.seed(), e.manifest()) else {
        return starting();
    };
    let Some(nonce) = data_encoding::BASE64URL_NOPAD
        .decode(q.nonce.as_bytes())
        .ok()
        .filter(|n| (1..=MAX_NONCE).contains(&n.len()))
    else {
        return bad_request("The nonce is not 1 to 64 bytes of base64url.");
    };
    if let Err(retry) = e.rates.check(
        &format!("attest:{}", q.account),
        ATTESTS_PER_MINUTE,
        Instant::now(),
    ) {
        return refuse(
            StatusCode::TOO_MANY_REQUESTS,
            "klav_rate_limited",
            "Too many attestations for this account this minute.",
            "Wait retry_after seconds, then retry.",
            Some(retry),
        );
    }
    let Some(account) = e.account(q.account) else {
        return refuse(
            StatusCode::NOT_FOUND,
            "klav_hosted_not_enrolled",
            "Klav Cloud's proxy has no agent for this account.",
            "Set Klav Cloud's proxy up on one of your devices.",
            None,
        );
    };
    let en = &account.enrollment;
    let keys = derive_account_keys(&seed, en.account_id, en.generation);
    let binding = enclave_binding(en.account_id, en.agent_id, keys.public(), en.generation);
    drop(keys);
    let nsm = Arc::clone(&e.nsm);
    let document = tokio::task::spawn_blocking(move || {
        nsm.attest(&AttestRequest {
            user_data: Some(&binding),
            nonce: Some(&nonce),
            public_key: None,
        })
    })
    .await;
    match document {
        Ok(Ok(document)) => Json(AttestAnswer {
            document: Blob::new(document),
            agent_id: en.agent_id,
            generation: en.generation,
            manifest_seq: manifest.verified.seq(),
        })
        .into_response(),
        _ => refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "klav_hosted_attestation",
            "The enclave could not attest right now.",
            "Retry in a minute.",
            Some(30),
        ),
    }
}

async fn enroll(State(e): State<Arc<Enclave>>, Json(req): Json<EnrollRequest>) -> Response {
    let Some(seed) = e.seed() else {
        return starting();
    };
    if let Err(retry) = e.rates.check(
        &format!("enroll:{}", req.account_id),
        ENROLLS_PER_MINUTE,
        Instant::now(),
    ) {
        return refuse(
            StatusCode::TOO_MANY_REQUESTS,
            "klav_rate_limited",
            "Too many enroll requests for this account this minute.",
            "Wait retry_after seconds, then retry.",
            Some(retry),
        );
    }
    if now_ms().abs_diff(req.at_ms) > ENROLL_SKEW_MS {
        return bad_request("The enroll request was not signed within 5 minutes of now.");
    }
    let email = req.email.trim();
    if !(3..=254).contains(&email.len()) || !email.contains('@') {
        return bad_request("The e-mail is not an address.");
    }
    let Ok(identity) = PublicIdentity::decode(req.account_public_identity.as_bytes()) else {
        return bad_request("The account identity is not a public identity.");
    };
    let Ok(signature) = <[u8; 64]>::try_from(req.signature.as_bytes()) else {
        return bad_request("The signature is not 64 bytes.");
    };
    if verify_enroll(
        &identity,
        req.account_id,
        req.generation,
        req.at_ms,
        &Signature::from_bytes(signature),
    )
    .is_err()
    {
        return refuse(
            StatusCode::FORBIDDEN,
            "klav_not_allowed",
            "The enroll request is not signed by that account identity.",
            "Sign it with the account's identity.",
            None,
        );
    }
    if let Some(existing) = e.account(req.account_id) {
        let en = &existing.enrollment;
        if en.account_public_identity == req.account_public_identity {
            if req.generation == en.generation {
                return Json(EnrollAnswer {
                    agent_id: en.agent_id,
                    generation: en.generation,
                    channel: existing.name.clone(),
                    expires_at: 0,
                })
                .into_response();
            }
            if req.generation < en.generation {
                return refuse(
                    StatusCode::CONFLICT,
                    "klav_hosted_generation",
                    "Klav Cloud's proxy already serves a newer generation for this account.",
                    "Ask for the current generation or a newer one.",
                    None,
                );
            }
        } else if existing.served.load(Ordering::SeqCst) {
            // Someone else's key for an account whose agent the person
            // already approved: never replaced (§6.1).
            return refuse(
                StatusCode::CONFLICT,
                "klav_hosted_enrolled",
                "This account is already enrolled in Klav Cloud's proxy.",
                "Reset Klav Cloud's proxy from a device of the account.",
                None,
            );
        }
    }
    let enrollment = Enrollment {
        account_id: req.account_id,
        agent_id: AgentId::generate(),
        generation: req.generation,
        email: email.to_owned(),
        account_public_identity: req.account_public_identity.clone(),
        enrolled_at_ms: now_ms(),
    };
    let keys = derive_account_keys(&seed, enrollment.account_id, enrollment.generation);
    let mark = sign_hosted_registration(
        &hosted_service_keys(&seed),
        enrollment.account_id,
        enrollment.agent_id,
        keys.public(),
        enrollment.generation,
    );
    let agent = match Agent::in_memory(e.memory_agent(&enrollment), keys) {
        Ok(agent) => agent,
        Err(_) => return bad_request("The enrollment cannot make an agent."),
    };
    // The mark goes in the registration's body (`RegisterHostedAgent.hosted`,
    // spec §15.8): the server checks it with the service key's public half
    // and the account's entitlement, and answers one `403` for any refusal.
    let hosted = HostedRegistrationProof {
        account_id: enrollment.account_id,
        generation: enrollment.generation,
        signature: Blob::new(mark.to_bytes().to_vec()),
    };
    let registered = match agent
        .register_self(
            Some("Klav Cloud's hosted credential proxy, in an attested AWS Nitro Enclave".into()),
            Some(hosted),
        )
        .await
    {
        Ok(registered) => registered,
        Err(ClientError::Api { status: 403, .. }) => {
            // Not entitled, or the server holds another service key: the
            // server doesn't say which, and retrying won't change it.
            tracing::warn!("the server refused a hosted agent's registration with 403");
            return refuse(
                StatusCode::FORBIDDEN,
                "klav_hosted_not_entitled",
                "Klav's server did not accept this account for Klav Cloud's proxy.",
                "Klav Cloud's proxy is for invited accounts; check that yours has it.",
                None,
            );
        }
        Err(err) => {
            tracing::warn!(
                kind = crate::proxy::redacted_kind(&err),
                "the server refused a hosted agent's registration"
            );
            return refuse(
                StatusCode::BAD_GATEWAY,
                "klav_server_unreachable",
                "Klav's server did not register the hosted agent.",
                "Retry in a minute.",
                Some(60),
            );
        }
    };
    let agent_id = enrollment.agent_id;
    let generation = enrollment.generation;
    let channel = match e.add_account(&seed, enrollment, None) {
        Ok(name) => name,
        Err(_) => return bad_request("The enrollment cannot be served."),
    };
    Json(EnrollAnswer {
        agent_id,
        generation,
        channel,
        expires_at: registered.expires_at,
    })
    .into_response()
}

async fn handoff_hello(State(e): State<Arc<Enclave>>, Json(req): Json<HelloRequest>) -> Response {
    let (Some(_), Some(manifest)) = (e.seed(), e.manifest()) else {
        return starting();
    };
    let joiner_nonce = req.nonce.as_bytes().to_vec();
    if !(1..=MAX_NONCE).contains(&joiner_nonce.len()) {
        return bad_request("The nonce is not 1 to 64 bytes.");
    }
    let session = klav_core::crypto::random::array::<16>();
    let holder_nonce = klav_core::crypto::random::array::<32>();
    {
        let mut pending = e
            .handoffs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        pending.retain(|_, p| p.expires > now);
        if pending.len() >= MAX_PENDING_HANDOFFS {
            return refuse(
                StatusCode::TOO_MANY_REQUESTS,
                "klav_rate_limited",
                "Too many hand-offs at once.",
                "Retry in a minute.",
                Some(60),
            );
        }
        pending.insert(
            session,
            PendingHandoff {
                holder_nonce,
                joiner_nonce: joiner_nonce.clone(),
                expires: now + HANDOFF_SESSION_TTL,
            },
        );
    }
    let nsm = Arc::clone(&e.nsm);
    let document = tokio::task::spawn_blocking(move || {
        nsm.attest(&AttestRequest {
            nonce: Some(&joiner_nonce),
            ..AttestRequest::default()
        })
    })
    .await;
    let Ok(Ok(document)) = document else {
        return starting();
    };
    Json(HelloAnswer {
        session: Blob::new(session.to_vec()),
        nonce: Blob::new(holder_nonce.to_vec()),
        document: Blob::new(document),
        manifest: manifest_wire(&manifest.signed),
    })
    .into_response()
}

async fn handoff_seal(State(e): State<Arc<Enclave>>, Json(req): Json<SealRequest>) -> Response {
    let Ok(session) = <[u8; 16]>::try_from(req.session.as_bytes()) else {
        return bad_request("The session is not 16 bytes.");
    };
    let pending = e
        .handoffs
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&session);
    let Some(pending) = pending.filter(|p| p.expires > Instant::now()) else {
        return handoff_refused("session");
    };
    let (Some(seed), Some(current)) = (e.seed(), e.manifest()) else {
        return starting();
    };
    let Ok(signed) = parse_manifest_wire(&req.manifest) else {
        return handoff_refused("manifest_malformed");
    };
    let now = now_ms();
    // The joiner's manifest: signed, not older than the one served here.
    let verified = match e
        .anchors
        .manifest(&signed, Some(current.verified.seq()), now)
    {
        Ok(verified) => verified,
        Err(err) => return handoff_refused(err.code()),
    };
    // Published in the repository, byte for byte (§4.2 step 2).
    if is_published(e.published.as_ref(), verified.seq(), &signed)
        .await
        .is_err()
    {
        return handoff_refused("unpublished");
    }
    let own = match verified.image_for(&e.own) {
        Ok(own) => own.clone(),
        Err(err) => return handoff_refused(err.code()),
    };
    let peer = match e.anchors.peer(
        req.document.as_bytes(),
        &verified,
        &own,
        &pending.holder_nonce,
        now,
    ) {
        Ok(peer) => peer,
        Err(err) => {
            tracing::info!(refused = err.code(), "hand-off refused");
            return handoff_refused(err.code());
        }
    };
    let info = handoff_info(
        &e.own.pcr0,
        &peer.measurement.pcr0,
        &pending.joiner_nonce,
        &pending.holder_nonce,
    );
    let state = e.shared_state().await.encode();
    let sealed = match seal_handoff(&seed, &state, &peer.x25519, &info) {
        Ok(sealed) => sealed,
        Err(_) => return handoff_refused("seal"),
    };
    tracing::info!(
        holder = %own.version_text(),
        joiner = %peer.image.version_text(),
        "hand-off sealed"
    );
    Json(SealAnswer {
        sealed: Blob::new(sealed),
    })
    .into_response()
}
