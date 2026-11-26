//! The channel listener (ADR 0036 §6; layer 6): where sandboxes' forwarders
//! reach the proxy, over TLS 1.3 with raw Ed25519 keys on both ends
//! ([`klav_forward::channel`]).
//!
//! - **Who is on the other end** is the SHA-256 of the key the forwarder
//!   proved in the handshake, nothing it says: every route looks that key
//!   up ([`crate::claims::bound`]), except the claim that binds it.
//! - **Anyone who reaches the port can finish a handshake** with a
//!   throwaway key, so nothing a peer does before it is bound to a sandbox
//!   may hold the proxy for long ([`ChannelLimits`]):
//!   - handshakes run apart from the accept loop, each with a deadline,
//!     and only so many at once;
//!   - a request's head must arrive in time, and an idle connection closes
//!     after the same time; an answer the proxy is still working on (an
//!     approval it waits for) is never cut by it;
//!   - connections whose key is bound to no sandbox have their own cap,
//!     below the total, and a deadline to become bound; when the cap is
//!     full, the oldest of them is closed for the newcomer, so holding
//!     the slots takes a steady stream of connections;
//!   - each key has its own cap, so one sandbox cannot take every slot,
//!     and a bound connection checks again every few seconds that its
//!     sandbox is still live: a stopped, revoked or expired sandbox loses
//!     its connections;
//!   - a claim's body is at most 1 KiB and must arrive in time;
//!   - on shutdown, connections get a short grace and are then cut.
//! - **Routes:**
//!   - `POST /_klav/claim` `{sandbox_id, secret}` binds the sandbox to the
//!     key ([`crate::claims::claim`]);
//!   - `GET /_klav/status` says which sandbox the key is bound to;
//!   - `POST /_klav/release` ends it with `released`;
//!   - any other path is a call to one of the sandbox's profiles, as mode
//!     (a) on the loopback listener: `/<profile>/<path>`.
//!
//! Every refusal is the `Klav-Error` answer of ADR 0036 §10.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use klav_core::crypto::channel::TlsSigner;
use klav_core::ids::SandboxId;
use klav_proto::Blob;
use serde::Deserialize;
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use zeroize::Zeroizing;

use crate::claims::{self, ChannelError};
use crate::errors::KLAV_ERROR;
use crate::proxy::ProxyState;

/// Where a claim goes.
pub const CLAIM: &str = "/_klav/claim";
/// What the key is bound to.
pub const STATUS: &str = "/_klav/status";
/// Ends the key's sandbox with `released`.
pub const RELEASE: &str = "/_klav/release";
/// Open channel connections at once; more are closed after the handshake.
pub const MAX_CHANNEL_CONNECTIONS: usize = 256;
/// How long a handshake may take: a forwarder's takes one round trip.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
/// Largest claim body: an ID and a 32-byte secret.
pub const MAX_CLAIM_BODY: usize = 1024;
/// How long a claim's body may take to arrive.
const CLAIM_BODY_TIMEOUT: Duration = Duration::from_secs(10);

/// What a peer may hold on the channel, and for how long.
#[derive(Debug, Clone, Copy)]
pub struct ChannelLimits {
    /// How long a handshake may take.
    pub handshake: Duration,
    /// Handshakes at once; the accept loop waits for a free one.
    pub max_handshakes: usize,
    /// Open connections at once.
    pub max_connections: usize,
    /// Open connections whose key is bound to no sandbox (claims, scans):
    /// below `max_connections`. When full, the oldest is closed.
    pub max_unbound: usize,
    /// Open connections of one key; more are closed.
    pub max_per_key: usize,
    /// How often a bound connection checks that its sandbox is still live.
    pub bound_recheck: Duration,
    /// How long a request's head may take, and how long an idle
    /// connection stays open (the forwarder's pool keeps idle connections
    /// for less).
    pub header_read: Duration,
    /// How long a connection may stay open with its key bound to no
    /// sandbox.
    pub unbound_deadline: Duration,
    /// How long connections are served after the stop, or after a
    /// connection is told to close, before they are cut.
    pub shutdown_grace: Duration,
}

impl Default for ChannelLimits {
    fn default() -> Self {
        Self {
            handshake: HANDSHAKE_TIMEOUT,
            max_handshakes: 64,
            max_connections: MAX_CHANNEL_CONNECTIONS,
            max_unbound: 32,
            max_per_key: 16,
            bound_recheck: Duration::from_secs(5),
            header_read: Duration::from_secs(20),
            unbound_deadline: Duration::from_secs(30),
            shutdown_grace: Duration::from_secs(5),
        }
    }
}

/// Who is on a connection: its address and the SHA-256 of the channel key
/// it proved.
#[derive(Clone, Copy, Debug)]
pub struct Peer {
    /// The address it connected from (for nothing but logs).
    pub addr: SocketAddr,
    /// SHA-256 of its key's SPKI.
    pub key: [u8; 32],
}

/// What a channel connection runs over once its handshake is done: TLS
/// over TCP here, TLS over vsock or a test transport in Klav Cloud's
/// enclave (ADR 0051 §1).
pub trait ChannelIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static {}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> ChannelIo for T {}

/// A connection that finished its handshake, and its slot.
pub struct Accepted {
    io: Box<dyn ChannelIo>,
    _slot: OwnedSemaphorePermit,
}

impl Accepted {
    /// A connection the hosted enclave accepted and routed to this
    /// account's listener (ADR 0051 §3.4), holding one of `slots`; `None`
    /// when they are all taken.
    pub fn routed(io: Box<dyn ChannelIo>, slots: &Arc<Semaphore>) -> Option<Self> {
        let slot = Arc::clone(slots).try_acquire_owned().ok()?;
        Some(Self { io, _slot: slot })
    }
}

/// The TLS listener: hands [`serve`] only connections whose handshake is
/// done.
pub struct ChannelListener {
    ready: mpsc::Receiver<(Accepted, Peer)>,
    local: SocketAddr,
    limits: ChannelLimits,
}

/// Binds `addr` and starts accepting with the proxy's identity.
pub async fn bind(addr: SocketAddr, signer: TlsSigner) -> Result<ChannelListener, String> {
    bind_with(addr, signer, ChannelLimits::default()).await
}

/// [`bind`] with other limits (tests).
pub async fn bind_with(
    addr: SocketAddr,
    signer: TlsSigner,
    limits: ChannelLimits,
) -> Result<ChannelListener, String> {
    let config =
        klav_forward::channel::server_config(signer).map_err(|e| format!("channel TLS: {e}"))?;
    let tcp = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("cannot listen on {addr}: {e}"))?;
    let local = tcp
        .local_addr()
        .map_err(|e| format!("cannot read the bound address: {e}"))?;
    let (tx, ready) = mpsc::channel(16);
    let acceptor = TlsAcceptor::from(config);
    let handshakes = Arc::new(Semaphore::new(limits.max_handshakes));
    let open = Arc::new(Semaphore::new(limits.max_connections));
    tokio::spawn(async move {
        loop {
            // Ends with the listener (`serve` returned or never ran).
            let next = tokio::select! {
                () = tx.closed() => return,
                // The semaphore is never closed.
                slot = Arc::clone(&handshakes).acquire_owned() => match slot {
                    Ok(slot) => tokio::select! {
                        () = tx.closed() => return,
                        accepted = tcp.accept() => (slot, accepted),
                    },
                    Err(_) => return,
                },
            };
            let (handshake_slot, (stream, addr)) = match next {
                (slot, Ok(pair)) => (slot, pair),
                (_, Err(e)) => {
                    tracing::warn!(error = %e, "channel accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            let open = Arc::clone(&open);
            tokio::spawn(async move {
                let shaken = tokio::time::timeout(limits.handshake, acceptor.accept(stream)).await;
                drop(handshake_slot);
                let io = match shaken {
                    Ok(Ok(io)) => io,
                    // A refused key, TLS 1.2, a client without a key or a
                    // port scan: the address only, at debug level.
                    Ok(Err(e)) => {
                        tracing::debug!(%addr, error = %e, "channel handshake refused");
                        return;
                    }
                    Err(_) => {
                        tracing::debug!(%addr, "channel handshake timed out");
                        return;
                    }
                };
                let Some(key) = klav_forward::channel::peer_key(io.get_ref().1) else {
                    return;
                };
                let Ok(slot) = open.try_acquire_owned() else {
                    tracing::debug!(%addr, "channel full: connection closed");
                    return;
                };
                let io: TlsStream<TcpStream> = io;
                let _ = tx
                    .send((
                        Accepted {
                            io: Box::new(io),
                            _slot: slot,
                        },
                        Peer { addr, key },
                    ))
                    .await;
            });
        }
    });
    Ok(ChannelListener {
        ready,
        local,
        limits,
    })
}

impl ChannelListener {
    /// A listener fed by someone else's acceptor: Klav Cloud's enclave
    /// finishes each handshake itself, picks the account by SNI and sends
    /// the connection to that account's listener (ADR 0051 §3.4).
    pub fn from_receiver(
        ready: mpsc::Receiver<(Accepted, Peer)>,
        local: SocketAddr,
        limits: ChannelLimits,
    ) -> Self {
        Self {
            ready,
            local,
            limits,
        }
    }

    /// The address it listens on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

impl tokio::io::AsyncRead for Accepted {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Accepted {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// The routes of the channel.
pub fn router(state: Arc<ProxyState>) -> Router {
    Router::new()
        .route(CLAIM, post(claim))
        .route(STATUS, get(status))
        .route(RELEASE, post(release))
        .fallback(call)
        .with_state(state)
}

/// Serves the channel until `stop` completes; then each connection gets
/// [`ChannelLimits::shutdown_grace`] to finish and is cut.
pub async fn serve(
    listener: ChannelListener,
    state: Arc<ProxyState>,
    stop: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    let routes = router(Arc::clone(&state));
    serve_routes(listener, state, routes, stop).await
}

/// [`serve`] with these routes (tests add slow ones; Klav Cloud's enclave
/// adds its per-account quotas, ADR 0051 §3.3).
pub(crate) async fn serve_routes(
    mut listener: ChannelListener,
    state: Arc<ProxyState>,
    routes: Router,
    stop: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    let limits = listener.limits;
    let admission = state.channel_admission();
    let (stopping, stopped) = watch::channel(false);
    let mut connections = tokio::task::JoinSet::new();
    tokio::pin!(stop);
    loop {
        let next = tokio::select! {
            () = &mut stop => break,
            next = listener.ready.recv() => next,
        };
        let Some((accepted, peer)) = next else {
            break;
        };
        while connections.try_join_next().is_some() {}
        let bound = claims::is_bound(&state, &peer.key).await;
        let Some(ticket) = Admission::admit(&admission, &peer, bound, &limits) else {
            continue;
        };
        connections.spawn(connection(
            accepted,
            peer,
            routes.clone(),
            Arc::clone(&state),
            limits,
            ticket,
            stopped.clone(),
        ));
    }
    drop(listener);
    let _ = stopping.send(true);
    let drained = tokio::time::timeout(limits.shutdown_grace, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    Ok(())
}

/// Who holds the channel's connections: each key's count, and the
/// connections bound to no sandbox, oldest first.
#[derive(Default)]
pub(crate) struct Admission {
    inner: std::sync::Mutex<AdmissionState>,
}

#[derive(Default)]
struct AdmissionState {
    next: u64,
    unbound: std::collections::VecDeque<(u64, [u8; 32], Arc<Notify>)>,
    per_key: std::collections::HashMap<[u8; 32], usize>,
}

/// A connection's place: given back when the connection ends.
struct Ticket {
    id: u64,
    key: [u8; 32],
    admission: Arc<Admission>,
    /// Closes the connection (an unbound one evicted), within the grace.
    close: Arc<Notify>,
}

impl Admission {
    fn lock(&self) -> std::sync::MutexGuard<'_, AdmissionState> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A place for `peer`, or none when its key already holds
    /// `max_per_key` connections. An unbound newcomer that finds the
    /// unbound cap full closes the oldest unbound connection.
    fn admit(this: &Arc<Self>, peer: &Peer, bound: bool, limits: &ChannelLimits) -> Option<Ticket> {
        let mut state = this.lock();
        let count = state.per_key.entry(peer.key).or_insert(0);
        if *count >= limits.max_per_key {
            tracing::debug!(addr = %peer.addr, "too many channel connections with one key: closed");
            return None;
        }
        *count += 1;
        state.next += 1;
        let id = state.next;
        let close = Arc::new(Notify::new());
        if !bound {
            while state.unbound.len() >= limits.max_unbound.max(1) {
                if let Some((_, _, oldest)) = state.unbound.pop_front() {
                    tracing::debug!(
                        "too many channel connections bound to no sandbox: the oldest closed"
                    );
                    oldest.notify_one();
                }
            }
            state.unbound.push_back((id, peer.key, Arc::clone(&close)));
        }
        Some(Ticket {
            id,
            key: peer.key,
            admission: Arc::clone(this),
            close,
        })
    }
}

impl Admission {
    /// The keys that hold at least one connection now.
    pub(crate) fn connected_keys(&self) -> std::collections::HashSet<[u8; 32]> {
        self.lock().per_key.keys().copied().collect()
    }

    /// `key` was just bound to a sandbox: every connection with it leaves
    /// the unbound list at once, so none of them can be evicted for a
    /// newcomer, also the one that made the claim (review of #304, N1).
    fn bind_key(&self, key: &[u8; 32]) {
        self.lock().unbound.retain(|(_, k, _)| k != key);
    }
}

impl Ticket {
    /// Its key is bound now: it leaves the unbound list.
    fn bind(&self) {
        self.admission
            .lock()
            .unbound
            .retain(|(id, _, _)| *id != self.id);
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let mut state = self.admission.lock();
        state.unbound.retain(|(id, _, _)| *id != self.id);
        if let Some(count) = state.per_key.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                state.per_key.remove(&self.key);
            }
        }
    }
}

/// Serves one connection: HTTP/1.1 with a deadline on each request's head
/// and on idleness. While its key is bound to no sandbox it has a deadline
/// to become bound; once bound, it checks every
/// [`ChannelLimits::bound_recheck`] that the sandbox is still live, and
/// closes when it is not.
async fn connection(
    accepted: Accepted,
    peer: Peer,
    routes: Router,
    state: Arc<ProxyState>,
    limits: ChannelLimits,
    ticket: Ticket,
    mut stopped: watch::Receiver<bool>,
) {
    let service = TowerToHyperService::new(
        routes
            .layer(axum::Extension(ConnectInfo(peer)))
            .layer(axum::Extension(Arc::clone(&ticket.admission))),
    );
    let mut http = hyper::server::conn::http1::Builder::new();
    // `half_close`: the forwarder passes on a caller that closes its
    // sending side after its request; the answer still goes back, and the
    // connection then ends instead of waiting for the next head.
    http.timer(TokioTimer::new())
        .header_read_timeout(limits.header_read)
        .keep_alive(true)
        .half_close(true);
    let served = http.serve_connection(TokioIo::new(accepted), service);
    tokio::pin!(served);
    // A key whose sandbox already ended connects as an unbound one (it
    // learns `401` and goes); one that ends while connected is closed.
    let mut bound = claims::is_bound(&state, &peer.key).await;
    let ended_before =
        !bound && claims::key_state(&state, &peer.key).await == claims::KeyState::Ended;
    if bound {
        ticket.bind();
    }
    // Bound or not, it looks every `bound_recheck`: a key that binds on
    // this connection is then held to the bound rules at once.
    let unbound_until = tokio::time::Instant::now() + limits.unbound_deadline;
    let next_check = |bound: bool| {
        let next = tokio::time::Instant::now() + limits.bound_recheck;
        if bound { next } else { next.min(unbound_until) }
    };
    let check = tokio::time::sleep_until(next_check(bound));
    tokio::pin!(check);
    let close = Arc::clone(&ticket.close);
    // Set once the connection was told to close: then it is cut at this
    // instant whatever it is doing.
    let mut cut: Option<tokio::time::Instant> = None;
    loop {
        let cut_at =
            cut.unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86_400));
        tokio::select! {
            done = served.as_mut() => {
                if let Err(e) = done {
                    tracing::debug!(addr = %peer.addr, error = %e, "channel connection closed");
                }
                return;
            }
            // Evicted for a newer unbound connection: closed like at
            // shutdown, so an answer on its way (a claim's) still goes
            // out within the grace. The claim itself runs apart and
            // finishes anyway.
            () = close.notified(), if cut.is_none() => {
                served.as_mut().graceful_shutdown();
                cut = Some(tokio::time::Instant::now() + limits.shutdown_grace);
            }
            () = &mut check, if cut.is_none() => {
                let now_state = claims::key_state(&state, &peer.key).await;
                let ended_here = now_state == claims::KeyState::Ended && !ended_before;
                if now_state == claims::KeyState::Live {
                    if !bound {
                        bound = true;
                        ticket.bind();
                    }
                    check.as_mut().reset(next_check(true));
                } else if !bound && !ended_here && tokio::time::Instant::now() < unbound_until {
                    check.as_mut().reset(next_check(false));
                } else {
                    tracing::debug!(addr = %peer.addr, was_bound = bound, "channel connection bound to no live sandbox: closed");
                    served.as_mut().graceful_shutdown();
                    cut = Some(tokio::time::Instant::now() + limits.shutdown_grace);
                }
            }
            changed = stopped.changed(), if cut.is_none() => {
                if changed.is_err() || *stopped.borrow() {
                    served.as_mut().graceful_shutdown();
                    cut = Some(tokio::time::Instant::now() + limits.shutdown_grace);
                }
            }
            () = tokio::time::sleep_until(cut_at), if cut.is_some() => return,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimBody {
    sandbox_id: SandboxId,
    secret: String,
}

/// No browser check here, unlike `status` and `release`: a claim needs
/// the one-time secret, which a web page cannot read (no route answers
/// with it), and without it a claim has no effect. A wrong secret, from the key the forwarder bound
/// or any other, is `401 klav_sandbox_revoked` with nothing spent, nothing
/// ended and nothing counted against anyone; a form body is not JSON
/// (`400 klav_bad_request`).
async fn claim(
    State(state): State<Arc<ProxyState>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    axum::Extension(admission): axum::Extension<Arc<Admission>>,
    body: Body,
) -> Response {
    let run = async {
        let body = tokio::time::timeout(
            CLAIM_BODY_TIMEOUT,
            axum::body::to_bytes(body, MAX_CLAIM_BODY),
        )
        .await
        .map_err(|_| ChannelError::BadRequest)?
        .map_err(|_| ChannelError::TooLarge)?;
        let asked: ClaimBody =
            serde_json::from_slice(&body).map_err(|_| ChannelError::BadRequest)?;
        let secret_text = Zeroizing::new(asked.secret);
        let bytes = Zeroizing::new(
            Blob::from_text(&secret_text)
                .ok_or(ChannelError::BadRequest)?
                .into_bytes(),
        );
        drop(secret_text);
        let secret = claims::secret_from(&bytes).ok_or(ChannelError::BadRequest)?;
        drop(bytes);
        // Apart from the connection: a peer that goes away, or a
        // connection cut at its deadline, never leaves a claim half done.
        let sandbox = asked.sandbox_id;
        let state = Arc::clone(&state);
        let bound =
            tokio::spawn(async move { claims::claim(&state, sandbox, &secret, peer.key).await })
                .await
                .map_err(|_| ChannelError::Store)??;
        admission.bind_key(&peer.key);
        Ok(Json(bound).into_response())
    };
    let answer = run.await;
    match &answer {
        // What anyone who reaches the port can cause with a throwaway key
        // (a wrong secret, an unknown or ended sandbox, a malformed body):
        // never above debug, so it cannot flood the log.
        Err(
            e @ (ChannelError::Revoked
            | ChannelError::Expired
            | ChannelError::BadRequest
            | ChannelError::TooLarge),
        ) => {
            tracing::debug!(error = code(*e), "sandbox claim refused");
        }
        // Only a holder of the secret gets here.
        Err(e) => tracing::info!(error = code(*e), "sandbox claim refused"),
        Ok(_) => {}
    }
    answer.unwrap_or_else(refusal)
}

/// The refusal of a web page's request to the channel's own routes: a
/// browser in the sandbox reaches them through the forwarder's plaintext
/// loopback port, so the key alone does not say a program asked. Checked
/// before the sandbox is looked up, so it ends nothing, spends nothing and
/// counts as no activity.
fn from_a_page(headers: &HeaderMap) -> Option<Response> {
    crate::proxy::not_forwarder_own(headers).then(|| {
        fixed(
            StatusCode::FORBIDDEN,
            "klav_not_allowed",
            "Klav's credential proxy takes a sandbox's status and release only from its forwarder or a program addressed to 127.0.0.1 or localhost, and refuses requests that carry a browser's Origin or Sec-Fetch-Site header.",
            STOP,
        )
    })
}

async fn status(
    State(state): State<Arc<ProxyState>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    headers: HeaderMap,
) -> Response {
    if let Some(refused) = from_a_page(&headers) {
        return refused;
    }
    // The sandbox first: its status counts as activity, so a pause never
    // ends it for an hour without a connection.
    match claims::bound(&state, &peer.key).await {
        // `klav-forward status` exits 7 on it, as its help says (papercut
        // 5): the last answer the proxy had from the server, at most
        // `GRANT_REFRESH` old.
        Ok(_) if state.paused() => refusal(ChannelError::AgentsPaused),
        Ok(bound) => Json(bound).into_response(),
        Err(e) => refusal(e),
    }
}

async fn release(
    State(state): State<Arc<ProxyState>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    headers: HeaderMap,
) -> Response {
    // A cross-site form `POST` from any page the agent's browser opens
    // would otherwise end the sandbox.
    if let Some(refused) = from_a_page(&headers) {
        return refused;
    }
    match claims::release(&state, &peer.key).await {
        Ok(logged) => Json(json!({ "logged": logged })).into_response(),
        Err(e) => refusal(e),
    }
}

/// A call to a profile from the sandbox the key is bound to: the same
/// path as a call from this machine ([`crate::proxy::serve_call`]), with
/// the sandbox's profiles, its rate, and `sandbox` in each access.
async fn call(
    State(state): State<Arc<ProxyState>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    req: axum::extract::Request,
) -> Response {
    match claims::bound(&state, &peer.key).await {
        Ok(bound) => {
            crate::proxy::serve_call(
                &state,
                req,
                crate::proxy::Caller::Sandbox {
                    bound,
                    key: peer.key,
                },
            )
            .await
        }
        Err(e) => refusal(e),
    }
}

/// The `error` code of a refusal (ADR 0036 §10).
pub fn code(e: ChannelError) -> &'static str {
    match e {
        ChannelError::Revoked => "klav_sandbox_revoked",
        ChannelError::Ended(reason) => crate::errors::ended_code(reason),
        ChannelError::Expired => "klav_sandbox_expired",
        ChannelError::AgentsPaused => "klav_agents_paused",
        ChannelError::ServerUnreachable => "klav_server_unreachable",
        ChannelError::Busy => "klav_rate_limited",
        ChannelError::ServerDenied | ChannelError::ServerTooOld => "klav_not_allowed",
        ChannelError::Store => "klav_proxy_store",
        ChannelError::BadRequest | ChannelError::TooLarge => "klav_bad_request",
    }
}

const STOP: &str = "Tell the person this exact message and stop. Do not retry in a loop and do not look for the token elsewhere.";

/// The status, `message` and `next` of a refusal.
fn texts(e: ChannelError) -> (StatusCode, &'static str, &'static str) {
    match e {
        ChannelError::Revoked => (
            StatusCode::UNAUTHORIZED,
            "This sandbox's access to Klav's credential proxy has ended: it was stopped, revoked, or its one-time package was already used.",
            "Tell the person this exact message and stop. Only the person or the agent that started the sandbox can start another one. Do not retry and do not look for the token elsewhere.",
        ),
        ChannelError::Ended(reason) => (
            StatusCode::UNAUTHORIZED,
            crate::errors::ended_message(reason),
            "Tell the person this exact message and stop. Only the person or the agent that started the sandbox can start another one. Do not retry and do not look for the token elsewhere.",
        ),
        ChannelError::Expired => (
            StatusCode::UNAUTHORIZED,
            "This sandbox's time with Klav's credential proxy is over.",
            "Tell the person this exact message and stop. Only the person or the agent that started the sandbox can start another one. Do not retry and do not look for the token elsewhere.",
        ),
        ChannelError::AgentsPaused => (
            StatusCode::LOCKED,
            "The person paused Klav's agents: no call goes through until they resume them.",
            STOP,
        ),
        ChannelError::ServerUnreachable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Klav's credential proxy could not reach the Klav server, so it cannot check this sandbox.",
            STOP,
        ),
        ChannelError::Busy => (
            StatusCode::TOO_MANY_REQUESTS,
            "Klav's credential proxy is already handling a claim of this sandbox.",
            "Wait a few seconds and try once more. Do not retry in a loop.",
        ),
        ChannelError::ServerDenied => (
            StatusCode::FORBIDDEN,
            "The Klav server refused the credential proxy: the person may have revoked it.",
            STOP,
        ),
        ChannelError::ServerTooOld => (
            StatusCode::FORBIDDEN,
            "The Klav server is older than this credential proxy and cannot log a sandbox's claim yet.",
            STOP,
        ),
        ChannelError::Store => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Klav's credential proxy could not save this sandbox's state.",
            "Wait a few seconds and try once more. Do not retry in a loop.",
        ),
        ChannelError::TooLarge => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "Klav's credential proxy did not understand this request from the sandbox's forwarder.",
            STOP,
        ),
        ChannelError::BadRequest => (
            StatusCode::BAD_REQUEST,
            "Klav's credential proxy did not understand this request from the sandbox's forwarder.",
            STOP,
        ),
    }
}

/// `(status, code, message)` of a refusal (tests).
#[cfg(test)]
pub(crate) fn refusal_of(e: ChannelError) -> (u16, &'static str, &'static str) {
    let (status, message, _) = texts(e);
    (status.as_u16(), code(e), message)
}

fn refusal(e: ChannelError) -> Response {
    let (status, message, next) = texts(e);
    let mut res = fixed(status, code(e), message, next);
    if e == ChannelError::Busy {
        res.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            HeaderValue::from_static("1"),
        );
    }
    res
}

fn fixed(status: StatusCode, code: &'static str, message: &str, next: &str) -> Response {
    let mut res = (
        status,
        Json(json!({ "error": code, "message": message, "next": next })),
    )
        .into_response();
    res.headers_mut()
        .insert(KLAV_ERROR, HeaderValue::from_static(code));
    res
}
