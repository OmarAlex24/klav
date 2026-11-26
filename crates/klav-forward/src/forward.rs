//! The forwarder's two jobs (ADR 0036 §5, §7 mode (a), §10): claim the
//! sandbox once over the pinned channel, then relay every local connection
//! to the proxy over a channel connection of its own.
//!
//! A tool's call goes through as bytes: the proxy parses it, applies the
//! profile, and answers every refusal with its own `Klav-Error` JSON. The
//! forwarder answers by itself only when it cannot reach the proxy
//! (`klav_proxy_unreachable`).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use klav_core::crypto::channel::TlsSigner;
use klav_core::crypto::sandbox::{PIN_LEN, SandboxPackage, URL_SCHEME};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

use crate::http::{self, Answer};

/// How long a connection to the proxy may take (TCP and the handshake).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the proxy may take to answer a claim: its own trip to Klav's
/// server takes up to 60 s.
pub const CLAIM_TIMEOUT: Duration = Duration::from_secs(90);
/// How long the proxy may take to answer a status.
pub const STATUS_TIMEOUT: Duration = Duration::from_secs(20);
/// How long a release may take in all, the connection included, tried
/// once (`klav-forward down`). Short on purpose: `down` may be the line
/// before `up` in a setup script, and must not hold it while the proxy is
/// away. The proxy ends the sandbox before it sends the end to Klav's
/// server, so a release cut off after its request left was most likely
/// done anyway, and `down` says it cannot tell.
pub const RELEASE_TIMEOUT: Duration = Duration::from_secs(10);
/// Channel connections at once for calls, below the proxy's 16 per key,
/// so [`STATUS_LANE`] and the status of `keep_alive` always find room.
pub const MAX_RELAYED: usize = 12;
/// Channel connections at once for `GET /_klav/status` (`klav-forward
/// status`), apart from the calls: a status never waits for a call.
pub const STATUS_LANE: usize = 2;
/// Local connections that may wait at once, for their first byte or for
/// a turn; one more gets `klav_forward_busy` at once.
pub const MAX_WAITING: usize = 64;
/// How long a local connection may stay silent before its first byte. It
/// holds no turn meanwhile; the proxy gives a request's head as long.
pub const FIRST_BYTE: Duration = Duration::from_secs(20);
/// How long a request waits for one of the [`MAX_RELAYED`] turns before it
/// gets `klav_forward_busy`.
pub const TURN_WAIT: Duration = Duration::from_secs(10);
/// How long a relayed connection may pass no byte in either direction.
/// Longer than the proxy can stay silent in a call: up to 60 s for Klav's
/// server and 120 s for the provider (`klav-proxy serve --timeout`).
pub const RELAY_IDLE: Duration = Duration::from_secs(240);
/// How often a running forwarder tells the proxy it is still there: the
/// proxy ends a sandbox after 1 hour with no call (ADR 0036 §5).
pub const KEEP_ALIVE: Duration = Duration::from_secs(5 * 60);

/// The sandbox the channel key is bound to, as the proxy says it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bound {
    /// Its ID.
    pub sandbox_id: String,
    /// Its issuer's label.
    pub label: String,
    /// The profiles its calls may use.
    pub profiles: Vec<String>,
    /// When it ends (Unix ms).
    pub expires_at: i64,
}

/// A refusal, as the proxy (or the forwarder) words it (ADR 0036 §10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    /// HTTP status.
    #[serde(skip)]
    pub status: u16,
    /// `klav_*` code.
    pub error: String,
    /// What happened, for the person.
    pub message: String,
    /// What the agent should do.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

/// The message and next step of `klav_proxy_unreachable` (ADR 0036 §10).
pub const UNREACHABLE_MESSAGE: &str = "Klav's credential proxy did not answer (its host may be down, or the Mac that runs it is asleep).";
/// See [`UNREACHABLE_MESSAGE`].
pub const UNREACHABLE_NEXT: &str = "Tell the person this exact message and stop. Do not retry in a loop and do not look for the token elsewhere.";

/// The message and next step of `klav_forward_busy`.
pub const BUSY_MESSAGE: &str = "Klav's forwarder in this sandbox already has as many calls open as it relays at once, and this one waited too long for a turn.";
/// See [`BUSY_MESSAGE`].
pub const BUSY_NEXT: &str = "Wait a few seconds and try again, with fewer calls at once. Close connections a tool keeps open and idle. Do not start another klav-forward.";

impl Refusal {
    /// Every turn is taken (the forwarder's own answer).
    pub fn busy() -> Self {
        Self {
            status: 503,
            error: "klav_forward_busy".into(),
            message: BUSY_MESSAGE.into(),
            next: Some(BUSY_NEXT.into()),
        }
    }

    /// The proxy could not be reached.
    pub fn unreachable() -> Self {
        Self {
            status: 503,
            error: "klav_proxy_unreachable".into(),
            message: UNREACHABLE_MESSAGE.into(),
            next: Some(UNREACHABLE_NEXT.into()),
        }
    }

    /// Worth trying again with the same secret: the proxy or its server
    /// did not answer, or another attempt of this key is on its way.
    pub fn retryable(&self) -> bool {
        matches!(
            self.error.as_str(),
            "klav_proxy_unreachable" | "klav_server_unreachable" | "klav_rate_limited"
        )
    }

    /// A refusal from the proxy's answer.
    pub fn of(answer: &Answer) -> Self {
        let mut refusal: Refusal =
            serde_json::from_slice(&answer.body).unwrap_or_else(|_| Refusal {
                status: 0,
                error: answer
                    .header("klav-error")
                    .unwrap_or("klav_proxy_unreachable")
                    .to_owned(),
                message: format!(
                    "The proxy answered {} without an explanation.",
                    answer.status
                ),
                next: None,
            });
        refusal.status = answer.status;
        refusal
    }
}

/// The server name a forwarder before ADR 0051's layer 3 sent whatever the
/// URL: the pin, not the name, authenticated the proxy. Still what goes
/// out when the URL's host is not a valid DNS name.
pub const LEGACY_SERVER_NAME: &str = "klav-proxy";

/// The TLS server name for a proxy at `address` (`HOST:PORT`): the URL's
/// host, so Klav Cloud's hosted proxy can pick the account's key by SNI
/// (`a<agent_id>.proxy.klav.dev`, ADR 0051 §3.4). An IP literal (`[::1]:443`
/// or `127.0.0.1:443`) becomes an IP name, for which rustls sends no SNI; a
/// host that is not a valid name falls back to [`LEGACY_SERVER_NAME`]. A
/// self-hosted proxy ignores SNI, so nothing changes for it.
pub fn server_name_for(address: &str) -> ServerName<'static> {
    let host = if let Some(rest) = address.strip_prefix('[') {
        rest.split_once(']').map(|(host, _)| host)
    } else {
        address.rsplit_once(':').map(|(host, _)| host)
    };
    host.filter(|h| !h.is_empty())
        .and_then(|h| ServerName::try_from(h.to_ascii_lowercase()).ok())
        .unwrap_or_else(|| ServerName::try_from(LEGACY_SERVER_NAME).expect("a valid name"))
}

/// The proxy, as the package names it, and the channel key.
pub struct Proxy {
    config: Arc<rustls::ClientConfig>,
    address: String,
    name: ServerName<'static>,
}

impl Proxy {
    /// The proxy at `url` (`tls://HOST:PORT`), pinned to `pin`, with the
    /// channel key `signer`.
    pub fn new(url: &str, pin: [u8; PIN_LEN], signer: TlsSigner) -> Result<Self, String> {
        let address = url
            .strip_prefix(URL_SCHEME)
            .ok_or_else(|| "the proxy address is not tls://host:port".to_owned())?;
        let config = crate::channel::client_config(signer, pin)
            .map_err(|e| format!("channel configuration: {e}"))?;
        Ok(Self {
            config: Arc::new(config),
            address: address.to_owned(),
            name: server_name_for(address),
        })
    }

    /// [`Proxy::new`] sending `name` as SNI whatever the URL: what a
    /// forwarder before ADR 0051's layer 3 did with [`LEGACY_SERVER_NAME`]
    /// (tests of the hosted proxy check it fails closed).
    pub fn with_server_name(mut self, name: ServerName<'static>) -> Self {
        self.name = name;
        self
    }

    /// A new channel connection.
    pub async fn connect(&self) -> std::io::Result<TlsStream<TcpStream>> {
        let connect = async {
            let tcp = TcpStream::connect(&self.address).await?;
            tcp.set_nodelay(true)?;
            // The pin names the proxy; the name is what SNI carries, which
            // the hosted proxy routes on (ADR 0051 §3.4).
            TlsConnector::from(Arc::clone(&self.config))
                .connect(self.name.clone(), tcp)
                .await
        };
        tokio::time::timeout(CONNECT_TIMEOUT, connect)
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect"))?
    }

    /// One request of the forwarder's own, read to the end.
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        wait: Duration,
    ) -> Result<Answer, Refusal> {
        self.request_noting(method, path, body, wait, &AtomicBool::new(false))
            .await
    }

    /// [`Proxy::request`], setting `sent` just before the first byte of the
    /// request is written: until then only the TCP connection and the TLS
    /// handshake ran (no early data), and the proxy has nothing to act on.
    async fn request_noting(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        wait: Duration,
        sent: &AtomicBool,
    ) -> Result<Answer, Refusal> {
        let run = async {
            let mut tls = self.connect().await.map_err(|_| Refusal::unreachable())?;
            let mut req = Zeroizing::new(
                format!(
                    "{method} {path} HTTP/1.1\r\nhost: klav-proxy\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes(),
            );
            req.extend_from_slice(body);
            sent.store(true, Ordering::SeqCst);
            tls.write_all(&req)
                .await
                .map_err(|_| Refusal::unreachable())?;
            tls.flush().await.map_err(|_| Refusal::unreachable())?;
            http::read_answer(&mut tls)
                .await
                .map_err(|_| Refusal::unreachable())
        };
        tokio::time::timeout(wait, run)
            .await
            .map_err(|_| Refusal::unreachable())?
    }

    /// Claims the sandbox with its one-time secret, once.
    pub async fn claim(&self, package: &SandboxPackage) -> Result<Bound, Refusal> {
        self.claim_noting(package, &AtomicBool::new(false)).await
    }

    /// [`Proxy::claim`], setting `sent` once a byte of the claim's request
    /// may have left (see [`Proxy::request_noting`]).
    async fn claim_noting(
        &self,
        package: &SandboxPackage,
        sent: &AtomicBool,
    ) -> Result<Bound, Refusal> {
        // Built in one zeroized buffer: the secret is never in a `String`
        // or a JSON value (base64url needs no escaping).
        let mut body = Zeroizing::new(Vec::with_capacity(160));
        body.extend_from_slice(b"{\"sandbox_id\":\"");
        body.extend_from_slice(package.sandbox_id.to_string().as_bytes());
        body.extend_from_slice(b"\",\"secret\":\"");
        base64url_into(package.secret.expose(), &mut body);
        body.extend_from_slice(b"\"}");
        let answer = self
            .request_noting("POST", "/_klav/claim", &body, CLAIM_TIMEOUT, sent)
            .await?;
        bound_of(&answer)
    }

    /// Claims the sandbox, trying again while the refusal says to (the
    /// proxy or its server down, another attempt on its way) until
    /// `deadline`. The secret stays in memory meanwhile (ADR 0036 §5).
    /// `sent` turns true once any attempt may have written a byte of its
    /// request; while it is false, the package was not used.
    pub async fn claim_until(
        &self,
        package: &SandboxPackage,
        deadline: tokio::time::Instant,
        sent: &AtomicBool,
    ) -> Result<Bound, Refusal> {
        let mut wait = Duration::from_secs(1);
        loop {
            match self.claim_noting(package, sent).await {
                Err(refusal)
                    if refusal.retryable() && tokio::time::Instant::now() + wait < deadline =>
                {
                    tokio::time::sleep(wait).await;
                    wait = (wait * 2).min(Duration::from_secs(10));
                }
                other => return other,
            }
        }
    }

    /// Ends the sandbox the key is bound to, with `released` (`POST
    /// /_klav/release`): what `klav-forward down` does before it stops.
    /// `Ok(logged)` says whether Klav's server already has the end. `sent`
    /// turns true once a byte of the request may have left: while it is
    /// false, the proxy got nothing and the sandbox was not released.
    pub async fn release(&self, sent: &AtomicBool) -> Result<bool, Refusal> {
        let answer = self
            .request_noting("POST", "/_klav/release", b"", RELEASE_TIMEOUT, sent)
            .await?;
        if answer.status != 200 {
            return Err(Refusal::of(&answer));
        }
        let logged = serde_json::from_slice::<serde_json::Value>(&answer.body)
            .ok()
            .and_then(|v| v.get("logged").and_then(serde_json::Value::as_bool))
            .unwrap_or(false);
        Ok(logged)
    }

    /// The sandbox the key is bound to (it counts as activity).
    pub async fn status(&self) -> Result<Bound, Refusal> {
        let answer = self
            .request("GET", "/_klav/status", b"", STATUS_TIMEOUT)
            .await?;
        bound_of(&answer)
    }
}

fn bound_of(answer: &Answer) -> Result<Bound, Refusal> {
    if answer.status == 200 {
        serde_json::from_slice(&answer.body).map_err(|_| Refusal {
            status: answer.status,
            error: "klav_proxy_unreachable".into(),
            message: "The proxy's answer could not be read.".into(),
            next: Some(UNREACHABLE_NEXT.into()),
        })
    } else {
        Err(Refusal::of(answer))
    }
}

/// Appends `bytes` as unpadded base64url, the proxy's text form of the
/// secret (`Blob`), to `out`: no intermediate copy outside `out`.
fn base64url_into(bytes: &[u8], out: &mut Vec<u8>) {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]);
        }
    }
}

/// How the relay holds local connections; [`RelayLimits::default`] is
/// the constants above, and tests use shorter ones.
#[derive(Debug, Clone, Copy)]
pub struct RelayLimits {
    /// [`MAX_RELAYED`].
    pub max_relayed: usize,
    /// [`MAX_WAITING`].
    pub max_waiting: usize,
    /// [`FIRST_BYTE`].
    pub first_byte: Duration,
    /// [`TURN_WAIT`].
    pub turn_wait: Duration,
    /// [`RELAY_IDLE`].
    pub idle: Duration,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_relayed: MAX_RELAYED,
            max_waiting: MAX_WAITING,
            first_byte: FIRST_BYTE,
            turn_wait: TURN_WAIT,
            idle: RELAY_IDLE,
        }
    }
}

/// Relays every connection on `listener` to the proxy, each over a
/// channel connection of its own, with [`RelayLimits::default`].
pub async fn serve(listener: TcpListener, proxy: Arc<Proxy>) {
    serve_with(listener, proxy, RelayLimits::default()).await;
}

/// [`serve`] with `limits`. A connection waits for its first byte without
/// a turn; `GET /_klav/status` then takes one of the [`STATUS_LANE`], any
/// other request one of `max_relayed`. Past `max_waiting`, or after
/// `turn_wait`, it gets `klav_forward_busy`: never a hang.
pub async fn serve_with(listener: TcpListener, proxy: Arc<Proxy>, limits: RelayLimits) {
    let calls = Arc::new(tokio::sync::Semaphore::new(limits.max_relayed));
    let statuses = Arc::new(tokio::sync::Semaphore::new(STATUS_LANE));
    let waiting = Arc::new(tokio::sync::Semaphore::new(limits.max_waiting));
    // Connections past `max_waiting` being answered and closed, each for
    // [`DRAIN`] at most.
    let refusing = Arc::new(tokio::sync::Semaphore::new(limits.max_waiting));
    loop {
        let Ok((local, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let Ok(waits) = Arc::clone(&waiting).try_acquire_owned() else {
            match Arc::clone(&refusing).try_acquire_owned() {
                // Answered and closed as any refusal: what the caller sent
                // is read away first, so the close does not reset the
                // answer away.
                Ok(refusal) => {
                    tokio::spawn(async move {
                        answer_and_close(local, &busy_answer()).await;
                        drop(refusal);
                    });
                }
                // A flood past both: the answer without waiting (it fits in
                // the socket's buffer), and a close that may reset it.
                Err(_) => {
                    let _ = local.try_write(&busy_answer());
                }
            }
            continue;
        };
        let (proxy, calls, statuses) = (
            Arc::clone(&proxy),
            Arc::clone(&calls),
            Arc::clone(&statuses),
        );
        tokio::spawn(async move {
            let Some(status) = first_bytes(&local, limits.first_byte).await else {
                return;
            };
            let lane = if status { statuses } else { calls };
            let turn = tokio::time::timeout(limits.turn_wait, lane.acquire_owned()).await;
            drop(waits);
            let Ok(Ok(turn)) = turn else {
                answer_and_close(local, &busy_answer()).await;
                return;
            };
            relay(local, &proxy, limits.idle, turn).await;
        });
    }
}

/// The forwarder's `klav_forward_busy` answer.
fn busy_answer() -> Vec<u8> {
    let r = Refusal::busy();
    http::error_answer(
        r.status,
        "Service Unavailable",
        &r.error,
        &serde_json::to_value(&r).expect("json"),
    )
}

/// How long a closing local connection reads and drops what its caller
/// still sends.
const DRAIN: Duration = Duration::from_secs(1);

/// Writes the forwarder's own answer and closes: its sending side first,
/// then what the caller still sends is read and dropped for a moment
/// ([`drain`]), so the close does not reset the connection before the
/// caller reads it.
async fn answer_and_close(mut local: TcpStream, answer: &[u8]) {
    let done = async {
        local.write_all(answer).await?;
        local.shutdown().await
    };
    let Ok(Ok(())) = tokio::time::timeout(DRAIN, done).await else {
        return;
    };
    drain(&mut local).await;
}

/// Reads and drops what the caller still sends, until it closes its side
/// or [`DRAIN`] passes. A socket closed with unread input is reset, and a
/// reset can take away the answer the caller has not read yet.
async fn drain<R: tokio::io::AsyncRead + Unpin>(local: &mut R) {
    use tokio::io::AsyncReadExt;
    let read = async {
        let mut sink = [0u8; 16 * 1024];
        while local.read(&mut sink).await.is_ok_and(|n| n > 0) {}
    };
    let _ = tokio::time::timeout(DRAIN, read).await;
}

/// Waits up to `deadline` for a connection's first bytes, without reading
/// them: `Some(true)` for `GET /_klav/status`, `Some(false)` for anything
/// else, `None` if it closed or stayed silent.
async fn first_bytes(local: &TcpStream, deadline: Duration) -> Option<bool> {
    const STATUS: &[u8] = b"GET /_klav/status";
    let peek = async {
        let mut seen = [0u8; STATUS.len()];
        loop {
            let n = local.peek(&mut seen).await.ok()?;
            if n == 0 {
                return None;
            }
            if !STATUS.starts_with(&seen[..n]) {
                return Some(false);
            }
            if n == STATUS.len() {
                return Some(true);
            }
            // Part of the line: `peek` would return the same bytes at once.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(deadline, peek).await.ok().flatten()
}

/// One local connection: its bytes to the proxy and back, or the
/// forwarder's own `klav_proxy_unreachable`. `turn` goes back as soon as
/// the channel connection is closed (or, with no proxy, once the caller's
/// request head is read), before the local one is drained.
async fn relay(
    mut local: TcpStream,
    proxy: &Proxy,
    idle: Duration,
    turn: tokio::sync::OwnedSemaphorePermit,
) {
    let _ = local.set_nodelay(true);
    match proxy.connect().await {
        Ok(remote) => pump(local, remote, idle, Some(turn)).await,
        Err(_) => {
            // Answer the request the caller sent, so the tool shows why.
            // The turn stays taken while the head is awaited: connections
            // that never finish theirs are then no more than the turns.
            let head =
                tokio::time::timeout(Duration::from_secs(5), http::read_head(&mut local)).await;
            drop(turn);
            if let Ok(Some(_)) = head {
                let r = Refusal::unreachable();
                let answer = http::error_answer(
                    r.status,
                    "Service Unavailable",
                    &r.error,
                    &serde_json::to_value(&r).expect("json"),
                );
                answer_and_close(local, &answer).await;
            } else {
                let _ = local.shutdown().await;
            }
        }
    }
}

/// The bytes of one connection, both ways, until the proxy closes its
/// side (the local side is closed right after, whatever the caller does)
/// or no byte passes either way for `idle`. A caller that closes its
/// sending side still gets the rest of the answer: the proxy is told (its
/// channel takes half-closed connections) and closes after answering.
/// At the end, the channel connection closes and `turn` goes back first;
/// then what the caller still sends is read away ([`drain`]) so the
/// local close does not reset the answer.
pub(crate) async fn pump<R>(
    local: TcpStream,
    remote: R,
    idle: Duration,
    turn: Option<tokio::sync::OwnedSemaphorePermit>,
) where
    R: tokio::io::AsyncRead + tokio::io::AsyncWrite,
{
    use tokio::io::AsyncReadExt;
    let (mut local_in, mut local_out) = local.into_split();
    let (mut remote_in, mut remote_out) = tokio::io::split(remote);
    let mut up = vec![0u8; 16 * 1024];
    let mut down = vec![0u8; 16 * 1024];
    let mut caller_sends = true;
    loop {
        tokio::select! {
            read = local_in.read(&mut up), if caller_sends => match read {
                // The caller sends no more: the proxy learns it too, answers
                // what it has, and closes, which gives the turn back.
                Ok(0) | Err(_) => {
                    caller_sends = false;
                    let _ = tokio::time::timeout(idle, remote_out.shutdown()).await;
                }
                Ok(n) => {
                    let sent = async {
                        remote_out.write_all(&up[..n]).await?;
                        remote_out.flush().await
                    };
                    if !matches!(tokio::time::timeout(idle, sent).await, Ok(Ok(()))) {
                        break;
                    }
                }
            },
            read = remote_in.read(&mut down) => match read {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let sent = local_out.write_all(&down[..n]);
                    if !matches!(tokio::time::timeout(idle, sent).await, Ok(Ok(()))) {
                        break;
                    }
                }
            },
            () = tokio::time::sleep(idle) => break,
        }
    }
    // The answer is all written: the end of it, the channel connection
    // and the turn go, then what the caller still sends is read away.
    let _ = tokio::time::timeout(DRAIN, local_out.shutdown()).await;
    drop((remote_in, remote_out, turn));
    if caller_sends {
        drain(&mut local_in).await;
    }
}

/// Tells the proxy every `every` ([`KEEP_ALIVE`] by default) that the
/// forwarder is still there, and returns the proxy's refusal once its own
/// status says the sandbox was revoked before its time was up
/// ([`stops_on`]): the forwarder then stops (papercut 13). Only this
/// status counts, never a relayed call's refusal, which the server may
/// give while the proxy still holds the sandbox. A pause, an expired
/// sandbox, or a proxy out of reach, is logged and waited out.
pub async fn keep_alive(proxy: Arc<Proxy>, every: Duration, expires_at: i64) -> Refusal {
    let mut said_expired = false;
    loop {
        tokio::time::sleep(every).await;
        match proxy.status().await {
            Ok(_) => {}
            Err(r) if stops_on(&r, now_ms(), expires_at) => {
                tracing_line(&format!("the sandbox ended ({}): {}", r.error, r.message));
                return r;
            }
            // Logged once: it keeps asking, so the proxy keeps the
            // sandbox's connection alive, but an expiry does not change.
            Err(r) if r.error == EXPIRED => {
                if !said_expired {
                    tracing_line(&format!("the sandbox expired ({}): {}", r.error, r.message));
                    said_expired = true;
                }
            }
            Err(r) => tracing_line(&format!("status: {}: {}", r.error, r.message)),
        }
    }
}

/// The proxy's code for a sandbox whose time is over.
const EXPIRED: &str = "klav_sandbox_expired";

/// How close to its `expires_at` a revocation may be the proxy's end for
/// the sandbox's time: a proxy that restarted, or an older one, says
/// `klav_sandbox_revoked` for that too, and clocks drift.
pub const EXPIRY_MARGIN_MS: i64 = 10 * 60 * 1000;

/// Whether the proxy's refusal of a status stops the forwarder: the
/// sandbox was revoked, more than [`EXPIRY_MARGIN_MS`] before its time was
/// up. An expired sandbox's forwarder keeps listening, so each tool gets
/// `klav_sandbox_expired` with its `next` (ADR 0036, accepted default "El
/// reenviador al vencer"), and a pause stops nothing: it can end.
///
/// `now_ms` is the sandbox's clock and `expires_at` the proxy's: a sandbox
/// whose clock runs more than the margin behind the proxy's, against a
/// restarted or older proxy that says `klav_sandbox_revoked` for an end by
/// time, still exits then.
pub fn stops_on(r: &Refusal, now_ms: i64, expires_at: i64) -> bool {
    r.error == "klav_sandbox_revoked" && now_ms.saturating_add(EXPIRY_MARGIN_MS) < expires_at
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or_default()
}

/// One line on the forwarder's log (stderr, or its log file as a daemon).
/// Never a secret: only codes and the proxy's own messages.
#[allow(clippy::print_stderr)]
pub fn tracing_line(line: &str) {
    eprintln!("klav-forward: {line}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Papercut 13: only a revocation well before the sandbox's time stops
    /// the forwarder; an expiry, a revocation near it (a restarted or older
    /// proxy says revoked for its time too) and a pause never do.
    #[test]
    fn only_a_revocation_before_its_time_stops_the_forwarder() {
        let refusal = |error: &str| Refusal {
            status: 401,
            error: error.into(),
            message: String::new(),
            next: None,
        };
        let expires_at = 10 * EXPIRY_MARGIN_MS;
        let early = expires_at - EXPIRY_MARGIN_MS - 1;
        assert!(stops_on(
            &refusal("klav_sandbox_revoked"),
            early,
            expires_at
        ));
        assert!(!stops_on(
            &refusal("klav_sandbox_revoked"),
            early + 1,
            expires_at
        ));
        assert!(!stops_on(
            &refusal("klav_sandbox_revoked"),
            expires_at + 1,
            expires_at
        ));
        for other in [
            "klav_sandbox_expired",
            "klav_agents_paused",
            "klav_proxy_unreachable",
        ] {
            assert!(!stops_on(&refusal(other), early, expires_at), "{other}");
        }
    }

    #[test]
    fn the_secret_is_unpadded_base64url() {
        let b64 = |bytes: &[u8]| {
            let mut out = Vec::new();
            base64url_into(bytes, &mut out);
            String::from_utf8(out).expect("ascii")
        };
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg");
        assert_eq!(b64(b"fo"), "Zm8");
        assert_eq!(b64(b"foo"), "Zm9v");
        assert_eq!(b64(b"foob"), "Zm9vYg");
        assert_eq!(b64(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64(&[7u8; 32]).len(), 43);
    }

    #[test]
    fn only_a_missing_proxy_or_server_or_a_busy_claim_is_retried() {
        for (code, retry) in [
            ("klav_proxy_unreachable", true),
            ("klav_server_unreachable", true),
            ("klav_rate_limited", true),
            ("klav_sandbox_revoked", false),
            ("klav_sandbox_expired", false),
            ("klav_agents_paused", false),
            ("klav_not_allowed", false),
        ] {
            let r = Refusal {
                status: 0,
                error: code.into(),
                message: String::new(),
                next: None,
            };
            assert_eq!(r.retryable(), retry, "{code}");
        }
    }

    /// A local connection (the caller's end, the forwarder's end) and a
    /// stand-in for the channel (the forwarder's end, the proxy's end),
    /// with `pump` running between them.
    async fn pumped(
        idle: Duration,
    ) -> (
        TcpStream,
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let caller = TcpStream::connect(listener.local_addr().expect("addr"))
            .await
            .expect("connect");
        let (local, _) = listener.accept().await.expect("accept");
        let (remote, proxy) = tokio::io::duplex(64 * 1024);
        (caller, proxy, tokio::spawn(pump(local, remote, idle, None)))
    }

    /// The pump has ended (its turn came back before the drain), within 2 s.
    async fn ended(pump: tokio::task::JoinHandle<()>) {
        tokio::time::timeout(Duration::from_secs(2), pump)
            .await
            .expect("the pump ends")
            .expect("pump");
    }

    async fn read_all(stream: &mut TcpStream, within: Duration) -> Vec<u8> {
        use tokio::io::AsyncReadExt;
        let mut out = Vec::new();
        tokio::time::timeout(within, stream.read_to_end(&mut out))
            .await
            .expect("closed in time")
            .expect("read");
        out
    }

    /// The proxy closes its side (its idle deadline): the local side is
    /// closed at once, though the caller (a pooling client) stays silent,
    /// so its turn comes back.
    #[tokio::test]
    async fn the_local_side_closes_when_the_proxy_does() {
        let (mut caller, proxy, pump) = pumped(Duration::from_secs(60)).await;
        drop(proxy);
        assert!(
            read_all(&mut caller, Duration::from_secs(2))
                .await
                .is_empty()
        );
        tokio::time::timeout(Duration::from_secs(2), pump)
            .await
            .expect("the turn is back")
            .expect("pump");
    }

    /// No byte either way for `idle`: the connection ends.
    #[tokio::test]
    async fn a_silent_connection_ends_after_its_idle_deadline() {
        let (mut caller, _proxy, pump) = pumped(Duration::from_millis(300)).await;
        let started = tokio::time::Instant::now();
        assert!(
            read_all(&mut caller, Duration::from_secs(3))
                .await
                .is_empty()
        );
        assert!(started.elapsed() >= Duration::from_millis(250));
        ended(pump).await;
    }

    /// A slow answer that keeps flowing outlives the idle deadline in total:
    /// idle means no byte in either direction.
    #[tokio::test]
    async fn a_slow_answer_that_flows_is_never_cut() {
        use tokio::io::AsyncWriteExt;
        let (mut caller, mut proxy, pump) = pumped(Duration::from_millis(300)).await;
        let started = tokio::time::Instant::now();
        let writer = tokio::spawn(async move {
            for b in b"a slow answer" {
                tokio::time::sleep(Duration::from_millis(100)).await;
                proxy.write_all(&[*b]).await.expect("write");
            }
        });
        writer.await.expect("writer");
        // The proxy has gone quiet: the idle deadline ends it now.
        assert_eq!(
            read_all(&mut caller, Duration::from_secs(3)).await,
            b"a slow answer"
        );
        assert!(started.elapsed() >= Duration::from_millis(1300));
        ended(pump).await;
    }

    /// A caller that sends its request and closes its sending side still
    /// gets the whole answer, and the connection then ends.
    #[tokio::test]
    async fn a_caller_that_half_closes_gets_its_answer() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut caller, mut proxy, pump) = pumped(Duration::from_secs(60)).await;
        caller
            .write_all(b"GET / HTTP/1.1\r\n\r\n")
            .await
            .expect("send");
        caller.shutdown().await.expect("half-close");
        let mut request = [0u8; 18];
        tokio::time::timeout(Duration::from_secs(2), proxy.read_exact(&mut request))
            .await
            .expect("the request in time")
            .expect("the request");
        assert_eq!(&request, b"GET / HTTP/1.1\r\n\r\n");
        tokio::time::sleep(Duration::from_millis(100)).await;
        proxy.write_all(b"the answer").await.expect("answer");
        drop(proxy);
        assert_eq!(
            read_all(&mut caller, Duration::from_secs(2)).await,
            b"the answer"
        );
        ended(pump).await;
    }

    /// A request with a `len`-byte body the forwarder never reads.
    fn request_with_body(len: usize) -> Vec<u8> {
        let mut out = format!(
            "POST /northflank/v1/x HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: {len}\r\n\r\n"
        )
        .into_bytes();
        out.resize(out.len() + len, b'x');
        out
    }

    /// A proxy that is never reached: nothing listens at its address.
    fn unreached_proxy() -> Arc<Proxy> {
        let free = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = free.local_addr().expect("addr");
        drop(free);
        Arc::new(
            Proxy::new(
                &format!("tls://{addr}"),
                [0u8; PIN_LEN],
                TlsSigner::channel_key(),
            )
            .expect("proxy"),
        )
    }

    /// Every waiting place held by a silent connection: the next one gets
    /// the forwarder's own `503 klav_forward_busy` at once, and whole,
    /// though it sent a request whose body the forwarder never reads. The
    /// close reads that body away first, so the answer is not reset away
    /// before the caller reads it.
    #[tokio::test]
    async fn the_connection_past_the_waiting_places_gets_its_whole_busy_answer() {
        use tokio::io::AsyncWriteExt;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let limits = RelayLimits {
            first_byte: Duration::from_secs(30),
            ..RelayLimits::default()
        };
        // Connected first, so the forwarder accepts them first.
        let mut silent = Vec::new();
        for _ in 0..MAX_WAITING {
            silent.push(TcpStream::connect(addr).await.expect("connect"));
        }
        let mut late = TcpStream::connect(addr).await.expect("connect");
        late.write_all(&request_with_body(16 * 1024))
            .await
            .expect("send");
        tokio::spawn(serve_with(listener, unreached_proxy(), limits));
        // The forwarder answers and closes before the caller reads.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let answer = read_all(&mut late, Duration::from_secs(3)).await;
        let text = String::from_utf8_lossy(&answer).to_ascii_lowercase();
        assert!(text.starts_with("http/1.1 503"), "{text}");
        assert!(text.contains("klav-error: klav_forward_busy"), "{text}");
        assert!(text.contains(&BUSY_NEXT.to_ascii_lowercase()), "{text}");
        drop(silent);
    }

    /// The proxy answers and closes while the caller is still sending (a
    /// body the proxy did not need, a pipelined request): the caller still
    /// reads the whole answer, because the forwarder reads what is left
    /// before it closes the local side instead of resetting it.
    #[tokio::test]
    async fn an_answer_ahead_of_the_callers_bytes_is_not_reset_away() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (caller, mut proxy, pump) = pumped(Duration::from_secs(60)).await;
        let (mut caller_in, mut caller_out) = caller.into_split();
        // The proxy answers at once, closes its sending side and drops
        // whatever else comes.
        proxy.write_all(b"the answer").await.expect("answer");
        proxy.shutdown().await.expect("close");
        tokio::spawn(async move {
            let mut sink = vec![0u8; 64 * 1024];
            while proxy.read(&mut sink).await.is_ok_and(|n| n > 0) {}
        });
        // Meanwhile the caller sends 4 MiB, and keeps its side open.
        let sender = tokio::spawn(async move {
            let chunk = vec![b'x'; 64 * 1024];
            for _ in 0..64 {
                if caller_out.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            caller_out
        });
        ended(pump).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut answer = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), caller_in.read_to_end(&mut answer))
            .await
            .expect("closed in time")
            .expect("the answer, not a reset");
        assert_eq!(answer, b"the answer");
        drop(sender);
    }

    /// When the proxy closes, the turn comes back at once, while the local
    /// side is still being drained of a caller that keeps it open (a
    /// pooling client that has not noticed the close yet).
    #[tokio::test]
    async fn the_turn_comes_back_before_the_local_side_is_drained() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let _caller = TcpStream::connect(listener.local_addr().expect("addr"))
            .await
            .expect("connect");
        let (local, _) = listener.accept().await.expect("accept");
        let (remote, proxy) = tokio::io::duplex(1024);
        let turns = Arc::new(tokio::sync::Semaphore::new(1));
        let turn = Arc::clone(&turns).try_acquire_owned().expect("turn");
        let pump = tokio::spawn(pump(local, remote, Duration::from_secs(60), Some(turn)));
        drop(proxy);
        let begun = tokio::time::Instant::now();
        while turns.available_permits() == 0 && begun.elapsed() < Duration::from_secs(2) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(turns.available_permits(), 1);
        assert!(
            begun.elapsed() < Duration::from_millis(500),
            "{:?}",
            begun.elapsed()
        );
        // Still draining the silent caller, for at most [`DRAIN`].
        assert!(!pump.is_finished());
        ended(pump).await;
    }

    /// The proxy cannot be reached: the forwarder's own `503
    /// klav_proxy_unreachable` arrives whole, though the request's body
    /// was never read.
    #[tokio::test]
    async fn the_unreachable_answer_is_not_reset_away_by_an_unread_body() {
        use tokio::io::AsyncWriteExt;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(serve_with(
            listener,
            unreached_proxy(),
            RelayLimits::default(),
        ));
        let mut caller = TcpStream::connect(addr).await.expect("connect");
        caller
            .write_all(&request_with_body(16 * 1024))
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(500)).await;
        let answer = read_all(&mut caller, Duration::from_secs(3)).await;
        let text = String::from_utf8_lossy(&answer).to_ascii_lowercase();
        assert!(text.starts_with("http/1.1 503"), "{text}");
        assert!(
            text.contains("klav-error: klav_proxy_unreachable"),
            "{text}"
        );
    }
}
