//! `klav-nitro-parent` (ADR 0051 §1, §1.2, §5.3): the untrusted EC2 host's
//! side of Klav Cloud's hosted proxy. It holds no Klav key and uses no
//! `klav-core` cryptography; it moves bytes.
//!
//! - **Inbound** ([`serve_inbound`]): each TCP connection from the load
//!   balancer goes, byte for byte, to the enclave's vsock port. TLS is
//!   never terminated here: the channel's handshake and the API's bytes
//!   reach the enclave as they came. Per source IP, connections are rate
//!   limited before any byte reaches the enclave (§3.3).
//! - **Egress** ([`serve_egress`]): the enclave cannot open a socket; it
//!   asks the parent with an HTTP `CONNECT host:port` over vsock. The
//!   parent resolves the name and **refuses** every address that is not
//!   public ([`crate::net::is_public`]: loopback, RFC 1918, CGNAT
//!   `100.64.0.0/10`, link-local with `169.254.169.254`, the instance
//!   metadata service, multicast, unspecified, IPv6 outside `2000::/3`
//!   with `fd00:ec2::254`), and every port but 443 unless the operator
//!   listed it (§1.2, §11 #10). One refused address refuses the whole
//!   name, and the connection goes to an address it checked, never to a
//!   second lookup. The enclave keeps its own checks; this list is the
//!   SSRF barrier the enclave can no longer apply itself (it resolves no
//!   names).
//! - **Health** ([`serve_health`]): `GET /healthz` for the load balancer,
//!   `200` when the enclave's port accepts a connection. No account data.
//!
//! The parent sees what §1.1 says: source IPs, SNI, sizes, timing, and
//! the names the enclave asks it to resolve. Never a key, a token or a
//! body: those are inside TLS the enclave terminates.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;

use crate::transport::{BoxIo, Connector, Listener};

/// The only egress port allowed unless the operator lists others.
pub const DEFAULT_EGRESS_PORT: u16 = 443;
/// Largest `CONNECT` head the enclave may send.
pub const MAX_CONNECT_HEAD: usize = 4096;
/// How long the enclave has to send its `CONNECT` head.
pub const CONNECT_HEAD_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a connection to an upstream may take.
pub const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a relayed connection may move no byte either way.
pub const RELAY_IDLE: Duration = Duration::from_secs(300);
/// Inbound connections at once, over all sources.
pub const MAX_INBOUND: usize = 4096;
/// Egress connections at once.
pub const MAX_EGRESS: usize = 1024;
/// New inbound connections per source IP per minute, by default.
pub const DEFAULT_PER_IP_PER_MINUTE: u32 = 600;

/// Where the enclave may connect.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    ports: Vec<u16>,
    /// Addresses allowed although not public. Always empty outside tests:
    /// there is no flag for it.
    exempt: Vec<IpAddr>,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            ports: vec![DEFAULT_EGRESS_PORT],
            exempt: Vec::new(),
        }
    }
}

impl EgressPolicy {
    /// Port 443 and `extra` (the operator's list, Klav-wide, §1.2).
    pub fn with_ports(extra: &[u16]) -> Self {
        let mut ports = vec![DEFAULT_EGRESS_PORT];
        ports.extend(extra.iter().copied().filter(|p| *p != 0));
        ports.sort_unstable();
        ports.dedup();
        Self {
            ports,
            exempt: Vec::new(),
        }
    }

    /// Tests only: also allow these addresses (mock upstreams on loopback).
    #[cfg(test)]
    pub(crate) fn exempting(mut self, ips: &[IpAddr]) -> Self {
        self.exempt.extend_from_slice(ips);
        self
    }

    /// Whether `port` is allowed.
    pub fn allows_port(&self, port: u16) -> bool {
        self.ports.contains(&port)
    }

    /// Whether `ip` may be connected to.
    pub fn allows_ip(&self, ip: IpAddr) -> bool {
        crate::net::is_public(ip) || self.exempt.contains(&ip)
    }
}

/// Resolves names for the enclave.
pub trait Resolve: Send + Sync + 'static {
    /// The addresses of `host`.
    fn lookup<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>>;
}

/// The system's resolver.
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn lookup<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            Ok(tokio::net::lookup_host((host, 0))
                .await?
                .map(|a| a.ip())
                .collect())
        })
    }
}

/// Why the parent refused an egress request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressRefusal {
    /// Not a `CONNECT host:port` head, too long, or too slow.
    BadRequest,
    /// A port the operator did not list.
    Port,
    /// The name resolved to an address that is not public, or is one.
    Address,
    /// The name did not resolve.
    Unresolved,
    /// No address accepted the connection.
    Unreachable,
}

impl EgressRefusal {
    /// The code in the `klav-egress` header of the refusal.
    pub fn code(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::Port => "port_refused",
            Self::Address => "address_refused",
            Self::Unresolved => "unresolved",
            Self::Unreachable => "unreachable",
        }
    }

    fn status(self) -> &'static str {
        match self {
            Self::BadRequest => "400 Bad Request",
            Self::Port | Self::Address => "403 Forbidden",
            Self::Unresolved | Self::Unreachable => "502 Bad Gateway",
        }
    }
}

/// Splits `host:port` (`[v6]:port` for an IPv6 literal).
fn split_target(target: &str) -> Option<(&str, u16)> {
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        (host, rest.strip_prefix(':')?)
    } else {
        let (host, port) = target.rsplit_once(':')?;
        if host.contains(':') {
            return None;
        }
        (host, port)
    };
    if host.is_empty() || host.len() > 253 || port.is_empty() || port.len() > 5 {
        return None;
    }
    let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
    Some((host, port))
}

/// The addresses the enclave may reach for `host:port`, checked, or why
/// not. A host that is an IP literal is judged as is.
pub async fn decide(
    policy: &EgressPolicy,
    resolver: &dyn Resolve,
    host: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, EgressRefusal> {
    if !policy.allows_port(port) {
        return Err(EgressRefusal::Port);
    }
    let ips = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => {
            if !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
            {
                return Err(EgressRefusal::BadRequest);
            }
            resolver
                .lookup(host)
                .await
                .map_err(|_| EgressRefusal::Unresolved)?
        }
    };
    if ips.is_empty() {
        return Err(EgressRefusal::Unresolved);
    }
    if ips.iter().any(|ip| !policy.allows_ip(*ip)) {
        return Err(EgressRefusal::Address);
    }
    Ok(ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}

/// Reads a `CONNECT host:port HTTP/1.1` head; returns the target and any
/// bytes read past the head.
async fn read_connect(io: &mut BoxIo) -> Result<(String, u16, Vec<u8>), EgressRefusal> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() >= MAX_CONNECT_HEAD {
            return Err(EgressRefusal::BadRequest);
        }
        let n = io
            .read(&mut chunk)
            .await
            .map_err(|_| EgressRefusal::BadRequest)?;
        if n == 0 {
            return Err(EgressRefusal::BadRequest);
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| EgressRefusal::BadRequest)?;
    let line = head.split("\r\n").next().unwrap_or_default();
    let mut parts = line.split(' ');
    let (Some("CONNECT"), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(EgressRefusal::BadRequest);
    };
    if !version.starts_with("HTTP/1.") {
        return Err(EgressRefusal::BadRequest);
    }
    let (host, port) = split_target(target).ok_or(EgressRefusal::BadRequest)?;
    Ok((host.to_ascii_lowercase(), port, buf[end..].to_vec()))
}

async fn refuse(io: &mut BoxIo, why: EgressRefusal) {
    let answer = format!(
        "HTTP/1.1 {}\r\nklav-egress: {}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        why.status(),
        why.code()
    );
    let _ = io.write_all(answer.as_bytes()).await;
    let _ = io.shutdown().await;
}

/// One egress request, start to end.
pub async fn egress_one(
    mut io: BoxIo,
    policy: &EgressPolicy,
    resolver: &dyn Resolve,
) -> Result<(), EgressRefusal> {
    let read = tokio::time::timeout(CONNECT_HEAD_TIMEOUT, read_connect(&mut io))
        .await
        .unwrap_or(Err(EgressRefusal::BadRequest));
    let (host, port, early) = match read {
        Ok(head) => head,
        Err(why) => {
            refuse(&mut io, why).await;
            return Err(why);
        }
    };
    let addrs = match decide(policy, resolver, &host, port).await {
        Ok(addrs) => addrs,
        Err(why) => {
            tracing::info!(host = %host, port, refused = why.code(), "egress refused");
            refuse(&mut io, why).await;
            return Err(why);
        }
    };
    let mut upstream = None;
    for addr in addrs {
        if let Ok(Ok(stream)) = tokio::time::timeout(
            UPSTREAM_CONNECT_TIMEOUT,
            tokio::net::TcpStream::connect(addr),
        )
        .await
        {
            upstream = Some(stream);
            break;
        }
    }
    let Some(upstream) = upstream else {
        tracing::info!(host = %host, port, "egress unreachable");
        refuse(&mut io, EgressRefusal::Unreachable).await;
        return Err(EgressRefusal::Unreachable);
    };
    let _ = upstream.set_nodelay(true);
    let mut upstream: BoxIo = Box::new(upstream);
    if io
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .is_err()
    {
        return Ok(());
    }
    if !early.is_empty() && upstream.write_all(&early).await.is_err() {
        return Ok(());
    }
    let moved = crate::transport::relay(&mut io, &mut upstream, RELAY_IDLE).await;
    if let Ok((up, down)) = moved {
        tracing::debug!(host = %host, port, up, down, "egress closed");
    }
    Ok(())
}

/// Serves the enclave's egress requests until the listener fails.
pub async fn serve_egress(
    listener: Box<dyn Listener>,
    policy: Arc<EgressPolicy>,
    resolver: Arc<dyn Resolve>,
) {
    let open = Arc::new(Semaphore::new(MAX_EGRESS));
    loop {
        let io = match listener.accept().await {
            Ok(io) => io,
            Err(e) => {
                tracing::warn!(error = %e, "egress accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(slot) = Arc::clone(&open).try_acquire_owned() else {
            continue;
        };
        let policy = Arc::clone(&policy);
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move {
            let _ = egress_one(io, &policy, resolver.as_ref()).await;
            drop(slot);
        });
    }
}

/// New connections per source IP in a rolling minute.
pub struct PerIpLimiter {
    per_minute: u32,
    seen: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl PerIpLimiter {
    /// At most `per_minute` new connections per source IP.
    pub fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Whether a new connection from `ip` at `now` fits.
    pub fn admit(&self, ip: IpAddr, now: Instant) -> bool {
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if seen.len() > 100_000 {
            seen.retain(|_, (start, _)| now.duration_since(*start) < Duration::from_secs(60));
        }
        let entry = seen.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= Duration::from_secs(60) {
            *entry = (now, 0);
        }
        if entry.1 >= self.per_minute {
            return false;
        }
        entry.1 += 1;
        true
    }
}

/// Relays each inbound TCP connection to the enclave, unopened.
pub async fn serve_inbound(
    listener: tokio::net::TcpListener,
    enclave: Arc<dyn Connector>,
    limiter: Arc<PerIpLimiter>,
) {
    let open = Arc::new(Semaphore::new(MAX_INBOUND));
    loop {
        let (stream, from) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "inbound accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        if !limiter.admit(from.ip(), Instant::now()) {
            tracing::debug!(ip = %from.ip(), "inbound rate limited");
            continue;
        }
        let Ok(slot) = Arc::clone(&open).try_acquire_owned() else {
            continue;
        };
        let enclave = Arc::clone(&enclave);
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            let mut inbound: BoxIo = Box::new(stream);
            if let Ok(mut to_enclave) = enclave.connect().await {
                let _ = crate::transport::relay(&mut inbound, &mut to_enclave, RELAY_IDLE).await;
            }
            drop(slot);
        });
    }
}

/// `GET /healthz`: `200` when the enclave accepts a connection.
pub async fn serve_health(listener: tokio::net::TcpListener, enclave: Arc<dyn Connector>) {
    use axum::routing::get;
    let app = axum::Router::new().route(
        "/healthz",
        get(move || {
            let enclave = Arc::clone(&enclave);
            async move {
                match tokio::time::timeout(Duration::from_secs(2), enclave.connect()).await {
                    Ok(Ok(_)) => (axum::http::StatusCode::OK, "ok"),
                    _ => (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        "enclave unreachable",
                    ),
                }
            }
        }),
    );
    if let Err(e) = axum::serve(listener, app).await {
        tracing::warn!(error = %e, "health check server ended");
    }
}

/// The command line of `klav-nitro-parent`.
#[derive(Debug, clap::Parser)]
#[command(
    name = "klav-nitro-parent",
    version,
    about = "Klav Cloud's Nitro parent: moves bytes between the load balancer, the enclave and the providers. Holds no keys."
)]
pub struct Args {
    /// TCP address for sandbox channels (`a<agent_id>.proxy.klav.dev`).
    #[arg(long, default_value = "0.0.0.0:443")]
    pub channel_listen: SocketAddr,
    /// The enclave's channel port (`vsock:CID:PORT`, or `tcp:IP:PORT`).
    #[arg(long)]
    pub channel_enclave: crate::transport::Endpoint,
    /// TCP address for the public API (`/v1/manifest`, `/v1/attest`,
    /// `/v1/enroll`, `/v1/status`, the hand-off).
    #[arg(long, default_value = "0.0.0.0:8443")]
    pub api_listen: SocketAddr,
    /// The enclave's API port.
    #[arg(long)]
    pub api_enclave: crate::transport::Endpoint,
    /// Where the enclave asks for egress (`vsock:4294967295:PORT` listens
    /// on every CID).
    #[arg(long)]
    pub egress_listen: crate::transport::Endpoint,
    /// TCP address of the load balancer's health check.
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub health_listen: SocketAddr,
    /// Another egress port besides 443 (repeatable).
    #[arg(long = "allow-port")]
    pub allow_ports: Vec<u16>,
    /// New inbound connections per source IP per minute.
    #[arg(long, default_value_t = DEFAULT_PER_IP_PER_MINUTE)]
    pub per_ip_per_minute: u32,
}

/// Runs the parent until a listener cannot be bound.
pub async fn run(args: Args) -> Result<(), String> {
    let limiter = Arc::new(PerIpLimiter::new(args.per_ip_per_minute));
    let bind = |addr: SocketAddr| async move {
        tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("cannot listen on {addr}: {e}"))
    };
    let channel = bind(args.channel_listen).await?;
    let api = bind(args.api_listen).await?;
    let health = bind(args.health_listen).await?;
    let egress = args
        .egress_listen
        .listen()
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", args.egress_listen))?;
    let policy = Arc::new(EgressPolicy::with_ports(&args.allow_ports));
    tracing::info!(
        channel = %args.channel_listen,
        api = %args.api_listen,
        egress = %args.egress_listen,
        ports = ?policy.ports,
        "klav-nitro-parent listening"
    );
    let channel_enclave = args.channel_enclave.connector();
    let api_enclave = args.api_enclave.connector();
    tokio::select! {
        () = serve_inbound(channel, Arc::clone(&channel_enclave), Arc::clone(&limiter)) => {}
        () = serve_inbound(api, api_enclave, limiter) => {}
        () = serve_egress(egress, policy, Arc::new(SystemResolver)) => {}
        () = serve_health(health, channel_enclave) => {}
    }
    Err("a listener ended".into())
}

/// `klav-nitro-parent`'s `main`.
pub fn main() -> std::process::ExitCode {
    use clap::Parser as _;
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("KLAV_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .with_writer(std::io::stderr)
        .init();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "klav-nitro-parent cannot start its runtime");
            return std::process::ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(args)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "klav-nitro-parent stopped");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TcpAcceptor;

    /// A resolver with fixed answers.
    struct Fixed(Vec<(&'static str, Vec<IpAddr>)>);

    impl Resolve for Fixed {
        fn lookup<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
            Box::pin(async move {
                self.0
                    .iter()
                    .find(|(h, _)| *h == host)
                    .map(|(_, ips)| ips.clone())
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such name"))
            })
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    fn resolver() -> Fixed {
        Fixed(vec![
            ("api.northflank.com", vec![ip("203.0.114.10")]),
            ("internal.example", vec![ip("10.0.0.1")]),
            ("metadata.example", vec![ip("169.254.169.254")]),
            ("mixed.example", vec![ip("203.0.114.11"), ip("192.168.1.7")]),
            ("v6local.example", vec![ip("fe80::1")]),
            ("empty.example", vec![]),
        ])
    }

    /// ADR 0051 §1.2: the default policy refuses metadata, loopback,
    /// private, CGNAT, link-local, multicast and unspecified addresses,
    /// by literal or by name, and every port but 443.
    #[tokio::test]
    async fn the_default_policy_refuses_what_it_must() {
        let policy = EgressPolicy::default();
        let r = resolver();
        let refused_addresses = [
            "169.254.169.254",
            "127.0.0.1",
            "10.0.0.1",
            "172.16.5.4",
            "192.168.0.1",
            "100.64.0.1",
            "100.127.255.254",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd00:ec2::254",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ];
        for host in refused_addresses {
            assert_eq!(
                decide(&policy, &r, host, 443).await,
                Err(EgressRefusal::Address),
                "{host}"
            );
        }
        for host in [
            "internal.example",
            "metadata.example",
            "mixed.example",
            "v6local.example",
        ] {
            assert_eq!(
                decide(&policy, &r, host, 443).await,
                Err(EgressRefusal::Address),
                "{host}"
            );
        }
        assert_eq!(
            decide(&policy, &r, "empty.example", 443).await,
            Err(EgressRefusal::Unresolved)
        );
        assert_eq!(
            decide(&policy, &r, "nowhere.example", 443).await,
            Err(EgressRefusal::Unresolved)
        );
        for port in [80, 22, 8443, 6379] {
            assert_eq!(
                decide(&policy, &r, "api.northflank.com", port).await,
                Err(EgressRefusal::Port),
                "{port}"
            );
        }
        assert_eq!(
            decide(&policy, &r, "api.northflank.com", 443).await,
            Ok(vec!["203.0.114.10:443".parse().expect("addr")])
        );
        assert_eq!(
            decide(&policy, &r, "1.1.1.1", 443).await,
            Ok(vec!["1.1.1.1:443".parse().expect("addr")])
        );
        assert_eq!(
            decide(&policy, &r, "bad_name!", 443).await,
            Err(EgressRefusal::BadRequest)
        );
        // An operator's extra port.
        let with_80 = EgressPolicy::with_ports(&[80]);
        assert!(with_80.allows_port(80) && with_80.allows_port(443) && !with_80.allows_port(22));
    }

    #[test]
    fn targets_split() {
        assert_eq!(
            split_target("api.example.com:443"),
            Some(("api.example.com", 443))
        );
        assert_eq!(split_target("[::1]:443"), Some(("::1", 443)));
        assert_eq!(split_target("1.2.3.4:443"), Some(("1.2.3.4", 443)));
        for bad in [
            "api.example.com",
            "::1:443",
            "[::1]443",
            ":443",
            "h:0",
            "h:99999",
            "h:",
        ] {
            assert_eq!(split_target(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_per_ip_limit_rolls_each_minute() {
        let limiter = PerIpLimiter::new(2);
        let now = Instant::now();
        let a = ip("198.51.100.1");
        let b = ip("198.51.100.2");
        assert!(limiter.admit(a, now));
        assert!(limiter.admit(a, now));
        assert!(!limiter.admit(a, now));
        assert!(limiter.admit(b, now));
        assert!(limiter.admit(a, now + Duration::from_secs(61)));
    }

    async fn connect_through(egress: SocketAddr, target: &str) -> (String, tokio::net::TcpStream) {
        let mut s = tokio::net::TcpStream::connect(egress)
            .await
            .expect("connect");
        s.write_all(format!("CONNECT {target} HTTP/1.1\r\nhost: {target}\r\n\r\n").as_bytes())
            .await
            .expect("write");
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if s.read(&mut byte).await.expect("read") == 0 {
                break;
            }
            head.push(byte[0]);
        }
        (String::from_utf8(head).expect("utf8"), s)
    }

    /// The whole egress path over TCP: a refused target gets a `403` with
    /// its code and no connection; an allowed one is relayed.
    #[tokio::test]
    async fn egress_refuses_or_relays() {
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let upstream_addr = upstream.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((mut s, _)) = upstream.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4];
                    if s.read_exact(&mut buf).await.is_ok() {
                        let _ = s.write_all(b"pong").await;
                    }
                });
            }
        });

        // The default policy: loopback is refused even where it listens.
        let listener = TcpAcceptor(
            tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind"),
        );
        let egress = listener.local_addr().expect("addr");
        tokio::spawn(serve_egress(
            Box::new(listener),
            Arc::new(EgressPolicy::with_ports(&[upstream_addr.port()])),
            Arc::new(resolver()),
        ));
        for target in [
            upstream_addr.to_string(),
            "169.254.169.254:443".into(),
            "10.0.0.1:443".into(),
            "[::1]:443".into(),
            "[fe80::1]:443".into(),
            "internal.example:443".into(),
        ] {
            let (head, _) = connect_through(egress, &target).await;
            assert!(head.starts_with("HTTP/1.1 403"), "{target}: {head}");
            assert!(
                head.contains("klav-egress: address_refused"),
                "{target}: {head}"
            );
        }
        let (head, _) = connect_through(egress, "api.northflank.com:80").await;
        assert!(head.contains("klav-egress: port_refused"), "{head}");
        let (head, _) = connect_through(egress, "not a target").await;
        assert!(head.starts_with("HTTP/1.1 400"), "{head}");

        // The test exemption for the mock upstream.
        let listener = TcpAcceptor(
            tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind"),
        );
        let egress = listener.local_addr().expect("addr");
        tokio::spawn(serve_egress(
            Box::new(listener),
            Arc::new(
                EgressPolicy::with_ports(&[upstream_addr.port()]).exempting(&[upstream_addr.ip()]),
            ),
            Arc::new(resolver()),
        ));
        let (head, mut s) = connect_through(egress, &upstream_addr.to_string()).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        s.write_all(b"ping").await.expect("write");
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"pong");
    }

    /// Inbound bytes reach the enclave unchanged, both ways, and the health
    /// check follows the enclave's port.
    #[tokio::test]
    async fn inbound_is_relayed_unopened_and_health_follows_the_enclave() {
        let enclave = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let enclave_addr = enclave.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((mut s, _)) = enclave.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 10];
                    if s.read_exact(&mut buf).await.is_ok() {
                        buf.reverse();
                        let _ = s.write_all(&buf).await;
                    }
                });
            }
        });
        let front = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let front_addr = front.local_addr().expect("addr");
        tokio::spawn(serve_inbound(
            front,
            Arc::new(crate::transport::TcpTarget(enclave_addr)),
            Arc::new(PerIpLimiter::new(2)),
        ));
        // A TLS ClientHello's first bytes go through as they are.
        let hello = b"\x16\x03\x01\x00\x05hello";
        let mut s = tokio::net::TcpStream::connect(front_addr)
            .await
            .expect("connect");
        s.write_all(hello).await.expect("write");
        let mut back = [0u8; 10];
        s.read_exact(&mut back).await.expect("read");
        let mut expected = *hello;
        expected.reverse();
        assert_eq!(back, expected);
        // The third connection from this IP in a minute is dropped.
        let _second = tokio::net::TcpStream::connect(front_addr)
            .await
            .expect("connect");
        let mut third = tokio::net::TcpStream::connect(front_addr)
            .await
            .expect("connect");
        let _ = third.write_all(hello).await;
        let mut buf = [0u8; 1];
        let got = tokio::time::timeout(Duration::from_secs(5), third.read(&mut buf)).await;
        assert!(matches!(got, Ok(Ok(0)) | Ok(Err(_))), "{got:?}");

        let health = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let health_addr = health.local_addr().expect("addr");
        tokio::spawn(serve_health(
            health,
            Arc::new(crate::transport::TcpTarget(enclave_addr)),
        ));
        let ok = reqwest::get(format!("http://{health_addr}/healthz"))
            .await
            .expect("get");
        assert_eq!(ok.status(), 200);
        let gone = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let gone_addr = gone.local_addr().expect("addr");
        drop(gone);
        let health = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let health_addr = health.local_addr().expect("addr");
        tokio::spawn(serve_health(
            health,
            Arc::new(crate::transport::TcpTarget(gone_addr)),
        ));
        let down = reqwest::get(format!("http://{health_addr}/healthz"))
            .await
            .expect("get");
        assert_eq!(down.status(), 503);
    }
}
