//! `klav-proxy enclave` (ADR 0051 §1, §4, §7.1): what the enclave image
//! starts. It opens `/dev/nsm`, listens on vsock, and either starts the
//! first seed (`--bootstrap genesis`, the first enclave or the first after
//! a total loss, §4.4) or takes the seed and every account's live state
//! from a live peer through the attested hand-off (`--bootstrap join`, a
//! restart or a rolling upgrade, §4.2, §7.4).
//!
//! - **Listeners** (`vsock:CID:PORT`, or `tcp:IP:PORT` off an enclave):
//!   the channel (sandboxes' TLS, routed by SNI), the API (`/v1/manifest`,
//!   `/v1/attest`, `/v1/enroll`, `/v1/status`, `/healthz`) and, with
//!   `--peer`, the hand-off on a port of its own (without it, on the API).
//! - **Egress** (`--egress vsock:3:PORT`): an enclave has no network. Each
//!   connection to the server, a provider or the repository goes, as an
//!   HTTP `CONNECT`, through a loopback port this command bridges to the
//!   parent's egress port; the parent resolves the name and refuses every
//!   address that isn't public (`klav-nitro-parent`). TLS stays end to end
//!   inside the enclave.
//! - **Trust:** the release authority's keys are compiled into `klav-core`
//!   and can't be swapped. `--release-key` only states which key the image
//!   expects: the command refuses to start when this build doesn't pin it,
//!   and when it pins none (ADR 0051 §14: none exist yet).
//!
//! Every flag also reads an environment variable (`KLAV_ENCLAVE_…`), for
//! the image's entry point. No flag carries a secret.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use clap::ValueEnum;

use super::attest::AttestationProvider;
use super::engine::{Enclave, EnclaveConfig};
use super::trust::{Anchors, DEFAULT_PUBLISHED_BASE, ManifestSource, PublishedRepo};
use super::{QuotaLimits, now_ms};
use crate::channel::ChannelLimits;
use crate::transport::{Connector, Endpoint, Listener};

/// How long a bridged egress connection may move no byte.
const EGRESS_IDLE: Duration = Duration::from_secs(300);
/// Between two attempts to join a holder.
const JOIN_RETRY: Duration = Duration::from_secs(5);

/// How the enclave gets its seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Bootstrap {
    /// A new seed: the first enclave, or the first after a total loss.
    /// It knows no account until each enrolls again (ADR 0051 §4.4).
    Genesis,
    /// The seed and every account's state from a live peer (`--join`).
    Join,
}

/// `klav-proxy enclave`'s flags.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// How the enclave gets its seed.
    #[arg(long, env = "KLAV_ENCLAVE_BOOTSTRAP", value_enum)]
    pub bootstrap: Bootstrap,
    /// With `--bootstrap join`: the live holder's hand-off base URL, as
    /// this enclave reaches it through the parent's egress.
    #[arg(long, env = "KLAV_ENCLAVE_JOIN", value_name = "URL")]
    pub join: Option<String>,
    /// With `--bootstrap join`: how many times to try before giving up
    /// (every 5 s).
    #[arg(long, env = "KLAV_ENCLAVE_JOIN_ATTEMPTS", default_value_t = 60)]
    pub join_attempts: u32,
    /// With `--bootstrap genesis`: the `seq` of the published manifest to
    /// serve. Without it, the enclave waits for one on `POST /v1/manifest`.
    #[arg(long, env = "KLAV_ENCLAVE_MANIFEST_SEQ")]
    pub manifest_seq: Option<u64>,
    /// The release authority's Ed25519 public key the image expects (64
    /// hex characters; repeatable, or comma-separated). The enclave starts
    /// only if this build pins every one of them.
    #[arg(
        long = "release-key",
        env = "KLAV_ENCLAVE_RELEASE_KEYS",
        value_delimiter = ',',
        required = true
    )]
    pub release_keys: Vec<String>,
    /// Where sandboxes' channels arrive (TLS, routed by SNI).
    #[arg(
        long,
        env = "KLAV_ENCLAVE_CHANNEL",
        default_value = "vsock:4294967295:5000"
    )]
    pub channel: Endpoint,
    /// Where the public API is served.
    #[arg(
        long,
        env = "KLAV_ENCLAVE_API",
        default_value = "vsock:4294967295:5001"
    )]
    pub api: Endpoint,
    /// Where other enclaves ask for the hand-off. Without it, the hand-off
    /// is served on the API.
    #[arg(long, env = "KLAV_ENCLAVE_PEER")]
    pub peer: Option<Endpoint>,
    /// The parent's egress port (`vsock:3:PORT`). Without it, the enclave
    /// connects directly: only for a run outside an enclave.
    #[arg(long, env = "KLAV_ENCLAVE_EGRESS")]
    pub egress: Option<Endpoint>,
    /// The Klav server every account lives on.
    #[arg(
        long,
        env = "KLAV_ENCLAVE_SERVER",
        default_value = "https://api.klav.dev"
    )]
    pub server: String,
    /// The proxy's DNS name: each account's channel is `a<agent_id>.<this>`.
    #[arg(long, env = "KLAV_ENCLAVE_ENDPOINT", default_value = "proxy.klav.dev")]
    pub endpoint: String,
    /// Where the signed manifests are published (a URL ending in `/`).
    #[arg(long, env = "KLAV_ENCLAVE_MANIFESTS", default_value = DEFAULT_PUBLISHED_BASE)]
    pub manifests: String,
}

/// What the enclave does to get its seed, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Plan {
    Genesis { manifest_seq: Option<u64> },
    Join { holder: String, attempts: u32 },
}

impl Args {
    /// The plan these flags ask for, or why they don't make one.
    pub(crate) fn plan(&self) -> Result<Plan, String> {
        match (self.bootstrap, &self.join) {
            (Bootstrap::Genesis, None) => Ok(Plan::Genesis {
                manifest_seq: self.manifest_seq,
            }),
            (Bootstrap::Genesis, Some(_)) => {
                Err("--join goes with --bootstrap join, not genesis".into())
            }
            (Bootstrap::Join, None) => Err("--bootstrap join needs --join URL".into()),
            (Bootstrap::Join, Some(_)) if self.manifest_seq.is_some() => Err(
                "--manifest-seq goes with --bootstrap genesis: a joiner takes the holder's manifest"
                    .into(),
            ),
            (Bootstrap::Join, Some(url)) => {
                let parsed =
                    reqwest::Url::parse(url).map_err(|_| format!("--join {url:?} is not a URL"))?;
                if !matches!(parsed.scheme(), "http" | "https") {
                    return Err("--join must be an http or https URL".into());
                }
                Ok(Plan::Join {
                    holder: url.trim_end_matches('/').to_owned(),
                    attempts: self.join_attempts.max(1),
                })
            }
        }
    }
}

/// Checks that every key the image expects is one `pinned` holds, and that
/// `pinned` holds one at all.
pub(crate) fn check_release_keys(given: &[String], pinned: &[[u8; 32]]) -> Result<(), String> {
    if pinned.is_empty() {
        return Err(
            "this build pins no release-authority key, so no manifest can verify (ADR 0051 §14): build from a release that pins them"
                .into(),
        );
    }
    if given.is_empty() {
        return Err("name the release-authority key the image expects (--release-key)".into());
    }
    for key in given {
        let bytes: [u8; 32] = data_encoding::HEXLOWER_PERMISSIVE
            .decode(key.trim().as_bytes())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| format!("--release-key {key:?} is not 64 hex characters"))?;
        if !pinned.contains(&bytes) {
            return Err(format!(
                "--release-key {key} is not a key this build pins: the image and the binary disagree"
            ));
        }
    }
    Ok(())
}

/// Opens `/dev/nsm` (Linux, inside an enclave).
#[cfg(target_os = "linux")]
fn open_nsm() -> Result<Arc<dyn AttestationProvider>, String> {
    Ok(Arc::new(super::attest::Nsm::open()?))
}

/// Off Linux there is no Nitro Secure Module.
#[cfg(not(target_os = "linux"))]
fn open_nsm() -> Result<Arc<dyn AttestationProvider>, String> {
    Err("klav-proxy enclave runs only inside an AWS Nitro Enclave (Linux, /dev/nsm)".into())
}

/// Bridges each connection to `listener` (the enclave's loopback) to the
/// parent's egress port.
async fn bridge_egress(listener: tokio::net::TcpListener, egress: Arc<dyn Connector>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let egress = Arc::clone(&egress);
        tokio::spawn(async move {
            let Ok(mut out) = egress.connect().await else {
                tracing::warn!("the parent's egress port did not accept a connection");
                return;
            };
            let mut inner: crate::transport::BoxIo = Box::new(stream);
            let _ = crate::transport::relay(&mut inner, &mut out, EGRESS_IDLE).await;
        });
    }
}

/// Starts the egress bridge on the enclave's loopback; the proxy URL every
/// client of the enclave uses.
async fn start_egress(egress: &Endpoint) -> Result<reqwest::Url, String> {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|e| format!("egress bridge on loopback: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("egress bridge on loopback: {e}"))?
        .port();
    tokio::spawn(bridge_egress(listener, egress.connector()));
    reqwest::Url::parse(&format!("http://127.0.0.1:{port}"))
        .map_err(|e| format!("egress bridge URL: {e}"))
}

/// A client to the server, the repository or a peer: through `proxy` when
/// there is one, never through the environment's proxies.
fn plain_client(proxy: Option<&reqwest::Url>) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(proxy) = proxy {
        builder = builder.proxy(reqwest::Proxy::all(proxy.clone()).map_err(|e| e.to_string())?);
    }
    builder.build().map_err(|e| format!("HTTP client: {e}"))
}

/// What [`serve`] needs, every piece of it replaceable in a test.
pub(crate) struct Startup {
    pub(crate) plan: Plan,
    pub(crate) config: EnclaveConfig,
    pub(crate) channel: Box<dyn Listener>,
    pub(crate) api: Box<dyn Listener>,
    pub(crate) peer: Option<Box<dyn Listener>>,
    pub(crate) published: Arc<dyn ManifestSource>,
    /// How the joiner reaches the holder.
    pub(crate) peer_client: reqwest::Client,
    pub(crate) join_retry: Duration,
}

/// Runs the enclave: listens, gets its seed as `plan` says, then serves
/// until a listener ends. `ready` gets the enclave once it holds its seed.
pub(crate) async fn serve(
    startup: Startup,
    nsm: Arc<dyn AttestationProvider>,
    anchors: Anchors,
    ready: Option<tokio::sync::oneshot::Sender<Arc<Enclave>>>,
) -> Result<(), String> {
    let Startup {
        plan,
        config,
        channel,
        api,
        peer,
        published,
        peer_client,
        join_retry,
    } = startup;
    let enclave = Enclave::new(config, nsm, anchors, Arc::clone(&published))?;
    tracing::info!(
        image = %data_encoding::HEXLOWER.encode(&enclave.measurement().pcr0[..8]),
        "enclave starting"
    );
    // Served from the start: until the seed is here, the API answers
    // `klav_hosted_starting` and the channel presents no key.
    let mut tasks = tokio::task::JoinSet::new();
    let e = Arc::clone(&enclave);
    tasks.spawn(async move {
        e.serve_channel(channel).await;
        "channel"
    });
    match peer {
        Some(peer) => {
            let e = Arc::clone(&enclave);
            tasks.spawn(async move {
                let _ = e.serve_router(api, false).await;
                "api"
            });
            let e = Arc::clone(&enclave);
            tasks.spawn(async move {
                let _ = e.serve_peer(peer).await;
                "peer"
            });
        }
        None => {
            let e = Arc::clone(&enclave);
            tasks.spawn(async move {
                let _ = e.serve_router(api, true).await;
                "api"
            });
        }
    }
    match plan {
        Plan::Genesis { manifest_seq } => {
            enclave.start_fresh()?;
            if let Some(seq) = manifest_seq {
                let signed = published
                    .fetch(seq)
                    .await
                    .map_err(|e| format!("manifest {seq}: {e}"))?;
                enclave
                    .load_manifest(signed)
                    .map_err(|code| format!("manifest {seq} refused: {code}"))?;
                tracing::info!(seq, "serving the published manifest");
            } else {
                tracing::info!("no manifest yet: waiting for POST /v1/manifest");
            }
        }
        Plan::Join { holder, attempts } => {
            let mut tried = 0;
            loop {
                tried += 1;
                match enclave.join(&holder, &peer_client).await {
                    Ok(()) => break,
                    Err(e) if tried < attempts => {
                        tracing::warn!(attempt = tried, error = %e, "hand-off failed: retrying");
                        tokio::time::sleep(join_retry).await;
                    }
                    Err(e) => return Err(format!("no hand-off after {tried} attempts: {e}")),
                }
            }
        }
    }
    if let Some(ready) = ready {
        let _ = ready.send(Arc::clone(&enclave));
    }
    tracing::info!(at_ms = now_ms(), "enclave serving");
    match tasks.join_next().await {
        Some(Ok(which)) => Err(format!("the {which} listener ended")),
        Some(Err(e)) => Err(format!("a listener stopped: {e}")),
        None => Err("no listener".into()),
    }
}

/// `klav-proxy enclave`.
pub async fn run(args: Args) -> Result<(), String> {
    let plan = args.plan()?;
    check_release_keys(&args.release_keys, klav_core::nitro::RELEASE_AUTHORITY_KEYS)?;
    let nsm = open_nsm()?;
    crate::net::check_roots()?;
    let proxy = match &args.egress {
        Some(egress) => Some(start_egress(egress).await?),
        None => None,
    };
    let upstream = match &proxy {
        Some(proxy) => crate::net::upstream_client_through(proxy.clone()),
        None => crate::net::upstream_client(),
    }
    .map_err(|e| format!("provider client: {e}"))?;
    let listen = |endpoint: Endpoint| async move {
        endpoint
            .listen()
            .await
            .map_err(|e| format!("cannot listen on {endpoint}: {e}"))
    };
    let startup = Startup {
        plan,
        config: EnclaveConfig {
            server: args.server.trim_end_matches('/').to_owned(),
            endpoint: args.endpoint.to_ascii_lowercase(),
            server_http: plain_client(proxy.as_ref())?,
            upstream,
            limits: QuotaLimits::default(),
            channel_limits: ChannelLimits::default(),
        },
        channel: listen(args.channel).await?,
        api: listen(args.api).await?,
        peer: match args.peer {
            Some(peer) => Some(listen(peer).await?),
            None => None,
        },
        published: Arc::new(PublishedRepo::new(
            &args.manifests,
            plain_client(proxy.as_ref())?,
        )?),
        peer_client: plain_client(proxy.as_ref())?,
        join_retry: JOIN_RETRY,
    };
    tracing::info!(
        channel = %args.channel,
        api = %args.api,
        peer = ?args.peer.map(|p| p.to_string()),
        egress = ?args.egress.map(|p| p.to_string()),
        "klav-proxy enclave listening"
    );
    serve(startup, nsm, Anchors::production(), None).await
}

/// Loopback TCP listeners for a run off an enclave (tests).
#[cfg(all(test, feature = "enclave-testkit"))]
pub(crate) async fn loopback() -> (Box<dyn Listener>, std::net::SocketAddr) {
    let listener = crate::transport::TcpAcceptor(
        tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind"),
    );
    let addr = listener.local_addr().expect("addr");
    (Box::new(listener), addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: Args,
    }

    fn parse(extra: &[&str]) -> Result<Args, String> {
        let key = "ab".repeat(32);
        // Off Linux, vsock (the defaults) does not parse.
        let mut argv = vec![
            "enclave",
            "--release-key",
            key.as_str(),
            "--channel",
            "tcp:127.0.0.1:5000",
            "--api",
            "tcp:127.0.0.1:5001",
        ];
        argv.extend_from_slice(extra);
        Cli::try_parse_from(argv)
            .map(|c| c.args)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn the_flags_make_a_plan_or_say_why_not() {
        let genesis = parse(&["--bootstrap", "genesis", "--manifest-seq", "7"]).expect("genesis");
        assert_eq!(
            genesis.plan(),
            Ok(Plan::Genesis {
                manifest_seq: Some(7)
            })
        );
        let join =
            parse(&["--bootstrap", "join", "--join", "http://10.0.0.5:8443/"]).expect("join");
        assert_eq!(
            join.plan(),
            Ok(Plan::Join {
                holder: "http://10.0.0.5:8443".into(),
                attempts: 60
            })
        );
        for bad in [
            &["--bootstrap", "join"][..],
            &["--bootstrap", "genesis", "--join", "http://h"],
            &["--bootstrap", "join", "--join", "ftp://h"],
            &[
                "--bootstrap",
                "join",
                "--join",
                "http://h",
                "--manifest-seq",
                "1",
            ],
        ] {
            assert!(parse(bad).expect("parses").plan().is_err(), "{bad:?}");
        }
        assert!(parse(&["--bootstrap", "elsewhere"]).is_err());
        assert!(
            Cli::try_parse_from(["enclave", "--bootstrap", "genesis"]).is_err(),
            "the release key is required"
        );
    }

    #[test]
    fn the_release_key_must_be_one_the_build_pins() {
        let pinned = [[0xab; 32]];
        assert_eq!(check_release_keys(&["ab".repeat(32)], &pinned), Ok(()));
        assert!(check_release_keys(&["cd".repeat(32)], &pinned).is_err());
        assert!(check_release_keys(&["abc".into()], &pinned).is_err());
        assert!(check_release_keys(&[], &pinned).is_err());
        // Today's build pins none (ADR 0051 §14): it never starts.
        assert!(
            check_release_keys(&["ab".repeat(32)], klav_core::nitro::RELEASE_AUTHORITY_KEYS)
                .is_err()
        );
    }

    /// The defaults an enclave image starts with: vsock on every context
    /// ID, ports 5000 and 5001.
    #[cfg(target_os = "linux")]
    #[test]
    fn on_linux_the_defaults_are_vsock() {
        let key = "ab".repeat(32);
        let cli = Cli::try_parse_from([
            "enclave",
            "--bootstrap",
            "genesis",
            "--release-key",
            key.as_str(),
        ])
        .expect("parses");
        assert_eq!(
            cli.args.channel,
            Endpoint::Vsock {
                cid: u32::MAX,
                port: 5000
            }
        );
        assert_eq!(
            cli.args.api,
            Endpoint::Vsock {
                cid: u32::MAX,
                port: 5001
            }
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn off_linux_there_is_no_nsm() {
        assert!(open_nsm().is_err());
    }

    /// The egress bridge moves bytes both ways between the enclave's
    /// loopback and the parent's egress port.
    #[tokio::test]
    async fn the_egress_bridge_relays_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let parent = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let parent_addr = parent.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut s, _) = parent.accept().await.expect("accept");
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.expect("read");
            buf.reverse();
            s.write_all(&buf).await.expect("write");
        });
        let proxy = start_egress(&Endpoint::Tcp(parent_addr))
            .await
            .expect("bridge");
        let mut s = tokio::net::TcpStream::connect((
            proxy.host_str().expect("host"),
            proxy.port().expect("port"),
        ))
        .await
        .expect("connect");
        s.write_all(b"hello").await.expect("write");
        let mut back = [0u8; 5];
        s.read_exact(&mut back).await.expect("read");
        assert_eq!(&back, b"olleh");
    }
}
