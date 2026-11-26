//! Claims end to end (ADR 0036 §5, §6, E3.3; layer 6): a real
//! `klav-server`, the issuer starting a sandbox through the proxy's
//! loopback API, and a forwarder (here, a reqwest client with the
//! production channel configuration) claiming it over the pinned TLS 1.3
//! channel. Each test checks the person's log, and that it verifies.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicI64;

use klav_client::Unlocked;
use klav_core::crypto::channel::TlsSigner;
use klav_core::crypto::sandbox::{SandboxPackage, decode_package};
use klav_proto::Blob;
use klav_sdk::sandbox as issuer_api;
use klav_sdk::{Agent, Session};

use crate::channel::ChannelLimits;
use crate::e2e_tests::common::ServerProcess;
use crate::proxy::{ProxyState, router};
use crate::sandbox_e2e_tests::{Manual, credential_at, ends, real_now, request, setup, setup_with};
use crate::sandboxes::{INACTIVITY_MS, Sandboxes, sweep};

/// The proxy with its loopback API and its channel, both on ephemeral
/// ports, with `clock` and a store at `store`.
async fn serve(
    proxy: Agent,
    clock: Arc<Manual>,
    store: std::path::PathBuf,
) -> (Arc<ProxyState>, u16, SocketAddr) {
    serve_through(proxy, clock, store, reqwest::Client::new()).await
}

/// [`serve`], reaching providers through `client`.
async fn serve_through(
    proxy: Agent,
    clock: Arc<Manual>,
    store: std::path::PathBuf,
    client: reqwest::Client,
) -> (Arc<ProxyState>, u16, SocketAddr) {
    let (state, port, addr, _) =
        serve_limited(proxy, clock, store, client, ChannelLimits::default(), None).await;
    (state, port, addr)
}

/// [`serve_through`] with these channel limits, extra channel routes, and
/// a stop for the channel (send `()` to stop it; the handle ends when it
/// has).
pub(crate) async fn serve_limited(
    proxy: Agent,
    clock: Arc<Manual>,
    store: std::path::PathBuf,
    client: reqwest::Client,
    limits: ChannelLimits,
    extra: Option<axum::Router>,
) -> (
    Arc<ProxyState>,
    u16,
    SocketAddr,
    (
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<Result<(), String>>,
    ),
) {
    serve_configured(proxy, clock, store, client, limits, extra, |s| s).await
}

/// [`serve_limited`], with the state changed by `configure` before it
/// serves (`--no-local-calls`, for one).
pub(crate) async fn serve_configured(
    proxy: Agent,
    clock: Arc<Manual>,
    store: std::path::PathBuf,
    client: reqwest::Client,
    limits: ChannelLimits,
    extra: Option<axum::Router>,
    configure: impl FnOnce(ProxyState) -> ProxyState,
) -> (
    Arc<ProxyState>,
    u16,
    SocketAddr,
    (
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<Result<(), String>>,
    ),
) {
    let signer = proxy.tls_server_signer();
    let session = Session::open(proxy).await.expect("proxy session");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    // The redaction counts next to the store, saved as `serve` does.
    let counts = crate::counts::Counts::at(
        store.with_extension(crate::counts::COUNTS_EXTENSION),
        real_now(),
    )
    .expect("counts");
    let sandboxes = Sandboxes::open(store, clock).expect("store");
    let state = Arc::new(configure(
        ProxyState::new(session, client, port)
            .with_sandboxes(sandboxes)
            .with_counts(counts),
    ));
    tokio::spawn(state.counts().write_on_change());
    let served = Arc::clone(&state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(served)).await;
    });
    let channel = crate::channel::bind_with("127.0.0.1:0".parse().expect("addr"), signer, limits)
        .await
        .expect("channel");
    let addr = channel.local_addr();
    let mut routes = crate::channel::router(Arc::clone(&state));
    if let Some(extra) = extra {
        routes = extra.merge(routes);
    }
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn(crate::channel::serve_routes(
        channel,
        Arc::clone(&state),
        routes,
        async move {
            // A dropped sender never stops it.
            if stopped.await.is_err() {
                std::future::pending::<()>().await;
            }
        },
    ));
    (state, port, addr, (stop, served))
}

/// A forwarder: a fresh channel key, pinned to the package's proxy.
struct Forwarder {
    http: reqwest::Client,
    base: String,
}

impl Forwarder {
    fn new(package: &SandboxPackage, addr: SocketAddr) -> Self {
        Self::with_pin(package.proxy_pin, addr)
    }

    fn with_pin(pin: [u8; 32], addr: SocketAddr) -> Self {
        let config = klav_forward::channel::client_config(TlsSigner::channel_key(), pin)
            .expect("client config");
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(config)
            .no_proxy()
            .build()
            .expect("client");
        Self {
            http,
            base: format!("https://{addr}"),
        }
    }

    /// `(status, error code or "", body)`.
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Vec<u8>,
    ) -> (u16, String, serde_json::Value) {
        let res = self
            .http
            .request(method, format!("{}{path}", self.base))
            .body(body)
            .send()
            .await
            .expect("the channel answers");
        let status = res.status().as_u16();
        let code = res
            .headers()
            .get("klav-error")
            .map(|v| v.to_str().expect("ascii").to_owned())
            .unwrap_or_default();
        let body = res.bytes().await.expect("body");
        let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, code, json)
    }

    async fn claim(&self, package: &SandboxPackage) -> (u16, String, serde_json::Value) {
        let body = serde_json::json!({
            "sandbox_id": package.sandbox_id,
            "secret": Blob::new(package.secret.expose().to_vec()).to_text(),
        });
        self.send(
            reqwest::Method::POST,
            crate::channel::CLAIM,
            serde_json::to_vec(&body).expect("json"),
        )
        .await
    }

    async fn status(&self) -> (u16, String, serde_json::Value) {
        self.send(reqwest::Method::GET, crate::channel::STATUS, Vec::new())
            .await
    }

    async fn release(&self) -> (u16, String, serde_json::Value) {
        self.send(reqwest::Method::POST, crate::channel::RELEASE, Vec::new())
            .await
    }
}

/// The `sandbox.*` actions of the person's log, oldest first, after it
/// verifies.
async fn actions(ana: &mut Unlocked) -> Vec<String> {
    ana.verify_audit().await.expect("the chain verifies");
    ana.audit_log(&klav_client::audit::LogFilter::default())
        .await
        .expect("log")
        .into_iter()
        .rev()
        .filter(|l| l.action.starts_with("sandbox."))
        .map(|l| l.action)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forwarder_claims_its_sandbox_over_the_pinned_channel_and_releases_it() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let store = dir.path().join("proxy.sandbox-store");
    let (state, port, addr) = serve(proxy, clock, store.clone()).await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");
    let forwarder = Forwarder::new(&package, addr);

    // Not claimed yet: the key is nobody's.
    assert_eq!(forwarder.status().await.1, "klav_sandbox_revoked");
    // A wrong secret is the same answer as an unknown sandbox.
    let wrong = SandboxPackage {
        secret: klav_core::crypto::sandbox::SandboxSecret::generate(),
        ..decode_package(&started.package).expect("package")
    };
    let (status, code, _) = forwarder.claim(&wrong).await;
    assert_eq!((status, code.as_str()), (401, "klav_sandbox_revoked"));

    // The claim binds the sandbox to this key; the server logged it.
    let (status, _, body) = forwarder.claim(&package).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["sandbox_id"], started.sandbox_id.to_string());
    assert_eq!(body["profiles"], serde_json::json!(["northflank"]));
    assert_eq!(body["label"], "chat-1");
    let (status, _, body) = forwarder.status().await;
    assert_eq!(
        (status, body["sandbox_id"].clone()),
        (200, serde_json::json!(started.sandbox_id.to_string()))
    );
    // The same key again (a lost answer): the same claim, nothing new logged.
    assert_eq!(forwarder.claim(&package).await.0, 200);
    assert_eq!(
        actions(&mut ana).await,
        ["sandbox.issued", "sandbox.claimed"]
    );
    assert!(state.sandboxes().views().await[0].claimed);
    // On disk: the channel's digest, never the key or the secret.
    let channels = std::fs::read_to_string(crate::claims::path_of(&store)).expect("channels");
    assert!(channels.contains(&started.sandbox_id.to_string()));
    assert!(!channels.contains(&Blob::new(package.secret.expose().to_vec()).to_text()));

    // A pin of another proxy never reaches it.
    let elsewhere = Forwarder::with_pin([7; 32], addr);
    assert!(
        elsewhere
            .http
            .get(format!("{}{}", elsewhere.base, crate::channel::STATUS))
            .send()
            .await
            .is_err()
    );

    // Release: ended at once, `released` logged after the claim.
    let (status, _, body) = forwarder.release().await;
    assert_eq!(
        (status, body["logged"].clone()),
        (200, serde_json::json!(true))
    );
    assert_eq!(forwarder.status().await.1, "klav_sandbox_revoked");
    assert_eq!(state.sandboxes().live().await, 0);
    assert_eq!(ends(&mut ana).await, [Some("released".to_owned())]);
    issuer_api::list(&t3, port)
        .await
        .expect("list")
        .is_empty()
        .then_some(())
        .expect("none live");
}

/// The heartbeat says a sandbox is connected while its forwarder holds a
/// connection over the channel, and not once that closes (ADR 0036 E3.3).
#[tokio::test(flavor = "multi_thread")]
async fn the_heartbeat_says_whether_a_forwarder_is_connected() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (_ana, proxy, mut t3) = setup(&server, &dir).await;
    let now = real_now();
    let clock = Arc::new(Manual(AtomicI64::new(now)));
    let (state, port, addr) = serve(proxy, clock, dir.path().join("proxy.sandbox-store")).await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");
    let connected = |links: Vec<klav_proto::sandbox::SandboxLink>| {
        links
            .into_iter()
            .map(|l| (l.id, l.connected))
            .collect::<Vec<_>>()
    };
    let links = crate::heartbeat::links(&state, now).await.2;
    assert_eq!(connected(links), [(started.sandbox_id, false)], "unclaimed");
    let forwarder = Forwarder::new(&package, addr);
    assert_eq!(forwarder.claim(&package).await.0, 200);
    let links = crate::heartbeat::links(&state, now).await.2;
    assert_eq!(connected(links), [(started.sandbox_id, true)]);
    // Its connection closes with it.
    drop(forwarder);
    let mut closed = false;
    for _ in 0..50 {
        let links = crate::heartbeat::links(&state, now).await.2;
        if connected(links) == [(started.sandbox_id, false)] {
            closed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(closed, "still connected after the forwarder closed");

    // At most `MAX_HEARTBEAT_SANDBOXES`, the most recently heard from
    // first, and never one that has expired (review of #357).
    use klav_proto::sandbox::MAX_HEARTBEAT_SANDBOXES as MAX;
    let (expired, mut extra) = (klav_core::ids::SandboxId::generate(), Vec::new());
    {
        let mut store = state.sandboxes().store.lock().await;
        let issuer_id = store.sandboxes[0].issuer_id;
        let stored = |id, expires_at, seen| crate::sandboxes::Stored {
            sandbox_id: id,
            issuer_id,
            label: "x".into(),
            profiles: Vec::new(),
            issued_at: now - 10_000,
            expires_at,
            secret_sha256: Blob::new(vec![0; 32]),
            claimed_at: Some(seen),
        };
        for i in 0..MAX + 5 {
            let id = klav_core::ids::SandboxId::generate();
            let seen = now - 1_000 - i64::try_from(i).expect("i");
            store.sandboxes.push(stored(id, now + 60_000, seen));
            extra.push(id);
        }
        store.sandboxes.push(stored(expired, now, now));
    }
    let (live, _, links) = crate::heartbeat::links(&state, now).await;
    assert!(live);
    assert_eq!(links.len(), MAX);
    let named: Vec<_> = links.iter().map(|l| l.id).collect();
    assert!(!named.contains(&expired), "expired");
    assert_eq!(named[0], started.sandbox_id, "heard from last");
    assert_eq!(named[1..], extra[..MAX - 1], "the oldest left out");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_right_secret_from_a_second_key_ends_the_sandbox_with_theft() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port, addr) = serve(proxy, clock, dir.path().join("proxy.sandbox-store")).await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");
    let first = Forwarder::new(&package, addr);
    let second = Forwarder::new(&package, addr);
    assert_eq!(first.claim(&package).await.0, 200);
    // Whoever copied the package: refused, and the sandbox ends for both,
    // with the same words, so neither learns which claim came first.
    let (status, code, lost) = second.claim(&package).await;
    assert_eq!((status, code.as_str()), (401, "klav_sandbox_revoked"));
    let (status, code, kept) = first.status().await;
    assert_eq!((status, code.as_str()), (401, "klav_sandbox_revoked"));
    assert_eq!(lost, kept);
    assert_eq!(
        kept["message"],
        crate::errors::ended_message(klav_proto::sandbox::SandboxEnd::Theft)
    );
    assert_eq!(state.sandboxes().live().await, 0);
    assert_eq!(state.sandboxes().unsent().await, 0);
    assert_eq!(
        actions(&mut ana).await,
        ["sandbox.issued", "sandbox.claimed", "sandbox.revoked"]
    );
    assert_eq!(ends(&mut ana).await, [Some("theft".to_owned())]);
    // The person's list names it as a theft (the CLI's plain list and
    // `klav proxy status` say it as a security warning).
    let list = ana.sandbox_list().await.expect("list");
    let thefts: Vec<_> = list.thefts().iter().map(|r| r.sandbox_id).collect();
    assert_eq!(thefts, [started.sandbox_id]);
}

/// The words a key that was never bound gets: the same for an unknown
/// sandbox, a wrong secret and an ended one.
const NOT_BOUND: &str = "This sandbox's access to Klav's credential proxy has ended: it was stopped, revoked, or its one-time package was already used.";

/// An ended sandbox's own key is told why it ended (papercut 4): stopped by
/// its issuer, released, or its time over (`klav_sandbox_expired`, exit 6
/// in `klav-forward`, once the sweep ended it too). Any other key, the
/// claim of an ended sandbox with its right secret among them, gets the
/// words it always got.
#[tokio::test(flavor = "multi_thread")]
async fn an_ended_sandbox_tells_its_own_key_why_and_no_other() {
    use klav_proto::sandbox::SandboxEnd;
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (_ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port, addr) = serve(
        proxy,
        Arc::clone(&clock),
        dir.path().join("proxy.sandbox-store"),
    )
    .await;
    // One at a time: the issuer's `max_live` is below three.
    macro_rules! claimed {
        ($label:expr) => {{
            let started = issuer_api::start(&mut t3, port, &request($label, &["northflank"]))
                .await
                .expect("start");
            let package = decode_package(&started.package).expect("package");
            let forwarder = Forwarder::new(&package, addr);
            assert_eq!(forwarder.claim(&package).await.0, 200);
            (started.sandbox_id, package, forwarder)
        }};
    }
    let said = |answer: (u16, String, serde_json::Value)| {
        (
            answer.0,
            answer.1,
            answer.2["message"].as_str().unwrap_or_default().to_owned(),
        )
    };

    // Stopped by its issuer.
    let (stopped, stopped_package, first) = &claimed!("stopped");
    issuer_api::stop(&t3, port, *stopped).await.expect("stop");
    assert_eq!(
        said(first.status().await),
        (
            401,
            "klav_sandbox_revoked".to_owned(),
            crate::errors::ended_message(SandboxEnd::Stop).to_owned()
        )
    );
    // Another key: never told, not even with the ended sandbox's secret.
    let stranger = Forwarder::new(stopped_package, addr);
    for answer in [
        stranger.status().await,
        stranger.claim(stopped_package).await,
    ] {
        assert_eq!(
            said(answer),
            (401, "klav_sandbox_revoked".to_owned(), NOT_BOUND.to_owned())
        );
    }

    // Released by its forwarder.
    let released = &claimed!("released").2;
    assert_eq!(released.release().await.0, 200);
    assert_eq!(
        said(released.status().await).2,
        crate::errors::ended_message(SandboxEnd::Released)
    );

    // Past its time: `expired` before the sweep, and after it too.
    let late = &claimed!("expired").2;
    clock
        .0
        .fetch_add(25 * 3_600_000, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(late.status().await.1, "klav_sandbox_expired");
    sweep(&state).await;
    assert_eq!(state.sandboxes().live().await, 0);
    assert_eq!(
        said(late.status().await),
        (
            401,
            "klav_sandbox_expired".to_owned(),
            crate::errors::ended_message(SandboxEnd::Ttl).to_owned()
        )
    );
}

/// The person pauses the agents: the sandbox's own status says so with
/// `423 klav_agents_paused` (`klav-forward status` exits 7, as its help
/// says: papercut 5), the sandbox stays live, and after the resume its
/// status is live again. The proxy learns it from its next signed request,
/// here the grant's refresh.
#[tokio::test(flavor = "multi_thread")]
async fn a_paused_proxy_says_so_to_its_sandboxes_status() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port, addr) = serve(
        proxy,
        Arc::clone(&clock),
        dir.path().join("proxy.sandbox-store"),
    )
    .await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");
    let forwarder = Forwarder::new(&package, addr);
    assert_eq!(forwarder.claim(&package).await.0, 200);
    assert_eq!(forwarder.status().await.0, 200);

    ana.pause_agents(None, 0).await.expect("pause");
    assert!(state.refresh().await.is_err(), "the server refuses it");
    let (status, code, body) = forwarder.status().await;
    assert_eq!(
        (status, code.as_str()),
        (423, "klav_agents_paused"),
        "{body}"
    );
    assert_eq!(state.sandboxes().live().await, 1, "a pause ends nothing");
    // A long pause: a status answered 423 still counts as activity, so the
    // sweep does not end the sandbox for an hour without a connection.
    let forty_minutes = 40 * 60_000;
    for _ in 0..2 {
        clock
            .0
            .fetch_add(forty_minutes, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(forwarder.status().await.0, 423);
    }
    clock
        .0
        .fetch_add(forty_minutes, std::sync::atomic::Ordering::SeqCst);
    sweep(&state).await;
    assert_eq!(state.sandboxes().live().await, 1, "two hours paused");

    ana.resume_agents(None).await.expect("resume");
    state.refresh().await.expect("refresh");
    let (status, _, body) = forwarder.status().await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["sandbox_id"], started.sandbox_id.to_string());
}

/// The server does not answer a claim: whether it logged it is unknown,
/// so the key stays on record and only it may claim again. Another key
/// with the secret meanwhile is theft, and the end goes after the claim
/// that the server may lack.
#[tokio::test(flavor = "multi_thread")]
async fn a_claim_the_server_may_have_logged_holds_its_key_and_theft_logs_it_first() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let store = dir.path().join("proxy.sandbox-store");
    let (state, port, addr) = serve(proxy, clock, store.clone()).await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");
    let first = Forwarder::new(&package, addr);

    server.stop();
    let (status, code, _) = first.claim(&package).await;
    assert_eq!((status, code.as_str()), (503, "klav_server_unreachable"));
    // Recorded before it asked, and kept: the server may have it.
    let channels: serde_json::Value =
        serde_json::from_slice(&std::fs::read(crate::claims::path_of(&store)).expect("channels"))
            .expect("json");
    assert_eq!(channels["channels"][0]["logged"], false);
    // Not bound yet: the key cannot use the sandbox.
    assert_eq!(first.status().await.1, "klav_sandbox_revoked");

    // A second key with the right secret: theft, ended here at once; its
    // end waits for the server with the first key's claim before it.
    let second = Forwarder::new(&package, addr);
    assert_eq!(second.claim(&package).await.1, "klav_sandbox_revoked");
    assert_eq!(state.sandboxes().live().await, 0);
    assert_eq!(state.sandboxes().unsent().await, 1);
    // The first key comes back: the sandbox is gone for it too.
    assert_eq!(first.claim(&package).await.1, "klav_sandbox_revoked");

    server.restart();
    sweep(&state).await;
    assert_eq!(state.sandboxes().unsent().await, 0);
    assert_eq!(
        actions(&mut ana).await,
        ["sandbox.issued", "sandbox.claimed", "sandbox.revoked"]
    );
    assert_eq!(ends(&mut ana).await, [Some("theft".to_owned())]);
    // Nothing left on record once the end is in.
    let channels: serde_json::Value =
        serde_json::from_slice(&std::fs::read(crate::claims::path_of(&store)).expect("channels"))
            .expect("json");
    assert_eq!(channels["channels"], serde_json::json!([]));
}

/// The same lost answer, then the same key once the server is back: the
/// claim completes (the server logged it once), and the secret was never
/// spent by a refusal.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_key_finishes_a_claim_whose_answer_was_lost() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port, addr) = serve(proxy, clock, dir.path().join("proxy.sandbox-store")).await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");
    let forwarder = Forwarder::new(&package, addr);
    server.stop();
    assert_eq!(forwarder.claim(&package).await.0, 503);
    server.restart();
    assert_eq!(forwarder.claim(&package).await.0, 200);
    assert_eq!(forwarder.status().await.0, 200);
    assert!(state.sandboxes().views().await[0].claimed);
    assert_eq!(
        actions(&mut ana).await,
        ["sandbox.issued", "sandbox.claimed"]
    );
}

/// A claim the server refuses logs nothing and spends nothing: paused, the
/// claim fails with the pause; resumed, the same secret claims from
/// another key, since no key was ever logged.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_claim_spends_nothing() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (_state, port, addr) = serve(proxy, clock, dir.path().join("proxy.sandbox-store")).await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");
    ana.pause_agents(None, 0).await.expect("pause");
    let (status, code, _) = Forwarder::new(&package, addr).claim(&package).await;
    assert_eq!((status, code.as_str()), (423, "klav_agents_paused"));
    ana.resume_agents(None).await.expect("resume");
    assert_eq!(Forwarder::new(&package, addr).claim(&package).await.0, 200);
    assert_eq!(
        actions(&mut ana).await,
        ["sandbox.issued", "sandbox.claimed"]
    );
}

/// Claimed and then silent for an hour: `inactivity`. A call within the
/// hour keeps it alive.
#[tokio::test(flavor = "multi_thread")]
async fn a_claimed_sandbox_silent_for_an_hour_ends_with_inactivity() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port, addr) = serve(
        proxy,
        Arc::clone(&clock),
        dir.path().join("proxy.sandbox-store"),
    )
    .await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");
    let forwarder = Forwarder::new(&package, addr);
    assert_eq!(forwarder.claim(&package).await.0, 200);
    let advance = |ms: i64| {
        clock.0.fetch_add(ms, std::sync::atomic::Ordering::SeqCst);
    };
    advance(INACTIVITY_MS - 60_000);
    assert_eq!(forwarder.status().await.0, 200);
    advance(INACTIVITY_MS - 60_000);
    assert_eq!(sweep(&state).await, 0);
    advance(60_001);
    assert_eq!(sweep(&state).await, 1);
    assert_eq!(forwarder.status().await.1, "klav_sandbox_revoked");
    assert_eq!(ends(&mut ana).await, [Some("inactivity".to_owned())]);
}

/// The server out of reach while sandboxes are live: neither the grant
/// nor `me` can be refreshed, the last list of gone issuers stays as it
/// was, and nothing ends because of it (review of #298).
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_me_keeps_the_last_gone_list_and_ends_nothing() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port, addr) = serve(proxy, clock, dir.path().join("proxy.sandbox-store")).await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");
    let forwarder = Forwarder::new(&package, addr);
    assert_eq!(forwarder.claim(&package).await.0, 200);
    // A list from before that names some other agent, not this issuer.
    let someone = klav_core::ids::AgentId::generate();
    state.set_gone_issuers(vec![someone]);

    server.stop();
    assert!(state.refresh_gone_issuers().await.is_err());
    assert!(state.refresh().await.is_err(), "the grant cannot refresh");
    assert_eq!(state.gone_issuers(), [someone]);
    assert_eq!(sweep(&state).await, 0);
    assert_eq!(state.sandboxes().live().await, 1);
    assert_eq!(forwarder.status().await.0, 200);

    server.restart();
    state.refresh().await.expect("refresh");
    assert!(state.gone_issuers().is_empty(), "the server's list again");
    assert_eq!(sweep(&state).await, 0);
    assert_eq!(forwarder.status().await.0, 200);
    assert_eq!(
        actions(&mut ana).await,
        ["sandbox.issued", "sandbox.claimed"]
    );
}

/// A client that reaches the fake provider `upstream.test` on loopback.
pub(crate) fn upstream_client() -> reqwest::Client {
    let lookup = crate::net::tests::FakeLookup::new(&[(
        "upstream.test",
        &["127.0.0.1".parse::<std::net::IpAddr>().expect("ip")],
    )]);
    crate::net::test_client(
        lookup,
        vec!["127.0.0.1".parse().expect("ip")],
        include_bytes!("../tests/fixtures/ca.der"),
    )
    .expect("client")
}

/// The sandbox's calls go to its profiles through the channel, as mode (a)
/// does on this machine: the credential reaches the provider and never the
/// sandbox. Another
/// profile, a stopped sandbox and a revoked issuer are refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_claimed_sandbox_calls_its_profiles_through_the_channel() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let upstream = crate::e2e_tests::Upstream::start().await;
    let mut spec = credential_at(
        "northflank",
        &format!("https://upstream.test:{}", upstream.port),
    );
    spec.rate_per_minute = Some(1000);
    let (mut ana, proxy, mut t3) = setup_with(&server, &dir, spec).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port, addr) = serve_through(
        proxy,
        clock,
        dir.path().join("proxy.sandbox-store"),
        upstream_client(),
    )
    .await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");
    let forwarder = Forwarder::new(&package, addr);

    // Not claimed: no call.
    let (status, code, _) = forwarder
        .send(reqwest::Method::GET, "/northflank/v1/projects", Vec::new())
        .await;
    assert_eq!((status, code.as_str()), (401, "klav_sandbox_revoked"));
    assert_eq!(forwarder.claim(&package).await.0, 200);

    // A call: the provider gets the token, the sandbox gets the answer
    // with the token redacted, even when the provider echoes it.
    let res = forwarder
        .http
        .get(format!("{}/northflank/v1/echo", forwarder.base))
        .header("authorization", "Bearer klav-placeholder")
        .send()
        .await
        .expect("answer");
    assert_eq!(res.status(), 200);
    let echoed = res.headers()["x-echo"].to_str().expect("ascii").to_owned();
    let body = res.text().await.expect("body");
    assert!(!echoed.contains("token-0123456789") && !body.contains("token-0123456789"));
    let seen = upstream.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].target, "/v1/echo");
    assert_eq!(
        seen[0].header("authorization"),
        Some("Bearer token-0123456789")
    );

    // The access is logged, and the chain (whose `agent.access` body now
    // names the sandbox) verifies. That the body names it is what the
    // revoked-issuer test below shows: the server bars the call.
    ana.verify_audit().await.expect("the chain verifies");
    let accesses: Vec<_> = ana
        .audit_log(&klav_client::audit::LogFilter::default())
        .await
        .expect("log")
        .into_iter()
        .filter(|l| l.action == "agent.access")
        .collect();
    assert_eq!(accesses.len(), 1);

    // A profile the sandbox was not started with.
    let (status, code, _) = forwarder
        .send(reqwest::Method::GET, "/maple/v1/projects", Vec::new())
        .await;
    assert_eq!((status, code.as_str()), (403, "klav_not_allowed"));

    // Sixty calls a minute per sandbox, whatever the profile allows.
    for _ in 0..59 {
        let (status, _, _) = forwarder
            .send(reqwest::Method::GET, "/northflank/v1/projects", Vec::new())
            .await;
        assert_eq!(status, 200);
    }
    let (status, code, body) = forwarder
        .send(reqwest::Method::GET, "/northflank/v1/projects", Vec::new())
        .await;
    assert_eq!(
        (status, code.as_str()),
        (429, "klav_rate_limited"),
        "{body}"
    );
    assert!(body["retry_after"].as_u64().is_some());
    drop(state);
}

/// The server bars a sandbox whose issuer it no longer counts, before the
/// proxy hears of it: the call gets `klav_sandbox_revoked`, nothing is
/// decrypted, and the sandbox ends at the proxy's next refresh and sweep.
#[tokio::test(flavor = "multi_thread")]
async fn the_server_bars_a_sandbox_of_a_revoked_issuer_before_the_proxy_knows() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let upstream = crate::e2e_tests::Upstream::start().await;
    let spec = credential_at(
        "northflank",
        &format!("https://upstream.test:{}", upstream.port),
    );
    let (mut ana, proxy, mut t3) = setup_with(&server, &dir, spec).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port, addr) = serve_through(
        proxy,
        clock,
        dir.path().join("proxy.sandbox-store"),
        upstream_client(),
    )
    .await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");
    let forwarder = Forwarder::new(&package, addr);
    assert_eq!(forwarder.claim(&package).await.0, 200);
    assert_eq!(
        forwarder
            .send(reqwest::Method::GET, "/northflank/v1/projects", Vec::new())
            .await
            .0,
        200
    );

    ana.revoke_agent(t3.id(), false).await.expect("revoke");
    let (status, code, _) = forwarder
        .send(reqwest::Method::GET, "/northflank/v1/projects", Vec::new())
        .await;
    assert_eq!((status, code.as_str()), (401, "klav_sandbox_revoked"));
    assert_eq!(
        upstream.requests().len(),
        1,
        "the provider saw only the first"
    );
    state.refresh().await.expect("refresh");
    assert_eq!(sweep(&state).await, 1);
    assert_eq!(forwarder.status().await.1, "klav_sandbox_revoked");
    assert_eq!(ends(&mut ana).await, [Some("issuer_removed".to_owned())]);
}

/// Review of #449, item 1: the person pauses one issuer. Its sandbox's
/// calls get `klav_agents_paused` from the server, but the proxy itself is
/// not paused: another issuer's sandbox still reads live on its status,
/// before and after the grant's refresh.
#[tokio::test(flavor = "multi_thread")]
async fn a_paused_issuer_never_reads_as_a_paused_proxy() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let upstream = crate::e2e_tests::Upstream::start().await;
    let spec = credential_at(
        "northflank",
        &format!("https://upstream.test:{}", upstream.port),
    );
    let (mut ana, proxy, mut t3) = setup_with(&server, &dir, spec).await;
    let mut builder =
        crate::sandbox_e2e_tests::second_issuer(&server, &dir, &mut ana, "builder").await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port, addr) = serve_through(
        proxy,
        clock,
        dir.path().join("proxy.sandbox-store"),
        upstream_client(),
    )
    .await;
    let mut forwarders = Vec::new();
    for (issuer, label) in [(&mut t3, "chat-1"), (&mut builder, "build-1")] {
        let started = issuer_api::start(issuer, port, &request(label, &["northflank"]))
            .await
            .expect("start");
        let package = decode_package(&started.package).expect("package");
        let forwarder = Forwarder::new(&package, addr);
        assert_eq!(forwarder.claim(&package).await.0, 200);
        forwarders.push(forwarder);
    }
    let (paused, other) = (&forwarders[0], &forwarders[1]);

    ana.pause_agents(Some(t3.id()), 0)
        .await
        .expect("pause one issuer");
    let (status, code, _) = paused
        .send(reqwest::Method::GET, "/northflank/v1/projects", Vec::new())
        .await;
    assert_eq!((status, code.as_str()), (423, "klav_agents_paused"));
    let (status, _, body) = other.status().await;
    assert_eq!(status, 200, "{body}");
    state.refresh().await.expect("the proxy is not paused");
    let (status, _, body) = other.status().await;
    assert_eq!(status, 200, "{body}");
    assert!(
        upstream.requests().is_empty(),
        "the paused call went nowhere"
    );
}

/// Review of #304, item 1: the server logged the first key's claim but its
/// answer was lost; the retry is refused (here, the person paused the
/// agents, which the server checks before it looks at the claim). The
/// refused retry keeps the key on record, so another key with the secret
/// is theft, never a new binding.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_retry_after_a_lost_answer_keeps_the_key_and_another_key_is_theft() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let store = dir.path().join("proxy.sandbox-store");
    let (state, port, addr) = serve(proxy, clock, store.clone()).await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");
    let first = Forwarder::new(&package, addr);

    // The claim reaches the server and is logged; its answer is lost.
    // (Played in two steps: the attempt meets a stopped server, which
    // leaves the key on record and unlogged, then the server logs that
    // key's claim, as it would have.)
    server.stop();
    assert_eq!(first.claim(&package).await.0, 503);
    server.restart();
    let first_key: [u8; 32] = state.sandboxes().store.lock().await.channels[0]
        .channel_key_sha256
        .as_bytes()
        .try_into()
        .expect("32 bytes");
    crate::claims::post_claim(&state, package.sandbox_id, first_key)
        .await
        .expect("the server logs the first key's claim");

    // The retry is refused: the key stays on record.
    ana.pause_agents(None, 0).await.expect("pause");
    let (status, code, _) = first.claim(&package).await;
    assert_eq!((status, code.as_str()), (423, "klav_agents_paused"));
    let channels: serde_json::Value =
        serde_json::from_slice(&std::fs::read(crate::claims::path_of(&store)).expect("channels"))
            .expect("json");
    assert_eq!(channels["channels"].as_array().map(Vec::len), Some(1));
    ana.resume_agents(None).await.expect("resume");

    // Another key with the secret: theft, not a binding.
    let second = Forwarder::new(&package, addr);
    let (status, code, _) = second.claim(&package).await;
    assert_eq!((status, code.as_str()), (401, "klav_sandbox_revoked"));
    assert_eq!(second.status().await.1, "klav_sandbox_revoked");
    assert_eq!(state.sandboxes().live().await, 0);
    sweep(&state).await;
    assert_eq!(state.sandboxes().unsent().await, 0);
    assert_eq!(
        actions(&mut ana).await,
        ["sandbox.issued", "sandbox.claimed", "sandbox.revoked"]
    );
    assert_eq!(ends(&mut ana).await, [Some("theft".to_owned())]);
}

/// Review of #304, item 1, second part: the server holds a claim from a
/// key the proxy has no record of (here, logged behind its back; in life,
/// a channels file lost after a lost answer). A key recorded by this very
/// attempt that meets `409 sandbox_claimed` is theft.
#[tokio::test(flavor = "multi_thread")]
async fn a_claim_the_server_holds_from_an_unrecorded_key_is_theft() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port, addr) = serve(proxy, clock, dir.path().join("proxy.sandbox-store")).await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");
    crate::claims::post_claim(&state, package.sandbox_id, [9; 32])
        .await
        .expect("a claim the proxy has no record of");
    assert!(state.sandboxes().store.lock().await.channels.is_empty());

    let forwarder = Forwarder::new(&package, addr);
    let (status, code, _) = forwarder.claim(&package).await;
    assert_eq!((status, code.as_str()), (401, "klav_sandbox_revoked"));
    assert_eq!(forwarder.status().await.1, "klav_sandbox_revoked");
    assert_eq!(state.sandboxes().live().await, 0);
    assert_eq!(state.sandboxes().unsent().await, 0);
    assert_eq!(
        actions(&mut ana).await,
        ["sandbox.issued", "sandbox.claimed", "sandbox.revoked"]
    );
    assert_eq!(ends(&mut ana).await, [Some("theft".to_owned())]);
}

/// Review of #304, item 3: a theft whose end the server no longer takes
/// (by the time it is back, the sandbox's issuer was removed) is kept in
/// the channels file and shown by `klav-proxy status`, since the proxy
/// cannot confirm the person's log has it.
#[tokio::test(flavor = "multi_thread")]
async fn a_theft_the_server_no_longer_takes_is_kept_for_status() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    // Where `klav-proxy status` reads it.
    let home = klav_client::Home::at(dir.path().join("agent-klav-proxy"));
    let store = Sandboxes::path_in(&home, "klav-proxy");
    let (state, port, addr) = serve(proxy, clock, store.clone()).await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");

    server.stop();
    assert_eq!(Forwarder::new(&package, addr).claim(&package).await.0, 503);
    let second = Forwarder::new(&package, addr);
    assert_eq!(second.claim(&package).await.1, "klav_sandbox_revoked");
    assert_eq!(state.sandboxes().unsent().await, 1);

    server.restart();
    ana.revoke_agent(t3.id(), false).await.expect("revoke");
    sweep(&state).await;
    assert_eq!(state.sandboxes().unsent().await, 0);
    let kept = state.sandboxes().unconfirmed_thefts().await;
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].sandbox_id, package.sandbox_id);
    let on_disk = crate::claims::load(&crate::claims::path_of(&store)).expect("channels");
    assert_eq!(on_disk.unconfirmed_thefts.len(), 1);
    assert!(on_disk.channels.is_empty());
    // `klav-proxy status`, another process, shows it.
    let report = crate::app::status(&home, "klav-proxy", &crate::app::StartEnv::default())
        .await
        .expect("status");
    assert_eq!(report.unconfirmed_thefts.len(), 1);
    assert_eq!(report.unconfirmed_thefts[0].sandbox_id, package.sandbox_id);
    let shown = serde_json::to_value(&report).expect("json");
    assert_eq!(
        shown["unconfirmed_thefts"][0]["sandbox_id"],
        package.sandbox_id.to_string()
    );
    assert_eq!(actions(&mut ana).await, ["sandbox.issued"]);
}

/// The other reading of the same answer: the server logged the theft and
/// the proxy lost its answer, so the retry meets "already ended". The proxy
/// cannot tell the two apart, so it lists this one as unconfirmed too; the
/// person's log has it.
#[tokio::test(flavor = "multi_thread")]
async fn a_theft_logged_behind_a_lost_answer_is_listed_as_unconfirmed() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port, addr) = serve(proxy, clock, dir.path().join("proxy.sandbox-store")).await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");

    server.stop();
    assert_eq!(Forwarder::new(&package, addr).claim(&package).await.0, 503);
    assert_eq!(
        Forwarder::new(&package, addr).claim(&package).await.1,
        "klav_sandbox_revoked"
    );
    server.restart();
    // The flush's claim and end reach the server; their answers are lost.
    crate::claims::log_pending_claim(&state, package.sandbox_id)
        .await
        .expect("claim");
    state
        .post_signed(
            &klav_proto::sandbox::sandbox_path(
                package.sandbox_id,
                klav_proto::sandbox::SUFFIX_REVOKED,
            ),
            &klav_proto::sandbox::SandboxRevoked::new(klav_proto::sandbox::SandboxEnd::Theft),
        )
        .await
        .expect("end");
    sweep(&state).await;
    assert_eq!(state.sandboxes().unsent().await, 0);
    assert_eq!(state.sandboxes().unconfirmed_thefts().await.len(), 1);
    assert_eq!(ends(&mut ana).await, [Some("theft".to_owned())]);
}

/// A raw TLS connection to the channel with a fresh key, to send bytes as
/// slowly as an attacker would.
pub(crate) struct Raw {
    io: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
}

impl Raw {
    /// A fresh key.
    async fn connect(pin: [u8; 32], addr: SocketAddr) -> Self {
        Self::with(&key(pin), addr).await
    }

    /// The key of `config`.
    pub(crate) async fn with(config: &Arc<rustls::ClientConfig>, addr: SocketAddr) -> Self {
        Self::named(
            config,
            addr,
            rustls::pki_types::ServerName::try_from("klav-proxy").expect("name"),
        )
        .await
        .expect("handshake")
    }

    /// [`Raw::with`], sending `name` as SNI; `None` when the handshake
    /// fails (Klav Cloud's enclave routes by SNI, ADR 0051 §3.4).
    pub(crate) async fn named(
        config: &Arc<rustls::ClientConfig>,
        addr: SocketAddr,
        name: rustls::pki_types::ServerName<'static>,
    ) -> Option<Self> {
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("tcp");
        let mut io = tokio_rustls::TlsConnector::from(Arc::clone(config))
            .connect(name, tcp)
            .await
            .ok()?;
        // In TLS 1.3 a refused client key or a server that found no key
        // for the name shows on the first round trip: flush and peek.
        use tokio::io::AsyncWriteExt;
        io.flush().await.ok()?;
        Some(Self { io })
    }

    pub(crate) async fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        self.io.write_all(bytes).await?;
        self.io.flush().await
    }

    /// A whole answer (head and a `content-length` body), or `None` when
    /// the connection closed or nothing came within `wait`.
    pub(crate) async fn answer(&mut self, wait: std::time::Duration) -> Option<(u16, String)> {
        self.whole(wait)
            .await
            .map(|(status, _, body)| (status, body))
    }

    /// The lowercased head of a whole answer.
    async fn head(&mut self, wait: std::time::Duration) -> Option<String> {
        self.whole(wait).await.map(|(_, head, _)| head)
    }

    pub(crate) async fn whole(
        &mut self,
        wait: std::time::Duration,
    ) -> Option<(u16, String, String)> {
        use tokio::io::AsyncReadExt;
        let read = async {
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
                    let status = head[9..12].parse().expect("status");
                    if head.contains("transfer-encoding: chunked") {
                        if let Some(body) = dechunk(&got[end + 4..]) {
                            return Some((status, head, body));
                        }
                    } else {
                        let len: usize = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .map_or(0, |v| v.trim().parse().expect("length"));
                        if got.len() >= end + 4 + len {
                            let body =
                                String::from_utf8_lossy(&got[end + 4..end + 4 + len]).into_owned();
                            return Some((status, head, body));
                        }
                    }
                }
                match self.io.read(&mut buf).await {
                    Ok(0) | Err(_) => return None,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
        };
        tokio::time::timeout(wait, read).await.ok().flatten()
    }

    /// Whether the proxy closed the connection within `wait`.
    async fn closed_within(&mut self, wait: std::time::Duration) -> bool {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 1024];
        matches!(
            tokio::time::timeout(wait, async {
                loop {
                    match self.io.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                }
            })
            .await,
            Ok(())
        )
    }
}

/// A whole chunked body, or `None` while its last chunk has not come.
fn dechunk(mut rest: &[u8]) -> Option<String> {
    let mut body = Vec::new();
    loop {
        let line = rest.windows(2).position(|w| w == b"\r\n")?;
        let size =
            usize::from_str_radix(std::str::from_utf8(&rest[..line]).expect("size").trim(), 16)
                .expect("size");
        rest = &rest[line + 2..];
        if size == 0 {
            return rest
                .starts_with(b"\r\n")
                .then(|| String::from_utf8_lossy(&body).into_owned());
        }
        if rest.len() < size + 2 {
            return None;
        }
        body.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

/// A fresh channel key pinned to `pin`, for several connections.
pub(crate) fn key(pin: [u8; 32]) -> Arc<rustls::ClientConfig> {
    Arc::new(
        klav_forward::channel::client_config(TlsSigner::channel_key(), pin).expect("client config"),
    )
}

/// A claim request, as raw HTTP.
pub(crate) fn claim_request(package: &SandboxPackage) -> Vec<u8> {
    let body = serde_json::to_vec(&serde_json::json!({
        "sandbox_id": package.sandbox_id,
        "secret": Blob::new(package.secret.expose().to_vec()).to_text(),
    }))
    .expect("json");
    let mut claim = format!(
        "POST /_klav/claim HTTP/1.1\r\nhost: klav-proxy\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    claim.extend_from_slice(&body);
    claim
}

const STATUS_REQUEST: &[u8] = b"GET /_klav/status HTTP/1.1\r\nhost: klav-proxy\r\n\r\n";

fn short_limits() -> ChannelLimits {
    ChannelLimits {
        header_read: std::time::Duration::from_secs(1),
        unbound_deadline: std::time::Duration::from_secs(3),
        shutdown_grace: std::time::Duration::from_secs(1),
        max_unbound: 2,
        ..ChannelLimits::default()
    }
}

/// Review of #304, item 2: what a peer that reached the port can hold, and
/// for how long. A stalled head, an idle connection, a connection whose
/// key never binds (even one that keeps asking), a fourth unbound
/// connection over the cap: each is closed. A bound forwarder's
/// connection is not cut by the unbound deadline or the cap.
#[tokio::test(flavor = "multi_thread")]
async fn the_channel_drops_peers_that_stall_or_never_bind() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (_ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (_state, port, addr, _stop) = serve_limited(
        proxy,
        clock,
        dir.path().join("proxy.sandbox-store"),
        reqwest::Client::new(),
        short_limits(),
        None,
    )
    .await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");
    let pin = package.proxy_pin;
    let second = std::time::Duration::from_secs(1);

    // Half a head, then silence: closed at the head deadline.
    let mut stalled = Raw::connect(pin, addr).await;
    stalled
        .send(b"GET /_klav/status HTTP/1.1\r\nhost: kla")
        .await
        .expect("send");
    assert!(stalled.closed_within(3 * second).await, "a stalled head");

    // One answer, then idle: closed at the same deadline.
    let mut idle = Raw::connect(pin, addr).await;
    idle.send(STATUS_REQUEST).await.expect("send");
    assert_eq!(idle.answer(3 * second).await.map(|a| a.0), Some(401));
    assert!(idle.closed_within(3 * second).await, "an idle connection");

    // A key that keeps asking but never binds: closed at the unbound
    // deadline, though it is never idle.
    let mut chatty = Raw::connect(pin, addr).await;
    let begun = std::time::Instant::now();
    let mut answered = 0;
    while begun.elapsed() < 10 * second && chatty.send(STATUS_REQUEST).await.is_ok() {
        if chatty.answer(3 * second).await.is_none() {
            break;
        }
        answered += 1;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
    let lasted = begun.elapsed();
    assert!(answered >= 3, "{answered}");
    assert!(
        lasted >= 2 * second && lasted < 8 * second,
        "closed after {lasted:?}"
    );
}

/// Review of #304, item 2, the other side: a forwarder bound to a sandbox
/// keeps its connection past the unbound deadline, and two unbound
/// connections that fill their cap never keep it out. (A long head
/// deadline here, so idle connections are not what closes.)
#[tokio::test(flavor = "multi_thread")]
async fn a_bound_forwarder_is_never_cut_or_kept_out_by_unbound_peers() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (_ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let limits = ChannelLimits {
        header_read: std::time::Duration::from_secs(60),
        ..short_limits()
    };
    let (_state, port, addr, _stop) = serve_limited(
        proxy,
        clock,
        dir.path().join("proxy.sandbox-store"),
        reqwest::Client::new(),
        limits,
        None,
    )
    .await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");
    let pin = package.proxy_pin;
    let second = std::time::Duration::from_secs(1);

    // A forwarder that claims on its connection keeps it past the
    // unbound deadline while it keeps working.
    let mut bound = Raw::connect(pin, addr).await;
    bound.send(&claim_request(&package)).await.expect("send");
    assert_eq!(bound.answer(5 * second).await.map(|a| a.0), Some(200));
    let begun = std::time::Instant::now();
    while begun.elapsed() < 5 * second {
        bound.send(STATUS_REQUEST).await.expect("still open");
        assert_eq!(bound.answer(3 * second).await.map(|a| a.0), Some(200));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }

    // Two unbound connections fill their cap: a third closes the oldest
    // (review of #304, F5: holding the slots takes a steady stream), and
    // the bound forwarder still gets in.
    let mut oldest = Raw::connect(pin, addr).await;
    oldest.send(STATUS_REQUEST).await.expect("send");
    assert_eq!(oldest.answer(second).await.map(|a| a.0), Some(401));
    let mut middle = Raw::connect(pin, addr).await;
    middle.send(STATUS_REQUEST).await.expect("send");
    assert_eq!(middle.answer(second).await.map(|a| a.0), Some(401));
    let mut newest = Raw::connect(pin, addr).await;
    newest.send(STATUS_REQUEST).await.expect("send");
    assert_eq!(newest.answer(second).await.map(|a| a.0), Some(401));
    assert!(oldest.closed_within(second).await, "the oldest is evicted");
    middle.send(STATUS_REQUEST).await.expect("send");
    assert_eq!(middle.answer(second).await.map(|a| a.0), Some(401));
    bound.send(STATUS_REQUEST).await.expect("bound still open");
    assert_eq!(bound.answer(3 * second).await.map(|a| a.0), Some(200));
}

/// Review of #304, N1: the connection that made the claim leaves the
/// unbound queue with its `200`, not at the next recheck, so peers that
/// fill the queue right after can never evict it.
#[tokio::test(flavor = "multi_thread")]
async fn the_claiming_connection_cannot_be_evicted_right_after_its_claim() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (_ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    // Only eviction could close it: every other deadline is far away.
    let limits = ChannelLimits {
        header_read: std::time::Duration::from_secs(60),
        unbound_deadline: std::time::Duration::from_secs(60),
        bound_recheck: std::time::Duration::from_secs(60),
        ..short_limits()
    };
    let (_state, port, addr, _stop) = serve_limited(
        proxy,
        clock,
        dir.path().join("proxy.sandbox-store"),
        reqwest::Client::new(),
        limits,
        None,
    )
    .await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");
    let second = std::time::Duration::from_secs(1);
    let mut forwarder = Raw::connect(package.proxy_pin, addr).await;
    forwarder
        .send(&claim_request(&package))
        .await
        .expect("send");
    assert_eq!(forwarder.answer(5 * second).await.map(|a| a.0), Some(200));
    // Throwaway keys fill the unbound queue and one more.
    let mut peers = Vec::new();
    for _ in 0..=limits.max_unbound {
        let mut peer = Raw::connect(package.proxy_pin, addr).await;
        peer.send(STATUS_REQUEST).await.expect("send");
        assert_eq!(peer.answer(second).await.map(|a| a.0), Some(401));
        peers.push(peer);
    }
    assert!(
        peers[0].closed_within(2 * second).await,
        "a peer is evicted"
    );
    forwarder.send(STATUS_REQUEST).await.expect("still open");
    assert_eq!(forwarder.answer(3 * second).await.map(|a| a.0), Some(200));
}

/// Review of #304, F1: one sandbox's key holds at most `max_per_key`
/// connections, so it cannot take every slot; and once its sandbox ends
/// (here, its issuer stops it), every connection of the key closes within
/// the recheck, though it keeps asking.
#[tokio::test(flavor = "multi_thread")]
async fn a_key_has_its_own_cap_and_loses_its_connections_when_its_sandbox_ends() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (_ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let limits = ChannelLimits {
        header_read: std::time::Duration::from_secs(60),
        unbound_deadline: std::time::Duration::from_secs(60),
        bound_recheck: std::time::Duration::from_secs(1),
        max_per_key: 2,
        ..short_limits()
    };
    let (_state, port, addr, _stop) = serve_limited(
        proxy,
        clock,
        dir.path().join("proxy.sandbox-store"),
        reqwest::Client::new(),
        limits,
        None,
    )
    .await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");
    let second = std::time::Duration::from_secs(1);
    let mine = key(package.proxy_pin);
    let mut first = Raw::with(&mine, addr).await;
    first.send(&claim_request(&package)).await.expect("send");
    assert_eq!(first.answer(5 * second).await.map(|a| a.0), Some(200));
    let mut again = Raw::with(&mine, addr).await;
    again.send(STATUS_REQUEST).await.expect("send");
    assert_eq!(again.answer(second).await.map(|a| a.0), Some(200));
    // A third connection of the same key: closed.
    let mut third = Raw::with(&mine, addr).await;
    let _ = third.send(STATUS_REQUEST).await;
    assert_eq!(third.answer(second).await, None, "over the key's cap");
    // Another key still gets in.
    let mut other = Raw::connect(package.proxy_pin, addr).await;
    other.send(STATUS_REQUEST).await.expect("send");
    assert_eq!(other.answer(second).await.map(|a| a.0), Some(401));

    issuer_api::stop(&t3, port, started.sandbox_id)
        .await
        .expect("stop");
    let begun = std::time::Instant::now();
    for conn in [&mut first, &mut again] {
        while begun.elapsed() < 10 * second && conn.send(STATUS_REQUEST).await.is_ok() {
            if conn.answer(3 * second).await.is_none() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }
    assert!(
        begun.elapsed() < 5 * second,
        "closed after {:?}",
        begun.elapsed()
    );
}

/// Review of #304, item 2: an answer the proxy works on for longer than
/// the head deadline (an approval it waits for, a slow provider) is never
/// cut by it.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_slower_than_the_head_deadline_still_arrives() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (_ana, proxy, _t3) = setup(&server, &dir).await;
    let pin = klav_core::crypto::sandbox::proxy_pin(proxy.public_identity());
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let slow = axum::Router::new().route(
        "/_test/slow",
        axum::routing::get(|| async {
            tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
            "done"
        }),
    );
    let limits = ChannelLimits {
        unbound_deadline: std::time::Duration::from_secs(60),
        ..short_limits()
    };
    let (_state, _port, addr, _stop) = serve_limited(
        proxy,
        clock,
        dir.path().join("proxy.sandbox-store"),
        reqwest::Client::new(),
        limits,
        Some(slow),
    )
    .await;
    let mut raw = Raw::connect(pin, addr).await;
    raw.send(b"GET /_test/slow HTTP/1.1\r\nhost: klav-proxy\r\n\r\n")
        .await
        .expect("send");
    assert_eq!(
        raw.answer(std::time::Duration::from_secs(5)).await,
        Some((200, "done".to_owned()))
    );
}

/// Review of #304, item 2: a claim body over 1 KiB gets `413` before the
/// proxy reads the rest; and on shutdown, a stalled connection is cut
/// after the grace instead of holding the proxy open.
#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_claim_is_refused_and_shutdown_does_not_wait_for_stalled_peers() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (_ana, proxy, _t3) = setup(&server, &dir).await;
    let pin = klav_core::crypto::sandbox::proxy_pin(proxy.public_identity());
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let limits = ChannelLimits {
        header_read: std::time::Duration::from_secs(60),
        unbound_deadline: std::time::Duration::from_secs(60),
        ..short_limits()
    };
    let (_state, _port, addr, (stop, served)) = serve_limited(
        proxy,
        clock,
        dir.path().join("proxy.sandbox-store"),
        reqwest::Client::new(),
        limits,
        None,
    )
    .await;

    // Announces 2 MiB, sends 4 KiB and waits: refused without the rest.
    let mut big = Raw::connect(pin, addr).await;
    let mut claim =
        b"POST /_klav/claim HTTP/1.1\r\nhost: klav-proxy\r\ncontent-length: 2097152\r\n\r\n"
            .to_vec();
    claim.extend_from_slice(&[b'a'; 4096]);
    big.send(&claim).await.expect("send");
    let (status, body) = big
        .answer(std::time::Duration::from_secs(3))
        .await
        .expect("an answer before the rest of the body");
    assert_eq!(status, 413);
    assert!(body.contains("klav_bad_request"), "{body}");

    // A peer stalled in the middle of a head; the proxy stops.
    let mut stalled = Raw::connect(pin, addr).await;
    stalled
        .send(b"GET /_klav/status HTTP/1.1\r\nhost: kla")
        .await
        .expect("send");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let begun = std::time::Instant::now();
    stop.send(()).expect("stop");
    tokio::time::timeout(std::time::Duration::from_secs(4), served)
        .await
        .expect("serve returns after the grace")
        .expect("task")
        .expect("served");
    assert!(begun.elapsed() < std::time::Duration::from_secs(4));
    assert!(
        stalled
            .closed_within(std::time::Duration::from_secs(2))
            .await
    );
}

/// A claimed sandbox, its proxy and a fake provider, for the tests of
/// calls through the channel (review of #306).
struct Calls {
    _server: ServerProcess,
    _dir: tempfile::TempDir,
    ana: Unlocked,
    t3: Agent,
    state: Arc<ProxyState>,
    port: u16,
    addr: SocketAddr,
    upstream: crate::e2e_tests::Upstream,
    package: SandboxPackage,
    /// The sandbox's channel key, claimed.
    key: Arc<rustls::ClientConfig>,
    /// The connection that made the claim, still open.
    claimer: Raw,
    clock: Arc<Manual>,
}

async fn calls(limits: ChannelLimits) -> Calls {
    calls_with(limits, 1000).await
}

/// [`calls`], with the profile's rate.
async fn calls_with(limits: ChannelLimits, rate_per_minute: u32) -> Calls {
    calls_configured(limits, rate_per_minute, |s| s).await
}

/// [`calls_with`], with the state changed by `configure` before it serves.
async fn calls_configured(
    limits: ChannelLimits,
    rate_per_minute: u32,
    configure: impl FnOnce(ProxyState) -> ProxyState,
) -> Calls {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let upstream = crate::e2e_tests::Upstream::start().await;
    let mut spec = credential_at(
        "northflank",
        &format!("https://upstream.test:{}", upstream.port),
    );
    spec.rate_per_minute = Some(rate_per_minute);
    spec.methods = vec!["GET".into(), "POST".into(), "DELETE".into()];
    spec.ask_methods = vec!["DELETE".into()];
    let (ana, proxy, mut t3) = setup_with(&server, &dir, spec).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port, addr, _) = serve_configured(
        proxy,
        Arc::clone(&clock),
        Sandboxes::path_in(
            &klav_client::Home::at(dir.path().join("agent-klav-proxy")),
            "klav-proxy",
        ),
        upstream_client(),
        limits,
        None,
        configure,
    )
    .await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("package");
    let key = key(package.proxy_pin);
    let mut first = Raw::with(&key, addr).await;
    first.send(&claim_request(&package)).await.expect("send");
    assert_eq!(
        first
            .answer(std::time::Duration::from_secs(5))
            .await
            .map(|a| a.0),
        Some(200)
    );
    Calls {
        _server: server,
        _dir: dir,
        ana,
        t3,
        state,
        port,
        addr,
        upstream,
        package,
        key,
        claimer: first,
        clock,
    }
}

const SECOND: std::time::Duration = std::time::Duration::from_secs(1);

/// Review of #306, F7: a provider's `Set-Cookie` never reaches a sandbox
/// (it is a credential of its own); a program on this machine still gets
/// it, as before.
#[tokio::test(flavor = "multi_thread")]
async fn a_providers_cookie_never_reaches_a_sandbox() {
    let c = calls(ChannelLimits::default()).await;
    let mut raw = Raw::with(&c.key, c.addr).await;
    raw.send(b"GET /northflank/v1/cookie HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n")
        .await
        .expect("send");
    let head = raw.head(5 * SECOND).await.expect("answer");
    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert!(!head.contains("set-cookie"), "{head}");
    assert!(!head.contains("provider-session"), "{head}");
    let local = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/northflank/v1/cookie", c.port))
        .send()
        .await
        .expect("local");
    assert!(local.headers().contains_key("set-cookie"));
}

/// Review of #306, F2: a body that stops in the middle frees its slots
/// within the body deadline; one sandbox holds at most its share of the
/// slots; and ending the sandbox frees what its stalled calls held.
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_body_holds_little_and_not_for_long() {
    let c = calls(ChannelLimits {
        bound_recheck: SECOND,
        shutdown_grace: SECOND,
        ..ChannelLimits::default()
    })
    .await;
    let all = crate::proxy::MAX_IN_FLIGHT;
    const STALLED: &[u8] =
        b"POST /northflank/v1/upload HTTP/1.1\r\nhost: 127.0.0.1:8790\r\ncontent-length: 10485760\r\n\r\nfirst bytes";

    // One stalled body, with a short deadline: it is refused and its slot
    // comes back.
    c.state.set_request_body_idle(SECOND);
    let mut one = Raw::with(&c.key, c.addr).await;
    one.send(STALLED).await.expect("send");
    let (status, body) = one.answer(4 * SECOND).await.expect("an answer");
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("klav_not_allowed"), "{body}");
    assert_eq!(c.state.free_slots(), all);

    // With a long deadline: the sandbox's share fills, and the next call
    // gets `429` while every other slot stays free for others.
    c.state.set_request_body_idle(60 * SECOND);
    let mut stalled = Vec::new();
    for _ in 0..crate::proxy::SANDBOX_IN_FLIGHT {
        let mut raw = Raw::with(&c.key, c.addr).await;
        raw.send(STALLED).await.expect("send");
        stalled.push(raw);
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(c.state.free_slots(), all - crate::proxy::SANDBOX_IN_FLIGHT);
    let mut over = Raw::with(&c.key, c.addr).await;
    over.send(STALLED).await.expect("send");
    assert_eq!(over.answer(3 * SECOND).await.map(|a| a.0), Some(429));
    assert!(c.upstream.requests().is_empty());

    // Ending the sandbox closes its connections, and the slots come back.
    issuer_api::stop(&c.t3, c.port, c.package.sandbox_id)
        .await
        .expect("stop");
    let begun = std::time::Instant::now();
    while c.state.free_slots() < all && begun.elapsed() < 10 * SECOND {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(c.state.free_slots(), all, "after {:?}", begun.elapsed());
    assert!(begun.elapsed() < 5 * SECOND, "{:?}", begun.elapsed());
}

/// Review of #306: through the channel too, an absolute-form target is
/// refused (also with a loopback `Host`, so that this check is what
/// refuses it) and a `Host` header never chooses where the call goes (one
/// that is not loopback is refused, review of #317); a
/// sandbox past its time gets `klav_sandbox_expired`.
#[tokio::test(flavor = "multi_thread")]
async fn the_channel_keeps_the_target_and_the_time() {
    let c = calls(ChannelLimits::default()).await;
    let mut raw = Raw::with(&c.key, c.addr).await;
    raw.send(
        b"GET https://evil.example/northflank/v1/projects HTTP/1.1\r\nhost: evil.example\r\n\r\n",
    )
    .await
    .expect("send");
    let (status, body) = raw.answer(5 * SECOND).await.expect("answer");
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("klav_not_allowed"), "{body}");
    // Refused by its `Host`, before the target is looked at.
    assert!(body.contains("only takes requests addressed"), "{body}");
    assert!(c.upstream.requests().is_empty());
    // The same target with the forwarder's loopback `Host`: the `Host`
    // check passes, and the absolute form is what is refused.
    raw.send(
        b"GET https://evil.example/northflank/v1/projects HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n",
    )
    .await
    .expect("send");
    let (status, body) = raw.answer(5 * SECOND).await.expect("answer");
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("klav_not_allowed"), "{body}");
    assert!(body.contains("only forwards plain requests"), "{body}");
    assert!(c.upstream.requests().is_empty());

    // A `Host` other than the forwarder's loopback one is refused (a page
    // that rebinds its name, review of #317); the forwarder's own `Host`
    // still never chooses where the call goes.
    raw.send(b"GET /northflank/v1/projects HTTP/1.1\r\nhost: evil.example\r\n\r\n")
        .await
        .expect("send");
    let (status, body) = raw.answer(5 * SECOND).await.expect("answer");
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("klav_not_allowed"), "{body}");
    assert!(c.upstream.requests().is_empty());
    raw.send(b"GET /northflank/v1/projects HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n")
        .await
        .expect("send");
    assert_eq!(raw.answer(5 * SECOND).await.map(|a| a.0), Some(200));
    let seen = c.upstream.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].header("host"),
        Some(format!("upstream.test:{}", c.upstream.port).as_str())
    );

    c.clock.0.fetch_add(
        i64::try_from(std::time::Duration::from_secs(24 * 3600).as_millis()).expect("ms"),
        std::sync::atomic::Ordering::SeqCst,
    );
    raw.send(b"GET /northflank/v1/projects HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n")
        .await
        .expect("send");
    let (status, body) = raw.answer(5 * SECOND).await.expect("answer");
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("klav_sandbox_expired"), "{body}");
    assert_eq!(c.upstream.requests().len(), 1);
}

/// Review of #306: a call in `ask` from a sandbox waits for the person
/// (`409 klav_approval_pending` with its approval), its retry checks the
/// same approval, and nothing reaches the provider.
#[tokio::test(flavor = "multi_thread")]
async fn a_sandbox_call_in_ask_waits_for_its_own_approval() {
    let mut c = calls(ChannelLimits::default()).await;
    let mut raw = Raw::with(&c.key, c.addr).await;
    let delete = b"DELETE /northflank/v1/projects/p1 HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n";
    raw.send(delete).await.expect("send");
    let (status, body) = raw.answer(10 * SECOND).await.expect("answer");
    assert_eq!(status, 409, "{body}");
    let pending: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(pending["error"], "klav_approval_pending");
    let from_sandbox = pending["approval_id"].as_str().expect("id").to_owned();
    // The retry checks the same approval.
    raw.send(delete).await.expect("send");
    let (_, body) = raw.answer(10 * SECOND).await.expect("answer");
    let again: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(again["approval_id"], from_sandbox.as_str());
    assert!(c.upstream.requests().is_empty());
    // Whether this machine or another sandbox gets its own request is the
    // server's to decide (its `target_key`); the server change that adds
    // the sandbox there carries that test.
    // The person sees the sandbox's request: the log verifies.
    let _ = actions(&mut c.ana).await;
}

/// Every line this test binary logs, from any thread: a sandbox's call
/// runs on the runtime's workers, where a thread's own subscriber does not
/// reach. Set once; a test reads only the lines of its own sandbox. Klav's
/// own crates log at TRACE here, so a test that looks for what must never
/// be logged sees every line.
pub(crate) fn global_log() -> &'static crate::proxy::tests::LogBuffer {
    static LOG: std::sync::OnceLock<crate::proxy::tests::LogBuffer> = std::sync::OnceLock::new();
    LOG.get_or_init(|| {
        let log = crate::proxy::tests::LogBuffer::default();
        tracing::subscriber::set_global_default(log.verbose_subscriber())
            .expect("the only global subscriber");
        log
    })
}

/// A call the server refuses for its path or its method says which, not
/// the server's wide reason, and names nothing of the rules; nothing
/// reaches the provider (papercut 9 of the rehearsal). The proxy's log
/// says that this sandbox made a call outside its profile, which profile
/// and which method, and nothing of the path, the query, a header, the
/// body or the credential.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_outside_the_rules_says_whether_the_path_or_the_method() {
    let log = global_log();
    let c = calls(ChannelLimits::default()).await;
    let mut raw = Raw::with(&c.key, c.addr).await;
    for (request, said) in [
        (
            &b"GET /northflank/v2/projects/MARKER-path?q=MARKER-query HTTP/1.1\r\nhost: 127.0.0.1:8790\r\nx-note: MARKER-header\r\n\r\n"[..],
            "This call's path is outside what the person allowed for this credential.",
        ),
        (
            &b"PATCH /northflank/v1/projects HTTP/1.1\r\nhost: 127.0.0.1:8790\r\ncontent-length: 11\r\n\r\nMARKER-body"[..],
            "This call's method is outside what the person allowed for this credential.",
        ),
    ] {
        raw.send(request).await.expect("send");
        let (status, body) = raw.answer(10 * SECOND).await.expect("answer");
        assert_eq!(status, 403, "{body}");
        let refused: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(refused["error"], "klav_not_allowed", "{body}");
        assert_eq!(refused["message"], said, "{body}");
    }
    assert!(c.upstream.requests().is_empty());
    let sandbox = format!("sandbox=\"{}\"", c.package.sandbox_id);
    let text = log.text();
    let lines: Vec<&str> = text.lines().filter(|l| l.contains(&sandbox)).collect();
    // The capture works: both calls' `proxied call` lines are there.
    let proxied = lines
        .iter()
        .filter(|l| {
            l.contains("proxied call") && l.contains("status=403 error=\"klav_not_allowed\"")
        })
        .count();
    assert_eq!(proxied, 2, "{lines:#?}");
    let outside: Vec<&&str> = lines
        .iter()
        .filter(|l| l.contains(" WARN ") && l.contains("a call outside its profile was refused"))
        .collect();
    assert_eq!(outside.len(), 2, "{lines:#?}");
    for (line, (method, part)) in outside.iter().zip([("GET", "path"), ("PATCH", "method")]) {
        assert!(line.contains(&format!(" method={method} ")), "{line}");
        assert!(line.contains(" profile=\"northflank\" "), "{line}");
        assert!(
            line.ends_with(&format!(" error=\"denied\" outside=\"{part}\"")),
            "{line}"
        );
    }
    for line in &lines {
        for never in [
            "MARKER",
            "projects",
            "/v",
            "token-0123456789",
            "upstream.test",
        ] {
            assert!(!line.contains(never), "{never}: {line}");
        }
    }
}

/// T149, Omar's answer (ADR 0036 E9): the proxy redacts only the whole
/// value. A sandbox that makes the provider echo a guess gets the same
/// answer for a right guess as for a wrong one (status, headers, length,
/// body), so nothing tells it which guess is part of the value; the person
/// sees the count, in `klav-proxy status`. The whole value is still
/// redacted.
#[tokio::test(flavor = "multi_thread")]
async fn a_guessed_piece_comes_back_as_it_was_and_only_the_person_counts_it() {
    const VALUE: &str = "token-0123456789";
    let c = calls(ChannelLimits::default()).await;
    let mut raw = Raw::with(&c.key, c.addr).await;
    let ask = |guess: &str| {
        format!("GET /northflank/v1/reflect/{guess} HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n")
    };
    let without_date = |head: String| -> String {
        head.lines()
            .filter(|l| !l.starts_with("date:"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let (right, wrong) = (&VALUE[..12], "token-01234x");
    raw.send(ask(right).as_bytes()).await.expect("send");
    let (status, head, body) = raw.whole(5 * SECOND).await.expect("answer");
    raw.send(ask(wrong).as_bytes()).await.expect("send");
    let (status_wrong, head_wrong, body_wrong) = raw.whole(5 * SECOND).await.expect("answer");
    assert_eq!(status, 404);
    assert!(body.contains(right), "{body}");
    assert!(
        head.contains(&format!("x-route: /v1/reflect/{right}")),
        "{head}"
    );
    assert_eq!(status, status_wrong);
    assert_eq!(body.replace(right, wrong), body_wrong);
    assert_eq!(
        without_date(head).replace(right, wrong),
        without_date(head_wrong)
    );

    // The person's count: one answer with a piece (in its header and its
    // body), none redacted.
    let begun = std::time::Instant::now();
    while c.state.partial_matches("northflank") == 0 && begun.elapsed() < 5 * SECOND {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(c.state.partial_matches("northflank"), 2);
    assert_eq!(c.state.redactions("northflank"), 0);

    // The whole value is redacted in the header and the body.
    raw.send(ask(VALUE).as_bytes()).await.expect("send");
    let (_, head, body) = raw.whole(5 * SECOND).await.expect("answer");
    for shown in [&head, &body] {
        assert!(!shown.contains(VALUE), "{shown}");
        assert!(
            shown.contains(&klav_sdk::actions::REDACTED.to_ascii_lowercase())
                || shown.contains(klav_sdk::actions::REDACTED),
            "{shown}"
        );
    }
    let begun = std::time::Instant::now();
    while c.state.redactions("northflank") < 2 && begun.elapsed() < 5 * SECOND {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(c.state.redactions("northflank"), 2);
    assert_eq!(c.state.partial_matches("northflank"), 2);

    // `klav-proxy status`, another process, reads the counts from disk.
    let home = klav_client::Home::at(c._dir.path().join("agent-klav-proxy"));
    let begun = std::time::Instant::now();
    let counted = loop {
        let report = crate::app::status(&home, "klav-proxy", &crate::app::StartEnv::default())
            .await
            .expect("status");
        let counted = report
            .redactions
            .and_then(|r| r.profiles.get("northflank").copied())
            .unwrap_or_default();
        if counted.redacted == 2 || begun.elapsed() > 5 * SECOND {
            break counted;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    };
    assert_eq!(
        counted,
        crate::counts::ProfileCounts {
            redacted: 2,
            partial: 2
        }
    );
}

/// Review of #304, N1, with calls: a call already in flight on the
/// connection that made the claim is never cut by peers that fill the
/// unbound queue right after; its answer arrives.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_in_flight_on_the_claiming_connection_survives_a_flood() {
    let mut c = calls(ChannelLimits {
        header_read: 60 * SECOND,
        unbound_deadline: 60 * SECOND,
        bound_recheck: 60 * SECOND,
        ..short_limits()
    })
    .await;
    c.claimer
        .send(b"GET /northflank/v1/slow HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n")
        .await
        .expect("send");
    let mut peers = Vec::new();
    for _ in 0..=short_limits().max_unbound {
        let mut peer = Raw::connect(c.package.proxy_pin, c.addr).await;
        peer.send(STATUS_REQUEST).await.expect("send");
        assert_eq!(peer.answer(SECOND).await.map(|a| a.0), Some(401));
        peers.push(peer);
    }
    let (status, body) = c.claimer.answer(5 * SECOND).await.expect("the answer");
    assert_eq!((status, body.as_str()), (200, "slow"));
    assert_eq!(c.upstream.requests().len(), 1);
}

/// Review of #306, N2: a sandbox that ends while its call waits for the
/// server never gets the value injected: the call is refused after the
/// access, and the provider sees nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_sandbox_stopped_during_its_access_gets_nothing_injected() {
    let mut c = calls(ChannelLimits::default()).await;
    let (reached, go) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    c.state
        .hold_after_access(Arc::clone(&reached), Arc::clone(&go));
    c.claimer
        .send(b"GET /northflank/v1/projects HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n")
        .await
        .expect("send");
    tokio::time::timeout(5 * SECOND, reached.notified())
        .await
        .expect("the call reaches its access");
    issuer_api::stop(&c.t3, c.port, c.package.sandbox_id)
        .await
        .expect("stop");
    go.notify_one();
    let (status, body) = c.claimer.answer(5 * SECOND).await.expect("answer");
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("klav_sandbox_revoked"), "{body}");
    assert!(c.upstream.requests().is_empty());
}

/// Review of #306, N2: the same when the sandbox's time runs out during
/// the access, with its own code.
#[tokio::test(flavor = "multi_thread")]
async fn a_sandbox_that_expires_during_its_access_gets_nothing_injected() {
    let mut c = calls(ChannelLimits::default()).await;
    let (reached, go) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    c.state
        .hold_after_access(Arc::clone(&reached), Arc::clone(&go));
    c.claimer
        .send(b"GET /northflank/v1/projects HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n")
        .await
        .expect("send");
    tokio::time::timeout(5 * SECOND, reached.notified())
        .await
        .expect("the call reaches its access");
    c.clock.0.fetch_add(
        i64::try_from(std::time::Duration::from_secs(24 * 3600).as_millis()).expect("ms"),
        std::sync::atomic::Ordering::SeqCst,
    );
    go.notify_one();
    let (status, body) = c.claimer.answer(5 * SECOND).await.expect("answer");
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("klav_sandbox_expired"), "{body}");
    assert!(c.upstream.requests().is_empty());
}

/// Review of #306, N3 (and F4 end to end): a sandbox over its own rate
/// spends none of the profile's, so a program on this machine still gets
/// through on what is left.
#[tokio::test(flavor = "multi_thread")]
async fn a_sandbox_over_its_rate_leaves_the_profiles_rate_to_others() {
    // Room in the profile for the sandbox's 60 calls and 2 more.
    let mut c = calls_with(ChannelLimits::default(), 62).await;
    let call = b"GET /northflank/v1/projects HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n";
    for i in 0..crate::proxy::SANDBOX_RATE_PER_MINUTE {
        c.claimer.send(call).await.expect("send");
        assert_eq!(
            c.claimer.answer(5 * SECOND).await.map(|a| a.0),
            Some(200),
            "call {i}"
        );
    }
    for _ in 0..5 {
        c.claimer.send(call).await.expect("send");
        let (status, body) = c.claimer.answer(5 * SECOND).await.expect("answer");
        assert_eq!(status, 429, "{body}");
    }
    for _ in 0..2 {
        let local = reqwest::Client::new()
            .get(format!(
                "http://127.0.0.1:{}/northflank/v1/projects",
                c.port
            ))
            .send()
            .await
            .expect("local");
        assert_eq!(local.status(), 200);
    }
    let local = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/northflank/v1/projects",
            c.port
        ))
        .send()
        .await
        .expect("local");
    assert_eq!(local.status(), 429, "the profile's own rate still holds");
}

/// Starts a second sandbox for `c`'s issuer, unclaimed.
async fn second_sandbox(c: &mut Calls) -> SandboxPackage {
    let started = issuer_api::start(&mut c.t3, c.port, &request("chat-2", &["northflank"]))
        .await
        .expect("start");
    decode_package(&started.package).expect("package")
}

/// Follow-up 1 of the review of #304/#306: a key bound to one sandbox
/// cannot claim another with that one's secret, and the refusal spends
/// nothing: the other sandbox is still claimed by its own forwarder.
#[tokio::test(flavor = "multi_thread")]
async fn a_bound_key_cannot_claim_a_second_sandbox() {
    let mut c = calls(ChannelLimits::default()).await;
    let other = second_sandbox(&mut c).await;
    c.claimer.send(&claim_request(&other)).await.expect("send");
    let (status, body) = c.claimer.answer(5 * SECOND).await.expect("answer");
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("klav_sandbox_revoked"), "{body}");
    // The key still runs as the first sandbox.
    c.claimer.send(STATUS_REQUEST).await.expect("send");
    let (status, body) = c.claimer.answer(5 * SECOND).await.expect("answer");
    assert_eq!(status, 200, "{body}");
    assert!(body.contains(&c.package.sandbox_id.to_string()), "{body}");
    // The second sandbox's secret is not spent.
    let mut its_own = Raw::with(&key(other.proxy_pin), c.addr).await;
    its_own.send(&claim_request(&other)).await.expect("send");
    assert_eq!(its_own.answer(5 * SECOND).await.map(|a| a.0), Some(200));
}

/// Follow-up 1 of the review of #304/#306, the call's half: if a key ever
/// were on record for two sandboxes, a call the server authorised for one
/// gets nothing injected when that one ends during its access, though the
/// other is live.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_authorised_for_one_sandbox_never_runs_as_another() {
    let mut c = calls(ChannelLimits::default()).await;
    let other = second_sandbox(&mut c).await;
    {
        // What the claim now refuses, put on record by hand: the same key
        // bound to the second sandbox too.
        let sandboxes = c.state.sandboxes();
        let mut store = sandboxes.store.lock().await;
        let now = sandboxes.now();
        let first = store
            .channels
            .iter()
            .find(|ch| ch.sandbox_id == c.package.sandbox_id)
            .expect("the first claim")
            .channel_key_sha256
            .clone();
        store.channels.push(crate::claims::Channel {
            sandbox_id: other.sandbox_id,
            channel_key_sha256: first,
            logged: true,
        });
        store
            .sandboxes
            .iter_mut()
            .find(|s| s.sandbox_id == other.sandbox_id)
            .expect("the second sandbox")
            .claimed_at = Some(now);
    }
    let (reached, go) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    c.state
        .hold_after_access(Arc::clone(&reached), Arc::clone(&go));
    c.claimer
        .send(b"GET /northflank/v1/projects HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n")
        .await
        .expect("send");
    tokio::time::timeout(5 * SECOND, reached.notified())
        .await
        .expect("the call reaches its access");
    issuer_api::stop(&c.t3, c.port, c.package.sandbox_id)
        .await
        .expect("stop");
    go.notify_one();
    let (status, body) = c.claimer.answer(5 * SECOND).await.expect("answer");
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("klav_sandbox_revoked"), "{body}");
    assert!(c.upstream.requests().is_empty());
}

/// Limits where only eviction closes an unbound connection.
fn eviction_only(shutdown_grace: std::time::Duration) -> ChannelLimits {
    ChannelLimits {
        header_read: 60 * SECOND,
        unbound_deadline: 60 * SECOND,
        bound_recheck: 60 * SECOND,
        shutdown_grace,
        max_unbound: 2,
        ..ChannelLimits::default()
    }
}

/// Throwaway keys that fill the unbound queue and one more.
async fn flood(c: &Calls, pin: [u8; 32]) -> Vec<Raw> {
    let mut peers = Vec::new();
    for _ in 0..=2 {
        let mut peer = Raw::connect(pin, c.addr).await;
        peer.send(STATUS_REQUEST).await.expect("send");
        assert_eq!(peer.answer(SECOND).await.map(|a| a.0), Some(401));
        peers.push(peer);
    }
    peers
}

/// Re-check of #304/#306, follow-up 2: an unbound connection evicted with
/// a request in flight is closed gracefully, so its answer still arrives
/// within the grace. Here the request is a claim waiting for the server.
#[tokio::test(flavor = "multi_thread")]
async fn an_evicted_connection_still_gets_the_answer_in_flight() {
    let mut c = calls(eviction_only(4 * SECOND)).await;
    let other = second_sandbox(&mut c).await;
    let (reached, go) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    c.state
        .hold_before_claim_log(Arc::clone(&reached), Arc::clone(&go));
    let mut forwarder = Raw::with(&key(other.proxy_pin), c.addr).await;
    forwarder.send(&claim_request(&other)).await.expect("send");
    tokio::time::timeout(5 * SECOND, reached.notified())
        .await
        .expect("the claim reaches the server's turn");
    // The forwarder's connection is the oldest unbound one: evicted.
    let _peers = flood(&c, other.proxy_pin).await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    go.notify_one();
    let (status, body) = forwarder.answer(3 * SECOND).await.expect("the answer");
    assert_eq!(status, 200, "{body}");
    assert!(forwarder.closed_within(5 * SECOND).await, "then it closes");
}

/// Re-check of #304/#306, follow-up 2: an eviction that cuts the
/// connection while its claim waits for the server (`post_claim`) does not
/// leave the claim half done: it finishes apart, and the forwarder's
/// retry with the same key finds it bound.
#[tokio::test(flavor = "multi_thread")]
async fn an_eviction_during_the_servers_turn_never_leaves_a_claim_half_done() {
    let mut c = calls(eviction_only(SECOND)).await;
    let other = second_sandbox(&mut c).await;
    let (reached, go) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    c.state
        .hold_before_claim_log(Arc::clone(&reached), Arc::clone(&go));
    let its_key = key(other.proxy_pin);
    let mut forwarder = Raw::with(&its_key, c.addr).await;
    forwarder.send(&claim_request(&other)).await.expect("send");
    tokio::time::timeout(5 * SECOND, reached.notified())
        .await
        .expect("the claim reaches the server's turn");
    let _peers = flood(&c, other.proxy_pin).await;
    // Past the grace: the connection is cut with the claim still waiting.
    assert!(forwarder.closed_within(3 * SECOND).await, "evicted");
    go.notify_one();
    let mut retry = Raw::with(&its_key, c.addr).await;
    let begun = std::time::Instant::now();
    let answer = loop {
        retry.send(&claim_request(&other)).await.expect("send");
        let answer = retry.answer(5 * SECOND).await.expect("answer");
        if answer.0 == 200 || begun.elapsed() > 5 * SECOND {
            break answer;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };
    assert_eq!(answer.0, 200, "{}", answer.1);
}

/// Re-check of #304/#306, follow-up 2 (N3): a call refused for want of a
/// slot spends no rate. The sandbox's slots are held by slow calls, which
/// spend theirs; the calls refused meanwhile spend nothing, so exactly the
/// rest of the profile's rate is left.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_refused_for_a_slot_spends_no_rate() {
    let share = crate::proxy::SANDBOX_IN_FLIGHT;
    let room = 2;
    let c = calls_with(
        ChannelLimits::default(),
        u32::try_from(share + room).expect("small"),
    )
    .await;
    let mut slow = Vec::new();
    for _ in 0..share {
        let mut raw = Raw::with(&c.key, c.addr).await;
        raw.send(b"GET /northflank/v1/slow HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n")
            .await
            .expect("send");
        slow.push(raw);
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let call = b"GET /northflank/v1/projects HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n";
    let mut over = Raw::with(&c.key, c.addr).await;
    for _ in 0..3 {
        over.send(call).await.expect("send");
        assert_eq!(over.answer(SECOND).await.map(|a| a.0), Some(429));
    }
    for mut raw in slow {
        assert_eq!(raw.answer(5 * SECOND).await.map(|a| a.0), Some(200));
    }
    for i in 0..room {
        over.send(call).await.expect("send");
        assert_eq!(
            over.answer(5 * SECOND).await.map(|a| a.0),
            Some(200),
            "call {i}"
        );
    }
    over.send(call).await.expect("send");
    assert_eq!(over.answer(5 * SECOND).await.map(|a| a.0), Some(429));
}

/// Re-check of #304/#306, follow-up 2 (N3): a call refused for a stalled
/// body spends no rate.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_refused_for_a_stalled_body_spends_no_rate() {
    const STALLED: &[u8] =
        b"POST /northflank/v1/upload HTTP/1.1\r\nhost: 127.0.0.1:8790\r\ncontent-length: 10485760\r\n\r\nfirst bytes";
    let room = 2;
    let c = calls_with(ChannelLimits::default(), room).await;
    c.state.set_request_body_idle(SECOND);
    for _ in 0..3 {
        let mut raw = Raw::with(&c.key, c.addr).await;
        raw.send(STALLED).await.expect("send");
        let (status, body) = raw.answer(4 * SECOND).await.expect("an answer");
        assert_eq!(status, 403, "{body}");
    }
    let call = b"GET /northflank/v1/projects HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n";
    let mut raw = Raw::with(&c.key, c.addr).await;
    for i in 0..room {
        raw.send(call).await.expect("send");
        assert_eq!(
            raw.answer(5 * SECOND).await.map(|a| a.0),
            Some(200),
            "call {i}"
        );
    }
    raw.send(call).await.expect("send");
    assert_eq!(raw.answer(5 * SECOND).await.map(|a| a.0), Some(429));
}

/// Follow-up 1 of the review of #304/#306, with the theft signal: the
/// right secret of a sandbox already claimed by its own key is theft, also
/// from a key bound to another sandbox. The one-key refusal never hides it.
#[tokio::test(flavor = "multi_thread")]
async fn a_bound_key_with_a_claimed_sandboxs_secret_is_theft() {
    let mut c = calls(ChannelLimits::default()).await;
    let other = second_sandbox(&mut c).await;
    let mut its_own = Raw::with(&key(other.proxy_pin), c.addr).await;
    its_own.send(&claim_request(&other)).await.expect("send");
    assert_eq!(its_own.answer(5 * SECOND).await.map(|a| a.0), Some(200));
    c.claimer.send(&claim_request(&other)).await.expect("send");
    let (status, body) = c.claimer.answer(5 * SECOND).await.expect("answer");
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("klav_sandbox_revoked"), "{body}");
    assert_eq!(ends(&mut c.ana).await, [Some("theft".to_owned())]);
    // The first sandbox goes on.
    c.claimer.send(STATUS_REQUEST).await.expect("send");
    assert_eq!(c.claimer.answer(5 * SECOND).await.map(|a| a.0), Some(200));
}

// The MCP gate's streams (ADR 0036 §7, note of 2026-11-19, step M3).

/// Reads into `got` until it holds `needle`: `false` if the connection
/// closed or `wait` passed first.
async fn read_until(
    raw: &mut Raw,
    got: &mut Vec<u8>,
    needle: &[u8],
    wait: std::time::Duration,
) -> bool {
    use tokio::io::AsyncReadExt;
    let read = async {
        let mut buf = [0u8; 4096];
        loop {
            if got.windows(needle.len()).any(|w| w == needle) {
                return true;
            }
            match raw.io.read(&mut buf).await {
                Ok(0) | Err(_) => return false,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
    };
    tokio::time::timeout(wait, read).await.unwrap_or(false)
}

/// Reads into `got` until the connection closes: `false` if it was still
/// open after `wait`.
async fn read_to_close(raw: &mut Raw, got: &mut Vec<u8>, wait: std::time::Duration) -> bool {
    use tokio::io::AsyncReadExt;
    let read = async {
        let mut buf = [0u8; 4096];
        loop {
            match raw.io.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
    };
    tokio::time::timeout(wait, read).await.is_ok()
}

/// The sandbox's credential (`setup_with`), which the provider echoes.
const SANDBOX_VALUE: &str = "token-0123456789";

/// Opens the fake provider's stream through the sandbox's channel, and
/// reads its head and its first event.
async fn open_stream(c: &Calls) -> (Raw, Vec<u8>) {
    let mut raw = Raw::with(&c.key, c.addr).await;
    raw.send(b"GET /northflank/v1/sse HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n")
        .await
        .expect("send");
    let mut got = Vec::new();
    assert!(
        read_until(&mut raw, &mut got, b"\"}\n\n", 5 * SECOND).await,
        "the first event: {}",
        String::from_utf8_lossy(&got)
    );
    (raw, got)
}

/// Waits for every request slot to come back.
async fn slots_back(c: &Calls) {
    let begun = std::time::Instant::now();
    while c.state.free_slots() < crate::proxy::MAX_IN_FLIGHT && begun.elapsed() < 3 * SECOND {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(c.state.free_slots(), crate::proxy::MAX_IN_FLIGHT);
}

/// A provider's stream reaches a sandbox as it comes, with the injected
/// bearer replaced even when the provider split it across two chunks of a
/// line, and without the provider's `WWW-Authenticate`; a program on this
/// machine still gets that header, as it gets `Set-Cookie`. A sandbox's
/// non-stream answer loses it too. A caller that leaves a stream the
/// provider keeps writing frees its slots at the next write.
#[tokio::test(flavor = "multi_thread")]
async fn a_stream_reaches_a_sandbox_redacted_and_without_a_sign_in_challenge() {
    let c = calls(ChannelLimits::default()).await;
    let (mut raw, mut got) = open_stream(&c).await;
    let text = String::from_utf8_lossy(&got).to_string();
    let head = text.to_ascii_lowercase();
    assert!(head.starts_with("http/1.1 200"), "{text}");
    assert!(head.contains("content-type: text/event-stream"), "{text}");
    assert!(!head.contains("www-authenticate"), "{text}");
    assert!(!head.contains("resource_metadata"), "{text}");
    assert!(text.contains("event: message\n"), "{text}");
    assert!(
        text.contains(&format!(
            "data: {{\"seen\":\"{}\"}}\n\n",
            klav_sdk::actions::REDACTED
        )),
        "{text}"
    );
    assert!(!text.contains(SANDBOX_VALUE), "{text}");
    // It stays open and goes on.
    assert!(read_until(&mut raw, &mut got, b": ping\n\n", 5 * SECOND).await);
    assert_eq!(
        c.state.free_slots(),
        crate::proxy::MAX_IN_FLIGHT - 1,
        "an open stream holds its slot"
    );
    drop(raw);
    slots_back(&c).await;

    // An event goes out with the chunk that ends its line, even when the
    // provider then goes quiet for 5 s: nothing of it waits for a next
    // chunk. (A caller that leaves a quiet stream keeps its slot until the
    // proxy's next write fails, or the idle limit: the channel takes a
    // half-close, so only a write tells the proxy it went away.)
    let mut raw = Raw::with(&c.key, c.addr).await;
    raw.send(b"GET /northflank/v1/sse-quiet HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n")
        .await
        .expect("send");
    let mut got = Vec::new();
    assert!(
        read_until(&mut raw, &mut got, b"data: hello\n\n", SECOND).await,
        "the event came at once: {}",
        String::from_utf8_lossy(&got)
    );
    drop(raw);

    // A non-stream answer to a sandbox loses the challenge too.
    let mut raw = Raw::with(&c.key, c.addr).await;
    raw.send(b"GET /northflank/v1/unauthorized HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n")
        .await
        .expect("send");
    let head = raw.head(5 * SECOND).await.expect("answer");
    assert!(head.starts_with("http/1.1 401"), "{head}");
    assert!(!head.contains("www-authenticate"), "{head}");

    // A program on this machine keeps it, stream or not.
    let local = reqwest::Client::new();
    for path in ["/northflank/v1/unauthorized", "/northflank/v1/sse"] {
        let res = local
            .get(format!("http://127.0.0.1:{}{path}", c.port))
            .send()
            .await
            .expect("local");
        assert!(res.headers().contains_key("www-authenticate"), "{path}");
    }
}

/// How a sandbox ends in [`an_ended_sandbox_cuts_its_open_stream`].
#[derive(Debug, Clone, Copy)]
enum End {
    /// Its issuer stops it.
    Stop,
    /// The person revokes it; the proxy's sweep reads the revocation.
    Person,
    /// Its time runs out; the proxy's sweep ends it.
    Ttl,
    /// The person pauses every agent; the proxy's refresh learns it.
    Pause,
    /// The person pauses its issuer; the proxy learns it from a refused
    /// call of the sandbox.
    IssuerPause,
}

/// An open stream is cut, with an error and at once, when its sandbox ends
/// for any reason or the person pauses the agents: not at the channel's
/// next check of the connection (here 10 minutes away).
async fn an_ended_sandbox_cuts_its_open_stream(end: End) {
    let mut c = calls(ChannelLimits {
        bound_recheck: 600 * SECOND,
        shutdown_grace: 600 * SECOND,
        ..ChannelLimits::default()
    })
    .await;
    let (mut raw, mut got) = open_stream(&c).await;
    // Another call, still waiting for the provider's headers.
    let mut waiting = Raw::with(&c.key, c.addr).await;
    waiting
        .send(b"GET /northflank/v1/very-slow HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n")
        .await
        .expect("send");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    match end {
        End::Stop => {
            issuer_api::stop(&c.t3, c.port, c.package.sandbox_id)
                .await
                .expect("stop");
        }
        End::Person => {
            let proxy = c.state.proxy_id().await;
            c.ana
                .revoke_sandboxes(
                    proxy,
                    klav_proto::sandbox::RevokeTarget::One(c.package.sandbox_id),
                )
                .await
                .expect("revoke");
            assert_eq!(sweep(&c.state).await, 1);
        }
        End::Ttl => {
            c.clock.0.fetch_add(
                i64::try_from(std::time::Duration::from_secs(24 * 3600).as_millis()).expect("ms"),
                std::sync::atomic::Ordering::SeqCst,
            );
            assert_eq!(sweep(&c.state).await, 1);
        }
        End::Pause => {
            c.ana.pause_agents(None, 0).await.expect("pause");
            assert!(c.state.refresh().await.is_err(), "the server refuses it");
        }
        End::IssuerPause => {
            c.ana
                .pause_agents(Some(c.t3.id()), 0)
                .await
                .expect("pause the issuer");
            c.claimer
                .send(b"GET /northflank/v1/projects HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n")
                .await
                .expect("send");
            let (status, body) = c.claimer.answer(5 * SECOND).await.expect("answer");
            assert_eq!(status, 423, "{body}");
        }
    }
    let begun = std::time::Instant::now();
    assert!(
        read_to_close(&mut raw, &mut got, 3 * SECOND).await,
        "{end:?}: the stream stayed open"
    );
    assert!(
        begun.elapsed() < 2 * SECOND,
        "{end:?}: {:?}",
        begun.elapsed()
    );
    assert!(
        !got.ends_with(b"0\r\n\r\n"),
        "{end:?}: a cut never looks like a clean end"
    );
    // The waiting call answers at once, as a pause when it was one.
    let (status, body) = waiting.answer(2 * SECOND).await.expect("the waiting call");
    match end {
        End::Pause | End::IssuerPause => {
            assert_eq!(status, 423, "{end:?}: {body}");
            assert!(body.contains("klav_agents_paused"), "{end:?}: {body}");
        }
        _ => assert_eq!(status, 401, "{end:?}: {body}"),
    }
    slots_back(&c).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stopping_a_sandbox_cuts_its_open_stream() {
    an_ended_sandbox_cuts_its_open_stream(End::Stop).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_persons_revocation_cuts_an_open_stream() {
    an_ended_sandbox_cuts_its_open_stream(End::Person).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sandbox_past_its_time_has_its_open_stream_cut() {
    an_ended_sandbox_cuts_its_open_stream(End::Ttl).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pausing_the_agents_cuts_an_open_stream() {
    an_ended_sandbox_cuts_its_open_stream(End::Pause).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pausing_the_issuer_cuts_its_sandboxes_open_stream() {
    an_ended_sandbox_cuts_its_open_stream(End::IssuerPause).await;
}

/// The request timeout covers a stream's headers only: a stream that
/// outlives it arrives whole, while a slow non-stream body is cut. A stream
/// past its own longest life is cut, and so is one with a line over the
/// redactor's 1 MiB hold; neither ever ends cleanly.
#[tokio::test(flavor = "multi_thread")]
async fn a_stream_has_its_own_limits() {
    let c = calls_configured(ChannelLimits::default(), 1000, |s| {
        s.with_request_timeout(SECOND)
    })
    .await;
    let local = reqwest::Client::new();
    let get = |path: &'static str| {
        local
            .get(format!("http://127.0.0.1:{}/northflank{path}", c.port))
            .send()
    };
    // 12 events over 2.4 s, past the 1 s timeout.
    let res = get("/v1/sse-for/12").await.expect("headers in time");
    let body = res.text().await.expect("a whole stream");
    assert!(
        body.contains("data: 0\n\n") && body.ends_with("data: 11\n\n"),
        "{body}"
    );
    // Not a stream: the timeout covers the body too.
    let res = get("/v1/slow-body").await.expect("headers in time");
    assert!(res.bytes().await.is_err(), "the slow body is cut");
    // A line over the hold: cut for its length, not when the provider
    // leaves 10 s later.
    let res = get("/v1/sse-long-line").await.expect("headers");
    let begun = std::time::Instant::now();
    assert!(res.bytes().await.is_err(), "the long line is cut");
    assert!(begun.elapsed() < 3 * SECOND, "{:?}", begun.elapsed());
    // The stream's own longest life.
    c.state.set_stream_limits(SECOND, crate::proxy::STREAM_IDLE);
    let res = get("/v1/sse-for/12").await.expect("headers");
    let begun = std::time::Instant::now();
    assert!(res.bytes().await.is_err(), "cut at its longest life");
    assert!(begun.elapsed() < 2 * SECOND, "{:?}", begun.elapsed());
    // And its idle limit.
    c.state.set_stream_limits(
        crate::proxy::STREAM_MAX,
        std::time::Duration::from_millis(300),
    );
    let res = get("/v1/sse-quiet").await.expect("headers");
    let begun = std::time::Instant::now();
    assert!(res.bytes().await.is_err(), "cut when it went quiet");
    assert!(begun.elapsed() < 2 * SECOND, "{:?}", begun.elapsed());
    slots_back(&c).await;
}
