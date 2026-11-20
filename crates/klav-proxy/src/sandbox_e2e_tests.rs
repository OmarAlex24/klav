//! Sandboxes end to end (ADR 0036 §4, E3.3; layer 5): a real
//! `klav-server`, the person's client making `t3-code` an issuer of the
//! proxy, the proxy's issuer API on a loopback port, and the issuer's SDK
//! starting, listing and stopping sandboxes. The proxy's clock is a manual
//! one, so the sweeper's TTL and inactivity run without waiting.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use crate::e2e_tests::common::ServerProcess;
use klav_client::issuers::IssuerSpec;
use klav_client::proxy_admin::{PairingCheck, ProxyCredentialSpec};
use klav_client::{Home, SignupRequest, Unlocked, signup};
use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::sandbox::{decode_package, proxy_pin};
use klav_core::model::item::{Item, ItemKind};
use klav_sdk::sandbox::{self as issuer_api, SandboxError, StartRequest};
use klav_sdk::{Agent, KeyStore, Registration, Session};

use crate::proxy::{ProxyState, router};
use crate::sandboxes::{Clock, INACTIVITY_MS, MAX_OUTBOX, Sandboxes, sweep};

const EMAIL: &str = "ana@example.com";
const URL: &str = "tls://proxy.example.com:8443";

/// A clock the test moves.
pub(crate) struct Manual(pub(crate) AtomicI64);

impl Clock for Manual {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

pub(crate) fn real_now() -> i64 {
    crate::sandboxes::SystemClock.now_ms()
}

async fn register(server: &ServerProcess, dir: &tempfile::TempDir, name: &str) -> Agent {
    Agent::register(
        &Home::at(dir.path().join(format!("agent-{name}"))),
        Registration {
            name: name.into(),
            server: server.url.clone(),
            email: EMAIL.into(),
            note: None,
            key_store: KeyStore::File {
                path: dir.path().join(format!("{name}.key")),
            },
        },
    )
    .await
    .expect("register")
    .0
}

async fn account(server: &ServerProcess, dir: &tempfile::TempDir) -> Unlocked {
    let (mut ana, _) = signup(
        &Home::at(dir.path().join("laptop")),
        SignupRequest {
            server: server.url.clone(),
            email: EMAIL.into(),
            password: MasterPassword::new("correct horse battery staple"),
            device_name: "laptop".into(),
            device_kind: klav_proto::auth::DeviceKind::Cli,
        },
    )
    .await
    .expect("sign-up");
    let vault = ana.find_vault("Personal").expect("vault");
    let project = ana.find_project(vault, "General").expect("project");
    let mut item = Item::from_template(ItemKind::Login, "Northflank").expect("item");
    item.field_mut("password")
        .expect("password")
        .set_value("token-0123456789")
        .expect("set");
    ana.add_item(vault, project, &item).await.expect("add item");
    ana
}

fn credential(profile: &str) -> ProxyCredentialSpec {
    credential_at(profile, "https://api.northflank.com")
}

pub(crate) fn credential_at(profile: &str, upstream: &str) -> ProxyCredentialSpec {
    ProxyCredentialSpec {
        profile: profile.into(),
        upstream: upstream.into(),
        header: "authorization".into(),
        prefix: "Bearer ".into(),
        methods: vec!["GET".into()],
        path_prefixes: vec!["/v1".into()],
        ..ProxyCredentialSpec::default()
    }
}

/// The account's proxy holds `northflank`, and `t3-code` is its issuer
/// with at most two live sandboxes.
pub(crate) async fn setup(
    server: &ServerProcess,
    dir: &tempfile::TempDir,
) -> (Unlocked, Agent, Agent) {
    setup_with(server, dir, credential("northflank")).await
}

/// [`setup`], with `northflank` going where `spec` says.
pub(crate) async fn setup_with(
    server: &ServerProcess,
    dir: &tempfile::TempDir,
    spec: ProxyCredentialSpec,
) -> (Unlocked, Agent, Agent) {
    let mut ana = account(server, dir).await;
    let proxy = register(server, dir, "klav-proxy").await;
    let prepared = ana
        .prepare_proxy_use(Some("klav-proxy"))
        .await
        .expect("use");
    ana.commit_proxy_use(prepared).await.expect("use");
    let prepared = ana
        .prepare_proxy_grant("Northflank", &spec, PairingCheck::InPrompt)
        .await
        .expect("grant");
    prepared.require_updated_devices(true).expect("ack");
    assert!(
        ana.commit_proxy_change(prepared)
            .await
            .expect("grant")
            .complete()
    );
    let t3 = register(server, dir, "t3-code").await;
    let prepared = ana
        .prepare_issuer_add(
            "t3-code",
            &IssuerSpec {
                profiles: vec!["northflank".into()],
                url: URL.into(),
                max_live: Some(2),
                ..IssuerSpec::default()
            },
            PairingCheck::InPrompt,
        )
        .await
        .expect("issuer add");
    prepared.require_updated_devices(true).expect("ack");
    assert!(
        ana.commit_issuer_change(prepared)
            .await
            .expect("add")
            .complete()
    );
    (ana, proxy, t3)
}

/// Serves the proxy's router on a loopback port with `clock` and a store
/// in `dir`; returns its state and port.
async fn serve(
    proxy: Agent,
    clock: Arc<Manual>,
    store: std::path::PathBuf,
) -> (Arc<ProxyState>, u16) {
    let session = Session::open(proxy).await.expect("proxy session");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let heartbeats = crate::heartbeat::Heartbeats::open(crate::heartbeat::path_of(&store));
    let sandboxes = Sandboxes::open(store, clock).expect("store");
    let state = Arc::new(
        ProxyState::new(session, reqwest::Client::new(), port)
            .with_sandboxes(sandboxes)
            .with_heartbeats(heartbeats),
    );
    let served = Arc::clone(&state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(served)).await;
    });
    (state, port)
}

pub(crate) fn request(label: &str, profiles: &[&str]) -> StartRequest {
    StartRequest {
        label: label.into(),
        profiles: profiles.iter().map(|p| (*p).to_owned()).collect(),
        ttl_secs: None,
    }
}

fn refused(e: SandboxError) -> String {
    e.code().to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_issuer_starts_lists_and_stops_its_sandboxes() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    // The key the proxy registered with, which the person paired.
    let proxy_public =
        PublicIdentity::decode(proxy.config().public_identity.as_bytes()).expect("identity");
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    // Where `klav-proxy serve` keeps it, so `status` reads it.
    let home = Home::at(dir.path().join("agent-klav-proxy"));
    let store = Sandboxes::path_in(&home, "klav-proxy");
    let (state, port) = serve(proxy, Arc::clone(&clock), store.clone()).await;

    // 1. A start gives a package built from the issuer's own grant: the
    // address the person signed and the pin of the proxy they paired.
    let started = issuer_api::start(&mut t3, port, &request("chat-123", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("a ksb1_ package");
    assert_eq!(package.sandbox_id, started.sandbox_id);
    assert_eq!(package.url, URL);
    assert_eq!(package.proxy_pin, proxy_pin(&proxy_public));
    let ttl = started.expires_at - clock.now_ms();
    assert!(
        (8 * 3_600_000 - 5_000..=8 * 3_600_000).contains(&ttl),
        "{ttl}"
    );

    // The store keeps the digest, never the secret, in a 0600 file.
    let kept = std::fs::read(&store).expect("store");
    let secret = package.secret.expose();
    assert!(!kept.windows(secret.len()).any(|w| w == secret));
    for text in [
        klav_proto::Blob::new(secret.to_vec()).to_text(),
        secret
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    ] {
        assert!(!String::from_utf8_lossy(&kept).contains(&text));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&store)
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // 2. Its own limits: a profile it was not given, and more live
    // sandboxes than it may have.
    let e = issuer_api::start(&mut t3, port, &request("chat-124", &["maple"]))
        .await
        .err()
        .expect("refused");
    assert_eq!(refused(e), "klav_profile_not_allowed");
    let second = issuer_api::start(&mut t3, port, &request("chat-124", &["northflank"]))
        .await
        .expect("second");
    let e = issuer_api::start(&mut t3, port, &request("chat-125", &["northflank"]))
        .await
        .err()
        .expect("refused");
    assert_eq!(refused(e), "klav_too_many_sandboxes");

    // `klav-proxy status` lists both, with nothing secret.
    let report = crate::app::status(&home, "klav-proxy", &crate::app::StartEnv::default())
        .await
        .expect("status");
    assert!(report.store_error.is_none());
    let mut labels: Vec<&str> = report.sandboxes.iter().map(|s| s.label.as_str()).collect();
    labels.sort_unstable();
    assert_eq!(labels, ["chat-123", "chat-124"]);
    assert_eq!(report.unsent_ends, 0);
    let shown = serde_json::to_string(&report).expect("json");
    assert!(!shown.contains("secret_sha256"));
    assert!(!shown.contains(&klav_proto::Blob::new(secret.to_vec()).to_text()));
    // ADR 0044 §3.1: no `memory` until a `serve` wrote its record (this
    // test binds in its own process, which is never hardened); then
    // `status --json` shows what that `serve` turned on.
    assert!(report.memory.is_none() && report.memory_error.is_none());
    assert!(!shown.contains("\"memory\""));
    let record = crate::memory::MemoryRecord {
        report: crate::memory::MemoryReport {
            core_dumps: crate::memory::CoreDumps::Off,
            dumpable: Some(false),
            locked: false,
            lock_turned_off: false,
            vm_lck_kib: None,
            why: Some("the memlock limit is 8 MiB (hard limit 8 MiB)".into()),
            lock_not_undone: false,
        },
        since: 7,
    };
    klav_client::home::write_private(
        &crate::app::memory_path_in(&home, "klav-proxy"),
        &record.to_file().expect("bytes"),
    )
    .expect("record");
    let report = crate::app::status(&home, "klav-proxy", &crate::app::StartEnv::default())
        .await
        .expect("status");
    assert_eq!(report.memory.as_ref(), Some(&record));
    let shown = serde_json::to_value(&report).expect("json");
    assert_eq!(
        shown["memory"],
        serde_json::json!({
            "core_dumps": "off",
            "dumpable": false,
            "locked": false,
            "why": "the memlock limit is 8 MiB (hard limit 8 MiB)",
            "since": 7,
        })
    );
    // A record it can't read is said, and the rest of `status` stays.
    klav_client::home::write_private(&crate::app::memory_path_in(&home, "klav-proxy"), b"{")
        .expect("write");
    let report = crate::app::status(&home, "klav-proxy", &crate::app::StartEnv::default())
        .await
        .expect("status");
    assert!(report.memory.is_none() && report.memory_error.is_some());
    assert_eq!(report.sandboxes.len(), 2);

    // 3. `ls` and `stop` see only this issuer's; `stop` frees a place.
    let live = issuer_api::list(&t3, port).await.expect("ls");
    assert_eq!(live.len(), 2);
    assert!(live.iter().any(|s| s.label == "chat-123"));
    assert!(
        issuer_api::stop(&t3, port, second.sandbox_id)
            .await
            .expect("stop")
    );
    let e = issuer_api::stop(&t3, port, second.sandbox_id)
        .await
        .expect_err("gone");
    assert_eq!(refused(e), "klav_sandbox_not_found");
    assert_eq!(issuer_api::list(&t3, port).await.expect("ls").len(), 1);

    // 4. Another agent, even an approved one, is no issuer: the proxy
    // checks its own grant.
    let mut ci = register(&server, &dir, "ci").await;
    let e = issuer_api::start(&mut ci, port, &request("x", &["northflank"]))
        .await
        .err()
        .expect("refused");
    assert_eq!(refused(e), "klav_not_issuer");
    // Signed by an agent the proxy's grant does not list: the same `401`
    // as a bad signature, so nobody learns who the issuers are.
    let body = br#"{"label":"x","profiles":["northflank"]}"#;
    let own_port = format!("/_klav/sandboxes?port={port}");
    let (status, code) = signed_raw(&ci, port, &own_port, body).await;
    assert_eq!((status, code.as_str()), (401, "klav_not_allowed"));
    // An issuer's request signed for another port, or for none, is
    // refused: it was meant for a proxy elsewhere.
    for path in [
        "/_klav/sandboxes".to_owned(),
        format!("/_klav/sandboxes?port={}", port.wrapping_add(1)),
    ] {
        let (status, code) = signed_raw(&t3, port, &path, body).await;
        assert_eq!((status, code.as_str()), (403, "klav_not_allowed"), "{path}");
    }

    // 5. The sweeper: unclaimed for an hour ends with `inactivity`.
    clock.0.fetch_add(INACTIVITY_MS, Ordering::SeqCst);
    assert_eq!(sweep(&state).await, 1);
    assert_eq!(state.sandboxes().live().await, 0);
    assert_eq!(state.sandboxes().unsent().await, 0);

    // The person's log verifies, with each step of each sandbox.
    ana.verify_audit().await.expect("the chain verifies");
    let lines = ana
        .audit_log(&klav_client::audit::LogFilter::default())
        .await
        .expect("log");
    let outcomes: Vec<(String, Option<String>)> = lines
        .iter()
        .rev()
        .filter(|l| l.action.starts_with("sandbox."))
        .map(|l| (l.action.clone(), l.outcome.clone()))
        .collect();
    assert_eq!(
        outcomes,
        [
            ("sandbox.issued".to_owned(), None),
            ("sandbox.issued".to_owned(), None),
            ("sandbox.revoked".to_owned(), Some("stop".to_owned())),
            ("sandbox.revoked".to_owned(), Some("inactivity".to_owned())),
        ]
    );
}

/// A request signed by `agent` sent as it is; returns the status and the
/// `Klav-Error`.
async fn signed_raw(agent: &Agent, port: u16, path: &str, body: &[u8]) -> (u16, String) {
    let proof = agent.sign_request(&reqwest::Method::POST, path, body);
    let res = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("client")
        .post(format!("http://127.0.0.1:{port}{path}"))
        .header("klav-agent", agent.id().to_string())
        .header("klav-timestamp", proof.timestamp_ms.to_string())
        .header("klav-nonce", proof.nonce.to_text())
        .header("klav-signature", proof.signature.to_text())
        .body(body.to_vec())
        .send()
        .await
        .expect("send");
    let code = res
        .headers()
        .get("klav-error")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    (res.status().as_u16(), code)
}

#[tokio::test(flavor = "multi_thread")]
async fn replays_old_requests_and_removed_issuers_are_refused_and_ended() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let store = dir.path().join("proxy-sandboxes.json");
    let (state, port) = serve(proxy, Arc::clone(&clock), store.clone()).await;

    // A replayed start is refused before anything happens.
    let path = format!("/_klav/sandboxes?port={port}");
    let path = path.as_str();
    let body = br#"{"label":"chat-9","profiles":["northflank"]}"#;
    let proof = t3.sign_request(&reqwest::Method::POST, path, body);
    let send = || async {
        let res = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("client")
            .post(format!("http://127.0.0.1:{port}{path}"))
            .header("klav-agent", t3.id().to_string())
            .header("klav-timestamp", proof.timestamp_ms.to_string())
            .header("klav-nonce", proof.nonce.to_text())
            .header("klav-signature", proof.signature.to_text())
            .body(body.to_vec())
            .send()
            .await
            .expect("send");
        res.status().as_u16()
    };
    assert_eq!(send().await, 200);
    assert_eq!(send().await, 401, "the same nonce twice");
    // A web page is never an issuer.
    let res = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("client")
        .get(format!("http://127.0.0.1:{port}{path}"))
        .header("origin", "https://evil.example")
        .send()
        .await
        .expect("send");
    assert_eq!(res.status().as_u16(), 403);

    // A request signed before the proxy started (its nonces are gone):
    // the restarted proxy's clock is a second ahead of the signer's.
    drop(state);
    let clock2 = Arc::new(Manual(AtomicI64::new(real_now() + 1_000)));
    let proxy = Agent::load(&Home::at(dir.path().join("agent-klav-proxy")), "klav-proxy")
        .expect("load proxy");
    let (state, port2) = serve(proxy, Arc::clone(&clock2), store.clone()).await;
    let path2 = format!("/_klav/sandboxes?port={port2}");
    let old = t3.sign_request(&reqwest::Method::GET, &path2, b"");
    let res = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("client")
        .get(format!("http://127.0.0.1:{port2}{path2}"))
        .header("klav-agent", t3.id().to_string())
        .header("klav-timestamp", old.timestamp_ms.to_string())
        .header("klav-nonce", old.nonce.to_text())
        .header("klav-signature", old.signature.to_text())
        .send()
        .await
        .expect("send");
    assert_eq!(res.status().as_u16(), 401);
    // The store survived the restart.
    assert_eq!(state.sandboxes().live().await, 1);

    // The person removes the issuer: its sandbox ends with `issuer_removed`
    // on the next sweep after the proxy's grant changes.
    let prepared = ana.prepare_issuer_remove("t3-code").await.expect("remove");
    assert!(
        ana.commit_issuer_change(prepared)
            .await
            .expect("remove")
            .complete()
    );
    state.refresh().await.expect("refresh");
    assert_eq!(sweep(&state).await, 1);
    let e = issuer_api::start(&mut t3, port2, &request("chat-10", &["northflank"]))
        .await
        .err()
        .expect("no longer");
    assert_eq!(refused(e), "klav_no_proxy");
    ana.verify_audit().await.expect("the chain verifies");
    let last = ana
        .audit_log(&klav_client::audit::LogFilter::default())
        .await
        .expect("log")
        .into_iter()
        .find(|l| l.action == "sandbox.revoked")
        .expect("revoked");
    assert_eq!(last.outcome.as_deref(), Some("issuer_removed"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pause_holds_the_ends_until_the_proxy_can_log_them() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port) = serve(proxy, clock, dir.path().join("store.json")).await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");

    ana.pause_agents(None, 0).await.expect("pause");
    let e = issuer_api::start(&mut t3, port, &request("chat-2", &["northflank"]))
        .await
        .err()
        .expect("paused");
    assert_eq!(refused(e), "klav_agents_paused");
    // `stop` takes effect at once, and the server gets it after the pause.
    assert!(
        !issuer_api::stop(&t3, port, started.sandbox_id)
            .await
            .expect("stop")
    );
    assert_eq!(state.sandboxes().live().await, 0);
    assert_eq!(state.sandboxes().unsent().await, 1, "held while paused");
    ana.resume_agents(None).await.expect("resume");
    assert_eq!(sweep(&state).await, 0);
    assert_eq!(state.sandboxes().unsent().await, 0, "sent after the pause");
    ana.verify_audit().await.expect("the chain verifies");
    let last = ana
        .audit_log(&klav_client::audit::LogFilter::default())
        .await
        .expect("log")
        .into_iter()
        .find(|l| l.action == "sandbox.revoked")
        .expect("revoked");
    assert_eq!(last.outcome.as_deref(), Some("stop"));
}

/// A store the proxy cannot write after the server logged the sandbox:
/// nothing is handed out, and the server gets its end.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_sandbox_the_proxy_cannot_keep_is_never_handed_out_or_lost() {
    use std::os::unix::fs::PermissionsExt;
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let stores = dir.path().join("stores");
    std::fs::create_dir(&stores).expect("dir");
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port) = serve(proxy, clock, stores.join("store.json")).await;
    let kept = issuer_api::start(&mut t3, port, &request("chat-0", &["northflank"]))
        .await
        .expect("started");
    std::fs::set_permissions(&stores, std::fs::Permissions::from_mode(0o500)).expect("chmod");
    // A start: its pending end cannot be written, so the server never
    // hears of it.
    let result = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"])).await;
    assert_eq!(refused(result.err().expect("not kept")), "klav_proxy_store");
    // A stop it cannot save leaves the sandbox live, here and on disk.
    let e = issuer_api::stop(&t3, port, kept.sandbox_id)
        .await
        .expect_err("not saved");
    assert_eq!(refused(e), "klav_proxy_store");
    std::fs::set_permissions(&stores, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    assert_eq!(state.sandboxes().live().await, 1);
    assert_eq!(state.sandboxes().unsent().await, 0);
    let listed = issuer_api::list(&t3, port).await.expect("ls");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].sandbox_id, kept.sandbox_id);
    assert!(
        issuer_api::stop(&t3, port, kept.sandbox_id)
            .await
            .expect("stop")
    );
    ana.verify_audit().await.expect("the chain verifies");
    let outcomes: Vec<(String, Option<String>)> = ana
        .audit_log(&klav_client::audit::LogFilter::default())
        .await
        .expect("log")
        .into_iter()
        .rev()
        .filter(|l| l.action.starts_with("sandbox."))
        .map(|l| (l.action, l.outcome))
        .collect();
    assert_eq!(
        outcomes,
        [
            ("sandbox.issued".to_owned(), None),
            ("sandbox.revoked".to_owned(), Some("stop".to_owned())),
        ]
    );
}

/// Adds `name` as a second issuer of the proxy, with `northflank`.
pub(crate) async fn second_issuer(
    server: &ServerProcess,
    dir: &tempfile::TempDir,
    ana: &mut Unlocked,
    name: &str,
) -> Agent {
    let agent = register(server, dir, name).await;
    let prepared = ana
        .prepare_issuer_add(
            name,
            &IssuerSpec {
                profiles: vec!["northflank".into()],
                url: URL.into(),
                max_live: Some(2),
                ..IssuerSpec::default()
            },
            PairingCheck::InPrompt,
        )
        .await
        .expect("issuer add");
    prepared.require_updated_devices(true).expect("ack");
    assert!(
        ana.commit_issuer_change(prepared)
            .await
            .expect("add")
            .complete()
    );
    agent
}

#[tokio::test(flavor = "multi_thread")]
async fn issuers_see_and_stop_only_their_own_and_max_live_holds_at_once() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let mut other = second_issuer(&server, &dir, &mut ana, "builder").await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (_state, port) = serve(proxy, clock, dir.path().join("store.json")).await;

    let mine = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("t3 starts");
    let theirs = issuer_api::start(&mut other, port, &request("build-1", &["northflank"]))
        .await
        .expect("builder starts");
    let ids =
        |l: Vec<issuer_api::LiveSandbox>| l.into_iter().map(|s| s.sandbox_id).collect::<Vec<_>>();
    assert_eq!(
        ids(issuer_api::list(&t3, port).await.expect("ls")),
        [mine.sandbox_id]
    );
    assert_eq!(
        ids(issuer_api::list(&other, port).await.expect("ls")),
        [theirs.sandbox_id]
    );
    // Another issuer's sandbox is "not found", and stays live.
    let e = issuer_api::stop(&t3, port, theirs.sandbox_id)
        .await
        .expect_err("not mine");
    assert_eq!(refused(e), "klav_sandbox_not_found");
    assert_eq!(
        ids(issuer_api::list(&other, port).await.expect("ls")),
        [theirs.sandbox_id]
    );

    // At max_live - 1, two starts at once: one gets the last place.
    let mut t3b =
        Agent::load(&Home::at(dir.path().join("agent-t3-code")), "t3-code").expect("load");
    let (two, three) = (
        request("chat-2", &["northflank"]),
        request("chat-3", &["northflank"]),
    );
    let (a, b) = tokio::join!(
        issuer_api::start(&mut t3, port, &two),
        issuer_api::start(&mut t3b, port, &three),
    );
    let mut codes: Vec<String> = [a, b]
        .into_iter()
        .map(|r| r.map_or_else(refused, |_| "ok".to_owned()))
        .collect();
    codes.sort();
    assert_eq!(codes, ["klav_too_many_sandboxes", "ok"]);
    assert_eq!(issuer_api::list(&t3, port).await.expect("ls").len(), 2);
    ana.verify_audit().await.expect("the chain verifies");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_start_the_server_may_have_logged_is_ended_once_it_is_back() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let store = dir.path().join("store.json");
    let (state, port) = serve(proxy, clock, store.clone()).await;

    // The server does not answer: whether it logged the issue is unknown,
    // so the proxy keeps an end for it, on disk before it asked.
    server.stop();
    let body = br#"{"label":"chat-1","profiles":["northflank"]}"#;
    let (status, code) =
        signed_raw(&t3, port, &format!("/_klav/sandboxes?port={port}"), body).await;
    assert_eq!((status, code.as_str()), (503, "klav_server_unreachable"));
    assert_eq!(state.sandboxes().live().await, 0);
    assert_eq!(state.sandboxes().unsent().await, 1);
    let on_disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&store).expect("store")).expect("json");
    assert_eq!(on_disk["outbox"].as_array().expect("outbox").len(), 1);
    // Still down: the sweep keeps it.
    sweep(&state).await;
    assert_eq!(state.sandboxes().unsent().await, 1);
    // Back: it never had the sandbox (`404`), so the end is dropped.
    server.restart();
    sweep(&state).await;
    assert_eq!(state.sandboxes().unsent().await, 0);
    ana.verify_audit().await.expect("the chain verifies");
    let events = ana
        .audit_log(&klav_client::audit::LogFilter::default())
        .await
        .expect("log")
        .into_iter()
        .filter(|l| l.action.starts_with("sandbox."))
        .count();
    assert_eq!(events, 0);
}

/// The sandbox ends in the person's log, oldest first.
pub(crate) async fn ends(ana: &mut Unlocked) -> Vec<Option<String>> {
    ana.verify_audit().await.expect("the chain verifies");
    ana.audit_log(&klav_client::audit::LogFilter::default())
        .await
        .expect("log")
        .into_iter()
        .rev()
        .filter(|l| l.action == "sandbox.revoked")
        .map(|l| l.outcome)
        .collect()
}

/// Signs again what `builder` may give its sandboxes.
async fn builder_profiles(ana: &mut Unlocked, profiles: &[&str]) {
    let spec = IssuerSpec {
        profiles: profiles.iter().map(|p| (*p).to_owned()).collect(),
        url: URL.into(),
        max_live: Some(2),
        ..IssuerSpec::default()
    };
    let prepared = ana
        .prepare_issuer_add("builder", &spec, PairingCheck::InPrompt)
        .await
        .expect("issuer add");
    prepared.require_updated_devices(true).expect("ack");
    assert!(
        ana.commit_issuer_change(prepared)
            .await
            .expect("add")
            .complete()
    );
}

/// Revoking an issuer (`klav agent revoke`, T156) ends its sandboxes: the
/// server names it in the proxy's `gone_issuers`, and the next sweep ends
/// them with `issuer_removed`. So does taking a profile from it, for the
/// sandboxes that use that profile.
#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_issuer_or_a_removed_profile_ends_its_sandboxes() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    // A second profile on the proxy, and an issuer with both.
    let vault = ana.find_vault("Personal").expect("vault");
    let project = ana.find_project(vault, "General").expect("project");
    let mut maple = Item::from_template(ItemKind::Login, "Maple").expect("item");
    maple
        .field_mut("password")
        .expect("password")
        .set_value("maple-0123456789")
        .expect("set");
    ana.add_item(vault, project, &maple)
        .await
        .expect("add item");
    let prepared = ana
        .prepare_proxy_grant("Maple", &credential("maple"), PairingCheck::InPrompt)
        .await
        .expect("grant");
    prepared.require_updated_devices(true).expect("ack");
    assert!(
        ana.commit_proxy_change(prepared)
            .await
            .expect("grant")
            .complete()
    );
    let mut builder = second_issuer(&server, &dir, &mut ana, "builder").await;
    builder_profiles(&mut ana, &["northflank", "maple"]).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port) = serve(proxy, clock, dir.path().join("store.json")).await;
    state.refresh().await.expect("refresh");
    issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("t3 starts");
    let nf = issuer_api::start(&mut builder, port, &request("b-1", &["northflank"]))
        .await
        .expect("builder starts");
    issuer_api::start(&mut builder, port, &request("b-2", &["maple"]))
        .await
        .expect("builder starts with maple");

    // `maple` is taken from `builder`: only its sandbox with `maple` ends.
    builder_profiles(&mut ana, &["northflank"]).await;
    state.refresh().await.expect("refresh");
    assert_eq!(sweep(&state).await, 1);
    let left: Vec<_> = issuer_api::list(&builder, port)
        .await
        .expect("ls")
        .into_iter()
        .map(|s| s.sandbox_id)
        .collect();
    assert_eq!(left, [nf.sandbox_id]);

    // `t3-code` is revoked as an agent: nothing re-signs the proxy's grant,
    // but the server names it, and its sandbox ends.
    let t3_id = t3.id();
    ana.revoke_agent(t3_id, false).await.expect("revoke");
    assert_eq!(sweep(&state).await, 0, "not before the proxy hears of it");
    state.refresh().await.expect("refresh");
    assert_eq!(state.gone_issuers(), [t3_id]);
    assert_eq!(sweep(&state).await, 1);
    assert_eq!(state.sandboxes().live().await, 1, "builder's other one");
    assert_eq!(state.sandboxes().unsent().await, 0);
    assert_eq!(
        ends(&mut ana).await,
        [
            Some("issuer_removed".to_owned()),
            Some("issuer_removed".to_owned())
        ]
    );
}

/// With [`MAX_OUTBOX`] ends waiting, no sandbox starts and none of them
/// is dropped; once the server takes them (here it never had them, and
/// says so with `sandbox_not_found`), starts work again.
#[tokio::test(flavor = "multi_thread")]
async fn a_full_outbox_holds_new_starts_until_the_server_takes_it() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (_ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port) = serve(proxy, clock, dir.path().join("store.json")).await;
    state.sandboxes().fill_outbox(MAX_OUTBOX).await;
    let e = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .err()
        .expect("held");
    assert_eq!(refused(e), "klav_proxy_backlog");
    assert_eq!(state.sandboxes().unsent().await, MAX_OUTBOX, "none dropped");
    sweep(&state).await;
    assert_eq!(state.sandboxes().unsent().await, 0);
    issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("starts again");
}

/// The store is never held across a call to the server (F6): while a
/// start waits on a server that does not answer, `ls` answers and `stop`
/// ends a sandbox at once; both finish once the server is back.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_stop_takes_effect_while_a_start_waits_for_the_server() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port) = serve(proxy, clock, dir.path().join("store.json")).await;
    let first = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let t3 = Arc::new(t3);

    let frozen = server.freeze();
    // A start straight to the proxy (the SDK would ask the server first).
    let starting = {
        let t3 = Arc::clone(&t3);
        tokio::spawn(async move {
            let body = br#"{"label":"chat-2","profiles":["northflank"]}"#;
            signed_raw(&t3, port, &format!("/_klav/sandboxes?port={port}"), body).await
        })
    };
    let waited = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while state.sandboxes().unsent().await == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(waited.is_ok(), "the start reserved its place");
    let stopping = {
        let t3 = Arc::clone(&t3);
        let id = first.sandbox_id;
        tokio::spawn(async move {
            signed_raw(
                &t3,
                port,
                &format!("/_klav/sandboxes/{id}/stop?port={port}"),
                b"",
            )
            .await
        })
    };
    // Ended here at once, and `ls` answers, while both calls wait on the
    // server.
    let at_once = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while state.sandboxes().live().await != 0 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        issuer_api::list(&t3, port).await.expect("ls")
    })
    .await
    .expect("not held behind the start");
    assert!(at_once.is_empty());
    assert!(!starting.is_finished() && !stopping.is_finished());

    drop(frozen);
    let (started, stopped) = (
        starting.await.expect("start task"),
        stopping.await.expect("stop task"),
    );
    assert_eq!(started.0, 200);
    assert_eq!(stopped.0, 200);
    assert_eq!(state.sandboxes().live().await, 1);
    assert_eq!(state.sandboxes().unsent().await, 0);
    assert_eq!(ends(&mut ana).await, [Some("stop".to_owned())]);
}

/// The person's revocations, one sandbox and then `all`, and the proxy's
/// ends that answer them, from the server's log to `klav log verify` on
/// the person's device: the `all` the server builds is the list the
/// verifier rebuilds from the chain (an ended sandbox out, one the person
/// revoked and the proxy has not ended in), and a `person` end verifies.
/// `person_local` is still refused by the server (review of #341, 1).
#[tokio::test(flavor = "multi_thread")]
async fn the_persons_revocations_verify_on_the_persons_device() {
    use klav_proto::sandbox::{
        RevokeTarget, SUFFIX_REVOKED, SandboxEnd, SandboxRevoked, sandbox_path,
    };
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let proxy_id = proxy.id();
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port) = serve(proxy, clock, dir.path().join("store.json")).await;

    // One ended, then two live: the issuer's limit.
    let ended = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    assert!(
        issuer_api::stop(&t3, port, ended.sandbox_id)
            .await
            .expect("stop")
    );
    let mut live = Vec::new();
    for label in ["chat-2", "chat-3"] {
        live.push(
            issuer_api::start(&mut t3, port, &request(label, &["northflank"]))
                .await
                .expect("start")
                .sandbox_id,
        );
    }
    let (one, other) = (live[0], live[1]);

    // The person revokes one, then all: the proxy has not ended the first,
    // so `all` covers both live ones, and not the ended one.
    let first = ana
        .revoke_sandboxes(proxy_id, RevokeTarget::One(one))
        .await
        .expect("revoke one");
    assert_eq!(first.sandbox_ids, [one]);
    let all = ana
        .revoke_sandboxes(proxy_id, RevokeTarget::All)
        .await
        .expect("revoke all");
    let mut both = vec![one, other];
    both.sort();
    assert_eq!(all.sandbox_ids, both);
    ana.verify_audit()
        .await
        .expect("the revocations verify before the proxy answers");

    // `person_local` (the proxy's own socket) is refused, and nothing is
    // logged: only the proxy's key signs it, and released verifiers reject
    // it.
    let before = ana
        .audit_log(&klav_client::audit::LogFilter::default())
        .await
        .expect("log")
        .len();
    let refused = state
        .post_signed(
            &sandbox_path(other, SUFFIX_REVOKED),
            &SandboxRevoked::new(SandboxEnd::PersonLocal),
        )
        .await
        .expect_err("person_local is refused");
    assert!(
        matches!(refused, klav_client::ClientError::Api { status: 400, .. }),
        "{refused:?}"
    );
    assert_eq!(
        ana.audit_log(&klav_client::audit::LogFilter::default())
            .await
            .expect("log")
            .len(),
        before,
        "nothing logged"
    );

    // The proxy answers with `person`: the first revocation's `at` for
    // one, the `all`'s for the other.
    for (id, at) in [(one, first.at), (other, all.at)] {
        let mut answer = SandboxRevoked::new(SandboxEnd::Person);
        answer.at = Some(at);
        state
            .post_signed(&sandbox_path(id, SUFFIX_REVOKED), &answer)
            .await
            .expect("person end");
    }

    let report = ana.verify_audit().await.expect("the chain verifies");
    assert!(
        !report.warnings.iter().any(|w| w.contains("sandbox")),
        "{:?}",
        report.warnings
    );
    let lines = ana
        .audit_log(&klav_client::audit::LogFilter::default())
        .await
        .expect("log");
    let steps: Vec<(String, Option<String>)> = lines
        .iter()
        .rev()
        .filter(|l| l.action.starts_with("sandbox."))
        .map(|l| (l.action.clone(), l.outcome.clone()))
        .collect();
    let step = |a: &str, o: Option<&str>| (a.to_owned(), o.map(str::to_owned));
    assert_eq!(
        steps,
        [
            step("sandbox.issued", None),
            step("sandbox.revoked", Some("stop")),
            step("sandbox.issued", None),
            step("sandbox.issued", None),
            step("sandbox.revoke_requested", None),
            step("sandbox.revoke_requested", None),
            step("sandbox.revoked", Some("person")),
            step("sandbox.revoked", Some("person")),
        ]
    );
}

/// The proxy reads the person's revocations by their cursor and ends what
/// they cover with `person`, answering each one's `at`, and the person's
/// log verifies. While the proxy is paused the read waits; a sandbox
/// started after an `all` is not covered; reading them all again from the
/// start (as after a restart, the cursor being in memory) ends nothing
/// twice.
#[tokio::test(flavor = "multi_thread")]
async fn the_proxy_ends_what_the_person_revoked() {
    use klav_proto::sandbox::RevokeTarget;
    async fn started(t3: &mut Agent, port: u16, label: &str) -> klav_core::ids::SandboxId {
        issuer_api::start(t3, port, &request(label, &["northflank"]))
            .await
            .expect("start")
            .sandbox_id
    }
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let proxy_id = proxy.id();
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port) = serve(proxy, clock, dir.path().join("store.json")).await;
    let one = started(&mut t3, port, "chat-1").await;
    let _two = started(&mut t3, port, "chat-2").await;
    assert_eq!(sweep(&state).await, 0, "nothing revoked");
    assert_eq!(state.revocation_cursor(), 0);

    // One sandbox: ended with `person` and sent at the next sweep.
    let first = ana
        .revoke_sandboxes(proxy_id, RevokeTarget::One(one))
        .await
        .expect("revoke one");
    assert_eq!(sweep(&state).await, 1);
    assert_eq!(state.sandboxes().live().await, 1);
    assert_eq!(state.sandboxes().unsent().await, 0);
    assert_eq!(state.revocation_cursor(), first.seq);

    // The person revokes all while the proxy is paused: the read waits,
    // and the cursor with it.
    ana.pause_agents(None, 0).await.expect("pause");
    let all = ana
        .revoke_sandboxes(proxy_id, RevokeTarget::All)
        .await
        .expect("revoke all");
    assert_eq!(sweep(&state).await, 0, "paused: nothing read");
    assert_eq!(state.sandboxes().live().await, 1);
    assert_eq!(state.revocation_cursor(), first.seq);
    ana.resume_agents(None).await.expect("resume");
    assert_eq!(sweep(&state).await, 1);
    assert_eq!(state.sandboxes().live().await, 0);
    assert_eq!(state.sandboxes().unsent().await, 0);
    assert_eq!(state.revocation_cursor(), all.seq);

    // A sandbox started after the `all` is not covered by it.
    let three = started(&mut t3, port, "chat-3").await;
    assert_eq!(sweep(&state).await, 0);
    // From the start again, as after a restart: nothing ends twice, and
    // the new sandbox stays.
    state.set_revocation_cursor(0);
    assert_eq!(sweep(&state).await, 0);
    assert_eq!(state.revocation_cursor(), all.seq);
    let views = state.sandboxes().views().await;
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].sandbox_id, three);

    let report = ana.verify_audit().await.expect("the chain verifies");
    assert!(
        !report.warnings.iter().any(|w| w.contains("sandbox")),
        "{:?}",
        report.warnings
    );
    assert_eq!(
        ends(&mut ana).await,
        [Some("person".to_owned()), Some("person".to_owned())]
    );
}

/// A revoked sandbox is served no more as soon as the proxy reads the
/// revocation, before the server takes its end (review of #348, 2): with
/// the proxy paused between the read and the send, the end waits in the
/// outbox and a claim is already refused. The pending `person` end keeps
/// its `at` through a restart (save, open; review of #348, 3), and is sent
/// on resume.
#[tokio::test]
async fn a_revoked_sandbox_is_refused_before_the_server_takes_its_end() {
    use klav_proto::sandbox::RevokeTarget;
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let proxy_id = proxy.id();
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let store = dir.path().join("store.json");
    let (state, port) = serve(proxy, Arc::clone(&clock), store.clone()).await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");
    let package = decode_package(&started.package).expect("a ksb1_ package");
    ana.revoke_sandboxes(proxy_id, RevokeTarget::One(started.sandbox_id))
        .await
        .expect("revoke");

    let revoked = crate::sandboxes::read_revocations(&state).await.covered;
    assert_eq!(revoked.len(), 1);
    let at = revoked[&started.sandbox_id];
    ana.pause_agents(None, 0).await.expect("pause");
    assert_eq!(crate::sandboxes::end_due(&state, &revoked).await, 1);
    crate::sandboxes::flush(&state).await;
    assert_eq!(state.sandboxes().live().await, 0, "served no more");
    assert_eq!(state.sandboxes().unsent().await, 1, "the end waits");
    assert!(matches!(
        crate::claims::claim(&state, started.sandbox_id, &package.secret, [7; 32]).await,
        Err(crate::claims::ChannelError::Revoked)
    ));
    // A failed send keeps the end: another try while paused changes nothing.
    crate::sandboxes::flush(&state).await;
    assert_eq!(state.sandboxes().unsent().await, 1);

    // The store holds the `person` end with its `at`, and a proxy
    // restarted after the resume (a paused one does not start) reads it
    // back before any sweep sends it.
    let saved = std::fs::read_to_string(&store).expect("store");
    assert!(saved.contains(&format!("\"at\":{at}")), "the at is saved");
    ana.resume_agents(None).await.expect("resume");
    drop(state);
    let proxy = Agent::load(&Home::at(dir.path().join("agent-klav-proxy")), "klav-proxy")
        .expect("load proxy");
    let (state, _) = serve(proxy, clock, store).await;
    assert_eq!(state.sandboxes().live().await, 0);
    assert_eq!(
        state.sandboxes().unsent().await,
        1,
        "kept through a restart"
    );
    sweep(&state).await;
    assert_eq!(state.sandboxes().unsent().await, 0, "sent on resume");
    assert_eq!(ends(&mut ana).await, [Some("person".to_owned())]);
}

/// Revocations for two pages of the server: `a` once, first, then `b`
/// again and again, so the second page covers only `b`. Returns the last
/// one's position.
async fn two_pages(
    ana: &mut Unlocked,
    proxy: klav_core::ids::AgentId,
    a: klav_core::ids::SandboxId,
    b: klav_core::ids::SandboxId,
) -> u64 {
    use klav_proto::sandbox::{MAX_REVOCATIONS_PAGE, RevokeTarget};
    ana.revoke_sandboxes(proxy, RevokeTarget::One(a))
        .await
        .expect("revoke a");
    let mut last = 0;
    for _ in 0..MAX_REVOCATIONS_PAGE {
        last = ana
            .revoke_sandboxes(proxy, RevokeTarget::One(b))
            .await
            .expect("revoke b")
            .seq;
    }
    last
}

/// A sweep cut short between reading a page and ending what it covers
/// (the first sweep's time limit, with a second page that never comes)
/// commits no cursor, so the next sweep reads the first page again and
/// ends `a` (review of #348, 1). Before the fix, the cursor had passed
/// `a`'s revocation and the next sweep ended only `b`.
#[tokio::test(flavor = "multi_thread")]
async fn a_sweep_cut_short_mid_read_skips_no_revocation() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let proxy_id = proxy.id();
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port) = serve(proxy, clock, dir.path().join("store.json")).await;
    let mut started = Vec::new();
    for label in ["chat-a", "chat-b"] {
        let s = issuer_api::start(&mut t3, port, &request(label, &["northflank"]))
            .await
            .expect("start");
        started.push(s.sandbox_id);
    }
    let last = two_pages(&mut ana, proxy_id, started[0], started[1]).await;

    state.stall_revocations_after(Some(1));
    let cut = tokio::time::timeout(std::time::Duration::from_secs(3), sweep(&state)).await;
    assert!(cut.is_err(), "the second page never comes");
    assert_eq!(state.revocation_cursor(), 0, "no cursor without the ends");
    assert_eq!(state.sandboxes().live().await, 2);

    state.stall_revocations_after(None);
    assert_eq!(sweep(&state).await, 2, "a and b");
    assert_eq!(state.sandboxes().live().await, 0);
    assert_eq!(state.sandboxes().unsent().await, 0);
    assert_eq!(state.revocation_cursor(), last);
    // A sweep that started from an older cursor never sets it back.
    state.commit_revocation_cursor(0, 1);
    assert_eq!(state.revocation_cursor(), last);
}

/// `Bound::run` ends what the person revoked while the proxy was stopped
/// before it serves anything (ADR 0036 E3.3, T169; review of #348, 2).
/// A start whose read stalls past the bound serves anyway, with nothing
/// committed, and the next sweep ends the sandboxes; a later start with
/// the server answering ends them before the first answer.
#[tokio::test(flavor = "multi_thread")]
async fn the_proxy_ends_revoked_sandboxes_before_it_serves() {
    use crate::app::{ServeOptions, StartEnv, bind};
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let proxy_id = proxy.id();
    let home = Home::at(dir.path().join("agent-klav-proxy"));
    let store = Sandboxes::path_in(&home, "klav-proxy");
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port) = serve(proxy, clock, store).await;
    let mut started = Vec::new();
    for label in ["chat-a", "chat-b"] {
        let s = issuer_api::start(&mut t3, port, &request(label, &["northflank"]))
            .await
            .expect("start");
        started.push(s.sandbox_id);
    }
    // Stopped: it serves no more, and the person revokes meanwhile.
    drop(state);
    let last = two_pages(&mut ana, proxy_id, started[0], started[1]).await;
    let options = || ServeOptions {
        home: home.clone(),
        name: "klav-proxy".into(),
        port: 0,
        channel: None,
        max_body: crate::proxy::DEFAULT_MAX_BODY,
        request_timeout: crate::proxy::DEFAULT_REQUEST_TIMEOUT,
        no_local_calls: false,
        env: StartEnv::from_lookup(|_| None),
    };
    // Runs a bound proxy; the stop is the sender.
    let run = |bound: crate::app::Bound| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(bound.run(async {
            let _ = stopped.await;
        }));
        (stop, task)
    };
    async fn live(t3: &Agent, port: u16) -> Vec<klav_core::ids::SandboxId> {
        let mut ids: Vec<_> = issuer_api::list(t3, port)
            .await
            .expect("list")
            .into_iter()
            .map(|s| s.sandbox_id)
            .collect();
        ids.sort();
        ids
    }

    // The second page stalls past the bound: it serves anyway, and the
    // first answer still lists both.
    let bound = bind(options())
        .await
        .expect("bind")
        .with_first_sweep_limit(std::time::Duration::from_secs(2));
    let (state, port) = (bound.state(), bound.port());
    state.stall_revocations_after(Some(1));
    let (stop, task) = run(bound);
    let mut all = started.clone();
    all.sort();
    assert_eq!(live(&t3, port).await, all, "served, nothing ended");
    assert_eq!(state.revocation_cursor(), 0, "nothing committed");
    // The next sweep reads both pages and ends a and b.
    state.stall_revocations_after(None);
    assert_eq!(sweep(&state).await, 2);
    assert_eq!(live(&t3, port).await, Vec::new());
    assert_eq!(state.revocation_cursor(), last);
    let c = issuer_api::start(&mut t3, port, &request("chat-c", &["northflank"]))
        .await
        .expect("start c")
        .sandbox_id;
    assert_eq!(live(&t3, port).await, vec![c]);
    stop.send(()).expect("stop");
    task.await.expect("join").expect("run");

    // The person revokes c while it is stopped; the next start ends it
    // before its first answer.
    ana.revoke_sandboxes(proxy_id, klav_proto::sandbox::RevokeTarget::One(c))
        .await
        .expect("revoke c");
    let bound = bind(options()).await.expect("bind");
    let (state, port) = (bound.state(), bound.port());
    let (stop, task) = run(bound);
    assert_eq!(live(&t3, port).await, Vec::new(), "ended before serving");
    assert_eq!(state.sandboxes().live().await, 0);
    // Its end goes out from the sweeper, without holding up the listener.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while state.sandboxes().unsent().await > 0 {
        assert!(std::time::Instant::now() < deadline, "the end was sent");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    stop.send(()).expect("stop");
    task.await.expect("join").expect("run");
    let ends = ends(&mut ana).await;
    assert_eq!(ends.len(), 3, "{ends:?}");
    assert!(
        ends.iter().all(|e| e.as_deref() == Some("person")),
        "{ends:?}"
    );
}

/// The proxy logs its store's epoch before its first heartbeat, sends
/// heartbeats under it with a growing `seq` saved in its heartbeat file,
/// and the person's log verifies with that epoch as the proxy's current
/// one (ADR 0036 E3.3, spec §13.12). A heartbeat file restored from an old
/// copy gets a `409`, and the proxy starts a new epoch rather than reuse a
/// `seq`; a restored file whose epoch the server already has gets a `409`
/// on the reset, and the proxy starts another at once. No attempt sends
/// more than two resets and one heartbeat, so a rolled-back store never
/// loops. A heartbeat refused in a pause is kept and sent as it is after
/// the resume.
#[tokio::test(flavor = "multi_thread")]
async fn the_proxy_heartbeats_and_a_rolled_back_store_starts_a_new_epoch() {
    use crate::heartbeat::{Heartbeats, Sent, beat, path_of};
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let proxy_id = proxy.id();
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let store = dir.path().join("proxy.sandbox-store");
    let file = path_of(&store);
    let (state, port) = serve(proxy, Arc::clone(&clock), store.clone()).await;
    issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");

    // First heartbeat: the reset, then seq 1.
    assert_eq!(beat(&state, false).await, Sent::Sent);
    let (epoch, logged, seq) = state.heartbeats().epoch().await;
    assert!(logged);
    assert_eq!(seq, 1);
    // Not due again until the period passes.
    assert_eq!(beat(&state, false).await, Sent::NotDue);
    let old_copy = std::fs::read(&file).expect("heartbeat file");
    assert_eq!(beat(&state, true).await, Sent::Sent);
    assert_eq!(state.heartbeats().epoch().await.2, 2);
    let report = ana.verify_audit().await.expect("the chain verifies");
    assert_eq!(report.store_epochs.len(), 1);
    assert_eq!(report.store_epochs[0].proxy, proxy_id);
    assert_eq!(report.store_epochs[0].store_epoch, epoch);
    assert_eq!(resets(&mut ana).await, 1);

    // Signed for the path with a query string, even a bare `?`: a `400`,
    // nothing logged or kept, and the chain still verifies (review of
    // #357, 1).
    for query in ["?x=1", "?"] {
        let reset = klav_proto::sandbox::SandboxStoreReset {
            store_epoch: klav_proto::Blob::new(vec![9; klav_proto::sandbox::STORE_EPOCH_LEN]),
        };
        let path = format!("{}{query}", klav_proto::sandbox::PATH_STORE_RESET);
        let refused = state.post_signed(&path, &reset).await;
        assert!(
            matches!(
                refused,
                Err(klav_client::ClientError::Api { status: 400, .. })
            ),
            "{path}"
        );
        let beat_body = klav_proto::sandbox::SandboxHeartbeat {
            v: klav_proto::sandbox::HEARTBEAT_VERSION,
            store_epoch: epoch.clone(),
            seq: 3,
            sent_at_ms: real_now(),
            sandboxes: Vec::new(),
        };
        let path = format!("{}{query}", klav_proto::sandbox::PATH_SANDBOX_STATE);
        let refused = state.put_signed(&path, &beat_body).await;
        assert!(
            matches!(
                refused,
                Err(klav_client::ClientError::Api { status: 400, .. })
            ),
            "{path}"
        );
    }
    assert_eq!(resets(&mut ana).await, 1);
    // `seq` 3 was not taken: the next heartbeat uses it.
    assert_eq!(beat(&state, true).await, Sent::Sent);
    assert_eq!(state.heartbeats().epoch().await.2, 3);

    // The file rolled back to seq 1: its next heartbeat would reuse seq 2.
    std::fs::write(&file, &old_copy).expect("restore");
    state.set_heartbeats(Heartbeats::open(file.clone()));
    assert_eq!(beat(&state, true).await, Sent::Failed, "409: a new epoch");
    let (fresh, logged, seq) = state.heartbeats().epoch().await;
    assert_ne!(fresh, epoch);
    assert!(!logged);
    assert_eq!(seq, 0);
    assert_eq!(beat(&state, true).await, Sent::Sent);
    assert_eq!(resets(&mut ana).await, 2);

    // A file whose epoch the server already has, its reset not marked as
    // logged (the answer was lost): the reset gets a 409, a new epoch is
    // logged in the same attempt, and the heartbeat goes.
    let lost = serde_json::json!({
        "v": 1, "store_epoch": fresh, "logged": false, "seq": 0
    });
    std::fs::write(&file, serde_json::to_vec(&lost).expect("json")).expect("write");
    state.set_heartbeats(Heartbeats::open(file.clone()));
    assert_eq!(beat(&state, true).await, Sent::Sent);
    assert_eq!(resets(&mut ana).await, 3);
    let report = ana.verify_audit().await.expect("the chain verifies");
    assert_eq!(
        report.store_epochs[0].store_epoch,
        state.heartbeats().epoch().await.0
    );

    // Paused: the server refuses it, and the proxy keeps that heartbeat,
    // which names the live sandbox; more attempts in the pause send the
    // same one and use no `seq`. After the resume it goes as it is, and a
    // fresh one follows a minute later (ADR 0036 E3.3).
    let sandbox = state.sandboxes().views().await[0].sandbox_id;
    ana.pause_agents(None, 0).await.expect("pause");
    assert_eq!(beat(&state, true).await, Sent::Failed);
    let kept = state.heartbeats().kept().await.expect("kept");
    let named: Vec<_> = kept.sandboxes.iter().map(|l| (l.id, l.connected)).collect();
    assert_eq!(named, [(sandbox, false)]);
    let seq = state.heartbeats().epoch().await.2;
    assert_eq!(kept.seq, seq);
    assert_eq!(beat(&state, true).await, Sent::Failed);
    assert_eq!(state.heartbeats().epoch().await.2, seq, "no seq used");
    ana.resume_agents(None).await.expect("resume");
    assert_eq!(beat(&state, false).await, Sent::NotDue, "a minute apart");
    clock
        .0
        .fetch_add(crate::heartbeat::SOONEST_MS, Ordering::SeqCst);
    assert_eq!(beat(&state, false).await, Sent::Resent);
    assert!(state.heartbeats().kept().await.is_none());
    assert_eq!(state.heartbeats().epoch().await.2, seq);
    assert_eq!(beat(&state, false).await, Sent::NotDue);
    clock
        .0
        .fetch_add(crate::heartbeat::SOONEST_MS, Ordering::SeqCst);
    assert_eq!(beat(&state, false).await, Sent::Sent, "a fresh one");
    assert_eq!(state.heartbeats().epoch().await.2, seq + 1);

    // A server that refuses every epoch and every heartbeat: each attempt
    // stops after two resets (the second under a fresh epoch), or after one
    // reset and one heartbeat, and the next attempt waits a minute.
    state.always_conflict(true);
    assert_eq!(beat(&state, true).await, Sent::Failed);
    assert_eq!(state.conflicts(), 1, "the heartbeat, then a new epoch");
    assert_eq!(beat(&state, true).await, Sent::Failed);
    assert_eq!(state.conflicts(), 3, "two resets, then it stops");
    assert_eq!(beat(&state, false).await, Sent::NotDue, "a minute apart");
    assert_eq!(state.conflicts(), 3);
    state.always_conflict(false);
    assert_eq!(resets(&mut ana).await, 3, "none of them reached the server");

    // A kept heartbeat the server can never take (a `400`: here its
    // `sent_at_ms` is six minutes ahead of the server's clock) is dropped,
    // and the next attempt sends a fresh one (review of #357, 7).
    assert_eq!(beat(&state, true).await, Sent::Sent);
    let real = clock.0.load(Ordering::SeqCst);
    clock.0.store(real + 6 * 60 * 1000, Ordering::SeqCst);
    ana.pause_agents(None, 0).await.expect("pause");
    assert_eq!(beat(&state, true).await, Sent::Failed);
    let held = state.heartbeats().kept().await.expect("kept");
    ana.resume_agents(None).await.expect("resume");
    clock.0.store(real, Ordering::SeqCst);
    assert_eq!(beat(&state, true).await, Sent::Failed, "400: dropped");
    assert!(state.heartbeats().kept().await.is_none());
    assert!(
        Heartbeats::open(file.clone()).kept().await.is_none(),
        "saved"
    );
    assert_eq!(beat(&state, true).await, Sent::Sent);
    assert_eq!(state.heartbeats().epoch().await.2, held.seq + 1);

    // A new epoch is saved before its reset is sent: a reset refused in a
    // pause leaves the file holding the epoch it tried, so an epoch the
    // server may have taken is never sent again as new.
    std::fs::remove_file(&file).expect("remove");
    state.set_heartbeats(Heartbeats::open(file.clone()));
    let (tried, _, _) = state.heartbeats().epoch().await;
    ana.pause_agents(None, 0).await.expect("pause");
    assert_eq!(beat(&state, true).await, Sent::Failed);
    assert_eq!(
        Heartbeats::open(file.clone()).epoch().await,
        (tried, false, 0)
    );
    ana.resume_agents(None).await.expect("resume");
}

/// How many `sandbox.store_reset` the person's log has, once it verifies.
async fn resets(ana: &mut Unlocked) -> usize {
    ana.verify_audit().await.expect("the chain verifies");
    ana.audit_log(&klav_client::audit::LogFilter::default())
        .await
        .expect("log")
        .iter()
        .filter(|l| l.action == "sandbox.store_reset")
        .count()
}

/// What the real proxy signs, read back from `sandbox_state` as the person,
/// passes the device's check: the person's list shows the chain's sandbox
/// with the proxy's heartbeat, the watermark is kept on the device, and
/// the heartbeat speaks only of a sandbox the chain shows live (ADR 0036
/// E2.1, E3.3).
#[tokio::test(flavor = "multi_thread")]
async fn the_persons_list_shows_the_chain_and_the_real_proxys_heartbeat() {
    use crate::heartbeat::{Sent, beat};
    use klav_client::sandboxes::{EndReason, NoSigns, SANDBOX_MARKS_FILE, SandboxStatus};
    use klav_proto::sandbox::RevokeTarget;
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let (proxy_id, t3_id) = (proxy.id(), t3.id());
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let store = dir.path().join("proxy.sandbox-store");
    let (state, port) = serve(proxy, Arc::clone(&clock), store).await;
    let started = issuer_api::start(&mut t3, port, &request("chat-1", &["northflank"]))
        .await
        .expect("start");

    // No heartbeat yet: the chain's sandbox, and no signs of the proxy.
    let list = ana.sandbox_list().await.expect("list");
    let view = list.proxy.clone().expect("the account's proxy");
    assert_eq!(view.agent_id, proxy_id);
    assert_eq!(view.name.as_deref(), Some("klav-proxy"));
    assert_eq!(
        (view.no_signs, view.quiet, view.paused),
        (Some(NoSigns::NoHeartbeat), true, false)
    );
    let row = &list.sandboxes[..];
    assert_eq!(row.len(), 1);
    let row = &row[0];
    assert_eq!(
        (row.sandbox_id, row.status, row.label.as_str()),
        (started.sandbox_id, SandboxStatus::Waiting, "chat-1")
    );
    assert_eq!(
        (row.issuer_id, row.issuer_name.as_deref(), row.proxy_id),
        (t3_id, Some("t3-code"), proxy_id)
    );
    assert_eq!(row.connected, None);
    let marks = dir.path().join("laptop").join(SANDBOX_MARKS_FILE);
    assert!(!marks.exists());

    // The proxy logs its epoch and beats: the device checks what it
    // signed, with its signed time, and keeps the watermark.
    assert_eq!(beat(&state, true).await, Sent::Sent);
    let list = ana.sandbox_list().await.expect("list");
    let view = list.proxy.expect("proxy");
    assert_eq!(view.no_signs, None);
    assert_eq!(view.heartbeat_sent_at, Some(clock.0.load(Ordering::SeqCst)));
    assert!(!view.quiet);
    assert_eq!(list.sandboxes[0].connected, Some(false));
    assert!(marks.exists());
    assert!(!list.marks_unreadable);
    assert_eq!(beat(&state, true).await, Sent::Sent);
    assert!(ana.sandbox_list().await.expect("list").proxy.is_some());

    // A damaged marks file: the list still shows the heartbeat, says the
    // file could not be used, and writes it again.
    std::fs::write(&marks, b"not sealed").expect("damage");
    let list = ana.sandbox_list().await.expect("list");
    assert!(list.marks_unreadable);
    assert!(
        list.warnings
            .iter()
            .any(|w| w.contains("sandbox-marks.bin"))
    );
    assert_eq!(list.proxy.expect("proxy").no_signs, None);
    let list = ana.sandbox_list().await.expect("list");
    assert!(!list.marks_unreadable, "written again");

    // A server that does not list the account's proxy among its agents
    // would hide all its sandboxes: the list refuses it (here the setting
    // names an agent the server does not have, which reads the same).
    let real = ana.preferences().expect("preferences").proxy();
    let hidden = klav_core::model::preferences::ProxySetting {
        mode: klav_core::model::preferences::ProxyMode::Own,
        agent_id: Some(klav_core::ids::AgentId::generate()),
    };
    ana.set_proxy_setting(hidden).await.expect("setting");
    let refused = ana.sandbox_list().await;
    assert!(
        matches!(refused, Err(klav_client::ClientError::Security(_))),
        "{refused:?}"
    );
    // For the app, the same refusal names its check and keeps the words.
    let checked = ana.sandbox_list_checked().await.expect("checked");
    let refusal = checked.expect_err("refused");
    assert_eq!(
        refusal.check,
        klav_client::sandboxes::ListCheck::UnlistedProxy {
            agent_id: hidden.agent_id.expect("named"),
        }
    );
    assert!(
        refusal.message.contains("klav proxy status"),
        "{}",
        refusal.message
    );
    ana.set_proxy_setting(real).await.expect("setting");

    // A pause the account signed shows on the proxy, and goes with it.
    ana.pause_agents(None, 0).await.expect("pause");
    assert!(
        ana.sandbox_list()
            .await
            .expect("list")
            .proxy
            .expect("proxy")
            .paused
    );
    ana.resume_agents(None).await.expect("resume");
    assert!(
        !ana.sandbox_list()
            .await
            .expect("list")
            .proxy
            .expect("proxy")
            .paused
    );

    // With a live sandbox, a heartbeat signed 11 minutes ago is quiet: the
    // age comes from the proxy's signed time, not the server's.
    let real = clock.0.load(Ordering::SeqCst);
    let quiet_at = |minutes: i64| real_now() - minutes * 60 * 1000;
    clock.0.store(quiet_at(11), Ordering::SeqCst);
    assert_eq!(beat(&state, true).await, Sent::Sent);
    let view = ana
        .sandbox_list()
        .await
        .expect("list")
        .proxy
        .expect("proxy");
    assert!(view.quiet, "live: quiet past 10 minutes");
    assert!(view.heartbeat_age_ms.expect("age") >= 11 * 60 * 1000);
    clock.0.store(real, Ordering::SeqCst);
    assert_eq!(beat(&state, true).await, Sent::Sent);

    // The person revokes it: revoking until the proxy logs its end, then
    // ended with `person`, and the heartbeat no longer speaks of it.
    ana.revoke_sandboxes(proxy_id, RevokeTarget::One(started.sandbox_id))
        .await
        .expect("revoke");
    // Then all of them: the row shows the latest revocation that covered it.
    let all = ana
        .revoke_sandboxes(proxy_id, RevokeTarget::All)
        .await
        .expect("revoke all");
    let list = ana.sandbox_list().await.expect("list");
    assert_eq!(list.sandboxes[0].status, SandboxStatus::Revoking);
    assert_eq!(list.sandboxes[0].revoked_by_person_at, Some(all.at));
    assert_eq!(list.sandboxes[0].connected, Some(false));
    assert_eq!(sweep(&state).await, 1);
    assert_eq!(beat(&state, true).await, Sent::Sent);
    let list = ana.sandbox_list().await.expect("list");
    let row = &list.sandboxes[0];
    assert_eq!(
        (row.status, row.end_reason, row.connected),
        (SandboxStatus::Ended, Some(EndReason::Person), None)
    );
    assert!(row.ended_at.is_some() && row.revoked_by_person_at.is_some());

    // Without a live sandbox the proxy beats every 30 minutes: quiet only
    // past 40.
    for (minutes, quiet) in [(11, false), (41, true)] {
        clock.0.store(quiet_at(minutes), Ordering::SeqCst);
        assert_eq!(beat(&state, true).await, Sent::Sent);
        let view = ana
            .sandbox_list()
            .await
            .expect("list")
            .proxy
            .expect("proxy");
        assert_eq!(view.quiet, quiet, "idle, {minutes} minutes");
    }
}
