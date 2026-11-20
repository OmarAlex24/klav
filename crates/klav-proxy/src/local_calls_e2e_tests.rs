//! `klav-proxy serve --no-local-calls` end to end (ADR 0042 §3, layer 2):
//! a real `klav-server`, the person making `t3-code` an issuer, and the
//! proxy's loopback listener with and without the flag. With it, every
//! profile call on the loopback listener is refused before the server is
//! asked or a credential read, whatever its path, method or headers; the
//! issuers' signed API and the sandboxes' channel keep working. Without
//! it, nothing changes.

use std::sync::Arc;
use std::sync::atomic::AtomicI64;

use klav_core::crypto::channel::TlsSigner;
use klav_core::crypto::sandbox::decode_package;
use klav_forward::forward::{self, Proxy};
use klav_sdk::sandbox as issuer_api;

use crate::channel::ChannelLimits;
use crate::channel_e2e_tests::{serve_configured, upstream_client};
use crate::e2e_tests::Upstream;
use crate::e2e_tests::common::ServerProcess;
use crate::errors::{NotAllowed, ProxyError};
use crate::proxy::ProxyState;
use crate::sandbox_e2e_tests::{Manual, credential_at, real_now, request, setup_with};

/// The `message` of the refusal `--no-local-calls` gives.
async fn local_calls_off() -> String {
    let res = axum::response::IntoResponse::into_response(ProxyError::NotAllowed(
        NotAllowed::LocalCallsOff,
    ));
    assert_eq!(res.status(), 403);
    assert_eq!(res.headers()["klav-error"], "klav_not_allowed");
    let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
        .await
        .expect("body");
    let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
    body["message"].as_str().expect("message").to_owned()
}

/// What the proxy answered: status, `Klav-Error` and the body's `message`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Answer {
    status: u16,
    code: String,
    message: String,
}

/// One request to the loopback listener: method, path and extra headers.
struct Shape {
    method: &'static str,
    path: String,
    headers: Vec<(&'static str, &'static str)>,
}

fn shape(method: &'static str, path: &str) -> Shape {
    Shape {
        method,
        path: path.to_owned(),
        headers: Vec::new(),
    }
}

/// Every kind of request the loopback listener serves other than a signed
/// issuer request: each route and path shape of `proxy::router`, a known
/// profile with every method, and the refusals that come before a profile
/// is looked up.
fn shapes(sandbox: &str) -> Vec<Shape> {
    let mut all = Vec::new();
    // A known profile, every method (the policy allows only `GET /v1`).
    for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
        all.push(shape(method, "/northflank/v1/projects"));
    }
    // The profile's root, an unknown profile and the listener's root.
    all.push(shape("GET", "/northflank"));
    all.push(shape("GET", "/maple/v1/projects"));
    all.push(shape("GET", "/"));
    // `/_klav/` paths that are not issuer routes: the channel's own routes
    // (served only on the channel) and others.
    all.push(shape("GET", "/_klav/status"));
    all.push(shape("POST", "/_klav/release"));
    all.push(shape("GET", "/_klav/other"));
    all.push(shape("GET", &format!("/_klav/sandboxes/{sandbox}")));
    all.push(shape(
        "POST",
        &format!("/_klav/sandboxes/{sandbox}/stop/more"),
    ));
    // A browser's headers and another `Host`, refused today too.
    let mut page = shape("GET", "/northflank/v1/projects");
    page.headers.push(("origin", "https://evil.example"));
    all.push(page);
    let mut rebound = shape("GET", "/northflank/v1/projects");
    rebound.headers.push(("host", "evil.example"));
    all.push(rebound);
    all
}

/// A method the policy cannot judge, sent on the wire as it is.
const ODD_METHOD: &[u8] = b"get /northflank/v1/projects HTTP/1.1\r\n";

/// Request lines a client library would not send as they are: `CONNECT`
/// in authority-form, a doubled slash before the issuer's path, and its
/// slash escaped. None of them is an issuer route, so with the flag each
/// is a refused local call.
const RAW_SHAPES: [&[u8]; 5] = [
    b"CONNECT host:443 HTTP/1.1\r\n",
    b"GET //_klav/sandboxes HTTP/1.1\r\n",
    b"POST //_klav/sandboxes HTTP/1.1\r\n",
    b"GET /_klav%2Fsandboxes HTTP/1.1\r\n",
    b"POST /_klav%2Fsandboxes HTTP/1.1\r\n",
];

async fn send(port: u16, s: &Shape) -> Answer {
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("client");
    let mut req = client.request(
        reqwest::Method::from_bytes(s.method.as_bytes()).expect("method"),
        format!("http://127.0.0.1:{port}{}", s.path),
    );
    for (name, value) in &s.headers {
        req = req.header(*name, *value);
    }
    answer(req.send().await.expect("an answer")).await
}

async fn answer(res: reqwest::Response) -> Answer {
    let status = res.status().as_u16();
    let code = res
        .headers()
        .get("klav-error")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = res.text().await.unwrap_or_default();
    let message = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v["message"].as_str().map(str::to_owned))
        .unwrap_or_default();
    Answer {
        status,
        code,
        message,
    }
}

/// A request written on the wire as it is (for a method `reqwest` would
/// not send): the status and the `Klav-Error`.
async fn raw(port: u16, head: &[u8]) -> (u16, String) {
    let a = raw_answer(port, head).await;
    (a.status, a.code)
}

/// [`raw`], with the error's message.
async fn raw_answer(port: u16, head: &[u8]) -> Answer {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let mut request = head.to_vec();
    request.extend_from_slice(
        format!("host: 127.0.0.1:{port}\r\nconnection: close\r\n\r\n").as_bytes(),
    );
    tcp.write_all(&request).await.expect("write");
    let mut out = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tcp.read_to_end(&mut out),
    )
    .await;
    let text = String::from_utf8_lossy(&out).into_owned();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let code = text
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("klav-error: ")
                .map(str::to_owned)
        })
        .unwrap_or_default();
    let body = text.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    let message = body
        .find('{')
        .zip(body.rfind('}'))
        .and_then(|(from, to)| serde_json::from_str::<serde_json::Value>(&body[from..=to]).ok())
        .and_then(|v| v["message"].as_str().map(str::to_owned))
        .unwrap_or_default();
    Answer {
        status,
        code,
        message,
    }
}

/// How many accesses the server logged (one per profile call it was
/// asked about).
async fn accesses(ana: &mut klav_client::Unlocked) -> usize {
    ana.audit_log(&klav_client::audit::LogFilter::default())
        .await
        .expect("log")
        .iter()
        .filter(|l| l.action == "agent.access")
        .count()
}

struct World {
    server: ServerProcess,
    _dir: tempfile::TempDir,
    ana: klav_client::Unlocked,
    t3: klav_sdk::Agent,
    _state: Arc<ProxyState>,
    port: u16,
    channel: std::net::SocketAddr,
    upstream: Upstream,
    _stop: (
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<Result<(), String>>,
    ),
}

async fn world(no_local_calls: bool) -> World {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let upstream = Upstream::start().await;
    let mut spec = credential_at(
        "northflank",
        &format!("https://upstream.test:{}", upstream.port),
    );
    spec.rate_per_minute = Some(1000);
    let (ana, proxy, t3) = setup_with(&server, &dir, spec).await;
    let clock = Arc::new(Manual(AtomicI64::new(real_now())));
    let (state, port, channel, stop) = serve_configured(
        proxy,
        clock,
        dir.path().join("proxy.sandbox-store"),
        upstream_client(),
        ChannelLimits::default(),
        None,
        |s| {
            if no_local_calls {
                s.without_local_calls()
            } else {
                s
            }
        },
    )
    .await;
    World {
        server,
        _dir: dir,
        ana,
        t3,
        _state: state,
        port,
        channel,
        upstream,
        _stop: stop,
    }
}

impl World {
    /// The issuer's three signed routes: start, list and stop. Returns the
    /// sandbox it started and left live.
    async fn issuer_routes_work(&mut self) -> klav_core::crypto::sandbox::SandboxPackage {
        let started = issuer_api::start(&mut self.t3, self.port, &request("kept", &["northflank"]))
            .await
            .expect("a signed start");
        let other = issuer_api::start(&mut self.t3, self.port, &request("gone", &["northflank"]))
            .await
            .expect("a signed start");
        let live = issuer_api::list(&self.t3, self.port)
            .await
            .expect("a signed list");
        assert_eq!(live.len(), 2);
        assert!(
            issuer_api::stop(&self.t3, self.port, other.sandbox_id)
                .await
                .expect("a signed stop")
        );
        assert_eq!(
            issuer_api::list(&self.t3, self.port)
                .await
                .expect("ls")
                .len(),
            1
        );
        decode_package(&started.package).expect("package")
    }

    /// The issuer routes with a method they do not take: axum's own
    /// answer, before any handler.
    async fn wrong_methods(&self, sandbox: &str) -> Vec<Answer> {
        vec![
            send(self.port, &shape("DELETE", "/_klav/sandboxes")).await,
            send(
                self.port,
                &shape("GET", &format!("/_klav/sandboxes/{sandbox}/stop")),
            )
            .await,
        ]
    }

    /// A forwarder claims `package` through the channel and relays a
    /// tool's call: the answer, and what the provider saw.
    async fn through_the_channel(
        &self,
        package: &klav_core::crypto::sandbox::SandboxPackage,
    ) -> u16 {
        let proxy = Proxy::new(
            &format!("tls://{}", self.channel),
            package.proxy_pin,
            TlsSigner::channel_key(),
        )
        .expect("proxy");
        proxy.claim(package).await.expect("claimed");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let local = listener.local_addr().expect("addr").port();
        tokio::spawn(forward::serve_with(
            listener,
            Arc::new(proxy),
            forward::RelayLimits::default(),
        ));
        let res = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("client")
            .get(format!("http://127.0.0.1:{local}/northflank/v1/projects"))
            .header("authorization", "Bearer klav-placeholder")
            .send()
            .await
            .expect("an answer");
        res.status().as_u16()
    }
}

/// With `--no-local-calls`: every shape gets the same `403`, before the
/// server is asked (no access logged, and the same answer with the server
/// gone) and before any credential is read (the provider sees nothing).
/// The issuer's three signed routes and a sandbox's call through the
/// channel still work.
#[tokio::test(flavor = "multi_thread")]
async fn no_local_calls_refuses_every_local_call_and_keeps_the_issuer_api() {
    let mut w = world(true).await;
    let refused = Answer {
        status: 403,
        code: "klav_not_allowed".into(),
        message: local_calls_off().await,
    };

    let package = w.issuer_routes_work().await;
    let sandbox = package.sandbox_id.to_string();
    let before = accesses(&mut w.ana).await;

    for s in shapes(&sandbox) {
        assert_eq!(send(w.port, &s).await, refused, "{} {}", s.method, s.path);
    }
    assert_eq!(
        raw(w.port, ODD_METHOD).await,
        (403, "klav_not_allowed".into())
    );
    for head in RAW_SHAPES {
        assert_eq!(
            raw_answer(w.port, head).await,
            refused,
            "{}",
            String::from_utf8_lossy(head)
        );
    }
    // Not handled by the fallback: the router's own `405`, as without the
    // flag (the second test).
    for a in w.wrong_methods(&sandbox).await {
        assert_eq!(a.status, 405, "{a:?}");
    }
    assert!(
        w.upstream.requests().is_empty(),
        "a refused local call reached the provider"
    );
    assert_eq!(
        accesses(&mut w.ana).await,
        before,
        "the server was asked about a refused local call"
    );

    // A sandbox's call through the channel is served: the flag is only
    // about the loopback listener.
    assert_eq!(w.through_the_channel(&package).await, 200);
    let seen = w.upstream.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].target, "/v1/projects");
    assert_eq!(accesses(&mut w.ana).await, before + 1);

    // With the server gone, the refusal is the same: it never asks.
    w.server.stop();
    for s in shapes(&sandbox) {
        assert_eq!(send(w.port, &s).await, refused, "{} {}", s.method, s.path);
    }
    assert_eq!(w.upstream.requests().len(), 1);
}

/// Without the flag nothing changes: a known profile is served, the other
/// shapes get the refusals they got before, never the `--no-local-calls`
/// one, and with the server gone a profile call says so.
#[tokio::test(flavor = "multi_thread")]
async fn without_the_flag_local_calls_are_served_as_before() {
    let mut w = world(false).await;
    let off = local_calls_off().await;
    let package = w.issuer_routes_work().await;
    let sandbox = package.sandbox_id.to_string();
    let before = accesses(&mut w.ana).await;

    let mut answers = Vec::new();
    for s in shapes(&sandbox) {
        let a = send(w.port, &s).await;
        assert_ne!(a.message, off, "{} {}", s.method, s.path);
        answers.push((s.method, s.path, a));
    }
    let of = |method: &str, path: &str| {
        answers
            .iter()
            .find(|(m, p, _)| *m == method && p == path)
            .map(|(_, _, a)| a.clone())
            .expect("asked")
    };
    // Served: the provider got it, and the server logged it.
    let get = of("GET", "/northflank/v1/projects");
    assert_eq!(get.status, 200, "{get:?}");
    assert!(
        w.upstream
            .requests()
            .iter()
            .any(|r| r.method == "GET" && r.target == "/v1/projects")
    );
    assert!(accesses(&mut w.ana).await > before);
    // Outside the policy: the server refuses.
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        let a = of(method, "/northflank/v1/projects");
        assert_eq!(
            (a.status, a.code.as_str()),
            (403, "klav_not_allowed"),
            "{method}"
        );
    }
    // No such profile: `""`, `maple` and `_klav` alike.
    let unknown = of("GET", "/maple/v1/projects");
    assert_eq!(
        (unknown.status, unknown.code.as_str()),
        (403, "klav_not_allowed")
    );
    for path in [
        "/".to_owned(),
        "/_klav/status".to_owned(),
        "/_klav/other".to_owned(),
        format!("/_klav/sandboxes/{sandbox}"),
    ] {
        assert_eq!(of("GET", &path), unknown, "{path}");
    }
    assert_eq!(of("POST", "/_klav/release"), unknown);
    // The last two shapes, a page's `Origin` and another `Host`: refused
    // as not local, before the profile is looked up.
    let foreign: Vec<&Answer> = answers[answers.len() - 2..]
        .iter()
        .map(|(_, _, a)| a)
        .collect();
    assert_eq!(foreign[0], foreign[1]);
    assert_eq!(
        (foreign[0].status, foreign[0].code.as_str()),
        (403, "klav_not_allowed")
    );
    assert_ne!(foreign[0].message, unknown.message);
    assert_eq!(
        of("POST", &format!("/_klav/sandboxes/{sandbox}/stop/more")),
        unknown
    );
    assert_eq!(
        raw(w.port, ODD_METHOD).await,
        (403, "klav_not_allowed".into())
    );
    for a in w.wrong_methods(&sandbox).await {
        assert_eq!(a.status, 405, "{a:?}");
    }

    // The channel works as well.
    assert_eq!(w.through_the_channel(&package).await, 200);

    // With the server gone, a local profile call is not refused: the proxy
    // asks and cannot reach it.
    w.server.stop();
    let a = send(w.port, &shape("GET", "/northflank/v1/projects")).await;
    assert_eq!(
        (a.status, a.code.as_str()),
        (503, "klav_server_unreachable")
    );
}

/// `klav-proxy serve --no-local-calls` through the real startup path
/// (`app::bind` and `Bound::run`, as `main` calls them): a local profile
/// call is refused, the issuer's signed list answers.
#[tokio::test(flavor = "multi_thread")]
async fn serve_options_carry_the_flag() {
    use crate::app::{ServeOptions, StartEnv};
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (_ana, proxy, t3) = setup_with(
        &server,
        &dir,
        credential_at("northflank", "https://api.northflank.com"),
    )
    .await;
    drop(proxy);
    for no_local_calls in [true, false] {
        let bound = crate::app::bind(ServeOptions {
            home: klav_client::Home::at(dir.path().join("agent-klav-proxy")),
            name: "klav-proxy".into(),
            port: 0,
            channel: None,
            max_body: crate::proxy::DEFAULT_MAX_BODY,
            request_timeout: crate::proxy::DEFAULT_REQUEST_TIMEOUT,
            no_local_calls,
            env: StartEnv::from_lookup(|_| None),
        })
        .await
        .expect("bind");
        let port = bound.port();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(bound.run(async {
            let _ = stopped.await;
        }));
        // `maple` is no profile of this proxy: refused either way, with
        // the flag's own refusal only when it is on.
        let a = send(port, &shape("GET", "/maple/v1")).await;
        assert_eq!((a.status, a.code.as_str()), (403, "klav_not_allowed"));
        assert_eq!(
            a.message == local_calls_off().await,
            no_local_calls,
            "{a:?}"
        );
        assert!(issuer_api::list(&t3, port).await.expect("ls").is_empty());
        let _ = stop.send(());
        task.await.expect("join").expect("run");
    }
}

/// ADR 0044 §3.1: `serve` writes what `main` turned on in the memory, once
/// it listens, and `klav-proxy status --json` shows it as `memory`. A
/// `serve` that fails before it listens leaves an existing record as it is
/// (finding 2 of the re-review of #466: it may be a running `serve`'s); one
/// that listens replaces it; one that stops removes only its own. (This
/// test process is never hardened: the report is the one `main` would
/// pass.)
#[tokio::test(flavor = "multi_thread")]
async fn status_shows_what_serve_turned_on_in_its_memory() {
    use crate::app::{ServeOptions, StartEnv};
    use crate::memory::{CoreDumps, MemoryReport};
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (_ana, proxy, _t3) = setup_with(
        &server,
        &dir,
        credential_at("northflank", "https://api.northflank.com"),
    )
    .await;
    drop(proxy);
    let home = klav_client::Home::at(dir.path().join("agent-klav-proxy"));
    let env = StartEnv::from_lookup(|_| None);
    let before = crate::app::status(&home, "klav-proxy", &env)
        .await
        .expect("status");
    assert!(before.memory.is_none() && before.memory_error.is_none());
    let memory = MemoryReport {
        core_dumps: CoreDumps::Off,
        dumpable: Some(false),
        locked: false,
        lock_turned_off: false,
        vm_lck_kib: None,
        why: Some("the memlock limit is 8 MiB (hard limit 8 MiB)".into()),
        lock_not_undone: false,
    };
    let path = crate::app::memory_path_in(&home, "klav-proxy");
    // A running serve's record: a second serve on the same home that fails
    // before it listens (here, a port already taken) leaves it untouched.
    let stale = crate::memory::MemoryRecord {
        report: MemoryReport {
            locked: true,
            vm_lck_kib: Some(2832),
            why: None,
            ..memory.clone()
        },
        since: 1,
    };
    klav_client::home::write_private(&path, &stale.to_file().expect("bytes")).expect("stale");
    assert_eq!(
        crate::app::status(&home, "klav-proxy", &env)
            .await
            .expect("status")
            .memory,
        Some(stale.clone())
    );
    let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let options = |port: u16| ServeOptions {
        home: home.clone(),
        name: "klav-proxy".into(),
        port,
        channel: None,
        max_body: crate::proxy::DEFAULT_MAX_BODY,
        request_timeout: crate::proxy::DEFAULT_REQUEST_TIMEOUT,
        no_local_calls: false,
        env: StartEnv::from_lookup(|_| None),
    };
    let failed = crate::app::serve_until(
        options(taken.local_addr().expect("addr").port()),
        memory.clone(),
        std::future::pending(),
    )
    .await;
    assert!(failed.is_err());
    assert_eq!(
        std::fs::read(&path).expect("still there"),
        stale.to_file().expect("bytes"),
        "a serve that failed before it listened touched the record"
    );
    assert_eq!(
        crate::app::status(&home, "klav-proxy", &env)
            .await
            .expect("status")
            .memory,
        Some(stale.clone())
    );
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(crate::app::serve_until(options(0), memory.clone(), async {
        let _ = stopped.await;
    }));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while crate::app::read_memory(&path).expect("record").as_ref() == Some(&stale) || !path.exists()
    {
        assert!(std::time::Instant::now() < deadline, "serve never wrote it");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let report = crate::app::status(&home, "klav-proxy", &env)
        .await
        .expect("status");
    let record = report.memory.as_ref().expect("memory");
    assert_eq!(record.report, memory);
    assert!(record.since > 0);
    let shown = serde_json::to_value(&report).expect("json");
    assert_eq!(shown["memory"]["core_dumps"], "off");
    assert_eq!(shown["memory"]["dumpable"], false);
    assert_eq!(shown["memory"]["locked"], false);
    assert_eq!(
        shown["memory"]["why"],
        "the memlock limit is 8 MiB (hard limit 8 MiB)"
    );
    assert!(
        crate::app::memory_words(&report, record.since + 120_000).contains(
            "as recorded by the klav-proxy serve that last wrote this record, 2 min ago; status can't tell whether that proxy still runs"
        )
    );
    // A later serve's record replaces this one's while it runs: this one,
    // stopping, leaves it alone.
    klav_client::home::write_private(&path, &stale.to_file().expect("bytes")).expect("later");
    let _ = stop.send(());
    task.await.expect("join").expect("serve");
    assert_eq!(
        crate::app::read_memory(&path).expect("record"),
        Some(stale.clone()),
        "a serve that stopped removed a later serve's record"
    );
    // Its own record, once it stops: gone, and `status` says only that
    // there is no record, never that no proxy runs.
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(crate::app::serve_until(options(0), memory.clone(), async {
        let _ = stopped.await;
    }));
    while crate::app::read_memory(&path).expect("record").as_ref() == Some(&stale) {
        assert!(std::time::Instant::now() < deadline, "serve never wrote it");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let _ = stop.send(());
    task.await.expect("join").expect("serve");
    assert!(!path.exists(), "a serve that stopped left its record");
    let after = crate::app::status(&home, "klav-proxy", &env)
        .await
        .expect("status");
    assert!(after.memory.is_none() && after.memory_error.is_none());
    let words = crate::app::memory_words(&after, 0);
    assert_eq!(
        words,
        "Memory: no record from a klav-proxy serve on this home."
    );
    assert!(!words.contains("running"), "{words}");
}
