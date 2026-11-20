//! `klav-forward` end to end (ADR 0036 §5, §7 mode (a), §10): a real
//! `klav-server`, the issuer starting a sandbox through the proxy, and the
//! forwarder's own code (`klav_forward::forward`) claiming it over the
//! pinned channel and relaying a local port, as `klav-forward up` runs it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicI64;

use klav_core::crypto::channel::TlsSigner;
use klav_core::crypto::sandbox::{SandboxPackage, decode_package};
use klav_forward::forward::{self, Proxy};
use klav_sdk::sandbox as issuer_api;

use crate::channel::ChannelLimits;
use crate::channel_e2e_tests::{serve_limited, upstream_client};
use crate::e2e_tests::Upstream;
use crate::e2e_tests::common::ServerProcess;
use crate::proxy::ProxyState;
use crate::sandbox_e2e_tests::{Manual, credential_at, ends, real_now, request, setup_with};

const SECOND: std::time::Duration = std::time::Duration::from_secs(1);

/// What stops the channel, and its task.
type ChannelStop = (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), String>>,
);

struct World {
    _server: ServerProcess,
    _dir: tempfile::TempDir,
    ana: klav_client::Unlocked,
    t3: klav_sdk::Agent,
    _state: Arc<ProxyState>,
    port: u16,
    /// The channel's address.
    addr: SocketAddr,
    upstream: Upstream,
    stop: Option<ChannelStop>,
}

async fn world() -> World {
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
    let (state, port, addr, stop) = serve_limited(
        proxy,
        clock,
        dir.path().join("proxy.sandbox-store"),
        upstream_client(),
        ChannelLimits::default(),
        None,
    )
    .await;
    World {
        _server: server,
        _dir: dir,
        ana,
        t3,
        _state: state,
        port,
        addr,
        upstream,
        stop: Some(stop),
    }
}

impl World {
    async fn start(&mut self, label: &str) -> SandboxPackage {
        let started = issuer_api::start(&mut self.t3, self.port, &request(label, &["northflank"]))
            .await
            .expect("start");
        decode_package(&started.package).expect("package")
    }

    /// A forwarder for `package` with a fresh channel key, reaching the
    /// channel where this test serves it (the package names the address
    /// the person signed for the issuer).
    fn forwarder(&self, package: &SandboxPackage) -> Proxy {
        Proxy::new(
            &format!("tls://{}", self.addr),
            package.proxy_pin,
            TlsSigner::channel_key(),
        )
        .expect("proxy")
    }
}

/// Relays a fresh local port to `proxy`, as `klav-forward up` does.
async fn relay(proxy: Proxy) -> u16 {
    relay_with(proxy, forward::RelayLimits::default()).await
}

/// [`relay`] with other limits.
async fn relay_with(proxy: Proxy, limits: forward::RelayLimits) -> u16 {
    relay_shared(Arc::new(proxy), limits).await
}

/// [`relay_with`] for a forwarder the test also uses, as `klav-forward up`
/// shares it with its keep-alive.
async fn relay_shared(proxy: Arc<Proxy>, limits: forward::RelayLimits) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(forward::serve_with(listener, proxy, limits));
    port
}

/// A tool's call to the forwarder, with the placeholder token a tool
/// needs to start.
async fn call(port: u16, path: &str) -> reqwest::Response {
    reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}{path}"))
        .header("authorization", "Bearer klav-placeholder")
        .send()
        .await
        .expect("an answer")
}

/// The forwarder claims the sandbox and relays a tool's call; the
/// provider sees the real credential and never the placeholder. When the
/// issuer stops the sandbox, the proxy's refusal comes through as it is;
/// when the channel is gone, the forwarder answers by itself with
/// `klav_proxy_unreachable` and its `next`.
#[tokio::test(flavor = "multi_thread")]
async fn a_forwarder_claims_relays_and_says_why_it_stopped() {
    let mut w = world().await;
    let package = w.start("chat-1").await;
    let proxy = w.forwarder(&package);
    let bound = proxy.claim(&package).await.expect("claimed");
    assert_eq!(bound.sandbox_id, package.sandbox_id.to_string());
    assert_eq!(bound.label, "chat-1");
    assert_eq!(bound.profiles, ["northflank"]);
    assert_eq!(proxy.status().await.expect("live").label, "chat-1");
    let local = relay(proxy).await;

    let res = call(local, "/northflank/v1/projects").await;
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.expect("body"), "ok");
    let seen = w.upstream.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].target, "/v1/projects");
    let auth = seen[0].header("authorization").expect("a credential");
    assert!(auth.starts_with("Bearer "), "{auth}");
    assert_ne!(auth, "Bearer klav-placeholder");

    // A profile the sandbox did not start with: the proxy's own refusal.
    let res = call(local, "/railway/graphql").await;
    assert_eq!(res.status(), 403);
    assert_eq!(res.headers()["klav-error"], "klav_not_allowed");

    // The issuer stops it: every call is refused, nothing reaches the
    // provider.
    issuer_api::stop(&w.t3, w.port, package.sandbox_id)
        .await
        .expect("stop");
    let res = call(local, "/northflank/v1/projects").await;
    assert_eq!(res.status(), 401);
    assert_eq!(res.headers()["klav-error"], "klav_sandbox_revoked");
    assert_eq!(w.upstream.requests().len(), 1);

    // The channel goes away: the forwarder's own answer.
    let (stop, stopped) = w.stop.take().expect("stop");
    let _ = stop.send(());
    let _ = tokio::time::timeout(10 * SECOND, stopped).await;
    let res = call(local, "/northflank/v1/projects").await;
    assert_eq!(res.status(), 503);
    assert_eq!(res.headers()["klav-error"], "klav_proxy_unreachable");
    let body: serde_json::Value = res.json().await.expect("json");
    assert_eq!(body["error"], "klav_proxy_unreachable");
    assert_eq!(body["message"], forward::UNREACHABLE_MESSAGE);
    assert_eq!(body["next"], forward::UNREACHABLE_NEXT);
    assert_eq!(w.upstream.requests().len(), 1);
    // The person's log has the sandbox's whole life, and it verifies.
    assert_eq!(ends(&mut w.ana).await, [Some("stop".to_owned())]);
}

/// Papercut 12: the proxy's loopback port and a forwarder's both default
/// to 8790. Asked what holds a port, each answers as itself: the real
/// proxy (also with `--no-local-calls`), a real forwarder whose sandbox is
/// live and one whose sandbox ended, and another program.
#[tokio::test(flavor = "multi_thread")]
async fn a_taken_port_says_whether_klav_proxy_or_klav_forward_holds_it() {
    use klav_forward::http::{PortHolder, port_holder};
    let mut w = world().await;
    assert_eq!(port_holder(w.port, 10 * SECOND).await, PortHolder::Proxy);
    let package = w.start("chat-1").await;
    let proxy = w.forwarder(&package);
    proxy.claim(&package).await.expect("claimed");
    let local = relay(proxy).await;
    assert_eq!(port_holder(local, 10 * SECOND).await, PortHolder::Forwarder);
    issuer_api::stop(&w.t3, w.port, package.sandbox_id)
        .await
        .expect("stop");
    assert_eq!(port_holder(local, 10 * SECOND).await, PortHolder::Forwarder);

    // `--no-local-calls`: still klav-proxy.
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (_ana, agent, _t3) = setup_with(
        &server,
        &dir,
        credential_at("northflank", "https://upstream.test"),
    )
    .await;
    let (_state, closed, _, _stop) = crate::channel_e2e_tests::serve_configured(
        agent,
        Arc::new(Manual(AtomicI64::new(real_now()))),
        dir.path().join("proxy.sandbox-store"),
        upstream_client(),
        ChannelLimits::default(),
        None,
        ProxyState::without_local_calls,
    )
    .await;
    assert_eq!(port_holder(closed, 10 * SECOND).await, PortHolder::Proxy);

    // Another program: an answer of its own, or none.
    let other = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let other_port = other.local_addr().expect("addr").port();
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        while let Ok((mut tcp, _)) = other.accept().await {
            let _ = tcp
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await;
        }
    });
    assert_eq!(
        port_holder(other_port, 10 * SECOND).await,
        PortHolder::Other
    );
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let silent_port = silent.local_addr().expect("addr").port();
    assert_eq!(
        port_holder(silent_port, std::time::Duration::from_millis(300)).await,
        PortHolder::Unknown
    );
    drop(silent);
}

/// Papercut 13: once the proxy's answer to its own status says the
/// sandbox ended, the forwarder's keep-alive returns that refusal (the
/// forwarder then stops and frees its port); a pause is waited out.
#[tokio::test(flavor = "multi_thread")]
async fn the_keep_alive_returns_once_the_sandbox_ended_and_waits_out_a_pause() {
    let mut w = world().await;
    let package = w.start("chat-1").await;
    let proxy = Arc::new(w.forwarder(&package));
    proxy.claim(&package).await.expect("claimed");
    let tick = std::time::Duration::from_millis(200);
    let bound = proxy.status().await.expect("live");
    let mut kept = tokio::spawn(forward::keep_alive(
        Arc::clone(&proxy),
        tick,
        bound.expires_at,
    ));

    w.ana.pause_agents(None, 0).await.expect("pause");
    assert!(w._state.refresh().await.is_err(), "paused");
    assert_eq!(
        proxy.status().await.expect_err("paused").error,
        "klav_agents_paused"
    );
    assert!(
        tokio::time::timeout(5 * tick, &mut kept).await.is_err(),
        "a pause is not an end"
    );
    w.ana.resume_agents(None).await.expect("resume");
    w._state.refresh().await.expect("refresh");

    issuer_api::stop(&w.t3, w.port, package.sandbox_id)
        .await
        .expect("stop");
    let ended = tokio::time::timeout(10 * SECOND, kept)
        .await
        .expect("it returns")
        .expect("task");
    assert_eq!(ended.error, "klav_sandbox_revoked");
    assert_eq!(
        ended.message,
        crate::errors::ended_message(klav_proto::sandbox::SandboxEnd::Stop)
    );
}

/// Raw requests written at once on one connection to the forwarder (the
/// last with `connection: close`), and every answer the proxy sent back.
async fn raw(port: u16, requests: &[String]) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    tcp.write_all(requests.concat().as_bytes())
        .await
        .expect("write");
    let mut out = Vec::new();
    tokio::time::timeout(30 * SECOND, tcp.read_to_end(&mut out))
        .await
        .expect("the answers in time")
        .expect("read");
    String::from_utf8_lossy(&out).into_owned()
}

/// A `GET` to the profile, with `extra` header lines.
fn get(host: &str, extra: &str, close: bool) -> String {
    let connection = if close { "connection: close\r\n" } else { "" };
    format!(
        "GET /northflank/v1/projects HTTP/1.1\r\nhost: {host}\r\nauthorization: Bearer klav-placeholder\r\n{extra}{connection}\r\n"
    )
}

/// A web page in the sandbox (a headless browser an agent drives) never
/// uses the profiles: the proxy checks the browser's headers and the
/// `Host` of every request through the channel, as on its own loopback
/// listener, since the forwarder relays bytes. Refused before the policy,
/// the server or the provider, spending nothing and ending nothing; the
/// second request on a kept-alive connection is checked as the first.
#[tokio::test(flavor = "multi_thread")]
async fn a_web_page_in_the_sandbox_never_reaches_the_profiles() {
    let mut w = world().await;
    let package = w.start("chat-1").await;
    let proxy = w.forwarder(&package);
    proxy.claim(&package).await.expect("claimed");
    let local = relay(proxy).await;
    let ours = format!("127.0.0.1:{local}");
    let refused = |answer: &str| {
        (answer.starts_with("HTTP/1.1 403") || answer.starts_with("HTTP/1.0 403"))
            && answer
                .to_ascii_lowercase()
                .contains("klav-error: klav_not_allowed")
    };
    for (what, request) in [
        (
            "a foreign Origin",
            get(&ours, "origin: https://evil.example\r\n", true),
        ),
        (
            "a cross-site fetch",
            get(&ours, "sec-fetch-site: cross-site\r\n", true),
        ),
        (
            "a rebinding Host",
            get(&format!("evil.example:{local}"), "", true),
        ),
        ("an IPv6 Host", get(&format!("[::1]:{local}"), "", true)),
        ("a Host without a port", get("127.0.0.1", "", true)),
    ] {
        let answer = raw(local, &[request]).await;
        assert!(refused(&answer), "{what}: {answer}");
    }
    // No Host at all (HTTP/1.0 allows it).
    let answer = raw(
        local,
        &["GET /northflank/v1/projects HTTP/1.0\r\nauthorization: Bearer klav-placeholder\r\n\r\n".to_owned()],
    )
    .await;
    assert!(refused(&answer), "no Host: {answer}");
    assert!(w.upstream.requests().is_empty());

    // An ordinary call, then a page's request on the same connection.
    let answer = raw(
        local,
        &[
            get(&ours, "", false),
            get(&ours, "origin: https://evil.example\r\n", true),
        ],
    )
    .await;
    let second = answer
        .find("HTTP/1.1 403")
        .expect("a second answer, refused");
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(refused(&answer[second..]), "{answer}");
    assert_eq!(w.upstream.requests().len(), 1);

    // A curl-shaped call, with `localhost`, still passes; nothing ended.
    let res = call(local, "/northflank/v1/projects").await;
    assert_eq!(res.status(), 200);
    let answer = raw(local, &[get(&format!("LocalHost:{local}"), "", true)]).await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert_eq!(w.upstream.requests().len(), 3);
    assert!(ends(&mut w.ana).await.is_empty());
}

/// A request to the channel's own routes through the forwarder, with
/// `extra` header lines and `connection: close`.
fn own(method: &str, path: &str, host: &str, extra: &str) -> String {
    format!(
        "{method} {path} HTTP/1.1\r\nhost: {host}\r\n{extra}content-length: 0\r\nconnection: close\r\n\r\n"
    )
}

/// Whether `answer` is the proxy's refusal of a web page.
fn refused_as_a_page(answer: &str) -> bool {
    answer.starts_with("HTTP/1.1 403")
        && answer
            .to_ascii_lowercase()
            .contains("klav-error: klav_not_allowed")
}

/// A web page in the sandbox cannot end it: a cross-site form `POST
/// /_klav/release` (no preflight, so the browser sends it) reaches the
/// forwarder's plaintext loopback port, and the proxy refuses it by its
/// headers, ending nothing. A program's release, through the same port,
/// still ends the sandbox.
#[tokio::test(flavor = "multi_thread")]
async fn a_web_page_in_the_sandbox_cannot_release_it() {
    let mut w = world().await;
    let package = w.start("chat-1").await;
    let proxy = w.forwarder(&package);
    proxy.claim(&package).await.expect("claimed");
    // The relay and the keep-alive share the forwarder's key.
    let keep_alive = Arc::new(proxy);
    let local = relay_shared(Arc::clone(&keep_alive), forward::RelayLimits::default()).await;
    let ours = format!("127.0.0.1:{local}");
    let release = crate::channel::RELEASE;
    let form = "content-type: application/x-www-form-urlencoded\r\n";
    for (what, request) in [
        (
            "a cross-site form",
            own(
                "POST",
                release,
                &ours,
                &format!(
                    "{form}origin: https://evil.example\r\nsec-fetch-site: cross-site\r\nsec-fetch-mode: navigate\r\n"
                ),
            ),
        ),
        (
            "a form with Origin only",
            own(
                "POST",
                release,
                &ours,
                &format!("{form}origin: https://evil.example\r\n"),
            ),
        ),
        (
            "a form with Sec-Fetch-Site only",
            own(
                "POST",
                release,
                &ours,
                &format!("{form}sec-fetch-site: cross-site\r\n"),
            ),
        ),
        (
            "a page that rebinds its name",
            own("POST", release, &format!("evil.example:{local}"), form),
        ),
        (
            "the forwarder's Host with a page's Origin",
            own("POST", release, "klav-proxy", "origin: null\r\n"),
        ),
    ] {
        let answer = raw(local, &[request]).await;
        assert!(refused_as_a_page(&answer), "{what}: {answer}");
        // Still alive, for the forwarder and in the person's log.
        keep_alive.status().await.expect("still live");
    }
    assert!(ends(&mut w.ana).await.is_empty());

    // A program's release (curl, through the forwarder) ends it.
    let answer = raw(local, &[own("POST", release, &ours, "")]).await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.contains("\"logged\""), "{answer}");
    assert_eq!(ends(&mut w.ana).await, [Some("released".to_owned())]);
}

/// A web page in the sandbox cannot read its status (its ID, label,
/// profiles and expiry): not with a browser's headers, and not with a
/// rebinding, whose `Host` is the page's own name even when an engine
/// leaves out `Origin` on a same-origin `GET`. The forwarder's own
/// status still answers: its keep-alive over the channel, and
/// `klav-forward status` through the local port with `host: klav-proxy`.
#[tokio::test(flavor = "multi_thread")]
async fn a_web_page_in_the_sandbox_cannot_read_its_status() {
    let mut w = world().await;
    let package = w.start("chat-1").await;
    let proxy = w.forwarder(&package);
    proxy.claim(&package).await.expect("claimed");
    // The relay and the keep-alive share the forwarder's key.
    let keep_alive = Arc::new(proxy);
    let local = relay_shared(Arc::clone(&keep_alive), forward::RelayLimits::default()).await;
    let ours = format!("127.0.0.1:{local}");
    let status = crate::channel::STATUS;
    let id = package.sandbox_id.to_string();
    for (what, request) in [
        (
            "a foreign Origin",
            own("GET", status, &ours, "origin: https://evil.example\r\n"),
        ),
        (
            "a cross-site fetch",
            own("GET", status, &ours, "sec-fetch-site: cross-site\r\n"),
        ),
        (
            "a same-origin fetch after a rebinding",
            own(
                "GET",
                status,
                &format!("evil.example:{local}"),
                "sec-fetch-site: same-origin\r\n",
            ),
        ),
        (
            "a rebinding with no browser header",
            own("GET", status, &format!("evil.example:{local}"), ""),
        ),
        (
            "the forwarder's Host with a page's header",
            own(
                "GET",
                status,
                "klav-proxy",
                "sec-fetch-site: same-origin\r\n",
            ),
        ),
    ] {
        let answer = raw(local, &[request]).await;
        assert!(refused_as_a_page(&answer), "{what}: {answer}");
        assert!(!answer.contains(&id), "{what}: {answer}");
        assert!(!answer.contains("chat-1"), "{what}: {answer}");
    }

    // `klav-forward status`'s own request, and a program's with curl.
    for host in ["klav-proxy", ours.as_str(), &format!("localhost:{local}")] {
        let answer = raw(local, &[own("GET", status, host, "")]).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{host}: {answer}");
        assert!(answer.contains(&id), "{host}: {answer}");
    }
    assert_eq!(
        keep_alive.status().await.expect("live").sandbox_id,
        package.sandbox_id.to_string()
    );
    assert!(ends(&mut w.ana).await.is_empty());
}

/// Local connections that never send a byte hold no turn: after twenty of
/// them (more than the twelve turns), a call still goes through at once.
#[tokio::test(flavor = "multi_thread")]
async fn silent_local_connections_hold_no_turn() {
    let mut w = world().await;
    let package = w.start("chat-1").await;
    let proxy = w.forwarder(&package);
    proxy.claim(&package).await.expect("claimed");
    let local = relay(proxy).await;
    let mut silent = Vec::new();
    for _ in 0..20 {
        silent.push(
            tokio::net::TcpStream::connect(("127.0.0.1", local))
                .await
                .expect("connect"),
        );
    }
    let res = tokio::time::timeout(5 * SECOND, call(local, "/northflank/v1/projects"))
        .await
        .expect("an answer in time");
    assert_eq!(res.status(), 200);
    drop(silent);
}

/// A caller that sends its request and closes its sending side (as `nc -N`
/// does) gets the whole answer, and the connection then ends at once
/// rather than after the proxy's 20 s wait for another head.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_that_half_closes_gets_its_answer_and_its_turn_back() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut w = world().await;
    let package = w.start("chat-1").await;
    let proxy = w.forwarder(&package);
    proxy.claim(&package).await.expect("claimed");
    let local = relay(proxy).await;
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", local))
        .await
        .expect("connect");
    tcp.write_all(get(&format!("127.0.0.1:{local}"), "", false).as_bytes())
        .await
        .expect("write");
    tcp.shutdown().await.expect("half-close");
    let begun = tokio::time::Instant::now();
    let mut out = Vec::new();
    tokio::time::timeout(10 * SECOND, tcp.read_to_end(&mut out))
        .await
        .expect("closed well before the proxy's head deadline")
        .expect("read");
    let answer = String::from_utf8_lossy(&out);
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.contains("\r\n\r\n2\r\nok\r\n0\r\n\r\n"), "{answer}");
    assert!(begun.elapsed() < 10 * SECOND);
    assert_eq!(w.upstream.requests().len(), 1);
    assert!(ends(&mut w.ana).await.is_empty());
}

/// When every turn is taken (twelve requests whose heads stall: the proxy
/// waits 20 s for a head), the next
/// call gets the forwarder's `klav_forward_busy` within the turn's wait,
/// never a hang, and `GET /_klav/status` still answers: it has a lane of
/// its own.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_with_every_turn_taken_is_told_so_and_status_still_answers() {
    use tokio::io::AsyncWriteExt;
    let mut w = world().await;
    let package = w.start("chat-1").await;
    let proxy = w.forwarder(&package);
    proxy.claim(&package).await.expect("claimed");
    let limits = forward::RelayLimits {
        turn_wait: 2 * SECOND,
        ..forward::RelayLimits::default()
    };
    let local = relay_with(proxy, limits).await;
    let mut stalled = Vec::new();
    for _ in 0..forward::MAX_RELAYED {
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", local))
            .await
            .expect("connect");
        tcp.write_all(
            format!("GET /northflank/v1/projects HTTP/1.1\r\nhost: 127.0.0.1:{local}\r\n")
                .as_bytes(),
        )
        .await
        .expect("write");
        stalled.push(tcp);
    }
    tokio::time::sleep(SECOND).await;
    let begun = tokio::time::Instant::now();
    let res = tokio::time::timeout(10 * SECOND, call(local, "/northflank/v1/projects"))
        .await
        .expect("an answer, not a hang");
    assert!(begun.elapsed() >= SECOND, "{:?}", begun.elapsed());
    assert_eq!(res.status(), 503);
    assert_eq!(res.headers()["klav-error"], "klav_forward_busy");
    let body: serde_json::Value = res.json().await.expect("json");
    assert_eq!(body["message"], forward::BUSY_MESSAGE);
    assert_eq!(body["next"], forward::BUSY_NEXT);
    let status = tokio::time::timeout(
        5 * SECOND,
        raw(
            local,
            &[format!(
                "GET /_klav/status HTTP/1.1\r\nhost: 127.0.0.1:{local}\r\nconnection: close\r\n\r\n"
            )],
        ),
    )
    .await
    .expect("status in time");
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert!(w.upstream.requests().is_empty());
    // A turn comes back: the call goes through.
    drop(stalled);
    tokio::time::sleep(SECOND).await;
    assert_eq!(call(local, "/northflank/v1/projects").await.status(), 200);
    assert!(ends(&mut w.ana).await.is_empty());
}

/// A forwarder pinned to another key never finishes the handshake, so it
/// never sends the secret: the claim fails as `klav_proxy_unreachable`, and
/// the right forwarder still claims the sandbox.
#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_pin_never_sends_the_secret() {
    let mut w = world().await;
    let package = w.start("chat-1").await;
    let mut wrong = package.proxy_pin;
    wrong[0] ^= 1;
    let impostor = Proxy::new(
        &format!("tls://{}", w.addr),
        wrong,
        TlsSigner::channel_key(),
    )
    .expect("proxy");
    let refusal = impostor.claim(&package).await.expect_err("refused");
    assert_eq!(refusal.error, "klav_proxy_unreachable");
    assert!(refusal.retryable());
    w.forwarder(&package)
        .claim(&package)
        .await
        .expect("the secret is not spent");
    assert!(ends(&mut w.ana).await.is_empty());
}

/// A second forwarder with the same package is the theft signal: refused,
/// and the sandbox ends for both (`theft` in the person's log). A package
/// whose sandbox already ended is refused the same way, without a new end.
#[tokio::test(flavor = "multi_thread")]
async fn a_spent_package_is_refused_and_a_second_forwarder_is_theft() {
    let mut w = world().await;
    let package = w.start("chat-1").await;
    let first = w.forwarder(&package);
    first.claim(&package).await.expect("claimed");
    let second = w.forwarder(&package);
    let refusal = second.claim(&package).await.expect_err("refused");
    assert_eq!(
        (refusal.status, refusal.error.as_str()),
        (401, "klav_sandbox_revoked")
    );
    assert!(!refusal.retryable());
    assert_eq!(
        first.status().await.expect_err("ended").error,
        "klav_sandbox_revoked"
    );
    assert_eq!(ends(&mut w.ana).await, [Some("theft".to_owned())]);

    // Another sandbox, stopped before its forwarder came up.
    let late = w.start("chat-2").await;
    issuer_api::stop(&w.t3, w.port, late.sandbox_id)
        .await
        .expect("stop");
    let refusal = w.forwarder(&late).claim(&late).await.expect_err("refused");
    assert_eq!(refusal.error, "klav_sandbox_revoked");
    assert_eq!(
        ends(&mut w.ana).await,
        [Some("theft".to_owned()), Some("stop".to_owned())]
    );
}

/// While the proxy does not answer, the forwarder keeps the secret and
/// tries again until its deadline; it then says the proxy is unreachable.
#[tokio::test(flavor = "multi_thread")]
async fn the_claim_is_tried_again_until_its_deadline() {
    let mut w = world().await;
    let package = w.start("chat-1").await;
    // A port where nothing listens.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let nowhere = closed.local_addr().expect("addr");
    drop(closed);
    let proxy = Proxy::new(
        &format!("tls://{nowhere}"),
        package.proxy_pin,
        TlsSigner::channel_key(),
    )
    .expect("proxy");
    let begun = tokio::time::Instant::now();
    let sent = std::sync::atomic::AtomicBool::new(false);
    let refusal = proxy
        .claim_until(&package, begun + 4 * SECOND, &sent)
        .await
        .expect_err("unreachable");
    assert_eq!(refusal.error, "klav_proxy_unreachable");
    // No attempt got past connecting: `klav-forward up` keeps the package
    // usable (no claim marker).
    assert!(!sent.load(std::sync::atomic::Ordering::SeqCst));
    assert!(begun.elapsed() >= 2 * SECOND, "{:?}", begun.elapsed());
    // Nothing was spent: the real forwarder claims it.
    w.forwarder(&package)
        .claim(&package)
        .await
        .expect("claimed");
}
