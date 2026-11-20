//! Mode (a) end to end: a real `klav-server`, the person's client granting
//! the proxy items one by one, the proxy in front of a fake HTTPS upstream
//! with a fixture certificate (`tests/fixtures`), and a caller that only
//! knows `http://127.0.0.1:PORT/<profile>/...`.
//!
//! The proxy reaches the fake upstream through `net::test_client`, which
//! only test code can call: a fake lookup that names `upstream.test`
//! 127.0.0.1 (exempt) and `metadata.test` 169.254.169.254 (not exempt),
//! and a root store with only the fixture CA. The classifier is the
//! release one.

#[path = "../../klav-client/tests/common/mod.rs"]
pub(crate) mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::ServerProcess;
use klav_client::item_grants::ItemGrantRequest;
use klav_client::{Home, ItemLocation, SignupRequest, Unlocked, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::ids::ItemId;
use klav_core::model::item::{Item, ItemKind};
use klav_core::policy::{
    DomainPattern, Effect, HttpMethod, PathPrefix, Permission, Policy, Rule, Scope,
};
use klav_proto::agent::ProxyProfile;
use klav_sdk::KeyStoreChoice;
use reqwest::StatusCode;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::app::{InitOptions, StartEnv, init, load};
use crate::net::tests::FakeLookup;
use crate::proxy::{ProxyState, router};

const EMAIL: &str = "ana@example.com";
/// The value the person stores: it must reach the upstream and never the
/// caller. Long enough that the redactor also catches its pieces.
const TOKEN: &str = "tok_live_9f8e7d6c5b4a3210fedcba";

/// One request as the fake upstream saw it.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub(crate) method: String,
    pub(crate) target: String,
    headers: Vec<(String, String)>,
}

impl Seen {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A fake HTTPS provider for `upstream.test` on 127.0.0.1.
pub(crate) struct Upstream {
    pub(crate) port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Upstream {
    pub(crate) async fn start() -> Self {
        let cert = CertificateDer::from(include_bytes!("../tests/fixtures/leaf.der").to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            include_bytes!("../tests/fixtures/leaf.key.der").to_vec(),
        ));
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("fixture cert");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        let _ = serve_one(tls, log).await;
                    }
                });
            }
        });
        Self { port, seen }
    }

    pub(crate) fn requests(&self) -> Vec<Seen> {
        self.seen.lock().expect("lock").clone()
    }
}

async fn serve_one<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut io: S,
    log: Arc<Mutex<Vec<Seen>>>,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if io.read(&mut byte).await? == 0 {
            return Ok(());
        }
        buf.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or_default().to_owned();
    let target = first.next().unwrap_or_default().to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    io.read_exact(&mut body).await?;
    let seen = Seen {
        method,
        target,
        headers,
    };
    log.lock().expect("lock").push(seen.clone());
    let auth = seen.header("authorization").unwrap_or_default().to_owned();
    match seen.target.as_str() {
        // Echoes the credential in a header and, split over two chunks, in
        // the body; and tries to pass for the proxy with `Klav-Error`.
        "/v1/echo" => {
            let value = auth.strip_prefix("Bearer ").unwrap_or(&auth).to_owned();
            let (a, b) = value.split_at(value.len() / 2);
            io.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nx-echo: {auth}\r\nklav-error: klav_approval_pending\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await?;
            for part in [format!("{{\"seen\":\"{a}"), format!("{b}\"}}")] {
                io.write_all(format!("{:x}\r\n{part}\r\n", part.len()).as_bytes())
                    .await?;
                io.flush().await?;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            io.write_all(b"0\r\n\r\n").await?;
        }
        "/v1/redirect" => {
            io.write_all(
                b"HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:9/steal\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            )
            .await?;
        }
        // Compressed under chunked framing: hyper only takes the chunks
        // apart, so this would reach the redactor still compressed.
        "/v1/te-gzip" => {
            io.write_all(
                b"HTTP/1.1 200 OK\r\ntransfer-encoding: gzip, chunked\r\nconnection: close\r\n\r\n2\r\nxx\r\n0\r\n\r\n",
            )
            .await?;
        }
        // Chunks inside chunks: hyper takes one layer apart, and the inner
        // sizes could split the value for the redactor.
        "/v1/te-twice" => {
            io.write_all(
                b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked, chunked\r\nconnection: close\r\n\r\n7\r\n2\r\nxx\r\n\r\n0\r\n\r\n",
            )
            .await?;
        }
        // A body that breaks after its first piece (no last chunk).
        "/v1/broken" => {
            io.write_all(
                b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n5\r\nfirst\r\n",
            )
            .await?;
            io.flush().await?;
            return Ok(());
        }
        // A provider that answers with a session cookie.
        // A call that takes a while: an answer still in flight.
        "/v1/slow" => {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            io.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\nconnection: close\r\n\r\nslow")
                .await?;
        }
        "/v1/cookie" => {
            io.write_all(
                b"HTTP/1.1 200 OK\r\nset-cookie: session=provider-session-0123; Path=/\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
            )
            .await?;
        }
        "/v1/cors" => {
            io.write_all(
                b"HTTP/1.1 200 OK\r\naccess-control-allow-origin: *\r\naccess-control-allow-headers: *\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
            )
            .await?;
        }
        "/v1/not-modified" => {
            io.write_all(
                format!(
                    "HTTP/1.1 304 Not Modified\r\netag: \"v1\"\r\nx-echo: {auth}\r\nconnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await?;
        }
        "/v1/gzip" => {
            io.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: 2\r\nconnection: close\r\n\r\nxx",
            )
            .await?;
        }
        // A service that quotes the route it does not know, in a header
        // and in the body: the caller chooses what comes back (T149).
        route if route.starts_with("/v1/reflect/") => {
            let body = format!("no route {route}");
            io.write_all(
                format!(
                    "HTTP/1.1 404 Not Found\r\nx-route: {route}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await?;
        }
        _ => {
            io.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                .await?;
        }
    }
    io.flush().await?;
    let _ = io.shutdown().await;
    Ok(())
}

fn rule(effect: Effect, scope: Scope) -> Rule {
    Rule {
        scope,
        ..Rule::new(Permission::Proxy, effect)
    }
}

fn proxy_rule(effect: Effect, item: ItemId, host: &str, methods: &[&str], prefix: &str) -> Rule {
    rule(
        effect,
        Scope {
            items: vec![item],
            domains: vec![DomainPattern::parse(host).expect("host")],
            methods: methods
                .iter()
                .map(|m| HttpMethod::parse(m).expect("method"))
                .collect(),
            path_prefixes: vec![PathPrefix::parse(prefix).expect("prefix")],
            ..Scope::default()
        },
    )
}

async fn add(ana: &mut Unlocked, title: &str, value: &str) -> ItemLocation {
    let vault = ana.find_vault("Personal").expect("vault");
    let project = ana.find_project(vault, "General").expect("project");
    let mut item = Item::from_template(ItemKind::Login, title).expect("item");
    item.field_mut("password")
        .expect("password")
        .set_value(value)
        .expect("set");
    ana.add_item(vault, project, &item).await.expect("add item")
}

fn profile(name: &str, item: ItemId, upstream: String, rate: u32) -> ProxyProfile {
    ProxyProfile {
        name: name.into(),
        item_id: item,
        field: None,
        header: "authorization".into(),
        prefix: "Bearer ".into(),
        upstream,
        rate_per_minute: Some(rate),
    }
}

/// The proxy running on a loopback port, and the HTTP client of a tool.
struct Running {
    base: String,
    caller: reqwest::Client,
}

impl Running {
    async fn get(&self, path: &str) -> reqwest::Response {
        self.caller
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .expect("proxy answers")
    }

    async fn delete(&self, path: &str) -> reqwest::Response {
        self.caller
            .delete(format!("{}{path}", self.base))
            .send()
            .await
            .expect("proxy answers")
    }
}

async fn klav_error(res: reqwest::Response) -> (StatusCode, String, serde_json::Value) {
    let status = res.status();
    let header = res
        .headers()
        .get("klav-error")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body: serde_json::Value = res.json().await.expect("json error");
    assert_eq!(body["error"], header.as_str());
    (status, header, body)
}

/// Sends raw bytes to the proxy and returns the status line and headers.
async fn raw(addr: SocketAddr, request: &[u8]) -> String {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    tcp.write_all(request).await.expect("write");
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn mode_a_end_to_end() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let upstream = Upstream::start().await;
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
    let main = add(&mut ana, "Provider", TOKEN).await;
    let meta = add(&mut ana, "Metadata", "meta-token-0123456789abcdef").await;
    let rated = add(&mut ana, "Rated", "rated-token-0123456789abcdef").await;

    // The proxy pairs like any agent; its key goes in a 0600 file.
    let home = Home::at(dir.path().join("proxy"));
    let report = init(InitOptions {
        home: home.clone(),
        name: "klav-proxy".into(),
        server: server.url.clone(),
        email: EMAIL.into(),
        key_store: KeyStoreChoice::File,
        key_file: None,
        // Never the machine's: a CI image that sets SSL_CERT_FILE must not
        // change what this test checks.
        env: StartEnv::default(),
    })
    .await
    .expect("init");
    let proxy_id: klav_core::ids::AgentId = report.agent_id.parse().expect("id");
    let origin = format!("https://upstream.test:{}", upstream.port);
    let mut rules = vec![
        proxy_rule(
            Effect::Allow,
            main.item,
            "upstream.test",
            &["GET", "POST"],
            "/v1",
        ),
        proxy_rule(
            Effect::Ask,
            main.item,
            "upstream.test",
            &["DELETE"],
            "/v1/items",
        ),
        proxy_rule(Effect::Allow, meta.item, "metadata.test", &["GET"], "/"),
        proxy_rule(Effect::Allow, rated.item, "upstream.test", &["GET"], "/v1"),
    ];
    for p in [Permission::Reveal, Permission::Inject, Permission::Fill] {
        rules.push(Rule::new(p, Effect::Deny));
    }
    ana.grant_items(
        proxy_id,
        ItemGrantRequest {
            items: vec![main, meta, rated],
            profiles: vec![
                profile("up", main.item, origin.clone(), 50),
                profile(
                    "meta",
                    meta.item,
                    format!("https://metadata.test:{}", upstream.port),
                    50,
                ),
                profile("rated", rated.item, origin.clone(), 2),
            ],
            policy: Policy {
                rules,
                expires_at: None,
            },
            issuers: Vec::new(),
        },
        &report.pairing_code,
    )
    .await
    .expect("grant items");

    let agent = load(&home, "klav-proxy", &StartEnv::default()).expect("load proxy");
    let session = klav_sdk::Session::open(agent).await.expect("session");
    let lookup = FakeLookup::new(&[
        (
            "upstream.test",
            &["127.0.0.1".parse::<IpAddr>().expect("ip")],
        ),
        (
            "metadata.test",
            &["169.254.169.254".parse::<IpAddr>().expect("ip")],
        ),
    ]);
    let client = crate::net::test_client(
        lookup,
        vec!["127.0.0.1".parse().expect("ip")],
        include_bytes!("../tests/fixtures/ca.der"),
    )
    .expect("client");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let state = Arc::new(ProxyState::new(session, client, addr.port()));
    let served = Arc::clone(&state);
    tokio::spawn(async move {
        let listener = crate::listener::Limited::new(listener, crate::proxy::MAX_CONNECTIONS);
        let _ = axum::serve(listener, router(served)).await;
    });
    let proxy = Running {
        base: format!("http://{addr}"),
        caller: reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("caller"),
    };

    // 1. The credential reaches the upstream, in the profile's header and
    // nowhere else; the caller's own credentials, overrides and Host never
    // do; and the answer comes back with the value redacted from the
    // headers and from a body that split it over two chunks.
    let res = proxy
        .caller
        .get(format!("{}/up/v1/echo", proxy.base))
        .header("authorization", "Bearer klav-placeholder")
        .header("cookie", "session=placeholder")
        .header("x-http-method-override", "DELETE")
        .header("x-forwarded-port", "1")
        .header("x-original-url", "/admin")
        .header("accept-encoding", "gzip")
        .send()
        .await
        .expect("proxy answers");
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers().get("klav-error").is_none(),
        "no spoofed Klav-Error"
    );
    let echoed = res
        .headers()
        .get("x-echo")
        .expect("x-echo")
        .as_bytes()
        .to_vec();
    let body = res.bytes().await.expect("body");
    let fragment = &TOKEN.as_bytes()[..12];
    for bytes in [&echoed[..], &body[..]] {
        assert!(
            !bytes.windows(fragment.len()).any(|w| w == fragment),
            "the caller must never see the credential or a piece of it"
        );
        assert!(
            bytes
                .windows(klav_sdk::actions::REDACTED.len())
                .any(|w| w == klav_sdk::actions::REDACTED.as_bytes())
        );
    }
    let seen = upstream.requests();
    assert_eq!(seen.len(), 1);
    let first = &seen[0];
    assert_eq!(first.method, "GET");
    assert_eq!(first.target, "/v1/echo");
    assert!(
        first.header("authorization") == Some(format!("Bearer {TOKEN}").as_str()),
        "the upstream must get the stored credential"
    );
    assert_eq!(
        first.header("host"),
        Some(format!("upstream.test:{}", upstream.port).as_str())
    );
    assert_eq!(first.header("accept-encoding"), Some("identity"));
    assert!(first.header("cookie").is_none());
    assert!(first.header("x-http-method-override").is_none());
    assert!(first.header("x-forwarded-port").is_none());
    assert!(first.header("x-original-url").is_none());
    // The match was counted for the profile (and logged, without it).
    let mut counted = 0;
    for _ in 0..50 {
        counted = state.redactions("up");
        if counted > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(counted >= 2, "header and body matches counted: {counted}");

    // 1b. Only programs of this machine: a request that carries a
    // browser's `Origin` or `Sec-Fetch-Site`, or names another host (DNS
    // rebinding), is refused before the server is asked;
    // `localhost:<port>` is fine, and so is `Sec-Fetch-Mode` alone, which
    // Node's built-in `fetch` sends.
    for (name, value) in [
        ("origin", "https://evil.test".to_owned()),
        ("sec-fetch-site", "cross-site".to_owned()),
        ("host", "evil.test".to_owned()),
        ("host", format!("evil.test:{}", addr.port())),
        ("host", "127.0.0.1:1".to_owned()),
    ] {
        let res = proxy
            .caller
            .get(format!("{}/up/v1/echo", proxy.base))
            .header(name, value.as_str())
            .send()
            .await
            .expect("answer");
        let (status, code, body) = klav_error(res).await;
        assert_eq!(
            (status, code.as_str()),
            (StatusCode::FORBIDDEN, "klav_not_allowed"),
            "{name}: {value}"
        );
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|m| m.contains("Sec-Fetch-Site")),
            "{body}"
        );
    }
    let res = proxy
        .caller
        .get(format!("{}/up/v1/cors", proxy.base))
        .header("host", format!("localhost:{}", addr.port()))
        .send()
        .await
        .expect("answer");
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers()
            .keys()
            .all(|n| !n.as_str().starts_with("access-control-")),
        "no CORS header reaches a page"
    );
    let res = proxy
        .caller
        .get(format!("{}/up/v1/plain", proxy.base))
        .header("sec-fetch-mode", "cors")
        .send()
        .await
        .expect("answer");
    assert_eq!(res.status(), StatusCode::OK, "Node's fetch is let through");
    assert_eq!(upstream.requests().len(), 3);

    // 2. Outside the profile: another path, an unknown profile, a path in
    // another spelling, CONNECT, an absolute URI, and a path the URL parser
    // would re-encode. None reaches the upstream.
    for path in [
        "/up/admin",
        "/up/v1/%65cho",
        "/up/v1/../admin",
        "/nope/v1/echo",
    ] {
        let (status, code, _) = klav_error(proxy.get(path).await).await;
        assert_eq!(
            (status, code.as_str()),
            (StatusCode::FORBIDDEN, "klav_not_allowed"),
            "{path}"
        );
    }
    let (status, code, _) = klav_error(
        proxy
            .caller
            .post(format!("{}/up/other", proxy.base))
            .send()
            .await
            .expect("answer"),
    )
    .await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::FORBIDDEN, "klav_not_allowed")
    );
    let absolute = raw(
        addr,
        b"GET http://evil.test/up/v1/echo HTTP/1.1\r\nhost: evil.test\r\nconnection: close\r\n\r\n",
    )
    .await;
    assert!(absolute.starts_with("HTTP/1.1 403"), "{absolute}");
    assert!(
        absolute
            .to_ascii_lowercase()
            .contains("klav-error: klav_not_allowed")
    );
    let reencoded = raw(
        addr,
        format!(
            "GET /up/v1/a{{b}} HTTP/1.1\r\nhost: 127.0.0.1:{}\r\nconnection: close\r\n\r\n",
            addr.port()
        )
        .as_bytes(),
    )
    .await;
    assert!(
        reencoded.starts_with("HTTP/1.1 403") || reencoded.starts_with("HTTP/1.1 400"),
        "{reencoded}"
    );
    let connect = raw(
        addr,
        b"CONNECT upstream.test:443 HTTP/1.1\r\nhost: upstream.test:443\r\nconnection: close\r\n\r\n",
    )
    .await;
    assert!(!connect.starts_with("HTTP/1.1 2"), "{connect}");
    assert_eq!(upstream.requests().len(), 3);

    // 3. The SSRF defence: a host that resolves to the metadata address is
    // refused at connect time, and a redirect is never followed.
    let (status, code, body) = klav_error(proxy.get("/meta/").await).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::BAD_GATEWAY, "klav_upstream_blocked")
    );
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("metadata address")),
        "refused for its address, not because the connection failed: {body}"
    );
    assert_eq!(
        upstream.requests().len(),
        3,
        "the metadata host is never reached"
    );
    let (status, code, _) = klav_error(proxy.get("/up/v1/redirect").await).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::BAD_GATEWAY, "klav_upstream_blocked")
    );
    // A compressed answer is blocked, not passed unchecked.
    let (status, code, _) = klav_error(proxy.get("/up/v1/gzip").await).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::BAD_GATEWAY, "klav_upstream_blocked")
    );
    // So is one compressed under chunked framing (`Transfer-Encoding:
    // gzip, chunked`), which the HTTP client only de-chunks.
    let (status, code, _) = klav_error(proxy.get("/up/v1/te-gzip").await).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::BAD_GATEWAY, "klav_upstream_blocked")
    );
    // A `304 Not Modified` passes, with no body and its headers redacted.
    let res = proxy
        .caller
        .get(format!("{}/up/v1/not-modified", proxy.base))
        .header("if-none-match", "\"v1\"")
        .send()
        .await
        .expect("answer");
    assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(res.headers()["etag"], "\"v1\"");
    let echoed = res.headers()["x-echo"].as_bytes().to_vec();
    assert!(!echoed.windows(fragment.len()).any(|w| w == fragment));
    assert!(res.bytes().await.expect("body").is_empty());
    let conditional = upstream.requests().pop().expect("request");
    assert_eq!(conditional.header("if-none-match"), Some("\"v1\""));
    // Two layers of chunked framing are blocked like a compressed one.
    let (status, code, _) = klav_error(proxy.get("/up/v1/te-twice").await).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::BAD_GATEWAY, "klav_upstream_blocked")
    );
    // A body that breaks upstream reaches the caller broken, never as a
    // short answer that looks whole.
    let res = proxy.get("/up/v1/broken").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(res.bytes().await.is_err(), "a cut answer is an error");
    assert_eq!(upstream.requests().len(), 9);

    // 4. The profile's rate.
    assert_eq!(proxy.get("/rated/v1/a").await.status(), StatusCode::OK);
    assert_eq!(proxy.get("/rated/v1/b").await.status(), StatusCode::OK);
    let (status, code, body) = klav_error(proxy.get("/rated/v1/c").await).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::TOO_MANY_REQUESTS, "klav_rate_limited")
    );
    assert!(body["retry_after"].as_u64().is_some_and(|s| s > 0));
    assert_eq!(upstream.requests().len(), 11);

    // 5. `ask`: the call waits for the person; a retry gives back the same
    // approval; once she approves, the retry goes through, and the
    // approval fits only that request.
    let (status, code, body) = klav_error(proxy.delete("/up/v1/items/1").await).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::CONFLICT, "klav_approval_pending")
    );
    let approval = body["approval_id"]
        .as_str()
        .expect("approval id")
        .to_owned();
    let (_, _, again) = klav_error(proxy.delete("/up/v1/items/1").await).await;
    assert_eq!(again["approval_id"], approval.as_str());
    assert_eq!(upstream.requests().len(), 11);
    let view = ana
        .approvals(false)
        .await
        .expect("approvals")
        .into_iter()
        .find(|v| v.id.to_string() == approval)
        .expect("pending approval");
    ana.decide_approval(view.id, true, None, &view.request_digest)
        .await
        .expect("approve");
    assert_eq!(
        proxy.delete("/up/v1/items/1").await.status(),
        StatusCode::OK
    );
    let last = upstream.requests().pop().expect("request");
    assert_eq!(
        (last.method.as_str(), last.target.as_str()),
        ("DELETE", "/v1/items/1")
    );
    let (_, code, body) = klav_error(proxy.delete("/up/v1/items/2").await).await;
    assert_eq!(
        code, "klav_approval_pending",
        "another path needs its own approval"
    );
    let other = body["approval_id"]
        .as_str()
        .expect("approval id")
        .to_owned();
    let view = ana
        .approvals(false)
        .await
        .expect("approvals")
        .into_iter()
        .find(|v| v.id.to_string() == other)
        .expect("pending approval");
    ana.decide_approval(view.id, false, None, &view.request_digest)
        .await
        .expect("deny");
    let (status, code, _) = klav_error(proxy.delete("/up/v1/items/2").await).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::FORBIDDEN, "klav_approval_denied")
    );
    assert_eq!(upstream.requests().len(), 12);

    // 6. Exactly the bytes checked reach the upstream: an escaped space,
    // and reserved characters written as themselves. A client that escapes
    // them itself is refused, told which escape and how to send it, and
    // the rest of its path is not echoed.
    for path in ["/v1/a%20b", "/v1/x,y:z@w"] {
        assert_eq!(
            proxy.get(&format!("/up{path}")).await.status(),
            StatusCode::OK,
            "{path}"
        );
        let last = upstream.requests().pop().expect("request");
        assert_eq!(last.target, path);
    }
    let (status, code, body) = klav_error(proxy.get("/up/v1/tok_hidden/x%2Cy").await).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::FORBIDDEN, "klav_not_allowed")
    );
    let message = body["message"].as_str().expect("message");
    assert!(
        message.contains("`%2C`") && message.contains("send `,` unescaped"),
        "{message}"
    );
    assert!(!body.to_string().contains("tok_hidden"));
    // The query goes byte for byte, but never one that names the method,
    // in any spelling of the name.
    assert_eq!(
        proxy.get("/up/v1/q?a=1&b=%2F%20x;c").await.status(),
        StatusCode::OK
    );
    let last = upstream.requests().pop().expect("request");
    assert_eq!(last.target, "/v1/q?a=1&b=%2F%20x;c");
    for query in [
        "_method=DELETE",
        "a=1&%5Fmethod=DELETE",
        "_METHOD=DELETE",
        "a=1&%255Fmethod=DELETE",
        "x-http-method-override=DELETE",
    ] {
        let (status, code, _) = klav_error(proxy.get(&format!("/up/v1/q?{query}")).await).await;
        assert_eq!(
            (status, code.as_str()),
            (StatusCode::FORBIDDEN, "klav_not_allowed"),
            "{query}"
        );
    }
    assert_eq!(upstream.requests().len(), 15);

    // 7. Revoking the proxy cuts the next call: no authorization is cached.
    let revoked = ana.revoke_agent(proxy_id, false).await.expect("revoke");
    assert!(revoked.complete(), "{revoked:?}");
    let (status, code, body) = klav_error(proxy.get("/up/v1/echo").await).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::FORBIDDEN, "klav_not_allowed")
    );
    // The server answers a revoked agent with a plain 403, as it answers
    // its policy: the message names both. (A 401, which the proxy tells
    // apart by its status, is a signature the server does not know.)
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("revoked this credential proxy")),
        "{body}"
    );
    assert_eq!(
        upstream.requests().len(),
        15,
        "nothing reaches the upstream after revocation"
    );
}
