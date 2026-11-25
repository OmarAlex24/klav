//! Agents filling through the extension: `klavd` relays `browser_tab` and
//! `browser_fill` to an attached extension (here, a fake one on the socket)
//! and the agent gets field names back, never values. A fill needs the
//! unlocked session and, once per connection, the person's presence in
//! Klav's frame (ADR 0041 §3.1): the fake answers it with the master
//! password.

mod common;

use std::time::Duration;

use klav_client::Home;
use klav_client::ops::SecretText;
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{BrowserTab, ErrorCode, Request};
use klav_daemon::{Config, serve};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

const PASSWORD: &str = "correct horse battery staple";

struct FakeExtension {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    next: u64,
    /// Requests whose answers [`FakeExtension::line`] skips: the master
    /// passwords [`FakeExtension::answer`] typed for the presence gate.
    skip: Vec<u64>,
}

impl FakeExtension {
    async fn attach(home: &Home, browser: &str) -> Self {
        let stream = UnixStream::connect(home.socket_path())
            .await
            .expect("connect");
        let (read, writer) = stream.into_split();
        let mut ext = Self {
            reader: BufReader::new(read),
            writer,
            next: 1,
            skip: Vec::new(),
        };
        ext.send(json!({ "op": "extension_attach", "browser": browser }))
            .await;
        let answer = ext.line().await;
        assert!(answer.get("ok").is_some(), "{answer}");
        ext
    }

    async fn send(&mut self, request: Value) {
        let line = json!({ "v": 1, "id": self.next, "request": request });
        self.next += 1;
        let mut bytes = serde_json::to_vec(&line).expect("json");
        bytes.push(b'\n');
        self.writer.write_all(&bytes).await.expect("write");
    }

    /// The next line, past the answers to the master passwords typed for
    /// the presence gate.
    async fn line(&mut self) -> Value {
        loop {
            let mut line = String::new();
            tokio::time::timeout(Duration::from_secs(10), self.reader.read_line(&mut line))
                .await
                .expect("in time")
                .expect("read");
            let line: Value = serde_json::from_str(&line).expect("json line");
            let answered = line["id"]
                .as_u64()
                .filter(|_| line.get("event").is_none())
                .and_then(|id| self.skip.iter().position(|s| *s == id));
            match answered {
                Some(at) => {
                    assert!(line.get("ok").is_some(), "presence: {line}");
                    self.skip.remove(at);
                }
                None => return line,
            }
        }
    }

    /// Answers the presence gate's `presence` event, the next line, with
    /// the master password.
    async fn presence(&mut self) {
        let line = self.line().await;
        assert_eq!(line["event"]["kind"], "presence", "{line}");
        self.type_password(&line["event"]).await;
    }

    /// The master password for `event`, as the person types it in Klav's
    /// frame; its answer is skipped.
    async fn type_password(&mut self, event: &Value) {
        self.skip.push(self.next);
        self.send(json!({
            "op": "extension_presence",
            "event": event["id"],
            "password": PASSWORD,
        }))
        .await;
    }

    /// Waits for an event and answers it with `answer(event)`. The
    /// presence gate's `presence` event before it, if any, gets the master
    /// password, as the person types it in Klav's frame.
    async fn answer(&mut self, answer: impl FnOnce(&Value) -> Value) -> Value {
        let mut line = self.line().await;
        if line["event"]["kind"] == "presence" {
            self.type_password(&line["event"]).await;
            line = self.line().await;
        }
        let event = line["event"].clone();
        assert!(event.is_object(), "expected an event, got {line}");
        let id = event["id"].as_u64().expect("event id");
        let mut reply = answer(&event);
        reply["op"] = json!("extension_reply");
        reply["event"] = json!(id);
        self.send(reply).await;
        let ack = self.line().await;
        assert!(ack.get("ok").is_some(), "{ack}");
        event
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn agents_fill_the_active_tab_through_the_extension() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = Home::at(dir.path().join("home"));
    let server = common::ServerProcess::start(900);
    account(&server, &home).await;
    let config = Config {
        home: home.clone(),
        idle_lock: Duration::from_secs(60),
        touch_id: false,
        sync_after: klav_daemon::SYNC_AFTER,
        build: None,
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let daemon = tokio::spawn(serve(config, async {
        let _ = stopped.await;
    }));
    wait_until_listening(&home, &daemon).await;

    let mut agent = DaemonClient::connect(&home).await.expect("klavd");
    // No browser yet: a clear error, and klavd is locked anyway.
    let err = agent
        .call::<BrowserTab>(Request::BrowserTab)
        .await
        .expect_err("no browser");
    assert_eq!(err.code, ErrorCode::NotFound);
    assert!(err.message.contains("extension"), "{}", err.message);
    unlock(&mut agent).await;

    let mut chrome = FakeExtension::attach(&home, "Chrome").await;
    let mut firefox = FakeExtension::attach(&home, "Firefox").await;

    // The focused browser wins (Chrome here, though Firefox attached last).
    let ask = tokio::spawn(async move {
        let tab = agent
            .call::<BrowserTab>(Request::BrowserTab)
            .await
            .map(|(t, _)| t);
        (agent, tab)
    });
    firefox
        .answer(
            |_| json!({ "ok": { "tab_id": 7, "url": "https://example.org/", "focused": false } }),
        )
        .await;
    chrome
        .answer(|_| {
            json!({ "ok": { "tab_id": 3, "url": "https://github.com/login", "focused": true } })
        })
        .await;
    let (mut agent, tab) = ask.await.expect("task");
    let tab = tab.expect("tab");
    // The agent gets the origin, never the path or query.
    assert_eq!(tab.url, "https://github.com");
    assert_eq!(tab.browser, "Chrome");

    // The fill reaches only Chrome, with the values; the agent gets names.
    let fill = Request::BrowserFill {
        tab: tab.tab.clone(),
        host: "github.com".into(),
        agent: "claude-code".into(),
        agent_id: None,
        item: None,
        reason: "log in to check CI".into(),
        kind: klav_core::model::item::ItemKind::Login,
        fields: serde_json::from_value(json!([
            { "name": "username", "kind": "username", "value": "ana" },
            { "name": "password", "kind": "password", "value": "MARKER-pw" }
        ]))
        .expect("fields"),
        selectors: Vec::new(),
        submit: false,
    };
    let ask = tokio::spawn(async move {
        let report = agent.call::<Value>(fill).await.map(|(r, _)| r);
        (agent, report)
    });
    // With two attached, Chrome must be the one with the focus before it is
    // asked for presence (ADR 0041 §3.1, P25), and again before the fill.
    let unfocused = |_: &Value| json!({ "ok": { "tab_id": 7, "url": "https://example.org/", "focused": false } });
    let focused = |_: &Value| json!({ "ok": { "tab_id": 3, "url": "https://github.com/login", "focused": true } });
    // `klavd` asks the newest first, one at a time.
    firefox.answer(unfocused).await;
    chrome.answer(focused).await;
    chrome.presence().await;
    firefox.answer(unfocused).await;
    chrome.answer(focused).await;
    let event = chrome
        .answer(|event| {
            json!({ "ok": {
                "url": "https://github.com/login?token=MARKER-token",
                "filled": event["fields"].as_array().unwrap_or_else(|| panic!("a fill: {event}")).iter()
                    .map(|f| f["name"].clone()).collect::<Vec<_>>()
            } })
        })
        .await;
    assert_eq!(event["kind"], "fill");
    assert_eq!(event["tab_id"], 3);
    assert_eq!(event["host"], "github.com");
    assert_eq!(event["agent"], "claude-code");
    assert_eq!(event["fields"][1]["value"], "MARKER-pw");
    let (mut agent, report) = ask.await.expect("task");
    let report = report.expect("report");
    assert_eq!(report["filled"], json!(["username", "password"]));
    assert_eq!(report["url"], "https://github.com");
    assert!(!report.to_string().contains("MARKER"), "{report}");

    // The extension's refusal (the tab moved) reaches the agent as is.
    let fill = Request::BrowserFill {
        tab: tab.tab.clone(),
        host: "github.com".into(),
        agent: "claude-code".into(),
        agent_id: None,
        item: None,
        reason: "again".into(),
        kind: klav_core::model::item::ItemKind::Login,
        fields: Vec::new(),
        selectors: Vec::new(),
        submit: false,
    };
    let ask = tokio::spawn(async move { agent.call::<Value>(fill).await.map(|(r, _)| r) });
    // The connection's presence holds until the lock; the focus is asked
    // before every fill.
    firefox.answer(unfocused).await;
    chrome.answer(focused).await;
    chrome
        .answer(|_| {
            json!({ "error": { "code": "denied", "message": "the tab is now on evil.example" } })
        })
        .await;
    let err = ask.await.expect("task").expect_err("denied");
    assert_eq!(err.code, ErrorCode::Denied);

    // A browser that goes away is forgotten.
    drop(chrome);
    let mut agent = DaemonClient::connect(&home).await.expect("klavd");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let err = agent
        .call::<Value>(Request::BrowserFill {
            tab: tab.tab,
            host: "github.com".into(),
            agent: "a".into(),
            agent_id: None,
            item: None,
            reason: "r".into(),
            kind: klav_core::model::item::ItemKind::Login,
            fields: Vec::new(),
            selectors: Vec::new(),
            submit: false,
        })
        .await
        .expect_err("closed");
    assert_eq!(err.code, ErrorCode::NotFound);

    // An extension cannot answer an event sent to another one.
    firefox
        .send(json!({ "op": "extension_reply", "event": 1, "ok": {} }))
        .await;
    let answer = firefox.line().await;
    assert_eq!(answer["error"]["code"], "not_found");

    let _ = stop.send(());
    daemon.await.expect("join").expect("serve");
}

/// An account in `home`, for `klavd` to unlock.
async fn account(server: &common::ServerProcess, home: &Home) {
    let (unlocked, _kit) = klav_client::signup(
        home,
        klav_client::SignupRequest {
            server: server.url.clone(),
            email: "ana@example.com".into(),
            password: klav_core::crypto::kdf::MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: klav_proto::auth::DeviceKind::Cli,
        },
    )
    .await
    .expect("sign-up");
    drop(unlocked);
}

async fn unlock(client: &mut DaemonClient) {
    client
        .call::<Value>(Request::Unlock {
            password: Some(SecretText::new(PASSWORD)),
            passkey_flow: false,
        })
        .await
        .expect("unlock");
}

/// `klavd` in `dir`, with no account: locked for good.
async fn start(dir: &std::path::Path) -> (Home, tokio::sync::oneshot::Sender<()>) {
    let home = Home::at(dir.join("home"));
    let config = Config {
        home: home.clone(),
        idle_lock: Duration::from_secs(60),
        touch_id: false,
        sync_after: klav_daemon::SYNC_AFTER,
        build: None,
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let daemon = tokio::spawn(serve(config, async {
        let _ = stopped.await;
    }));
    wait_until_listening(&home, &daemon).await;
    (home, stop)
}

/// Waits until the in-process `klavd` has its socket. A fixed few seconds
/// of polling were not enough on a loaded machine: the loop gave up without
/// a word and the next connection failed. The bound is generous, and a
/// `klavd` that stopped first fails at once. It looks for the socket file
/// and does not connect: `klavd` numbers its connections, a tab's ID starts
/// with its extension's number, and these tests name tabs of the first
/// connection ("1.3", or "2.3" after an unlock), which a probe would take.
async fn wait_until_listening(home: &Home, daemon: &tokio::task::JoinHandle<Result<(), String>>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while !home.socket_path().exists() {
        assert!(!daemon.is_finished(), "klavd stopped before it listened");
        assert!(
            tokio::time::Instant::now() < deadline,
            "klavd did not listen on {} within 60 s",
            home.socket_path().display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// `klavd` in `dir` with an account, unlocked by the first connection:
/// the next one, the extension's, is number 2, so its tabs are "2.<id>".
async fn start_unlocked(
    dir: &std::path::Path,
) -> (
    Home,
    tokio::sync::oneshot::Sender<()>,
    common::ServerProcess,
) {
    let server = common::ServerProcess::start(900);
    let home = Home::at(dir.join("home"));
    account(&server, &home).await;
    let (home, stop) = start(dir).await;
    let mut person = DaemonClient::connect(&home).await.expect("klavd");
    unlock(&mut person).await;
    (home, stop, server)
}

fn fill(tab: &str, agent: &str, reason: &str, value: &str) -> Request {
    Request::BrowserFill {
        tab: tab.to_owned(),
        host: "github.com".into(),
        agent: agent.to_owned(),
        agent_id: None,
        item: None,
        reason: reason.to_owned(),
        kind: klav_core::model::item::ItemKind::Login,
        fields: serde_json::from_value(json!([
            { "name": "password", "kind": "password", "value": value }
        ]))
        .expect("fields"),
        selectors: Vec::new(),
        submit: false,
    }
}

/// What the agent declares reaches the page's notice filtered and cut.
#[tokio::test(flavor = "multi_thread")]
async fn the_agents_name_and_reason_are_cleaned_before_the_page_sees_them() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (home, _stop, _server) = start_unlocked(dir.path()).await;
    let mut chrome = FakeExtension::attach(&home, "Chrome").await;
    let mut agent = DaemonClient::connect(&home).await.expect("klavd");
    let long = "x".repeat(500);
    let name = format!("Klav\u{202E}nimda\n{long}");
    let ask = tokio::spawn(async move {
        agent
            .call::<Value>(fill("2.3", &name, "check\u{200B} CI\r\nnow", "pw"))
            .await
            .map(|(r, _)| r)
    });
    let event = chrome.answer(|_| json!({ "ok": { "filled": [] } })).await;
    let shown = event["agent"].as_str().expect("agent");
    assert!(shown.starts_with("Klav nimda x"), "{shown}");
    assert!(shown.chars().count() <= 64, "{shown}");
    assert!(!shown.chars().any(klav_core::text::is_hidden), "{shown:?}");
    assert_eq!(event["reason"], "check CI now");
    ask.await.expect("task").expect("filled");

    // A host that is not one is refused before reaching the page.
    let mut agent = DaemonClient::connect(&home).await.expect("klavd");
    let mut bad = fill("2.3", "a", "r", "pw");
    if let Request::BrowserFill { host, .. } = &mut bad {
        *host = "evil.example/<script>".into();
    }
    let err = agent.call::<Value>(bad).await.expect_err("bad host");
    assert_eq!(err.code, ErrorCode::BadRequest);
}

/// An extension that stops reading does not hold agents' requests: it is
/// disconnected after a few seconds. It answers the presence gate and one
/// fill first, so the values reach it.
#[tokio::test(flavor = "multi_thread")]
async fn an_extension_that_stops_reading_is_disconnected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (home, _stop, _server) = start_unlocked(dir.path()).await;
    let mut stuck = FakeExtension::attach(&home, "Stuck").await;
    let first = {
        let home = home.clone();
        tokio::spawn(async move {
            let mut agent = DaemonClient::connect(&home).await.expect("klavd");
            agent.call::<Value>(fill("2.1", "a", "r", "pw")).await
        })
    };
    stuck.answer(|_| json!({ "ok": { "filled": [] } })).await;
    first.await.expect("task").expect("filled");
    let big = "v".repeat(256 * 1024);
    let mut asks = Vec::new();
    for _ in 0..48 {
        let home = home.clone();
        let big = big.clone();
        asks.push(tokio::spawn(async move {
            let mut agent = DaemonClient::connect(&home).await.expect("klavd");
            agent
                .call::<Value>(fill("2.1", "a", "r", &big))
                .await
                .map(|(r, _)| r)
        }));
    }
    let disconnected = tokio::time::timeout(Duration::from_secs(30), async {
        for ask in asks {
            if let Ok(Err(e)) = ask.await
                && e.message.contains("not answering")
            {
                return true;
            }
        }
        false
    })
    .await
    .expect("agents' requests are not held by a stuck extension");
    assert!(disconnected, "some request saw the extension dropped");
    let mut agent = DaemonClient::connect(&home).await.expect("klavd");
    let err = agent
        .call::<BrowserTab>(Request::BrowserTab)
        .await
        .expect_err("no browser left");
    assert_eq!(err.code, ErrorCode::NotFound);
    drop(stuck);
}

/// A pause of every agent works with `klavd` locked (ADR 0033 §7.2, P2):
/// it holds here at once and a fill never reaches the page.
#[tokio::test(flavor = "multi_thread")]
async fn a_pause_while_locked_stops_fills_before_the_page() {
    use klav_daemon::protocol::{DaemonStatus, PauseInEffect};
    let dir = tempfile::tempdir().expect("tempdir");
    let (home, _stop) = start(dir.path()).await;
    let _chrome = FakeExtension::attach(&home, "Chrome").await;
    let mut person = DaemonClient::connect(&home).await.expect("klavd");

    // No account in this home: nothing to sign a pause with, ever.
    let err = person
        .call::<Value>(Request::PauseAgents {
            agent: None,
            until: None,
        })
        .await
        .expect_err("no account");
    assert_eq!(err.code, ErrorCode::NotLoggedIn);
    let server = common::ServerProcess::start(900);
    let (unlocked, _kit) = klav_client::signup(
        &home,
        klav_client::SignupRequest {
            server: server.url.clone(),
            email: "ana@example.com".into(),
            password: klav_core::crypto::kdf::MasterPassword::new("correct horse battery staple"),
            device_name: "laptop".into(),
            device_kind: klav_proto::auth::DeviceKind::Cli,
            invite: None,
        },
    )
    .await
    .expect("sign-up");
    drop(unlocked);

    // One agent needs the account (to find it); a pause already over is
    // refused.
    let err = person
        .call::<Value>(Request::PauseAgents {
            agent: Some(klav_core::ids::AgentId::generate()),
            until: None,
        })
        .await
        .expect_err("locked");
    assert_eq!(err.code, ErrorCode::Locked);
    let err = person
        .call::<Value>(Request::PauseAgents {
            agent: None,
            until: Some(1),
        })
        .await
        .expect_err("over");
    assert_eq!(err.code, ErrorCode::Invalid);

    let (pauses, warnings) = person
        .call::<Vec<PauseInEffect>>(Request::PauseAgents {
            agent: None,
            until: None,
        })
        .await
        .expect("paused");
    assert_eq!(pauses.len(), 1);
    assert!(pauses[0].local && pauses[0].agent_id.is_none() && pauses[0].until.is_none());
    assert!(warnings[0].contains("this computer only"), "{warnings:?}");
    let (status, _) = person
        .call::<DaemonStatus>(Request::Status)
        .await
        .expect("status");
    assert!(!status.unlocked);
    assert_eq!(status.agents_paused, pauses);

    // Refused here, with or without the agent's ID: the fake extension
    // gets no event (it would block this call waiting for an answer).
    let mut agent = DaemonClient::connect(&home).await.expect("klavd");
    let err = agent
        .call::<Value>(fill("1.3", "claude-code", "log in", "pw"))
        .await
        .expect_err("paused");
    assert_eq!(err.code, ErrorCode::AgentsPaused);
    assert!(err.message.contains("agents_paused"), "{}", err.message);
    let mut with_id = fill("1.3", "claude-code", "log in", "pw");
    if let Request::BrowserFill { agent_id, .. } = &mut with_id {
        *agent_id = Some(klav_core::ids::AgentId::generate());
    }
    let err = agent.call::<Value>(with_id).await.expect_err("paused");
    assert_eq!(err.code, ErrorCode::AgentsPaused);

    // Resuming needs the account: locked, it says so.
    let err = person
        .call::<Value>(Request::ResumeAgents {
            agent: None,
            password: None,
        })
        .await
        .expect_err("locked");
    assert_eq!(err.code, ErrorCode::Locked);
}
