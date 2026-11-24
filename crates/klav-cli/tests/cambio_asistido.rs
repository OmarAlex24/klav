//! Assisted password changes through `klavd` (ADR 0022 §5) with the real
//! server and binaries: an agent with a task that covers `rotate` on a
//! login starts a change with the server, hands the person's `klavd` the
//! request it signed, and `klavd` checks it, asks the tab (a fake extension
//! on the socket) for the field's rules, stores the new password as pending
//! in the item and only then fills. The agent gets field names and the
//! change's ID, never a value. Confirming makes the new one current;
//! cancelling keeps the current one and files the new one as generated, not
//! confirmed. A page on another host, a tampered request and a replayed one
//! fill and store nothing.
//!
//! The same flow through `klav mcp` (ADR 0022 §7): `change_password_url`,
//! `rotate_password` (only to the `extension` target), `rotate_confirm`,
//! `rotate_cancel` and `create_item` with `generate`, and no tool answer
//! ever holds a password.

mod common;

use std::time::Duration;

use common::mcp::Mcp;
use common::{Device, ServerProcess};
use klav_client::Home;
use klav_client::rotate::RotationStep;
use klav_core::ids::{ItemId, TaskId};
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{BrowserTab, ErrorBody, ErrorCode, Request};
use klav_proto::agent::Claims;
use klav_proto::rotate::{
    AgentRequestProof, AgentRotateFinish, AgentRotateStart, RotationInfo, RotationStarted,
    RotationStatus,
};
use klav_sdk::agent::Agent;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

const OLD: &str = "MARKER-rotate-old-pass-1";
const SITE: &str = "https://bank.example.com/settings/password";

fn json_of(run: &common::Run) -> Value {
    serde_json::from_str(&run.stdout)
        .unwrap_or_else(|e| panic!("json: {e}\nstdout: {}\nstderr: {}", run.stdout, run.stderr))
}

/// Stops `klavd` when the test ends, also if it fails.
struct StopDaemon<'a>(&'a Device);

impl Drop for StopDaemon<'_> {
    fn drop(&mut self) {
        let _ = self.0.run(&["lock", "--stop"], "");
    }
}

/// The person's browser with Klav's extension, as `klavd` sees it.
struct FakeExtension {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    next: u64,
}

impl FakeExtension {
    async fn attach(home: &Home) -> Self {
        let stream = UnixStream::connect(home.socket_path())
            .await
            .expect("connect");
        let (read, writer) = stream.into_split();
        let mut ext = Self {
            reader: BufReader::new(read),
            writer,
            next: 1,
        };
        ext.send(json!({ "op": "extension_attach", "browser": "Chrome" }))
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

    async fn line(&mut self) -> Value {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(30), self.reader.read_line(&mut line))
            .await
            .expect("in time")
            .expect("read");
        serde_json::from_str(&line).expect("json line")
    }

    /// Waits for an event of `kind` and answers it with `answer(event)`.
    async fn answer(&mut self, kind: &str, answer: impl FnOnce(&Value) -> Value) -> Value {
        let line = self.line().await;
        let event = line["event"].clone();
        assert_eq!(event["kind"], kind, "expected a {kind} event, got {line}");
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

/// Where the probe would fill: the top frame, at `url`.
fn target(url: &str, focused: bool, rules: Value) -> Value {
    json!({ "ok": {
        "frame_id": 0,
        "url": url,
        "focused": focused,
        "token": "0123456789abcdef0123",
        "rules": rules,
    }})
}

fn filled() -> Value {
    json!({ "ok": { "filled": ["new_password", "confirm_password", "current_password"] } })
}

type Answer = Result<(Value, Vec<String>), ErrorBody>;

struct Rig {
    agent: Agent,
    item: ItemId,
    task: TaskId,
    home: Home,
}

impl Rig {
    async fn start(&self, reason: &str) -> (RotationStarted, AgentRequestProof) {
        self.agent
            .call_proved(
                "/v1/agent/rotations",
                &AgentRotateStart {
                    item_id: self.item,
                    reason: reason.into(),
                    claims: Claims {
                        tags: Vec::new(),
                        domain: Some("bank.example.com".into()),
                        ..Claims::default()
                    },
                    task_id: Some(self.task),
                },
            )
            .await
            .expect("rotate start")
    }

    async fn finish(&self, rotation: &RotationInfo, step: &str) -> AgentRequestProof {
        let (info, proof): (RotationInfo, _) = self
            .agent
            .call_proved(
                &format!("/v1/agent/rotations/{}/{step}", rotation.id),
                &AgentRotateFinish {
                    item_id: self.item,
                    reason: format!("the site said: {step}"),
                },
            )
            .await
            .expect("rotate finish");
        assert_ne!(info.status, RotationStatus::Started);
        proof
    }

    fn step(&self, rotation: &RotationInfo, request: AgentRequestProof) -> RotationStep {
        RotationStep {
            agent_id: self.agent.id(),
            task_id: self.task,
            rotation_id: rotation.id,
            item_id: self.item,
            request,
        }
    }

    /// The active tab, as an agent asks for it.
    async fn tab(&self, ext: &mut FakeExtension, url: &str) -> String {
        let home = self.home.clone();
        let ask = tokio::spawn(async move {
            let mut daemon = DaemonClient::connect(&home).await.expect("klavd");
            daemon
                .call::<BrowserTab>(Request::BrowserTab)
                .await
                .expect("tab")
                .0
        });
        let url = url.to_owned();
        ext.answer(
            "tab",
            move |_| json!({ "ok": { "tab_id": 4, "url": url, "focused": true } }),
        )
        .await;
        ask.await.expect("join").tab
    }

    /// `agent_rotate_begin`, from the agent's own connection.
    fn begin(&self, tab: String, step: RotationStep) -> tokio::task::JoinHandle<Answer> {
        let home = self.home.clone();
        tokio::spawn(async move {
            let mut daemon = DaemonClient::connect(&home).await.expect("klavd");
            daemon
                .call::<Value>(Request::AgentRotateBegin {
                    tab,
                    step,
                    submit: false,
                })
                .await
        })
    }

    async fn call(&self, request: Request) -> Result<Value, ErrorBody> {
        let mut daemon = DaemonClient::connect(&self.home).await.expect("klavd");
        daemon.call::<Value>(request).await.map(|(v, _)| v)
    }
}

fn password(person: &Device) -> String {
    password_of(person, "Bank")
}

fn password_of(person: &Device, title: &str) -> String {
    let view = json_of(
        &person
            .run(&["item", "get", title, "--reveal", "--json"], "")
            .ok(),
    );
    view["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .find(|f| f["name"] == "password")
        .and_then(|f| f["value"].as_str())
        .expect("password")
        .to_owned()
}

fn history(person: &Device) -> Value {
    json_of(&person.run(&["item", "history", "Bank", "--json"], "").ok())
}

/// The person with a «Bank» login, an agent `bot` with a grant on
/// Personal/General, and their server.
struct World {
    server: ServerProcess,
    root: tempfile::TempDir,
    person: Device,
    agent_device: Device,
}

fn world() -> World {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = Device::new(root.path(), "person");
    person.signup(&server, "ana@example.com");
    person
        .unlocked(
            &[
                "item",
                "add",
                "login",
                "--title",
                "Bank",
                "--username",
                "ana",
                "--url",
                "https://bank.example.com/login",
                "--secret-stdin",
                "password",
            ],
            &format!("{OLD}\n"),
        )
        .ok();
    let agent_device = Device::new(root.path(), "agent");
    let words = agent_device
        .run(
            &[
                "agent",
                "register",
                "--name",
                "bot",
                "--server",
                &server.url,
                "--email",
                "ana@example.com",
                "--key-store",
                "file",
            ],
            "",
        )
        .ok()
        .stdout
        .trim()
        .to_owned();
    person
        .unlocked(
            &[
                "agent",
                "approve",
                "bot",
                "--project",
                "Personal/General",
                "--ask",
                "fill",
                "--words",
                &words,
            ],
            "",
        )
        .ok();

    World {
        server,
        root,
        person,
        agent_device,
    }
}

impl World {
    /// Unlocks the person's `klavd` (Touch ID is off in tests) and gets a
    /// task with `rotate` on Bank approved. Returns the task and the item.
    fn rotate_task(&self) -> (String, ItemId) {
        let World {
            root,
            person,
            agent_device,
            ..
        } = self;
        // klavd unlocked (Touch ID is off in tests); the task through it.
        person.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
        let file = root.path().join("tarea.json");
        std::fs::write(
            &file,
            r#"{"task":"Change the bank password","reason":"It is reused","duration":"30m",
            "access":[{"ref":"klav://Personal/General/Bank","permissions":["rotate"]}]}"#,
        )
        .expect("tarea.json");
        let asked = json_of(&agent_device.run(
            &[
                "agent",
                "task",
                "request",
                file.to_str().expect("utf-8"),
                "--json",
            ],
            "",
        ));
        let task = asked["task_id"].as_str().expect("task_id").to_owned();
        person.unlocked(&["task", "approve", &task[..8]], "").ok();

        let item: ItemId = json_of(&person.run(&["item", "get", "Bank", "--json"], "").ok())["id"]
            .as_str()
            .expect("id")
            .parse()
            .expect("item id");
        (task, item)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_changes_a_password_without_seeing_it() {
    let w = world();
    let person = &w.person;
    let _stop = StopDaemon(person);
    let (task, item) = w.rotate_task();
    let home = Home::at(&person.home);
    let rig = Rig {
        agent: Agent::load(&Home::at(&w.agent_device.home), "bot").expect("agent"),
        item,
        task: task.parse().expect("task id"),
        home: home.clone(),
    };
    let mut ext = FakeExtension::attach(&home).await;

    // --- 1. Start, fill with the field's rules, confirm. ---------------------
    let (started, proof) = rig.start("rotate the reused password").await;
    let tab = rig.tab(&mut ext, SITE).await;
    let begin = rig.begin(tab, rig.step(&started.rotation, proof));
    let probe = ext
        .answer("rotate_probe", |_| {
            target(
                SITE,
                true,
                json!({ "password_rules": "minlength: 24; required: digit;" }),
            )
        })
        .await;
    assert_eq!(probe["host"], "bank.example.com");
    assert_eq!(probe["tab_id"], 4);
    // Before anything is filled, the new password is already pending in
    // the item, on the server.
    let fill = ext
        .answer("rotate_fill", |_| {
            let pending = history(person);
            assert_eq!(pending["pending"], true, "{pending}");
            filled()
        })
        .await;
    assert_eq!(fill["current"], OLD);
    assert_eq!(fill["agent"], "bot");
    assert_eq!(fill["frame_id"], 0);
    let first = fill["new"].as_str().expect("new").to_owned();
    assert_eq!(first.chars().count(), 24, "the field's passwordrules");
    assert!(first.chars().any(|c| c.is_ascii_digit()));
    assert_ne!(first, OLD);
    let (answer, _) = begin.await.expect("join").expect("begin");
    assert_eq!(
        answer,
        json!({
            "filled": ["new_password", "confirm_password", "current_password"],
            "pending_id": started.rotation.id,
        })
    );
    let said = answer.to_string();
    assert!(!said.contains(OLD) && !said.contains(&first));
    // Still the old one until the agent confirms.
    assert_eq!(password(person), OLD);

    let confirm = rig.finish(&started.rotation, "confirm").await;
    let step = rig.step(&started.rotation, confirm);
    assert_eq!(
        rig.call(Request::AgentRotateConfirm { step: step.clone() })
            .await
            .expect("confirm"),
        json!({ "ok": true })
    );
    assert_eq!(password(person), first);
    let after = history(person);
    assert_eq!(after["pending"], false, "{after}");
    assert_eq!(after["entries"][0]["unconfirmed"], Value::Null, "{after}");
    // The same signed request again: refused.
    let replay = rig
        .call(Request::AgentRotateConfirm { step })
        .await
        .expect_err("replayed");
    assert_eq!(replay.code, ErrorCode::Denied, "{}", replay.message);

    // --- 2. A tampered request, and a page on another host: nothing. --------
    let (started, proof) = rig.start("rotate again").await;
    let mut forged = proof.clone();
    forged.timestamp_ms += 1;
    let tab = rig.tab(&mut ext, SITE).await;
    let refused = rig
        .begin(tab.clone(), rig.step(&started.rotation, forged))
        .await
        .expect("join")
        .expect_err("tampered");
    assert_eq!(refused.code, ErrorCode::Security, "{}", refused.message);
    let begin = rig.begin(tab, rig.step(&started.rotation, proof));
    ext.answer("rotate_probe", |_| {
        target("https://bank.example.com.evil.io/password", true, json!({}))
    })
    .await;
    let refused = begin.await.expect("join").expect_err("another host");
    assert_eq!(refused.code, ErrorCode::Denied, "{}", refused.message);
    assert_eq!(history(person)["pending"], false);
    assert_eq!(password(person), first);
    // The agent closes that change with the server; klavd has nothing
    // pending for it.
    let cancel = rig.finish(&started.rotation, "cancel").await;
    let none = rig
        .call(Request::AgentRotateCancel {
            step: rig.step(&started.rotation, cancel),
        })
        .await
        .expect_err("nothing pending");
    assert_eq!(none.code, ErrorCode::NotFound, "{}", none.message);

    // --- 3. The site refuses the new one: cancel keeps the current. ---------
    let (started, proof) = rig.start("rotate once more").await;
    let tab = rig.tab(&mut ext, SITE).await;
    let begin = rig.begin(tab, rig.step(&started.rotation, proof));
    ext.answer("rotate_probe", |_| target(SITE, false, json!({})))
        .await;
    let fill = ext.answer("rotate_fill", |_| filled()).await;
    assert_eq!(fill["current"], first);
    let second = fill["new"].as_str().expect("new").to_owned();
    assert_eq!(second.chars().count(), 20, "random, 20 characters");
    let (answer, warnings) = begin.await.expect("join").expect("begin");
    assert_eq!(answer["pending_id"], json!(started.rotation.id));
    assert!(warnings.iter().any(|w| w.contains("focus")), "{warnings:?}");
    let cancel = rig.finish(&started.rotation, "cancel").await;
    rig.call(Request::AgentRotateCancel {
        step: rig.step(&started.rotation, cancel),
    })
    .await
    .expect("cancel");
    assert_eq!(password(person), first);
    let after = history(person);
    assert_eq!(after["pending"], false, "{after}");
    assert_eq!(after["entries"][0]["unconfirmed"], true, "{after}");
    let kept = person
        .run(&["item", "history", "Bank", "--reveal", "0"], "")
        .ok();
    assert!(kept.stdout.contains(&second), "the refused one is kept");

    // --- 4. The person resolves a pending change from the card. -------------
    let (started, proof) = rig.start("one last time").await;
    let tab = rig.tab(&mut ext, SITE).await;
    let begin = rig.begin(tab, rig.step(&started.rotation, proof));
    ext.answer("rotate_probe", |_| target(SITE, true, json!({})))
        .await;
    let fill = ext.answer("rotate_fill", |_| filled()).await;
    let third = fill["new"].as_str().expect("new").to_owned();
    begin.await.expect("join").expect("begin");
    let resolved = rig
        .call(Request::ResolvePending {
            query: item.to_string(),
            accept: true,
        })
        .await
        .expect("resolve");
    assert_eq!(resolved["pending"], false);
    assert_eq!(password(person), third);
    // The person's klavd closed the change with the server: the agent's
    // confirm is refused there, and klavd finds nothing to confirm.
    let path = format!("/v1/agent/rotations/{}/confirm", started.rotation.id);
    let body = AgentRotateFinish {
        item_id: rig.item,
        reason: "the site took it".into(),
    };
    let refused = rig
        .agent
        .call_proved::<_, RotationInfo>(&path, &body)
        .await
        .expect_err("closed by the person");
    assert!(
        matches!(refused, klav_client::ClientError::Api { status: 409, .. }),
        "{refused:?}"
    );
    let confirm = rig.agent.sign_post(&path, &body).expect("sign");
    let late = rig
        .call(Request::AgentRotateConfirm {
            step: rig.step(&started.rotation, confirm),
        })
        .await
        .expect_err("already resolved");
    assert_eq!(late.code, ErrorCode::NotFound, "{}", late.message);

    // --- 5. Paused: klavd neither starts nor confirms a change. -------------
    let (started, proof) = rig.start("before the pause").await;
    let tab = rig.tab(&mut ext, SITE).await;
    let begin = rig.begin(tab.clone(), rig.step(&started.rotation, proof));
    ext.answer("rotate_probe", |_| target(SITE, true, json!({})))
        .await;
    ext.answer("rotate_fill", |_| filled()).await;
    begin.await.expect("join").expect("begin");
    // The agent told the server before the pause; klavd hears after it.
    let confirm = rig.finish(&started.rotation, "confirm").await;
    rig.call(Request::PauseAgents {
        agent: Some(rig.agent.id()),
        until: None,
    })
    .await
    .expect("pause");
    let paused = rig
        .call(Request::AgentRotateConfirm {
            step: rig.step(&started.rotation, confirm.clone()),
        })
        .await
        .expect_err("paused");
    assert_eq!(paused.code, ErrorCode::AgentsPaused, "{}", paused.message);
    // The new one stays pending, for the person to decide from the card.
    assert_eq!(password(person), third);
    assert_eq!(history(person)["pending"], true);
    let paused = rig
        .begin(tab, rig.step(&started.rotation, confirm))
        .await
        .expect("join")
        .expect_err("paused");
    assert_eq!(paused.code, ErrorCode::AgentsPaused, "{}", paused.message);
    person.run(&["log", "verify"], "").ok();
}

/// Starts the person's `klavd` again with the presence gate on (ADR 0041,
/// layer 4) and Touch ID off, and unlocks it with the master password.
async fn gated_klavd(w: &World) -> common::Klavd {
    w.person.run(&["lock", "--stop"], "").ok();
    let socket = w.person.home.join("klavd.sock");
    assert!(common::wait_until(30, || !socket.exists()), "klavd stopped");
    let klavd = common::Klavd::start(&w.person, w.root.path(), true);
    unlock(&Home::at(&w.person.home)).await;
    klavd
}

async fn unlock(home: &Home) {
    let mut client = DaemonClient::connect(home).await.expect("klavd");
    let unlock: Request =
        serde_json::from_value(json!({ "op": "unlock", "password": common::PASSWORD }))
            .expect("unlock");
    client.call::<Value>(unlock).await.expect("unlocked");
}

#[tokio::test(flavor = "multi_thread")]
async fn with_the_gate_the_browser_asks_before_a_password_change_fills() {
    let w = world();
    let person = &w.person;
    let _stop = StopDaemon(person);
    let (task, item) = w.rotate_task();
    let _klavd = gated_klavd(&w).await;
    let home = Home::at(&person.home);
    let rig = Rig {
        agent: Agent::load(&Home::at(&w.agent_device.home), "bot").expect("agent"),
        item,
        task: task.parse().expect("task id"),
        home: home.clone(),
    };
    let mut ext = FakeExtension::attach(&home).await;

    // The probe finds the form; before the fill, the connection asks,
    // naming the agent and the title from the vault.
    let (started, proof) = rig.start("rotate the reused password").await;
    let tab = rig.tab(&mut ext, SITE).await;
    let begin = rig.begin(tab, rig.step(&started.rotation, proof));
    ext.answer("rotate_probe", |_| target(SITE, true, json!({})))
        .await;
    let line = ext.line().await;
    let presence = line["event"].clone();
    assert_eq!(presence["kind"], "presence", "{line}");
    let ask = &presence["presence"];
    assert_eq!(ask["lasts"], "until_lock", "{presence}");
    assert_eq!(ask["browser"]["event"], "password_change", "{presence}");
    assert_eq!(ask["browser"]["agent"], "bot", "{presence}");
    assert_eq!(ask["browser"]["title"], "Bank", "{presence}");
    assert_eq!(ask["browser"].get("site"), None, "{presence}");
    ext.send(json!({
        "op": "extension_presence",
        "event": presence["id"],
        "password": common::PASSWORD,
    }))
    .await;
    let ack = ext.line().await;
    assert!(ack.get("ok").is_some(), "{ack}");
    let fill = ext.answer("rotate_fill", |_| filled()).await;
    assert_eq!(fill["current"], OLD);
    let (answer, _) = begin.await.expect("join").expect("begin");
    assert_eq!(answer["pending_id"], json!(started.rotation.id));

    // Locked and unlocked again: the next fill asks again, and a cancel
    // fills nothing.
    rig.call(Request::Lock).await.expect("lock");
    unlock(&home).await;
    let cancel = rig.finish(&started.rotation, "cancel").await;
    rig.call(Request::AgentRotateCancel {
        step: rig.step(&started.rotation, cancel),
    })
    .await
    .expect("cancel");
    let (started, proof) = rig.start("rotate again").await;
    let tab = rig.tab(&mut ext, SITE).await;

    // A second browser, and both in front: the probe found the form, but
    // nothing is asked or filled while it isn't clear which browser the
    // person is looking at (P25).
    let mut other = FakeExtension::attach(&home).await;
    let begin = rig.begin(tab.clone(), rig.step(&started.rotation, proof));
    ext.answer("rotate_probe", |_| target(SITE, true, json!({})))
        .await;
    // klavd asks the newest connection first.
    for ext in [&mut other, &mut ext] {
        ext.answer(
            "tab",
            |_| json!({ "ok": { "tab_id": 4, "url": SITE, "focused": true } }),
        )
        .await;
    }
    let err = begin.await.expect("join").expect_err("ambiguous");
    assert_eq!(err.code, ErrorCode::BrowserAmbiguous, "{err:?}");
    drop(other);
    // Refused before the new password was stored: nothing is pending.
    let cancel = rig.finish(&started.rotation, "cancel").await;
    let nothing = rig
        .call(Request::AgentRotateCancel {
            step: rig.step(&started.rotation, cancel),
        })
        .await
        .expect_err("nothing pending");
    assert_eq!(nothing.code, ErrorCode::NotFound, "{nothing:?}");
    // The other browser is gone: one connection, no focus rule.
    let (started, proof) = rig.start("rotate once more").await;
    let begin = rig.begin(tab, rig.step(&started.rotation, proof));
    ext.answer("rotate_probe", |_| target(SITE, true, json!({})))
        .await;
    ext.answer(
        "presence",
        |_| json!({ "error": { "code": "denied", "message": "canceled" } }),
    )
    .await;
    let err = begin.await.expect("join").expect_err("declined");
    assert_eq!(err.code, ErrorCode::Denied, "{err:?}");
    assert!(err.message.contains("declined in the browser"), "{err:?}");
}

/// `klav mcp` driven from a blocking thread while the test answers the fake
/// extension.
struct Tools(Option<Mcp>);

impl Tools {
    fn spawn(
        &mut self,
        name: &'static str,
        args: Value,
    ) -> tokio::task::JoinHandle<(Mcp, (String, bool))> {
        let mut mcp = self.0.take().expect("one call at a time");
        tokio::task::spawn_blocking(move || {
            let reply = mcp.tool(name, args);
            (mcp, reply)
        })
    }

    async fn join(
        &mut self,
        call: tokio::task::JoinHandle<(Mcp, (String, bool))>,
    ) -> (String, bool) {
        let (mcp, reply) = call.await.expect("join");
        self.0 = Some(mcp);
        reply
    }

    async fn tool(&mut self, name: &'static str, args: Value) -> (String, bool) {
        let call = self.spawn(name, args);
        self.join(call).await
    }
}

fn tab_on(url: &str) -> impl FnOnce(&Value) -> Value {
    let url = url.to_owned();
    move |_| json!({ "ok": { "tab_id": 4, "url": url, "focused": true } })
}

const BANK: &str = "klav://Personal/General/Bank";
const GAME: &str = "klav://Personal/General/Activision";

#[tokio::test(flavor = "multi_thread")]
async fn the_mcp_tools_change_a_password_and_never_answer_a_value() {
    let w = world();
    let person = &w.person;
    let _stop = StopDaemon(person);
    let (task, _) = w.rotate_task();
    let home = Home::at(&person.home);
    let mut ext = FakeExtension::attach(&home).await;
    let repo = w.root.path().join("repo");
    std::fs::create_dir_all(&repo).expect("repo");
    let log = w.root.path().join("mcp.log");
    let mut mcp = Mcp::start_with(
        &w.agent_device,
        &repo,
        Some(&log),
        &[("KLAV_BROWSER_HOME", person.home.as_path())],
    );
    mcp.initialize();
    let tools = mcp.request("tools/list", json!({}));
    let rotate = tools["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .find(|t| t["name"] == "rotate_password")
        .expect("rotate_password")
        .clone();
    assert_eq!(
        rotate["inputSchema"]["properties"]["target"]["enum"],
        json!(["extension"])
    );
    let mut tools = Tools(Some(mcp));

    // --- The change pages: the site's own, or Klav's bundled list. --------
    let (text, err) = tools
        .tool(
            "change_password_url",
            json!({ "ref": BANK, "reason": "find the bank's change page" }),
        )
        .await;
    assert!(!err, "{text}");
    let page: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(
        page["url"],
        "https://bank.example.com/.well-known/change-password"
    );
    assert_eq!(page["source"], "well_known");

    // --- A new account with a password nobody sees. -----------------------
    let (text, err) = tools
        .tool(
            "create_item",
            json!({
                "type": "login", "title": "Activision", "vault": "Personal", "project": "General",
                "fields": { "username": "ana" }, "urls": ["https://www.activision.com/signup"],
                "generate": true, "reason": "open the game account",
            }),
        )
        .await;
    assert!(!err, "{text}");
    let created: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(created["generated"]["field"], "password");
    assert_eq!(created["generated"]["type"], "smart");
    assert_eq!(
        created["generated"]["rules"]["source"], "bundled",
        "{created}"
    );
    assert_eq!(created["generated"]["site"], "activision.com");
    person.unlocked(&["sync"], "").ok();
    let generated = password_of(person, "Activision");
    assert!(generated.len() >= 8, "a password was sealed in the item");
    // Both at once, or a type the generator does not know: refused.
    let (text, err) = tools
        .tool(
            "create_item",
            json!({ "type": "login", "title": "Other", "vault": "Personal", "project": "General",
                    "fields": { "password": "MARKER-typed" }, "generate": { "type": "pin" }, "reason": "x" }),
        )
        .await;
    assert!(err && text.contains("not both"), "{text}");
    let (text, err) = tools
        .tool(
            "create_item",
            json!({ "type": "login", "title": "Other", "vault": "Personal", "project": "General",
                    "generate": { "type": "strong" }, "reason": "x" }),
        )
        .await;
    assert!(err && text.contains("generator type"), "{text}");
    let (text, err) = tools
        .tool(
            "change_password_url",
            json!({ "ref": GAME, "reason": "find its change page" }),
        )
        .await;
    assert!(!err, "{text}");
    let page: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(page["source"], "bundled");
    assert_eq!(page["domain"], "activision.com");
    assert!(
        page["url"]
            .as_str()
            .is_some_and(|u| u.starts_with("https://"))
    );

    // --- Refused before anything happens. ----------------------------------
    let (text, err) = tools
        .tool(
            "rotate_password",
            json!({ "ref": BANK, "target": "sdk:shop", "reason": "rotate in my browser" }),
        )
        .await;
    assert!(
        err && text.contains("\"extension\"") && text.contains("pass through you"),
        "{text}"
    );
    // No task covers rotate on this item.
    let call = tools.spawn(
        "rotate_password",
        json!({ "ref": GAME, "target": "extension", "reason": "rotate the game password" }),
    );
    ext.answer("tab", tab_on("https://www.activision.com/password"))
        .await;
    let (text, err) = tools.join(call).await;
    assert!(
        err && text.contains("request_task") && text.contains("list_tasks"),
        "{text}"
    );
    // The tab is not on the item's site.
    let call = tools.spawn(
        "rotate_password",
        json!({ "ref": BANK, "target": "extension", "reason": "rotate the bank password" }),
    );
    ext.answer("tab", tab_on("https://bank.example.com.evil.io/password"))
        .await;
    let (text, err) = tools.join(call).await;
    assert!(err && text.contains("phishing"), "{text}");

    // --- 1. rotate_password, then rotate_confirm. ---------------------------
    let call = tools.spawn(
        "rotate_password",
        json!({ "ref": BANK, "target": "extension", "task_id": task, "reason": "rotate the reused password" }),
    );
    ext.answer("tab", tab_on(SITE)).await;
    ext.answer("rotate_probe", |_| {
        target(
            SITE,
            true,
            json!({ "password_rules": "minlength: 24; required: digit;" }),
        )
    })
    .await;
    let fill = ext.answer("rotate_fill", |_| filled()).await;
    assert_eq!(fill["current"], OLD);
    let first = fill["new"].as_str().expect("new").to_owned();
    assert_eq!(first.chars().count(), 24);
    let (text, err) = tools.join(call).await;
    assert!(!err, "{text}");
    let answer: Value = serde_json::from_str(&text).expect("json");
    let pending = answer["pending_id"]
        .as_str()
        .expect("pending_id")
        .to_owned();
    assert_eq!(
        answer,
        json!({ "filled": ["new_password", "confirm_password", "current_password"], "pending_id": pending })
    );
    assert_eq!(password(person), OLD, "nothing changes before confirming");
    let (text, err) = tools
        .tool(
            "rotate_confirm",
            json!({ "ref": BANK, "pending_id": pending, "reason": "the site said it changed" }),
        )
        .await;
    assert!(!err, "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text).expect("json"),
        json!({ "ok": true })
    );
    assert_eq!(password(person), first);
    // Once is enough.
    let (text, err) = tools
        .tool(
            "rotate_confirm",
            json!({ "ref": BANK, "pending_id": pending, "reason": "confirm again" }),
        )
        .await;
    assert!(err, "{text}");

    // --- 2. klavd refuses the page: the change is closed at once. -----------
    let call = tools.spawn(
        "rotate_password",
        json!({ "ref": BANK, "target": "extension", "reason": "rotate again" }),
    );
    ext.answer("tab", tab_on(SITE)).await;
    ext.answer("rotate_probe", |_| {
        target("https://bank.example.com.evil.io/password", true, json!({}))
    })
    .await;
    let (text, err) = tools.join(call).await;
    assert!(err, "{text}");
    assert_eq!(history(person)["pending"], false);

    // --- 2b. With submit too: klavd stored nothing, so nothing reached the
    // page, and the change is closed at once (a cancel later could not tell
    // it from a change settled here). --------------------------------------
    let call = tools.spawn(
        "rotate_password",
        json!({ "ref": BANK, "target": "extension", "submit": true, "reason": "rotate and submit" }),
    );
    ext.answer("tab", tab_on(SITE)).await;
    ext.answer("rotate_probe", |_| {
        target("https://bank.example.com.evil.io/password", true, json!({}))
    })
    .await;
    let (text, err) = tools.join(call).await;
    assert!(
        err && text.contains("nothing was typed: this change (")
            && text.contains(") was cancelled"),
        "{text}"
    );
    assert_eq!(history(person)["pending"], false);

    // --- 3. A new try works (nothing left open); the site refuses it. -------
    let call = tools.spawn(
        "rotate_password",
        json!({ "ref": BANK, "target": "extension", "reason": "rotate once more" }),
    );
    ext.answer("tab", tab_on(SITE)).await;
    ext.answer("rotate_probe", |_| target(SITE, false, json!({})))
        .await;
    let fill = ext.answer("rotate_fill", |_| filled()).await;
    assert_eq!(fill["current"], first);
    let second = fill["new"].as_str().expect("new").to_owned();
    let (text, err) = tools.join(call).await;
    assert!(!err, "{text}");
    let answer: Value = serde_json::from_str(&text).expect("json");
    let pending = answer["pending_id"]
        .as_str()
        .expect("pending_id")
        .to_owned();
    let (text, err) = tools
        .tool(
            "rotate_cancel",
            json!({ "ref": BANK, "pending_id": pending, "reason": "the site said the password is too long" }),
        )
        .await;
    assert!(!err, "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text).expect("json"),
        json!({ "ok": true })
    );
    assert_eq!(password(person), first);
    let after = history(person);
    assert_eq!(after["pending"], false, "{after}");
    assert_eq!(after["entries"][0]["unconfirmed"], true, "{after}");

    // --- The task, as the agent lists it. -----------------------------------
    let (text, err) = tools.tool("list_tasks", json!({})).await;
    assert!(!err, "{text}");
    let tasks: Value = serde_json::from_str(&text).expect("json");
    let listed = tasks["tasks"]
        .as_array()
        .expect("tasks")
        .iter()
        .find(|t| t["task_id"] == task.as_str())
        .expect("the task")
        .clone();
    // `offered` only shows on a task the person offered (ADR 0022 §6).
    assert_eq!(listed.get("offered"), None, "{listed}");
    assert_eq!(listed["access"][0]["permissions"], json!(["rotate"]));

    // --- No answer, error or log line ever held a password. -----------------
    let mut mcp = tools.0.take().expect("idle");
    let said = mcp.seen.join("\n");
    mcp.child.kill().ok();
    mcp.child.wait().ok();
    let logged = std::fs::read_to_string(&log).unwrap_or_default();
    for (what, value) in [
        ("old", OLD),
        ("first", first.as_str()),
        ("second", second.as_str()),
        ("generated", generated.as_str()),
    ] {
        assert!(
            !said.contains(value),
            "the {what} password reached the agent"
        );
        assert!(!logged.contains(value), "the {what} password was logged");
    }
    person.run(&["log", "verify"], "").ok();
}

/// A login with `password` and the given URL (none if empty) and extra
/// secret fields.
fn add_login(person: &Device, title: &str, url: &str, password: &str, totp: Option<&str>) {
    let mut args = vec![
        "item",
        "add",
        "login",
        "--title",
        title,
        "--username",
        "ana",
    ];
    if !url.is_empty() {
        args.extend(["--url", url]);
    }
    args.extend(["--secret-stdin", "password"]);
    let mut input = format!("{password}\n");
    if let Some(totp) = totp {
        args.extend(["--secret-stdin", "totp"]);
        input.push_str(&format!("{totp}\n"));
    }
    person.unlocked(&args, &input).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_person_offers_the_reused_passwords_and_the_agent_changes_them() {
    let w = world();
    let person = &w.person;
    let _stop = StopDaemon(person);
    // Bank (from the world) shares OLD with Shop, Forum (with a one-time
    // code), Games and Notes (no website). Unique has its own password.
    add_login(person, "Shop", "https://shop.example.com/login", OLD, None);
    add_login(
        person,
        "Forum",
        "https://forum.example.org",
        OLD,
        Some("otpauth://totp/Forum:ana?secret=JBSWY3DPEHPK3PXP&issuer=Forum"),
    );
    add_login(person, "Games", "https://games.example.net", OLD, None);
    add_login(person, "Notes", "", OLD, None);
    add_login(
        person,
        "Unique",
        "https://unique.example.com",
        "MARKER-unique-pass-9",
        None,
    );
    person.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();

    // --- What the person sees: the reused logins, with their change pages.
    let preview = person
        .run(&["health", "--fix-with", "bot", "--skip", "Games"], "")
        .err();
    assert!(
        preview.stderr.contains("--yes"),
        "no terminal and no --yes: nothing is offered\n{}",
        preview.stderr
    );
    for title in ["Bank", "Shop", "Forum", "Games", "Notes"] {
        assert!(
            preview.stdout.contains(title),
            "{title}\n{}",
            preview.stdout
        );
    }
    assert!(!preview.stdout.contains("Unique"), "{}", preview.stdout);
    assert!(
        preview
            .stdout
            .contains("https://bank.example.com/.well-known/change-password"),
        "{}",
        preview.stdout
    );
    assert!(
        preview.stdout.contains("it has no website"),
        "{}",
        preview.stdout
    );
    // A login that cannot go in the task cannot be picked.
    let refused = person
        .run(
            &["health", "--fix-with", "bot", "--only", "Notes", "--yes"],
            "",
        )
        .err();
    assert!(refused.stderr.contains("no website"), "{}", refused.stderr);
    assert!(person.run(&["task", "ls", "--json"], "").ok().stdout.trim() == "[]");

    // --- One approval offers the task (password for presence: Touch ID is
    // off in tests).
    let card = json_of(&person.unlocked(
        &[
            "health",
            "--fix-with",
            "bot",
            "--skip",
            "klav://Personal/General/Games",
            "--for",
            "1h",
            "--yes",
            "--json",
        ],
        "",
    ));
    let task = card["id"].as_str().expect("task id").to_owned();
    assert_eq!(card["status"], "approved", "{card}");
    assert_eq!(card["offered"], true, "{card}");
    assert_eq!(card["task"], "Change passwords");
    let titles: Vec<&str> = card["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|r| r["title"].as_str().expect("title"))
        .collect();
    assert_eq!(titles, ["Bank", "Forum", "Shop"], "sorted by site");
    let forum = &card["rows"][1];
    assert_eq!(
        forum["permissions"],
        json!([
            { "permission": "rotate", "checked": true, "asked": false, "added_by_klav": false, "denied_by_policy": false, "no_site": false },
            { "permission": "totp", "checked": true, "asked": false, "added_by_klav": true, "denied_by_policy": false, "no_site": false },
        ]),
        "{forum}"
    );

    // --- The agent finds it with list_tasks: sites, never the reused list.
    let home = Home::at(&person.home);
    let mut ext = FakeExtension::attach(&home).await;
    let repo = w.root.path().join("repo");
    std::fs::create_dir_all(&repo).expect("repo");
    let log = w.root.path().join("mcp.log");
    let mut mcp = Mcp::start_with(
        &w.agent_device,
        &repo,
        Some(&log),
        &[("KLAV_BROWSER_HOME", person.home.as_path())],
    );
    mcp.initialize();
    // No tool tells an agent which passwords repeat (ADR 0022 §6).
    let listed = mcp.request("tools/list", json!({}));
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .map(|t| t["name"].as_str().expect("name"))
        .collect();
    for name in &names {
        assert!(
            !name.contains("health") && !name.contains("reuse") && !name.contains("weak"),
            "{name}"
        );
    }
    let (text, err) = mcp.tool(
        "vault_health",
        json!({ "reason": "which passwords repeat?" }),
    );
    assert!(err, "{text}");
    let mut tools = Tools(Some(mcp));
    let (text, err) = tools.tool("list_tasks", json!({})).await;
    assert!(!err, "{text}");
    let tasks: Value = serde_json::from_str(&text).expect("json");
    let offered = tasks["tasks"]
        .as_array()
        .expect("tasks")
        .iter()
        .find(|t| t["task_id"] == task.as_str())
        .expect("the offered task")
        .clone();
    assert_eq!(offered["offered"], true, "{offered}");
    let refs: Vec<&str> = offered["access"]
        .as_array()
        .expect("access")
        .iter()
        .map(|a| a["ref"].as_str().expect("ref"))
        .collect();
    assert_eq!(
        refs,
        [
            "klav://Personal/General/Bank",
            "klav://Personal/General/Forum",
            "klav://Personal/General/Shop"
        ],
        "{offered}"
    );
    for word in ["Games", "Notes", "Unique", "group", "reuse", "share"] {
        assert!(!text.contains(word), "{word} reached the agent: {text}");
    }

    // --- Bank: changed. -----------------------------------------------------
    let call = tools.spawn(
        "rotate_password",
        json!({ "ref": BANK, "target": "extension", "task_id": task, "reason": "change the bank password" }),
    );
    ext.answer("tab", tab_on(SITE)).await;
    ext.answer("rotate_probe", |_| target(SITE, true, json!({})))
        .await;
    let fill = ext.answer("rotate_fill", |_| filled()).await;
    let bank_new = fill["new"].as_str().expect("new").to_owned();
    let (text, err) = tools.join(call).await;
    assert!(!err, "{text}");
    let pending = serde_json::from_str::<Value>(&text).expect("json")["pending_id"]
        .as_str()
        .expect("pending_id")
        .to_owned();
    let (text, err) = tools
        .tool(
            "rotate_confirm",
            json!({ "ref": BANK, "pending_id": pending, "reason": "the bank said it changed" }),
        )
        .await;
    assert!(!err, "{text}");
    assert_eq!(password(person), bank_new);

    // --- Shop: the site refuses it. ------------------------------------------
    const SHOP: &str = "https://shop.example.com/account/password";
    let call = tools.spawn(
        "rotate_password",
        json!({ "ref": "klav://Personal/General/Shop", "target": "extension", "reason": "change the shop password" }),
    );
    ext.answer("tab", tab_on(SHOP)).await;
    ext.answer("rotate_probe", |_| target(SHOP, true, json!({})))
        .await;
    let fill = ext.answer("rotate_fill", |_| filled()).await;
    let shop_new = fill["new"].as_str().expect("new").to_owned();
    let (text, err) = tools.join(call).await;
    assert!(!err, "{text}");
    let pending = serde_json::from_str::<Value>(&text).expect("json")["pending_id"]
        .as_str()
        .expect("pending_id")
        .to_owned();
    let (text, err) = tools
        .tool(
            "rotate_cancel",
            json!({ "ref": "klav://Personal/General/Shop", "pending_id": pending, "reason": "the shop refused it" }),
        )
        .await;
    assert!(!err, "{text}");
    assert_eq!(password_of(person, "Shop"), OLD);

    // --- Games was left out: the task does not cover it. --------------------
    let call = tools.spawn(
        "rotate_password",
        json!({ "ref": "klav://Personal/General/Games", "target": "extension", "reason": "change it too" }),
    );
    ext.answer("tab", tab_on("https://games.example.net/password"))
        .await;
    let (text, err) = tools.join(call).await;
    assert!(err, "{text}");
    assert_eq!(password_of(person, "Games"), OLD);

    // --- klav log --task: each site changed, pending or failed. --------------
    let summary = json_of(
        &person
            .run(&["log", "--task", &task[..8], "--json"], "")
            .ok(),
    );
    let sites = summary["sites"].as_array().expect("sites");
    let state = |title: &str| {
        sites
            .iter()
            .find(|s| s["title"] == title)
            .unwrap_or_else(|| panic!("{title} in {summary}"))["state"]
            .clone()
    };
    assert_eq!(sites.len(), 3, "{summary}");
    assert_eq!(state("Bank"), "changed");
    assert_eq!(state("Shop"), "failed");
    assert_eq!(state("Forum"), "pending");
    let text = person.run(&["log", "--task", &task[..8]], "").ok().stdout;
    assert!(text.contains("1 changed, 1 pending, 1 failed"), "{text}");
    // The popup reads the same through klavd.
    let progress = Rig {
        agent: Agent::load(&Home::at(&w.agent_device.home), "bot").expect("agent"),
        item: ItemId::from_bytes([0; 16]),
        task: task.parse().expect("task id"),
        home: home.clone(),
    }
    .call(Request::TaskProgress { task: task.clone() })
    .await
    .expect("task_progress");
    assert_eq!(progress["sites"], summary["sites"], "{progress}");

    // --- No answer, error or log line ever held a password. -----------------
    let mut mcp = tools.0.take().expect("idle");
    let said = mcp.seen.join("\n");
    mcp.child.kill().ok();
    mcp.child.wait().ok();
    let logged = std::fs::read_to_string(&log).unwrap_or_default();
    for value in [
        OLD,
        bank_new.as_str(),
        shop_new.as_str(),
        "MARKER-unique-pass-9",
    ] {
        assert!(!said.contains(value), "a password reached the agent");
        assert!(!logged.contains(value), "a password was logged");
    }
    person.run(&["log", "verify"], "").ok();
}

/// Starts a change of Bank through `klav mcp` and the fake extension.
/// Returns the `pending_id` and the new password (as typed into the page).
async fn begin(tools: &mut Tools, ext: &mut FakeExtension, task: &str) -> (String, String) {
    let call = tools.spawn(
        "rotate_password",
        json!({ "ref": BANK, "target": "extension", "task_id": task, "reason": "rotate the bank password" }),
    );
    ext.answer("tab", tab_on(SITE)).await;
    ext.answer("rotate_probe", |_| target(SITE, true, json!({})))
        .await;
    let fill = ext.answer("rotate_fill", |_| filled()).await;
    let new = fill["new"].as_str().expect("new").to_owned();
    let (text, err) = tools.join(call).await;
    assert!(!err, "{text}");
    let answer: Value = serde_json::from_str(&text).expect("json");
    let pending = answer["pending_id"]
        .as_str()
        .expect("pending_id")
        .to_owned();
    (pending, new)
}

/// How many `action` events the log has for the agent `bot`, by the agent
/// (`by_person: false`) or by the person.
fn events(person: &Device, action: &str, by_person: bool) -> usize {
    let lines = json_of(
        &person
            .run(&["log", "--agent", "bot", "-n", "10000", "--json"], "")
            .ok(),
    );
    lines
        .as_array()
        .expect("lines")
        .iter()
        .filter(|l| l["action"] == action && (l["actor"] == "you") == by_person)
        .count()
}

/// The person's choice on the item's card, through their `klavd`.
async fn resolve(home: &Home, accept: bool) {
    let mut daemon = DaemonClient::connect(home).await.expect("klavd");
    daemon
        .call::<Value>(Request::ResolvePending {
            query: "Bank".into(),
            accept,
        })
        .await
        .expect("resolve_pending");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_step_is_recorded_only_while_klavd_holds_its_password() {
    let w = world();
    let person = &w.person;
    let _stop = StopDaemon(person);
    let (task, _) = w.rotate_task();
    let home = Home::at(&person.home);
    let mut ext = FakeExtension::attach(&home).await;
    let repo = w.root.path().join("repo");
    std::fs::create_dir_all(&repo).expect("repo");
    let mut mcp = Mcp::start_with(
        &w.agent_device,
        &repo,
        None,
        &[("KLAV_BROWSER_HOME", person.home.as_path())],
    );
    mcp.initialize();
    let mut tools = Tools(Some(mcp));
    let confirm =
        |pending: &str| json!({ "ref": BANK, "pending_id": pending, "reason": "the site took it" });
    let cancel = |pending: &str| json!({ "ref": BANK, "pending_id": pending, "reason": "the site refused it" });

    // --- klavd locked: the question to klavd fails, so the server records
    // nothing; unlocked, the same confirm goes through and is recorded once.
    let (pending, first) = begin(&mut tools, &mut ext, &task).await;
    person.run(&["lock"], "").ok();
    let (text, err) = tools.tool("rotate_confirm", confirm(&pending)).await;
    assert!(err, "a locked klavd applies nothing: {text}");
    person.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    assert_eq!(events(person, "rotate.confirmed", false), 0);
    assert_eq!(password(person), OLD);
    assert_eq!(history(person)["pending"], true);
    let (text, err) = tools.tool("rotate_confirm", confirm(&pending)).await;
    assert!(!err, "{text}");
    assert_eq!(password(person), first);
    assert_eq!(events(person, "rotate.confirmed", false), 1);

    // --- «Mantener la actual» from the card: the person's klavd closes the
    // change with the server; klavd then holds nothing pending for it, so
    // the agent's confirm and cancel both fail and record nothing. ---------
    let (pending, _) = begin(&mut tools, &mut ext, &task).await;
    resolve(&home, false).await;
    assert_eq!(events(person, "rotate.cancelled", true), 1);
    let (text, err) = tools.tool("rotate_confirm", confirm(&pending)).await;
    assert!(
        err && text.contains("the person may have decided already"),
        "{text}"
    );
    let (text, err) = tools.tool("rotate_cancel", cancel(&pending)).await;
    assert!(
        err && text.contains("no pending password") && text.contains("recorded nothing"),
        "{text}"
    );
    assert_eq!(events(person, "rotate.confirmed", false), 1);
    assert_eq!(events(person, "rotate.cancelled", false), 0);
    assert_eq!(password(person), first);

    // --- «Usar la nueva»: confirmed under the person; the agent's cancel
    // then fails and records nothing. The item is free for another change.
    let (pending, third) = begin(&mut tools, &mut ext, &task).await;
    resolve(&home, true).await;
    assert_eq!(events(person, "rotate.confirmed", true), 1);
    assert_eq!(password(person), third);
    let (text, err) = tools.tool("rotate_cancel", cancel(&pending)).await;
    assert!(err && text.contains("no pending password"), "{text}");
    let (text, err) = tools.tool("rotate_confirm", confirm(&pending)).await;
    assert!(err && text.contains("no pending password"), "{text}");
    assert_eq!(events(person, "rotate.confirmed", false), 1);
    assert_eq!(events(person, "rotate.cancelled", false), 0);

    // --- The task's log: each site as the person left it. ------------------
    let summary = json_of(
        &person
            .run(&["log", "--task", &task[..8], "--json"], "")
            .ok(),
    );
    assert_eq!(summary["sites"][0]["state"], "changed", "{summary}");
    let (pending, _) = begin(&mut tools, &mut ext, &task).await;
    let (text, err) = tools.tool("rotate_cancel", cancel(&pending)).await;
    assert!(!err, "{text}");
    assert_eq!(events(person, "rotate.cancelled", false), 1);
    person.run(&["log", "verify"], "").ok();
}

/// What [`Relay`] does with the next request of one operation.
enum Fault {
    /// Answers `locked`, as a locked `klavd` would, without passing it on.
    Locked,
    /// Closes the connection, as a `klavd` that dies would.
    Close,
    /// Passes the request on and closes the connection instead of handing
    /// back the answer: `klavd` did the work and the agent never hears it.
    DropReply,
}

#[derive(Default)]
struct RelayScript {
    /// Every operation the agent sent, in order.
    ops: Vec<String>,
    /// One fault, for the next request of that operation.
    fault: Option<(String, Fault)>,
    /// Answers `agent_rotate_pending` as a `klavd` older than it does: it
    /// cannot read the request, so `bad_request` with `id` 0.
    older: bool,
    /// The person's choice on the card, made on another connection while
    /// one agent request is on its way: the next request of that operation.
    card: Option<Card>,
    /// The warnings the card's choice got.
    card_warnings: Vec<String>,
}

/// The person decides on the card in the middle of an agent's step.
struct Card {
    op: String,
    /// `false`: once `klavd` answered the request, before the agent reads
    /// the answer. `true`: before the request reaches `klavd`.
    before: bool,
    accept: bool,
}

/// The person's `klavd` as the agent reaches it: a socket in its own
/// directory (`KLAV_BROWSER_HOME`) that passes every request on to the
/// real one, except the faults the test asks for. The extension stays on
/// the real socket.
struct Relay {
    dir: std::path::PathBuf,
    script: std::sync::Arc<std::sync::Mutex<RelayScript>>,
    task: tokio::task::JoinHandle<()>,
}

impl Relay {
    fn start(dir: std::path::PathBuf, upstream: std::path::PathBuf) -> Self {
        std::fs::create_dir_all(&dir).expect("relay dir");
        let listener = tokio::net::UnixListener::bind(dir.join("klavd.sock")).expect("relay");
        let script = std::sync::Arc::new(std::sync::Mutex::new(RelayScript::default()));
        let shared = script.clone();
        let task = tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                tokio::spawn(relay(client, upstream.clone(), shared.clone()));
            }
        });
        Self { dir, script, task }
    }

    fn fail_next(&self, op: &str, fault: Fault) {
        self.script.lock().expect("script").fault = Some((op.to_owned(), fault));
    }

    fn card(&self, op: &str, before: bool, accept: bool) {
        self.script.lock().expect("script").card = Some(Card {
            op: op.to_owned(),
            before,
            accept,
        });
    }

    fn card_warnings(&self) -> Vec<String> {
        std::mem::take(&mut self.script.lock().expect("script").card_warnings)
    }

    fn older(&self, older: bool) {
        self.script.lock().expect("script").older = older;
    }

    /// The operations sent since the last call.
    fn take_ops(&self) -> Vec<String> {
        std::mem::take(&mut self.script.lock().expect("script").ops)
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn relay(
    client: UnixStream,
    upstream: std::path::PathBuf,
    script: std::sync::Arc<std::sync::Mutex<RelayScript>>,
) {
    let Ok(up) = UnixStream::connect(&upstream).await else {
        return;
    };
    let (from_agent, mut to_agent) = client.into_split();
    let mut from_agent = BufReader::new(from_agent);
    let (from_klavd, mut to_klavd) = up.into_split();
    let mut from_klavd = BufReader::new(from_klavd);
    loop {
        let mut line = String::new();
        if from_agent.read_line(&mut line).await.unwrap_or(0) == 0 {
            return;
        }
        let request: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
        let op = request["request"]["op"].as_str().unwrap_or("").to_owned();
        let card = {
            let mut s = script.lock().expect("script");
            match s.card.take() {
                Some(c) if c.op == op => Some(c),
                other => {
                    s.card = other;
                    None
                }
            }
        };
        let decide = |accept: bool| {
            let upstream = upstream.clone();
            let script = script.clone();
            async move {
                let mut daemon = DaemonClient::connect_path(&upstream).await.expect("klavd");
                let (_, warnings) = daemon
                    .call::<Value>(Request::ResolvePending {
                        query: "Bank".into(),
                        accept,
                    })
                    .await
                    .expect("the card");
                script.lock().expect("script").card_warnings = warnings;
            }
        };
        if let Some(Card {
            before: true,
            accept,
            ..
        }) = card
        {
            decide(accept).await;
        }
        let fake = {
            let mut s = script.lock().expect("script");
            s.ops.push(op.clone());
            if s.older && op == "agent_rotate_pending" {
                Some(json!({ "v": 1, "id": 0,
                    "error": { "code": "bad_request", "message": "malformed request" } }))
            } else if s
                .fault
                .as_ref()
                .is_some_and(|(o, f)| *o == op && !matches!(f, Fault::DropReply))
            {
                match s.fault.take() {
                    Some((_, Fault::Close)) => return,
                    _ => Some(json!({ "v": 1, "id": request["id"],
                        "error": { "code": "locked", "message": "klavd is locked" } })),
                }
            } else {
                None
            }
        };
        let reply = match fake {
            Some(reply) => format!("{reply}\n"),
            None => {
                if to_klavd.write_all(line.as_bytes()).await.is_err() {
                    return;
                }
                let mut reply = String::new();
                if from_klavd.read_line(&mut reply).await.unwrap_or(0) == 0 {
                    return;
                }
                let drop_reply = {
                    let mut s = script.lock().expect("script");
                    let drop = s
                        .fault
                        .as_ref()
                        .is_some_and(|(o, f)| *o == op && matches!(f, Fault::DropReply));
                    if drop {
                        s.fault = None;
                    }
                    drop
                };
                if drop_reply {
                    return;
                }
                if let Some(Card {
                    before: false,
                    accept,
                    ..
                }) = card
                {
                    decide(accept).await;
                }
                reply
            }
        };
        if to_agent.write_all(reply.as_bytes()).await.is_err() {
            return;
        }
    }
}

/// Makes the server refuse to log the agent's `action` (or lets it again):
/// with the server stopped, a trigger on its `audit_events`, then the same
/// server on the same port. The step's event fails as it is logged.
async fn refuse_event(server: &mut ServerProcess, action: &str, refuse: bool) {
    assert!(action == "rotate.confirmed" || action == "rotate.cancelled");
    server.stop();
    let url = format!("sqlite://{}", server.dir.path().join("klav.db").display());
    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("open server db");
    let name = format!("klav_test_refuse_{}", action.replace('.', "_"));
    // `action` is one of two fixed names, so it is safe to interpolate.
    let sql = if refuse {
        format!(
            "CREATE TRIGGER {name} BEFORE INSERT ON audit_events \
             WHEN NEW.action = '{action}' \
             BEGIN SELECT RAISE(ABORT, 'test: append refused'); END"
        )
    } else {
        format!("DROP TRIGGER {name}")
    };
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .execute(&pool)
        .await
        .expect("test trigger");
    pool.close().await;
    server.restart();
}

/// Whether Bank's current password is `value` (compared here, so a failed
/// test never prints a password).
fn current_is(person: &Device, value: &str) -> bool {
    password(person) == value
}

#[tokio::test(flavor = "multi_thread")]
async fn the_server_records_a_step_before_klavd_applies_it() {
    let mut w = world();
    let person = &w.person;
    let _stop = StopDaemon(person);
    let (task, item) = w.rotate_task();
    let home = Home::at(&person.home);
    let mut ext = FakeExtension::attach(&home).await;
    let relay = Relay::start(w.root.path().join("relay"), home.socket_path());
    let repo = w.root.path().join("repo");
    std::fs::create_dir_all(&repo).expect("repo");
    let mut mcp = Mcp::start_with(
        &w.agent_device,
        &repo,
        None,
        &[("KLAV_BROWSER_HOME", relay.dir.as_path())],
    );
    mcp.initialize();
    let mut tools = Tools(Some(mcp));
    let confirm =
        |pending: &str| json!({ "ref": BANK, "pending_id": pending, "reason": "the site took it" });
    let cancel = |pending: &str| json!({ "ref": BANK, "pending_id": pending, "reason": "the site refused it" });
    let agent = |action: &str| events(person, action, false);

    // --- The server refuses the step as its event is logged: klavd is not
    // asked, the new password stays pending, and a retry or the card still
    // closes the change. (In the old order klavd moved it first.) ----------
    let (pending, _) = begin(&mut tools, &mut ext, &task).await;
    refuse_event(&mut w.server, "rotate.cancelled", true).await;
    relay.take_ops();
    let (text, err) = tools.tool("rotate_cancel", cancel(&pending)).await;
    assert!(err, "the server refused it: {text}");
    assert!(!relay.take_ops().contains(&"agent_rotate_cancel".to_owned()));
    assert_eq!(history(person)["pending"], true);
    assert!(current_is(person, OLD));
    assert_eq!(agent("rotate.cancelled"), 0);
    refuse_event(&mut w.server, "rotate.cancelled", false).await;
    let (text, err) = tools.tool("rotate_cancel", cancel(&pending)).await;
    assert!(!err, "{text}");
    let after = history(person);
    assert_eq!(after["pending"], false, "{after}");
    assert_eq!(after["entries"][0]["unconfirmed"], true, "{after}");
    assert_eq!(agent("rotate.cancelled"), 1);

    let (pending, first) = begin(&mut tools, &mut ext, &task).await;
    refuse_event(&mut w.server, "rotate.confirmed", true).await;
    let (text, err) = tools.tool("rotate_confirm", confirm(&pending)).await;
    assert!(err, "the server refused it: {text}");
    assert_eq!(history(person)["pending"], true);
    assert!(current_is(person, OLD));
    refuse_event(&mut w.server, "rotate.confirmed", false).await;
    resolve(&home, true).await;
    assert!(current_is(person, &first), "the card still works");
    assert_eq!(events(person, "rotate.confirmed", true), 1);
    assert_eq!(agent("rotate.confirmed"), 0);

    // --- 3. The server records a confirm, then klavd fails: the agent is
    // told the item and the log disagree. (b) A cancel then stops at the
    // server's 409 and never reaches klavd. (a) Confirming again finishes
    // it: the 409 «already confirmed» goes on to klavd. --------------------
    let (pending, second) = begin(&mut tools, &mut ext, &task).await;
    // The question to klavd is signed for a path the server has no route
    // for: sent there, it proves no step and logs nothing.
    let rig = Rig {
        agent: Agent::load(&Home::at(&w.agent_device.home), "bot").expect("agent"),
        item,
        task: task.parse().expect("task id"),
        home: home.clone(),
    };
    let rotation: klav_core::ids::RotationId = pending.parse().expect("pending_id");
    let question = rig
        .agent
        .sign_post(
            &format!("/v1/agent/rotations/{rotation}/pending"),
            &AgentRotateFinish {
                item_id: item,
                reason: "is this change pending here?".into(),
            },
        )
        .expect("sign");
    let logged = || {
        json_of(&person.run(&["log", "-n", "10000", "--json"], "").ok())
            .as_array()
            .expect("lines")
            .len()
    };
    let before = logged();
    let sent = rig.agent.send_proved::<Value>(&question).await;
    assert!(
        matches!(sent, Err(klav_client::ClientError::Api { status: 404, .. })),
        "{sent:?}"
    );
    assert_eq!(logged(), before);

    relay.fail_next("agent_rotate_confirm", Fault::Locked);
    let (text, err) = tools.tool("rotate_confirm", confirm(&pending)).await;
    assert!(
        err && text.contains("the item and the log disagree")
            && text.contains("rotate_confirm again"),
        "{text}"
    );
    assert_eq!(agent("rotate.confirmed"), 1);
    assert_eq!(history(person)["pending"], true);
    assert!(current_is(person, &first));
    relay.take_ops();
    let (text, err) = tools.tool("rotate_cancel", cancel(&pending)).await;
    assert!(
        err && text.contains("already confirmed") && text.contains("klavd was not asked"),
        "{text}"
    );
    assert!(!relay.take_ops().contains(&"agent_rotate_cancel".to_owned()));
    assert_eq!(history(person)["pending"], true);
    assert_eq!(agent("rotate.cancelled"), 1);
    let (text, err) = tools.tool("rotate_confirm", confirm(&pending)).await;
    assert!(!err, "{text}");
    assert!(
        relay
            .take_ops()
            .contains(&"agent_rotate_confirm".to_owned())
    );
    assert!(current_is(person, &second), "the retry applied it");
    assert_eq!(history(person)["pending"], false);
    assert_eq!(agent("rotate.confirmed"), 1, "the retry logs nothing more");

    // --- 4. The same for a cancel, with klavd dying on it: a confirm then
    // stops at «already cancelled»; cancelling again finishes it. ----------
    let (pending, _) = begin(&mut tools, &mut ext, &task).await;
    relay.fail_next("agent_rotate_cancel", Fault::Close);
    let (text, err) = tools.tool("rotate_cancel", cancel(&pending)).await;
    assert!(
        err && text.contains("the item and the log disagree"),
        "{text}"
    );
    assert_eq!(agent("rotate.cancelled"), 2);
    assert_eq!(history(person)["pending"], true);
    relay.take_ops();
    let (text, err) = tools.tool("rotate_confirm", confirm(&pending)).await;
    assert!(
        err && text.contains("already cancelled") && text.contains("klavd was not asked"),
        "{text}"
    );
    assert!(
        !relay
            .take_ops()
            .contains(&"agent_rotate_confirm".to_owned())
    );
    assert_eq!(history(person)["pending"], true);
    let (text, err) = tools.tool("rotate_cancel", cancel(&pending)).await;
    assert!(!err, "{text}");
    let after = history(person);
    assert_eq!(after["pending"], false, "{after}");
    assert_eq!(after["entries"][0]["unconfirmed"], true, "{after}");
    assert!(current_is(person, &second));
    assert_eq!(agent("rotate.cancelled"), 2);
    assert_eq!(agent("rotate.confirmed"), 1);

    // --- 3c. The log says confirmed and klavd did not apply it; the person
    // keeps the current one on the card: klavd warns that they disagree.
    let (pending, _) = begin(&mut tools, &mut ext, &task).await;
    relay.fail_next("agent_rotate_confirm", Fault::Locked);
    let (text, err) = tools.tool("rotate_confirm", confirm(&pending)).await;
    assert!(err, "{text}");
    let mut daemon = DaemonClient::connect(&home).await.expect("klavd");
    let (_, warnings) = daemon
        .call::<Value>(Request::ResolvePending {
            query: "Bank".into(),
            accept: false,
        })
        .await
        .expect("resolve_pending");
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("the log says confirmed")),
        "{warnings:?}"
    );
    assert!(current_is(person, &second));
    assert_eq!(history(person)["entries"][0]["unconfirmed"], true);
    let (text, err) = tools.tool("rotate_confirm", confirm(&pending)).await;
    assert!(err && text.contains("no pending password"), "{text}");
    assert_eq!(agent("rotate.confirmed"), 2);

    // --- 5a. The person decides on the card while the agent's step is on
    // its way: after klavd said «pending», before the server gets the step.
    // The same outcome: the server's 409 goes on to klavd, which has
    // nothing pending any more, and the agent is told the person decided.
    let (pending, used) = begin(&mut tools, &mut ext, &task).await;
    relay.card("agent_rotate_pending", false, true);
    let (text, err) = tools.tool("rotate_confirm", confirm(&pending)).await;
    assert!(
        err && text.contains("the person decided from the item's card meanwhile"),
        "{text}"
    );
    assert!(current_is(person, &used));
    assert_eq!(history(person)["pending"], false);
    assert_eq!(events(person, "rotate.confirmed", true), 2);
    assert_eq!(agent("rotate.confirmed"), 2);
    // The other outcome: the server's 409 stops it, and klavd is not asked.
    let (pending, _) = begin(&mut tools, &mut ext, &task).await;
    relay.card("agent_rotate_pending", false, false);
    relay.take_ops();
    let (text, err) = tools.tool("rotate_confirm", confirm(&pending)).await;
    assert!(
        err && text.contains("already cancelled") && text.contains("klavd was not asked"),
        "{text}"
    );
    assert!(
        !relay
            .take_ops()
            .contains(&"agent_rotate_confirm".to_owned())
    );
    assert!(current_is(person, &used));
    assert_eq!(history(person)["entries"][0]["unconfirmed"], true);
    assert_eq!(agent("rotate.confirmed"), 2);

    // --- 5b. The server records the agent's confirm, and the person keeps
    // the current one before klavd gets it: the card warns, and the agent
    // is told the item and the log disagree. --------------------------------
    let (pending, _) = begin(&mut tools, &mut ext, &task).await;
    relay.card("agent_rotate_confirm", true, false);
    let (text, err) = tools.tool("rotate_confirm", confirm(&pending)).await;
    assert!(
        err && text.contains("If the person kept the current one, the item and the log disagree"),
        "{text}"
    );
    let warnings = relay.card_warnings();
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("the log says confirmed")),
        "{warnings:?}"
    );
    assert!(current_is(person, &used));
    assert_eq!(history(person)["pending"], false);
    assert_eq!(agent("rotate.confirmed"), 3);

    // --- 8a. An older klavd, without the question: the step goes to the
    // server and then to klavd, as the question had said «pending». -------
    relay.older(true);
    let (pending, third) = begin(&mut tools, &mut ext, &task).await;
    relay.take_ops();
    let (text, err) = tools.tool("rotate_confirm", confirm(&pending)).await;
    assert!(!err, "{text}");
    let ops = relay.take_ops();
    assert!(
        ops.contains(&"agent_rotate_pending".to_owned())
            && ops.contains(&"agent_rotate_confirm".to_owned()),
        "{ops:?}"
    );
    assert!(current_is(person, &third));
    assert_eq!(agent("rotate.confirmed"), 4);
    relay.older(false);

    // --- 6. klavd refuses the page before storing anything: the runtime
    // cancels the change with the server at once, and the item is free. ----
    let call = tools.spawn(
        "rotate_password",
        json!({ "ref": BANK, "target": "extension", "task_id": task, "reason": "rotate the bank password" }),
    );
    ext.answer("tab", tab_on(SITE)).await;
    ext.answer("rotate_probe", |_| {
        target("https://bank.example.com.evil.io/password", true, json!({}))
    })
    .await;
    let (text, err) = tools.join(call).await;
    assert!(err && text.contains(") was cancelled"), "{text}");
    assert_eq!(agent("rotate.cancelled"), 3, "the server closed it");
    assert_eq!(history(person)["pending"], false);
    assert!(current_is(person, &third));

    // --- 8b. An older SDK, klavd first and then the server with the same
    // request: this klavd still takes it. --------------------------------
    let (started, proof) = rig.start("an older SDK").await;
    let tab = rig.tab(&mut ext, SITE).await;
    let begun = rig.begin(tab, rig.step(&started.rotation, proof));
    ext.answer("rotate_probe", |_| target(SITE, true, json!({})))
        .await;
    let fill = ext.answer("rotate_fill", |_| filled()).await;
    let fourth = fill["new"].as_str().expect("new").to_owned();
    begun.await.expect("join").expect("begin");
    let path = format!("/v1/agent/rotations/{}/confirm", started.rotation.id);
    let body = AgentRotateFinish {
        item_id: item,
        reason: "the site took it".into(),
    };
    let request = rig.agent.sign_post(&path, &body).expect("sign");
    rig.call(Request::AgentRotateConfirm {
        step: rig.step(&started.rotation, request.clone()),
    })
    .await
    .expect("klavd first");
    let info: RotationInfo = rig
        .agent
        .send_proved(&request)
        .await
        .expect("then the server");
    assert_eq!(info.status, RotationStatus::Confirmed);
    assert!(current_is(person, &fourth));
    assert_eq!(agent("rotate.confirmed"), 5);

    // --- 7. A change an older SDK left stranded: klavd applied the confirm
    // and the server never got it. This SDK records neither step over it.
    let (started, proof) = rig.start("stranded by an older SDK").await;
    let tab = rig.tab(&mut ext, SITE).await;
    let begun = rig.begin(tab, rig.step(&started.rotation, proof));
    ext.answer("rotate_probe", |_| target(SITE, true, json!({})))
        .await;
    let fill = ext.answer("rotate_fill", |_| filled()).await;
    let fifth = fill["new"].as_str().expect("new").to_owned();
    begun.await.expect("join").expect("begin");
    let request = rig
        .agent
        .sign_post(
            &format!("/v1/agent/rotations/{}/confirm", started.rotation.id),
            &body,
        )
        .expect("sign");
    rig.call(Request::AgentRotateConfirm {
        step: rig.step(&started.rotation, request),
    })
    .await
    .expect("klavd applies");
    assert!(current_is(person, &fifth));
    let stranded = started.rotation.id.to_string();
    let (text, err) = tools.tool("rotate_cancel", cancel(&stranded)).await;
    assert!(
        err && text.contains("no pending password") && text.contains("recorded nothing"),
        "{text}"
    );
    let (text, err) = tools.tool("rotate_confirm", confirm(&stranded)).await;
    assert!(err && text.contains("no pending password"), "{text}");
    assert_eq!(agent("rotate.cancelled"), 3);
    assert_eq!(agent("rotate.confirmed"), 5);
    assert!(current_is(person, &fifth));
    person.run(&["log", "verify"], "").ok();
}

/// Whatever the agent was told carries the change's `pending_id` after
/// `pending_id `.
fn pending_id_in(text: &str) -> String {
    let at = text.find("pending_id ").expect("a pending_id") + "pending_id ".len();
    text[at..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit() || *c == '-')
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_step_whose_answer_is_lost_and_a_change_that_cannot_close() {
    let mut w = world();
    let person = &w.person;
    let _stop = StopDaemon(person);
    let (task, _) = w.rotate_task();
    let home = Home::at(&person.home);
    let mut ext = FakeExtension::attach(&home).await;
    let relay = Relay::start(w.root.path().join("relay"), home.socket_path());
    let repo = w.root.path().join("repo");
    std::fs::create_dir_all(&repo).expect("repo");
    let mut mcp = Mcp::start_with(
        &w.agent_device,
        &repo,
        None,
        &[("KLAV_BROWSER_HOME", relay.dir.as_path())],
    );
    mcp.initialize();
    let mut tools = Tools(Some(mcp));
    let confirm =
        |pending: &str| json!({ "ref": BANK, "pending_id": pending, "reason": "the site took it" });
    let cancel = |pending: &str| json!({ "ref": BANK, "pending_id": pending, "reason": "the site refused it" });
    let agent = |action: &str| events(person, action, false);
    let rotate = |task: &str| json!({ "ref": BANK, "target": "extension", "task_id": task, "reason": "rotate the bank password" });

    // --- 6″. Filling fails after klavd stored the new password: the
    // runtime cancels the change, so klavd's «cancel the change» hint is
    // replaced by the fact. -------------------------------------------------
    let call = tools.spawn("rotate_password", rotate(&task));
    ext.answer("tab", tab_on(SITE)).await;
    ext.answer("rotate_probe", |_| target(SITE, true, json!({})))
        .await;
    ext.answer(
        "rotate_fill",
        |_| json!({ "error": { "code": "invalid", "message": "the form went away" } }),
    )
    .await;
    let (text, err) = tools.join(call).await;
    assert!(
        err && text.contains("the form went away") && text.contains(") was cancelled"),
        "{text}"
    );
    assert!(!text.contains("kept as pending"), "{text}");
    let after = history(person);
    assert_eq!(after["pending"], false, "{after}");
    assert_eq!(after["entries"][0]["unconfirmed"], true, "{after}");
    assert!(current_is(person, OLD));
    assert_eq!(agent("rotate.cancelled"), 1);

    // --- 3′. klavd applies the confirm and its answer is lost: the agent is
    // told klavd may have applied it; the retry then finds nothing pending
    // and records nothing. --------------------------------------------------
    let (pending, first) = begin(&mut tools, &mut ext, &task).await;
    relay.fail_next("agent_rotate_confirm", Fault::DropReply);
    let (text, err) = tools.tool("rotate_confirm", confirm(&pending)).await;
    assert!(
        err && text.contains("klavd did not say it applied it")
            && text.contains("rotate_confirm again"),
        "{text}"
    );
    assert!(current_is(person, &first), "klavd applied it");
    assert_eq!(history(person)["pending"], false);
    assert_eq!(agent("rotate.confirmed"), 1);
    let (text, err) = tools.tool("rotate_confirm", confirm(&pending)).await;
    assert!(
        err && text.contains("no pending password")
            && text.contains("may have been applied")
            && text.contains("recorded nothing"),
        "{text}"
    );
    assert!(current_is(person, &first));
    assert_eq!(agent("rotate.confirmed"), 1);

    // --- 3″. The server records a confirm that klavd does not apply; the
    // agent then starts a new change of the same item under the same task.
    // klavd refuses it, so the confirmed password is not buried, and the
    // runtime cancels the new change; confirming the first one finishes it.
    let (pending, second) = begin(&mut tools, &mut ext, &task).await;
    relay.fail_next("agent_rotate_confirm", Fault::Locked);
    let (text, err) = tools.tool("rotate_confirm", confirm(&pending)).await;
    assert!(err && text.contains("rotate_confirm again"), "{text}");
    assert_eq!(agent("rotate.confirmed"), 2);
    let call = tools.spawn("rotate_password", rotate(&task));
    ext.answer("tab", tab_on(SITE)).await;
    let (text, err) = tools.join(call).await;
    assert!(
        err && text.contains(&format!("still holds the new password of change {pending}"))
            && text.contains(") was cancelled"),
        "{text}"
    );
    assert_eq!(agent("rotate.started"), 4);
    assert_eq!(agent("rotate.cancelled"), 2, "the new change is closed");
    assert_eq!(history(person)["pending"], true, "the first one is kept");
    assert!(current_is(person, &first));
    let (text, err) = tools.tool("rotate_confirm", confirm(&pending)).await;
    assert!(!err, "{text}");
    assert!(current_is(person, &second));
    assert_eq!(history(person)["pending"], false);
    assert_eq!(agent("rotate.confirmed"), 2);
    let summary = json_of(
        &person
            .run(&["log", "--task", &task[..8], "--json"], "")
            .ok(),
    );
    assert_eq!(summary["sites"][0]["state"], "changed", "{summary}");

    // --- 6‴. The person chooses «Use the new one» on the card while klavd
    // is filling, and then the fill fails: the server has the change
    // confirmed already, so the automatic cancel's 409 «already confirmed»
    // leaves nothing to cancel, and the agent is not told it stays open. --
    let by_person = events(person, "rotate.confirmed", true);
    let call = tools.spawn("rotate_password", rotate(&task));
    ext.answer("tab", tab_on(SITE)).await;
    ext.answer("rotate_probe", |_| target(SITE, true, json!({})))
        .await;
    let line = ext.line().await;
    let fill = line["event"].clone();
    assert_eq!(fill["kind"], "rotate_fill", "{line}");
    let chosen = fill["new"].as_str().expect("new").to_owned();
    resolve(&home, true).await;
    assert_eq!(events(person, "rotate.confirmed", true), by_person + 1);
    ext.send(json!({
        "op": "extension_reply",
        "event": fill["id"].as_u64().expect("event id"),
        "error": { "code": "invalid", "message": "the form went away" },
    }))
    .await;
    let ack = ext.line().await;
    assert!(ack.get("ok").is_some(), "{ack}");
    let (text, err) = tools.join(call).await;
    assert!(
        err && text.contains("the form went away")
            && text.contains("nothing left to cancel")
            && text.contains("already confirmed"),
        "{text}"
    );
    for wrong in ["stays open", "end_task", "kept as pending"] {
        assert!(!text.contains(wrong), "{wrong}: {text}");
    }
    assert!(current_is(person, &chosen), "the person's choice holds");
    assert_eq!(history(person)["pending"], false);
    assert_eq!(agent("rotate.cancelled"), 2, "the cancel was not recorded");

    // --- 6′. klavd dies during the begin and the automatic cancel is
    // refused: the agent is told the change is still open, with its
    // pending_id; its rotate_cancel records nothing (klavd holds nothing
    // pending), the item is busy, and ending the task frees it. -----------
    refuse_event(&mut w.server, "rotate.cancelled", true).await;
    relay.fail_next("agent_rotate_begin", Fault::Close);
    let call = tools.spawn("rotate_password", rotate(&task));
    ext.answer("tab", tab_on(SITE)).await;
    let (text, err) = tools.join(call).await;
    assert!(
        err && text.contains("could not be cancelled")
            && text.contains("stays open with the server")
            && text.contains("end_task"),
        "{text}"
    );
    assert!(!text.contains(") was cancelled"), "{text}");
    let stuck = pending_id_in(&text);
    refuse_event(&mut w.server, "rotate.cancelled", false).await;
    let (text, err) = tools.tool("rotate_cancel", cancel(&stuck)).await;
    assert!(
        err && text.contains("no pending password") && text.contains("end_task"),
        "{text}"
    );
    assert_eq!(agent("rotate.cancelled"), 2);
    let call = tools.spawn("rotate_password", rotate(&task));
    ext.answer("tab", tab_on(SITE)).await;
    let (text, err) = tools.join(call).await;
    assert!(err && text.contains("already in progress"), "{text}");
    let (text, err) = tools
        .tool(
            "end_task",
            json!({ "task_id": task, "reason": "the change is stuck" }),
        )
        .await;
    assert!(!err, "{text}");
    let (task, _) = w.rotate_task();
    let (pending, _) = begin(&mut tools, &mut ext, &task).await;
    let (text, err) = tools.tool("rotate_cancel", cancel(&pending)).await;
    assert!(!err, "{text}");
    assert!(current_is(person, &chosen));
    person.run(&["log", "verify"], "").ok();
}
