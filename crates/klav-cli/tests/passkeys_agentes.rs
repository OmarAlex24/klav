//! Agents signing in with the person's passkeys (ADR 0020 §9) through
//! `klavd`, with the real server and binaries. An agent with a task that
//! covers `passkey` on a login asks the server (which logs it), hands the
//! person's `klavd` the request it signed, and `klavd` checks it all again
//! on its own before arming one use in the tab (a fake extension on the
//! socket). The extension answers the page's sign-in with that use: `klavd`
//! signs with UV, once, only for that connection, tab, host and login, and
//! logs `passkey.used` with the agent and the task.
//!
//! `klavd` refuses, and arms nothing, a replayed or tampered request, one
//! the server never saw for a login or a host the task does not cover, a
//! host that cannot use the passkey's rpId, another agent's request under
//! this task, and any request while it is locked or once the person asked
//! to delete the account (ADR 0037 §3). Through `klav mcp`,
//! `passkey_sign_in` refuses `sdk:` and other sites before anything else.

mod common;

use std::time::Duration;

use common::mcp::Mcp;
use common::{Device, PASSWORD, ServerProcess};
use klav_client::Home;
use klav_client::agent_passkeys::{ACCESS_PATH, PasskeyArmStep};
use klav_client::ops::SecretText;
use klav_client::passkeys::{PasskeyAssertion, PasskeyCreateOutcome, PasskeyCreateRequest};
use klav_core::ids::{ItemId, TaskId};
use klav_core::policy::Permission;
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{BrowserTab, ErrorBody, ErrorCode, PasskeyArmed, Request};
use klav_proto::Blob;
use klav_proto::agent::{AccessRequest, Claims, PasskeyAccess};
use klav_proto::rotate::AgentRequestProof;
use klav_sdk::agent::Agent;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

const SHOP: &str = "klav://Personal/General/Shop";
const FORUM: &str = "klav://Personal/General/Forum";
/// Shop's confirmed address: the task's domain. Its passkey is for the
/// registrable domain, `shop.example`.
const SHOP_PAGE: &str = "https://login.shop.example/";
const SHOP_HOST: &str = "login.shop.example";
/// UP·UV·BE·BS (ADR 0020 §5).
const FLAGS_UV: u8 = 0x1D;

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
    /// Requests whose answers [`FakeExtension::line`] skips: the master
    /// passwords [`FakeExtension::event`] typed for the presence gate.
    skip: Vec<u64>,
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
            skip: Vec::new(),
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

    /// The next line, past the answers to the master passwords typed for
    /// the presence gate.
    async fn line(&mut self) -> Value {
        loop {
            let mut line = String::new();
            tokio::time::timeout(Duration::from_secs(30), self.reader.read_line(&mut line))
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

    /// The next event, which must be of `kind`. The presence gate's
    /// `presence` event before it, if any, gets the master password, as
    /// the person types it in Klav's frame (ADR 0041 §3.1).
    async fn event(&mut self, kind: &str) -> Value {
        let mut line = self.line().await;
        if kind != "presence" && line["event"]["kind"] == "presence" {
            self.skip.push(self.next);
            self.send(json!({
                "op": "extension_presence",
                "event": line["event"]["id"],
                "password": PASSWORD,
            }))
            .await;
            line = self.line().await;
        }
        let event = line["event"].clone();
        assert_eq!(event["kind"], kind, "expected a {kind} event, got {line}");
        event
    }

    /// Answers event `event`.
    async fn reply(&mut self, event: &Value, mut reply: Value) {
        reply["op"] = json!("extension_reply");
        reply["event"] = event["id"].clone();
        self.send(reply).await;
        let ack = self.line().await;
        assert!(ack.get("ok").is_some(), "{ack}");
    }

    /// Waits for an event of `kind` and answers it with `reply`.
    async fn answer(&mut self, kind: &str, reply: Value) -> Value {
        let event = self.event(kind).await;
        self.reply(&event, reply).await;
        event
    }

    /// `agent_passkey_use` from this connection: the page's sign-in, for
    /// `shop.example` (a page of `login.shop.example` names it as rpId).
    async fn use_passkey(&mut self, origin: &str, token: &str) -> Value {
        self.send(json!({
            "op": "agent_passkey_use",
            "tab_id": 4,
            "origin": origin,
            "rp_id": "shop.example",
            "challenge": Blob::from(&b"0123456789abcdef"[..]).to_text(),
            "token": token,
        }))
        .await;
        self.line().await
    }
}

/// The person with «Shop» and «Forum» (each with a password and a
/// passkey), the agents `bot` and `bot2` with a grant on Personal/General,
/// and their server.
struct World {
    _server: ServerProcess,
    root: tempfile::TempDir,
    person: Device,
    agent_device: Device,
    other_device: Device,
}

fn agent(person: &Device, server: &ServerProcess, device: &Device, name: &str) {
    let words = device
        .run(
            &[
                "agent",
                "register",
                "--name",
                name,
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
                name,
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
}

fn world() -> World {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = Device::new(root.path(), "person");
    person.signup(&server, "ana@example.com");
    for (title, url) in [("Shop", SHOP_PAGE), ("Forum", "https://forum.example/")] {
        person
            .unlocked(
                &[
                    "item",
                    "add",
                    "login",
                    "--title",
                    title,
                    "--username",
                    "ana",
                    "--url",
                    url,
                    "--secret-stdin",
                    "password",
                ],
                "MARKER-not-the-point-1\n",
            )
            .ok();
    }
    let agent_device = Device::new(root.path(), "agent");
    agent(&person, &server, &agent_device, "bot");
    let other_device = Device::new(root.path(), "other");
    agent(&person, &server, &other_device, "bot2");
    person.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    World {
        _server: server,
        root,
        person,
        agent_device,
        other_device,
    }
}

fn item_id(person: &Device, title: &str) -> ItemId {
    json_of(&person.run(&["item", "get", title, "--json"], "").ok())["id"]
        .as_str()
        .expect("id")
        .parse()
        .expect("item id")
}

impl World {
    /// Passkeys in Shop (for `shop.example`) and Forum, through the
    /// person's `klavd`; then a task of `bot` with `passkey` on Shop, only
    /// on `login.shop.example` (saving the passkey added `shop.example` to
    /// its URLs), and only `fill` on Forum, approved.
    async fn setup(&self) -> (TaskId, ItemId, ItemId) {
        let home = Home::at(&self.person.home);
        let mut client = DaemonClient::connect(&home).await.expect("klavd");
        let shop = item_id(&self.person, "Shop");
        let forum = item_id(&self.person, "Forum");
        for (item, origin, rp_id) in [
            (shop, "https://login.shop.example", Some("shop.example")),
            (forum, "https://forum.example", None),
        ] {
            let (created, _): (PasskeyCreateOutcome, _) = client
                .call(Request::PasskeyCreate {
                    request: PasskeyCreateRequest {
                        origin: origin.into(),
                        rp_id: rp_id.map(str::to_owned),
                        user_id: Blob::from(&b"ana-0001"[..]).to_text(),
                        user_name: "ana".into(),
                        challenge: Blob::from(&b"0123456789abcdef"[..]).to_text(),
                        item: Some(item.to_string()),
                        ..PasskeyCreateRequest::default()
                    },
                    password: Some(SecretText::new(PASSWORD)),
                })
                .await
                .expect("create");
            assert!(
                matches!(created, PasskeyCreateOutcome::Created(_)),
                "{created:?}"
            );
        }
        let file = self.root.path().join("tarea.json");
        std::fs::write(
            &file,
            format!(
                r#"{{"task":"Sign in to the shop","reason":"Check the order","duration":"30m",
                "access":[{{"ref":"{SHOP}","permissions":["passkey"],"domain":"{SHOP_HOST}"}},
                          {{"ref":"{FORUM}","permissions":["fill"]}}]}}"#
            ),
        )
        .expect("tarea.json");
        let asked = json_of(&self.agent_device.run(
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
        self.person
            .unlocked(&["task", "approve", &task[..8]], "")
            .ok();
        (task.parse().expect("task id"), shop, forum)
    }
}

/// What the agent asks for: `passkey` on `item` at `host`, under `task`.
fn asked(item: ItemId, host: &str, task: TaskId) -> AccessRequest {
    AccessRequest {
        item_id: item,
        permission: Permission::Passkey,
        reason: "check the order".into(),
        claims: Claims {
            tags: Vec::new(),
            domain: Some(host.into()),
            ..Claims::default()
        },
        approval_id: None,
        task_id: Some(task),
        include_attachments: false,
        sandbox: None,
        local_client: None,
        items: Vec::new(),
    }
}

struct Rig {
    agent: Agent,
    home: Home,
    task: TaskId,
}

type Armed = Result<PasskeyArmed, ErrorBody>;

impl Rig {
    /// The agent's request to the server (it logs it).
    async fn access(
        &self,
        item: ItemId,
        host: &str,
    ) -> klav_client::ClientResult<(PasskeyAccess, AgentRequestProof)> {
        self.agent
            .call_proved(ACCESS_PATH, &asked(item, host, self.task))
            .await
    }

    fn step(&self, agent: &Agent, item: ItemId, request: AgentRequestProof) -> PasskeyArmStep {
        PasskeyArmStep {
            agent_id: agent.id(),
            task_id: self.task,
            item_id: item,
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
        ext.answer(
            "tab",
            json!({ "ok": { "tab_id": 4, "url": url, "focused": true } }),
        )
        .await;
        ask.await.expect("join").tab
    }

    /// `agent_passkey_arm`, from the agent's own connection.
    fn arm(&self, tab: String, step: PasskeyArmStep) -> tokio::task::JoinHandle<Armed> {
        let home = self.home.clone();
        tokio::spawn(async move {
            let mut daemon = DaemonClient::connect(&home).await.expect("klavd");
            daemon
                .call::<PasskeyArmed>(Request::AgentPasskeyArm { tab, step })
                .await
                .map(|(armed, _)| armed)
        })
    }

    /// An arm `klavd` must refuse before telling the browser anything.
    async fn refused(&self, tab: &str, step: PasskeyArmStep) -> ErrorBody {
        self.arm(tab.to_owned(), step)
            .await
            .expect("join")
            .expect_err("klavd must refuse it")
    }
}

fn assertion_of(reply: &Value) -> PasskeyAssertion {
    serde_json::from_value(reply["ok"].clone()).unwrap_or_else(|e| panic!("{e}: {reply}"))
}

fn flags(assertion: &PasskeyAssertion) -> u8 {
    Blob::from_text(&assertion.authenticator_data)
        .expect("authenticatorData")
        .as_bytes()[32]
}

async fn passkey_uses(home: &Home) -> Vec<Value> {
    let mut client = DaemonClient::connect(home).await.expect("klavd");
    let mut used = Vec::new();
    for _ in 0..100 {
        let (lines, _): (Vec<Value>, _) = client
            .call(Request::AuditLog {
                filter: Default::default(),
            })
            .await
            .expect("log");
        used = lines
            .into_iter()
            .filter(|l| l["action"] == "passkey.used")
            .collect();
        if !used.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    used
}

#[tokio::test(flavor = "multi_thread")]
async fn klavd_signs_for_an_agent_only_inside_its_task() {
    let w = world();
    let person = &w.person;
    let _stop = StopDaemon(person);
    let (task, shop, forum) = w.setup().await;
    let home = Home::at(&person.home);
    let rig = Rig {
        agent: Agent::load(&Home::at(&w.agent_device.home), "bot").expect("agent"),
        home: home.clone(),
        task,
    };
    let other = Agent::load(&Home::at(&w.other_device.home), "bot2").expect("bot2");
    let mut ext = FakeExtension::attach(&home).await;

    // --- 1. The server logs the use and answers without the item. ----------
    let (granted, proof) = rig.access(shop, SHOP_HOST).await.expect("access");
    assert_eq!(
        granted,
        PasskeyAccess {
            task_id: task,
            item_id: shop,
            domain: SHOP_HOST.into(),
        }
    );
    // A login the task only lets the agent fill: the server says no.
    let err = rig
        .access(forum, "forum.example")
        .await
        .expect_err("not in the task");
    assert!(err.to_string().contains("passkey"), "{err}");

    // --- 2. klavd arms one use and tells the tab. --------------------------
    let tab = rig.tab(&mut ext, SHOP_PAGE).await;
    let arm = rig.arm(tab.clone(), rig.step(&rig.agent, shop, proof.clone()));
    let event = ext
        .answer("passkey_arm", json!({ "ok": { "used": false } }))
        .await;
    assert_eq!(event["host"], SHOP_HOST);
    assert_eq!(event["rp_id"], "shop.example");
    assert_eq!(event["item"], shop.to_string());
    assert_eq!(
        (event["title"].clone(), event["agent"].clone()),
        (json!("Shop"), json!("bot"))
    );
    assert_eq!(event["reason"], "check the order");
    assert_eq!(event["tab_id"], 4);
    let token = event["token"].as_str().expect("token").to_owned();
    assert!(token.starts_with("kpa_"), "{token}");
    let armed = arm.await.expect("join").expect("armed");
    assert_eq!(
        armed,
        PasskeyArmed {
            used: false,
            rp_id: "shop.example".into(),
            expires_in_s: Some(60),
        }
    );

    // --- 3. Only from that connection and tab, on the armed host. ----------
    let mut stranger = DaemonClient::connect(&home).await.expect("klavd");
    let err = stranger
        .call::<Value>(Request::AgentPasskeyUse {
            tab_id: 4,
            origin: SHOP_PAGE.into(),
            rp_id: Some("shop.example".into()),
            challenge: Blob::from(&b"0123456789abcdef"[..]).to_text(),
            token: SecretText::new(token.clone()),
        })
        .await
        .expect_err("another connection");
    assert_eq!(err.code, ErrorCode::Denied);
    // Still armed: the stranger took nothing. The page signs in, with UV.
    let reply = ext.use_passkey(SHOP_PAGE, &token).await;
    let assertion = assertion_of(&reply);
    assert_eq!(assertion.item, shop);
    assert_eq!(flags(&assertion), FLAGS_UV);
    // Once.
    let again = ext.use_passkey(SHOP_PAGE, &token).await;
    assert_eq!(again["error"]["code"], "denied", "{again}");

    // `passkey.used`, with the agent and the task.
    let used = passkey_uses(&home).await;
    assert_eq!(used.len(), 1, "{used:?}");
    assert_eq!(used[0]["item_id"], shop.to_string());
    assert_eq!(used[0]["agent_id"], rig.agent.id().to_string());
    assert_eq!(used[0]["task_id"], task.to_string());

    // --- 4. Another page of the tab gets nothing, and the use is gone. -----
    let (_, proof) = rig.access(shop, SHOP_HOST).await.expect("access");
    let arm = rig.arm(tab.clone(), rig.step(&rig.agent, shop, proof));
    let event = ext
        .answer("passkey_arm", json!({ "ok": { "used": false } }))
        .await;
    arm.await.expect("join").expect("armed");
    let token = event["token"].as_str().expect("token").to_owned();
    let evil = ext.use_passkey("https://evil.example/", &token).await;
    assert_eq!(evil["error"]["code"], "denied", "{evil}");
    let late = ext.use_passkey(SHOP_PAGE, &token).await;
    assert_eq!(late["error"]["code"], "denied", "{late}");

    // --- 5. The extension's word is not enough: used only if klavd signed. --
    let (_, proof) = rig.access(shop, SHOP_HOST).await.expect("access");
    // A forged copy with the agent's nonce is refused, and does not use up
    // the real request.
    let mut forged = proof.clone();
    forged.timestamp_ms += 1;
    let err = rig.refused(&tab, rig.step(&rig.agent, shop, forged)).await;
    assert_eq!(err.code, ErrorCode::Security, "{err:?}");
    let arm = rig.arm(tab.clone(), rig.step(&rig.agent, shop, proof));
    ext.answer("passkey_arm", json!({ "ok": { "used": true } }))
        .await;
    let armed = arm.await.expect("join").expect("armed");
    assert!(!armed.used && armed.expires_in_s == Some(60), "{armed:?}");

    // --- 6. A page already waiting gets it before the agent's answer. ------
    let (_, proof) = rig.access(shop, SHOP_HOST).await.expect("access");
    let arm = rig.arm(tab.clone(), rig.step(&rig.agent, shop, proof.clone()));
    let event = ext.event("passkey_arm").await;
    let token = event["token"].as_str().expect("token").to_owned();
    let reply = ext.use_passkey(SHOP_PAGE, &token).await;
    assert_eq!(flags(&assertion_of(&reply)), FLAGS_UV);
    ext.reply(&event, json!({ "ok": { "used": true } })).await;
    let armed = arm.await.expect("join").expect("armed");
    assert_eq!(
        armed,
        PasskeyArmed {
            used: true,
            rp_id: "shop.example".into(),
            expires_in_s: None,
        }
    );

    // --- 7. What klavd refuses on its own, arming nothing. -----------------
    // Replayed: the request of step 6 again.
    let used_in_6 = proof.clone();
    let err = rig.refused(&tab, rig.step(&rig.agent, shop, proof)).await;
    assert!(err.message.contains("already used"), "{err:?}");
    // Tampered: another body under the agent's signature.
    let (_, mut tampered) = rig.access(shop, SHOP_HOST).await.expect("access");
    let mut body = asked(shop, SHOP_HOST, task);
    body.reason = "something else".into();
    tampered.body = Blob::from(serde_json::to_vec(&body).expect("json").as_slice());
    let err = rig
        .refused(&tab, rig.step(&rig.agent, shop, tampered))
        .await;
    assert_eq!(err.code, ErrorCode::Security, "{err:?}");
    // Signed but never shown to the server, so only klavd checks these:
    let signed = |agent: &Agent, item: ItemId, host: &str, task: TaskId| {
        agent
            .sign_post(ACCESS_PATH, &asked(item, host, task))
            .expect("sign")
    };
    // a login the task only lets it fill,
    let request = signed(&rig.agent, forum, "forum.example", task);
    let err = rig
        .refused(&tab, rig.step(&rig.agent, forum, request))
        .await;
    assert_eq!(err.code, ErrorCode::Denied, "{err:?}");
    assert!(err.message.contains("`passkey`"), "{err:?}");
    // a host that cannot use the passkey's rpId,
    let request = signed(&rig.agent, shop, "evil.example", task);
    let err = rig.refused(&tab, rig.step(&rig.agent, shop, request)).await;
    assert!(err.message.contains("cannot use the passkey"), "{err:?}");
    // a host the rpId allows but the task did not approve,
    let request = signed(&rig.agent, shop, "shop.example", task);
    let err = rig.refused(&tab, rig.step(&rig.agent, shop, request)).await;
    assert!(err.message.contains("on shop.example"), "{err:?}");
    // another task than the one the request names,
    let request = signed(&rig.agent, shop, SHOP_HOST, task);
    let mut step = rig.step(&rig.agent, shop, request);
    step.task_id = TaskId::generate();
    let err = rig.refused(&tab, step).await;
    assert!(err.message.contains("something else"), "{err:?}");
    // another agent under this agent's task,
    let request = signed(&other, shop, SHOP_HOST, task);
    let err = rig.refused(&tab, rig.step(&other, shop, request)).await;
    assert!(err.message.contains("another agent"), "{err:?}");
    // and a request everything allows, but that never went to the server:
    // its log has no record of it, so nothing is armed.
    let request = signed(&rig.agent, shop, SHOP_HOST, task);
    let err = rig.refused(&tab, rig.step(&rig.agent, shop, request)).await;
    assert_eq!(err.code, ErrorCode::Denied, "{err:?}");
    assert!(err.message.contains("no record"), "{err:?}");

    // --- 8. Locked: refused, no prompt, nothing armed. ---------------------
    let (_, proof) = rig.access(shop, SHOP_HOST).await.expect("access");
    person.run(&["lock"], "").ok();
    let err = rig.refused(&tab, rig.step(&rig.agent, shop, proof)).await;
    assert_eq!(err.code, ErrorCode::Locked, "{err:?}");
    person.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    // A new session does not forget what was used: step 6's request,
    // still within its 5 minutes, arms nothing again (T139).
    let err = rig
        .refused(&tab, rig.step(&rig.agent, shop, used_in_6))
        .await;
    assert!(err.message.contains("already used"), "{err:?}");
    // Only the two real uses were logged.
    assert_eq!(passkey_uses(&home).await.len(), 2);

    // The server logged each request before answering, under the task;
    // the one for Forum as a denial.
    let log = json_of(&person.run(&["log", "--agent", "bot", "--json"], "").ok());
    let passkey: Vec<&Value> = log
        .as_array()
        .expect("array")
        .iter()
        .filter(|l| l["action"] == "agent.access" && l["permission"] == "passkey")
        .collect();
    let allowed = |l: &&&Value| l["outcome"] == "allow";
    assert_eq!(passkey.iter().filter(allowed).count(), 6, "{log}");
    assert!(
        passkey
            .iter()
            .filter(allowed)
            .all(|l| l["task_id"] == task.to_string()
                && l["domain"] == SHOP_HOST
                && l["reason"] == "check the order"),
        "{log}"
    );
    assert!(
        passkey
            .iter()
            .any(|l| l["outcome"] == "deny" && l["item_id"] == forum.to_string()),
        "{log}"
    );

    // --- 9. Paused: a use armed before is not used, nothing more is armed. -
    let (_, proof) = rig.access(shop, SHOP_HOST).await.expect("access");
    let arm = rig.arm(tab.clone(), rig.step(&rig.agent, shop, proof));
    let event = ext
        .answer("passkey_arm", json!({ "ok": { "used": false } }))
        .await;
    arm.await.expect("join").expect("armed");
    let token = event["token"].as_str().expect("token").to_owned();
    let mut daemon = DaemonClient::connect(&home).await.expect("klavd");
    daemon
        .call::<Value>(Request::PauseAgents {
            agent: Some(rig.agent.id()),
            until: None,
        })
        .await
        .expect("pause");
    let paused = ext.use_passkey(SHOP_PAGE, &token).await;
    assert_eq!(paused["error"]["code"], "agents_paused", "{paused}");
    // Signed but never sent: the server would refuse it now.
    let request = signed(&rig.agent, shop, SHOP_HOST, task);
    let err = rig.refused(&tab, rig.step(&rig.agent, shop, request)).await;
    assert_eq!(err.code, ErrorCode::AgentsPaused, "{err:?}");
    assert_eq!(passkey_uses(&home).await.len(), 2);

    // --- 10. The person asks to delete the account from another device:
    // klavd learns it when it syncs and refuses first (ADR 0037 §3). -----
    let phone = Device::new(w.root.path(), "phone");
    let kit = person.home.with_extension("kit.txt");
    phone
        .run(
            &[
                "--password-stdin",
                "login",
                "--server",
                &w._server.url,
                "--email",
                "ana@example.com",
                "--emergency-kit",
                kit.to_str().expect("utf-8 path"),
            ],
            &format!("{PASSWORD}\n"),
        )
        .ok();
    let _stop_phone = StopDaemon(&phone);
    klav_client::deletion::request_account_deletion(
        &Home::at(&phone.home),
        &klav_core::crypto::kdf::MasterPassword::new(PASSWORD),
    )
    .await
    .expect("ask to delete");
    daemon.call::<Value>(Request::Sync).await.expect("sync");
    let request = signed(&rig.agent, shop, SHOP_HOST, task);
    let err = rig.refused(&tab, rig.step(&rig.agent, shop, request)).await;
    assert_eq!(err.code, ErrorCode::AccountDeleting, "{err:?}");
    assert_eq!(passkey_uses(&home).await.len(), 2);
}

/// Starts the person's `klavd` again with the presence gate on (ADR 0041,
/// layer 4) and Touch ID off, and unlocks it with the master password.
async fn gated_klavd(w: &World) -> common::Klavd {
    w.person.run(&["lock", "--stop"], "").ok();
    let socket = w.person.home.join("klavd.sock");
    assert!(common::wait_until(30, || !socket.exists()), "klavd stopped");
    let klavd = common::Klavd::start(&w.person, w.root.path());
    let mut client = DaemonClient::connect(&Home::at(&w.person.home))
        .await
        .expect("klavd");
    let unlock: Request =
        serde_json::from_value(json!({ "op": "unlock", "password": PASSWORD })).expect("unlock");
    client.call::<Value>(unlock).await.expect("unlocked");
    klavd
}

/// The `presence` event on the extension's connection, answered with the
/// master password on that same connection; returns the event and the
/// next event of `kind`, which may come before or after the answer's ack.
async fn presence_then(ext: &mut FakeExtension, kind: &str) -> (Value, Value) {
    let presence = ext.event("presence").await;
    ext.send(json!({
        "op": "extension_presence",
        "event": presence["id"],
        "password": PASSWORD,
    }))
    .await;
    let (first, second) = (ext.line().await, ext.line().await);
    let (ack, next) = if first.get("event").is_some() {
        (second, first)
    } else {
        (first, second)
    };
    assert!(ack.get("ok").is_some(), "{ack}");
    assert_eq!(next["event"]["kind"], kind, "{next}");
    (presence, next["event"].clone())
}

#[tokio::test(flavor = "multi_thread")]
async fn with_the_gate_the_browser_asks_before_a_passkey_sign_in() {
    let w = world();
    let person = &w.person;
    let _stop = StopDaemon(person);
    let (task, shop, _) = w.setup().await;
    let _klavd = gated_klavd(&w).await;
    let home = Home::at(&person.home);
    let rig = Rig {
        agent: Agent::load(&Home::at(&w.agent_device.home), "bot").expect("agent"),
        home: home.clone(),
        task,
    };
    let mut ext = FakeExtension::attach(&home).await;
    let tab = rig.tab(&mut ext, SHOP_PAGE).await;

    // The first arm asks on the connection, naming the agent, the title
    // and the rpId from the vault; then it arms.
    let (_, proof) = rig.access(shop, SHOP_HOST).await.expect("access");
    let arm = rig.arm(tab.clone(), rig.step(&rig.agent, shop, proof));
    let (presence, event) = presence_then(&mut ext, "passkey_arm").await;
    let ask = &presence["presence"];
    assert_eq!(ask["window"], "5m", "{presence}");
    assert_eq!(ask["lasts"], "until_lock", "{presence}");
    assert_eq!(ask["browser"]["event"], "passkey_sign_in", "{presence}");
    assert_eq!(ask["browser"]["agent"], "bot", "{presence}");
    assert_eq!(ask["browser"]["title"], "Shop", "{presence}");
    assert_eq!(ask["browser"]["site"], "shop.example", "{presence}");
    assert_eq!(presence["tab_id"], 4, "{presence}");
    ext.reply(&event, json!({ "ok": { "used": false } })).await;
    arm.await.expect("join").expect("armed");

    // The connection stays verified until Klav locks: no second question.
    let (_, proof) = rig.access(shop, SHOP_HOST).await.expect("access");
    let arm = rig.arm(tab.clone(), rig.step(&rig.agent, shop, proof));
    ext.answer("passkey_arm", json!({ "ok": { "used": false } }))
        .await;
    arm.await.expect("join").expect("armed");

    // A second browser attaches: right before the arm, exactly one of the
    // two must be in front, and it must be the tab's (P25).
    let mut other = FakeExtension::attach(&home).await;
    for (mine, theirs) in [(false, true), (true, true), (false, false)] {
        let (_, proof) = rig.access(shop, SHOP_HOST).await.expect("access");
        let arm = rig.arm(tab.clone(), rig.step(&rig.agent, shop, proof));
        // klavd asks the newest connection first.
        for (ext, focused) in [(&mut other, theirs), (&mut ext, mine)] {
            ext.answer(
                "tab",
                json!({ "ok": { "tab_id": 4, "url": SHOP_PAGE, "focused": focused } }),
            )
            .await;
        }
        let err = arm.await.expect("join").expect_err("ambiguous");
        assert_eq!(
            err.code,
            ErrorCode::BrowserAmbiguous,
            "{mine} {theirs}: {err:?}"
        );
    }
    let (_, proof) = rig.access(shop, SHOP_HOST).await.expect("access");
    let arm = rig.arm(tab.clone(), rig.step(&rig.agent, shop, proof));
    for (ext, focused) in [(&mut other, false), (&mut ext, true)] {
        ext.answer(
            "tab",
            json!({ "ok": { "tab_id": 4, "url": SHOP_PAGE, "focused": focused } }),
        )
        .await;
    }
    ext.answer("passkey_arm", json!({ "ok": { "used": false } }))
        .await;
    arm.await.expect("join").expect("armed");
    drop(other);

    // A cancel in the frame arms nothing and tells the agent why.
    let mut client = DaemonClient::connect(&home).await.expect("klavd");
    client.call::<Value>(Request::Lock).await.expect("lock");
    let unlock: Request =
        serde_json::from_value(json!({ "op": "unlock", "password": PASSWORD })).expect("unlock");
    client.call::<Value>(unlock).await.expect("unlocked");
    let (_, proof) = rig.access(shop, SHOP_HOST).await.expect("access");
    let arm = rig.arm(tab.clone(), rig.step(&rig.agent, shop, proof));
    let presence = ext.event("presence").await;
    ext.reply(
        &presence,
        json!({ "error": { "code": "denied", "message": "canceled" } }),
    )
    .await;
    let err = arm.await.expect("join").expect_err("declined");
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

#[tokio::test(flavor = "multi_thread")]
async fn passkey_sign_in_through_mcp_only_in_the_persons_browser() {
    let w = world();
    let person = &w.person;
    let _stop = StopDaemon(person);
    w.setup().await;
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
    let mut tools = Tools(Some(mcp));
    let reason = "check the order";

    // `sdk:`: refused before anything else (no tab asked, nothing logged).
    let (text, err) = tools
        .tool(
            "passkey_sign_in",
            json!({ "ref": SHOP, "target": "sdk:mine", "reason": reason }),
        )
        .await;
    assert!(
        err && text.contains("never in a browser of your runtime"),
        "{text}"
    );

    // The person's tab on the shop: armed for the next sign-in.
    let call = tools.spawn(
        "passkey_sign_in",
        json!({ "ref": SHOP, "target": "extension", "reason": reason }),
    );
    ext.answer(
        "tab",
        json!({ "ok": { "tab_id": 4, "url": SHOP_PAGE, "focused": true } }),
    )
    .await;
    let event = ext
        .answer("passkey_arm", json!({ "ok": { "used": false } }))
        .await;
    let (text, err) = tools.join(call).await;
    assert!(!err, "{text}");
    let out: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(out["used"], false);
    assert_eq!(out["armed"], true);
    assert_eq!(out["expires_in_s"], 60);
    assert_eq!(out["rp_id"], "shop.example");
    assert!(
        out["next"].as_str().is_some_and(|n| n.contains("button")),
        "{out}"
    );
    let token = event["token"].as_str().expect("token");
    assert!(!text.contains(token), "the agent never sees the token");
    let reply = ext.use_passkey(SHOP_PAGE, token).await;
    assert_eq!(flags(&assertion_of(&reply)), FLAGS_UV);

    // Another site in the tab: refused before the server.
    let call = tools.spawn(
        "passkey_sign_in",
        json!({ "ref": SHOP, "target": "extension", "reason": reason }),
    );
    ext.answer(
        "tab",
        json!({ "ok": { "tab_id": 4, "url": "https://evil.example/", "focused": true } }),
    )
    .await;
    let (text, err) = tools.join(call).await;
    assert!(err && text.contains("phishing"), "{text}");

    // A login whose passkey the task does not cover.
    let call = tools.spawn(
        "passkey_sign_in",
        json!({ "ref": FORUM, "target": "extension", "reason": reason }),
    );
    ext.answer(
        "tab",
        json!({ "ok": { "tab_id": 4, "url": "https://forum.example/", "focused": true } }),
    )
    .await;
    let (text, err) = tools.join(call).await;
    assert!(err && text.contains("request_task"), "{text}");
}
