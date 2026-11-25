//! The MCP gateway in the apps (ADR 0049, layer 6), against a real server:
//! the account grants its proxy an MCP profile with tool rules and a local
//! client; the proxy signs tool calls and session messages as `klav-proxy`
//! does. The iPhone (`KlavCore`) and the Mac (`DaemonEngine` through a
//! `klavd` in this process, Touch ID off) then show the approval card with
//! the caller, profile and tool, Activity with «called» and folded session
//! rows, «Development › MCP servers», and turn the switch on.

#![cfg(feature = "daemon")]

mod common;

use std::time::Duration;

use common::ServerProcess;
use klav_client::proxy_admin::{LocalClientChange, McpSpec, PairingCheck, ProxyCredentialSpec};
use klav_client::{Home, SignupRequest};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::mcp::{LocalClientToken, digest_text};
use klav_core::model::item::{Item, ItemKind};
use klav_ffi::{DaemonEngine, KlavCore, KlavError, LogFilterInput};
use klav_proto::Blob;
use klav_sdk::proxy::{ProxyAccess, ProxyCall};
use klav_sdk::{Agent, KeyStore, Registration, Session};

const PASSWORD: &str = "correct horse battery staple";
const HOST: &str = "api.maple.dev";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test setup")
}

/// A `klavd` for `home` on its own runtime, stopped when dropped.
struct Daemon {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Daemon {
    fn start(home: &std::path::Path) -> Self {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let home = Home::at(home);
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("test setup");
            let config = klav_daemon::Config {
                home,
                idle_lock: Duration::from_secs(15 * 60),
                touch_id: false,
                sync_after: klav_daemon::SYNC_AFTER,
                build: None,
            };
            let _ = rt.block_on(klav_daemon::serve(config, async {
                let _ = stopped.await;
            }));
        });
        Self {
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !ok() {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

async fn sign_up(
    server: &ServerProcess,
    home: &std::path::Path,
    email: &str,
) -> klav_client::Unlocked {
    klav_client::signup(
        &Home::at(home),
        SignupRequest {
            server: server.url.clone(),
            email: email.into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "mac".into(),
            device_kind: klav_proto::auth::DeviceKind::Cli,
            invite: None,
        },
    )
    .await
    .expect("sign-up")
    .0
}

/// What the setup left: the approval the proxy is waiting on.
struct Made {
    approval: String,
}

/// Signs up `email`, makes `klav-proxy` the account's proxy with the MCP
/// profile `maple` (query_* allowed, delete_* asked, create_api_key
/// denied) and the local client `claude-code`. The proxy then signs, as
/// `klav-proxy` does for `claude-code`: two session messages, a
/// `query_logs` call and a `delete_service` call that asks the person.
async fn setup(server: &ServerProcess, home: &std::path::Path, email: &str) -> Made {
    let dir = home.parent().expect("parent").to_path_buf();
    let mut ana = sign_up(server, home, email).await;
    let vault = ana.find_vault("Personal").expect("vault");
    let project = ana.find_project(vault, "General").expect("project");
    let mut item = Item::from_template(ItemKind::Login, "Maple").expect("item");
    item.field_mut("password")
        .expect("password")
        .set_value("maple_ak_live_0123456789")
        .expect("set");
    ana.add_item(vault, project, &item).await.expect("add item");

    let proxy = Agent::register(
        &Home::at(dir.join("agent-proxy")),
        Registration {
            name: "klav-proxy".into(),
            server: server.url.clone(),
            email: email.into(),
            note: None,
            key_store: KeyStore::File {
                path: dir.join("proxy.key"),
            },
        },
    )
    .await
    .expect("register")
    .0;
    let proxy_id = proxy.id();
    let prepared = ana
        .prepare_proxy_use(Some("klav-proxy"))
        .await
        .expect("use");
    ana.commit_proxy_use(prepared).await.expect("use");
    let list = |l: &[&str]| l.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>();
    let spec = ProxyCredentialSpec {
        profile: "maple".into(),
        upstream: format!("https://{HOST}"),
        header: "authorization".into(),
        prefix: "Bearer ".into(),
        methods: list(&["POST", "GET", "DELETE"]),
        path_prefixes: list(&["/mcp"]),
        mcp: Some(McpSpec {
            endpoint: "/mcp".into(),
            headers: Vec::new(),
            tools_allow: list(&["query_*", "get_*"]),
            tools_ask: list(&["delete_*"]),
            tools_deny: list(&["create_api_key"]),
        }),
        ..ProxyCredentialSpec::default()
    };
    let prepared = ana
        .prepare_proxy_grant("Maple", &spec, PairingCheck::InPrompt)
        .await
        .expect("grant");
    prepared.require_updated_devices(true).expect("ack");
    assert!(
        ana.commit_proxy_change(prepared)
            .await
            .expect("grant")
            .granted
    );
    let token = LocalClientToken::generate();
    let digest = Blob::new(token.digest(proxy_id).expect("digest").to_vec());
    let prepared = ana
        .prepare_local_client(
            "claude-code",
            &LocalClientChange::Set {
                profiles: list(&["maple"]),
                token_digest: Some(digest),
            },
        )
        .await
        .expect("client");
    assert!(
        ana.commit_local_client(prepared)
            .await
            .expect("sign")
            .granted
    );
    let maple = ana.find_item("Maple").expect("maple").item;
    drop(ana);

    let session = Session::open(proxy).await.expect("proxy session");
    let args = digest_text(&[4; 32]);
    let call = |tool: Option<&'static str>| ProxyCall {
        item: maple,
        host: HOST,
        method: "POST",
        path: "/mcp",
        tags: &[],
        reason: "MCP call from claude-code",
        sandbox: None,
        mcp_tool: tool,
        mcp_args: tool.map(|_| args.as_str()),
        local_client: Some("claude-code"),
    };
    // `initialize`, then `tools/list`: no tool claim, folded in the views.
    for _ in 0..2 {
        let access = session
            .proxy_access(&call(None), 0)
            .await
            .expect("session message");
        assert!(matches!(access, ProxyAccess::Granted { .. }));
    }
    let access = session
        .proxy_access(&call(Some("query_logs")), 0)
        .await
        .expect("query_logs");
    assert!(matches!(access, ProxyAccess::Granted { .. }));
    let access = session
        .proxy_access(&call(Some("delete_service")), 0)
        .await
        .expect("delete_service");
    let ProxyAccess::Pending { approval_id, .. } = access else {
        panic!("delete_service should ask");
    };
    Made {
        approval: approval_id.to_string(),
    }
}

#[test]
fn the_apps_show_mcp_calls_and_the_gateway() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("klav");
    let made = runtime().block_on(setup(&server, &home, "mcp@example.com"));

    // The iPhone: the card names the caller, the profile and the tool.
    {
        let core = KlavCore::new(home.display().to_string()).expect("core");
        core.unlock_with_password(PASSWORD.into(), None)
            .expect("unlock");
        let approvals = core.approvals().expect("approvals");
        let card = approvals
            .iter()
            .find(|a| a.id == made.approval)
            .expect("the card");
        assert_eq!(card.mcp_tool.as_deref(), Some("delete_service"));
        assert_eq!(card.mcp_profile.as_deref(), Some("maple"));
        assert_eq!(card.local_client.as_deref(), Some("claude-code"));
        assert_eq!(card.sandbox_id, None);
        assert!(!card.security);
        assert_eq!(card.permission, "proxy");

        let lines = core.audit_log(LogFilterInput::default()).expect("log");
        let called = lines
            .iter()
            .find(|l| l.mcp_tool.as_deref() == Some("query_logs"))
            .expect("the call");
        assert_eq!(called.mcp_profile.as_deref(), Some("maple"));
        assert_eq!(called.local_client.as_deref(), Some("claude-code"));
        assert!(!called.mcp_session);
        // The two session messages fold into one row.
        let sessions: Vec<_> = lines.iter().filter(|l| l.mcp_session).collect();
        assert_eq!(sessions.len(), 1, "{lines:?}");
        assert_eq!(sessions[0].folded, 1);
        assert_eq!(sessions[0].mcp_profile.as_deref(), Some("maple"));
        assert_eq!(sessions[0].mcp_tool, None);
        core.lock();
    }

    // The Mac, through klavd.
    let engine = DaemonEngine::new(home.display().to_string()).expect("engine");
    let _daemon = Daemon::start(&home);
    wait_until("klavd", || engine.status().running);
    engine.unlock(Some(PASSWORD.into()), None).expect("unlock");

    let card = engine
        .approvals()
        .expect("approvals")
        .into_iter()
        .find(|a| a.id == made.approval)
        .expect("the card");
    assert_eq!(
        (
            card.mcp_tool.as_deref(),
            card.mcp_profile.as_deref(),
            card.local_client.as_deref(),
            card.security
        ),
        (
            Some("delete_service"),
            Some("maple"),
            Some("claude-code"),
            false
        )
    );

    let servers = engine.mcp_servers().expect("MCP servers");
    assert_eq!(servers.gateway_on, Some(true));
    assert_eq!(servers.proxy.as_deref(), Some("klav-proxy"));
    assert_eq!(servers.servers.len(), 1);
    let maple = &servers.servers[0];
    assert_eq!(maple.profile, "maple");
    assert_eq!(maple.title, "Maple");
    assert_eq!(maple.upstream, format!("https://{HOST}"));
    assert_eq!(maple.endpoint, "/mcp");
    assert_eq!(maple.local_url, "http://127.0.0.1:8790/maple/mcp");
    assert_eq!(maple.tools_allow, ["query_*", "get_*"]);
    assert_eq!(maple.tools_ask, ["delete_*"]);
    assert_eq!(maple.tools_deny, ["create_api_key"]);
    assert_eq!(maple.clients, ["claude-code"]);
    assert_eq!(servers.local_clients.len(), 1);
    // Never a token, nor its digest.
    assert!(!format!("{servers:?}").contains("klc1_"));

    let lines = engine
        .audit_log(LogFilterInput::default())
        .expect("activity");
    assert!(
        lines
            .iter()
            .any(|l| l.mcp_tool.as_deref() == Some("query_logs")
                && l.mcp_profile.as_deref() == Some("maple"))
    );
    let sessions: Vec<_> = lines.iter().filter(|l| l.mcp_session).collect();
    assert_eq!((sessions.len(), sessions[0].folded), (1, 1), "{lines:?}");

    // Already on: nothing to confirm, and no prompt.
    assert!(engine.turn_mcp_gateway_on(false).expect("already on"));

    // Approving once: Touch ID is off here, so the master password.
    assert!(matches!(
        engine.decide_approval(made.approval.clone(), true, 0, card.request_digest.clone()),
        Err(KlavError::BiometryUnavailable { .. })
    ));
    engine
        .decide_approval_with_password(
            made.approval.clone(),
            true,
            0,
            card.request_digest.clone(),
            Some(PASSWORD.into()),
        )
        .expect("approve once");
    assert!(
        engine
            .approvals()
            .expect("approvals")
            .iter()
            .all(|a| a.id != made.approval)
    );
}

/// An account without the gateway: the switch is off, nothing is turned
/// on without the person's word that every device is updated, and then
/// only with presence.
#[test]
fn the_mac_turns_the_gateway_on_only_after_the_warning() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("klav");
    runtime().block_on(async {
        drop(sign_up(&server, &home, "off@example.com").await);
    });
    let engine = DaemonEngine::new(home.display().to_string()).expect("engine");
    let _daemon = Daemon::start(&home);
    wait_until("klavd", || engine.status().running);
    engine.unlock(Some(PASSWORD.into()), None).expect("unlock");

    let servers = engine.mcp_servers().expect("MCP servers");
    assert_eq!(servers.gateway_on, Some(false));
    assert_eq!(servers.proxy, None);
    assert!(servers.servers.is_empty() && servers.local_clients.is_empty());

    // Without the acknowledgement: refused before any prompt.
    match engine.turn_mcp_gateway_on(false) {
        Err(KlavError::Invalid { message }) => {
            assert!(message.contains("older than the MCP gateway"), "{message}");
        }
        other => panic!("not refused: {other:?}"),
    }
    assert_eq!(engine.mcp_servers().expect("again").gateway_on, Some(false));
    // With it, presence: Touch ID is off, so the master password.
    assert!(matches!(
        engine.turn_mcp_gateway_on(true),
        Err(KlavError::BiometryUnavailable { .. })
    ));
    assert!(matches!(
        engine.turn_mcp_gateway_on_with_password(true, Some("wrong".into())),
        Err(KlavError::WrongCredentials)
    ));
    assert_eq!(engine.mcp_servers().expect("again").gateway_on, Some(false));
    assert!(
        engine
            .turn_mcp_gateway_on_with_password(true, Some(PASSWORD.into()))
            .expect("on")
    );
    assert_eq!(engine.mcp_servers().expect("on").gateway_on, Some(true));
}
