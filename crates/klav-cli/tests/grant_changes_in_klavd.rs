//! Changing an active agent's grant and revoking it through `klavd` (ADR
//! 0033, amendment of 2026-11-10, layer 3), against a real server and an
//! in-process `klavd` with Touch ID off: only widening asks for presence
//! (P8); a sheet built over a grant that changed since is not signed
//! (T188); `approve_agent` takes only pending agents (T187); and a key
//! change cut off half way shows in `status`, also while locked, and
//! `klavd` finishes it by itself at the next unlock (P11).

mod common;

use std::time::{Duration, Instant};

use common::{PASSWORD, ServerProcess};
use klav_client::agents::{AgentView, GrantRequest};
use klav_client::grant_change::{
    ChangePolicy, ChangeWhat, EditorPolicy, GrantChange, GrantChangePreview, GrantChangeReport,
    GrantEditor, PermissionSetting,
};
use klav_client::ops::SecretText;
use klav_client::revoke::{PendingRevocation, RevokeReport};
use klav_client::{Home, ItemFilter, ItemSummary, SignupRequest, Unlocked, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::ids::AgentId;
use klav_core::model::item::{Item, ItemKind};
use klav_core::policy::{Effect, Permission, Policy};
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{DaemonStatus, ErrorBody, ErrorCode, Request};
use klav_daemon::{Config, serve};
use klav_sdk::{Agent, KeyStore, Registration};

const EMAIL: &str = "ana@example.com";

async fn account(server: &ServerProcess, root: &tempfile::TempDir) -> (Home, Unlocked) {
    let home = Home::at(root.path().join("laptop"));
    let (unlocked, _kit) = signup(
        &home,
        SignupRequest {
            server: server.url.clone(),
            email: EMAIL.into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: klav_proto::auth::DeviceKind::Cli,
            invite: None,
        },
    )
    .await
    .expect("sign-up");
    (home, unlocked)
}

/// `Personal/<name>` for each of `names` (General already exists), each
/// with a few items, so a key change has something to re-wrap.
async fn projects(ana: &mut Unlocked, names: &[&str]) {
    let vault = ana.find_vault("Personal").expect("vault");
    for name in names {
        if *name != "General" {
            ana.create_project(vault, name).await.expect("project");
        }
        let project = ana.find_project(vault, name).expect("project");
        for n in 0..3 {
            ana.add_item(
                vault,
                project,
                &Item::from_template(ItemKind::Login, &format!("{name} {n}")).expect("item"),
            )
            .await
            .expect("item");
        }
    }
}

/// Registers agent `name` and approves it with `projects` and the default
/// policy.
async fn agent(
    server: &ServerProcess,
    root: &tempfile::TempDir,
    ana: &mut Unlocked,
    name: &str,
    projects: &[&str],
) -> AgentId {
    let (agent, _) = Agent::register(
        &Home::at(root.path().join(format!("agent-{name}"))),
        Registration {
            name: name.into(),
            server: server.url.clone(),
            email: EMAIL.into(),
            note: None,
            key_store: KeyStore::File {
                path: root.path().join(format!("{name}.key")),
            },
        },
    )
    .await
    .expect("register");
    ana.approve_agent(
        agent.id(),
        GrantRequest {
            projects: projects.iter().map(|p| (*p).to_owned()).collect(),
            vaults: Vec::new(),
            policy: Policy::default(),
        },
        &agent.pairing_code(),
    )
    .await
    .expect("approve");
    agent.id()
}

/// An in-process `klavd` for `home`, Touch ID off; stops when the sender
/// drops.
async fn daemon(home: &Home) -> tokio::sync::oneshot::Sender<()> {
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let daemon = tokio::spawn(serve(
        Config {
            home: home.clone(),
            idle_lock: Duration::from_secs(600),
            touch_id: false,
            sync_after: klav_daemon::SYNC_AFTER,
            build: None,
        },
        async {
            let _ = stopped.await;
        },
    ));
    wait_until_listening(home, &daemon).await;
    stop
}

/// Waits until the in-process `klavd` answers on its socket. A fixed few
/// seconds of polling for the socket file were not enough on a loaded
/// machine: the loop gave up without a word and the next connection failed.
/// The bound is generous, and a `klavd` that stopped first fails at once.
async fn wait_until_listening(home: &Home, daemon: &tokio::task::JoinHandle<Result<(), String>>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while DaemonClient::connect(home).await.is_none() {
        assert!(!daemon.is_finished(), "klavd stopped before it listened");
        assert!(
            tokio::time::Instant::now() < deadline,
            "klavd did not listen on {} within 60 s",
            home.socket_path().display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn client(home: &Home) -> DaemonClient {
    DaemonClient::connect(home).await.expect("klavd")
}

async fn call<T: serde::de::DeserializeOwned>(
    home: &Home,
    request: Request,
) -> Result<T, ErrorBody> {
    client(home)
        .await
        .call(request)
        .await
        .map(|(value, _)| value)
}

async fn unlock(home: &Home) -> DaemonStatus {
    call(
        home,
        Request::Unlock {
            password: Some(SecretText::new(PASSWORD)),
            passkey_flow: false,
        },
    )
    .await
    .expect("unlock")
}

async fn status(home: &Home) -> DaemonStatus {
    call(home, Request::Status).await.expect("status")
}

async fn view(home: &Home, id: AgentId) -> AgentView {
    let agents: Vec<AgentView> = call(home, Request::Agents).await.expect("agents");
    agents.into_iter().find(|a| a.id == id).expect("the agent")
}

async fn version(home: &Home, id: AgentId) -> u64 {
    view(home, id).await.grant.map_or(0, |g| g.version)
}

fn change(projects: &[&str], fill: Option<Effect>) -> GrantChange {
    GrantChange {
        projects: projects.iter().map(|p| (*p).to_owned()).collect(),
        vaults: Vec::new(),
        policy: ChangePolicy::Editor(EditorPolicy {
            permissions: fill
                .map(|effect| PermissionSetting {
                    permission: Permission::Fill,
                    effect: Some(effect),
                })
                .into_iter()
                .collect(),
            ..EditorPolicy::default()
        }),
        rotate_removed: false,
    }
}

async fn prepare(home: &Home, agent: AgentId, change: &GrantChange) -> GrantChangePreview {
    call(
        home,
        Request::GrantChangePrepare {
            agent,
            change: change.clone(),
        },
    )
    .await
    .expect("prepare")
}

async fn apply(
    home: &Home,
    agent: AgentId,
    change: &GrantChange,
    digest: &str,
    password: Option<&str>,
) -> Result<GrantChangeReport, ErrorBody> {
    call(
        home,
        Request::GrantChangeApply {
            agent,
            change: change.clone(),
            digest: digest.to_owned(),
            password: password.map(SecretText::new),
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn only_widening_asks_for_presence_and_a_stale_sheet_is_not_signed() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (home, mut ana) = account(&server, &root).await;
    projects(&mut ana, &["General", "Work"]).await;
    let bot = agent(&server, &root, &mut ana, "bot", &["Personal/General"]).await;
    drop(ana);
    let _stop = daemon(&home).await;
    unlock(&home).await;

    let editor: GrantEditor = call(&home, Request::GrantEditor { agent: bot })
        .await
        .expect("editor");
    assert!(editor.editable, "{editor:?}");
    assert_eq!(editor.version, 1);

    // Adding a project widens: without presence nothing is signed.
    let wider = change(&["Personal/General", "Personal/Work"], None);
    let sheet = prepare(&home, bot, &wider).await;
    assert!(sheet.widens);
    assert_eq!(
        sheet.lines[0].what,
        ChangeWhat::ProjectAdded {
            project: "Personal/Work".into()
        }
    );
    let refused = apply(&home, bot, &wider, &sheet.digest, None)
        .await
        .expect_err("no presence");
    assert_eq!(refused.code, ErrorCode::BiometryUnavailable, "{refused:?}");
    assert_eq!(version(&home, bot).await, 1);
    let wrong = apply(&home, bot, &wider, &sheet.digest, Some("not the password"))
        .await
        .expect_err("wrong password");
    assert_ne!(wrong.code, ErrorCode::BiometryUnavailable, "{wrong:?}");
    assert_eq!(version(&home, bot).await, 1);
    let report = apply(&home, bot, &wider, &sheet.digest, Some(PASSWORD))
        .await
        .expect("with presence");
    assert_eq!(report.agent.grant.as_ref().map(|g| g.version), Some(2));

    // Two narrowing sheets over the same grant: the first one signed
    // without presence; the second was built over the grant before it, so
    // it is not signed.
    let back = change(&["Personal/General"], Some(Effect::Deny));
    let no_fill = change(&["Personal/General", "Personal/Work"], Some(Effect::Deny));
    let back_sheet = prepare(&home, bot, &back).await;
    let no_fill_sheet = prepare(&home, bot, &no_fill).await;
    assert!(!back_sheet.widens && !no_fill_sheet.widens);
    apply(&home, bot, &no_fill, &no_fill_sheet.digest, None)
        .await
        .expect("narrowing asks for nothing");
    assert_eq!(version(&home, bot).await, 3);
    let stale = apply(&home, bot, &back, &back_sheet.digest, None)
        .await
        .expect_err("stale sheet");
    assert_eq!(stale.code, ErrorCode::Security, "{stale:?}");
    assert!(
        stale.message.contains("changed while you were looking"),
        "{stale:?}"
    );
    assert_eq!(version(&home, bot).await, 3);
    // Opened again, it signs.
    let back_sheet = prepare(&home, bot, &back).await;
    apply(&home, bot, &back, &back_sheet.digest, None)
        .await
        .expect("narrowing");
    let now = view(&home, bot).await;
    let grant = now.grant.expect("grant");
    assert_eq!(grant.version, 4);
    assert_eq!(grant.projects.len(), 1);

    // `approve_agent` is for pending registrations only (T187): the dialog
    // that only names projects never widens an active agent.
    let again: Result<AgentView, ErrorBody> = call(
        &home,
        Request::ApproveAgent {
            agent: bot,
            grant: GrantRequest {
                projects: vec!["Personal/General".into(), "Personal/Work".into()],
                vaults: Vec::new(),
                policy: Policy::default(),
            },
            pairing_code: now.pairing_code.clone(),
            password: Some(SecretText::new(PASSWORD)),
        },
    )
    .await;
    let again = again.expect_err("active agent");
    assert_eq!(again.code, ErrorCode::Invalid, "{again:?}");
    assert!(again.message.contains("already active"), "{again:?}");
    assert_eq!(version(&home, bot).await, 4);
}

/// Waits until `status` says no key change is left.
async fn finished(home: &Home) -> DaemonStatus {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let s = status(home).await;
        if s.revocations.is_empty() {
            return s;
        }
        assert!(
            Instant::now() < deadline,
            "the key change did not finish: {:?}",
            s.revocations
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_change_cut_off_shows_while_locked_and_finishes_by_itself_at_unlock() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (home, mut ana) = account(&server, &root).await;
    let names = ["General", "Work", "Home", "Bank", "Travel", "Health"];
    projects(&mut ana, &names).await;
    let all: Vec<String> = names.iter().map(|n| format!("Personal/{n}")).collect();
    let all: Vec<&str> = all.iter().map(String::as_str).collect();
    let bot = agent(&server, &root, &mut ana, "bot", &all).await;
    agent(&server, &root, &mut ana, "keeper", &all).await;

    // A revocation whose key change stopped after one project, as a lock
    // or a lost network leaves it (the steps are the client's, layer 2).
    ana.revoke_first(bot, true).await.expect("revoke");
    let step = ana.rotation_step(bot).await.expect("one step");
    assert!(step.rotated.is_some() && !step.done, "{step:?}");
    drop(ana);

    let _stop = daemon(&home).await;
    // Locked: nothing is known yet (the record is sealed).
    assert!(status(&home).await.revocations.is_empty());

    // The unlock says what is left, and resumes it by itself (P11).
    let unlocked = unlock(&home).await;
    let bot_left = unlocked
        .revocations
        .iter()
        .find(|r| r.agent_id == bot)
        .unwrap_or_else(|| panic!("no progress for bot: {:?}", unlocked.revocations));
    assert_eq!(bot_left.name.as_deref(), Some("bot"));
    assert_eq!(bot_left.projects, 6);
    assert!(bot_left.rotated >= 1, "{bot_left:?}");

    // Locking stops it; `status` still says what is left, while locked.
    let locked: DaemonStatus = call(&home, Request::Lock).await.expect("lock");
    assert!(!locked.unlocked);
    let while_locked = status(&home).await;
    // Five projects with items to re-wrap and grants to issue do not all
    // finish before the lock arrives.
    let left = while_locked
        .revocations
        .iter()
        .find(|r| r.agent_id == bot)
        .unwrap_or_else(|| panic!("nothing left while locked: {while_locked:?}"));
    assert!(!left.running, "{left:?}");
    assert!(left.rotated < left.projects, "{left:?}");
    // Locked, only the counts: no name, no error that could name a vault
    // or project.
    assert!(left.name.is_none() && left.last_error.is_none(), "{left:?}");
    let text = serde_json::to_string(&while_locked).expect("json");
    for name in names {
        assert!(!text.contains(name), "{text}");
    }

    // Unlocked again, it finishes without being asked; meanwhile, each
    // request waits for one project at most, not for the whole change.
    unlock(&home).await;
    let pending: Vec<PendingRevocation> = call(&home, Request::AgentRevocations)
        .await
        .expect("revocations");
    let bot_pending = pending
        .iter()
        .find(|p| p.agent_id == bot)
        .unwrap_or_else(|| panic!("bot is not pending: {pending:?}"));
    assert!(!bot_pending.pending.is_empty(), "{bot_pending:?}");
    let items: Vec<ItemSummary> = call(
        &home,
        Request::List {
            filter: ItemFilter::default(),
        },
    )
    .await
    .expect("the vault answers while keys change");
    assert_eq!(items.len(), 18);
    let meanwhile = status(&home).await;
    let still = meanwhile
        .revocations
        .iter()
        .find(|r| r.agent_id == bot)
        .unwrap_or_else(|| panic!("the change ended before the list: {meanwhile:?}"));
    assert!(still.running, "{still:?}");
    finished(&home).await;
    let pending: Vec<PendingRevocation> = call(&home, Request::AgentRevocations)
        .await
        .expect("revocations");
    assert!(pending.is_empty(), "{pending:?}");

    // Every project rotated once: asking again rotates nothing.
    let report: RevokeReport = call(
        &home,
        Request::RevokeAgent {
            agent: bot,
            rotate: true,
            background: false,
        },
    )
    .await
    .expect("revoke again");
    assert!(report.complete(), "{report:?}");
    assert!(report.rotated.is_empty(), "{report:?}");
    assert_eq!(report.already_rotated.len(), 6, "{report:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn revoking_through_klavd_rotates_every_project_and_says_so() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (home, mut ana) = account(&server, &root).await;
    projects(&mut ana, &["General", "Work", "Home"]).await;
    let all = ["Personal/General", "Personal/Work", "Personal/Home"];
    let bot = agent(&server, &root, &mut ana, "bot", &all).await;
    let quiet = agent(&server, &root, &mut ana, "quiet", &all).await;
    agent(&server, &root, &mut ana, "keeper", &all).await;
    drop(ana);
    let _stop = daemon(&home).await;
    unlock(&home).await;

    // Without a key change: revoked, and nothing pending anywhere.
    let report: RevokeReport = call(
        &home,
        Request::RevokeAgent {
            agent: quiet,
            rotate: false,
            background: false,
        },
    )
    .await
    .expect("revoke");
    assert!(report.complete() && report.rotated.is_empty());
    assert!(status(&home).await.revocations.is_empty());

    // The apps' two calls (F2): the revocation alone, then the key change.
    let first: RevokeReport = call(
        &home,
        Request::RevokeAgent {
            agent: bot,
            rotate: false,
            background: false,
        },
    )
    .await
    .expect("revoke");
    assert_eq!(first.agent.status, klav_proto::agent::AgentStatus::Revoked);
    let second: RevokeReport = call(
        &home,
        Request::RevokeAgent {
            agent: bot,
            rotate: true,
            background: false,
        },
    )
    .await
    .expect("key change");
    assert!(second.complete(), "{second:?}");
    assert_eq!(second.rotated.len(), 3, "{second:?}");
    assert_eq!(second.regranted, vec!["keeper".to_owned()], "{second:?}");
    assert!(status(&home).await.revocations.is_empty());
    let pending: Vec<PendingRevocation> = call(&home, Request::AgentRevocations)
        .await
        .expect("revocations");
    assert!(pending.is_empty(), "{pending:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_change_in_the_background_is_written_down_before_the_reply_and_survives_a_lock() {
    // Older callers send the same bytes as before.
    let plain = serde_json::to_string(&Request::RevokeAgent {
        agent: klav_core::ids::AgentId::from_bytes([7; 16]),
        rotate: true,
        background: false,
    })
    .expect("json");
    assert!(!plain.contains("background"), "{plain}");

    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (home, mut ana) = account(&server, &root).await;
    let names = ["General", "Work", "Home", "Bank", "Travel", "Health"];
    projects(&mut ana, &names).await;
    let all: Vec<String> = names.iter().map(|n| format!("Personal/{n}")).collect();
    let all: Vec<&str> = all.iter().map(String::as_str).collect();
    let bot = agent(&server, &root, &mut ana, "bot", &all).await;
    agent(&server, &root, &mut ana, "keeper", &all).await;
    drop(ana);
    let _stop = daemon(&home).await;
    unlock(&home).await;

    // The reply comes once the agent is revoked and the key change is
    // written down, before any project is rotated.
    let first: RevokeReport = call(
        &home,
        Request::RevokeAgent {
            agent: bot,
            rotate: true,
            background: true,
        },
    )
    .await
    .expect("revoke");
    assert_eq!(first.agent.status, klav_proto::agent::AgentStatus::Revoked);
    assert!(first.failed.is_none(), "{first:?}");
    assert!(first.rotated.is_empty(), "{first:?}");
    assert_eq!(first.pending.len(), 6, "{first:?}");

    // A lock right away (the app quits, the Mac sleeps): the request is
    // already in the record, so the next unlock resumes it (P11).
    let locked: DaemonStatus = call(&home, Request::Lock).await.expect("lock");
    assert!(!locked.unlocked);
    unlock(&home).await;
    finished(&home).await;
    let pending: Vec<PendingRevocation> = call(&home, Request::AgentRevocations)
        .await
        .expect("revocations");
    assert!(pending.is_empty(), "{pending:?}");

    // Every project's key changed once: asking again rotates nothing.
    let again: RevokeReport = call(
        &home,
        Request::RevokeAgent {
            agent: bot,
            rotate: true,
            background: false,
        },
    )
    .await
    .expect("revoke again");
    assert!(again.complete(), "{again:?}");
    assert!(again.rotated.is_empty(), "{again:?}");
    assert_eq!(again.already_rotated.len(), 6, "{again:?}");
}
