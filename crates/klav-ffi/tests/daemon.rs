//! `DaemonEngine` (the Mac app's engine, ADR 0027 §3) against a real
//! `klavd` on a real server: the app signs up with `KlavCore`, lets go of
//! the account and asks `klavd` to unlock; then it reads, edits, approves
//! an agent and locks through the socket, and sees `klavd` stop.
//!
//! `klavd` runs inside this test process on a home in a temporary
//! directory, with Touch ID off: nothing touches the real `KLAV_HOME`.

#![cfg(feature = "daemon")]

mod common;

use std::time::Duration;

use common::ServerProcess;
use klav_core::crypto::identity::IdentityKeyPair;
use klav_core::ids::AgentId;
use klav_ffi::{
    ChangeKind, DaemonEngine, FieldEdit, FieldType, GrantChangeInput, GrantEditorInfo, ItemEdit,
    ItemQuery, Kind, KlavCore, KlavError, LogFilterInput, NewItemInput, OfferInput,
    PermissionSettingInput, ReadOnlyKind,
};
use klav_proto::Blob;
use klav_proto::agent::RegisterAgent;

const PASSWORD: &str = "correct horse battery staple";
const SECRET: &str = "MARKER-daemon-engine-password-41";
const TOTP: &str = "JBSWY3DPEHPK3PXP";

/// A `klavd` for `home` on its own runtime, stopped when dropped.
struct Daemon {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Daemon {
    fn start(home: &std::path::Path) -> Self {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let home = klav_client::Home::at(home);
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
                presence_gate: false,
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

    /// Waits until `klavd` stopped by itself (`shutdown`).
    fn join(mut self) {
        if let Some(thread) = self.thread.take() {
            thread.join().expect("klavd thread");
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
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

fn register_agent(server: &str, email: &str) -> (AgentId, String) {
    let keys = IdentityKeyPair::generate();
    let id = AgentId::generate();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test setup");
    let status = rt.block_on(async {
        reqwest::Client::new()
            .post(format!("{server}/v1/agents/register"))
            .json(&RegisterAgent {
                id,
                email: email.into(),
                name: "mac-agent".into(),
                public_identity: Blob::new(keys.public().encode().to_vec()),
                note: None,
            })
            .send()
            .await
            .expect("test setup")
            .status()
    });
    assert_eq!(status.as_u16(), 202);
    (id, klav_core::crypto::agent::pairing_code(keys.public()))
}

fn all_items() -> ItemQuery {
    ItemQuery {
        vault_id: None,
        project_id: None,
        kind: None,
        kinds: Vec::new(),
        codes: false,
        text: None,
        trash: false,
    }
}

#[test]
fn the_mac_app_works_through_klavd() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("klav");
    let home_str = home.display().to_string();
    let engine = DaemonEngine::new(home_str.clone()).expect("engine");

    // No klavd yet: the app sees it as not running, not as an error.
    let status = engine.status();
    assert!(!status.running && !status.logged_in);
    assert!(matches!(
        engine.vaults(),
        Err(KlavError::DaemonUnavailable { .. })
    ));

    // The LaunchAgent's klavd runs before there is an account (ADR 0027
    // §4): it answers, signed out, and sees the account the app makes.
    let daemon = Daemon::start(&home);
    wait_until("klavd", || engine.status().running);
    assert!(!engine.status().logged_in);

    // Sign up in the app's process, as `klav signup`, then let go.
    let core = KlavCore::new(home_str.clone()).expect("core");
    let kit = core
        .sign_up(
            server.url.clone(),
            "mac@example.com".into(),
            PASSWORD.into(),
            "Mac de prueba".into(),
        )
        .expect("sign up");
    assert!(kit.contains("Secret Key: K1-"));
    assert!(kit.contains("mac@example.com"));
    drop(kit);
    assert!(core.status().unlocked);
    core.lock();
    drop(core);

    let status = engine.status();
    assert!(status.logged_in && !status.unlocked);
    assert_eq!(status.email.as_deref(), Some("mac@example.com"));
    assert!(status.version.is_some());
    assert!(matches!(engine.vaults(), Err(KlavError::Locked)));

    // Touch ID is off in this klavd: the app falls back to the password.
    assert!(matches!(
        engine.unlock(None, None),
        Err(KlavError::BiometryUnavailable { .. })
    ));
    assert!(matches!(
        engine.unlock(Some("wrong password".into()), None),
        Err(KlavError::WrongCredentials)
    ));
    engine.unlock(Some(PASSWORD.into()), None).expect("unlock");
    let status = engine.status();
    assert!(status.unlocked);
    assert_eq!(status.unlocked_with.as_deref(), Some("password"));

    let vaults = engine.vaults().expect("vaults");
    assert_eq!(vaults.len(), 1);
    let projects = engine
        .projects(Some(vaults[0].id.clone()))
        .expect("projects");
    assert!(!projects.is_empty());

    // Create, read without values, reveal one field, code, edit, history.
    let login = |title: &str, fields: Vec<FieldEdit>| NewItemInput {
        kind: Kind::Login,
        title: title.into(),
        vault_id: None,
        project_id: None,
        fields,
        urls: vec!["https://github.com".into()],
        tags: Vec::new(),
        notes: Some("recovery codes in the safe".into()),
    };
    let field = |name: &str, value: &str, kind: FieldType| FieldEdit {
        name: name.into(),
        value: value.into(),
        kind: Some(kind),
    };
    let created = engine
        .create_item(login(
            "GitHub",
            vec![
                field("username", "ana", FieldType::Username),
                field("password", SECRET, FieldType::Password),
                field("totp", TOTP, FieldType::Totp),
            ],
        ))
        .expect("create");
    // A repeated title is refused, as everywhere else.
    assert!(engine.create_item(login("GitHub", Vec::new())).is_err());
    let items = engine
        .items(ItemQuery {
            text: Some("git".into()),
            ..all_items()
        })
        .expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].id, created.id);
    assert_eq!(items[0].username.as_deref(), Some("ana"));

    let detail = engine.item(created.id.clone()).expect("item");
    assert!(detail.has_totp);
    assert!(
        detail
            .fields
            .iter()
            .all(|f| f.value.as_deref() != Some(SECRET)),
        "item() must not carry secret values"
    );
    assert_eq!(
        engine
            .field_value(created.id.clone(), "password".into())
            .expect("reveal"),
        SECRET
    );
    assert!(matches!(
        engine.field_value(created.id.clone(), "nope".into()),
        Err(KlavError::NotFound { .. })
    ));
    assert_eq!(
        engine.notes(created.id.clone()).expect("notes").as_deref(),
        Some("recovery codes in the safe")
    );
    let code = engine.totp(created.id.clone()).expect("totp");
    assert_eq!(code.code.len(), 6);
    assert!(code.remaining <= 30 && code.period == 30);

    engine
        .edit_item(
            created.id.clone(),
            ItemEdit {
                title: None,
                set: vec![FieldEdit {
                    name: "password".into(),
                    value: "new-password-of-the-test".into(),
                    kind: None,
                }],
                remove: Vec::new(),
                add_urls: Vec::new(),
                remove_urls: Vec::new(),
                add_tags: Vec::new(),
                notes: None,
            },
        )
        .expect("edit");
    let history = engine
        .password_history(created.id.clone())
        .expect("history");
    assert_eq!(history.entries.len(), 1);
    assert_eq!(
        engine
            .previous_password(created.id.clone(), history.entries[0].index)
            .expect("previous"),
        SECRET
    );

    // The generator history goes through klavd too.
    let at = engine
        .record_generated(
            "generated-in-the-mac-app".into(),
            Some("https://example.com/x".into()),
        )
        .expect("record");
    let entries = engine.generator_history().expect("generator history");
    assert!(entries.iter().any(|e| e.created_at == at));
    assert_eq!(
        engine.generated_value(at).expect("value"),
        "generated-in-the-mac-app"
    );
    assert!(engine.clear_generator_history().expect("clear") >= 1);

    // Health and its setting.
    engine.vault_health().expect("health");
    assert!(!engine.health_settings().expect("settings").breach_check);
    assert!(engine.set_breach_check(true).expect("on").breach_check);
    assert!(!engine.set_breach_check(false).expect("off").breach_check);

    // An agent registers; Touch ID is off, so approving needs the password.
    assert!(engine.approvals().expect("approvals").is_empty());
    assert!(engine.tasks().expect("tasks").is_empty());
    let (agent, words) = register_agent(&server.url, "mac@example.com");
    let agents = engine.agents().expect("agents");
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].status, "pending");
    assert_eq!(agents[0].pairing_words, words);
    let project = projects[0].id.clone();
    assert!(matches!(
        engine.approve_agent(
            agent.to_string(),
            words.clone(),
            vec![project.clone()],
            Some(7)
        ),
        Err(KlavError::BiometryUnavailable { .. })
    ));
    let approved = engine
        .approve_agent_with_password(
            agent.to_string(),
            words,
            vec![project],
            Some(7),
            Some(PASSWORD.into()),
        )
        .expect("approve agent");
    assert_eq!(approved.status, "active");
    assert_eq!(approved.projects.len(), 1);

    // «Activity» (ADR 0033 §8): the log through klavd, its filters, and
    // what is verified. Nothing is verified on this Mac yet.
    let log = engine
        .audit_log(LogFilterInput::default())
        .expect("activity");
    assert!(log.iter().any(|l| l.action == "agent.granted"), "{log:?}");
    assert!(log.iter().all(|l| !l.verified));
    let status = engine.audit_status().expect("status");
    assert!(status.events >= u64::try_from(log.len()).expect("len"));
    assert_eq!((status.verified, status.unverified), (None, status.events));
    let report = engine.verify_audit().expect("verify");
    assert_eq!(report.events, status.events);
    assert_eq!(report.signed_head, Some(status.events));
    let status = engine.audit_status().expect("status");
    assert_eq!(
        (status.verified, status.unverified),
        (Some(status.events), 0)
    );
    let registered = engine
        .audit_log(LogFilterInput {
            text: Some("MAC-AGENT".into()),
            limit: Some(1),
            ..LogFilterInput::default()
        })
        .expect("activity");
    assert_eq!(registered.len(), 1);
    assert_eq!(registered[0].action, "agent.registered");
    assert!(registered[0].verified && registered[0].actor == "mac-agent");
    assert!(
        engine
            .audit_log(LogFilterInput {
                permissions: vec!["fill".into()],
                ..LogFilterInput::default()
            })
            .expect("activity")
            .is_empty()
    );
    assert!(matches!(
        engine.audit_log(LogFilterInput {
            permissions: vec!["peek".into()],
            ..LogFilterInput::default()
        }),
        Err(KlavError::Invalid { .. })
    ));
    // «Who used it»: no agent touched GitHub.
    let used = engine
        .item_activity(created.id.clone())
        .expect("who used it");
    assert_eq!(used.item_id, created.id);
    assert!(used.uses.is_empty() && !used.trashed && !used.deleted);

    // «Pause agents» (ADR 0033 §7): at once, then resumed with the
    // password (Touch ID is off here).
    assert!(engine.status().agents_paused.is_empty());
    let paused = engine.pause_agents(None, None).expect("pause");
    assert_eq!(paused.len(), 1);
    assert!(
        paused[0].agent_id.is_none() && !paused[0].local,
        "{paused:?}"
    );
    assert_eq!(engine.status().agents_paused.len(), 1);
    engine.sync().expect("sync");
    let dev = engine.dev_agents().expect("dev agents");
    let bot = dev
        .iter()
        .find(|a| a.agent.id == agent.to_string())
        .expect("bot");
    assert!(bot.paused.as_ref().is_some_and(|p| p.everyone), "{bot:?}");
    assert!(bot.approved_ms.is_some());
    assert!(matches!(
        engine.resume_agents(None),
        Err(KlavError::BiometryUnavailable { .. })
    ));
    let left = engine
        .resume_agents_with_password(None, Some(PASSWORD.into()))
        .expect("resume");
    assert!(left.is_empty(), "{left:?}");
    assert!(engine.status().agents_paused.is_empty());
    assert!(matches!(
        engine.pause_agents(Some("not-an-id".into()), None),
        Err(KlavError::Invalid { .. })
    ));

    // «Fix my reused passwords» from the Mac (ADR 0022 §6): two logins
    // share a password, the approved agent can take them, and offering
    // asks for presence (the password here, Touch ID being off).
    let twin = engine
        .create_item(NewItemInput {
            urls: vec!["https://gitea.example.com".into()],
            notes: None,
            ..login(
                "Gitea",
                vec![field(
                    "password",
                    "new-password-of-the-test",
                    FieldType::Password,
                )],
            )
        })
        .expect("create twin");
    let offer = engine.reused_offer(None).expect("reused offer");
    assert_eq!(
        offer.agent.as_ref().map(|a| a.id.clone()),
        Some(agent.to_string())
    );
    let mut offered: Vec<String> = offer
        .rows
        .iter()
        .filter(|r| r.blocked.is_none())
        .map(|r| r.item_id.clone())
        .collect();
    offered.sort();
    let mut expected = vec![created.id.clone(), twin.id.clone()];
    expected.sort();
    assert_eq!(offered, expected, "{offer:?}");
    let input = |items: Vec<String>| OfferInput {
        agent: agent.to_string(),
        items,
        task: Some("Change passwords".into()),
        reason: None,
        duration_secs: Some(15 * 60),
    };
    assert!(matches!(
        engine.offer_task_with_password(input(Vec::new()), Some(PASSWORD.into())),
        Err(KlavError::Invalid { .. })
    ));
    assert!(matches!(
        engine.offer_task_with_password(input(offered.clone()), None),
        Err(KlavError::BiometryUnavailable { .. })
    ));
    assert!(matches!(
        engine.offer_task_with_password(input(offered.clone()), Some("wrong password".into())),
        Err(KlavError::WrongCredentials)
    ));
    let task = engine
        .offer_task_with_password(input(offered.clone()), Some(PASSWORD.into()))
        .expect("offer");
    assert!(task.offered && task.status == "approved", "{task:?}");
    let progress = engine.task_progress(task.id.clone()).expect("progress");
    assert_eq!(progress.task_id, task.id);
    assert_eq!(progress.sites.len(), 2);
    assert!(
        progress
            .sites
            .iter()
            .all(|s| s.state == "pending" && !s.started),
        "{progress:?}"
    );
    engine.end_task(task.id).expect("end task");
    engine.trash_item(twin.id).expect("trash twin");

    changes_and_revokes_the_agent(&engine, &agent.to_string());

    engine.trash_item(created.id.clone()).expect("trash");
    assert!(engine.items(all_items()).expect("items").is_empty());

    // Locking in the app locks klavd, for the CLI and the extension too.
    engine.lock().expect("lock");
    assert!(!engine.status().unlocked);
    assert!(matches!(engine.items(all_items()), Err(KlavError::Locked)));

    // `shutdown` stops it (the LaunchAgent would start the new one).
    engine.shutdown().expect("shutdown");
    daemon.join();
    let status = engine.status();
    assert!(!status.running && status.logged_in);
}

/// The editor's change that leaves `editor` as it is.
fn unchanged(editor: &GrantEditorInfo) -> GrantChangeInput {
    let policy = editor.editor.clone().expect("editable");
    GrantChangeInput {
        project_ids: editor
            .projects
            .iter()
            .map(|p| p.project_id.clone())
            .collect(),
        permissions: policy
            .permissions
            .into_iter()
            .map(|p| PermissionSettingInput {
                permission: p.permission,
                effect: p.effect,
            })
            .collect(),
        fill_sites: policy.fill_sites,
        hours: policy.hours,
        expires_at_secs: policy.expires_at_secs,
        rotate_removed: false,
    }
}

fn with(mut change: GrantChangeInput, permission: &str, effect: &str) -> GrantChangeInput {
    change.permissions.retain(|p| p.permission != permission);
    change.permissions.push(PermissionSettingInput {
        permission: permission.into(),
        effect: Some(effect.into()),
    });
    change
}

/// The amendment of 2026-11-10 (F5) through `DaemonEngine`: the grant in
/// the editor, a change that narrows (no presence) and one that widens
/// (the password here, Touch ID being off), a stale sheet that is not
/// signed, then «what it saw» and revoking in two calls.
fn changes_and_revokes_the_agent(engine: &DaemonEngine, agent: &str) {
    let editor = engine.grant_editor(agent.into()).expect("grant editor");
    assert!(editor.editable && editor.read_only.is_none(), "{editor:?}");
    assert_eq!(editor.projects.len(), 1);
    assert!(editor.expires_at_secs.is_some(), "approved for 7 days");
    let policy = editor.editor.clone().expect("the editor's model");
    assert_eq!(policy.permissions.len(), 8);
    assert!(policy.permissions.iter().all(|p| p.effect.is_none()));

    // Nothing changed: klavd signs nothing.
    assert!(
        engine
            .grant_change_prepare(agent.into(), unchanged(&editor))
            .is_err()
    );

    // Narrowing: no presence (P8).
    let narrow = with(unchanged(&editor), "fill", "deny");
    let sheet = engine
        .grant_change_prepare(agent.into(), narrow.clone())
        .expect("prepare narrowing");
    assert!(!sheet.widens, "{sheet:?}");
    assert_eq!(sheet.version, editor.version + 1);
    assert!(
        matches!(
            sheet.lines.as_slice(),
            [line] if !line.widens && line.kind == ChangeKind::Permission {
                permission: "fill".into(),
                before: "allow".into(),
                before_default: true,
                after: "deny".into(),
                after_default: false,
            }
        ),
        "{sheet:?}"
    );
    let report = engine
        .grant_change_apply(agent.into(), narrow.clone(), sheet.digest)
        .expect("narrowing asks for nothing");
    assert!(
        report.complete && report.agent.status == "active",
        "{report:?}"
    );

    // Widening: Touch ID is off, so the password; a stale sheet is not
    // signed.
    let editor = engine.grant_editor(agent.into()).expect("grant editor");
    let wide = with(unchanged(&editor), "reveal", "ask");
    let sheet = engine
        .grant_change_prepare(agent.into(), wide.clone())
        .expect("prepare widening");
    assert!(
        sheet.widens && sheet.lines.iter().all(|l| l.widens),
        "{sheet:?}"
    );
    assert!(matches!(
        engine.grant_change_apply(agent.into(), wide.clone(), sheet.digest.clone()),
        Err(KlavError::BiometryUnavailable { .. })
    ));
    assert!(matches!(
        engine.grant_change_apply_with_password(
            agent.into(),
            wide.clone(),
            "0".repeat(64),
            Some(PASSWORD.into()),
        ),
        Err(KlavError::Security { .. })
    ));
    let report = engine
        .grant_change_apply_with_password(agent.into(), wide, sheet.digest, Some(PASSWORD.into()))
        .expect("widening with the password");
    assert!(report.complete, "{report:?}");
    let editor = engine.grant_editor(agent.into()).expect("grant editor");
    let effects: Vec<(String, Option<String>)> = editor
        .editor
        .expect("still editable")
        .permissions
        .into_iter()
        .filter(|p| p.effect.is_some())
        .map(|p| (p.permission, p.effect))
        .collect();
    assert_eq!(
        effects,
        [
            ("fill".to_owned(), Some("deny".to_owned())),
            ("reveal".to_owned(), Some("ask".to_owned())),
        ]
    );

    // «What it saw», then revoking as the app does: klavd answers once the
    // agent is revoked and the key change written down, and changes the
    // keys in the background.
    let seen = engine.agent_exposure(agent.into()).expect("exposure");
    assert_eq!(seen.projects.len(), 1);
    assert!(!seen.projects_unknown);
    assert!(seen.cost.other_agents.is_empty());
    assert!(
        !seen.cost.items_at_least && !seen.cost.others_at_least,
        "{:?}",
        seen.cost
    );
    let revoked = engine
        .revoke_agent_in_background(agent.into())
        .expect("revoke")
        .expect("this klavd knows it");
    assert_eq!(revoked.agent.status, "revoked");
    assert!(revoked.failed.is_none(), "{revoked:?}");
    wait_until("the key change", || {
        engine
            .status()
            .revocations
            .iter()
            .all(|r| r.agent_id != agent)
    });
    let done = engine
        .revoke_agent(agent.into(), true)
        .expect("asked again");
    assert!(done.complete, "{done:?}");
    assert!(done.rotated.is_empty(), "{done:?}");
    assert_eq!(done.already_rotated.len(), 1, "{done:?}");
    assert!(engine.agent_revocations().expect("revocations").is_empty());
    assert!(engine.status().revocations.is_empty());
    let after = engine.grant_editor(agent.into()).expect("grant editor");
    assert!(!after.editable);
    assert_eq!(after.read_only, Some(ReadOnlyKind::NotActive));
}

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("ms")
}

/// Moves the deletion of every account to `at`, in the server's SQLite
/// database. `false` without the `sqlite3` program, which says so.
#[allow(clippy::print_stderr)]
fn move_delete_at(server: &ServerProcess, at: i64) -> bool {
    let sql = format!("PRAGMA busy_timeout = 5000; UPDATE account_deletions SET delete_at = {at};");
    match std::process::Command::new("sqlite3")
        .arg(server.dir.path().join("klav.db"))
        .arg(sql)
        .output()
    {
        Ok(out) => {
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            true
        }
        Err(_) => {
            eprintln!("no sqlite3 here: the deleted account is not checked");
            false
        }
    }
}

/// Deleting the account from the Mac app (ADR 0037, layer 5): the request
/// runs in the app's process, `klavd` only confirms Touch ID where it is
/// set up and learns the deletion at once; cancel asks for presence, the
/// master password here; after the purge the copy stays, read-only, until
/// «Delete this Mac’s copy».
#[test]
fn the_mac_app_asks_to_delete_the_account_and_klavd_learns_it() {
    let mut server = ServerProcess::start_purging();
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("klav");
    let home_str = home.display().to_string();
    let engine = DaemonEngine::new(home_str.clone()).expect("engine");
    let daemon = Daemon::start(&home);
    wait_until("klavd", || engine.status().running);
    let core = KlavCore::new(home_str).expect("core");
    drop(
        core.sign_up(
            server.url.clone(),
            "mac@example.com".into(),
            PASSWORD.into(),
            "Mac de Ana".into(),
        )
        .expect("sign up"),
    );
    core.lock();
    drop(core);
    assert!(engine.deletion_supported().expect("health"));
    assert_eq!(engine.status().account_deletion, None);

    // T162: Touch ID is set up for this home and klavd cannot confirm it
    // (here it is off; on a Mac, locked out or with the lid closed). The
    // request is refused before the password, not left to the password.
    let enrolment = home.join(klav_daemon::client::TOUCH_ID_FILE);
    std::fs::write(&enrolment, b"{}").expect("test setup");
    assert!(!engine.status().touch_id_enrolled, "klavd says unavailable");
    assert!(matches!(
        engine.request_account_deletion(PASSWORD.into()),
        Err(KlavError::BiometryUnavailable { .. })
    ));
    std::fs::remove_file(&enrolment).expect("test setup");
    // A wrong password, with klavd locked: refused here.
    assert!(matches!(
        engine.request_account_deletion("wrong password".into()),
        Err(KlavError::WrongCredentials)
    ));

    // Unlocked, klavd learns the request at once: nothing was asked
    // before, then 7 days from this Mac.
    engine.unlock(Some(PASSWORD.into()), None).expect("unlock");
    engine.sync().expect("sync");
    assert_eq!(engine.status().account_deletion, None);
    let asked = engine
        .request_account_deletion(PASSWORD.into())
        .expect("ask");
    assert_eq!(asked.delete_at - asked.requested_at, 7 * 24 * 3600 * 1000);
    assert!(asked.this_device);
    assert_eq!(asked.device_name, "Mac de Ana");
    let status = engine.status();
    assert_eq!(status.account_deletion, Some(asked));
    assert!(!status.account_deleted);

    // Cancel asks what resuming agents asks (ADR 0037 A2). Touch ID is off
    // in this klavd, so it can't confirm: nothing is canceled, and the app
    // asks for the master password. A wrong one cancels nothing either.
    assert!(matches!(
        engine.cancel_account_deletion(),
        Err(KlavError::BiometryUnavailable { .. })
    ));
    assert!(matches!(
        engine.cancel_account_deletion_with_password(Some("wrong password".into())),
        Err(KlavError::WrongCredentials)
    ));
    assert!(engine.status().account_deletion.is_some());
    assert!(
        engine
            .cancel_account_deletion_with_password(Some(PASSWORD.into()))
            .expect("cancel")
    );
    assert_eq!(engine.status().account_deletion, None);
    assert!(
        !engine
            .cancel_account_deletion_with_password(Some(PASSWORD.into()))
            .expect("nothing left")
    );
    // Locked, klavd has no session to cancel with: unlock first.
    engine.lock().expect("lock");
    assert!(matches!(
        engine.cancel_account_deletion_with_password(Some(PASSWORD.into())),
        Err(KlavError::Locked)
    ));

    // Asked again from a locked klavd: it learns at its next sync.
    let asked = engine
        .request_account_deletion(PASSWORD.into())
        .expect("ask locked");
    engine.unlock(Some(PASSWORD.into()), None).expect("unlock");
    engine.sync().expect("sync");
    assert_eq!(engine.status().account_deletion, Some(asked));

    // The time comes in a few seconds; klavd syncs before it.
    let delete_at = now_ms() + 4_000;
    if !move_delete_at(&server, delete_at) {
        return;
    }
    engine.sync().expect("sync before the purge");
    assert!(now_ms() < delete_at, "too slow: the sync must come first");
    // Then, offline, the extension's generator records a password through
    // klavd: it waits in the outbox. klavd locks before the server comes
    // back, so it never uploads it: the site has it, the account doesn't.
    server.stop();
    engine
        .record_generated(
            "generated offline".into(),
            Some("https://example.com".into()),
        )
        .expect("queued");
    let outbox = home.join("generator-outbox.bin");
    assert!(outbox.exists(), "the generated password waits");
    engine.lock().expect("lock");
    while now_ms() <= delete_at {
        std::thread::sleep(Duration::from_millis(100));
    }
    server.restart();
    wait_until_long("the purge", || account_count(&server) == 0);
    engine.unlock(Some(PASSWORD.into()), None).expect("unlock");
    wait_until_long("klavd learns it", || {
        let _ = engine.sync();
        engine.status().account_deleted
    });
    let status = engine.status();
    assert_eq!(
        status.account_deletion.map(|d| d.delete_at),
        Some(delete_at),
        "the date stays, for «Klav deleted your account»"
    );
    // T165: nothing deleted the copy; klavd still reads it.
    assert!(status.unlocked && status.logged_in);
    assert_eq!(engine.vaults().expect("vaults").len(), 1);

    // D-C: klavd writes nothing more (S1 of the re-review). The generator
    // records nothing, and what waits stays, unsent: klavd no longer
    // tries to upload it. The history still reads, to copy it.
    let refused = engine.record_generated("generated after the purge".into(), None);
    assert!(
        matches!(refused, Err(KlavError::AccountDeleted { .. })),
        "generator: {refused:?}"
    );
    let history = engine.generator_history().expect("history");
    assert_eq!(history.len(), 1);
    assert!(history[0].pending, "never uploaded");
    assert_eq!(
        engine
            .generated_value(history[0].created_at)
            .expect("copy it"),
        "generated offline"
    );
    // Nor does `reset_cache` empty the copy it could never fill again.
    let reset = reset_cache(&home);
    assert_eq!(
        reset.map_err(|e| e.code),
        Err(klav_daemon::protocol::ErrorCode::AccountDeleted)
    );
    assert_eq!(engine.vaults().expect("vaults").len(), 1);
    std::thread::sleep(Duration::from_secs(5));
    assert!(outbox.exists(), "still waiting, for the person");

    // «Delete this Mac’s copy» (Q3 of the re-review): the generated
    // password that never went up is only here. Klav says how many and
    // refuses before klavd stops, so the app can still list them to copy.
    let check = engine.delete_copy_check().expect("check");
    assert_eq!(
        (check.unsent_generated, check.locked_with_queue),
        (1, false)
    );
    let refused = engine.delete_this_copy(false);
    assert!(
        matches!(refused, Err(KlavError::Denied { .. })),
        "{refused:?}"
    );
    assert!(engine.status().running && engine.status().logged_in);
    assert!(outbox.exists(), "nothing deleted");
    // Locked, klavd can't list them: any outbox file is too many.
    engine.lock().expect("lock");
    let check = engine.delete_copy_check().expect("check");
    assert_eq!((check.unsent_generated, check.locked_with_queue), (0, true));
    assert!(matches!(
        engine.delete_this_copy(false),
        Err(KlavError::Denied { .. })
    ));
    assert!(engine.status().running, "klavd keeps running");

    // «Delete anyway»: klavd stops and the account's files go, the outbox
    // with them.
    engine.delete_this_copy(true).expect("delete the copy");
    daemon.join();
    let status = engine.status();
    assert!(!status.running && !status.logged_in);
    for name in [
        "account.json",
        "cache.bin",
        "session.bin",
        "secret-key",
        "deletion.bin",
        "account-deletion.json",
        "generator-outbox.bin",
    ] {
        assert!(!home.join(name).exists(), "{name} is left");
    }
}

/// Accounts left in the server's SQLite database.
fn account_count(server: &ServerProcess) -> u64 {
    let out = std::process::Command::new("sqlite3")
        .args(["-cmd", ".timeout 5000"])
        .arg(server.dir.path().join("klav.db"))
        .arg("SELECT count(*) FROM accounts;")
        .output()
        .expect("sqlite3");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("a count")
}

/// `reset_cache`, straight to `klavd` (the app has no button for it).
fn reset_cache(
    home: &std::path::Path,
) -> Result<serde_json::Value, klav_daemon::protocol::ErrorBody> {
    let home = klav_client::Home::at(home);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test setup")
        .block_on(async {
            let mut client = klav_daemon::client::DaemonClient::connect(&home)
                .await
                .expect("klavd");
            client
                .call::<serde_json::Value>(klav_daemon::protocol::Request::ResetCache)
                .await
                .map(|(answer, _)| answer)
        })
}

fn wait_until_long(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("timed out waiting for {what}");
}

/// «Sandboxes» on the Mac (ADR 0036 E2.1, E2.3): `klavd` lists the
/// account's sandboxes with the proxy's heartbeat and signs the person's
/// revocations, one and all, without Touch ID.
#[test]
fn the_mac_app_lists_and_revokes_sandboxes_through_klavd() {
    use klav_ffi::{SandboxRevokeInfo, SandboxStatusInfo};
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("klav");
    let made = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test setup")
        .block_on(common::sandboxes::setup(&server, &home, "mac@example.com"));
    let (proxy, claimed, waiting) = (
        made.proxy.to_string(),
        made.claimed.to_string(),
        made.waiting.to_string(),
    );
    let engine = DaemonEngine::new(home.display().to_string()).expect("engine");
    let _daemon = Daemon::start(&home);
    wait_until("klavd", || engine.status().running);
    assert!(matches!(engine.sandbox_list(false), Err(KlavError::Locked)));
    engine
        .unlock(Some(common::sandboxes::PASSWORD.into()), None)
        .expect("unlock");

    let list = engine.sandbox_list(false).expect("list");
    let view = list.proxy.expect("proxy");
    assert_eq!(
        (view.agent_id.as_str(), view.no_signs),
        (proxy.as_str(), None)
    );
    let rows: Vec<_> = list
        .sandboxes
        .iter()
        .map(|s| (s.sandbox_id.clone(), s.status, s.connected))
        .collect();
    assert_eq!(
        rows,
        [
            (claimed.clone(), SandboxStatusInfo::Active, Some(true)),
            (waiting.clone(), SandboxStatusInfo::Waiting, None),
        ]
    );

    let one = engine
        .revoke_sandbox(proxy.clone(), claimed.clone())
        .expect("revoke");
    assert!(
        matches!(&one, SandboxRevokeInfo::Revoked { scope, .. } if *scope == claimed),
        "{one:?}"
    );
    let all = engine.revoke_all_sandboxes(proxy.clone()).expect("all");
    assert!(
        matches!(&all, SandboxRevokeInfo::Revoked { scope, sandbox_ids, .. }
            if scope == "all" && sandbox_ids.contains(&waiting)),
        "{all:?}"
    );
    let list = engine.sandbox_list(false).expect("list");
    assert!(
        list.sandboxes
            .iter()
            .all(|s| s.status == SandboxStatusInfo::Revoking)
    );
    assert!(matches!(
        engine.revoke_sandbox(proxy, "nope".into()),
        Err(KlavError::Invalid { .. })
    ));
}

/// A stand-in `klavd` that answers each request of the list with `reply`
/// (by op), echoing its `id`, `n` times; returns the ops it got.
fn list_stand_in(
    engine: &DaemonEngine,
    n: usize,
    reply: fn(&str) -> serde_json::Value,
) -> std::thread::JoinHandle<Vec<String>> {
    let listener = std::os::unix::net::UnixListener::bind(engine.socket_path()).expect("socket");
    std::thread::spawn(move || {
        let mut ops = Vec::new();
        for _ in 0..n {
            let (stream, _) = listener.accept().expect("accept");
            let mut line = String::new();
            std::io::BufRead::read_line(&mut std::io::BufReader::new(&stream), &mut line)
                .expect("read");
            let request: serde_json::Value = serde_json::from_str(&line).expect("a line");
            let op = request["request"]["op"].as_str().unwrap_or("").to_owned();
            let mut answer = reply(&op);
            if answer["id"].is_null() {
                answer["id"] = request["id"].clone();
            }
            std::io::Write::write_all(&mut &stream, format!("{answer}\n").as_bytes())
                .expect("write");
            ops.push(op);
        }
        ops
    })
}

/// The flagged list on the Mac: a `klavd` that flags it gives the flag as
/// its own case. One older than the flag answers `bad_request`, so the
/// engine asks `sandbox_list`, whose `security` error stays an error:
/// never a list without the problem. The plain `sandbox_list` of this
/// build asks only `sandbox_list`, as an app that cannot show the flag.
#[test]
fn the_flagged_sandbox_list_shows_the_flag_or_fails_closed_on_an_older_klavd() {
    let home = tempfile::tempdir().expect("home");
    let engine = DaemonEngine::new(home.path().to_string_lossy().into_owned()).expect("engine");

    let newer = list_stand_in(&engine, 1, |_| {
        serde_json::json!({"v": 1, "ok": {
            "sandboxes": [], "verified_events": 2,
            "security": {"kind": "preferences_by_agent",
                         "agent_id": "6f1c2b8e-4d3a-4f5b-9c7d-1e2f3a4b5c6d"},
        }})
    });
    let list = engine.sandbox_list_flagged(false).expect("flagged");
    assert!(
        matches!(&list.security, Some(klav_ffi::SandboxSecurityInfo::PreferencesByAgent { agent_id, .. })
            if agent_id == "6f1c2b8e-4d3a-4f5b-9c7d-1e2f3a4b5c6d"),
        "{:?}",
        list.security
    );
    assert_eq!(newer.join().expect("newer"), ["sandbox_list_flagged"]);
    std::fs::remove_file(engine.socket_path()).expect("socket");

    let older = list_stand_in(&engine, 3, |op| match op {
        "sandbox_list" => serde_json::json!({"v": 1,
            "error": {"code": "security", "message": "SECURITY: the account's preferences were written by agent x"}}),
        _ => serde_json::json!({"v": 1, "id": 0,
            "error": {"code": "bad_request", "message": "malformed request"}}),
    });
    let flagged = engine.sandbox_list_flagged(false);
    assert!(
        matches!(flagged, Err(KlavError::Security { .. })),
        "{flagged:?}"
    );
    let plain = engine.sandbox_list(false);
    assert!(
        matches!(plain, Err(KlavError::Security { .. })),
        "{plain:?}"
    );
    assert_eq!(
        older.join().expect("older"),
        ["sandbox_list_flagged", "sandbox_list", "sandbox_list"]
    );
}

/// The checked list on the Mac: each check `klavd` names crosses typed,
/// with `klav-client`'s words apart; one this build does not know, or an
/// answer with neither a list nor a refusal, is still a refusal; the list
/// itself comes through. A `klavd` older than the op answers `bad_request`,
/// so the engine asks `sandbox_list_flagged`, whose `security` error stays
/// an error: never a list a check refused.
#[test]
fn the_checked_sandbox_list_names_its_check_or_fails_closed_on_an_older_klavd() {
    use klav_ffi::{SandboxCheckInfo as Check, SandboxListCheckedInfo as Checked};
    let home = tempfile::tempdir().expect("home");
    let engine = DaemonEngine::new(home.path().to_string_lossy().into_owned()).expect("engine");
    let agent = "6f1c2b8e-4d3a-4f5b-9c7d-1e2f3a4b5c6d";
    let refused = |check: serde_json::Value| serde_json::json!({"v": 1, "ok": {"refused": {"check": check, "message": "audit log: x"}}});
    let cases: [(serde_json::Value, Check); 12] = [
        (
            refused(serde_json::json!({"kind": "unlisted_proxy", "agent_id": agent})),
            Check::UnlistedProxy {
                agent_id: agent.into(),
            },
        ),
        (
            refused(serde_json::json!({"kind": "proxy_heartbeat", "agent_id": agent})),
            Check::ProxyHeartbeat {
                agent_id: agent.into(),
            },
        ),
        (refused(serde_json::json!({"kind": "log"})), Check::Log),
        (
            refused(serde_json::json!({"kind": "keys_by_server", "n": 2})),
            Check::Unknown,
        ),
        (serde_json::json!({"v": 1, "ok": {}}), Check::Unknown),
        // A refusal that does not decode is still one, through the real
        // engine: never a decoding error that keeps the last list.
        (
            serde_json::json!({"v": 1, "ok": {"refused": {"check": {"kind": "log"}}}}),
            Check::Log,
        ),
        (
            refused(serde_json::json!({"kind": "unlisted_proxy"})),
            Check::Unknown,
        ),
        (
            refused(serde_json::json!({"kind": "proxy_heartbeat", "agent_id": "not-a-uuid"})),
            Check::Unknown,
        ),
        (
            serde_json::json!({"v": 1, "ok": {"refused": "log"}}),
            Check::Unknown,
        ),
        // Both: the refusal wins, also over a list that does not decode.
        (
            serde_json::json!({"v": 1, "ok": {
                "list": {"sandboxes": [], "verified_events": 2},
                "refused": {"check": {"kind": "log"}, "message": "audit log: x"}}}),
            Check::Log,
        ),
        (
            serde_json::json!({"v": 1, "ok": {
                "list": {"sandboxes": 7},
                "refused": {"check": {"kind": "log"}, "message": "audit log: x"}}}),
            Check::Log,
        ),
        (
            serde_json::json!({"v": 1, "ok": {
                "list": "x",
                "refused": {"check": {"kind": "log"}, "message": "audit log: x"}}}),
            Check::Log,
        ),
    ];
    for (answer, expected) in cases {
        std::thread::scope(|scope| {
            let listener =
                std::os::unix::net::UnixListener::bind(engine.socket_path()).expect("socket");
            let stand_in = scope.spawn(move || {
                let (stream, _) = listener.accept().expect("accept");
                let mut line = String::new();
                std::io::BufRead::read_line(&mut std::io::BufReader::new(&stream), &mut line)
                    .expect("read");
                let request: serde_json::Value = serde_json::from_str(&line).expect("a line");
                let mut answer = answer;
                answer["id"] = request["id"].clone();
                std::io::Write::write_all(&mut &stream, format!("{answer}\n").as_bytes())
                    .expect("write");
                request["request"]["op"].as_str().unwrap_or("").to_owned()
            });
            let checked = engine.sandbox_list_checked(false).expect("checked");
            assert!(
                matches!(&checked, Checked::Refused { check, .. } if *check == expected),
                "{checked:?}"
            );
            assert_eq!(stand_in.join().expect("stand-in"), "sandbox_list_checked");
        });
        std::fs::remove_file(engine.socket_path()).expect("socket");
    }

    let listed = list_stand_in(
        &engine,
        1,
        |_| serde_json::json!({"v": 1, "ok": {"list": {"sandboxes": [], "verified_events": 2}}}),
    );
    let checked = engine.sandbox_list_checked(false).expect("checked");
    assert!(
        matches!(&checked, Checked::Listed { list } if list.verified_events == 2),
        "{checked:?}"
    );
    assert_eq!(listed.join().expect("listed"), ["sandbox_list_checked"]);
    std::fs::remove_file(engine.socket_path()).expect("socket");

    // Without a refusal a list that does not decode is an error, as ever:
    // never read as an empty list.
    let malformed = list_stand_in(
        &engine,
        1,
        |_| serde_json::json!({"v": 1, "ok": {"list": {"sandboxes": 7}}}),
    );
    let checked = engine.sandbox_list_checked(false);
    assert!(
        matches!(checked, Err(KlavError::Invalid { .. })),
        "{checked:?}"
    );
    assert_eq!(
        malformed.join().expect("malformed"),
        ["sandbox_list_checked"]
    );
    std::fs::remove_file(engine.socket_path()).expect("socket");

    let older = list_stand_in(&engine, 2, |op| match op {
        "sandbox_list_flagged" => serde_json::json!({"v": 1,
            "error": {"code": "security", "message": "SECURITY: audit log: event 3 was rewritten"}}),
        _ => serde_json::json!({"v": 1, "id": 0,
            "error": {"code": "bad_request", "message": "malformed request"}}),
    });
    let checked = engine.sandbox_list_checked(false);
    assert!(
        matches!(checked, Err(KlavError::Security { .. })),
        "{checked:?}"
    );
    assert_eq!(
        older.join().expect("older"),
        ["sandbox_list_checked", "sandbox_list_flagged"]
    );
}

/// A newer app against a `klavd` older than the sandbox operations: such a
/// `klavd` cannot parse `sandbox_list` or `sandbox_revoke` and answers
/// `bad_request` with `id` 0, and the app says to update Klav, for the
/// list and both revocations, instead of failing with klavd's words.
#[test]
fn the_sandboxes_on_a_klavd_older_than_them_say_update_klav() {
    let home = tempfile::tempdir().expect("home");
    let engine = DaemonEngine::new(home.path().to_string_lossy().into_owned()).expect("engine");
    let listener = std::os::unix::net::UnixListener::bind(engine.socket_path()).expect("socket");
    let older = std::thread::spawn(move || {
        let mut ops = Vec::new();
        for _ in 0..3 {
            let (stream, _) = listener.accept().expect("accept");
            let mut line = String::new();
            std::io::BufRead::read_line(&mut std::io::BufReader::new(&stream), &mut line)
                .expect("read");
            let request: serde_json::Value = serde_json::from_str(&line).expect("a line");
            ops.push(request["request"].clone());
            let reply = serde_json::json!({
                "v": 1, "id": 0,
                "error": {"code": "bad_request", "message": "malformed request"},
            });
            std::io::Write::write_all(&mut &stream, format!("{reply}\n").as_bytes())
                .expect("write");
        }
        ops
    });
    let proxy = AgentId::generate().to_string();
    let sandbox = klav_core::ids::SandboxId::generate().to_string();
    let results = [
        engine.sandbox_list(false).map(drop),
        engine
            .revoke_sandbox(proxy.clone(), sandbox.clone())
            .map(drop),
        engine.revoke_all_sandboxes(proxy.clone()).map(drop),
    ];
    for result in results {
        assert!(
            matches!(&result, Err(KlavError::Invalid { message })
                if message.contains("older than the sandbox list and revocation")
                    && message.contains("Update Klav")),
            "{result:?}"
        );
    }
    let ops = older.join().expect("the older klavd");
    assert_eq!(ops[0]["op"], "sandbox_list");
    assert_eq!(ops[1]["op"], "sandbox_revoke");
    assert_eq!(ops[1]["scope"], sandbox.as_str());
    assert_eq!(ops[2]["proxy"], proxy.as_str());
    assert_eq!(ops[2]["scope"], "all");
}
