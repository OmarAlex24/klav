//! `klav log verify` against a real server (ADR 0030 §4): an honest chain
//! with every kind of event verifies clean, and a server that edits what an
//! event says (keeping the hash chain consistent) is caught. A malicious
//! server is played by editing its SQLite file while it is stopped.

#[path = "../../klav-client/tests/common/mod.rs"]
mod common;

use std::future::Future;
use std::time::Duration;

use common::ServerProcess;
use klav_client::activity::How;
use klav_client::agents::GrantRequest;
use klav_client::audit::{LogFilter, LogLine, Unpinned};
use klav_client::offer::OfferRequest;
use klav_client::ops::{ItemPatch, NewItem};
use klav_client::rotate::{PageRules, RotationStep};
use klav_client::sandboxes::ListCheck;
use klav_client::tasks::TaskChoice;
use klav_client::{ClientError, Home, SignupRequest, Unlocked, signup, unlock_with_password};
use klav_core::crypto::audit::{GENESIS, chain_hash};
use klav_core::crypto::identity::IdentityKeyPair;
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::keys::LocalKey;
use klav_core::crypto::local::seal_local_data;
use klav_core::ids::{AccountId, AgentId};
use klav_core::model::item::{Item, ItemKind};
use klav_core::policy::{Effect, Permission, Policy, Rule};
use klav_core::task::{TaskSpec, TaskSpecAccess};
use klav_proto::agent::{AgentStatus, Claims};
use klav_proto::auth::DeviceKind;
use klav_proto::rotate::{AgentRotateFinish, AgentRotateStart, RotationInfo, RotationStarted};
use klav_sdk::{Access, Agent, KeyStore, Registration, Session};
use serde_json::Value;
use sqlx::any::AnyPoolOptions;
use sqlx::{AnyPool, Row};

const PASSWORD: &str = "correct horse battery staple";

/// Runs `edit` on the server database with the server stopped.
async fn with_db<F, Fut, T>(server: &mut ServerProcess, edit: F) -> T
where
    F: FnOnce(AnyPool) -> Fut,
    Fut: Future<Output = T>,
{
    server.stop();
    sqlx::any::install_default_drivers();
    let url = format!("sqlite://{}", server.dir.path().join("klav.db").display());
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("open server db");
    let out = edit(pool.clone()).await;
    pool.close().await;
    server.restart();
    out
}

async fn account(server: &ServerProcess, dir: &tempfile::TempDir, email: &str) -> Unlocked {
    signup(
        &Home::at(dir.path().join(email)),
        SignupRequest {
            server: server.url.clone(),
            email: email.into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
            invite: None,
        },
    )
    .await
    .expect("sign-up")
    .0
}

async fn register(server: &ServerProcess, dir: &tempfile::TempDir, name: &str) -> Agent {
    Agent::register(
        &Home::at(dir.path().join(format!("agent-{name}"))),
        Registration {
            name: name.into(),
            server: server.url.clone(),
            email: "ana@example.com".into(),
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

fn new_item(title: &str) -> NewItem {
    NewItem {
        kind: ItemKind::Login,
        title: title.into(),
        vault: None,
        project: None,
        fields: Vec::new(),
        urls: Vec::new(),
        tags: Vec::new(),
        notes: None,
        allow_duplicate: false,
    }
}

fn spec(title: &str) -> TaskSpec {
    TaskSpec {
        task: title.into(),
        reason: "descargar las facturas".into(),
        duration: "30m".into(),
        access: vec![TaskSpecAccess {
            reference: "klav://Personal/General/GitHub".into(),
            permissions: vec![Permission::Inject],
            domain: None,
        }],
    }
}

/// One stored row of the chain.
struct Row3 {
    seq: i64,
    event: Vec<u8>,
    hash: Vec<u8>,
}

async fn rows(pool: &AnyPool, account: AccountId) -> Vec<Row3> {
    sqlx::query("SELECT seq, event, hash FROM audit_events WHERE account_id = $1 ORDER BY seq")
        .bind(account.to_string())
        .fetch_all(pool)
        .await
        .expect("rows")
        .iter()
        .map(|r| Row3 {
            seq: r.try_get("seq").expect("seq"),
            event: r.try_get("event").expect("event"),
            hash: r.try_get("hash").expect("hash"),
        })
        .collect()
}

async fn write_rows(pool: &AnyPool, account: AccountId, rows: &[Row3]) {
    for r in rows {
        sqlx::query(
            "UPDATE audit_events SET event = $1, hash = $2 WHERE account_id = $3 AND seq = $4",
        )
        .bind(r.event.clone())
        .bind(r.hash.clone())
        .bind(account.to_string())
        .bind(r.seq)
        .execute(pool)
        .await
        .expect("write row");
    }
}

/// Rewrites the account's chain as a server with database access would:
/// `edit` changes the parsed events (returning `false` if it found nothing
/// to change) and every hash is recomputed, so the chain stays consistent.
/// Returns the original rows, to put them back.
async fn rewrite<F>(server: &mut ServerProcess, account: AccountId, edit: F) -> Vec<Row3>
where
    F: FnOnce(&mut [Value]) -> bool,
{
    with_db(server, |pool| async move {
        let original = rows(&pool, account).await;
        let mut events: Vec<Value> = original
            .iter()
            .map(|r| serde_json::from_slice(&r.event).expect("event"))
            .collect();
        assert!(edit(&mut events), "nothing to tamper with");
        let mut previous = GENESIS;
        let rewritten: Vec<Row3> = original
            .iter()
            .zip(&events)
            .map(|(r, e)| {
                let bytes = if serde_json::from_slice::<Value>(&r.event).expect("event") == *e {
                    r.event.clone()
                } else {
                    serde_json::to_vec(e).expect("event")
                };
                let hash = chain_hash(u64::try_from(r.seq).expect("seq"), &previous, &bytes);
                previous = hash;
                Row3 {
                    seq: r.seq,
                    event: bytes,
                    hash: hash.to_vec(),
                }
            })
            .collect();
        write_rows(&pool, account, &rewritten).await;
        original
    })
    .await
}

async fn restore(server: &mut ServerProcess, account: AccountId, original: Vec<Row3>) {
    with_db(server, |pool| async move {
        write_rows(&pool, account, &original).await;
    })
    .await;
}

/// The index of the first event that matches.
fn find(events: &[Value], wanted: impl Fn(&Value) -> bool) -> Option<usize> {
    events.iter().position(wanted)
}

fn is_inject_access(e: &Value) -> bool {
    e["action"] == "agent.access" && e["permission"] == "inject" && e["outcome"] == "allow"
}

/// `klav log` with `filter`.
async fn log(ana: &mut Unlocked, filter: LogFilter) -> Vec<LogLine> {
    ana.audit_log(&filter).await.expect("log")
}

/// `klav log verify` must refuse the chain, saying `why`; and the sandbox
/// list names the log as the check that refused it (the Mac app's words),
/// with the same text.
async fn assert_tampered(ana: &mut Unlocked, why: &str) {
    let message = match ana.verify_audit().await {
        Err(ClientError::Security(message)) => {
            assert!(message.contains(why), "expected {why:?}, got {message:?}");
            message
        }
        other => panic!("expected {why:?}, got {other:?}"),
    };
    match ana.sandbox_list_checked().await {
        Ok(Err(refusal)) => {
            assert_eq!(refusal.check, ListCheck::Log, "{why}");
            assert_eq!(refusal.message, message);
        }
        other => panic!("expected the log's check for {why:?}, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_audit_log_verifies_honest_chains_and_catches_a_lying_server() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir, "ana@example.com").await;
    let bob = account(&server, &dir, "bob@example.com").await;
    let me = ana.account().account_id;
    let vault = ana.find_vault("Personal").expect("vault");
    let project = ana.find_project(vault, "General").expect("project");
    let github = ana
        .add_item(
            vault,
            project,
            &Item::from_template(ItemKind::Login, "GitHub").expect("item"),
        )
        .await
        .expect("add");

    // ---- an honest chain with every kind of event --------------------
    let stranger = register(&server, &dir, "stranger").await;
    ana.deny_agent(stranger.id()).await.expect("deny");
    let bot = register(&server, &dir, "bot").await;
    let bot_id = bot.id();
    ana.approve_agent(
        bot_id,
        GrantRequest {
            projects: vec!["Personal/General".into()],
            vaults: Vec::new(),
            policy: Policy {
                rules: vec![
                    Rule::new(Permission::Update, Effect::Allow),
                    Rule::new(Permission::Delete, Effect::Ask),
                ],
                expires_at: None,
            },
        },
        &bot.pairing_code(),
    )
    .await
    .expect("approve");
    let mut session = Session::open(bot).await.expect("session");
    // Two identical allowed accesses (same body, different requests).
    for _ in 0..2 {
        let got = session
            .access(github.item, Permission::Inject, "deploy", None, None)
            .await
            .expect("inject");
        assert!(matches!(got, Access::Granted(_)));
    }
    // `ask`, decided by the person, then used.
    let Access::Pending { approval_id, .. } = session
        .access(github.item, Permission::Totp, "2fa", None, None)
        .await
        .expect("totp")
    else {
        panic!("totp should ask");
    };
    let shown = ana
        .find_approval(&approval_id.to_string())
        .await
        .expect("card")
        .request_digest;
    ana.decide_approval(approval_id, true, None, &shown)
        .await
        .expect("decide");
    let got = session
        .access(
            github.item,
            Permission::Totp,
            "2fa",
            None,
            Some(approval_id),
        )
        .await
        .expect("totp with approval");
    assert!(matches!(got, Access::Granted(_)));
    // Writes.
    let created = session
        .create_item(project, &new_item("Staging"), "store it", Duration::ZERO)
        .await
        .expect("create");
    session
        .update_item(
            created.id,
            &ItemPatch {
                add_tags: vec!["ci".into()],
                ..ItemPatch::default()
            },
            "tag it",
            Duration::ZERO,
        )
        .await
        .expect("update");
    // `delete` asks: the request goes first, without the body (residual
    // risk 35); the write follows with the approval.
    let Err(ClientError::PendingApproval { id: asked, .. }) = session
        .trash_item(created.id, "clean up", Duration::ZERO)
        .await
    else {
        panic!("delete should ask");
    };
    let shown = ana
        .find_approval(&asked.to_string())
        .await
        .expect("card")
        .request_digest;
    ana.decide_approval(asked, true, None, &shown)
        .await
        .expect("decide");
    session.claim_approval(asked).await.expect("claim");
    session
        .trash_item(created.id, "clean up", Duration::ZERO)
        .await
        .expect("trash");
    session.release_claim();
    // Tasks: ended by the agent, by the person, and by the revocation.
    let ask = |title: &'static str| {
        let session = &session;
        async move {
            let request = session.task_request(&spec(title), None).expect("request");
            session
                .submit_task(&request)
                .await
                .expect("submit")
                .pending_task_id
        }
    };
    let first = ask("primera").await;
    let shown = ana
        .task(&first.to_string())
        .await
        .expect("card")
        .request_digest;
    ana.decide_task(first, true, &TaskChoice::default(), &shown)
        .await
        .expect("decide task");
    session
        .agent()
        .end_task(first, "listo")
        .await
        .expect("agent ends");
    let second = ask("segunda").await;
    let shown = ana
        .task(&second.to_string())
        .await
        .expect("card")
        .request_digest;
    ana.decide_task(second, true, &TaskChoice::default(), &shown)
        .await
        .expect("decide task");
    ana.end_task(second).await.expect("person ends");
    let third = ask("tercera").await;
    let shown = ana
        .task(&third.to_string())
        .await
        .expect("card")
        .request_digest;
    ana.decide_task(third, true, &TaskChoice::default(), &shown)
        .await
        .expect("decide task");
    // Assisted password changes (ADR 0022 §5–6) in a task the person
    // offered: one the agent confirms, one the person settles from the
    // item's card.
    let mut banco_item = Item::from_template(ItemKind::Login, "Banco").expect("item");
    banco_item.add_url("https://banco.example").expect("url");
    banco_item
        .field_mut("password")
        .expect("password")
        .set_value("repetida-123")
        .expect("password");
    let banco = ana
        .add_item(vault, project, &banco_item)
        .await
        .expect("add banco");
    let offered = ana
        .offer_task(&OfferRequest {
            agent: bot_id.to_string(),
            items: vec![banco.item],
            task: None,
            reason: None,
            duration_secs: None,
        })
        .await
        .expect("offer");
    let start = |reason: &'static str| {
        let session = &session;
        async move {
            session
                .agent()
                .call_proved::<_, RotationStarted>(
                    "/v1/agent/rotations",
                    &AgentRotateStart {
                        item_id: banco.item,
                        reason: reason.into(),
                        claims: Claims {
                            tags: Vec::new(),
                            domain: Some("banco.example".into()),
                            ..Claims::default()
                        },
                        task_id: Some(offered.id),
                    },
                )
                .await
                .expect("start a change")
        }
    };
    let (first_change, _) = start("cambiar la repetida").await;
    let confirm = session
        .agent()
        .sign_post(
            &format!("/v1/agent/rotations/{}/confirm", first_change.rotation.id),
            &AgentRotateFinish {
                item_id: banco.item,
                reason: "el sitio la aceptó".into(),
            },
        )
        .expect("sign confirm");
    let _: RotationInfo = session
        .agent()
        .send_proved(&confirm)
        .await
        .expect("agent confirms");
    let (second_change, proof) = start("otra vez").await;
    let plan = ana
        .rotation_begin(&RotationStep {
            agent_id: bot_id,
            task_id: offered.id,
            rotation_id: second_change.rotation.id,
            item_id: banco.item,
            request: proof,
        })
        .await
        .expect("klavd checks the start");
    ana.rotation_store_pending(&plan, &PageRules::default())
        .await
        .expect("pending");
    drop(plan);
    ana.resolve_pending(banco, false)
        .await
        .expect("the person keeps the current one");

    // The person's own changes, a rotation and the revocation.
    let mut edited = ana.open_item(github).expect("open");
    edited.set_title("GitHub (work)").expect("title");
    ana.update_item(github, &edited).await.expect("update");
    ana.rotate_project_key(project).await.expect("rotate");
    ana.revoke_agent(bot_id, false).await.expect("revoke");

    let actions: std::collections::BTreeSet<String> = ana
        .audit_entries()
        .await
        .expect("entries")
        .iter()
        .map(|e| match e.event.outcome.as_deref() {
            Some(o) if e.event.action == "task.ended" => format!("task.ended/{o}"),
            _ => e.event.action.clone(),
        })
        .collect();
    for wanted in [
        "item.created",
        "item.updated",
        "agent.registered",
        "agent.denied",
        "agent.granted",
        "agent.access",
        "approval.decided",
        "agent.create",
        "agent.update",
        "agent.trash",
        "agent.ask",
        "task.requested",
        "task.decided",
        "task.ended/agent",
        "task.ended/person",
        "task.ended/revocation",
        "project.rotated",
        "agent.revoked",
        "rotate.started",
        "rotate.confirmed",
        "rotate.cancelled",
    ] {
        assert!(actions.contains(wanted), "missing {wanted}: {actions:?}");
    }

    // ---- a server that edits events, keeping the chain consistent ----
    // (Before the first verification: no head is pinned or signed yet, so
    // only the rules of ADR 0030 §4 can catch these.)

    // §4.2: the access loses the body the agent signed.
    let original = rewrite(&mut server, me, |events| {
        let Some(i) = find(events, is_inject_access) else {
            return false;
        };
        events[i]["agent_proof"]
            .as_object_mut()
            .expect("proof")
            .remove("body");
        true
    })
    .await;
    assert_tampered(&mut ana, "lacks the body").await;
    restore(&mut server, me, original).await;

    // §4.4: another item, permission or reason than the agent signed.
    let created_id = created.id.to_string();
    let original = rewrite(&mut server, me, move |events| {
        let Some(i) = find(events, is_inject_access) else {
            return false;
        };
        events[i]["item_id"] = Value::String(created_id);
        true
    })
    .await;
    assert_tampered(&mut ana, "the item differs").await;
    restore(&mut server, me, original).await;
    let original = rewrite(&mut server, me, |events| {
        let Some(i) = find(events, is_inject_access) else {
            return false;
        };
        events[i]["reason"] = Value::String("routine check".into());
        true
    })
    .await;
    assert_tampered(&mut ana, "the reason differs").await;
    restore(&mut server, me, original).await;
    let original = rewrite(&mut server, me, |events| {
        let Some(i) = find(events, |e| e["action"] == "approval.decided") else {
            return false;
        };
        events[i]["permission"] = Value::String("reveal".into());
        true
    })
    .await;
    assert_tampered(&mut ana, "the permission differs").await;
    restore(&mut server, me, original).await;

    // §4.1: an agent's write passed off as the person's, and an action
    // the table does not know.
    let original = rewrite(&mut server, me, |events| {
        let Some(i) = find(events, |e| e["action"] == "agent.update") else {
            return false;
        };
        events[i]["action"] = Value::String("item.updated".into());
        events[i]["actor"] = Value::String("person".into());
        true
    })
    .await;
    assert_tampered(&mut ana, "carries an agent request it does not take").await;
    restore(&mut server, me, original).await;
    let original = rewrite(&mut server, me, |events| {
        let Some(i) = find(events, |e| e["action"] == "item.updated") else {
            return false;
        };
        events[i]["action"] = Value::String("item.exported".into());
        true
    })
    .await;
    assert_tampered(&mut ana, "unknown action").await;
    restore(&mut server, me, original).await;

    // §4.3: the agent's request was for another route.
    let original = rewrite(&mut server, me, |events| {
        let Some(i) = find(events, |e| e["action"] == "agent.trash") else {
            return false;
        };
        events[i]["action"] = Value::String("agent.update".into());
        events[i]["permission"] = Value::String("update".into());
        true
    })
    .await;
    assert_tampered(&mut ana, "not this action").await;
    restore(&mut server, me, original).await;

    // The request asked before a write (residual risk 35) is checked like
    // the write: another permission than the agent signed.
    let original = rewrite(&mut server, me, |events| {
        let Some(i) = find(events, |e| e["action"] == "agent.ask") else {
            return false;
        };
        events[i]["permission"] = Value::String("update".into());
        true
    })
    .await;
    assert_tampered(&mut ana, "the permission differs").await;
    restore(&mut server, me, original).await;

    // §4.6: one signed request backing two events (its signature is
    // valid), and a request logged long after the agent signed it.
    let original = rewrite(&mut server, me, |events| {
        let Some(first) = find(events, is_inject_access) else {
            return false;
        };
        let Some(offset) = find(&events[first + 1..], is_inject_access) else {
            return false;
        };
        let proof = events[first]["agent_proof"].clone();
        events[first + 1 + offset]["agent_proof"] = proof;
        true
    })
    .await;
    assert_tampered(&mut ana, "already used").await;
    restore(&mut server, me, original).await;
    let original = rewrite(&mut server, me, |events| {
        let Some(i) = find(events, is_inject_access) else {
            return false;
        };
        let at = events[i]["at"].as_i64().expect("at");
        events[i]["at"] = Value::from(at + 6 * 60 * 1000);
        true
    })
    .await;
    assert_tampered(&mut ana, "too far").await;
    restore(&mut server, me, original).await;

    // §4.5: the server swaps the agent's key in `GET /v1/agents`; the
    // grant in the chain no longer verifies with it.
    let other_key = IdentityKeyPair::generate().public().encode().to_vec();
    let real_key: Vec<u8> = with_db(&mut server, |pool| async move {
        let key: Vec<u8> = sqlx::query_scalar("SELECT public_identity FROM agents WHERE id = $1")
            .bind(bot_id.to_string())
            .fetch_one(&pool)
            .await
            .expect("key");
        sqlx::query("UPDATE agents SET public_identity = $1 WHERE id = $2")
            .bind(other_key)
            .bind(bot_id.to_string())
            .execute(&pool)
            .await
            .expect("swap");
        key
    })
    .await;
    assert_tampered(&mut ana, "does not verify").await;
    set_agent(&mut server, bot_id, "public_identity", real_key).await;

    // ADR 0022 §5: the person's decision on a change moved to another host.
    let original = rewrite(&mut server, me, |events| {
        let Some(i) = find(events, |e| {
            e["action"] == "rotate.cancelled" && e["actor"] == "person"
        }) else {
            return false;
        };
        events[i]["domain"] = Value::String("evil.example".into());
        true
    })
    .await;
    assert_tampered(&mut ana, "names no change started").await;
    restore(&mut server, me, original).await;

    // ---- the honest chain verifies --------------------------------------
    let report = ana.verify_audit().await.expect("verify");
    assert!(report.agent_signatures >= 10, "{report:?}");
    assert!(report.account_signatures >= 7, "{report:?}");
    // First verification on this device: said, not silent (§4.8).
    assert_eq!(report.warnings.len(), 1, "{report:?}");
    assert!(report.warnings[0].contains("had not verified"));
    // The same warning as a code, which the apps word themselves.
    assert_eq!(report.unpinned, Some(Unpinned::Missing));
    assert_eq!(report.warnings[0], Unpinned::Missing.warning());
    let report = ana.verify_audit().await.expect("verify again");
    assert!(report.warnings.is_empty(), "{report:?}");
    assert_eq!(report.unpinned, None);
    assert_eq!(report.heads, 1);

    // An agent the server no longer lists: a warning, not tampering.
    let bob_id = bob.account().account_id.to_string();
    set_agent_account(&mut server, bot_id, &bob_id).await;
    let report = ana.verify_audit().await.expect("verify without the agent");
    assert_eq!(report.agent_signatures, 0, "{report:?}");
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains(&bot_id.to_string())),
        "{report:?}"
    );
    set_agent_account(&mut server, bot_id, &me.to_string()).await;

    // The pinned head belongs to an account; another account's is not used.
    let pin_path = ana.home().file("audit-head.json");
    let pin: Value = serde_json::from_slice(&std::fs::read(&pin_path).expect("pin")).expect("pin");
    assert_eq!(pin["account_id"], Value::String(me.to_string()));
    let mut foreign = pin.clone();
    foreign["account_id"] = Value::String(bob_id);
    std::fs::write(&pin_path, serde_json::to_vec(&foreign).expect("pin")).expect("write pin");
    let report = ana.verify_audit().await.expect("verify");
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("another account")),
        "{report:?}"
    );
    std::fs::remove_file(&pin_path).expect("remove pin");
    let report = ana.verify_audit().await.expect("verify");
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("had not verified")),
        "{report:?}"
    );
    assert!(
        ana.verify_audit()
            .await
            .expect("verify")
            .warnings
            .is_empty()
    );

    // ---- the copy on this device (ADR 0033 §8) --------------------------
    // «Who used it»: every agent event about GitHub, with what let it in.
    let activity = ana
        .item_activity(&github.item.to_string())
        .await
        .expect("who used it");
    assert!(
        activity
            .reference
            .as_deref()
            .is_some_and(|r| r.contains("GitHub")),
        "{:?}",
        activity.reference
    );
    let hows: Vec<(Option<&str>, How)> = activity
        .uses
        .iter()
        .map(|u| (u.line.permission.as_deref(), u.how))
        .collect();
    assert_eq!(
        hows.iter()
            .filter(|h| **h == (Some("inject"), How::Policy))
            .count(),
        2,
        "{hows:?}"
    );
    assert!(hows.contains(&(Some("totp"), How::Asked)), "{hows:?}");
    assert!(
        hows.contains(&(Some("totp"), How::ApprovedOnce)),
        "{hows:?}"
    );
    assert!(
        activity
            .uses
            .iter()
            .all(|u| u.line.agent_id == Some(bot_id) && u.line.verified),
        "{:?}",
        activity.uses
    );

    // The filters by permission, outcome and text.
    let totp = log(
        &mut ana,
        LogFilter {
            permissions: vec![Permission::Totp],
            ..LogFilter::default()
        },
    )
    .await;
    assert!(totp.len() >= 3, "{totp:?}");
    assert!(totp.iter().all(|l| l.permission.as_deref() == Some("totp")));
    let asked = log(
        &mut ana,
        LogFilter {
            outcomes: vec!["ask".into()],
            ..LogFilter::default()
        },
    )
    .await;
    assert!(!asked.is_empty());
    assert!(asked.iter().all(|l| l.outcome.as_deref() == Some("ask")));
    let deploys = log(
        &mut ana,
        LogFilter {
            text: Some("DEPLOY".into()),
            ..LogFilter::default()
        },
    )
    .await;
    assert_eq!(deploys.len(), 2, "{deploys:?}");

    // An agent to revoke once the server's log no longer matches this
    // device's copy (below).
    let spare = register(&server, &dir, "spare").await;
    let spare_id = spare.id();
    ana.approve_agent(
        spare_id,
        GrantRequest {
            projects: vec!["Personal/General".into()],
            vaults: Vec::new(),
            policy: Policy {
                rules: vec![Rule::new(Permission::Fill, Effect::Allow)],
                expires_at: None,
            },
        },
        &spare.pairing_code(),
    )
    .await
    .expect("approve the spare agent");
    ana.verify_audit()
        .await
        .expect("verify with the spare agent");

    // Everything downloaded is verified; a later event is not, yet.
    let status = ana.audit_status();
    assert!(status.events > 0 && status.verified == Some(status.events));
    server.snapshot("before-later");
    ana.add_item(
        vault,
        project,
        &Item::from_template(ItemKind::Login, "Later").expect("item"),
    )
    .await
    .expect("add later");
    let newest = log(&mut ana, LogFilter::default()).await;
    assert_eq!(newest[0].action, "item.created");
    assert!(!newest[0].verified && newest[1].verified);
    assert_eq!(ana.audit_status().unverified(), 1);

    // A server that rewrites what this device downloaded is caught by the
    // next view, without `klav log verify`: the event it already has
    // changed.
    let original = rewrite(&mut server, me, |events| {
        let Some(i) = find(events, is_inject_access) else {
            return false;
        };
        events[i]["reason"] = Value::String("routine check".into());
        true
    })
    .await;
    match ana.audit_log(&LogFilter::default()).await {
        Err(ClientError::Security(m)) => assert!(m.contains("rewritten"), "{m}"),
        other => panic!("expected a rewritten chain, got {other:?}"),
    }
    restore(&mut server, me, original).await;
    assert!(!log(&mut ana, LogFilter::default()).await.is_empty());

    // And one that forgets the last events (an old backup, T7).
    server.restore("before-later");
    match ana.audit_log(&LogFilter::default()).await {
        Err(ClientError::Security(m)) => assert!(m.contains("truncated"), "{m}"),
        other => panic!("expected a truncated chain, got {other:?}"),
    }
    assert_tampered(&mut ana, "truncated").await;

    // ---- what does not come from the log still works ------------------
    // Revoking, when a stolen key needs it most (ADR 0033 §7.7): the
    // revocation goes first, and "what it saw" says why it lists nothing.
    let report = ana
        .revoke_agent(spare_id, false)
        .await
        .expect("revoke with a log that does not match the copy");
    assert_eq!(report.agent.status, AgentStatus::Revoked);
    assert!(report.exposure.items.is_empty());
    assert_eq!(report.exposure.projects.len(), 1, "{report:?}");
    let warning = report
        .exposure
        .log_warning
        .as_deref()
        .expect("why no items");
    assert!(
        warning.contains("SECURITY") && warning.contains("klav log reset"),
        "{warning}"
    );
    // `klav agent show`.
    let shown = ana.agent_exposure(spare_id).await.expect("what it saw");
    assert!(shown.items.is_empty() && shown.log_warning.is_some());
    assert_eq!(shown.projects.len(), 1);
    // A task's card, without its events; the progress of a password change.
    let task = ana.task_log(&first.to_string()).await.expect("task log");
    assert!(task.card.is_some() && task.events.is_empty(), "{task:?}");
    assert!(task.log_warning.is_some());
    let progress = ana
        .task_progress(&offered.id.to_string())
        .await
        .expect("progress");
    assert!(progress.card.is_some() && progress.sites.is_empty());
    assert!(progress.log_warning.is_some());
    // The log's own views still say it does not match.
    match ana.item_activity(&github.item.to_string()).await {
        Err(ClientError::Security(m)) => assert!(m.contains("rewritten"), "{m}"),
        other => panic!("expected a rewritten chain, got {other:?}"),
    }
    // Rotating the projects it had. The vaults went back with the backup
    // too ("Later" is gone), which `klav sync --reset-cache` accepts; a
    // chain the server rewrote does not stop it. It is not done, though:
    // the log, which lists every project the agent was granted, could not
    // be read.
    ana.reset_cache().await.expect("reset the vaults' copy");
    let report = ana.revoke_agent(spare_id, true).await.expect("rotate");
    assert_eq!(report.rotated.len(), 1, "{report:?}");
    assert!(report.log_unchecked && !report.complete(), "{report:?}");
    assert!(report.exposure.log_warning.is_some());

    // `klav log reset`: this device accepts the restored chain, and the
    // next verification starts over from it, saying so.
    let removed = ana.forget_audit_copy().expect("reset the log's copy");
    assert_eq!(removed, ["audit-chain.bin", "audit-head.json"]);
    assert!(!ana.home().file("audit-chain.bin").exists());
    assert_eq!(
        ana.audit_status(),
        klav_client::audit::ChainStatus::default()
    );
    let newest = log(&mut ana, LogFilter::default()).await;
    assert_eq!(newest[0].action, "project.rotated");
    assert!(newest.iter().all(|l| !l.verified));
    let report = ana.verify_audit().await.expect("verify the restored chain");
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("had not verified")),
        "{report:?}"
    );
    let shown = ana.agent_exposure(spare_id).await.expect("what it saw");
    assert!(shown.log_warning.is_none(), "{shown:?}");
    assert!(ana.forget_audit_copy().expect("again").len() == 2);
    assert!(
        klav_client::audit::forget_audit_copy(ana.home())
            .expect("nothing left")
            .is_empty()
    );
}

/// `home` unlocked again: no copy of the chain in memory.
fn unlock_again(home: &Home) -> Unlocked {
    unlock_with_password(home, &MasterPassword::new(PASSWORD)).expect("unlock")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_copy_of_the_chain_that_does_not_open_is_downloaded_again_and_replaced() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir, "ana@example.com").await;
    let bob = account(&server, &dir, "bob@example.com").await;
    let vault = ana.find_vault("Personal").expect("vault");
    let project = ana.find_project(vault, "General").expect("project");
    for title in ["Uno", "Dos"] {
        ana.add_item(
            vault,
            project,
            &Item::from_template(ItemKind::Login, title).expect("item"),
        )
        .await
        .expect("add");
    }
    let events = u64::try_from(log(&mut ana, LogFilter::default()).await.len()).expect("events");
    assert!(events >= 2);
    let home = ana.home().clone();
    let path = home.file("audit-chain.bin");
    let good = std::fs::read(&path).expect("the copy");
    let me = ana.account().account_id;
    let ctx = ana.account().local_context();
    let sealed = |key: &LocalKey, v: u32, account: AccountId| {
        let json = serde_json::json!({ "v": v, "account_id": account, "entries": [] });
        seal_local_data(
            key,
            &ctx,
            "audit",
            &serde_json::to_vec(&json).expect("json"),
        )
        .expect("seal")
    };
    let cases: Vec<(&str, Vec<u8>, Option<&str>)> = vec![
        (
            "cut short",
            good[..good.len() / 2].to_vec(),
            Some("it does not open"),
        ),
        ("not sealed", b"{}".to_vec(), Some("it does not open")),
        (
            "another key",
            sealed(&LocalKey::generate(), 1, me),
            Some("it does not open"),
        ),
        (
            "another version",
            sealed(ana.local_key(), 2, me),
            Some("version 2"),
        ),
        // Another account's copy is none, without a word.
        (
            "another account",
            sealed(ana.local_key(), 1, bob.account().account_id),
            None,
        ),
    ];
    for (case, bytes, said) in cases {
        std::fs::write(&path, &bytes).expect("write");
        let mut u = unlock_again(&home);
        assert_eq!(
            log(&mut u, LogFilter::default()).await.len(),
            usize::try_from(events).expect("events"),
            "{case}"
        );
        let warned: Vec<&String> = u
            .warnings()
            .iter()
            .filter(|w| w.contains("audit-chain.bin"))
            .collect();
        match said {
            Some(why) => assert!(
                warned.len() == 1
                    && warned[0].contains(why)
                    && warned[0].contains("downloading the audit log again"),
                "{case}: {warned:?}"
            ),
            None => assert!(warned.is_empty(), "{case}: {warned:?}"),
        }
        // Replaced by the chain downloaded again: the next unlock opens
        // it without a word.
        assert_ne!(std::fs::read(&path).expect("read"), bytes, "{case}");
        let mut next = unlock_again(&home);
        assert_eq!(next.audit_status().events, events, "{case}");
        assert!(
            next.warnings()
                .iter()
                .all(|w| !w.contains("audit-chain.bin")),
            "{case}: {:?}",
            next.warnings()
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn who_used_it_says_an_approval_for_a_while_and_a_task() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir, "ana@example.com").await;
    let vault = ana.find_vault("Personal").expect("vault");
    let project = ana.find_project(vault, "General").expect("project");
    let github = ana
        .add_item(
            vault,
            project,
            &Item::from_template(ItemKind::Login, "GitHub").expect("item"),
        )
        .await
        .expect("add");
    let bot = register(&server, &dir, "bot").await;
    let bot_id = bot.id();
    ana.approve_agent(
        bot_id,
        GrantRequest {
            projects: vec!["Personal/General".into()],
            vaults: Vec::new(),
            policy: Policy {
                rules: vec![
                    Rule::new(Permission::Totp, Effect::Ask),
                    Rule::new(Permission::Inject, Effect::Ask),
                ],
                expires_at: None,
            },
        },
        &bot.pairing_code(),
    )
    .await
    .expect("approve");
    let mut session = Session::open(bot).await.expect("session");
    // Approved for 15 minutes.
    let Access::Pending { approval_id, .. } = session
        .access(github.item, Permission::Totp, "2fa", None, None)
        .await
        .expect("totp")
    else {
        panic!("totp should ask");
    };
    let shown = ana
        .find_approval(&approval_id.to_string())
        .await
        .expect("card")
        .request_digest;
    ana.decide_approval(
        approval_id,
        true,
        Some(Duration::from_secs(15 * 60)),
        &shown,
    )
    .await
    .expect("decide");
    let got = session
        .access(
            github.item,
            Permission::Totp,
            "2fa",
            None,
            Some(approval_id),
        )
        .await
        .expect("totp with the approval");
    assert!(matches!(got, Access::Granted(_)));
    // Inside a task the person approved.
    let request = session
        .task_request(&spec("facturas de marzo"), None)
        .expect("request");
    let task = session
        .submit_task(&request)
        .await
        .expect("submit")
        .pending_task_id;
    let shown = ana
        .task(&task.to_string())
        .await
        .expect("card")
        .request_digest;
    ana.decide_task(task, true, &TaskChoice::default(), &shown)
        .await
        .expect("decide task");
    // The runtime learns the running task and names it.
    session.refresh().await.expect("refresh");
    session.use_task(task).expect("use the task");
    let got = session
        .access(github.item, Permission::Inject, "deploy", None, None)
        .await
        .expect("inject inside the task");
    assert!(matches!(got, Access::Granted(_)));

    let activity = ana
        .item_activity(&github.item.to_string())
        .await
        .expect("who used it");
    let lease = activity
        .uses
        .iter()
        .find(|u| u.how == How::ApprovedFor)
        .unwrap_or_else(|| panic!("approved for a while: {:?}", activity.uses));
    assert_eq!(lease.line.permission.as_deref(), Some("totp"));
    let (at, until) = (
        lease.approved_at.expect("decided at"),
        lease.lease_until.expect("until"),
    );
    assert!(
        (14 * 60_000..=16 * 60_000).contains(&(until - at)),
        "{at} → {until}"
    );
    let inside = activity
        .uses
        .iter()
        .find(|u| u.how == How::Task)
        .unwrap_or_else(|| panic!("inside the task: {:?}", activity.uses));
    assert_eq!(inside.line.permission.as_deref(), Some("inject"));
    assert_eq!(inside.line.task_id, Some(task));
    assert_eq!(inside.task.as_deref(), Some("facturas de marzo"));
    assert!(inside.lease_until.is_none() && inside.approved_at.is_none());
    assert!(
        activity
            .uses
            .iter()
            .all(|u| u.line.by_agent && u.line.agent_id == Some(bot_id))
    );
}

async fn set_agent(server: &mut ServerProcess, agent: AgentId, column: &str, value: Vec<u8>) {
    let sql = format!("UPDATE agents SET {column} = $1 WHERE id = $2");
    with_db(server, |pool| async move {
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(value)
            .bind(agent.to_string())
            .execute(&pool)
            .await
            .expect("set agent");
    })
    .await;
}

async fn set_agent_account(server: &mut ServerProcess, agent: AgentId, account: &str) {
    let account = account.to_owned();
    with_db(server, |pool| async move {
        sqlx::query("UPDATE agents SET account_id = $1 WHERE id = $2")
            .bind(account)
            .bind(agent.to_string())
            .execute(&pool)
            .await
            .expect("move agent");
    })
    .await;
}

/// An agent that signs a write with a query string in its path is refused
/// with `400` and nothing is logged, so the person's log still verifies
/// (the verifier takes the route exactly as signed). Its retry without the
/// query goes through and verifies too.
#[tokio::test(flavor = "multi_thread")]
async fn a_signed_write_with_a_query_never_breaks_the_log() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir, "ana@example.com").await;
    let vault = ana.find_vault("Personal").expect("vault");
    let project = ana.find_project(vault, "General").expect("project");
    let github = ana
        .add_item(
            vault,
            project,
            &Item::from_template(ItemKind::Login, "GitHub").expect("item"),
        )
        .await
        .expect("add");
    let bot = register(&server, &dir, "bot").await;
    ana.approve_agent(
        bot.id(),
        GrantRequest {
            projects: vec!["Personal/General".into()],
            vaults: Vec::new(),
            policy: Policy::default(),
        },
        &bot.pairing_code(),
    )
    .await
    .expect("approve");
    let session = Session::open(bot).await.expect("session");
    let body = serde_json::to_vec(&serde_json::json!({
        "item_id": github.item, "permission": "inject", "reason": "deploy",
    }))
    .expect("body");

    let res = session
        .agent()
        .send(reqwest::Method::POST, "/v1/agent/access?x=1", Some(&body))
        .await
        .expect("send");
    let status = res.status();
    ana.verify_audit().await.expect("the log verifies");
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);

    let res = session
        .agent()
        .send(reqwest::Method::POST, "/v1/agent/access", Some(&body))
        .await
        .expect("send");
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    ana.verify_audit().await.expect("the log verifies");
}

/// A passkey `access` signed with a host that is not in normal form (here
/// in mixed case) is refused with `400` and nothing is logged. The server
/// used to log the host normalized, which is not what the agent signed, so
/// `klav log verify` refused the chain for good. The same request with the
/// host in normal form goes through and verifies.
#[tokio::test(flavor = "multi_thread")]
async fn a_passkey_host_not_in_normal_form_never_breaks_the_log() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir, "ana@example.com").await;
    // A login with a passkey for shop.example, made by Klav.
    let created = ana
        .passkey_create(
            &klav_client::passkeys::PasskeyCreateRequest {
                origin: "https://shop.example".into(),
                rp_id: Some("shop.example".into()),
                rp_name: Some("Shop".into()),
                user_id: "dXNlci1hbmE".into(),
                user_name: "ana".into(),
                user_display_name: Some("Ana".into()),
                challenge: "Y3JlYXRlLWNoYWxsZW5nZS0wMTIzNDU2Nzg5".into(),
                ..Default::default()
            },
            true,
        )
        .await
        .expect("passkey");
    let klav_client::passkeys::PasskeyCreateOutcome::Created(created) = created else {
        panic!("no passkey created");
    };
    let item = created.item;
    let bot = register(&server, &dir, "bot").await;
    ana.approve_agent(
        bot.id(),
        GrantRequest {
            projects: vec!["Personal/General".into()],
            vaults: Vec::new(),
            policy: Policy::default(),
        },
        &bot.pairing_code(),
    )
    .await
    .expect("approve");
    let session = Session::open(bot).await.expect("session");
    let mut passkey = spec("entrar a la tienda");
    passkey.access[0].reference = "klav://Personal/General/Shop".into();
    passkey.access[0].permissions = vec![Permission::Passkey];
    passkey.access[0].domain = Some("shop.example".into());
    let request = session.task_request(&passkey, None).expect("request");
    let task = session
        .submit_task(&request)
        .await
        .expect("submit")
        .pending_task_id;
    let shown = ana
        .task(&task.to_string())
        .await
        .expect("card")
        .request_digest;
    ana.decide_task(task, true, &TaskChoice::default(), &shown)
        .await
        .expect("decide task");
    let access = |domain: &str| {
        serde_json::to_vec(&serde_json::json!({
            "item_id": item, "permission": "passkey", "reason": "entrar",
            "claims": {"domain": domain}, "task_id": task,
        }))
        .expect("body")
    };

    let res = session
        .agent()
        .send(
            reqwest::Method::POST,
            "/v1/agent/access",
            Some(&access("Shop.Example")),
        )
        .await
        .expect("send");
    let status = res.status();
    ana.verify_audit().await.expect("the log verifies");
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);

    let res = session
        .agent()
        .send(
            reqwest::Method::POST,
            "/v1/agent/access",
            Some(&access("shop.example")),
        )
        .await
        .expect("send");
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    ana.verify_audit().await.expect("the log verifies");
}
