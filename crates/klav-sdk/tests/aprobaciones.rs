//! The agent's runtime does not take the server's word for its policy
//! (ADR 0030 §3, layer 04 of the 2026-11 security round): a `200` its own
//! policy would ask about needs an approval the account signed (or a
//! verified task), a denial here sends nothing, the policy is checked again
//! with the version actually delivered, a refresh never goes back to an
//! older version, and attachments are bounded by their authenticated size.
//! A malicious server is played by editing its SQLite file while it is
//! stopped.

#[path = "../../klav-client/tests/common/mod.rs"]
mod common;

use std::future::Future;
use std::time::Duration;

use common::ServerProcess;
use klav_client::agents::GrantRequest;
use klav_client::ops::{ItemPatch, NewItem};
use klav_client::{ClientError, Home, ItemLocation, SignupRequest, Unlocked, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::ids::ItemId;
use klav_core::model::item::{Item, ItemKind};
use klav_core::policy::{Effect, Permission, Policy, Rule, Scope};
use klav_proto::auth::DeviceKind;
use klav_sdk::{Access, Agent, KeyStore, Registration, Session};
use sqlx::AnyPool;
use sqlx::any::AnyPoolOptions;

const PASSWORD: &str = "correct horse battery staple";
const EMAIL: &str = "ana@example.com";

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

async fn account(server: &ServerProcess, dir: &tempfile::TempDir) -> Unlocked {
    let (u, _) = signup(
        &Home::at(dir.path().join("laptop")),
        SignupRequest {
            server: server.url.clone(),
            email: EMAIL.into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
            invite: None,
        },
    )
    .await
    .expect("sign-up");
    u
}

/// Registers agent `bot` and approves it on Personal/General with `policy`.
async fn agent(
    server: &ServerProcess,
    dir: &tempfile::TempDir,
    ana: &mut Unlocked,
    policy: Policy,
) -> Agent {
    let home = Home::at(dir.path().join("agent-bot"));
    let (agent, _) = Agent::register(
        &home,
        Registration {
            name: "bot".into(),
            server: server.url.clone(),
            email: EMAIL.into(),
            note: None,
            key_store: KeyStore::File {
                path: dir.path().join("bot.key"),
            },
        },
    )
    .await
    .expect("register");
    ana.approve_agent(
        agent.id(),
        GrantRequest {
            projects: vec!["Personal/General".into()],
            vaults: Vec::new(),
            policy,
        },
        &agent.pairing_code(),
    )
    .await
    .expect("approve");
    agent
}

async fn add(ana: &mut Unlocked, kind: ItemKind, title: &str) -> ItemLocation {
    let vault = ana.find_vault("Personal").expect("vault");
    let project = ana.find_project(vault, "General").expect("project");
    ana.add_item(
        vault,
        project,
        &Item::from_template(kind, title).expect("item"),
    )
    .await
    .expect("add item")
}

fn rule(permission: Permission, effect: Effect, tags: &[&str]) -> Rule {
    Rule {
        permission,
        effect,
        scope: Scope {
            tags: tags.iter().map(|t| (*t).to_owned()).collect(),
            ..Scope::default()
        },
        expires_at: None,
        once: false,
        origin: None,
    }
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

fn tag(name: &str) -> ItemPatch {
    ItemPatch {
        add_tags: vec![name.into()],
        ..ItemPatch::default()
    }
}

/// The server's copy of the grant policy becomes `rules` (the signed grant
/// the agent holds does not change).
async fn server_policy(
    server: &mut ServerProcess,
    agent: klav_core::ids::AgentId,
    rules: Vec<Rule>,
) {
    with_db(server, |pool| async move {
        let payload: Vec<u8> = sqlx::query_scalar("SELECT grant_payload FROM agents WHERE id = $1")
            .bind(agent.to_string())
            .fetch_one(&pool)
            .await
            .expect("payload");
        let mut payload: serde_json::Value = serde_json::from_slice(&payload).expect("json");
        payload["policy"] = serde_json::to_value(Policy {
            rules,
            expires_at: None,
        })
        .expect("policy");
        sqlx::query("UPDATE agents SET grant_payload = $1 WHERE id = $2")
            .bind(serde_json::to_vec(&payload).expect("json"))
            .bind(agent.to_string())
            .execute(&pool)
            .await
            .expect("hostile grant");
    })
    .await;
}

fn is_security<T>(result: &Result<T, ClientError>) -> bool {
    matches!(result, Err(ClientError::Security(_)))
}

fn show<T>(result: &Result<T, ClientError>) -> String {
    match result {
        Ok(_) => "Ok".into(),
        Err(e) => format!("{e:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_ignores_ask_or_deny_gets_nothing_used() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir).await;
    let loc = add(&mut ana, ItemKind::Login, "GitHub").await;
    // Defaults (totp and update ask, delete deny) and create on ask.
    let bot = agent(
        &server,
        &dir,
        &mut ana,
        Policy {
            rules: vec![rule(Permission::Create, Effect::Ask, &[])],
            expires_at: None,
        },
    )
    .await;
    let bot_id = bot.id();
    let mut session = Session::open(bot).await.expect("session");

    // The server now allows everything, whatever the person signed.
    server_policy(
        &mut server,
        bot_id,
        [
            Permission::Totp,
            Permission::Update,
            Permission::Delete,
            Permission::Create,
        ]
        .into_iter()
        .map(|p| rule(p, Effect::Allow, &[]))
        .collect(),
    )
    .await;

    // A `200` without an approval for what the policy asks about.
    let got = session
        .access(loc.item, Permission::Totp, "2fa", None, None)
        .await;
    assert!(is_security(&got), "{}", show(&got));
    let got = session
        .update_item(loc.item, &tag("ci"), "tag it", Duration::ZERO)
        .await;
    assert!(is_security(&got), "{}", show(&got));
    let got = session
        .create_item(
            loc.project,
            &new_item("Staging"),
            "store it",
            Duration::ZERO,
        )
        .await;
    // Asked before the body goes (residual risk 35): never sent.
    assert!(
        matches!(&got, Err(ClientError::Security(m)) if m.contains("nothing was sent")),
        "{}",
        show(&got)
    );

    // Denied here: not even sent, so the server cannot apply it.
    let got = session
        .trash_item(loc.item, "clean up", Duration::ZERO)
        .await;
    assert!(
        matches!(&got, Err(ClientError::Denied(_))),
        "{}",
        show(&got)
    );
    ana.sync().await.expect("sync");
    let still = ana.open_item(loc).expect("still there");
    assert!(still.tags().is_empty(), "the update was written");
    assert!(ana.find_item("GitHub").is_ok(), "the item was trashed");
    assert!(ana.find_item("Staging").is_err(), "the create was written");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_approval_the_account_did_not_sign_is_refused() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir).await;
    let loc = add(&mut ana, ItemKind::Login, "GitHub").await;
    let bot = agent(&server, &dir, &mut ana, Policy::default()).await;
    let mut session = Session::open(bot).await.expect("session");

    let Access::Pending { approval_id, .. } = session
        .access(loc.item, Permission::Totp, "2fa", None, None)
        .await
        .expect("asks")
    else {
        panic!("totp asks by default");
    };
    // The server marks it approved without the person's signature.
    with_db(&mut server, |pool| async move {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis() as i64;
        sqlx::query(
            "UPDATE approvals SET status = 'approved', decided_at = $1, lease_until = $2, \
             signature = NULL WHERE id = $3",
        )
        .bind(now)
        .bind(now + 15 * 60 * 1000)
        .bind(approval_id.to_string())
        .execute(&pool)
        .await
        .expect("forge approval");
    })
    .await;

    // Reused by the server on a plain retry, or named by the agent.
    let got = session
        .access(loc.item, Permission::Totp, "2fa", None, None)
        .await;
    assert!(is_security(&got), "{}", show(&got));
    let got = session.claim_approval(approval_id).await;
    assert!(is_security(&got), "{}", show(&got));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_policy_is_checked_again_with_the_version_delivered() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir).await;
    let github = add(&mut ana, ItemKind::Login, "GitHub").await;
    let gitlab = add(&mut ana, ItemKind::Login, "GitLab").await;
    let bot = agent(
        &server,
        &dir,
        &mut ana,
        Policy {
            rules: vec![
                rule(Permission::Inject, Effect::Allow, &[]),
                rule(Permission::Inject, Effect::Deny, &["prod"]),
                rule(Permission::Update, Effect::Allow, &[]),
                rule(Permission::Update, Effect::Deny, &["locked"]),
            ],
            expires_at: None,
        },
    )
    .await;
    let mut session = Session::open(bot).await.expect("session");

    // The person tags it `prod` after the agent listed it: the listed copy
    // (and the claims sent) say nothing, the version delivered does.
    let mut edited = ana.open_item(github).expect("open");
    edited.add_tag("prod").expect("tag");
    ana.update_item(github, &edited).await.expect("update");
    let got = session
        .access(github.item, Permission::Inject, "deploy", None, None)
        .await;
    assert!(
        matches!(&got, Err(ClientError::Denied(_))),
        "{}",
        show(&got)
    );

    // `add_tags` cannot take an item where `update` is denied: refused
    // here, before anything is sent.
    let got = session
        .update_item(gitlab.item, &tag("locked"), "lock it", Duration::ZERO)
        .await;
    assert!(
        matches!(&got, Err(ClientError::Denied(m)) if m.contains("on this item")),
        "{}",
        show(&got)
    );
    ana.sync().await.expect("sync");
    assert!(ana.open_item(gitlab).expect("open").tags().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_never_goes_back_to_an_older_version() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir).await;
    let loc = add(&mut ana, ItemKind::Login, "GitHub").await;
    let mut edited = ana.open_item(loc).expect("open");
    edited.set_title("GitHub (work)").expect("title");
    ana.update_item(loc, &edited).await.expect("update");
    let bot = agent(&server, &dir, &mut ana, Policy::default()).await;
    let mut session = Session::open(bot).await.expect("session");
    assert_eq!(
        session.item_info(loc.item).expect("info").title,
        "GitHub (work)"
    );

    // The server lists version 1 again (it keeps the old versions).
    let item = loc.item;
    with_db(&mut server, |pool| async move {
        sqlx::query(
            "UPDATE items SET version = 1, \
             wrapped_key = (SELECT wrapped_key FROM item_versions WHERE item_id = $1 AND version = 1), \
             overview = (SELECT overview FROM item_versions WHERE item_id = $1 AND version = 1), \
             details = (SELECT details FROM item_versions WHERE item_id = $1 AND version = 1) \
             WHERE id = $1",
        )
        .bind(item.to_string())
        .execute(&pool)
        .await
        .expect("roll back");
    })
    .await;
    session.refresh().await.expect("refresh");
    assert_eq!(
        session.item_info(loc.item).expect("info").title,
        "GitHub (work)"
    );
    let got = session
        .access(loc.item, Permission::Inject, "deploy", None, None)
        .await;
    assert!(
        matches!(&got, Err(ClientError::Rollback(_))),
        "{}",
        show(&got)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn attachments_are_bounded_by_their_authenticated_size() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir).await;
    let loc = add(&mut ana, ItemKind::Note, "APNs").await;
    ana.attach("APNs", "key", "AuthKey.p8", None, b"MARKER-p8")
        .await
        .expect("attach");
    let bot = agent(&server, &dir, &mut ana, Policy::default()).await;
    let mut session = Session::open(bot).await.expect("session");
    let (_, files) = session
        .access_for_inject(loc.item, "sign the token", Duration::ZERO)
        .await
        .expect("inject");
    assert_eq!(files.len(), 1);

    // The server pads the stored ciphertext and lists the larger size.
    let (vault, attachment): (String, String) = with_db(&mut server, |pool| async move {
        let row: (String, String) =
            sqlx::query_as("SELECT vault_id, id FROM attachments WHERE item_id = $1")
                .bind(loc.item.to_string())
                .fetch_one(&pool)
                .await
                .expect("attachment");
        sqlx::query("UPDATE attachments SET size = size + 4096 WHERE id = $1")
            .bind(&row.1)
            .execute(&pool)
            .await
            .expect("size");
        row
    })
    .await;
    let path = server
        .dir
        .path()
        .join("data")
        .join("attachments")
        .join(vault)
        .join(attachment);
    let mut content = std::fs::read(&path).expect("stored");
    content.extend_from_slice(&[0u8; 4096]);
    std::fs::write(&path, content).expect("pad");

    let got = session
        .access_for_inject(loc.item, "sign the token", Duration::ZERO)
        .await;
    assert!(
        matches!(&got, Err(ClientError::Corrupt(m)) if m.contains("byte file")),
        "{}",
        show(&got)
    );
    let _: ItemId = loc.item;
}
