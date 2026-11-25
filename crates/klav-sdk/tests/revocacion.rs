//! Revoking an agent and rotating its projects' keys against a real server
//! (ADR 0014 §7): the revoked agent is never re-granted, a rotation that
//! misses an item key is refused, a rotation that stops half way is
//! finished by running it again, and nothing is written with a project key
//! that already rotated. A malicious server is played by editing its
//! SQLite file while it is stopped.

#[path = "../../klav-client/tests/common/mod.rs"]
mod common;

use std::future::Future;
use std::time::Duration;

use common::ServerProcess;
use klav_client::agents::GrantRequest;
use klav_client::ops::NewItem;
use klav_client::{Home, LoginRequest, SignupRequest, Unlocked, login, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::secret_key::SecretKey;
use klav_core::ids::{AgentId, ItemId, ProjectId};
use klav_core::model::item::{Item, ItemKind};
use klav_core::policy::Policy;
use klav_proto::auth::DeviceKind;
use klav_sdk::{Agent, KeyStore, Registration, Session};
use secrecy::ExposeSecret;
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

async fn account(server: &ServerProcess, dir: &tempfile::TempDir) -> (Unlocked, String) {
    let (u, kit) = signup(
        &Home::at(dir.path().join("laptop")),
        SignupRequest {
            server: server.url.clone(),
            email: EMAIL.into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("sign-up");
    let secret = kit.secret_key().to_text().expose_secret().to_owned();
    (u, secret)
}

async fn second_device(server: &ServerProcess, dir: &tempfile::TempDir, secret: &str) -> Unlocked {
    login(
        &Home::at(dir.path().join("phone")),
        LoginRequest {
            server: server.url.clone(),
            email: EMAIL.into(),
            password: MasterPassword::new(PASSWORD),
            secret_key: SecretKey::parse(secret).expect("secret key"),
            device_name: "phone".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("login")
}

/// Registers agent `name` and approves it with `projects`.
async fn agent(
    server: &ServerProcess,
    dir: &tempfile::TempDir,
    ana: &mut Unlocked,
    name: &str,
    projects: &[&str],
) -> Agent {
    let home = Home::at(dir.path().join(format!("agent-{name}")));
    let (agent, _) = Agent::register(
        &home,
        Registration {
            name: name.into(),
            server: server.url.clone(),
            email: EMAIL.into(),
            note: None,
            key_store: KeyStore::File {
                path: dir.path().join(format!("{name}.key")),
            },
        },
    )
    .await
    .expect("register");
    approve(ana, agent.id(), &agent.pairing_code(), projects).await;
    agent
}

async fn approve(ana: &mut Unlocked, id: AgentId, pairing: &str, projects: &[&str]) {
    ana.approve_agent(
        id,
        GrantRequest {
            projects: projects.iter().map(|p| (*p).to_owned()).collect(),
            vaults: Vec::new(),
            policy: Policy::default(),
        },
        pairing,
    )
    .await
    .expect("approve");
}

async fn add(ana: &mut Unlocked, project: &str, title: &str) -> klav_client::ItemLocation {
    let vault = ana.find_vault("Personal").expect("vault");
    let project = ana.find_project(vault, project).expect("project");
    ana.add_item(
        vault,
        project,
        &Item::from_template(ItemKind::Login, title).expect("item"),
    )
    .await
    .expect("add item")
}

/// Takes the wrapped key of `item` away from the server's listing of the
/// project keys without telling any device (no new revision): the server
/// "forgets" one key when a rotation asks for them. Returns the key, to put
/// it back.
async fn hide_item_key(server: &mut ServerProcess, item: ItemId) -> Vec<u8> {
    with_db(server, |pool| async move {
        let key: Vec<u8> = sqlx::query_scalar("SELECT wrapped_key FROM items WHERE id = $1")
            .bind(item.to_string())
            .fetch_one(&pool)
            .await
            .expect("key");
        sqlx::query("UPDATE items SET wrapped_key = NULL WHERE id = $1")
            .bind(item.to_string())
            .execute(&pool)
            .await
            .expect("hide");
        key
    })
    .await
}

async fn restore_item_key(server: &mut ServerProcess, item: ItemId, key: Vec<u8>) {
    with_db(server, |pool| async move {
        sqlx::query("UPDATE items SET wrapped_key = $1 WHERE id = $2")
            .bind(key)
            .bind(item.to_string())
            .execute(&pool)
            .await
            .expect("restore");
    })
    .await;
}

async fn project_version(server: &mut ServerProcess, project: ProjectId) -> i64 {
    with_db(server, |pool| async move {
        sqlx::query_scalar("SELECT version FROM projects WHERE id = $1")
            .bind(project.to_string())
            .fetch_one(&pool)
            .await
            .expect("version")
    })
    .await
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

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_agent_is_never_granted_the_new_keys() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    add(&mut ana, "General", "GitHub").await;
    let general = ["Personal/General"];
    let bot = agent(&server, &dir, &mut ana, "bot", &general).await;
    let helper = agent(&server, &dir, &mut ana, "helper", &general).await;
    agent(&server, &dir, &mut ana, "keeper", &general).await;

    // Revoked without rotating; then the server marks it active again.
    let report = ana.revoke_agent(bot.id(), false).await.expect("revoke");
    assert!(report.rotated.is_empty() && report.regranted.is_empty());
    let bot_id = bot.id();
    with_db(&mut server, |pool| async move {
        sqlx::query("UPDATE agents SET status = 'active', revoked_at = NULL WHERE id = $1")
            .bind(bot_id.to_string())
            .execute(&pool)
            .await
            .expect("un-revoke");
    })
    .await;

    // Revoking another agent with a rotation re-grants only the one that
    // was never revoked, and says so.
    let report = ana.revoke_agent(helper.id(), true).await.expect("revoke");
    assert!(report.complete(), "{report:?}");
    assert_eq!(report.rotated.len(), 1);
    assert_eq!(report.regranted, vec!["keeper".to_owned()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rotation_the_server_leaves_an_item_out_of_is_refused_and_finished_later() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let vault = ana.find_vault("Personal").expect("vault");
    ana.create_project(vault, "Work").await.expect("project");
    let general = ana.find_project(vault, "General").expect("general");
    let work = ana.find_project(vault, "Work").expect("work");
    // Projects rotate in ID order: the server will fail the second one.
    let (first, second) = if general < work {
        (general, work)
    } else {
        (work, general)
    };
    let name = |p: ProjectId| if p == general { "General" } else { "Work" };
    add(&mut ana, name(first), "First").await;
    add(&mut ana, name(second), "Second A").await;
    let hidden = add(&mut ana, name(second), "Second B").await;
    let both = ["Personal/General", "Personal/Work"];
    let bot = agent(&server, &dir, &mut ana, "bot", &both).await;
    agent(&server, &dir, &mut ana, "keeper", &both).await;

    let key = hide_item_key(&mut server, hidden.item).await;
    let report = ana.revoke_agent(bot.id(), true).await.expect("revoke");
    assert!(!report.complete());
    assert_eq!(report.rotated.len(), 1, "{report:?}");
    assert_eq!(report.rotated[0].project_id, first);
    let failed = report.failed.clone().expect("failed");
    assert!(failed.contains("left out 1"), "{failed}");
    assert_eq!(report.pending, vec![format!("Personal/{}", name(second))]);
    // The agents that keep working got the key that did rotate.
    assert_eq!(report.regranted, vec!["keeper".to_owned()]);
    assert_eq!(project_version(&mut server, first).await, 2);
    assert_eq!(project_version(&mut server, second).await, 1);

    // Run again once the server lists every key: the first project is not
    // rotated twice, the second one is, with both of its items.
    restore_item_key(&mut server, hidden.item, key).await;
    let report = ana.revoke_agent(bot.id(), true).await.expect("retry");
    assert!(report.complete(), "{report:?}");
    assert_eq!(
        report.already_rotated,
        vec![format!("Personal/{}", name(first))]
    );
    assert_eq!(report.rotated.len(), 1);
    assert_eq!(report.rotated[0].project_id, second);
    assert_eq!(report.rotated[0].items, 2);
    assert_eq!(project_version(&mut server, first).await, 2);
    assert_eq!(project_version(&mut server, second).await, 2);
    ana.sync().await.expect("sync");
    ana.open_item(hidden).expect("still opens");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_that_missed_the_rotation_writes_with_the_new_key() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut laptop, secret) = account(&server, &dir).await;
    let loc = add(&mut laptop, "General", "GitHub").await;
    let mut phone = second_device(&server, &dir, &secret).await;
    phone.sync().await.expect("sync");

    // The laptop rotates; the phone writes before syncing.
    laptop
        .rotate_project_key(loc.project)
        .await
        .expect("rotate");
    let mut edited = phone.open_item(loc).expect("open");
    edited.set_title("GitHub (work)").expect("title");
    phone.update_item(loc, &edited).await.expect("update");
    let added = phone
        .add_item(
            loc.vault,
            loc.project,
            &Item::from_template(ItemKind::Login, "GitLab").expect("item"),
        )
        .await
        .expect("add");

    // Both writes open with the new key on the laptop.
    laptop.sync().await.expect("sync");
    assert_eq!(
        laptop.open_item(loc).expect("opens").title(),
        "GitHub (work)"
    );
    assert_eq!(laptop.open_item(added).expect("opens").title(), "GitLab");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_does_not_write_with_a_project_key_that_rotated() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let loc = add(&mut ana, "General", "GitHub").await;
    let general = ["Personal/General"];
    let bot = agent(&server, &dir, &mut ana, "bot", &general).await;
    let (bot_id, pairing) = (bot.id(), bot.pairing_code());
    let mut session = Session::open(bot).await.expect("session");

    // The key rotates without a new grant: the agent's key is the old one,
    // and an item it wrapped with it would not open for the person.
    ana.rotate_project_key(loc.project).await.expect("rotate");
    session.refresh().await.expect("refresh");
    let refused = session
        .create_item(
            loc.project,
            &new_item("Staging"),
            "store it",
            Duration::ZERO,
        )
        .await;
    assert!(
        matches!(&refused, Err(klav_client::ClientError::Denied(m)) if m.contains("key")),
        "{:?}",
        refused.as_ref().map(|_| ())
    );

    // With a new grant (what `revoke --rotate` does for the others), the
    // session picks up the new key and the item opens for the person.
    approve(&mut ana, bot_id, &pairing, &general).await;
    session.refresh().await.expect("refresh");
    let info = session
        .create_item(
            loc.project,
            &new_item("Staging"),
            "store it",
            Duration::ZERO,
        )
        .await
        .expect("create");
    ana.sync().await.expect("sync");
    let created = ana.find_item(&info.reference).expect("listed");
    assert_eq!(ana.open_item(created).expect("opens").title(), "Staging");
}

/// A narrowing change of `id`'s grant, as `klav agent approve` sends it.
fn narrowing(projects: &[&str]) -> klav_client::grant_change::GrantChange {
    klav_client::grant_change::GrantChange {
        projects: projects.iter().map(|p| (*p).to_owned()).collect(),
        vaults: Vec::new(),
        policy: klav_client::grant_change::ChangePolicy::Rules(Policy {
            rules: vec![klav_core::policy::Rule::new(
                klav_core::policy::Permission::Reveal,
                klav_core::policy::Effect::Deny,
            )],
            expires_at: None,
        }),
        rotate_removed: false,
    }
}

/// The grant row the server keeps for `id`: payload, signature, version.
async fn grant_row(server: &mut ServerProcess, id: AgentId) -> (Vec<u8>, Vec<u8>, i64) {
    with_db(server, |pool| async move {
        let row: (Vec<u8>, Vec<u8>, i64) = sqlx::query_as(
            "SELECT grant_payload, grant_signature, grant_version FROM agents WHERE id = $1",
        )
        .bind(id.to_string())
        .fetch_one(&pool)
        .await
        .expect("grant row");
        row
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_grant_change_never_reaches_an_agent_this_device_revoked() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    add(&mut ana, "General", "GitHub").await;
    let general = ["Personal/General"];
    let bot = agent(&server, &dir, &mut ana, "bot", &general).await;
    agent(&server, &dir, &mut ana, "keeper", &general).await;

    // Revoked and rotated here; then the server calls it active again,
    // with its old grant (T24).
    let report = ana.revoke_agent(bot.id(), true).await.expect("revoke");
    assert!(report.complete(), "{report:?}");
    let bot_id = bot.id();
    with_db(&mut server, |pool| async move {
        sqlx::query("UPDATE agents SET status = 'active', revoked_at = NULL WHERE id = $1")
            .bind(bot_id.to_string())
            .execute(&pool)
            .await
            .expect("un-revoke");
    })
    .await;

    // A narrowing change asks for nothing, so any local process could
    // send it: it is refused before a grant with the new keys is built.
    let refused = ana
        .prepare_grant_change(bot.id(), &narrowing(&general))
        .await
        .expect_err("revoked here");
    assert!(
        matches!(refused, klav_client::ClientError::Security(_)),
        "{refused:?}"
    );
    let refused = ana
        .change_grant(bot.id(), &narrowing(&general), "any")
        .await
        .expect_err("revoked here");
    assert!(
        matches!(refused, klav_client::ClientError::Security(_)),
        "{refused:?}"
    );
    // The editor shows it as not active, whatever the server says.
    let editor = ana.grant_editor(bot.id()).await.expect("editor");
    assert_eq!(
        editor.reason,
        Some(klav_client::grant_change::ReadOnlyReason::NotActive)
    );
    // An approval has no check of its own: the one where every grant this
    // device signs goes out (`upload_grant`) refuses it.
    let before = grant_row(&mut server, bot.id()).await.2;
    let refused = ana
        .approve_agent(
            bot.id(),
            GrantRequest {
                projects: general.iter().map(|p| (*p).to_owned()).collect(),
                vaults: Vec::new(),
                policy: Policy::default(),
            },
            &bot.pairing_code(),
        )
        .await
        .expect_err("revoked here");
    assert!(
        matches!(&refused, klav_client::ClientError::Security(m) if m.contains("never granted again")),
        "{refused:?}"
    );
    assert_eq!(grant_row(&mut server, bot.id()).await.2, before);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_older_grant_replayed_by_the_server_leaves_no_project_out_of_the_key_change() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let vault = ana.find_vault("Personal").expect("vault");
    ana.create_project(vault, "Work").await.expect("project");
    let general = ana.find_project(vault, "General").expect("general");
    let work = ana.find_project(vault, "Work").expect("work");
    add(&mut ana, "General", "GitHub").await;
    add(&mut ana, "Work", "Jira").await;
    let bot = agent(&server, &dir, &mut ana, "bot", &["Personal/General"]).await;
    let old = grant_row(&mut server, bot.id()).await;

    // Widened to Work, then the server serves the first grant again: it
    // is signed by the account, so it verifies.
    let change = klav_client::grant_change::GrantChange {
        projects: vec!["Personal/General".into(), "Personal/Work".into()],
        vaults: Vec::new(),
        policy: klav_client::grant_change::ChangePolicy::Rules(Policy::default()),
        rotate_removed: false,
    };
    let prepared = ana
        .prepare_grant_change(bot.id(), &change)
        .await
        .expect("prepare");
    let digest = prepared.preview().digest.clone();
    ana.change_grant(bot.id(), &change, &digest)
        .await
        .expect("widen");
    let bot_id = bot.id();
    with_db(&mut server, |pool| async move {
        sqlx::query(
            "UPDATE agents SET grant_payload = $1, grant_signature = $2, grant_version = $3 WHERE id = $4",
        )
        .bind(old.0)
        .bind(old.1)
        .bind(old.2)
        .bind(bot_id.to_string())
        .execute(&pool)
        .await
        .expect("replay");
    })
    .await;
    let served = ana.agent("bot").await.expect("agent");
    assert_eq!(served.grant.as_ref().map(|g| g.projects.len()), Some(1));

    // «What it saw» and the key change both come from the log as well.
    let seen = ana.agent_exposure(bot.id()).await.expect("exposure");
    let mut seen: Vec<ProjectId> = seen.projects.iter().map(|p| p.project_id).collect();
    seen.sort();
    let mut both = vec![general, work];
    both.sort();
    assert_eq!(seen, both);
    let report = ana.revoke_agent(bot.id(), true).await.expect("revoke");
    assert!(report.complete(), "{report:?}");
    let mut rotated: Vec<ProjectId> = report.rotated.iter().map(|r| r.project_id).collect();
    rotated.sort();
    assert_eq!(rotated, both);
    assert_eq!(project_version(&mut server, work).await, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_hides_the_grant_and_the_approval_still_gets_the_key_changed() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let vault = ana.find_vault("Personal").expect("vault");
    let general = ana.find_project(vault, "General").expect("general");
    add(&mut ana, "General", "GitHub").await;
    let bot = agent(&server, &dir, &mut ana, "bot", &["Personal/General"]).await;
    let bot_id = bot.id();
    with_db(&mut server, |pool| async move {
        sqlx::query(
            "UPDATE agents SET grant_payload = NULL, grant_signature = NULL, approved_at = NULL WHERE id = $1",
        )
        .bind(bot_id.to_string())
        .execute(&pool)
        .await
        .expect("hide");
    })
    .await;
    let report = ana.revoke_agent(bot.id(), true).await.expect("revoke");
    assert!(report.complete(), "{report:?}");
    assert_eq!(report.rotated.len(), 1, "{report:?}");
    assert_eq!(report.rotated[0].project_id, general);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_crash_after_a_rotation_never_leaves_the_others_on_the_old_key() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let vault = ana.find_vault("Personal").expect("vault");
    let general = ana.find_project(vault, "General").expect("general");
    add(&mut ana, "General", "GitHub").await;
    let bot = agent(&server, &dir, &mut ana, "bot", &["Personal/General"]).await;
    agent(&server, &dir, &mut ana, "keeper", &["Personal/General"]).await;

    let first = ana.revoke_first(bot.id(), true).await.expect("revoke");
    assert!(first.failed.is_none(), "{first:?}");
    // The process dies right after the server rotated the project, at the
    // first write after it (a directory where `revocations.bin`'s
    // temporary file goes stands for the crash). Had the mark that the
    // project rotated been written first, it would be on disk now, and
    // the restart below would find nothing left with keeper on the old
    // key.
    let blocker = ana
        .home()
        .file(&format!(".revocations.bin.{}.tmp", std::process::id()));
    std::fs::create_dir(&blocker).expect("blocker");
    let cut = ana.rotation_step(bot.id()).await;
    std::fs::remove_dir(&blocker).expect("blocker");
    assert!(cut.is_err(), "{cut:?}");
    assert_eq!(project_version(&mut server, general).await, 2);

    // A restart reads only what reached the disk.
    let home = ana.home().clone();
    drop(ana);
    let mut ana =
        klav_client::unlock_with_password(&home, &MasterPassword::new(PASSWORD)).expect("unlock");
    let left = ana.pending_revocations().expect("record");
    assert_eq!(left.len(), 1, "{left:?}");
    assert_eq!(left[0].pending, vec!["Personal/General".to_owned()]);

    // Keeper gets the new key before anything says done; the project
    // rotates once more (one more version, nothing lost).
    let mut regranted = Vec::new();
    loop {
        let step = ana.rotation_step(bot.id()).await.expect("step");
        assert!(step.failed.is_none(), "{step:?}");
        regranted.extend(step.regranted);
        if step.done {
            break;
        }
    }
    assert!(regranted.iter().any(|n| n == "keeper"), "{regranted:?}");
    assert!(ana.pending_revocations().expect("record").is_empty());
    assert_eq!(project_version(&mut server, general).await, 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_save_of_the_regrants_leaves_the_project_to_rotate_again() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let vault = ana.find_vault("Personal").expect("vault");
    let general = ana.find_project(vault, "General").expect("general");
    add(&mut ana, "General", "GitHub").await;
    let bot = agent(&server, &dir, &mut ana, "bot", &["Personal/General"]).await;
    agent(&server, &dir, &mut ana, "keeper", &["Personal/General"]).await;

    let first = ana.revoke_first(bot.id(), true).await.expect("revoke");
    assert!(first.failed.is_none(), "{first:?}");
    // `revocations.bin` cannot be written (a directory where its
    // temporary file goes): the step stops right after the server rotated
    // its one project. Were the project marked rotated first, the next
    // step would find nothing left and say done with keeper on the old key.
    let blocker = ana
        .home()
        .file(&format!(".revocations.bin.{}.tmp", std::process::id()));
    std::fs::create_dir(&blocker).expect("blocker");
    let cut = ana.rotation_step(bot.id()).await;
    std::fs::remove_dir(&blocker).expect("blocker");
    assert!(cut.is_err(), "{cut:?}");
    assert_eq!(project_version(&mut server, general).await, 2);

    let mut regranted = Vec::new();
    loop {
        let step = ana.rotation_step(bot.id()).await.expect("step");
        assert!(step.failed.is_none(), "{step:?}");
        regranted.extend(step.regranted);
        if step.done {
            break;
        }
    }
    assert!(regranted.iter().any(|n| n == "keeper"), "{regranted:?}");
    assert_eq!(project_version(&mut server, general).await, 3);
}

/// Deletes the log from `id`'s last `agent.granted` event on, as a server
/// that ends the chain early: the head is the last row it keeps.
async fn cut_log_at_last_grant(server: &mut ServerProcess, id: AgentId) {
    with_db(server, |pool| async move {
        let seq: i64 = sqlx::query_scalar(
            "SELECT MAX(seq) FROM audit_events WHERE action = 'agent.granted' AND agent_id = $1",
        )
        .bind(id.to_string())
        .fetch_one(&pool)
        .await
        .expect("grant event");
        sqlx::query("DELETE FROM audit_events WHERE seq >= $1")
            .bind(seq)
            .execute(&pool)
            .await
            .expect("cut");
    })
    .await;
}

/// Widens `bot` from `Personal/General` to `Personal/Work` too.
async fn widen_to_work(ana: &mut Unlocked, bot: AgentId) {
    let change = klav_client::grant_change::GrantChange {
        projects: vec!["Personal/General".into(), "Personal/Work".into()],
        vaults: Vec::new(),
        policy: klav_client::grant_change::ChangePolicy::Rules(Policy::default()),
        rotate_removed: false,
    };
    let prepared = ana
        .prepare_grant_change(bot, &change)
        .await
        .expect("prepare");
    let digest = prepared.preview().digest.clone();
    ana.change_grant(bot, &change, &digest)
        .await
        .expect("widen");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_log_the_server_cuts_short_neither_keeps_a_project_out_nor_lets_it_say_done() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let vault = ana.find_vault("Personal").expect("vault");
    ana.create_project(vault, "Work").await.expect("project");
    let work = ana.find_project(vault, "Work").expect("work");
    add(&mut ana, "General", "GitHub").await;
    add(&mut ana, "Work", "Jira").await;
    let bot = agent(&server, &dir, &mut ana, "bot", &["Personal/General"]).await;
    let old = grant_row(&mut server, bot.id()).await;
    widen_to_work(&mut ana, bot.id()).await;

    // The server serves the first grant again and ends the log before the
    // grant that added Work: neither names Work any more.
    let bot_id = bot.id();
    with_db(&mut server, |pool| async move {
        sqlx::query(
            "UPDATE agents SET grant_payload = $1, grant_signature = $2, grant_version = $3 WHERE id = $4",
        )
        .bind(old.0)
        .bind(old.1)
        .bind(old.2)
        .bind(bot_id.to_string())
        .execute(&pool)
        .await
        .expect("replay");
    })
    .await;
    cut_log_at_last_grant(&mut server, bot.id()).await;

    // This device wrote down what it signed: Work changes all the same,
    // and the key change is not done while the log lacks that grant.
    let report = ana.revoke_agent(bot.id(), true).await.expect("revoke");
    assert!(
        report.rotated.iter().any(|r| r.project_id == work),
        "{report:?}"
    );
    assert_eq!(project_version(&mut server, work).await, 2);
    assert!(report.log_unchecked, "{report:?}");
    assert!(!report.complete(), "{report:?}");
    let said: Vec<&String> = report.warnings.iter().chain(report.failed.iter()).collect();
    assert!(
        said.iter().any(|w| w.contains("grant version 2")),
        "{said:?}"
    );

    // Written down, so `klavd` and the apps keep showing it after the
    // projects rotated, also after a restart.
    let home = ana.home().clone();
    drop(ana);
    let ana =
        klav_client::unlock_with_password(&home, &MasterPassword::new(PASSWORD)).expect("unlock");
    let left = ana.pending_revocations().expect("record");
    assert_eq!(left.len(), 1, "{left:?}");
    assert!(
        left[0].log_unchecked && left[0].pending.is_empty(),
        "{left:?}"
    );
    assert!(left[0].needs_work());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_hides_the_approval_and_cuts_the_log_still_gets_the_signed_projects_changed()
{
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let vault = ana.find_vault("Personal").expect("vault");
    let general = ana.find_project(vault, "General").expect("general");
    add(&mut ana, "General", "GitHub").await;
    let bot = agent(&server, &dir, &mut ana, "bot", &["Personal/General"]).await;
    let bot_id = bot.id();
    with_db(&mut server, |pool| async move {
        sqlx::query(
            "UPDATE agents SET grant_payload = NULL, grant_signature = NULL, approved_at = NULL WHERE id = $1",
        )
        .bind(bot_id.to_string())
        .execute(&pool)
        .await
        .expect("hide");
    })
    .await;
    cut_log_at_last_grant(&mut server, bot.id()).await;

    // No grant, no approval, no grant in the log: only this device's
    // record names General.
    let report = ana.revoke_agent(bot.id(), true).await.expect("revoke");
    assert_eq!(report.rotated.len(), 1, "{report:?}");
    assert_eq!(report.rotated[0].project_id, general);
    assert!(!report.exposure.projects_unknown, "{report:?}");
    assert!(report.log_unchecked && !report.complete(), "{report:?}");
}

/// Makes the log fail to verify (a bad hash on the first event), and
/// returns the hash to put back.
async fn break_log(server: &mut ServerProcess) -> Vec<u8> {
    with_db(server, |pool| async move {
        let hash: Vec<u8> = sqlx::query_scalar("SELECT hash FROM audit_events WHERE seq = 1")
            .fetch_one(&pool)
            .await
            .expect("hash");
        sqlx::query("UPDATE audit_events SET hash = X'00' WHERE seq = 1")
            .execute(&pool)
            .await
            .expect("break");
        hash
    })
    .await
}

async fn mend_log(server: &mut ServerProcess, hash: Vec<u8>) {
    with_db(server, |pool| async move {
        sqlx::query("UPDATE audit_events SET hash = $1 WHERE seq = 1")
            .bind(hash)
            .execute(&pool)
            .await
            .expect("mend");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_change_in_steps_waits_for_the_log_it_could_not_read() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let vault = ana.find_vault("Personal").expect("vault");
    let general = ana.find_project(vault, "General").expect("general");
    add(&mut ana, "General", "GitHub").await;
    let bot = agent(&server, &dir, &mut ana, "bot", &["Personal/General"]).await;
    let hash = break_log(&mut server).await;

    // `klavd`'s path: the revocation, then steps.
    let first = ana.revoke_first(bot.id(), true).await.expect("revoke");
    assert!(first.log_unchecked && first.failed.is_none(), "{first:?}");
    let failed = loop {
        let step = ana.rotation_step(bot.id()).await.expect("step");
        assert!(!step.done, "done without the log: {step:?}");
        if step.failed.is_some() {
            break step.failed;
        }
    };
    assert!(
        failed.as_deref().is_some_and(|f| f.contains("audit log")),
        "{failed:?}"
    );
    assert_eq!(project_version(&mut server, general).await, 2);
    let left = ana.pending_revocations().expect("record");
    assert_eq!(left.len(), 1, "{left:?}");
    assert!(
        left[0].log_unchecked && left[0].pending.is_empty(),
        "{left:?}"
    );

    // A later run reads the log, and only then is it done.
    mend_log(&mut server, hash).await;
    let step = ana.rotation_step(bot.id()).await.expect("step");
    assert!(step.done && step.failed.is_none(), "{step:?}");
    assert!(ana.pending_revocations().expect("record").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deleted_vault_is_skipped_and_its_key_change_comes_back_when_restored() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let work = ana.create_vault("Work").await.expect("vault");
    ana.create_project(work, "Infra").await.expect("project");
    let infra = ana.find_project(work, "Infra").expect("infra");
    add(&mut ana, "General", "GitHub").await;
    let bot = agent(
        &server,
        &dir,
        &mut ana,
        "bot",
        &["Personal/General", "Work/Infra"],
    )
    .await;
    let set_deleted = |deleted: Option<i64>| {
        let work = work.to_string();
        move |pool: AnyPool| async move {
            sqlx::query(
                "UPDATE vaults SET deleted_at = $1, revision = revision + 1, meta_revision = revision + 1 WHERE id = $2",
            )
            .bind(deleted)
            .bind(work)
            .execute(&pool)
            .await
            .expect("vault");
        }
    };
    // Deleted now: a time past the retention period would be purged when
    // the server starts.
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("ms");
    with_db(&mut server, set_deleted(Some(now))).await;

    // The server refuses a deleted vault's writes: its project is skipped,
    // said, and never blocks the rest from being done.
    let report = ana.revoke_agent(bot.id(), true).await.expect("revoke");
    assert!(report.complete(), "{report:?}");
    assert_eq!(report.rotated.len(), 1, "{report:?}");
    assert!(
        report
            .skipped
            .iter()
            .any(|s| s.starts_with("Work/Infra") && s.contains("its vault is deleted")),
        "{report:?}"
    );
    let left = ana.pending_revocations().expect("record");
    assert_eq!(left.len(), 1, "{left:?}");
    assert!(
        left[0].pending.is_empty() && !left[0].needs_work(),
        "{left:?}"
    );
    assert_eq!(left[0].skipped.len(), 1, "{left:?}");

    // Restored: its key change is owed again, and a step does it.
    with_db(&mut server, set_deleted(None)).await;
    ana.sync().await.expect("sync");
    let left = ana.pending_revocations().expect("record");
    assert_eq!(left[0].pending, vec!["Work/Infra".to_owned()], "{left:?}");
    assert!(left[0].needs_work());
    loop {
        let step = ana.rotation_step(bot.id()).await.expect("step");
        assert!(step.failed.is_none(), "{step:?}");
        if step.done {
            break;
        }
    }
    assert_eq!(project_version(&mut server, infra).await, 2);
    assert!(ana.pending_revocations().expect("record").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_vault_no_longer_listed_or_a_deleted_project_is_skipped_but_a_failed_read_is_not() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let personal = ana.find_vault("Personal").expect("vault");
    ana.create_project(personal, "Old").await.expect("project");
    let old = ana.find_project(personal, "Old").expect("old");
    let work = ana.create_vault("Work").await.expect("vault");
    ana.create_project(work, "Infra").await.expect("project");
    add(&mut ana, "General", "GitHub").await;
    let projects = ["Personal/General", "Personal/Old", "Work/Infra"];
    let bot = agent(&server, &dir, &mut ana, "bot", &projects).await;

    // Old is deleted (an empty project).
    let old_id = old.to_string();
    with_db(&mut server, |pool| async move {
        let revision: i64 = sqlx::query_scalar(
            "UPDATE vaults SET revision = revision + 1 WHERE id = $1 RETURNING revision",
        )
        .bind(personal.to_string())
        .fetch_one(&pool)
        .await
        .expect("revision");
        sqlx::query(
            "UPDATE projects SET deleted_at = 1, wrapped_key = NULL, meta = NULL, revision = $1 WHERE id = $2",
        )
        .bind(revision)
        .bind(old_id)
        .execute(&pool)
        .await
        .expect("delete project");
    })
    .await;
    // Even from a cache rebuilt from scratch: the tombstone comes back.
    ana.reset_cache().await.expect("reset");
    // The server stops listing Work for this account (purged, or access
    // lost): this device keeps its copy, marked.
    let work_id = work.to_string();
    with_db(&mut server, |pool| async move {
        sqlx::query("UPDATE vault_members SET revoked_at = 1 WHERE vault_id = $1")
            .bind(work_id)
            .execute(&pool)
            .await
            .expect("unlist");
    })
    .await;
    ana.sync().await.expect("sync");

    let first = ana.revoke_first(bot.id(), true).await.expect("revoke");
    assert!(first.failed.is_none(), "{first:?}");
    // A step that cannot reach the server says so; it never takes a
    // project for gone.
    server.stop();
    let step = ana.rotation_step(bot.id()).await.expect("step");
    assert!(step.failed.is_some() && step.skipped.is_empty(), "{step:?}");
    assert!(!step.done);
    server.restart();

    let mut skipped = Vec::new();
    let mut rotated = Vec::new();
    loop {
        let step = ana.rotation_step(bot.id()).await.expect("step");
        assert!(step.failed.is_none(), "{step:?}");
        rotated.extend(step.rotated.map(|r| r.project));
        skipped.extend(step.skipped);
        if step.done {
            break;
        }
    }
    assert_eq!(rotated, vec!["Personal/General".to_owned()]);
    assert_eq!(skipped.len(), 2, "{skipped:?}");
    assert!(
        skipped
            .iter()
            .any(|s| s.contains("the project was deleted")),
        "{skipped:?}"
    );
    assert!(
        skipped
            .iter()
            .any(|s| s.contains("no longer lists its vault")),
        "{skipped:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_narrowing_key_change_is_written_down_and_finished_after_a_restart() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let vault = ana.find_vault("Personal").expect("vault");
    ana.create_project(vault, "Work").await.expect("project");
    let work = ana.find_project(vault, "Work").expect("work");
    add(&mut ana, "General", "GitHub").await;
    let jira = add(&mut ana, "Work", "Jira").await;
    let bot = agent(
        &server,
        &dir,
        &mut ana,
        "bot",
        &["Personal/General", "Personal/Work"],
    )
    .await;

    // Work is taken away with its key changed, but the server leaves an
    // item key out of the rotation: refused, and left to do.
    let key = hide_item_key(&mut server, jira.item).await;
    let change = klav_client::grant_change::GrantChange {
        rotate_removed: true,
        ..narrowing(&["Personal/General"])
    };
    let prepared = ana
        .prepare_grant_change(bot.id(), &change)
        .await
        .expect("prepare");
    let digest = prepared.preview().digest.clone();
    let report = ana
        .change_grant(bot.id(), &change, &digest)
        .await
        .expect("narrow");
    assert!(report.failed.is_some(), "{report:?}");
    assert_eq!(report.pending, vec!["Personal/Work".to_owned()]);
    assert!(!report.complete());

    // Written down: a restart still owes it, and `klavd` resumes it.
    let home = ana.home().clone();
    drop(ana);
    let mut ana =
        klav_client::unlock_with_password(&home, &MasterPassword::new(PASSWORD)).expect("unlock");
    let left = ana.pending_revocations().expect("record");
    assert_eq!(left.len(), 1, "{left:?}");
    assert!(left[0].narrowed && left[0].needs_work(), "{left:?}");
    assert_eq!(left[0].pending, vec!["Personal/Work".to_owned()]);
    assert!(left[0].last_error.is_some(), "{left:?}");

    restore_item_key(&mut server, jira.item, key).await;
    loop {
        let step = ana.rotation_step(bot.id()).await.expect("step");
        assert!(step.failed.is_none(), "{step:?}");
        if step.done {
            break;
        }
    }
    assert_eq!(project_version(&mut server, work).await, 2);
    assert!(ana.pending_revocations().expect("record").is_empty());
    // The agent stays active: a narrowing never revokes it.
    let view = ana.agent("bot").await.expect("agent");
    assert_eq!(view.status, klav_proto::agent::AgentStatus::Active);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_record_is_an_error_never_nothing_pending() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    add(&mut ana, "General", "GitHub").await;
    let bot = agent(&server, &dir, &mut ana, "bot", &["Personal/General"]).await;
    let path = ana.home().file(klav_client::revoke::REVOCATIONS_FILE);
    std::fs::write(&path, b"not a sealed record").expect("garbage");

    let err = ana.pending_revocations().expect_err("unreadable");
    assert!(
        matches!(&err, klav_client::ClientError::Corrupt(m) if m.contains("revocations.bin")),
        "{err:?}"
    );
    ana.rotation_step(bot.id()).await.expect_err("unreadable");

    // The revocation still goes through; the key change says it cannot be
    // written down, and the file is left as it was for the person to see.
    let report = ana.revoke_first(bot.id(), true).await.expect("revoke");
    assert_eq!(report.agent.status, klav_proto::agent::AgentStatus::Revoked);
    assert!(
        report
            .failed
            .as_deref()
            .is_some_and(|f| f.contains("revocations.bin")),
        "{report:?}"
    );
    assert!(!report.complete());
    assert_eq!(
        std::fs::read(&path).expect("record"),
        b"not a sealed record"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_change_whose_only_skip_is_a_deleted_project_is_done_and_gone() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let personal = ana.find_vault("Personal").expect("vault");
    ana.create_project(personal, "Old").await.expect("project");
    let old = ana.find_project(personal, "Old").expect("old");
    add(&mut ana, "General", "GitHub").await;
    let bot = agent(
        &server,
        &dir,
        &mut ana,
        "bot",
        &["Personal/General", "Personal/Old"],
    )
    .await;
    with_db(&mut server, |pool| async move {
        let revision: i64 = sqlx::query_scalar(
            "UPDATE vaults SET revision = revision + 1 WHERE id = $1 RETURNING revision",
        )
        .bind(personal.to_string())
        .fetch_one(&pool)
        .await
        .expect("revision");
        sqlx::query(
            "UPDATE projects SET deleted_at = 1, wrapped_key = NULL, meta = NULL, revision = $1 WHERE id = $2",
        )
        .bind(revision)
        .bind(old.to_string())
        .execute(&pool)
        .await
        .expect("delete project");
    })
    .await;
    ana.sync().await.expect("sync");

    // A deleted project never comes back: said once, and nothing is kept
    // that would show it forever.
    let report = ana.revoke_agent(bot.id(), true).await.expect("revoke");
    assert!(report.complete(), "{report:?}");
    assert!(
        report
            .skipped
            .iter()
            .any(|s| s.contains("the project was deleted")),
        "{report:?}"
    );
    assert!(ana.pending_revocations().expect("record").is_empty());
}

/// An in-process `klavd` for `home`, Touch ID off; stops when the sender
/// drops.
async fn klavd(home: &Home) -> tokio::sync::oneshot::Sender<()> {
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let daemon = tokio::spawn(klav_daemon::serve(
        klav_daemon::Config {
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
    while klav_daemon::client::DaemonClient::connect(home)
        .await
        .is_none()
    {
        assert!(!daemon.is_finished(), "klavd stopped before it listened");
        assert!(
            tokio::time::Instant::now() < deadline,
            "klavd did not listen on {} within 60 s",
            home.socket_path().display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn klavd_call<T: serde::de::DeserializeOwned>(
    home: &Home,
    request: klav_daemon::protocol::Request,
) -> Result<T, klav_daemon::protocol::ErrorBody> {
    klav_daemon::client::DaemonClient::connect(home)
        .await
        .expect("klavd")
        .call(request)
        .await
        .map(|(value, _)| value)
}

async fn klavd_unlock(home: &Home) -> klav_daemon::protocol::DaemonStatus {
    klavd_call(
        home,
        klav_daemon::protocol::Request::Unlock {
            password: Some(klav_client::ops::SecretText::new(PASSWORD)),
            passkey_flow: false,
        },
    )
    .await
    .expect("unlock")
}

async fn klavd_status(home: &Home) -> klav_daemon::protocol::DaemonStatus {
    klavd_call(home, klav_daemon::protocol::Request::Status)
        .await
        .expect("status")
}

#[tokio::test(flavor = "multi_thread")]
async fn klavd_shows_a_narrowing_key_change_and_finishes_it_at_unlock() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let vault = ana.find_vault("Personal").expect("vault");
    ana.create_project(vault, "Work").await.expect("project");
    let work = ana.find_project(vault, "Work").expect("work");
    add(&mut ana, "General", "GitHub").await;
    let jira = add(&mut ana, "Work", "Jira").await;
    let bot = agent(
        &server,
        &dir,
        &mut ana,
        "bot",
        &["Personal/General", "Personal/Work"],
    )
    .await;
    let key = hide_item_key(&mut server, jira.item).await;
    let change = klav_client::grant_change::GrantChange {
        rotate_removed: true,
        ..narrowing(&["Personal/General"])
    };
    let prepared = ana
        .prepare_grant_change(bot.id(), &change)
        .await
        .expect("prepare");
    let digest = prepared.preview().digest.clone();
    let report = ana
        .change_grant(bot.id(), &change, &digest)
        .await
        .expect("narrow");
    assert_eq!(report.pending, vec!["Personal/Work".to_owned()]);
    let home = ana.home().clone();
    drop(ana);

    // klavd shows it from the moment it unlocks, as a narrowing.
    let _stop = klavd(&home).await;
    let unlocked = klavd_unlock(&home).await;
    let left = unlocked
        .revocations
        .iter()
        .find(|r| r.agent_id == bot.id())
        .unwrap_or_else(|| panic!("no progress for bot: {:?}", unlocked.revocations));
    assert!(left.narrowed, "{left:?}");
    assert!(!unlocked.revocations_unreadable);

    // Once the server serves every key again, the next unlock finishes it
    // without being asked (P11).
    let _: klav_daemon::protocol::DaemonStatus =
        klavd_call(&home, klav_daemon::protocol::Request::Lock)
            .await
            .expect("lock");
    restore_item_key(&mut server, jira.item, key).await;
    klavd_unlock(&home).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let s = klavd_status(&home).await;
        if s.revocations.is_empty() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the narrowing did not finish: {:?}",
            s.revocations
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(project_version(&mut server, work).await, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn klavd_says_when_it_cannot_read_the_record_instead_of_an_empty_list() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    add(&mut ana, "General", "GitHub").await;
    let bot = agent(&server, &dir, &mut ana, "bot", &["Personal/General"]).await;
    // A key change owed, then a record that no longer opens.
    ana.revoke_first(bot.id(), true).await.expect("revoke");
    let home = ana.home().clone();
    drop(ana);
    let path = home.file(klav_client::revoke::REVOCATIONS_FILE);
    std::fs::write(&path, b"not a sealed record").expect("garbage");

    let _stop = klavd(&home).await;
    let unlocked = klavd_unlock(&home).await;
    assert!(unlocked.revocations_unreadable, "{unlocked:?}");
    // Not taken for an older klavd (that is `BadRequest`), and it says why.
    let err = klavd_call::<Vec<klav_client::revoke::PendingRevocation>>(
        &home,
        klav_daemon::protocol::Request::AgentRevocations,
    )
    .await
    .expect_err("unreadable");
    assert_ne!(err.code, klav_daemon::protocol::ErrorCode::BadRequest);
    assert!(err.message.contains("revocations.bin"), "{err:?}");

    // Moved aside, the next read clears the flag.
    std::fs::remove_file(&path).expect("move aside");
    let _ = klavd_call::<Vec<klav_client::revoke::PendingRevocation>>(
        &home,
        klav_daemon::protocol::Request::AgentRevocations,
    )
    .await
    .expect("readable");
    assert!(!klavd_status(&home).await.revocations_unreadable);
}

/// A key change whose only skip is a deleted project leaves no entry in the
/// record, yet `klavd` keeps saying what it skipped: no app may read its
/// end as "every key changed" (third re-check, N5).
#[tokio::test(flavor = "multi_thread")]
async fn klavd_says_what_a_finished_key_change_skipped() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let personal = ana.find_vault("Personal").expect("vault");
    ana.create_project(personal, "Old").await.expect("project");
    let old = ana.find_project(personal, "Old").expect("old");
    add(&mut ana, "General", "GitHub").await;
    let bot = agent(
        &server,
        &dir,
        &mut ana,
        "bot",
        &["Personal/General", "Personal/Old"],
    )
    .await;
    // The key change is written down; klavd resumes it at unlock.
    ana.revoke_first(bot.id(), true).await.expect("revoke");
    with_db(&mut server, |pool| async move {
        let revision: i64 = sqlx::query_scalar(
            "UPDATE vaults SET revision = revision + 1 WHERE id = $1 RETURNING revision",
        )
        .bind(personal.to_string())
        .fetch_one(&pool)
        .await
        .expect("revision");
        sqlx::query(
            "UPDATE projects SET deleted_at = 1, wrapped_key = NULL, meta = NULL, revision = $1 WHERE id = $2",
        )
        .bind(revision)
        .bind(old.to_string())
        .execute(&pool)
        .await
        .expect("delete project");
    })
    .await;
    let home = ana.home().clone();
    drop(ana);

    let _stop = klavd(&home).await;
    klavd_unlock(&home).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let left = loop {
        let s = klavd_status(&home).await;
        if let Some(left) = s
            .revocations
            .iter()
            .find(|r| r.agent_id == bot.id() && !r.running && !r.needs_work)
        {
            break left.clone();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "klavd never said what the finished key change skipped: {:?}",
            s.revocations
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(left.skipped, 1, "{left:?}");
    assert_eq!(left.to_change, 0, "{left:?}");
    assert!(left.last_error.is_none(), "{left:?}");
    // The record holds nothing for it: a deleted project never comes back.
    let pending = klavd_call::<Vec<klav_client::revoke::PendingRevocation>>(
        &home,
        klav_daemon::protocol::Request::AgentRevocations,
    )
    .await
    .expect("record");
    assert!(pending.is_empty(), "{pending:?}");
}

/// Once the narrowed grant is in force, a key change that stops because
/// this device can no longer write its record is the key change's: the
/// grant change answers with the report, never an error (third re-check,
/// N6). The upload waits on the server's database while the record's
/// writes start failing.
#[tokio::test(flavor = "multi_thread")]
async fn a_key_change_that_stops_after_the_grant_is_in_force_is_reported_not_a_failed_change() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let vault = ana.find_vault("Personal").expect("vault");
    ana.create_project(vault, "Work").await.expect("project");
    add(&mut ana, "General", "GitHub").await;
    add(&mut ana, "Work", "Jira").await;
    let bot = agent(
        &server,
        &dir,
        &mut ana,
        "bot",
        &["Personal/General", "Personal/Work"],
    )
    .await;
    let change = klav_client::grant_change::GrantChange {
        rotate_removed: true,
        ..narrowing(&["Personal/General"])
    };
    let prepared = ana
        .prepare_grant_change(bot.id(), &change)
        .await
        .expect("prepare");

    // Hold the server's database: the grant upload waits for it.
    sqlx::any::install_default_drivers();
    let url = format!("sqlite://{}", server.dir.path().join("klav.db").display());
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("open server db");
    let mut conn = pool.acquire().await.expect("connection");
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *conn)
        .await
        .expect("lock");
    let blocker = ana
        .home()
        .file(&format!(".revocations.bin.{}.tmp", std::process::id()));
    let interfere = async {
        // The record is written before the upload; after it, no write
        // goes through.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        std::fs::create_dir(&blocker).expect("blocker");
        sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .expect("unlock");
    };
    let (report, ()) = tokio::join!(ana.commit_grant_change(prepared), interfere);
    std::fs::remove_dir(&blocker).expect("blocker");
    drop(conn);
    pool.close().await;

    let report = report.expect("the grant is in force: not a failed change");
    let failed = report.failed.clone().expect("the key change stopped");
    assert!(failed.contains("the new grant is in force"), "{failed}");
    assert!(!report.complete(), "{report:?}");
    let served = ana.agent("bot").await.expect("agent");
    assert_eq!(
        served.grant.as_ref().map(|g| g.projects.len()),
        Some(1),
        "{served:?}"
    );
}

/// Waits until `klavd`'s `status` lists `agent` as over (nothing running,
/// nothing it can still do), and returns that entry.
async fn klavd_over(home: &Home, agent: AgentId) -> klav_daemon::protocol::RevocationProgress {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let s = klavd_status(home).await;
        if let Some(left) = s
            .revocations
            .iter()
            .find(|r| r.agent_id == agent && !r.running && !r.needs_work)
        {
            return left.clone();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "klavd never said the key change of {agent} was over: {:?}",
            s.revocations
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// A revocation without the key change whose item this device stops
/// seeing before `klavd` resumes it: `status` says it was a revocation
/// without the key change, so no app reads its end as "every key it can
/// reach" changed (fifth re-check, 1).
#[tokio::test(flavor = "multi_thread")]
async fn klavd_says_a_revocation_without_the_key_change_is_one() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let a = add(&mut ana, "General", "GitHub").await;
    let b = add(&mut ana, "General", "Jira").await;
    let bot = agent(&server, &dir, &mut ana, "bot", &["Personal/General"]).await;
    ana.revoke_first(bot.id(), false).await.expect("revoke");
    // Two items' keys still owed, as a first call that stopped leaves them.
    let record = format!(
        r#"{{"v":1,"agents":{{{}:{{"name":"bot","rotate":false,"items":[{},{}]}}}}}}"#,
        serde_json::to_string(&bot.id()).expect("id"),
        serde_json::to_string(&a.item).expect("a"),
        serde_json::to_string(&b.item).expect("b"),
    );
    let blob = klav_core::crypto::local::seal_local_data(
        ana.local_key(),
        &ana.account().local_context(),
        "revocations",
        record.as_bytes(),
    )
    .expect("seal");
    std::fs::write(ana.home().file(klav_client::revoke::REVOCATIONS_FILE), blob).expect("write");
    // B is purged before the next unlock.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64;
    with_db(&mut server, |pool| async move {
        let revision: i64 = sqlx::query_scalar(
            "UPDATE vaults SET revision = revision + 1 WHERE id = $1 RETURNING revision",
        )
        .bind(b.vault.to_string())
        .fetch_one(&pool)
        .await
        .expect("revision");
        sqlx::query("DELETE FROM item_versions WHERE item_id = $1")
            .bind(b.item.to_string())
            .execute(&pool)
            .await
            .expect("versions");
        sqlx::query(
            "UPDATE items SET wrapped_key = NULL, overview = NULL, details = NULL, \
             purged_at = $1, revision = $2 WHERE id = $3",
        )
        .bind(now)
        .bind(revision)
        .bind(b.item.to_string())
        .execute(&pool)
        .await
        .expect("purge");
    })
    .await;
    let home = ana.home().clone();
    drop(ana);

    let _stop = klavd(&home).await;
    klavd_unlock(&home).await;
    let left = klavd_over(&home, bot.id()).await;
    assert!(left.without_key_change, "{left:?}");
    assert_eq!((left.projects, left.skipped), (0, 1), "{left:?}");
    assert!(left.last_error.is_none(), "{left:?}");
}

/// A narrowing whose key change finished skipping a deleted project, then
/// a revocation of the same agent without the key change: `status` no
/// longer calls it a narrowing, which would say the agent is active (fifth
/// re-check, 3).
#[tokio::test(flavor = "multi_thread")]
async fn revoking_forgets_a_finished_narrowing_in_klavd() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let vault = ana.find_vault("Personal").expect("vault");
    for name in ["Spare", "Old"] {
        ana.create_project(vault, name).await.expect("project");
    }
    let spare = ana.find_project(vault, "Spare").expect("spare");
    let old = ana.find_project(vault, "Old").expect("old");
    add(&mut ana, "General", "GitHub").await;
    add(&mut ana, "Spare", "Jira").await;
    let bot = agent(&server, &dir, &mut ana, "bot", &["Personal/General"]).await;
    // Two projects taken away from it, their key change still owed. The
    // record is written as a narrowing whose key change stopped leaves it:
    // shorter than stopping one for real, and nothing here depends on how
    // it stopped. `Old` holds no item, so deleting it below is a deletion
    // the server allows (it refuses a project that is not empty).
    let record = format!(
        r#"{{"v":1,"agents":{{}},"narrowed":{{{}:{{"name":"bot","projects":[{},{}]}}}}}}"#,
        serde_json::to_string(&bot.id()).expect("id"),
        serde_json::to_string(&spare).expect("spare"),
        serde_json::to_string(&old).expect("old"),
    );
    let blob = klav_core::crypto::local::seal_local_data(
        ana.local_key(),
        &ana.account().local_context(),
        "revocations",
        record.as_bytes(),
    )
    .expect("seal");
    std::fs::write(ana.home().file(klav_client::revoke::REVOCATIONS_FILE), blob).expect("write");
    // One of them is deleted before klavd resumes it.
    with_db(&mut server, |pool| async move {
        let revision: i64 = sqlx::query_scalar(
            "UPDATE vaults SET revision = revision + 1 WHERE id = $1 RETURNING revision",
        )
        .bind(vault.to_string())
        .fetch_one(&pool)
        .await
        .expect("revision");
        sqlx::query(
            "UPDATE projects SET deleted_at = 1, wrapped_key = NULL, meta = NULL, revision = $1 WHERE id = $2",
        )
        .bind(revision)
        .bind(old.to_string())
        .execute(&pool)
        .await
        .expect("delete project");
    })
    .await;
    let home = ana.home().clone();
    drop(ana);

    let _stop = klavd(&home).await;
    klavd_unlock(&home).await;
    let left = klavd_over(&home, bot.id()).await;
    assert!(left.narrowed && left.skipped == 1, "{left:?}");

    let _: serde_json::Value = klavd_call(
        &home,
        klav_daemon::protocol::Request::RevokeAgent {
            agent: bot.id(),
            rotate: false,
            background: false,
        },
    )
    .await
    .expect("revoke");
    let s = klavd_status(&home).await;
    assert!(
        !s.revocations
            .iter()
            .any(|r| r.agent_id == bot.id() && r.narrowed),
        "{:?}",
        s.revocations
    );
}

/// Writes `json` as this device's sealed `revocations.bin`.
fn write_record(ana: &Unlocked, json: &str) {
    let blob = klav_core::crypto::local::seal_local_data(
        ana.local_key(),
        &ana.account().local_context(),
        "revocations",
        json.as_bytes(),
    )
    .expect("seal");
    std::fs::write(ana.home().file(klav_client::revoke::REVOCATIONS_FILE), blob).expect("write");
}

/// A narrowing owed, then a revocation without the key change whose entry
/// stays for good (an item this device no longer sees): the steps reach
/// the narrowing and finish it, instead of taking the revocation first
/// forever (review of #308, N1).
#[tokio::test(flavor = "multi_thread")]
async fn a_kept_revocation_never_hides_a_narrowing_owed() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let vault = ana.find_vault("Personal").expect("vault");
    ana.create_project(vault, "Work").await.expect("project");
    let work = ana.find_project(vault, "Work").expect("work");
    add(&mut ana, "General", "GitHub").await;
    add(&mut ana, "Work", "Jira").await;
    let bot = agent(&server, &dir, &mut ana, "bot", &["Personal/General"]).await;
    ana.revoke_first(bot.id(), false).await.expect("revoke");
    // As the record stands then: Work's key change owed by an earlier
    // narrowing, and the revocation's entry kept for an item this device
    // no longer sees (an ID it never saw is the same to it as a purged one).
    let unseen = ItemId::generate();
    write_record(
        &ana,
        &format!(
            r#"{{"v":1,"agents":{{{id}:{{"name":"bot","rotate":false,"items":[{unseen}]}}}},"narrowed":{{{id}:{{"name":"bot","projects":[{work}]}}}}}}"#,
            id = serde_json::to_string(&bot.id()).expect("id"),
            unseen = serde_json::to_string(&unseen).expect("item"),
            work = serde_json::to_string(&work).expect("work"),
        ),
    );
    let before = project_version(&mut server, work).await;

    let mut done = false;
    for _ in 0..5 {
        let step = ana.rotation_step(bot.id()).await.expect("step");
        assert!(step.failed.is_none(), "{step:?}");
        if step.done {
            let said = format!("item {unseen}: this device no longer sees it");
            assert!(
                step.skipped.iter().any(|s| s.starts_with(&said)),
                "{step:?}"
            );
            done = true;
            break;
        }
    }
    assert!(done, "the steps never reached the narrowing");
    assert_eq!(project_version(&mut server, work).await, before + 1);
    let left = ana.pending_revocations().expect("record");
    assert!(left.iter().all(|p| !p.narrowed), "{left:?}");
    // The revocation's entry stays, with nothing klavd could still do.
    assert!(left.iter().all(|p| !p.needs_work()), "{left:?}");
}

/// A key change klavd stopped for lack of progress says so in the record:
/// `status`, the apps and `klav agent show` read `last_error`, never a key
/// change still running; the next step that changes a key clears it
/// (review of #308, follow-up 2).
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_key_change_says_so_until_a_step_moves() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    add(&mut ana, "General", "GitHub").await;
    let bot = agent(&server, &dir, &mut ana, "bot", &["Personal/General"]).await;
    ana.revoke_first(bot.id(), true).await.expect("revoke");

    ana.note_no_progress(bot.id()).expect("noted");
    let left = ana.pending_revocations().expect("record");
    let entry = left.iter().find(|p| p.agent_id == bot.id()).expect("owed");
    let why = entry.last_error.as_deref().expect("said");
    assert!(why.contains("no progress"), "{why}");
    assert!(
        !why.contains("General") && !why.contains("Personal"),
        "{why}"
    );
    assert!(entry.needs_work(), "klavd still resumes it at unlock");

    let step = ana.rotation_step(bot.id()).await.expect("step");
    assert!(step.rotated.is_some() && step.failed.is_none(), "{step:?}");
    let left = ana.pending_revocations().expect("record");
    assert!(left.iter().all(|p| p.last_error.is_none()), "{left:?}");
}
