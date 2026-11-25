//! Changing an active agent's grant and revoking it from the apps (ADR
//! 0033, amendment of 2026-11-10, layer 2), against a real server: the
//! editor's view of a grant, the sheet of differences and whether it
//! widens, the digest that refuses to sign over a grant that changed, the
//! rotation one project at a time with what is left on record, and
//! revoking an agent whose grant this device cannot read or the server
//! does not send. A malicious server is played by editing its SQLite file
//! while it is stopped.

#[path = "../../klav-client/tests/common/mod.rs"]
mod common;

use std::future::Future;

use common::ServerProcess;
use klav_client::agents::GrantRequest;
use klav_client::grant_change::{
    ChangePolicy, ChangeWhat, EditorPolicy, GrantChange, PermissionSetting, ReadOnlyReason,
};
use klav_client::{ClientError, Home, LoginRequest, SignupRequest, Unlocked, login, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::secret_key::SecretKey;
use klav_core::ids::{AgentId, ProjectId};
use klav_core::model::item::{Item, ItemKind};
use klav_core::policy::{Effect, Permission, Policy, Rule, Scope};
use klav_proto::agent::AgentStatus;
use klav_proto::auth::DeviceKind;
use klav_sdk::{Agent, KeyStore, Registration};
use secrecy::ExposeSecret;
use sqlx::AnyPool;
use sqlx::any::AnyPoolOptions;

const PASSWORD: &str = "correct horse battery staple";
const EMAIL: &str = "ana@example.com";

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
            invite: None,
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

/// Registers agent `name` and approves it with `projects` and `policy`.
async fn agent(
    server: &ServerProcess,
    dir: &tempfile::TempDir,
    ana: &mut Unlocked,
    name: &str,
    projects: &[&str],
    policy: Policy,
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
    ana.approve_agent(
        agent.id(),
        GrantRequest {
            projects: projects.iter().map(|p| (*p).to_owned()).collect(),
            vaults: Vec::new(),
            policy,
        },
        &agent.pairing_code(),
    )
    .await
    .expect("approve");
    agent
}

async fn two_projects(ana: &mut Unlocked) -> (ProjectId, ProjectId) {
    let vault = ana.find_vault("Personal").expect("vault");
    ana.create_project(vault, "Work").await.expect("project");
    for (project, title) in [("General", "GitHub"), ("Work", "AWS")] {
        let project = ana.find_project(vault, project).expect("project");
        ana.add_item(
            vault,
            project,
            &Item::from_template(ItemKind::Login, title).expect("item"),
        )
        .await
        .expect("add item");
    }
    (
        ana.find_project(vault, "General").expect("general"),
        ana.find_project(vault, "Work").expect("work"),
    )
}

fn change(projects: &[&str], settings: &[(Permission, Effect)]) -> GrantChange {
    GrantChange {
        projects: projects.iter().map(|p| (*p).to_owned()).collect(),
        vaults: Vec::new(),
        policy: ChangePolicy::Editor(EditorPolicy {
            permissions: settings
                .iter()
                .map(|(p, e)| PermissionSetting {
                    permission: *p,
                    effect: Some(*e),
                })
                .collect(),
            ..EditorPolicy::default()
        }),
        rotate_removed: false,
    }
}

async fn grant_version(ana: &mut Unlocked, id: AgentId) -> u64 {
    let agents = ana.agents().await.expect("agents");
    agents
        .iter()
        .find(|a| a.id == id)
        .and_then(|a| a.grant.as_ref())
        .map_or(0, |g| g.version)
}

#[tokio::test(flavor = "multi_thread")]
async fn adding_a_project_widens_and_taking_it_away_narrows() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let (general, work) = two_projects(&mut ana).await;
    let bot = agent(
        &server,
        &dir,
        &mut ana,
        "bot",
        &["Personal/General"],
        Policy::default(),
    )
    .await;

    let editor = ana.grant_editor(bot.id()).await.expect("editor");
    assert!(editor.editable, "{editor:?}");
    assert_eq!(editor.editor, Some(EditorPolicy::default()));
    assert_eq!(editor.version, 1);
    assert_eq!(editor.projects.len(), 1);

    // More projects: widens, and the sheet says which.
    let wider = change(&["Personal/General", "Personal/Work"], &[]);
    let prepared = ana
        .prepare_grant_change(bot.id(), &wider)
        .await
        .expect("prepare");
    assert!(prepared.widens());
    assert_eq!(
        prepared
            .preview()
            .lines
            .iter()
            .map(|l| l.what.clone())
            .collect::<Vec<_>>(),
        vec![ChangeWhat::ProjectAdded {
            project: "Personal/Work".into()
        }]
    );
    assert_eq!(prepared.widening_lines().len(), 1);
    // The same change on the same grant gives the same digest.
    let again = ana
        .prepare_grant_change(bot.id(), &wider)
        .await
        .expect("prepare");
    assert_eq!(again.preview().digest, prepared.preview().digest);
    let report = ana.commit_grant_change(prepared).await.expect("commit");
    assert!(report.complete());
    let grant = report.agent.grant.expect("grant");
    assert_eq!(grant.version, 2);
    let mut ids: Vec<ProjectId> = grant.projects.iter().map(|p| p.project_id).collect();
    ids.sort();
    let mut want = vec![general, work];
    want.sort();
    assert_eq!(ids, want);

    // Fewer projects and `reveal` denied outright: only narrows.
    let narrower = change(&["Personal/General"], &[(Permission::Reveal, Effect::Deny)]);
    let prepared = ana
        .prepare_grant_change(bot.id(), &narrower)
        .await
        .expect("prepare");
    assert!(!prepared.widens(), "{:?}", prepared.preview());
    assert_eq!(
        prepared.preview().removed_projects,
        vec!["Personal/Work".to_owned()]
    );
    assert!(prepared.widening_lines().is_empty());
    ana.commit_grant_change(prepared).await.expect("commit");
    assert_eq!(grant_version(&mut ana, bot.id()).await, 3);

    // Nothing to change: refused.
    let err = ana
        .prepare_grant_change(bot.id(), &narrower)
        .await
        .expect_err("no change");
    assert!(err.to_string().contains("nothing changes"), "{err}");
}

/// T188: the sheet is bound to the grant in force; a grant that changed in
/// between (another device, the terminal) is not signed over.
#[tokio::test(flavor = "multi_thread")]
async fn a_change_shown_before_the_grant_changed_is_not_signed() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, secret) = account(&server, &dir).await;
    two_projects(&mut ana).await;
    let bot = agent(
        &server,
        &dir,
        &mut ana,
        "bot",
        &["Personal/General"],
        Policy::default(),
    )
    .await;
    let shown_change = change(&["Personal/General"], &[(Permission::Reveal, Effect::Ask)]);
    let shown = ana
        .prepare_grant_change(bot.id(), &shown_change)
        .await
        .expect("prepare")
        .preview()
        .digest
        .clone();

    // Meanwhile the phone changes the grant.
    let mut phone = second_device(&server, &dir, &secret).await;
    let wider = change(&["Personal/General", "Personal/Work"], &[]);
    let phone_shown = phone
        .prepare_grant_change(bot.id(), &wider)
        .await
        .expect("prepare")
        .preview()
        .digest
        .clone();
    phone
        .change_grant(bot.id(), &wider, &phone_shown)
        .await
        .expect("phone changes it");

    let err = ana
        .change_grant(bot.id(), &shown_change, &shown)
        .await
        .expect_err("refused");
    assert!(matches!(err, ClientError::Security(_)), "{err}");
    assert!(
        err.to_string().contains("changed while you were looking"),
        "{err}"
    );
    // What the phone signed stands.
    assert_eq!(grant_version(&mut ana, bot.id()).await, 2);
    // And another change than the one shown is refused just the same.
    let fresh = ana
        .prepare_grant_change(bot.id(), &shown_change)
        .await
        .expect("prepare")
        .preview()
        .digest
        .clone();
    let other = change(
        &["Personal/General"],
        &[(Permission::Reveal, Effect::Allow)],
    );
    let err = ana
        .change_grant(bot.id(), &other, &fresh)
        .await
        .expect_err("another change");
    assert!(matches!(err, ClientError::Security(_)), "{err}");
    assert_eq!(grant_version(&mut ana, bot.id()).await, 2);
}

/// Rules the editor does not model leave the apps read-only; the CLI's
/// whole-policy path still changes them, and keeps what it does not touch.
#[tokio::test(flavor = "multi_thread")]
async fn a_grant_with_rules_the_editor_does_not_model_is_read_only() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    two_projects(&mut ana).await;
    let tagged = Policy {
        rules: vec![Rule {
            scope: Scope {
                tags: vec!["prod".into()],
                ..Scope::default()
            },
            ..Rule::new(Permission::Reveal, Effect::Ask)
        }],
        expires_at: None,
    };
    let bot = agent(
        &server,
        &dir,
        &mut ana,
        "bot",
        &["Personal/General"],
        tagged.clone(),
    )
    .await;
    let editor = ana.grant_editor(bot.id()).await.expect("editor");
    assert!(!editor.editable);
    assert_eq!(editor.reason, Some(ReadOnlyReason::Rules));
    assert_eq!(editor.policy.as_ref(), Some(&tagged));
    // klavd refuses the editor's model on it too, not only the apps: it
    // would sign a simpler copy of the rules.
    let simpler = ana
        .prepare_grant_change(
            bot.id(),
            &change(&["Personal/General"], &[(Permission::Delete, Effect::Deny)]),
        )
        .await
        .expect_err("rules");
    assert!(
        matches!(&simpler, ClientError::Invalid(m) if m.contains("the editor does not change it")),
        "{simpler}"
    );

    // From the terminal, the same rules plus a `deny` only narrow.
    let mut stricter = tagged.clone();
    stricter
        .rules
        .push(Rule::new(Permission::Delete, Effect::Deny));
    let cli = GrantChange {
        projects: vec!["Personal/General".into()],
        vaults: Vec::new(),
        policy: ChangePolicy::Rules(stricter.clone()),
        rotate_removed: false,
    };
    let prepared = ana
        .prepare_grant_change(bot.id(), &cli)
        .await
        .expect("prepare");
    assert!(!prepared.widens());
    assert_eq!(prepared.preview().lines.len(), 1);
    assert_eq!(prepared.preview().lines[0].what, ChangeWhat::Rules);
    let report = ana.commit_grant_change(prepared).await.expect("commit");
    assert_eq!(report.agent.grant.expect("grant").policy, stricter);

    // Not an active agent: nothing to edit.
    ana.revoke_agent(bot.id(), false).await.expect("revoke");
    let editor = ana.grant_editor(bot.id()).await.expect("editor");
    assert_eq!(editor.reason, Some(ReadOnlyReason::NotActive));
    let err = ana
        .prepare_grant_change(bot.id(), &cli)
        .await
        .expect_err("revoked");
    assert!(matches!(err, ClientError::Security(_)), "{err}");
}

/// T188: the digest covers what the change resolves to. A whole vault is
/// resolved again when signing: a project created in between is a change
/// the sheet never showed.
#[tokio::test(flavor = "multi_thread")]
async fn a_project_created_after_the_sheet_changes_its_digest() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    two_projects(&mut ana).await;
    let bot = agent(
        &server,
        &dir,
        &mut ana,
        "bot",
        &["Personal/General"],
        Policy::default(),
    )
    .await;
    let whole = GrantChange {
        projects: Vec::new(),
        vaults: vec!["Personal".into()],
        policy: ChangePolicy::Rules(Policy::default()),
        rotate_removed: false,
    };
    let shown = ana
        .prepare_grant_change(bot.id(), &whole)
        .await
        .expect("prepare")
        .preview()
        .digest
        .clone();
    let before = grant_version(&mut ana, bot.id()).await;
    let vault = ana.find_vault("Personal").expect("vault");
    ana.create_project(vault, "Home").await.expect("project");
    let refused = ana
        .change_grant(bot.id(), &whole, &shown)
        .await
        .expect_err("a project the sheet did not show");
    assert!(matches!(refused, ClientError::Security(_)), "{refused}");
    assert_eq!(grant_version(&mut ana, bot.id()).await, before);

    // Shown again, with Home on the sheet, it signs.
    let prepared = ana
        .prepare_grant_change(bot.id(), &whole)
        .await
        .expect("prepare again");
    assert_ne!(prepared.preview().digest, shown);
    assert_eq!(
        prepared.preview().lines.len(),
        2,
        "{:?}",
        prepared.preview().lines
    );
    let digest = prepared.preview().digest.clone();
    ana.change_grant(bot.id(), &whole, &digest)
        .await
        .expect("signed");
}

/// P9: taking a project away offers to change its key; with it, the key
/// changes and the other agents that hold the project get a new grant.
#[tokio::test(flavor = "multi_thread")]
async fn taking_a_project_away_can_change_its_key() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    two_projects(&mut ana).await;
    let both = ["Personal/General", "Personal/Work"];
    let bot = agent(&server, &dir, &mut ana, "bot", &both, Policy::default()).await;
    agent(&server, &dir, &mut ana, "keeper", &both, Policy::default()).await;
    let mut away = change(&["Personal/General"], &[]);
    away.rotate_removed = true;
    let prepared = ana
        .prepare_grant_change(bot.id(), &away)
        .await
        .expect("prepare");
    assert!(prepared.preview().rotate_removed);
    let report = ana.commit_grant_change(prepared).await.expect("commit");
    assert!(report.complete(), "{report:?}");
    assert_eq!(report.rotated.len(), 1);
    assert_eq!(report.rotated[0].project, "Personal/Work");
    assert_eq!(report.regranted, vec!["keeper".to_owned()]);
}

/// F2 and T189: the revocation goes first, alone; the rotation then goes
/// one project at a time, with what is left on record after each step,
/// until it is done. A revocation without a rotation has nothing pending.
#[tokio::test(flavor = "multi_thread")]
async fn a_rotation_goes_one_project_at_a_time_with_what_is_left_on_record() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    two_projects(&mut ana).await;
    let both = ["Personal/General", "Personal/Work"];
    let bot = agent(&server, &dir, &mut ana, "bot", &both, Policy::default()).await;
    agent(&server, &dir, &mut ana, "keeper", &both, Policy::default()).await;
    let quiet = agent(&server, &dir, &mut ana, "quiet", &both, Policy::default()).await;

    // Without a rotation: revoked, nothing pending.
    let report = ana.revoke_agent(quiet.id(), false).await.expect("revoke");
    assert!(report.complete());
    assert!(ana.pending_revocations().expect("record").is_empty());

    // With one: revoked first, then nothing rotated until the steps run.
    let first = ana.revoke_first(bot.id(), true).await.expect("revoke");
    assert_eq!(first.agent.status, AgentStatus::Revoked);
    assert!(first.rotated.is_empty());
    let pending = ana.pending_revocations().expect("record");
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert_eq!(pending[0].name, "bot");
    assert_eq!(pending[0].pending.len(), 2);
    assert!(pending[0].rotated.is_empty());

    let step = ana.rotation_step(bot.id()).await.expect("step");
    assert!(step.rotated.is_some() && !step.done && step.failed.is_none());
    assert_eq!(step.regranted, vec!["keeper".to_owned()]);
    let pending = ana.pending_revocations().expect("record");
    assert_eq!(pending[0].pending.len(), 1);
    assert_eq!(pending[0].rotated.len(), 1);
    assert!(pending[0].regrants.is_empty(), "{pending:?}");

    // The record survives a new process (a lock, a restart).
    let home = Home::at(dir.path().join("laptop"));
    drop(ana);
    let mut ana =
        klav_client::unlock_with_password(&home, &MasterPassword::new(PASSWORD)).expect("unlock");
    assert_eq!(
        ana.pending_revocations().expect("record")[0].pending.len(),
        1
    );

    let step = ana.rotation_step(bot.id()).await.expect("step");
    assert!(step.rotated.is_some() && step.done, "{step:?}");
    assert!(ana.pending_revocations().expect("record").is_empty());
    // Asking again does nothing more.
    let step = ana.rotation_step(bot.id()).await.expect("step");
    assert!(step.done && step.rotated.is_none());
    let report = ana.revoke_agent(bot.id(), true).await.expect("again");
    assert!(report.complete() && report.rotated.is_empty(), "{report:?}");
    assert_eq!(report.already_rotated.len(), 2);
}

/// F1 gap 4: one grant this device cannot read neither hides the other
/// agents nor stops the revocation; its projects come from the last grant
/// the account signed in the log.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_grant_does_not_stop_the_list_or_the_revocation() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let (general, _) = two_projects(&mut ana).await;
    let bot = agent(
        &server,
        &dir,
        &mut ana,
        "bot",
        &["Personal/General"],
        Policy::default(),
    )
    .await;
    agent(
        &server,
        &dir,
        &mut ana,
        "keeper",
        &["Personal/General"],
        Policy::default(),
    )
    .await;
    let id = bot.id();
    with_db(&mut server, |pool| async move {
        sqlx::query("UPDATE agents SET grant_signature = zeroblob(64) WHERE id = $1")
            .bind(id.to_string())
            .execute(&pool)
            .await
            .expect("break the signature");
    })
    .await;

    let agents = ana.agents().await.expect("the list still comes");
    assert_eq!(agents.len(), 2);
    let broken = agents.iter().find(|a| a.id == id).expect("bot");
    assert!(broken.grant.is_none());
    assert!(
        broken
            .grant_error
            .as_deref()
            .is_some_and(|e| e.contains("cannot read"))
    );
    let editor = ana.grant_editor(id).await.expect("editor");
    assert_eq!(editor.reason, Some(ReadOnlyReason::Unreadable));

    let report = ana.revoke_agent(id, true).await.expect("revoked anyway");
    assert_eq!(report.agent.status, AgentStatus::Revoked);
    assert!(!report.warnings.is_empty());
    assert!(report.complete(), "{report:?}");
    assert_eq!(report.rotated.len(), 1);
    assert_eq!(report.rotated[0].project_id, general);
    assert_eq!(report.regranted, vec!["keeper".to_owned()]);
}

/// F1 gap 3: a device with no record of the revocation, and a server that
/// no longer sends the revoked agent's grant, still rotates the projects
/// of the last grant the account signed.
#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_hides_a_revoked_agents_grant_still_gets_its_projects_rotated() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, secret) = account(&server, &dir).await;
    let (general, work) = two_projects(&mut ana).await;
    let both = ["Personal/General", "Personal/Work"];
    let bot = agent(&server, &dir, &mut ana, "bot", &both, Policy::default()).await;
    ana.revoke_agent(bot.id(), false).await.expect("revoke");
    let id = bot.id();
    with_db(&mut server, |pool| async move {
        sqlx::query("UPDATE agents SET grant_payload = NULL, grant_signature = NULL WHERE id = $1")
            .bind(id.to_string())
            .execute(&pool)
            .await
            .expect("hide the grant");
    })
    .await;

    let mut phone = second_device(&server, &dir, &secret).await;
    let report = phone.revoke_agent(id, true).await.expect("finish");
    assert!(report.complete(), "{report:?}");
    let mut rotated: Vec<ProjectId> = report.rotated.iter().map(|r| r.project_id).collect();
    rotated.sort();
    let mut want = vec![general, work];
    want.sort();
    assert_eq!(rotated, want);
    assert!(phone.pending_revocations().expect("record").is_empty());
}

/// The digest covers the projects by ID: the same change asked with its
/// projects in another order is the same change (R2-5).
#[tokio::test(flavor = "multi_thread")]
async fn the_same_projects_in_another_order_give_the_same_digest() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    two_projects(&mut ana).await;
    let bot = agent(
        &server,
        &dir,
        &mut ana,
        "bot",
        &["Personal/General"],
        Policy::default(),
    )
    .await;
    let settings = [(Permission::Delete, Effect::Deny)];
    let one = ana
        .prepare_grant_change(
            bot.id(),
            &change(&["Personal/General", "Personal/Work"], &settings),
        )
        .await
        .expect("prepare");
    let other = ana
        .prepare_grant_change(
            bot.id(),
            &change(&["Personal/Work", "Personal/General"], &settings),
        )
        .await
        .expect("prepare");
    assert_eq!(one.preview().digest, other.preview().digest);
}
