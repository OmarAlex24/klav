//! An import over a login an agent touched (ADR 0024, ADR 0030 §7): the
//! version the import saves is the person's, so the sites the agent added
//! and nobody confirmed must not ride along and become confirmed.

#[path = "../../klav-client/tests/common/mod.rs"]
mod common;

use std::time::Duration;

use common::ServerProcess;
use klav_client::agents::GrantRequest;
use klav_client::klav_import::{Action, Change, ImportSet};
use klav_client::ops::ItemPatch;
use klav_client::{Home, SignupRequest, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::model::item::{FieldValue, Item, ItemKind};
use klav_core::policy::{Effect, Permission, Policy, Rule};
use klav_proto::auth::DeviceKind;
use klav_sdk::{Agent, KeyStore, Registration, Session};

const PASSWORD: &str = "correct horse battery staple";
const EMAIL: &str = "ana@example.com";

/// Bitwarden's export of the same login, with a newer password.
const EXPORT: &str = r#"{"encrypted": false, "items": [
  {"id": "1", "type": 1, "name": "GitHub", "revisionDate": "2026-11-01T09:00:00.000Z",
   "deletedDate": null,
   "login": {"uris": [{"match": null, "uri": "https://github.com"}],
             "username": "ana", "password": "sample-gh-new", "totp": null}}]}"#;

#[tokio::test(flavor = "multi_thread")]
async fn an_import_never_confirms_an_agents_site() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut laptop, _kit) = signup(
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
    let vault = laptop.find_vault("Personal").expect("vault");
    let project = laptop.find_project(vault, "General").expect("project");
    let mut github = Item::from_template(ItemKind::Login, "GitHub").expect("test setup");
    for (name, value) in [("username", "ana"), ("password", "sample-gh-old")] {
        github
            .field_mut(name)
            .expect("test setup")
            .set_value(value)
            .expect("test setup");
    }
    github.add_url("https://github.com").expect("test setup");
    let item = laptop
        .add_item(vault, project, &github)
        .await
        .expect("add")
        .item;

    let (bot, _) = Agent::register(
        &Home::at(dir.path().join("agent-bot")),
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
    laptop
        .approve_agent(
            bot.id(),
            GrantRequest {
                projects: vec!["Personal/General".into()],
                vaults: Vec::new(),
                policy: Policy {
                    rules: vec![Rule::new(Permission::Update, Effect::Allow)],
                    expires_at: None,
                },
            },
            &bot.pairing_code(),
        )
        .await
        .expect("approve");
    let mut session = Session::open(bot).await.expect("session");
    session
        .update_item(
            item,
            &ItemPatch {
                add_urls: vec!["https://github-login.example".into()],
                ..ItemPatch::default()
            },
            "add the new login page",
            Duration::ZERO,
        )
        .await
        .expect("agent update");
    laptop.sync().await.expect("sync");
    let loc = laptop.find_item("GitHub").expect("find");
    assert_eq!(
        laptop.item_summary(loc).expect("summary").pending_urls,
        ["https://github-login.example"]
    );

    let mut set = ImportSet::new();
    set.add("bitwarden.json", EXPORT.as_bytes(), None)
        .expect("export");
    let preview = laptop
        .import_preview(&set, None, None, 100)
        .expect("preview");
    assert_eq!(preview.rows.len(), 1);
    assert_eq!(preview.rows[0].action, Action::Merge);
    assert_eq!(preview.rows[0].changes, vec![Change::PasswordReplaced]);
    let done = laptop.import_apply(&set, None, None).await.expect("apply");
    assert_eq!((done.created, done.updated), (0, 1));

    // The person's version: the new password, and only the confirmed site.
    let summary = laptop.item_summary(loc).expect("summary");
    assert!(summary.pending_urls.is_empty() && summary.author_agent_id.is_none());
    let saved = laptop.open_item(loc).expect("open");
    assert_eq!(saved.urls(), ["https://github.com"]);
    let FieldValue::Secret(current) = saved.field("password").expect("password").value() else {
        panic!("password is a secret");
    };
    assert_eq!(current.expose(), "sample-gh-new");
}
