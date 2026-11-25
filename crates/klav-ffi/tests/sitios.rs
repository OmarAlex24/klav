//! Sites an agent added to a login, from the phone (ADR 0030 §7, layer 11
//! of the 2026-11 round): `ItemInfo` tells them apart from the confirmed
//! ones, AutoFill does not offer them, and the person confirms them (any
//! edit of hers) or removes them, like `klav item sites`. Also: error text
//! from the server reaches the app on one line, without hidden characters.

mod common;

use std::time::Duration;

use common::ServerProcess;
use klav_client::agents::GrantRequest;
use klav_client::ops::ItemPatch;
use klav_client::{ClientError, Home, SignupRequest};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::model::item::{Item, ItemKind};
use klav_core::policy::{Effect, Permission, Policy, Rule};
use klav_ffi::{ItemEdit, ItemInfo, ItemQuery, KlavCore, KlavError};
use klav_proto::auth::DeviceKind;
use klav_sdk::{Agent, KeyStore, Registration, Session};
use secrecy::ExposeSecret;

const PASSWORD: &str = "correct horse battery staple";
const EMAIL: &str = "ana@example.com";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test setup")
}

fn github() -> Item {
    let mut item = Item::from_template(ItemKind::Login, "GitHub").expect("test setup");
    item.field_mut("username")
        .expect("test setup")
        .set_value("ana")
        .expect("test setup");
    item.field_mut("password")
        .expect("test setup")
        .set_value("MARKER-ffi-sites-password")
        .expect("test setup");
    item.add_url("https://github.com").expect("test setup");
    item
}

/// The phone's only login, as listed.
fn listed(core: &KlavCore) -> ItemInfo {
    let mut items = core.items(ItemQuery::default()).expect("items");
    assert_eq!(items.len(), 1);
    items.remove(0)
}

#[test]
fn the_phone_shows_confirms_and_removes_sites_an_agent_added() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let rt = runtime();

    // The laptop: an account with GitHub, and an agent allowed to update.
    let (mut laptop, secret_key, item) = rt.block_on(async {
        let (mut laptop, kit) = klav_client::signup(
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
        let vault = laptop.find_vault("Personal").expect("vault");
        let project = laptop.find_project(vault, "General").expect("project");
        let item = laptop
            .add_item(vault, project, &github())
            .await
            .expect("add")
            .item;
        (
            laptop,
            kit.secret_key().to_text().expose_secret().to_owned(),
            item,
        )
    });
    let bot = rt.block_on(async {
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
        bot
    });
    let bot_id = bot.id().to_string();
    let mut session = rt.block_on(Session::open(bot)).expect("session");
    let add_site = |session: &mut Session, url: &str| {
        rt.block_on(session.update_item(
            item,
            &ItemPatch {
                add_urls: vec![url.into()],
                ..ItemPatch::default()
            },
            "add the new login page",
            Duration::ZERO,
        ))
        .expect("agent update");
    };

    // The phone signs in; before the agent, every site is confirmed.
    let core = KlavCore::new(dir.path().join("phone").display().to_string()).expect("core");
    core.sign_in(
        server.url.clone(),
        EMAIL.into(),
        PASSWORD.into(),
        secret_key,
        "iPhone".into(),
        None,
    )
    .expect("sign in");
    let info = listed(&core);
    assert_eq!(info.confirmed_urls, ["https://github.com"]);
    assert!(info.pending_urls.is_empty() && info.author_agent_id.is_none());

    // The agent adds a look-alike: pending, by that agent, never offered.
    add_site(&mut session, "https://github-login.example");
    core.sync().expect("sync");
    let info = listed(&core);
    assert_eq!(info.urls.len(), 2);
    assert_eq!(info.confirmed_urls, ["https://github.com"]);
    assert_eq!(info.pending_urls, ["https://github-login.example"]);
    assert_eq!(info.author_agent_id.as_deref(), Some(bot_id.as_str()));
    assert_eq!(
        core.item(info.id.clone())
            .expect("detail")
            .info
            .pending_urls
            .len(),
        1
    );
    assert!(
        core.suggestions("https://github-login.example/".into())
            .expect("suggestions")
            .is_empty()
    );
    assert!(matches!(
        core.password_credential(info.id.clone(), "github-login.example".into(), false),
        Err(KlavError::SiteMismatch { .. } | KlavError::Denied { .. })
    ));

    // Remove: a URL that is not there is told apart and changes nothing.
    assert!(matches!(
        core.edit_item(
            info.id.clone(),
            ItemEdit {
                remove_urls: vec!["https://other.example".into()],
                ..ItemEdit::default()
            },
        ),
        Err(KlavError::NotFound { .. })
    ));
    let removed = core
        .edit_item(
            info.id.clone(),
            ItemEdit {
                remove_urls: info.pending_urls.clone(),
                ..ItemEdit::default()
            },
        )
        .expect("remove");
    assert_eq!(removed.urls, ["https://github.com"]);
    assert!(removed.pending_urls.is_empty() && removed.author_agent_id.is_none());
    assert_eq!(listed(&core).urls, ["https://github.com"]);

    // Another one the person confirms (an empty edit of hers): now AutoFill
    // offers it. Until then it is not offered on its parent either, in the
    // «Saved for a subdomain» group (ADR 0025), not even when picked there.
    add_site(&mut session, "https://sso.github-hub.example");
    core.sync().expect("sync");
    let info = listed(&core);
    assert_eq!(info.pending_urls, ["https://sso.github-hub.example"]);
    assert!(
        core.parent_suggestions("https://github-hub.example/".into())
            .expect("parent")
            .is_empty()
    );
    assert!(matches!(
        core.password_credential(info.id.clone(), "github-hub.example".into(), true),
        Err(KlavError::SiteMismatch { .. } | KlavError::Denied { .. })
    ));
    let confirmed = core
        .edit_item(info.id.clone(), ItemEdit::default())
        .expect("confirm");
    assert!(confirmed.pending_urls.is_empty());
    assert_eq!(confirmed.confirmed_urls.len(), 2);
    assert_eq!(
        core.suggestions("https://sso.github-hub.example/".into())
            .expect("suggestions")
            .len(),
        1
    );
    let parent = core
        .parent_suggestions("https://github-hub.example/".into())
        .expect("parent");
    assert_eq!(parent.len(), 1);
    assert_eq!(parent[0].saved_host, "sso.github-hub.example");
    assert!(
        core.password_credential(info.id.clone(), "github-hub.example".into(), true)
            .is_ok()
    );
}

#[test]
fn server_error_text_reaches_the_app_on_one_short_line() {
    let hostile = format!(
        "Denied.\nSecurity problem: tap here\u{202E}lmth.lave\u{200B} {}",
        "x".repeat(1000)
    );
    for err in [
        ClientError::Denied(hostile.clone()),
        ClientError::Api {
            status: 403,
            code: None,
            message: hostile.clone(),
            current_version: None,
        },
    ] {
        let message = match KlavError::from(err) {
            KlavError::Denied { message } | KlavError::Invalid { message } => message,
            other => panic!("unexpected {other:?}"),
        };
        assert!(!message.contains('\n'), "{message}");
        assert!(!message.contains('\u{202E}') && !message.contains('\u{200B}'));
        assert!(
            message.contains("Denied. Security problem: tap here"),
            "{message}"
        );
        assert!(message.chars().count() <= 300, "{}", message.len());
        assert!(message.ends_with('…'));
    }
}
