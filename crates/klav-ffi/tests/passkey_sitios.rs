//! A passkey saved on the phone into a login an agent touched (ADR 0020
//! §11, ADR 0030 §7): saving writes a version of the person, so the sites
//! the agent added must not ride along and become confirmed. Both when the
//! extension queues it and when the app uploads it over a newer version
//! the agent wrote meanwhile.

mod common;

use std::time::Duration;

use common::ServerProcess;
use klav_client::agents::GrantRequest;
use klav_client::ops::ItemPatch;
use klav_client::{Home, SignupRequest};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::ids::ItemId;
use klav_core::model::item::{Item, ItemKind};
use klav_core::policy::{Effect, Permission, Policy, Rule};
use klav_ffi::{
    ItemInfo, ItemQuery, KlavCore, PasskeyRegistrationInput, PasskeyRegistrationOutcome,
};
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
    item.add_url("https://github.com").expect("test setup");
    item
}

fn listed(core: &KlavCore) -> ItemInfo {
    let mut items = core.items(ItemQuery::default()).expect("items");
    assert_eq!(items.len(), 1);
    items.remove(0)
}

fn register(core: &KlavCore, item: ItemId, replace: bool) {
    let outcome = core
        .passkey_registration(PasskeyRegistrationInput {
            rp_id: "github.com".into(),
            rp_name: None,
            user_name: "ana".into(),
            user_display_name: None,
            user_handle: b"ana-0001".to_vec(),
            exclude_credentials: Vec::new(),
            item_id: Some(item.to_string()),
            replace,
            vault: None,
            project: None,
        })
        .expect("register");
    assert!(
        matches!(outcome, PasskeyRegistrationOutcome::Created { .. }),
        "{outcome:?}"
    );
}

#[test]
fn a_passkey_saved_offline_never_confirms_an_agents_site() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let rt = runtime();

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
    let mut session = rt.block_on(Session::open(bot)).expect("session");
    let mut add_site = |url: &str| {
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

    // Queued into a login whose current version is the agent's.
    add_site("https://github-login.example");
    core.sync().expect("sync");
    assert_eq!(listed(&core).pending_urls, ["https://github-login.example"]);
    register(&core, item, false);
    let queued = listed(&core);
    assert_eq!(queued.urls, ["https://github.com"]);
    assert!(queued.pending_urls.is_empty());
    core.sync().expect("upload");
    assert!(core.passkey_outbox().expect("outbox").passkeys.is_empty());
    let uploaded = listed(&core);
    assert_eq!(uploaded.urls, ["https://github.com"]);
    assert!(uploaded.author_agent_id.is_none());

    // Queued over the person's version, uploaded after the agent wrote a
    // newer one: the passkey goes on that version, without its new site.
    register(&core, item, true);
    add_site("https://github-sso.example");
    core.sync().expect("sync and upload");
    assert!(core.passkey_outbox().expect("outbox").passkeys.is_empty());
    let after = listed(&core);
    assert_eq!(after.urls, ["https://github.com"]);
    assert!(after.pending_urls.is_empty() && after.author_agent_id.is_none());
    assert!(
        core.suggestions("https://github-sso.example/".into())
            .expect("suggestions")
            .is_empty()
    );
}
