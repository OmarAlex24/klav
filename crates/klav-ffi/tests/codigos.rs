//! «Set up codes in Klav» (ADR 0035) against the real server: a code link
//! read while locked, the logins it could go into, and nothing replaced
//! without «Replace». Test vectors only (the RFC 4648 `JBSWY3DPEHPK3PXP`).

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::ServerProcess;
use klav_client::agents::GrantRequest;
use klav_client::ops::ItemPatch;
use klav_client::{Home, SignupRequest};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::model::item::{Item, ItemKind};
use klav_core::policy::{Effect, Permission, Policy, Rule};
use klav_ffi::{
    CodeLink, CodeSaveOutcome, CodeState, FieldEdit, FieldType, Kind, KlavCore, KlavError,
    NewCodeLogin, NewItemInput,
};
use klav_proto::auth::DeviceKind;
use klav_sdk::{Agent, KeyStore, Registration, Session};
use secrecy::ExposeSecret;

const PASSWORD: &str = "correct horse battery staple";
const LINK: &str = "otpauth://totp/Example:ana@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
const NEW_LINK: &str =
    "otpauth://totp/Example:ana@example.com?secret=KRSXG5CTMVRXEZLU&issuer=Example";

/// An empty account made on a laptop; its Secret Key.
fn laptop(server: &str, dir: &std::path::Path) -> String {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test setup");
    rt.block_on(async {
        let (_, kit) = klav_client::signup(
            &Home::at(dir.join("laptop")),
            SignupRequest {
                server: server.to_owned(),
                email: "ana@example.com".into(),
                password: MasterPassword::new(PASSWORD),
                device_name: "laptop".into(),
                device_kind: DeviceKind::Cli,
                invite: None,
            },
        )
        .await
        .expect("test setup");
        kit.secret_key().to_text().expose_secret().to_owned()
    })
}

fn login(core: &KlavCore, title: &str, user: &str, url: &str) -> String {
    core.create_item(NewItemInput {
        kind: Kind::Login,
        title: title.into(),
        vault_id: None,
        project_id: None,
        fields: vec![
            FieldEdit {
                name: "username".into(),
                value: user.into(),
                kind: None,
            },
            FieldEdit {
                name: "password".into(),
                value: format!("{title}-pass"),
                kind: None,
            },
        ],
        urls: vec![url.into()],
        tags: Vec::new(),
        notes: None,
    })
    .expect("test setup")
    .id
}

fn code_field(core: &KlavCore, id: &str) -> String {
    core.field_value(id.into(), "totp".into())
        .expect("its code")
}

#[test]
fn a_code_link_goes_where_the_person_chooses_and_replaces_only_when_asked() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let secret_key = laptop(&server.url, dir.path());
    let core = KlavCore::new(dir.path().join("phone").display().to_string()).unwrap();

    // Locked (not even signed in here): the link is read, nothing else.
    let link = CodeLink::new(LINK.into()).unwrap();
    assert!(matches!(
        core.code_targets(link.clone()),
        Err(KlavError::Locked)
    ));
    core.sign_in(
        server.url.clone(),
        "ana@example.com".into(),
        PASSWORD.into(),
        secret_key,
        "iPhone".into(),
        None,
    )
    .unwrap();

    let example = login(
        &core,
        "Example",
        "ana@example.com",
        "https://login.example.com",
    );
    let other_user = login(
        &core,
        "Example (bob)",
        "bob@example.com",
        "https://example.com",
    );
    let unrelated = login(&core, "Bank", "ana@example.com", "https://bank.test");

    // The login of the issuer and the account first, then the issuer's,
    // then the rest; none has a code yet.
    let targets = core.code_targets(link.clone()).unwrap();
    let order: Vec<&str> = targets.iter().map(|t| t.item.id.as_str()).collect();
    assert_eq!(
        order,
        [example.as_str(), other_user.as_str(), unrelated.as_str()]
    );
    assert!(targets[0].issuer_match && targets[0].account_match);
    assert!(targets[1].issuer_match && !targets[1].account_match);
    assert!(!targets[2].issuer_match && targets[2].account_match);
    assert!(targets.iter().all(|t| t.code == CodeState::None));

    // Saved where the person chose: the code works from the login.
    let CodeSaveOutcome::Saved { item } = core
        .save_code(link.clone(), example.clone(), false)
        .unwrap()
    else {
        panic!("saved");
    };
    let saved_version = item.version;
    assert!(code_field(&core, &example).contains("secret=JBSWY3DPEHPK3PXP"));
    assert_eq!(core.totp(example.clone()).unwrap().code.len(), 6);

    // The same code again writes nothing.
    assert!(matches!(
        core.save_code(link.clone(), example.clone(), true).unwrap(),
        CodeSaveOutcome::AlreadyThere { item } if item.version == saved_version
    ));
    let targets = core.code_targets(link.clone()).unwrap();
    assert_eq!(targets[0].code, CodeState::Same);

    // Another code for the same login: nothing changes without «Replace».
    let new_link = CodeLink::new(NEW_LINK.into()).unwrap();
    assert_eq!(
        core.code_targets(new_link.clone()).unwrap()[0].code,
        CodeState::Other
    );
    assert!(matches!(
        core.save_code(new_link.clone(), example.clone(), false).unwrap(),
        CodeSaveOutcome::NeedsReplace { item } if item.version == saved_version
    ));
    assert!(code_field(&core, &example).contains("secret=JBSWY3DPEHPK3PXP"));
    assert!(matches!(
        core.save_code(new_link.clone(), example.clone(), true).unwrap(),
        CodeSaveOutcome::Saved { item } if item.version > saved_version
    ));
    assert!(code_field(&core, &example).contains("secret=KRSXG5CTMVRXEZLU"));

    // A new login: the person's title, user and site, no password. A
    // title the project already has is refused.
    let taken = core
        .save_code_new(
            link.clone(),
            NewCodeLogin {
                title: "Example".into(),
                username: Some("ana@example.com".into()),
                site: Some("https://example.org".into()),
                vault_id: None,
                project_id: None,
            },
        )
        .expect_err("the title is taken");
    assert!(!taken.to_string().contains("JBSW"));
    let made = core
        .save_code_new(
            link.clone(),
            NewCodeLogin {
                title: "Example 2".into(),
                username: Some("ana@example.com".into()),
                site: Some("https://example.org".into()),
                vault_id: None,
                project_id: None,
            },
        )
        .unwrap();
    assert_eq!(made.kind, Kind::Login);
    assert_eq!(made.username.as_deref(), Some("ana@example.com"));
    assert_eq!(made.confirmed_urls, ["https://example.org"]);
    assert!(code_field(&core, &made.id).contains("secret=JBSWY3DPEHPK3PXP"));
    assert!(
        core.field_value(made.id.clone(), "password".into())
            .unwrap()
            .is_empty()
    );

    // Only into a login.
    let note = core
        .create_item(NewItemInput {
            kind: Kind::Note,
            title: "Note".into(),
            vault_id: None,
            project_id: None,
            fields: Vec::new(),
            urls: Vec::new(),
            tags: Vec::new(),
            notes: Some("text".into()),
        })
        .unwrap();
    assert!(
        core.save_code(link.clone(), note.id.clone(), false)
            .is_err()
    );

    // Only live logins are offered: not the note, not one in the trash,
    // and one in the trash takes no code.
    core.trash_item(unrelated.clone()).unwrap();
    let offered: Vec<String> = core
        .code_targets(link.clone())
        .unwrap()
        .into_iter()
        .map(|t| t.item.id)
        .collect();
    assert!(offered.contains(&example) && offered.contains(&made.id));
    assert!(!offered.contains(&note.id) && !offered.contains(&unrelated));
    assert!(core.save_code(link.clone(), unrelated, false).is_err());

    // A new login without a site has no URL at all.
    let no_site = core
        .save_code_new(
            link.clone(),
            NewCodeLogin {
                title: "Example (no site)".into(),
                username: None,
                site: None,
                vault_id: None,
                project_id: None,
            },
        )
        .unwrap();
    assert!(no_site.urls.is_empty() && no_site.confirmed_urls.is_empty());
    assert!(no_site.username.is_none());
    assert!(code_field(&core, &no_site.id).contains("secret=JBSWY3DPEHPK3PXP"));

    // Locked again: nothing is listed or written.
    core.lock();
    assert!(matches!(
        core.code_targets(link.clone()),
        Err(KlavError::Locked)
    ));
    assert!(matches!(
        core.save_code(link, example, true),
        Err(KlavError::Locked)
    ));
}

/// The phone, signed in to the laptop's account as `name`.
fn device(server: &str, dir: &std::path::Path, secret_key: &str, name: &str) -> Arc<KlavCore> {
    let core = KlavCore::new(dir.join(name).display().to_string()).expect("test setup");
    core.sign_in(
        server.to_owned(),
        "ana@example.com".into(),
        PASSWORD.into(),
        secret_key.to_owned(),
        name.into(),
        None,
    )
    .expect("test setup");
    core
}

/// Compared with `==`, never `assert_eq!`: a failure would print the value.
fn same_value(core: &KlavCore, id: &str, field: &str, before: &str) -> bool {
    core.field_value(id.into(), field.into())
        .expect("the field")
        == before
}

#[test]
fn only_the_code_autofill_uses_counts_and_replace_changes_nothing_else() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let secret_key = laptop(&server.url, dir.path());
    let core = device(&server.url, dir.path(), &secret_key, "iPhone");

    // This code only in a second field («(imported)»); the first one, the
    // one AutoFill fills, has another.
    let twin = core
        .create_item(NewItemInput {
            kind: Kind::Login,
            title: "Example".into(),
            vault_id: None,
            project_id: None,
            fields: vec![
                FieldEdit {
                    name: "username".into(),
                    value: "ana@example.com".into(),
                    kind: None,
                },
                FieldEdit {
                    name: "password".into(),
                    value: "Example-pass".into(),
                    kind: None,
                },
                FieldEdit {
                    name: "totp".into(),
                    value: NEW_LINK.into(),
                    kind: None,
                },
                FieldEdit {
                    name: "totp-imported".into(),
                    value: LINK.into(),
                    kind: Some(FieldType::Totp),
                },
            ],
            urls: vec![
                "https://example.com".into(),
                "https://login.example.com".into(),
            ],
            tags: Vec::new(),
            notes: None,
        })
        .unwrap();
    let before = |field: &str| core.field_value(twin.id.clone(), field.into()).unwrap();
    let (password, imported) = (before("password"), before("totp-imported"));

    // «Done» would show the first field's code: this is another code.
    let link = CodeLink::new(LINK.into()).unwrap();
    let targets = core.code_targets(link.clone()).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].code, CodeState::Other);
    assert!(matches!(
        core.save_code(link.clone(), twin.id.clone(), false).unwrap(),
        CodeSaveOutcome::NeedsReplace { item } if item.version == twin.version
    ));
    assert!(code_field(&core, &twin.id).contains("secret=KRSXG5CTMVRXEZLU"));

    // «Replace» changes the first code field and nothing else.
    let CodeSaveOutcome::Saved { item } =
        core.save_code(link.clone(), twin.id.clone(), true).unwrap()
    else {
        panic!("saved");
    };
    assert!(code_field(&core, &twin.id).contains("secret=JBSWY3DPEHPK3PXP"));
    assert!(same_value(&core, &twin.id, "password", &password));
    assert!(same_value(&core, &twin.id, "totp-imported", &imported));
    assert_eq!(item.username.as_deref(), Some("ana@example.com"));
    assert_eq!(item.urls, twin.urls);
    assert_eq!(item.confirmed_urls, twin.confirmed_urls);
    assert_eq!(item.title, "Example");
    // What AutoFill fills is now this code: the same link is «already there».
    assert_eq!(
        core.code_targets(link.clone()).unwrap()[0].code,
        CodeState::Same
    );
    assert!(matches!(
        core.save_code(link, twin.id.clone(), false).unwrap(),
        CodeSaveOutcome::AlreadyThere { .. }
    ));
}

#[test]
fn a_change_on_another_device_is_a_conflict_and_the_sheet_asks_again() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let secret_key = laptop(&server.url, dir.path());
    let phone = device(&server.url, dir.path(), &secret_key, "iPhone");
    let ipad = device(&server.url, dir.path(), &secret_key, "iPad");

    let id = login(&phone, "Example", "ana@example.com", "https://example.com");
    ipad.sync().unwrap();

    // The iPad saves a code first; the phone still has the login without one.
    let new_link = CodeLink::new(NEW_LINK.into()).unwrap();
    assert!(matches!(
        ipad.save_code(new_link, id.clone(), false).unwrap(),
        CodeSaveOutcome::Saved { .. }
    ));

    // The phone's write is refused by the server, never forced over it.
    let link = CodeLink::new(LINK.into()).unwrap();
    assert!(matches!(
        phone.save_code(link.clone(), id.clone(), false),
        Err(KlavError::Conflict { .. })
    ));
    assert!(code_field(&phone, &id).contains("secret=KRSXG5CTMVRXEZLU"));

    // Asked again (the conflict synced the phone), the login now has
    // another code: nothing is written without «Replace».
    assert_eq!(
        phone.code_targets(link.clone()).unwrap()[0].code,
        CodeState::Other
    );
    assert!(matches!(
        phone.save_code(link, id.clone(), false).unwrap(),
        CodeSaveOutcome::NeedsReplace { .. }
    ));
    ipad.sync().unwrap();
    assert!(code_field(&ipad, &id).contains("secret=KRSXG5CTMVRXEZLU"));
}

#[test]
fn saving_a_code_confirms_the_sites_an_agent_added() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test setup");

    // The laptop: GitHub, and an agent allowed to update it.
    let (mut laptop, secret_key, item) = rt.block_on(async {
        let (mut laptop, kit) = klav_client::signup(
            &Home::at(dir.path().join("laptop")),
            SignupRequest {
                server: server.url.clone(),
                email: "ana@example.com".into(),
                password: MasterPassword::new(PASSWORD),
                device_name: "laptop".into(),
                device_kind: DeviceKind::Cli,
                invite: None,
            },
        )
        .await
        .expect("sign-up");
        let mut github = Item::from_template(ItemKind::Login, "GitHub").expect("test setup");
        github
            .field_mut("username")
            .expect("test setup")
            .set_value("ana")
            .expect("test setup");
        github.add_url("https://github.com").expect("test setup");
        let vault = laptop.find_vault("Personal").expect("vault");
        let project = laptop.find_project(vault, "General").expect("project");
        let item = laptop
            .add_item(vault, project, &github)
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
                email: "ana@example.com".into(),
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
    rt.block_on(session.update_item(
        item,
        &ItemPatch {
            add_urls: vec!["https://github-login.example".into()],
            ..ItemPatch::default()
        },
        "add the new login page",
        Duration::ZERO,
    ))
    .expect("agent update");

    let phone = device(&server.url, dir.path(), &secret_key, "iPhone");
    let link =
        CodeLink::new("otpauth://totp/GitHub:ana?secret=JBSWY3DPEHPK3PXP&issuer=GitHub".into())
            .unwrap();
    let targets = phone.code_targets(link.clone()).unwrap();
    assert_eq!(targets.len(), 1);
    // The agent's site is pending: the sheet says saving confirms it, and
    // the issuer is compared only with the confirmed one.
    assert_eq!(
        targets[0].item.pending_urls,
        ["https://github-login.example"]
    );
    assert!(targets[0].issuer_match);

    // Saving the code is the person's edit: it confirms the agent's site.
    let CodeSaveOutcome::Saved { item } = phone
        .save_code(link, targets[0].item.id.clone(), false)
        .unwrap()
    else {
        panic!("saved");
    };
    assert!(item.pending_urls.is_empty() && item.author_agent_id.is_none());
    assert_eq!(
        item.confirmed_urls,
        ["https://github.com", "https://github-login.example"]
    );
}
