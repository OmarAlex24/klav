//! The person's side of the credential proxy against a real server (ADR
//! 0036 §3, §14, layer 4): `use` records which agent is the proxy, which
//! then cannot get a project grant; `grant` pairs it on its first
//! credential (with its words) and adds more without them; `revoke` takes
//! one away and changes its key; a change prepared from an older grant is
//! never signed; and an item waiting in the trash does not block taking
//! another one away.

#[path = "../../klav-client/tests/common/mod.rs"]
mod common;

use common::ServerProcess;
use klav_client::agents::GrantRequest;
use klav_client::item_grants::ItemGrantRequest;
use klav_client::proxy_admin::{
    LOST_WITHOUT_PROXY, OLDER_CLIENTS, OLDER_CLIENTS_PREFERENCES, PairingCheck, ProxyCredentialSpec,
};
use klav_client::{ClientError, Home, ItemLocation, SignupRequest, Unlocked, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::ids::AgentId;
use klav_core::ids::ItemId;
use klav_core::model::history::system_project_id;
use klav_core::model::item::{Item, ItemKind};
use klav_core::model::preferences::ProxyMode;
use klav_core::model::preferences::{Preferences, ProxySetting};
use klav_core::model::{SealedItem, open_item};
use klav_core::policy::{Effect, Permission, Policy};
use klav_proto::agent::{AccessGranted, AccessRequest, AgentStatus, Claims};
use klav_sdk::{Agent, KeyStore, Registration, Session};
use reqwest::Method;

const PASSWORD: &str = "correct horse battery staple";
const EMAIL: &str = "ana@example.com";
const RAILWAY: &str = "backboard.railway.app";
const TOKEN: &str = "token-of-the-provider-0123456789";

async fn account(server: &ServerProcess, dir: &tempfile::TempDir) -> Unlocked {
    signup(
        &Home::at(dir.path().join("laptop")),
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
    .expect("sign-up")
    .0
}

async fn register(server: &ServerProcess, dir: &tempfile::TempDir, name: &str) -> Agent {
    let home = Home::at(dir.path().join(format!("agent-{name}")));
    Agent::register(
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
    .expect("register")
    .0
}

async fn add(ana: &mut Unlocked, title: &str) -> ItemLocation {
    let vault = ana.find_vault("Personal").expect("vault");
    let project = ana.find_project(vault, "General").expect("project");
    let mut item = Item::from_template(ItemKind::Login, title).expect("item");
    item.field_mut("password")
        .expect("password")
        .set_value(TOKEN)
        .expect("set");
    ana.add_item(vault, project, &item).await.expect("add item")
}

fn spec(profile: &str) -> ProxyCredentialSpec {
    ProxyCredentialSpec {
        profile: profile.into(),
        upstream: format!("https://{RAILWAY}"),
        header: "Authorization".into(),
        prefix: "Bearer ".into(),
        field: Some("password".into()),
        methods: vec!["POST".into()],
        path_prefixes: vec!["/graphql".into()],
        ..ProxyCredentialSpec::default()
    }
}

/// A proxied call through the server, opened with the grant's item key.
async fn proxied(session: &Session, item: ItemId) -> Result<Item, ClientError> {
    let granted: AccessGranted = session
        .agent()
        .call(
            Method::POST,
            "/v1/agent/access",
            Some(&AccessRequest {
                item_id: item,
                permission: Permission::Proxy,
                reason: "deploy".into(),
                claims: Claims {
                    domain: Some(RAILWAY.into()),
                    method: Some("POST".into()),
                    path: Some("/graphql".into()),
                    ..Claims::default()
                },
                approval_id: None,
                task_id: None,
                include_attachments: false,
                sandbox: None,
            }),
        )
        .await?;
    let key = session
        .grant()
        .items
        .get(&item)
        .ok_or_else(|| ClientError::NotFound("item key".into()))?;
    let wire = granted.item;
    Ok(open_item(
        &key.key,
        &key.ctx,
        wire.version,
        &SealedItem {
            overview: wire.overview.expect("overview").into_bytes(),
            details: wire.details.expect("details").into_bytes(),
        },
    )?)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_person_pairs_grants_and_revokes_through_the_proxy_setting() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir).await;
    let railway = add(&mut ana, "Railway").await;
    let other = add(&mut ana, "Other").await;
    let proxy = register(&server, &dir, "klav-proxy").await;
    let words = proxy.pairing_code();

    // No proxy yet: what is lost, and nothing to grant to.
    let status = ana.proxy_status().await.expect("status");
    assert_eq!(status.mode, ProxyMode::None);
    assert_eq!(status.lost.len(), LOST_WITHOUT_PROXY.len());
    assert!(matches!(
        ana.preview_proxy_grant("Railway", &spec("railway")).await,
        Err(ClientError::Invalid(_))
    ));

    // `use` records it; the first time, with the older-clients warning.
    let prepared = ana
        .prepare_proxy_use(Some("klav-proxy"))
        .await
        .expect("prepare use");
    assert_eq!(prepared.agent.as_deref(), Some("klav-proxy"));
    assert_eq!(
        prepared.warnings,
        vec![OLDER_CLIENTS_PREFERENCES.to_owned()]
    );
    ana.commit_proxy_use(prepared).await.expect("use");
    let status = ana.proxy_status().await.expect("status");
    assert_eq!(status.mode, ProxyMode::Own);
    assert_eq!(
        status.agent.as_ref().map(|a| a.status),
        Some(AgentStatus::Pending)
    );
    assert_eq!(
        status.agent.as_ref().map(|a| a.pairing_code.as_str()),
        Some(words.as_str())
    );
    assert!(status.lost.is_empty() && status.credentials.is_empty());

    // L4-a: from now on no client gives it whole projects.
    let err = ana
        .approve_agent(
            proxy.id(),
            GrantRequest {
                projects: vec!["Personal/General".into()],
                vaults: Vec::new(),
                policy: Policy::default(),
            },
            &words,
        )
        .await
        .expect_err("a project grant for the proxy");
    assert!(err.to_string().contains("klav proxy grant"), "{err}");

    // The first credential shows the proxy's words, the profile and the
    // warnings, and needs the words.
    let preview = ana
        .preview_proxy_grant("Railway", &spec("railway"))
        .await
        .expect("preview");
    assert!(preview.first);
    assert_eq!(preview.pairing_code, words);
    assert_eq!(preview.base_version, 0);
    assert!(preview.warnings.iter().any(|w| w == OLDER_CLIENTS));
    assert!(preview.warnings.iter().any(|w| w.contains("Railway")));
    let shown = serde_json::to_string(&preview).expect("json");
    assert!(!shown.contains(TOKEN), "never a value");
    let profile = preview
        .credential
        .as_ref()
        .and_then(|c| c.profile.as_ref())
        .expect("profile");
    assert_eq!(profile.header, "authorization");
    assert!(matches!(
        ana.prepare_proxy_grant("Railway", &spec("railway"), PairingCheck::Typed(None))
            .await,
        Err(ClientError::Invalid(_))
    ));
    assert!(matches!(
        ana.prepare_proxy_grant(
            "Railway",
            &spec("railway"),
            PairingCheck::Typed(Some("one two three four five six"))
        )
        .await,
        Err(ClientError::Security(_))
    ));
    let prepared = ana
        .prepare_proxy_grant(
            "Railway",
            &spec("railway"),
            PairingCheck::Typed(Some(&words)),
        )
        .await
        .expect("prepare grant");
    let report = ana.commit_proxy_change(prepared).await.expect("grant");
    assert!(report.granted, "{report:?}");
    let grant = report.agent.grant.expect("grant");
    assert_eq!(grant.version, 1);
    assert!(grant.projects.is_empty());
    for p in [Permission::Reveal, Permission::Inject, Permission::Fill] {
        assert!(
            grant
                .policy
                .rules
                .iter()
                .filter(|r| r.permission == p)
                .all(|r| r.effect == Effect::Deny)
        );
    }

    // The proxy uses it.
    let mut session = Session::open(proxy).await.expect("session");
    let opened = proxied(&session, railway.item).await.expect("proxied");
    assert_eq!(opened.title(), "Railway");

    // More credentials need no words: its key is the one already approved.
    let prepared = ana
        .prepare_proxy_grant("Other", &spec("other"), PairingCheck::Typed(None))
        .await
        .expect("second grant");
    assert!(!prepared.view().first);
    ana.commit_proxy_change(prepared)
        .await
        .expect("grant other");

    // A change prepared from version 2 is not signed over version 3.
    let stale = ana
        .prepare_proxy_grant(
            "Railway",
            &ProxyCredentialSpec {
                ask: true,
                ..spec("railway")
            },
            PairingCheck::Typed(None),
        )
        .await
        .expect("stale prepare");
    assert!(stale.view().replaces);
    assert_eq!(stale.view().base_version, 2);

    // Taking `Other` away: its key changes and the proxy loses it.
    let prepared = ana
        .prepare_proxy_revoke("Other")
        .await
        .expect("prepare revoke");
    let report = ana.commit_proxy_change(prepared).await.expect("revoke");
    assert!(report.granted && report.failed.is_none(), "{report:?}");
    assert_eq!(report.rekeyed, vec![other.item]);
    let err = ana
        .commit_proxy_change(stale)
        .await
        .expect_err("stale change");
    assert!(err.to_string().contains("changed since"), "{err}");
    let status = ana.proxy_status().await.expect("status");
    assert_eq!(status.credentials.len(), 1);
    assert_eq!(status.credentials[0].item_id, railway.item);
    assert_eq!(status.credentials[0].rules[0].effect, Effect::Allow);
    session.refresh().await.expect("refresh");
    assert!(proxied(&session, other.item).await.is_err());
    proxied(&session, railway.item)
        .await
        .expect("still proxies Railway");

    // The last one is taken away by revoking the proxy.
    let err = ana
        .prepare_proxy_revoke("Railway")
        .await
        .expect_err("last credential");
    assert!(err.to_string().contains("klav agent revoke"), "{err}");
    // And it is not swapped for another while it holds credentials.
    let err = ana
        .prepare_proxy_use(None)
        .await
        .expect_err("switch while holding");
    assert!(err.to_string().contains("still holds credentials"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_item_in_the_trash_does_not_block_taking_another_away() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir).await;
    let railway = add(&mut ana, "Railway").await;
    let other = add(&mut ana, "Other").await;
    let proxy = register(&server, &dir, "klav-proxy").await;
    let words = proxy.pairing_code();
    let prepared = ana
        .prepare_proxy_use(Some("klav-proxy"))
        .await
        .expect("use");
    ana.commit_proxy_use(prepared).await.expect("use");
    let prepared = ana
        .prepare_proxy_grant(
            "Railway",
            &spec("railway"),
            PairingCheck::Typed(Some(&words)),
        )
        .await
        .expect("grant");
    ana.commit_proxy_change(prepared).await.expect("grant");
    let prepared = ana
        .prepare_proxy_grant("Other", &spec("other"), PairingCheck::Typed(None))
        .await
        .expect("grant other");
    ana.commit_proxy_change(prepared)
        .await
        .expect("grant other");

    ana.trash_item(railway).await.expect("trash");
    let prepared = ana.prepare_proxy_revoke("Other").await.expect("revoke");
    let report = ana.commit_proxy_change(prepared).await.expect("revoke");
    assert!(report.granted, "{report:?}");
    assert_eq!(report.rekeyed, vec![other.item]);
    let grant = report.agent.grant.expect("grant");
    assert_eq!(grant.items.len(), 1);
    assert_eq!(grant.items[0].item_id, railway.item);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_that_holds_projects_is_never_the_proxy() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir).await;
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
    let err = ana
        .prepare_proxy_use(Some("bot"))
        .await
        .expect_err("a project holder as proxy");
    assert!(err.to_string().contains("whole projects"), "{err}");
    assert_eq!(
        ana.proxy_status().await.expect("status").mode,
        ProxyMode::None
    );
}

/// An account whose proxy, `klav-proxy`, holds `Railway`, granted the way
/// klavd does: words in the prompt, devices acknowledged.
async fn paired(
    server: &ServerProcess,
    dir: &tempfile::TempDir,
) -> (Unlocked, Agent, ItemLocation, ItemLocation) {
    let mut ana = account(server, dir).await;
    let railway = add(&mut ana, "Railway").await;
    let other = add(&mut ana, "Other").await;
    let proxy = register(server, dir, "klav-proxy").await;
    let prepared = ana
        .prepare_proxy_use(Some("klav-proxy"))
        .await
        .expect("use");
    ana.commit_proxy_use(prepared).await.expect("use");
    let prepared = ana
        .prepare_proxy_grant("Railway", &spec("railway"), PairingCheck::InPrompt)
        .await
        .expect("grant");
    prepared
        .require_updated_devices(true)
        .expect("acknowledged");
    let report = ana.commit_proxy_change(prepared).await.expect("grant");
    assert!(report.complete(), "{report:?}");
    (ana, proxy, railway, other)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_first_grant_needs_the_acknowledgement_and_shows_the_fetched_words() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir).await;
    add(&mut ana, "Railway").await;
    add(&mut ana, "Other").await;
    let proxy = register(&server, &dir, "klav-proxy").await;
    let prepared = ana
        .prepare_proxy_use(Some("klav-proxy"))
        .await
        .expect("use");
    ana.commit_proxy_use(prepared).await.expect("use");

    // klavd's path: no words from the caller. The view carries the words
    // of the key fetched for this commit, which the prompt shows.
    let prepared = ana
        .prepare_proxy_grant("Railway", &spec("railway"), PairingCheck::InPrompt)
        .await
        .expect("prepare");
    let view = prepared.view();
    assert!(view.first && view.first_on_account);
    assert_eq!(view.pairing_code, proxy.pairing_code());
    let err = prepared
        .require_updated_devices(false)
        .expect_err("first per-item grant without the acknowledgement");
    assert!(
        err.to_string().contains("--every-device-is-updated"),
        "{err}"
    );
    assert!(
        err.to_string().contains("--rotate"),
        "names what breaks: {err}"
    );
    prepared
        .require_updated_devices(true)
        .expect("acknowledged");
    assert!(
        ana.commit_proxy_change(prepared)
            .await
            .expect("grant")
            .complete()
    );

    // Later grants need no acknowledgement and no words.
    let prepared = ana
        .prepare_proxy_grant("Other", &spec("other"), PairingCheck::InPrompt)
        .await
        .expect("second");
    assert!(!prepared.view().first && !prepared.view().first_on_account);
    prepared
        .require_updated_devices(false)
        .expect("not the first");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_grant_is_refused_before_presence_when_it_cannot_be_shown_or_used() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _proxy, _railway, _other) = paired(&server, &dir).await;

    // More than the prompt shows in full: split it.
    let wide = ProxyCredentialSpec {
        path_prefixes: vec!["/a".into(), "/b".into(), "/c".into(), "/d".into()],
        ..spec("other")
    };
    let err = ana
        .prepare_proxy_grant("Other", &wide, PairingCheck::InPrompt)
        .await
        .expect_err("over the cap");
    assert!(err.to_string().contains("at most"), "{err}");

    // An item with no main secret needs --field.
    let vault = ana.find_vault("Personal").expect("vault");
    let project = ana.find_project(vault, "General").expect("project");
    let note = Item::from_template(ItemKind::Note, "Notes").expect("note");
    ana.add_item(vault, project, &note).await.expect("add note");
    let err = ana
        .prepare_proxy_grant(
            "Notes",
            &ProxyCredentialSpec {
                field: None,
                ..spec("notes")
            },
            PairingCheck::InPrompt,
        )
        .await
        .expect_err("a note without --field");
    assert!(err.to_string().contains("--field"), "{err}");
    // A login without --field uses its password.
    ana.prepare_proxy_grant(
        "Other",
        &ProxyCredentialSpec {
            field: None,
            ..spec("other")
        },
        PairingCheck::InPrompt,
    )
    .await
    .expect("a login's main secret");

    // A profile name another credential uses.
    assert!(
        ana.prepare_proxy_grant("Other", &spec("railway"), PairingCheck::InPrompt)
            .await
            .is_err(),
        "a clashing profile name"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn granting_an_item_again_leaves_exactly_the_new_rules() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _proxy, railway, _other) = paired(&server, &dir).await;
    let again = ProxyCredentialSpec {
        methods: vec!["GET".into()],
        path_prefixes: vec!["/v2".into()],
        ask_methods: vec!["DELETE".into()],
        ..spec("railway")
    };
    let prepared = ana
        .prepare_proxy_grant("Railway", &again, PairingCheck::InPrompt)
        .await
        .expect("again");
    assert!(prepared.view().replaces);
    assert!(
        ana.commit_proxy_change(prepared)
            .await
            .expect("grant")
            .complete()
    );
    let status = ana.proxy_status().await.expect("status");
    assert_eq!(status.credentials.len(), 1);
    let credential = &status.credentials[0];
    assert_eq!(credential.item_id, railway.item);
    let mut rules: Vec<_> = credential
        .rules
        .iter()
        .map(|r| {
            (
                r.effect,
                r.methods.clone(),
                r.hosts.clone(),
                r.path_prefixes.clone(),
            )
        })
        .collect();
    rules.sort_by_key(|r| format!("{:?}", r.0));
    assert_eq!(
        rules,
        vec![
            (
                Effect::Allow,
                vec!["GET".to_owned()],
                vec![RAILWAY.to_owned()],
                vec!["/v2".to_owned()]
            ),
            (
                Effect::Ask,
                vec!["DELETE".to_owned()],
                vec![RAILWAY.to_owned()],
                vec!["/v2".to_owned()]
            ),
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn running_a_revoke_again_finishes_the_other_holders_reissue() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _proxy, _railway, other) = paired(&server, &dir).await;
    let prepared = ana
        .prepare_proxy_grant("Other", &spec("other"), PairingCheck::InPrompt)
        .await
        .expect("grant other");
    ana.commit_proxy_change(prepared)
        .await
        .expect("grant other");
    // Another agent holds `Other` one by one too.
    let ci = register(&server, &dir, "ci").await;
    let mut policy = Policy::default();
    for p in [Permission::Reveal, Permission::Inject, Permission::Fill] {
        policy
            .rules
            .push(klav_core::policy::Rule::new(p, Effect::Deny));
    }
    let report = ana
        .grant_items(
            ci.id(),
            ItemGrantRequest {
                items: vec![other],
                profiles: Vec::new(),
                policy,
                issuers: Vec::new(),
            },
            &ci.pairing_code(),
        )
        .await
        .expect("grant ci");
    assert!(report.complete(), "{report:?}");

    let prepared = ana.prepare_proxy_revoke("Other").await.expect("revoke");
    let report = ana.commit_proxy_change(prepared).await.expect("revoke");
    assert!(report.complete(), "{report:?}");
    assert_eq!(report.rekeyed, vec![other.item]);
    assert_eq!(report.regranted, vec!["ci".to_owned()]);

    let ci_version = |agents: Vec<klav_client::agents::AgentView>| {
        agents
            .into_iter()
            .find(|a| a.name == "ci")
            .and_then(|a| a.grant)
            .map(|g| g.version)
            .expect("ci's grant")
    };
    let before = ci_version(ana.agents().await.expect("agents"));

    // A re-issue that failed is finished by the same command: the proxy no
    // longer holds the item, so it only re-issues those that still do.
    // (Making one re-issue fail needs a fault the test server cannot
    // inject: this shows the retry re-issues, with the current keys.)
    let prepared = ana.prepare_proxy_revoke("Other").await.expect("retry");
    assert!(prepared.view().reissue_only);
    assert!(prepared.view().warnings.iter().any(|w| w.contains("ci")));
    let report = ana.commit_proxy_change(prepared).await.expect("retry");
    assert!(report.complete(), "{report:?}");
    assert!(report.rekeyed.is_empty());
    assert_eq!(report.regranted, vec!["ci".to_owned()]);
    assert_eq!(ci_version(ana.agents().await.expect("agents")), before + 1);
    let mut ci_session = Session::open(ci).await.expect("ci session");
    ci_session.refresh().await.expect("refresh");
    assert!(ci_session.grant().items.contains_key(&other.item));

    // With nobody else holding it, there is nothing to finish.
    let id = ana
        .agents()
        .await
        .expect("agents")
        .into_iter()
        .find(|a| a.name == "ci")
        .expect("ci")
        .id;
    ana.revoke_agent(id, false).await.expect("revoke ci");
    assert!(matches!(
        ana.prepare_proxy_revoke("Other").await,
        Err(ClientError::NotFound(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_setting_that_names_a_gone_agent_can_be_changed() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir).await;
    add(&mut ana, "Railway").await;

    // Missing: an agent the server does not know.
    ana.set_proxy_setting(ProxySetting::own(AgentId::generate()))
        .await
        .expect("set");
    let status = ana.proxy_status().await.expect("status");
    assert!(!status.problems.is_empty());
    assert!(
        ana.preview_proxy_grant("Railway", &spec("railway"))
            .await
            .is_err()
    );

    // Pending: switching away from it, or to none, is allowed.
    register(&server, &dir, "first").await;
    register(&server, &dir, "second").await;
    for name in [Some("first"), Some("second"), None, Some("first")] {
        let prepared = ana.prepare_proxy_use(name).await.expect("switch");
        ana.commit_proxy_use(prepared).await.expect("switch");
    }

    // Denied: the setting reports it, nothing is granted to it, and it can
    // be replaced.
    let first = ana
        .agents()
        .await
        .expect("agents")
        .into_iter()
        .find(|a| a.name == "first")
        .expect("first")
        .id;
    ana.deny_agent(first).await.expect("deny");
    let status = ana.proxy_status().await.expect("status");
    assert!(!status.problems.is_empty());
    let err = ana
        .preview_proxy_grant("Railway", &spec("railway"))
        .await
        .expect_err("a denied proxy");
    assert!(err.to_string().contains("use own"), "{err}");
    let prepared = ana.prepare_proxy_use(Some("second")).await.expect("switch");
    ana.commit_proxy_use(prepared).await.expect("switch");

    // Revoked, after it held a credential: replaced as well.
    let second = ana
        .agents()
        .await
        .expect("agents")
        .into_iter()
        .find(|a| a.name == "second")
        .expect("second")
        .id;
    let prepared = ana
        .prepare_proxy_grant("Railway", &spec("railway"), PairingCheck::InPrompt)
        .await
        .expect("grant");
    ana.commit_proxy_change(prepared).await.expect("grant");
    ana.revoke_agent(second, false).await.expect("revoke");
    assert!(
        ana.preview_proxy_grant("Railway", &spec("railway"))
            .await
            .is_err()
    );
    let prepared = ana.prepare_proxy_use(None).await.expect("none");
    ana.commit_proxy_use(prepared).await.expect("none");
    assert_eq!(
        ana.proxy_status().await.expect("status").mode,
        ProxyMode::None
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ordinary_agent_is_approved_when_the_setting_does_not_read() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir).await;
    let prepared = ana.prepare_proxy_use(None).await.expect("none");
    ana.commit_proxy_use(prepared)
        .await
        .expect("write the item");
    // A second copy that disagrees: the setting does not read.
    let vault = ana.find_vault("Personal").expect("vault");
    let mut second = Item::new(ItemKind::Preferences, "Preferences").expect("item");
    second
        .set_preferences(Some(Preferences {
            developer: None,
            proxy: Some(ProxySetting::own(AgentId::generate())),
        }))
        .expect("set");
    ana.add_item(vault, system_project_id(vault), &second)
        .await
        .expect("add");
    assert!(ana.preferences().is_err());

    let bot = register(&server, &dir, "bot").await;
    let prepared = ana
        .prepare_grant(
            bot.id(),
            GrantRequest {
                projects: vec!["Personal/General".into()],
                vaults: Vec::new(),
                policy: Policy::default(),
            },
            &bot.pairing_code(),
        )
        .await
        .expect("approved as before the setting existed");
    assert!(
        prepared
            .warnings()
            .iter()
            .any(|w| w.contains("could not check whether this agent")),
        "{:?}",
        prepared.warnings()
    );
    ana.grant_prepared(prepared).await.expect("grant");
}
