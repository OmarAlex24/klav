//! Sandbox issuers against a real server (ADR 0036 §4, E6.2, layer 5):
//! `klav proxy issuer add` signs the issuer's grant and the proxy's, both
//! `v: 3`; a pending issuer is approved with no projects; the account's
//! first one needs the acknowledgement; an approval or a rotation keeps
//! the fields; `issuer remove` and `use` take them away again.

#[path = "../../klav-client/tests/common/mod.rs"]
mod common;

use common::ServerProcess;
use klav_client::agents::GrantRequest;
use klav_client::issuers::{IssuerSpec, OLDER_CLIENTS_ISSUERS};
use klav_client::proxy_admin::{PairingCheck, ProxyCredentialSpec};
use klav_client::{ClientError, Home, ItemLocation, SignupRequest, Unlocked, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::model::item::{Item, ItemKind};
use klav_core::policy::{Effect, Permission, Policy};
use klav_proto::agent::{AgentStatus, GRANT_PAYLOAD_VERSION_SANDBOXES};
use klav_sdk::{Agent, KeyStore, Registration, Session};

const EMAIL: &str = "ana@example.com";
const URL: &str = "tls://proxy.example.com:8443";

async fn account(server: &ServerProcess, dir: &tempfile::TempDir) -> Unlocked {
    signup(
        &Home::at(dir.path().join("laptop")),
        SignupRequest {
            server: server.url.clone(),
            email: EMAIL.into(),
            password: MasterPassword::new("correct horse battery staple"),
            device_name: "laptop".into(),
            device_kind: klav_proto::auth::DeviceKind::Cli,
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
        .set_value("token-0123456789")
        .expect("set");
    ana.add_item(vault, project, &item).await.expect("add item")
}

fn credential(profile: &str) -> ProxyCredentialSpec {
    ProxyCredentialSpec {
        profile: profile.into(),
        upstream: "https://api.northflank.com".into(),
        header: "authorization".into(),
        prefix: "Bearer ".into(),
        methods: vec!["GET".into()],
        path_prefixes: vec!["/v1".into()],
        ..ProxyCredentialSpec::default()
    }
}

fn issuer(profiles: &[&str]) -> IssuerSpec {
    IssuerSpec {
        profiles: profiles.iter().map(|p| (*p).to_owned()).collect(),
        url: URL.into(),
        ..IssuerSpec::default()
    }
}

/// An account whose proxy holds `Northflank` with profile `northflank`.
async fn with_proxy(server: &ServerProcess, dir: &tempfile::TempDir) -> (Unlocked, Agent) {
    let mut ana = account(server, dir).await;
    add(&mut ana, "Northflank").await;
    let proxy = register(server, dir, "klav-proxy").await;
    let prepared = ana
        .prepare_proxy_use(Some("klav-proxy"))
        .await
        .expect("use");
    ana.commit_proxy_use(prepared).await.expect("use");
    let prepared = ana
        .prepare_proxy_grant(
            "Northflank",
            &credential("northflank"),
            PairingCheck::InPrompt,
        )
        .await
        .expect("grant");
    prepared.require_updated_devices(true).expect("ack");
    assert!(
        ana.commit_proxy_change(prepared)
            .await
            .expect("grant")
            .complete()
    );
    (ana, proxy)
}

fn sandbox_of(agent: &klav_client::agents::AgentView) -> Option<klav_proto::agent::IssuerGrant> {
    agent.grant.as_ref().and_then(|g| g.sandbox.clone())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pending_issuer_is_approved_with_no_projects_and_both_grants_change() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy) = with_proxy(&server, &dir).await;
    let t3 = register(&server, &dir, "t3-code").await;

    let view = ana
        .preview_issuer_add("t3-code", &issuer(&["northflank"]))
        .await
        .expect("preview");
    assert!(view.pending && view.first_on_account);
    assert_eq!(view.pairing_code, t3.pairing_code());
    assert!(view.warnings.iter().any(|w| w == OLDER_CLIENTS_ISSUERS));
    assert_eq!(view.max_ttl_secs, 8 * 3600);
    assert_eq!(view.max_live, 3);

    // The words, when typed, must match; the first issuer needs the
    // acknowledgement.
    assert!(matches!(
        ana.prepare_issuer_add(
            "t3-code",
            &issuer(&["northflank"]),
            PairingCheck::Typed(Some("one two three four five six"))
        )
        .await,
        Err(ClientError::Security(_))
    ));
    let prepared = ana
        .prepare_issuer_add("t3-code", &issuer(&["northflank"]), PairingCheck::InPrompt)
        .await
        .expect("prepare");
    let err = prepared.require_updated_devices(false).expect_err("no ack");
    assert!(
        err.to_string().contains("--every-device-is-updated"),
        "{err}"
    );
    prepared.require_updated_devices(true).expect("ack");
    let report = ana.commit_issuer_change(prepared).await.expect("add");
    assert!(report.complete(), "{report:?}");
    assert_eq!(report.issuer.status, AgentStatus::Active);
    let grant = report.issuer.grant.as_ref().expect("grant");
    assert!(grant.projects.is_empty() && grant.items.is_empty());
    assert_eq!(grant.v, GRANT_PAYLOAD_VERSION_SANDBOXES);
    let named = sandbox_of(&report.issuer)
        .and_then(|s| s.proxy)
        .expect("names the proxy");
    assert_eq!(named.agent_id, proxy.id());
    assert_eq!(named.url, URL);

    // The proxy's grant lists it, and the proxy can still open it.
    let agents = ana.agents().await.expect("agents");
    let held = agents
        .iter()
        .find(|a| a.id == proxy.id())
        .and_then(|a| a.grant.as_ref())
        .expect("proxy grant");
    assert_eq!(held.issuers.len(), 1);
    assert_eq!(held.issuers[0].agent_id, t3.id());
    assert_eq!(held.issuers[0].profiles, vec!["northflank".to_owned()]);
    let session = Session::open(proxy)
        .await
        .expect("the proxy opens its v3 grant");
    assert_eq!(session.grant().payload.issuers.len(), 1);
    let issuer_session = Session::open(t3).await.expect("the issuer opens its grant");
    assert!(issuer_session.grant().payload.sandbox.is_some());

    // The same again changes nothing.
    let err = ana
        .prepare_issuer_add("t3-code", &issuer(&["northflank"]), PairingCheck::InPrompt)
        .await
        .err()
        .expect("nothing to change");
    assert!(err.to_string().contains("already an issuer"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_issuer_with_projects_keeps_them_and_the_field_survives_approvals_and_rotations() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _proxy) = with_proxy(&server, &dir).await;
    let t3 = register(&server, &dir, "t3-code").await;
    let projects = GrantRequest {
        projects: vec!["Personal/General".into()],
        vaults: Vec::new(),
        policy: Policy::default(),
    };
    ana.approve_agent(t3.id(), projects.clone(), &t3.pairing_code())
        .await
        .expect("approve");

    // `inject` is allowed by default: the warning, and `--inject-ask`.
    let view = ana
        .preview_issuer_add("t3-code", &issuer(&["northflank"]))
        .await
        .expect("preview");
    assert!(!view.pending && view.inject_allowed);
    assert!(view.warnings.iter().any(|w| w.contains("--inject-ask")));
    let spec = IssuerSpec {
        inject_ask: true,
        ..issuer(&["northflank"])
    };
    let prepared = ana
        .prepare_issuer_add("t3-code", &spec, PairingCheck::InPrompt)
        .await
        .expect("prepare");
    prepared.require_updated_devices(true).expect("ack");
    let report = ana.commit_issuer_change(prepared).await.expect("add");
    assert!(report.complete(), "{report:?}");
    let grant = report.issuer.grant.as_ref().expect("grant");
    assert_eq!(grant.projects.len(), 1);
    assert!(
        grant
            .policy
            .rules
            .iter()
            .any(|r| r.permission == Permission::Inject && r.effect == Effect::Ask)
    );

    // The apps leave an issuer's grant to the CLI, and klavd refuses the
    // editor's model on it too: it would sign a copy without `sandbox`
    // (F3, R2-6b).
    let editor = ana.grant_editor(t3.id()).await.expect("editor");
    assert!(!editor.editable);
    assert_eq!(
        editor.reason,
        Some(klav_client::grant_change::ReadOnlyReason::Issuer)
    );
    let simpler = ana
        .prepare_grant_change(
            t3.id(),
            &klav_client::grant_change::GrantChange {
                projects: vec!["Personal/General".into()],
                vaults: Vec::new(),
                policy: klav_client::grant_change::ChangePolicy::Editor(
                    klav_client::grant_change::EditorPolicy::default(),
                ),
                rotate_removed: false,
            },
        )
        .await
        .expect_err("issuer");
    assert!(
        matches!(&simpler, ClientError::Invalid(m) if m.contains("the editor does not change it")),
        "{simpler}"
    );

    // Approving it again with projects keeps `sandbox`, but signs the
    // policy it is given: the `inject: ask` goes, and the approval says so.
    let prepared = ana
        .prepare_grant(t3.id(), projects.clone(), &t3.pairing_code())
        .await
        .expect("prepare approve");
    assert!(
        prepared
            .warnings()
            .iter()
            .any(|w| w.contains("starts sandboxes") && w.contains("--ask inject")),
        "{:?}",
        prepared.warnings()
    );
    let view = ana.grant_prepared(prepared).await.expect("approve again");
    assert!(sandbox_of(&view).is_some());
    let policy = &view.grant.as_ref().expect("grant").policy;
    assert!(
        !policy
            .rules
            .iter()
            .any(|r| r.permission == Permission::Inject && r.effect == Effect::Ask),
        "an approval replaces the policy"
    );
    // Given `--ask inject`, it keeps asking, and nothing is said.
    let asking = GrantRequest {
        policy: Policy {
            rules: vec![klav_core::policy::Rule::new(
                Permission::Inject,
                Effect::Ask,
            )],
            expires_at: None,
        },
        ..projects.clone()
    };
    let prepared = ana
        .prepare_grant(t3.id(), asking, &t3.pairing_code())
        .await
        .expect("prepare approve");
    assert!(
        prepared
            .warnings()
            .iter()
            .all(|w| !w.contains("starts sandboxes")),
        "{:?}",
        prepared.warnings()
    );
    // So does the re-grant after a rotation of the project it holds.
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
    .expect("approve bot");
    let revoked = ana
        .revoke_agent(bot.id(), true)
        .await
        .expect("revoke --rotate");
    assert!(revoked.complete(), "{:?}", revoked.not_regranted);
    assert!(
        revoked.regranted.iter().any(|n| n == "t3-code"),
        "{:?}",
        revoked.regranted
    );
    let t3_view = ana.agent("t3-code").await.expect("agent");
    assert!(sandbox_of(&t3_view).and_then(|s| s.proxy).is_some());

    // Removing it: the proxy's grant first, then its own (it has projects).
    let prepared = ana.prepare_issuer_remove("t3-code").await.expect("remove");
    let report = ana.commit_issuer_change(prepared).await.expect("remove");
    assert!(report.complete(), "{report:?}");
    assert!(sandbox_of(&report.issuer).is_none());
    assert_eq!(
        report.issuer.grant.as_ref().map(|g| g.projects.len()),
        Some(1)
    );
    let proxy_grant = ana
        .agent("klav-proxy")
        .await
        .expect("proxy")
        .grant
        .expect("grant");
    assert!(proxy_grant.issuers.is_empty());
    assert!(matches!(
        ana.prepare_issuer_remove("t3-code").await,
        Err(ClientError::NotFound(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_issuer_never_holds_credentials_and_only_gets_the_proxys_profiles() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _proxy) = with_proxy(&server, &dir).await;
    register(&server, &dir, "t3-code").await;
    for (spec, why) in [
        (issuer(&["maple"]), "no profile"),
        (issuer(&[]), "at least one"),
        (
            IssuerSpec {
                url: "https://proxy.example.com".into(),
                ..issuer(&["northflank"])
            },
            "tls://",
        ),
        (
            IssuerSpec {
                max_ttl_secs: Some(25 * 3600),
                ..issuer(&["northflank"])
            },
            "--max-ttl",
        ),
        (
            IssuerSpec {
                max_live: Some(0),
                ..issuer(&["northflank"])
            },
            "--max-live",
        ),
    ] {
        let err = ana
            .prepare_issuer_add("t3-code", &spec, PairingCheck::InPrompt)
            .await
            .err()
            .expect(why);
        assert!(err.to_string().contains(why), "{why}: {err}");
    }
    let err = ana
        .prepare_issuer_add(
            "klav-proxy",
            &issuer(&["northflank"]),
            PairingCheck::InPrompt,
        )
        .await
        .err()
        .expect("the proxy itself");
    assert!(err.to_string().contains("is the credential proxy"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn using_no_proxy_leaves_the_issuer_with_none() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy) = with_proxy(&server, &dir).await;
    register(&server, &dir, "t3-code").await;
    let prepared = ana
        .prepare_issuer_add("t3-code", &issuer(&["northflank"]), PairingCheck::InPrompt)
        .await
        .expect("prepare");
    prepared.require_updated_devices(true).expect("ack");
    ana.commit_issuer_change(prepared).await.expect("add");

    // `use` is refused while the proxy holds credentials: revoke it first.
    ana.revoke_agent(proxy.id(), false)
        .await
        .expect("revoke proxy");
    let prepared = ana.prepare_proxy_use(None).await.expect("use none");
    let resigned = ana.commit_proxy_use(prepared).await.expect("use none");
    assert_eq!(resigned.done, vec!["t3-code".to_owned()]);
    assert!(resigned.failed.is_empty());
    let t3 = ana.agent("t3-code").await.expect("agent");
    let sandbox = sandbox_of(&t3).expect("still an issuer");
    assert!(sandbox.proxy.is_none(), "names no proxy");
    // Again: nothing left to re-sign.
    let prepared = ana.prepare_proxy_use(None).await.expect("use none");
    assert!(
        ana.commit_proxy_use(prepared)
            .await
            .expect("again")
            .done
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_half_done_add_says_which_grant_changed_and_running_it_again_finishes() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy) = with_proxy(&server, &dir).await;
    let t3 = register(&server, &dir, "t3-code").await;
    let prepared = ana
        .prepare_issuer_add("t3-code", &issuer(&["northflank"]), PairingCheck::InPrompt)
        .await
        .expect("prepare");
    prepared.require_updated_devices(true).expect("ack");

    // The proxy's grant changes in between (another device grants it a
    // credential): the issuer's grant is signed first, the proxy's then
    // fails on its version.
    add(&mut ana, "Other").await;
    let other = ana
        .prepare_proxy_grant("Other", &credential("other"), PairingCheck::InPrompt)
        .await
        .expect("grant other");
    assert!(
        ana.commit_proxy_change(other)
            .await
            .expect("grant other")
            .complete()
    );
    let report = ana.commit_issuer_change(prepared).await.expect("add");
    assert!(!report.complete(), "{report:?}");
    assert!(report.issuer_done && !report.proxy_done, "{report:?}");
    assert!(report.failed.is_some());
    let proxy_view = |agents: &[klav_client::agents::AgentView]| {
        agents
            .iter()
            .find(|a| a.id == proxy.id())
            .and_then(|a| a.grant.clone())
            .expect("proxy grant")
    };
    assert!(
        proxy_view(&ana.agents().await.expect("agents"))
            .issuers
            .is_empty()
    );

    // Running it again finishes: the proxy lists it now.
    let prepared = ana
        .prepare_issuer_add("t3-code", &issuer(&["northflank"]), PairingCheck::InPrompt)
        .await
        .expect("prepare again");
    let report = ana.commit_issuer_change(prepared).await.expect("add again");
    assert!(report.complete(), "{report:?}");
    let held = proxy_view(&ana.agents().await.expect("agents"));
    assert_eq!(held.issuers.len(), 1);
    assert_eq!(held.issuers[0].agent_id, t3.id());

    // Removing the last issuer takes the proxy's grant back to version 2
    // (version 3 only carries issuers or a sandbox proxy); the issuer's
    // keeps `sandbox` with no proxy, so it stays 3.
    let prepared = ana.prepare_issuer_remove("t3-code").await.expect("remove");
    assert!(
        ana.commit_issuer_change(prepared)
            .await
            .expect("remove")
            .complete()
    );
    let agents = ana.agents().await.expect("agents");
    let held = proxy_view(&agents);
    assert!(held.issuers.is_empty());
    assert_eq!(held.v, klav_proto::agent::GRANT_PAYLOAD_VERSION_ITEMS);
    let issuer = agents.iter().find(|a| a.id == t3.id()).expect("issuer");
    let grant = issuer.grant.as_ref().expect("issuer grant");
    assert_eq!(grant.v, GRANT_PAYLOAD_VERSION_SANDBOXES);
    assert!(grant.sandbox.as_ref().is_some_and(|s| s.proxy.is_none()));
}

/// `klav proxy grant` on an item the proxy already holds replaces its
/// profile: under the same name the issuers keep it, under the new rules,
/// and the preview names them; under another name they lose it, and the
/// preview says so, as does taking the item away.
#[tokio::test(flavor = "multi_thread")]
async fn granting_an_item_again_keeps_the_issuers_profile_under_the_same_name() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy) = with_proxy(&server, &dir).await;
    add(&mut ana, "Maple").await;
    let prepared = ana
        .prepare_proxy_grant("Maple", &credential("maple"), PairingCheck::InPrompt)
        .await
        .expect("grant");
    assert!(
        ana.commit_proxy_change(prepared)
            .await
            .expect("grant")
            .complete()
    );
    register(&server, &dir, "t3-code").await;
    let prepared = ana
        .prepare_issuer_add(
            "t3-code",
            &issuer(&["northflank", "maple"]),
            PairingCheck::InPrompt,
        )
        .await
        .expect("prepare");
    prepared.require_updated_devices(true).expect("ack");
    assert!(
        ana.commit_issuer_change(prepared)
            .await
            .expect("add")
            .complete()
    );
    let issuers = |agents: &[klav_client::agents::AgentView]| {
        agents
            .iter()
            .find(|a| a.id == proxy.id())
            .and_then(|a| a.grant.as_ref())
            .map(|g| g.issuers.clone())
            .unwrap_or_default()
    };

    // Same name, new rules: nothing lost, and the issuer that keeps the
    // profile under the new rules is named before anything is signed. It
    // is said whether or not the rules changed.
    let mut spec = credential("northflank");
    spec.methods = vec!["GET".into(), "POST".into()];
    for same in [credential("northflank"), spec.clone()] {
        let prepared = ana
            .prepare_proxy_grant("Northflank", &same, PairingCheck::InPrompt)
            .await
            .expect("grant");
        assert!(prepared.view().replaces);
        assert!(prepared.view().issuers_losing.is_empty());
        assert_eq!(prepared.view().issuers_keeping, ["t3-code"]);
        assert_eq!(prepared.issuers_keeping(), 1, "counted in what is signed");
        assert!(
            prepared.view().warnings.iter().any(
                |w| w.starts_with("t3-code keeps the profile northflank, with the rules above")
            ),
            "{:?}",
            prepared.view().warnings
        );
    }
    let prepared = ana
        .prepare_proxy_grant("Northflank", &spec, PairingCheck::InPrompt)
        .await
        .expect("grant");
    assert!(
        ana.commit_proxy_change(prepared)
            .await
            .expect("grant")
            .complete()
    );
    let held = issuers(&ana.agents().await.expect("agents"));
    assert_eq!(held[0].profiles, ["northflank", "maple"]);

    // Another name: the issuer loses the old one, and is told.
    let prepared = ana
        .prepare_proxy_grant("Northflank", &credential("nf"), PairingCheck::InPrompt)
        .await
        .expect("grant");
    assert_eq!(prepared.view().issuers_losing, ["t3-code"]);
    assert!(prepared.view().issuers_keeping.is_empty());
    assert_eq!(prepared.issuers_keeping(), 0);
    assert!(
        prepared
            .view()
            .warnings
            .iter()
            .any(|w| w.contains("t3-code loses the profile northflank")),
        "{:?}",
        prepared.view().warnings
    );
    assert!(
        ana.commit_proxy_change(prepared)
            .await
            .expect("grant")
            .complete()
    );
    let held = issuers(&ana.agents().await.expect("agents"));
    assert_eq!(held[0].profiles, ["maple"]);

    // Taking its last profile's item away: it stops being an issuer.
    let prepared = ana.prepare_proxy_revoke("Maple").await.expect("revoke");
    assert_eq!(prepared.view().issuers_losing, ["t3-code"]);
    assert!(
        prepared
            .view()
            .warnings
            .iter()
            .any(|w| w.contains("t3-code stops being a sandbox issuer")),
        "{:?}",
        prepared.view().warnings
    );
    assert!(
        ana.commit_proxy_change(prepared)
            .await
            .expect("revoke")
            .complete()
    );
    assert!(issuers(&ana.agents().await.expect("agents")).is_empty());
}

/// Every agent made an issuer is warned about older Klav, not only the
/// account's first, and `inject` is warned about even without projects
/// yet: a later `klav agent approve` can add them, and signs the policy
/// that command is given, which by default allows `inject`.
#[tokio::test(flavor = "multi_thread")]
async fn every_new_issuer_is_warned_about_older_klav_and_inject() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _proxy) = with_proxy(&server, &dir).await;
    register(&server, &dir, "t3-code").await;
    register(&server, &dir, "ci").await;
    let view = ana
        .preview_issuer_add("t3-code", &issuer(&["northflank"]))
        .await
        .expect("preview");
    assert!(view.warnings.iter().any(|w| w == OLDER_CLIENTS_ISSUERS));
    assert!(view.inject_allowed);
    assert!(
        view.warnings
            .iter()
            .any(|w| w.contains("may `inject` without asking once it is approved")),
        "{:?}",
        view.warnings
    );
    let prepared = ana
        .prepare_issuer_add("t3-code", &issuer(&["northflank"]), PairingCheck::InPrompt)
        .await
        .expect("prepare");
    prepared.require_updated_devices(true).expect("ack");
    assert!(
        ana.commit_issuer_change(prepared)
            .await
            .expect("add")
            .complete()
    );

    let view = ana
        .preview_issuer_add("ci", &issuer(&["northflank"]))
        .await
        .expect("preview");
    assert!(!view.first_on_account);
    assert!(view.warnings.iter().all(|w| w != OLDER_CLIENTS_ISSUERS));
    assert!(
        view.warnings
            .iter()
            .any(|w| w.contains("\"ci\" gets a grant in a format a Klav older")),
        "{:?}",
        view.warnings
    );
    // With --inject-ask, no `inject` warning.
    let spec = IssuerSpec {
        inject_ask: true,
        ..issuer(&["northflank"])
    };
    let view = ana.preview_issuer_add("ci", &spec).await.expect("preview");
    assert!(view.warnings.iter().all(|w| !w.contains("inject` without")));
    // ...but it says the `ask` lasts only until the next approval.
    assert!(
        view.warnings
            .iter()
            .any(|w| w.contains("lasts until its next `klav agent approve`")),
        "{:?}",
        view.warnings
    );
}

/// The proxy's reports of a sandbox's life, written by the real server,
/// pass the person's `klav log verify` (spec §13.7): issued, claimed and
/// released, each with the body the proxy signed.
#[tokio::test(flavor = "multi_thread")]
async fn the_proxys_sandbox_events_pass_the_log_verifier() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy) = with_proxy(&server, &dir).await;
    let t3 = register(&server, &dir, "t3-code").await;
    let prepared = ana
        .prepare_issuer_add("t3-code", &issuer(&["northflank"]), PairingCheck::InPrompt)
        .await
        .expect("prepare");
    prepared.require_updated_devices(true).expect("ack");
    assert!(
        ana.commit_issuer_change(prepared)
            .await
            .expect("add")
            .complete()
    );

    let sandbox = klav_core::ids::SandboxId::generate();
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("time");
    let steps = [
        (
            klav_proto::sandbox::PATH_SANDBOXES.to_owned(),
            serde_json::json!({"sandbox_id": sandbox, "issuer_id": t3.id(), "label": "chat-123",
                "profiles": ["northflank"], "expires_at": now + 3_600_000}),
        ),
        (
            klav_proto::sandbox::sandbox_path(sandbox, klav_proto::sandbox::SUFFIX_CLAIMED),
            serde_json::json!({"channel_key_sha256": klav_proto::Blob::new(vec![7; 32])}),
        ),
        (
            klav_proto::sandbox::sandbox_path(sandbox, klav_proto::sandbox::SUFFIX_REVOKED),
            serde_json::json!({"reason": "released"}),
        ),
    ];
    for (path, body) in steps {
        let bytes = serde_json::to_vec(&body).expect("body");
        let res = proxy
            .send(reqwest::Method::POST, &path, Some(&bytes))
            .await
            .expect("send");
        assert_eq!(res.status(), reqwest::StatusCode::NO_CONTENT, "{path}");
    }
    let report = ana.verify_audit().await.expect("the chain verifies");
    assert!(
        report.warnings.iter().all(|w| !w.contains("sandbox")),
        "{:?}",
        report.warnings
    );
    let lines = ana
        .audit_log(&klav_client::audit::LogFilter::default())
        .await
        .expect("log");
    let mut actions: Vec<&str> = lines
        .iter()
        .filter(|l| l.action.starts_with("sandbox."))
        .map(|l| l.action.as_str())
        .collect();
    actions.reverse();
    assert_eq!(
        actions,
        ["sandbox.issued", "sandbox.claimed", "sandbox.revoked"]
    );
}

/// T190: when a rotation issues an issuer's grant again, everything it
/// signed stays as it was (projects, policy, `sandbox`, profiles, items);
/// only the version, the time and the keys change.
#[tokio::test(flavor = "multi_thread")]
async fn an_issuers_grant_comes_back_from_a_rotation_unchanged_but_for_version_time_and_keys() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _proxy) = with_proxy(&server, &dir).await;
    let general = GrantRequest {
        projects: vec!["Personal/General".into()],
        vaults: Vec::new(),
        policy: Policy::default(),
    };
    let t3 = register(&server, &dir, "t3-code").await;
    ana.approve_agent(t3.id(), general.clone(), &t3.pairing_code())
        .await
        .expect("approve");
    let spec = IssuerSpec {
        inject_ask: true,
        ..issuer(&["northflank"])
    };
    let prepared = ana
        .prepare_issuer_add("t3-code", &spec, PairingCheck::InPrompt)
        .await
        .expect("prepare");
    prepared.require_updated_devices(true).expect("ack");
    assert!(
        ana.commit_issuer_change(prepared)
            .await
            .expect("add")
            .complete()
    );
    let before = ana
        .agent("t3-code")
        .await
        .expect("agent")
        .grant
        .expect("grant");
    assert!(before.sandbox.is_some());

    let bot = register(&server, &dir, "bot").await;
    ana.approve_agent(bot.id(), general, &bot.pairing_code())
        .await
        .expect("approve bot");
    let revoked = ana.revoke_agent(bot.id(), true).await.expect("revoke");
    assert!(revoked.complete(), "{revoked:?}");
    assert!(revoked.regranted.iter().any(|n| n == "t3-code"));

    let after = ana
        .agent("t3-code")
        .await
        .expect("agent")
        .grant
        .expect("grant");
    assert!(after.version > before.version);
    let signed = |g: &klav_client::agents::GrantView| {
        let mut v = serde_json::to_value(g).expect("json");
        let map = v.as_object_mut().expect("object");
        map.remove("version");
        map.remove("issued_at");
        v
    };
    assert_eq!(signed(&after), signed(&before));
}
