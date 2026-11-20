//! Per-item grants from the person's client to the agent against a real
//! server (ADR 0036 §2, §18): the proxy opens only its items' keys,
//! revoking it changes those keys (attachments included) and re-issues the
//! grants of the other holders, and no path that re-issues a grant drops
//! its items or lowers its `v`.

#[path = "../../klav-client/tests/common/mod.rs"]
mod common;

use common::ServerProcess;
use klav_client::agents::GrantRequest;
use klav_client::item_grants::ItemGrantRequest;
use klav_client::{
    ClientError, Home, ItemLocation, LoginRequest, SignupRequest, Unlocked, login, signup,
};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::secret_key::SecretKey;
use klav_core::ids::ItemId;
use klav_core::model::item::{Item, ItemKind};
use klav_core::model::{SealedItem, open_item, seal_item};
use klav_core::policy::{
    DomainPattern, Effect, HttpMethod, PathPrefix, Permission, Policy, Rule, Scope,
};
use klav_proto::agent::{AccessGranted, AccessRequest, Claims, ProxyProfile};
use klav_sdk::{Agent, KeyStore, Registration, Session};
use reqwest::Method;
use secrecy::ExposeSecret;
use sqlx::AnyPool;
use sqlx::any::AnyPoolOptions;

const PASSWORD: &str = "correct horse battery staple";
const EMAIL: &str = "ana@example.com";
const RAILWAY: &str = "backboard.railway.app";

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

/// Runs `read` on the server database, read-only, with the server running:
/// the database is in WAL mode, so a reader in another process sees what
/// the server committed. No restart, so the clients' next request never
/// follows one.
async fn read_db<F, Fut, T>(server: &ServerProcess, read: F) -> T
where
    F: FnOnce(AnyPool) -> Fut,
    Fut: Future<Output = T>,
{
    sqlx::any::install_default_drivers();
    let url = format!(
        "sqlite://{}?mode=ro",
        server.dir.path().join("klav.db").display()
    );
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("open server db");
    let out = read(pool.clone()).await;
    pool.close().await;
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
            device_kind: klav_proto::auth::DeviceKind::Cli,
        },
    )
    .await
    .expect("sign-up");
    let secret = kit.secret_key().to_text().expose_secret().to_owned();
    (u, secret)
}

async fn register(server: &ServerProcess, dir: &tempfile::TempDir, name: &str) -> Agent {
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
    agent
}

async fn add(ana: &mut Unlocked, title: &str) -> ItemLocation {
    let vault = ana.find_vault("Personal").expect("vault");
    let project = ana.find_project(vault, "General").expect("project");
    let mut item = Item::from_template(ItemKind::Login, title).expect("item");
    item.field_mut("password")
        .expect("password")
        .set_value("token-of-the-provider")
        .expect("set");
    ana.add_item(vault, project, &item).await.expect("add item")
}

fn rule(permission: Permission, effect: Effect, scope: Scope) -> Rule {
    Rule {
        scope,
        ..Rule::new(permission, effect)
    }
}

fn proxy_policy(items: &[ItemId]) -> Policy {
    let mut rules: Vec<Rule> = items
        .iter()
        .map(|item| {
            rule(
                Permission::Proxy,
                Effect::Allow,
                Scope {
                    items: vec![*item],
                    domains: vec![DomainPattern::parse(RAILWAY).expect("host")],
                    methods: vec![HttpMethod::parse("POST").expect("method")],
                    path_prefixes: vec![PathPrefix::parse("/graphql").expect("prefix")],
                    ..Scope::default()
                },
            )
        })
        .collect();
    for p in [Permission::Reveal, Permission::Inject, Permission::Fill] {
        rules.push(rule(p, Effect::Deny, Scope::default()));
    }
    Policy {
        rules,
        expires_at: None,
    }
}

fn request(items: &[ItemLocation]) -> ItemGrantRequest {
    ItemGrantRequest {
        items: items.to_vec(),
        profiles: vec![ProxyProfile {
            name: "railway".into(),
            item_id: items[0].item,
            field: Some("password".into()),
            header: "authorization".into(),
            prefix: "Bearer ".into(),
            upstream: format!("https://{RAILWAY}"),
            rate_per_minute: Some(30),
        }],
        policy: proxy_policy(&items.iter().map(|l| l.item).collect::<Vec<_>>()),
        issuers: Vec::new(),
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
async fn revoking_a_proxy_changes_its_item_keys_and_regrants_the_other_holders() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, secret) = account(&server, &dir).await;
    let railway = add(&mut ana, "Railway").await;
    ana.attach(
        "Railway",
        "key",
        "key.p8",
        None,
        b"-----BEGIN PRIVATE KEY-----",
    )
    .await
    .expect("attach");
    let first = register(&server, &dir, "proxy-a").await;
    let second = register(&server, &dir, "proxy-b").await;
    let report = ana
        .grant_items(first.id(), request(&[railway]), &first.pairing_code())
        .await
        .expect("grant a");
    let grant = report.agent.grant.expect("grant");
    assert_eq!(grant.items.len(), 1);
    assert_eq!(grant.items[0].title, "Railway");
    assert!(grant.projects.is_empty());
    ana.grant_items(second.id(), request(&[railway]), &second.pairing_code())
        .await
        .expect("grant b");

    let a = Session::open(first).await.expect("session a");
    let mut b = Session::open(second).await.expect("session b");
    assert_eq!(a.grant().payload.v, 2);
    assert!(a.grant().keys.is_empty());
    let old = proxied(&a, railway.item).await.expect("a proxies");
    assert_eq!(old.title(), "Railway");
    proxied(&b, railway.item).await.expect("b proxies");

    // Revoking A changes the item's key even without a rotation, and B
    // gets a new grant with the new key and everything else as signed.
    let report = ana
        .revoke_agent(a.agent().id(), false)
        .await
        .expect("revoke");
    assert!(report.complete(), "{report:?}");
    assert_eq!(report.rekeyed, vec![railway.item]);
    assert_eq!(report.regranted, vec!["proxy-b".to_owned()]);
    assert!(proxied(&a, railway.item).await.is_err());

    let before = b.grant().payload.clone();
    // A section sealed with B's old key, to tell the keys apart.
    let held = &b.grant().items[&railway.item];
    let ctx = held.ctx;
    let probe = seal_item(&held.key, &ctx, 1, &old);
    b.refresh().await.expect("refresh");
    let after = &b.grant().payload;
    assert_eq!(after.v, 2);
    assert_eq!(after.version, before.version + 1);
    assert_eq!(after.items.len(), 1);
    assert_eq!(after.items[0].item_id, railway.item);
    assert_eq!(after.profiles, before.profiles);
    assert_eq!(after.policy, before.policy);
    let new = &b.grant().items[&railway.item];
    assert!(open_item(&new.key, &ctx, 1, &probe).is_err());
    let item = proxied(&b, railway.item)
        .await
        .expect("b proxies with the new key");
    assert_eq!(item.title(), "Railway");

    // Another device still opens the item and its attachment.
    let mut phone = login(
        &Home::at(dir.path().join("phone")),
        LoginRequest {
            server: server.url.clone(),
            email: EMAIL.into(),
            password: MasterPassword::new(PASSWORD),
            secret_key: SecretKey::parse(&secret).expect("secret key"),
            device_name: "phone".into(),
            device_kind: klav_proto::auth::DeviceKind::Cli,
        },
    )
    .await
    .expect("login");
    let loc = phone.find_item("Railway").expect("find");
    let item = phone.open_item(loc).expect("open");
    let file = item
        .attachments()
        .first()
        .map(|a| a.id)
        .expect("attachment");
    let content = phone
        .download_attachment(loc, file)
        .await
        .expect("download");
    assert_eq!(content.as_slice(), b"-----BEGIN PRIVATE KEY-----");
}

#[tokio::test(flavor = "multi_thread")]
async fn rotating_a_project_key_keeps_per_item_and_v2_grants_whole() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let railway = add(&mut ana, "Railway").await;
    let general = ["Personal/General".to_owned()];

    let proxy = register(&server, &dir, "proxy").await;
    ana.grant_items(proxy.id(), request(&[railway]), &proxy.pairing_code())
        .await
        .expect("grant proxy");
    // A project grant that is version 2 only because of its policy: a
    // `proxy` deny rule with a method.
    let keeper = register(&server, &dir, "keeper").await;
    let mut keeper_policy = Policy::default();
    keeper_policy.rules.push(rule(
        Permission::Proxy,
        Effect::Deny,
        Scope {
            methods: vec![HttpMethod::parse("DELETE").expect("method")],
            ..Scope::default()
        },
    ));
    let view = ana
        .approve_agent(
            keeper.id(),
            GrantRequest {
                projects: general.to_vec(),
                vaults: Vec::new(),
                policy: keeper_policy,
            },
            &keeper.pairing_code(),
        )
        .await
        .expect("approve keeper");
    assert_eq!(view.grant.expect("grant").version, 1);
    let bot = register(&server, &dir, "bot").await;
    ana.approve_agent(
        bot.id(),
        GrantRequest {
            projects: general.to_vec(),
            vaults: Vec::new(),
            policy: Policy::default(),
        },
        &bot.pairing_code(),
    )
    .await
    .expect("approve bot");

    let mut proxy = Session::open(proxy).await.expect("proxy session");
    let mut keeper = Session::open(keeper).await.expect("keeper session");
    assert_eq!(keeper.grant().payload.v, 2);
    let proxy_before = proxy.grant().payload.clone();

    // Revoking the bot with a rotation re-issues the keeper's grant with
    // the new project key, still version 2; the proxy holds no project
    // and its grant stays whole, items, profiles and all.
    let report = ana.revoke_agent(bot.id(), true).await.expect("revoke");
    assert!(report.complete(), "{report:?}");
    assert_eq!(report.rotated.len(), 1);
    assert_eq!(report.regranted, vec!["keeper".to_owned()]);
    assert!(report.rekeyed.is_empty());

    keeper.refresh().await.expect("refresh keeper");
    assert_eq!(keeper.grant().payload.v, 2);
    assert_eq!(keeper.grant().payload.version, 2);
    proxy.refresh().await.expect("refresh proxy");
    let proxy_after = &proxy.grant().payload;
    assert_eq!(proxy_after, &proxy_before);
    assert_eq!(proxy_after.v, 2);
    assert_eq!(proxy_after.items[0].item_id, railway.item);
    // Item keys do not change with the project's: the proxy still works.
    proxied(&proxy, railway.item)
        .await
        .expect("the proxy still proxies");
}

#[tokio::test(flavor = "multi_thread")]
async fn grants_are_never_rewritten_into_the_other_kind() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let railway = add(&mut ana, "Railway").await;
    let other = add(&mut ana, "Other").await;
    let proxy = register(&server, &dir, "proxy").await;
    ana.grant_items(
        proxy.id(),
        request(&[railway, other]),
        &proxy.pairing_code(),
    )
    .await
    .expect("grant");

    // A project grant over a per-item one would drop its items: refused.
    let err = ana
        .approve_agent(
            proxy.id(),
            GrantRequest {
                projects: vec!["Personal/General".into()],
                vaults: Vec::new(),
                policy: Policy::default(),
            },
            &proxy.pairing_code(),
        )
        .await
        .expect_err("project grant over items");
    assert!(err.to_string().contains("per-item"), "{err}");

    // Narrowing the per-item grant changes the key of the item it drops.
    let report = ana
        .grant_items(proxy.id(), request(&[railway]), &proxy.pairing_code())
        .await
        .expect("narrow");
    assert_eq!(report.rekeyed, vec![other.item]);
    assert!(report.failed.is_none(), "{report:?}");
    let grant = report.agent.grant.expect("grant");
    assert_eq!(grant.version, 2);
    assert_eq!(grant.items.len(), 1);

    // And an agent with projects is not turned into a per-item one.
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
    let err = ana
        .grant_items(bot.id(), request(&[railway]), &bot.pairing_code())
        .await
        .expect_err("items over projects");
    assert!(err.to_string().contains("whole projects"), "{err}");

    // A policy that would let a value out is refused before signing.
    let mut bad = request(&[railway]);
    bad.policy
        .rules
        .retain(|r| r.permission != Permission::Fill);
    assert!(
        ana.grant_items(proxy.id(), bad, &proxy.pairing_code())
            .await
            .is_err()
    );
}

/// Narrowing a per-item grant gives the items it drops their new keys
/// **before** the new grant is uploaded. If that fails, nothing is
/// uploaded: the agent keeps its old grant (whose dropped items it can no
/// longer open once their keys change) and running it again finishes.
#[tokio::test(flavor = "multi_thread")]
async fn a_narrowed_grant_is_uploaded_only_after_the_dropped_keys_change() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let railway = add(&mut ana, "Railway").await;
    let spare = add(&mut ana, "Spare").await;
    let proxy = register(&server, &dir, "proxy").await;
    let code = proxy.pairing_code();
    ana.grant_items(proxy.id(), request(&[railway, spare]), &code)
        .await
        .expect("grant");
    let mut session = Session::open(proxy).await.expect("session");

    // An upload in progress on the item to drop: the server refuses its
    // new key (409), so the key change fails.
    let upload = klav_core::ids::AttachmentId::generate();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64;
    with_db(&mut server, |pool| async move {
        sqlx::query(
            "INSERT INTO attachments (id, vault_id, item_id, size, received, wrapped_key, \
             revision, created_at, updated_at) VALUES ($1, $2, $3, 64, 0, $4, 0, $5, $5)",
        )
        .bind(upload.to_string())
        .bind(spare.vault.to_string())
        .bind(spare.item.to_string())
        .bind(vec![0u8; 8])
        .bind(now)
        .execute(&pool)
        .await
        .expect("upload in progress");
    })
    .await;
    let report = ana
        .grant_items(session.agent().id(), request(&[railway]), &code)
        .await
        .expect("report");
    assert!(!report.granted, "{report:?}");
    assert!(report.failed.is_some());
    assert_eq!(report.pending, vec![spare.item]);
    session.refresh().await.expect("refresh");
    assert_eq!(session.grant().payload.version, 1, "nothing uploaded");
    assert!(session.grant().items.contains_key(&spare.item));

    // The upload goes away; running it again finishes.
    with_db(&mut server, |pool| async move {
        sqlx::query("DELETE FROM attachments WHERE id = $1")
            .bind(upload.to_string())
            .execute(&pool)
            .await
            .expect("drop the upload");
    })
    .await;
    let report = ana
        .grant_items(session.agent().id(), request(&[railway]), &code)
        .await
        .expect("again");
    assert!(report.granted && report.failed.is_none(), "{report:?}");
    assert_eq!(report.rekeyed, vec![spare.item]);
    session.refresh().await.expect("refresh");
    assert_eq!(session.grant().payload.version, 2);
    assert!(!session.grant().items.contains_key(&spare.item));
}

/// Revoking changes the key of an item in the trash too (it stays in the
/// trash), and the other holder keeps it in its re-issued grant with the
/// new key: nothing is left pending because of the trash.
#[tokio::test(flavor = "multi_thread")]
async fn revoking_changes_the_key_of_an_item_in_the_trash() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let railway = add(&mut ana, "Railway").await;
    let spare = add(&mut ana, "Spare").await;
    let first = register(&server, &dir, "proxy-a").await;
    let second = register(&server, &dir, "proxy-b").await;
    ana.grant_items(
        first.id(),
        request(&[railway, spare]),
        &first.pairing_code(),
    )
    .await
    .expect("grant a");
    ana.grant_items(
        second.id(),
        request(&[railway, spare]),
        &second.pairing_code(),
    )
    .await
    .expect("grant b");
    let a = Session::open(first).await.expect("a");
    let mut b = Session::open(second).await.expect("b");
    let held = &b.grant().items[&spare.item];
    let ctx = held.ctx;
    let plain = ana.open_item(spare).expect("open");
    let probe = seal_item(&held.key, &ctx, 1, &plain);
    ana.trash_item(spare).await.expect("trash");

    let report = ana
        .revoke_agent(a.agent().id(), false)
        .await
        .expect("revoke");
    assert!(report.complete(), "{report:?}");
    let mut rekeyed = report.rekeyed.clone();
    rekeyed.sort();
    let mut both = vec![railway.item, spare.item];
    both.sort();
    assert_eq!(rekeyed, both);
    assert!(report.items_pending.is_empty());
    assert_eq!(report.regranted, vec!["proxy-b".to_owned()]);
    // Still in the trash (not found by title), and this device opens it
    // with its new key.
    assert!(ana.find_item("Spare").is_err());
    assert_eq!(ana.open_item(spare).expect("opens").title(), "Spare");

    b.refresh().await.expect("refresh");
    let new = &b.grant().items[&spare.item];
    assert!(open_item(&new.key, &ctx, 1, &probe).is_err(), "a new key");
}

/// One holder whose grant cannot be re-issued does not stop the others,
/// and the report says which got a new grant and which did not.
#[tokio::test(flavor = "multi_thread")]
async fn one_failed_regrant_does_not_stop_the_others() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let railway = add(&mut ana, "Railway").await;
    let mut agents = Vec::new();
    for name in ["proxy-a", "proxy-b", "proxy-c"] {
        let agent = register(&server, &dir, name).await;
        ana.grant_items(agent.id(), request(&[railway]), &agent.pairing_code())
            .await
            .expect("grant");
        agents.push(agent);
    }
    // B's stored grant no longer matches its signature: it cannot be
    // opened, so it cannot be re-issued.
    let broken = agents[1].id();
    with_db(&mut server, |pool| async move {
        sqlx::query("UPDATE agents SET grant_signature = $1 WHERE id = $2")
            .bind(vec![0u8; 64])
            .bind(broken.to_string())
            .execute(&pool)
            .await
            .expect("break b");
    })
    .await;
    let report = ana
        .revoke_agent(agents[0].id(), false)
        .await
        .expect("revoke");
    assert_eq!(report.rekeyed, vec![railway.item]);
    assert_eq!(report.regranted, vec!["proxy-c".to_owned()]);
    assert_eq!(report.not_regranted.len(), 1, "{report:?}");
    assert!(
        report.not_regranted[0].starts_with("proxy-b:"),
        "{report:?}"
    );
    assert!(report.failed.is_some() && !report.complete());
}

/// A narrowed grant that cannot be built (a wanted item it did not hold is
/// in the trash) fails before anything changes: the dropped items keep
/// their keys, and no grant is touched. An item it already held keeps its
/// place in the trash instead (layer 4): that one is not the failure.
#[tokio::test(flavor = "multi_thread")]
async fn a_grant_that_cannot_be_built_changes_no_key() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let railway = add(&mut ana, "Railway").await;
    let spare = add(&mut ana, "Spare").await;
    let proxy = register(&server, &dir, "proxy").await;
    let other = register(&server, &dir, "proxy-b").await;
    let code = proxy.pairing_code();
    ana.grant_items(proxy.id(), request(&[railway, spare]), &code)
        .await
        .expect("grant");
    ana.grant_items(other.id(), request(&[spare]), &other.pairing_code())
        .await
        .expect("grant b");
    let mut session = Session::open(proxy).await.expect("session");
    let mut b = Session::open(other).await.expect("b");
    proxied(&b, spare.item).await.expect("b proxies");
    let fresh = add(&mut ana, "Fresh").await;
    ana.trash_item(fresh).await.expect("trash");

    let err = ana
        .grant_items(session.agent().id(), request(&[fresh]), &code)
        .await
        .expect_err("an item in the trash is not granted");
    assert!(matches!(err, ClientError::Invalid(_)), "{err}");
    session.refresh().await.expect("refresh");
    assert_eq!(session.grant().payload.version, 1);
    b.refresh().await.expect("refresh b");
    assert_eq!(b.grant().payload.version, 1, "nothing to re-issue");
    // The item as the server has it now still opens with B's key: it
    // never got a new one.
    proxied(&b, spare.item)
        .await
        .expect("the dropped item kept its key");
}

/// When the new grant's upload fails after the dropped items got new keys,
/// the other holders still get theirs and a report comes back.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_upload_still_regrants_the_other_holders() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let railway = add(&mut ana, "Railway").await;
    let spare = add(&mut ana, "Spare").await;
    let proxy = register(&server, &dir, "proxy").await;
    let other = register(&server, &dir, "proxy-b").await;
    let code = proxy.pairing_code();
    ana.grant_items(proxy.id(), request(&[railway, spare]), &code)
        .await
        .expect("grant");
    ana.grant_items(other.id(), request(&[spare]), &other.pairing_code())
        .await
        .expect("grant b");
    let mut session = Session::open(proxy).await.expect("session");
    let mut b = Session::open(other).await.expect("b");
    let held = &b.grant().items[&spare.item];
    let ctx = held.ctx;
    let probe = seal_item(&held.key, &ctx, 1, &ana.open_item(spare).expect("open"));

    // The server fails to store this agent's next grant (and only its).
    let failing = session.agent().id();
    with_db(&mut server, |pool| async move {
        // The agent ID is a UUID this test generated: nothing to escape.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE TRIGGER fail_grant BEFORE UPDATE OF grant_payload ON agents \
             WHEN OLD.id = '{failing}' BEGIN SELECT RAISE(ABORT, 'test: the upload fails'); END"
        )))
        .execute(&pool)
        .await
        .expect("trigger");
    })
    .await;
    let report = ana
        .grant_items(failing, request(&[railway]), &code)
        .await
        .expect("a report, not an error");
    assert!(!report.granted, "{report:?}");
    assert!(
        report
            .failed
            .as_deref()
            .is_some_and(|f| f.starts_with("uploading the new grant")),
        "{report:?}"
    );
    assert_eq!(report.rekeyed, vec![spare.item]);
    assert_eq!(report.regranted, vec!["proxy-b".to_owned()]);
    session.refresh().await.expect("refresh");
    assert_eq!(session.grant().payload.version, 1, "its old grant stays");
    b.refresh().await.expect("refresh b");
    assert_eq!(b.grant().payload.version, 2);
    let new = &b.grant().items[&spare.item];
    assert!(open_item(&new.key, &ctx, 1, &probe).is_err(), "a new key");
}

/// Sets the vault's `deleted_at` without a new revision: the server refuses
/// its writes, and a sync does not tell this device (a write refused for a
/// reason the sync cannot see).
async fn refuse_writes(server: &mut ServerProcess, vault: klav_core::ids::VaultId, on: bool) {
    let deleted: Option<i64> = on.then(|| {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_millis(),
        )
        .expect("ms")
    });
    with_db(server, |pool| async move {
        sqlx::query("UPDATE vaults SET deleted_at = $1 WHERE id = $2")
            .bind(deleted)
            .bind(vault.to_string())
            .execute(&pool)
            .await
            .expect("vault");
    })
    .await;
}

/// Sets whether the server lists the vault for the account, as a vault
/// purged or shared and taken back.
async fn listed(server: &mut ServerProcess, vault: klav_core::ids::VaultId, on: bool) {
    with_db(server, |pool| async move {
        sqlx::query("UPDATE vault_members SET revoked_at = $1 WHERE vault_id = $2")
            .bind((!on).then_some(1_i64))
            .bind(vault.to_string())
            .execute(&pool)
            .await
            .expect("membership");
        sqlx::query(
            "UPDATE vaults SET revision = revision + 1, meta_revision = revision + 1 WHERE id = $1",
        )
        .bind(vault.to_string())
        .execute(&pool)
        .await
        .expect("revision");
    })
    .await;
}

/// An item whose key could not change when its agent was revoked without
/// the projects' key change is written down: a restart still shows it, a
/// later step finishes it, and no project's key changes (P7).
#[tokio::test(flavor = "multi_thread")]
async fn an_item_left_by_a_revocation_without_the_key_change_survives_a_restart() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let railway = add(&mut ana, "Railway").await;
    let proxy = register(&server, &dir, "proxy").await;
    ana.grant_items(proxy.id(), request(&[railway]), &proxy.pairing_code())
        .await
        .expect("grant");
    let before = project_version(&server, railway.project).await;

    refuse_writes(&mut server, railway.vault, true).await;
    let report = ana.revoke_agent(proxy.id(), false).await.expect("revoke");
    assert_eq!(report.items_pending, vec![railway.item], "{report:?}");
    assert!(report.skipped.is_empty(), "{report:?}");
    assert!(!report.complete());

    // A restart reads it back; `klavd` resumes it at unlock.
    let home = ana.home().clone();
    drop(ana);
    let mut ana =
        klav_client::unlock_with_password(&home, &MasterPassword::new(PASSWORD)).expect("unlock");
    let left = ana.pending_revocations().expect("record");
    assert_eq!(left.len(), 1, "{left:?}");
    assert_eq!(left[0].items, 1, "{left:?}");
    assert!(
        left[0].pending.is_empty() && left[0].needs_work(),
        "{left:?}"
    );

    refuse_writes(&mut server, railway.vault, false).await;
    let mut rekeyed = Vec::new();
    loop {
        let step = ana.rotation_step(proxy.id()).await.expect("step");
        assert!(step.failed.is_none(), "{step:?}");
        assert!(step.rotated.is_none(), "no project's key: {step:?}");
        rekeyed.extend(step.rekeyed);
        if step.done {
            break;
        }
    }
    assert_eq!(rekeyed, vec![railway.item]);
    assert!(ana.pending_revocations().expect("record").is_empty());
    assert_eq!(project_version(&server, railway.project).await, before);
}

/// An item whose vault the server no longer lists cannot get a new key
/// from here: it is skipped, said, and never blocks the rest; when the
/// vault comes back it is pending again.
#[tokio::test(flavor = "multi_thread")]
async fn an_item_in_a_vault_no_longer_listed_is_skipped_until_it_comes_back() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let railway = add(&mut ana, "Railway").await;
    let proxy = register(&server, &dir, "proxy").await;
    ana.grant_items(proxy.id(), request(&[railway]), &proxy.pairing_code())
        .await
        .expect("grant");

    listed(&mut server, railway.vault, false).await;
    ana.sync().await.expect("sync");
    let report = ana.revoke_agent(proxy.id(), false).await.expect("revoke");
    assert!(report.complete(), "{report:?}");
    assert!(report.items_pending.is_empty(), "{report:?}");
    assert!(
        report
            .skipped
            .iter()
            .any(|s| s.contains(&railway.item.to_string())
                && s.contains("no longer lists its vault")),
        "{report:?}"
    );
    let step = ana.rotation_step(proxy.id()).await.expect("step");
    assert!(step.done && step.failed.is_none(), "{step:?}");
    let left = ana.pending_revocations().expect("record");
    assert_eq!(left.len(), 1, "{left:?}");
    assert!(left[0].items == 0 && !left[0].needs_work(), "{left:?}");
    assert_eq!(left[0].skipped.len(), 1, "{left:?}");

    listed(&mut server, railway.vault, true).await;
    ana.sync().await.expect("sync");
    let left = ana.pending_revocations().expect("record");
    assert!(left[0].items == 1 && left[0].needs_work(), "{left:?}");
    let mut rekeyed = Vec::new();
    loop {
        let step = ana.rotation_step(proxy.id()).await.expect("step");
        assert!(step.failed.is_none(), "{step:?}");
        rekeyed.extend(step.rekeyed);
        if step.done {
            break;
        }
    }
    assert_eq!(rekeyed, vec![railway.item]);
    assert!(ana.pending_revocations().expect("record").is_empty());
}

async fn project_version(server: &ServerProcess, project: klav_core::ids::ProjectId) -> i64 {
    read_db(server, |pool| async move {
        sqlx::query_scalar("SELECT version FROM projects WHERE id = $1")
            .bind(project.to_string())
            .fetch_one(&pool)
            .await
            .expect("version")
    })
    .await
}

/// The stored grant of agent `id` (payload, signature, version).
async fn grant_row(
    server: &ServerProcess,
    id: klav_core::ids::AgentId,
) -> (Option<Vec<u8>>, Option<Vec<u8>>, i64) {
    read_db(server, |pool| async move {
        let row: (Option<Vec<u8>>, Option<Vec<u8>>, i64) = sqlx::query_as(
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

/// Makes the server serve `row` as agent `id`'s grant: an older one it
/// kept, or none at all.
async fn serve_grant(
    server: &mut ServerProcess,
    id: klav_core::ids::AgentId,
    row: (Option<Vec<u8>>, Option<Vec<u8>>, i64),
) {
    with_db(server, |pool| async move {
        sqlx::query(
            "UPDATE agents SET grant_payload = $1, grant_signature = $2, grant_version = $3 WHERE id = $4",
        )
        .bind(row.0)
        .bind(row.1)
        .bind(row.2)
        .bind(id.to_string())
        .execute(&pool)
        .await
        .expect("serve grant");
    })
    .await;
}

/// A proxy granted item A, then A and B. Returns the session-less agent
/// ID, both items, and the first grant's stored row.
async fn proxy_with_two_grants(
    server: &mut ServerProcess,
    dir: &tempfile::TempDir,
    ana: &mut Unlocked,
) -> (
    klav_core::ids::AgentId,
    ItemLocation,
    ItemLocation,
    (Option<Vec<u8>>, Option<Vec<u8>>, i64),
) {
    let a = add(ana, "Railway").await;
    let b = add(ana, "Spare").await;
    let proxy = register(server, dir, "proxy").await;
    let code = proxy.pairing_code();
    ana.grant_items(proxy.id(), request(&[a]), &code)
        .await
        .expect("grant A");
    let first = grant_row(server, proxy.id()).await;
    ana.grant_items(proxy.id(), request(&[a, b]), &code)
        .await
        .expect("grant A and B");
    (proxy.id(), a, b, first)
}

/// A server that serves the older grant of A alone cannot keep B, which
/// this device also granted, from getting a new key (T189 for items).
#[tokio::test(flavor = "multi_thread")]
async fn an_older_item_grant_served_again_leaves_no_item_out_of_the_revocation() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let (id, a, b, first) = proxy_with_two_grants(&mut server, &dir, &mut ana).await;
    serve_grant(&mut server, id, first).await;
    let served = ana.agent("proxy").await.expect("agent");
    assert_eq!(served.grant.as_ref().map(|g| g.items.len()), Some(1));

    let report = ana.revoke_agent(id, false).await.expect("revoke");
    assert!(report.complete(), "{report:?}");
    let mut rekeyed = report.rekeyed.clone();
    rekeyed.sort();
    let mut both = vec![a.item, b.item];
    both.sort();
    assert_eq!(rekeyed, both, "{report:?}");
}

/// A server that serves no grant at all for the proxy still sees both
/// items' keys changed: this device wrote them down when it signed.
#[tokio::test(flavor = "multi_thread")]
async fn a_hidden_item_grant_still_gets_every_signed_item_a_new_key() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let (id, a, b, _) = proxy_with_two_grants(&mut server, &dir, &mut ana).await;
    serve_grant(&mut server, id, (None, None, 0)).await;
    let served = ana.agent("proxy").await.expect("agent");
    assert!(served.grant.is_none(), "{served:?}");

    let report = ana.revoke_agent(id, false).await.expect("revoke");
    assert!(report.complete(), "{report:?}");
    let mut rekeyed = report.rekeyed.clone();
    rekeyed.sort();
    let mut both = vec![a.item, b.item];
    both.sort();
    assert_eq!(rekeyed, both, "{report:?}");
}

/// Writes `json` as this device's `revocations.bin`, sealed with its local
/// key: a record from a newer Klav, say.
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

/// The sealed record as JSON (`revocations.bin`), entries `pending_revocations`
/// hides included.
fn read_record(ana: &Unlocked) -> serde_json::Value {
    // No file: no entry left (the last one removes it).
    let Ok(blob) = std::fs::read(ana.home().file(klav_client::revoke::REVOCATIONS_FILE)) else {
        return serde_json::json!({ "agents": {} });
    };
    let json = klav_core::crypto::local::open_local_data(
        ana.local_key(),
        &ana.account().local_context(),
        "revocations",
        &blob,
    )
    .expect("open");
    serde_json::from_slice(&json).expect("json")
}

/// Revoking without the key change over a record that does not open
/// (newer, or corrupt) still revokes, and is never complete: the record
/// may name items the server no longer serves (third re-check, F1).
#[tokio::test(flavor = "multi_thread")]
async fn a_revocation_over_a_record_that_does_not_open_is_never_complete() {
    for newer in [true, false] {
        let mut server = ServerProcess::start(900);
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut ana, _) = account(&server, &dir).await;
        let (id, _, _, first) = proxy_with_two_grants(&mut server, &dir, &mut ana).await;
        serve_grant(&mut server, id, first).await;
        let path = ana.home().file(klav_client::revoke::REVOCATIONS_FILE);
        if newer {
            write_record(&ana, r#"{"v":2,"agents":{},"later":true}"#);
        } else {
            std::fs::write(&path, b"not a sealed record").expect("garbage");
        }
        let before = std::fs::read(&path).expect("read");

        let report = ana.revoke_agent(id, false).await.expect("revoke");
        assert!(!report.complete(), "newer {newer}: {report:?}");
        let failed = report.failed.clone().expect("said");
        assert!(failed.contains("revocations.bin"), "{failed}");
        if newer {
            assert!(failed.contains("newer version of Klav"), "{failed}");
        }
        let agent = ana.agent("proxy").await.expect("agent");
        assert_eq!(
            agent.status,
            klav_proto::agent::AgentStatus::Revoked,
            "{agent:?}"
        );
        assert_eq!(std::fs::read(&path).expect("read"), before);
    }
}

/// Purges item `b` on the server, as a purge after its deletion leaves it.
async fn purge(server: &mut ServerProcess, b: ItemLocation) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64;
    with_db(server, |pool| async move {
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
}

/// A signed item this device no longer sees (the server sent it as purged)
/// has no key to change here: the revocation says so, never "every key
/// changed" (third re-check, F2).
#[tokio::test(flavor = "multi_thread")]
async fn a_signed_item_this_device_no_longer_sees_is_said_skipped() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let (id, a, b, _) = proxy_with_two_grants(&mut server, &dir, &mut ana).await;
    purge(&mut server, b).await;
    ana.sync().await.expect("sync");

    let report = ana.revoke_agent(id, false).await.expect("revoke");
    assert_eq!(report.rekeyed, vec![a.item], "{report:?}");
    let said = format!("item {}: this device no longer sees it", b.item);
    assert!(
        report.skipped.iter().any(|s| s.starts_with(&said)),
        "{report:?}"
    );
    assert!(
        report.complete(),
        "out of reach is not left to do: {report:?}"
    );
    // Written down, so it changes if it comes back (fifth re-check, 2).
    let pending = ana.pending_revocations().expect("record");
    let left = pending.iter().find(|p| p.agent_id == id).expect("kept");
    assert!(left.without_key_change && !left.needs_work(), "{left:?}");
    assert_eq!(left.skipped.len(), 1, "{left:?}");
}

/// A revocation without the key change whose item goes out of reach
/// before `klavd`'s next step: the step says so, keeps the item written
/// down so it changes if it comes back, and never reads as a key change
/// (fifth re-check, 1, 2 and 6).
#[tokio::test(flavor = "multi_thread")]
async fn a_step_says_an_item_this_device_no_longer_sees_and_keeps_it() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = account(&server, &dir).await;
    let (id, a, b, _) = proxy_with_two_grants(&mut server, &dir, &mut ana).await;
    // Revoked without the key change, both items' keys still owed. Written
    // directly: here `revoke_first` changes both keys at once, and this
    // test needs them owed, as a first call that stopped partway leaves
    // them. `b` is then purged for real.
    ana.revoke_first(id, false).await.expect("revoke");
    write_record(
        &ana,
        &format!(
            r#"{{"v":1,"agents":{{{}:{{"name":"proxy","rotate":false,"items":[{},{}]}}}}}}"#,
            serde_json::to_string(&id).expect("id"),
            serde_json::to_string(&a.item).expect("a"),
            serde_json::to_string(&b.item).expect("b"),
        ),
    );
    purge(&mut server, b).await;
    let said = format!("item {}: this device no longer sees it", b.item);

    let step = ana.rotation_step(id).await.expect("step");
    assert_eq!(step.rekeyed, vec![a.item], "{step:?}");
    assert!(
        step.skipped.iter().any(|s| s.starts_with(&said)),
        "{step:?}"
    );
    assert!(!step.done && step.failed.is_none(), "{step:?}");

    let step = ana.rotation_step(id).await.expect("step");
    assert!(step.done && step.failed.is_none(), "{step:?}");
    assert!(
        step.skipped.iter().any(|s| s.starts_with(&said)),
        "{step:?}"
    );

    // Still written down, out of reach, and never a key change.
    let pending = ana.pending_revocations().expect("record");
    let left = pending
        .iter()
        .find(|p| p.agent_id == id)
        .expect("kept while out of reach");
    assert!(left.without_key_change, "{left:?}");
    assert!(!left.needs_work() && left.items == 0, "{left:?}");
    assert_eq!(left.skipped.len(), 1, "{left:?}");
    assert!(left.skipped[0].starts_with(&said), "{left:?}");
}

/// Item keys still owed that this device knows only from its own record
/// (signed on another device, or read from the log), while the server no
/// longer serves the grant: running the revoke again, as `klav agent show`
/// hints, finishes them and never posts the revocation again, which the
/// server refuses (`409`, already revoked). With or without the key change,
/// and it never changes a project's key nobody asked for (P7) (review of
/// #315, 2). Nothing is left afterwards (review of #318, 2).
#[tokio::test(flavor = "multi_thread")]
async fn revoking_again_finishes_item_keys_owed_that_the_server_no_longer_shows() {
    for asked in [true, false] {
        let mut server = ServerProcess::start(900);
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut ana, _) = account(&server, &dir).await;
        let (id, a, b, _) = proxy_with_two_grants(&mut server, &dir, &mut ana).await;
        ana.revoke_first(id, asked).await.expect("revoke");
        // What this device's record says is still owed, with no grant it
        // signed: as when another device signed them.
        let rotate = if asked { "" } else { r#","rotate":false"# };
        write_record(
            &ana,
            &format!(
                r#"{{"v":1,"agents":{{{}:{{"name":"proxy"{rotate},"items":[{},{}]}}}}}}"#,
                serde_json::to_string(&id).expect("id"),
                serde_json::to_string(&a.item).expect("a"),
                serde_json::to_string(&b.item).expect("b"),
            ),
        );
        let (_, _, version) = grant_row(&server, id).await;
        serve_grant(&mut server, id, (None, None, version)).await;
        let vault = ana.find_vault("Personal").expect("vault");
        let general = ana.find_project(vault, "General").expect("project");
        let before = project_version(&server, general).await;

        // The hint runs it without `--rotate` when there are no projects.
        let report = ana
            .revoke_agent(id, false)
            .await
            .unwrap_or_else(|e| panic!("asked {asked}: finished, not posted again: {e}"));
        assert!(
            report.rekeyed.contains(&a.item) && report.rekeyed.contains(&b.item),
            "asked {asked}: {report:?}"
        );
        assert!(report.complete(), "asked {asked}: {report:?}");
        assert_eq!(
            project_version(&server, general).await,
            before,
            "asked {asked}: no project key changed"
        );
        // Asked or declined, nothing is left, and the entry goes: a proxy
        // has no project, so an asked entry with no item owes nothing, and
        // no step would ever remove it (review of #318, 2).
        let record = read_record(&ana);
        assert!(entry_of(&record, id).is_null(), "asked {asked}: {record}");
    }
}

/// Agent `id`'s entry in the record [`read_record`] returns (null if none).
fn entry_of(record: &serde_json::Value, id: klav_core::ids::AgentId) -> &serde_json::Value {
    &record["agents"][serde_json::to_string(&id).expect("id").trim_matches('"')]
}

/// Marks `project` of `vault` deleted on the server (an empty project), as
/// `revocacion.rs` does; a sync tells this device.
async fn delete_project(
    server: &mut ServerProcess,
    vault: klav_core::ids::VaultId,
    project: klav_core::ids::ProjectId,
) {
    with_db(server, |pool| async move {
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
        .bind(project.to_string())
        .execute(&pool)
        .await
        .expect("delete project");
    })
    .await;
}

/// A key change the person asked for, whose only project was deleted, with
/// an item key still owed: the run that changes the item's key closes the
/// key change and says once that the project's key could not change, with
/// or without `--rotate` (review of #322, 1). Declined, it says nothing
/// about the project: its key was never going to change. Nothing is left.
#[tokio::test(flavor = "multi_thread")]
async fn closing_a_key_change_says_its_deleted_project_once() {
    for (asked, rotate) in [(true, false), (true, true), (false, false)] {
        let mut server = ServerProcess::start(900);
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut ana, _) = account(&server, &dir).await;
        let a = add(&mut ana, "Railway").await;
        let vault = ana.find_vault("Personal").expect("vault");
        ana.create_project(vault, "Old").await.expect("project");
        let old = ana.find_project(vault, "Old").expect("project");
        let agent = register(&server, &dir, "agent").await;
        ana.approve_agent(
            agent.id(),
            GrantRequest {
                projects: vec!["Personal/Old".to_owned()],
                vaults: Vec::new(),
                policy: Policy::default(),
            },
            &agent.pairing_code(),
        )
        .await
        .expect("approve");
        let id = agent.id();
        ana.revoke_first(id, asked).await.expect("revoke");
        // With an item key still owed (from history: the log or another
        // device's grant).
        let declined = if asked { "" } else { r#","rotate":false"# };
        write_record(
            &ana,
            &format!(
                r#"{{"v":1,"agents":{{{}:{{"name":"agent"{declined},"items":[{}]}}}}}}"#,
                serde_json::to_string(&id).expect("id"),
                serde_json::to_string(&a.item).expect("a"),
            ),
        );
        delete_project(&mut server, vault, old).await;
        ana.sync().await.expect("sync");

        let deleted = |lines: &[String]| {
            lines
                .iter()
                .filter(|s| s.contains("the project was deleted"))
                .count()
        };
        if rotate {
            // What `klavd` runs: the first call, then the steps. The step
            // that finishes the entry says the project, so `klavd` keeps it
            // in `status`; the first call leaves the entry to it.
            let first = ana.revoke_first(id, true).await.expect("revoke");
            assert_eq!(first.rekeyed, vec![a.item], "{first:?}");
            assert_eq!(deleted(&first.skipped), 0, "{first:?}");
            assert!(
                !entry_of(&read_record(&ana), id).is_null(),
                "left to the step"
            );
            let step = ana.rotation_step(id).await.expect("step");
            assert!(step.done && step.failed.is_none(), "{step:?}");
            assert_eq!(deleted(&step.skipped), 1, "{step:?}");
        } else {
            let report = ana
                .revoke_agent(id, false)
                .await
                .unwrap_or_else(|e| panic!("asked {asked}: {e}"));
            assert_eq!(report.rekeyed, vec![a.item], "asked {asked}: {report:?}");
            // Said once when asked; a deleted project's name is gone, so the
            // line names it as a step's does.
            assert_eq!(
                deleted(&report.skipped),
                usize::from(asked),
                "asked {asked}: {report:?}"
            );
        }
        let record = read_record(&ana);
        assert!(entry_of(&record, id).is_null(), "rotate {rotate}: {record}");
    }
}

/// The plain revoke that finishes owed item keys never drops a key change
/// the person asked for while it still owes something else, and never
/// changes a project's key (P7): a project not rotated yet, grants to issue
/// again, projects nobody knows, or a log not read yet each keep the
/// entry. A declined one goes, and nothing rotates for it afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn a_plain_revoke_keeps_a_key_change_still_owed_and_never_starts_one() {
    for case in [
        "project",
        "regrants",
        "unknown",
        "log_unchecked",
        "vault_unlisted",
        "declined",
    ] {
        let mut server = ServerProcess::start(900);
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut ana, _) = account(&server, &dir).await;
        let a = add(&mut ana, "Railway").await;
        let vault = ana.find_vault("Personal").expect("vault");
        let general = ana.find_project(vault, "General").expect("project");
        // A project agent for the project cases (its record names
        // `General`, or `Work/Infra` in a vault that stops being listed),
        // a proxy for the others (no project at all).
        let with_project = matches!(case, "project" | "vault_unlisted" | "declined");
        let work = ana.create_vault("Work").await.expect("vault");
        ana.create_project(work, "Infra").await.expect("project");
        let project = if case == "vault_unlisted" {
            "Work/Infra"
        } else {
            "Personal/General"
        };
        let agent = register(&server, &dir, "agent").await;
        if with_project {
            ana.approve_agent(
                agent.id(),
                GrantRequest {
                    projects: vec![project.to_owned()],
                    vaults: Vec::new(),
                    policy: Policy::default(),
                },
                &agent.pairing_code(),
            )
            .await
            .expect("approve");
        } else {
            ana.grant_items(agent.id(), request(&[a]), &agent.pairing_code())
                .await
                .expect("grant");
        }
        let id = agent.id();
        let asked = case != "declined";
        ana.revoke_first(id, asked).await.expect("revoke");
        // The entry as the first run left it, with an item key still owed.
        let extra = match case {
            "regrants" => format!(
                r#","regrants":[{}]"#,
                serde_json::to_string(&general).expect("project")
            ),
            "unknown" => r#","unknown":true"#.to_owned(),
            "log_unchecked" => r#","log_unchecked":true"#.to_owned(),
            "declined" => r#","rotate":false"#.to_owned(),
            _ => String::new(),
        };
        write_record(
            &ana,
            &format!(
                r#"{{"v":1,"agents":{{{}:{{"name":"agent"{extra},"items":[{}]}}}}}}"#,
                serde_json::to_string(&id).expect("id"),
                serde_json::to_string(&a.item).expect("a"),
            ),
        );
        if case == "vault_unlisted" {
            // The server stops listing Work: Infra may come back.
            listed(&mut server, work, false).await;
            ana.sync().await.expect("sync");
        }
        let before = project_version(&server, general).await;

        let report = ana
            .revoke_agent(id, false)
            .await
            .unwrap_or_else(|e| panic!("{case}: {e}"));
        assert_eq!(report.rekeyed, vec![a.item], "{case}: {report:?}");
        let record = read_record(&ana);
        let entry = entry_of(&record, id);
        if case == "declined" {
            assert!(entry.is_null(), "{case}: {record}");
        } else {
            assert!(
                entry.is_object(),
                "{case}: the key change is still owed: {record}"
            );
            assert!(
                entry.get("rotate").is_none_or(|r| r == true),
                "{case}: {record}"
            );
            assert!(
                entry["items"].as_array().is_none_or(Vec::is_empty),
                "{case}: {record}"
            );
            if !matches!(case, "project" | "vault_unlisted") {
                assert!(entry.get(case).is_some(), "{case}: {record}");
            }
        }
        if case == "vault_unlisted" {
            // Work comes back: the key change the person asked for goes on.
            listed(&mut server, work, true).await;
            ana.sync().await.expect("sync");
            let infra = ana.find_project(work, "Infra").expect("project");
            let infra_before = project_version(&server, infra).await;
            let step = ana.rotation_step(id).await.expect("step");
            assert!(step.rotated.is_some(), "{case}: {step:?}");
            assert!(project_version(&server, infra).await > infra_before);
        } else if with_project {
            // Asked: the project is still owed. Declined: a step finds
            // nothing to do.
            let step = ana.rotation_step(id).await.expect("step");
            assert_eq!(step.rotated.is_some(), asked, "{case}: {step:?}");
        }
        let after = project_version(&server, general).await;
        if case == "project" {
            assert!(after > before, "{case}: the asked key change goes on");
        } else {
            assert_eq!(after, before, "{case}: no project key changed");
        }
    }
}
