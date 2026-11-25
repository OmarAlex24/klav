//! Tasks and approvals against a real server (layer 06 of the 2026-11
//! security round, ADR 0030 §5–§7): the person signs only the request she
//! was shown. A malicious server is played by editing its SQLite file while
//! it is stopped.

#[path = "../../klav-client/tests/common/mod.rs"]
mod common;

use std::future::Future;
use std::time::Duration;

use common::ServerProcess;
use klav_client::agents::GrantRequest;
use klav_client::fill::FillPart;
use klav_client::offer::OfferRequest;
use klav_client::ops::ItemPatch;
use klav_client::tasks::TaskChoice;
use klav_client::{ClientError, Home, ItemFilter, ItemLocation, SignupRequest, Unlocked, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::model::item::{Item, ItemKind};
use klav_core::policy::{Effect, Permission, Policy, Rule};
use klav_core::task::{TaskSpec, TaskSpecAccess};
use klav_proto::agent::{ApprovalRequest, ApprovalStatus, Claims, GrantPayload};
use klav_proto::auth::DeviceKind;
use klav_proto::rotate::{AgentRotateStart, RotationStarted};
use klav_proto::task::TaskStatus;
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
    named_agent(server, dir, ana, "bot", policy).await
}

/// Registers agent `name` and approves it on Personal/General with `policy`.
async fn named_agent(
    server: &ServerProcess,
    dir: &tempfile::TempDir,
    ana: &mut Unlocked,
    name: &str,
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

async fn add(ana: &mut Unlocked, item: Item) -> ItemLocation {
    let vault = ana.find_vault("Personal").expect("vault");
    let project = ana.find_project(vault, "General").expect("project");
    ana.add_item(vault, project, &item).await.expect("add item")
}

fn login(title: &str, urls: &[&str]) -> Item {
    let mut item = Item::from_template(ItemKind::Login, title).expect("item");
    for url in urls {
        item.add_url(url).expect("url");
    }
    item
}

fn spec(title: &str, reference: &str, permissions: &[Permission]) -> TaskSpec {
    TaskSpec {
        task: title.into(),
        reason: "descargar las facturas".into(),
        duration: "30m".into(),
        access: vec![TaskSpecAccess {
            reference: reference.into(),
            permissions: permissions.to_vec(),
            domain: None,
        }],
    }
}

fn show<T>(result: &Result<T, ClientError>) -> String {
    match result {
        Ok(_) => "Ok".into(),
        Err(e) => format!("{e:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_swapped_after_the_card_is_not_signed() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir).await;
    let github = add(&mut ana, login("GitHub", &["https://github.com"])).await;
    let bank = add(&mut ana, login("Bank", &["https://bank.example"])).await;
    let bot = agent(&server, &dir, &mut ana, Policy::default()).await;
    let mut session = Session::open(bot).await.expect("session");

    // An approval request: the person is shown `totp` on GitHub.
    let Access::Pending { approval_id, .. } = session
        .access(github.item, Permission::Totp, "2fa", None, None)
        .await
        .expect("asks")
    else {
        panic!("totp asks by default");
    };
    let card = ana
        .find_approval(&approval_id.to_string())
        .await
        .expect("card");
    assert_eq!(card.permission, Permission::Totp);

    // A task request: the person is shown `inject` on GitHub.
    let request = session
        .task_request(
            &spec(
                "facturas",
                "klav://Personal/General/GitHub",
                &[Permission::Inject],
            ),
            None,
        )
        .expect("request");
    let task_id = session
        .submit_task(&request)
        .await
        .expect("submit")
        .pending_task_id;
    let task_card = ana.task(&task_id.to_string()).await.expect("task card");

    // The server swaps both before the person signs: `reveal` instead of
    // `totp`, and the bank instead of GitHub.
    with_db(&mut server, |pool| async move {
        let bytes: Vec<u8> = sqlx::query_scalar("SELECT request FROM approvals WHERE id = $1")
            .bind(approval_id.to_string())
            .fetch_one(&pool)
            .await
            .expect("approval request");
        let mut swapped: ApprovalRequest = serde_json::from_slice(&bytes).expect("request");
        swapped.permission = Permission::Reveal;
        sqlx::query("UPDATE approvals SET request = $1 WHERE id = $2")
            .bind(serde_json::to_vec(&swapped).expect("json"))
            .bind(approval_id.to_string())
            .execute(&pool)
            .await
            .expect("swap approval");
        let bytes: Vec<u8> = sqlx::query_scalar("SELECT request FROM tasks WHERE id = $1")
            .bind(task_id.to_string())
            .fetch_one(&pool)
            .await
            .expect("task request");
        let mut swapped: serde_json::Value = serde_json::from_slice(&bytes).expect("request");
        swapped["access"][0]["item_id"] = bank.item.to_string().into();
        sqlx::query("UPDATE tasks SET request = $1 WHERE id = $2")
            .bind(serde_json::to_vec(&swapped).expect("json"))
            .bind(task_id.to_string())
            .execute(&pool)
            .await
            .expect("swap task");
    })
    .await;

    let got = ana
        .decide_approval(approval_id, true, None, &card.request_digest)
        .await;
    assert!(
        matches!(&got, Err(ClientError::Security(m)) if m.contains("changed")),
        "{}",
        show(&got)
    );
    let got = ana.add_to_task(approval_id, &card.request_digest).await;
    assert!(
        matches!(&got, Err(ClientError::Security(_))),
        "{}",
        show(&got)
    );
    let got = ana
        .decide_task(
            task_id,
            true,
            &TaskChoice::default(),
            &task_card.request_digest,
        )
        .await;
    assert!(
        matches!(&got, Err(ClientError::Security(m)) if m.contains("changed")),
        "{}",
        show(&got)
    );
    // Denying signs the request too: also refused.
    let got = ana
        .decide_task(
            task_id,
            false,
            &TaskChoice::default(),
            &task_card.request_digest,
        )
        .await;
    assert!(
        matches!(&got, Err(ClientError::Security(_))),
        "{}",
        show(&got)
    );

    // Nothing was signed: both stay pending.
    let pending = ana.approvals(false).await.expect("approvals");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].status, ApprovalStatus::Pending);
    assert_ne!(pending[0].request_digest, card.request_digest);
    let task = ana.task(&task_id.to_string()).await.expect("task");
    assert_eq!(task.status, TaskStatus::Pending);
    assert_ne!(task.request_digest, task_card.request_digest);

    // What the person sees now can be decided.
    ana.decide_approval(approval_id, false, None, &pending[0].request_digest)
        .await
        .expect("deny what is shown");
}

/// Residual risk 35 (ADR 0030 §3): a write the agent's policy asks about
/// is not sent until the account's signature on its approval checks out.
/// The server's copy of the grant is edited to `allow` it: before, the
/// runtime sent the sealed write and the server applied it.
#[tokio::test(flavor = "multi_thread")]
async fn a_write_the_policy_asks_about_waits_for_a_signed_approval() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir).await;
    let github = add(&mut ana, login("GitHub", &["https://github.com"])).await;
    let bank = add(&mut ana, login("Bank", &["https://bank.example"])).await;
    let policy = Policy {
        rules: vec![Rule::new(Permission::Delete, Effect::Ask)],
        expires_at: None,
    };
    let bot = agent(&server, &dir, &mut ana, policy).await;
    let bot_id = bot.id();
    let mut session = Session::open(bot).await.expect("session");

    // An honest server: the request is asked first, the body goes later.
    let got = session
        .trash_item(github.item, "clean up", Duration::ZERO)
        .await;
    let Err(ClientError::PendingApproval {
        id: approval_id, ..
    }) = got
    else {
        panic!("delete asks: {}", show(&got));
    };
    let card = ana
        .find_approval(&approval_id.to_string())
        .await
        .expect("card");
    assert_eq!(card.permission, Permission::Delete);
    assert!(card.target.contains("GitHub"), "{}", card.target);
    ana.sync().await.expect("sync");
    let trashed = |ana: &Unlocked, item| {
        ana.list_items(&ItemFilter {
            trash: true,
            ..ItemFilter::default()
        })
        .expect("list")
        .iter()
        .any(|i| i.id == item)
    };
    assert!(
        !trashed(&ana, github.item),
        "nothing was written before the decision"
    );
    // Approved once: the next try finds it (unspent by the asking) and the
    // write spends it.
    ana.decide_approval(approval_id, true, None, &card.request_digest)
        .await
        .expect("approve");
    session
        .trash_item(github.item, "clean up", Duration::ZERO)
        .await
        .expect("trash with the approval");
    ana.sync().await.expect("sync");
    assert!(trashed(&ana, github.item));

    // A server that ignores the policy: its grant now allows `delete`.
    with_db(&mut server, |pool| async move {
        let bytes: Vec<u8> = sqlx::query_scalar("SELECT grant_payload FROM agents WHERE id = $1")
            .bind(bot_id.to_string())
            .fetch_one(&pool)
            .await
            .expect("grant");
        let mut grant: GrantPayload = serde_json::from_slice(&bytes).expect("grant");
        grant.policy.rules = vec![Rule::new(Permission::Delete, Effect::Allow)];
        sqlx::query("UPDATE agents SET grant_payload = $1 WHERE id = $2")
            .bind(serde_json::to_vec(&grant).expect("json"))
            .bind(bot_id.to_string())
            .execute(&pool)
            .await
            .expect("edit grant");
    })
    .await;
    let got = session
        .trash_item(bank.item, "clean up", Duration::ZERO)
        .await;
    assert!(
        matches!(&got, Err(ClientError::Security(m)) if m.contains("nothing was sent")),
        "{}",
        show(&got)
    );
    ana.sync().await.expect("sync");
    assert!(!trashed(&ana, bank.item), "the server never got the write");
}

fn has_login(ana: &Unlocked, url: &str, item: klav_core::ids::ItemId) -> bool {
    ana.suggest(url)
        .expect("suggest")
        .logins
        .iter()
        .any(|s| s.id == item)
}

/// G8 (ADR 0030 §7): a site an agent adds to a login waits for the person.
/// Her autofill does not offer it, a task marks it as not matching, and the
/// agent's runtime does not fill it, until she confirms it.
#[tokio::test(flavor = "multi_thread")]
async fn a_site_an_agent_added_waits_for_the_person() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir).await;
    let github = add(&mut ana, login("GitHub", &["https://github.com"])).await;
    let policy = Policy {
        rules: vec![Rule::new(Permission::Update, Effect::Allow)],
        expires_at: None,
    };
    let bot = agent(&server, &dir, &mut ana, policy).await;
    let bot_id = bot.id();
    let mut session = Session::open(bot).await.expect("session");

    // Before: the person's version, every site confirmed.
    session
        .access(
            github.item,
            Permission::Fill,
            "log in",
            Some("github.com"),
            None,
        )
        .await
        .expect("fill");
    assert_eq!(session.confirmed_urls(github.item), ["https://github.com"]);

    // The agent adds a phishing site to the login.
    session
        .update_item(
            github.item,
            &ItemPatch {
                add_urls: vec!["https://github-login.example".into()],
                ..ItemPatch::default()
            },
            "add the new login page",
            Duration::ZERO,
        )
        .await
        .expect("agent update");
    ana.sync().await.expect("sync");
    let summary = ana.item_summary(github).expect("summary");
    assert_eq!(summary.author_agent_id, Some(bot_id));
    assert_eq!(summary.confirmed_urls, ["https://github.com"]);
    assert_eq!(summary.pending_urls, ["https://github-login.example"]);
    assert_eq!(summary.urls.len(), 2);

    // The person's autofill: not offered, not filled.
    assert!(has_login(&ana, "https://github.com/login", github.item));
    assert!(!has_login(
        &ana,
        "https://github-login.example/",
        github.item
    ));
    let id = github.item.to_string();
    let got = ana.autofill(&id, "https://github-login.example/", FillPart::All, false);
    assert!(
        matches!(&got, Err(ClientError::Denied(m)) if m.contains("agent")),
        "{}",
        show(&got)
    );

    // The agent's runtime: the server delivers it, the runtime does not
    // count it.
    session
        .access(
            github.item,
            Permission::Fill,
            "log in",
            Some("github-login.example"),
            None,
        )
        .await
        .expect("fill access");
    assert_eq!(session.confirmed_urls(github.item), ["https://github.com"]);

    // A task for that site: «the site does not match».
    let mut asked = spec(
        "entrar",
        "klav://Personal/General/GitHub",
        &[Permission::Fill],
    );
    asked.access[0].domain = Some("github-login.example".into());
    let request = session.task_request(&asked, None).expect("request");
    let task_id = session
        .submit_task(&request)
        .await
        .expect("submit")
        .pending_task_id;
    let card = ana.task(&task_id.to_string()).await.expect("card");
    assert!(card.rows[0].domain_mismatch, "{:?}", card.rows[0]);

    // She confirms it (an edit of hers): now it counts everywhere.
    ana.edit(&id, &ItemPatch::default()).await.expect("confirm");
    let summary = ana.item_summary(github).expect("summary");
    assert_eq!(summary.author_agent_id, None);
    assert!(summary.pending_urls.is_empty());
    assert!(has_login(
        &ana,
        "https://github-login.example/",
        github.item
    ));
    session
        .access(
            github.item,
            Permission::Fill,
            "log in",
            Some("github-login.example"),
            None,
        )
        .await
        .expect("fill access");
    assert_eq!(session.confirmed_urls(github.item).len(), 2);

    // Another one she removes instead. A subdomain an agent added is not
    // offered on its parent page either (ADR 0025 §1), not even when she
    // picks it there.
    session
        .update_item(
            github.item,
            &ItemPatch {
                add_urls: vec!["https://accounts.evil.example".into()],
                ..ItemPatch::default()
            },
            "one more",
            Duration::ZERO,
        )
        .await
        .expect("agent update");
    ana.sync().await.expect("sync");
    assert_eq!(
        ana.item_summary(github).expect("summary").pending_urls,
        ["https://accounts.evil.example"]
    );
    let offered = ana.suggest("https://evil.example/").expect("suggest");
    assert!(
        !offered
            .parent
            .iter()
            .chain(&offered.logins)
            .any(|s| s.id == github.item)
    );
    let got = ana.autofill(&id, "https://evil.example/", FillPart::All, true);
    assert!(
        matches!(&got, Err(ClientError::Denied(_))),
        "{}",
        show(&got)
    );
    ana.edit(
        &id,
        &ItemPatch {
            remove_urls: vec!["https://accounts.evil.example".into()],
            ..ItemPatch::default()
        },
    )
    .await
    .expect("remove");
    let summary = ana.item_summary(github).expect("summary");
    assert!(summary.pending_urls.is_empty());
    assert!(!summary.urls.iter().any(|u| u.contains("evil")));

    // A rotation of the project key (after revoking an agent, say) rewraps
    // the stored versions: the person's confirmed sites survive it.
    session
        .update_item(
            github.item,
            &ItemPatch {
                add_urls: vec!["https://after.example".into()],
                ..ItemPatch::default()
            },
            "one more",
            Duration::ZERO,
        )
        .await
        .expect("agent update");
    ana.sync().await.expect("sync");
    ana.rotate_project_key(github.project)
        .await
        .expect("rotate");
    ana.sync().await.expect("sync");
    let summary = ana.item_summary(github).expect("summary");
    assert_eq!(summary.pending_urls, ["https://after.example"]);
    assert_eq!(summary.confirmed_urls.len(), 2, "{summary:?}");
}

/// ADR 0022 §5–6 with ADR 0030 §7: a site an agent added is no place for a
/// password change. The person's offer only covers the sites she
/// confirmed, so the server lets no change start on the agent's.
#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_only_goes_to_a_site_the_person_confirmed() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir).await;
    let with_password = |mut item: Item| {
        item.field_mut("password")
            .expect("password")
            .set_value("repetida-123")
            .expect("password");
        item
    };
    let banco = add(
        &mut ana,
        with_password(login("Banco", &["https://banco.example"])),
    )
    .await;
    let siteless = add(&mut ana, with_password(login("Sin sitio", &[]))).await;
    let policy = Policy {
        rules: vec![Rule::new(Permission::Update, Effect::Allow)],
        expires_at: None,
    };
    let bot = agent(&server, &dir, &mut ana, policy).await;
    let bot_id = bot.id();
    let session = Session::open(bot).await.expect("session");

    // The agent adds its own sites to both logins.
    let mut session = session;
    for (item, url) in [
        (banco.item, "https://banco-login.example"),
        (siteless.item, "https://sin-sitio.example"),
    ] {
        session
            .update_item(
                item,
                &ItemPatch {
                    add_urls: vec![url.into()],
                    ..ItemPatch::default()
                },
                "add the login page",
                Duration::ZERO,
            )
            .await
            .expect("agent update");
    }
    ana.sync().await.expect("sync");
    assert_eq!(
        ana.item_summary(banco).expect("summary").pending_urls,
        ["https://banco-login.example"]
    );

    // A login whose only site is the agent's cannot be offered.
    let offer = |items: Vec<klav_core::ids::ItemId>| OfferRequest {
        agent: bot_id.to_string(),
        items,
        task: None,
        reason: None,
        duration_secs: None,
    };
    let refused = ana.offer_task(&offer(vec![siteless.item])).await;
    assert!(
        show(&refused).contains("cannot go in the task"),
        "{}",
        show(&refused)
    );

    // The bank's offer covers banco.example only.
    let offered = ana
        .offer_task(&offer(vec![banco.item]))
        .await
        .expect("offer");
    let start = |host: &'static str| {
        let session = &session;
        async move {
            session
                .agent()
                .call_proved::<_, RotationStarted>(
                    "/v1/agent/rotations",
                    &AgentRotateStart {
                        item_id: banco.item,
                        reason: "cambiar la repetida".into(),
                        claims: Claims {
                            tags: Vec::new(),
                            domain: Some(host.into()),
                            ..Claims::default()
                        },
                        task_id: Some(offered.id),
                    },
                )
                .await
                .map(|(started, _)| started)
        }
    };
    let on_agents_site = start("banco-login.example").await;
    assert!(
        matches!(
            on_agents_site,
            Err(ClientError::Denied(_) | ClientError::Api { status: 403, .. })
        ),
        "{}",
        show(&on_agents_site)
    );
    start("banco.example").await.expect("on the person's site");
}

/// An agent with `update` changes a password and keeps the password record
/// as it was: the old value is not in the history. The person's next edit
/// puts it there (ADR 0022 §3, ADR 0030 layer 10).
#[tokio::test(flavor = "multi_thread")]
async fn a_password_an_agent_replaced_reaches_the_history_on_the_persons_next_edit() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir).await;
    let mut item = login("GitHub", &["https://github.com"]);
    item.field_mut("password")
        .expect("password")
        .set_value("MARKER-first")
        .expect("set");
    let github = add(&mut ana, item).await;
    // A first edit by the person: the record exists from here on.
    let mut edited = ana.open_item(github).expect("open");
    edited
        .field_mut("password")
        .expect("password")
        .set_value("MARKER-second")
        .expect("set");
    ana.update_item(github, &edited).await.expect("person edit");
    assert_eq!(
        ana.password_history(github).expect("history").entries.len(),
        1
    );

    let policy = Policy {
        rules: vec![Rule::new(Permission::Update, Effect::Allow)],
        expires_at: None,
    };
    let bot = agent(&server, &dir, &mut ana, policy).await;
    let mut session = Session::open(bot).await.expect("session");
    session
        .update_item(
            github.item,
            &ItemPatch {
                set: vec![klav_client::ops::FieldInput {
                    name: "password".into(),
                    value: klav_client::ops::SecretText::new("MARKER-agents"),
                    kind: None,
                    secret: true,
                }],
                ..ItemPatch::default()
            },
            "rotate the password",
            Duration::ZERO,
        )
        .await
        .expect("agent update");
    ana.sync().await.expect("sync");

    // The person edits something else: the value the agent replaced
    // ("MARKER-second") goes to the history, before the agent's.
    let mut edited = ana.open_item(github).expect("open");
    edited.set_notes(Some("rotated by the bot"));
    ana.update_item(github, &edited).await.expect("person edit");
    let values: Vec<String> = (0..ana.password_history(github).expect("history").entries.len())
        .map(|i| {
            ana.previous_password(github, i)
                .expect("value")
                .expose()
                .to_owned()
        })
        .collect();
    assert_eq!(values, ["MARKER-second", "MARKER-first"]);
    // The agent's value is the current one.
    let current = ana.open_item(github).expect("open");
    assert!(matches!(
        current.field("password").expect("password").value(),
        klav_core::model::item::FieldValue::Secret(v) if v.expose() == "MARKER-agents"
    ));
}

/// A login for a local program on one port is not offered nor filled on
/// another port of the same machine (another program). Nor is it offered
/// as a login saved for a subdomain (ADR 0025) on another port of its
/// parent.
#[tokio::test(flavor = "multi_thread")]
async fn a_login_with_a_port_fills_only_that_port() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir).await;
    let dev = add(&mut ana, login("Dev", &["http://localhost:3000"])).await;
    let any = add(&mut ana, login("Site", &["https://example.com"])).await;
    let sub = add(&mut ana, login("Sub", &["http://my.app.localhost:3000"])).await;
    assert!(has_login(&ana, "http://localhost:3000/login", dev.item));
    assert!(!has_login(&ana, "http://localhost:4000/login", dev.item));
    let id = dev.item.to_string();
    assert!(
        ana.autofill(&id, "http://localhost:3000/", FillPart::All, false)
            .is_ok()
    );
    let got = ana.autofill(&id, "http://localhost:4000/", FillPart::All, false);
    assert!(
        matches!(&got, Err(ClientError::Denied(_))),
        "{}",
        show(&got)
    );
    // An item URL without a port covers every port of its host.
    assert!(has_login(&ana, "https://example.com:8443/", any.item));

    // The parent page on the item's port: in its own group, and filled
    // only when the person picks it.
    let parent = |url: &str| -> Vec<_> {
        let offered = ana.suggest(url).expect("suggest");
        offered
            .parent
            .iter()
            .map(|s| (s.id, s.site.clone()))
            .collect()
    };
    assert_eq!(
        parent("http://app.localhost:3000/login"),
        [(sub.item, Some("my.app.localhost".to_owned()))]
    );
    let sub_id = sub.item.to_string();
    assert!(
        ana.autofill(&sub_id, "http://app.localhost:3000/", FillPart::All, true)
            .is_ok()
    );
    // On another port, the parent is another program: not offered, not
    // filled, even when picked.
    assert!(parent("http://app.localhost:4000/login").is_empty());
    let got = ana.autofill(&sub_id, "http://app.localhost:4000/", FillPart::All, true);
    assert!(
        matches!(&got, Err(ClientError::Denied(_))),
        "{}",
        show(&got)
    );
}

/// ADR 0022 §7 with ADR 0030 §7: the agent that created a login (a sign-up
/// with a generated password) fills it on its own sites. Nobody else's
/// secret is in it. Another agent does not, the person's autofill still
/// waits for her, and once she writes a version, hers rules again.
#[tokio::test(flavor = "multi_thread")]
async fn the_agent_fills_the_login_it_created_and_nobody_touched() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, &dir).await;
    let policy = Policy {
        rules: vec![
            Rule::new(Permission::Create, Effect::Allow),
            Rule::new(Permission::Update, Effect::Allow),
        ],
        expires_at: None,
    };
    let bot = agent(&server, &dir, &mut ana, policy.clone()).await;
    let other = named_agent(&server, &dir, &mut ana, "other", policy).await;
    let mut session = Session::open(bot).await.expect("session");
    let vault = ana.find_vault("Personal").expect("vault");
    let project = ana.find_project(vault, "General").expect("project");
    let (created, _) = session
        .create_item_generated(
            project,
            klav_client::ops::NewItem {
                kind: ItemKind::Login,
                title: "Registro".into(),
                vault: None,
                project: None,
                fields: Vec::new(),
                urls: vec!["https://signup.example".into()],
                tags: Vec::new(),
                notes: None,
                allow_duplicate: false,
            },
            &klav_sdk::GenerateSpec::default(),
            "create an account",
            Duration::ZERO,
        )
        .await
        .expect("create");

    // Its own item, every version its own: it fills there.
    session
        .access(
            created.id,
            Permission::Fill,
            "sign up",
            Some("signup.example"),
            None,
        )
        .await
        .expect("fill access");
    assert_eq!(
        session.confirmed_urls(created.id),
        ["https://signup.example"]
    );
    // Still after a second version of its own.
    session
        .update_item(
            created.id,
            &ItemPatch {
                add_urls: vec!["https://accounts.signup.example".into()],
                ..ItemPatch::default()
            },
            "the login page moved",
            Duration::ZERO,
        )
        .await
        .expect("agent update");
    session
        .access(
            created.id,
            Permission::Fill,
            "log in",
            Some("signup.example"),
            None,
        )
        .await
        .expect("fill access");
    assert_eq!(session.confirmed_urls(created.id).len(), 2);

    // The person's autofill still waits for her.
    ana.sync().await.expect("sync");
    let loc = ana.find_item(&created.reference).expect("listed");
    let summary = ana.item_summary(loc).expect("summary");
    assert!(summary.confirmed_urls.is_empty(), "{summary:?}");
    assert_eq!(summary.pending_urls.len(), 2);
    assert!(!has_login(&ana, "https://signup.example/", created.id));

    // Another agent: not its item, nothing confirmed.
    let mut theirs = Session::open(other).await.expect("session");
    theirs
        .access(
            created.id,
            Permission::Fill,
            "log in",
            Some("signup.example"),
            None,
        )
        .await
        .expect("fill access");
    assert!(theirs.confirmed_urls(created.id).is_empty());
    // And once the other agent writes a version, not even the creator's.
    theirs
        .update_item(
            created.id,
            &ItemPatch {
                add_urls: vec!["https://phish.example".into()],
                ..ItemPatch::default()
            },
            "one more",
            Duration::ZERO,
        )
        .await
        .expect("other update");
    session.refresh().await.expect("refresh");
    session
        .access(
            created.id,
            Permission::Fill,
            "log in",
            Some("signup.example"),
            None,
        )
        .await
        .expect("fill access");
    assert!(session.confirmed_urls(created.id).is_empty());

    // The person writes a version: hers rules. Then the creator adds a
    // site: only hers count, as for any other item.
    let id = created.id.to_string();
    ana.sync().await.expect("sync");
    ana.edit(
        &id,
        &ItemPatch {
            remove_urls: vec!["https://phish.example".into()],
            ..ItemPatch::default()
        },
    )
    .await
    .expect("person edit");
    session.refresh().await.expect("refresh");
    session
        .update_item(
            created.id,
            &ItemPatch {
                add_urls: vec!["https://new.example".into()],
                ..ItemPatch::default()
            },
            "one more",
            Duration::ZERO,
        )
        .await
        .expect("agent update");
    session
        .access(
            created.id,
            Permission::Fill,
            "log in",
            Some("new.example"),
            None,
        )
        .await
        .expect("fill access");
    let mut confirmed = session.confirmed_urls(created.id).to_vec();
    confirmed.sort();
    assert_eq!(
        confirmed,
        ["https://accounts.signup.example", "https://signup.example"]
    );
}
