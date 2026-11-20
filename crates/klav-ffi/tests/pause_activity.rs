//! Agents' pause and activity from the phone (ADR 0033 §9): `KlavCore`
//! pauses an agent at once, the agent is refused by the server, a wrong
//! master password resumes nothing and the right one does. «Who used it»,
//! the log and its chain come from the same `klav-client` code as the Mac,
//! and `by_agent` tells an agent's event from the person's decision about
//! that agent.

mod common;

use std::time::Duration;

use common::ServerProcess;
use klav_client::agents::GrantRequest;
use klav_client::{ClientError, Home, SignupRequest};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::model::item::{Item, ItemKind};
use klav_core::policy::{Effect, Permission, Policy, Rule};
use klav_ffi::{KlavCore, KlavError, LogFilterInput, UnpinnedHead, UseHow};
use klav_proto::auth::DeviceKind;
use klav_sdk::{Agent, KeyStore, Registration, Session};
use secrecy::ExposeSecret;

const PASSWORD: &str = "correct horse battery staple";
const EMAIL: &str = "ana@example.com";
const TOTP: &str = "JBSWY3DPEHPK3PXP";
const REASON: &str = "sign in to GitHub for the release";
const DENIED_REASON: &str = "show the password to the person";

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
    item.field_mut("totp")
        .expect("test setup")
        .set_value(TOTP)
        .expect("test setup");
    item.add_url("https://github.com").expect("test setup");
    item
}

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("clock")
}

fn by_agent(agent: &str) -> LogFilterInput {
    LogFilterInput {
        agent: Some(agent.to_owned()),
        ..LogFilterInput::default()
    }
}

#[test]
fn the_phone_pauses_an_agent_and_shows_what_it_did() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let rt = runtime();

    // The laptop: an account with GitHub, and an agent allowed its code.
    let (mut laptop, secret_key, item) = rt.block_on(async {
        let (mut laptop, kit) = klav_client::signup(
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
                        rules: vec![Rule::new(Permission::Totp, Effect::Allow)],
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
    let code = |session: &mut Session| {
        rt.block_on(session.totp(item, None, REASON, Duration::ZERO))
            .map(drop)
    };
    code(&mut session).expect("the agent's code");

    // The phone signs in.
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
    assert!(core.agents_paused().expect("pauses").is_empty());

    // «Who used it»: the agent's use, its reason, how it got through.
    let used = core.item_activity(item.to_string()).expect("who used it");
    assert_eq!(used.item_id, item.to_string());
    assert!(!used.trashed && !used.deleted);
    assert_eq!(used.uses.len(), 1, "{:?}", used.uses);
    let first = &used.uses[0];
    assert!(first.entry.by_agent);
    assert_eq!(first.entry.agent_id.as_deref(), Some(bot_id.as_str()));
    assert_eq!(first.entry.actor, "bot");
    assert_eq!(first.entry.permission.as_deref(), Some("totp"));
    assert_eq!(first.entry.reason.as_deref(), Some(REASON));
    assert_eq!(first.how, UseHow::Policy);

    // Pausing the agent asks for nothing and stops it on the server.
    let paused = core
        .pause_agents(Some(bot_id.clone()), None)
        .expect("pause");
    assert_eq!(paused.len(), 1, "{paused:?}");
    assert_eq!(paused[0].agent_id.as_deref(), Some(bot_id.as_str()));
    assert!(paused[0].until_ms.is_none() && !paused[0].local);
    assert_eq!(core.agents_paused().expect("pauses").len(), 1);
    assert!(
        matches!(code(&mut session), Err(ClientError::Paused(_))),
        "a paused agent gets no code"
    );
    let dev = core.dev_agents().expect("agents");
    let row = dev.iter().find(|a| a.agent.id == bot_id).expect("bot");
    assert!(row.paused.as_ref().is_some_and(|p| !p.everyone), "{row:?}");
    assert!(row.approved_ms.is_some());

    // The log names the agent in the person's pause: `by_agent` says who
    // wrote it, not the agent's ID.
    let story = core.audit_log(by_agent(&bot_id)).expect("activity");
    let pause = story
        .iter()
        .find(|l| l.action == "agents.paused")
        .expect("the pause is in the agent's story");
    assert!(!pause.by_agent && pause.actor == "you", "{pause:?}");
    assert_eq!(pause.agent_id.as_deref(), Some(bot_id.as_str()));
    let access = story
        .iter()
        .find(|l| l.action == "agent.access")
        .expect("the use is in the agent's story");
    assert!(access.by_agent && !access.verified);

    // A wrong password resumes nothing; the right one does.
    assert!(matches!(
        core.resume_agents_with_password(Some(bot_id.clone()), "not the password".into()),
        Err(KlavError::WrongCredentials)
    ));
    assert_eq!(core.agents_paused().expect("pauses").len(), 1);
    let left = core
        .resume_agents_with_password(Some(bot_id.clone()), PASSWORD.into())
        .expect("resume");
    assert!(left.is_empty(), "{left:?}");
    code(&mut session).expect("resumed, the agent works again");

    // A permission its policy denies: refused, and written as `deny`. A
    // paused agent's request writes nothing, so this one comes after the
    // resume.
    let reveal = rt.block_on(session.access(item, Permission::Reveal, DENIED_REASON, None, None));
    assert!(
        matches!(reveal, Err(ClientError::Denied(_))),
        "the policy denies reveal"
    );
    let everything = core.audit_log(LogFilterInput::default()).expect("activity");
    assert!(
        everything
            .iter()
            .any(|l| l.outcome.as_deref() != Some("deny")),
        "{everything:?}"
    );
    // «Result › Denied» leaves only the denied use, of the item searched.
    let denied = core
        .audit_log(LogFilterInput {
            outcomes: vec!["deny".into()],
            text: Some("github".into()),
            ..LogFilterInput::default()
        })
        .expect("activity");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0].action, "agent.access");
    assert_eq!(denied[0].outcome.as_deref(), Some("deny"));
    assert_eq!(denied[0].permission.as_deref(), Some("reveal"));
    assert_eq!(denied[0].reason.as_deref(), Some(DENIED_REASON));
    assert!(denied[0].by_agent);
    // «Who used it» says how each use went: the denied one first.
    let used = core.item_activity(item.to_string()).expect("who used it");
    assert_eq!(used.uses[0].how, UseHow::Denied, "{:?}", used.uses);
    assert_eq!(used.uses[0].entry.permission.as_deref(), Some("reveal"));

    // Every agent for an hour, learned again by a sync after unlocking.
    let until = now_ms() + 3_600_000;
    let paused = core.pause_agents(None, Some(until)).expect("pause all");
    assert_eq!(paused.len(), 1);
    assert!(paused[0].agent_id.is_none() && paused[0].until_ms == Some(until));
    core.lock();
    assert!(matches!(core.agents_paused(), Err(KlavError::Locked)));
    core.unlock_with_password(PASSWORD.into(), None)
        .expect("unlock");
    core.sync().expect("sync");
    let known = core.agents_paused().expect("pauses");
    assert_eq!(known.len(), 1, "{known:?}");
    assert_eq!(known[0].until_ms, Some(until));
    // After Face ID (the app checks it), with no password.
    assert!(core.resume_agents(None).expect("resume all").is_empty());

    // «Verify now», and the chain line after it.
    let status = core.audit_status().expect("status");
    assert!(status.verified.is_none() && status.unverified == status.events);
    let report = core.verify_audit().expect("verify");
    assert!(report.account_signatures >= 4, "{report:?}");
    // The first verification on the phone: a code the app words, not
    // klav-client's English among the warnings.
    assert_eq!(report.unpinned, Some(UnpinnedHead::Missing), "{report:?}");
    assert!(
        report
            .warnings
            .iter()
            .all(|w| !w.contains("had not verified")),
        "{report:?}"
    );
    let status = core.audit_status().expect("status");
    assert_eq!(status.verified, report.signed_head);
    assert_eq!(status.unverified, 0);
    let again = core.verify_audit().expect("verify again");
    assert_eq!(again.unpinned, None, "{again:?}");

    assert!(matches!(
        core.pause_agents(Some("not-an-id".into()), None),
        Err(KlavError::Invalid { .. })
    ));
}
