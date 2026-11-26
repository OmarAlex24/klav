//! The account's preferences (ADR 0032 §7, ADR 0036 §3) against the real
//! server: without the item, no proxy and nothing written; the setting
//! reaches another device; lists never show the item; two items that
//! disagree are an error until the setting is written again, which writes
//! it in both; and the hosted proxy is never written. Preferences an agent
//! wrote (the server's word, played by editing its database) fail every
//! reader, flag the sandbox list, and only `klav proxy use` replaces them,
//! whole, using nothing in them.

mod common;

use common::ServerProcess;
use klav_client::sandboxes::SecurityFlag;
use klav_client::{
    ClientError, Home, ItemFilter, ItemLocation, LoginRequest, SignupRequest, Unlocked, login,
    signup,
};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::secret_key::SecretKey;
use klav_core::ids::AgentId;
use klav_core::model::history::system_project_id;
use klav_core::model::item::{Item, ItemKind};
use klav_core::model::preferences::{Preferences, ProxyMode, ProxySetting};
use klav_proto::auth::DeviceKind;
use secrecy::ExposeSecret;
use sqlx::any::AnyPoolOptions;

const PASSWORD: &str = "correct horse battery staple";

#[tokio::test(flavor = "multi_thread")]
async fn the_proxy_setting_syncs_and_fails_closed() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let (mut a, kit) = signup(
        &Home::at(dir.path().join("a")),
        SignupRequest {
            server: server.url.clone(),
            email: "prefs@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
            invite: None,
        },
    )
    .await
    .expect("sign-up");
    let secret_key = kit.secret_key().to_text().expose_secret().to_owned();
    let vault = a.find_vault("Personal").unwrap();

    // No item: no proxy, «Development» on, and reading writes nothing.
    let prefs = a.preferences().unwrap();
    assert_eq!(prefs.proxy(), ProxySetting::NONE);
    assert!(prefs.developer());
    assert!(a.system_items(vault, ItemKind::Preferences).is_empty());

    // Setting it creates the item in the system project, never listed.
    let proxy = AgentId::generate();
    a.set_proxy_setting(ProxySetting::own(proxy)).await.unwrap();
    let items = a.system_items(vault, ItemKind::Preferences);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].project, system_project_id(vault));
    assert!(a.list_items(&ItemFilter::default()).unwrap().is_empty());
    assert_eq!(a.vaults()[0].items, 0);
    let written = a.open_item(items[0]).unwrap();
    // Only the key chosen: no `developer` nobody set.
    assert_eq!(written.preferences().unwrap().developer, None);
    // Found by ID, but never trashed by hand: that would read as «no
    // proxy» without anyone setting it.
    let by_id = items[0].item.to_string();
    assert!(matches!(
        a.trash(&by_id).await,
        Err(ClientError::Invalid(_))
    ));
    assert_eq!(a.preferences().unwrap().proxy(), ProxySetting::own(proxy));

    // The hosted proxy does not exist yet: never written.
    assert!(matches!(
        a.set_proxy_setting(ProxySetting {
            mode: ProxyMode::Klav,
            agent_id: None,
        })
        .await,
        Err(ClientError::Invalid(_))
    ));

    // Another device reads it, and its change comes back.
    let mut b = login(
        &Home::at(dir.path().join("b")),
        LoginRequest {
            server: server.url.clone(),
            email: "prefs@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            secret_key: SecretKey::parse(&secret_key).unwrap(),
            device_name: "phone".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("login");
    assert_eq!(b.preferences().unwrap().proxy(), ProxySetting::own(proxy));
    b.set_proxy_setting(ProxySetting::NONE).await.unwrap();
    a.sync().await.unwrap();
    assert_eq!(a.preferences().unwrap().proxy(), ProxySetting::NONE);
    assert_eq!(a.system_items(vault, ItemKind::Preferences).len(), 1);

    // Two devices that created it at once leave two items: if they
    // disagree, reading is an error (never «no proxy»), and writing the
    // setting again puts it in both.
    let mut second = Item::new(ItemKind::Preferences, "Preferences").unwrap();
    second
        .set_preferences(Some(Preferences {
            developer: Some(false),
            proxy: Some(ProxySetting::own(proxy)),
        }))
        .unwrap();
    let second_loc = a
        .add_item(vault, system_project_id(vault), &second)
        .await
        .unwrap();
    assert!(matches!(a.preferences(), Err(ClientError::Invalid(_))));
    let other = AgentId::generate();
    a.set_proxy_setting(ProxySetting::own(other)).await.unwrap();
    assert_eq!(a.preferences().unwrap().proxy(), ProxySetting::own(other));
    // Each item keeps its other keys.
    let kept = a.open_item(second_loc).unwrap();
    assert_eq!(kept.preferences().unwrap().developer, Some(false));
    b.sync().await.unwrap();
    assert_eq!(b.preferences().unwrap().proxy(), ProxySetting::own(other));
}

/// Marks `loc` as written by `agent`, with the server stopped, as a server
/// (or an agent that got the system project's key) would: the next sync
/// brings it.
async fn written_by(server: &mut ServerProcess, loc: ItemLocation, agent: AgentId) {
    server.stop();
    sqlx::any::install_default_drivers();
    let url = format!("sqlite://{}", server.dir.path().join("klav.db").display());
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("open server db");
    for (sql, binds) in [
        (
            "UPDATE items SET author_agent_id = $1, \
             revision = (SELECT revision + 1 FROM vaults WHERE id = $2) WHERE id = $3",
            vec![
                agent.to_string(),
                loc.vault.to_string(),
                loc.item.to_string(),
            ],
        ),
        (
            "UPDATE vaults SET revision = revision + 1 WHERE id = $1",
            vec![loc.vault.to_string()],
        ),
    ] {
        let mut q = sqlx::query(sql);
        for b in binds {
            q = q.bind(b);
        }
        q.execute(&pool).await.expect(sql);
    }
    pool.close().await;
    server.restart();
}

/// A preferences item of the person's, with `developer` set so that a
/// rewrite that kept the agent's body would show. The first one is written
/// by the setting, which also creates the system project; the next ones
/// are added beside it, as two devices that created it at once leave them.
async fn person_item(a: &mut Unlocked, setting: ProxySetting) -> ItemLocation {
    let vault = a.find_vault("Personal").expect("person item");
    let prefs = Preferences {
        developer: Some(false),
        proxy: Some(setting),
    };
    if a.system_items(vault, ItemKind::Preferences).is_empty() {
        a.set_proxy_setting(setting).await.expect("person item");
        let loc = a.system_items(vault, ItemKind::Preferences)[0];
        let mut item = a.open_item(loc).expect("person item");
        item.set_preferences(Some(prefs)).expect("person item");
        a.update_item(loc, &item).await.expect("person item");
        return loc;
    }
    let mut item = Item::new(ItemKind::Preferences, "Preferences").expect("person item");
    item.set_preferences(Some(prefs)).expect("person item");
    a.add_item(vault, system_project_id(vault), &item)
        .await
        .expect("person item")
}

#[tokio::test(flavor = "multi_thread")]
async fn preferences_an_agent_wrote_flag_the_list_and_only_proxy_use_replaces_them() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let (mut a, _kit) = signup(
        &Home::at(dir.path().join("a")),
        SignupRequest {
            server: server.url.clone(),
            email: "agent-prefs@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
            invite: None,
        },
    )
    .await
    .expect("sign-up");
    // The agent's item names a proxy the server does not list: a list that
    // trusted it would fail («the server does not list»), not show rows.
    let named_proxy = AgentId::generate();
    let loc = person_item(&mut a, ProxySetting::own(named_proxy)).await;
    let agent = AgentId::generate();
    written_by(&mut server, loc, agent).await;
    a.sync().await.expect("sync");
    assert_eq!(a.item_summary(loc).unwrap().author_agent_id, Some(agent));

    // Every reader fails, naming the agent and the way out.
    let named = |e: &ClientError| {
        let text = e.to_string();
        matches!(e, ClientError::Security(_))
            && text.contains(&agent.to_string())
            && text.contains("klav proxy use")
    };
    let e = a.preferences().expect_err("preferences");
    assert!(named(&e), "{e}");
    let e = a.proxy_status().await.expect_err("status");
    assert!(named(&e), "{e}");
    let e = a.sandbox_list().await.expect_err("the plain list");
    assert!(named(&e), "{e}");
    // Writing the setting without `use` fails too, and writes nothing.
    let e = a
        .set_proxy_setting(ProxySetting::own(AgentId::generate()))
        .await
        .expect_err("set");
    assert!(named(&e), "{e}");
    assert_eq!(a.item_summary(loc).unwrap().author_agent_id, Some(agent));

    // The flagged list: the chain's rows, no proxy (not the one the
    // agent's item names), the flag, and not a plain warning.
    let list = a
        .sandbox_list_flagged()
        .await
        .expect("flagged list, not the named proxy's");
    assert_eq!(
        list.security,
        Some(SecurityFlag::PreferencesByAgent { agent_id: agent })
    );
    assert_eq!(list.proxy, None);
    assert!(
        list.warnings
            .iter()
            .all(|w| !w.contains(&named_proxy.to_string())),
        "{:?}",
        list.warnings
    );
    assert!(
        list.warnings
            .iter()
            .all(|w| !w.contains(&agent.to_string())),
        "{:?}",
        list.warnings
    );

    // A second item the agent writes after `use` was prepared is not
    // replaced: the commit fails before writing anything. It holds exactly
    // the setting the person will choose (no proxy): the rewrite below
    // must happen anyway.
    let prepared = a.prepare_proxy_use(None).await.expect("prepare");
    assert_eq!(prepared.replaces_agent, Some(agent));
    assert!(
        prepared
            .warnings
            .iter()
            .any(|w| w.contains(&agent.to_string()) && w.contains("former proxy")),
        "{:?}",
        prepared.warnings
    );
    let later = person_item(&mut a, ProxySetting::NONE).await;
    let other = AgentId::generate();
    written_by(&mut server, later, other).await;
    a.sync().await.expect("sync");
    let e = a
        .commit_proxy_use(prepared)
        .await
        .expect_err("not prepared");
    assert!(
        matches!(&e, ClientError::Security(t) if t.contains(&other.to_string())),
        "{e}"
    );
    assert_eq!(a.item_summary(loc).unwrap().author_agent_id, Some(agent));

    // Prepared again, it replaces both: the person's authorship and a body
    // with only the chosen setting (the agent's `developer` is gone).
    let prepared = a.prepare_proxy_use(None).await.expect("prepare");
    a.commit_proxy_use(prepared).await.expect("replace");
    for loc in [loc, later] {
        assert_eq!(a.item_summary(loc).unwrap().author_agent_id, None);
        let written = a.open_item(loc).unwrap();
        assert_eq!(
            written.preferences().cloned(),
            Some(Preferences {
                developer: None,
                proxy: Some(ProxySetting::NONE),
            })
        );
        assert!(written.fields().is_empty() && written.notes().is_none());
    }
    assert_eq!(a.preferences().unwrap().proxy(), ProxySetting::NONE);
    let list = a.sandbox_list().await.expect("the plain list again");
    assert_eq!(list.security, None);
}

/// ADR 0051 §9: another device names Klav Cloud's proxy (`{mode: "klav",
/// agent_id}`). Without the `hosted-proxy` feature this client reads it,
/// says it doesn't support it, and refuses every proxy command; with it,
/// the status checks the enclave and fails closed when it can't (here the
/// server doesn't know the agent, and no release key is pinned). Neither
/// writes `klav` through `set_proxy_setting`.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_refuses_the_hosted_proxy_it_cannot_verify() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let (mut a, _) = signup(
        &Home::at(dir.path().join("a")),
        SignupRequest {
            server: server.url.clone(),
            email: "hosted@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
            invite: None,
        },
    )
    .await
    .expect("sign-up");
    let hosted = AgentId::generate();
    // A newer device wrote it: the item, as that device writes it.
    let loc = person_item(&mut a, ProxySetting::NONE).await;
    let mut item = a.open_item(loc).unwrap();
    item.set_preferences(Some(Preferences {
        developer: None,
        proxy: Some(ProxySetting::klav(hosted)),
    }))
    .unwrap();
    a.update_item(loc, &item).await.unwrap();
    assert_eq!(a.preferences().unwrap().proxy(), ProxySetting::klav(hosted));

    // `set_proxy_setting` never writes it: only `use klav`, verified.
    assert!(matches!(
        a.set_proxy_setting(ProxySetting::klav(hosted)).await,
        Err(ClientError::Invalid(_))
    ));
    let status = a.proxy_status().await.expect("status reads");
    assert_eq!(status.mode, ProxyMode::Klav);
    let spec = klav_client::proxy_admin::ProxyCredentialSpec {
        profile: "railway".into(),
        upstream: "https://backboard.railway.app".into(),
        header: "authorization".into(),
        prefix: "Bearer ".into(),
        methods: vec!["POST".into()],
        path_prefixes: vec!["/graphql".into()],
        ..Default::default()
    };
    let refused = a
        .prepare_proxy_grant(
            "anything",
            &spec,
            klav_client::proxy_admin::PairingCheck::Typed(None),
        )
        .await
        .expect_err("refused");
    #[cfg(not(feature = "hosted-proxy"))]
    {
        assert!(status.hosted.is_none());
        assert!(
            status
                .problems
                .iter()
                .any(|p| p == klav_client::hosted_proxy::UNSUPPORTED),
            "{:?}",
            status.problems
        );
        assert!(!status.lost.is_empty());
        assert!(
            refused
                .to_string()
                .contains(klav_client::hosted_proxy::UNSUPPORTED),
            "{refused}"
        );
    }
    #[cfg(feature = "hosted-proxy")]
    {
        let view = status.hosted.expect("checked");
        assert!(view.state.needs_attention(), "{view:?}");
        assert_ne!(view.state, klav_client::hosted_proxy::HostedState::Verified);
        // The server doesn't know that agent: the grant can't be built.
        let _ = refused;
    }
}
