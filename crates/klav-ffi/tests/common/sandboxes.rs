//! An account whose proxy issued two sandboxes and sent a heartbeat, for
//! the apps' sandbox list (ADR 0036 E2.1). The person's side runs as the
//! apps do (`klav-client`); the proxy's side is its signed requests, sent
//! by hand with the proxy agent's own key, as `klav-proxy` sends them.

use klav_client::issuers::IssuerSpec;
use klav_client::proxy_admin::{PairingCheck, ProxyCredentialSpec};
use klav_client::{Home, SignupRequest};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::ids::{AgentId, SandboxId};
use klav_core::model::item::{Item, ItemKind};
use klav_proto::Blob;
use klav_proto::sandbox::{
    HEARTBEAT_VERSION, PATH_SANDBOX_STATE, PATH_SANDBOXES, PATH_STORE_RESET, SUFFIX_CLAIMED,
    SandboxClaimed, SandboxHeartbeat, SandboxIssue, SandboxLink, SandboxStoreReset, sandbox_path,
};
use klav_sdk::{Agent, KeyStore, Registration, Session};
use reqwest::Method;

use super::ServerProcess;

pub const PASSWORD: &str = "correct horse battery staple";

/// What the setup left on the server.
pub struct Sandboxes {
    pub proxy: AgentId,
    /// Claimed, and connected per the heartbeat.
    pub claimed: SandboxId,
    /// Issued, not claimed.
    pub waiting: SandboxId,
    /// The proxy's session, to send more.
    pub session: Session,
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

async fn register(server: &ServerProcess, dir: &std::path::Path, email: &str, name: &str) -> Agent {
    Agent::register(
        &Home::at(dir.join(format!("agent-{name}"))),
        Registration {
            name: name.into(),
            server: server.url.clone(),
            email: email.into(),
            note: None,
            key_store: KeyStore::File {
                path: dir.join(format!("{name}.key")),
            },
        },
    )
    .await
    .expect("register")
    .0
}

/// One signed request of the proxy, which must answer 2xx.
pub async fn send<B: serde::Serialize>(session: &Session, method: Method, path: &str, body: &B) {
    let bytes = serde_json::to_vec(body).expect("json");
    let res = session
        .agent()
        .send(method, path, Some(&bytes))
        .await
        .expect("request");
    klav_client::api::empty(res).await.expect(path);
}

/// Signs up `email` in `home`, makes `klav-proxy` the account's proxy with
/// `northflank` and `t3-code` its issuer; the proxy issues two sandboxes,
/// one claimed, logs its store epoch and sends one heartbeat. `home` is
/// left signed up and locked.
pub async fn setup(server: &ServerProcess, home: &std::path::Path, email: &str) -> Sandboxes {
    let dir = home.parent().expect("parent").to_path_buf();
    let (mut ana, _) = klav_client::signup(
        &Home::at(home),
        SignupRequest {
            server: server.url.clone(),
            email: email.into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "phone".into(),
            device_kind: klav_proto::auth::DeviceKind::Cli,
        },
    )
    .await
    .expect("sign-up");
    let vault = ana.find_vault("Personal").expect("vault");
    let project = ana.find_project(vault, "General").expect("project");
    let mut item = Item::from_template(ItemKind::Login, "Northflank").expect("item");
    item.field_mut("password")
        .expect("password")
        .set_value("token-0123456789")
        .expect("set");
    ana.add_item(vault, project, &item).await.expect("add item");

    let proxy = register(server, &dir, email, "klav-proxy").await;
    let prepared = ana
        .prepare_proxy_use(Some("klav-proxy"))
        .await
        .expect("use");
    ana.commit_proxy_use(prepared).await.expect("use");
    let spec = ProxyCredentialSpec {
        profile: "northflank".into(),
        upstream: "https://api.northflank.com".into(),
        header: "authorization".into(),
        prefix: "Bearer ".into(),
        methods: vec!["GET".into()],
        path_prefixes: vec!["/v1".into()],
        ..ProxyCredentialSpec::default()
    };
    let prepared = ana
        .prepare_proxy_grant("Northflank", &spec, PairingCheck::InPrompt)
        .await
        .expect("grant");
    prepared.require_updated_devices(true).expect("ack");
    assert!(
        ana.commit_proxy_change(prepared)
            .await
            .expect("grant")
            .complete()
    );
    let t3 = register(server, &dir, email, "t3-code").await;
    let prepared = ana
        .prepare_issuer_add(
            "t3-code",
            &IssuerSpec {
                profiles: vec!["northflank".into()],
                url: "tls://proxy.example.com:8443".into(),
                max_live: Some(3),
                ..IssuerSpec::default()
            },
            PairingCheck::InPrompt,
        )
        .await
        .expect("issuer add");
    prepared.require_updated_devices(true).expect("ack");
    assert!(
        ana.commit_issuer_change(prepared)
            .await
            .expect("add")
            .complete()
    );
    let issuer = t3.id();
    let proxy_id = proxy.id();
    drop(ana);

    let session = Session::open(proxy).await.expect("proxy session");
    let (claimed, waiting) = (SandboxId::generate(), SandboxId::generate());
    for (id, label) in [(claimed, "chat-1"), (waiting, "chat-2")] {
        let issue = SandboxIssue {
            sandbox_id: id,
            issuer_id: issuer,
            label: label.into(),
            profiles: vec!["northflank".into()],
            expires_at: now_ms() + 60 * 60 * 1000,
        };
        send(&session, Method::POST, PATH_SANDBOXES, &issue).await;
    }
    let claim = SandboxClaimed {
        channel_key_sha256: Blob::new(vec![7; 32]),
    };
    send(
        &session,
        Method::POST,
        &sandbox_path(claimed, SUFFIX_CLAIMED),
        &claim,
    )
    .await;
    let epoch = Blob::new(vec![5; klav_proto::sandbox::STORE_EPOCH_LEN]);
    send(
        &session,
        Method::POST,
        PATH_STORE_RESET,
        &SandboxStoreReset {
            store_epoch: epoch.clone(),
        },
    )
    .await;
    let now = now_ms();
    let beat = SandboxHeartbeat {
        v: HEARTBEAT_VERSION,
        store_epoch: epoch,
        seq: 1,
        sent_at_ms: now,
        sandboxes: vec![SandboxLink {
            id: claimed,
            connected: true,
            last_seen_at: Some(now),
        }],
    };
    send(&session, Method::PUT, PATH_SANDBOX_STATE, &beat).await;
    Sandboxes {
        proxy: proxy_id,
        claimed,
        waiting,
        session,
    }
}
