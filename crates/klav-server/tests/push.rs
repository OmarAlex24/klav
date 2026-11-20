//! Approval pushes against a mock APNs (ADR 0018 §5): the phone registers
//! its token, a new agent, an `ask` approval and a task request reach it with a JWT signed
//! by the team key, the payload carries no names or reasons, and a dead
//! token is forgotten.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use common::TestServer;
use common::agent::TestAgent;
use common::vault::login_item;
use data_encoding::{BASE64, BASE64URL_NOPAD};
use klav_core::policy::{Permission, Policy};
use klav_core::task::{TASK_FORMAT_VERSION, TaskAccessRequest, TaskRequest};
use klav_proto::agent::PendingApproval;
use klav_proto::task::PendingTask;
use klav_server::ApnsConfig;
use reqwest::Method;
use serde_json::{Value, json};
use tokio::sync::mpsc;

const PHONE: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
const DEAD: &str = "dead0000000000000000000000000000000000000000000000000000000000ff";

#[derive(Debug)]
struct Delivered {
    token: String,
    headers: HeaderMap,
    body: Value,
}

async fn apns(
    State(tx): State<mpsc::UnboundedSender<Delivered>>,
    Path(token): Path<String>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, String) {
    let dead = token.starts_with("dead");
    let _ = tx.send(Delivered {
        token,
        headers,
        body: serde_json::from_str(&body).expect("json payload"),
    });
    if dead {
        (
            StatusCode::GONE,
            json!({"reason": "Unregistered"}).to_string(),
        )
    } else {
        (StatusCode::OK, String::new())
    }
}

/// A mock APNs (plain HTTP on loopback) and a team key on disk.
async fn mock_apns(
    dir: &std::path::Path,
) -> (ApnsConfig, Vec<u8>, mpsc::UnboundedReceiver<Delivered>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let app = Router::new()
        .route("/3/device/{token}", post(apns))
        .with_state(tx);
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("mock apns") });

    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .expect("key");
    let public = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
        .expect("key")
        .public_key()
        .as_ref()
        .to_vec();
    let path = dir.join("AuthKey_TEST.p8");
    std::fs::write(
        &path,
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            BASE64.encode(pkcs8.as_ref())
        ),
    )
    .expect("write key");
    let config = ApnsConfig {
        key_path: Some(path),
        key: None,
        key_id: "KEY1234567".into(),
        team_id: "TEAM123456".into(),
        topic: "dev.klav.ios".into(),
        endpoint_override: Some(format!("http://{addr}")),
    };
    (config, public, rx)
}

async fn next(rx: &mut mpsc::UnboundedReceiver<Delivered>) -> Delivered {
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("a push in time")
        .expect("channel open")
}

fn check_jwt(headers: &HeaderMap, public: &[u8]) {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .expect("authorization");
    let jwt = auth.strip_prefix("bearer ").expect("bearer");
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let claims: Value =
        serde_json::from_slice(&BASE64URL_NOPAD.decode(parts[1].as_bytes()).expect("b64"))
            .expect("claims");
    assert_eq!(claims["iss"], "TEAM123456");
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public)
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &BASE64URL_NOPAD.decode(parts[2].as_bytes()).expect("b64"),
        )
        .expect("signed with the team key");
    assert_eq!(headers["apns-topic"], "dev.klav.ios");
    assert_eq!(headers["apns-push-type"], "alert");
}

#[tokio::test]
async fn approvals_and_registrations_reach_the_phone_without_details() {
    let keys = tempfile::tempdir().expect("tempdir");
    let (apns_config, public, mut rx) = mock_apns(keys.path()).await;
    let server = TestServer::start_with(|c| c.push.apns = Some(apns_config)).await;
    let creds = server.signup("ana@example.com", "pw").await;
    let laptop = server.login(&creds, "laptop").await;
    let phone = server.login(&creds, "iPhone").await;
    let old = server.login(&creds, "old iPhone").await;

    // Registering a token: hex only, then the phone and an old phone.
    let bad = server
        .put_auth(&phone, "/v1/devices/current/push")
        .json(&json!({"token": "not-hex", "environment": "sandbox"}))
        .send()
        .await
        .expect("request");
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    for (session, token) in [(&phone, PHONE), (&old, DEAD)] {
        let res = server
            .put_auth(session, "/v1/devices/current/push")
            .json(&json!({"token": token.to_uppercase(), "environment": "sandbox"}))
            .send()
            .await
            .expect("request");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
    }

    // A new agent: both phones hear about it; the dead token is dropped.
    let vault = server.create_vault(&laptop).await;
    let project = server.create_project(&laptop, &vault).await;
    let item = login_item("GitHub", "ana", "hunter2");
    server.create_item(&laptop, &vault, &project, &item).await;
    let agent = TestAgent::new();
    server
        .register_agent_ok(&agent, "ana@example.com", "deploy-bot")
        .await;
    let mut got = vec![next(&mut rx).await, next(&mut rx).await];
    got.sort_by(|a, b| a.token.cmp(&b.token));
    assert_eq!(got[0].token, PHONE);
    assert_eq!(got[1].token, DEAD);
    for d in &got {
        check_jwt(&d.headers, &public);
        assert_eq!(d.body["klav"]["type"], "agent");
        assert_eq!(d.body["klav"]["id"], agent.id.to_string());
        assert_eq!(d.body["aps"]["alert"]["loc-key"], "PUSH_AGENT_BODY");
        assert!(!d.body.to_string().contains("deploy-bot"));
    }
    // An unknown e-mail sends nothing (and answers the same).
    server
        .register_agent_ok(&TestAgent::new(), "nobody@example.com", "x")
        .await;

    // An `ask` (totp by default) reaches only the live phone.
    let grant =
        TestServer::build_grant(&laptop, &agent, 1, Policy::default(), &[(&vault, &project)]);
    assert_eq!(
        server.post_grant(&laptop, &agent, &grant).await.status(),
        StatusCode::OK
    );
    let res = server
        .agent_call(
            &agent,
            Method::POST,
            "/v1/agent/access",
            Some(&json!({"item_id": item.id(), "permission": "totp", "reason": "secret-reason-text"})),
        )
        .await;
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let pending: PendingApproval = res.json().await.expect("pending");
    let d = next(&mut rx).await;
    assert_eq!(d.token, PHONE);
    check_jwt(&d.headers, &public);
    assert_eq!(d.body["klav"]["type"], "approval");
    assert_eq!(
        d.body["klav"]["id"],
        pending.pending_approval_id.to_string()
    );
    assert_eq!(
        d.headers["apns-collapse-id"],
        pending.pending_approval_id.to_string()
    );
    let text = d.body.to_string();
    assert!(!text.contains("secret-reason-text") && !text.contains("GitHub"));

    // A task request (ADR 0021 §8): the kind and the task's ID, no title,
    // reason or agent name, and it expires when the task must be decided.
    let request = TaskRequest {
        v: TASK_FORMAT_VERSION,
        task: "secret-task-title".into(),
        reason: "secret-task-reason".into(),
        duration_secs: 3600,
        access: vec![TaskAccessRequest {
            vault_id: vault.id,
            project_id: project.id,
            item_id: item.id(),
            permissions: vec![Permission::Fill],
            domain: None,
        }],
    };
    let res = server
        .agent_call(
            &agent,
            Method::POST,
            "/v1/agent/tasks",
            Some(&serde_json::to_value(&request).expect("request")),
        )
        .await;
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let task: PendingTask = res.json().await.expect("pending task");
    let d = next(&mut rx).await;
    assert_eq!(d.token, PHONE);
    check_jwt(&d.headers, &public);
    assert_eq!(
        d.body["klav"],
        json!({"type": "task", "id": task.pending_task_id.to_string()})
    );
    assert_eq!(d.body["aps"]["alert"]["title-loc-key"], "PUSH_TASK_TITLE");
    assert_eq!(d.body["aps"]["alert"]["loc-key"], "PUSH_TASK_BODY");
    assert_eq!(
        d.headers["apns-collapse-id"],
        task.pending_task_id.to_string()
    );
    let expiration: i64 = d.headers["apns-expiration"]
        .to_str()
        .expect("header")
        .parse()
        .expect("seconds");
    let decide_by = task.expires_at / 1000;
    assert!(
        (decide_by - 5..=decide_by + 5).contains(&expiration),
        "the push expires with the task's deadline: {expiration} vs {decide_by}"
    );
    let text = d.body.to_string();
    assert!(
        !text.contains("secret-task") && !text.contains("deploy-bot") && !text.contains("GitHub")
    );

    // The same pending request again does not push twice.
    let again = server
        .agent_call(
            &agent,
            Method::POST,
            "/v1/agent/access",
            Some(&json!({"item_id": item.id(), "permission": "totp", "reason": "again"})),
        )
        .await;
    assert_eq!(again.status(), StatusCode::ACCEPTED);

    // Unregistered: no more pushes to the phone.
    let res = server
        .delete_auth(&phone, "/v1/devices/current/push")
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let res = server
        .agent_call(
            &agent,
            Method::POST,
            "/v1/agent/access",
            Some(&json!({"item_id": item.id(), "permission": "update", "reason": "edit"})),
        )
        .await;
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert!(
        tokio::time::timeout(Duration::from_millis(800), rx.recv())
            .await
            .is_err(),
        "no push after unregistering (and none for the repeated request)"
    );

    // Revoking a device removes its token too.
    let res = server
        .put_auth(&phone, "/v1/devices/current/push")
        .json(&json!({"token": PHONE, "environment": "production"}))
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let db = server.raw_db().await;
    let count = |db: sqlx::AnyPool| async move {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM push_tokens")
            .fetch_one(&db)
            .await
            .expect("count")
    };
    assert_eq!(count(db.clone()).await, 1);
    let res = server
        .delete_auth(&laptop, &format!("/v1/devices/{}", phone.device_id))
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(count(db).await, 0);
}

/// ADR 0037 §5.4: asking, canceling and the deletion itself reach the
/// phones with a key and no ID; the last one reaches them although the
/// deletion removed their tokens.
#[tokio::test]
async fn the_deletion_of_the_account_reaches_the_phones_without_details() {
    let keys = tempfile::tempdir().expect("tempdir");
    let (apns_config, public, mut rx) = mock_apns(keys.path()).await;
    let server = TestServer::start_with(|c| c.push.apns = Some(apns_config)).await;
    let creds = server.signup("ana@example.com", "pw").await;
    let laptop = server.login(&creds, "laptop").await;
    let phone = server.login(&creds, "iPhone").await;
    let res = server
        .put_auth(&phone, "/v1/devices/current/push")
        .json(&json!({"token": PHONE, "environment": "sandbox"}))
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let check = |got: Delivered, title: &str, body: &str| {
        assert_eq!(got.token, PHONE);
        check_jwt(&got.headers, &public);
        assert_eq!(got.body["klav"], json!({"type": "account"}));
        assert_eq!(got.body["aps"]["alert"]["title-loc-key"], title);
        assert_eq!(got.body["aps"]["alert"]["loc-key"], body);
        assert!(got.body["aps"]["alert"].get("body").is_none());
        // Nothing replaces the notice that a deletion was asked.
        assert!(got.headers.get("apns-collapse-id").is_none());
        let text = got.body.to_string();
        assert!(!text.contains("ana@example.com") && !text.contains("laptop"));
        got
    };
    server.ask_deletion(&laptop, &creds).await;
    let got = check(
        next(&mut rx).await,
        "PUSH_ACCOUNT_DELETION_TITLE",
        "PUSH_ACCOUNT_DELETION_BODY",
    );
    let expiry: i64 = got.headers["apns-expiration"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(expiry >= common::agent::now_ms() / 1000 + 7 * 24 * 3600 - 60);
    assert_eq!(
        server.cancel_deletion(&laptop).await,
        StatusCode::NO_CONTENT
    );
    check(
        next(&mut rx).await,
        "PUSH_ACCOUNT_CANCELED_TITLE",
        "PUSH_ACCOUNT_CANCELED_BODY",
    );
    let asked = server.ask_deletion(&laptop, &creds).await;
    next(&mut rx).await;
    server
        .server_handle()
        .purge_expired(asked.delete_at)
        .await
        .unwrap();
    check(
        next(&mut rx).await,
        "PUSH_ACCOUNT_DELETED_TITLE",
        "PUSH_ACCOUNT_DELETED_BODY",
    );
    let db = server.raw_db().await;
    let tokens: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM push_tokens")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(tokens, 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), rx.recv())
            .await
            .is_err(),
        "one notice per event"
    );
}

#[tokio::test]
async fn a_bad_key_file_stops_the_server_from_starting() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("AuthKey.p8");
    std::fs::write(
        &path,
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
    )
    .expect("write");
    let mut config = klav_server::Config {
        database_url: format!("sqlite://{}", dir.path().join("db.sqlite").display()),
        data_dir: dir.path().join("data"),
        ..klav_server::Config::default()
    };
    config.push.apns = Some(ApnsConfig {
        key_path: Some(path),
        key: None,
        key_id: "K".into(),
        team_id: "T".into(),
        topic: "dev.klav.ios".into(),
        endpoint_override: None,
    });
    let err = klav_server::Server::new(config)
        .await
        .err()
        .expect("refused");
    let message = err.to_string();
    assert!(message.contains("not a PKCS#8"), "{message}");
}

#[tokio::test]
async fn a_bad_key_in_the_variable_stops_the_server_without_echoing_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pem = "-----BEGIN PRIVATE KEY-----\nS3NTINELb64AAAA\n-----END PRIVATE KEY-----\n";
    let mut config = klav_server::Config::load(
        None,
        [
            ("KLAV_APNS_KEY", pem),
            ("KLAV_APNS_KEY_ID", "K"),
            ("KLAV_APNS_TEAM_ID", "T"),
            ("KLAV_APNS_TOPIC", "dev.klav.ios"),
        ]
        .map(|(k, v)| (k.to_owned(), v.to_owned())),
    )
    .expect("config");
    config.database_url = format!("sqlite://{}", dir.path().join("db.sqlite").display());
    config.data_dir = dir.path().join("data");
    assert!(!format!("{config:?}").contains("S3NTINEL"));
    let err = klav_server::Server::new(config)
        .await
        .err()
        .expect("refused");
    let message = err.to_string();
    assert!(message.contains("not a PKCS#8"), "{message}");
    assert!(!message.contains("S3NTINEL"), "{message}");
    assert!(!format!("{err:?}").contains("S3NTINEL"));
}
