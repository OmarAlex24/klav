//! Deleting an account from the apps (ADR 0037): the master password again
//! through OPAQUE bound to the session and the purpose, 7 days to cancel
//! from any device, agents cut off at once, and a purge that leaves no row
//! naming the account, its devices or its agents, and no file.
//!
//! Each test names the threat it covers (`docs/modelo-de-amenazas.md`
//! §5.18).

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use common::TestServer;
use common::agent::{TestAgent, now_ms};
use common::client::{Credentials, Session};
use common::vault::{TestProject, TestVault, login_item};
use klav_core::crypto::kdf::{KdfParams, MasterPassword, derive_account_keys};
use klav_core::crypto::opaque;
use klav_core::crypto::secret_key::SecretKey;
use klav_core::policy::Policy;
use klav_proto::agent::{AgentMe, PendingApproval};
use klav_proto::auth::{
    AccountInfo, DeviceInfo, DeviceKind, LoginFinishRequest, LoginStartRequest, LoginStartResponse,
    PreloginRequest, PreloginResponse,
};
use klav_proto::sync::SyncState;
use klav_proto::task::PendingTask;
use klav_proto::{Blob, HealthResponse};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

const DAY_MS: i64 = 24 * 3600 * 1000;

async fn account_info(server: &TestServer, session: &Session) -> AccountInfo {
    let res = server
        .get_auth(session, "/v1/account")
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::OK);
    res.json().await.expect("account")
}

async fn sync_state(server: &TestServer, session: &Session) -> SyncState {
    let res = server
        .get_auth(session, "/v1/sync")
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::OK);
    res.json().await.expect("sync")
}

async fn error_json(res: reqwest::Response, status: StatusCode) -> Value {
    assert_eq!(res.status(), status);
    res.json().await.expect("error body")
}

/// An agent of `session`'s account, approved for `vault`/`project`.
async fn approved_agent(
    server: &TestServer,
    session: &Session,
    email: &str,
    vault: &TestVault,
    project: &TestProject,
) -> TestAgent {
    let agent = TestAgent::new();
    server.register_agent_ok(&agent, email, "bot").await;
    let grant = TestServer::build_grant(session, &agent, 1, Policy::default(), &[(vault, project)]);
    assert_eq!(
        server.post_grant(session, &agent, &grant).await.status(),
        StatusCode::OK
    );
    agent
}

/// A login's handle and the KE3 that would finish it.
async fn login_handle(server: &TestServer, creds: &Credentials) -> (String, Vec<u8>) {
    let prelogin: PreloginResponse = server
        .post_ok(
            "/v1/auth/prelogin",
            &PreloginRequest {
                email: creds.email.clone(),
            },
        )
        .await;
    let params =
        KdfParams::decode_insecure_for_tests(prelogin.kdf_params.as_bytes()).expect("params");
    let keys = derive_account_keys(
        &MasterPassword::new(&creds.password),
        &SecretKey::parse(&creds.secret_key_text).expect("secret key"),
        &params,
    )
    .expect("derive");
    let (client, ke1) = opaque::client_start_login(keys.opaque_input()).expect("ke1");
    let start: LoginStartResponse = server
        .post_ok(
            "/v1/auth/login/start",
            &LoginStartRequest {
                email: creds.email.clone(),
                credential_request: Blob::new(ke1),
            },
        )
        .await;
    let ke3 = client
        .finish(keys.opaque_input(), start.credential_response.as_bytes())
        .expect("ke3");
    (start.login_id, ke3)
}

async fn login_finish(server: &TestServer, handle: &str, ke3: &[u8]) -> StatusCode {
    server
        .post_json(
            "/v1/auth/login/finish",
            &LoginFinishRequest {
                login_id: handle.into(),
                credential_finalization: Blob::new(ke3.to_vec()),
                device: DeviceInfo {
                    id: None,
                    name: "tablet".into(),
                    kind: DeviceKind::Other,
                },
            },
        )
        .await
        .status()
}

#[tokio::test]
async fn asking_schedules_the_deletion_in_seven_days_and_every_device_sees_it() {
    let server = TestServer::start().await;
    let health: HealthResponse = server
        .http
        .get(server.url("/v1/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health.account_deletion, Some(true));

    let creds = server.signup("ana@example.com", "pw").await;
    let laptop = server.login(&creds, "laptop").await;
    let phone = server.login(&creds, "iPhone").await;
    assert!(account_info(&server, &laptop).await.deletion.is_none());

    let before = now_ms();
    let asked = server.ask_deletion(&phone, &creds).await;
    assert!(asked.requested_at >= before && asked.requested_at <= now_ms());
    assert_eq!(asked.delete_at, asked.requested_at + 7 * DAY_MS);
    assert_eq!(asked.device_id, phone.device_id);
    assert_eq!(asked.device_name, "iPhone");

    // The other device learns it from the account and on sync.
    assert_eq!(
        account_info(&server, &laptop).await.deletion,
        Some(asked.clone())
    );
    assert_eq!(
        sync_state(&server, &laptop).await.deletion,
        Some(asked.clone())
    );
    // Everything else keeps working for the person meanwhile.
    let vault = server.create_vault(&laptop).await;
    let project = server.create_project(&laptop, &vault).await;
    server
        .create_item(
            &laptop,
            &vault,
            &project,
            &login_item("GitHub", "ana", "pw"),
        )
        .await;
    // A new device can still sign in, to cancel from it.
    let tablet = server.login(&creds, "tablet").await;
    assert_eq!(account_info(&server, &tablet).await.deletion, Some(asked));
    // The account still exists: its e-mail cannot sign up again.
    assert_eq!(
        server.try_signup("ana@example.com", "other").await.err(),
        Some(StatusCode::CONFLICT)
    );
    // One deletion at a time: a second one is refused before the password.
    let res = server
        .reauth_start(&laptop, &creds, &creds.password)
        .await
        .expect_err("already scheduled");
    error_json(res, StatusCode::CONFLICT).await;

    // Any device cancels it, once.
    assert_eq!(
        server.cancel_deletion(&tablet).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(server.cancel_deletion(&laptop).await, StatusCode::NOT_FOUND);
    assert!(account_info(&server, &phone).await.deletion.is_none());
    assert!(sync_state(&server, &phone).await.deletion.is_none());
}

/// T162: a wrong password is refused with `403 reauth_failed`, never a
/// `401` that a client would take for the end of the session.
#[tokio::test]
async fn a_wrong_password_is_reauth_failed_and_keeps_the_session() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let laptop = server.login(&creds, "laptop").await;
    let (handle, ke3) = server
        .reauth_start(&laptop, &creds, "not the password")
        .await
        .expect("start");
    let body = error_json(
        server.reauth_finish(&laptop, &handle, &ke3).await,
        StatusCode::FORBIDDEN,
    )
    .await;
    assert_eq!(body["error"], "reauth_failed");
    // Nothing is scheduled, and the session is fine.
    assert!(account_info(&server, &laptop).await.deletion.is_none());
    // An unknown handle answers the same.
    let body = error_json(
        server.reauth_finish(&laptop, "del_nope", &ke3).await,
        StatusCode::FORBIDDEN,
    )
    .await;
    assert_eq!(body["error"], "reauth_failed");
}

/// T166: the proof is bound to the session and the purpose, and is spent
/// on its first use.
#[tokio::test]
async fn a_handle_finishes_only_the_deletion_of_its_own_session() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let laptop = server.login(&creds, "laptop").await;
    let phone = server.login(&creds, "iPhone").await;

    // A login's handle, with a valid KE3, cannot finish a deletion; and
    // that use spends it.
    let (login, ke3) = login_handle(&server, &creds).await;
    let body = error_json(
        server.reauth_finish(&laptop, &login, &ke3).await,
        StatusCode::FORBIDDEN,
    )
    .await;
    assert_eq!(body["error"], "reauth_failed");
    assert_eq!(
        login_finish(&server, &login, &ke3).await,
        StatusCode::UNAUTHORIZED
    );

    // A deletion's handle cannot open a session; and that use spends it.
    let (handle, ke3) = server
        .reauth_start(&laptop, &creds, &creds.password)
        .await
        .expect("start");
    assert_eq!(
        login_finish(&server, &handle, &ke3).await,
        StatusCode::UNAUTHORIZED
    );
    error_json(
        server.reauth_finish(&laptop, &handle, &ke3).await,
        StatusCode::FORBIDDEN,
    )
    .await;

    // Another session of the same account cannot finish it either.
    let (handle, ke3) = server
        .reauth_start(&laptop, &creds, &creds.password)
        .await
        .expect("start");
    error_json(
        server.reauth_finish(&phone, &handle, &ke3).await,
        StatusCode::FORBIDDEN,
    )
    .await;
    error_json(
        server.reauth_finish(&laptop, &handle, &ke3).await,
        StatusCode::FORBIDDEN,
    )
    .await;
    assert!(account_info(&server, &laptop).await.deletion.is_none());

    // The right one works once; replaying it is refused.
    let (handle, ke3) = server
        .reauth_start(&laptop, &creds, &creds.password)
        .await
        .expect("start");
    assert_eq!(
        server.reauth_finish(&laptop, &handle, &ke3).await.status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        server.cancel_deletion(&laptop).await,
        StatusCode::NO_CONTENT
    );
    let body = error_json(
        server.reauth_finish(&laptop, &handle, &ke3).await,
        StatusCode::FORBIDDEN,
    )
    .await;
    assert_eq!(body["error"], "reauth_failed");
    assert!(account_info(&server, &laptop).await.deletion.is_none());
}

/// T164: only a person's session reaches the routes; an agent's signed
/// request never does.
#[tokio::test]
async fn an_agent_cannot_reach_the_deletion_routes() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let agent = approved_agent(&server, &ana, "ana@example.com", &vault, &project).await;
    for (path, body) in [
        (
            "/v1/account/delete/start",
            json!({"credential_request": "AAAA"}),
        ),
        (
            "/v1/account/delete/finish",
            json!({"handle": "del_x", "credential_finalization": "AAAA"}),
        ),
        ("/v1/account/delete/cancel", json!({})),
    ] {
        let res = server
            .agent_call(&agent, Method::POST, path, Some(&body))
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{path}");
        let res = server
            .http
            .post(server.url(path))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
}

/// T164: while the deletion is asked for, every agent is refused with
/// `403 account_deleting` (but `me`, which says why), new registrations are
/// dropped without a word, and canceling brings the agents back.
#[tokio::test]
async fn agents_stop_at_once_and_come_back_when_it_is_canceled() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let item = login_item("GitHub", "ana", "hunter2");
    server.create_item(&ana, &vault, &project, &item).await;
    let agent = approved_agent(&server, &ana, "ana@example.com", &vault, &project).await;
    let body = json!({"item_id": item.id(), "permission": "inject", "reason": "deploy"});
    let inject = || server.agent_call(&agent, Method::POST, "/v1/agent/access", Some(&body));
    assert_eq!(inject().await.status(), StatusCode::OK);

    let asked = server.ask_deletion(&ana, &creds).await;
    for res in [
        inject().await,
        server
            .agent_call(&agent, Method::GET, "/v1/agent/items", None)
            .await,
    ] {
        let body = error_json(res, StatusCode::FORBIDDEN).await;
        assert_eq!(body["error"], "account_deleting");
        assert_eq!(body["delete_at"], asked.delete_at);
    }
    let res = server
        .agent_call(&agent, Method::GET, "/v1/agent/me", None)
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let me: AgentMe = res.json().await.unwrap();
    assert_eq!(me.account_delete_at, Some(asked.delete_at));

    // A new agent asking to register gets the usual answer, and nothing is
    // stored (anyone who knows the e-mail must not learn it is going).
    let newcomer = TestAgent::new();
    server
        .register_agent_ok(&newcomer, "ana@example.com", "newcomer")
        .await;
    let db = server.raw_db().await;
    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agents WHERE id = $1")
        .bind(newcomer.id.to_string())
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(stored, 0);

    assert_eq!(server.cancel_deletion(&ana).await, StatusCode::NO_CONTENT);
    assert_eq!(inject().await.status(), StatusCode::OK);
    let me: AgentMe = server
        .agent_call(&agent, Method::GET, "/v1/agent/me", None)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(me.account_delete_at, None);
}

/// T163: at most 5 reauthentications per account and hour, and at most 3
/// deletions asked per account in 7 days.
#[tokio::test]
async fn asking_over_and_over_is_limited() {
    let server = TestServer::start().await;
    let ana_creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&ana_creds, "laptop").await;
    for _ in 0..5 {
        server
            .reauth_start(&ana, &ana_creds, "wrong")
            .await
            .expect("within the hourly budget");
    }
    let res = server
        .reauth_start(&ana, &ana_creds, &ana_creds.password)
        .await
        .expect_err("over the hourly budget");
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(res.headers().contains_key("retry-after"));

    let bob_creds = server.signup("bob@example.com", "pw").await;
    let bob = server.login(&bob_creds, "laptop").await;
    for _ in 0..3 {
        server.ask_deletion(&bob, &bob_creds).await;
        assert_eq!(server.cancel_deletion(&bob).await, StatusCode::NO_CONTENT);
    }
    let res = server
        .reauth_start(&bob, &bob_creds, &bob_creds.password)
        .await
        .expect_err("three a week");
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
}

/// T163, §2: a cancel that commits before the purge's step for the
/// account always wins, even when the purge already listed the account as
/// due: the step looks again under the account's lock. Deterministic: the
/// listing, the cancel and the step run one after the other.
#[tokio::test]
async fn a_cancel_before_the_purge_step_always_wins() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let asked = server.ask_deletion(&ana, &creds).await;
    let later = asked.delete_at + 1000;
    // The purge listed it as due…
    let db = server.raw_db().await;
    let listed: Vec<String> =
        sqlx::query_scalar("SELECT account_id FROM account_deletions WHERE delete_at <= $1")
            .bind(later)
            .fetch_all(&db)
            .await
            .unwrap();
    assert_eq!(listed, vec![creds.account_id.to_string()]);
    // …then the person canceled…
    assert_eq!(server.cancel_deletion(&ana).await, StatusCode::NO_CONTENT);
    // …and the step for that account deletes nothing.
    let deleted = server
        .server_handle()
        .purge_account(creds.account_id, later)
        .await
        .unwrap();
    assert!(!deleted, "a canceled deletion went ahead");
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts WHERE id = $1")
        .bind(creds.account_id.to_string())
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(exists, 1);
    assert_eq!(
        account_info(&server, &ana).await.deletion,
        None,
        "the session still works"
    );
    // A whole purge later agrees.
    let report = server.server_handle().purge_expired(later).await.unwrap();
    assert_eq!(report.accounts, 0);
}

/// The other order: once the purge's step deleted the account, a cancel
/// finds no session (the account is gone), never half an account.
#[tokio::test]
async fn a_cancel_after_the_purge_step_finds_no_account() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let asked = server.ask_deletion(&ana, &creds).await;
    let deleted = server
        .server_handle()
        .purge_account(creds.account_id, asked.delete_at)
        .await
        .unwrap();
    assert!(deleted);
    assert_eq!(server.cancel_deletion(&ana).await, StatusCode::UNAUTHORIZED);
}

/// Cancels racing the purge, many at once: whichever side wins, each
/// account is either canceled and kept or deleted, and the report counts
/// exactly the deleted ones. Which side wins is up to the scheduler; the
/// two tests above fix the order.
#[tokio::test]
async fn cancels_racing_the_purge_leave_each_account_whole_or_gone() {
    let server = TestServer::start_with(|c| {
        c.rate_limit.ip_burst = 10_000;
    })
    .await;
    let mut people = Vec::new();
    for i in 0..8 {
        let creds = server.signup(&format!("p{i}@example.com"), "pw").await;
        let session = server.login(&creds, "laptop").await;
        server.ask_deletion(&session, &creds).await;
        people.push((creds, session));
    }
    let later = now_ms() + 7 * DAY_MS + 1000;
    let (purged, canceled) = tokio::join!(
        server.server_handle().purge_expired(later),
        futures_util::future::join_all(
            people
                .iter()
                .rev()
                .map(|(_, session)| server.cancel_deletion(session))
        )
    );
    let purged = purged.unwrap();
    let db = server.raw_db().await;
    let mut gone = 0;
    for ((creds, _), status) in people.iter().rev().zip(canceled) {
        let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts WHERE id = $1")
            .bind(creds.account_id.to_string())
            .fetch_one(&db)
            .await
            .unwrap();
        match status {
            StatusCode::NO_CONTENT => assert_eq!(exists, 1, "canceled, then deleted"),
            // Deleted first: the session no longer exists.
            StatusCode::UNAUTHORIZED => {
                assert_eq!(exists, 0);
                gone += 1;
            }
            other => panic!("cancel: {other}"),
        }
    }
    assert_eq!(purged.accounts, gone);
}

/// Review finding 4: one account whose deletion keeps failing does not
/// stop the purge. The others due are deleted, the trash is still
/// purged, and the failing one is tried again at the next run.
#[tokio::test]
async fn one_failing_account_does_not_stop_the_purge() {
    let server = TestServer::start_with(|c| {
        c.rate_limit.ip_burst = 10_000;
        c.rate_limit.account_burst = 10_000;
    })
    .await;
    let stuck = server.signup("stuck@example.com", "pw").await;
    let stuck_session = server.login(&stuck, "laptop").await;
    let ana = server.signup("ana@example.com", "pw").await;
    let ana_session = server.login(&ana, "laptop").await;
    let bob = server.signup("bob@example.com", "pw").await;
    let bob_session = server.login(&bob, "laptop").await;
    // The stuck account is due first, so the purge meets it first.
    let first = server.ask_deletion(&stuck_session, &stuck).await;
    let second = server.ask_deletion(&ana_session, &ana).await;
    assert!(first.delete_at <= second.delete_at);
    // Bob keeps his account and has an item long in the trash.
    let vault = server.create_vault(&bob_session).await;
    let project = server.create_project(&bob_session, &vault).await;
    let item = login_item("old", "bob", "pw");
    server
        .create_item(&bob_session, &vault, &project, &item)
        .await;
    let res = server
        .delete_auth(
            &bob_session,
            &format!("/v1/vaults/{}/items/{}", vault.id, item.id()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let db = server.raw_db().await;
    sqlx::query("UPDATE items SET trashed_at = 1")
        .execute(&db)
        .await
        .unwrap();
    // The database refuses to delete the stuck account.
    let stuck_id = stuck.account_id.to_string();
    if server.database_url.starts_with("postgres") {
        sqlx::query(
            "CREATE FUNCTION klav_test_refuse() RETURNS trigger AS $$ \
             BEGIN RAISE EXCEPTION 'refused by the test'; END; $$ LANGUAGE plpgsql",
        )
        .execute(&db)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER klav_test_refuse BEFORE DELETE ON accounts FOR EACH ROW \
             WHEN (OLD.email = 'stuck@example.com') EXECUTE FUNCTION klav_test_refuse()",
        )
        .execute(&db)
        .await
        .unwrap();
    } else {
        sqlx::query(
            "CREATE TRIGGER klav_test_refuse BEFORE DELETE ON accounts \
             WHEN OLD.email = 'stuck@example.com' \
             BEGIN SELECT RAISE(ABORT, 'refused by the test'); END",
        )
        .execute(&db)
        .await
        .unwrap();
    }
    let count = |id: String| {
        let db = db.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM accounts WHERE id = $1")
                .bind(id)
                .fetch_one(&db)
                .await
                .unwrap()
        }
    };

    let later = second.delete_at + 1000;
    let report = server.server_handle().purge_expired(later).await.unwrap();
    assert_eq!(report.accounts, 1, "the other due account is deleted");
    assert_eq!(report.items, 1, "the trash is still purged");
    assert_eq!(count(stuck_id.clone()).await, 1, "the stuck one stays");
    assert_eq!(count(ana.account_id.to_string()).await, 0);
    assert_eq!(count(bob.account_id.to_string()).await, 1);
    // Nothing of the stuck account was half deleted, and its lock is free:
    // its session still answers.
    assert_eq!(
        account_info(&server, &stuck_session).await.deletion,
        Some(first.clone())
    );

    // Fixed: the next run deletes it.
    let drop = if server.database_url.starts_with("postgres") {
        "DROP TRIGGER klav_test_refuse ON accounts"
    } else {
        "DROP TRIGGER klav_test_refuse"
    };
    sqlx::query(drop).execute(&db).await.unwrap();
    let report = server.server_handle().purge_expired(later).await.unwrap();
    assert_eq!(report.accounts, 1);
    assert_eq!(count(stuck_id).await, 0);
}

/// T167: the event streams of the account close at once, and a login in
/// progress cannot finish after it.
#[tokio::test]
async fn nothing_in_memory_outlives_the_account() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let mut events = server
        .get_auth(&ana, "/v1/events")
        .send()
        .await
        .expect("events");
    assert_eq!(events.status(), StatusCode::OK);
    let ready = tokio::time::timeout(Duration::from_secs(5), events.chunk())
        .await
        .expect("ready in time")
        .unwrap()
        .expect("a first event");
    assert!(String::from_utf8_lossy(&ready).contains("ready"));
    let (login, ke3) = login_handle(&server, &creds).await;

    let asked = server.ask_deletion(&ana, &creds).await;
    let report = server
        .server_handle()
        .purge_expired(asked.delete_at - 1)
        .await
        .unwrap();
    assert_eq!(report.accounts, 0, "not due yet");
    let report = server
        .server_handle()
        .purge_expired(asked.delete_at)
        .await
        .unwrap();
    assert_eq!(report.accounts, 1);

    // The stream ends well before its 30 s session check.
    let ended = tokio::time::timeout(Duration::from_secs(5), async {
        while events.chunk().await.ok().flatten().is_some() {}
    })
    .await;
    assert!(ended.is_ok(), "the event stream is still open");
    // The login started before the deletion is forgotten (not a 500).
    assert_eq!(
        login_finish(&server, &login, &ke3).await,
        StatusCode::UNAUTHORIZED
    );
}

// ------------------------------------------------- every table, every file

/// Tables that belong to the server, not to any account.
const SERVER_TABLES: &[&str] = &["server_state", "_sqlx_migrations"];
/// Columns that name an account, a device or an agent (ADR 0037 §5.2).
const NAMING_COLUMNS: &[&str] = &[
    "account_id",
    "owner_account_id",
    "member_id",
    "device_id",
    "agent_id",
    "author_agent_id",
];
/// Naming columns without an `ON DELETE CASCADE` foreign key, and why their
/// rows still go. A new one has to be added here, with its reason, or the
/// test fails.
const WITHOUT_CASCADE: &[(&str, &str, &str)] = &[
    (
        "vault_members",
        "member_id",
        "deleted explicitly by member_type and member_id before the account",
    ),
    (
        "audit_events",
        "agent_id",
        "an agent of the same account: the row goes with account_id",
    ),
    (
        "audit_heads",
        "device_id",
        "a device of the same account: the row goes with account_id",
    ),
    (
        "agent_pauses",
        "device_id",
        "a device of the same account: the row goes with account_id",
    ),
    (
        "items",
        "author_agent_id",
        "an agent of the vault's owner: the row goes with the vault",
    ),
    (
        "item_versions",
        "author_agent_id",
        "an agent of the vault's owner: the row goes with its item",
    ),
    (
        "account_deletions",
        "device_id",
        "a device of the same account: the row goes with account_id",
    ),
    (
        "sandbox_revocations",
        "device_id",
        "a device of the same account: the row goes with account_id",
    ),
];

struct Column {
    name: String,
    text: bool,
}

struct ForeignKey {
    column: String,
    table: String,
    cascade: bool,
}

struct Table {
    name: String,
    columns: Vec<Column>,
    foreign_keys: Vec<ForeignKey>,
}

/// Column names and types, as the database reports them.
type RawColumns = Vec<(String, String)>;
/// Foreign keys as (column, referenced table, delete rule).
type RawForeignKeys = Vec<(String, String, String)>;

/// Every table of the database, discovered (`sqlite_master` and its
/// pragmas, or `information_schema` on Postgres).
async fn schema(db: &sqlx::AnyPool, postgres: bool) -> Vec<Table> {
    let names: Vec<String> = if postgres {
        sqlx::query_scalar(
            "SELECT CAST(table_name AS TEXT) FROM information_schema.tables \
             WHERE table_schema = current_schema() AND table_type = 'BASE TABLE' ORDER BY 1",
        )
        .fetch_all(db)
        .await
        .expect("database")
    } else {
        sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'table' \
             AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .fetch_all(db)
        .await
        .expect("database")
    };
    let mut tables = Vec::new();
    for name in names {
        let (columns, foreign_keys): (RawColumns, RawForeignKeys) = if postgres {
            (
                sqlx::query_as(
                    "SELECT CAST(column_name AS TEXT), CAST(data_type AS TEXT) \
                         FROM information_schema.columns \
                         WHERE table_schema = current_schema() AND table_name = $1",
                )
                .bind(&name)
                .fetch_all(db)
                .await
                .expect("database"),
                sqlx::query_as(
                    "SELECT CAST(k.column_name AS TEXT), CAST(u.table_name AS TEXT), \
                         CAST(r.delete_rule AS TEXT) \
                         FROM information_schema.referential_constraints r \
                         JOIN information_schema.key_column_usage k \
                           ON k.constraint_schema = r.constraint_schema \
                          AND k.constraint_name = r.constraint_name \
                         JOIN information_schema.constraint_column_usage u \
                           ON u.constraint_schema = r.unique_constraint_schema \
                          AND u.constraint_name = r.unique_constraint_name \
                         WHERE k.table_schema = current_schema() AND k.table_name = $1",
                )
                .bind(&name)
                .fetch_all(db)
                .await
                .expect("database"),
            )
        } else {
            (
                sqlx::query_as("SELECT name, type FROM pragma_table_info($1)")
                    .bind(&name)
                    .fetch_all(db)
                    .await
                    .expect("database"),
                sqlx::query_as(
                    "SELECT \"from\", \"table\", on_delete FROM pragma_foreign_key_list($1)",
                )
                .bind(&name)
                .fetch_all(db)
                .await
                .expect("database"),
            )
        };
        tables.push(Table {
            name,
            columns: columns
                .into_iter()
                .map(|(name, kind)| Column {
                    name,
                    text: kind.eq_ignore_ascii_case("text"),
                })
                .collect(),
            foreign_keys: foreign_keys
                .into_iter()
                .map(|(column, table, rule)| ForeignKey {
                    column,
                    table,
                    cascade: rule.eq_ignore_ascii_case("cascade"),
                })
                .collect(),
        });
    }
    tables
}

/// The schema itself guarantees the cascade: every table but the server's
/// reaches `accounts` through `ON DELETE CASCADE` foreign keys, and every
/// column that names an account, a device or an agent is one of those
/// keys or is listed, with its reason, in [`WITHOUT_CASCADE`]. A new table
/// without its foreign key fails here even if no test ever fills it.
fn check_schema(tables: &[Table]) {
    let names: BTreeSet<&str> = tables.iter().map(|t| t.name.as_str()).collect();
    for table in SERVER_TABLES.iter().chain(["accounts"].iter()) {
        assert!(names.contains(table), "table {table} not found");
    }
    let mut reached: BTreeSet<&str> = BTreeSet::from(["accounts"]);
    loop {
        let before = reached.len();
        for table in tables {
            if table
                .foreign_keys
                .iter()
                .any(|fk| fk.cascade && reached.contains(fk.table.as_str()))
            {
                reached.insert(&table.name);
            }
        }
        if reached.len() == before {
            break;
        }
    }
    let orphans: Vec<&str> = names
        .iter()
        .copied()
        .filter(|t| !reached.contains(t) && !SERVER_TABLES.contains(t))
        .collect();
    assert!(
        orphans.is_empty(),
        "tables that deleting an account does not reach through ON DELETE CASCADE: {orphans:?}"
    );

    let mut unexplained = Vec::new();
    for table in tables {
        for column in &table.columns {
            if !NAMING_COLUMNS.contains(&column.name.as_str()) {
                continue;
            }
            let cascades = table
                .foreign_keys
                .iter()
                .any(|fk| fk.column == column.name && fk.cascade);
            let listed = WITHOUT_CASCADE
                .iter()
                .any(|(t, c, _)| *t == table.name && *c == column.name);
            if !cascades && !listed {
                unexplained.push(format!("{}.{}", table.name, column.name));
            }
        }
    }
    assert!(
        unexplained.is_empty(),
        "columns naming an account, device or agent without ON DELETE CASCADE: {unexplained:?}"
    );
    // The list does not rot: each entry still exists and still has no
    // cascading key.
    for (table, column, _) in WITHOUT_CASCADE {
        let found = tables
            .iter()
            .find(|t| t.name == *table)
            .unwrap_or_else(|| panic!("{table} no longer exists"));
        assert!(
            found.columns.iter().any(|c| c.name == *column),
            "{table}.{column} no longer exists"
        );
        assert!(
            !found
                .foreign_keys
                .iter()
                .any(|fk| fk.column == *column && fk.cascade),
            "{table}.{column} cascades now: drop it from WITHOUT_CASCADE"
        );
    }
}

/// Every `id` of every table that has one.
async fn all_ids(db: &sqlx::AnyPool, tables: &[Table]) -> BTreeMap<String, BTreeSet<String>> {
    let mut ids = BTreeMap::new();
    for table in tables {
        if !table.columns.iter().any(|c| c.name == "id" && c.text) {
            continue;
        }
        let found: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT id FROM \"{}\"",
            table.name
        )))
        .fetch_all(db)
        .await
        .expect("database");
        ids.insert(table.name.clone(), found.into_iter().collect());
    }
    ids
}

/// The rows (`table.column`) whose text contains one of `ids`.
async fn rows_naming(db: &sqlx::AnyPool, tables: &[Table], ids: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    for table in tables {
        for column in table.columns.iter().filter(|c| c.text) {
            for chunk in ids.chunks(50) {
                let conditions: Vec<String> = (1..=chunk.len())
                    .map(|i| format!("\"{}\" LIKE ${i}", column.name))
                    .collect();
                let sql = format!(
                    "SELECT COUNT(*) FROM \"{}\" WHERE {}",
                    table.name,
                    conditions.join(" OR ")
                );
                let mut query = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql));
                for id in chunk {
                    query = query.bind(format!("%{id}%"));
                }
                let count = query.fetch_one(db).await.expect("database");
                if count > 0 {
                    found.push(format!("{}.{} ({count})", table.name, column.name));
                }
            }
        }
    }
    found
}

/// Fills as many tables as the account can reach: two devices with a push
/// token, a vault with an item, a version and a file, an approved agent
/// with nonces, a pending approval, a pending task with its targets and a
/// password change, an audit head, a pause decision, items written by the
/// agent, and a membership in someone else's vault.
async fn fill(server: &TestServer, creds: &Credentials) -> (Session, TestVault) {
    let laptop = server.login(creds, "laptop").await;
    let phone = server.login(creds, "iPhone").await;
    let res = server
        .put_auth(&phone, "/v1/devices/current/push")
        // One token per account: a token another account's device holds
        // is refused.
        .json(
            &json!({"token": creds.account_id.to_string().replace('-', ""),
                      "environment": "sandbox"}),
        )
        .send()
        .await
        .expect("database");
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let vault = server.create_vault(&laptop).await;
    let project = server.create_project(&laptop, &vault).await;
    let item = login_item("GitHub", "ana", "pw");
    let (key, _) = server.create_item(&laptop, &vault, &project, &item).await;
    assert_eq!(
        server
            .put_item(&laptop, &vault, &project, &item, &key, 2)
            .await
            .status(),
        StatusCode::OK
    );
    server
        .upload_attachment(&laptop, &vault, &project, item.id(), b"a file", true)
        .await;
    let agent = approved_agent(server, &laptop, &creds.email, &vault, &project).await;
    let res = server
        .agent_call(
            &agent,
            Method::POST,
            "/v1/agent/access",
            Some(&json!({"item_id": item.id(), "permission": "update", "reason": "rotate"})),
        )
        .await;
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let _: PendingApproval = res.json().await.expect("database");
    let res = server
        .agent_call(
            &agent,
            Method::POST,
            "/v1/agent/tasks",
            Some(
                &json!({"v": 1, "task": "deploy", "reason": "run the deploy",
                "duration_secs": 600, "access": [{"vault_id": vault.id,
                "project_id": project.id, "item_id": item.id(), "permissions": ["inject"]}]}),
            ),
        )
        .await;
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let task: PendingTask = res.json().await.expect("database");

    // What no route lets a test reach quickly goes in directly.
    let db = server.raw_db().await;
    let target = json!(["inject", vault.id, project.id, item.id()]).to_string();
    sqlx::query("INSERT INTO task_targets (task_id, target_key, hosts) VALUES ($1, $2, '[]')")
        .bind(task.pending_task_id.to_string())
        .bind(target)
        .execute(&db)
        .await
        .expect("database");
    sqlx::query(
        "INSERT INTO rotations (id, account_id, agent_id, task_id, vault_id, project_id, \
         item_id, host, status, started_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(klav_core::ids::VaultId::generate().to_string())
    .bind(creds.account_id.to_string())
    .bind(agent.id.to_string())
    .bind(task.pending_task_id.to_string())
    .bind(vault.id.to_string())
    .bind(project.id.to_string())
    .bind(item.id().to_string())
    .bind("github.com")
    .bind("cancelled")
    .bind(now_ms())
    .execute(&db)
    .await
    .expect("database");
    sqlx::query(
        "INSERT INTO audit_heads (account_id, seq, hash, signature, device_id, signed_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(creds.account_id.to_string())
    .bind(1_i64)
    .bind(vec![0_u8; 32])
    .bind(vec![0_u8; 64])
    .bind(laptop.device_id.to_string())
    .bind(now_ms())
    .execute(&db)
    .await
    .expect("database");
    // A sandbox the agent issued to itself: the proxy and the issuer are
    // agents of the same account (ADR 0036 §4).
    let sandbox = klav_core::ids::SandboxId::generate().to_string();
    sqlx::query(
        "INSERT INTO sandboxes (id, account_id, proxy_id, issuer_id, expires_at, issued_at) \
         VALUES ($1, $2, $3, $3, $4, $4)",
    )
    .bind(&sandbox)
    .bind(creds.account_id.to_string())
    .bind(agent.id.to_string())
    .bind(now_ms())
    .execute(&db)
    .await
    .expect("database");
    // The person's side of it (migration 0019): a revocation, the
    // barrier's row, a heartbeat, a store epoch and a push.
    let (account, proxy, now) = (creds.account_id.to_string(), agent.id.to_string(), now_ms());
    sqlx::query(
        "INSERT INTO sandbox_revocations (account_id, seq, proxy_id, scope, at_ms, signature, \
         device_id, sandbox_ids, created_at) VALUES ($1, 1, $2, 'all', $3, $4, $5, '[]', $3)",
    )
    .bind(&account)
    .bind(&proxy)
    .bind(now)
    .bind(vec![0_u8; 64])
    .bind(laptop.device_id.to_string())
    .execute(&db)
    .await
    .expect("database");
    sqlx::query(
        "INSERT INTO sandbox_person_revoked (sandbox_id, account_id, proxy_id, seq, at_ms, \
         created_at) VALUES ($1, $2, $3, 1, $4, $4)",
    )
    .bind(&sandbox)
    .bind(&account)
    .bind(&proxy)
    .bind(now)
    .execute(&db)
    .await
    .expect("database");
    sqlx::query(
        "INSERT INTO sandbox_heartbeats (proxy_id, account_id, store_epoch, seq, sent_at_ms, \
         proof, received_at) VALUES ($1, $2, $3, 1, $4, $3, $4)",
    )
    .bind(&proxy)
    .bind(&account)
    .bind(vec![0_u8; 16])
    .bind(now)
    .execute(&db)
    .await
    .expect("database");
    sqlx::query(
        "INSERT INTO sandbox_store_epochs (proxy_id, epoch, account_id, seq, created_at) \
         VALUES ($1, $2, $3, 1, $4)",
    )
    .bind(&proxy)
    .bind(vec![0_u8; 16])
    .bind(&account)
    .bind(now)
    .execute(&db)
    .await
    .expect("database");
    sqlx::query(
        "INSERT INTO sandbox_pushes (sandbox_id, kind, account_id, sent_at) \
         VALUES ($1, 'sandbox_theft', $2, $3)",
    )
    .bind(&sandbox)
    .bind(&account)
    .bind(now)
    .execute(&db)
    .await
    .expect("database");
    sqlx::query(
        "INSERT INTO agent_pauses (account_id, scope, state, at_ms, until_ms, signature, \
         device_id) VALUES ($1, $2, 'resume', $3, 0, $4, $5)",
    )
    .bind(creds.account_id.to_string())
    .bind(agent.id.to_string())
    .bind(now_ms())
    .bind(vec![0_u8; 64])
    .bind(laptop.device_id.to_string())
    .execute(&db)
    .await
    .expect("database");
    // Secret request (ADR 0046, migration 0020).
    let secret_request_id = klav_core::ids::SecretRequestId::generate().to_string();
    sqlx::query(
        "INSERT INTO secret_requests (id, account_id, agent_id, mode, reason, \
         proposal_digest, proposal_blob, status, created_at, expires_at) \
         VALUES ($1, $2, $3, 'create', 'purge test', $4, $5, 'pending', $6, $7)",
    )
    .bind(&secret_request_id)
    .bind(creds.account_id.to_string())
    .bind(agent.id.to_string())
    .bind(vec![0_u8; 32])
    .bind(vec![0_u8; 32])
    .bind(now)
    .bind(now + 60_000)
    .execute(&db)
    .await
    .expect("database");
    for table in ["items", "item_versions"] {
        let column = if table == "items" { "id" } else { "item_id" };
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE {table} SET author_agent_id = $1 WHERE {column} = $2"
        )))
        .bind(agent.id.to_string())
        .bind(item.id().to_string())
        .execute(&db)
        .await
        .expect("database");
    }
    (phone, vault)
}

/// T167: after the purge, no row anywhere names the account or anything it
/// had, its files are gone from the disk, and someone else's account is
/// untouched. The tables and columns are discovered, not listed.
#[tokio::test]
async fn the_purge_leaves_no_row_and_no_file_of_the_account() {
    let server = TestServer::start_with(|c| {
        c.rate_limit.ip_burst = 10_000;
        c.rate_limit.account_burst = 10_000;
    })
    .await;
    let postgres = server.database_url.starts_with("postgres");
    let ana_creds = server.signup("ana@example.com", "pw").await;
    let bob_creds = server.signup("bob@example.com", "pw").await;
    let (_, bob_vault) = fill(&server, &bob_creds).await;
    let (ana, ana_vault) = fill(&server, &ana_creds).await;
    // Ana is also a member of Bob's vault: `member_id` has no foreign key.
    let db = server.raw_db().await;
    sqlx::query(
        "INSERT INTO vault_members (vault_id, member_type, member_id, role, shared_key, \
         revision, created_at, updated_at) VALUES ($1, 'account', $2, 'member', $3, 1, $4, $4)",
    )
    .bind(bob_vault.id.to_string())
    .bind(ana_creds.account_id.to_string())
    .bind(vec![0_u8; 32])
    .bind(now_ms())
    .execute(&db)
    .await
    .unwrap();

    let tables = schema(&db, postgres).await;
    check_schema(&tables);
    let empty: Vec<&str> = {
        let mut empty = Vec::new();
        for table in tables
            .iter()
            .filter(|t| !SERVER_TABLES.contains(&t.name.as_str()))
        {
            let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT COUNT(*) FROM \"{}\"",
                table.name
            )))
            .fetch_one(&db)
            .await
            .unwrap();
            if count == 0 {
                empty.push(table.name.as_str());
            }
        }
        empty
    };
    // Only the deletion's own table is still empty (it fills below).
    assert_eq!(
        empty,
        vec!["account_deletions"],
        "tables the test does not fill"
    );

    let asked = server.ask_deletion(&ana, &ana_creds).await;
    let before = all_ids(&db, &tables).await;
    let files = server.data_dir.path().join("data").join("attachments");
    assert!(files.join(ana_vault.id.to_string()).exists());
    assert!(files.join(bob_vault.id.to_string()).exists());

    let report = server
        .server_handle()
        .purge_expired(asked.delete_at + 1)
        .await
        .unwrap();
    assert_eq!(report.accounts, 1);

    let after = all_ids(&db, &tables).await;
    let mut gone: Vec<String> = Vec::new();
    for (table, ids) in &before {
        gone.extend(ids.difference(&after[table]).cloned());
    }
    // What Ana had is gone; what Bob has is not.
    for id in [ana_creds.account_id.to_string(), ana_vault.id.to_string()] {
        assert!(gone.contains(&id), "{id} survived");
    }
    for id in [bob_creds.account_id.to_string(), bob_vault.id.to_string()] {
        assert!(!gone.contains(&id), "{id} was deleted");
    }
    assert!(gone.contains(&ana.device_id.to_string()));
    // No text column of any table still names any of it.
    let leftovers = rows_naming(&db, &tables, &gone).await;
    assert!(
        leftovers.is_empty(),
        "rows naming the deleted account: {leftovers:?}"
    );
    // Bob's membership rows, items and agent are all still there.
    let bob_rows = rows_naming(&db, &tables, &[bob_creds.account_id.to_string()]).await;
    assert!(bob_rows.iter().any(|r| r.starts_with("agents.account_id")));
    assert!(
        bob_rows
            .iter()
            .any(|r| r.starts_with("audit_events.account_id"))
    );

    // The files, now, not at the next orphan sweep.
    assert!(!files.join(ana_vault.id.to_string()).exists());
    assert!(files.join(bob_vault.id.to_string()).exists());

    // The sessions are gone; the e-mail is free for a new, unrelated account.
    let res = server.get_auth(&ana, "/v1/account").send().await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let again = server.signup("ana@example.com", "pw").await;
    assert_ne!(again.account_id, ana_creds.account_id);
    let (res, _) = server
        .login_raw(
            &ana_creds,
            &ana_creds.password,
            DeviceInfo {
                id: None,
                name: "old kit".into(),
                kind: DeviceKind::Other,
            },
        )
        .await;
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "the old Secret Key does not open the new account"
    );
}

/// T164 and T167: an agent of a deleted account is unknown, like one the
/// server never had.
#[tokio::test]
async fn an_agent_of_a_deleted_account_is_unknown() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let agent = approved_agent(&server, &ana, "ana@example.com", &vault, &project).await;
    let asked = server.ask_deletion(&ana, &creds).await;
    server
        .server_handle()
        .purge_expired(asked.delete_at)
        .await
        .unwrap();
    for path in ["/v1/agent/me", "/v1/agent/items"] {
        let res = server.agent_call(&agent, Method::GET, path, None).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
}

/// The schema check itself: a new table that names an account without a
/// cascading foreign key fails it, even with no row in it.
#[tokio::test]
async fn the_schema_check_catches_a_table_without_its_foreign_key() {
    let server = TestServer::start().await;
    let postgres = server.database_url.starts_with("postgres");
    let db = server.raw_db().await;
    check_schema(&schema(&db, postgres).await);
    sqlx::query("CREATE TABLE stray_notes (id TEXT PRIMARY KEY, account_id TEXT NOT NULL)")
        .execute(&db)
        .await
        .unwrap();
    let tables = schema(&db, postgres).await;
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check_schema(&tables)));
    assert!(caught.is_err(), "a table without its foreign key passed");
}
