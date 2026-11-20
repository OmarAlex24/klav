//! Retention and attachments under concurrency (layer 07 of the 2026-11
//! security round): the purge never takes what the person just restored,
//! takes everything the server kept about a purged vault, removes idle
//! uploads and orphan files, and unfinished uploads have a cap.

mod common;

use common::TestServer;
use common::agent::{TestAgent, now_ms};
use common::client::Session;
use common::vault::{TestProject, TestVault, login_item};
use klav_core::crypto::agent::{self as agent_crypto, TaskDecisionToSign};
use klav_core::crypto::keys::ItemKey;
use klav_core::crypto::wrap::wrap_attachment_key;
use klav_core::ids::{AttachmentId, ItemId, TaskId};
use klav_core::policy::{Permission, Policy};
use klav_core::task::{TASK_FORMAT_VERSION, TaskAccessDecision, TaskDecision, TaskOffer};
use klav_proto::Blob;
use klav_proto::sync::CreateAttachment;
use klav_proto::task::OfferTask;
use reqwest::{Method, StatusCode};
use serde_json::json;

const DAY_MS: i64 = 24 * 3600 * 1000;

async fn account(server: &TestServer) -> (Session, TestVault, TestProject) {
    let ana = server
        .login(&server.signup("ana@example.com", "pw").await, "laptop")
        .await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    (ana, vault, project)
}

#[tokio::test]
async fn a_restored_item_is_never_purged() {
    let server = TestServer::start_with(|c| {
        c.rate_limit.ip_burst = 10_000;
        c.rate_limit.account_burst = 10_000;
    })
    .await;
    let (ana, vault, project) = account(&server).await;
    let mut ids = Vec::new();
    for i in 0..40 {
        let item = login_item(&format!("item {i}"), "ana", "pw");
        server.create_item(&ana, &vault, &project, &item).await;
        let res = server
            .delete_auth(
                &ana,
                &format!("/v1/vaults/{}/items/{}", vault.id, item.id()),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        ids.push(item.id());
    }
    // Trashed long ago: all of them are due.
    let db = server.raw_db().await;
    sqlx::query("UPDATE items SET trashed_at = 1")
        .execute(&db)
        .await
        .unwrap();

    let restore = |id: ItemId| {
        let server = &server;
        let ana = &ana;
        let vault = vault.id;
        async move {
            let res = server
                .post_auth(ana, &format!("/v1/vaults/{vault}/items/{id}/restore"))
                .send()
                .await
                .unwrap();
            (id, res.status())
        }
    };
    let (purged, restored) = tokio::join!(
        server.server_handle().purge_expired(now_ms()),
        futures_util::future::join_all(ids.iter().rev().map(|id| restore(*id)))
    );
    purged.unwrap();
    for (id, status) in restored {
        let row: (Option<i64>, Option<Vec<u8>>) =
            sqlx::query_as("SELECT purged_at, overview FROM items WHERE id = $1")
                .bind(id.to_string())
                .fetch_one(&db)
                .await
                .unwrap();
        match status {
            // Restored: it must have survived, with its contents.
            StatusCode::OK => assert!(
                row.0.is_none() && row.1.is_some(),
                "item {id} was restored and then purged"
            ),
            // Purged first: the restore found the tombstone.
            StatusCode::NOT_FOUND => assert!(row.0.is_some()),
            other => panic!("restore of {id}: {other}"),
        }
    }
}

#[tokio::test]
async fn a_restored_vault_is_never_purged() {
    let server = TestServer::start().await;
    let (ana, _, _) = account(&server).await;
    let mut vaults = Vec::new();
    for i in 0..12 {
        let vault = server.create_vault(&ana).await;
        let project = server.create_project(&ana, &vault).await;
        let item = login_item(&format!("item {i}"), "ana", "pw");
        server.create_item(&ana, &vault, &project, &item).await;
        let res = server
            .delete_auth(&ana, &format!("/v1/vaults/{}", vault.id))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        vaults.push(vault.id);
    }
    let db = server.raw_db().await;
    sqlx::query("UPDATE vaults SET deleted_at = 1 WHERE deleted_at IS NOT NULL")
        .execute(&db)
        .await
        .unwrap();
    let restore = |id: klav_core::ids::VaultId| {
        let server = &server;
        let ana = &ana;
        async move {
            let res = server
                .post_auth(ana, &format!("/v1/vaults/{id}/restore"))
                .send()
                .await
                .unwrap();
            (id, res.status())
        }
    };
    let (purged, restored) = tokio::join!(
        server.server_handle().purge_expired(now_ms()),
        futures_util::future::join_all(vaults.iter().rev().map(|id| restore(*id)))
    );
    purged.unwrap();
    for (id, status) in restored {
        let items: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM items WHERE vault_id = $1")
            .bind(id.to_string())
            .fetch_one(&db)
            .await
            .unwrap();
        match status {
            StatusCode::OK => assert_eq!(items, 1, "vault {id} was restored and then purged"),
            StatusCode::NOT_FOUND => assert_eq!(items, 0),
            other => panic!("restore of {id}: {other}"),
        }
    }
}

#[tokio::test]
async fn a_purged_vault_takes_its_approvals_and_tasks_with_it() {
    let server = TestServer::start().await;
    let (ana, vault, project) = account(&server).await;
    let item = login_item("GitHub", "ana", "pw");
    server.create_item(&ana, &vault, &project, &item).await;
    // A second vault the agent also uses: its rows stay.
    let other = server.create_vault(&ana).await;
    let other_project = server.create_project(&ana, &other).await;
    let other_item = login_item("Bank", "ana", "pw");
    server
        .create_item(&ana, &other, &other_project, &other_item)
        .await;

    let agent = TestAgent::new();
    server
        .register_agent_ok(&agent, "ana@example.com", "bot")
        .await;
    let grant = TestServer::build_grant(
        &ana,
        &agent,
        1,
        Policy::default(),
        &[(&vault, &project), (&other, &other_project)],
    );
    assert_eq!(
        server.post_grant(&ana, &agent, &grant).await.status(),
        StatusCode::OK
    );
    // `update` asks by default: one pending approval per vault.
    for id in [item.id(), other_item.id()] {
        let res = server
            .agent_call(
                &agent,
                Method::POST,
                "/v1/agent/access",
                Some(&json!({"item_id": id, "permission": "update", "reason": "rotate it"})),
            )
            .await;
        assert_eq!(res.status(), StatusCode::ACCEPTED);
    }
    // A task only about the purged vault, and one about both.
    let task = |access: serde_json::Value| {
        json!({"v": 1, "task": "deploy", "reason": "run the deploy", "duration_secs": 600,
               "access": access})
    };
    let here = json!({"vault_id": vault.id, "project_id": project.id, "item_id": item.id(),
                      "permissions": ["inject"]});
    let there = json!({"vault_id": other.id, "project_id": other_project.id,
                       "item_id": other_item.id(), "permissions": ["inject"]});
    let mut task_ids = Vec::new();
    for body in [task(json!([here])), task(json!([here, there]))] {
        let res = server
            .agent_call(&agent, Method::POST, "/v1/agent/tasks", Some(&body))
            .await;
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let pending: klav_proto::task::PendingTask = res.json().await.unwrap();
        task_ids.push(pending.pending_task_id.to_string());
    }
    // A task Ana offered (ADR 0022 §6) only about the purged vault: no
    // request, its accesses are in the decision. The agent starts a change
    // in it, which keeps the item's host in the clear.
    let offer = |decision: &TaskDecision| {
        let bytes = serde_json::to_vec(decision).unwrap();
        let decided_at = now_ms();
        let signature = agent_crypto::sign_task_decision(
            &ana.identity,
            &TaskDecisionToSign {
                task: decision.task_id,
                agent: decision.agent_id,
                request: &[],
                decision: &bytes,
                approve: true,
                decided_at_ms: u64::try_from(decided_at).unwrap(),
            },
        );
        server.post_auth(&ana, "/v1/tasks").json(&OfferTask {
            task_id: decision.task_id,
            agent_id: decision.agent_id,
            decision: Blob::new(bytes),
            decided_at,
            signature: Blob::new(signature.to_bytes().to_vec()),
        })
    };
    let offered = TaskDecision {
        v: TASK_FORMAT_VERSION,
        task_id: TaskId::generate(),
        agent_id: agent.id,
        revision: 1,
        expires_at_ms: u64::try_from(now_ms() + 3_600_000).unwrap(),
        access: vec![TaskAccessDecision {
            vault_id: vault.id,
            project_id: project.id,
            item_id: item.id(),
            permissions: vec![Permission::Rotate],
            domains: vec!["github.com".into()],
            added_by_klav: Vec::new(),
        }],
        offer: Some(TaskOffer {
            task: "Arreglar mis contraseñas repetidas".into(),
            reason: "Cada sitio con su propia contraseña".into(),
        }),
    };
    let res = offer(&offered).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let res = server
        .agent_call(
            &agent,
            Method::POST,
            "/v1/agent/rotations",
            Some(
                &json!({"item_id": item.id(), "reason": "cambiar la repetida",
                         "claims": {"domain": "github.com"}, "task_id": offered.task_id}),
            ),
        )
        .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let started: klav_proto::rotate::RotationStarted = res.json().await.unwrap();
    // Targets as an approved task would have them.
    let db = server.raw_db().await;
    let key = |v: &TestVault, p: &TestProject, i: ItemId| {
        json!(["inject", v.id.to_string(), p.id.to_string(), i.to_string()]).to_string()
    };
    for (task, target) in [
        (&task_ids[0], key(&vault, &project, item.id())),
        (&task_ids[1], key(&vault, &project, item.id())),
        (&task_ids[1], key(&other, &other_project, other_item.id())),
    ] {
        sqlx::query("INSERT INTO task_targets (task_id, target_key, hosts) VALUES ($1, $2, '[]')")
            .bind(task)
            .bind(target)
            .execute(&db)
            .await
            .unwrap();
    }

    let res = server
        .delete_auth(&ana, &format!("/v1/vaults/{}", vault.id))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    // Deleted, not yet purged: out of reach for a new offer and for the
    // agent's step of the change (layer 07).
    let again = TaskDecision {
        task_id: TaskId::generate(),
        ..offered.clone()
    };
    assert_eq!(
        offer(&again).send().await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let res = server
        .agent_call(
            &agent,
            Method::POST,
            &format!("/v1/agent/rotations/{}/confirm", started.rotation.id),
            Some(&json!({"item_id": item.id(), "reason": "listo"})),
        )
        .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let report = server
        .server_handle()
        .purge_expired(now_ms() + 31 * DAY_MS)
        .await
        .unwrap();
    assert_eq!(report.vaults, 1);

    let count = |sql: &'static str, bind: String| {
        let db = db.clone();
        async move {
            sqlx::query_scalar::<_, i64>(sql)
                .bind(bind)
                .fetch_one(&db)
                .await
                .unwrap()
        }
    };
    let id = vault.id.to_string();
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM approvals WHERE vault_id = $1",
            id.clone()
        )
        .await,
        0
    );
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM approvals WHERE vault_id = $1",
            other.id.to_string()
        )
        .await,
        1
    );
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM tasks WHERE id = $1",
            task_ids[0].clone()
        )
        .await,
        0,
        "a task only about the purged vault"
    );
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM tasks WHERE id = $1",
            task_ids[1].clone()
        )
        .await,
        1,
        "a task that also names another vault"
    );
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM tasks WHERE id = $1",
            offered.task_id.to_string()
        )
        .await,
        0,
        "a task the person offered only about the purged vault"
    );
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM rotations WHERE vault_id = $1",
            id.clone()
        )
        .await,
        0,
        "its password changes, with the host in the clear"
    );
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM task_targets WHERE target_key LIKE $1",
            format!("%\"{id}\"%")
        )
        .await,
        0
    );
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM task_targets WHERE task_id = $1",
            task_ids[1].clone()
        )
        .await,
        1
    );
}

/// Declares an attachment of `size` bytes (nothing uploaded).
async fn declare(
    server: &TestServer,
    ana: &Session,
    vault: &TestVault,
    project: &TestProject,
    item: ItemId,
    size: u64,
) -> StatusCode {
    let id = AttachmentId::generate();
    let ctx = vault.item_ctx(project.id, item).attachment(id);
    server
        .post_auth(
            ana,
            &format!("/v1/vaults/{}/items/{item}/attachments", vault.id),
        )
        .json(&CreateAttachment {
            item_version: None,
            id,
            size,
            wrapped_key: Blob::new(wrap_attachment_key(
                &ItemKey::generate(),
                &ctx,
                &klav_core::crypto::keys::AttachmentKey::generate(),
            )),
        })
        .send()
        .await
        .expect("request")
        .status()
}

#[tokio::test]
async fn unfinished_uploads_have_a_cap_even_when_declared_at_once() {
    let server = TestServer::start_with(|c| {
        c.limits.max_attachment_bytes = 4096;
        c.limits.max_pending_upload_bytes = 4096;
    })
    .await;
    let (ana, vault, project) = account(&server).await;
    let item = login_item("SSH", "ana", "pw");
    server.create_item(&ana, &vault, &project, &item).await;
    let answers = futures_util::future::join_all(
        (0..12).map(|_| declare(&server, &ana, &vault, &project, item.id(), 1000)),
    )
    .await;
    let created = answers
        .iter()
        .filter(|s| **s == StatusCode::CREATED)
        .count();
    assert_eq!(created, 4, "{answers:?}");
    assert!(
        answers
            .iter()
            .all(|s| matches!(*s, StatusCode::CREATED | StatusCode::CONFLICT))
    );
    // A completed upload frees its share.
    let db = server.raw_db().await;
    sqlx::query("UPDATE attachments SET completed_at = 1")
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(
        declare(&server, &ana, &vault, &project, item.id(), 1000).await,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn attachments_of_a_deleted_vault_are_frozen() {
    let server = TestServer::start().await;
    let (ana, vault, project) = account(&server).await;
    let item = login_item("SSH", "ana", "pw");
    server.create_item(&ana, &vault, &project, &item).await;
    let pending = server
        .upload_attachment(&ana, &vault, &project, item.id(), b"half", false)
        .await;
    server
        .delete_auth(&ana, &format!("/v1/vaults/{}", vault.id))
        .send()
        .await
        .unwrap();
    // No new attachment, no chunk, no completion.
    assert_eq!(
        declare(&server, &ana, &vault, &project, item.id(), 1000).await,
        StatusCode::NOT_FOUND
    );
    let base = format!("/v1/vaults/{}/attachments/{pending}", vault.id);
    let res = server
        .put_auth(&ana, &format!("{base}/content?offset=0"))
        .body(vec![0x01, 0x30, 0, 0])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let res = server
        .post_auth(&ana, &format!("{base}/complete"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

/// Runs `POST …/complete` through the router, polling it by hand, and drops
/// it at the first poll that finds the attachment under its final name: the
/// file has moved and the handler has not yet seen its commit through. That
/// is what hyper does to a handler whose client goes away mid-request (the
/// connection ends and takes the handler's future with it). `None` when it
/// was dropped there; the answer when it finished first.
async fn complete_dropped_after_the_move(
    server: &TestServer,
    ana: &Session,
    path: &str,
    file: &std::path::Path,
) -> Option<axum::http::StatusCode> {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    use tower::ServiceExt;

    let mut req = axum::http::Request::post(path)
        .header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", ana.tokens.access_token),
        )
        .body(axum::body::Body::empty())
        .expect("request");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            40_000,
        ))));
    let call = server.server_handle().router().oneshot(req);
    let mut call = std::pin::pin!(call);
    let mut cx = Context::from_waker(Waker::noop());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if file.exists() {
            return None;
        }
        if let Poll::Ready(res) = call.as_mut().poll(&mut cx) {
            return Some(res.unwrap().status());
        }
        assert!(
            std::time::Instant::now() < deadline,
            "complete never moved the file"
        );
        tokio::task::yield_now().await;
    }
}

/// A completion whose client goes away after the file moved and before the
/// commit is never left half done: the file and its row end up agreeing,
/// the next purge pass keeps the file, and completing again answers 200
/// with the content in place. It used to leave the file under its final
/// name with the row still pending: the sweep then deleted it, and a retry
/// answered "upload incomplete: 0 of N", so the upload was lost.
#[tokio::test]
async fn a_completion_whose_client_goes_away_is_never_left_half_done() {
    let server = TestServer::start().await;
    let (ana, vault, project) = account(&server).await;
    let item = login_item("SSH", "ana", "pw");
    server.create_item(&ana, &vault, &project, &item).await;
    let id = server
        .upload_attachment(&ana, &vault, &project, item.id(), b"the whole file", false)
        .await;
    let base = format!("/v1/vaults/{}/attachments/{id}", vault.id);
    let file = server
        .data_dir
        .path()
        .join("data/attachments")
        .join(vault.id.to_string())
        .join(id.to_string());
    let mut dropped = false;
    for _ in 0..50 {
        match complete_dropped_after_the_move(&server, &ana, &format!("{base}/complete"), &file)
            .await
        {
            None => {
                dropped = true;
                break;
            }
            // The boot purge pass can hold the upload's guard for a moment.
            Some(StatusCode::CONFLICT) => tokio::task::yield_now().await,
            Some(other) => panic!("complete finished before its file moved: {other}"),
        }
    }
    assert!(dropped, "complete was never dropped after the move");

    // The file kept its final name, so its row must end up completed.
    let db = server.raw_db().await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let completed: Option<i64> =
            sqlx::query_scalar("SELECT completed_at FROM attachments WHERE id = $1")
                .bind(id.to_string())
                .fetch_one(&db)
                .await
                .unwrap();
        if completed.is_some() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the row is still pending while the file is {}",
            if file.exists() {
                "under its final name"
            } else {
                "gone"
            }
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // What a purge pass and a retry find once the dropped completion has
    // settled (it may still hold the upload's guard for a moment: 409 "in
    // progress", never "incomplete").
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let res = loop {
        server
            .server_handle()
            .purge_expired(now_ms())
            .await
            .unwrap();
        let res = server
            .post_auth(&ana, &format!("{base}/complete"))
            .send()
            .await
            .unwrap();
        if res.status() != StatusCode::CONFLICT {
            break res;
        }
        let text = res.text().await.unwrap();
        assert!(text.contains("in progress"), "retried complete: {text}");
        assert!(std::time::Instant::now() < deadline, "{text}");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    };
    assert_eq!(res.status(), StatusCode::OK);
    let meta: serde_json::Value = res.json().await.unwrap();
    assert!(meta["completed_at"].is_i64(), "{meta}");
    assert!(file.exists(), "the completed file is in place");
    assert!(!file.with_extension("part").exists());
    let res = server
        .get_auth(&ana, &format!("{base}/content"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        Some(res.bytes().await.unwrap().len() as u64),
        meta["size"].as_u64()
    );
}

/// A completion whose commit fails, with the database still there to say
/// that the row stayed pending: the file goes back to `.part`, so
/// completing again (once the commit can succeed) answers 200 with the
/// content in place. Postgres only: the test's own database gets a
/// constraint trigger that runs at commit time and refuses it; SQLite has
/// no check that runs at commit.
#[tokio::test]
// The skip on SQLite says so, instead of passing as if it had run.
#[allow(clippy::print_stderr)]
async fn a_completion_whose_commit_fails_puts_the_file_back() {
    let server = TestServer::start().await;
    if !server.database_url.starts_with("postgres") {
        eprintln!(
            "a_completion_whose_commit_fails_puts_the_file_back: skipped, needs Postgres (KLAV_TEST_DATABASE_URL)"
        );
        return;
    }
    let (ana, vault, project) = account(&server).await;
    let item = login_item("SSH", "ana", "pw");
    server.create_item(&ana, &vault, &project, &item).await;
    let id = server
        .upload_attachment(&ana, &vault, &project, item.id(), b"the whole file", false)
        .await;
    let base = format!("/v1/vaults/{}/attachments/{id}", vault.id);
    let file = server
        .data_dir
        .path()
        .join("data/attachments")
        .join(vault.id.to_string())
        .join(id.to_string());
    let db = server.raw_db().await;
    sqlx::query(
        "CREATE FUNCTION klav_test_refuse() RETURNS trigger AS $$ \
         BEGIN RAISE EXCEPTION 'refused by the test'; END; $$ LANGUAGE plpgsql",
    )
    .execute(&db)
    .await
    .unwrap();
    sqlx::query(
        "CREATE CONSTRAINT TRIGGER klav_test_refuse AFTER UPDATE ON attachments \
         DEFERRABLE INITIALLY DEFERRED FOR EACH ROW \
         WHEN (NEW.completed_at IS NOT NULL) EXECUTE FUNCTION klav_test_refuse()",
    )
    .execute(&db)
    .await
    .unwrap();

    let res = server
        .post_auth(&ana, &format!("{base}/complete"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let completed: Option<i64> =
        sqlx::query_scalar("SELECT completed_at FROM attachments WHERE id = $1")
            .bind(id.to_string())
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(completed, None, "the commit was refused");
    assert!(!file.exists(), "the file went back");
    assert!(file.with_extension("part").exists(), "the file went back");

    sqlx::query("DROP TRIGGER klav_test_refuse ON attachments")
        .execute(&db)
        .await
        .unwrap();
    server
        .server_handle()
        .purge_expired(now_ms())
        .await
        .unwrap();
    let res = server
        .post_auth(&ana, &format!("{base}/complete"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(file.exists());
    let res = server
        .get_auth(&ana, &format!("{base}/content"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

/// The purge pass (hourly, and once at every boot) never makes a client's
/// upload fail: its orphan sweep reads the rows of the files it lists
/// without taking their upload guards, so the completions that come while
/// passes run back to back are never refused with 409 ("an upload of this
/// attachment is in progress").
#[tokio::test]
async fn a_purge_pass_never_holds_up_an_upload() {
    // About 120 requests in a row: past the default bursts.
    let server = TestServer::start_with(|c| {
        c.rate_limit.ip_burst = 10_000;
        c.rate_limit.account_burst = 10_000;
    })
    .await;
    let (ana, vault, project) = account(&server).await;
    let item = login_item("SSH", "ana", "pw");
    server.create_item(&ana, &vault, &project, &item).await;
    let mut pending = Vec::new();
    for _ in 0..40 {
        pending.push(
            server
                .upload_attachment(&ana, &vault, &project, item.id(), b"in progress", false)
                .await,
        );
    }
    let done = std::sync::atomic::AtomicBool::new(false);
    let sweeping = async {
        let mut passes = 0_u32;
        while !done.load(std::sync::atomic::Ordering::SeqCst) {
            server
                .server_handle()
                .purge_expired(now_ms())
                .await
                .unwrap();
            passes += 1;
        }
        passes
    };
    let completing = async {
        let mut refused = Vec::new();
        for id in &pending {
            let res = server
                .post_auth(
                    &ana,
                    &format!("/v1/vaults/{}/attachments/{id}/complete", vault.id),
                )
                .send()
                .await
                .unwrap();
            if res.status() != StatusCode::OK {
                refused.push((res.status(), res.text().await.unwrap()));
            }
        }
        done.store(true, std::sync::atomic::Ordering::SeqCst);
        refused
    };
    let (passes, refused) = tokio::join!(sweeping, completing);
    assert!(passes > 0);
    assert!(
        refused.is_empty(),
        "refused beside a purge pass: {refused:?}"
    );
}

#[tokio::test]
async fn idle_uploads_and_orphan_files_are_removed() {
    let server = TestServer::start().await;
    let (ana, vault, project) = account(&server).await;
    let item = login_item("SSH", "ana", "pw");
    server.create_item(&ana, &vault, &project, &item).await;
    let idle = server
        .upload_attachment(&ana, &vault, &project, item.id(), b"never completed", false)
        .await;
    let done = server
        .upload_attachment(&ana, &vault, &project, item.id(), b"completed", true)
        .await;
    let root = server.data_dir.path().join("data/attachments");
    let dir = root.join(vault.id.to_string());
    let part = dir.join(format!("{idle}.part"));
    assert!(part.exists());
    // Files no row points to, and a directory of a vault that does not exist.
    let orphan = dir.join(AttachmentId::generate().to_string());
    std::fs::write(&orphan, b"x").unwrap();
    let ghost = root.join(klav_core::ids::VaultId::generate().to_string());
    std::fs::create_dir_all(&ghost).unwrap();
    std::fs::write(ghost.join(AttachmentId::generate().to_string()), b"x").unwrap();
    // Not ours: left alone.
    let foreign = dir.join("README");
    std::fs::write(&foreign, b"x").unwrap();

    // A day is not over yet: the idle upload stays.
    let report = server
        .server_handle()
        .purge_expired(now_ms())
        .await
        .unwrap();
    assert_eq!(report.uploads, 0);
    assert!(part.exists());
    assert!(!orphan.exists() && !ghost.exists(), "orphans removed");
    assert!(foreign.exists());

    let report = server
        .server_handle()
        .purge_expired(now_ms() + DAY_MS + 60_000)
        .await
        .unwrap();
    assert_eq!(report.uploads, 1);
    assert!(!part.exists());
    let db = server.raw_db().await;
    let left: Vec<String> = sqlx::query_scalar("SELECT id FROM attachments")
        .fetch_all(&db)
        .await
        .unwrap();
    assert_eq!(left, [done.to_string()]);
    assert!(dir.join(done.to_string()).exists(), "completed file kept");
}
