//! Task requests (ADR 0021): the agent asks for a set of items and
//! permissions at once, the person signs one decision, and the server lets
//! the agent use that set (and nothing else) until the task ends.

mod common;

use std::sync::Arc;

use common::agent::{TestAgent, escaped, now_ms};
use common::client::Session;
use common::vault::{TestProject, TestVault, login_item};
use common::{Dropped, TestServer, until_dropped};
use klav_core::crypto::agent::{self, TaskDecisionToSign};
use klav_core::ids::{ItemId, RotationId, TaskId};
use klav_core::policy::{Effect, Permission, Policy, Rule};
use klav_core::task::{
    TASK_FORMAT_VERSION, TaskAccessDecision, TaskDecision, TaskOffer, TaskRequest,
};
use klav_proto::Blob;
use klav_proto::agent::{AccessGranted, PendingApproval};
use klav_proto::audit::{AuditEvent, AuditPage};
use klav_proto::rotate::{RotationInfo, RotationStarted, RotationStatus};
use klav_proto::task::{
    DecideTask, EndTask, OfferTask, PendingTask, TaskEndedBy, TaskInfo, TaskList, TaskStatus,
};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

/// One account on a test server: Ana's in every test but the purge's,
/// which adds another account on the same server ([`World::another`]).
struct World {
    server: Arc<TestServer>,
    ana: Session,
    vault: TestVault,
    project: TestProject,
    agent: TestAgent,
    aws: ItemId,
    telmex: ItemId,
    bank: ItemId,
}

/// `fill` and `totp` on `ask`: without a task every use needs the person.
fn ask_policy() -> Policy {
    Policy {
        rules: vec![
            Rule::new(Permission::Fill, Effect::Ask),
            Rule::new(Permission::Totp, Effect::Ask),
        ],
        expires_at: None,
    }
}

async fn world() -> World {
    world_on(TestServer::start().await).await
}

async fn world_on(server: TestServer) -> World {
    world_of(Arc::new(server), "ana@example.com").await
}

/// The account `email` on `server`: a vault, a project with three
/// logins, an agent and its grant (`ask` for `fill` and `totp`).
async fn world_of(server: Arc<TestServer>, email: &str) -> World {
    let ana = server
        .login(&server.signup(email, "pw").await, "laptop")
        .await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let mut ids = Vec::new();
    for title in ["AWS", "Telmex", "Banco"] {
        let item = login_item(title, "ana", "hunter2");
        server.create_item(&ana, &vault, &project, &item).await;
        ids.push(item.id());
    }
    let agent = TestAgent::new();
    server.register_agent_ok(&agent, email, "bot").await;
    let grant = TestServer::build_grant(&ana, &agent, 1, ask_policy(), &[(&vault, &project)]);
    assert_eq!(
        server.post_grant(&ana, &agent, &grant).await.status(),
        StatusCode::OK
    );
    World {
        server,
        ana,
        vault,
        project,
        agent,
        aws: ids[0],
        telmex: ids[1],
        bank: ids[2],
    }
}

impl World {
    fn request(&self) -> TaskRequest {
        TaskRequest {
            v: TASK_FORMAT_VERSION,
            task: "Descargar las facturas de octubre".into(),
            reason: "Conciliar los gastos del mes".into(),
            duration_secs: 7200,
            access: vec![
                klav_core::task::TaskAccessRequest {
                    vault_id: self.vault.id,
                    project_id: self.project.id,
                    item_id: self.aws,
                    permissions: vec![Permission::Fill, Permission::Passkey],
                    domain: None,
                },
                klav_core::task::TaskAccessRequest {
                    vault_id: self.vault.id,
                    project_id: self.project.id,
                    item_id: self.telmex,
                    permissions: vec![Permission::Fill],
                    domain: Some("telmex.com".into()),
                },
            ],
        }
    }

    async fn agent(&self, method: Method, path: &str, body: Option<&Value>) -> reqwest::Response {
        self.server
            .agent_call(&self.agent, method, path, body)
            .await
    }

    async fn ask_task(&self, request: &TaskRequest) -> reqwest::Response {
        self.agent(
            Method::POST,
            "/v1/agent/tasks",
            Some(&serde_json::to_value(request).expect("test")),
        )
        .await
    }

    async fn pending_task(&self) -> TaskId {
        let res = self.ask_task(&self.request()).await;
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let p: PendingTask = res.json().await.expect("test");
        p.pending_task_id
    }

    async fn task(&self, id: TaskId) -> TaskInfo {
        self.server
            .get_auth(&self.ana, &format!("/v1/tasks/{id}"))
            .send()
            .await
            .expect("test")
            .json()
            .await
            .expect("test")
    }

    /// The approval of the vectors: AWS `fill` + `passkey` on its sign-in
    /// host with `totp` added by Klav, Telmex `fill` on its host.
    fn approval(&self, id: TaskId, expires_at_ms: u64) -> TaskDecision {
        TaskDecision {
            v: TASK_FORMAT_VERSION,
            task_id: id,
            agent_id: self.agent.id,
            revision: 1,
            expires_at_ms,
            access: vec![
                TaskAccessDecision {
                    vault_id: self.vault.id,
                    project_id: self.project.id,
                    item_id: self.aws,
                    permissions: vec![Permission::Fill, Permission::Passkey, Permission::Totp],
                    domains: vec!["signin.aws.amazon.com".into()],
                    added_by_klav: vec![Permission::Totp],
                },
                TaskAccessDecision {
                    vault_id: self.vault.id,
                    project_id: self.project.id,
                    item_id: self.telmex,
                    permissions: vec![Permission::Fill],
                    domains: vec!["telmex.com".into()],
                    added_by_klav: vec![],
                },
            ],
            offer: None,
        }
    }

    async fn decide_as(
        &self,
        signer: &Session,
        id: TaskId,
        approve: bool,
        decision: &TaskDecision,
        decided_at: i64,
    ) -> reqwest::Response {
        let body = self
            .decide_body(signer, id, approve, decision, decided_at)
            .await;
        self.server
            .post_auth(&self.ana, &format!("/v1/tasks/{id}/decide"))
            .json(&body)
            .send()
            .await
            .expect("test")
    }

    /// The body of `POST /v1/tasks/{id}/decide`, signed by `signer`.
    async fn decide_body(
        &self,
        signer: &Session,
        id: TaskId,
        approve: bool,
        decision: &TaskDecision,
        decided_at: i64,
    ) -> DecideTask {
        let info = self.task(id).await;
        let bytes = serde_json::to_vec(decision).expect("test");
        let signature = agent::sign_task_decision(
            &signer.identity,
            &TaskDecisionToSign {
                task: id,
                agent: self.agent.id,
                request: info.request.as_bytes(),
                decision: &bytes,
                approve,
                decided_at_ms: u64::try_from(decided_at).expect("test"),
            },
        );
        DecideTask {
            approve,
            decision: Blob::new(bytes),
            decided_at,
            signature: Blob::new(signature.to_bytes().to_vec()),
        }
    }

    async fn decide(
        &self,
        id: TaskId,
        approve: bool,
        decision: &TaskDecision,
    ) -> reqwest::Response {
        self.decide_as(&self.ana, id, approve, decision, now_ms())
            .await
    }

    async fn approved_task(&self) -> (TaskId, TaskDecision) {
        let id = self.pending_task().await;
        let decision = self.approval(id, u64::try_from(now_ms() + 3_600_000).expect("test"));
        let res = self.decide(id, true, &decision).await;
        assert_eq!(res.status(), StatusCode::OK);
        (id, decision)
    }

    async fn access(
        &self,
        item: ItemId,
        permission: &str,
        domain: Option<&str>,
        extra: Value,
    ) -> reqwest::Response {
        let mut body = json!({
            "item_id": item,
            "permission": permission,
            "reason": "descargar la factura",
            "claims": domain.map(|d| json!({"domain": d})).unwrap_or(json!({})),
        });
        if let Value::Object(extra) = extra {
            body.as_object_mut().expect("test").extend(extra);
        }
        self.agent(Method::POST, "/v1/agent/access", Some(&body))
            .await
    }

    async fn events(&self) -> Vec<AuditEvent> {
        let page: AuditPage = self
            .server
            .get_auth(&self.ana, "/v1/audit")
            .send()
            .await
            .expect("test")
            .json()
            .await
            .expect("test");
        page.entries
            .iter()
            .map(|e| serde_json::from_slice(e.event.as_bytes()).expect("test"))
            .collect()
    }

    async fn end_as_person(&self, id: TaskId) -> reqwest::Response {
        self.server
            .post_auth(&self.ana, &format!("/v1/tasks/{id}/end"))
            .json(&self.end_body(id))
            .send()
            .await
            .expect("test")
    }

    /// The body of `POST /v1/tasks/{id}/end`, signed by Ana now.
    fn end_body(&self, id: TaskId) -> EndTask {
        let ended_at = now_ms();
        let signature = agent::sign_task_end(
            &self.ana.identity,
            self.ana.account_id,
            id,
            self.agent.id,
            u64::try_from(ended_at).expect("test"),
        );
        EndTask {
            ended_at,
            signature: Blob::new(signature.to_bytes().to_vec()),
        }
    }
}

async fn error_text(res: reqwest::Response) -> String {
    res.text().await.expect("test")
}

#[tokio::test]
async fn task_requests_are_checked() {
    let w = world().await;
    // reveal, delete, list and create never go in a task.
    for permission in [
        Permission::Reveal,
        Permission::Delete,
        Permission::List,
        Permission::Create,
    ] {
        let mut r = w.request();
        r.access[0].permissions = vec![Permission::Fill, permission];
        let res = w.ask_task(&r).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{permission}");
    }
    let mut r = w.request();
    r.access[0].permissions = vec![Permission::Reveal];
    assert!(
        error_text(w.ask_task(&r).await)
            .await
            .contains("never goes in a task")
    );
    // Limits.
    let mut r = w.request();
    r.duration_secs = 25 * 3600;
    assert_eq!(w.ask_task(&r).await.status(), StatusCode::BAD_REQUEST);
    let mut r = w.request();
    r.task = "x".repeat(121);
    assert_eq!(w.ask_task(&r).await.status(), StatusCode::BAD_REQUEST);
    let mut r = w.request();
    r.access.clear();
    assert_eq!(w.ask_task(&r).await.status(), StatusCode::BAD_REQUEST);
    // Items outside the grant, or that do not exist.
    let mut r = w.request();
    r.access[0].item_id = ItemId::generate();
    assert_eq!(w.ask_task(&r).await.status(), StatusCode::BAD_REQUEST);
    let other = w.server.create_project(&w.ana, &w.vault).await;
    let mut r = w.request();
    r.access[0].project_id = other.id;
    assert_eq!(w.ask_task(&r).await.status(), StatusCode::BAD_REQUEST);
    // At most 5 pending requests per agent.
    for _ in 0..5 {
        w.pending_task().await;
    }
    assert_eq!(
        w.ask_task(&w.request()).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    // Only the person's signature is accepted, and only the pending ones.
    let list: TaskList = w
        .server
        .get_auth(&w.ana, "/v1/tasks")
        .send()
        .await
        .expect("test")
        .json()
        .await
        .expect("test");
    assert_eq!(list.tasks.len(), 5);
    assert!(list.tasks.iter().all(|t| t.status == TaskStatus::Pending));
    assert_eq!(list.tasks[0].agent_name, "bot");
    let id = list.tasks[0].id;
    let mallory = w
        .server
        .login(
            &w.server.signup("mallory@example.com", "pw").await,
            "laptop",
        )
        .await;
    let decision = w.approval(id, u64::try_from(now_ms() + 3_600_000).expect("test"));
    let res = w.decide_as(&mallory, id, true, &decision, now_ms()).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // Longer than requested.
    let long = w.approval(id, u64::try_from(now_ms() + 3 * 3_600_000).expect("test"));
    assert_eq!(
        w.decide(id, true, &long).await.status(),
        StatusCode::BAD_REQUEST
    );
    // An item that was not requested.
    let mut extra = decision.clone();
    extra.access[1].item_id = w.bank;
    assert_eq!(
        w.decide(id, true, &extra).await.status(),
        StatusCode::BAD_REQUEST
    );
    // A permission Klav cannot add.
    let mut widened = decision.clone();
    widened.access[1].permissions.push(Permission::Inject);
    widened.access[1].added_by_klav.push(Permission::Inject);
    assert_eq!(
        w.decide(id, true, &widened).await.status(),
        StatusCode::BAD_REQUEST
    );
    // Denying is signed too; then the task is closed.
    let deny = klav_core::task::denial(id, w.agent.id);
    assert_eq!(w.decide(id, false, &deny).await.status(), StatusCode::OK);
    assert_eq!(w.task(id).await.status, TaskStatus::Denied);
    assert_eq!(
        w.decide(id, true, &decision).await.status(),
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn a_task_covers_its_targets_and_nothing_else() {
    let w = world().await;
    // Without a task, fill asks.
    let res = w
        .access(w.aws, "fill", Some("signin.aws.amazon.com"), json!({}))
        .await;
    assert_eq!(res.status(), StatusCode::ACCEPTED);

    let id = w.pending_task().await;
    // While nobody decides, a short long-poll answers pending.
    let pending: TaskInfo = w
        .agent(Method::GET, &format!("/v1/agent/tasks/{id}?wait=1"), None)
        .await
        .json()
        .await
        .expect("test");
    assert_eq!(pending.status, TaskStatus::Pending);
    let decision = w.approval(id, u64::try_from(now_ms() + 3_600_000).expect("test"));
    assert_eq!(w.decide(id, true, &decision).await.status(), StatusCode::OK);
    let info: TaskInfo = w
        .agent(Method::GET, &format!("/v1/agent/tasks/{id}?wait=5"), None)
        .await
        .json()
        .await
        .expect("test");
    assert_eq!(info.status, TaskStatus::Approved);
    assert_eq!(info.revision, 1);
    assert_eq!(
        info.expires_at,
        Some(i64::try_from(decision.expires_at_ms).expect("test"))
    );
    // The runtime can check the decision with the account identity.
    agent::verify_task_decision(
        w.ana.identity.public(),
        &TaskDecisionToSign {
            task: id,
            agent: w.agent.id,
            request: info.request.as_bytes(),
            decision: info.decision.as_ref().expect("test").as_bytes(),
            approve: true,
            decided_at_ms: u64::try_from(info.decided_at.expect("test")).expect("test"),
        },
        &klav_core::crypto::sign::Signature::from_bytes(
            info.signature
                .as_ref()
                .expect("test")
                .as_bytes()
                .try_into()
                .expect("test"),
        ),
    )
    .expect("test");

    // Inside the task: the approved host and its subdomains, with and
    // without task_id.
    for host in ["signin.aws.amazon.com", "eu.signin.aws.amazon.com"] {
        let res = w.access(w.aws, "fill", Some(host), json!({})).await;
        assert_eq!(res.status(), StatusCode::OK, "{host}");
        let _: AccessGranted = res.json().await.expect("test");
    }
    let res = w
        .access(w.telmex, "fill", Some("telmex.com"), json!({"task_id": id}))
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    // totp added by Klav.
    assert_eq!(
        w.access(w.aws, "totp", None, json!({})).await.status(),
        StatusCode::OK
    );
    // Outside: another host, another item, a permission not approved.
    assert_eq!(
        w.access(w.aws, "fill", Some("console.aws.amazon.com"), json!({}))
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        w.access(w.bank, "fill", Some("banco.example"), json!({}))
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    let res = w.access(w.telmex, "totp", None, json!({})).await;
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let out_of_task: PendingApproval = res.json().await.expect("test");
    // A task_id that is not this task does not help either.
    assert_eq!(
        w.access(w.aws, "totp", None, json!({"task_id": TaskId::generate()}))
            .await
            .status(),
        StatusCode::ACCEPTED
    );

    // passkey: denied outside a task; inside one, the task and the host
    // (mandatory) are checked and logged, and the answer holds no item:
    // the person's klavd signs (ADR 0020 §9).
    let res = w
        .access(w.telmex, "passkey", Some("telmex.com"), json!({}))
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(error_text(res).await.contains("request_task"));
    // The host is logged as signed, so one not already in normal form is
    // refused and leaves nothing in the log.
    let before = w.events().await.len();
    for host in [
        "SignIn.AWS.Amazon.com.",
        "SignIn.AWS.Amazon.com",
        "signin.aws.amazon.com.",
    ] {
        let res = w.access(w.aws, "passkey", Some(host), json!({})).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{host}");
        assert!(error_text(res).await.contains("claims.domain"), "{host}");
    }
    assert_eq!(w.events().await.len(), before);
    let res = w
        .access(w.aws, "passkey", Some("signin.aws.amazon.com"), json!({}))
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("test");
    assert_eq!(
        body,
        json!({"task_id": id, "item_id": w.aws, "domain": "signin.aws.amazon.com"})
    );
    assert!(w.events().await.iter().any(|e| e.action == "agent.access"
        && e.permission == Some(Permission::Passkey)
        && e.outcome.as_deref() == Some("allow")
        && e.task_id == Some(id)));
    assert_eq!(
        w.access(w.aws, "passkey", None, json!({})).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        w.access(w.aws, "passkey", Some("evil.example"), json!({}))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        w.access(w.bank, "rotate", Some("banco.example"), json!({}))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );

    // «Add to the task»: only the next revision, same expiry, nothing removed.
    let mut added = decision.clone();
    added.revision = 2;
    added.access[1].permissions.push(Permission::Totp);
    let mut longer = added.clone();
    longer.expires_at_ms += 60_000;
    assert_eq!(
        w.decide(id, true, &longer).await.status(),
        StatusCode::BAD_REQUEST
    );
    let mut skipped = added.clone();
    skipped.revision = 3;
    assert_eq!(
        w.decide(id, true, &skipped).await.status(),
        StatusCode::CONFLICT
    );
    let mut removed = added.clone();
    removed.access.remove(0);
    assert_eq!(
        w.decide(id, true, &removed).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(w.decide(id, true, &added).await.status(), StatusCode::OK);
    assert_eq!(w.task(id).await.revision, 2);
    assert_eq!(
        w.decide(id, true, &added).await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        w.access(w.telmex, "totp", None, json!({})).await.status(),
        StatusCode::OK
    );

    // A new grant does not end the task, but its deny wins.
    let mut policy = ask_policy();
    policy.rules.push(Rule::new(Permission::Totp, Effect::Deny));
    let grant = TestServer::build_grant(&w.ana, &w.agent, 2, policy, &[(&w.vault, &w.project)]);
    assert_eq!(
        w.server.post_grant(&w.ana, &w.agent, &grant).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        w.access(w.aws, "totp", None, json!({})).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        w.access(w.aws, "fill", Some("signin.aws.amazon.com"), json!({}))
            .await
            .status(),
        StatusCode::OK
    );

    // The person ends it: the next use asks again.
    assert_eq!(w.end_as_person(id).await.status(), StatusCode::OK);
    let info = w.task(id).await;
    assert_eq!(info.status, TaskStatus::Ended);
    assert_eq!(info.ended_by, Some(TaskEndedBy::Person));
    assert_eq!(
        w.access(w.aws, "fill", Some("signin.aws.amazon.com"), json!({}))
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(w.end_as_person(id).await.status(), StatusCode::CONFLICT);

    // The log: request, decisions, uses under the task and the end.
    let events = w.events().await;
    let task_events: Vec<(&str, Option<&str>)> = events
        .iter()
        .filter(|e| e.action.starts_with("task."))
        .map(|e| (e.action.as_str(), e.outcome.as_deref()))
        .collect();
    assert_eq!(
        task_events,
        [
            ("task.requested", None),
            ("task.decided", Some("approve")),
            ("task.decided", Some("approve")),
            ("task.ended", Some("person")),
        ]
    );
    let requested = events
        .iter()
        .find(|e| e.action == "task.requested")
        .expect("test");
    assert_eq!(requested.task_id, Some(id));
    assert_eq!(
        requested.reason.as_deref(),
        Some("Conciliar los gastos del mes")
    );
    assert!(
        requested
            .agent_proof
            .as_ref()
            .is_some_and(|p| p.body.is_some())
    );
    let decided = events
        .iter()
        .find(|e| e.action == "task.decided")
        .expect("test");
    assert!(decided.account_signature.is_some());
    assert!(decided.signed.is_some() && decided.task_request.is_some());
    let uses = events
        .iter()
        .filter(|e| {
            e.action == "agent.access"
                && e.task_id == Some(id)
                && e.outcome.as_deref() == Some("allow")
        })
        .count();
    // Six, plus the passkey use on AWS (ADR 0020 §9).
    assert_eq!(uses, 7);
    // Out-of-task uses keep their approval_id and no task.
    assert!(events.iter().any(|e| e.action == "agent.access"
        && e.outcome.as_deref() == Some("ask")
        && e.approval_id == Some(out_of_task.pending_approval_id)));
}

#[tokio::test]
async fn tasks_end_by_agent_expiry_and_revocation() {
    let w = world().await;
    // The agent ends its own task.
    let (first, _) = w.approved_task().await;
    let res = w
        .agent(
            Method::POST,
            &format!("/v1/agent/tasks/{first}/end"),
            Some(&json!({"reason": "facturas descargadas"})),
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let info: TaskInfo = res.json().await.expect("test");
    assert_eq!(info.ended_by, Some(TaskEndedBy::Agent));
    assert_eq!(
        w.access(w.aws, "totp", None, json!({})).await.status(),
        StatusCode::ACCEPTED
    );

    // Expiry: noticed on the next look and logged once.
    let (second, _) = w.approved_task().await;
    assert_eq!(
        w.access(w.aws, "totp", None, json!({})).await.status(),
        StatusCode::OK
    );
    let db = w.server.raw_db().await;
    sqlx::query("UPDATE tasks SET expires_at = $1 WHERE id = $2")
        .bind(now_ms() - 1)
        .bind(second.to_string())
        .execute(&db)
        .await
        .expect("test");
    assert_eq!(
        w.access(w.aws, "totp", None, json!({})).await.status(),
        StatusCode::ACCEPTED
    );
    let info = w.task(second).await;
    assert_eq!(info.status, TaskStatus::Ended);
    assert_eq!(info.ended_by, Some(TaskEndedBy::Expiry));
    let _ = w.task(second).await;

    // Revocation ends running tasks and denies pending ones.
    let (third, _) = w.approved_task().await;
    let pending = w.pending_task().await;
    let revoked_at = now_ms();
    let signature = agent::sign_revocation(
        &w.ana.identity,
        w.ana.account_id,
        w.agent.id,
        u64::try_from(revoked_at).expect("test"),
    );
    let res = w
        .server
        .post_auth(&w.ana, &format!("/v1/agents/{}/revoke", w.agent.id))
        .json(&klav_proto::agent::RevokeAgent {
            revoked_at,
            signature: Blob::new(signature.to_bytes().to_vec()),
        })
        .send()
        .await
        .expect("test");
    assert_eq!(res.status(), StatusCode::OK);
    let info = w.task(third).await;
    assert_eq!(info.status, TaskStatus::Ended);
    assert_eq!(info.ended_by, Some(TaskEndedBy::Revocation));
    assert_eq!(w.task(pending).await.status, TaskStatus::Denied);

    let ends: Vec<Option<String>> = w
        .events()
        .await
        .into_iter()
        .filter(|e| e.action == "task.ended")
        .map(|e| e.outcome)
        .collect();
    assert_eq!(
        ends,
        [
            Some("agent".to_owned()),
            Some("expiry".to_owned()),
            Some("revocation".to_owned()),
        ]
    );
}

impl World {
    fn revocation(&self) -> klav_proto::agent::RevokeAgent {
        let revoked_at = now_ms();
        let signature = agent::sign_revocation(
            &self.ana.identity,
            self.ana.account_id,
            self.agent.id,
            u64::try_from(revoked_at).expect("test"),
        );
        klav_proto::agent::RevokeAgent {
            revoked_at,
            signature: Blob::new(signature.to_bytes().to_vec()),
        }
    }

    /// The actions logged about the agent, oldest first, with the task
    /// and outcome of each.
    async fn agent_log(&self) -> Vec<(String, Option<TaskId>, Option<String>)> {
        self.events()
            .await
            .into_iter()
            .filter(|e| e.agent_id == Some(self.agent.id))
            .map(|e| (e.action, e.task_id, e.outcome))
            .collect()
    }
}

/// A revocation whose client goes away is never stored without its
/// `agent.revoked` and the `task.ended` of each task it ended: the call is
/// driven through the router by hand and dropped as soon as the agent
/// reads as revoked, before the handler sees its commit.
#[tokio::test]
async fn a_revocation_whose_client_goes_away_is_logged_with_its_task_ends() {
    // A world per try: a revocation that finished first leaves no agent to
    // revoke.
    let (w, task, before) = until_dropped(async || {
        let w = world().await;
        let (task, _) = w.approved_task().await;
        let before = w.agent_log().await;
        let db = w.server.raw_db().await;
        let path = format!("/v1/agents/{}/revoke", w.agent.id);
        let status = w
            .server
            .call_dropped_once(Some(&w.ana), &path, &w.revocation(), || async {
                w.server.agent_status(&db, w.agent.id).await.as_deref() == Some("revoked")
            })
            .await;
        db.close().await;
        (status, (w, task, before))
    })
    .await;
    assert_eq!(w.task(task).await.ended_by, Some(TaskEndedBy::Revocation));
    let after = w.agent_log().await;
    assert_eq!(
        after[before.len()..],
        [
            ("agent.revoked".to_owned(), None, None),
            (
                "task.ended".to_owned(),
                Some(task),
                Some("revocation".to_owned())
            ),
        ]
    );
}

/// A revocation whose `agent.revoked`, or one of whose `task.ended`, the
/// log refuses is not made: they are appended in the revocation's own
/// transaction.
#[tokio::test]
async fn a_revocation_that_cannot_be_logged_is_not_made() {
    let w = world().await;
    let db = w.server.raw_db().await;
    let path = format!("/v1/agents/{}/revoke", w.agent.id);
    // No task first: the refused `agent.revoked` is the last append, so an
    // error ignored there would reach the commit.
    let before = w.agent_log().await;
    w.server.refuse_audit_action("agent.revoked").await;
    let res = w
        .server
        .post_auth(&w.ana, &path)
        .json(&w.revocation())
        .send()
        .await
        .expect("test");
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        w.server.agent_status(&db, w.agent.id).await.as_deref(),
        Some("active")
    );
    assert_eq!(w.agent_log().await, before);
    w.server.allow_audit_action("agent.revoked").await;

    let (task, _) = w.approved_task().await;
    let before = w.agent_log().await;
    for action in ["agent.revoked", "task.ended"] {
        w.server.refuse_audit_action(action).await;
        let res = w
            .server
            .post_auth(&w.ana, &path)
            .json(&w.revocation())
            .send()
            .await
            .expect("test");
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR, "{action}");
        assert_eq!(
            w.server.agent_status(&db, w.agent.id).await.as_deref(),
            Some("active"),
            "{action}"
        );
        assert_eq!(w.task(task).await.status, TaskStatus::Approved, "{action}");
        assert_eq!(w.agent_log().await, before, "{action}");
        w.server.allow_audit_action(action).await;
    }
    let res = w
        .server
        .post_auth(&w.ana, &path)
        .json(&w.revocation())
        .send()
        .await
        .expect("test");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(w.agent_log().await.len(), before.len() + 2);
}

/// A revocation whose write to the agent, or to one of its tasks, the
/// database refuses logs neither its `agent.revoked` nor a `task.ended`:
/// they are appended in the revocation's transaction, not in one of their
/// own before it.
#[tokio::test]
async fn a_revocation_that_cannot_be_stored_is_not_logged() {
    let w = world().await;
    let db = w.server.raw_db().await;
    let path = format!("/v1/agents/{}/revoke", w.agent.id);
    let (task, _) = w.approved_task().await;
    let before = w.agent_log().await;
    for table in ["agents", "tasks"] {
        w.server.refuse_writes(table).await;
        let res = w
            .server
            .post_auth(&w.ana, &path)
            .json(&w.revocation())
            .send()
            .await
            .expect("test");
        w.server.allow_writes(table).await;
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR, "{table}");
        assert_eq!(
            w.server.agent_status(&db, w.agent.id).await.as_deref(),
            Some("active"),
            "{table}"
        );
        assert!(
            w.stored_as(&db, task, TaskStatus::Approved).await,
            "{table}"
        );
        assert_eq!(w.agent_log().await, before, "{table}");
    }
    let res = w
        .server
        .post_auth(&w.ana, &path)
        .json(&w.revocation())
        .send()
        .await
        .expect("test");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(w.agent_log().await.len(), before.len() + 2);
}

/// Postgres only: a revocation writes the agent, ends its task and logs
/// `agent.revoked` and `task.ended` in one transaction.
#[tokio::test]
async fn a_revocation_and_its_events_share_one_transaction() {
    let w = world().await;
    if !w.server.is_postgres() {
        return;
    }
    let db = w.server.raw_db().await;
    let (task, _) = w.approved_task().await;
    let res = w
        .server
        .post_auth(&w.ana, &format!("/v1/agents/{}/revoke", w.agent.id))
        .json(&w.revocation())
        .send()
        .await
        .expect("test");
    assert_eq!(res.status(), StatusCode::OK);
    let agent = w.agent.id.to_string();
    let task = task.to_string();
    let s = &w.server;
    s.assert_written_with(&db, w.ana.account_id, "agents", &agent, "agent.revoked")
        .await;
    s.assert_written_with(&db, w.ana.account_id, "agents", &agent, "task.ended")
        .await;
    s.assert_written_with(&db, w.ana.account_id, "tasks", &task, "task.ended")
        .await;
}

/// A revocation takes the account's lock before the agent's row, as every
/// write that logs in its own transaction does: in the other order it
/// deadlocks with them (Postgres; SQLite has one writer at a time).
#[tokio::test]
async fn a_revocation_locks_the_account_before_the_agent() {
    let w = world().await;
    if !w.server.is_postgres() {
        return;
    }
    let (task, _) = w.approved_task().await;
    let send = w
        .server
        .post_auth(&w.ana, &format!("/v1/agents/{}/revoke", w.agent.id))
        .json(&w.revocation())
        .send();
    let res = w
        .server
        .assert_account_locked_before_agent(w.ana.account_id, w.agent.id, send)
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(w.task(task).await.ended_by, Some(TaskEndedBy::Revocation));
}

// -------------------------------- task events in the write's transaction --

impl World {
    /// The task's stored status and revision, read straight from the
    /// database (`None` if there is no such task).
    async fn stored(&self, db: &sqlx::AnyPool, id: TaskId) -> Option<(String, i64)> {
        sqlx::query_as("SELECT status, revision FROM tasks WHERE id = $1")
            .bind(id.to_string())
            .fetch_optional(db)
            .await
            .expect("test")
    }

    /// Whether task `id` is stored in `status`.
    async fn stored_as(&self, db: &sqlx::AnyPool, id: TaskId, status: TaskStatus) -> bool {
        self.stored(db, id)
            .await
            .is_some_and(|(s, _)| s == status.as_str())
    }

    /// Ana's `action` events of task `id`, read straight from the database.
    async fn logged(&self, db: &sqlx::AnyPool, action: &str, id: TaskId) -> Vec<AuditEvent> {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT event FROM audit_events WHERE account_id = $1 AND action = $2 ORDER BY seq",
        )
        .bind(self.ana.account_id.to_string())
        .bind(action)
        .fetch_all(db)
        .await
        .expect("test");
        rows.iter()
            .map(|bytes| serde_json::from_slice::<AuditEvent>(bytes).expect("test"))
            .filter(|e| e.task_id == Some(id))
            .collect()
    }
}

/// An hour from now, as a task's expiry.
fn in_an_hour() -> u64 {
    u64::try_from(now_ms() + 3_600_000).expect("test")
}

/// An offer whose client goes away is never stored without its
/// `task.decided`: the call is driven through the router by hand and
/// dropped as soon as the task reads as stored, before the handler sees
/// its commit.
#[tokio::test]
async fn an_offer_whose_client_goes_away_is_logged_with_it() {
    let w = world().await;
    let db = w.server.raw_db().await;
    // The task of a try that finished first, ended by the next try (under
    // the cap of running tasks) and kept if it was the last.
    let mut finished = None;
    let (id, body) = until_dropped(async || {
        if let Some(id) = finished.take() {
            assert_eq!(w.end_as_person(id).await.status(), StatusCode::OK);
        }
        let decision = w.offered();
        let id = decision.task_id;
        let body = w.offer_body(&decision, &[], now_ms());
        let status = w
            .server
            .call_dropped_once(Some(&w.ana), "/v1/tasks", &body, || async {
                w.stored(&db, id).await.is_some()
            })
            .await;
        if status.is_some() {
            finished = Some(id);
        }
        (status, (id, body))
    })
    .await;
    assert!(w.stored_as(&db, id, TaskStatus::Approved).await);
    let logged = w.logged(&db, "task.decided", id).await;
    assert_eq!(logged.len(), 1);
    assert_eq!(logged[0].outcome.as_deref(), Some("approve"));
    assert_eq!(logged[0].signed.as_ref(), Some(&body.decision));
}

/// A decision whose client goes away (an approval, a denial, a revision)
/// is never stored without its `task.decided`.
#[tokio::test]
async fn a_decision_whose_client_goes_away_is_logged_with_it() {
    // Three cases of up to `DROP_TRIES` tasks each, more than the default
    // bursts allow when every try finishes first.
    let w = world_on(
        TestServer::start_with(|c| {
            c.rate_limit.ip_burst = 10_000;
            c.rate_limit.account_burst = 10_000;
        })
        .await,
    )
    .await;
    let db = w.server.raw_db().await;
    // A new task per try: one whose decision finished first is decided.
    // `revision` 2 revises an approved task.
    let cases = [
        (true, TaskStatus::Approved, 1),
        (false, TaskStatus::Denied, 0),
        (true, TaskStatus::Approved, 2),
    ];
    for (approve, status, revision) in cases {
        let case = format!("{} r{revision}", status.as_str());
        let (id, body) = until_dropped(async || {
            let (id, decision) = if revision == 2 {
                let (id, first) = w.approved_task().await;
                let mut added = first;
                added.revision = 2;
                added.access[1].permissions.push(Permission::Totp);
                (id, added)
            } else {
                let id = w.pending_task().await;
                let decision = if approve {
                    w.approval(id, in_an_hour())
                } else {
                    klav_core::task::denial(id, w.agent.id)
                };
                (id, decision)
            };
            let body = w
                .decide_body(&w.ana, id, approve, &decision, now_ms())
                .await;
            let dropped = w
                .server
                .call_dropped_once(
                    Some(&w.ana),
                    &format!("/v1/tasks/{id}/decide"),
                    &body,
                    || async {
                        w.stored(&db, id).await.is_some_and(|(s, r)| {
                            s == status.as_str() && (revision == 0 || r == revision)
                        })
                    },
                )
                .await;
            if approve {
                // Under the cap of running tasks for the next try and case.
                assert_eq!(w.end_as_person(id).await.status(), StatusCode::OK);
            }
            (dropped, (id, body))
        })
        .await;
        let logged = w.logged(&db, "task.decided", id).await;
        // The first approval's own event before the revision's.
        assert_eq!(logged.len(), usize::from(revision == 2) + 1, "{case}");
        let last = logged.last().expect("test");
        let outcome = if approve { "approve" } else { "deny" };
        assert_eq!(last.outcome.as_deref(), Some(outcome), "{case}");
        assert_eq!(last.signed.as_ref(), Some(&body.decision), "{case}");
    }
}

/// The person's end of a task whose client goes away is never stored
/// without its `task.ended`.
#[tokio::test]
async fn an_end_whose_client_goes_away_is_logged_with_it() {
    let w = world().await;
    let db = w.server.raw_db().await;
    let (id, body) = until_dropped(async || {
        let (id, _) = w.approved_task().await;
        let body = w.end_body(id);
        let status = w
            .server
            .call_dropped_once(
                Some(&w.ana),
                &format!("/v1/tasks/{id}/end"),
                &body,
                || async { w.stored_as(&db, id, TaskStatus::Ended).await },
            )
            .await;
        (status, (id, body))
    })
    .await;
    let logged = w.logged(&db, "task.ended", id).await;
    assert_eq!(logged.len(), 1);
    assert_eq!(logged[0].outcome.as_deref(), Some("person"));
    assert_eq!(logged[0].decided_at, Some(body.ended_at));
}

/// A decision dropped at each point of its call, one point per try, until
/// it is dropped after its commit: before the commit it leaves neither the
/// decision nor its `task.decided`, and at no point one without the other.
/// A try that finished first is checked the same way and the sweep goes on.
#[tokio::test]
#[allow(clippy::print_stderr)]
async fn a_decision_dropped_anywhere_leaves_both_or_neither() {
    // About two calls per try, more than the default bursts allow.
    let w = world_on(
        TestServer::start_with(|c| {
            c.rate_limit.ip_burst = 10_000;
            c.rate_limit.account_burst = 10_000;
        })
        .await,
    )
    .await;
    let db = w.server.raw_db().await;
    let mut id = w.pending_task().await;
    let (mut neither, mut finished) = (0, 0);
    for wakes in 1.. {
        assert!(wakes < 1000, "never dropped after its commit");
        if !w.stored_as(&db, id, TaskStatus::Pending).await {
            if w.stored_as(&db, id, TaskStatus::Approved).await {
                // Under the cap of running tasks.
                assert_eq!(w.end_as_person(id).await.status(), StatusCode::OK);
            }
            id = w.pending_task().await;
        }
        let body = w
            .decide_body(&w.ana, id, true, &w.approval(id, in_an_hour()), now_ms())
            .await;
        let dropped = w
            .server
            .call_dropped_at(
                Some(&w.ana),
                &format!("/v1/tasks/{id}/decide"),
                &body,
                Some(wakes),
                || async { w.stored_as(&db, id, TaskStatus::Approved).await },
            )
            .await;
        // A commit sent before the drop lands, or the transaction is
        // rolled back, before this reads.
        w.server.settle(&db, w.ana.account_id).await;
        let decided = w.stored_as(&db, id, TaskStatus::Approved).await;
        let logged = w.logged(&db, "task.decided", id).await.len();
        assert_eq!(
            (decided, logged),
            if decided { (true, 1) } else { (false, 0) },
            "dropped at wake {wakes}: {dropped:?}"
        );
        match dropped {
            Dropped::Before => neither += usize::from(!decided),
            Dropped::After => break,
            Dropped::Finished(status) => {
                assert_eq!(status, StatusCode::OK, "at wake {wakes}");
                finished += 1;
            }
        }
    }
    eprintln!(
        "dropped before its commit with neither {neither} times; finished first {finished} times"
    );
    assert!(neither > 0, "never dropped before its commit");
}

/// An offer whose `task.decided` the log refuses is not stored: the event
/// is appended in the offer's own transaction.
#[tokio::test]
async fn an_offer_that_cannot_be_logged_is_not_made() {
    let w = world().await;
    let db = w.server.raw_db().await;
    let decision = w.offered();
    let id = decision.task_id;
    w.server.refuse_audit_action("task.decided").await;
    assert_eq!(
        w.offer(&decision).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(w.stored(&db, id).await, None);
    assert!(w.logged(&db, "task.decided", id).await.is_empty());
    w.server.allow_audit_action("task.decided").await;
    assert_eq!(w.offer(&decision).await.status(), StatusCode::CREATED);
    assert_eq!(w.logged(&db, "task.decided", id).await.len(), 1);
}

/// A decision (an approval, a denial, a revision) whose `task.decided` the
/// log refuses is not made.
#[tokio::test]
async fn a_decision_that_cannot_be_logged_is_not_made() {
    let w = world().await;
    let db = w.server.raw_db().await;
    let approved = w.pending_task().await;
    let denied = w.pending_task().await;
    let first = w.approval(approved, in_an_hour());
    let mut added = first.clone();
    added.revision = 2;
    added.access[1].permissions.push(Permission::Totp);
    let cases = [
        (approved, true, first),
        (denied, false, klav_core::task::denial(denied, w.agent.id)),
        (approved, true, added),
    ];
    for (id, approve, decision) in cases {
        let before = (
            w.stored(&db, id).await,
            w.logged(&db, "task.decided", id).await.len(),
        );
        let case = format!("{approve} r{}", decision.revision);
        w.server.refuse_audit_action("task.decided").await;
        assert_eq!(
            w.decide(id, approve, &decision).await.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "{case}"
        );
        let after = (
            w.stored(&db, id).await,
            w.logged(&db, "task.decided", id).await.len(),
        );
        assert_eq!(after, before, "{case}");
        w.server.allow_audit_action("task.decided").await;
        assert_eq!(
            w.decide(id, approve, &decision).await.status(),
            StatusCode::OK,
            "{case}"
        );
        assert_eq!(
            w.logged(&db, "task.decided", id).await.len(),
            before.1 + 1,
            "{case}"
        );
    }
}

/// The person's end whose `task.ended` the log refuses is not made.
#[tokio::test]
async fn an_end_that_cannot_be_logged_is_not_made() {
    let w = world().await;
    let db = w.server.raw_db().await;
    let (id, _) = w.approved_task().await;
    w.server.refuse_audit_action("task.ended").await;
    assert_eq!(
        w.end_as_person(id).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(w.stored_as(&db, id, TaskStatus::Approved).await);
    assert!(w.logged(&db, "task.ended", id).await.is_empty());
    w.server.allow_audit_action("task.ended").await;
    assert_eq!(w.end_as_person(id).await.status(), StatusCode::OK);
    assert_eq!(w.logged(&db, "task.ended", id).await.len(), 1);
}

/// An offer whose task the database refuses to store logs no
/// `task.decided`: the event is appended in the offer's transaction, not
/// in one of its own before it.
#[tokio::test]
async fn an_offer_that_cannot_be_stored_is_not_logged() {
    let w = world().await;
    let db = w.server.raw_db().await;
    let decision = w.offered();
    let id = decision.task_id;
    w.server.refuse_writes("tasks").await;
    let status = w.offer(&decision).await.status();
    w.server.allow_writes("tasks").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(w.stored(&db, id).await, None);
    assert!(w.logged(&db, "task.decided", id).await.is_empty());
    assert_eq!(w.offer(&decision).await.status(), StatusCode::CREATED);
    assert_eq!(w.logged(&db, "task.decided", id).await.len(), 1);
}

/// A decision (an approval, a denial, a revision) the database refuses to
/// store logs no `task.decided`.
#[tokio::test]
async fn a_decision_that_cannot_be_stored_is_not_logged() {
    let w = world().await;
    let db = w.server.raw_db().await;
    let approved = w.pending_task().await;
    let denied = w.pending_task().await;
    let first = w.approval(approved, in_an_hour());
    let mut added = first.clone();
    added.revision = 2;
    added.access[1].permissions.push(Permission::Totp);
    let cases = [
        (approved, true, first),
        (denied, false, klav_core::task::denial(denied, w.agent.id)),
        (approved, true, added),
    ];
    for (id, approve, decision) in cases {
        let before = (
            w.stored(&db, id).await,
            w.logged(&db, "task.decided", id).await.len(),
        );
        let case = format!("{approve} r{}", decision.revision);
        w.server.refuse_writes("tasks").await;
        let status = w.decide(id, approve, &decision).await.status();
        w.server.allow_writes("tasks").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{case}");
        let after = (
            w.stored(&db, id).await,
            w.logged(&db, "task.decided", id).await.len(),
        );
        assert_eq!(after, before, "{case}");
        assert_eq!(
            w.decide(id, approve, &decision).await.status(),
            StatusCode::OK,
            "{case}"
        );
        assert_eq!(
            w.logged(&db, "task.decided", id).await.len(),
            before.1 + 1,
            "{case}"
        );
    }
}

/// The person's end the database refuses to store logs no `task.ended`.
#[tokio::test]
async fn an_end_that_cannot_be_stored_is_not_logged() {
    let w = world().await;
    let db = w.server.raw_db().await;
    let (id, _) = w.approved_task().await;
    w.server.refuse_writes("tasks").await;
    let status = w.end_as_person(id).await.status();
    w.server.allow_writes("tasks").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(w.stored_as(&db, id, TaskStatus::Approved).await);
    assert!(w.logged(&db, "task.ended", id).await.is_empty());
    assert_eq!(w.end_as_person(id).await.status(), StatusCode::OK);
    assert_eq!(w.logged(&db, "task.ended", id).await.len(), 1);
}

/// Postgres only: an offer, an approval, a denial, a revision and the
/// person's end each write the task and append its event in one
/// transaction.
#[tokio::test]
async fn each_task_write_and_its_event_share_one_transaction() {
    let w = world().await;
    if !w.server.is_postgres() {
        return;
    }
    let db = w.server.raw_db().await;
    let same = async |id: TaskId, action: &str| {
        w.server
            .assert_written_with(&db, w.ana.account_id, "tasks", &id.to_string(), action)
            .await;
    };
    let offered = w.offered();
    assert_eq!(w.offer(&offered).await.status(), StatusCode::CREATED);
    same(offered.task_id, "task.decided").await;
    let approved = w.pending_task().await;
    let first = w.approval(approved, in_an_hour());
    assert_eq!(
        w.decide(approved, true, &first).await.status(),
        StatusCode::OK
    );
    same(approved, "task.decided").await;
    let denied = w.pending_task().await;
    let denial = klav_core::task::denial(denied, w.agent.id);
    assert_eq!(
        w.decide(denied, false, &denial).await.status(),
        StatusCode::OK
    );
    same(denied, "task.decided").await;
    let mut added = first;
    added.revision = 2;
    added.access[1].permissions.push(Permission::Totp);
    assert_eq!(
        w.decide(approved, true, &added).await.status(),
        StatusCode::OK
    );
    same(approved, "task.decided").await;
    assert_eq!(w.end_as_person(approved).await.status(), StatusCode::OK);
    same(approved, "task.ended").await;
}

/// An offer and a decision take the account's lock before the agent's
/// row, as every write that logs in its own transaction does: in the other
/// order they deadlock with them (Postgres; SQLite has one writer at a
/// time).
#[tokio::test]
async fn an_offer_and_a_decision_lock_the_account_before_the_agent() {
    let w = world().await;
    if !w.server.is_postgres() {
        return;
    }
    let send = w
        .server
        .post_auth(&w.ana, "/v1/tasks")
        .json(&w.offer_body(&w.offered(), &[], now_ms()))
        .send();
    let res = w
        .server
        .assert_account_locked_before_agent(w.ana.account_id, w.agent.id, send)
        .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let id = w.pending_task().await;
    let body = w
        .decide_body(&w.ana, id, true, &w.approval(id, in_an_hour()), now_ms())
        .await;
    let send = w
        .server
        .post_auth(&w.ana, &format!("/v1/tasks/{id}/decide"))
        .json(&body)
        .send();
    let res = w
        .server
        .assert_account_locked_before_agent(w.ana.account_id, w.agent.id, send)
        .await;
    assert_eq!(res.status(), StatusCode::OK);
}

/// A revocation and the person's end of the same task never both end it.
/// Both take the account's lock first, so a revocation reads the agent's
/// running tasks before or after the end, never in between: the task has
/// one `task.ended` (Postgres; SQLite has one writer at a time). The
/// task's row is held so that the end waits on it first and the
/// revocation second, the order that ends it twice without the lock.
#[tokio::test]
async fn a_revocation_never_ends_a_task_the_person_ended() {
    let w = world().await;
    if !w.server.is_postgres() {
        return;
    }
    let (id, _) = w.approved_task().await;
    let db = w.server.raw_db().await;
    let held = w.server.raw_db().await;
    let mut row = held.begin().await.expect("test");
    sqlx::query("UPDATE tasks SET status = status WHERE id = $1")
        .bind(id.to_string())
        .execute(&mut *row)
        .await
        .expect("test");
    let waiting = |n: i64| {
        let db = db.clone();
        async move {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                let waiting: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM pg_stat_activity \
                     WHERE datname = current_database() AND wait_event_type = 'Lock'",
                )
                .fetch_one(&db)
                .await
                .expect("test");
                if waiting >= n {
                    return;
                }
                assert!(std::time::Instant::now() < deadline, "{waiting} waiting");
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }
    };
    let end = tokio::spawn(
        w.server
            .post_auth(&w.ana, &format!("/v1/tasks/{id}/end"))
            .json(&w.end_body(id))
            .send(),
    );
    waiting(1).await;
    let revoke = tokio::spawn(
        w.server
            .post_auth(&w.ana, &format!("/v1/agents/{}/revoke", w.agent.id))
            .json(&w.revocation())
            .send(),
    );
    waiting(2).await;
    row.rollback().await.expect("test");
    let end = end.await.expect("test").expect("test");
    let revoke = revoke.await.expect("test").expect("test");
    assert_eq!(end.status(), StatusCode::OK);
    assert_eq!(revoke.status(), StatusCode::OK);
    assert_eq!(w.task(id).await.ended_by, Some(TaskEndedBy::Person));
    let ended: Vec<_> = w
        .logged(&db, "task.ended", id)
        .await
        .into_iter()
        .map(|e| e.outcome)
        .collect();
    assert_eq!(ended, [Some("person".to_owned())]);
}

/// Postgres only: the expiry sweep holds the account's lock and waits on
/// the task's row, which the test holds, while a revocation of its agent
/// waits on the account. Released, the sweep ends the task, logs it and
/// commits; the revocation then takes the account, and its
/// `UPDATE … RETURNING` finds the task already ended and skips it. The
/// task gets one `task.ended`, the sweep's.
#[tokio::test]
async fn a_revocation_never_logs_the_end_of_a_task_the_sweep_ended() {
    let w = world().await;
    if !w.server.is_postgres() {
        return;
    }
    let (id, _) = w.approved_task().await;
    let db = w.server.raw_db().await;
    // Expired, for the sweep; still approved, for the revocation.
    sqlx::query("UPDATE tasks SET expires_at = $1 WHERE id = $2")
        .bind(now_ms() - 1_000)
        .bind(id.to_string())
        .execute(&db)
        .await
        .expect("test");
    let held = w.server.raw_db().await;
    let mut row = held.begin().await.expect("test");
    sqlx::query("UPDATE tasks SET status = status WHERE id = $1")
        .bind(id.to_string())
        .execute(&mut *row)
        .await
        .expect("test");
    let waiting = |n: i64| {
        let db = db.clone();
        async move {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                let waiting: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM pg_stat_activity \
                     WHERE datname = current_database() AND wait_event_type = 'Lock'",
                )
                .fetch_one(&db)
                .await
                .expect("test");
                if waiting >= n {
                    return;
                }
                assert!(std::time::Instant::now() < deadline, "{waiting} waiting");
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }
    };
    // The person's task list runs the sweep first.
    let sweep = tokio::spawn(w.server.get_auth(&w.ana, "/v1/tasks").send());
    waiting(1).await;
    let revoke = tokio::spawn(
        w.server
            .post_auth(&w.ana, &format!("/v1/agents/{}/revoke", w.agent.id))
            .json(&w.revocation())
            .send(),
    );
    waiting(2).await;
    row.rollback().await.expect("test");
    let sweep = sweep.await.expect("test").expect("test");
    let revoke = revoke.await.expect("test").expect("test");
    assert_eq!(sweep.status(), StatusCode::OK);
    assert_eq!(revoke.status(), StatusCode::OK);
    assert_eq!(w.task(id).await.ended_by, Some(TaskEndedBy::Expiry));
    let ended: Vec<_> = w
        .logged(&db, "task.ended", id)
        .await
        .into_iter()
        .map(|e| e.outcome)
        .collect();
    assert_eq!(ended, [Some("expiry".to_owned())]);
}

// ------------------------------- the expiry sweep in its own transaction --

/// What runs the expiry sweep: the person's task list sweeps the account,
/// the agent's task list sweeps the agent.
#[derive(Clone, Copy, Debug)]
enum Sweeper {
    Person,
    Agent,
}

const SWEEPERS: [Sweeper; 2] = [Sweeper::Person, Sweeper::Agent];

impl World {
    /// An approved task already past its expiry, not swept yet.
    async fn expired_task(&self, db: &sqlx::AnyPool) -> TaskId {
        let (id, _) = self.approved_task().await;
        sqlx::query("UPDATE tasks SET expires_at = $1 WHERE id = $2")
            .bind(now_ms() - 1_000)
            .bind(id.to_string())
            .execute(db)
            .await
            .expect("test");
        id
    }

    /// A request whose first step is the expiry sweep.
    async fn sweep_by(&self, sweeper: Sweeper) -> StatusCode {
        match sweeper {
            Sweeper::Person => self
                .server
                .get_auth(&self.ana, "/v1/tasks")
                .send()
                .await
                .expect("test")
                .status(),
            Sweeper::Agent => self
                .agent(Method::GET, "/v1/agent/tasks", None)
                .await
                .status(),
        }
    }
}

/// An expiry whose `task.ended` the log refuses is not stored: the task
/// stays approved (and, past its `expires_at`, covers nothing), the
/// request that swept fails, and the next sweep ends it with its event.
#[tokio::test]
async fn an_expiry_that_cannot_be_logged_is_not_stored() {
    let w = world().await;
    let db = w.server.raw_db().await;
    for sweeper in SWEEPERS {
        let id = w.expired_task(&db).await;
        w.server.refuse_audit_action("task.ended").await;
        let status = w.sweep_by(sweeper).await;
        w.server.allow_audit_action("task.ended").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{sweeper:?}");
        assert!(
            w.stored_as(&db, id, TaskStatus::Approved).await,
            "{sweeper:?}"
        );
        assert!(
            w.logged(&db, "task.ended", id).await.is_empty(),
            "{sweeper:?}"
        );
        assert_eq!(w.sweep_by(sweeper).await, StatusCode::OK, "{sweeper:?}");
        assert!(w.stored_as(&db, id, TaskStatus::Ended).await, "{sweeper:?}");
        let ended: Vec<_> = w
            .logged(&db, "task.ended", id)
            .await
            .into_iter()
            .map(|e| e.outcome)
            .collect();
        assert_eq!(ended, [Some("expiry".to_owned())], "{sweeper:?}");
    }
}

/// An expiry the database refuses to store logs no `task.ended`: the event
/// is appended in the sweep's transaction, not in one of its own before
/// it.
#[tokio::test]
async fn an_expiry_that_cannot_be_stored_is_not_logged() {
    let w = world().await;
    let db = w.server.raw_db().await;
    for sweeper in SWEEPERS {
        let id = w.expired_task(&db).await;
        w.server.refuse_writes("tasks").await;
        let status = w.sweep_by(sweeper).await;
        w.server.allow_writes("tasks").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{sweeper:?}");
        assert!(
            w.stored_as(&db, id, TaskStatus::Approved).await,
            "{sweeper:?}"
        );
        assert!(
            w.logged(&db, "task.ended", id).await.is_empty(),
            "{sweeper:?}"
        );
        assert_eq!(w.sweep_by(sweeper).await, StatusCode::OK, "{sweeper:?}");
        assert_eq!(
            w.logged(&db, "task.ended", id).await.len(),
            1,
            "{sweeper:?}"
        );
    }
}

/// Postgres only: the sweep ends the task and appends its `task.ended` in
/// one transaction.
#[tokio::test]
async fn an_expiry_and_its_event_share_one_transaction() {
    let w = world().await;
    if !w.server.is_postgres() {
        return;
    }
    let db = w.server.raw_db().await;
    for sweeper in SWEEPERS {
        let id = w.expired_task(&db).await;
        assert_eq!(w.sweep_by(sweeper).await, StatusCode::OK, "{sweeper:?}");
        w.server
            .assert_written_with(
                &db,
                w.ana.account_id,
                "tasks",
                &id.to_string(),
                "task.ended",
            )
            .await;
    }
}

/// Postgres only: two sweeps of one account at once, one from the
/// person's request and one from the agent's, end the task once and log
/// one `task.ended`. Each takes the account's lock first; the test holds
/// it until both wait for it, then the second one's `UPDATE … RETURNING`
/// finds the task already ended and logs nothing.
#[tokio::test]
async fn two_sweeps_at_once_log_one_expiry() {
    let w = world().await;
    if !w.server.is_postgres() {
        return;
    }
    let db = w.server.raw_db().await;
    let id = w.expired_task(&db).await;
    let held = w.server.raw_db().await;
    let mut account = held.begin().await.expect("test");
    sqlx::query("UPDATE accounts SET updated_at = updated_at WHERE id = $1")
        .bind(w.ana.account_id.to_string())
        .execute(&mut *account)
        .await
        .expect("test");
    let release = async {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_stat_activity \
                 WHERE datname = current_database() AND wait_event_type = 'Lock'",
            )
            .fetch_one(&db)
            .await
            .expect("test");
            if waiting >= 2 {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "{waiting} waiting");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        account.rollback().await.expect("test");
    };
    let (person, agent, ()) = tokio::join!(
        w.sweep_by(Sweeper::Person),
        w.sweep_by(Sweeper::Agent),
        release
    );
    assert_eq!(person, StatusCode::OK);
    assert_eq!(agent, StatusCode::OK);
    assert_eq!(w.task(id).await.ended_by, Some(TaskEndedBy::Expiry));
    assert_eq!(w.logged(&db, "task.ended", id).await.len(), 1);
}

// ------------------------------------ the periodic purge, account by account --

impl World {
    /// Another account on the same server, with its own vault, logins,
    /// agent and grant (its session is this world's `ana`).
    async fn another(&self, email: &str) -> World {
        world_of(Arc::clone(&self.server), email).await
    }

    /// Moves task `id`'s expiry to `at`.
    async fn expires_at(&self, db: &sqlx::AnyPool, id: TaskId, at: i64) {
        sqlx::query("UPDATE tasks SET expires_at = $1 WHERE id = $2")
            .bind(at)
            .bind(id.to_string())
            .execute(db)
            .await
            .expect("test");
    }

    /// This account's `task.ended` events, in its chain's order: each
    /// one's task, outcome and `decided_at`.
    async fn ends_logged(&self, db: &sqlx::AnyPool) -> Vec<(TaskId, Option<String>, Option<i64>)> {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT event FROM audit_events WHERE account_id = $1 AND action = 'task.ended' \
             ORDER BY seq",
        )
        .bind(self.ana.account_id.to_string())
        .fetch_all(db)
        .await
        .expect("test");
        rows.iter()
            .map(|bytes| serde_json::from_slice::<AuditEvent>(bytes).expect("test"))
            .map(|e| (e.task_id.expect("test"), e.outcome, e.decided_at))
            .collect()
    }

    /// Puts a corrupt head on this account's chain (a hash that is not 32
    /// bytes), so that every append to its log fails, and only to its log.
    /// Returns the head's `seq`, for [`World::heal_chain`].
    async fn corrupt_chain(&self, db: &sqlx::AnyPool) -> i64 {
        let last: Option<i64> =
            sqlx::query_scalar("SELECT MAX(seq) FROM audit_events WHERE account_id = $1")
                .bind(self.ana.account_id.to_string())
                .fetch_one(db)
                .await
                .expect("test");
        let seq = last.unwrap_or(0) + 1;
        sqlx::query(
            "INSERT INTO audit_events (account_id, seq, event, hash, at, action) \
             VALUES ($1, $2, $3, $4, $5, 'test.corrupt')",
        )
        .bind(self.ana.account_id.to_string())
        .bind(seq)
        .bind(b"{}".to_vec())
        .bind(vec![0_u8])
        .bind(now_ms())
        .execute(db)
        .await
        .expect("test");
        seq
    }

    /// Removes the head [`World::corrupt_chain`] put.
    async fn heal_chain(&self, db: &sqlx::AnyPool, seq: i64) {
        let removed = sqlx::query("DELETE FROM audit_events WHERE account_id = $1 AND seq = $2")
            .bind(self.ana.account_id.to_string())
            .bind(seq)
            .execute(db)
            .await
            .expect("test");
        assert_eq!(removed.rows_affected(), 1);
    }
}

/// The hourly purge ends the expired tasks of every account and logs one
/// `task.ended` (by `expiry`) per task, each in its own account's chain,
/// in `(expires_at, id)` order.
#[tokio::test]
async fn the_purge_logs_each_expiry_in_its_own_accounts_chain() {
    let ana = world().await;
    let bea = ana.another("bea@example.com").await;
    let db = ana.server.raw_db().await;
    // Every task approved first, then expired: a request for a task sweeps
    // the agent's expired ones. Ana's later task is created first, so that
    // creation order is not the order.
    let (later, _) = ana.approved_task().await;
    let (earlier, _) = ana.approved_task().await;
    let (other, _) = bea.approved_task().await;
    let now = now_ms();
    ana.expires_at(&db, later, now - 1_000).await;
    ana.expires_at(&db, earlier, now - 2_000).await;
    bea.expires_at(&db, other, now - 1_500).await;

    ana.server
        .server_handle()
        .purge_expired(now)
        .await
        .expect("purge");

    let expiry = Some("expiry".to_owned());
    assert_eq!(
        ana.ends_logged(&db).await,
        [
            (earlier, expiry.clone(), Some(now - 2_000)),
            (later, expiry.clone(), Some(now - 1_000)),
        ]
    );
    assert_eq!(
        bea.ends_logged(&db).await,
        [(other, expiry, Some(now - 1_500))]
    );
    for (w, id) in [(&ana, earlier), (&ana, later), (&bea, other)] {
        assert!(w.stored_as(&db, id, TaskStatus::Ended).await);
    }
}

/// An account whose log cannot take its `task.ended` never stops the
/// hourly purge: the other accounts' tasks are ended and logged, the purge
/// goes on, and that account's task stays approved (read as ended) until a
/// later run, with the log healthy again, ends and logs it once.
#[tokio::test]
async fn an_account_that_cannot_log_its_expiry_never_stops_the_purge() {
    let ana = world().await;
    let bea = ana.another("bea@example.com").await;
    let db = ana.server.raw_db().await;
    let stuck = ana.expired_task(&db).await;
    let other = bea.expired_task(&db).await;
    let head = ana.corrupt_chain(&db).await;

    let report = ana.server.server_handle().purge_expired(now_ms()).await;
    assert!(report.is_ok(), "the purge stopped at Ana's account");
    assert!(ana.stored_as(&db, stuck, TaskStatus::Approved).await);
    assert!(ana.ends_logged(&db).await.is_empty());
    assert!(bea.stored_as(&db, other, TaskStatus::Ended).await);
    let expiry = Some("expiry".to_owned());
    assert_eq!(
        bea.ends_logged(&db).await,
        [(other, expiry.clone(), bea.task(other).await.ended_at)]
    );

    ana.heal_chain(&db, head).await;
    ana.server
        .server_handle()
        .purge_expired(now_ms())
        .await
        .expect("purge");
    assert!(ana.stored_as(&db, stuck, TaskStatus::Ended).await);
    let ends: Vec<_> = ana
        .ends_logged(&db)
        .await
        .into_iter()
        .map(|(id, outcome, _)| (id, outcome))
        .collect();
    assert_eq!(ends, [(stuck, expiry.clone())]);
    assert_eq!(bea.ends_logged(&db).await.len(), 1);
}

#[tokio::test]
async fn grants_cannot_carry_task_only_permissions() {
    let w = world().await;
    for permission in [Permission::Passkey, Permission::Rotate] {
        let mut policy = ask_policy();
        policy.rules.push(Rule::new(permission, Effect::Allow));
        let grant = TestServer::build_grant(&w.ana, &w.agent, 2, policy, &[(&w.vault, &w.project)]);
        let res = w.server.post_grant(&w.ana, &w.agent, &grant).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{permission}");
        assert!(
            error_text(res)
                .await
                .contains("only exists inside an approved task")
        );
    }
}

#[tokio::test]
async fn at_most_ten_running_tasks() {
    let w = world().await;
    for _ in 0..10 {
        w.approved_task().await;
    }
    // A new request is refused while ten are running.
    assert_eq!(
        w.ask_task(&w.request()).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let list: TaskList = w
        .agent(Method::GET, "/v1/agent/tasks", None)
        .await
        .json()
        .await
        .expect("test");
    assert_eq!(
        list.tasks
            .iter()
            .filter(|t| t.status == TaskStatus::Approved)
            .count(),
        10
    );
}

// ------------------------------------------- offered tasks and rotate ----

impl World {
    /// A task the person offers (ADR 0022 §6): `rotate` (and `totp`, added
    /// by Klav) on the bank's login, on its site, for an hour.
    fn offered(&self) -> TaskDecision {
        TaskDecision {
            v: TASK_FORMAT_VERSION,
            task_id: TaskId::generate(),
            agent_id: self.agent.id,
            revision: 1,
            expires_at_ms: u64::try_from(now_ms() + 3_600_000).expect("test"),
            access: vec![TaskAccessDecision {
                vault_id: self.vault.id,
                project_id: self.project.id,
                item_id: self.bank,
                permissions: vec![Permission::Rotate, Permission::Totp],
                domains: vec!["banco.example".into()],
                added_by_klav: vec![Permission::Totp],
            }],
            offer: Some(TaskOffer {
                task: "Arreglar mis contraseñas repetidas".into(),
                reason: "Cada sitio con su propia contraseña".into(),
            }),
        }
    }

    /// `POST /v1/tasks`, signed by Ana over `request` (empty in a real
    /// offer).
    async fn offer_signed(
        &self,
        decision: &TaskDecision,
        request: &[u8],
        decided_at: i64,
    ) -> reqwest::Response {
        self.server
            .post_auth(&self.ana, "/v1/tasks")
            .json(&self.offer_body(decision, request, decided_at))
            .send()
            .await
            .expect("test")
    }

    /// The body of `POST /v1/tasks`, signed by Ana over `request`.
    fn offer_body(&self, decision: &TaskDecision, request: &[u8], decided_at: i64) -> OfferTask {
        let bytes = serde_json::to_vec(decision).expect("test");
        let signature = agent::sign_task_decision(
            &self.ana.identity,
            &TaskDecisionToSign {
                task: decision.task_id,
                agent: decision.agent_id,
                request,
                decision: &bytes,
                approve: true,
                decided_at_ms: u64::try_from(decided_at).expect("test"),
            },
        );
        OfferTask {
            task_id: decision.task_id,
            agent_id: decision.agent_id,
            decision: Blob::new(bytes),
            decided_at,
            signature: Blob::new(signature.to_bytes().to_vec()),
        }
    }

    async fn offer(&self, decision: &TaskDecision) -> reqwest::Response {
        self.offer_signed(decision, &[], now_ms()).await
    }

    async fn rotate_start(&self, item: ItemId, domain: Option<&str>) -> reqwest::Response {
        let mut body = json!({"item_id": item, "reason": "cambiar la contraseña repetida"});
        if let Some(domain) = domain {
            body["claims"] = json!({"domain": domain});
        }
        self.agent(Method::POST, "/v1/agent/rotations", Some(&body))
            .await
    }

    async fn rotate_finish(&self, id: RotationId, item: ItemId, step: &str) -> reqwest::Response {
        self.agent(
            Method::POST,
            &format!("/v1/agent/rotations/{id}/{step}"),
            Some(&json!({"item_id": item, "reason": "el sitio respondió"})),
        )
        .await
    }
}

#[tokio::test]
async fn the_person_offers_a_task_and_the_agent_sees_it() {
    let w = world().await;
    let offered = w.offered();

    // What the server refuses: a signature over a request, no offer,
    // rotate without a site, an item outside the grant, a clock too far
    // off, an unknown agent.
    assert_eq!(
        w.offer_signed(&offered, b"{}", now_ms()).await.status(),
        StatusCode::BAD_REQUEST
    );
    let mut bare = offered.clone();
    bare.offer = None;
    assert_eq!(w.offer(&bare).await.status(), StatusCode::BAD_REQUEST);
    let mut nowhere = offered.clone();
    nowhere.access[0].domains.clear();
    let res = w.offer(&nowhere).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(
        error_text(res)
            .await
            .contains("rotate needs the item's site")
    );
    let mut stranger = offered.clone();
    stranger.access[0].item_id = ItemId::generate();
    assert_eq!(w.offer(&stranger).await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        w.offer_signed(&offered, &[], now_ms() - 3_600_000)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut other_agent = offered.clone();
    other_agent.agent_id = klav_core::ids::AgentId::generate();
    assert_eq!(w.offer(&other_agent).await.status(), StatusCode::NOT_FOUND);

    // Offered: approved from the start, with an empty request.
    let res = w.offer(&offered).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let info: TaskInfo = res.json().await.expect("test");
    assert_eq!(info.id, offered.task_id);
    assert_eq!(info.status, TaskStatus::Approved);
    assert!(info.request.as_bytes().is_empty());
    assert_eq!(info.revision, 1);
    assert_eq!(
        info.expires_at,
        Some(i64::try_from(offered.expires_at_ms).expect("test"))
    );
    // The same ID twice is a conflict.
    assert_eq!(w.offer(&offered).await.status(), StatusCode::CONFLICT);

    // The agent lists it, with the signed decision and its offer.
    let list: TaskList = w
        .agent(Method::GET, "/v1/agent/tasks", None)
        .await
        .json()
        .await
        .expect("test");
    let seen = list
        .tasks
        .iter()
        .find(|t| t.id == offered.task_id)
        .expect("the agent sees the offered task");
    let decision: TaskDecision =
        serde_json::from_slice(seen.decision.as_ref().expect("test").as_bytes()).expect("test");
    assert_eq!(decision, offered);
    assert!(
        agent::verify_task_decision(
            w.ana.identity.public(),
            &TaskDecisionToSign {
                task: seen.id,
                agent: w.agent.id,
                request: seen.request.as_bytes(),
                decision: seen.decision.as_ref().expect("test").as_bytes(),
                approve: true,
                decided_at_ms: u64::try_from(seen.decided_at.expect("test")).expect("test"),
            },
            &klav_core::crypto::sign::Signature::from_bytes(
                seen.signature
                    .as_ref()
                    .expect("test")
                    .as_bytes()
                    .try_into()
                    .expect("test"),
            ),
        )
        .is_ok()
    );

    // The log has the decision with the empty request it answers.
    let events = w.events().await;
    let decided = events
        .iter()
        .find(|e| e.action == "task.decided" && e.task_id == Some(offered.task_id))
        .expect("task.decided");
    assert_eq!(decided.outcome.as_deref(), Some("approve"));
    assert!(
        decided
            .task_request
            .as_ref()
            .is_some_and(|r| r.as_bytes().is_empty())
    );

    // «Add to the task» works on an offered task and keeps the offer.
    let mut added = offered.clone();
    added.revision = 2;
    added.offer = None;
    assert_eq!(
        w.decide(offered.task_id, true, &added).await.status(),
        StatusCode::BAD_REQUEST
    );
    added.offer.clone_from(&offered.offer);
    added.access[0].domains.push("www.banco.example".into());
    assert_eq!(
        w.decide(offered.task_id, true, &added).await.status(),
        StatusCode::OK
    );
}

/// A task or rotation step the person's log verifier would refuse is never
/// logged: a signed path with a query string (a bare `?` too) or an escaped
/// ID is refused with `400`, and a request signed at the edge of the clock
/// window whose body arrives past it with `401`, as a stale one. Nothing
/// it would have started is left behind, and the log keeps only what
/// verifies.
#[tokio::test]
async fn a_task_step_the_log_would_refuse_is_never_logged() {
    let w = world().await;
    let server = &w.server;
    let mut wrong = Vec::new();
    let bad = StatusCode::BAD_REQUEST;
    let world = &w;
    let call = |method: Method, path: String, body: Value| async move {
        world.agent(method, &path, Some(&body)).await
    };

    // task.requested, and a late one.
    let request = serde_json::to_value(w.request()).expect("test");
    for q in ["?x=1", "?"] {
        server
            .refused_unlogged(
                &w.ana,
                &format!("task.requested with `{q}`"),
                bad,
                call(Method::POST, format!("/v1/agent/tasks{q}"), request.clone()),
                &mut wrong,
            )
            .await;
    }
    server
        .refused_unlogged(
            &w.ana,
            "task.requested, its body past the clock window",
            StatusCode::UNAUTHORIZED,
            server.agent_call_late(
                &w.agent,
                Method::POST,
                "/v1/agent/tasks",
                &request,
                std::time::Duration::from_millis(1500),
            ),
            &mut wrong,
        )
        .await;
    let tasks: Vec<TaskInfo> = w
        .agent(Method::GET, "/v1/agent/tasks", None)
        .await
        .json::<TaskList>()
        .await
        .expect("test")
        .tasks;
    if !tasks.is_empty() {
        wrong.push(format!("a refused request left {} task(s)", tasks.len()));
    }

    // The agent's task.ended, each case on a task of its own.
    let end = json!({"reason": "facturas descargadas"});
    for what in ["query", "escaped ID"] {
        let (task, _) = w.approved_task().await;
        let path = match what {
            "query" => format!("/v1/agent/tasks/{task}/end?x=1"),
            _ => format!("/v1/agent/tasks/{}/end", escaped(task)),
        };
        server
            .refused_unlogged(
                &w.ana,
                &format!("task.ended with a {what}"),
                bad,
                call(Method::POST, path, end.clone()),
                &mut wrong,
            )
            .await;
        TestServer::expect_status(
            &mut wrong,
            &format!("the honest task.ended after the {what}"),
            call(
                Method::POST,
                format!("/v1/agent/tasks/{task}/end"),
                end.clone(),
            )
            .await
            .status(),
            StatusCode::OK,
        );
    }

    // The agent's rotate.confirmed and rotate.cancelled, each case on a
    // change of its own, then rotate.started.
    let offered = w.offered();
    assert_eq!(w.offer(&offered).await.status(), StatusCode::CREATED);
    let start = json!({
        "item_id": w.bank, "reason": "r", "claims": {"domain": "banco.example"},
    });
    let finish = json!({"item_id": w.bank, "reason": "el sitio respondió"});
    for step in ["confirm", "cancel"] {
        for what in ["query", "escaped ID"] {
            let res = call(Method::POST, "/v1/agent/rotations".into(), start.clone()).await;
            assert_eq!(res.status(), StatusCode::CREATED);
            let rotation = res
                .json::<RotationStarted>()
                .await
                .expect("test")
                .rotation
                .id;
            let path = match what {
                "query" => format!("/v1/agent/rotations/{rotation}/{step}?x=1"),
                _ => format!("/v1/agent/rotations/{}/{step}", escaped(rotation)),
            };
            server
                .refused_unlogged(
                    &w.ana,
                    &format!("rotate {step} with a {what}"),
                    bad,
                    call(Method::POST, path, finish.clone()),
                    &mut wrong,
                )
                .await;
            TestServer::expect_status(
                &mut wrong,
                &format!("the honest rotate.cancelled after {step} with a {what}"),
                w.rotate_finish(rotation, w.bank, "cancel").await.status(),
                StatusCode::OK,
            );
        }
    }
    server
        .refused_unlogged(
            &w.ana,
            "rotate.started with a query",
            bad,
            call(Method::POST, "/v1/agent/rotations?x=1".into(), start),
            &mut wrong,
        )
        .await;

    // The log verifies.
    wrong.extend(server.proofs_the_log_refuses(&w.ana).await);
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// A task request or end that passes the extractor's checks but whose
/// signature has left the clock window by the time it is logged is refused
/// with `401` (as a stale request) and leaves nothing behind: no task, no
/// ended task, no event. The account's lock holds it between the two
/// (`agent_call_held`).
#[tokio::test]
async fn a_task_step_logged_too_late_leaves_nothing_behind() {
    let w = world().await;
    let server = &w.server;
    let tasks = || async {
        w.agent(Method::GET, "/v1/agent/tasks", None)
            .await
            .json::<TaskList>()
            .await
            .expect("test")
            .tasks
    };
    let request = serde_json::to_value(w.request()).expect("test");
    let before = server.chain_of(&w.ana).await.len();
    let res = server
        .agent_call_held(&w.ana, &w.agent, Method::POST, "/v1/agent/tasks", &request)
        .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(server.chain_of(&w.ana).await.len(), before);
    assert!(tasks().await.is_empty(), "a refused request left a task");

    let (task, _) = w.approved_task().await;
    let end = json!({"reason": "facturas descargadas"});
    let path = format!("/v1/agent/tasks/{task}/end");
    let before = server.chain_of(&w.ana).await.len();
    let res = server
        .agent_call_held(&w.ana, &w.agent, Method::POST, &path, &end)
        .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(server.chain_of(&w.ana).await.len(), before);
    assert_eq!(w.task(task).await.status, TaskStatus::Approved);
    assert_eq!(
        w.agent(Method::POST, &path, Some(&end)).await.status(),
        StatusCode::OK
    );
    let wrong = server.proofs_the_log_refuses(&w.ana).await;
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[tokio::test]
async fn rotate_goes_step_by_step_inside_a_task() {
    let w = world().await;

    // Without a task, rotate is denied (and logged).
    let res = w.rotate_start(w.bank, Some("banco.example")).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(error_text(res).await.contains("request_task"));

    let offered = w.offered();
    assert_eq!(w.offer(&offered).await.status(), StatusCode::CREATED);
    // The host is mandatory, and must be the task's.
    assert_eq!(
        w.rotate_start(w.bank, None).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        w.rotate_start(w.bank, Some("otro.example")).await.status(),
        StatusCode::FORBIDDEN
    );
    // Another item is not in the task.
    assert_eq!(
        w.rotate_start(w.aws, Some("signin.aws.amazon.com"))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );

    // Started: the change and its task, for klavd to verify.
    let res = w.rotate_start(w.bank, Some("Banco.Example")).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let started: RotationStarted = res.json().await.expect("test");
    assert_eq!(started.rotation.status, RotationStatus::Started);
    assert_eq!(started.rotation.item_id, w.bank);
    assert_eq!(started.rotation.host, "banco.example");
    assert_eq!(started.rotation.task_id, offered.task_id);
    assert_eq!(started.task.id, offered.task_id);
    assert!(started.task.decision.is_some() && started.task.signature.is_some());
    let first = started.rotation.id;
    // One change per item at a time.
    let res = w.rotate_start(w.bank, Some("banco.example")).await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
    assert!(error_text(res).await.contains(&first.to_string()));
    // access still never serves rotate.
    assert_eq!(
        w.access(w.bank, "rotate", Some("banco.example"), json!({}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );

    // Confirmed once, for the same item only.
    assert_eq!(
        w.rotate_finish(first, w.aws, "confirm").await.status(),
        StatusCode::BAD_REQUEST
    );
    let res = w.rotate_finish(first, w.bank, "confirm").await;
    assert_eq!(res.status(), StatusCode::OK);
    let done: RotationInfo = res.json().await.expect("test");
    assert_eq!(done.status, RotationStatus::Confirmed);
    assert!(done.finished_at.is_some());
    for step in ["confirm", "cancel"] {
        assert_eq!(
            w.rotate_finish(first, w.bank, step).await.status(),
            StatusCode::CONFLICT
        );
    }
    assert_eq!(
        w.rotate_finish(RotationId::generate(), w.bank, "confirm")
            .await
            .status(),
        StatusCode::NOT_FOUND
    );

    // A second change, cancelled.
    let second: RotationStarted = w
        .rotate_start(w.bank, Some("banco.example"))
        .await
        .json()
        .await
        .expect("test");
    let res = w.rotate_finish(second.rotation.id, w.bank, "cancel").await;
    assert_eq!(res.status(), StatusCode::OK);
    let cancelled: RotationInfo = res.json().await.expect("test");
    assert_eq!(cancelled.status, RotationStatus::Cancelled);

    // A third, left started when the person ends the task: confirming is
    // denied now, and the next task's first start abandons it.
    let third: RotationStarted = w
        .rotate_start(w.bank, Some("banco.example"))
        .await
        .json()
        .await
        .expect("test");
    assert_eq!(
        w.end_as_person(offered.task_id).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        w.rotate_finish(third.rotation.id, w.bank, "confirm")
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let again = w.offered();
    assert_eq!(w.offer(&again).await.status(), StatusCode::CREATED);
    let res = w.rotate_start(w.bank, Some("banco.example")).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let fourth: RotationStarted = res.json().await.expect("test");
    assert_eq!(fourth.rotation.task_id, again.task_id);
    assert_eq!(
        w.rotate_finish(third.rotation.id, w.bank, "cancel")
            .await
            .status(),
        StatusCode::CONFLICT,
        "the third change was abandoned"
    );

    // The log: each step under its task, with the item and the host,
    // never a value.
    let events = w.events().await;
    let steps: Vec<(&str, &str)> = events
        .iter()
        .filter(|e| e.action.starts_with("rotate."))
        .map(|e| (e.action.as_str(), e.outcome.as_deref().unwrap_or("")))
        .collect();
    assert_eq!(
        steps,
        [
            ("rotate.started", "deny"),
            ("rotate.started", "deny"),
            ("rotate.started", "deny"),
            ("rotate.started", "allow"),
            ("rotate.confirmed", "allow"),
            ("rotate.started", "allow"),
            ("rotate.cancelled", "allow"),
            ("rotate.started", "allow"),
            ("rotate.confirmed", "deny"),
            ("rotate.started", "allow"),
        ]
    );
    for e in events.iter().filter(|e| e.action.starts_with("rotate.")) {
        assert_eq!(e.permission, Some(Permission::Rotate));
        assert!(e.agent_proof.is_some());
        let json = serde_json::to_string(e).expect("test");
        assert!(!json.contains("hunter2"), "a value in {json}");
        if e.outcome.as_deref() == Some("allow") {
            assert_eq!(e.item_id, Some(w.bank));
            assert_eq!(e.domain.as_deref(), Some("banco.example"));
            assert!(e.task_id == Some(offered.task_id) || e.task_id == Some(again.task_id));
        }
    }
}

// --------------------- the person's rotation step in its own transaction --

/// The person's two steps on a started change: the path's last part, the
/// event and the status it leaves.
const PERSON_STEPS: [(&str, &str, RotationStatus); 2] = [
    ("confirm", "rotate.confirmed", RotationStatus::Confirmed),
    ("cancel", "rotate.cancelled", RotationStatus::Cancelled),
];

impl World {
    /// Offers the task that lets the agent change the bank's password.
    async fn rotation_task(&self) -> TaskId {
        let offered = self.offered();
        assert_eq!(self.offer(&offered).await.status(), StatusCode::CREATED);
        offered.task_id
    }

    /// A change of the bank's password the agent started inside the task.
    async fn started_rotation(&self) -> RotationId {
        let res = self.rotate_start(self.bank, Some("banco.example")).await;
        assert_eq!(res.status(), StatusCode::CREATED);
        let started: RotationStarted = res.json().await.expect("test");
        started.rotation.id
    }

    /// The change's stored status, read straight from the database.
    async fn rotation_status(&self, db: &sqlx::AnyPool, id: RotationId) -> String {
        sqlx::query_scalar("SELECT status FROM rotations WHERE id = $1")
            .bind(id.to_string())
            .fetch_one(db)
            .await
            .expect("test")
    }

    /// The person settles the change from the item's card.
    fn person_step(
        &self,
        id: RotationId,
        step: &str,
    ) -> impl std::future::Future<Output = reqwest::Result<reqwest::Response>> + use<> {
        self.server
            .post_auth(&self.ana, &format!("/v1/rotations/{id}/{step}"))
            .send()
    }
}

/// A step of the person on a change whose event the log refuses is not
/// made: the change stays started, with no event, and the same step then
/// succeeds.
#[tokio::test]
async fn a_rotation_step_that_cannot_be_logged_is_not_made() {
    let w = world().await;
    let db = w.server.raw_db().await;
    let task = w.rotation_task().await;
    for (step, action, done) in PERSON_STEPS {
        let id = w.started_rotation().await;
        let before = w.logged(&db, action, task).await.len();
        w.server.refuse_audit_action(action).await;
        let res = w.person_step(id, step).await.expect("test");
        w.server.allow_audit_action(action).await;
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR, "{step}");
        assert_eq!(
            w.rotation_status(&db, id).await,
            RotationStatus::Started.as_str(),
            "{step}"
        );
        assert_eq!(w.logged(&db, action, task).await.len(), before, "{step}");
        let res = w.person_step(id, step).await.expect("test");
        assert_eq!(res.status(), StatusCode::OK, "{step}");
        assert_eq!(w.rotation_status(&db, id).await, done.as_str(), "{step}");
        assert_eq!(
            w.logged(&db, action, task).await.len(),
            before + 1,
            "{step}"
        );
    }
}

/// A step of the person the database refuses to store logs no event: the
/// event is appended in the step's transaction, not in one of its own
/// before it.
#[tokio::test]
async fn a_rotation_step_that_cannot_be_stored_is_not_logged() {
    let w = world().await;
    let db = w.server.raw_db().await;
    let task = w.rotation_task().await;
    for (step, action, done) in PERSON_STEPS {
        let id = w.started_rotation().await;
        let before = w.logged(&db, action, task).await.len();
        w.server.refuse_writes("rotations").await;
        let res = w.person_step(id, step).await.expect("test");
        w.server.allow_writes("rotations").await;
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR, "{step}");
        assert_eq!(
            w.rotation_status(&db, id).await,
            RotationStatus::Started.as_str(),
            "{step}"
        );
        assert_eq!(w.logged(&db, action, task).await.len(), before, "{step}");
        let res = w.person_step(id, step).await.expect("test");
        assert_eq!(res.status(), StatusCode::OK, "{step}");
        assert_eq!(w.rotation_status(&db, id).await, done.as_str(), "{step}");
        assert_eq!(
            w.logged(&db, action, task).await.len(),
            before + 1,
            "{step}"
        );
    }
}

/// Postgres only: each step of the person writes the change and appends
/// its event in one transaction.
#[tokio::test]
async fn a_rotation_step_and_its_event_share_one_transaction() {
    let w = world().await;
    if !w.server.is_postgres() {
        return;
    }
    let db = w.server.raw_db().await;
    w.rotation_task().await;
    for (step, action, _) in PERSON_STEPS {
        let id = w.started_rotation().await;
        let res = w.person_step(id, step).await.expect("test");
        assert_eq!(res.status(), StatusCode::OK, "{step}");
        w.server
            .assert_written_with(&db, w.ana.account_id, "rotations", &id.to_string(), action)
            .await;
    }
}

/// Postgres only: a step of the person takes the account's lock before
/// the change's row, as every write that logs in its own transaction does.
#[tokio::test]
async fn a_rotation_step_locks_the_account_before_the_change() {
    let w = world().await;
    if !w.server.is_postgres() {
        return;
    }
    w.rotation_task().await;
    let id = w.started_rotation().await;
    let res = w
        .server
        .assert_account_locked_first(
            w.ana.account_id,
            "UPDATE rotations SET status = status WHERE id = $1",
            id.to_string(),
            w.person_step(id, "confirm"),
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
}

impl World {
    async fn person_event(&self, session: &Session, body: &Value) -> reqwest::Response {
        self.server
            .post_auth(session, "/v1/audit/person")
            .json(body)
            .send()
            .await
            .expect("test")
    }
}

/// `POST /v1/audit/person` (ADR 0020 §10): a device of the person logs
/// `passkey.used` with only the item (and the agent and task when an agent
/// used it); the server adds vault, project and device and checks the rest.
#[tokio::test]
async fn the_person_logs_passkey_use() {
    let w = world().await;
    let res = w
        .person_event(&w.ana, &json!({"action": "passkey.used", "item_id": w.aws}))
        .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let used = w.events().await.pop().expect("event");
    assert_eq!(used.action, "passkey.used");
    assert_eq!(used.actor, klav_proto::audit::ActorKind::Person);
    assert_eq!(used.item_id, Some(w.aws));
    assert_eq!(used.vault_id, Some(w.vault.id));
    assert_eq!(used.project_id, Some(w.project.id));
    assert!(used.device_id.is_some());
    assert!(used.domain.is_none() && used.agent_id.is_none() && used.task_id.is_none());

    // An agent's use, under its task.
    let (task, _) = w.approved_task().await;
    let res = w
        .person_event(
            &w.ana,
            &json!({"action": "passkey.used", "item_id": w.aws, "agent_id": w.agent.id, "task_id": task}),
        )
        .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let used = w.events().await.pop().expect("event");
    assert_eq!(
        (used.agent_id, used.task_id),
        (Some(w.agent.id), Some(task))
    );

    // Only person actions, no extra fields, agent and task together and
    // matching, an item of the account.
    let before = w.events().await.len();
    let other_agent = TestAgent::new();
    let bad = [
        json!({"action": "item.updated", "item_id": w.aws}),
        json!({"action": "agent.access", "item_id": w.aws}),
        json!({"action": "passkey.used", "item_id": w.aws, "domain": "aws.amazon.com"}),
        json!({"action": "passkey.used", "item_id": w.aws, "task_id": task}),
        json!({"action": "passkey.used", "item_id": w.aws, "agent_id": w.agent.id}),
        json!({"action": "passkey.used", "item_id": w.aws, "agent_id": other_agent.id, "task_id": task}),
    ];
    for body in &bad {
        let status = w.person_event(&w.ana, body).await.status();
        assert!(status.is_client_error(), "{body}: {status}");
    }
    assert_eq!(
        w.person_event(
            &w.ana,
            &json!({"action": "passkey.used", "item_id": w.aws, "agent_id": w.agent.id, "task_id": TaskId::generate()}),
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        w.person_event(
            &w.ana,
            &json!({"action": "passkey.used", "item_id": ItemId::generate()})
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    // Another account cannot log a use of Ana's item, nor of her task.
    let bea = w
        .server
        .login(&w.server.signup("bea@example.com", "pw").await, "phone")
        .await;
    assert_eq!(
        w.person_event(&bea, &json!({"action": "passkey.used", "item_id": w.aws}))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    // An agent does not reach it: it has no device session.
    let res = w
        .agent(
            Method::POST,
            "/v1/audit/person",
            Some(&json!({"action": "passkey.used", "item_id": w.aws})),
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(w.events().await.len(), before, "nothing was logged");

    // A device that floods the chain is cut off.
    let mut limited = false;
    for _ in 0..40 {
        let status = w
            .person_event(
                &w.ana,
                &json!({"action": "passkey.used", "item_id": w.telmex}),
            )
            .await
            .status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    assert!(limited);
}

/// The log keeps the body of a task request and of an agent's end, so the
/// person can check the reason the agent signed (ADR 0030 §4.2): a larger
/// body is refused before anything is stored or logged.
#[tokio::test]
async fn task_bodies_too_large_to_log_are_refused() {
    let w = world().await;
    let send_padded = |path: String, value: Value| {
        let w = &w;
        async move {
            let mut bytes = serde_json::to_vec(&value).expect("test");
            // Valid JSON, just larger than the log keeps.
            bytes.splice(1..1, std::iter::repeat_n(b' ', 17 * 1024));
            let signed = w.agent.sign("POST", &path, &bytes, now_ms());
            w.server
                .agent_raw(&w.agent, Method::POST, &path, Some(&bytes), &signed)
                .await
        }
    };
    let before = w.events().await.len();
    let request = serde_json::to_value(w.request()).expect("test");
    let res = send_padded("/v1/agent/tasks".into(), request).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let (task, _) = w.approved_task().await;
    let after_task = w.events().await.len();
    assert_eq!(after_task, before + 2, "only the honest task is logged");
    let res = send_padded(
        format!("/v1/agent/tasks/{task}/end"),
        json!({"reason": "listo"}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(w.events().await.len(), after_task);
    // Within the limit the same request goes through, body and all.
    assert_eq!(
        w.ask_task(&w.request()).await.status(),
        StatusCode::ACCEPTED
    );
    let events = w.events().await;
    let last = events.last().expect("event");
    assert_eq!(last.action, "task.requested");
    assert!(last.agent_proof.as_ref().is_some_and(|p| p.body.is_some()));
}

#[tokio::test]
async fn fill_without_a_site_never_goes_through_a_task() {
    // ADR 0030 §6: the server refuses to store a decision with `fill` and no
    // host, and an old one stored that way fails closed.
    let w = world().await;
    let id = w.pending_task().await;
    let mut decision = w.approval(id, u64::try_from(now_ms() + 3_600_000).expect("test"));
    decision.access[1].domains.clear();
    let res = w.decide(id, true, &decision).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(error_text(res).await.contains("need a site"));

    let (id, mut decision) = w.approved_task().await;
    assert_eq!(
        w.access(w.telmex, "fill", Some("telmex.com"), json!({}))
            .await
            .status(),
        StatusCode::OK
    );
    decision.access[1].domains.clear();
    let db = w.server.raw_db().await;
    sqlx::query("UPDATE tasks SET decision = $1 WHERE id = $2")
        .bind(serde_json::to_vec(&decision).expect("test"))
        .bind(id.to_string())
        .execute(&db)
        .await
        .expect("test");
    for host in [Some("telmex.com"), Some("evil.example"), None] {
        assert_eq!(
            w.access(w.telmex, "fill", host, json!({})).await.status(),
            StatusCode::ACCEPTED,
            "{host:?}"
        );
    }
}

/// Layer 06 of the 2026-11 round: the caps are counted and taken in one
/// step. Twenty requests at once never leave more than five pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_requests_never_pass_the_cap() {
    let w = world().await;
    let request = w.request();
    let answers = futures_util::future::join_all((0..20).map(|_| w.ask_task(&request))).await;
    let accepted = answers
        .iter()
        .filter(|r| r.status() == StatusCode::ACCEPTED)
        .count();
    assert!(
        answers.iter().all(|r| matches!(
            r.status(),
            StatusCode::ACCEPTED | StatusCode::TOO_MANY_REQUESTS
        )),
        "{:?}",
        answers
            .iter()
            .map(reqwest::Response::status)
            .collect::<Vec<_>>()
    );
    let pending: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM tasks WHERE agent_id = $1 AND status = 'pending'")
            .bind(w.agent.id.to_string())
            .fetch_one(&w.server.raw_db().await)
            .await
            .expect("count");
    assert_eq!(accepted, 5, "accepted");
    assert_eq!(pending, 5, "pending in the database");
}

// ------------------- the agent's own task writes: request and end, guarded --

impl World {
    /// The agent's tasks, of any status, read straight from the database.
    async fn tasks_stored(&self, db: &sqlx::AnyPool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM tasks WHERE agent_id = $1")
            .bind(self.agent.id.to_string())
            .fetch_one(db)
            .await
            .expect("test")
    }

    /// How many of Ana's events have `action`, read straight from the
    /// database.
    async fn actions_logged(&self, db: &sqlx::AnyPool, action: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE account_id = $1 AND action = $2",
        )
        .bind(self.ana.account_id.to_string())
        .bind(action)
        .fetch_one(db)
        .await
        .expect("test")
    }

    /// `POST /v1/agent/tasks/{id}/end`: the agent finishes, or withdraws
    /// its request.
    async fn end_as_agent(&self, id: TaskId) -> reqwest::Response {
        self.agent(
            Method::POST,
            &format!("/v1/agent/tasks/{id}/end"),
            Some(&json!({"reason": "las facturas ya están"})),
        )
        .await
    }
}

/// The agent's task request whose `task.requested` the log refuses stores
/// no task: the request is logged in the task's own transaction. The same
/// request then goes through, with one event.
#[tokio::test]
async fn a_task_request_that_cannot_be_logged_is_not_stored() {
    let w = world().await;
    let db = w.server.raw_db().await;
    w.server.refuse_audit_action("task.requested").await;
    let status = w.ask_task(&w.request()).await.status();
    w.server.allow_audit_action("task.requested").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(w.tasks_stored(&db).await, 0, "no task stored");
    assert_eq!(w.actions_logged(&db, "task.requested").await, 0);
    let id = w.pending_task().await;
    assert!(w.stored_as(&db, id, TaskStatus::Pending).await);
    assert_eq!(w.logged(&db, "task.requested", id).await.len(), 1);
}

/// The agent's task request the database refuses to store logs no
/// `task.requested`: the event is appended in the task's transaction, not
/// in one of its own before it.
#[tokio::test]
async fn a_task_request_that_cannot_be_stored_is_not_logged() {
    let w = world().await;
    let db = w.server.raw_db().await;
    w.server.refuse_writes("tasks").await;
    let status = w.ask_task(&w.request()).await.status();
    w.server.allow_writes("tasks").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(w.tasks_stored(&db).await, 0, "no task stored");
    assert_eq!(w.actions_logged(&db, "task.requested").await, 0);
    let id = w.pending_task().await;
    assert_eq!(w.logged(&db, "task.requested", id).await.len(), 1);
}

/// Postgres only: the agent's task request writes the task and appends its
/// `task.requested` in one transaction.
#[tokio::test]
async fn a_task_request_and_its_event_share_one_transaction() {
    let w = world().await;
    if !w.server.is_postgres() {
        return;
    }
    let db = w.server.raw_db().await;
    let id = w.pending_task().await;
    w.server
        .assert_written_with(
            &db,
            w.ana.account_id,
            "tasks",
            &id.to_string(),
            "task.requested",
        )
        .await;
}

/// The agent's end whose `task.ended` the log refuses is not made, for an
/// approved task and for a pending request it withdraws: the task stays
/// as it was, with no event, until an end the log takes.
#[tokio::test]
async fn an_agent_end_that_cannot_be_logged_is_not_made() {
    let w = world().await;
    let db = w.server.raw_db().await;
    let (approved, _) = w.approved_task().await;
    let pending = w.pending_task().await;
    for (id, status) in [
        (approved, TaskStatus::Approved),
        (pending, TaskStatus::Pending),
    ] {
        w.server.refuse_audit_action("task.ended").await;
        let res = w.end_as_agent(id).await.status();
        w.server.allow_audit_action("task.ended").await;
        assert_eq!(res, StatusCode::INTERNAL_SERVER_ERROR, "{status:?}");
        assert!(w.stored_as(&db, id, status).await, "{status:?}");
        assert!(
            w.logged(&db, "task.ended", id).await.is_empty(),
            "{status:?}"
        );
        assert_eq!(w.end_as_agent(id).await.status(), StatusCode::OK);
        assert!(w.stored_as(&db, id, TaskStatus::Ended).await, "{status:?}");
        let ended: Vec<_> = w
            .logged(&db, "task.ended", id)
            .await
            .into_iter()
            .map(|e| e.outcome)
            .collect();
        assert_eq!(ended, [Some("agent".to_owned())], "{status:?}");
    }
}

/// The agent's end the database refuses to store logs no `task.ended`.
#[tokio::test]
async fn an_agent_end_that_cannot_be_stored_is_not_logged() {
    let w = world().await;
    let db = w.server.raw_db().await;
    let (approved, _) = w.approved_task().await;
    let pending = w.pending_task().await;
    for (id, status) in [
        (approved, TaskStatus::Approved),
        (pending, TaskStatus::Pending),
    ] {
        w.server.refuse_writes("tasks").await;
        let res = w.end_as_agent(id).await.status();
        w.server.allow_writes("tasks").await;
        assert_eq!(res, StatusCode::INTERNAL_SERVER_ERROR, "{status:?}");
        assert!(w.stored_as(&db, id, status).await, "{status:?}");
        assert!(
            w.logged(&db, "task.ended", id).await.is_empty(),
            "{status:?}"
        );
        assert_eq!(w.end_as_agent(id).await.status(), StatusCode::OK);
        assert_eq!(w.logged(&db, "task.ended", id).await.len(), 1, "{status:?}");
    }
}

/// Postgres only: the agent's end writes the task and appends its
/// `task.ended` in one transaction.
#[tokio::test]
async fn an_agent_end_and_its_event_share_one_transaction() {
    let w = world().await;
    if !w.server.is_postgres() {
        return;
    }
    let db = w.server.raw_db().await;
    let (approved, _) = w.approved_task().await;
    let pending = w.pending_task().await;
    for id in [approved, pending] {
        assert_eq!(w.end_as_agent(id).await.status(), StatusCode::OK);
        w.server
            .assert_written_with(
                &db,
                w.ana.account_id,
                "tasks",
                &id.to_string(),
                "task.ended",
            )
            .await;
    }
}

// ------------- an agent revoked while its request waits for the lock --
//
// The extractor reads the agent's status before the account's lock. Each
// agent request that logs is checked again when its event is appended,
// under that lock (`audit::append_in`), so a revocation committed while
// the request waited leaves nothing written and nothing logged after
// `agent.revoked`.

/// An agent request that writes or logs (a denial is logged too).
#[derive(Clone, Copy, Debug)]
enum AgentWrite {
    Access,
    Deny,
    Ask,
    Task,
    Create,
    Update,
    Trash,
    RotateStart,
    RotateFinish,
}

const AGENT_WRITES: [AgentWrite; 9] = [
    AgentWrite::Access,
    AgentWrite::Deny,
    AgentWrite::Ask,
    AgentWrite::Task,
    AgentWrite::Create,
    AgentWrite::Update,
    AgentWrite::Trash,
    AgentWrite::RotateStart,
    AgentWrite::RotateFinish,
];

impl AgentWrite {
    /// What an active agent gets.
    fn taken(self) -> StatusCode {
        match self {
            AgentWrite::Access | AgentWrite::Update | AgentWrite::Trash => StatusCode::OK,
            AgentWrite::RotateFinish => StatusCode::OK,
            AgentWrite::Deny => StatusCode::FORBIDDEN,
            AgentWrite::Ask | AgentWrite::Task => StatusCode::ACCEPTED,
            AgentWrite::Create | AgentWrite::RotateStart => StatusCode::CREATED,
        }
    }
}

/// An agent's signed request, made before it is sent.
struct Prepared {
    method: Method,
    path: String,
    body: Value,
}

/// What the agent's requests leave behind, and the account's log.
#[derive(Debug, PartialEq, Eq)]
struct Footprint {
    events: i64,
    approvals: i64,
    tasks: i64,
    items: i64,
    versions: i64,
    trashed: i64,
    rotations: i64,
    started: i64,
}

impl World {
    /// The body of `POST /v1/agent/items` for a new login in the project.
    fn new_item(
        &self,
    ) -> (
        klav_core::model::Item,
        klav_core::crypto::keys::ItemKey,
        Value,
    ) {
        let key = klav_core::crypto::keys::ItemKey::generate();
        let item = login_item("Staging DB", "svc", "pw-1");
        let upload = common::vault::seal(&self.vault, &self.project, &item, &key, 1);
        let body = json!({
            "vault_id": self.vault.id,
            "reason": "guardar las credenciales de staging",
            "item": {
                "id": item.id(), "project_id": self.project.id, "version": 1,
                "wrapped_key": Blob::new(upload.wrapped_key),
                "project_version": 1,
                "overview": Blob::new(upload.sealed.overview),
                "details": Blob::new(upload.sealed.details),
            },
        });
        (item, key, body)
    }

    /// Readies everything `write` needs (a task, an item of the agent's,
    /// a started change, a grant that allows updates and deletes), so that
    /// an active agent's request would be taken, and returns the request.
    async fn ready_for(&self, write: AgentWrite) -> Prepared {
        let post = |path: &str, body: Value| Prepared {
            method: Method::POST,
            path: path.to_owned(),
            body,
        };
        let access = |item: ItemId, permission: &str, domain: Option<&str>| {
            post(
                "/v1/agent/access",
                json!({
                    "item_id": item,
                    "permission": permission,
                    "reason": "descargar la factura",
                    "claims": domain.map(|d| json!({"domain": d})).unwrap_or(json!({})),
                }),
            )
        };
        match write {
            AgentWrite::Access => {
                self.approved_task().await;
                access(self.aws, "fill", Some("signin.aws.amazon.com"))
            }
            AgentWrite::Deny => access(self.bank, "reveal", None),
            AgentWrite::Ask => access(self.telmex, "totp", None),
            AgentWrite::Task => post(
                "/v1/agent/tasks",
                serde_json::to_value(self.request()).expect("test"),
            ),
            AgentWrite::Create => post("/v1/agent/items", self.new_item().2),
            AgentWrite::Update | AgentWrite::Trash => {
                let mut policy = ask_policy();
                policy
                    .rules
                    .push(Rule::new(Permission::Update, Effect::Allow));
                policy
                    .rules
                    .push(Rule::new(Permission::Delete, Effect::Allow));
                let grant = TestServer::build_grant(
                    &self.ana,
                    &self.agent,
                    2,
                    policy,
                    &[(&self.vault, &self.project)],
                );
                assert_eq!(
                    self.server
                        .post_grant(&self.ana, &self.agent, &grant)
                        .await
                        .status(),
                    StatusCode::OK
                );
                let (item, key, body) = self.new_item();
                let res = self
                    .agent(Method::POST, "/v1/agent/items", Some(&body))
                    .await;
                assert_eq!(res.status(), StatusCode::CREATED);
                if matches!(write, AgentWrite::Trash) {
                    return post(
                        &format!("/v1/agent/items/{}/trash", item.id()),
                        json!({"reason": "limpiar"}),
                    );
                }
                let upload = common::vault::seal(&self.vault, &self.project, &item, &key, 2);
                Prepared {
                    method: Method::PUT,
                    path: format!("/v1/agent/items/{}", item.id()),
                    body: json!({
                        "reason": "cambiar la contraseña",
                        "item": {
                            "version": 2,
                            "wrapped_key": Blob::new(upload.wrapped_key),
                            "project_version": 1,
                            "overview": Blob::new(upload.sealed.overview),
                            "details": Blob::new(upload.sealed.details),
                        },
                    }),
                }
            }
            AgentWrite::RotateStart => {
                self.rotation_task().await;
                post(
                    "/v1/agent/rotations",
                    json!({
                        "item_id": self.bank,
                        "reason": "cambiar la contraseña repetida",
                        "claims": {"domain": "banco.example"},
                    }),
                )
            }
            AgentWrite::RotateFinish => {
                self.rotation_task().await;
                let id = self.started_rotation().await;
                post(
                    &format!("/v1/agent/rotations/{id}/confirm"),
                    json!({"item_id": self.bank, "reason": "el sitio respondió"}),
                )
            }
        }
    }

    /// The person revokes the agent, through the route.
    async fn revoke(&self) {
        let at = now_ms();
        let res = self
            .server
            .post_auth(&self.ana, &format!("/v1/agents/{}/revoke", self.agent.id))
            .json(&klav_proto::agent::RevokeAgent {
                revoked_at: at,
                signature: Blob::new(
                    agent::sign_revocation(
                        &self.ana.identity,
                        self.ana.account_id,
                        self.agent.id,
                        u64::try_from(at).expect("test"),
                    )
                    .to_bytes()
                    .to_vec(),
                ),
            })
            .send()
            .await
            .expect("test");
        assert_eq!(res.status(), StatusCode::OK);
    }

    async fn send(&self, req: &Prepared) -> reqwest::Response {
        self.agent(req.method.clone(), &req.path, Some(&req.body))
            .await
    }

    async fn footprint(&self, db: &sqlx::AnyPool) -> Footprint {
        let count = |sql: &'static str| async move {
            sqlx::query_scalar::<_, i64>(sql)
                .fetch_one(db)
                .await
                .expect("count")
        };
        Footprint {
            events: count("SELECT COUNT(*) FROM audit_events").await,
            approvals: count("SELECT COUNT(*) FROM approvals").await,
            tasks: count("SELECT COUNT(*) FROM tasks").await,
            items: count("SELECT COUNT(*) FROM items").await,
            versions: count("SELECT COUNT(*) FROM item_versions").await,
            trashed: count("SELECT COUNT(*) FROM items WHERE trashed_at IS NOT NULL").await,
            rotations: count("SELECT COUNT(*) FROM rotations").await,
            started: count("SELECT COUNT(*) FROM rotations WHERE status = 'started'").await,
        }
    }
}

/// What the extractor answers an agent that is not active.
fn not_active() -> (StatusCode, klav_proto::ErrorCode, String) {
    (
        StatusCode::FORBIDDEN,
        klav_proto::ErrorCode::Forbidden,
        "not allowed".to_owned(),
    )
}

/// The status, code and message of a response.
async fn answer(res: reqwest::Response) -> (StatusCode, klav_proto::ErrorCode, String) {
    let status = res.status();
    let body: klav_proto::ErrorBody = res.json().await.expect("error body");
    (status, body.error, body.message)
}

/// The fixtures of the two tests below take each request through: an
/// active agent's request gets its usual answer, and leaves something
/// behind (its event at least).
#[tokio::test]
async fn each_agent_write_is_taken_while_the_agent_is_active() {
    for write in AGENT_WRITES {
        let w = world().await;
        let req = w.ready_for(write).await;
        let db = w.server.raw_db().await;
        let before = w.footprint(&db).await;
        let res = w.send(&req).await;
        assert_eq!(res.status(), write.taken(), "{write:?}");
        let after = w.footprint(&db).await;
        assert!(after.events > before.events, "{write:?}: not logged");
    }
}

/// An agent the person revoked before the request: each of its writes is
/// refused by the extractor (`403 forbidden`), and nothing is written or
/// logged.
#[tokio::test]
async fn an_agent_revoked_before_it_writes_is_refused() {
    for write in AGENT_WRITES {
        let w = world().await;
        let req = w.ready_for(write).await;
        w.revoke().await;
        let db = w.server.raw_db().await;
        let before = w.footprint(&db).await;
        let res = w.send(&req).await;
        assert_eq!(answer(res).await, not_active(), "{write:?}");
        assert_eq!(w.footprint(&db).await, before, "{write:?}: nothing written");
    }
}

/// An agent revoked after the extractor let its request through, while the
/// request waits for the account's lock: when its event is appended, under
/// the lock, the server reads the agent's status again and gives the
/// extractor's answer, with nothing written and nothing logged after
/// `agent.revoked`. The test holds the account's lock (as the revocation
/// does), waits until the request waits on it (a backend that
/// `pg_blocking_pids` says this transaction blocks), marks the agent
/// revoked in that same transaction and commits. Postgres only, as the
/// proxy's pair in `sandboxes.rs`: on SQLite a request waiting for the
/// writer sits in SQLite's own busy handler, which nothing shows.
#[tokio::test]
async fn an_agent_revoked_while_its_request_waits_for_the_lock_is_refused() {
    let mut taken = Vec::new();
    for write in AGENT_WRITES {
        let w = world().await;
        if !w.server.is_postgres() {
            return;
        }
        let req = w.ready_for(write).await;
        let db = w.server.raw_db().await;
        let before = w.footprint(&db).await;
        let held = w.server.raw_db().await;
        let mut account = held.begin().await.expect("test");
        sqlx::query("UPDATE accounts SET updated_at = updated_at WHERE id = $1")
            .bind(w.ana.account_id.to_string())
            .execute(&mut *account)
            .await
            .expect("test");
        // Only a backend this transaction blocks counts: no other test's
        // request, nor a job of this server, can stand in for this one.
        let holder: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *account)
            .await
            .expect("test");
        let revoke = async {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                let waiting: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM pg_stat_activity \
                     WHERE datname = current_database() AND $1 = ANY(pg_blocking_pids(pid)) \
                     AND query LIKE 'UPDATE accounts SET updated_at = updated_at%'",
                )
                .bind(holder)
                .fetch_one(&db)
                .await
                .expect("test");
                if waiting >= 1 {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "{write:?}: not waiting"
                );
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            // A direct `UPDATE`, not the route: a second waiter on a
            // Postgres row lock has no guaranteed place in the queue. Same
            // columns as the person's revocation (`routes/agents.rs`).
            sqlx::query("UPDATE agents SET status = 'revoked', revoked_at = $1 WHERE id = $2")
                .bind(now_ms())
                .bind(w.agent.id.to_string())
                .execute(&mut *account)
                .await
                .expect("test");
            account.commit().await.expect("test");
        };
        let (res, ()) = tokio::join!(w.send(&req), revoke);
        // Every request is tried, and every one that went through is named.
        let status = res.status();
        if status == StatusCode::FORBIDDEN {
            let got = answer(res).await;
            if got != not_active() {
                taken.push(format!("{write:?}: {got:?}"));
            }
        } else {
            taken.push(format!("{write:?}: {status}"));
        }
        let after = w.footprint(&db).await;
        if after != before {
            taken.push(format!("{write:?}: wrote {after:?}, was {before:?}"));
        }
    }
    assert!(taken.is_empty(), "taken after the revocation: {taken:#?}");
}

// ------------- an agent revoked between its event and its write --
//
// Five agent writes log their event in a transaction of its own, then write
// in another: an item created, updated or sent to the trash, and a password
// change started or finished. That write takes the account's lock and reads
// the agent's status again under it, so a revocation committed after the
// event leaves the event (an `allow` without its write, as a `409` already
// can) and writes nothing.

const WRITES_AFTER_LOG: [AgentWrite; 5] = [
    AgentWrite::Create,
    AgentWrite::Update,
    AgentWrite::Trash,
    AgentWrite::RotateStart,
    AgentWrite::RotateFinish,
];

/// What `before` and `after` must differ in: one more event, nothing else.
fn only_the_event(before: &Footprint, after: &Footprint) -> bool {
    after.events == before.events + 1
        && Footprint {
            events: before.events,
            ..*after
        } == *before
}

impl World {
    /// The agent's ID, checked to be safe in a test trigger's SQL.
    fn agent_sql_id(&self) -> String {
        let id = self.agent.id.to_string();
        assert!(id.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        id
    }

    /// From now on, an event of this agent commits `meanwhile` in the
    /// event's own transaction: the event is logged (the agent was active,
    /// not paused, and the account not being deleted when it was checked),
    /// and the change is committed with it, before the write that follows.
    async fn with_its_next_event(&self, meanwhile: Meanwhile) {
        let id = self.agent_sql_id();
        let pg = self.server.is_postgres();
        let blob = if pg { "decode('00', 'hex')" } else { "x'00'" };
        let body = match meanwhile {
            Meanwhile::Revokes => "UPDATE agents SET status = 'revoked', revoked_at = NEW.at \
                 WHERE id = NEW.agent_id"
                .to_owned(),
            // The agent's own pause, with no end; the server stores the
            // person's signature and never checks it.
            Meanwhile::Pauses => format!(
                "INSERT INTO agent_pauses (account_id, scope, state, at_ms, until_ms, signature) \
                 VALUES (NEW.account_id, NEW.agent_id, 'pause', NEW.at, 0, {blob})"
            ),
            // A week away: no purge reaches it during the test.
            Meanwhile::AsksToDelete => "INSERT INTO account_deletions \
                 (account_id, device_id, requested_at, delete_at) \
                 VALUES (NEW.account_id, 'test', NEW.at, NEW.at + 604800000)"
                .to_owned(),
        };
        let statements = if pg {
            vec![
                format!(
                    "CREATE OR REPLACE FUNCTION klav_test_meanwhile() RETURNS trigger \
                     LANGUAGE plpgsql AS $$ BEGIN {body}; RETURN NEW; END $$"
                ),
                format!(
                    "CREATE TRIGGER klav_test_meanwhile AFTER INSERT ON audit_events \
                     FOR EACH ROW WHEN (NEW.agent_id = '{id}') \
                     EXECUTE FUNCTION klav_test_meanwhile()"
                ),
            ]
        } else {
            vec![format!(
                "CREATE TRIGGER klav_test_meanwhile AFTER INSERT ON audit_events \
                 WHEN NEW.agent_id = '{id}' BEGIN {body}; END"
            )]
        };
        let db = self.server.raw_db().await;
        for sql in statements {
            // The ID is checked above, so it is safe to interpolate.
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(&db)
                .await
                .expect("test trigger");
        }
        db.close().await;
    }
}

/// What a test trigger commits with the agent's event, before its write.
#[derive(Clone, Copy, Debug)]
enum Meanwhile {
    /// The person revokes the agent.
    Revokes,
    /// The person pauses the agent (ADR 0033 §7).
    Pauses,
    /// The person asks to delete the account (ADR 0037).
    AsksToDelete,
}

impl Meanwhile {
    /// The status and code the write gets.
    fn refusal(self) -> (StatusCode, klav_proto::ErrorCode) {
        let code = match self {
            Self::Revokes => klav_proto::ErrorCode::Forbidden,
            Self::Pauses => klav_proto::ErrorCode::AgentsPaused,
            Self::AsksToDelete => klav_proto::ErrorCode::AccountDeleting,
        };
        (StatusCode::FORBIDDEN, code)
    }
}

/// An agent revoked, paused, or whose account the person asked to delete
/// after its write's event was logged, before the write: the write gets
/// the answer the event's check would have given (for a revocation, the
/// extractor's `403 forbidden`; `403 agents_paused`; `403
/// account_deleting`), its event stays, and nothing else is written. Each
/// of the five writes after a revocation; an item write and a rotation's
/// start (the two transactions that write after the event,
/// `VaultWrite::begin_for_agent` and `rotate.rs`'s `agent_write`) after a
/// pause and a deletion request. A rotation's finish is not stopped by
/// those two (the test after this one). A trigger commits the change with
/// the event, so the order is the same on both databases.
#[tokio::test]
async fn an_agent_stopped_after_its_event_writes_nothing() {
    let mut cases: Vec<(Meanwhile, AgentWrite)> = WRITES_AFTER_LOG
        .iter()
        .map(|&write| (Meanwhile::Revokes, write))
        .collect();
    for meanwhile in [Meanwhile::Pauses, Meanwhile::AsksToDelete] {
        for write in [AgentWrite::Update, AgentWrite::RotateStart] {
            cases.push((meanwhile, write));
        }
    }
    let mut taken = Vec::new();
    for (meanwhile, write) in cases {
        let w = world().await;
        let req = w.ready_for(write).await;
        let db = w.server.raw_db().await;
        w.with_its_next_event(meanwhile).await;
        let before = w.footprint(&db).await;
        let res = w.send(&req).await;
        // Every write is tried, and every one that went through is named.
        let status = res.status();
        if status == StatusCode::FORBIDDEN {
            let got = answer(res).await;
            let expected = match meanwhile {
                Meanwhile::Revokes => got == not_active(),
                _ => (got.0, got.1) == meanwhile.refusal(),
            };
            if !expected {
                taken.push(format!("{meanwhile:?} {write:?}: {got:?}"));
            }
        } else {
            taken.push(format!("{meanwhile:?} {write:?}: {status}"));
        }
        let after = w.footprint(&db).await;
        if !only_the_event(&before, &after) {
            taken.push(format!(
                "{meanwhile:?} {write:?}: wrote {after:?}, was {before:?}"
            ));
        }
    }
    assert!(taken.is_empty(), "written after the event: {taken:#?}");
}

/// A rotation's finish whose event is logged still closes its row when a
/// pause or a deletion request lands between the event and the write:
/// `klavd` has already settled the item, so refusing the row's update
/// would strand a change nobody can close (`rotate.rs`'s `agent_write`).
/// Only a revocation stops it (the test above). Same trigger, both
/// databases.
#[tokio::test]
async fn a_finish_logged_before_a_pause_or_a_deletion_request_closes_its_change() {
    let mut stopped = Vec::new();
    for meanwhile in [Meanwhile::Pauses, Meanwhile::AsksToDelete] {
        let w = world().await;
        let req = w.ready_for(AgentWrite::RotateFinish).await;
        let db = w.server.raw_db().await;
        w.with_its_next_event(meanwhile).await;
        let before = w.footprint(&db).await;
        let status = w.send(&req).await.status();
        if status != AgentWrite::RotateFinish.taken() {
            stopped.push(format!("{meanwhile:?}: {status}"));
        }
        let after = w.footprint(&db).await;
        let closed = Footprint {
            events: before.events + 1,
            started: before.started - 1,
            ..before
        };
        if after != closed {
            stopped.push(format!("{meanwhile:?}: {after:?}, was {before:?}"));
        }
    }
    assert!(stopped.is_empty(), "finish stopped: {stopped:#?}");
}

/// The same, with the revocation committed while the write waits for the
/// account's lock (Postgres only, as #413's pair). Each step is ordered by
/// a lock the test holds, never by the order of a row lock's queue, which
/// Postgres does not promise once the row's holder commits an update of it:
///
/// 1. A trigger stalls the event's transaction after its insert, on an
///    advisory lock the test holds. That transaction already holds the
///    account's row.
/// 2. The test closes a gate: a statement trigger on `accounts` waits on
///    a second advisory lock before any row is locked. Then it lets the
///    event commit.
/// 3. The write reaches its `UPDATE accounts` and waits at the gate. The
///    test locks the account's row (its own statements pass the gate),
///    then opens the gate: the write waits on the row behind the test.
/// 4. The test revokes the agent in that transaction and commits.
#[tokio::test]
async fn an_agent_revoked_while_its_write_waits_for_the_lock_writes_nothing() {
    use std::time::{Duration, Instant};

    /// The first backend `blocker` blocks whose query starts with `query`;
    /// `what` names the step in the panic.
    async fn blocked_by(db: &sqlx::AnyPool, blocker: i32, query: &str, what: &str) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let pid: Option<i32> = sqlx::query_scalar(
                "SELECT pid FROM pg_stat_activity \
                 WHERE datname = current_database() AND $1 = ANY(pg_blocking_pids(pid)) \
                 AND query LIKE $2 LIMIT 1",
            )
            .bind(blocker)
            .bind(format!("{query}%"))
            .fetch_optional(db)
            .await
            .expect("test");
            if let Some(pid) = pid {
                return pid;
            }
            assert!(
                Instant::now() < deadline,
                "nothing waits on {blocker}: {what}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    async fn pid(tx: &mut sqlx::Transaction<'_, sqlx::Any>) -> i32 {
        sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut **tx)
            .await
            .expect("test")
    }

    let mut taken = Vec::new();
    for write in WRITES_AFTER_LOG {
        let w = world().await;
        if !w.server.is_postgres() {
            return;
        }
        let req = w.ready_for(write).await;
        let db = w.server.raw_db().await;
        let id = w.agent_sql_id();
        for sql in [
            "CREATE OR REPLACE FUNCTION klav_test_stall() RETURNS trigger \
             LANGUAGE plpgsql AS $$ BEGIN \
             PERFORM pg_advisory_xact_lock_shared(4242); RETURN NEW; END $$"
                .to_owned(),
            format!(
                "CREATE TRIGGER klav_test_stall AFTER INSERT ON audit_events \
                 FOR EACH ROW WHEN (NEW.agent_id = '{id}') \
                 EXECUTE FUNCTION klav_test_stall()"
            ),
            // The gate: before any row is locked, wait while the test holds
            // 4243, and hold nothing after (a session lock taken and let go
            // at once), so a transaction that passed it never blocks the
            // test from closing it. The test's own transactions pass.
            "CREATE OR REPLACE FUNCTION klav_test_gate() RETURNS trigger \
             LANGUAGE plpgsql AS $$ BEGIN \
             IF current_setting('klav.test_bypass', true) IS DISTINCT FROM 'on' THEN \
             PERFORM pg_advisory_lock_shared(4243); \
             PERFORM pg_advisory_unlock_shared(4243); \
             END IF; RETURN NULL; END $$"
                .to_owned(),
            "CREATE TRIGGER klav_test_gate BEFORE UPDATE ON accounts \
             FOR EACH STATEMENT EXECUTE FUNCTION klav_test_gate()"
                .to_owned(),
        ] {
            // The ID is checked, so it is safe to interpolate.
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(&db)
                .await
                .expect("test trigger");
        }
        let before = w.footprint(&db).await;
        let stall_db = w.server.raw_db().await;
        let mut stall = stall_db.begin().await.expect("test");
        sqlx::query("SELECT pg_advisory_xact_lock(4242)")
            .execute(&mut *stall)
            .await
            .expect("test");
        let staller = pid(&mut stall).await;
        let gate_db = w.server.raw_db().await;
        let mut gate = gate_db.begin().await.expect("test");
        let gater = pid(&mut gate).await;
        let held_db = w.server.raw_db().await;
        let mut account = held_db.begin().await.expect("test");
        sqlx::query("SET LOCAL klav.test_bypass = 'on'")
            .execute(&mut *account)
            .await
            .expect("test");
        let holder = pid(&mut account).await;

        let revoke = async {
            // 1. The request's event, inserted and stalled: it holds the
            // account's row.
            blocked_by(&db, staller, "INSERT INTO audit_events", "the event").await;
            // 2. Close the gate, then let the event commit.
            sqlx::query("SELECT pg_advisory_xact_lock(4243)")
                .execute(&mut *gate)
                .await
                .expect("test");
            stall.commit().await.expect("test");
            // 3. The write waits at the gate, before the account's row:
            // lock the row, then open the gate.
            blocked_by(&db, gater, "UPDATE accounts", "the write, at the gate").await;
            let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
                .fetch_one(&db)
                .await
                .expect("test");
            assert_eq!(events, before.events + 1, "{write:?}: the event first");
            sqlx::query("UPDATE accounts SET updated_at = updated_at WHERE id = $1")
                .bind(w.ana.account_id.to_string())
                .execute(&mut *account)
                .await
                .expect("test");
            gate.commit().await.expect("test");
            blocked_by(
                &db,
                holder,
                "UPDATE accounts",
                "the write, on the account's row",
            )
            .await;
            // 4. A direct `UPDATE`, as in #413's pair: same columns as the
            // person's revocation (`routes/agents.rs`).
            sqlx::query("UPDATE agents SET status = 'revoked', revoked_at = $1 WHERE id = $2")
                .bind(now_ms())
                .bind(w.agent.id.to_string())
                .execute(&mut *account)
                .await
                .expect("test");
            account.commit().await.expect("test");
        };
        let (res, ()) = tokio::join!(w.send(&req), revoke);
        let status = res.status();
        if status == StatusCode::FORBIDDEN {
            let got = answer(res).await;
            if got != not_active() {
                taken.push(format!("{write:?}: {got:?}"));
            }
        } else {
            taken.push(format!("{write:?}: {status}"));
        }
        let after = w.footprint(&db).await;
        if !only_the_event(&before, &after) {
            taken.push(format!("{write:?}: wrote {after:?}, was {before:?}"));
        }
    }
    assert!(taken.is_empty(), "written after the revocation: {taken:#?}");
}
