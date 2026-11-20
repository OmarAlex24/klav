//! Pausing agents (ADR 0033 §7, spec §13.9): a decision signed by the
//! account that the server enforces on every signed agent request, that
//! the audit log records, and that an old resume cannot undo.

mod common;

use common::TestServer;
use common::agent::{TestAgent, now_ms};
use common::client::Session;
use common::vault::{TestProject, TestVault, login_item};
use klav_core::crypto::agent::{PauseScope, PauseToSign, sign_pause};
use klav_core::crypto::identity::IdentityKeyPair;
use klav_core::ids::{AgentId, ItemId};
use klav_core::policy::Policy;
use klav_proto::agent::{
    AgentInfo, AgentList, AgentMe, AgentPauses, AgentStatus, PauseAgents, PauseState,
};
use klav_proto::audit::{AuditEvent, AuditPage};
use klav_proto::sync::SyncState;
use klav_proto::{Blob, ErrorBody, ErrorCode};
use reqwest::{Method, StatusCode};
use serde_json::json;

struct World {
    server: TestServer,
    ana: Session,
    vault: TestVault,
    project: TestProject,
    agent: TestAgent,
    item: ItemId,
}

async fn world() -> World {
    let server = TestServer::start().await;
    let ana = server
        .login(&server.signup("ana@example.com", "pw").await, "laptop")
        .await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let item = login_item("GitHub", "ana", "hunter2");
    server.create_item(&ana, &vault, &project, &item).await;
    let agent = TestAgent::new();
    let w = World {
        server,
        ana,
        vault,
        project,
        agent,
        item: item.id(),
    };
    w.approve(&w.agent, "bot").await;
    w
}

impl World {
    async fn approve(&self, agent: &TestAgent, name: &str) {
        self.server
            .register_agent_ok(agent, "ana@example.com", name)
            .await;
        let grant = TestServer::build_grant(
            &self.ana,
            agent,
            1,
            Policy::default(),
            &[(&self.vault, &self.project)],
        );
        assert_eq!(
            self.server
                .post_grant(&self.ana, agent, &grant)
                .await
                .status(),
            StatusCode::OK
        );
    }

    /// `inject` is allowed by the default policy.
    async fn inject(&self, agent: &TestAgent) -> reqwest::Response {
        let body =
            json!({"item_id": self.item, "permission": "inject", "reason": "run the deploy"});
        self.server
            .agent_call(agent, Method::POST, "/v1/agent/access", Some(&body))
            .await
    }

    fn decision(
        &self,
        signer: &IdentityKeyPair,
        agent: Option<AgentId>,
        pause: bool,
        at: i64,
        until: i64,
    ) -> PauseAgents {
        let signature = sign_pause(
            signer,
            &PauseToSign {
                account: self.ana.account_id,
                scope: agent.map_or(PauseScope::All, PauseScope::Agent),
                pause,
                at_ms: u64::try_from(at).expect("time"),
                until_ms: u64::try_from(until).expect("time"),
            },
        );
        PauseAgents {
            state: if pause {
                PauseState::Pause
            } else {
                PauseState::Resume
            },
            at,
            until,
            signature: Blob::new(signature.to_bytes().to_vec()),
        }
    }

    async fn post(&self, agent: Option<AgentId>, body: &PauseAgents) -> reqwest::Response {
        let path = match agent {
            Some(id) => format!("/v1/agents/{id}/pause"),
            None => "/v1/agents/pause".to_owned(),
        };
        self.server
            .post_auth(&self.ana, &path)
            .json(body)
            .send()
            .await
            .expect("post")
    }

    async fn decide(
        &self,
        agent: Option<AgentId>,
        pause: bool,
        at: i64,
        until: i64,
    ) -> AgentPauses {
        let res = self
            .post(
                agent,
                &self.decision(&self.ana.identity, agent, pause, at, until),
            )
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        res.json().await.expect("pauses")
    }

    async fn me(&self, agent: &TestAgent) -> AgentMe {
        let res = self
            .server
            .agent_call(agent, Method::GET, "/v1/agent/me", None)
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        res.json().await.expect("me")
    }

    async fn events(&self) -> Vec<AuditEvent> {
        let page: AuditPage = self
            .server
            .get_auth(&self.ana, "/v1/audit?after=0")
            .send()
            .await
            .expect("request")
            .json()
            .await
            .expect("page");
        page.entries
            .iter()
            .map(|e| serde_json::from_slice(e.event.as_bytes()).expect("event"))
            .collect()
    }
}

async fn paused_body(res: reqwest::Response) -> ErrorBody {
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let body: ErrorBody = res.json().await.expect("error body");
    assert_eq!(body.error, ErrorCode::AgentsPaused);
    body
}

#[tokio::test]
async fn pausing_every_agent_refuses_all_but_me_and_resuming_restores_it() {
    let w = world().await;
    assert_eq!(w.inject(&w.agent).await.status(), StatusCode::OK);

    let at = now_ms();
    let pauses = w.decide(None, true, at, 0).await;
    assert_eq!(pauses.pauses.len(), 1);
    assert_eq!(pauses.pauses[0].agent_id, None);

    // Every route but `me` says why, with the pause.
    let body = paused_body(w.inject(&w.agent).await).await;
    let paused = body.paused.expect("pause in the body");
    assert_eq!(paused.scope, klav_proto::agent::PauseScope::All);
    assert_eq!((paused.since, paused.until), (at, None));
    paused_body(
        w.server
            .agent_call(&w.agent, Method::GET, "/v1/agent/items", None)
            .await,
    )
    .await;
    // `me` answers: still active, with the pause.
    let me = w.me(&w.agent).await;
    assert_eq!(me.status, AgentStatus::Active);
    assert!(me.grant.is_some());
    assert_eq!(me.paused.map(|p| p.since), Some(at));

    // The person sees it on the agent and in the sync state, signed.
    let list: AgentList = w
        .server
        .get_auth(&w.ana, "/v1/agents")
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("agents");
    assert!(list.agents[0].paused.is_some());
    let sync: SyncState = w
        .server
        .get_auth(&w.ana, "/v1/sync")
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("sync");
    assert_eq!(sync.agent_pauses, pauses.pauses);

    let resumed = w.decide(None, false, at + 1, 0).await;
    assert!(resumed.pauses.is_empty());
    assert_eq!(w.inject(&w.agent).await.status(), StatusCode::OK);
    assert!(w.me(&w.agent).await.paused.is_none());

    // Both decisions are in the chain with the account's signature, and
    // no allowed access lies between them.
    let events = w.events().await;
    let paused_at = events
        .iter()
        .position(|e| e.action == "agents.paused")
        .expect("paused event");
    let resumed_at = events
        .iter()
        .position(|e| e.action == "agents.resumed")
        .expect("resumed event");
    assert!(paused_at < resumed_at);
    let paused = &events[paused_at];
    assert_eq!(paused.agent_id, None);
    assert_eq!(paused.decided_at, Some(at));
    assert_eq!(paused.until, None);
    assert!(paused.account_signature.is_some());
    assert!(paused.signed.is_none());
    assert!(
        events[paused_at..resumed_at]
            .iter()
            .all(|e| e.action != "agent.access")
    );
}

#[tokio::test]
async fn a_replayed_resume_is_rejected() {
    let w = world().await;
    let t = now_ms();
    w.decide(None, true, t, 0).await;
    let resume = w.decision(&w.ana.identity, None, false, t + 1, 0);
    assert_eq!(w.post(None, &resume).await.status(), StatusCode::OK);
    w.decide(None, true, t + 2, 0).await;
    // The same signed resume again: older than the last decision. The
    // body says when that one was, so a device can sign after it.
    let replayed = w.post(None, &resume).await;
    assert_eq!(replayed.status(), StatusCode::CONFLICT);
    let body: ErrorBody = replayed.json().await.expect("error body");
    assert_eq!(body.last_at, Some(t + 2));
    assert_eq!(body.current_version, None);
    paused_body(w.inject(&w.agent).await).await;
    // So is a decision at the same instant as the last one.
    let same = w.decision(&w.ana.identity, None, false, t + 2, 0);
    let same = w.post(None, &same).await;
    assert_eq!(same.status(), StatusCode::CONFLICT);
    let body: ErrorBody = same.json().await.expect("error body");
    assert_eq!(body.last_at, Some(t + 2));
    // Only one resume made it into the chain.
    let resumes = w
        .events()
        .await
        .iter()
        .filter(|e| e.action == "agents.resumed")
        .count();
    assert_eq!(resumes, 1);
}

#[tokio::test]
async fn a_pause_must_be_signed_by_the_account_and_close_to_now() {
    let w = world().await;
    let mallory = IdentityKeyPair::generate();
    let now = now_ms();
    let refused = [
        // Signed by someone else.
        w.decision(&mallory, None, true, now, 0),
        // Too old, or too far ahead.
        w.decision(&w.ana.identity, None, true, now - 3_600_000, 0),
        w.decision(&w.ana.identity, None, true, now + 3_600_000, 0),
        // A resume never has an end.
        w.decision(&w.ana.identity, None, false, now, now + 60_000),
        // An end that already passed.
        w.decision(&w.ana.identity, None, true, now, now - 1),
    ];
    for body in &refused {
        assert_eq!(w.post(None, body).await.status(), StatusCode::BAD_REQUEST);
    }
    // Signed for one scope, sent to the other.
    let for_all = w.decision(&w.ana.identity, None, true, now, 0);
    assert_eq!(
        w.post(Some(w.agent.id), &for_all).await.status(),
        StatusCode::BAD_REQUEST
    );
    // A pause as a resume: the signed state differs.
    let mut flipped = w.decision(&w.ana.identity, None, true, now, 0);
    flipped.state = PauseState::Resume;
    assert_eq!(
        w.post(None, &flipped).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(w.inject(&w.agent).await.status(), StatusCode::OK);
    assert!(
        w.events()
            .await
            .iter()
            .all(|e| !e.action.starts_with("agents."))
    );
}

#[tokio::test]
async fn one_agent_paused_leaves_the_others_working() {
    let w = world().await;
    let other = TestAgent::new();
    w.approve(&other, "other").await;
    let t = now_ms();
    w.decide(Some(w.agent.id), true, t, 0).await;
    let paused = paused_body(w.inject(&w.agent).await)
        .await
        .paused
        .expect("pause");
    assert_eq!(paused.scope, klav_proto::agent::PauseScope::Agent);
    assert_eq!(w.inject(&other).await.status(), StatusCode::OK);

    // Resuming every agent does not lift a pause of one agent.
    w.decide(None, true, t + 1, 0).await;
    paused_body(w.inject(&other).await).await;
    w.decide(None, false, t + 2, 0).await;
    assert_eq!(w.inject(&other).await.status(), StatusCode::OK);
    paused_body(w.inject(&w.agent).await).await;
    let info: AgentInfo = w
        .server
        .get_auth(&w.ana, &format!("/v1/agents/{}", w.agent.id))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("agent");
    assert_eq!(
        info.paused.map(|p| p.scope),
        Some(klav_proto::agent::PauseScope::Agent)
    );
    w.decide(Some(w.agent.id), false, t + 3, 0).await;
    assert_eq!(w.inject(&w.agent).await.status(), StatusCode::OK);

    // The events name the agent of a single pause.
    let events = w.events().await;
    let single = events
        .iter()
        .find(|e| e.action == "agents.paused")
        .expect("pause");
    assert_eq!(single.agent_id, Some(w.agent.id));
}

#[tokio::test]
async fn a_pause_with_an_end_lifts_by_itself() {
    let w = world().await;
    let now = now_ms();
    let until = now + 1_500;
    w.decide(None, true, now, until).await;
    let paused = paused_body(w.inject(&w.agent).await)
        .await
        .paused
        .expect("pause");
    assert_eq!(paused.until, Some(until));
    let event = w
        .events()
        .await
        .into_iter()
        .find(|e| e.action == "agents.paused")
        .expect("pause");
    assert_eq!(event.until, Some(until));
    tokio::time::sleep(std::time::Duration::from_millis(
        u64::try_from(until - now_ms() + 100).unwrap_or(0),
    ))
    .await;
    assert_eq!(w.inject(&w.agent).await.status(), StatusCode::OK);
    assert!(w.me(&w.agent).await.paused.is_none());
}

#[tokio::test]
async fn only_agents_that_can_act_are_paused_one_by_one() {
    let w = world().await;
    // Unknown agent, or another account's.
    let res = w
        .post(
            Some(AgentId::generate()),
            &w.decision(&w.ana.identity, None, true, now_ms(), 0),
        )
        .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    // A pending agent can be paused: the pause holds once it is approved.
    let pending = TestAgent::new();
    w.server
        .register_agent_ok(&pending, "ana@example.com", "later")
        .await;
    w.decide(Some(pending.id), true, now_ms(), 0).await;
    let me = w.me(&pending).await;
    assert_eq!(me.status, AgentStatus::Pending);
    let grant = TestServer::build_grant(
        &w.ana,
        &pending,
        1,
        Policy::default(),
        &[(&w.vault, &w.project)],
    );
    assert_eq!(
        w.server.post_grant(&w.ana, &pending, &grant).await.status(),
        StatusCode::OK
    );
    paused_body(w.inject(&pending).await).await;
}

// ----------------------------- a decision and its event, in one transaction --

/// The two scopes a decision has: every agent, and one.
fn scopes(w: &World) -> [Option<AgentId>; 2] {
    [None, Some(w.agent.id)]
}

impl World {
    /// The stored state of `scope` (`pause` or `resume`), read straight
    /// from the database; `None` before its first decision.
    async fn stored_state(&self, db: &sqlx::AnyPool, scope: Option<AgentId>) -> Option<String> {
        sqlx::query_scalar("SELECT state FROM agent_pauses WHERE account_id = $1 AND scope = $2")
            .bind(self.ana.account_id.to_string())
            .bind(scope.map_or_else(|| "all".to_owned(), |a| a.to_string()))
            .fetch_optional(db)
            .await
            .expect("test")
    }

    /// The events with `action` about `scope`, read straight from the
    /// database (an all-agents decision names no agent).
    async fn decisions_logged(
        &self,
        db: &sqlx::AnyPool,
        action: &str,
        scope: Option<AgentId>,
    ) -> usize {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT event FROM audit_events WHERE account_id = $1 AND action = $2",
        )
        .bind(self.ana.account_id.to_string())
        .bind(action)
        .fetch_all(db)
        .await
        .expect("test");
        rows.iter()
            .map(|bytes| serde_json::from_slice::<AuditEvent>(bytes).expect("test"))
            .filter(|e| e.agent_id == scope)
            .count()
    }

    /// `pause` (or resume) of `scope` signed for now, and always after the
    /// scope's stored decision (two in one millisecond would be `409`).
    async fn post_now(
        &self,
        db: &sqlx::AnyPool,
        scope: Option<AgentId>,
        pause: bool,
    ) -> StatusCode {
        let last: Option<i64> = sqlx::query_scalar(
            "SELECT at_ms FROM agent_pauses WHERE account_id = $1 AND scope = $2",
        )
        .bind(self.ana.account_id.to_string())
        .bind(scope.map_or_else(|| "all".to_owned(), |a| a.to_string()))
        .fetch_optional(db)
        .await
        .expect("test");
        let at = last.map_or(now_ms(), |last| now_ms().max(last + 1));
        let body = self.decision(&self.ana.identity, scope, pause, at, 0);
        self.post(scope, &body).await.status()
    }
}

/// A pause or a resume whose event the log refuses is not stored, for
/// every agent and for one: the first decision of a scope (an insert) and
/// a later one (an update). The same decision signed again then goes
/// through, with one event.
#[tokio::test]
async fn a_pause_decision_that_cannot_be_logged_is_not_made() {
    let w = world().await;
    let db = w.server.raw_db().await;
    for scope in scopes(&w) {
        for (pause, action, before, after) in [
            (true, "agents.paused", None, "pause"),
            (false, "agents.resumed", Some("pause"), "resume"),
        ] {
            w.server.refuse_audit_action(action).await;
            let status = w.post_now(&db, scope, pause).await;
            w.server.allow_audit_action(action).await;
            assert_eq!(
                status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "{scope:?} {action}"
            );
            assert_eq!(
                w.stored_state(&db, scope).await.as_deref(),
                before,
                "{scope:?} {action}"
            );
            assert_eq!(w.decisions_logged(&db, action, scope).await, 0);
            assert_eq!(w.post_now(&db, scope, pause).await, StatusCode::OK);
            assert_eq!(w.stored_state(&db, scope).await.as_deref(), Some(after));
            assert_eq!(w.decisions_logged(&db, action, scope).await, 1);
        }
    }
}

/// A pause or a resume the database refuses to store logs no event: the
/// event is appended in the decision's transaction, not in one of its own
/// before it.
#[tokio::test]
async fn a_pause_decision_that_cannot_be_stored_is_not_logged() {
    let w = world().await;
    let db = w.server.raw_db().await;
    for scope in scopes(&w) {
        for (pause, action, before) in [
            (true, "agents.paused", None),
            (false, "agents.resumed", Some("pause")),
        ] {
            w.server.refuse_writes("agent_pauses").await;
            let status = w.post_now(&db, scope, pause).await;
            w.server.allow_writes("agent_pauses").await;
            assert_eq!(
                status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "{scope:?} {action}"
            );
            assert_eq!(w.stored_state(&db, scope).await.as_deref(), before);
            assert_eq!(w.decisions_logged(&db, action, scope).await, 0);
            assert_eq!(w.post_now(&db, scope, pause).await, StatusCode::OK);
            assert_eq!(w.decisions_logged(&db, action, scope).await, 1);
        }
    }
}
