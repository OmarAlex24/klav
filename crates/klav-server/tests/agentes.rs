//! Agents: registration, approval with a signed grant, and the signed
//! requests that authenticate them (replay, clock skew, tampering).

mod common;

use common::agent::{TestAgent, now_ms};
use common::{TestServer, until_dropped};
use klav_core::crypto::agent::pairing_code;
use klav_core::crypto::identity::PublicIdentity;
use klav_core::model::reference::Selector;
use klav_core::policy::{Effect, Permission, Policy, Rule, Scope};
use klav_proto::agent::{AgentInfo, AgentList, AgentMe, AgentStatus, GrantPayload};
use reqwest::{Method, StatusCode};

#[tokio::test]
async fn registration_approval_and_grant() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;

    let agent = TestAgent::new();
    server
        .register_agent_ok(&agent, "ANA@example.com", "mi-agente")
        .await;

    // A pending agent can ask for its state but gets no grant.
    let me: AgentMe = server
        .agent_call(&agent, Method::GET, "/v1/agent/me", None)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(me.status, AgentStatus::Pending);
    assert!(me.grant.is_none());
    assert_eq!(me.account_id, ana.account_id);

    // The person sees the request and the same pairing words.
    let list: AgentList = server
        .get_auth(&ana, "/v1/agents")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.agents.len(), 1);
    let pending = &list.agents[0];
    assert_eq!(pending.status, AgentStatus::Pending);
    assert_eq!(pending.name, "mi-agente");
    let shown = PublicIdentity::decode(pending.public_identity.as_bytes()).unwrap();
    assert_eq!(pairing_code(&shown), pairing_code(agent.keys.public()));

    // Approve: a grant signed by the account with the project key for the agent.
    let grant = TestServer::build_grant(&ana, &agent, 1, Policy::default(), &[(&vault, &project)]);
    let res = server.post_grant(&ana, &agent, &grant).await;
    assert_eq!(res.status(), StatusCode::OK);
    let info: AgentInfo = res.json().await.unwrap();
    assert_eq!(info.status, AgentStatus::Active);
    assert!(info.approved_at.is_some());

    let me: AgentMe = server
        .agent_call(&agent, Method::GET, "/v1/agent/me", None)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(me.status, AgentStatus::Active);
    let stored = me.grant.expect("grant");
    // Byte-for-byte what the person signed.
    assert_eq!(stored, grant);
    let payload: GrantPayload = serde_json::from_slice(stored.payload.as_bytes()).unwrap();
    assert_eq!(payload.projects[0].project_id, project.id);

    // A replacement grant must carry the next version.
    let stale = TestServer::build_grant(&ana, &agent, 1, Policy::default(), &[(&vault, &project)]);
    assert_eq!(
        server.post_grant(&ana, &agent, &stale).await.status(),
        StatusCode::CONFLICT
    );
    let next = TestServer::build_grant(&ana, &agent, 2, Policy::default(), &[(&vault, &project)]);
    assert_eq!(
        server.post_grant(&ana, &agent, &next).await.status(),
        StatusCode::OK
    );
}

/// `GET /v1/agent/me`, parsed and as sent.
async fn me(server: &TestServer, agent: &TestAgent) -> (AgentMe, String) {
    let res = server
        .agent_call(agent, Method::GET, "/v1/agent/me", None)
        .await;
    let text = res.text().await.expect("body");
    (serde_json::from_str(&text).expect("me"), text)
}

/// A pending request that lapsed reads as denied, but `me` says nobody
/// decided (ADR 0033 E2.2); a denial the person made does not say so.
#[tokio::test]
async fn a_lapsed_request_is_not_a_denial() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let lapsed = TestAgent::new();
    server
        .register_agent_ok(&lapsed, "ana@example.com", "cursor")
        .await;
    let (pending, text) = me(&server, &lapsed).await;
    assert_eq!(pending.status, AgentStatus::Pending);
    assert!(!pending.lapsed && !text.contains("lapsed"), "{text}");
    sqlx::query("UPDATE agents SET expires_at = 1 WHERE id = $1")
        .bind(lapsed.id.to_string())
        .execute(&server.raw_db().await)
        .await
        .expect("lapse");
    let (gone, _) = me(&server, &lapsed).await;
    assert_eq!(gone.status, AgentStatus::Denied);
    assert!(gone.lapsed);

    let denied = TestAgent::new();
    server
        .register_agent_ok(&denied, "ana@example.com", "codex")
        .await;
    let res = server
        .post_auth(&ana, &format!("/v1/agents/{}/deny", denied.id))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let (refused, text) = me(&server, &denied).await;
    assert_eq!(refused.status, AgentStatus::Denied);
    assert!(!refused.lapsed && !text.contains("lapsed"), "{text}");
}

/// The actions logged about `agent`, oldest first.
async fn logged(
    server: &TestServer,
    ana: &common::client::Session,
    agent: &TestAgent,
) -> Vec<String> {
    let page: klav_proto::audit::AuditPage = server
        .get_auth(ana, "/v1/audit")
        .send()
        .await
        .expect("audit")
        .json()
        .await
        .expect("audit page");
    page.entries
        .iter()
        .map(|e| {
            serde_json::from_slice::<klav_proto::audit::AuditEvent>(e.event.as_bytes())
                .expect("event")
        })
        .filter(|e| e.agent_id == Some(agent.id))
        .map(|e| e.action)
        .collect()
}

fn registration(agent: &TestAgent) -> klav_proto::agent::RegisterAgent {
    klav_proto::agent::RegisterAgent {
        id: agent.id,
        email: "ana@example.com".into(),
        name: "bot".into(),
        public_identity: klav_proto::Blob::new(agent.keys.public().encode().to_vec()),
        note: None,
    }
}

/// A registration whose client goes away is never stored without its
/// `agent.registered`: the call is driven through the router by hand and
/// dropped as soon as the agent reads as stored, before the handler sees
/// its commit, as hyper drops a handler whose client goes away (a call
/// that finished first is tried again with a new agent).
#[tokio::test]
async fn a_registration_whose_client_goes_away_is_logged_with_it() {
    let server = TestServer::start().await;
    let ana = server
        .login(&server.signup("ana@example.com", "pw").await, "laptop")
        .await;
    let db = server.raw_db().await;
    let agent = until_dropped(async || {
        let agent = TestAgent::new();
        let status = server
            .call_dropped_once(
                None,
                "/v1/agents/register",
                &registration(&agent),
                || async { server.agent_status(&db, agent.id).await.is_some() },
            )
            .await;
        (status, agent)
    })
    .await;
    assert_eq!(
        server.agent_status(&db, agent.id).await.as_deref(),
        Some("pending")
    );
    assert_eq!(logged(&server, &ana, &agent).await, ["agent.registered"]);
}

/// The same for a denial and its `agent.denied`.
#[tokio::test]
async fn a_denial_whose_client_goes_away_is_logged_with_it() {
    let server = TestServer::start().await;
    let ana = server
        .login(&server.signup("ana@example.com", "pw").await, "laptop")
        .await;
    let db = server.raw_db().await;
    let agent = until_dropped(async || {
        let agent = TestAgent::new();
        server
            .register_agent_ok(&agent, "ana@example.com", "bot")
            .await;
        let path = format!("/v1/agents/{}/deny", agent.id);
        let status = server
            .call_dropped_once(Some(&ana), &path, &serde_json::json!({}), || async {
                server.agent_status(&db, agent.id).await.as_deref() == Some("denied")
            })
            .await;
        (status, agent)
    })
    .await;
    assert_eq!(
        server.agent_status(&db, agent.id).await.as_deref(),
        Some("denied")
    );
    assert_eq!(
        logged(&server, &ana, &agent).await,
        ["agent.registered", "agent.denied"]
    );
}

/// A registration whose `agent.registered` the log refuses is not stored:
/// the event is appended in the registration's own transaction.
#[tokio::test]
async fn a_registration_that_cannot_be_logged_is_not_stored() {
    let server = TestServer::start().await;
    server.signup("ana@example.com", "pw").await;
    let db = server.raw_db().await;
    server.refuse_audit_action("agent.registered").await;
    let agent = TestAgent::new();
    let res = server
        .post_json("/v1/agents/register", &registration(&agent))
        .await;
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(server.agent_status(&db, agent.id).await, None);
}

/// A denial whose `agent.denied` the log refuses is not made.
#[tokio::test]
async fn a_denial_that_cannot_be_logged_is_not_made() {
    let server = TestServer::start().await;
    let ana = server
        .login(&server.signup("ana@example.com", "pw").await, "laptop")
        .await;
    let db = server.raw_db().await;
    let agent = TestAgent::new();
    server
        .register_agent_ok(&agent, "ana@example.com", "bot")
        .await;
    server.refuse_audit_action("agent.denied").await;
    let res = server
        .post_auth(&ana, &format!("/v1/agents/{}/deny", agent.id))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        server.agent_status(&db, agent.id).await.as_deref(),
        Some("pending")
    );
    assert_eq!(logged(&server, &ana, &agent).await, ["agent.registered"]);
}

/// A grant whose `agent.granted` the log refuses is not made: the agent
/// stays pending with no grant in the chain, and the same grant then
/// succeeds once the log takes it.
#[tokio::test]
async fn a_grant_that_cannot_be_logged_is_not_made() {
    let server = TestServer::start().await;
    let ana = server
        .login(&server.signup("ana@example.com", "pw").await, "laptop")
        .await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let db = server.raw_db().await;
    let agent = TestAgent::new();
    server
        .register_agent_ok(&agent, "ana@example.com", "bot")
        .await;
    let grant = TestServer::build_grant(&ana, &agent, 1, Policy::default(), &[(&vault, &project)]);
    server.refuse_audit_action("agent.granted").await;
    let res = server.post_grant(&ana, &agent, &grant).await;
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        server.agent_status(&db, agent.id).await.as_deref(),
        Some("pending")
    );
    assert_eq!(logged(&server, &ana, &agent).await, ["agent.registered"]);
    server.allow_audit_action("agent.granted").await;
    let res = server.post_grant(&ana, &agent, &grant).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        server.agent_status(&db, agent.id).await.as_deref(),
        Some("active")
    );
    assert_eq!(
        logged(&server, &ana, &agent).await,
        ["agent.registered", "agent.granted"]
    );
}

/// A registration, a denial or a grant whose write to the agent the
/// database refuses logs no event: each is appended in the write's
/// transaction, not in one of its own before it.
#[tokio::test]
async fn an_agent_write_that_cannot_be_stored_is_not_logged() {
    let server = TestServer::start().await;
    let ana = server
        .login(&server.signup("ana@example.com", "pw").await, "laptop")
        .await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let db = server.raw_db().await;

    let agent = TestAgent::new();
    server.refuse_writes("agents").await;
    let res = server
        .post_json("/v1/agents/register", &registration(&agent))
        .await;
    server.allow_writes("agents").await;
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(server.agent_status(&db, agent.id).await, None);
    assert!(logged(&server, &ana, &agent).await.is_empty());
    server
        .register_agent_ok(&agent, "ana@example.com", "bot")
        .await;
    assert_eq!(logged(&server, &ana, &agent).await, ["agent.registered"]);

    server.refuse_writes("agents").await;
    let res = server
        .post_auth(&ana, &format!("/v1/agents/{}/deny", agent.id))
        .send()
        .await
        .unwrap();
    server.allow_writes("agents").await;
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        server.agent_status(&db, agent.id).await.as_deref(),
        Some("pending")
    );
    assert_eq!(logged(&server, &ana, &agent).await, ["agent.registered"]);

    let grant = TestServer::build_grant(&ana, &agent, 1, Policy::default(), &[(&vault, &project)]);
    server.refuse_writes("agents").await;
    let res = server.post_grant(&ana, &agent, &grant).await;
    server.allow_writes("agents").await;
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        server.agent_status(&db, agent.id).await.as_deref(),
        Some("pending")
    );
    assert_eq!(logged(&server, &ana, &agent).await, ["agent.registered"]);
    let res = server.post_grant(&ana, &agent, &grant).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        logged(&server, &ana, &agent).await,
        ["agent.registered", "agent.granted"]
    );
}

/// Postgres only: a registration, a denial and a grant each write the
/// agent and append its event in one transaction.
#[tokio::test]
async fn an_agent_write_and_its_event_share_one_transaction() {
    let server = TestServer::start().await;
    if !server.is_postgres() {
        return;
    }
    let ana = server
        .login(&server.signup("ana@example.com", "pw").await, "laptop")
        .await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let db = server.raw_db().await;
    let denied = TestAgent::new();
    server
        .register_agent_ok(&denied, "ana@example.com", "bot")
        .await;
    let id = denied.id.to_string();
    server
        .assert_written_with(&db, ana.account_id, "agents", &id, "agent.registered")
        .await;
    let res = server
        .post_auth(&ana, &format!("/v1/agents/{}/deny", denied.id))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    server
        .assert_written_with(&db, ana.account_id, "agents", &id, "agent.denied")
        .await;
    let granted = TestAgent::new();
    server
        .register_agent_ok(&granted, "ana@example.com", "bot")
        .await;
    let grant =
        TestServer::build_grant(&ana, &granted, 1, Policy::default(), &[(&vault, &project)]);
    let res = server.post_grant(&ana, &granted, &grant).await;
    assert_eq!(res.status(), StatusCode::OK);
    server
        .assert_written_with(
            &db,
            ana.account_id,
            "agents",
            &granted.id.to_string(),
            "agent.granted",
        )
        .await;
}

/// A denial takes the account's lock before the agent's row, as every
/// write that logs in its own transaction does: in the other order it
/// deadlocks with them (Postgres; SQLite has one writer at a time).
#[tokio::test]
async fn a_denial_locks_the_account_before_the_agent() {
    let server = TestServer::start().await;
    if !server.is_postgres() {
        return;
    }
    let ana = server
        .login(&server.signup("ana@example.com", "pw").await, "laptop")
        .await;
    let agent = TestAgent::new();
    server
        .register_agent_ok(&agent, "ana@example.com", "bot")
        .await;
    let send = server
        .post_auth(&ana, &format!("/v1/agents/{}/deny", agent.id))
        .send();
    let res = server
        .assert_account_locked_before_agent(ana.account_id, agent.id, send)
        .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        logged(&server, &ana, &agent).await,
        ["agent.registered", "agent.denied"]
    );
}

#[tokio::test]
async fn grants_are_checked() {
    let server = TestServer::start().await;
    let ana = server
        .login(&server.signup("ana@example.com", "pw").await, "laptop")
        .await;
    let bea = server
        .login(&server.signup("bea@example.com", "pw").await, "laptop")
        .await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let agent = TestAgent::new();
    server
        .register_agent_ok(&agent, "ana@example.com", "agente")
        .await;

    // Policies must name vaults and projects by ID.
    let by_name = Policy {
        rules: vec![Rule {
            scope: Scope {
                projects: vec![Selector::Name("acme".into())],
                ..Scope::default()
            },
            ..Rule::new(Permission::Fill, Effect::Allow)
        }],
        expires_at: None,
    };
    let grant = TestServer::build_grant(&ana, &agent, 1, by_name, &[(&vault, &project)]);
    assert_eq!(
        server.post_grant(&ana, &agent, &grant).await.status(),
        StatusCode::BAD_REQUEST
    );

    // A signature by another account does not verify.
    let forged = TestServer::build_grant(&bea, &agent, 1, Policy::default(), &[(&vault, &project)]);
    assert_eq!(
        server.post_grant(&ana, &agent, &forged).await.status(),
        StatusCode::BAD_REQUEST
    );

    // Another account cannot see or approve the agent.
    let grant = TestServer::build_grant(&bea, &agent, 1, Policy::default(), &[(&vault, &project)]);
    assert_eq!(
        server.post_grant(&bea, &agent, &grant).await.status(),
        StatusCode::NOT_FOUND
    );

    // Denied registrations cannot be granted later.
    let res = server
        .post_auth(&ana, &format!("/v1/agents/{}/deny", agent.id))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let grant = TestServer::build_grant(&ana, &agent, 1, Policy::default(), &[(&vault, &project)]);
    assert_eq!(
        server.post_grant(&ana, &agent, &grant).await.status(),
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn registration_does_not_reveal_accounts() {
    let server = TestServer::start().await;
    server.signup("ana@example.com", "pw").await;
    let known = server
        .register_agent(&TestAgent::new(), "ana@example.com", "a")
        .await;
    let unknown = server
        .register_agent(&TestAgent::new(), "nadie@example.com", "a")
        .await;
    assert_eq!(known.status(), StatusCode::ACCEPTED);
    assert_eq!(unknown.status(), StatusCode::ACCEPTED);
    let known: serde_json::Value = known.json().await.unwrap();
    let unknown: serde_json::Value = unknown.json().await.unwrap();
    assert_eq!(
        known.as_object().unwrap().keys().collect::<Vec<_>>(),
        unknown.as_object().unwrap().keys().collect::<Vec<_>>()
    );

    // Invalid public identities are rejected up front.
    let mut agent = TestAgent::new();
    agent.id = klav_core::ids::AgentId::generate();
    let res = server
        .post_json(
            "/v1/agents/register",
            &serde_json::json!({
                "id": agent.id,
                "email": "ana@example.com",
                "name": "x",
                "public_identity": "AQUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            }),
        )
        .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn signed_requests_reject_tampering_replay_and_skew() {
    let server = TestServer::start().await;
    server.signup("ana@example.com", "pw").await;
    let agent = TestAgent::new();
    server
        .register_agent_ok(&agent, "ana@example.com", "agente")
        .await;
    let path = "/v1/agent/me";

    // Fresh and valid.
    let signed = agent.sign("GET", path, b"", now_ms());
    let ok = server
        .agent_raw(&agent, Method::GET, path, None, &signed)
        .await;
    assert_eq!(ok.status(), StatusCode::OK);

    // The same request again (same nonce): replay.
    let again = server
        .agent_raw(&agent, Method::GET, path, None, &signed)
        .await;
    assert_eq!(again.status(), StatusCode::UNAUTHORIZED);

    // Outside the ±5 min window, in either direction.
    for offset in [-6 * 60_000, 6 * 60_000] {
        let skewed = agent.sign("GET", path, b"", now_ms() + offset);
        let res = server
            .agent_raw(&agent, Method::GET, path, None, &skewed)
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "offset {offset}");
    }

    // Signed for another path or body.
    let other = agent.sign("GET", "/v1/agent/other", b"", now_ms());
    assert_eq!(
        server
            .agent_raw(&agent, Method::GET, path, None, &other)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let with_body = agent.sign("GET", path, b"{}", now_ms());
    assert_eq!(
        server
            .agent_raw(&agent, Method::GET, path, Some(b"{\"x\":1}"), &with_body)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // Signed by another key.
    let impostor = TestAgent {
        id: agent.id,
        keys: klav_core::crypto::identity::IdentityKeyPair::generate(),
    };
    let forged = impostor.sign("GET", path, b"", now_ms());
    assert_eq!(
        server
            .agent_raw(&agent, Method::GET, path, None, &forged)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // Unknown agent.
    let stranger = TestAgent::new();
    let res = server.agent_call(&stranger, Method::GET, path, None).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_timestamp_far_in_the_past_is_401_not_a_crash() {
    let server = TestServer::start().await;
    server.signup("ana@example.com", "pw").await;
    let agent = TestAgent::new();
    server
        .register_agent_ok(&agent, "ana@example.com", "bot")
        .await;
    for timestamp in [i64::MIN, i64::MIN + 1, i64::MAX] {
        let signed = common::agent::Signed {
            timestamp,
            nonce: [7; 16],
            signature: vec![0; 64],
        };
        let res = server
            .agent_raw(&agent, Method::GET, "/v1/agent/me", None, &signed)
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{timestamp}");
    }
}

#[tokio::test]
async fn a_request_refused_by_the_rate_limit_cannot_be_replayed_later() {
    let server = TestServer::start_with(|c| {
        c.rate_limit.account_per_minute = 60;
        c.rate_limit.account_burst = 1;
    })
    .await;
    server.signup("ana@example.com", "pw").await;
    let agent = TestAgent::new();
    server
        .register_agent_ok(&agent, "ana@example.com", "bot")
        .await;
    let path = "/v1/agent/me";
    assert_eq!(
        server
            .agent_call(&agent, Method::GET, path, None)
            .await
            .status(),
        StatusCode::OK
    );
    // Signed and valid, but over the limit: 429…
    let signed = agent.sign("GET", path, b"", now_ms());
    let res = server
        .agent_raw(&agent, Method::GET, path, None, &signed)
        .await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    // …and once the bucket refills, the same request is a replay.
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let res = server
        .agent_raw(&agent, Method::GET, path, None, &signed)
        .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn concurrent_registrations_never_pass_the_cap() {
    let server = TestServer::start().await;
    let ana = server.signup("ana@example.com", "pw").await;
    let agents: Vec<TestAgent> = (0..40).map(|_| TestAgent::new()).collect();
    let answers = futures_util::future::join_all(
        agents
            .iter()
            .map(|a| server.register_agent(a, "ana@example.com", "bot")),
    )
    .await;
    // Same answer for everyone (nothing reveals the cap)…
    assert!(
        answers.iter().all(|r| r.status() == StatusCode::ACCEPTED),
        "{:?}",
        answers
            .iter()
            .map(reqwest::Response::status)
            .collect::<Vec<_>>()
    );
    // …but at most 20 are stored.
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM agents WHERE account_id = $1 AND status = 'pending'",
    )
    .bind(ana.account_id.to_string())
    .fetch_one(&server.raw_db().await)
    .await
    .expect("count");
    assert_eq!(pending, 20);
}

/// A grant whose client goes away is never left active without its
/// `agent.granted` in the person's chain: without it, `klav log verify`
/// finds no grant that vouches for the agent's key, and every later event
/// of that agent fails. The call is driven through the router by hand and
/// dropped as soon as the agent reads as active, before the handler sees
/// its commit, as hyper drops a handler whose client goes away.
#[tokio::test]
async fn a_grant_whose_client_goes_away_is_logged_with_it() {
    let server = TestServer::start().await;
    let ana = server
        .login(&server.signup("ana@example.com", "pw").await, "laptop")
        .await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let db = server.raw_db().await;
    let active = async |agent: &TestAgent| {
        server.agent_status(&db, agent.id).await.as_deref() == Some("active")
    };
    let agent = until_dropped(async || {
        let agent = TestAgent::new();
        server
            .register_agent_ok(&agent, "ana@example.com", "bot")
            .await;
        let grant =
            TestServer::build_grant(&ana, &agent, 1, Policy::default(), &[(&vault, &project)]);
        let status = server
            .call_dropped_once(
                Some(&ana),
                &format!("/v1/agents/{}/grant", agent.id),
                &grant,
                || active(&agent),
            )
            .await;
        (status, agent)
    })
    .await;
    assert!(active(&agent).await);
    // Only that the row is there: that a chain with it verifies end to end
    // is covered by `klav-sdk/tests/bitacora.rs`.
    let page: klav_proto::audit::AuditPage = server
        .get_auth(&ana, "/v1/audit?after=0")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let granted = page.entries.iter().any(|e| {
        let e: klav_proto::audit::AuditEvent = serde_json::from_slice(e.event.as_bytes()).unwrap();
        e.action == "agent.granted" && e.agent_id == Some(agent.id)
    });
    assert!(
        granted,
        "the agent is active and its grant is not in the chain"
    );
}
