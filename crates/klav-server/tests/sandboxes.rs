//! A sandbox's life as the credential proxy reports it (ADR 0036 §4, §9,
//! E3.3): `sandbox.issued`, `sandbox.claimed` and `sandbox.revoked`, what
//! the server checks before it logs each one, and that nothing is written
//! for a proxy whose grant names no issuer or for any other agent; and the
//! person's revocation of sandboxes (`sandbox.revoke_requested`), its
//! cursor and the barrier that holds against it; and the proxy's store
//! epochs (`sandbox.store_reset`) and heartbeats.
//! Runs on SQLite, and on Postgres when `KLAV_TEST_DATABASE_URL` says so.

mod common;

use common::TestServer;
use common::agent::{TestAgent, escaped, now_ms};
use common::client::Session;
use common::vault::login_item;
use klav_core::crypto::sandbox::{RevokeScope, RevokeToSign, sign_revoke, verify_revoke};
use klav_core::ids::{AgentId, ApprovalId, ItemId, SandboxId};
use klav_core::policy::{
    DomainPattern, Effect, HttpMethod, PathPrefix, Permission, Policy, Rule, Scope,
};
use klav_proto::agent::{
    GRANT_PAYLOAD_VERSION_SANDBOXES, GrantPayload, IssuerGrant, ProxyProfile, SandboxIssuer,
    SandboxProxy, SignedGrant,
};
use klav_proto::audit::{AuditEvent, AuditPage};
use klav_proto::sandbox::{
    PATH_SANDBOX_STATE, PATH_STORE_RESET, SandboxClaimed, SandboxHeartbeat, SandboxIssue,
    SandboxRevocation, SandboxRevocations, SandboxRevoke,
};
use klav_proto::{Blob, ErrorBody, ErrorCode};
use reqwest::{Method, StatusCode};
use serde_json::json;

const RAILWAY: &str = "backboard.railway.app";
const HOUR_MS: i64 = 60 * 60 * 1000;

struct World {
    /// Shared, so a second account can live on the same server.
    server: std::sync::Arc<TestServer>,
    /// Ana's account, to sign in from more devices.
    creds: common::client::Credentials,
    ana: Session,
    proxy: TestAgent,
    issuer: TestAgent,
    /// An agent with a project grant, never an issuer.
    plain: TestAgent,
    /// The proxy's per-item grant, before any issuer.
    proxy_v2: GrantPayload,
    /// The item behind the proxy's `railway` profile.
    railway: ItemId,
}

fn rule(permission: Permission, effect: Effect, scope: Scope) -> Rule {
    Rule {
        scope,
        ..Rule::new(permission, effect)
    }
}

async fn world() -> World {
    world_on(TestServer::start().await).await
}

/// [`world`], with rate limits no test of many calls at once reaches.
async fn busy_world() -> World {
    world_on(
        TestServer::start_with(|config| {
            config.rate_limit.account_per_minute = 100_000;
            config.rate_limit.account_burst = 100_000;
            config.rate_limit.ip_per_minute = 100_000;
            config.rate_limit.ip_burst = 100_000;
        })
        .await,
    )
    .await
}

async fn world_on(server: TestServer) -> World {
    account_on(std::sync::Arc::new(server), "ana@example.com").await
}

/// The same world for the account of `email`, on `server`.
async fn account_on(server: std::sync::Arc<TestServer>, email: &str) -> World {
    let creds = server.signup(email, "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let railway = login_item("Railway", "ana", "railway-token");
    let (key, _) = server.create_item(&ana, &vault, &project, &railway).await;
    let proxy = TestAgent::new();
    let issuer = TestAgent::new();
    let plain = TestAgent::new();
    for (agent, name) in [(&proxy, "proxy"), (&issuer, "t3-code"), (&plain, "plain")] {
        server.register_agent_ok(agent, email, name).await;
    }
    let mut rules = vec![rule(
        Permission::Proxy,
        Effect::Allow,
        Scope {
            items: vec![railway.id()],
            domains: vec![DomainPattern::parse(RAILWAY).expect("host")],
            methods: vec![HttpMethod::parse("POST").expect("method")],
            path_prefixes: vec![PathPrefix::parse("/graphql").expect("prefix")],
            ..Scope::default()
        },
    )];
    rules.extend(
        [Permission::Reveal, Permission::Inject, Permission::Fill]
            .into_iter()
            .map(|p| rule(p, Effect::Deny, Scope::default())),
    );
    let signed = TestServer::build_item_grant(
        &ana,
        &proxy,
        1,
        Policy {
            rules,
            expires_at: None,
        },
        &[(&vault, &project, railway.id(), &key)],
        vec![ProxyProfile {
            name: "railway".into(),
            item_id: railway.id(),
            field: None,
            header: "authorization".into(),
            prefix: "Bearer ".into(),
            upstream: format!("https://{RAILWAY}"),
            rate_per_minute: None,
        }],
    );
    let proxy_v2: GrantPayload = serde_json::from_slice(signed.payload.as_bytes()).expect("grant");
    let w = World {
        server,
        creds,
        ana,
        proxy,
        issuer,
        plain,
        proxy_v2,
        railway: railway.id(),
    };
    w.post(&w.proxy, &signed).await;
    let plain_grant = TestServer::build_grant(
        &w.ana,
        &w.plain,
        1,
        Policy::default(),
        &[(&vault, &project)],
    );
    w.post(&w.plain, &plain_grant).await;
    w
}

impl World {
    async fn post(&self, agent: &TestAgent, grant: &SignedGrant) {
        let res = self.server.post_grant(&self.ana, agent, grant).await;
        assert!(
            res.status().is_success(),
            "{}",
            res.text().await.expect("body")
        );
    }

    /// The issuer's grant names the proxy; the proxy's lists the issuer
    /// with `railway`, at most an hour and `max_live` sandboxes. What
    /// `klav proxy issuer add` signs.
    async fn make_issuer(&self, version: u64, max_live: u32) {
        self.make_issuer_with(version, max_live, Effect::Allow)
            .await;
    }

    /// [`Self::make_issuer`], with the proxy's `POST /graphql` rule set to
    /// `effect`.
    async fn make_issuer_with(&self, version: u64, max_live: u32, effect: Effect) {
        let issuer = GrantPayload {
            v: GRANT_PAYLOAD_VERSION_SANDBOXES,
            account_id: self.ana.account_id,
            agent_id: self.issuer.id,
            version,
            issued_at: now_ms(),
            policy: Policy::default(),
            projects: Vec::new(),
            items: Vec::new(),
            profiles: Vec::new(),
            issuers: Vec::new(),
            sandbox: Some(IssuerGrant {
                proxy: Some(SandboxProxy {
                    agent_id: self.proxy.id,
                    public_identity: Blob::new(self.proxy.keys.public().encode().to_vec()),
                    url: "tls://proxy.example.com:8443".into(),
                }),
            }),
        };
        self.post(
            &self.issuer,
            &TestServer::sign_payload(&self.ana, &self.issuer, &issuer),
        )
        .await;
        let mut policy = self.proxy_v2.policy.clone();
        policy.rules[0].effect = effect;
        let proxy = GrantPayload {
            v: GRANT_PAYLOAD_VERSION_SANDBOXES,
            version: version + 1,
            issued_at: now_ms(),
            policy,
            issuers: vec![SandboxIssuer {
                agent_id: self.issuer.id,
                public_identity: Blob::new(self.issuer.keys.public().encode().to_vec()),
                profiles: vec!["railway".into()],
                max_ttl_secs: 3600,
                max_live,
            }],
            ..self.proxy_v2.clone()
        };
        self.post(
            &self.proxy,
            &TestServer::sign_payload(&self.ana, &self.proxy, &proxy),
        )
        .await;
    }

    fn issue_body(&self, id: SandboxId, profiles: &[&str], expires_at: i64) -> serde_json::Value {
        serde_json::to_value(SandboxIssue {
            sandbox_id: id,
            issuer_id: self.issuer.id,
            label: "chat-123".into(),
            profiles: profiles.iter().map(|p| (*p).to_owned()).collect(),
            expires_at,
        })
        .expect("body")
    }

    async fn issue_as(&self, agent: &TestAgent, body: &serde_json::Value) -> reqwest::Response {
        self.server
            .agent_call(agent, Method::POST, "/v1/agent/sandboxes", Some(body))
            .await
    }

    async fn issue(&self, id: SandboxId) -> reqwest::Response {
        self.issue_as(
            &self.proxy,
            &self.issue_body(id, &["railway"], now_ms() + HOUR_MS),
        )
        .await
    }

    async fn claim_as(&self, agent: &TestAgent, id: SandboxId) -> reqwest::Response {
        let body = serde_json::to_value(SandboxClaimed {
            channel_key_sha256: Blob::new(vec![7; 32]),
        })
        .expect("body");
        self.server
            .agent_call(
                agent,
                Method::POST,
                &format!("/v1/agent/sandboxes/{id}/claimed"),
                Some(&body),
            )
            .await
    }

    async fn end_as(&self, agent: &TestAgent, id: SandboxId, reason: &str) -> reqwest::Response {
        self.server
            .agent_call(
                agent,
                Method::POST,
                &format!("/v1/agent/sandboxes/{id}/revoked"),
                Some(&json!({ "reason": reason })),
            )
            .await
    }

    async fn chain(&self) -> Vec<AuditEvent> {
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

    async fn sandbox_rows(&self) -> i64 {
        let db = self.server.raw_db().await;
        sqlx::query_scalar("SELECT COUNT(*) FROM sandboxes")
            .fetch_one(&db)
            .await
            .expect("count")
    }

    async fn pause(&self, agent: AgentId, pause: bool, at: i64) {
        use klav_core::crypto::agent::{PauseScope, PauseToSign, sign_pause};
        use klav_proto::agent::{PauseAgents, PauseState};
        let signature = sign_pause(
            &self.ana.identity,
            &PauseToSign {
                account: self.ana.account_id,
                scope: PauseScope::Agent(agent),
                pause,
                at_ms: u64::try_from(at).expect("time"),
                until_ms: 0,
            },
        );
        let res = self
            .server
            .post_auth(&self.ana, &format!("/v1/agents/{agent}/pause"))
            .json(&PauseAgents {
                state: if pause {
                    PauseState::Pause
                } else {
                    PauseState::Resume
                },
                at,
                until: 0,
                signature: Blob::new(signature.to_bytes().to_vec()),
            })
            .send()
            .await
            .expect("pause");
        assert!(
            res.status().is_success(),
            "{}",
            res.text().await.expect("body")
        );
    }
}

impl World {
    /// One proxied call of the proxy, for `sandbox` when given.
    async fn access(&self, permission: &str, sandbox: Option<SandboxId>) -> reqwest::Response {
        self.access_with(permission, sandbox, None).await
    }

    /// [`Self::access`], naming an approval when given.
    async fn access_with(
        &self,
        permission: &str,
        sandbox: Option<SandboxId>,
        approval: Option<ApprovalId>,
    ) -> reqwest::Response {
        let mut body = json!({
            "item_id": self.railway,
            "permission": permission,
            "reason": "deploy",
            "claims": { "domain": RAILWAY, "method": "POST", "path": "/graphql" },
        });
        if let Some(id) = sandbox {
            body["sandbox"] = json!(id);
        }
        if let Some(id) = approval {
            body["approval_id"] = json!(id);
        }
        self.server
            .agent_call(&self.proxy, Method::POST, "/v1/agent/access", Some(&body))
            .await
    }

    async fn me(&self, agent: &TestAgent) -> serde_json::Value {
        let res = self
            .server
            .agent_call(agent, Method::GET, "/v1/agent/me", None)
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        res.json().await.expect("me")
    }

    async fn revoke(&self, agent: AgentId) {
        let at = now_ms();
        let res = self
            .server
            .post_auth(&self.ana, &format!("/v1/agents/{agent}/revoke"))
            .json(&klav_proto::agent::RevokeAgent {
                revoked_at: at,
                signature: Blob::new(
                    klav_core::crypto::agent::sign_revocation(
                        &self.ana.identity,
                        self.ana.account_id,
                        agent,
                        u64::try_from(at).expect("time"),
                    )
                    .to_bytes()
                    .to_vec(),
                ),
            })
            .send()
            .await
            .expect("revoke");
        assert!(res.status().is_success());
    }
}

async fn code(res: reqwest::Response) -> (StatusCode, ErrorCode) {
    let status = res.status();
    let body: ErrorBody = res.json().await.expect("error body");
    (status, body.error)
}

#[tokio::test]
async fn a_proxy_logs_a_sandbox_life_in_order_and_once() {
    let w = world().await;
    w.make_issuer(1, 3).await;
    let id = SandboxId::generate();
    assert_eq!(w.issue(id).await.status(), StatusCode::NO_CONTENT);
    // The same ID again is refused, issued or not.
    assert_eq!(w.issue(id).await.status(), StatusCode::CONFLICT);
    // An end that needs a claim, before it.
    assert_eq!(
        w.end_as(&w.proxy, id, "theft").await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        w.claim_as(&w.proxy, id).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        code(w.claim_as(&w.proxy, id).await).await,
        (StatusCode::CONFLICT, ErrorCode::SandboxClaimed)
    );
    assert_eq!(
        w.end_as(&w.proxy, id, "theft").await.status(),
        StatusCode::NO_CONTENT
    );
    // Once: a retried report learns it is already recorded.
    assert_eq!(
        code(w.end_as(&w.proxy, id, "stop").await).await,
        (StatusCode::FORBIDDEN, ErrorCode::SandboxRevoked)
    );
    assert_eq!(
        code(w.claim_as(&w.proxy, id).await).await,
        (StatusCode::FORBIDDEN, ErrorCode::SandboxRevoked)
    );
    // A reason outside the closed set, and an unknown sandbox.
    let other = SandboxId::generate();
    assert_eq!(w.issue(other).await.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        w.end_as(&w.proxy, other, "person").await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        w.end_as(&w.proxy, SandboxId::generate(), "stop")
            .await
            .status(),
        StatusCode::NOT_FOUND
    );

    let chain = w.chain().await;
    let sandbox: Vec<&AuditEvent> = chain
        .iter()
        .filter(|e| e.action.starts_with("sandbox."))
        .collect();
    let steps: Vec<(&str, Option<&str>)> = sandbox
        .iter()
        .map(|e| (e.action.as_str(), e.outcome.as_deref()))
        .collect();
    assert_eq!(
        steps,
        [
            ("sandbox.issued", None),
            ("sandbox.claimed", None),
            ("sandbox.revoked", Some("theft")),
            ("sandbox.issued", None),
        ]
    );
    for e in &sandbox {
        assert_eq!(e.agent_id, Some(w.proxy.id));
        let proof = e.agent_proof.as_ref().expect("signed request");
        assert!(proof.body.is_some(), "logged with its body");
        assert!(e.item_id.is_none() && e.permission.is_none() && e.reason.is_none());
    }
    let issued: SandboxIssue = serde_json::from_slice(
        sandbox[0]
            .agent_proof
            .as_ref()
            .unwrap()
            .body
            .as_ref()
            .unwrap()
            .as_bytes(),
    )
    .expect("body");
    assert_eq!((issued.sandbox_id, issued.issuer_id), (id, w.issuer.id));
    assert_eq!(
        sandbox[1].agent_proof.as_ref().unwrap().path,
        format!("/v1/agent/sandboxes/{id}/claimed")
    );
}

/// A sandbox step the person's log verifier would refuse is never logged:
/// a signed path with a query string (a bare `?` too) or an escaped ID is
/// refused with `400`, and a request signed at the edge of the clock
/// window whose body arrives past it with `401`, as a stale one. The log
/// keeps only what verifies.
#[tokio::test]
async fn a_sandbox_step_the_log_would_refuse_is_never_logged() {
    let w = world().await;
    w.make_issuer(1, 10).await;
    let server = &w.server;
    let mut wrong = Vec::new();
    for q in ["?x=1", "?"] {
        let id = SandboxId::generate();
        let body = w.issue_body(id, &["railway"], now_ms() + HOUR_MS);
        let path = format!("/v1/agent/sandboxes{q}");
        server
            .refused_unlogged(
                &w.ana,
                &format!("sandbox.issued with `{q}`"),
                StatusCode::BAD_REQUEST,
                server.agent_call(&w.proxy, Method::POST, &path, Some(&body)),
                &mut wrong,
            )
            .await;
    }
    let id = SandboxId::generate();
    let body = w.issue_body(id, &["railway"], now_ms() + HOUR_MS);
    server
        .refused_unlogged(
            &w.ana,
            "sandbox.issued, its body past the clock window",
            StatusCode::UNAUTHORIZED,
            server.agent_call_late(
                &w.proxy,
                Method::POST,
                "/v1/agent/sandboxes",
                &body,
                std::time::Duration::from_millis(1500),
            ),
            &mut wrong,
        )
        .await;
    // Its retry, signed again, goes through.
    TestServer::expect_status(
        &mut wrong,
        "the late sandbox.issued signed again",
        w.issue_as(&w.proxy, &body).await.status(),
        StatusCode::NO_CONTENT,
    );

    let claimed = json!({ "channel_key_sha256": Blob::new(vec![7; 32]) });
    for what in ["query", "escaped ID"] {
        let id = SandboxId::generate();
        assert_eq!(w.issue(id).await.status(), StatusCode::NO_CONTENT);
        let path = |id: SandboxId| match what {
            "query" => format!("/v1/agent/sandboxes/{id}/claimed?x=1"),
            _ => format!("/v1/agent/sandboxes/{}/claimed", escaped(id)),
        };
        server
            .refused_unlogged(
                &w.ana,
                &format!("sandbox.claimed with a {what}"),
                StatusCode::BAD_REQUEST,
                server.agent_call(&w.proxy, Method::POST, &path(id), Some(&claimed)),
                &mut wrong,
            )
            .await;
    }
    let stop = json!({ "reason": "stop" });
    for what in ["query", "escaped ID"] {
        let id = SandboxId::generate();
        assert_eq!(w.issue(id).await.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            w.claim_as(&w.proxy, id).await.status(),
            StatusCode::NO_CONTENT
        );
        let path = match what {
            "query" => format!("/v1/agent/sandboxes/{id}/revoked?x=1"),
            _ => format!("/v1/agent/sandboxes/{}/revoked", escaped(id)),
        };
        server
            .refused_unlogged(
                &w.ana,
                &format!("sandbox.revoked with a {what}"),
                StatusCode::BAD_REQUEST,
                server.agent_call(&w.proxy, Method::POST, &path, Some(&stop)),
                &mut wrong,
            )
            .await;
        // The honest step still passes.
        TestServer::expect_status(
            &mut wrong,
            &format!("the honest sandbox.revoked after the {what}"),
            w.end_as(&w.proxy, id, "stop").await.status(),
            StatusCode::NO_CONTENT,
        );
    }
    // A signed read keeps its query: the proxy's `revocations?since=`
    // answers as before (`revocations_of` checks the `200`).
    w.revocations_of(&w.proxy, 0).await;
    wrong.extend(server.proofs_the_log_refuses(&w.ana).await);
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// A sandbox issued with a signature that has left the clock window by the
/// time it is logged is refused with `401` (as a stale request), stores
/// nothing and logs nothing: the same sandbox issued again goes through.
/// The account's lock holds it between the extractor and the log
/// (`agent_call_held`).
#[tokio::test]
async fn a_sandbox_logged_too_late_is_never_issued() {
    let w = world().await;
    w.make_issuer(1, 10).await;
    let id = SandboxId::generate();
    let body = w.issue_body(id, &["railway"], now_ms() + HOUR_MS);
    let before = w.server.chain_of(&w.ana).await.len();
    let res = w
        .server
        .agent_call_held(&w.ana, &w.proxy, Method::POST, "/v1/agent/sandboxes", &body)
        .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(w.server.chain_of(&w.ana).await.len(), before);
    assert_eq!(
        w.issue_as(&w.proxy, &body).await.status(),
        StatusCode::NO_CONTENT
    );
    let wrong = w.server.proofs_the_log_refuses(&w.ana).await;
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[tokio::test]
async fn only_a_listed_issuer_within_its_profiles_ttl_and_count() {
    let w = world().await;
    w.make_issuer(1, 2).await;
    let now = now_ms();
    // A profile the issuer was not given (the proxy has none of that name
    // either), and one it was given twice.
    let body = w.issue_body(SandboxId::generate(), &["northflank"], now + HOUR_MS);
    assert_eq!(
        code(w.issue_as(&w.proxy, &body).await).await,
        (StatusCode::FORBIDDEN, ErrorCode::ProfileNotAllowed)
    );
    let body = w.issue_body(
        SandboxId::generate(),
        &["railway", "railway"],
        now + HOUR_MS,
    );
    assert_eq!(
        w.issue_as(&w.proxy, &body).await.status(),
        StatusCode::BAD_REQUEST
    );
    // Past the issuer's hour (plus the clock window), or already over.
    let body = w.issue_body(SandboxId::generate(), &["railway"], now + 2 * HOUR_MS);
    assert_eq!(
        w.issue_as(&w.proxy, &body).await.status(),
        StatusCode::BAD_REQUEST
    );
    let body = w.issue_body(SandboxId::generate(), &["railway"], now - 1);
    assert_eq!(
        w.issue_as(&w.proxy, &body).await.status(),
        StatusCode::BAD_REQUEST
    );
    // Within the window is fine.
    let body = w.issue_body(SandboxId::generate(), &["railway"], now + HOUR_MS + 60_000);
    assert_eq!(
        w.issue_as(&w.proxy, &body).await.status(),
        StatusCode::NO_CONTENT
    );

    // `max_live` 2: a third is refused until one ends.
    let second = SandboxId::generate();
    assert_eq!(w.issue(second).await.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        code(w.issue(SandboxId::generate()).await).await,
        (StatusCode::CONFLICT, ErrorCode::TooManySandboxes)
    );
    assert_eq!(
        w.end_as(&w.proxy, second, "stop").await.status(),
        StatusCode::NO_CONTENT
    );
    let third = SandboxId::generate();
    assert_eq!(w.issue(third).await.status(), StatusCode::NO_CONTENT);

    // The issuer paused: no new sandbox, no claim; its end still goes in.
    w.pause(w.issuer.id, true, now_ms()).await;
    assert_eq!(
        code(w.issue(SandboxId::generate()).await).await,
        (StatusCode::FORBIDDEN, ErrorCode::AgentsPaused)
    );
    assert_eq!(
        code(w.claim_as(&w.proxy, third).await).await,
        (StatusCode::FORBIDDEN, ErrorCode::AgentsPaused)
    );
    w.pause(w.issuer.id, false, now_ms() + 1).await;
    assert_eq!(
        w.claim_as(&w.proxy, third).await.status(),
        StatusCode::NO_CONTENT
    );

    // The issuer revoked: not an issuer any more, and its sandbox cannot be
    // claimed, but its end is recorded.
    let unclaimed = SandboxId::generate();
    assert_eq!(
        w.end_as(&w.proxy, third, "released").await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(w.issue(unclaimed).await.status(), StatusCode::NO_CONTENT);
    let at = now_ms();
    let res = w
        .server
        .post_auth(&w.ana, &format!("/v1/agents/{}/revoke", w.issuer.id))
        .json(&klav_proto::agent::RevokeAgent {
            revoked_at: at,
            signature: Blob::new(
                klav_core::crypto::agent::sign_revocation(
                    &w.ana.identity,
                    w.ana.account_id,
                    w.issuer.id,
                    u64::try_from(at).expect("time"),
                )
                .to_bytes()
                .to_vec(),
            ),
        })
        .send()
        .await
        .expect("revoke");
    assert!(res.status().is_success());
    assert_eq!(
        code(w.issue(SandboxId::generate()).await).await,
        (StatusCode::FORBIDDEN, ErrorCode::NotIssuer)
    );
    assert_eq!(
        code(w.claim_as(&w.proxy, unclaimed).await).await,
        (StatusCode::FORBIDDEN, ErrorCode::SandboxRevoked)
    );
    assert_eq!(
        w.end_as(&w.proxy, unclaimed, "issuer_removed")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
}

/// A server deployed with these routes writes nothing new for an account
/// whose proxy's grant names no issuer, which only a person's client from
/// #284 on can sign: no event, no row, for the proxy or any other agent.
#[tokio::test]
async fn nothing_is_written_without_an_issuer_in_the_proxys_grant() {
    let w = world().await;
    let before = w.chain().await.len();
    let id = SandboxId::generate();
    let body = w.issue_body(id, &["railway"], now_ms() + HOUR_MS);
    for agent in [&w.proxy, &w.plain] {
        assert_eq!(
            code(w.issue_as(agent, &body).await).await,
            (StatusCode::FORBIDDEN, ErrorCode::NotIssuer)
        );
        assert_eq!(w.claim_as(agent, id).await.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            w.end_as(agent, id, "stop").await.status(),
            StatusCode::NOT_FOUND
        );
    }
    // The issuer, still pending, is refused like any agent that is not
    // active.
    assert_eq!(
        code(w.issue_as(&w.issuer, &body).await).await,
        (StatusCode::FORBIDDEN, ErrorCode::Forbidden)
    );
    // A time no reader can hold is refused before anything is read.
    let mut far = body.clone();
    far["expires_at"] = json!(i64::MAX);
    assert_eq!(
        w.issue_as(&w.proxy, &far).await.status(),
        StatusCode::BAD_REQUEST
    );
    far["expires_at"] = json!(u64::MAX);
    assert_eq!(
        w.issue_as(&w.proxy, &far).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(w.chain().await.len(), before, "no event");
    assert_eq!(w.sandbox_rows().await, 0, "no row");

    // Another agent's call on this proxy's sandbox is not found, like a
    // sandbox that does not exist.
    w.make_issuer(1, 3).await;
    assert_eq!(w.issue(id).await.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        w.claim_as(&w.plain, id).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        w.end_as(&w.plain, id, "stop").await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(w.sandbox_rows().await, 1);
}

/// Nothing takes an issuer out of the proxy's grant when it stops being an
/// active agent, so every issue checks it again: listed in the proxy's
/// current grant, and active. A pending one (listed but never approved)
/// is refused, and so is one whose grant no longer names this proxy.
#[tokio::test]
async fn an_issuer_listed_but_not_active_or_not_naming_the_proxy_is_refused() {
    let w = world().await;
    // The proxy's grant lists the issuer, whose own grant was never
    // uploaded: it is still pending.
    let proxy = GrantPayload {
        v: GRANT_PAYLOAD_VERSION_SANDBOXES,
        version: 2,
        issued_at: now_ms(),
        issuers: vec![SandboxIssuer {
            agent_id: w.issuer.id,
            public_identity: Blob::new(w.issuer.keys.public().encode().to_vec()),
            profiles: vec!["railway".into()],
            max_ttl_secs: 3600,
            max_live: 3,
        }],
        ..w.proxy_v2.clone()
    };
    w.post(
        &w.proxy,
        &TestServer::sign_payload(&w.ana, &w.proxy, &proxy),
    )
    .await;
    assert_eq!(
        code(w.issue(SandboxId::generate()).await).await,
        (StatusCode::FORBIDDEN, ErrorCode::NotIssuer)
    );
    // Approved, but its grant names no proxy (the account changed it).
    let issuer = GrantPayload {
        v: GRANT_PAYLOAD_VERSION_SANDBOXES,
        account_id: w.ana.account_id,
        agent_id: w.issuer.id,
        version: 1,
        issued_at: now_ms(),
        policy: Policy::default(),
        projects: Vec::new(),
        items: Vec::new(),
        profiles: Vec::new(),
        issuers: Vec::new(),
        sandbox: Some(IssuerGrant { proxy: None }),
    };
    w.post(
        &w.issuer,
        &TestServer::sign_payload(&w.ana, &w.issuer, &issuer),
    )
    .await;
    assert_eq!(
        code(w.issue(SandboxId::generate()).await).await,
        (StatusCode::FORBIDDEN, ErrorCode::NotIssuer)
    );
    // Both grants agree: it works.
    w.make_issuer(2, 3).await;
    assert_eq!(
        w.issue(SandboxId::generate()).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(w.sandbox_rows().await, 1);
}

/// The server as the second barrier (ADR 0036 E3.3): a proxied call that
/// names a sandbox passes only while the proxy's sandbox is live and its
/// issuer still is one, and the proxy's `me` names the issuers that are
/// gone so it can end their sandboxes. Only this layer's routes say
/// `sandbox_not_found`; a route the server lacks says `not_found`.
#[tokio::test]
async fn a_call_for_a_sandbox_passes_only_while_it_and_its_issuer_are_live() {
    let w = world().await;
    w.make_issuer(1, 3).await;
    let (live, stopped, short) = (
        SandboxId::generate(),
        SandboxId::generate(),
        SandboxId::generate(),
    );
    for id in [live, stopped] {
        assert_eq!(w.issue(id).await.status(), StatusCode::NO_CONTENT);
    }
    let soon = w.issue_body(short, &["railway"], now_ms() + 1500);
    assert_eq!(
        w.issue_as(&w.proxy, &soon).await.status(),
        StatusCode::NO_CONTENT
    );
    // A proxied call without a sandbox is what it was; with a live one it
    // passes too.
    assert_eq!(w.access("proxy", None).await.status(), StatusCode::OK);
    assert_eq!(w.access("proxy", Some(live)).await.status(), StatusCode::OK);
    // Only `proxy` names a sandbox.
    assert_eq!(
        w.access("reveal", Some(live)).await.status(),
        StatusCode::BAD_REQUEST
    );
    // Never logged by this proxy, ended, expired: refused before anything
    // is evaluated or logged.
    assert_eq!(
        w.end_as(&w.proxy, stopped, "stop").await.status(),
        StatusCode::NO_CONTENT
    );
    let before = w.chain().await.len();
    for id in [SandboxId::generate(), stopped] {
        assert_eq!(
            code(w.access("proxy", Some(id)).await).await,
            (StatusCode::FORBIDDEN, ErrorCode::SandboxRevoked)
        );
    }
    tokio::time::sleep(std::time::Duration::from_millis(1600)).await;
    assert_eq!(
        code(w.access("proxy", Some(short)).await).await,
        (StatusCode::FORBIDDEN, ErrorCode::SandboxRevoked)
    );
    assert_eq!(w.chain().await.len(), before, "nothing logged");

    // A paused issuer holds its sandboxes, and is not gone.
    assert!(w.me(&w.proxy).await.get("gone_issuers").is_none());
    w.pause(w.issuer.id, true, now_ms()).await;
    assert_eq!(
        code(w.access("proxy", Some(live)).await).await,
        (StatusCode::FORBIDDEN, ErrorCode::AgentsPaused)
    );
    assert!(w.me(&w.proxy).await.get("gone_issuers").is_none());
    w.pause(w.issuer.id, false, now_ms() + 1).await;
    assert_eq!(w.access("proxy", Some(live)).await.status(), StatusCode::OK);

    // Revoked (`klav agent revoke`, T156): its sandboxes are cut on the
    // next call, and the proxy is told.
    w.revoke(w.issuer.id).await;
    assert_eq!(
        code(w.access("proxy", Some(live)).await).await,
        (StatusCode::FORBIDDEN, ErrorCode::SandboxRevoked)
    );
    assert_eq!(w.me(&w.proxy).await["gone_issuers"], json!([w.issuer.id]));
    // Other agents' `me` is what it was.
    for agent in [&w.plain, &w.issuer] {
        assert!(w.me(agent).await.get("gone_issuers").is_none());
    }

    // An unknown sandbox has its own code on these routes; a route the
    // server does not have keeps the generic one.
    let unknown = SandboxId::generate();
    assert_eq!(
        code(w.end_as(&w.proxy, unknown, "stop").await).await,
        (StatusCode::NOT_FOUND, ErrorCode::SandboxNotFound)
    );
    assert_eq!(
        code(w.claim_as(&w.proxy, unknown).await).await,
        (StatusCode::NOT_FOUND, ErrorCode::SandboxNotFound)
    );
    let nowhere = w
        .server
        .agent_call(
            &w.proxy,
            Method::POST,
            &format!("/v1/agent/sandboxes/{unknown}/nowhere"),
            Some(&json!({})),
        )
        .await;
    assert_eq!(
        code(nowhere).await,
        (StatusCode::NOT_FOUND, ErrorCode::NotFound)
    );
}

/// An issuer whose grant no longer names the proxy is gone for it, like a
/// revoked one, while the proxy's grant still lists it.
#[tokio::test]
async fn an_issuer_that_names_no_proxy_is_gone_for_the_proxy() {
    let w = world().await;
    w.make_issuer(1, 3).await;
    let id = SandboxId::generate();
    assert_eq!(w.issue(id).await.status(), StatusCode::NO_CONTENT);
    let issuer = GrantPayload {
        v: GRANT_PAYLOAD_VERSION_SANDBOXES,
        account_id: w.ana.account_id,
        agent_id: w.issuer.id,
        version: 2,
        issued_at: now_ms(),
        policy: Policy::default(),
        projects: Vec::new(),
        items: Vec::new(),
        profiles: Vec::new(),
        issuers: Vec::new(),
        sandbox: Some(IssuerGrant { proxy: None }),
    };
    w.post(
        &w.issuer,
        &TestServer::sign_payload(&w.ana, &w.issuer, &issuer),
    )
    .await;
    assert_eq!(w.me(&w.proxy).await["gone_issuers"], json!([w.issuer.id]));
    assert_eq!(
        code(w.access("proxy", Some(id)).await).await,
        (StatusCode::FORBIDDEN, ErrorCode::SandboxRevoked)
    );
}

/// A sandbox of another account, or of another proxy of the same account,
/// is the same `404 sandbox_not_found` as one that never existed: the
/// answer says nothing about other proxies' sandboxes, and changes nothing.
#[tokio::test]
async fn another_accounts_or_proxys_sandbox_is_unknown() {
    let w = world().await;
    w.make_issuer(1, 3).await;
    let id = SandboxId::generate();
    assert_eq!(w.issue(id).await.status(), StatusCode::NO_CONTENT);

    // Bo's account and its agent, approved with a project grant.
    let bo = w
        .server
        .login(&w.server.signup("bo@example.com", "pw").await, "laptop")
        .await;
    let vault = w.server.create_vault(&bo).await;
    let project = w.server.create_project(&bo, &vault).await;
    let stranger = TestAgent::new();
    w.server
        .register_agent_ok(&stranger, "bo@example.com", "proxy")
        .await;
    let grant =
        TestServer::build_grant(&bo, &stranger, 1, Policy::default(), &[(&vault, &project)]);
    assert!(
        w.server
            .post_grant(&bo, &stranger, &grant)
            .await
            .status()
            .is_success()
    );

    let unknown = SandboxId::generate();
    for (agent, sandbox) in [
        (&stranger, id),
        (&stranger, unknown),
        // Another agent of Ana's account than the proxy that logged it.
        (&w.plain, id),
    ] {
        assert_eq!(
            code(w.claim_as(agent, sandbox).await).await,
            (StatusCode::NOT_FOUND, ErrorCode::SandboxNotFound)
        );
        assert_eq!(
            code(w.end_as(agent, sandbox, "stop").await).await,
            (StatusCode::NOT_FOUND, ErrorCode::SandboxNotFound)
        );
    }
    // Ana's sandbox is untouched: still unclaimed and live for its proxy.
    assert_eq!(
        w.claim_as(&w.proxy, id).await.status(),
        StatusCode::NO_CONTENT
    );
    let steps: Vec<String> = w
        .chain()
        .await
        .into_iter()
        .filter(|e| e.action.starts_with("sandbox."))
        .map(|e| e.action)
        .collect();
    assert_eq!(steps, ["sandbox.issued", "sandbox.claimed"]);
}

/// A proxied call's approval is for its sandbox (review of #306, F3): the
/// request the person sees for sandbox A, pending or approved, never
/// serves sandbox B or a call of the proxy's own machine, and B cannot
/// name A's. Calls without a sandbox keep their keys (they share one
/// request, as before).
#[tokio::test]
async fn one_sandboxs_approval_never_serves_another_or_the_proxy() {
    let w = world().await;
    w.make_issuer_with(1, 3, Effect::Ask).await;
    let (a, b) = (SandboxId::generate(), SandboxId::generate());
    for id in [a, b] {
        assert_eq!(w.issue(id).await.status(), StatusCode::NO_CONTENT);
    }
    async fn pending(res: reqwest::Response) -> ApprovalId {
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        res.json::<klav_proto::agent::PendingApproval>()
            .await
            .expect("pending")
            .pending_approval_id
    }
    let for_a = pending(w.access("proxy", Some(a)).await).await;
    let for_b = pending(w.access("proxy", Some(b)).await).await;
    let local = pending(w.access("proxy", None).await).await;
    assert_ne!(for_a, for_b);
    assert_ne!(for_a, local);
    assert_ne!(for_b, local);
    // The same caller again gets its own request back.
    assert_eq!(pending(w.access("proxy", Some(a)).await).await, for_a);
    assert_eq!(pending(w.access("proxy", None).await).await, local);

    // The person approves A's, once.
    assert!(
        w.server
            .decide(&w.ana, for_a, true, 0)
            .await
            .status()
            .is_success()
    );
    // B and this machine still wait for their own, and B cannot name A's.
    assert_eq!(pending(w.access("proxy", Some(b)).await).await, for_b);
    assert_eq!(pending(w.access("proxy", None).await).await, local);
    assert_eq!(
        w.access_with("proxy", Some(b), Some(for_a)).await.status(),
        StatusCode::BAD_REQUEST
    );
    // A spends it, once.
    assert_eq!(w.access("proxy", Some(a)).await.status(), StatusCode::OK);
    assert_eq!(
        w.access("proxy", Some(a)).await.status(),
        StatusCode::ACCEPTED
    );
}

/// A lease is for its sandbox too (review of #307, note 1): a lease the
/// person gives for sandbox A lets A through for its window, and never
/// serves sandbox B or a call of the proxy's own machine, with or without
/// naming A's approval.
#[tokio::test]
async fn one_sandboxs_lease_never_serves_another_or_the_proxy() {
    let w = world().await;
    w.make_issuer_with(1, 3, Effect::Ask).await;
    let (a, b) = (SandboxId::generate(), SandboxId::generate());
    for id in [a, b] {
        assert_eq!(w.issue(id).await.status(), StatusCode::NO_CONTENT);
    }
    async fn pending(res: reqwest::Response) -> ApprovalId {
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        res.json::<klav_proto::agent::PendingApproval>()
            .await
            .expect("pending")
            .pending_approval_id
    }
    let for_a = pending(w.access("proxy", Some(a)).await).await;
    // A lease of ten minutes for A's request.
    assert!(
        w.server
            .decide(&w.ana, for_a, true, 600_000)
            .await
            .status()
            .is_success()
    );
    // A goes through, again and again, within the lease.
    for _ in 0..3 {
        assert_eq!(w.access("proxy", Some(a)).await.status(), StatusCode::OK);
    }
    // B and this machine get requests of their own, and naming A's lease
    // does not help them.
    let for_b = pending(w.access("proxy", Some(b)).await).await;
    let local = pending(w.access("proxy", None).await).await;
    assert_ne!(for_b, for_a);
    assert_ne!(local, for_a);
    assert_eq!(
        w.access_with("proxy", Some(b), Some(for_a)).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        w.access_with("proxy", None, Some(for_a)).await.status(),
        StatusCode::BAD_REQUEST
    );
    // A still has its lease.
    assert_eq!(w.access("proxy", Some(a)).await.status(), StatusCode::OK);
}

// The person's revocation (ADR 0036 E3.3, spec §13.11, layer 5a).

impl World {
    /// The person's revocation of `scope` of the proxy, signed for `at`,
    /// sent from `device` with `sent_at` in the body (`at` unless a test
    /// sends something else than it signed).
    async fn revoke_from(
        &self,
        device: &Session,
        proxy: AgentId,
        scope: RevokeScope,
        at: i64,
        sent_at: i64,
    ) -> reqwest::Response {
        let signature = sign_revoke(
            &device.identity,
            &RevokeToSign {
                account: device.account_id,
                proxy,
                scope,
                at_ms: u64::try_from(at).expect("time"),
            },
        );
        let body = SandboxRevoke {
            proxy_id: proxy,
            scope: match scope {
                RevokeScope::All => "all".into(),
                RevokeScope::Sandbox(id) => id.to_string(),
            },
            at: sent_at,
            signature: Blob::new(signature.to_bytes().to_vec()),
        };
        self.server
            .post_auth(device, "/v1/sandboxes/revoke")
            .json(&body)
            .send()
            .await
            .expect("revoke")
    }

    /// Ana revokes `scope` of her proxy at `at`; the stored revocation.
    async fn person_revokes(&self, scope: RevokeScope, at: i64) -> SandboxRevocation {
        let res = self
            .revoke_from(&self.ana, self.proxy.id, scope, at, at)
            .await;
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "{}",
            res.text().await.expect("body")
        );
        res.json().await.expect("revocation")
    }

    /// The revocations `agent` reads after `since`.
    async fn revocations_of(&self, agent: &TestAgent, since: u64) -> SandboxRevocations {
        let res = self
            .server
            .agent_call(
                agent,
                Method::GET,
                &format!("/v1/agent/sandboxes/revocations?since={since}"),
                None,
            )
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        res.json().await.expect("revocations")
    }

    async fn end_with(&self, id: SandboxId, body: &serde_json::Value) -> reqwest::Response {
        self.server
            .agent_call(
                &self.proxy,
                Method::POST,
                &format!("/v1/agent/sandboxes/{id}/revoked"),
                Some(body),
            )
            .await
    }

    /// An end with `body` as raw bytes, signed as sent: JSON that a
    /// `serde_json::Value` cannot hold, such as a repeated key.
    async fn end_raw(&self, id: SandboxId, body: &[u8]) -> reqwest::Response {
        let path = format!("/v1/agent/sandboxes/{id}/revoked");
        let signed = self.proxy.sign("POST", &path, body, now_ms());
        self.server
            .agent_raw(&self.proxy, Method::POST, &path, Some(body), &signed)
            .await
    }

    /// The `sandbox.revoke_requested` events, in log order.
    async fn revoke_events(&self) -> Vec<AuditEvent> {
        self.chain()
            .await
            .into_iter()
            .filter(|e| e.action == "sandbox.revoke_requested")
            .collect()
    }
}

/// One sandbox: the person signs, the server logs it and bars the sandbox
/// at once, the proxy reads it with the account's signature, and the
/// proxy's end answers it.
#[tokio::test]
async fn the_person_revokes_one_sandbox_and_its_proxy_reads_it() {
    let w = world().await;
    w.make_issuer(1, 3).await;
    let (a, b) = (SandboxId::generate(), SandboxId::generate());
    for id in [a, b] {
        assert_eq!(w.issue(id).await.status(), StatusCode::NO_CONTENT);
    }
    assert_eq!(
        w.claim_as(&w.proxy, a).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(w.access("proxy", Some(a)).await.status(), StatusCode::OK);

    let at = now_ms();
    let stored = w.person_revokes(RevokeScope::Sandbox(a), at).await;
    assert_eq!(
        (stored.proxy_id, stored.scope.as_str(), stored.at),
        (w.proxy.id, a.to_string().as_str(), at)
    );
    assert_eq!(stored.sandbox_ids, [a]);
    // The server bars it on the next call; the other sandbox goes on.
    assert_eq!(
        code(w.access("proxy", Some(a)).await).await,
        (StatusCode::FORBIDDEN, ErrorCode::SandboxRevoked)
    );
    assert_eq!(w.access("proxy", Some(b)).await.status(), StatusCode::OK);

    // The proxy reads it, with a signature it can check against the
    // account's identity; after its position, nothing.
    let page = w.revocations_of(&w.proxy, 0).await;
    assert_eq!(page.revocations, std::slice::from_ref(&stored));
    assert!(!page.more);
    let signature: [u8; 64] = stored.signature.as_bytes().try_into().expect("64 bytes");
    verify_revoke(
        w.ana.identity.public(),
        &RevokeToSign {
            account: w.ana.account_id,
            proxy: w.proxy.id,
            scope: RevokeScope::Sandbox(a),
            at_ms: u64::try_from(at).expect("time"),
        },
        &klav_core::crypto::sign::Signature::from_bytes(signature),
    )
    .expect("the account signed it");
    assert!(
        w.revocations_of(&w.proxy, stored.seq)
            .await
            .revocations
            .is_empty()
    );
    // Another agent of the account reads none of this proxy's.
    assert!(w.revocations_of(&w.plain, 0).await.revocations.is_empty());

    // Logged as the person's, at the cursor's position.
    let events = w.revoke_events().await;
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.seq, stored.seq);
    assert_eq!(e.actor, klav_proto::audit::ActorKind::Person);
    assert_eq!(e.agent_id, Some(w.proxy.id));
    assert_eq!(e.sandbox_id, Some(a));
    assert!(e.sandbox_ids.is_empty());
    assert_eq!(e.decided_at, Some(at));
    assert_eq!(e.device_id, Some(w.ana.device_id));
    assert_eq!(e.account_signature.as_ref(), Some(&stored.signature));
    assert!(e.agent_proof.is_none());

    // The same, or an older one, again: refused with the last `at`, so a
    // device signs a later one.
    for again in [at, at - 1] {
        let res = w
            .revoke_from(&w.ana, w.proxy.id, RevokeScope::Sandbox(a), again, again)
            .await;
        assert_eq!(res.status(), StatusCode::CONFLICT);
        let body: ErrorBody = res.json().await.expect("error body");
        assert_eq!(body.last_at, Some(at));
    }
    // A signature over something else, and a time far from the server's.
    let res = w
        .revoke_from(&w.ana, w.proxy.id, RevokeScope::Sandbox(b), at + 1, at + 2)
        .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let far = now_ms() - 10 * 60 * 1000;
    let res = w
        .revoke_from(&w.ana, w.proxy.id, RevokeScope::Sandbox(b), far, far)
        .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(w.revoke_events().await.len(), 1, "nothing else logged");

    // No `at` but a number, and none with another reason, not even an
    // explicit `null`: `main` refused every body with an `at` (second
    // review of #333, 1). Nothing logged.
    let before = w.chain().await.len();
    for body in [
        json!({ "reason": "person", "at": null }),
        json!({ "reason": "stop", "at": null }),
        json!({ "reason": "stop", "at": 1 }),
        json!({ "reason": "stop", "at": 1.0 }),
        // The array form, which serde reads too: refused for every reason,
        // the person's included, even with a revocation's real `at`.
        json!(["stop", 1]),
        json!(["stop"]),
        json!(["person", at]),
        json!(["person"]),
    ] {
        assert_eq!(
            code(w.end_with(a, &body).await).await,
            (StatusCode::BAD_REQUEST, ErrorCode::BadRequest),
            "{body}"
        );
    }
    assert_eq!(w.chain().await.len(), before, "nothing logged");

    // `person_local` stays refused (review of #341, 1): only the proxy's
    // key signs it, and released verifiers reject it. Every shape of body
    // is a `400`. The plain shapes get the same `400` and message, before
    // it is read as an end, and nothing is logged.
    for body in [
        json!({ "reason": "person_local" }),
        json!({ "reason": "person_local", "at": at }),
        json!({ "reason": "person_local", "at": null }),
        json!({ "reason": "person_local", "at": 1.0 }),
        json!({ "reason": "person_local", "extra": 1 }),
        json!(["person_local"]),
        json!(["person_local", at]),
        // serde reads a unit variant from a one-key map too (delta review
        // of #341, 1): the typed value is refused, not only the string.
        json!({ "reason": { "person_local": null } }),
        json!([{ "person_local": null }]),
    ] {
        let res = w.end_with(b, &body).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{body}");
        let e: ErrorBody = res.json().await.expect("error body");
        assert_eq!(
            (e.error, e.message.as_str()),
            (ErrorCode::BadRequest, "unknown reason person_local"),
            "{body}"
        );
    }
    // A repeated key, as raw bytes: whichever `reason` serde would keep,
    // nothing is logged.
    for raw in [
        r#"{"reason":"expired","reason":"person_local"}"#,
        r#"{"reason":"person_local","reason":"expired"}"#,
        r#"{"reason":"ttl","reason":"person_local"}"#,
        r#"{"reason":"person_local","reason":"ttl"}"#,
    ] {
        let res = w.end_raw(b, raw.as_bytes()).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{raw}");
    }
    assert_eq!(w.chain().await.len(), before, "nothing logged");
    assert!(
        w.chain()
            .await
            .iter()
            .all(|e| e.outcome.as_deref() != Some("person_local")),
        "no person_local end in the log"
    );

    // The proxy's end: `person` needs the `at` of a revocation by the
    // person that covers the sandbox.
    assert_eq!(
        w.end_as(&w.proxy, a, "person").await.status(),
        StatusCode::BAD_REQUEST,
        "person without an at"
    );
    assert_eq!(
        w.end_with(a, &json!({ "reason": "person", "at": at + 5 }))
            .await
            .status(),
        StatusCode::CONFLICT,
        "an at no revocation has"
    );
    assert_eq!(
        w.end_with(b, &json!({ "reason": "person", "at": at }))
            .await
            .status(),
        StatusCode::CONFLICT,
        "a revocation that does not cover b"
    );
    assert_eq!(
        w.end_with(a, &json!({ "reason": "person", "at": at }))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let ends: Vec<Option<String>> = w
        .chain()
        .await
        .into_iter()
        .filter(|e| e.action == "sandbox.revoked")
        .map(|e| e.outcome)
        .collect();
    assert_eq!(ends, [Some("person".to_owned())]);

    // A sandbox the person revoked before its claim is never claimed.
    let c = SandboxId::generate();
    assert_eq!(w.issue(c).await.status(), StatusCode::NO_CONTENT);
    w.person_revokes(RevokeScope::Sandbox(c), now_ms()).await;
    assert_eq!(
        code(w.claim_as(&w.proxy, c).await).await,
        (StatusCode::FORBIDDEN, ErrorCode::SandboxRevoked)
    );
}

/// An `all` covers by the signed time, over-inclusive by the clock window
/// (spec §13.11), so a device clock 5 min ahead of the server's still
/// covers every live sandbox, and one 5 min behind lists some already
/// expired too: the server's own clock decides nothing.
#[tokio::test]
async fn an_all_covers_by_the_signed_time_whatever_the_devices_clock() {
    const MINUTE: i64 = 60_000;
    // Ahead: a sandbox that lives 2 more minutes expires before the signed
    // time, and is still listed and barred.
    let w = world().await;
    w.make_issuer(1, 3).await;
    let (live, brief) = (SandboxId::generate(), SandboxId::generate());
    let body = w.issue_body(live, &["railway"], now_ms() + 2 * MINUTE);
    assert_eq!(
        w.issue_as(&w.proxy, &body).await.status(),
        StatusCode::NO_CONTENT
    );
    let at = now_ms() + 5 * MINUTE - 10_000;
    let stored = w.person_revokes(RevokeScope::All, at).await;
    assert_eq!(stored.sandbox_ids, [live], "a device clock ahead");
    assert_eq!(
        code(w.access("proxy", Some(live)).await).await,
        (StatusCode::FORBIDDEN, ErrorCode::SandboxRevoked)
    );

    // Behind: a sandbox that expired a second ago is listed with the live
    // one (barred either way).
    let w = world().await;
    w.make_issuer(1, 3).await;
    let body = w.issue_body(brief, &["railway"], now_ms() + 1000);
    assert_eq!(
        w.issue_as(&w.proxy, &body).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(w.issue(live).await.status(), StatusCode::NO_CONTENT);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let at = now_ms() - 5 * MINUTE + 10_000;
    let stored = w.person_revokes(RevokeScope::All, at).await;
    let mut both = vec![live, brief];
    both.sort();
    assert_eq!(stored.sandbox_ids, both, "a device clock behind");
    assert_eq!(
        code(w.access("proxy", Some(live)).await).await,
        (StatusCode::FORBIDDEN, ErrorCode::SandboxRevoked)
    );
}

/// `all` covers the proxy's sandboxes the log issued before it, read under
/// the account's lock, not ended and not expired by the signed time (with
/// the clock window), and no later one; the ones it covers no longer count
/// against `max_live`.
#[tokio::test]
async fn a_revocation_of_all_covers_what_the_log_issued_before_it() {
    let w = world().await;
    w.make_issuer(1, 3).await;
    let (a, b, ended, short) = (
        SandboxId::generate(),
        SandboxId::generate(),
        SandboxId::generate(),
        SandboxId::generate(),
    );
    for id in [a, b, ended] {
        assert_eq!(w.issue(id).await.status(), StatusCode::NO_CONTENT);
    }
    assert_eq!(
        w.end_as(&w.proxy, ended, "stop").await.status(),
        StatusCode::NO_CONTENT
    );
    let soon = w.issue_body(short, &["railway"], now_ms() + 1500);
    assert_eq!(
        w.issue_as(&w.proxy, &soon).await.status(),
        StatusCode::NO_CONTENT
    );
    // At its limit of three live ones.
    assert_eq!(
        w.issue(SandboxId::generate()).await.status(),
        StatusCode::CONFLICT
    );
    tokio::time::sleep(std::time::Duration::from_millis(1600)).await;

    let at = now_ms();
    let stored = w.person_revokes(RevokeScope::All, at).await;
    // `short` expired just before: within the clock window of the signed
    // time, so it is listed too (spec §13.11, over-inclusive).
    let mut covered = vec![a, b, short];
    covered.sort();
    assert_eq!(stored.scope, "all");
    assert_eq!(stored.sandbox_ids, covered, "live ones, sorted");
    let events = w.revoke_events().await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].sandbox_id, None);
    assert_eq!(events[0].sandbox_ids, covered);
    for id in [a, b] {
        assert_eq!(
            code(w.access("proxy", Some(id)).await).await,
            (StatusCode::FORBIDDEN, ErrorCode::SandboxRevoked)
        );
    }
    // A sandbox issued after it is not covered, and the covered ones no
    // longer hold places under `max_live`.
    let (later, later2) = (SandboxId::generate(), SandboxId::generate());
    for id in [later, later2] {
        assert_eq!(w.issue(id).await.status(), StatusCode::NO_CONTENT);
    }
    assert_eq!(
        w.access("proxy", Some(later)).await.status(),
        StatusCode::OK
    );

    // The proxy answers the `all` for a sandbox it covers, with its `at`;
    // the same `at` answers nothing for a sandbox issued after it.
    assert_eq!(
        w.end_with(later, &json!({ "reason": "person", "at": at }))
            .await
            .status(),
        StatusCode::CONFLICT,
        "issued after the all"
    );
    assert_eq!(
        w.end_with(b, &json!({ "reason": "person", "at": at }))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        w.access("proxy", Some(later)).await.status(),
        StatusCode::OK,
        "still live"
    );

    // One sandbox again, already covered or already ended: accepted and
    // logged (a revocation only takes away).
    for id in [a, ended] {
        let one = w.person_revokes(RevokeScope::Sandbox(id), now_ms()).await;
        assert_eq!(one.sandbox_ids, [id]);
    }

    // Unknown to this proxy (never issued, or another agent's): the same
    // `404 sandbox_not_found`. A proxy that is not the account's agent:
    // `404 not_found`, the same as one that does not exist.
    // One reading of the clock per request: two could differ by a
    // millisecond, and then the body's `at` is not the one signed (a `400`
    // that made this test flaky on a slow run).
    for (proxy, scope) in [(w.proxy.id, SandboxId::generate()), (w.plain.id, later)] {
        let now = now_ms();
        let res = w
            .revoke_from(&w.ana, proxy, RevokeScope::Sandbox(scope), now, now)
            .await;
        assert_eq!(
            code(res).await,
            (StatusCode::NOT_FOUND, ErrorCode::SandboxNotFound)
        );
    }
    let bo = w
        .server
        .login(&w.server.signup("bo@example.com", "pw").await, "laptop")
        .await;
    // Another account gets the same `404` for Ana's proxy as for none,
    // before anything that depends on the proxy's state: even with the
    // `at` of Ana's `all`, which Ana's own device would get a `409` for.
    for proxy in [w.proxy.id, AgentId::generate()] {
        for scope in [RevokeScope::All, RevokeScope::Sandbox(later)] {
            for sent in [now_ms(), at] {
                let res = w.revoke_from(&bo, proxy, scope, sent, sent).await;
                assert_eq!(
                    code(res).await,
                    (StatusCode::NOT_FOUND, ErrorCode::NotFound),
                    "{proxy} {sent}"
                );
            }
        }
    }
    assert_eq!(
        w.revoke_from(&w.ana, w.proxy.id, RevokeScope::All, at, at)
            .await
            .status(),
        StatusCode::CONFLICT,
        "Ana's own device: the replay clock"
    );
    // Bo's attempts changed nothing for Ana.
    assert_eq!(
        w.access("proxy", Some(later)).await.status(),
        StatusCode::OK
    );
    assert_eq!(w.revoke_events().await.len(), 3);
}

/// The proxy pages through its revocations by their position in the log.
#[tokio::test]
async fn revocations_are_paged_by_their_position_in_the_log() {
    let w = world().await;
    w.make_issuer(1, 3).await;
    let base = now_ms();
    for i in 0..101 {
        w.person_revokes(RevokeScope::All, base + i).await;
    }
    let first = w.revocations_of(&w.proxy, 0).await;
    assert_eq!(first.revocations.len(), 100);
    assert!(first.more);
    assert!(first.revocations.windows(2).all(|p| p[0].seq < p[1].seq));
    let last = first.revocations.last().expect("page").seq;
    let second = w.revocations_of(&w.proxy, last).await;
    assert_eq!(second.revocations.len(), 1);
    assert!(!second.more);
    assert_eq!(second.revocations[0].at, base + 100);
    // A cursor that is not a number is refused.
    let res = w
        .server
        .agent_call(
            &w.proxy,
            Method::GET,
            "/v1/agent/sandboxes/revocations?since=x",
            None,
        )
        .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// Several devices revoke at once while the proxy polls: the cursor never
/// skips one. Each revocation's position is its event's in the log, given
/// and committed under the account's lock, so they become visible in
/// order. Only a database with concurrent writers can break this
/// (Postgres); on SQLite, writers already take turns.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_poller_never_misses_a_revocation_made_from_several_devices() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    const DEVICES: usize = 3;
    const EACH: usize = 12;
    let w = busy_world().await;
    w.make_issuer(1, 50).await;
    let mut ids = Vec::new();
    for _ in 0..DEVICES * EACH {
        let id = SandboxId::generate();
        assert_eq!(w.issue(id).await.status(), StatusCode::NO_CONTENT);
        ids.push(id);
    }
    let mut devices = Vec::new();
    for n in 0..DEVICES {
        devices.push(
            w.server
                .login_device(&w.creds, &format!("device-{n}"), None)
                .await,
        );
    }
    let w = Arc::new(w);
    let devices = Arc::new(devices);
    let done = Arc::new(AtomicBool::new(false));
    let poller = {
        let (w, done) = (w.clone(), done.clone());
        tokio::spawn(async move {
            let (mut cursor, mut seen) = (0, Vec::new());
            loop {
                let finished = done.load(Ordering::SeqCst);
                let page = w.revocations_of(&w.proxy, cursor).await;
                let empty = page.revocations.is_empty();
                for r in page.revocations {
                    assert!(r.seq > cursor);
                    cursor = r.seq;
                    seen.push(r.seq);
                }
                if empty && finished {
                    return seen;
                }
            }
        })
    };
    let mut writers = tokio::task::JoinSet::new();
    for (n, chunk) in ids.chunks(EACH).enumerate() {
        let (w, devices, chunk) = (w.clone(), devices.clone(), chunk.to_vec());
        writers.spawn(async move {
            for id in chunk {
                let at = now_ms();
                let res = w
                    .revoke_from(&devices[n], w.proxy.id, RevokeScope::Sandbox(id), at, at)
                    .await;
                assert_eq!(res.status(), StatusCode::OK);
            }
        });
    }
    while let Some(r) = writers.join_next().await {
        r.expect("writer");
    }
    done.store(true, Ordering::SeqCst);
    let seen = poller.await.expect("poller");
    let mut all = Vec::new();
    let mut cursor = 0;
    loop {
        let page = w.revocations_of(&w.proxy, cursor).await;
        all.extend(page.revocations.iter().map(|r| r.seq));
        cursor = all.last().copied().unwrap_or(0);
        if !page.more {
            break;
        }
    }
    assert_eq!(all.len(), DEVICES * EACH);
    assert_eq!(seen, all, "the poller saw every revocation, in order");
}

/// The barrier runs again in the transaction that logs an allowed call, so
/// the log never shows an allowed call for a sandbox after the person's
/// revocation of it, however the two race.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_call_is_allowed_after_the_persons_revocation_in_the_log() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    const ROUNDS: usize = 4;
    const CALLERS: usize = 16;
    let w = busy_world().await;
    w.make_issuer(1, 50).await;
    let w = Arc::new(w);
    let mut refused = 0;
    for _ in 0..ROUNDS {
        let id = SandboxId::generate();
        assert_eq!(w.issue(id).await.status(), StatusCode::NO_CONTENT);
        // Callers call again and again until the server refuses them; the
        // person revokes once a few calls passed, with the others in flight.
        let passed = Arc::new(AtomicUsize::new(0));
        let mut calls = tokio::task::JoinSet::new();
        for _ in 0..CALLERS {
            let (w, passed) = (w.clone(), passed.clone());
            calls.spawn(async move {
                for _ in 0..200 {
                    let status = w.access("proxy", Some(id)).await.status();
                    if status != StatusCode::OK {
                        return status;
                    }
                    passed.fetch_add(1, Ordering::SeqCst);
                }
                StatusCode::OK
            });
        }
        while passed.load(Ordering::SeqCst) < CALLERS {
            tokio::task::yield_now().await;
        }
        w.person_revokes(RevokeScope::Sandbox(id), now_ms()).await;
        while let Some(status) = calls.join_next().await {
            let status = status.expect("call");
            assert_eq!(status, StatusCode::FORBIDDEN, "every caller ends refused");
            refused += 1;
        }
    }
    assert!(refused > 0, "some calls lost the race");
    // In the log, every allowed call for a sandbox comes before its
    // revocation.
    let chain = w.chain().await;
    let mut revoked = std::collections::HashMap::new();
    for e in &chain {
        if e.action == "sandbox.revoke_requested" {
            revoked.insert(e.sandbox_id.expect("one"), e.seq);
        }
    }
    let mut allowed = 0;
    for e in chain
        .iter()
        .filter(|e| e.action == "agent.access" && e.outcome.as_deref() == Some("allow"))
    {
        let body = e
            .agent_proof
            .as_ref()
            .and_then(|p| p.body.as_ref())
            .expect("body");
        let req: serde_json::Value = serde_json::from_slice(body.as_bytes()).expect("request");
        let Some(sandbox) = req.get("sandbox") else {
            continue;
        };
        let sandbox: SandboxId = serde_json::from_value(sandbox.clone()).expect("id");
        allowed += 1;
        assert!(
            e.seq < revoked[&sandbox],
            "an allowed call for {sandbox} at {} after its revocation at {}",
            e.seq,
            revoked[&sandbox]
        );
    }
    assert!(allowed > 0, "some calls won the race");
}

/// How many times [`an_all_racing_issues_covers_exactly_those_logged_before_it`]
/// plays its race, at most: under load the revocation can land before or
/// after every issue, which checks the property but not the race.
const RACE_TRIES: usize = 5;

/// An `all` that races the proxy's issues covers exactly the sandboxes
/// whose `sandbox.issued` the log has before it, and none issued after:
/// the list is read under the account's lock that orders the chain.
///
/// Every try checks the property, in a world of its own. A try in which
/// the revocation landed before or after all the issues is played again,
/// up to [`RACE_TRIES`] times; the test fails if the property breaks in
/// any try, or if the race never happened.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn an_all_racing_issues_covers_exactly_those_logged_before_it() {
    let mut covered = Vec::new();
    for n in 1..=RACE_TRIES {
        let before = race_an_all_against_issues().await;
        if !before.is_empty() && before.len() < RACE_ISSUES {
            eprintln!(
                "the race happened on try {n}: {} of {RACE_ISSUES} covered",
                before.len()
            );
            return;
        }
        eprintln!(
            "try {n}: no race, {} of {RACE_ISSUES} covered",
            before.len()
        );
        covered.push(before.len());
    }
    panic!(
        "the race never happened in {RACE_TRIES} tries (sandboxes covered of {RACE_ISSUES}: \
         {covered:?}); the property held in each"
    );
}

/// The sandboxes [`race_an_all_against_issues`] issues.
const RACE_ISSUES: usize = 40;

/// One try of the race, in a world of its own: the proxy issues
/// [`RACE_ISSUES`] sandboxes while the person revokes `all`. Checks the
/// property and returns the sandboxes the log has before the revocation.
async fn race_an_all_against_issues() -> Vec<SandboxId> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    const ISSUES: usize = RACE_ISSUES;
    let w = Arc::new(busy_world().await);
    w.make_issuer(1, 50).await;
    let issued = Arc::new(AtomicUsize::new(0));
    let issuer = {
        let (w, issued) = (w.clone(), issued.clone());
        tokio::spawn(async move {
            let mut ids = Vec::new();
            for _ in 0..ISSUES {
                let id = SandboxId::generate();
                assert_eq!(w.issue(id).await.status(), StatusCode::NO_CONTENT);
                ids.push(id);
                issued.fetch_add(1, Ordering::SeqCst);
            }
            ids
        })
    };
    // Revoke while issues are still coming.
    while issued.load(Ordering::SeqCst) < ISSUES / 4 {
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    let stored = w.person_revokes(RevokeScope::All, now_ms()).await;
    let ids = issuer.await.expect("issuer");

    let chain = w.chain().await;
    let revoke_seq = chain
        .iter()
        .find(|e| e.action == "sandbox.revoke_requested")
        .expect("logged")
        .seq;
    let mut before = Vec::new();
    for e in chain.iter().filter(|e| e.action == "sandbox.issued") {
        let body = e
            .agent_proof
            .as_ref()
            .and_then(|p| p.body.as_ref())
            .expect("body");
        let req: SandboxIssue = serde_json::from_slice(body.as_bytes()).expect("issue");
        if e.seq < revoke_seq {
            before.push(req.sandbox_id);
        }
    }
    before.sort();
    assert_eq!(stored.sandbox_ids, before, "exactly the ones before it");
    for id in ids {
        let expect = if before.contains(&id) {
            StatusCode::FORBIDDEN
        } else {
            StatusCode::OK
        };
        assert_eq!(w.access("proxy", Some(id)).await.status(), expect, "{id}");
    }
    before
}

impl World {
    /// A signed request of `agent` with `body`, as sent.
    async fn signed_as(
        &self,
        agent: &TestAgent,
        method: Method,
        path: &str,
        body: &serde_json::Value,
    ) -> reqwest::Response {
        let body = serde_json::to_vec(body).expect("json");
        let signed = agent.sign(method.as_str(), path, &body, now_ms());
        self.server
            .agent_raw(agent, method, path, Some(&body), &signed)
            .await
    }

    async fn reset_as(&self, agent: &TestAgent, epoch: &[u8]) -> reqwest::Response {
        self.signed_as(
            agent,
            Method::POST,
            PATH_STORE_RESET,
            &json!({ "store_epoch": Blob::new(epoch.to_vec()) }),
        )
        .await
    }

    async fn beat_as(&self, agent: &TestAgent, epoch: &[u8], seq: u64) -> reqwest::Response {
        let sent = now_ms();
        self.signed_as(
            agent,
            Method::PUT,
            PATH_SANDBOX_STATE,
            &json!({"v": 1, "store_epoch": Blob::new(epoch.to_vec()), "seq": seq,
                "sent_at_ms": sent, "sandboxes": []}),
        )
        .await
    }

    async fn sandbox_state(&self) -> Vec<klav_proto::sandbox::SandboxState> {
        let state: klav_proto::sync::SyncState = self
            .server
            .get_auth(&self.ana, "/v1/sync")
            .send()
            .await
            .expect("request")
            .json()
            .await
            .expect("sync");
        state.sandbox_state
    }
}

/// The proxy logs a new store's epoch once, then heartbeats under it with
/// a growing `seq`; every device gets the last one, as signed, in
/// `GET /v1/sync`, and the log verifies (spec §13.12).
#[tokio::test]
async fn a_proxy_resets_its_store_and_heartbeats_under_the_epoch() {
    let w = world().await;
    let (one, two) = ([1u8; 16], [2u8; 16]);
    assert!(w.sandbox_state().await.is_empty());
    // No heartbeat before a reset.
    assert_eq!(
        w.beat_as(&w.proxy, &one, 1).await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        w.reset_as(&w.proxy, &one).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        w.beat_as(&w.proxy, &one, 1).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        w.beat_as(&w.proxy, &one, 3).await.status(),
        StatusCode::NO_CONTENT
    );
    // A seq that does not grow, and the same epoch again: 409.
    for seq in [3, 2] {
        assert_eq!(
            w.beat_as(&w.proxy, &one, seq).await.status(),
            StatusCode::CONFLICT
        );
    }
    assert_eq!(
        w.reset_as(&w.proxy, &one).await.status(),
        StatusCode::CONFLICT
    );
    let state = w.sandbox_state().await;
    assert_eq!(state.len(), 1);
    assert_eq!(state[0].proxy_id, w.proxy.id);
    let body: SandboxHeartbeat =
        serde_json::from_slice(state[0].proof.body.as_ref().expect("body").as_bytes())
            .expect("heartbeat");
    assert_eq!((body.seq, body.store_epoch.as_bytes()), (3, &one[..]));
    // A new store: the old epoch's heartbeats no longer pass, and seq
    // starts over under the new one.
    assert_eq!(
        w.reset_as(&w.proxy, &two).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        w.beat_as(&w.proxy, &one, 4).await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        w.beat_as(&w.proxy, &two, 1).await.status(),
        StatusCode::NO_CONTENT
    );
    // The log has the two resets and nothing for the heartbeats.
    let actions: Vec<String> = w
        .chain()
        .await
        .into_iter()
        .filter(|e| e.action.starts_with("sandbox."))
        .map(|e| e.action)
        .collect();
    assert_eq!(actions, ["sandbox.store_reset", "sandbox.store_reset"]);
}

/// Only an agent whose grant the account signed as a credential proxy
/// (profiles or issuers) may reset or heartbeat; a paused one may not; a
/// `seq` beyond `i64::MAX` is a typed `400`; nothing is logged for any of
/// them.
#[tokio::test]
async fn who_may_reset_or_heartbeat() {
    let w = world().await;
    let before = w.chain().await.len();
    assert_eq!(
        w.reset_as(&w.plain, &[1; 16]).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        w.beat_as(&w.plain, &[1; 16], 1).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        w.reset_as(&w.proxy, &[1; 15]).await.status(),
        StatusCode::BAD_REQUEST
    );
    let extra = w
        .signed_as(
            &w.proxy,
            Method::POST,
            PATH_STORE_RESET,
            &json!({ "store_epoch": Blob::new(vec![1; 16]), "v": 1 }),
        )
        .await;
    assert_eq!(extra.status(), StatusCode::BAD_REQUEST);
    assert_eq!(w.chain().await.len(), before, "nothing logged");
    assert_eq!(
        w.reset_as(&w.proxy, &[1; 16]).await.status(),
        StatusCode::NO_CONTENT
    );
    let ahead = w
        .signed_as(
            &w.proxy,
            Method::PUT,
            PATH_SANDBOX_STATE,
            &json!({"v": 1, "store_epoch": Blob::new(vec![1; 16]), "seq": 1,
                "sent_at_ms": now_ms() + 6 * 60 * 1000, "sandboxes": []}),
        )
        .await;
    assert_eq!(
        code(ahead).await,
        (StatusCode::BAD_REQUEST, ErrorCode::BadRequest)
    );
    let huge = w.beat_as(&w.proxy, &[1; 16], u64::MAX).await;
    assert_eq!(
        code(huge).await,
        (StatusCode::BAD_REQUEST, ErrorCode::BadRequest)
    );
    w.pause(w.proxy.id, true, now_ms()).await;
    let paused = w.beat_as(&w.proxy, &[1; 16], 1).await;
    assert_eq!(
        code(paused).await,
        (StatusCode::FORBIDDEN, ErrorCode::AgentsPaused)
    );
    let paused = w.reset_as(&w.proxy, &[2; 16]).await;
    assert_eq!(
        code(paused).await,
        (StatusCode::FORBIDDEN, ErrorCode::AgentsPaused)
    );
    assert!(w.sandbox_state().await.is_empty());
}

/// A reset or a heartbeat in the array form, which serde also reads into
/// the struct, signed by the proxy: a typed `400` before anything is
/// written. The person's log verifier takes a reset's body only as a JSON
/// object, so the server must never log one; nor keep such a heartbeat.
#[tokio::test]
async fn the_array_form_is_refused_and_nothing_is_kept() {
    let w = world().await;
    let before = w.chain().await.len();
    let epoch = Blob::new(vec![1; 16]);
    let res = w
        .signed_as(&w.proxy, Method::POST, PATH_STORE_RESET, &json!([epoch]))
        .await;
    assert_eq!(
        code(res).await,
        (StatusCode::BAD_REQUEST, ErrorCode::BadRequest)
    );
    assert_eq!(w.chain().await.len(), before, "nothing logged");
    // No epoch was stored: the object form still takes it, once.
    assert_eq!(
        w.reset_as(&w.proxy, &[1; 16]).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        w.reset_as(&w.proxy, &[1; 16]).await.status(),
        StatusCode::CONFLICT
    );
    let res = w
        .signed_as(
            &w.proxy,
            Method::PUT,
            PATH_SANDBOX_STATE,
            &json!([1, epoch, 1, now_ms(), []]),
        )
        .await;
    assert_eq!(
        code(res).await,
        (StatusCode::BAD_REQUEST, ErrorCode::BadRequest)
    );
    assert!(w.sandbox_state().await.is_empty(), "nothing kept");
    // And `seq` 1 is still free under the epoch.
    assert_eq!(
        w.beat_as(&w.proxy, &[1; 16], 1).await.status(),
        StatusCode::NO_CONTENT
    );
}

/// The rows of `sandbox_store_epochs`, every proxy's.
async fn epoch_rows(w: &World) -> i64 {
    let db = w.server.raw_db().await;
    sqlx::query_scalar("SELECT COUNT(*) FROM sandbox_store_epochs")
        .fetch_one(&db)
        .await
        .expect("count")
}

/// A store reset whose epoch cannot be stored logs nothing: the event and
/// the epoch share one transaction, so a retry with the same epoch is
/// logged once, never twice (a repeated epoch breaks the person's log).
#[tokio::test]
async fn a_store_reset_whose_epoch_cannot_be_kept_is_not_logged() {
    let w = world().await;
    let before = w.chain().await.len();
    w.server.refuse_writes("sandbox_store_epochs").await;
    let res = w.reset_as(&w.proxy, &[1; 16]).await;
    w.server.allow_writes("sandbox_store_epochs").await;
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(w.chain().await.len(), before, "nothing logged");
    assert_eq!(epoch_rows(&w).await, 0, "nothing kept");
    assert_eq!(
        w.reset_as(&w.proxy, &[1; 16]).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        w.reset_as(&w.proxy, &[1; 16]).await.status(),
        StatusCode::CONFLICT
    );
    let chain = w.chain().await;
    assert_eq!(chain.len(), before + 1, "logged once");
    assert_eq!(
        chain
            .iter()
            .filter(|e| e.action == "sandbox.store_reset")
            .count(),
        1
    );
}

/// The other way round: a store reset whose `sandbox.store_reset` the log
/// refuses keeps no epoch, and the same epoch is still taken afterwards.
#[tokio::test]
async fn a_store_reset_that_cannot_be_logged_keeps_no_epoch() {
    let w = world().await;
    let before = w.chain().await.len();
    w.server.refuse_audit_action("sandbox.store_reset").await;
    let res = w.reset_as(&w.proxy, &[2; 16]).await;
    w.server.allow_audit_action("sandbox.store_reset").await;
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(epoch_rows(&w).await, 0, "no epoch kept");
    assert_eq!(w.chain().await.len(), before, "nothing logged");
    assert_eq!(
        w.reset_as(&w.proxy, &[2; 16]).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(epoch_rows(&w).await, 1);
    assert_eq!(w.chain().await.len(), before + 1, "logged once");
}

/// A reset or a heartbeat signed for its path with any query string, even
/// a bare `?`, is a typed `400`: the person's verifier checks the exact
/// path, so it is never logged nor kept (review of #357, 1).
#[tokio::test]
async fn a_query_string_is_refused_and_nothing_is_kept() {
    let w = world().await;
    let before = w.chain().await.len();
    let reset = json!({ "store_epoch": Blob::new(vec![1; 16]) });
    for query in ["?x=1", "?"] {
        let path = format!("{PATH_STORE_RESET}{query}");
        let res = w.signed_as(&w.proxy, Method::POST, &path, &reset).await;
        assert_eq!(
            code(res).await,
            (StatusCode::BAD_REQUEST, ErrorCode::BadRequest),
            "{path}"
        );
    }
    assert_eq!(w.chain().await.len(), before, "nothing logged");
    // The epoch was not used: the exact path still takes it.
    assert_eq!(
        w.reset_as(&w.proxy, &[1; 16]).await.status(),
        StatusCode::NO_CONTENT
    );
    let beat = json!({"v": 1, "store_epoch": Blob::new(vec![1; 16]), "seq": 1,
        "sent_at_ms": now_ms(), "sandboxes": []});
    for query in ["?x=1", "?"] {
        let path = format!("{PATH_SANDBOX_STATE}{query}");
        let res = w.signed_as(&w.proxy, Method::PUT, &path, &beat).await;
        assert_eq!(
            code(res).await,
            (StatusCode::BAD_REQUEST, ErrorCode::BadRequest),
            "{path}"
        );
    }
    assert!(w.sandbox_state().await.is_empty(), "nothing kept");
    // And `seq` 1 is still free under the epoch.
    assert_eq!(
        w.beat_as(&w.proxy, &[1; 16], 1).await.status(),
        StatusCode::NO_CONTENT
    );
}

/// A reset signed inside the clock window whose body arrives after the
/// window closed: the extractor checks the window before it reads the
/// body and again once the body is in (#358), and answers `401` there;
/// `audit::append_in` checks the time the event would carry once more. The
/// verifier refuses an agent signature more than `CLOCK_SKEW_MS` from `at`,
/// so it is never logged (review of #357, 2).
#[tokio::test]
async fn a_reset_whose_body_arrives_after_the_window_is_refused() {
    const CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;
    let w = world().await;
    let before = w.chain().await.len();
    let body = serde_json::to_vec(&json!({ "store_epoch": Blob::new(vec![1; 16]) })).expect("json");
    // About 1 s inside the window; the body comes about 2.5 s later.
    let at = now_ms() - CLOCK_SKEW_MS + 1000;
    let signed = w.proxy.sign("POST", PATH_STORE_RESET, &body, at);
    // The control: the same signing time, another epoch, the body at once.
    // It must be taken: a signature at `at` is accepted when nothing is late.
    let control =
        serde_json::to_vec(&json!({ "store_epoch": Blob::new(vec![3; 16]) })).expect("json");
    let control_signed = w.proxy.sign("POST", PATH_STORE_RESET, &control, at);
    assert_eq!(
        w.server
            .agent_raw(
                &w.proxy,
                Method::POST,
                PATH_STORE_RESET,
                Some(&control),
                &control_signed
            )
            .await
            .status(),
        StatusCode::NO_CONTENT,
        "the control, signed at the same time with its body at once"
    );
    let before = before + 1;
    let slow = futures_util::stream::once(async move {
        tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
        Ok::<_, std::io::Error>(body)
    });
    let request = w
        .server
        .http
        .post(w.server.url(PATH_STORE_RESET))
        .header(klav_proto::agent::HEADER_AGENT, w.proxy.id.to_string())
        .header(
            klav_proto::agent::HEADER_TIMESTAMP,
            signed.timestamp.to_string(),
        )
        .header(
            klav_proto::agent::HEADER_NONCE,
            Blob::new(signed.nonce.to_vec()).to_text(),
        )
        .header(
            klav_proto::agent::HEADER_SIGNATURE,
            Blob::new(signed.signature.clone()).to_text(),
        )
        .header("content-type", "application/json")
        .body(reqwest::Body::wrap_stream(slow));
    // Both checks answer the same `401`, so the status alone cannot say
    // which one refused. The control shows a signature at `at` is accepted
    // with its body at once; this shows the headers leave with `at` still
    // at least 250 ms inside the window, so the extractor's first check
    // passes them. Together: the `401` below comes from the time the body
    // took (its second check, or `append_in`), not from the signing time.
    // On a runner that stalls past that margin this assertion fails rather
    // than letting the test pass for the wrong reason.
    assert!(
        now_ms() - at <= CLOCK_SKEW_MS - 250,
        "the headers would arrive outside the window"
    );
    let res = request.send().await.expect("request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(w.chain().await.len(), before, "nothing logged");
    // The epoch is still free.
    assert_eq!(
        w.reset_as(&w.proxy, &[1; 16]).await.status(),
        StatusCode::NO_CONTENT
    );
}

/// Two accounts on one server, each with its own proxy: each account's
/// `GET /v1/sync` holds only its own proxy's heartbeat (review of #357, 5).
#[tokio::test]
async fn each_account_gets_only_its_own_proxys_heartbeat() {
    let ana = world().await;
    let bea = account_on(ana.server.clone(), "bea@example.com").await;
    for w in [&ana, &bea] {
        assert_eq!(
            w.reset_as(&w.proxy, &[1; 16]).await.status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            w.beat_as(&w.proxy, &[1; 16], 1).await.status(),
            StatusCode::NO_CONTENT
        );
    }
    for w in [&ana, &bea] {
        let state = w.sandbox_state().await;
        let proxies: Vec<AgentId> = state.iter().map(|s| s.proxy_id).collect();
        assert_eq!(proxies, [w.proxy.id]);
    }
}

/// A revoked proxy's last heartbeat stays stored, but no device gets it
/// any more (review of #357, 6).
#[tokio::test]
async fn a_revoked_proxys_heartbeat_is_not_synced() {
    let w = world().await;
    assert_eq!(
        w.reset_as(&w.proxy, &[1; 16]).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        w.beat_as(&w.proxy, &[1; 16], 1).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(w.sandbox_state().await.len(), 1);
    w.revoke(w.proxy.id).await;
    assert!(w.sandbox_state().await.is_empty());
    let db = w.server.raw_db().await;
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sandbox_heartbeats")
        .fetch_one(&db)
        .await
        .expect("count");
    assert_eq!(rows, 1, "the row is kept");
}

/// Rows long expired and never ended (a proxy that died without sending
/// its `ttl` ends) are left out by the query itself, at the same cutoff as
/// `all_covers`: the list is the same with and without them, and the
/// cutoff is exact on both sides (delta review of #341).
#[tokio::test]
async fn an_all_list_is_the_same_with_long_expired_rows() {
    use klav_proto::sandbox::REVOKE_CLOCK_WINDOW_MS;
    let w = world().await;
    w.make_issuer(1, 3).await;
    let (live, edge, past) = (
        SandboxId::generate(),
        SandboxId::generate(),
        SandboxId::generate(),
    );
    for id in [live, edge, past] {
        assert_eq!(w.issue(id).await.status(), StatusCode::NO_CONTENT);
    }
    let at = now_ms();
    let cutoff = at - REVOKE_CLOCK_WINDOW_MS;
    // `edge` is just inside the window; `past` is exactly at the cutoff,
    // so neither the query nor `all_covers` takes it.
    let db = w.server.raw_db().await;
    for (id, expires_at) in [(edge, cutoff + 1), (past, cutoff)] {
        sqlx::query("UPDATE sandboxes SET expires_at = $1 WHERE id = $2")
            .bind(expires_at)
            .bind(id.to_string())
            .execute(&db)
            .await
            .expect("update");
    }
    drop(db);
    let stored = w.person_revokes(RevokeScope::All, at).await;
    let mut expected = vec![live, edge];
    expected.sort();
    assert_eq!(stored.sandbox_ids, expected);

    // The same without the long-expired row: the list does not change.
    let w2 = world().await;
    w2.make_issuer(1, 3).await;
    for id in [live, edge] {
        assert_eq!(w2.issue(id).await.status(), StatusCode::NO_CONTENT);
    }
    let db = w2.server.raw_db().await;
    sqlx::query("UPDATE sandboxes SET expires_at = $1 WHERE id = $2")
        .bind(cutoff + 1)
        .bind(edge.to_string())
        .execute(&db)
        .await
        .expect("update");
    drop(db);
    assert_eq!(
        w2.person_revokes(RevokeScope::All, at).await.sandbox_ids,
        expected
    );
    // And `klav log verify`'s rule agrees on each row.
    assert!(klav_proto::sandbox::all_covers(cutoff + 1, at));
    assert!(!klav_proto::sandbox::all_covers(cutoff, at));
}

// ------------------------------------- a proxy revoked while it writes --

/// The five writes of the proxy, each signed and checked under the
/// account's lock, and a proxied call for a sandbox, which is logged in
/// the transaction that checks the sandbox's barrier again.
#[derive(Clone, Copy, Debug)]
enum ProxyWrite {
    Issue,
    Claim,
    End,
    Reset,
    Heartbeat,
    Access,
}

const PROXY_WRITES: [ProxyWrite; 6] = [
    ProxyWrite::Issue,
    ProxyWrite::Claim,
    ProxyWrite::End,
    ProxyWrite::Reset,
    ProxyWrite::Heartbeat,
    ProxyWrite::Access,
];

/// What the proxy's writes leave behind: sandboxes, claims, ends, store
/// epochs, heartbeats, and the account's log.
#[derive(Debug, PartialEq, Eq)]
struct Footprint {
    sandboxes: i64,
    claimed: i64,
    ended: i64,
    epochs: i64,
    heartbeats: i64,
    events: i64,
}

impl World {
    /// Logs what `write` needs first (an issuer, a sandbox, a store epoch),
    /// so that it would be taken if the proxy were still active. Returns
    /// the sandbox it names.
    async fn ready_for(&self, write: ProxyWrite) -> SandboxId {
        self.make_issuer(1, 5).await;
        let id = SandboxId::generate();
        match write {
            ProxyWrite::Issue => {}
            ProxyWrite::Claim | ProxyWrite::End | ProxyWrite::Access => {
                assert_eq!(self.issue(id).await.status(), StatusCode::NO_CONTENT);
            }
            ProxyWrite::Reset => {}
            ProxyWrite::Heartbeat => {
                assert_eq!(
                    self.reset_as(&self.proxy, &[9; 16]).await.status(),
                    StatusCode::NO_CONTENT
                );
            }
        }
        id
    }

    /// The proxy's `write`, for `id`.
    async fn send_write(&self, write: ProxyWrite, id: SandboxId) -> reqwest::Response {
        match write {
            ProxyWrite::Issue => self.issue(id).await,
            ProxyWrite::Claim => self.claim_as(&self.proxy, id).await,
            ProxyWrite::End => self.end_as(&self.proxy, id, "stop").await,
            ProxyWrite::Reset => self.reset_as(&self.proxy, &[8; 16]).await,
            ProxyWrite::Heartbeat => self.beat_as(&self.proxy, &[9; 16], 1).await,
            ProxyWrite::Access => self.access("proxy", Some(id)).await,
        }
    }

    async fn footprint(&self, db: &sqlx::AnyPool) -> Footprint {
        let count = |sql: &'static str| async move {
            sqlx::query_scalar::<_, i64>(sql)
                .fetch_one(db)
                .await
                .expect("count")
        };
        let events: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE account_id = $1")
                .bind(self.ana.account_id.to_string())
                .fetch_one(db)
                .await
                .expect("count");
        Footprint {
            sandboxes: count("SELECT COUNT(*) FROM sandboxes").await,
            claimed: count("SELECT COUNT(*) FROM sandboxes WHERE claimed_at IS NOT NULL").await,
            ended: count("SELECT COUNT(*) FROM sandboxes WHERE revoked_at IS NOT NULL").await,
            epochs: count("SELECT COUNT(*) FROM sandbox_store_epochs").await,
            heartbeats: count("SELECT COUNT(*) FROM sandbox_heartbeats").await,
            events,
        }
    }
}

/// The status, code and text of `write`'s refusal.
async fn refusal(write: ProxyWrite, res: reqwest::Response) -> (StatusCode, ErrorCode, String) {
    let status = res.status();
    assert_eq!(status, StatusCode::FORBIDDEN, "{write:?} was not refused");
    let body: ErrorBody = res.json().await.expect("error body");
    (status, body.error, body.message)
}

/// What the extractor answers an agent that is not active.
fn not_active() -> (StatusCode, ErrorCode, String) {
    (
        StatusCode::FORBIDDEN,
        ErrorCode::Forbidden,
        "not allowed".to_owned(),
    )
}

/// A proxy the person revoked before the request: each of its five writes,
/// and its call for a sandbox, is refused by the extractor (`403 forbidden`), and nothing is written
/// or logged.
#[tokio::test]
async fn a_proxy_revoked_before_it_writes_is_refused() {
    for write in PROXY_WRITES {
        let w = world().await;
        let id = w.ready_for(write).await;
        w.revoke(w.proxy.id).await;
        let db = w.server.raw_db().await;
        let before = w.footprint(&db).await;
        let res = w.send_write(write, id).await;
        assert_eq!(refusal(write, res).await, not_active(), "{write:?}");
        assert_eq!(w.footprint(&db).await, before, "{write:?}: nothing written");
    }
}

/// A proxy revoked after the extractor let its request through, while the
/// request waits for the account's lock: under the lock the server reads
/// the proxy's status again and gives the extractor's answer, with nothing
/// written and nothing logged after `agent.revoked`. The test holds the
/// account's lock (as the revocation does), waits until the request waits
/// on it (a backend that `pg_blocking_pids` says this transaction blocks),
/// marks the proxy revoked in that same transaction and commits, as the
/// person's revocation does. Postgres only: on SQLite (WAL, one writer, a
/// `busy_timeout`) a request waiting for the writer sits in SQLite's own
/// busy handler, which nothing shows, so only sleeps could order the two.
#[tokio::test]
async fn a_proxy_revoked_while_its_write_waits_for_the_lock_is_refused() {
    let mut taken = Vec::new();
    for write in PROXY_WRITES {
        let w = world().await;
        if !w.server.is_postgres() {
            return;
        }
        let id = w.ready_for(write).await;
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
        // request, nor a job of this server, can stand in for this write.
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
                .bind(w.proxy.id.to_string())
                .execute(&mut *account)
                .await
                .expect("test");
            account.commit().await.expect("test");
        };
        let (res, ()) = tokio::join!(w.send_write(write, id), revoke);
        // Every write is tried, and every one that went through is named.
        let status = res.status();
        if status == StatusCode::FORBIDDEN {
            let body: ErrorBody = res.json().await.expect("error body");
            let answer = (status, body.error, body.message);
            if answer != not_active() {
                taken.push(format!("{write:?}: {answer:?}"));
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

/// A proxied call for a sandbox, with the proxy revoked and the sandbox's
/// end recorded while the call waits for the account's lock: the proxy's
/// status is read first under the lock, as for the proxy's own writes, so
/// the answer is the extractor's (`403 forbidden`), not the sandbox's
/// (`403 sandbox_revoked`), and nothing is logged. Postgres only, as the
/// pair above.
#[tokio::test]
async fn a_revoked_proxy_is_refused_before_its_ended_sandbox() {
    let w = world().await;
    if !w.server.is_postgres() {
        return;
    }
    let id = w.ready_for(ProxyWrite::Access).await;
    let db = w.server.raw_db().await;
    let before = w.footprint(&db).await;
    let held = w.server.raw_db().await;
    let mut account = held.begin().await.expect("test");
    sqlx::query("UPDATE accounts SET updated_at = updated_at WHERE id = $1")
        .bind(w.ana.account_id.to_string())
        .execute(&mut *account)
        .await
        .expect("test");
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
            assert!(std::time::Instant::now() < deadline, "not waiting");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        // Direct `UPDATE`s, as in the pair above: the person's revocation
        // of the proxy, and the sandbox's end.
        sqlx::query("UPDATE agents SET status = 'revoked', revoked_at = $1 WHERE id = $2")
            .bind(now_ms())
            .bind(w.proxy.id.to_string())
            .execute(&mut *account)
            .await
            .expect("test");
        sqlx::query("UPDATE sandboxes SET revoked_at = $1 WHERE id = $2")
            .bind(now_ms())
            .bind(id.to_string())
            .execute(&mut *account)
            .await
            .expect("test");
        account.commit().await.expect("test");
    };
    let (res, ()) = tokio::join!(w.send_write(ProxyWrite::Access, id), revoke);
    assert_eq!(refusal(ProxyWrite::Access, res).await, not_active());
    assert_eq!(
        w.footprint(&db).await.events,
        before.events,
        "nothing logged"
    );
}

/// The same at the second barrier, when the allowed call is logged: the
/// proxy revoked and the sandbox ended after the first barrier passed. A
/// deferred constraint trigger on the account's row commits both with the
/// first barrier's own transaction (it is the first to lock the row, on
/// Postgres), once; the logging step then reads the proxy's status before
/// the barrier and answers `403 forbidden`, not `403 sandbox_revoked`, with
/// nothing logged. Postgres only: SQLite has no deferred triggers.
#[tokio::test]
async fn a_revoked_proxy_is_refused_before_its_ended_sandbox_when_logged() {
    let w = world().await;
    if !w.server.is_postgres() {
        return;
    }
    let id = w.ready_for(ProxyWrite::Access).await;
    let db = w.server.raw_db().await;
    let before = w.footprint(&db).await;
    let safe = |s: String| {
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        s
    };
    let account = safe(w.ana.account_id.to_string());
    let proxy = safe(w.proxy.id.to_string());
    let sandbox = safe(id.to_string());
    for sql in [
        "CREATE TABLE klav_test_once (fired BOOLEAN NOT NULL)".to_owned(),
        "INSERT INTO klav_test_once VALUES (false)".to_owned(),
        format!(
            "CREATE FUNCTION klav_test_end() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
             UPDATE klav_test_once SET fired = true WHERE NOT fired; \
             IF FOUND THEN \
             UPDATE agents SET status = 'revoked', revoked_at = 1 WHERE id = '{proxy}'; \
             UPDATE sandboxes SET revoked_at = 1 WHERE id = '{sandbox}'; \
             END IF; RETURN NULL; END $$"
        ),
        format!(
            "CREATE CONSTRAINT TRIGGER klav_test_end AFTER UPDATE ON accounts \
             DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.id = '{account}') \
             EXECUTE FUNCTION klav_test_end()"
        ),
    ] {
        // Every ID is checked above, so it is safe to interpolate.
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(&db)
            .await
            .expect("test trigger");
    }
    let res = w.send_write(ProxyWrite::Access, id).await;
    let fired: bool = sqlx::query_scalar("SELECT fired FROM klav_test_once")
        .fetch_one(&db)
        .await
        .expect("test");
    assert!(fired, "the first barrier's commit ended nothing");
    assert_eq!(refusal(ProxyWrite::Access, res).await, not_active());
    assert_eq!(
        w.footprint(&db).await.events,
        before.events,
        "nothing logged"
    );
}

// ------------- each sandbox write and its event, in one transaction (guards) --
//
// The three guards #406 and #408 gave every write that logs in its own
// transaction: the log refuses the event and nothing is stored; the
// database refuses the write and nothing is logged; on Postgres, the row
// and its event were written by one transaction (`xmin`). The store reset
// has its pair above; the person's revocation has no `xmin` test, since
// neither of its tables has an `id` column.

/// What a sandbox's row says of its life: `(exists, claimed, ended)`.
async fn sandbox_life(w: &World, id: SandboxId) -> (bool, bool, bool) {
    let db = w.server.raw_db().await;
    let row: Option<(Option<i64>, Option<i64>)> =
        sqlx::query_as("SELECT claimed_at, revoked_at FROM sandboxes WHERE id = $1")
            .bind(id.to_string())
            .fetch_optional(&db)
            .await
            .expect("test");
    row.map_or((false, false, false), |(claimed, ended)| {
        (true, claimed.is_some(), ended.is_some())
    })
}

/// How many events of Ana's chain have `action`.
async fn logged(w: &World, action: &str) -> usize {
    w.chain()
        .await
        .iter()
        .filter(|e| e.action == action)
        .count()
}

/// A proxy's step, for the guards: issue, claim or end the sandbox.
#[derive(Clone, Copy, Debug)]
enum Step {
    Issue,
    Claim,
    End,
}

const STEPS: [Step; 3] = [Step::Issue, Step::Claim, Step::End];

impl Step {
    fn action(self) -> &'static str {
        match self {
            Step::Issue => "sandbox.issued",
            Step::Claim => "sandbox.claimed",
            Step::End => "sandbox.revoked",
        }
    }

    /// A sandbox ready for this step: none yet to issue, an issued one to
    /// claim, a claimed one to end.
    async fn ready(self, w: &World) -> SandboxId {
        let id = SandboxId::generate();
        if matches!(self, Step::Claim | Step::End) {
            assert_eq!(w.issue(id).await.status(), StatusCode::NO_CONTENT);
        }
        if matches!(self, Step::End) {
            assert_eq!(
                w.claim_as(&w.proxy, id).await.status(),
                StatusCode::NO_CONTENT
            );
        }
        id
    }

    async fn take(self, w: &World, id: SandboxId) -> StatusCode {
        match self {
            Step::Issue => w.issue(id).await,
            Step::Claim => w.claim_as(&w.proxy, id).await,
            Step::End => w.end_as(&w.proxy, id, "stop").await,
        }
        .status()
    }

    /// The sandbox's life before and after this step.
    fn lives(self) -> ((bool, bool, bool), (bool, bool, bool)) {
        match self {
            Step::Issue => ((false, false, false), (true, false, false)),
            Step::Claim => ((true, false, false), (true, true, false)),
            Step::End => ((true, true, false), (true, true, true)),
        }
    }
}

/// A sandbox step whose event the log refuses is not stored: issued,
/// claimed or ended, the sandbox stays as it was, and the same step taken
/// again goes through, logged once.
#[tokio::test]
async fn a_sandbox_step_that_cannot_be_logged_is_not_stored() {
    let w = world().await;
    w.make_issuer(1, 10).await;
    for step in STEPS {
        let id = step.ready(&w).await;
        let (before, after) = step.lives();
        let logged_before = logged(&w, step.action()).await;
        w.server.refuse_audit_action(step.action()).await;
        let status = step.take(&w, id).await;
        w.server.allow_audit_action(step.action()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{step:?}");
        assert_eq!(sandbox_life(&w, id).await, before, "{step:?}: not stored");
        assert_eq!(logged(&w, step.action()).await, logged_before, "{step:?}");
        assert_eq!(step.take(&w, id).await, StatusCode::NO_CONTENT, "{step:?}");
        assert_eq!(sandbox_life(&w, id).await, after, "{step:?}");
        assert_eq!(
            logged(&w, step.action()).await,
            logged_before + 1,
            "{step:?}: logged once"
        );
    }
}

/// A sandbox step the database refuses to store logs no event: the event
/// is appended in the step's transaction, not in one of its own before it.
#[tokio::test]
async fn a_sandbox_step_that_cannot_be_stored_is_not_logged() {
    let w = world().await;
    w.make_issuer(1, 10).await;
    for step in STEPS {
        let id = step.ready(&w).await;
        let (before, after) = step.lives();
        let logged_before = logged(&w, step.action()).await;
        w.server.refuse_writes("sandboxes").await;
        let status = step.take(&w, id).await;
        w.server.allow_writes("sandboxes").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{step:?}");
        assert_eq!(sandbox_life(&w, id).await, before, "{step:?}");
        assert_eq!(
            logged(&w, step.action()).await,
            logged_before,
            "{step:?}: nothing logged"
        );
        assert_eq!(step.take(&w, id).await, StatusCode::NO_CONTENT, "{step:?}");
        assert_eq!(sandbox_life(&w, id).await, after, "{step:?}");
        assert_eq!(logged(&w, step.action()).await, logged_before + 1);
    }
}

/// Postgres only: each sandbox step writes the sandbox's row and appends
/// its event in one transaction.
#[tokio::test]
async fn a_sandbox_step_and_its_event_share_one_transaction() {
    let w = world().await;
    if !w.server.is_postgres() {
        return;
    }
    w.make_issuer(1, 10).await;
    let db = w.server.raw_db().await;
    for step in STEPS {
        let id = step.ready(&w).await;
        assert_eq!(step.take(&w, id).await, StatusCode::NO_CONTENT, "{step:?}");
        w.server
            .assert_written_with(
                &db,
                w.ana.account_id,
                "sandboxes",
                &id.to_string(),
                step.action(),
            )
            .await;
    }
}

/// The rows a person's revocation of `id` left: `(revocations of the
/// account, barrier rows of the sandbox)`.
async fn revocation_rows(w: &World, id: SandboxId) -> (i64, i64) {
    let db = w.server.raw_db().await;
    let revocations =
        sqlx::query_scalar("SELECT COUNT(*) FROM sandbox_revocations WHERE account_id = $1")
            .bind(w.ana.account_id.to_string())
            .fetch_one(&db)
            .await
            .expect("test");
    let barred =
        sqlx::query_scalar("SELECT COUNT(*) FROM sandbox_person_revoked WHERE sandbox_id = $1")
            .bind(id.to_string())
            .fetch_one(&db)
            .await
            .expect("test");
    (revocations, barred)
}

/// A person's revocation whose `sandbox.revoke_requested` the log refuses
/// stores neither the revocation nor its barrier: the sandbox stays
/// usable, and the same revocation then goes through, logged once.
#[tokio::test]
async fn a_person_revocation_that_cannot_be_logged_is_not_stored() {
    let w = world().await;
    w.make_issuer(1, 10).await;
    let id = SandboxId::generate();
    assert_eq!(w.issue(id).await.status(), StatusCode::NO_CONTENT);
    w.server
        .refuse_audit_action("sandbox.revoke_requested")
        .await;
    let at = now_ms();
    let status = w
        .revoke_from(&w.ana, w.proxy.id, RevokeScope::Sandbox(id), at, at)
        .await
        .status();
    w.server
        .allow_audit_action("sandbox.revoke_requested")
        .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(revocation_rows(&w, id).await, (0, 0), "nothing stored");
    assert!(w.revoke_events().await.is_empty());
    assert_eq!(
        w.access("proxy", Some(id)).await.status(),
        StatusCode::OK,
        "not barred"
    );
    w.person_revokes(RevokeScope::Sandbox(id), now_ms()).await;
    assert_eq!(revocation_rows(&w, id).await, (1, 1));
    assert_eq!(w.revoke_events().await.len(), 1);
}

/// A person's revocation whose revocation row or barrier row the database
/// refuses logs no `sandbox.revoke_requested`: the event is appended in
/// the revocation's transaction, before both rows.
#[tokio::test]
async fn a_person_revocation_that_cannot_be_stored_is_not_logged() {
    let w = world().await;
    w.make_issuer(1, 10).await;
    for (n, table) in ["sandbox_revocations", "sandbox_person_revoked"]
        .into_iter()
        .enumerate()
    {
        let id = SandboxId::generate();
        assert_eq!(w.issue(id).await.status(), StatusCode::NO_CONTENT);
        let revocations = i64::try_from(n).expect("test");
        w.server.refuse_writes(table).await;
        let at = now_ms();
        let status = w
            .revoke_from(&w.ana, w.proxy.id, RevokeScope::Sandbox(id), at, at)
            .await
            .status();
        w.server.allow_writes(table).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{table}");
        assert_eq!(
            revocation_rows(&w, id).await,
            (revocations, 0),
            "{table}: nothing stored"
        );
        assert_eq!(w.revoke_events().await.len(), n, "{table}: nothing logged");
        w.person_revokes(RevokeScope::Sandbox(id), now_ms()).await;
        assert_eq!(revocation_rows(&w, id).await, (revocations + 1, 1));
        assert_eq!(w.revoke_events().await.len(), n + 1, "{table}");
    }
}
