//! Agent secret requests (ADR 0046): an agent asks the person to create a
//! missing item or update a secret field, the person enters the secret on
//! their device and signs the decision, and the server clears `proposal_blob`
//! on decision, expiry or revocation.

mod common;

use std::sync::Arc;

use common::TestServer;
use common::agent::{TestAgent, now_ms};
use common::client::Session;
use common::vault::{TestProject, TestVault, login_item};
use klav_core::crypto::agent::{
    self, SecretRequestDecisionToSign, body_digest, seal_secret_request,
};
use klav_core::ids::{ItemId, SecretRequestId};
use klav_core::model::ItemKind;
use klav_core::policy::{
    DomainPattern, Effect, HttpMethod, PathPrefix, Permission, Policy, Rule, Scope,
};
use klav_core::secret_request::{
    SECRET_REQUEST_FORMAT_VERSION, SecretRequestDecision, SecretRequestMode, SecretRequestProposal,
    SecretRequestStatus,
};
use klav_proto::Blob;
use klav_proto::agent::ProxyProfile;
use klav_proto::audit::{AuditEvent, AuditPage};
use klav_proto::secret_request::{
    CreateSecretRequest, DecideSecretRequest, PendingSecretRequest, SECRET_REQUEST_TTL_MS,
    SecretRequestInfo, SecretRequestList, SecretRequestState,
};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

struct World {
    server: Arc<TestServer>,
    ana: Session,
    vault: TestVault,
    project: TestProject,
    _other_project: TestProject,
    agent: TestAgent,
    granted_item: ItemId,
    ungranted_item: ItemId,
}

async fn world() -> World {
    let server = Arc::new(TestServer::start().await);
    let ana = server
        .login(&server.signup("ana@example.com", "pw").await, "laptop")
        .await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let other_project = server.create_project(&ana, &vault).await;

    let granted = login_item("Stripe", "ana", "sk_live_initial");
    server.create_item(&ana, &vault, &project, &granted).await;
    let ungranted = login_item("Private", "ana", "top_secret");
    server
        .create_item(&ana, &vault, &other_project, &ungranted)
        .await;

    let agent = TestAgent::new();
    server
        .register_agent_ok(&agent, "ana@example.com", "claude")
        .await;
    let policy = Policy {
        rules: vec![Rule::new(Permission::Inject, Effect::Allow)],
        expires_at: None,
    };
    let grant = TestServer::build_grant(&ana, &agent, 1, policy, &[(&vault, &project)]);
    assert_eq!(
        server.post_grant(&ana, &agent, &grant).await.status(),
        StatusCode::OK
    );

    World {
        server,
        ana,
        vault,
        project,
        _other_project: other_project,
        agent,
        granted_item: granted.id(),
        ungranted_item: ungranted.id(),
    }
}

impl World {
    fn build_create_body(
        &self,
        id: SecretRequestId,
        mode: SecretRequestMode,
        target_item_id: Option<ItemId>,
        reason: &str,
    ) -> (CreateSecretRequest, [u8; 32]) {
        let proposal = SecretRequestProposal {
            v: SECRET_REQUEST_FORMAT_VERSION,
            mode,
            kind: (mode == SecretRequestMode::Create).then_some(ItemKind::ApiKey),
            title: (mode == SecretRequestMode::Create).then(|| "Stripe API key".into()),
            vault_id: Some(self.vault.id),
            project_id: Some(self.project.id),
            target_item_id,
            field: "api_key".into(),
            placeholder: Some("sk_live_…".into()),
            setup_url: Some("https://dashboard.stripe.com/apikeys".into()),
            base_url: (mode == SecretRequestMode::Create).then(|| "https://api.stripe.com".into()),
            urls: vec![],
            notes: None,
            proxy_proposal: None,
        };
        proposal.validate().expect("test");
        let canonical = serde_json::to_vec(&proposal).expect("test");
        let digest = body_digest(&canonical);
        let blob = seal_secret_request(
            self.ana.identity.public(),
            self.ana.account_id,
            self.agent.id,
            id,
            &canonical,
        )
        .expect("test");
        (
            CreateSecretRequest {
                id,
                mode,
                target_item_id,
                reason: reason.into(),
                proposal_digest: Blob::new(digest.to_vec()),
                proposal_blob: Blob::new(blob),
            },
            digest,
        )
    }

    async fn agent_call(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> reqwest::Response {
        self.server
            .agent_call(&self.agent, method, path, body)
            .await
    }

    fn sign_decision(
        &self,
        id: SecretRequestId,
        digest: &[u8; 32],
        decision: &SecretRequestDecision,
        decided_at: i64,
    ) -> DecideSecretRequest {
        let bytes = serde_json::to_vec(decision).expect("test");
        let sig = agent::sign_secret_request_decision(
            &self.ana.identity,
            &SecretRequestDecisionToSign {
                request: id,
                agent: self.agent.id,
                proposal_digest: digest,
                decision: &bytes,
                decided_at_ms: u64::try_from(decided_at).expect("test"),
            },
        );
        DecideSecretRequest {
            decision: Blob::new(bytes),
            signature: Blob::new(sig.to_bytes().to_vec()),
            decided_at,
        }
    }
}

#[tokio::test]
async fn create_decide_fulfill_clears_blob_and_audits() {
    let w = world().await;
    let id = SecretRequestId::generate();
    let (body, digest) = w.build_create_body(
        id,
        SecretRequestMode::Create,
        None,
        "Needed for billing tests",
    );
    let res = w
        .agent_call(
            Method::POST,
            "/v1/agent/secret-requests",
            Some(&serde_json::to_value(&body).unwrap()),
        )
        .await;
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let pending: PendingSecretRequest = res.json().await.unwrap();
    assert_eq!(pending.request_id, id);

    // Person sees the proposal blob while pending.
    let res = w
        .server
        .get_auth(&w.ana, "/v1/secret-requests")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let list: SecretRequestList = res.json().await.unwrap();
    assert_eq!(list.secret_requests.len(), 1);
    assert_eq!(list.secret_requests[0].id, id);
    assert!(list.secret_requests[0].proposal_blob.is_some());

    // Agent does not get proposal_blob back on poll.
    let res = w
        .agent_call(
            Method::GET,
            &format!("/v1/agent/secret-requests/{id}"),
            None,
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let info: SecretRequestInfo = res.json().await.unwrap();
    assert_eq!(info.status, SecretRequestState::Pending);
    assert!(info.proposal_blob.is_none());

    // Person fulfills the request.
    let created_item = ItemId::generate();
    let decided_at = now_ms();
    let decision = SecretRequestDecision {
        v: SECRET_REQUEST_FORMAT_VERSION,
        request_id: id,
        agent_id: w.agent.id,
        status: SecretRequestStatus::Fulfilled,
        in_grant: true,
        vault_id: Some(w.vault.id),
        project_id: Some(w.project.id),
        item_id: Some(created_item),
        field: Some("api_key".into()),
        proxy_profile: None,
    };
    let decide_req = w.sign_decision(id, &digest, &decision, decided_at);
    let res = w
        .server
        .post_auth(&w.ana, &format!("/v1/secret-requests/{id}/decide"))
        .json(&decide_req)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let decided: SecretRequestInfo = res.json().await.unwrap();
    assert_eq!(decided.status, SecretRequestState::Fulfilled);
    assert!(decided.proposal_blob.is_none());
    assert!(decided.decision.is_some());
    assert!(decided.signature.is_some());

    // Second decision is rejected with 409.
    let res = w
        .server
        .post_auth(&w.ana, &format!("/v1/secret-requests/{id}/decide"))
        .json(&decide_req)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);

    // Audit log contains secret_request.created (without body) and secret_request.decided.
    let page: AuditPage = w
        .server
        .get_auth(&w.ana, "/v1/audit")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let events: Vec<AuditEvent> = page
        .entries
        .iter()
        .map(|e| serde_json::from_slice(e.event.as_bytes()).unwrap())
        .collect();
    let created_ev = events
        .iter()
        .find(|e| e.action == "secret_request.created")
        .expect("secret_request.created event");
    assert_eq!(created_ev.secret_request_id, Some(id));
    assert_eq!(
        created_ev.proposal_digest.as_ref().map(|b| b.as_bytes()),
        Some(digest.as_slice())
    );
    assert!(
        created_ev.agent_proof.as_ref().unwrap().body.is_none(),
        "proposal_blob must never be retained in audit_events"
    );
    let decided_ev = events
        .iter()
        .find(|e| e.action == "secret_request.decided")
        .expect("secret_request.decided event");
    assert_eq!(decided_ev.secret_request_id, Some(id));
    assert_eq!(decided_ev.outcome.as_deref(), Some("fulfilled"));
    assert_eq!(decided_ev.item_id, Some(created_item));
}

#[tokio::test]
async fn update_mode_hides_items_outside_grant() {
    let w = world().await;
    // Target inside grant succeeds.
    let id1 = SecretRequestId::generate();
    let (body1, _) = w.build_create_body(
        id1,
        SecretRequestMode::Update,
        Some(w.granted_item),
        "Rotate Stripe key",
    );
    let res = w
        .agent_call(
            Method::POST,
            "/v1/agent/secret-requests",
            Some(&serde_json::to_value(&body1).unwrap()),
        )
        .await;
    assert_eq!(res.status(), StatusCode::ACCEPTED);

    // Target outside grant returns 404 (same as nonexistent: T236).
    let id2 = SecretRequestId::generate();
    let (body2, _) = w.build_create_body(
        id2,
        SecretRequestMode::Update,
        Some(w.ungranted_item),
        "Probe private item",
    );
    let res = w
        .agent_call(
            Method::POST,
            "/v1/agent/secret-requests",
            Some(&serde_json::to_value(&body2).unwrap()),
        )
        .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // Nonexistent item also returns 404.
    let id3 = SecretRequestId::generate();
    let (body3, _) = w.build_create_body(
        id3,
        SecretRequestMode::Update,
        Some(ItemId::generate()),
        "Probe random item",
    );
    let res = w
        .agent_call(
            Method::POST,
            "/v1/agent/secret-requests",
            Some(&serde_json::to_value(&body3).unwrap()),
        )
        .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn pending_cap_and_expiry_sweep() {
    let w = world().await;
    for i in 0..5 {
        let id = SecretRequestId::generate();
        let (body, _) =
            w.build_create_body(id, SecretRequestMode::Create, None, &format!("Secret #{i}"));
        let res = w
            .agent_call(
                Method::POST,
                "/v1/agent/secret-requests",
                Some(&serde_json::to_value(&body).unwrap()),
            )
            .await;
        assert_eq!(res.status(), StatusCode::ACCEPTED);
    }
    // 6th pending request hits the cap of 5 (429).
    let extra = SecretRequestId::generate();
    let (body, _) = w.build_create_body(extra, SecretRequestMode::Create, None, "Too many");
    let res = w
        .agent_call(
            Method::POST,
            "/v1/agent/secret-requests",
            Some(&serde_json::to_value(&body).unwrap()),
        )
        .await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

    // Purge past TTL expires all 5 and clears their proposal blobs.
    w.server
        .server_handle()
        .purge_expired(now_ms() + SECRET_REQUEST_TTL_MS + 1_000)
        .await
        .unwrap();
    let list: SecretRequestList = w
        .server
        .get_auth(&w.ana, "/v1/secret-requests")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.secret_requests.len(), 5);
    for sr in &list.secret_requests {
        assert_eq!(sr.status, SecretRequestState::Expired);
        assert!(sr.proposal_blob.is_none());
    }
}

#[tokio::test]
async fn proxy_agent_is_refused() {
    let w = world().await;
    let proxy = TestAgent::new();
    w.server
        .register_agent_ok(&proxy, "ana@example.com", "proxy")
        .await;
    let item = login_item("Railway", "ana", "railway-token");
    let (item_key, _) = w
        .server
        .create_item(&w.ana, &w.vault, &w.project, &item)
        .await;
    let mut rules = vec![Rule {
        scope: Scope {
            items: vec![item.id()],
            domains: vec![DomainPattern::parse("api.example.com").expect("host")],
            methods: vec![HttpMethod::parse("POST").expect("method")],
            path_prefixes: vec![PathPrefix::parse("/v1").expect("prefix")],
            ..Scope::default()
        },
        ..Rule::new(Permission::Proxy, Effect::Allow)
    }];
    rules.extend(
        [Permission::Reveal, Permission::Inject, Permission::Fill]
            .into_iter()
            .map(|p| Rule::new(p, Effect::Deny)),
    );
    let grant = TestServer::build_item_grant(
        &w.ana,
        &proxy,
        1,
        Policy {
            rules,
            expires_at: None,
        },
        &[(&w.vault, &w.project, item.id(), &item_key)],
        vec![ProxyProfile {
            name: "railway".into(),
            item_id: item.id(),
            field: None,
            header: "authorization".into(),
            prefix: "Bearer ".into(),
            upstream: "https://api.example.com".into(),
            rate_per_minute: None,
            mcp: None,
        }],
    );
    assert_eq!(
        w.server.post_grant(&w.ana, &proxy, &grant).await.status(),
        StatusCode::OK
    );

    let id = SecretRequestId::generate();
    let proposal = SecretRequestProposal {
        v: SECRET_REQUEST_FORMAT_VERSION,
        mode: SecretRequestMode::Create,
        kind: Some(ItemKind::ApiKey),
        title: Some("API key".into()),
        vault_id: None,
        project_id: None,
        target_item_id: None,
        field: "api_key".into(),
        placeholder: None,
        setup_url: None,
        base_url: None,
        urls: vec![],
        notes: None,
        proxy_proposal: None,
    };
    let canonical = serde_json::to_vec(&proposal).unwrap();
    let digest = body_digest(&canonical);
    let blob = seal_secret_request(
        w.ana.identity.public(),
        w.ana.account_id,
        proxy.id,
        id,
        &canonical,
    )
    .unwrap();
    let body = json!({
        "id": id,
        "mode": "create",
        "reason": "Proxy should be refused",
        "proposal_digest": Blob::new(digest.to_vec()),
        "proposal_blob": Blob::new(blob),
    });
    let res = w
        .server
        .agent_call(
            &proxy,
            Method::POST,
            "/v1/agent/secret-requests",
            Some(&body),
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}
