//! Environments per repository on the server (ADR 0032 §3.1 and §4): `once`
//! only with `ask`, no lease on a target that always asks, a grant that
//! loses an inherited rule without `released` gets `409`, and one approval
//! covers an environment and the protected items it points to, one access
//! each.

mod common;

use common::TestServer;
use common::agent::TestAgent;
use common::client::Session;
use common::vault::{TestProject, TestVault, login_item};
use klav_core::ids::{ApprovalId, ItemId};
use klav_core::policy::{Effect, Permission, Policy, Rule};
use klav_proto::agent::{ApprovalInfo, ApprovalRequest, GrantPayload, PendingApproval};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

struct World {
    server: TestServer,
    ana: Session,
    vault: TestVault,
    project: TestProject,
    agent: TestAgent,
    /// The `production` environment (stored as a login here: the server
    /// never sees the kind).
    production: ItemId,
    /// The Stripe API key its reference points to.
    stripe: ItemId,
    /// Another item of the project.
    other: ItemId,
}

/// `inject` allowed in the project, written explicitly, and the protection
/// of production and Stripe for `inject` and `reveal`.
fn protected_policy(production: ItemId, stripe: ItemId) -> Policy {
    Policy {
        rules: vec![
            Rule::new(Permission::Inject, Effect::Allow),
            Rule {
                once: true,
                scope: klav_core::policy::Scope {
                    items: vec![production],
                    ..Default::default()
                },
                ..Rule::new(Permission::Inject, Effect::Ask)
            },
            Rule::protected(Permission::Inject, vec![stripe]),
            Rule::protected(Permission::Reveal, vec![stripe]),
        ],
        expires_at: None,
    }
}

async fn world() -> World {
    let server = TestServer::start().await;
    let ana = server
        .login(&server.signup("ana@example.com", "pw").await, "laptop")
        .await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let mut ids = Vec::new();
    for title in ["production", "Stripe", "GitHub"] {
        let item = login_item(title, "ana", "s3cret");
        server.create_item(&ana, &vault, &project, &item).await;
        ids.push(item.id());
    }
    let agent = TestAgent::new();
    server
        .register_agent_ok(&agent, "ana@example.com", "bot")
        .await;
    let w = World {
        server,
        ana,
        vault,
        project,
        agent,
        production: ids[0],
        stripe: ids[1],
        other: ids[2],
    };
    let grant = w.grant(1, protected_policy(w.production, w.stripe), Vec::new());
    assert_eq!(w.post(&grant).await, StatusCode::OK);
    w
}

impl World {
    fn grant(
        &self,
        version: u64,
        policy: Policy,
        released: Vec<ItemId>,
    ) -> klav_proto::agent::SignedGrant {
        let built = TestServer::build_grant(
            &self.ana,
            &self.agent,
            version,
            policy,
            &[(&self.vault, &self.project)],
        );
        let mut payload: GrantPayload =
            serde_json::from_slice(built.payload.as_bytes()).expect("payload");
        payload.released = released;
        TestServer::sign_payload(&self.ana, &self.agent, &payload)
    }

    async fn post(&self, grant: &klav_proto::agent::SignedGrant) -> StatusCode {
        self.server
            .post_grant(&self.ana, &self.agent, grant)
            .await
            .status()
    }

    async fn access(&self, item: ItemId, permission: &str, extra: Value) -> reqwest::Response {
        let mut body =
            json!({"item_id": item, "permission": permission, "reason": "deploy to production"});
        if let Value::Object(extra) = extra {
            body.as_object_mut().expect("object").extend(extra);
        }
        self.server
            .agent_call(&self.agent, Method::POST, "/v1/agent/access", Some(&body))
            .await
    }

    async fn pending(&self, res: reqwest::Response) -> ApprovalId {
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let p: PendingApproval = res.json().await.expect("pending");
        p.pending_approval_id
    }

    async fn approval(&self, id: ApprovalId) -> ApprovalInfo {
        self.server
            .get_auth(&self.ana, &format!("/v1/approvals/{id}"))
            .send()
            .await
            .expect("request")
            .json()
            .await
            .expect("approval")
    }
}

#[tokio::test]
async fn grants_keep_once_with_ask_and_inherited_rules_with_proof() {
    let w = world().await;
    // `once` with `allow` (or `deny`) is refused with `400`.
    let mut bad = protected_policy(w.production, w.stripe);
    bad.rules.push(Rule {
        once: true,
        ..Rule::new(Permission::Reveal, Effect::Deny)
    });
    assert_eq!(
        w.post(&w.grant(2, bad, Vec::new())).await,
        StatusCode::BAD_REQUEST
    );
    // A malformed inherited rule too.
    let mut bad = protected_policy(w.production, w.stripe);
    bad.rules
        .push(Rule::protected(Permission::List, vec![w.other]));
    assert_eq!(
        w.post(&w.grant(2, bad, Vec::new())).await,
        StatusCode::BAD_REQUEST
    );
    // Dropping Stripe's inherited rules without `released`: `409`.
    let mut dropped = protected_policy(w.production, w.stripe);
    dropped.rules.retain(|r| !r.is_protected());
    assert_eq!(
        w.post(&w.grant(2, dropped.clone(), Vec::new())).await,
        StatusCode::CONFLICT
    );
    // Dropping only one of the two permissions is a loss too.
    let mut half = protected_policy(w.production, w.stripe);
    half.rules
        .retain(|r| !(r.is_protected() && r.permission == Permission::Reveal));
    assert_eq!(
        w.post(&w.grant(2, half, Vec::new())).await,
        StatusCode::CONFLICT
    );
    // Released and still protected at once: `400`.
    assert_eq!(
        w.post(&w.grant(2, protected_policy(w.production, w.stripe), vec![w.stripe]))
            .await,
        StatusCode::BAD_REQUEST
    );
    // Keeping them is fine, and so is dropping them with proof.
    assert_eq!(
        w.post(&w.grant(2, protected_policy(w.production, w.stripe), Vec::new()))
            .await,
        StatusCode::OK
    );
    assert_eq!(
        w.post(&w.grant(3, dropped, vec![w.stripe])).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_target_that_always_asks_gets_no_lease_and_one_use() {
    let w = world().await;
    // Stripe: `inject` on a protected item asks, even though the project
    // allows `inject`. Another item does not.
    assert_eq!(
        w.access(w.other, "inject", json!({})).await.status(),
        StatusCode::OK
    );
    let id = w
        .pending(w.access(w.stripe, "inject", json!({})).await)
        .await;
    // «Approve 15 min» is refused; once is fine.
    assert_eq!(
        w.server
            .decide(&w.ana, id, true, 15 * 60_000)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        w.server.decide(&w.ana, id, true, 0).await.status(),
        StatusCode::OK
    );
    let res = w
        .access(w.stripe, "inject", json!({"approval_id": id}))
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    // Spent: a second use asks again.
    assert_eq!(
        w.access(w.stripe, "inject", json!({"approval_id": id}))
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        w.access(w.stripe, "inject", json!({})).await.status(),
        StatusCode::ACCEPTED
    );
}

#[tokio::test]
async fn one_approval_covers_an_environment_and_its_protected_items() {
    let w = world().await;
    // Items only with `inject`, never the item itself, never twice.
    for extra in [
        json!({"items": [w.stripe, w.stripe]}),
        json!({"items": [w.production]}),
    ] {
        assert_eq!(
            w.access(w.production, "inject", extra).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        w.access(w.production, "reveal", json!({"items": [w.stripe]}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    // An item outside the grant is not found.
    assert_eq!(
        w.access(
            w.production,
            "inject",
            json!({"items": [ItemId::generate()]})
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    let bundle = json!({"items": [w.stripe]});
    let id = w
        .pending(w.access(w.production, "inject", bundle.clone()).await)
        .await;
    // The signed request lists the items.
    let info = w.approval(id).await;
    let request: ApprovalRequest =
        serde_json::from_slice(info.request.as_bytes()).expect("request");
    assert_eq!(request.items, vec![w.stripe]);
    assert_eq!(request.item_id, Some(w.production));
    // No lease for it.
    assert_eq!(
        w.server.decide(&w.ana, id, true, 60_000).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        w.server.decide(&w.ana, id, true, 0).await.status(),
        StatusCode::OK
    );
    // The environment, then Stripe, each once with the same approval.
    let mut with_id = bundle.clone();
    with_id["approval_id"] = json!(id);
    assert_eq!(
        w.access(w.production, "inject", with_id.clone())
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        w.access(w.stripe, "inject", json!({"approval_id": id}))
            .await
            .status(),
        StatusCode::OK
    );
    // Both spent: neither serves again, and it never served another item
    // or another permission.
    assert_eq!(
        w.access(w.stripe, "inject", json!({"approval_id": id}))
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        w.access(w.production, "inject", with_id).await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        w.access(w.stripe, "reveal", json!({"approval_id": id}))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let spent = w.approval(id).await;
    assert!(spent.used_at.is_some(), "spent once every item was used");
}
