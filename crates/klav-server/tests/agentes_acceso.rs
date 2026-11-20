//! What an approved agent can do: the server enforces the signed policy on
//! every agent endpoint, `ask` becomes an approval the person signs, and
//! approvals are spent once or leased for a while.

mod common;

use common::agent::{TestAgent, escaped, now_ms};
use common::client::Session;
use common::vault::{TestProject, TestVault, login_item};
use common::{TestServer, until_dropped};
use klav_core::ids::{ApprovalId, VaultId};
use klav_core::model::reference::Selector;
use klav_core::policy::{DomainPattern, Effect, Permission, Policy, Rule, Scope, TimeWindow};
use klav_proto::agent::{AgentItems, ApprovalInfo, ApprovalList, ApprovalStatus, PendingApproval};
use klav_proto::audit::AuditEvent;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

struct World {
    server: TestServer,
    ana: Session,
    vault: TestVault,
    project: TestProject,
    other: TestProject,
    agent: TestAgent,
    item: klav_core::ids::ItemId,
    hidden: klav_core::ids::ItemId,
}

async fn world(policy: Policy) -> World {
    let server = TestServer::start().await;
    let ana = server
        .login(&server.signup("ana@example.com", "pw").await, "laptop")
        .await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let other = server.create_project(&ana, &vault).await;
    let item = login_item("GitHub", "ana", "hunter2");
    server.create_item(&ana, &vault, &project, &item).await;
    let hidden = login_item("Bank", "ana", "s3cret");
    server.create_item(&ana, &vault, &other, &hidden).await;
    let agent = TestAgent::new();
    server
        .register_agent_ok(&agent, "ana@example.com", "bot")
        .await;
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
        other,
        agent,
        item: item.id(),
        hidden: hidden.id(),
    }
}

impl World {
    async fn access(
        &self,
        item: klav_core::ids::ItemId,
        permission: &str,
        extra: Value,
    ) -> reqwest::Response {
        let mut body = json!({"item_id": item, "permission": permission, "reason": "log in to run the deploy"});
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
}

fn rule(permission: Permission, effect: Effect, scope: Scope) -> Rule {
    Rule {
        scope,
        ..Rule::new(permission, effect)
    }
}

#[tokio::test]
async fn the_server_enforces_the_policy() {
    let w = world(Policy {
        rules: vec![rule(
            Permission::Fill,
            Effect::Allow,
            Scope {
                domains: vec![DomainPattern::parse("*.example.com").expect("pattern")],
                ..Scope::default()
            },
        )],
        expires_at: None,
    })
    .await;

    // Only the granted project is listed, without details.
    let items: AgentItems = w
        .server
        .agent_call(&w.agent, Method::GET, "/v1/agent/items", None)
        .await
        .json()
        .await
        .expect("items");
    assert_eq!(items.grant_version, 1);
    assert_eq!(items.projects.len(), 1);
    assert_eq!(items.projects[0].project_id, w.project.id);
    assert_eq!(items.projects[0].items.len(), 1);
    assert!(items.projects[0].items[0].details.is_none());

    // fill: only on the allowed domain.
    let res = w
        .access(w.item, "fill", json!({"claims": {"domain": "github.com"}}))
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = w
        .access(
            w.item,
            "fill",
            json!({"claims": {"domain": "login.example.com"}}),
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let granted: klav_proto::agent::AccessGranted = res.json().await.expect("item");
    let opened = common::vault::decrypt(&w.vault, &w.project, &granted.item);
    assert_eq!(common::vault::field(&opened, "password"), "hunter2");

    // list gives the metadata, never the details.
    let res = w.access(w.item, "list", json!({})).await;
    assert_eq!(res.status(), StatusCode::OK);
    let listed: klav_proto::agent::AccessGranted = res.json().await.expect("item");
    assert!(listed.item.details.is_none());
    assert!(listed.item.overview.is_some());

    // reveal is denied by default; other projects do not exist for it.
    assert_eq!(
        w.access(w.item, "reveal", json!({})).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        w.access(w.hidden, "inject", json!({})).await.status(),
        StatusCode::NOT_FOUND
    );
    // A reason is mandatory.
    let res = w
        .server
        .agent_call(
            &w.agent,
            Method::POST,
            "/v1/agent/access",
            Some(&json!({"item_id": w.item, "permission": "inject", "reason": "  "})),
        )
        .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // Writes do not go through access; `update` may read (ask by default).
    assert_eq!(
        w.access(w.item, "create", json!({})).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        w.access(w.item, "update", json!({})).await.status(),
        StatusCode::ACCEPTED
    );
    // Attachments only come with inject (ADR 0016).
    assert_eq!(
        w.access(
            w.item,
            "fill",
            json!({"claims": {"domain": "login.example.com"}, "include_attachments": true}),
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let _ = &w.other;
}

#[tokio::test]
async fn ask_waits_for_a_signed_decision() {
    let w = world(Policy::default()).await;

    // totp is `ask` by default.
    let id = w.pending(w.access(w.item, "totp", json!({})).await).await;
    let status: ApprovalInfo = w
        .server
        .agent_call(
            &w.agent,
            Method::GET,
            &format!("/v1/agent/approvals/{id}"),
            None,
        )
        .await
        .json()
        .await
        .expect("approval");
    assert_eq!(status.status, ApprovalStatus::Pending);
    assert_eq!(
        w.access(w.item, "totp", json!({"approval_id": id}))
            .await
            .status(),
        StatusCode::CONFLICT
    );

    // The person sees it, with the agent's reason.
    let list: ApprovalList = w
        .server
        .get_auth(&w.ana, "/v1/approvals")
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("list");
    let shown: klav_proto::agent::ApprovalRequest =
        serde_json::from_slice(list.approvals[0].request.as_bytes()).expect("request");
    assert_eq!(shown.reason, "log in to run the deploy");
    assert_eq!(shown.agent_name, "bot");

    // A decision signed by someone else is refused.
    let mallory = w
        .server
        .login(
            &w.server.signup("mallory@example.com", "pw").await,
            "laptop",
        )
        .await;
    assert_eq!(
        w.server.decide(&mallory, id, true, 0).await.status(),
        StatusCode::NOT_FOUND
    );

    // Approved once: works once.
    assert_eq!(
        w.server.decide(&w.ana, id, true, 0).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        w.server.decide(&w.ana, id, true, 0).await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        w.access(w.item, "totp", json!({"approval_id": id}))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        w.access(w.item, "totp", json!({"approval_id": id}))
            .await
            .status(),
        StatusCode::CONFLICT
    );

    // Approved for 15 minutes: no more questions meanwhile.
    let id = w.pending(w.access(w.item, "totp", json!({})).await).await;
    assert_eq!(
        w.server
            .decide(&w.ana, id, true, 15 * 60_000)
            .await
            .status(),
        StatusCode::OK
    );
    for _ in 0..2 {
        assert_eq!(
            w.access(w.item, "totp", json!({})).await.status(),
            StatusCode::OK
        );
    }

    // Denied.
    let w2 = world(Policy::default()).await;
    let id = w2
        .pending(w2.access(w2.item, "totp", json!({})).await)
        .await;
    assert_eq!(
        w2.server.decide(&w2.ana, id, false, 0).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        w2.access(w2.item, "totp", json!({"approval_id": id}))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    // A lease on a denial makes no sense.
    let id = w2
        .pending(w2.access(w2.item, "totp", json!({})).await)
        .await;
    assert_eq!(
        w2.server.decide(&w2.ana, id, false, 60_000).await.status(),
        StatusCode::BAD_REQUEST
    );

    // A new grant voids the pending request.
    let grant = TestServer::build_grant(
        &w2.ana,
        &w2.agent,
        2,
        Policy::default(),
        &[(&w2.vault, &w2.project)],
    );
    assert_eq!(
        w2.server
            .post_grant(&w2.ana, &w2.agent, &grant)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        w2.server.decide(&w2.ana, id, true, 0).await.status(),
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn hours_and_listing_limits() {
    // reveal allowed only in a one-minute window two hours from now.
    let later = now_ms() / 1000 + 2 * 3600;
    let minute = u16::try_from((later % 86_400) / 60).expect("minute");
    let window: TimeWindow = format!(
        "daily {:02}:{:02}-{:02}:{:02} Z",
        minute / 60,
        minute % 60,
        ((minute + 1) % 1440) / 60,
        ((minute + 1) % 1440) % 60
    )
    .parse()
    .expect("window");
    let w = world(Policy {
        rules: vec![rule(
            Permission::Reveal,
            Effect::Allow,
            Scope {
                hours: vec![window],
                ..Scope::default()
            },
        )],
        expires_at: None,
    })
    .await;
    assert_eq!(
        w.access(w.item, "reveal", json!({})).await.status(),
        StatusCode::FORBIDDEN
    );

    // A project whose `list` is denied is not listed.
    let w = world(Policy {
        rules: vec![rule(
            Permission::List,
            Effect::Deny,
            Scope {
                projects: vec![Selector::Id(klav_core::ids::ProjectId::generate())],
                ..Scope::default()
            },
        )],
        expires_at: None,
    })
    .await;
    let items: AgentItems = w
        .server
        .agent_call(&w.agent, Method::GET, "/v1/agent/items", None)
        .await
        .json()
        .await
        .expect("items");
    // The only `list` rule is out of scope here: deny (ADR 0006).
    assert!(items.projects.is_empty());
}

/// An agent step the person's log verifier would refuse is never logged:
/// a signed path with a query string (a bare `?` too) or an escaped ID is
/// refused with `400`, and a request signed at the edge of the clock window
/// whose body arrives past it with `401`, as a stale one. An approve-once
/// the step would have spent is not spent, and the log keeps only what
/// verifies.
#[tokio::test]
async fn an_agent_step_the_log_would_refuse_is_never_logged() {
    let w = world(Policy {
        rules: vec![rule(Permission::Update, Effect::Allow, Scope::default())],
        expires_at: None,
    })
    .await;
    let server = &w.server;
    let mut wrong = Vec::new();
    let bad = StatusCode::BAD_REQUEST;
    let agent = &w.agent;
    let call = |method: Method, path: String, body: Value| async move {
        server.agent_call(agent, method, &path, Some(&body)).await
    };

    // agent.access, and a late one.
    let access = json!({"item_id": w.item, "permission": "reveal", "reason": "r"});
    for q in ["?x=1", "?"] {
        server
            .refused_unlogged(
                &w.ana,
                &format!("agent.access with `{q}`"),
                bad,
                call(Method::POST, format!("/v1/agent/access{q}"), access.clone()),
                &mut wrong,
            )
            .await;
    }
    server
        .refused_unlogged(
            &w.ana,
            "agent.access, its body past the clock window",
            StatusCode::UNAUTHORIZED,
            server.agent_call_late(
                &w.agent,
                Method::POST,
                "/v1/agent/access",
                &access,
                std::time::Duration::from_millis(1500),
            ),
            &mut wrong,
        )
        .await;

    // item.created.
    let key = klav_core::crypto::keys::ItemKey::generate();
    let new = login_item("Staging DB", "svc", "pw-1");
    let upload = common::vault::seal(&w.vault, &w.project, &new, &key, 1);
    let create = json!({
        "vault_id": w.vault.id,
        "reason": "store the staging credentials",
        "item": {
            "id": new.id(), "project_id": w.project.id, "version": 1,
            "wrapped_key": klav_proto::Blob::new(upload.wrapped_key),
            "project_version": 1,
            "overview": klav_proto::Blob::new(upload.sealed.overview),
            "details": klav_proto::Blob::new(upload.sealed.details),
        },
    });
    server
        .refused_unlogged(
            &w.ana,
            "item.created with a query",
            bad,
            call(Method::POST, "/v1/agent/items?x=1".into(), create.clone()),
            &mut wrong,
        )
        .await;
    TestServer::expect_status(
        &mut wrong,
        "the honest item.created",
        call(Method::POST, "/v1/agent/items".into(), create)
            .await
            .status(),
        StatusCode::CREATED,
    );

    // item.updated and item.trashed, with a query and with an escaped ID.
    let upload = common::vault::seal(&w.vault, &w.project, &new, &key, 2);
    let update = json!({
        "reason": "rotate the password",
        "item": {
            "version": 2,
            "wrapped_key": klav_proto::Blob::new(upload.wrapped_key),
            "project_version": 1,
            "overview": klav_proto::Blob::new(upload.sealed.overview),
            "details": klav_proto::Blob::new(upload.sealed.details),
        },
    });
    let trash = json!({"reason": "cleanup"});
    for (what, id) in [
        ("query", new.id().to_string()),
        ("escaped ID", escaped(new.id())),
    ] {
        let q = if what == "query" { "?x=1" } else { "" };
        server
            .refused_unlogged(
                &w.ana,
                &format!("item.updated with a {what}"),
                bad,
                call(
                    Method::PUT,
                    format!("/v1/agent/items/{id}{q}"),
                    update.clone(),
                ),
                &mut wrong,
            )
            .await;
        server
            .refused_unlogged(
                &w.ana,
                &format!("item.trashed with a {what}"),
                bad,
                call(
                    Method::POST,
                    format!("/v1/agent/items/{id}/trash{q}"),
                    trash.clone(),
                ),
                &mut wrong,
            )
            .await;
    }

    // agent.asked.
    let ask = json!({
        "permission": "delete", "vault_id": w.vault.id, "project_id": w.project.id,
        "item_id": w.item, "reason": "r",
    });
    server
        .refused_unlogged(
            &w.ana,
            "agent.asked with a query",
            bad,
            call(Method::POST, "/v1/agent/approvals?x=1".into(), ask),
            &mut wrong,
        )
        .await;

    // An approve-once the refused step would have spent is still there.
    let id = w.pending(w.access(w.item, "totp", json!({})).await).await;
    assert_eq!(
        w.server.decide(&w.ana, id, true, 0).await.status(),
        StatusCode::OK
    );
    server
        .refused_unlogged(
            &w.ana,
            "agent.access spending an approval, with a query",
            bad,
            call(
                Method::POST,
                "/v1/agent/access?x=1".into(),
                json!({"item_id": w.item, "permission": "totp", "reason": "r", "approval_id": id}),
            ),
            &mut wrong,
        )
        .await;
    TestServer::expect_status(
        &mut wrong,
        "the honest agent.access spending the approval",
        w.access(w.item, "totp", json!({"approval_id": id}))
            .await
            .status(),
        StatusCode::OK,
    );

    // The honest steps still pass, and the log verifies.
    TestServer::expect_status(
        &mut wrong,
        "the honest item.updated",
        call(Method::PUT, format!("/v1/agent/items/{}", new.id()), update)
            .await
            .status(),
        StatusCode::OK,
    );
    wrong.extend(server.proofs_the_log_refuses(&w.ana).await);
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// An agent step that passes the extractor's checks but whose signature
/// has left the clock window by the time it is logged is refused with
/// `401` (as a stale request) and leaves nothing behind: an ask stores no
/// approval request, and an approve-once it spent serves again. The
/// account's lock holds it between the two (`agent_call_held`).
#[tokio::test]
async fn an_agent_step_logged_too_late_leaves_nothing_behind() {
    let w = world(Policy::default()).await;
    let server = &w.server;
    let approvals = || async {
        server
            .get_auth(&w.ana, "/v1/approvals")
            .send()
            .await
            .expect("request")
            .json::<ApprovalList>()
            .await
            .expect("list")
            .approvals
    };
    // totp asks by default: a new approval request, refused as it is logged.
    let totp = json!({"item_id": w.item, "permission": "totp", "reason": "2fa"});
    let before = server.chain_of(&w.ana).await.len();
    let res = server
        .agent_call_held(&w.ana, &w.agent, Method::POST, "/v1/agent/access", &totp)
        .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(server.chain_of(&w.ana).await.len(), before);
    assert!(approvals().await.is_empty(), "a refused ask left a request");

    // An approve-once, spent by a step refused as it is logged, serves again.
    let id = w.pending(w.access(w.item, "totp", json!({})).await).await;
    assert_eq!(
        server.decide(&w.ana, id, true, 0).await.status(),
        StatusCode::OK
    );
    let mut spend = totp.clone();
    spend["approval_id"] = json!(id);
    let before = server.chain_of(&w.ana).await.len();
    let res = server
        .agent_call_held(&w.ana, &w.agent, Method::POST, "/v1/agent/access", &spend)
        .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(server.chain_of(&w.ana).await.len(), before);
    assert_eq!(
        w.access(w.item, "totp", json!({"approval_id": id}))
            .await
            .status(),
        StatusCode::OK,
        "the approve-once was not given back"
    );
    let wrong = server.proofs_the_log_refuses(&w.ana).await;
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[tokio::test]
async fn agents_write_within_the_policy() {
    let w = world(Policy {
        rules: vec![rule(Permission::Update, Effect::Allow, Scope::default())],
        expires_at: None,
    })
    .await;
    let key = klav_core::crypto::keys::ItemKey::generate();

    // create: allowed by default.
    let new = login_item("Staging DB", "svc", "pw-1");
    let upload = common::vault::seal(&w.vault, &w.project, &new, &key, 1);
    let res = w
        .server
        .agent_call(
            &w.agent,
            Method::POST,
            "/v1/agent/items",
            Some(&json!({
                "vault_id": w.vault.id,
                "reason": "store the staging credentials",
                "item": {
                    "id": new.id(), "project_id": w.project.id, "version": 1,
                    "wrapped_key": klav_proto::Blob::new(upload.wrapped_key),
                    "project_version": 1,
                    "overview": klav_proto::Blob::new(upload.sealed.overview),
                    "details": klav_proto::Blob::new(upload.sealed.details),
                },
            })),
        )
        .await;
    assert_eq!(res.status(), StatusCode::CREATED);

    // create in a project outside the grant: not found.
    let elsewhere = login_item("Nope", "x", "y");
    let upload = common::vault::seal(&w.vault, &w.other, &elsewhere, &key, 1);
    let res = w
        .server
        .agent_call(
            &w.agent,
            Method::POST,
            "/v1/agent/items",
            Some(&json!({
                "vault_id": w.vault.id,
                "reason": "x",
                "item": {
                    "id": elsewhere.id(), "project_id": w.other.id, "version": 1,
                    "wrapped_key": klav_proto::Blob::new(upload.wrapped_key),
                    "project_version": 1,
                    "overview": klav_proto::Blob::new(upload.sealed.overview),
                    "details": klav_proto::Blob::new(upload.sealed.details),
                },
            })),
        )
        .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // update: allowed by the rule; stale versions still conflict.
    let upload = common::vault::seal(&w.vault, &w.project, &new, &key, 2);
    let body = json!({
        "reason": "rotate the password",
        "item": {
            "version": 2,
            "wrapped_key": klav_proto::Blob::new(upload.wrapped_key),
                    "project_version": 1,
            "overview": klav_proto::Blob::new(upload.sealed.overview),
            "details": klav_proto::Blob::new(upload.sealed.details),
        },
    });
    let path = format!("/v1/agent/items/{}", new.id());
    assert_eq!(
        w.server
            .agent_call(&w.agent, Method::PUT, &path, Some(&body))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        w.server
            .agent_call(&w.agent, Method::PUT, &path, Some(&body))
            .await
            .status(),
        StatusCode::CONFLICT
    );

    // The project key changes (any new project version): a write whose item
    // key was wrapped for the old version is refused, for agents and for
    // people, until it is wrapped again for the current one.
    bump_project_version(&w).await;
    let items: AgentItems = w
        .server
        .agent_call(&w.agent, Method::GET, "/v1/agent/items", None)
        .await
        .json()
        .await
        .expect("items");
    assert_eq!(items.projects[0].project_version, 2);
    let upload = common::vault::seal(&w.vault, &w.project, &new, &key, 3);
    let mut body = json!({
        "reason": "rotate the password",
        "item": {
            "version": 3,
            "wrapped_key": klav_proto::Blob::new(upload.wrapped_key),
            "project_version": 1,
            "overview": klav_proto::Blob::new(upload.sealed.overview),
            "details": klav_proto::Blob::new(upload.sealed.details),
        },
    });
    let res = w
        .server
        .agent_call(&w.agent, Method::PUT, &path, Some(&body))
        .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
    let error: klav_proto::ErrorBody = res.json().await.expect("error");
    assert!(
        error.message.contains("project_version"),
        "{}",
        error.message
    );
    assert_eq!(error.current_version, None);
    body["item"]["project_version"] = json!(2);
    assert_eq!(
        w.server
            .agent_call(&w.agent, Method::PUT, &path, Some(&body))
            .await
            .status(),
        StatusCode::OK
    );
    let fresh = login_item("Prod DB", "svc", "pw-2");
    let upload = common::vault::seal(&w.vault, &w.project, &fresh, &key, 1);
    let create = |project_version: u64| klav_proto::vault::CreateItem {
        id: fresh.id(),
        project_id: w.project.id,
        version: 1,
        wrapped_key: klav_proto::Blob::new(upload.wrapped_key.clone()),
        project_version,
        overview: klav_proto::Blob::new(upload.sealed.overview.clone()),
        details: klav_proto::Blob::new(upload.sealed.details.clone()),
    };
    let post = |body: klav_proto::vault::CreateItem| {
        w.server
            .post_auth(&w.ana, &format!("/v1/vaults/{}/items", w.vault.id))
            .json(&body)
            .send()
    };
    assert_eq!(
        post(create(1)).await.expect("post").status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        post(create(2)).await.expect("post").status(),
        StatusCode::CREATED
    );

    // delete: denied by default.
    let trash = format!("/v1/agent/items/{}/trash", new.id());
    let res = w
        .server
        .agent_call(
            &w.agent,
            Method::POST,
            &trash,
            Some(&json!({"reason": "cleanup"})),
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // A pending agent can only ask about itself.
    let pending = TestAgent::new();
    w.server
        .register_agent_ok(&pending, "ana@example.com", "pending")
        .await;
    assert_eq!(
        w.server
            .agent_call(&pending, Method::GET, "/v1/agent/items", None)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
}

/// An access is logged with the body the agent signed (ADR 0030 §4.2), so
/// a body larger than the log keeps is refused, and nothing is logged.
#[tokio::test]
async fn an_access_too_large_to_log_is_refused() {
    use klav_proto::audit::AuditPage;

    let w = world(Policy::default()).await;
    let count = || async {
        let page: AuditPage = w
            .server
            .get_auth(&w.ana, "/v1/audit?after=0")
            .send()
            .await
            .expect("request")
            .json()
            .await
            .expect("page");
        page.entries.len()
    };
    let before = count().await;
    let tags: Vec<String> = (0..20)
        .map(|i| format!("{i}{}", "x".repeat(1000)))
        .collect();
    let res = w
        .access(w.item, "fill", json!({"claims": {"tags": tags}}))
        .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(count().await, before);
    assert_eq!(
        w.access(w.item, "fill", json!({})).await.status(),
        StatusCode::OK
    );
    assert_eq!(count().await, before + 1);
}

#[tokio::test]
async fn every_decision_is_chained_in_the_audit_log() {
    use klav_core::crypto::audit::{GENESIS, chain_hash, sign_head};
    use klav_proto::audit::{AuditEvent, AuditHeads, AuditPage, SignHead};

    let w = world(Policy::default()).await;
    assert_eq!(
        w.access(w.item, "fill", json!({})).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        w.access(w.item, "reveal", json!({})).await.status(),
        StatusCode::FORBIDDEN
    );
    let id = w.pending(w.access(w.item, "totp", json!({})).await).await;
    assert_eq!(
        w.server.decide(&w.ana, id, true, 0).await.status(),
        StatusCode::OK
    );

    let page: AuditPage = w
        .server
        .get_auth(&w.ana, "/v1/audit?after=0")
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("page");
    let mut previous = GENESIS;
    let mut events = Vec::new();
    for (i, entry) in page.entries.iter().enumerate() {
        assert_eq!(entry.seq, i as u64 + 1);
        let hash = chain_hash(entry.seq, &previous, entry.event.as_bytes());
        assert_eq!(entry.hash.as_bytes(), &hash[..]);
        previous = hash;
        events.push(serde_json::from_slice::<AuditEvent>(entry.event.as_bytes()).expect("event"));
    }
    assert_eq!(page.head_seq, page.entries.len() as u64);
    let actions: Vec<(&str, Option<&str>)> = events
        .iter()
        .map(|e| (e.action.as_str(), e.outcome.as_deref()))
        .collect();
    // Person CRUD (server-attested), registration, grant, then the agent.
    assert!(actions.contains(&("item.created", None)));
    assert!(actions.contains(&("agent.registered", None)));
    let tail: Vec<_> = actions.iter().rev().take(4).rev().copied().collect();
    assert_eq!(
        tail,
        [
            ("agent.access", Some("allow")),
            ("agent.access", Some("deny")),
            ("agent.access", Some("ask")),
            ("approval.decided", Some("approve")),
        ]
    );
    let fill = &events[events.len() - 4];
    assert_eq!(fill.reason.as_deref(), Some("log in to run the deploy"));
    assert_eq!(fill.alerts, ["first_use"]);
    assert!(fill.agent_proof.as_ref().is_some_and(|p| p.body.is_some()));
    assert_eq!(events[events.len() - 3].alerts, ["denied"]);
    let decided = events.last().expect("decision");
    assert!(decided.account_signature.is_some() && decided.signed.is_some());
    // The person's events cannot be read by others.
    let mallory = w
        .server
        .login(
            &w.server.signup("mallory@example.com", "pw").await,
            "laptop",
        )
        .await;
    let theirs: AuditPage = w
        .server
        .get_auth(&mallory, "/v1/audit")
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("page");
    assert!(theirs.entries.iter().all(|e| {
        serde_json::from_slice::<AuditEvent>(e.event.as_bytes()).is_ok_and(|e| e.agent_id.is_none())
    }));

    // Heads: only the account's signature over the stored hash is kept.
    let seq = page.head_seq;
    let head = |identity: &klav_core::crypto::identity::IdentityKeyPair, hash: [u8; 32]| SignHead {
        seq,
        hash: klav_proto::Blob::new(hash.to_vec()),
        signature: klav_proto::Blob::new(
            sign_head(identity, w.ana.account_id, seq, &hash)
                .to_bytes()
                .to_vec(),
        ),
    };
    let post = |body: SignHead| {
        w.server
            .post_auth(&w.ana, "/v1/audit/heads")
            .json(&body)
            .send()
    };
    assert_eq!(
        post(head(&w.ana.identity, [7; 32]))
            .await
            .expect("post")
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        post(head(&mallory.identity, previous))
            .await
            .expect("post")
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(head(&w.ana.identity, previous))
            .await
            .expect("post")
            .status(),
        StatusCode::NO_CONTENT
    );
    let heads: AuditHeads = w
        .server
        .get_auth(&w.ana, "/v1/audit/heads")
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("heads");
    assert_eq!(heads.heads.len(), 1);
    assert_eq!(heads.heads[0].device_id, w.ana.device_id);
}

#[tokio::test]
async fn revocation_is_signed_and_immediate() {
    use klav_core::crypto::agent::sign_revocation;
    use klav_proto::agent::RevokeAgent;

    let w = world(Policy::default()).await;
    let pending = w.pending(w.access(w.item, "totp", json!({})).await).await;
    let revoke = |identity: &klav_core::crypto::identity::IdentityKeyPair, at: i64| RevokeAgent {
        revoked_at: at,
        signature: klav_proto::Blob::new(
            sign_revocation(
                identity,
                w.ana.account_id,
                w.agent.id,
                u64::try_from(at).expect("time"),
            )
            .to_bytes()
            .to_vec(),
        ),
    };
    let path = format!("/v1/agents/{}/revoke", w.agent.id);
    let post = |body: RevokeAgent| w.server.post_auth(&w.ana, &path).json(&body).send();
    // Signed by someone else, or too old: refused.
    let mallory = klav_core::crypto::identity::IdentityKeyPair::generate();
    assert_eq!(
        post(revoke(&mallory, now_ms()))
            .await
            .expect("post")
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(revoke(&w.ana.identity, now_ms() - 3_600_000))
            .await
            .expect("post")
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        w.access(w.item, "inject", json!({})).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        post(revoke(&w.ana.identity, now_ms()))
            .await
            .expect("post")
            .status(),
        StatusCode::OK
    );
    // The very next request is refused, and its pending request denied.
    assert_eq!(
        w.access(w.item, "inject", json!({})).await.status(),
        StatusCode::FORBIDDEN
    );
    let info: ApprovalInfo = w
        .server
        .get_auth(&w.ana, &format!("/v1/approvals/{pending}"))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("approval");
    assert_eq!(info.status, ApprovalStatus::Denied);
    assert_eq!(
        post(revoke(&w.ana.identity, now_ms()))
            .await
            .expect("post")
            .status(),
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn rotating_a_project_key_rewraps_every_item_key() {
    use klav_core::crypto::keys::ProjectKey;
    use klav_core::crypto::wrap::{unwrap_item_key, wrap_item_key, wrap_project_key};
    use klav_core::model::{Meta, seal_project_meta};
    use klav_proto::vault::{ProjectKeys, RotateProject};

    let w = world(Policy::default()).await;
    // An item with a second version, so the history is rotated too.
    let edited = login_item("AWS", "ana", "v1");
    let (key, _) = w
        .server
        .create_item(&w.ana, &w.vault, &w.project, &edited)
        .await;
    assert_eq!(
        w.server
            .put_item(&w.ana, &w.vault, &w.project, &edited, &key, 2)
            .await
            .status(),
        StatusCode::OK
    );
    let base = format!("/v1/vaults/{}/projects/{}", w.vault.id, w.project.id);
    let keys: ProjectKeys = w
        .server
        .get_auth(&w.ana, &format!("{base}/keys"))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("keys");
    assert_eq!(keys.keys.len(), 3);
    assert_eq!(keys.keys.iter().filter(|k| k.version.is_some()).count(), 1);
    let new_key = ProjectKey::generate();
    let pctx = w.vault.project_ctx(w.project.id);
    let rewrap = |keys: &ProjectKeys| -> Vec<klav_proto::vault::WrappedItemKey> {
        keys.keys
            .iter()
            .map(|k| {
                let ictx = w.vault.item_ctx(w.project.id, k.item_id);
                let item_key = unwrap_item_key(&w.project.key, &ictx, k.wrapped_key.as_bytes())
                    .expect("unwrap");
                klav_proto::vault::WrappedItemKey {
                    item_id: k.item_id,
                    version: k.version,
                    wrapped_key: klav_proto::Blob::new(wrap_item_key(&new_key, &ictx, &item_key)),
                }
            })
            .collect()
    };
    let body = |version: u64, keys: Vec<klav_proto::vault::WrappedItemKey>| RotateProject {
        version,
        wrapped_key: klav_proto::Blob::new(wrap_project_key(&w.vault.key, &pctx, &new_key)),
        meta: klav_proto::Blob::new(seal_project_meta(
            &new_key,
            &pctx,
            version,
            &Meta::new("General", None).expect("meta"),
        )),
        keys,
    };
    let post = |b: RotateProject| {
        w.server
            .post_auth(&w.ana, &format!("{base}/rotate"))
            .json(&b)
            .send()
    };
    // Missing keys, or a stale version: refused, nothing changes.
    assert_eq!(
        post(body(keys.version + 1, Vec::new()))
            .await
            .expect("post")
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        post(body(keys.version, rewrap(&keys)))
            .await
            .expect("post")
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        post(body(keys.version + 1, rewrap(&keys)))
            .await
            .expect("post")
            .status(),
        StatusCode::OK
    );
    // The item now opens with the new key only.
    let item: klav_proto::vault::Item = w
        .server
        .get_auth(
            &w.ana,
            &format!("/v1/vaults/{}/items/{}", w.vault.id, w.item),
        )
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("item");
    let ictx = w.vault.item_ctx(w.project.id, w.item);
    let wrapped = item.wrapped_key.expect("key");
    assert!(unwrap_item_key(&new_key, &ictx, wrapped.as_bytes()).is_ok());
    assert!(unwrap_item_key(&w.project.key, &ictx, wrapped.as_bytes()).is_err());
}

#[tokio::test]
async fn only_the_owner_rotates_and_unknown_projects_are_404() {
    let w = world(Policy::default()).await;
    let keys = |session: &Session, vault: VaultId, project: klav_core::ids::ProjectId| {
        w.server
            .get_auth(
                session,
                &format!("/v1/vaults/{vault}/projects/{project}/keys"),
            )
            .send()
    };
    // A project that does not exist and one of another vault look the same
    // (it used to be a 500 for the first one).
    let missing = klav_core::ids::ProjectId::generate();
    assert_eq!(
        keys(&w.ana, w.vault.id, missing)
            .await
            .expect("get")
            .status(),
        StatusCode::NOT_FOUND
    );
    let second = w.server.create_vault(&w.ana).await;
    let elsewhere = w.server.create_project(&w.ana, &second).await;
    assert_eq!(
        keys(&w.ana, w.vault.id, elsewhere.id)
            .await
            .expect("get")
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        keys(&w.ana, w.vault.id, w.project.id)
            .await
            .expect("get")
            .status(),
        StatusCode::OK
    );

    // A member that is not the owner (there is no sharing yet: the row is
    // written by hand) can neither read the keys nor rotate.
    let bob = w
        .server
        .login(&w.server.signup("bob@example.com", "pw").await, "laptop")
        .await;
    sqlx::query(
        "INSERT INTO vault_members (vault_id, member_type, member_id, role, shared_key, \
         revision, created_at, updated_at) VALUES ($1, 'account', $2, 'member', $3, 1, 0, 0)",
    )
    .bind(w.vault.id.to_string())
    .bind(bob.account_id.to_string())
    .bind(vec![0_u8; 8])
    .execute(&w.server.raw_db().await)
    .await
    .expect("member");
    assert_eq!(
        keys(&bob, w.vault.id, w.project.id)
            .await
            .expect("get")
            .status(),
        StatusCode::FORBIDDEN
    );
    let res = w
        .server
        .post_auth(
            &bob,
            &format!("/v1/vaults/{}/projects/{}/rotate", w.vault.id, w.project.id),
        )
        .json(&klav_proto::vault::RotateProject {
            version: 2,
            wrapped_key: klav_proto::Blob::new(Vec::new()),
            meta: klav_proto::Blob::new(Vec::new()),
            keys: Vec::new(),
        })
        .send()
        .await
        .expect("post");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

// --------------------------- the project's rotation in its own transaction --

impl World {
    /// The rotation of Ana's project to a new key, built from the keys
    /// stored now: its path and its body.
    async fn project_rotation(&self) -> (String, Value) {
        use klav_core::crypto::keys::ProjectKey;
        use klav_core::crypto::wrap::{unwrap_item_key, wrap_item_key, wrap_project_key};
        use klav_core::model::{Meta, seal_project_meta};
        use klav_proto::vault::{ProjectKeys, RotateProject, WrappedItemKey};

        let base = format!("/v1/vaults/{}/projects/{}", self.vault.id, self.project.id);
        let keys: ProjectKeys = self
            .server
            .get_auth(&self.ana, &format!("{base}/keys"))
            .send()
            .await
            .expect("request")
            .json()
            .await
            .expect("keys");
        let new_key = ProjectKey::generate();
        let pctx = self.vault.project_ctx(self.project.id);
        let rewrapped = keys
            .keys
            .iter()
            .map(|k| {
                let ictx = self.vault.item_ctx(self.project.id, k.item_id);
                let item_key = unwrap_item_key(&self.project.key, &ictx, k.wrapped_key.as_bytes())
                    .expect("unwrap");
                WrappedItemKey {
                    item_id: k.item_id,
                    version: k.version,
                    wrapped_key: klav_proto::Blob::new(wrap_item_key(&new_key, &ictx, &item_key)),
                }
            })
            .collect();
        let version = keys.version + 1;
        let body = RotateProject {
            version,
            wrapped_key: klav_proto::Blob::new(wrap_project_key(&self.vault.key, &pctx, &new_key)),
            meta: klav_proto::Blob::new(seal_project_meta(
                &new_key,
                &pctx,
                version,
                &Meta::new("General", None).expect("meta"),
            )),
            keys: rewrapped,
        };
        (
            format!("{base}/rotate"),
            serde_json::to_value(&body).expect("test"),
        )
    }

    /// The project's stored key version, read straight from the database.
    async fn project_version(&self, db: &sqlx::AnyPool) -> i64 {
        sqlx::query_scalar("SELECT version FROM projects WHERE id = $1")
            .bind(self.project.id.to_string())
            .fetch_one(db)
            .await
            .expect("test")
    }

    /// How many `project.rotated` of Ana's project are logged.
    async fn rotations_logged(&self, db: &sqlx::AnyPool) -> usize {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT event FROM audit_events WHERE account_id = $1 AND action = 'project.rotated'",
        )
        .bind(self.ana.account_id.to_string())
        .fetch_all(db)
        .await
        .expect("test");
        rows.iter()
            .map(|bytes| serde_json::from_slice::<AuditEvent>(bytes).expect("test"))
            .filter(|e| e.project_id == Some(self.project.id))
            .count()
    }

    async fn rotate_project(&self, path: &str, body: &Value) -> StatusCode {
        self.server
            .post_auth(&self.ana, path)
            .json(body)
            .send()
            .await
            .expect("request")
            .status()
    }
}

/// A project rotation whose `project.rotated` the log refuses is not made:
/// the event is appended in the rotation's own transaction, so the key
/// stays the one before, and the same rotation then succeeds.
#[tokio::test]
async fn a_project_rotation_that_cannot_be_logged_is_not_made() {
    let w = world(Policy::default()).await;
    let db = w.server.raw_db().await;
    let before = w.project_version(&db).await;
    let (path, body) = w.project_rotation().await;
    w.server.refuse_audit_action("project.rotated").await;
    let status = w.rotate_project(&path, &body).await;
    w.server.allow_audit_action("project.rotated").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(w.project_version(&db).await, before);
    assert_eq!(w.rotations_logged(&db).await, 0);
    assert_eq!(w.rotate_project(&path, &body).await, StatusCode::OK);
    assert_eq!(w.project_version(&db).await, before + 1);
    assert_eq!(w.rotations_logged(&db).await, 1);
}

/// A project rotation the database refuses to store logs no
/// `project.rotated`: the event is appended in the rotation's
/// transaction, not in one of its own before it.
#[tokio::test]
async fn a_project_rotation_that_cannot_be_stored_is_not_logged() {
    let w = world(Policy::default()).await;
    let db = w.server.raw_db().await;
    let before = w.project_version(&db).await;
    let (path, body) = w.project_rotation().await;
    w.server.refuse_writes("projects").await;
    let status = w.rotate_project(&path, &body).await;
    w.server.allow_writes("projects").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(w.project_version(&db).await, before);
    assert_eq!(w.rotations_logged(&db).await, 0);
    assert_eq!(w.rotate_project(&path, &body).await, StatusCode::OK);
    assert_eq!(w.rotations_logged(&db).await, 1);
}

/// Postgres only: a project rotation writes the project, bumps the vault
/// and appends `project.rotated` in one transaction.
#[tokio::test]
async fn a_project_rotation_and_its_event_share_one_transaction() {
    let w = world(Policy::default()).await;
    if !w.server.is_postgres() {
        return;
    }
    let db = w.server.raw_db().await;
    let (path, body) = w.project_rotation().await;
    assert_eq!(w.rotate_project(&path, &body).await, StatusCode::OK);
    let account = w.ana.account_id;
    for (table, id) in [
        ("projects", w.project.id.to_string()),
        ("vaults", w.vault.id.to_string()),
    ] {
        w.server
            .assert_written_with(&db, account, table, &id, "project.rotated")
            .await;
    }
}

/// Postgres only: a project rotation takes the account's lock before the
/// vault's, as every person's vault write that logs in its own
/// transaction does.
#[tokio::test]
async fn a_project_rotation_locks_the_account_before_the_vault() {
    let w = world(Policy::default()).await;
    if !w.server.is_postgres() {
        return;
    }
    let (path, body) = w.project_rotation().await;
    let send = w.server.post_auth(&w.ana, &path).json(&body).send();
    let res = w
        .server
        .assert_account_locked_first(
            w.ana.account_id,
            "UPDATE vaults SET revision = revision WHERE id = $1",
            w.vault.id.to_string(),
            send,
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
}

/// Writes version 2 of `w.project` (same key, new metadata), as a rename
/// or a rotation would.
async fn bump_project_version(w: &World) {
    use klav_core::crypto::wrap::wrap_project_key;
    let pctx = w.vault.project_ctx(w.project.id);
    let res = w
        .server
        .put_auth(
            &w.ana,
            &format!("/v1/vaults/{}/projects/{}", w.vault.id, w.project.id),
        )
        .json(&klav_proto::vault::UpdateProject {
            version: 2,
            wrapped_key: klav_proto::Blob::new(wrap_project_key(
                &w.vault.key,
                &pctx,
                &w.project.key,
            )),
            meta: klav_proto::Blob::new(klav_core::model::seal_project_meta(
                &w.project.key,
                &pctx,
                2,
                &klav_core::model::Meta::new("General", None).expect("meta"),
            )),
        })
        .send()
        .await
        .expect("put");
    assert_eq!(res.status(), StatusCode::OK);
}

impl World {
    async fn approval(&self, id: ApprovalId, wait: Option<u64>) -> ApprovalInfo {
        let path = match wait {
            Some(s) => format!("/v1/agent/approvals/{id}?wait={s}"),
            None => format!("/v1/agent/approvals/{id}"),
        };
        let res = self
            .server
            .agent_call(&self.agent, Method::GET, &path, None)
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        res.json().await.expect("approval")
    }

    async fn agent_events(&self) -> Vec<klav_proto::audit::AuditEvent> {
        let page: klav_proto::audit::AuditPage = self
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
            .filter(|e: &klav_proto::audit::AuditEvent| e.action.starts_with("agent.access"))
            .collect()
    }
}

/// ADR 0015 §2: a retry without `approval_id` reuses the pending request
/// and then spends the approval the person gave; approve-once is spent
/// exactly once, and every step is in the audit log.
#[tokio::test]
async fn a_retry_reuses_the_request_and_spends_the_approval_once() {
    let w = world(Policy::default()).await;
    let first = w.pending(w.access(w.item, "totp", json!({})).await).await;
    // The same action again: the same request, not a second one.
    let again = w
        .pending(
            w.access(w.item, "totp", json!({"reason": "retrying the code"}))
                .await,
        )
        .await;
    assert_eq!(first, again);
    let list: ApprovalList = w
        .server
        .get_auth(&w.ana, "/v1/approvals")
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("list");
    assert_eq!(list.approvals.len(), 1);
    // Another action on the same item is another request.
    let update = w.pending(w.access(w.item, "update", json!({})).await).await;
    assert_ne!(update, first);

    // Approved after the call returned: the plain retry uses it, and the
    // answer names it so the runtime can verify the signature (ADR 0030 §3).
    assert_eq!(
        w.server.decide(&w.ana, first, true, 0).await.status(),
        StatusCode::OK
    );
    let res = w.access(w.item, "totp", json!({})).await;
    assert_eq!(res.status(), StatusCode::OK);
    let granted: klav_proto::agent::AccessGranted = res.json().await.expect("granted");
    assert_eq!(granted.approval_id, Some(first));
    // Allowed by the policy: no approval to name.
    let res = w.access(w.item, "inject", json!({})).await;
    assert_eq!(res.status(), StatusCode::OK);
    let granted: klav_proto::agent::AccessGranted = res.json().await.expect("granted");
    assert_eq!(granted.approval_id, None);
    let spent = w.approval(first, None).await;
    assert_eq!(spent.status, ApprovalStatus::Approved);
    assert!(spent.used_at.is_some());
    // Spent: the next retry asks again, and naming it does not help.
    let next = w.pending(w.access(w.item, "totp", json!({})).await).await;
    assert_ne!(next, first);
    assert_eq!(
        w.access(w.item, "totp", json!({"approval_id": first}))
            .await
            .status(),
        StatusCode::CONFLICT
    );

    // The log has the request, the reuse, the decision and the use.
    let events = w.agent_events().await;
    let totp: Vec<_> = events
        .iter()
        .filter(|e| e.permission == Some(Permission::Totp))
        .map(|e| (e.outcome.as_deref(), e.approval_id))
        .collect();
    assert_eq!(
        totp[..4],
        [
            (Some("ask"), Some(first)),
            (Some("ask"), Some(first)),
            (Some("allow"), Some(first)),
            (Some("ask"), Some(next)),
        ]
    );
}

/// ADR 0015 §1, §3: the target includes the claimed domain, and a named
/// approval must be for the same target.
#[tokio::test]
async fn approvals_are_bound_to_their_target() {
    let w = world(Policy {
        rules: vec![rule(Permission::Fill, Effect::Ask, Scope::default())],
        expires_at: None,
    })
    .await;
    let here = json!({"claims": {"domain": "login.example.com"}});
    let there = json!({"claims": {"domain": "evil.example.net"}});
    let a = w
        .pending(w.access(w.item, "fill", here.clone()).await)
        .await;
    let b = w
        .pending(w.access(w.item, "fill", there.clone()).await)
        .await;
    assert_ne!(a, b);
    assert_eq!(
        w.server.decide(&w.ana, a, true, 0).await.status(),
        StatusCode::OK
    );
    // Not for another site, nor another permission.
    let mut named = there.clone();
    named["approval_id"] = json!(a);
    assert_eq!(
        w.access(w.item, "fill", named).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        w.access(w.item, "totp", json!({"approval_id": a}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(w.pending(w.access(w.item, "fill", there).await).await, b);
    // The right one, named: once.
    let mut named = here.clone();
    named["approval_id"] = json!(a);
    assert_eq!(
        w.access(w.item, "fill", named.clone()).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        w.access(w.item, "fill", named).await.status(),
        StatusCode::CONFLICT
    );
    // Another agent's approval does not exist for this one.
    let w2 = world(Policy::default()).await;
    assert_eq!(
        w2.access(w2.item, "totp", json!({"approval_id": a}))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
}

/// Concurrent requests: one pending request per target, and an
/// approve-once decision lets exactly one of several retries through.
#[tokio::test]
async fn concurrent_retries_share_and_spend_once() {
    let w = world(Policy::default()).await;
    let (r1, r2, r3) = tokio::join!(
        w.access(w.item, "totp", json!({})),
        w.access(w.item, "totp", json!({})),
        w.access(w.item, "totp", json!({}))
    );
    let ids = [
        w.pending(r1).await,
        w.pending(r2).await,
        w.pending(r3).await,
    ];
    assert!(ids.iter().all(|id| *id == ids[0]), "{ids:?}");
    assert_eq!(
        w.server.decide(&w.ana, ids[0], true, 0).await.status(),
        StatusCode::OK
    );
    let (r1, r2, r3) = tokio::join!(
        w.access(w.item, "totp", json!({})),
        w.access(w.item, "totp", json!({"approval_id": ids[0]})),
        w.access(w.item, "totp", json!({}))
    );
    let ok = [r1.status(), r2.status(), r3.status()]
        .iter()
        .filter(|s| **s == StatusCode::OK)
        .count();
    assert_eq!(ok, 1);
}

/// A lease keeps working for its window, with or without its ID; an
/// approve-once decision can only be spent for 10 minutes; expired pending
/// requests are replaced.
#[tokio::test]
async fn leases_and_windows() {
    let w = world(Policy::default()).await;
    let id = w.pending(w.access(w.item, "totp", json!({})).await).await;
    assert_eq!(
        w.server
            .decide(&w.ana, id, true, 15 * 60_000)
            .await
            .status(),
        StatusCode::OK
    );
    for extra in [
        json!({}),
        json!({"approval_id": id}),
        json!({"approval_id": id}),
    ] {
        assert_eq!(
            w.access(w.item, "totp", extra).await.status(),
            StatusCode::OK
        );
    }

    let db = w.server.raw_db().await;
    // An approve-once decision older than 10 minutes is not spent.
    let id = w.pending(w.access(w.item, "update", json!({})).await).await;
    assert_eq!(
        w.server.decide(&w.ana, id, true, 0).await.status(),
        StatusCode::OK
    );
    sqlx::query("UPDATE approvals SET decided_at = decided_at - 600001 WHERE id = $1")
        .bind(id.to_string())
        .execute(&db)
        .await
        .expect("age");
    assert_eq!(
        w.access(w.item, "update", json!({"approval_id": id}))
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let fresh = w.pending(w.access(w.item, "update", json!({})).await).await;
    assert_ne!(fresh, id);
    // An expired pending request is not reused: a new one replaces it.
    sqlx::query("UPDATE approvals SET expires_at = 1 WHERE id = $1")
        .bind(fresh.to_string())
        .execute(&db)
        .await
        .expect("expire");
    assert_eq!(
        w.approval(fresh, None).await.status,
        ApprovalStatus::Expired
    );
    let newer = w.pending(w.access(w.item, "update", json!({})).await).await;
    assert_ne!(newer, fresh);
}

/// `?wait=` is a long-poll: it answers when the person decides, when the
/// request expires, or when the wait is over.
#[tokio::test]
async fn the_agent_waits_with_a_long_poll() {
    use std::time::{Duration, Instant};

    let w = world(Policy::default()).await;
    // Nobody decides: back after the wait, still pending.
    let id = w.pending(w.access(w.item, "totp", json!({})).await).await;
    let start = Instant::now();
    assert_eq!(
        w.approval(id, Some(1)).await.status,
        ApprovalStatus::Pending
    );
    assert!(start.elapsed() >= Duration::from_millis(900));

    // Approved while waiting: back at once.
    let start = Instant::now();
    let (info, decided) = tokio::join!(w.approval(id, Some(20)), async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        w.server.decide(&w.ana, id, true, 0).await.status()
    });
    assert_eq!(decided, StatusCode::OK);
    assert_eq!(info.status, ApprovalStatus::Approved);
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );

    // Denied while waiting.
    let id = w.pending(w.access(w.item, "update", json!({})).await).await;
    let (info, _) = tokio::join!(w.approval(id, Some(20)), async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        w.server.decide(&w.ana, id, false, 0).await
    });
    assert_eq!(info.status, ApprovalStatus::Denied);

    // Expires while waiting.
    let id = w.pending(w.access(w.item, "update", json!({})).await).await;
    sqlx::query("UPDATE approvals SET expires_at = $1 WHERE id = $2")
        .bind(now_ms() + 500)
        .bind(id.to_string())
        .execute(&w.server.raw_db().await)
        .await
        .expect("expire soon");
    let start = Instant::now();
    assert_eq!(
        w.approval(id, Some(20)).await.status,
        ApprovalStatus::Expired
    );
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
}

/// ADR 0020 §4, T85: an agent allowed to `reveal` a login with a passkey
/// gets the details, and with them the passkey's metadata and its sealed
/// key, but nothing it holds opens that key: the vault key never reaches an
/// agent. Only the person's vault key does.
#[tokio::test]
async fn an_agent_with_reveal_cannot_open_a_passkey_key() {
    use klav_core::crypto::context::VaultContext;
    use klav_core::crypto::share::{open_shared_project_key, share_project_key};
    use klav_core::crypto::wrap::unwrap_item_key;
    use klav_core::model::item::{SealedItem, open_item};
    use klav_core::model::reference::resolve_field;
    use klav_core::model::{Passkey, PasskeyAccount};

    let w = world(Policy {
        rules: vec![rule(Permission::Reveal, Effect::Allow, Scope::default())],
        expires_at: None,
    })
    .await;
    // The person adds a login with a passkey to the granted project.
    let mut item = login_item("Shop", "ana", "hunter2");
    let vault_ctx = VaultContext {
        account: w.vault.owner,
        vault: w.vault.id,
    };
    let (passkey, key) = Passkey::create(
        &w.vault.key,
        &vault_ctx,
        item.id(),
        &PasskeyAccount {
            rp_id: "shop.example",
            rp_name: None,
            user_handle: b"ana-0001",
            user_name: "ana",
            user_display_name: None,
            created_at: now_ms(),
        },
    )
    .expect("passkey");
    item.set_passkey(passkey).expect("login");
    w.server
        .create_item(&w.ana, &w.vault, &w.project, &item)
        .await;

    // The agent reveals it, with the project key the grant shared with it.
    let res = w.access(item.id(), "reveal", json!({})).await;
    assert_eq!(res.status(), StatusCode::OK);
    let granted: klav_proto::agent::AccessGranted = res.json().await.expect("item");
    let project_ctx = w.vault.project_ctx(w.project.id);
    let shared =
        share_project_key(w.agent.keys.public(), &project_ctx, &w.project.key).expect("share");
    let agent_project_key =
        open_shared_project_key(&w.agent.keys, &project_ctx, &shared).expect("agent's copy");
    let ctx = w.vault.item_ctx(w.project.id, item.id());
    let item_key = unwrap_item_key(
        &agent_project_key,
        &ctx,
        granted
            .item
            .wrapped_key
            .as_ref()
            .expect("wrapped key")
            .as_bytes(),
    )
    .expect("item key");
    let seen = open_item(
        &item_key,
        &ctx,
        granted.item.version,
        &SealedItem {
            overview: granted
                .item
                .overview
                .as_ref()
                .expect("overview")
                .as_bytes()
                .to_vec(),
            details: granted
                .item
                .details
                .as_ref()
                .expect("details")
                .as_bytes()
                .to_vec(),
        },
    )
    .expect("the agent decrypts the item");
    assert_eq!(common::vault::field(&seen, "password"), "hunter2");
    let passkey = seen.passkey().expect("the passkey is in the details");
    assert_eq!(passkey.rp_id(), "shop.example");
    assert_eq!(passkey.sealed_key().len(), 74);
    // No field holds the key.
    for name in ["passkey", "key", "private_key"] {
        assert!(resolve_field(&seen, &Selector::Name(name.into())).is_err());
    }
    // The key opens only with the person's vault key; the vault key of
    // another vault (the only other kind of key an agent could ever hold)
    // does not.
    assert!(
        passkey
            .open_key(
                &klav_core::crypto::keys::VaultKey::generate(),
                &vault_ctx,
                item.id()
            )
            .is_err()
    );
    let opened = passkey
        .open_key(&w.vault.key, &vault_ctx, item.id())
        .expect("the person opens it");
    assert_eq!(opened.public_key(), key.public_key());
}

/// ADR 0030 §7, the exception for ADR 0022 §7: `sole_author` only when the
/// agent asking wrote every version, the person none, and none is missing
/// from the history (a pruned one could be anybody's). Authors are played
/// by editing the rows, as the agent routes write them.
#[tokio::test]
async fn sole_author_needs_every_version_of_the_asking_agent() {
    let w = world(Policy::default()).await;
    let db = w.server.raw_db().await;
    let item = w.item.to_string();
    let me = w.agent.id.to_string();
    let someone = klav_core::ids::AgentId::generate().to_string();
    let sole = || async {
        let res = w.access(w.item, "list", json!({})).await;
        assert_eq!(res.status(), StatusCode::OK);
        let granted: klav_proto::agent::AccessGranted = res.json().await.expect("granted");
        granted.sole_author
    };
    let run = |sql: &'static str, binds: Vec<String>| {
        let db = db.clone();
        async move {
            let mut q = sqlx::query(sql);
            for b in binds {
                q = q.bind(b);
            }
            q.execute(&db).await.expect("edit");
        }
    };
    let set_version = |v: i64| {
        let db = db.clone();
        let item = item.clone();
        async move {
            sqlx::query("UPDATE items SET version = $1 WHERE id = $2")
                .bind(v)
                .bind(item)
                .execute(&db)
                .await
                .expect("version");
        }
    };

    // The person's item: no.
    assert!(!sole().await);
    // Created by this agent (version 1, no history): yes.
    run(
        "UPDATE items SET author_agent_id = $1 WHERE id = $2",
        vec![me.clone(), item.clone()],
    )
    .await;
    assert!(sole().await);
    // A second version of its own: yes.
    run(
        "INSERT INTO item_versions (item_id, version, project_id, wrapped_key, overview, \
         details, created_at, author_agent_id) SELECT id, version, project_id, wrapped_key, \
         overview, details, updated_at, $1 FROM items WHERE id = $2",
        vec![me.clone(), item.clone()],
    )
    .await;
    set_version(2).await;
    assert!(sole().await);
    // A version missing from the history (pruned): no.
    set_version(3).await;
    assert!(!sole().await);
    set_version(2).await;
    // A version of another agent: no.
    run(
        "UPDATE item_versions SET author_agent_id = $1 WHERE item_id = $2",
        vec![someone.clone(), item.clone()],
    )
    .await;
    assert!(!sole().await);
    // A version of the person: no (hers rules, `person_version`).
    run(
        "UPDATE item_versions SET author_agent_id = NULL WHERE item_id = $1",
        vec![item.clone()],
    )
    .await;
    assert!(!sole().await);
    // Every version of another agent: not this one's.
    run(
        "UPDATE item_versions SET author_agent_id = $1 WHERE item_id = $2",
        vec![someone.clone(), item.clone()],
    )
    .await;
    run(
        "UPDATE items SET author_agent_id = $1 WHERE id = $2",
        vec![someone, item],
    )
    .await;
    assert!(!sole().await);
}

// ------------------------------------------- layer 07 of the 2026-11 round --

#[tokio::test]
async fn a_deleted_vault_is_out_of_reach_for_agents() {
    let w = world(Policy {
        rules: vec![rule(Permission::Inject, Effect::Allow, Scope::default())],
        expires_at: None,
    })
    .await;
    assert_eq!(
        w.access(w.item, "inject", json!({})).await.status(),
        StatusCode::OK
    );
    let res = w
        .server
        .delete_auth(&w.ana, &format!("/v1/vaults/{}", w.vault.id))
        .send()
        .await
        .expect("delete vault");
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    // Until it is restored, the agent neither lists nor uses its items.
    let items: AgentItems = w
        .server
        .agent_call(&w.agent, Method::GET, "/v1/agent/items", None)
        .await
        .json()
        .await
        .expect("items");
    assert!(items.projects.is_empty(), "deleted vault listed");
    assert_eq!(
        w.access(w.item, "inject", json!({})).await.status(),
        StatusCode::NOT_FOUND
    );
    let task = json!({
        "v": 1, "task": "deploy", "reason": "run the deploy", "duration_secs": 600,
        "access": [{"vault_id": w.vault.id, "project_id": w.project.id,
                    "item_id": w.item, "permissions": ["inject"]}],
    });
    assert_eq!(
        w.server
            .agent_call(&w.agent, Method::POST, "/v1/agent/tasks", Some(&task))
            .await
            .status(),
        StatusCode::BAD_REQUEST,
        "a task on an item of a deleted vault"
    );

    let res = w
        .server
        .post_auth(&w.ana, &format!("/v1/vaults/{}/restore", w.vault.id))
        .send()
        .await
        .expect("restore vault");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        w.access(w.item, "inject", json!({})).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn attachment_contents_are_read_only_once_allowed() {
    let w = world(Policy {
        rules: vec![rule(Permission::Inject, Effect::Deny, Scope::default())],
        expires_at: None,
    })
    .await;
    let attachment = w
        .server
        .upload_attachment(&w.ana, &w.vault, &w.project, w.item, b"key file", true)
        .await;
    // The file disappears from the disk: a denied access must not notice,
    // because it must not read it at all.
    let path = w
        .server
        .data_dir
        .path()
        .join("data/attachments")
        .join(w.vault.id.to_string())
        .join(attachment.to_string());
    std::fs::remove_file(&path).expect("remove attachment file");
    assert_eq!(
        w.access(w.item, "inject", json!({"include_attachments": true}))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn claims_are_plain_and_bounded() {
    let w = world(Policy {
        rules: vec![
            rule(Permission::Fill, Effect::Allow, Scope::default()),
            rule(
                Permission::Fill,
                Effect::Deny,
                Scope {
                    domains: vec![DomainPattern::parse("bank.example.com").expect("pattern")],
                    ..Scope::default()
                },
            ),
        ],
        expires_at: None,
    })
    .await;
    let fill = |claims: Value| w.access(w.item, "fill", json!({ "claims": claims }));
    assert_eq!(
        fill(json!({"domain": "github.com"})).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        fill(json!({"domain": "bank.example.com"})).await.status(),
        StatusCode::FORBIDDEN
    );
    // Another spelling of the denied host does not slip past its rule.
    for domain in [
        "BANK.example.com",
        "bank.example.com.",
        "https://bank.example.com",
        "bank.example.com:443",
        "bank\u{202e}moc.elpmaxe",
        "",
    ] {
        assert_eq!(
            fill(json!({ "domain": domain })).await.status(),
            StatusCode::BAD_REQUEST,
            "{domain:?}"
        );
    }
    // Tags: few, short and plain.
    let many: Vec<String> = (0..65).map(|i| format!("t{i}")).collect();
    for tags in [
        json!(many),
        json!(["x".repeat(129)]),
        json!(["ops\u{202e}"]),
        json!(["a\u{200b}b"]),
        json!(["  "]),
    ] {
        assert_eq!(
            fill(json!({"domain": "github.com", "tags": tags}))
                .await
                .status(),
            StatusCode::BAD_REQUEST,
            "{tags}"
        );
    }
    assert_eq!(
        fill(json!({"domain": "github.com", "tags": ["ops", "Producción"]}))
            .await
            .status(),
        StatusCode::OK
    );
    // The reason the person reads before deciding: no bidi or zero-width.
    for reason in [
        "deploy \u{202e}txet",
        "line\u{2028}break",
        "zero\u{200b}width",
    ] {
        let res = w
            .server
            .agent_call(
                &w.agent,
                Method::POST,
                "/v1/agent/access",
                Some(
                    &json!({"item_id": w.item, "permission": "fill", "reason": reason,
                             "claims": {"domain": "github.com"}}),
                ),
            )
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{reason:?}");
    }
}

// ---------------------------- approval.decided in the decision's transaction --

impl World {
    /// The approval's stored status, read straight from the database.
    async fn approval_status(&self, db: &sqlx::AnyPool, id: ApprovalId) -> String {
        sqlx::query_scalar("SELECT status FROM approvals WHERE id = $1")
            .bind(id.to_string())
            .fetch_one(db)
            .await
            .expect("test")
    }

    /// Ana's `approval.decided` events for approval `id`, read straight
    /// from the database.
    async fn decided(&self, db: &sqlx::AnyPool, id: ApprovalId) -> Vec<AuditEvent> {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT event FROM audit_events WHERE account_id = $1 \
             AND action = 'approval.decided' ORDER BY seq",
        )
        .bind(self.ana.account_id.to_string())
        .fetch_all(db)
        .await
        .expect("test");
        rows.iter()
            .map(|bytes| serde_json::from_slice::<AuditEvent>(bytes).expect("test"))
            .filter(|e| e.approval_id == Some(id))
            .collect()
    }
}

/// A decision on an agent's request whose client goes away is never stored
/// without its `approval.decided`: the call is driven through the router
/// by hand and dropped as soon as the request reads as decided, before the
/// handler sees its commit (a try that finished first is made again in a
/// new world, whose request is still pending).
#[tokio::test]
async fn a_decision_whose_client_goes_away_is_logged_with_it() {
    let (w, db, id, body) = until_dropped(async || {
        let w = world(Policy::default()).await;
        let db = w.server.raw_db().await;
        // totp is `ask` by default.
        let id = w.pending(w.access(w.item, "totp", json!({})).await).await;
        let body = w.server.decide_body(&w.ana, id, true, 0).await;
        let status = w
            .server
            .call_dropped_once(
                Some(&w.ana),
                &format!("/v1/approvals/{id}/decide"),
                &body,
                || async { w.approval_status(&db, id).await != "pending" },
            )
            .await;
        (status, (w, db, id, body))
    })
    .await;
    assert_eq!(w.approval_status(&db, id).await, "approved");
    let decided = w.decided(&db, id).await;
    assert_eq!(decided.len(), 1);
    assert_eq!(decided[0].outcome.as_deref(), Some("approve"));
    assert_eq!(decided[0].decided_at, Some(body.decided_at));
    assert!(decided[0].alerts.is_empty());
}

/// A decision whose `approval.decided` the log refuses is not made: the
/// request stays pending, with no event, until a decision the log takes.
/// A denial keeps its `denied` alert.
#[tokio::test]
async fn a_decision_that_cannot_be_logged_is_not_made() {
    let w = world(Policy::default()).await;
    let db = w.server.raw_db().await;
    let id = w.pending(w.access(w.item, "totp", json!({})).await).await;
    w.server.refuse_audit_action("approval.decided").await;
    assert_eq!(
        w.server.decide(&w.ana, id, false, 0).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(w.approval_status(&db, id).await, "pending");
    assert!(w.decided(&db, id).await.is_empty());
    w.server.allow_audit_action("approval.decided").await;
    assert_eq!(
        w.server.decide(&w.ana, id, false, 0).await.status(),
        StatusCode::OK
    );
    assert_eq!(w.approval_status(&db, id).await, "denied");
    let decided = w.decided(&db, id).await;
    assert_eq!(decided.len(), 1);
    assert_eq!(decided[0].outcome.as_deref(), Some("deny"));
    assert_eq!(decided[0].alerts, ["denied"]);
}

/// A decision the database refuses to store logs no `approval.decided`:
/// the event is appended in the decision's transaction, not in one of its
/// own before it.
#[tokio::test]
async fn a_decision_that_cannot_be_stored_is_not_logged() {
    let w = world(Policy::default()).await;
    let db = w.server.raw_db().await;
    let id = w.pending(w.access(w.item, "totp", json!({})).await).await;
    w.server.refuse_writes("approvals").await;
    let status = w.server.decide(&w.ana, id, true, 0).await.status();
    w.server.allow_writes("approvals").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(w.approval_status(&db, id).await, "pending");
    assert!(w.decided(&db, id).await.is_empty());
    assert_eq!(
        w.server.decide(&w.ana, id, true, 0).await.status(),
        StatusCode::OK
    );
    assert_eq!(w.approval_status(&db, id).await, "approved");
    assert_eq!(w.decided(&db, id).await.len(), 1);
}

/// Postgres only: an approval and a denial each write the request and
/// append its `approval.decided` in one transaction. The denial first:
/// after the approval the same request is allowed, not asked.
#[tokio::test]
async fn a_decision_and_its_event_share_one_transaction() {
    let w = world(Policy::default()).await;
    if !w.server.is_postgres() {
        return;
    }
    let db = w.server.raw_db().await;
    for approve in [false, true] {
        let id = w.pending(w.access(w.item, "totp", json!({})).await).await;
        assert_eq!(
            w.server.decide(&w.ana, id, approve, 0).await.status(),
            StatusCode::OK,
            "{approve}"
        );
        w.server
            .assert_written_with(
                &db,
                w.ana.account_id,
                "approvals",
                &id.to_string(),
                "approval.decided",
            )
            .await;
    }
}

/// Postgres only: a decision takes the account's lock before the
/// approval's row, as every transaction that writes an approval and logs
/// in itself does (the agent's ask and the revocation take the account,
/// then the agent, then its approvals).
#[tokio::test]
async fn a_decision_locks_the_account_before_the_approval() {
    let w = world(Policy::default()).await;
    if !w.server.is_postgres() {
        return;
    }
    let id = w.pending(w.access(w.item, "totp", json!({})).await).await;
    let body = w.server.decide_body(&w.ana, id, true, 0).await;
    let send = w
        .server
        .post_auth(&w.ana, &format!("/v1/approvals/{id}/decide"))
        .json(&body)
        .send();
    let res = w
        .server
        .assert_account_locked_first(
            w.ana.account_id,
            "UPDATE approvals SET status = status WHERE id = $1",
            id.to_string(),
            send,
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
}

// ------------------------------- the agent's ask, in the request's transaction --

impl World {
    /// The agent's approval requests, of any status, read straight from
    /// the database.
    async fn requests_stored(&self, db: &sqlx::AnyPool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM approvals WHERE agent_id = $1")
            .bind(self.agent.id.to_string())
            .fetch_one(db)
            .await
            .expect("test")
    }

    /// Ana's `agent.access` events with outcome `ask`, read straight from
    /// the database: the approval each one asked for.
    async fn asks_logged(&self, db: &sqlx::AnyPool) -> Vec<Option<ApprovalId>> {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT event FROM audit_events WHERE account_id = $1 \
             AND action = 'agent.access' ORDER BY seq",
        )
        .bind(self.ana.account_id.to_string())
        .fetch_all(db)
        .await
        .expect("test");
        rows.iter()
            .map(|bytes| serde_json::from_slice::<AuditEvent>(bytes).expect("test"))
            .filter(|e| e.outcome.as_deref() == Some("ask"))
            .map(|e| e.approval_id)
            .collect()
    }
}

/// An agent's ask whose `agent.access` (`ask`) the log refuses stores no
/// approval request: the ask is logged in the request's own transaction.
/// The same access asked again then goes through, with one event.
#[tokio::test]
async fn an_ask_that_cannot_be_logged_stores_no_request() {
    let w = world(Policy::default()).await;
    let db = w.server.raw_db().await;
    w.server.refuse_audit_action("agent.access").await;
    // totp is `ask` by default.
    let status = w.access(w.item, "totp", json!({})).await.status();
    w.server.allow_audit_action("agent.access").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(w.requests_stored(&db).await, 0, "no request stored");
    assert!(w.asks_logged(&db).await.is_empty());
    let id = w.pending(w.access(w.item, "totp", json!({})).await).await;
    assert_eq!(w.approval_status(&db, id).await, "pending");
    assert_eq!(w.asks_logged(&db).await, [Some(id)]);
}

/// An agent's ask the database refuses to store logs no `agent.access`:
/// the event is appended in the request's transaction, not in one of its
/// own before it.
#[tokio::test]
async fn an_ask_that_cannot_be_stored_is_not_logged() {
    let w = world(Policy::default()).await;
    let db = w.server.raw_db().await;
    w.server.refuse_writes("approvals").await;
    let status = w.access(w.item, "totp", json!({})).await.status();
    w.server.allow_writes("approvals").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(w.requests_stored(&db).await, 0, "no request stored");
    assert!(w.asks_logged(&db).await.is_empty());
    let id = w.pending(w.access(w.item, "totp", json!({})).await).await;
    assert_eq!(w.asks_logged(&db).await, [Some(id)]);
}

/// Postgres only: an agent's ask writes the approval request and appends
/// its `agent.access` in one transaction.
#[tokio::test]
async fn an_ask_and_its_event_share_one_transaction() {
    let w = world(Policy::default()).await;
    if !w.server.is_postgres() {
        return;
    }
    let db = w.server.raw_db().await;
    let id = w.pending(w.access(w.item, "totp", json!({})).await).await;
    w.server
        .assert_written_with(
            &db,
            w.ana.account_id,
            "approvals",
            &id.to_string(),
            "agent.access",
        )
        .await;
}

// ------------- an approve-once decision spent by a refused action --

/// What the person does while the agent's action waits for the account's
/// lock to be logged.
#[derive(Clone, Copy, Debug)]
enum Meanwhile {
    /// Revokes the agent: the log refuses with `403 forbidden`.
    Revokes,
    /// Asks to delete the account: `403 account_deleting`.
    Deletes,
}

/// An action let through by an approve-once decision spends it, then waits
/// for the account's lock to be logged; the person revokes the agent or
/// asks to delete the account meanwhile, and the log refuses the action.
/// The action did not happen, so the decision is given back (`used_at`
/// cleared), as for a pause. Postgres only, as #413's pair: the test holds
/// the account's lock and waits until the action waits on it.
async fn a_spent_decision_is_given_back_when(meanwhile: Meanwhile) {
    let w = world(Policy::default()).await;
    if !w.server.is_postgres() {
        return;
    }
    let id = w.pending(w.access(w.item, "totp", json!({})).await).await;
    assert_eq!(
        w.server.decide(&w.ana, id, true, 0).await.status(),
        StatusCode::OK
    );
    let db = w.server.raw_db().await;
    let used_at = |db: sqlx::AnyPool| async move {
        sqlx::query_scalar::<_, Option<i64>>("SELECT used_at FROM approvals WHERE id = $1")
            .bind(id.to_string())
            .fetch_one(&db)
            .await
            .expect("test")
    };
    assert_eq!(used_at(db.clone()).await, None);
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
    let person = async {
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
        // The decision is spent before the action is logged.
        assert!(used_at(db.clone()).await.is_some(), "spent while it waits");
        // Direct writes, as in #413's pair: the columns the person's
        // revocation and deletion request write.
        match meanwhile {
            Meanwhile::Revokes => {
                sqlx::query("UPDATE agents SET status = 'revoked', revoked_at = $1 WHERE id = $2")
                    .bind(now_ms())
                    .bind(w.agent.id.to_string())
                    .execute(&mut *account)
                    .await
                    .expect("test");
            }
            Meanwhile::Deletes => {
                sqlx::query(
                    "INSERT INTO account_deletions (account_id, device_id, requested_at, delete_at) \
                     VALUES ($1, $2, $3, $4)",
                )
                .bind(w.ana.account_id.to_string())
                .bind(w.ana.device_id.to_string())
                .bind(now_ms())
                .bind(now_ms() + 86_400_000)
                .execute(&mut *account)
                .await
                .expect("test");
            }
        }
        account.commit().await.expect("test");
    };
    let (res, ()) = tokio::join!(w.access(w.item, "totp", json!({"approval_id": id})), person);
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "{meanwhile:?}");
    let body: klav_proto::ErrorBody = res.json().await.expect("error body");
    let expected = match meanwhile {
        Meanwhile::Revokes => klav_proto::ErrorCode::Forbidden,
        Meanwhile::Deletes => klav_proto::ErrorCode::AccountDeleting,
    };
    assert_eq!(body.error, expected, "{meanwhile:?}");
    assert_eq!(used_at(db).await, None, "{meanwhile:?}: given back");
}

#[tokio::test]
async fn a_spent_decision_is_given_back_when_the_agent_is_revoked_meanwhile() {
    a_spent_decision_is_given_back_when(Meanwhile::Revokes).await;
}

#[tokio::test]
async fn a_spent_decision_is_given_back_when_the_account_deletion_is_asked_meanwhile() {
    a_spent_decision_is_given_back_when(Meanwhile::Deletes).await;
}

/// A probe (`POST /v1/agent/approvals`) refused as it is logged, its
/// signature out of the window by then (`agent_call_held`, `401`), after it
/// read an approve-once decision unspent: it spent nothing, so nothing is
/// given back. A trigger records any `UPDATE` of the decision that leaves
/// `used_at` empty (a row trigger fires even when nothing changes), so the
/// give-back is seen on both databases even though there was nothing to
/// clear. The race it guards against is the Postgres test below.
#[tokio::test]
async fn a_probe_refused_as_it_is_logged_clears_nothing() {
    let w = world(Policy::default()).await;
    let id = w.pending(w.access(w.item, "update", json!({})).await).await;
    assert_eq!(
        w.server.decide(&w.ana, id, true, 0).await.status(),
        StatusCode::OK
    );
    let db = w.server.raw_db().await;
    let sql_id = id.to_string();
    assert!(
        sql_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    );
    let mut statements = vec!["CREATE TABLE klav_test_cleared (id TEXT NOT NULL)".to_owned()];
    if w.server.is_postgres() {
        statements.push(
            "CREATE FUNCTION klav_test_cleared() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN INSERT INTO klav_test_cleared VALUES (NEW.id); RETURN NEW; END $$"
                .to_owned(),
        );
        statements.push(format!(
            "CREATE TRIGGER klav_test_cleared AFTER UPDATE ON approvals FOR EACH ROW \
             WHEN (NEW.id = '{sql_id}' AND NEW.used_at IS NULL) \
             EXECUTE FUNCTION klav_test_cleared()"
        ));
    } else {
        statements.push(format!(
            "CREATE TRIGGER klav_test_cleared AFTER UPDATE ON approvals \
             WHEN NEW.id = '{sql_id}' AND NEW.used_at IS NULL \
             BEGIN INSERT INTO klav_test_cleared VALUES (NEW.id); END"
        ));
    }
    for sql in statements {
        // The ID is checked above, so it is safe to interpolate.
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(&db)
            .await
            .expect("test trigger");
    }
    let ask = json!({
        "permission": "update",
        "vault_id": w.vault.id,
        "project_id": w.project.id,
        "item_id": w.item,
        "reason": "log in to run the deploy",
    });
    let res = w
        .server
        .agent_call_held(&w.ana, &w.agent, Method::POST, "/v1/agent/approvals", &ask)
        .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let cleared: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM klav_test_cleared")
        .fetch_one(&db)
        .await
        .expect("test");
    assert_eq!(cleared, 0, "the probe gave back a decision it never spent");
    // The probe read X: an honest probe now still finds it.
    let res = w
        .server
        .agent_call(&w.agent, Method::POST, "/v1/agent/approvals", Some(&ask))
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let asked: Value = res.json().await.expect("asked");
    assert_eq!(asked["approval_id"], json!(id));
}

/// A probe (`POST /v1/agent/approvals`) only reads an approve-once
/// decision: it never spends one, so it never gives one back. The probe
/// reads decision X unspent and waits for the account's lock to be logged;
/// meanwhile a real step spends X and waits behind it; the person pauses the
/// agent until a time after the probe's logged time and before the real
/// step's, so the log refuses the probe (`403 agents_paused`) and takes the
/// real step. X stays spent. Postgres only, as the pair above: the test
/// holds the account's lock and waits until each request waits on it.
#[tokio::test]
async fn a_probe_refused_as_it_is_logged_gives_nothing_back() {
    use std::time::{Duration, Instant};

    let w = world(Policy::default()).await;
    if !w.server.is_postgres() {
        return;
    }
    let id = w.pending(w.access(w.item, "update", json!({})).await).await;
    assert_eq!(
        w.server.decide(&w.ana, id, true, 0).await.status(),
        StatusCode::OK
    );
    let db = w.server.raw_db().await;
    let used_at = |db: sqlx::AnyPool| async move {
        sqlx::query_scalar::<_, Option<i64>>("SELECT used_at FROM approvals WHERE id = $1")
            .bind(id.to_string())
            .fetch_one(&db)
            .await
            .expect("test")
    };
    let held = w.server.raw_db().await;
    let mut account = held.begin().await.expect("test");
    sqlx::query("UPDATE accounts SET updated_at = updated_at WHERE id = $1")
        .bind(w.ana.account_id.to_string())
        .execute(&mut *account)
        .await
        .expect("test");
    // Requests waiting on the account's row, behind this transaction or
    // behind one another (a second waiter's place in the queue is not
    // guaranteed, and does not matter here).
    let waiting = |db: sqlx::AnyPool, n: i64| async move {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_stat_activity \
                 WHERE datname = current_database() \
                 AND cardinality(pg_blocking_pids(pid)) > 0 \
                 AND query LIKE 'UPDATE accounts SET updated_at = updated_at%'",
            )
            .fetch_one(&db)
            .await
            .expect("test");
            if count >= n {
                return;
            }
            assert!(Instant::now() < deadline, "{n} not waiting");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    let ask = json!({
        "permission": "update",
        "vault_id": w.vault.id,
        "project_id": w.project.id,
        "item_id": w.item,
        "reason": "log in to run the deploy",
    });
    let (go, ready) = tokio::sync::oneshot::channel::<()>();
    let probe = w
        .server
        .agent_call(&w.agent, Method::POST, "/v1/agent/approvals", Some(&ask));
    let real = async {
        ready.await.expect("test");
        w.access(w.item, "update", json!({"approval_id": id})).await
    };
    let person = async {
        // The probe read X and waits to be logged, at a time before `until`.
        waiting(db.clone(), 1).await;
        assert_eq!(used_at(db.clone()).await, None, "a probe spends nothing");
        tokio::time::sleep(Duration::from_millis(5)).await;
        let until = now_ms();
        // The real step starts after `until`: its every check is past it.
        go.send(()).expect("test");
        waiting(db.clone(), 2).await;
        assert!(used_at(db.clone()).await.is_some(), "the real step spent X");
        // A direct write, as the pair above: the columns the person's pause
        // writes (its signature is the person's, never checked here).
        sqlx::query(
            "INSERT INTO agent_pauses (account_id, scope, state, at_ms, until_ms, signature) \
             VALUES ($1, $2, 'pause', $3, $4, $5)",
        )
        .bind(w.ana.account_id.to_string())
        .bind(w.agent.id.to_string())
        .bind(until - 60_000)
        .bind(until)
        .bind(vec![0_u8; 64])
        .execute(&mut *account)
        .await
        .expect("test");
        account.commit().await.expect("test");
    };
    let (probe, real, ()) = tokio::join!(probe, real, person);
    assert_eq!(probe.status(), StatusCode::FORBIDDEN);
    let body: klav_proto::ErrorBody = probe.json().await.expect("error body");
    assert_eq!(body.error, klav_proto::ErrorCode::AgentsPaused);
    assert_eq!(real.status(), StatusCode::OK);
    assert!(
        used_at(db).await.is_some(),
        "the probe gave back a decision the real step spent"
    );
}

// ------------------------------------- each device's latest signed head --

/// Ana, signed in on two devices, with one event in her chain.
async fn two_devices() -> (TestServer, Session, Session) {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let laptop = server.login(&creds, "laptop").await;
    let phone = server.login(&creds, "phone").await;
    assert_ne!(laptop.device_id, phone.device_id);
    server
        .register_agent_ok(&TestAgent::new(), "ana@example.com", "bot")
        .await;
    (server, laptop, phone)
}

/// `device` signs and posts the head of the chain as the server has it.
async fn post_head(server: &TestServer, device: &Session) {
    post_head_back(server, device, 0).await;
}

/// `device` signs and posts the head `back` events behind the last one.
async fn post_head_back(server: &TestServer, device: &Session, back: usize) {
    use klav_core::crypto::audit::sign_head;
    use klav_proto::audit::{AuditPage, SignHead};

    let page: AuditPage = server
        .get_auth(device, "/v1/audit?after=0")
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("page");
    let last = page.entries.iter().rev().nth(back).expect("an event");
    let hash: [u8; 32] = last.hash.as_bytes().try_into().expect("hash");
    let res = server
        .post_auth(device, "/v1/audit/heads")
        .json(&SignHead {
            seq: last.seq,
            hash: klav_proto::Blob::new(hash.to_vec()),
            signature: klav_proto::Blob::new(
                sign_head(&device.identity, device.account_id, last.seq, &hash)
                    .to_bytes()
                    .to_vec(),
            ),
        })
        .send()
        .await
        .expect("post");
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
}

async fn heads(server: &TestServer, device: &Session) -> Vec<klav_proto::audit::AuditHead> {
    let heads: klav_proto::audit::AuditHeads = server
        .get_auth(device, "/v1/audit/heads")
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("heads");
    heads.heads
}

/// A device that verifies often (each sandbox list does) no longer pushes
/// another device's head out of `GET /v1/audit/heads`: the phone's only
/// head stays, after the laptop's latest 100, newest first. Each device
/// posts its head through the route; the laptop's later posts of the same
/// head are copies of its row with a later `signed_at`, as a server before
/// posts were deduplicated stored them (the route now stores the same head
/// once, and its rate limit stops 120 posts in a test).
#[tokio::test]
async fn each_devices_latest_head_stays_listed() {
    let (server, laptop, phone) = two_devices().await;
    post_head(&server, &phone).await;
    // The phone's head is older than every one of the laptop's.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    post_head(&server, &laptop).await;
    let db = server.raw_db().await;
    for i in 1..120_i64 {
        sqlx::query(
            "INSERT INTO audit_heads (account_id, seq, hash, signature, device_id, signed_at) \
             SELECT account_id, seq, hash, signature, device_id, signed_at + $1 \
             FROM audit_heads WHERE device_id = $2 ORDER BY signed_at LIMIT 1",
        )
        .bind(i)
        .bind(laptop.device_id.to_string())
        .execute(&db)
        .await
        .expect("test");
    }
    let listed = heads(&server, &laptop).await;
    assert_eq!(listed.len(), 101);
    assert!(
        listed[..100]
            .iter()
            .all(|h| h.device_id == laptop.device_id)
    );
    assert_eq!(listed[100].device_id, phone.device_id);
    assert!(
        listed.windows(2).all(|w| w[0].signed_at >= w[1].signed_at),
        "newest first"
    );
    // Either device reads the same list.
    assert_eq!(heads(&server, &phone).await.len(), 101);
}

/// The response is bounded: the latest 100 heads, then each device's latest
/// one for the 1000 devices whose latest head is newest. The oldest
/// devices' heads are the ones left out. The rows are written straight to
/// the table (the route checks nothing on a read), with an increasing
/// `signed_at`.
#[tokio::test]
async fn the_heads_listed_are_bounded() {
    let (server, laptop, _) = two_devices().await;
    let db = server.raw_db().await;
    let devices: Vec<klav_core::ids::DeviceId> = (0..1050)
        .map(|_| klav_core::ids::DeviceId::generate())
        .collect();
    let mut tx = db.begin().await.expect("test");
    let mut at = 1_000_i64;
    let mut insert = async |device: klav_core::ids::DeviceId, at: i64| {
        sqlx::query(
            "INSERT INTO audit_heads (account_id, seq, hash, signature, device_id, signed_at) \
             VALUES ($1, 1, $2, $3, $4, $5)",
        )
        .bind(laptop.account_id.to_string())
        .bind(vec![0_u8; 32])
        .bind(vec![0_u8; 64])
        .bind(device.to_string())
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("test");
    };
    // Two heads per other device (only its latest counts), oldest first...
    for device in &devices {
        for _ in 0..2 {
            at += 1;
            insert(*device, at).await;
        }
    }
    // ...then 150 of the laptop's, the newest.
    for _ in 0..150 {
        at += 1;
        insert(laptop.device_id, at).await;
    }
    tx.commit().await.expect("test");

    let listed = heads(&server, &laptop).await;
    assert_eq!(listed.len(), 1100);
    assert!(
        listed[..100]
            .iter()
            .all(|h| h.device_id == laptop.device_id)
    );
    let rest: Vec<_> = listed[100..].iter().map(|h| h.device_id).collect();
    // The 1000 newest of the other devices, each once, with its latest
    // head, newest first.
    let expected: Vec<_> = devices.iter().rev().take(1000).copied().collect();
    assert_eq!(rest, expected);
    let latest = |i: usize| 1_000 + 2 * (i64::try_from(i).expect("test") + 1);
    for (h, device) in listed[100..].iter().zip(&expected) {
        let i = devices.iter().position(|d| d == device).expect("test");
        assert_eq!(h.signed_at, latest(i));
    }
}

/// The heads of `device` stored, as `(seq, signed_at)`, by position.
async fn stored_heads(server: &TestServer, device: &Session) -> Vec<(i64, i64)> {
    let db = server.raw_db().await;
    sqlx::query_as(
        "SELECT seq, signed_at FROM audit_heads WHERE device_id = $1 ORDER BY seq, signed_at",
    )
    .bind(device.device_id.to_string())
    .fetch_all(&db)
    .await
    .expect("test")
}

/// A post of a head this device already has, or of one behind its latest,
/// answers `204` and stores nothing, so verifying in a loop does not grow
/// the table every `GET /v1/audit/heads` reads; a head further along is
/// stored.
#[tokio::test]
async fn a_head_is_stored_once_per_device() {
    let (server, laptop, phone) = two_devices().await;
    // A second event, so that there is a head behind the last.
    server
        .register_agent_ok(&TestAgent::new(), "ana@example.com", "bot 2")
        .await;
    post_head(&server, &laptop).await;
    let first = stored_heads(&server, &laptop).await;
    assert_eq!(first.len(), 1);
    // The same head again: `204`, nothing new.
    post_head(&server, &laptop).await;
    assert_eq!(stored_heads(&server, &laptop).await, first);
    // An older head: `204`, nothing new.
    post_head_back(&server, &laptop, 1).await;
    assert_eq!(stored_heads(&server, &laptop).await, first);
    // Another device's same head is its own.
    post_head(&server, &phone).await;
    assert_eq!(stored_heads(&server, &phone).await.len(), 1);
    // A newer head is stored.
    server
        .register_agent_ok(&TestAgent::new(), "ana@example.com", "bot 3")
        .await;
    post_head(&server, &laptop).await;
    let now = stored_heads(&server, &laptop).await;
    assert_eq!(now.len(), 2);
    assert!(now[1].0 > first[0].0);
}

/// A device's latest head is the one furthest along the chain, not its
/// last post: a lower head stamped later (stored by an older server, or
/// before posts were deduplicated) never stands in for it. The laptop's
/// heads are pushed out of the latest 100 by the phone's, so only its
/// latest one is listed.
#[tokio::test]
async fn a_devices_latest_head_is_its_highest() {
    let (server, laptop, phone) = two_devices().await;
    server
        .register_agent_ok(&TestAgent::new(), "ana@example.com", "bot 2")
        .await;
    post_head(&server, &laptop).await;
    let high = stored_heads(&server, &laptop).await[0];
    let db = server.raw_db().await;
    // A lower head of the laptop, stamped after its high one.
    sqlx::query(
        "INSERT INTO audit_heads (account_id, seq, hash, signature, device_id, signed_at) \
         SELECT account_id, seq - 1, hash, signature, device_id, signed_at + 1 \
         FROM audit_heads WHERE device_id = $1",
    )
    .bind(laptop.device_id.to_string())
    .execute(&db)
    .await
    .expect("test");
    // 100 heads of the phone, all newer.
    post_head(&server, &phone).await;
    for i in 1..100_i64 {
        sqlx::query(
            "INSERT INTO audit_heads (account_id, seq, hash, signature, device_id, signed_at) \
             SELECT account_id, seq, hash, signature, device_id, signed_at + $1 \
             FROM audit_heads WHERE device_id = $2 ORDER BY signed_at LIMIT 1",
        )
        .bind(i)
        .bind(phone.device_id.to_string())
        .execute(&db)
        .await
        .expect("test");
    }
    let listed = heads(&server, &laptop).await;
    assert_eq!(listed.len(), 101);
    let theirs: Vec<_> = listed
        .iter()
        .filter(|h| h.device_id == laptop.device_id)
        .map(|h| (i64::try_from(h.seq).expect("test"), h.signed_at))
        .collect();
    assert_eq!(theirs, [high]);
}
