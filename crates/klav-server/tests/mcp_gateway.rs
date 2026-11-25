//! The MCP gateway against the real server (ADR 0049, layer 3): the
//! account's `mcp_gateway` switch, the tool claims and the local client,
//! «once» bound to the arguments and leases bound to the tool, and the
//! caller under the person's signature. Runs on SQLite, and on Postgres
//! when `KLAV_TEST_DATABASE_URL` says so.
//!
//! "Safe with older clients": with the switch off (the default), every
//! answer an older client or agent can get is what it was, and the only new
//! answer, `400 mcp_gateway_off`, goes only to a request with the new
//! fields, which only a new agent sends.

mod common;

use common::TestServer;
use common::agent::TestAgent;
use common::client::Session;
use common::vault::{TestProject, TestVault, login_item};
use klav_core::crypto::keys::ItemKey;
use klav_core::crypto::mcp::digest_text;
use klav_core::ids::{ApprovalId, ItemId};
use klav_core::policy::{
    DomainPattern, Effect, HttpMethod, PathPrefix, Permission, Policy, Rule, Scope, ToolPattern,
};
use klav_proto::Blob;
use klav_proto::agent::{
    ApprovalInfo, ApprovalRequest, GRANT_PAYLOAD_VERSION_MCP, GrantPayload, LocalClient,
    McpGatewaySwitch, McpProfile, ProxyProfile,
};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

const MAPLE: &str = "api.maple.dev";
const REST: &str = "api.example.com";

struct World {
    server: TestServer,
    ana: Session,
    vault: TestVault,
    project: TestProject,
    proxy: TestAgent,
    maple: (ItemId, ItemKey),
    rest: (ItemId, ItemKey),
}

fn rule(effect: Effect, scope: Scope) -> Rule {
    Rule {
        scope,
        ..Rule::new(Permission::Proxy, effect)
    }
}

fn base(item: ItemId, host: &str, prefix: &str) -> Scope {
    Scope {
        items: vec![item],
        domains: vec![DomainPattern::parse(host).expect("host")],
        path_prefixes: vec![PathPrefix::parse(prefix).expect("prefix")],
        ..Scope::default()
    }
}

fn tools(patterns: &[&str]) -> Vec<ToolPattern> {
    patterns
        .iter()
        .map(|p| p.parse().expect("pattern"))
        .collect()
}

fn profile(name: &str, item: ItemId, host: &str, mcp: Option<&str>) -> ProxyProfile {
    ProxyProfile {
        name: name.into(),
        item_id: item,
        field: None,
        header: "authorization".into(),
        prefix: "Bearer ".into(),
        upstream: format!("https://{host}"),
        rate_per_minute: None,
        mcp: mcp.map(|endpoint| McpProfile {
            endpoint: endpoint.into(),
            headers: Vec::new(),
        }),
    }
}

/// ADR 0049 §5.3's example on `maple` (an MCP profile), and a plain REST
/// profile on another item.
fn mcp_policy(maple: ItemId, rest: ItemId, host: &str) -> Policy {
    let mut session = base(maple, host, "/mcp");
    session.methods = ["POST", "GET", "DELETE"]
        .iter()
        .map(|m| HttpMethod::parse(m).expect("method"))
        .collect();
    let with = |effect, patterns: &[&str]| {
        rule(
            effect,
            Scope {
                mcp_tools: tools(patterns),
                ..base(maple, host, "/mcp")
            },
        )
    };
    let mut rules = vec![
        rule(Effect::Allow, session),
        with(Effect::Allow, &["get_*", "list_*", "query_*"]),
        with(
            Effect::Ask,
            &["create_*", "update_*", "delete_*", "deploy_*"],
        ),
        with(Effect::Deny, &["create_api_key", "get_api_key"]),
        rule(Effect::Allow, base(rest, REST, "/v1")),
    ];
    rules.extend(
        [Permission::Reveal, Permission::Inject, Permission::Fill]
            .into_iter()
            .map(|p| Rule::new(p, Effect::Deny)),
    );
    Policy {
        rules,
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
    let maple = login_item("Maple", "ana", "maple_ak_secret");
    let (maple_key, _) = server.create_item(&ana, &vault, &project, &maple).await;
    let rest = login_item("REST", "ana", "rest-token");
    let (rest_key, _) = server.create_item(&ana, &vault, &project, &rest).await;
    let proxy = TestAgent::new();
    server
        .register_agent_ok(&proxy, "ana@example.com", "proxy")
        .await;
    World {
        server,
        ana,
        vault,
        project,
        proxy,
        maple: (maple.id(), maple_key),
        rest: (rest.id(), rest_key),
    }
}

impl World {
    /// The proxy's `v: 4` grant, with local clients `claude-code` and
    /// `cursor` on `maple`, over `host` for the MCP profile.
    fn mcp_payload(&self, host: &str) -> GrantPayload {
        let signed = TestServer::build_item_grant(
            &self.ana,
            &self.proxy,
            1,
            mcp_policy(self.maple.0, self.rest.0, host),
            &[
                (&self.vault, &self.project, self.maple.0, &self.maple.1),
                (&self.vault, &self.project, self.rest.0, &self.rest.1),
            ],
            vec![
                profile("maple", self.maple.0, host, Some("/mcp")),
                profile("rest", self.rest.0, REST, None),
            ],
        );
        let mut payload: GrantPayload =
            serde_json::from_slice(signed.payload.as_bytes()).expect("payload");
        payload.local_clients = ["claude-code", "cursor"]
            .iter()
            .enumerate()
            .map(|(n, name)| LocalClient {
                name: (*name).into(),
                token_digest: Blob::new(vec![u8::try_from(n).expect("small") + 1; 32]),
                profiles: vec!["maple".into()],
            })
            .collect();
        payload.v = GRANT_PAYLOAD_VERSION_MCP;
        payload
    }

    async fn post(&self, payload: &GrantPayload) -> StatusCode {
        let grant = TestServer::sign_payload(&self.ana, &self.proxy, payload);
        self.server
            .post_grant(&self.ana, &self.proxy, &grant)
            .await
            .status()
    }

    async fn granted(self) -> Self {
        assert_eq!(self.post(&self.mcp_payload(MAPLE)).await, StatusCode::OK);
        self
    }

    async fn switch_on(&self) -> McpGatewaySwitch {
        let res = self
            .server
            .post_auth(&self.ana, "/v1/account/mcp-gateway")
            .send()
            .await
            .expect("request");
        assert_eq!(res.status(), StatusCode::OK);
        res.json().await.expect("switch")
    }

    async fn switch(&self) -> McpGatewaySwitch {
        let res = self
            .server
            .get_auth(&self.ana, "/v1/account/mcp-gateway")
            .send()
            .await
            .expect("request");
        assert_eq!(res.status(), StatusCode::OK);
        res.json().await.expect("switch")
    }

    async fn me(&self) -> Value {
        let res = self
            .server
            .agent_call(&self.proxy, Method::GET, "/v1/agent/me", None)
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        res.json().await.expect("me")
    }

    async fn access(&self, body: Value) -> reqwest::Response {
        self.server
            .agent_call(&self.proxy, Method::POST, "/v1/agent/access", Some(&body))
            .await
    }

    /// A proxied call on `maple`'s endpoint, with a tool and its argument
    /// digest (`args` makes the digest) and whatever `extra` adds.
    fn call(&self, tool: Option<&str>, args: u8, extra: Value) -> Value {
        let mut claims = json!({"domain": MAPLE, "method": "POST", "path": "/mcp"});
        if let Some(tool) = tool {
            claims["mcp_tool"] = tool.into();
            claims["mcp_args"] = digest_text(&[args; 32]).into();
        }
        let mut body = json!({
            "item_id": self.maple.0,
            "permission": "proxy",
            "reason": "look at the logs",
            "claims": claims,
        });
        if let Value::Object(extra) = extra {
            body.as_object_mut().expect("object").extend(extra);
        }
        body
    }

    async fn status(&self, body: Value) -> StatusCode {
        self.access(body).await.status()
    }

    async fn pending(&self, body: Value) -> ApprovalId {
        let res = self.access(body).await;
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let v: Value = res.json().await.expect("pending");
        v["pending_approval_id"]
            .as_str()
            .expect("id")
            .parse()
            .expect("approval id")
    }

    async fn approval(&self, id: ApprovalId) -> (ApprovalInfo, ApprovalRequest, Value) {
        let res = self
            .server
            .get_auth(&self.ana, &format!("/v1/approvals/{id}"))
            .send()
            .await
            .expect("request");
        assert_eq!(res.status(), StatusCode::OK);
        let info: ApprovalInfo = res.json().await.expect("approval");
        let request: ApprovalRequest =
            serde_json::from_slice(info.request.as_bytes()).expect("request");
        let raw: Value = serde_json::from_slice(info.request.as_bytes()).expect("json");
        (info, request, raw)
    }

    async fn decide(&self, id: ApprovalId, lease_ms: i64) {
        let res = self.server.decide(&self.ana, id, true, lease_ms).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    async fn error_code(&self, body: Value) -> (StatusCode, String) {
        let res = self.access(body).await;
        let status = res.status();
        let v: Value = res.json().await.unwrap_or_default();
        (status, v["error"].as_str().unwrap_or_default().to_owned())
    }
}

#[tokio::test]
async fn with_the_switch_off_nothing_changes_and_the_new_fields_are_refused() {
    let w = world().await.granted().await;
    assert_eq!(
        w.switch().await,
        McpGatewaySwitch {
            mcp_gateway: false,
            since: None
        }
    );
    // `/v1/agent/me` says nothing of it: the same keys as before.
    let me = w.me().await;
    assert!(me.get("mcp_gateway").is_none(), "{me}");
    // A plain call on the REST profile, and the MCP session without a
    // tool or a client: as before.
    let rest = json!({
        "item_id": w.rest.0, "permission": "proxy", "reason": "list",
        "claims": {"domain": REST, "method": "GET", "path": "/v1/projects"},
    });
    assert_eq!(w.status(rest).await, StatusCode::OK);
    assert_eq!(w.status(w.call(None, 0, json!({}))).await, StatusCode::OK);
    // Every new field: `400 mcp_gateway_off`, never evaluated or logged.
    let mut wrong = Vec::new();
    for (what, body) in [
        ("a tool", w.call(Some("query_logs"), 1, json!({}))),
        (
            "a local client",
            w.call(None, 0, json!({"local_client": "cursor"})),
        ),
        ("a tool on fill", {
            let mut b = w.call(Some("query_logs"), 1, json!({}));
            b["permission"] = "fill".into();
            let claims = b["claims"].as_object_mut().expect("claims");
            claims.remove("method");
            claims.remove("path");
            b
        }),
    ] {
        let (status, code) = w.error_code(body.clone()).await;
        if (status, code.as_str()) != (StatusCode::BAD_REQUEST, "mcp_gateway_off") {
            wrong.push(format!("{what}: {status} {code}"));
        }
        w.server
            .refused_unlogged(
                &w.ana,
                what,
                StatusCode::BAD_REQUEST,
                w.access(body),
                &mut wrong,
            )
            .await;
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
    // An approval asked with the switch off carries no `caller`: its bytes
    // are what older devices read.
    let mut ask = w.payload_with_rest_ask();
    ask.v = GRANT_PAYLOAD_VERSION_MCP;
    assert_eq!(w.post(&ask).await, StatusCode::OK);
    let rest_ask = json!({
        "item_id": w.rest.0, "permission": "proxy", "reason": "deploy",
        "claims": {"domain": REST, "method": "POST", "path": "/v1/deploy"},
    });
    let id = w.pending(rest_ask).await;
    let (_, request, raw) = w.approval(id).await;
    assert!(request.caller.is_none());
    assert!(raw.get("caller").is_none(), "{raw}");
    assert!(w.server.proofs_the_log_refuses(&w.ana).await.is_empty());
}

impl World {
    /// The `v: 4` grant with an `ask` rule on the REST profile for POST.
    fn payload_with_rest_ask(&self) -> GrantPayload {
        let mut payload = self.mcp_payload(MAPLE);
        payload.version = 2;
        let mut ask = base(self.rest.0, REST, "/v1/deploy");
        ask.methods = vec![HttpMethod::parse("POST").expect("method")];
        payload.policy.rules.push(rule(Effect::Ask, ask));
        payload
    }
}

#[tokio::test]
async fn the_switch_turns_on_once_by_the_person_only() {
    let w = world().await.granted().await;
    // Not by an agent: it has no session.
    let res = w
        .server
        .agent_call(&w.proxy, Method::POST, "/v1/account/mcp-gateway", None)
        .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert!(!w.switch().await.mcp_gateway);
    let on = w.switch_on().await;
    assert!(on.mcp_gateway);
    let since = on.since.expect("since");
    // Again: still on, from the first time. Nothing turns it off.
    assert_eq!(w.switch_on().await.since, Some(since));
    assert_eq!(w.switch().await.since, Some(since));
    let res = w
        .server
        .delete_auth(&w.ana, "/v1/account/mcp-gateway")
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(w.me().await["mcp_gateway"], json!(true));
}

#[tokio::test]
async fn a_version_4_grant_is_checked_stored_and_handed_back_as_signed() {
    let w = world().await;
    let payload = w.mcp_payload(MAPLE);
    let signed = TestServer::sign_payload(&w.ana, &w.proxy, &payload);
    let res = w.server.post_grant(&w.ana, &w.proxy, &signed).await;
    assert_eq!(res.status(), StatusCode::OK);
    let me = w.me().await;
    let back: klav_proto::agent::SignedGrant =
        serde_json::from_value(me["grant"].clone()).expect("grant");
    assert_eq!(back, signed, "stored and handed back byte for byte");
    // Anything the format refuses, the server refuses.
    let mut wrong = Vec::new();
    let cases: Vec<(&str, GrantPayload)> = vec![
        ("v4 parts as v2", {
            let mut p = w.mcp_payload(MAPLE);
            p.v = 2;
            p
        }),
        ("tools on a REST item", {
            let mut p = w.mcp_payload(MAPLE);
            p.policy.rules.push(rule(
                Effect::Allow,
                Scope {
                    mcp_tools: tools(&["*"]),
                    ..base(w.rest.0, REST, "/v1")
                },
            ));
            p
        }),
        ("a client on a REST profile", {
            let mut p = w.mcp_payload(MAPLE);
            p.local_clients[0].profiles = vec!["rest".into()];
            p
        }),
        ("a client name out of grammar", {
            let mut p = w.mcp_payload(MAPLE);
            p.local_clients[0].name = "Claude Code".into();
            p
        }),
        ("an endpoint no rule reaches", {
            let mut p = w.mcp_payload(MAPLE);
            p.profiles[0].mcp.as_mut().expect("mcp").endpoint = "/other".into();
            p
        }),
    ];
    for (what, mut p) in cases {
        p.version = 2;
        let status = w.post(&p).await;
        if status != StatusCode::BAD_REQUEST {
            wrong.push(format!("{what}: {status}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[tokio::test]
async fn tool_calls_follow_the_signed_tool_rules_and_the_grammars() {
    let w = world().await.granted().await;
    w.switch_on().await;
    // The session, then tools by their rules.
    assert_eq!(w.status(w.call(None, 0, json!({}))).await, StatusCode::OK);
    for (tool, want) in [
        ("query_logs", StatusCode::OK),
        ("get_dashboard", StatusCode::OK),
        ("delete_dashboard", StatusCode::ACCEPTED),
        ("get_api_key", StatusCode::FORBIDDEN),
        ("run_query", StatusCode::FORBIDDEN),
        ("Get_logs", StatusCode::FORBIDDEN),
    ] {
        assert_eq!(
            w.status(w.call(Some(tool), 1, json!({}))).await,
            want,
            "{tool}"
        );
    }
    // T260: out of their grammars, `400` before anything is logged.
    let mut wrong = Vec::new();
    let with = |edit: &dyn Fn(&mut Value)| {
        let mut b = w.call(Some("query_logs"), 1, json!({}));
        edit(&mut b);
        b
    };
    for (what, body) in [
        (
            "a space",
            with(&|b| b["claims"]["mcp_tool"] = "query logs".into()),
        ),
        (
            "bidi",
            with(&|b| b["claims"]["mcp_tool"] = "q\u{202e}l".into()),
        ),
        (
            "129 bytes",
            with(&|b| b["claims"]["mcp_tool"] = "a".repeat(129).into()),
        ),
        (
            "no args",
            with(&|b| {
                b["claims"]
                    .as_object_mut()
                    .expect("claims")
                    .remove("mcp_args");
            }),
        ),
        ("args alone", {
            let mut b = w.call(None, 0, json!({}));
            b["claims"]["mcp_args"] = digest_text(&[1; 32]).into();
            b
        }),
        (
            "args not a digest",
            with(&|b| b["claims"]["mcp_args"] = "abc".into()),
        ),
        (
            "a long path",
            with(&|b| {
                b["claims"]["path"] = format!("/mcp/{}", "a".repeat(64)).into();
            }),
        ),
        (
            "a client name",
            with(&|b| b["local_client"] = "Cursor".into()),
        ),
        (
            "an unknown client",
            with(&|b| b["local_client"] = "zed".into()),
        ),
        ("a client on a REST item", {
            let mut b = with(&|b| b["local_client"] = "cursor".into());
            b["item_id"] = w.rest.0.to_string().into();
            b["claims"] = json!({"domain": REST, "method": "GET", "path": "/v1/x"});
            b["claims"]["mcp_tool"] = "x".into();
            b["claims"]["mcp_args"] = digest_text(&[1; 32]).into();
            b
        }),
        ("a tool on fill", with(&|b| b["permission"] = "fill".into())),
    ] {
        w.server
            .refused_unlogged(
                &w.ana,
                what,
                StatusCode::BAD_REQUEST,
                w.access(body),
                &mut wrong,
            )
            .await;
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
    // A local client of the grant passes, and its call shows in the log
    // with the tool and the client, as the proxy signed them.
    assert_eq!(
        w.status(w.call(Some("query_logs"), 1, json!({"local_client": "cursor"})))
            .await,
        StatusCode::OK
    );
    let chain = w.server.chain_of(&w.ana).await;
    let last = chain.last().expect("an event");
    let body: Value = serde_json::from_slice(
        last.agent_proof
            .as_ref()
            .and_then(|p| p.body.as_ref())
            .expect("body")
            .as_bytes(),
    )
    .expect("json");
    assert_eq!(body["claims"]["mcp_tool"], "query_logs");
    assert_eq!(body["local_client"], "cursor");
    assert!(w.server.proofs_the_log_refuses(&w.ana).await.is_empty());
}

#[tokio::test]
async fn once_binds_the_arguments_and_a_lease_only_the_tool_and_the_caller() {
    let w = world().await.granted().await;
    w.switch_on().await;
    let deploy = |args, extra| w.call(Some("deploy_worker"), args, extra);
    // Approve once, for arguments A.
    let once = w.pending(deploy(1, json!({}))).await;
    // The same pending request for a retry with the same arguments, a new
    // one for other arguments.
    assert_eq!(w.pending(deploy(1, json!({}))).await, once);
    let other = w.pending(deploy(2, json!({}))).await;
    assert_ne!(other, once);
    w.decide(once, 0).await;
    // Named for other arguments: refused.
    let res = w.access(deploy(2, json!({"approval_id": once}))).await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
    // Arguments B are still pending; A passes, once.
    assert_eq!(w.status(deploy(2, json!({}))).await, StatusCode::ACCEPTED);
    let res = w.access(deploy(1, json!({}))).await;
    assert_eq!(res.status(), StatusCode::OK);
    let granted: Value = res.json().await.expect("granted");
    assert_eq!(granted["approval_id"], json!(once));
    assert_eq!(w.status(deploy(1, json!({}))).await, StatusCode::ACCEPTED);

    // A lease on B covers any arguments of the same tool…
    w.decide(other, 60_000).await;
    for args in [2, 3, 4] {
        let res = w.access(deploy(args, json!({}))).await;
        assert_eq!(res.status(), StatusCode::OK, "args {args}");
        let granted: Value = res.json().await.expect("granted");
        assert_eq!(granted["approval_id"], json!(other));
    }
    // …named too…
    assert_eq!(
        w.status(deploy(5, json!({"approval_id": other}))).await,
        StatusCode::OK
    );
    // …but never another tool, nor another caller.
    assert_eq!(
        w.status(w.call(Some("deploy_other"), 2, json!({}))).await,
        StatusCode::ACCEPTED
    );
    let by_cursor = w
        .pending(deploy(3, json!({"local_client": "cursor"})))
        .await;
    assert_ne!(by_cursor, other);
    assert_eq!(
        w.access(deploy(
            3,
            json!({"local_client": "cursor", "approval_id": other})
        ))
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    // A lease for one client does not serve the other.
    w.decide(by_cursor, 60_000).await;
    assert_eq!(
        w.status(deploy(9, json!({"local_client": "cursor"}))).await,
        StatusCode::OK
    );
    assert_eq!(
        w.status(deploy(9, json!({"local_client": "claude-code"})))
            .await,
        StatusCode::ACCEPTED
    );
    assert!(w.server.proofs_the_log_refuses(&w.ana).await.is_empty());
}

#[tokio::test]
async fn the_caller_is_signed_by_the_person_and_audited() {
    let w = world().await.granted().await;
    w.switch_on().await;
    let id = w
        .pending(w.call(
            Some("deploy_worker"),
            1,
            json!({"local_client": "claude-code"}),
        ))
        .await;
    let (info, request, raw) = w.approval(id).await;
    let caller = request.caller.expect("caller");
    assert_eq!(caller.local_client.as_deref(), Some("claude-code"));
    assert_eq!(caller.sandbox_id, None);
    assert_eq!(raw["caller"], json!({"local_client": "claude-code"}));
    assert_eq!(request.claims.mcp_tool.as_deref(), Some("deploy_worker"));
    assert_eq!(request.claims.mcp_args, Some(digest_text(&[1; 32])));
    // Without a caller (no sandbox, no client), still none.
    let plain = w.pending(w.call(Some("deploy_worker"), 2, json!({}))).await;
    assert!(w.approval(plain).await.1.caller.is_none());
    // The person signs those bytes, and the log keeps them.
    w.decide(id, 0).await;
    let chain = w.server.chain_of(&w.ana).await;
    let decided = chain
        .iter()
        .find(|e| e.action == "approval.decided" && e.approval_id == Some(id))
        .expect("decision logged");
    assert_eq!(
        decided.signed.as_ref().expect("signed").as_bytes(),
        info.request.as_bytes()
    );
}

/// The longest keys the gateway can make (a 253-byte host, a 128-byte
/// tool, a 32-byte client and a 64-byte endpoint) fit the approvals'
/// indexes, on Postgres too: the request waits for the person, and a lease
/// serves it.
#[tokio::test]
async fn the_longest_mcp_keys_fit_the_indexes() {
    let w = world().await;
    let host = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(host.len(), 253);
    let endpoint = format!("/{}", "m".repeat(63));
    let mut payload = w.mcp_payload(&host);
    payload.profiles[0].mcp.as_mut().expect("mcp").endpoint = endpoint.clone();
    for r in &mut payload.policy.rules {
        if r.scope.items == vec![w.maple.0] {
            r.scope.path_prefixes = vec![PathPrefix::parse(&endpoint).expect("prefix")];
        }
    }
    payload.local_clients[0].name = "c".repeat(32);
    assert_eq!(w.post(&payload).await, StatusCode::OK);
    w.switch_on().await;
    let tool = format!("deploy_{}", "x".repeat(121));
    assert_eq!(tool.len(), 128);
    let body = |args: u8| {
        json!({
            "item_id": w.maple.0,
            "permission": "proxy",
            "reason": "deploy",
            "local_client": "c".repeat(32),
            "claims": {
                "domain": host, "method": "POST", "path": endpoint,
                "mcp_tool": tool, "mcp_args": digest_text(&[args; 32]),
            },
        })
    };
    let id = w.pending(body(1)).await;
    w.decide(id, 60_000).await;
    assert_eq!(w.status(body(2)).await, StatusCode::OK);
}
