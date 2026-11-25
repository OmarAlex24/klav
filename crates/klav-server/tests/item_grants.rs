//! Per-item grants against the real server (ADR 0036 §2, spec §13.4
//! `v: 2`): what a grant may say, what the proxy reaches through it and
//! nothing else, and a new item key that takes every attachment with it.
//! Runs on SQLite, and on Postgres when `KLAV_TEST_DATABASE_URL` says so.

mod common;

use common::TestServer;
use common::agent::{TestAgent, now_ms};
use common::client::Session;
use common::vault::{TestProject, TestVault, login_item, seal};
use klav_core::crypto::keys::{AttachmentKey, ItemKey};
use klav_core::crypto::share::share_project_key;
use klav_core::crypto::wrap::wrap_attachment_key;
use klav_core::ids::{AttachmentId, ItemId, VaultId};
use klav_core::model::item::{Item, SealedItem, open_item};
use klav_core::policy::{
    DomainPattern, Effect, HttpMethod, PathPrefix, Permission, Policy, Rule, Scope,
};
use klav_proto::Blob;
use klav_proto::agent::{
    AgentItems, AgentUpdateItem, GRANT_PAYLOAD_VERSION, GrantPayload, ProxyProfile,
};
use klav_proto::sync::Changes;
use klav_proto::vault::{RewrappedAttachmentKey, UpdateItem};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

const RAILWAY: &str = "backboard.railway.app";
const NORTHFLANK: &str = "api.northflank.com";

struct World {
    server: TestServer,
    ana: Session,
    vault: TestVault,
    project: TestProject,
    proxy: TestAgent,
    railway_item: Item,
    railway: (ItemId, ItemKey),
    northflank: (ItemId, ItemKey),
    /// In the same project, never granted.
    bank: ItemId,
}

fn rule(permission: Permission, effect: Effect, scope: Scope) -> Rule {
    Rule {
        scope,
        ..Rule::new(permission, effect)
    }
}

fn proxy_rule(item: ItemId, host: &str, methods: &[&str], prefixes: &[&str]) -> Rule {
    rule(
        Permission::Proxy,
        Effect::Allow,
        Scope {
            items: vec![item],
            domains: vec![DomainPattern::parse(host).expect("host")],
            methods: methods
                .iter()
                .map(|m| HttpMethod::parse(m).expect("method"))
                .collect(),
            path_prefixes: prefixes
                .iter()
                .map(|p| PathPrefix::parse(p).expect("prefix"))
                .collect(),
            ..Scope::default()
        },
    )
}

/// The rules every proxy grant carries: no value ever leaves.
fn no_values() -> Vec<Rule> {
    [Permission::Reveal, Permission::Inject, Permission::Fill]
        .into_iter()
        .map(|p| rule(p, Effect::Deny, Scope::default()))
        .collect()
}

fn proxy_policy(railway: ItemId, northflank: ItemId) -> Policy {
    let mut rules = vec![
        proxy_rule(railway, RAILWAY, &["POST"], &["/graphql"]),
        proxy_rule(northflank, NORTHFLANK, &["GET"], &["/v1/projects"]),
    ];
    rules.extend(no_values());
    Policy {
        rules,
        expires_at: None,
    }
}

fn profile(name: &str, item: ItemId, host: &str) -> ProxyProfile {
    ProxyProfile {
        name: name.into(),
        item_id: item,
        field: None,
        header: "authorization".into(),
        prefix: "Bearer ".into(),
        upstream: format!("https://{host}"),
        rate_per_minute: None,
        mcp: None,
    }
}

async fn world() -> World {
    let server = TestServer::start().await;
    let ana = server
        .login(&server.signup("ana@example.com", "pw").await, "laptop")
        .await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let railway = login_item("Railway", "ana", "railway-token");
    let (railway_key, _) = server.create_item(&ana, &vault, &project, &railway).await;
    let northflank = login_item("Northflank", "ana", "northflank-token");
    let (northflank_key, _) = server
        .create_item(&ana, &vault, &project, &northflank)
        .await;
    let bank = login_item("Bank", "ana", "s3cret");
    server.create_item(&ana, &vault, &project, &bank).await;
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
        railway: (railway.id(), railway_key),
        railway_item: railway,
        northflank: (northflank.id(), northflank_key),
        bank: bank.id(),
    }
}

impl World {
    fn grant(&self, version: u64) -> klav_proto::agent::SignedGrant {
        TestServer::build_item_grant(
            &self.ana,
            &self.proxy,
            version,
            proxy_policy(self.railway.0, self.northflank.0),
            &[
                (&self.vault, &self.project, self.railway.0, &self.railway.1),
                (
                    &self.vault,
                    &self.project,
                    self.northflank.0,
                    &self.northflank.1,
                ),
            ],
            vec![
                profile("railway", self.railway.0, RAILWAY),
                profile("northflank", self.northflank.0, NORTHFLANK),
            ],
        )
    }

    async fn granted(self) -> Self {
        let res = self
            .server
            .post_grant(&self.ana, &self.proxy, &self.grant(1))
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        self
    }

    /// The payload of a valid grant, to break one thing at a time.
    fn payload(&self) -> GrantPayload {
        serde_json::from_slice(self.grant(1).payload.as_bytes()).expect("payload")
    }

    async fn post(&self, payload: &GrantPayload) -> StatusCode {
        let grant = TestServer::sign_payload(&self.ana, &self.proxy, payload);
        self.server
            .post_grant(&self.ana, &self.proxy, &grant)
            .await
            .status()
    }

    async fn access(&self, item: ItemId, permission: &str, claims: Value) -> reqwest::Response {
        self.access_with(item, permission, claims, json!({})).await
    }

    async fn access_with(
        &self,
        item: ItemId,
        permission: &str,
        claims: Value,
        extra: Value,
    ) -> reqwest::Response {
        let mut body = json!({
            "item_id": item,
            "permission": permission,
            "reason": "deploy the API",
            "claims": claims,
        });
        if let Value::Object(extra) = extra {
            body.as_object_mut().expect("object").extend(extra);
        }
        self.server
            .agent_call(&self.proxy, Method::POST, "/v1/agent/access", Some(&body))
            .await
    }

    async fn call(&self, item: ItemId, host: &str, method: &str, path: &str) -> StatusCode {
        self.access(
            item,
            "proxy",
            json!({"domain": host, "method": method, "path": path}),
        )
        .await
        .status()
    }
}

#[tokio::test]
async fn a_per_item_grant_is_checked_when_uploaded() {
    let w = world().await;
    let (railway, northflank) = (w.railway.0, w.northflank.0);

    // Items need version 2: a version 1 grant cannot carry them.
    let mut p = w.payload();
    p.v = GRANT_PAYLOAD_VERSION;
    assert_eq!(w.post(&p).await, StatusCode::BAD_REQUEST);

    // An unknown version fails closed.
    let mut p = w.payload();
    p.v = 3;
    assert_eq!(w.post(&p).await, StatusCode::BAD_REQUEST);

    // Items or projects, never both.
    let mut p = w.payload();
    p.projects = serde_json::from_slice::<GrantPayload>(
        TestServer::build_grant(
            &w.ana,
            &w.proxy,
            1,
            Policy::default(),
            &[(&w.vault, &w.project)],
        )
        .payload
        .as_bytes(),
    )
    .expect("payload")
    .projects;
    assert_eq!(w.post(&p).await, StatusCode::BAD_REQUEST);

    // `proxy` with a value that could leave: refused.
    let mut p = w.payload();
    p.policy
        .rules
        .retain(|r| r.permission != Permission::Reveal);
    assert_eq!(w.post(&p).await, StatusCode::BAD_REQUEST);
    let mut p = w.payload();
    for r in &mut p.policy.rules {
        if r.permission == Permission::Inject {
            r.effect = Effect::Allow;
        }
    }
    assert_eq!(w.post(&p).await, StatusCode::BAD_REQUEST);

    // A proxy rule for any host, or for an item the grant does not share.
    let mut p = w.payload();
    p.policy.rules[0].scope.domains = vec![DomainPattern::parse("*").expect("any")];
    assert_eq!(w.post(&p).await, StatusCode::BAD_REQUEST);
    let mut p = w.payload();
    p.policy.rules[0].scope.items = vec![w.bank];
    assert_eq!(w.post(&p).await, StatusCode::BAD_REQUEST);

    // HTTP dimensions only in proxy rules.
    let mut p = w.payload();
    p.policy.rules.push(rule(
        Permission::Totp,
        Effect::Allow,
        Scope {
            methods: vec![HttpMethod::parse("GET").expect("method")],
            ..Scope::default()
        },
    ));
    assert_eq!(w.post(&p).await, StatusCode::BAD_REQUEST);

    // A profile for an item the grant does not share, toward a host no
    // rule reaches, or twice the same name.
    let mut p = w.payload();
    p.profiles[0].item_id = w.bank;
    assert_eq!(w.post(&p).await, StatusCode::BAD_REQUEST);
    let mut p = w.payload();
    p.profiles[0].upstream = "https://evil.example.com".into();
    assert_eq!(w.post(&p).await, StatusCode::BAD_REQUEST);
    let mut p = w.payload();
    p.profiles[1].name = "railway".into();
    assert_eq!(w.post(&p).await, StatusCode::BAD_REQUEST);

    // The shared key must be an item key for HPKE (kind `0x23`): a project
    // key share (`0x21`) of the same length is refused.
    let mut p = w.payload();
    p.items[0].shared_key = Blob::new(
        share_project_key(
            w.proxy.keys.public(),
            &w.vault.project_ctx(w.project.id),
            &w.project.key,
        )
        .expect("share"),
    );
    assert_eq!(w.post(&p).await, StatusCode::BAD_REQUEST);

    // An item that is not there, or not in the project the grant names.
    let mut p = w.payload();
    p.items[0].item_id = ItemId::generate();
    p.policy.rules[0].scope.items = vec![p.items[0].item_id];
    p.profiles[0].item_id = p.items[0].item_id;
    assert_eq!(w.post(&p).await, StatusCode::BAD_REQUEST);
    let other = w.server.create_project(&w.ana, &w.vault).await;
    let mut p = w.payload();
    p.items[0].project_id = other.id;
    assert_eq!(w.post(&p).await, StatusCode::BAD_REQUEST);
    // ... or in a vault that is not the account's.
    let mut p = w.payload();
    p.items[0].vault_id = VaultId::generate();
    assert_ne!(w.post(&p).await, StatusCode::OK);

    // The well-formed one goes through, and the agent sees it as signed.
    assert_eq!(w.post(&w.payload()).await, StatusCode::OK);
    let me: klav_proto::agent::AgentMe = w
        .server
        .agent_call(&w.proxy, Method::GET, "/v1/agent/me", None)
        .await
        .json()
        .await
        .expect("me");
    let payload: GrantPayload =
        serde_json::from_slice(me.grant.expect("grant").payload.as_bytes()).expect("payload");
    assert_eq!(payload.v, 2);
    assert_eq!(
        payload.items.iter().map(|i| i.item_id).collect::<Vec<_>>(),
        vec![railway, northflank]
    );
    assert_eq!(payload.profiles.len(), 2);
}

#[tokio::test]
async fn the_proxy_reaches_only_its_items_where_the_rules_say() {
    let w = world().await.granted().await;
    let (railway, northflank) = (w.railway.0, w.northflank.0);

    // Allowed: the item comes with its details, and its key opens it.
    let res = w
        .access(
            railway,
            "proxy",
            json!({"domain": RAILWAY, "method": "POST", "path": "/graphql/v2"}),
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let granted: klav_proto::agent::AccessGranted = res.json().await.expect("granted");
    let wire = granted.item;
    let item = open_item(
        &w.railway.1,
        &w.vault.item_ctx(w.project.id, railway),
        wire.version,
        &SealedItem {
            overview: wire.overview.expect("overview").into_bytes(),
            details: wire.details.expect("details").into_bytes(),
        },
    )
    .expect("the shared key opens it");
    assert_eq!(item.id(), railway);
    assert!(granted.attachments.is_empty());

    // Host, method and path bind the call, and so does the item: the
    // Northflank rule never sends the Railway token.
    for (host, method, path) in [
        (RAILWAY, "POST", "/graphqlx"),
        (RAILWAY, "POST", "/"),
        (RAILWAY, "GET", "/graphql"),
        (RAILWAY, "post", "/graphql"),
        ("evil.example.com", "POST", "/graphql"),
        (NORTHFLANK, "GET", "/v1/projects"),
    ] {
        let status = w.call(railway, host, method, path).await;
        assert!(
            status == StatusCode::FORBIDDEN || status == StatusCode::BAD_REQUEST,
            "{host} {method} {path}: {status}"
        );
    }
    assert_eq!(
        w.call(northflank, NORTHFLANK, "GET", "/v1/projects/abc")
            .await,
        StatusCode::OK
    );

    // Ambiguous paths are refused, not normalized.
    for path in [
        "/graphql/../admin",
        "/graphql?x=1",
        "/graphql//x",
        "/graphql/%2e%2e/admin",
        "graphql",
    ] {
        assert_eq!(
            w.call(railway, RAILWAY, "POST", path).await,
            StatusCode::BAD_REQUEST,
            "{path}"
        );
    }

    // A proxied call says where it goes, takes no file, and nothing else
    // names a method or path.
    assert_eq!(
        w.access(
            railway,
            "proxy",
            json!({"domain": RAILWAY, "path": "/graphql"})
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        w.access_with(
            railway,
            "proxy",
            json!({"domain": RAILWAY, "method": "POST", "path": "/graphql"}),
            json!({"include_attachments": true}),
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        w.access(railway, "totp", json!({"method": "GET", "path": "/"}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );

    // Only what was granted, and only through `proxy`.
    assert_eq!(
        w.call(w.bank, RAILWAY, "POST", "/graphql").await,
        StatusCode::NOT_FOUND
    );
    for permission in ["reveal", "inject", "fill", "totp", "list"] {
        let status = w
            .access(railway, permission, json!({"domain": RAILWAY}))
            .await
            .status();
        assert!(
            status == StatusCode::NOT_FOUND || status == StatusCode::FORBIDDEN,
            "{permission}: {status}"
        );
    }
    let items: AgentItems = w
        .server
        .agent_call(&w.proxy, Method::GET, "/v1/agent/items", None)
        .await
        .json()
        .await
        .expect("items");
    assert!(items.projects.is_empty());

    // The item in the trash is out of reach.
    let res = w
        .server
        .delete_auth(
            &w.ana,
            &format!("/v1/vaults/{}/items/{railway}", w.vault.id),
        )
        .send()
        .await
        .expect("trash");
    assert!(res.status().is_success(), "{}", res.status());
    assert_eq!(
        w.call(railway, RAILWAY, "POST", "/graphql").await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn revoking_the_proxy_cuts_its_next_call() {
    use klav_core::crypto::agent::sign_revocation;
    use klav_proto::agent::RevokeAgent;

    let w = world().await.granted().await;
    let railway = w.railway.0;
    assert_eq!(
        w.call(railway, RAILWAY, "POST", "/graphql").await,
        StatusCode::OK
    );
    let at = now_ms();
    let res = w
        .server
        .post_auth(&w.ana, &format!("/v1/agents/{}/revoke", w.proxy.id))
        .json(&RevokeAgent {
            revoked_at: at,
            signature: Blob::new(
                sign_revocation(
                    &w.ana.identity,
                    w.ana.account_id,
                    w.proxy.id,
                    u64::try_from(at).expect("time"),
                )
                .to_bytes()
                .to_vec(),
            ),
        })
        .send()
        .await
        .expect("revoke");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        w.call(railway, RAILWAY, "POST", "/graphql").await,
        StatusCode::FORBIDDEN
    );
}

/// The next version of the Railway item under `new_key`.
async fn rekeyed(
    w: &World,
    version: u64,
    new_key: &ItemKey,
    attachment_keys: Option<Vec<RewrappedAttachmentKey>>,
) -> UpdateItem {
    let upload = seal(&w.vault, &w.project, &w.railway_item, new_key, version);
    UpdateItem {
        version,
        wrapped_key: Blob::new(upload.wrapped_key),
        project_version: w.server.project_version(&w.ana, &w.vault, &w.project).await,
        overview: Blob::new(upload.sealed.overview),
        details: Blob::new(upload.sealed.details),
        attachment_keys,
    }
}

async fn put(w: &World, body: &UpdateItem) -> StatusCode {
    w.server
        .put_auth(
            &w.ana,
            &format!("/v1/vaults/{}/items/{}", w.vault.id, w.railway.0),
        )
        .json(body)
        .send()
        .await
        .expect("put")
        .status()
}

fn rewrap(w: &World, id: AttachmentId, key: &ItemKey) -> RewrappedAttachmentKey {
    let ctx = w.vault.item_ctx(w.project.id, w.railway.0).attachment(id);
    RewrappedAttachmentKey {
        attachment_id: id,
        wrapped_key: Blob::new(wrap_attachment_key(key, &ctx, &AttachmentKey::generate())),
    }
}

async fn changes(w: &World, since: u64) -> Changes {
    let res = w
        .server
        .get_auth(
            &w.ana,
            &format!("/v1/vaults/{}/changes?since={since}", w.vault.id),
        )
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::OK);
    res.json().await.expect("changes")
}

#[tokio::test]
async fn a_new_item_key_takes_every_attachment_with_it() {
    let w = world().await;
    let item = w.railway.0;
    let one = w
        .server
        .upload_attachment(&w.ana, &w.vault, &w.project, item, b"one", true)
        .await;
    let two = w
        .server
        .upload_attachment(&w.ana, &w.vault, &w.project, item, b"two", true)
        .await;
    let before = changes(&w, 0).await;
    let new_key = ItemKey::generate();

    // Missing one, an unknown one, twice the same, none: refused.
    for keys in [
        vec![rewrap(&w, one, &new_key)],
        vec![
            rewrap(&w, one, &new_key),
            rewrap(&w, two, &new_key),
            rewrap(&w, AttachmentId::generate(), &new_key),
        ],
        vec![rewrap(&w, one, &new_key), rewrap(&w, one, &new_key)],
        Vec::new(),
    ] {
        let body = rekeyed(&w, 2, &new_key, Some(keys)).await;
        assert_eq!(put(&w, &body).await, StatusCode::CONFLICT);
    }
    // A key of the wrong kind.
    let mut bad = rewrap(&w, two, &new_key);
    bad.wrapped_key = Blob::new(vec![0x01; bad.wrapped_key.as_bytes().len()]);
    let body = rekeyed(&w, 2, &new_key, Some(vec![rewrap(&w, one, &new_key), bad])).await;
    assert_eq!(put(&w, &body).await, StatusCode::BAD_REQUEST);

    // An upload in progress holds a key wrapped with the old item key.
    w.server
        .upload_attachment(&w.ana, &w.vault, &w.project, item, b"three", false)
        .await;
    let all = vec![rewrap(&w, one, &new_key), rewrap(&w, two, &new_key)];
    let body = rekeyed(&w, 2, &new_key, Some(all.clone())).await;
    assert_eq!(put(&w, &body).await, StatusCode::CONFLICT);

    // Nothing above changed anything.
    let unchanged = changes(&w, before.revision).await;
    assert!(unchanged.items.is_empty() && unchanged.attachments.is_empty());

    // Agents never change an item's key.
    let agent = TestAgent::new();
    w.server
        .register_agent_ok(&agent, "ana@example.com", "bot")
        .await;
    let grant = TestServer::build_grant(
        &w.ana,
        &agent,
        1,
        Policy::default(),
        &[(&w.vault, &w.project)],
    );
    assert_eq!(
        w.server.post_grant(&w.ana, &agent, &grant).await.status(),
        StatusCode::OK
    );
    let update = AgentUpdateItem {
        item: rekeyed(&w, 2, &new_key, Some(all.clone())).await,
        reason: "tidy".into(),
        claims: klav_proto::agent::Claims::default(),
        approval_id: None,
        task_id: None,
    };
    let res = w
        .server
        .agent_call(
            &agent,
            Method::PUT,
            &format!("/v1/agent/items/{item}"),
            Some(&serde_json::to_value(&update).expect("json")),
        )
        .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_new_item_key_is_stored_with_its_attachments_in_one_revision() {
    let w = world().await;
    let item = w.railway.0;
    let one = w
        .server
        .upload_attachment(&w.ana, &w.vault, &w.project, item, b"one", true)
        .await;
    let two = w
        .server
        .upload_attachment(&w.ana, &w.vault, &w.project, item, b"two", true)
        .await;
    let before = changes(&w, 0).await;
    let new_key = ItemKey::generate();
    let all = vec![rewrap(&w, one, &new_key), rewrap(&w, two, &new_key)];
    let body = rekeyed(&w, 2, &new_key, Some(all.clone())).await;
    assert_eq!(put(&w, &body).await, StatusCode::OK);

    let after = changes(&w, before.revision).await;
    let wire = after.items.iter().find(|i| i.id == item).expect("item");
    assert_eq!(wire.version, 2);
    for sent in &all {
        let a = after
            .attachments
            .iter()
            .find(|a| a.id == sent.attachment_id)
            .expect("attachment changed");
        assert_eq!(a.wrapped_key.as_ref(), Some(&sent.wrapped_key));
        assert_eq!(a.revision, wire.revision);
    }

    // An edit that keeps the key leaves the attachments alone.
    let res = w
        .server
        .put_item(&w.ana, &w.vault, &w.project, &w.railway_item, &new_key, 3)
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let later = changes(&w, after.revision).await;
    assert!(later.attachments.is_empty());
}

/// How many audit events and approval requests the account has.
async fn logged(w: &World) -> (usize, usize) {
    let audit: klav_proto::audit::AuditPage = w
        .server
        .get_auth(&w.ana, "/v1/audit?after=0")
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("audit");
    let approvals: klav_proto::agent::ApprovalList = w
        .server
        .get_auth(&w.ana, "/v1/approvals")
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("approvals");
    (audit.entries.len(), approvals.approvals.len())
}

/// `method` and `path` belong to `proxy` only: on every other agent route
/// they are refused before anything is stored. An older `klav log verify`
/// or approvals list could not read them, and the event they would leave
/// cannot be taken out of the hash chain.
#[tokio::test]
async fn method_and_path_are_refused_outside_proxy() {
    let w = world().await;
    // An ordinary agent with a project grant that asks for everything, so
    // that a request that got through would leave an approval behind.
    let bot = TestAgent::new();
    w.server
        .register_agent_ok(&bot, "ana@example.com", "bot")
        .await;
    let ask = [
        Permission::Fill,
        Permission::Inject,
        Permission::Totp,
        Permission::Reveal,
        Permission::Create,
        Permission::Update,
        Permission::Delete,
    ]
    .into_iter()
    .map(|p| rule(p, Effect::Ask, Scope::default()))
    .collect();
    let grant = TestServer::build_grant(
        &w.ana,
        &bot,
        1,
        Policy {
            rules: ask,
            expires_at: None,
        },
        &[(&w.vault, &w.project)],
    );
    assert_eq!(
        w.server.post_grant(&w.ana, &bot, &grant).await.status(),
        StatusCode::OK
    );
    let http = json!({"domain": RAILWAY, "method": "GET", "path": "/x"});
    let only_method = json!({"method": "GET"});
    let before = logged(&w).await;

    let key = ItemKey::generate();
    let new = login_item("New", "u", "p");
    let upload = seal(&w.vault, &w.project, &new, &key, 1);
    let update = seal(&w.vault, &w.project, &w.railway_item, &w.railway.1, 2);
    let mut calls: Vec<(Method, String, Value)> = Vec::new();
    for permission in [
        "list", "fill", "inject", "totp", "reveal", "update", "passkey", "rotate",
    ] {
        for claims in [&http, &only_method] {
            calls.push((
                Method::POST,
                "/v1/agent/access".into(),
                json!({"item_id": w.bank, "permission": permission, "reason": "r", "claims": claims}),
            ));
        }
    }
    calls.push((
        Method::POST,
        "/v1/agent/items".into(),
        json!({
            "vault_id": w.vault.id, "reason": "r", "claims": http,
            "item": {
                "id": new.id(), "project_id": w.project.id, "version": 1,
                "wrapped_key": Blob::new(upload.wrapped_key),
                "project_version": 1,
                "overview": Blob::new(upload.sealed.overview),
                "details": Blob::new(upload.sealed.details),
            },
        }),
    ));
    calls.push((
        Method::PUT,
        format!("/v1/agent/items/{}", w.railway.0),
        json!({
            "reason": "r", "claims": http,
            "item": {
                "version": 2,
                "wrapped_key": Blob::new(update.wrapped_key),
                "project_version": 1,
                "overview": Blob::new(update.sealed.overview),
                "details": Blob::new(update.sealed.details),
            },
        }),
    ));
    calls.push((
        Method::POST,
        format!("/v1/agent/items/{}/trash", w.bank),
        json!({"reason": "r", "claims": http}),
    ));
    for (permission, item) in [
        ("update", Some(w.bank)),
        ("delete", Some(w.bank)),
        ("create", None),
    ] {
        calls.push((
            Method::POST,
            "/v1/agent/approvals".into(),
            json!({
                "permission": permission, "vault_id": w.vault.id, "project_id": w.project.id,
                "item_id": item, "reason": "r", "claims": http,
            }),
        ));
    }
    calls.push((
        Method::POST,
        "/v1/agent/rotations".into(),
        json!({"item_id": w.bank, "reason": "r", "claims": http}),
    ));
    for (method, path, body) in calls {
        let res = w
            .server
            .agent_call(&bot, method.clone(), &path, Some(&body))
            .await;
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "{method} {path} {body}"
        );
        // Refused for the method and path, not for another reason the
        // route would also have (`passkey` and `rotate` are task-only).
        let error: Value = res.json().await.expect("error body");
        assert!(
            error["message"]
                .as_str()
                .is_some_and(|m| m.contains("only for proxy")),
            "{method} {path} {body}: {error}"
        );
    }
    assert_eq!(logged(&w).await, before, "nothing was logged or asked");
}

/// Declares an attachment of the Railway item wrapped with `key`, saying
/// the item version the client saw.
async fn declare(w: &World, id: AttachmentId, key: &ItemKey, seen: Option<u64>) -> StatusCode {
    let ctx = w.vault.item_ctx(w.project.id, w.railway.0).attachment(id);
    w.server
        .post_auth(
            &w.ana,
            &format!(
                "/v1/vaults/{}/items/{}/attachments",
                w.vault.id, w.railway.0
            ),
        )
        .json(&klav_proto::sync::CreateAttachment {
            id,
            size: 64,
            wrapped_key: Blob::new(wrap_attachment_key(key, &ctx, &AttachmentKey::generate())),
            item_version: seen,
        })
        .send()
        .await
        .expect("declare")
        .status()
}

/// An upload declared around a new item key never ends up wrapped with the
/// old key: whichever commits first, the other is refused (`409`). Both
/// requests serialize on the vault's lock.
#[tokio::test]
async fn an_upload_declared_during_a_new_item_key_is_refused() {
    let w = world().await;
    let delete = |id: AttachmentId| {
        w.server
            .delete_auth(
                &w.ana,
                &format!("/v1/vaults/{}/attachments/{id}", w.vault.id),
            )
            .send()
    };

    // The new key first: a client that still has version 1 is refused,
    // and one that synced (version 2) is not.
    let key2 = ItemKey::generate();
    assert_eq!(
        put(&w, &rekeyed(&w, 2, &key2, Some(Vec::new())).await).await,
        StatusCode::OK
    );
    assert_eq!(
        declare(&w, AttachmentId::generate(), &w.railway.1, Some(1)).await,
        StatusCode::CONFLICT
    );
    let fresh = AttachmentId::generate();
    assert_eq!(
        declare(&w, fresh, &key2, Some(2)).await,
        StatusCode::CREATED
    );
    // The upload first: the new key finds it in progress.
    let key3 = ItemKey::generate();
    assert_eq!(
        put(&w, &rekeyed(&w, 3, &key3, Some(Vec::new())).await).await,
        StatusCode::CONFLICT
    );
    assert!(delete(fresh).await.expect("delete").status().is_success());
    // Without `item_version`, nothing is checked (older clients).
    let old = AttachmentId::generate();
    assert_eq!(
        declare(&w, old, &w.railway.1, None).await,
        StatusCode::CREATED
    );
    assert!(delete(old).await.expect("delete").status().is_success());

    // At the same moment, many times: never both.
    let mut version = 2;
    for _ in 0..12 {
        let next = ItemKey::generate();
        let id = AttachmentId::generate();
        let body = rekeyed(&w, version + 1, &next, Some(Vec::new())).await;
        let (rekey, upload) = tokio::join!(put(&w, &body), declare(&w, id, &key2, Some(version)));
        match (rekey, upload) {
            (StatusCode::OK, StatusCode::CONFLICT) => version += 1,
            (StatusCode::CONFLICT, StatusCode::CREATED) => {
                assert!(delete(id).await.expect("delete").status().is_success());
            }
            other => panic!("rekey and upload: {other:?}"),
        }
    }
}

/// `proxy` under `ask`, end to end: the call waits for the person, the
/// approval is for exactly that method and path, and the same call uses it
/// once (ADR 0015 §2, ADR 0036 §9).
#[tokio::test]
async fn a_proxied_call_under_ask_waits_and_its_approval_fits_only_itself() {
    let w = world().await;
    let mut rules = vec![rule(
        Permission::Proxy,
        Effect::Ask,
        Scope {
            items: vec![w.railway.0],
            domains: vec![DomainPattern::parse(RAILWAY).expect("host")],
            path_prefixes: vec![PathPrefix::parse("/v1").expect("prefix")],
            ..Scope::default()
        },
    )];
    rules.extend(no_values());
    let grant = TestServer::build_item_grant(
        &w.ana,
        &w.proxy,
        1,
        Policy {
            rules,
            expires_at: None,
        },
        &[(&w.vault, &w.project, w.railway.0, &w.railway.1)],
        vec![profile("railway", w.railway.0, RAILWAY)],
    );
    assert_eq!(
        w.server.post_grant(&w.ana, &w.proxy, &grant).await.status(),
        StatusCode::OK
    );
    let call = |method: &'static str, path: &'static str, approval: Option<String>| {
        let mut extra = json!({});
        if let Some(id) = approval {
            extra = json!({"approval_id": id});
        }
        w.access_with(
            w.railway.0,
            "proxy",
            json!({"domain": RAILWAY, "method": method, "path": path}),
            extra,
        )
    };
    // Pending.
    let res = call("GET", "/v1/a", None).await;
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let pending: Value = res.json().await.expect("pending");
    let id = pending["pending_approval_id"]
        .as_str()
        .expect("approval")
        .to_owned();
    let shown: klav_proto::agent::ApprovalInfo = w
        .server
        .get_auth(&w.ana, &format!("/v1/approvals/{id}"))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("approval");
    let request: klav_proto::agent::ApprovalRequest =
        serde_json::from_slice(shown.request.as_bytes()).expect("request");
    assert_eq!(request.claims.method.as_deref(), Some("GET"));
    assert_eq!(request.claims.path.as_deref(), Some("/v1/a"));
    // Approved once.
    let decided = w
        .server
        .decide(&w.ana, id.parse().expect("id"), true, 0)
        .await;
    assert_eq!(decided.status(), StatusCode::OK);
    // Another method or another path is not what was approved: naming the
    // approval is refused, and without it the person is asked again.
    for (method, path) in [("DELETE", "/v1/a"), ("GET", "/v1/b")] {
        let named = call(method, path, Some(id.clone())).await;
        assert!(
            !named.status().is_success(),
            "{method} {path} used the approval of GET /v1/a"
        );
        assert_eq!(
            call(method, path, None).await.status(),
            StatusCode::ACCEPTED,
            "{method} {path}"
        );
    }
    // The approved call goes through, with that approval, once.
    let res = call("GET", "/v1/a", None).await;
    assert_eq!(res.status(), StatusCode::OK);
    let granted: Value = res.json().await.expect("granted");
    assert_eq!(granted["approval_id"].as_str(), Some(id.as_str()));
    assert_eq!(
        call("GET", "/v1/a", None).await.status(),
        StatusCode::ACCEPTED
    );
}

/// A proxied path with a `"` is refused (`400`) before anything is
/// evaluated or stored. The approval's `target_key` is JSON, where each
/// `"` takes two bytes: on Postgres, a long path full of them overflowed
/// the index of pending approvals (2704 bytes) and answered `500`. The
/// longest canonical path without one still fits and waits for the person.
#[tokio::test]
async fn a_proxied_path_with_a_double_quote_is_refused_before_any_approval() {
    let w = world().await;
    let mut rules = vec![rule(
        Permission::Proxy,
        Effect::Ask,
        Scope {
            items: vec![w.railway.0],
            domains: vec![DomainPattern::parse(RAILWAY).expect("host")],
            path_prefixes: vec![PathPrefix::parse("/v1").expect("prefix")],
            ..Scope::default()
        },
    )];
    rules.extend(no_values());
    let grant = TestServer::build_item_grant(
        &w.ana,
        &w.proxy,
        1,
        Policy {
            rules,
            expires_at: None,
        },
        &[(&w.vault, &w.project, w.railway.0, &w.railway.1)],
        vec![profile("railway", w.railway.0, RAILWAY)],
    );
    assert_eq!(
        w.server.post_grant(&w.ana, &w.proxy, &grant).await.status(),
        StatusCode::OK
    );
    let call = |path: String| {
        w.access(
            w.railway.0,
            "proxy",
            json!({"domain": RAILWAY, "method": "POST", "path": path}),
        )
    };
    // The longest path the rule allows, of characters that do not repeat
    // in a pattern, so Postgres cannot compress the index entry.
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let longest = |quotes: bool| {
        let mut path = String::from("/v1/");
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        while path.len() < klav_core::policy::MAX_HTTP_PATH {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            path.push(if quotes && x.is_multiple_of(3) {
                '"'
            } else {
                ALPHABET[(x % 62) as usize] as char
            });
        }
        path
    };
    for path in ["/v1/a\"b".to_owned(), longest(true)] {
        let res = call(path.clone()).await;
        let status = res.status();
        let text = res.text().await.expect("body");
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{} bytes: {text}",
            path.len()
        );
        assert!(text.contains("must not contain"), "{text}");
    }
    let res = call(longest(false)).await;
    let status = res.status();
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "{}",
        res.text().await.expect("body")
    );
}

/// A new item key also reaches an item in the trash, which stays there;
/// every other write to it still waits for a restore.
#[tokio::test]
async fn a_new_item_key_reaches_an_item_in_the_trash() {
    let w = world().await;
    let item = w.railway.0;
    let trashed = w
        .server
        .delete_auth(&w.ana, &format!("/v1/vaults/{}/items/{item}", w.vault.id))
        .send()
        .await
        .expect("trash");
    assert!(trashed.status().is_success());
    let before = changes(&w, 0).await;
    let new_key = ItemKey::generate();
    // An ordinary edit: refused.
    let mut edit = rekeyed(&w, 2, &new_key, None).await;
    assert_eq!(put(&w, &edit).await, StatusCode::CONFLICT);
    // The new key: stored, still in the trash.
    edit.attachment_keys = Some(Vec::new());
    assert_eq!(put(&w, &edit).await, StatusCode::OK);
    let after = changes(&w, before.revision).await;
    let wire = after.items.iter().find(|i| i.id == item).expect("item");
    assert_eq!(wire.version, 2);
    assert!(wire.trashed_at.is_some(), "still in the trash");
    let was = before.items.iter().find(|i| i.id == item).expect("item");
    assert_eq!(wire.trashed_at, was.trashed_at, "trashed_at untouched");
}

/// A `v: 3` grant may only name agents of the same account (ADR 0036 §4,
/// spec §13.4): an issuer in the proxy's grant, and the proxy in an
/// issuer's. Only the account's signature makes either, so this guards
/// against a mistake, not an attacker; it is checked all the same.
#[tokio::test]
async fn a_sandbox_grant_naming_another_accounts_agent_is_refused() {
    use klav_proto::agent::{
        GRANT_PAYLOAD_VERSION_SANDBOXES, IssuerGrant, SandboxIssuer, SandboxProxy,
    };
    let w = world().await;
    w.server.signup("bob@example.com", "pw").await;
    let bobs = TestAgent::new();
    w.server
        .register_agent_ok(&bobs, "bob@example.com", "bob-agent")
        .await;
    let mine = TestAgent::new();
    w.server
        .register_agent_ok(&mine, "ana@example.com", "t3-code")
        .await;
    let base: GrantPayload =
        serde_json::from_slice(w.grant(1).payload.as_bytes()).expect("payload");
    let entry = |agent: &TestAgent| SandboxIssuer {
        agent_id: agent.id,
        public_identity: Blob::new(agent.keys.public().encode().to_vec()),
        profiles: vec!["railway".into()],
        max_ttl_secs: 3600,
        max_live: 3,
    };
    let proxy_with = |issuer: &TestAgent| GrantPayload {
        v: GRANT_PAYLOAD_VERSION_SANDBOXES,
        issuers: vec![entry(issuer)],
        ..base.clone()
    };
    let issuer_naming = |proxy: &TestAgent| GrantPayload {
        v: GRANT_PAYLOAD_VERSION_SANDBOXES,
        account_id: w.ana.account_id,
        agent_id: mine.id,
        version: 1,
        issued_at: now_ms(),
        policy: Policy::default(),
        projects: Vec::new(),
        items: Vec::new(),
        profiles: Vec::new(),
        issuers: Vec::new(),
        sandbox: Some(IssuerGrant {
            proxy: Some(SandboxProxy {
                agent_id: proxy.id,
                public_identity: Blob::new(proxy.keys.public().encode().to_vec()),
                url: "tls://proxy.example.com:8443".into(),
            }),
        }),
        local_clients: Vec::new(),
    };
    let post = |agent: &TestAgent, payload: &GrantPayload| {
        let signed = TestServer::sign_payload(&w.ana, agent, payload);
        let server = &w.server;
        let ana = &w.ana;
        let agent = agent.id;
        async move {
            server
                .post_auth(ana, &format!("/v1/agents/{agent}/grant"))
                .json(&signed)
                .send()
                .await
                .expect("request")
        }
    };
    // Bob's agent, or an agent no account has, as Ana's issuer or as her
    // issuer's proxy: refused, each with the reason.
    let unknown = TestAgent::new();
    for (agent, payload) in [
        (&w.proxy, proxy_with(&bobs)),
        (&mine, issuer_naming(&bobs)),
        (&w.proxy, proxy_with(&unknown)),
        (&mine, issuer_naming(&unknown)),
    ] {
        let res = post(agent, &payload).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let text = res.text().await.unwrap();
        assert!(text.contains("not an agent of this account"), "{text}");
    }
    // Her own agents: accepted.
    assert!(
        post(&mine, &issuer_naming(&w.proxy))
            .await
            .status()
            .is_success()
    );
    assert!(
        post(&w.proxy, &proxy_with(&mine))
            .await
            .status()
            .is_success()
    );
}
