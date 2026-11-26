//! Klav Cloud's hosted proxy on the server (ADR 0051 §3.5, §8, §9): the
//! per-account entitlement and `klav-server hosted-proxy`, hosted
//! registrations signed by the enclave's service key, `hosted_proxy` in
//! `GET /v1/agent/me`, and everything else staying as it was.

mod common;

use common::TestServer;
use common::agent::TestAgent;
use common::client::Session;
use klav_core::crypto::hosted::{HostedRegistration, sign_registration};
use klav_core::crypto::identity::IdentityKeyPair;
use klav_core::ids::AccountId;
use klav_proto::Blob;
use klav_proto::agent::{
    AgentList, AgentMe, HostedProxyStatus, HostedRegistrationProof, RegisterHostedAgent,
};
use klav_server::Config;
use klav_server::hosted_proxy::{self, Command};
use reqwest::{Method, StatusCode};
use serde_json::Value;

/// A server configured with the Ed25519 public key of the hosted proxy's
/// service key, as `api.klav.dev` will be.
async fn hosted_server(service: &IdentityKeyPair) -> TestServer {
    let key = data_encoding::HEXLOWER.encode(service.public().ed25519());
    TestServer::start_with(|c| c.hosted_proxy.service_key = Some(key)).await
}

/// `klav-server hosted-proxy …` against the server's database.
async fn admin(server: &TestServer, command: Command) -> Result<String, String> {
    let config = Config {
        database_url: server.database_url.clone(),
        ..Config::default()
    };
    hosted_proxy::run(&config, command).await
}

async fn enable(server: &TestServer, email: &str) -> String {
    admin(
        server,
        Command::Enable {
            email: email.into(),
        },
    )
    .await
    .expect("enable")
}

async fn disable(server: &TestServer, email: &str) -> String {
    admin(
        server,
        Command::Disable {
            email: email.into(),
        },
    )
    .await
    .expect("disable")
}

/// What the enclave sends for `agent`: marked by `service` over the fields
/// as given, then possibly changed on the way.
fn hosted_body(
    service: &IdentityKeyPair,
    agent: &TestAgent,
    account: AccountId,
    email: &str,
    generation: u32,
) -> RegisterHostedAgent {
    let signature = sign_registration(
        service,
        &HostedRegistration {
            account,
            agent: agent.id,
            agent_keys: agent.keys.public(),
            generation,
        },
    );
    RegisterHostedAgent {
        id: agent.id,
        email: email.into(),
        name: "Klav Cloud proxy".into(),
        public_identity: Blob::new(agent.keys.public().encode().to_vec()),
        note: None,
        hosted: Some(HostedRegistrationProof {
            account_id: account,
            generation,
            signature: Blob::new(signature.to_bytes().to_vec()),
        }),
    }
}

async fn register(server: &TestServer, body: &RegisterHostedAgent) -> (StatusCode, Value) {
    let res = server.post_json("/v1/agents/register", body).await;
    let status = res.status();
    (status, res.json().await.unwrap_or(Value::Null))
}

/// `GET /v1/agent/me`, parsed and as sent.
async fn me(server: &TestServer, agent: &TestAgent) -> (AgentMe, String) {
    let res = server
        .agent_call(agent, Method::GET, "/v1/agent/me", None)
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let text = res.text().await.expect("body");
    (serde_json::from_str(&text).expect("me"), text)
}

async fn entitlement(server: &TestServer, session: &Session) -> HostedProxyStatus {
    let res = server
        .get_auth(session, "/v1/account/hosted-proxy")
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::OK);
    res.json().await.expect("status")
}

/// `(hosted, hosted_generation)` of a stored agent, `None` if not stored.
async fn stored(server: &TestServer, agent: &TestAgent) -> Option<(i64, Option<i64>)> {
    let db = server.raw_db().await;
    let row: Option<(i64, Option<i64>)> =
        sqlx::query_as("SELECT hosted, hosted_generation FROM agents WHERE id = $1")
            .bind(agent.id.to_string())
            .fetch_optional(&db)
            .await
            .expect("query");
    db.close().await;
    row
}

/// ADR 0051 §9: with no service key (every self-hosted server) and on an
/// account nobody entitled, nothing an older client sees changes.
#[tokio::test]
async fn default_accounts_are_not_entitled_and_older_answers_stay() {
    let server = TestServer::start().await;
    let service = IdentityKeyPair::generate();
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;

    assert_eq!(
        entitlement(&server, &ana).await,
        HostedProxyStatus { entitled: false }
    );
    let db = server.raw_db().await;
    let on: i64 = sqlx::query_scalar("SELECT hosted_proxy FROM accounts WHERE id = $1")
        .bind(ana.account_id.to_string())
        .fetch_one(&db)
        .await
        .unwrap();
    db.close().await;
    assert_eq!(on, 0);

    // A proxy registered the way `klav-proxy init` does today.
    let proxy = TestAgent::new();
    server
        .register_agent_ok(&proxy, "ana@example.com", "my proxy")
        .await;
    assert_eq!(stored(&server, &proxy).await, Some((0, None)));
    let (me_now, text) = me(&server, &proxy).await;
    assert_eq!(me_now.hosted_proxy, None);
    assert!(!text.contains("hosted"), "{text}");
    // The person's list says nothing about it either.
    let list = server
        .get_auth(&ana, "/v1/agents")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!list.contains("hosted"), "{list}");

    // Without a service key, a hosted registration is refused and nothing
    // is stored, even for an existing account.
    let agent = TestAgent::new();
    let (status, body) = register(
        &server,
        &hosted_body(&service, &agent, ana.account_id, "ana@example.com", 0),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "forbidden");
    assert_eq!(stored(&server, &agent).await, None);
}

#[tokio::test]
async fn hosted_registrations_need_the_service_key_and_the_entitlement() {
    let service = IdentityKeyPair::generate();
    let server = hosted_server(&service).await;
    let ana_creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&ana_creds, "laptop").await;
    let bob_creds = server.signup("bob@example.com", "pw").await;
    let bob = server.login(&bob_creds, "laptop").await;

    // Not entitled yet: refused, nothing stored.
    let agent = TestAgent::new();
    let valid = hosted_body(&service, &agent, ana.account_id, "ana@example.com", 3);
    let (status, refused) = register(&server, &valid).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(stored(&server, &agent).await, None);

    let out = enable(&server, "Ana@Example.com").await;
    assert!(out.contains("is on for ana@example.com"), "{out}");
    assert!(
        enable(&server, "ana@example.com")
            .await
            .contains("already on")
    );
    assert_eq!(
        entitlement(&server, &ana).await,
        HostedProxyStatus { entitled: true }
    );
    assert_eq!(
        entitlement(&server, &bob).await,
        HostedProxyStatus { entitled: false }
    );
    assert!(
        admin(
            &server,
            Command::Enable {
                email: "nadie@example.com".into()
            }
        )
        .await
        .unwrap_err()
        .contains("no account")
    );

    // Forged or altered registrations: each refused with the same answer,
    // and nothing stored.
    let forger = IdentityKeyPair::generate();
    let mut other_generation = valid.clone();
    if let Some(proof) = other_generation.hosted.as_mut() {
        proof.generation = 4;
    }
    let mut short_signature = valid.clone();
    if let Some(proof) = short_signature.hosted.as_mut() {
        proof.signature = Blob::new(vec![0; 63]);
    }
    let mut other_name_ok = valid.clone();
    other_name_ok.name = "renamed".into();
    let mut swapped_keys = valid.clone();
    swapped_keys.public_identity = Blob::new(TestAgent::new().keys.public().encode().to_vec());
    let cases = [
        (
            "another service key",
            hosted_body(&forger, &agent, ana.account_id, "ana@example.com", 3),
        ),
        ("another generation", other_generation),
        ("a short signature", short_signature),
        ("other agent keys", swapped_keys),
        (
            "signed for bob's account with ana's e-mail",
            hosted_body(&service, &agent, bob.account_id, "ana@example.com", 3),
        ),
        (
            "a valid signature for bob, who isn't entitled",
            hosted_body(&service, &agent, bob.account_id, "bob@example.com", 3),
        ),
        (
            "a valid signature for an unknown e-mail",
            hosted_body(
                &service,
                &agent,
                AccountId::generate(),
                "nadie@example.com",
                3,
            ),
        ),
    ];
    for (what, body) in cases {
        let (status, answer) = register(&server, &body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{what}");
        assert_eq!(answer, refused, "{what}");
        assert_eq!(stored(&server, &agent).await, None, "{what}");
    }

    // The name isn't signed (the person sees it), so a valid signature
    // still registers; then the agent is marked hosted, generation kept.
    let (status, _) = register(&server, &other_name_ok).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(stored(&server, &agent).await, Some((1, Some(3))));
    // Replaying it: the agent ID is taken.
    assert_eq!(register(&server, &valid).await.0, StatusCode::CONFLICT);

    let (hosted_me, text) = me(&server, &agent).await;
    assert_eq!(
        hosted_me.hosted_proxy,
        Some(HostedProxyStatus { entitled: true })
    );
    assert!(
        text.contains(r#""hosted_proxy":{"entitled":true}"#),
        "{text}"
    );
    // The person sees an ordinary pending agent: the mark is server-side.
    let list: AgentList = server
        .get_auth(&ana, "/v1/agents")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.agents.len(), 1);
    assert_eq!(list.agents[0].id, agent.id);

    // A self-hosted proxy of the same, entitled account: unmarked, and its
    // answer has no `hosted_proxy`.
    let own = TestAgent::new();
    server
        .register_agent_ok(&own, "ana@example.com", "my own proxy")
        .await;
    assert_eq!(stored(&server, &own).await, Some((0, None)));
    let (own_me, own_before) = me(&server, &own).await;
    assert_eq!(own_me.hosted_proxy, None);

    let listed = admin(&server, Command::Ls).await.unwrap();
    assert!(listed.contains("ana@example.com"), "{listed}");
    assert!(listed.contains("1 hosted agent(s)"), "{listed}");
    assert!(!listed.contains("bob@example.com"), "{listed}");

    // Off again: the hosted agent reads `entitled: false`, the other agent
    // answers byte for byte as before, and new hosted registrations stop.
    let out = disable(&server, "ana@example.com").await;
    assert!(out.contains("is off for ana@example.com"), "{out}");
    assert!(
        disable(&server, "ana@example.com")
            .await
            .contains("already off")
    );
    assert_eq!(
        me(&server, &agent).await.0.hosted_proxy,
        Some(HostedProxyStatus { entitled: false })
    );
    assert_eq!(me(&server, &own).await.1, own_before);
    assert_eq!(
        entitlement(&server, &ana).await,
        HostedProxyStatus { entitled: false }
    );
    let again = TestAgent::new();
    let (status, answer) = register(
        &server,
        &hosted_body(&service, &again, ana.account_id, "ana@example.com", 4),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(answer, refused);
    assert_eq!(
        admin(&server, Command::Ls).await.unwrap(),
        "No account has Klav Cloud's hosted proxy.\n"
    );
    // Ordinary registrations never needed it.
    server
        .register_agent_ok(&TestAgent::new(), "ana@example.com", "another")
        .await;
}

/// An account whose deletion the person asked for takes no hosted agent,
/// with the same answer as every other refusal.
#[tokio::test]
async fn an_account_being_deleted_takes_no_hosted_agent() {
    let service = IdentityKeyPair::generate();
    let server = hosted_server(&service).await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    enable(&server, "ana@example.com").await;
    let refused = register(
        &server,
        &hosted_body(
            &service,
            &TestAgent::new(),
            AccountId::generate(),
            "ana@example.com",
            0,
        ),
    )
    .await;
    assert_eq!(refused.0, StatusCode::FORBIDDEN);

    server.ask_deletion(&ana, &creds).await;
    let agent = TestAgent::new();
    let answer = register(
        &server,
        &hosted_body(&service, &agent, ana.account_id, "ana@example.com", 0),
    )
    .await;
    assert_eq!(answer, refused);
    assert_eq!(stored(&server, &agent).await, None);
}
