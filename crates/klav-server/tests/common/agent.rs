//! A test agent: its own identity, signed requests (spec §13.3) and grants
//! built the way a person's client builds them.

use klav_core::crypto::agent::{self, GrantToSign, SignedRequest};
use klav_core::crypto::identity::IdentityKeyPair;
use klav_core::crypto::keys::ItemKey;
use klav_core::crypto::random;
use klav_core::crypto::share::{share_item_key, share_project_key};
use klav_core::ids::{AgentId, ItemId};
use klav_core::policy::Policy;
use klav_proto::Blob;
use klav_proto::agent::{
    GRANT_PAYLOAD_VERSION, GRANT_PAYLOAD_VERSION_ITEMS, GrantPayload, GrantedItem, GrantedProject,
    HEADER_AGENT, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP, ProxyProfile, RegisterAgent,
    RegisterAgentResponse, SignedGrant,
};
use klav_proto::audit::{AgentRoute, AuditEvent, AuditPage, signed_near};
use reqwest::{Method, Response, StatusCode};

use super::TestServer;
use super::client::Session;
use super::vault::{TestProject, TestVault};

pub struct TestAgent {
    pub id: AgentId,
    pub keys: IdentityKeyPair,
}

/// The parts of a signed request, for tests that tamper with them.
pub struct Signed {
    pub timestamp: i64,
    pub nonce: [u8; 16],
    pub signature: Vec<u8>,
}

pub fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test helper")
            .as_millis(),
    )
    .expect("test helper")
}

impl TestAgent {
    pub fn new() -> Self {
        Self {
            id: AgentId::generate(),
            keys: IdentityKeyPair::generate(),
        }
    }

    pub fn sign(&self, method: &str, path: &str, body: &[u8], timestamp: i64) -> Signed {
        let nonce = random::array::<16>();
        let digest = agent::body_digest(body);
        let sig = agent::sign_request(
            &self.keys,
            &SignedRequest {
                agent: self.id,
                method,
                path,
                timestamp_ms: u64::try_from(timestamp).expect("test helper"),
                nonce: &nonce,
                body_digest: &digest,
            },
        );
        Signed {
            timestamp,
            nonce,
            signature: sig.to_bytes().to_vec(),
        }
    }
}

/// `id` with its first character percent-escaped: the same ID once the
/// router decodes it, another path as signed.
pub fn escaped(id: impl std::fmt::Display) -> String {
    let id = id.to_string();
    format!("%{:02X}{}", id.as_bytes()[0], &id[1..])
}

impl TestServer {
    /// [`Self::agent_call`] signed at the old edge of the clock window
    /// (5 minutes less 300 ms ago), with its body held back `hold` after
    /// the headers: the server reads the headers in the window, and the
    /// rest past it.
    pub async fn agent_call_late(
        &self,
        agent: &TestAgent,
        method: Method,
        path: &str,
        body: &serde_json::Value,
        hold: std::time::Duration,
    ) -> Response {
        let bytes = serde_json::to_vec(body).expect("test helper");
        let signed = agent.sign(
            method.as_str(),
            path,
            &bytes,
            now_ms() - klav_proto::audit::CLOCK_SKEW_MS + 300,
        );
        let held = futures_util::stream::once(async move {
            tokio::time::sleep(hold).await;
            Ok::<_, std::io::Error>(bytes)
        });
        self.http
            .request(method, self.url(path))
            .header(HEADER_AGENT, agent.id.to_string())
            .header(HEADER_TIMESTAMP, signed.timestamp.to_string())
            .header(HEADER_NONCE, Blob::new(signed.nonce.to_vec()).to_text())
            .header(HEADER_SIGNATURE, Blob::new(signed.signature).to_text())
            .header("content-type", "application/json")
            .body(reqwest::Body::wrap_stream(held))
            .send()
            .await
            .expect("request")
    }

    /// [`Self::agent_call`] signed one second inside the old edge of the
    /// clock window, held at the extractor's first write (storing its
    /// nonce) until the signature has left the window: on SQLite by the
    /// database's write lock, on Postgres by a lock on `agent_nonces` (and
    /// the account row, as on SQLite). The extractor's time checks come
    /// before that write, so the request passes them, and the handler then
    /// runs entirely past the window: only the check when its event is
    /// logged (`append_in`) can refuse it. No sleep decides the outcome,
    /// only the order.
    pub async fn agent_call_held(
        &self,
        session: &Session,
        agent: &TestAgent,
        method: Method,
        path: &str,
        body: &serde_json::Value,
    ) -> Response {
        let db = self.raw_db().await;
        let mut lock = db.begin().await.expect("lock");
        let locked = sqlx::query("UPDATE accounts SET updated_at = updated_at WHERE id = $1")
            .bind(session.account_id.to_string())
            .execute(&mut *lock)
            .await
            .expect("lock the account");
        assert_eq!(locked.rows_affected(), 1);
        if self.database_url.starts_with("postgres") {
            sqlx::query("LOCK TABLE agent_nonces IN EXCLUSIVE MODE")
                .execute(&mut *lock)
                .await
                .expect("lock the nonces");
        }
        let bytes = serde_json::to_vec(body).expect("test helper");
        let timestamp = now_ms() - klav_proto::audit::CLOCK_SKEW_MS + 1000;
        let signed = agent.sign(method.as_str(), path, &bytes, timestamp);
        let sent = tokio::spawn(
            self.http
                .request(method, self.url(path))
                .header(HEADER_AGENT, agent.id.to_string())
                .header(HEADER_TIMESTAMP, signed.timestamp.to_string())
                .header(HEADER_NONCE, Blob::new(signed.nonce.to_vec()).to_text())
                .header(HEADER_SIGNATURE, Blob::new(signed.signature).to_text())
                .header("content-type", "application/json")
                .body(bytes)
                .send(),
        );
        // Hold the lock until the signature is out of the window.
        let out = timestamp + klav_proto::audit::CLOCK_SKEW_MS + 200;
        let wait = u64::try_from(out - now_ms()).unwrap_or(0);
        tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
        lock.rollback().await.expect("release");
        sent.await.expect("task").expect("request")
    }

    /// `session`'s audit log, every event.
    pub async fn chain_of(&self, session: &Session) -> Vec<AuditEvent> {
        let page: AuditPage = self
            .get_auth(session, "/v1/audit?after=0")
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

    /// The agent events of `session`'s log whose signed request the log
    /// verifier refuses (`klav log verify`, the same rules from
    /// `klav_proto::audit`): its route, or its signed time too far from
    /// when it was logged. Empty for an honest log.
    pub async fn proofs_the_log_refuses(&self, session: &Session) -> Vec<String> {
        let mut refused = Vec::new();
        for e in self.chain_of(session).await {
            let Some(proof) = &e.agent_proof else {
                continue;
            };
            let route = AgentRoute::of(&e);
            if !route.is_some_and(|r| r.matches(&e, proof)) {
                refused.push(format!(
                    "event {} ({}): signed `{} {}`",
                    e.seq, e.action, proof.method, proof.path
                ));
            }
            if !signed_near(proof.timestamp, e.at) {
                refused.push(format!(
                    "event {} ({}): signed {} ms from when it was logged",
                    e.seq,
                    e.action,
                    e.at - proof.timestamp
                ));
            }
        }
        refused
    }

    /// Notes in `wrong` an honest step that did not answer `want`, as a
    /// refused one before it would leave it (it ran after all).
    pub fn expect_status(wrong: &mut Vec<String>, what: &str, got: StatusCode, want: StatusCode) {
        if got != want {
            wrong.push(format!("{what}: {got} (expected {want})"));
        }
    }

    /// Sends one request the log would refuse to back, and notes in
    /// `wrong` anything but `expect` with nothing logged.
    pub async fn refused_unlogged(
        &self,
        session: &Session,
        what: &str,
        expect: StatusCode,
        send: impl std::future::Future<Output = Response>,
        wrong: &mut Vec<String>,
    ) {
        let before = self.chain_of(session).await.len();
        let res = send.await;
        let status = res.status();
        let logged = self.chain_of(session).await.len() - before;
        if status != expect || logged != 0 {
            let text: String = res
                .text()
                .await
                .unwrap_or_default()
                .chars()
                .take(160)
                .collect();
            wrong.push(format!(
                "{what}: {status} (expected {expect}), {logged} event(s) logged: {text}"
            ));
        }
    }

    pub async fn register_agent(&self, agent: &TestAgent, email: &str, name: &str) -> Response {
        self.post_json(
            "/v1/agents/register",
            &RegisterAgent {
                id: agent.id,
                email: email.into(),
                name: name.into(),
                public_identity: Blob::new(agent.keys.public().encode().to_vec()),
                note: None,
            },
        )
        .await
    }

    pub async fn register_agent_ok(&self, agent: &TestAgent, email: &str, name: &str) {
        let res = self.register_agent(agent, email, name).await;
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let _: RegisterAgentResponse = res.json().await.expect("test helper");
    }

    /// Sends a request with explicit signature parts.
    pub async fn agent_raw(
        &self,
        agent: &TestAgent,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        signed: &Signed,
    ) -> Response {
        let mut req = self
            .http
            .request(method, self.url(path))
            .header(HEADER_AGENT, agent.id.to_string())
            .header(HEADER_TIMESTAMP, signed.timestamp.to_string())
            .header(HEADER_NONCE, Blob::new(signed.nonce.to_vec()).to_text())
            .header(
                HEADER_SIGNATURE,
                Blob::new(signed.signature.clone()).to_text(),
            );
        if let Some(body) = body {
            req = req
                .header("content-type", "application/json")
                .body(body.to_vec());
        }
        req.send().await.expect("request")
    }

    /// A correctly signed agent request.
    pub async fn agent_call(
        &self,
        agent: &TestAgent,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Response {
        let bytes = body.map(|b| serde_json::to_vec(b).expect("test helper"));
        let signed = agent.sign(
            method.as_str(),
            path,
            bytes.as_deref().unwrap_or_default(),
            now_ms(),
        );
        self.agent_raw(agent, method, path, bytes.as_deref(), &signed)
            .await
    }

    /// Builds and signs a grant for `agent` over `projects`.
    pub fn build_grant(
        session: &Session,
        agent: &TestAgent,
        version: u64,
        policy: Policy,
        projects: &[(&TestVault, &TestProject)],
    ) -> SignedGrant {
        let payload = GrantPayload {
            v: GRANT_PAYLOAD_VERSION,
            account_id: session.account_id,
            agent_id: agent.id,
            version,
            issued_at: now_ms(),
            policy,
            projects: projects
                .iter()
                .map(|(vault, project)| GrantedProject {
                    vault_id: vault.id,
                    owner_account_id: vault.owner,
                    project_id: project.id,
                    shared_key: Blob::new(
                        share_project_key(
                            agent.keys.public(),
                            &vault.project_ctx(project.id),
                            &project.key,
                        )
                        .expect("test helper"),
                    ),
                    labels: Blob::new(agent::seal_grant_labels(
                        &project.key,
                        &vault.project_ctx(project.id),
                        agent.id,
                        br#"{"vault":"V","project":"P"}"#,
                    )),
                })
                .collect(),
            items: Vec::new(),
            profiles: Vec::new(),
            issuers: Vec::new(),
            sandbox: None,
        };
        let bytes = serde_json::to_vec(&payload).expect("test helper");
        let signature = agent::sign_grant(
            &session.identity,
            &GrantToSign {
                account: session.account_id,
                agent: agent.id,
                agent_public: agent.keys.public(),
                payload: &bytes,
            },
        );
        SignedGrant {
            payload: Blob::new(bytes),
            signature: Blob::new(signature.to_bytes().to_vec()),
        }
    }

    /// Builds and signs a per-item grant (`v: 2`, ADR 0036 §2) for
    /// `agent` over `items`, each shared with its own key (kind `0x23`).
    pub fn build_item_grant(
        session: &Session,
        agent: &TestAgent,
        version: u64,
        policy: Policy,
        items: &[(&TestVault, &TestProject, ItemId, &ItemKey)],
        profiles: Vec<ProxyProfile>,
    ) -> SignedGrant {
        let payload = GrantPayload {
            v: GRANT_PAYLOAD_VERSION_ITEMS,
            account_id: session.account_id,
            agent_id: agent.id,
            version,
            issued_at: now_ms(),
            policy,
            projects: Vec::new(),
            items: items
                .iter()
                .map(|(vault, project, item, key)| GrantedItem {
                    vault_id: vault.id,
                    owner_account_id: vault.owner,
                    project_id: project.id,
                    item_id: *item,
                    shared_key: Blob::new(
                        share_item_key(
                            agent.keys.public(),
                            &vault.item_ctx(project.id, *item),
                            key,
                        )
                        .expect("test helper"),
                    ),
                })
                .collect(),
            profiles,
            issuers: Vec::new(),
            sandbox: None,
        };
        Self::sign_payload(session, agent, &payload)
    }

    /// Signs `payload` as the account, whatever it says (tests build
    /// invalid ones on purpose).
    pub fn sign_payload(
        session: &Session,
        agent: &TestAgent,
        payload: &GrantPayload,
    ) -> SignedGrant {
        let bytes = serde_json::to_vec(payload).expect("test helper");
        let signature = agent::sign_grant(
            &session.identity,
            &GrantToSign {
                account: session.account_id,
                agent: agent.id,
                agent_public: agent.keys.public(),
                payload: &bytes,
            },
        );
        SignedGrant {
            payload: Blob::new(bytes),
            signature: Blob::new(signature.to_bytes().to_vec()),
        }
    }

    pub async fn post_grant(
        &self,
        session: &Session,
        agent: &TestAgent,
        grant: &SignedGrant,
    ) -> Response {
        self.post_auth(session, &format!("/v1/agents/{}/grant", agent.id))
            .json(grant)
            .send()
            .await
            .expect("request")
    }
}

impl TestServer {
    /// Signs and posts a decision on approval `id` as `session`.
    pub async fn decide(
        &self,
        session: &Session,
        id: klav_core::ids::ApprovalId,
        approve: bool,
        lease_ms: i64,
    ) -> Response {
        let res = self
            .get_auth(session, &format!("/v1/approvals/{id}"))
            .send()
            .await
            .expect("request");
        if res.status() != StatusCode::OK {
            return res;
        }
        let info: klav_proto::agent::ApprovalInfo = res.json().await.expect("approval");
        self.post_auth(session, &format!("/v1/approvals/{id}/decide"))
            .json(&sign_decision(session, id, &info, approve, lease_ms))
            .send()
            .await
            .expect("request")
    }

    /// The body of [`Self::decide`], signed by `session` now.
    pub async fn decide_body(
        &self,
        session: &Session,
        id: klav_core::ids::ApprovalId,
        approve: bool,
        lease_ms: i64,
    ) -> klav_proto::agent::DecideApproval {
        let res = self
            .get_auth(session, &format!("/v1/approvals/{id}"))
            .send()
            .await
            .expect("request");
        assert_eq!(res.status(), StatusCode::OK);
        let info: klav_proto::agent::ApprovalInfo = res.json().await.expect("approval");
        sign_decision(session, id, &info, approve, lease_ms)
    }
}

/// A decision on approval `id` (described by `info`), signed by `session`
/// now; a lease of `lease_ms` if it is positive.
fn sign_decision(
    session: &Session,
    id: klav_core::ids::ApprovalId,
    info: &klav_proto::agent::ApprovalInfo,
    approve: bool,
    lease_ms: i64,
) -> klav_proto::agent::DecideApproval {
    let decided_at = now_ms();
    let lease_until = if lease_ms > 0 {
        decided_at + lease_ms
    } else {
        0
    };
    let signature = agent::sign_approval(
        &session.identity,
        &agent::ApprovalToSign {
            approval: id,
            agent: info.agent_id,
            request: info.request.as_bytes(),
            approve,
            lease_until_ms: u64::try_from(lease_until).expect("lease"),
            decided_at_ms: u64::try_from(decided_at).expect("time"),
        },
    );
    klav_proto::agent::DecideApproval {
        approve,
        lease_until,
        decided_at,
        signature: Blob::new(signature.to_bytes().to_vec()),
        task_id: None,
    }
}
