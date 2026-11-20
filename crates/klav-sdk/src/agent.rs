//! An agent on this machine: its identity, the server and signed requests
//! (spec §13.3).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use klav_client::api;
use klav_client::{ClientError, ClientResult, Home, ServerUrl};
use klav_core::crypto::agent::{
    self as agent_crypto, GrantToSign, NONCE_LEN, SignedRequest, pairing_code,
};
use klav_core::crypto::identity::{IdentityKeyPair, PublicIdentity};
use klav_core::crypto::random;
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::ids::{AgentId, ApprovalId};
use klav_proto::Blob;
use klav_proto::agent::{
    AgentMe, AgentStatus, ApprovalInfo, ApprovalStatus, GrantPayload, HEADER_AGENT, HEADER_NONCE,
    HEADER_SIGNATURE, HEADER_TIMESTAMP, MAX_APPROVAL_WAIT_SECS, RegisterAgent,
    RegisterAgentResponse,
};
use klav_proto::rotate::AgentRequestProof;
use reqwest::{Method, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::config::{AgentConfig, validate_name};
use crate::grant::OpenGrant;
use crate::keystore::KeyStore;

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// What `register` needs.
#[derive(Debug, Clone)]
pub struct Registration {
    /// Local name, also shown to the person.
    pub name: String,
    /// Server URL.
    pub server: String,
    /// E-mail of the account to join.
    pub email: String,
    /// What the agent needs, shown to the person.
    pub note: Option<String>,
    /// Where to keep the private key.
    pub key_store: KeyStore,
}

/// The result of a registration: what to show on the agent's screen.
#[derive(Debug, Clone, Serialize)]
pub struct Registered {
    /// Agent ID.
    pub agent_id: AgentId,
    /// Local name.
    pub name: String,
    /// The agent's public identity (kind `0x05`), as the server lists it:
    /// what the Mac app compares, byte for byte, with the pending request
    /// it approves (ADR 0033 §3.1).
    pub public_identity: Blob,
    /// The 6-word pairing code the person must see on their screen too.
    pub pairing_code: String,
    /// When the request lapses (Unix ms).
    pub expires_at: i64,
    /// Where the key is.
    pub key_store: String,
}

/// The agent's state as the server reports it, after the local checks.
#[derive(Debug, Clone, Serialize)]
pub struct AgentState {
    /// Agent ID.
    pub agent_id: AgentId,
    /// Local name.
    pub name: String,
    /// Server.
    pub server: String,
    /// State.
    pub status: AgentStatus,
    /// `status` is `denied` only because the pending registration lapsed
    /// without a decision (ADR 0033 E2.2).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub lapsed: bool,
    /// The agent's pairing code.
    pub pairing_code: String,
    /// The account's pairing code (compare with `klav status` on the
    /// person's device to check the pinned account key).
    pub account_code: Option<String>,
    /// Grant version, when active.
    pub grant_version: Option<u64>,
    /// Number of shared projects.
    pub projects: usize,
    /// When the grant expires (Unix seconds), if it does.
    pub expires_at: Option<u64>,
    /// The person paused this agent (or every agent): every action is
    /// refused until it ends (ADR 0033 §7.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused: Option<klav_proto::agent::AgentPaused>,
    /// The person asked to delete the account, which happens at this time
    /// (Unix ms): every action is refused until then (ADR 0037 §3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_delete_at: Option<i64>,
}

/// An agent identity, loaded with its private key.
pub struct Agent {
    pub(crate) home: Home,
    pub(crate) config: AgentConfig,
    pub(crate) keys: IdentityKeyPair,
    pub(crate) server: ServerUrl,
    http: reqwest::Client,
}

impl Agent {
    /// Generates an identity, stores its key and sends the registration.
    /// Nothing is kept if the server refuses it.
    pub async fn register(home: &Home, req: Registration) -> ClientResult<(Self, Registered)> {
        validate_name(&req.name)?;
        if AgentConfig::exists(home, &req.name) {
            return Err(ClientError::Invalid(format!(
                "an agent named {:?} is already registered here; choose another name",
                req.name
            )));
        }
        let server = ServerUrl::parse(&klav_client::server::resolve(&req.server)?)?;
        let keys = IdentityKeyPair::generate();
        let agent_id = AgentId::generate();
        let http = api::http_client()?;
        let res = http
            .post(server.join("/v1/agents/register"))
            .json(&RegisterAgent {
                id: agent_id,
                email: req.email.trim().to_owned(),
                name: req.name.clone(),
                public_identity: Blob::new(keys.public().encode().to_vec()),
                note: req.note.clone(),
            })
            .send()
            .await
            .map_err(|e| ClientError::Network(api::without_url(&e)))?;
        let accepted: RegisterAgentResponse = api::json(res).await?;
        req.key_store.save(home, agent_id, &keys)?;
        let config = AgentConfig::new(
            &req.name,
            agent_id,
            server.as_str(),
            req.email.trim(),
            Blob::new(keys.public().encode().to_vec()),
            req.key_store.clone(),
            now_ms(),
        );
        if let Err(e) = config.save(home) {
            let _ = req.key_store.delete(agent_id);
            return Err(e);
        }
        let registered = Registered {
            agent_id,
            name: req.name,
            public_identity: Blob::new(keys.public().encode().to_vec()),
            pairing_code: pairing_code(keys.public()),
            expires_at: accepted.expires_at,
            key_store: req.key_store.describe(),
        };
        Ok((
            Self {
                home: home.clone(),
                config,
                keys,
                server,
                http,
            },
            registered,
        ))
    }

    /// Loads the agent `name` from `home`.
    pub fn load(home: &Home, name: &str) -> ClientResult<Self> {
        let config = AgentConfig::load(home, name)?;
        let keys = config.key_store.load(config.agent_id)?;
        let expected = PublicIdentity::decode(config.public_identity.as_bytes())?;
        if keys.public() != &expected {
            return Err(ClientError::Invalid(format!(
                "the key of agent {name:?} does not match its registration (check {})",
                if std::env::var_os(crate::keystore::KEY_ENV).is_some() {
                    crate::keystore::KEY_ENV.to_owned()
                } else {
                    config.key_store.describe()
                }
            )));
        }
        let server = ServerUrl::parse(&config.server)?;
        Ok(Self {
            home: home.clone(),
            config,
            keys,
            server,
            http: api::http_client()?,
        })
    }

    /// Agent ID.
    pub fn id(&self) -> AgentId {
        self.config.agent_id
    }

    /// Local name.
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Local config.
    pub fn config(&self) -> &AgentConfig {
        &self.config
    }

    /// The agent's pairing code.
    pub fn pairing_code(&self) -> String {
        pairing_code(self.keys.public())
    }

    /// The agent as the server side of a sandbox's pinned TLS channel
    /// (ADR 0036 §6): a signer of the server's TLS 1.3 `CertificateVerify`
    /// only, never of a Klav request. Only `klav-proxy` uses it.
    pub fn tls_server_signer(&self) -> klav_core::crypto::channel::TlsSigner {
        klav_core::crypto::channel::TlsSigner::server(&self.keys)
    }

    /// The agent's public identity.
    pub fn public_identity(&self) -> &klav_core::crypto::identity::PublicIdentity {
        self.keys.public()
    }

    /// Forgets the agent on this machine: config and stored key.
    pub fn forget(self) -> ClientResult<()> {
        self.config.key_store.delete(self.config.agent_id)?;
        self.config.remove(&self.home)
    }

    /// Sends a signed request and returns the raw response.
    pub async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
    ) -> ClientResult<Response> {
        self.send_signed(method, path, body)
            .await
            .map(|(res, _)| res)
    }

    /// [`Self::send`], also returning the request as signed.
    async fn send_signed(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
    ) -> ClientResult<(Response, AgentRequestProof)> {
        let proof = self.sign(&method, path, body.unwrap_or_default());
        let res = self.send_proof(&proof).await?;
        Ok((res, proof))
    }

    /// Signs a request without sending it.
    pub(crate) fn sign(&self, method: &Method, path: &str, body: &[u8]) -> AgentRequestProof {
        let nonce = random::array::<NONCE_LEN>();
        let timestamp = u64::try_from(now_ms()).unwrap_or(0);
        let digest = agent_crypto::body_digest(body);
        let signature = agent_crypto::sign_request(
            &self.keys,
            &SignedRequest {
                agent: self.config.agent_id,
                method: method.as_str(),
                path,
                timestamp_ms: timestamp,
                nonce: &nonce,
                body_digest: &digest,
            },
        );
        AgentRequestProof {
            method: method.as_str().to_owned(),
            path: path.to_owned(),
            timestamp_ms: timestamp,
            nonce: Blob::new(nonce.to_vec()),
            body: Blob::new(body.to_vec()),
            signature: Blob::new(signature.to_bytes().to_vec()),
        }
    }

    /// Sends a request exactly as [`Self::sign`] signed it.
    async fn send_proof(&self, proof: &AgentRequestProof) -> ClientResult<Response> {
        self.send_proof_to(&self.server, proof).await
    }

    /// [`Self::send_proof`] to another server (the check of a move).
    async fn send_proof_to(
        &self,
        server: &ServerUrl,
        proof: &AgentRequestProof,
    ) -> ClientResult<Response> {
        let method = Method::from_bytes(proof.method.as_bytes())
            .map_err(|_| ClientError::Invalid("request method".into()))?;
        let body = proof.body.as_bytes();
        let mut req = self
            .http
            .request(method, server.join(&proof.path))
            .header(HEADER_AGENT, self.config.agent_id.to_string())
            .header(HEADER_TIMESTAMP, proof.timestamp_ms.to_string())
            .header(HEADER_NONCE, proof.nonce.to_text())
            .header(HEADER_SIGNATURE, proof.signature.to_text());
        if !body.is_empty() {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        req.send()
            .await
            .map_err(|e| ClientError::Network(api::without_url(&e)))
    }

    fn refused(res: &Response) -> Option<ClientError> {
        (res.status() == reqwest::StatusCode::UNAUTHORIZED).then(|| {
            ClientError::Denied(
                "the server refused the agent's signature (revoked or unknown agent, clock off by more than 5 minutes, or a replayed request)".into(),
            )
        })
    }

    /// A signed `POST` that must succeed, also returning the request as
    /// signed: the person's `klavd` checks with it that this agent asked
    /// for this step of an assisted password change (ADR 0022 §5). The
    /// proof holds no secret: IDs, a reason and the signature.
    pub async fn call_proved<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> ClientResult<(R, AgentRequestProof)> {
        let bytes = serde_json::to_vec(body)
            .map_err(|e| ClientError::Invalid(format!("request body: {e}")))?;
        let (res, proof) = self.send_signed(Method::POST, path, Some(&bytes)).await?;
        if let Some(e) = Self::refused(&res) {
            return Err(e);
        }
        Ok((api::json(res).await?, proof))
    }

    /// Signs a request for somewhere other than the Klav server, with the
    /// same headers and message (spec §13.3): the credential proxy's
    /// issuer API (ADR 0036 §4) checks it with this agent's identity from
    /// its own grant. `path` is the path and query exactly as sent.
    pub fn sign_request(&self, method: &Method, path: &str, body: &[u8]) -> AgentRequestProof {
        self.sign(method, path, body)
    }

    /// Signs a JSON `POST` without sending it: an assisted change's
    /// confirm or cancel goes to the person's `klavd` first and to the
    /// server only once `klavd` applied it (ADR 0022 §5), with
    /// [`Self::send_proved`].
    pub fn sign_post<B: Serialize>(&self, path: &str, body: &B) -> ClientResult<AgentRequestProof> {
        let bytes = serde_json::to_vec(body)
            .map_err(|e| ClientError::Invalid(format!("request body: {e}")))?;
        Ok(self.sign(&Method::POST, path, &bytes))
    }

    /// Sends a request signed with [`Self::sign_post`]; it must succeed.
    pub async fn send_proved<R: DeserializeOwned>(
        &self,
        proof: &AgentRequestProof,
    ) -> ClientResult<R> {
        let res = self.send_proof(proof).await?;
        if let Some(e) = Self::refused(&res) {
            return Err(e);
        }
        api::json(res).await
    }

    /// Signed JSON request that must succeed.
    pub async fn call<B: Serialize, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> ClientResult<R> {
        let bytes = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|e| ClientError::Invalid(format!("request body: {e}")))?;
        let res = self.send(method, path, bytes.as_deref()).await?;
        if let Some(e) = Self::refused(&res) {
            return Err(e);
        }
        api::json(res).await
    }

    /// `GET /v1/agent/me`, pinning the account identity the first time and
    /// checking it afterwards.
    pub async fn me(&mut self) -> ClientResult<AgentMe> {
        self.migrate_server().await;
        let me: AgentMe = self
            .call::<(), _>(Method::GET, "/v1/agent/me", None)
            .await?;
        if me.id != self.config.agent_id {
            return Err(ClientError::Security(
                "the server answered for another agent".into(),
            ));
        }
        match (&self.config.account_public_identity, self.config.account_id) {
            (Some(pinned), Some(account)) => {
                if *pinned != me.account_public_identity || account != me.account_id {
                    return Err(ClientError::Security(
                        "the account's identity key changed since this agent first saw it; refusing to continue (re-register the agent if this is expected)".into(),
                    ));
                }
            }
            _ => {
                PublicIdentity::decode(me.account_public_identity.as_bytes())?;
                self.config.account_public_identity = Some(me.account_public_identity.clone());
                self.config.account_id = Some(me.account_id);
                self.config.save(&self.home)?;
            }
        }
        Ok(me)
    }

    /// Moves the agent off an old server URL of the table of moves (ADR
    /// 0028 §4), like the person's account: only if a signed
    /// `GET /v1/agent/me` on the new host answers for this agent with the
    /// account and identity it already pinned. An agent that has not
    /// pinned them yet stays where it is (nothing to compare with, and
    /// pinning from an unchecked host is what T111 forbids). Anything else
    /// changes nothing; the next load tries again. Returns the new URL.
    pub async fn migrate_server(&mut self) -> Option<String> {
        self.migrate_server_with(klav_client::server::MOVES).await
    }

    /// [`Agent::migrate_server`] with another table (tests only).
    #[doc(hidden)]
    pub async fn migrate_server_with(&mut self, moves: &[(&str, &str)]) -> Option<String> {
        let new = moves
            .iter()
            .find(|(old, _)| *old == self.config.server)
            .map(|(_, new)| (*new).to_owned())?;
        let (Some(pinned), Some(account)) = (
            self.config.account_public_identity.clone(),
            self.config.account_id,
        ) else {
            return None;
        };
        let target = ServerUrl::parse(&new).ok()?;
        let check = async {
            let proof = self.sign(&Method::GET, "/v1/agent/me", b"");
            let res = self.send_proof_to(&target, &proof).await.ok()?;
            if res.status() != reqwest::StatusCode::OK {
                return None;
            }
            let me: AgentMe = api::json(res).await.ok()?;
            (me.id == self.config.agent_id
                && me.account_id == account
                && me.account_public_identity == pinned)
                .then_some(())
        };
        tokio::time::timeout(Duration::from_secs(5), check)
            .await
            .ok()
            .flatten()?;
        // Saved from the file on disk: another process may have changed it.
        let mut on_disk = AgentConfig::load(&self.home, &self.config.name).ok()?;
        if on_disk.agent_id != self.config.agent_id || on_disk.server != self.config.server {
            return None;
        }
        on_disk.server = new.clone();
        on_disk.save(&self.home).ok()?;
        self.config = on_disk;
        self.server = target;
        Some(new)
    }

    /// The pinned account identity.
    pub(crate) fn account_identity(&self) -> ClientResult<PublicIdentity> {
        let blob = self
            .config
            .account_public_identity
            .as_ref()
            .ok_or_else(|| ClientError::Invalid("the account identity is not known yet".into()))?;
        Ok(PublicIdentity::decode(blob.as_bytes())?)
    }

    /// The state, for `klav agent status`.
    pub async fn state(&mut self) -> ClientResult<AgentState> {
        let me = self.me().await?;
        let grant = if me.status == AgentStatus::Active {
            Some(self.verify_grant(&me)?)
        } else {
            None
        };
        Ok(AgentState {
            agent_id: self.config.agent_id,
            name: self.config.name.clone(),
            server: self.config.server.clone(),
            status: me.status,
            lapsed: me.lapsed,
            pairing_code: self.pairing_code(),
            account_code: self.account_identity().ok().map(|a| pairing_code(&a)),
            grant_version: grant.as_ref().map(|g| g.payload.version),
            projects: grant.as_ref().map_or(0, |g| g.payload.projects.len()),
            expires_at: grant.as_ref().and_then(|g| g.payload.policy.expires_at),
            paused: me.paused,
            account_delete_at: me.account_delete_at,
        })
    }

    /// Verifies the grant in `me` against the pinned account identity and
    /// opens the project keys (spec §13.4).
    pub(crate) fn verify_grant(&mut self, me: &AgentMe) -> ClientResult<OpenGrant> {
        let grant = me
            .grant
            .as_ref()
            .ok_or_else(|| ClientError::Denied("the agent has no grant".into()))?;
        let account = self.account_identity()?;
        let signature: [u8; SIGNATURE_LEN] = grant
            .signature
            .as_bytes()
            .try_into()
            .map_err(|_| ClientError::Security("grant signature has a wrong length".into()))?;
        agent_crypto::verify_grant(
            &account,
            &GrantToSign {
                account: me.account_id,
                agent: self.config.agent_id,
                agent_public: self.keys.public(),
                payload: grant.payload.as_bytes(),
            },
            &Signature::from_bytes(signature),
        )
        .map_err(|_| ClientError::Security("the grant is not signed by the account".into()))?;
        let payload: GrantPayload = serde_json::from_slice(grant.payload.as_bytes())
            .map_err(|e| ClientError::Corrupt(format!("grant payload: {e}")))?;
        // Version 1, or 2 with its rules (a per-item grant, ADR 0036 §2);
        // any other version fails closed.
        payload
            .check_format()
            .map_err(|e| ClientError::Corrupt(format!("grant payload: {e}")))?;
        if payload.agent_id != self.config.agent_id || payload.account_id != me.account_id {
            return Err(ClientError::Security(
                "the grant is for another agent or account".into(),
            ));
        }
        if payload.version < self.config.grant_version {
            return Err(ClientError::Rollback(format!(
                "grant version {} after version {}",
                payload.version, self.config.grant_version
            )));
        }
        if payload.version > self.config.grant_version {
            self.config.grant_version = payload.version;
            self.config.save(&self.home)?;
        }
        OpenGrant::open(&self.keys, payload)
    }
}

impl Agent {
    /// The state of one of this agent's approval requests, waiting up to
    /// `wait` (at most [`MAX_APPROVAL_WAIT_SECS`]) while it is pending: a
    /// long-poll (ADR 0015 §4).
    pub async fn approval(&self, id: ApprovalId, wait: Duration) -> ClientResult<ApprovalInfo> {
        let secs = wait.as_secs().min(MAX_APPROVAL_WAIT_SECS);
        let path = if secs == 0 {
            format!("/v1/agent/approvals/{id}")
        } else {
            format!("/v1/agent/approvals/{id}?wait={secs}")
        };
        self.call::<(), _>(Method::GET, &path, None).await
    }

    /// Waits until the person decides on `id`, it expires, or `timeout`
    /// passes, with long-polls. Returns the last state.
    pub async fn wait_decision(
        &self,
        id: ApprovalId,
        timeout: Duration,
    ) -> ClientResult<ApprovalInfo> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            let asked = std::time::Instant::now();
            let info = self.approval(id, left).await?;
            if info.status != ApprovalStatus::Pending || left.as_secs() == 0 {
                return Ok(info);
            }
            // A server without long-polls answers at once: never ask more
            // than once a second.
            let pause = Duration::from_secs(1).saturating_sub(asked.elapsed());
            tokio::time::sleep(pause.min(left)).await;
        }
    }
}
