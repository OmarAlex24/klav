//! The issuer's side of sandboxes (ADR 0036 §4, E1.3, E6; layer 5): start,
//! list and stop sandboxes at the account's credential proxy.
//!
//! The issuer talks to the proxy's loopback listener only,
//! `http://127.0.0.1:<port>/_klav/sandboxes` (D3), with a request signed
//! like one to the Klav server (spec §13.3). It never follows a redirect or
//! an `HTTP_PROXY`: the answer to a start carries the sandbox's one-time
//! secret.
//!
//! The package (`ksb1_`, spec §13.10) is built here, from the proxy's
//! answer (the ID, the secret, the expiry) and from **this agent's own
//! grant**, signed by the account: the proxy's address and its pin. A
//! process that took the proxy's port cannot point a sandbox at another
//! address or key.

use std::time::Duration;

use klav_client::{ClientError, api};
use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::sandbox::{SECRET_LEN, SandboxPackage, SandboxSecret, proxy_pin};
use klav_core::ids::SandboxId;
use klav_proto::Blob;
use klav_proto::agent::{
    AgentStatus, HEADER_AGENT, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP,
};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::Agent;

/// Path of the issuer API on the proxy's listener.
pub const API: &str = "/_klav/sandboxes";
/// Port of the proxy's listener by default (`klav-proxy serve --port`).
pub const DEFAULT_PROXY_PORT: u16 = 8790;
/// Longest the issuer waits for the proxy (which waits for the server).
const TIMEOUT: Duration = Duration::from_secs(30);
/// Largest answer the issuer reads from the proxy.
const MAX_ANSWER: usize = 64 * 1024;

/// What `klav sandbox start` asks for.
#[derive(Debug, Clone, Serialize)]
pub struct StartRequest {
    /// The label the person sees (`chat-123`).
    pub label: String,
    /// The proxy's profiles the sandbox may use.
    pub profiles: Vec<String>,
    /// Its TTL in seconds; `None` for the default, capped by the issuer's
    /// limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
}

/// A started sandbox. No `Debug`: the package holds the secret.
pub struct Started {
    /// The package for the sandbox (`ksb1_…`), in a zeroizing buffer.
    pub package: Zeroizing<String>,
    /// Its ID.
    pub sandbox_id: SandboxId,
    /// When it expires (Unix ms).
    pub expires_at: i64,
}

/// One of this issuer's live sandboxes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveSandbox {
    /// Its ID.
    pub sandbox_id: SandboxId,
    /// Its label.
    pub label: String,
    /// The profiles it may use.
    pub profiles: Vec<String>,
    /// When it started (Unix ms).
    pub issued_at: i64,
    /// When it expires (Unix ms).
    pub expires_at: i64,
    /// Whether its forwarder claimed it.
    pub claimed: bool,
}

/// Why a sandbox call failed, with the code `klav sandbox` turns into its
/// exit code and its `next`.
#[derive(Debug)]
pub enum SandboxError {
    /// The account has no proxy this agent may use (`klav_no_proxy`): its
    /// grant names none. The person turned the proxy off or changed it, or
    /// removed this agent as an issuer when it had no projects: the signed
    /// grant is the same in all three (`sandbox: { proxy: null }`).
    NoProxy,
    /// Nothing answers on the proxy's port (`klav_proxy_unreachable`).
    ProxyUnreachable,
    /// The proxy refused, with its `error`, `message` and `next`.
    Refused {
        /// The `error` code (`klav_not_issuer`, `klav_agents_paused`…).
        code: String,
        /// Its message.
        message: String,
        /// What to do.
        next: String,
    },
    /// The proxy was asked to start a sandbox and its answer was lost or
    /// broken (a timeout, a cut body, a malformed answer): a sandbox may
    /// have started anyway.
    AnswerLost(String),
    /// Anything else (this agent's own state, the Klav server).
    Client(ClientError),
}

impl SandboxError {
    /// The `error` code.
    pub fn code(&self) -> &str {
        match self {
            Self::NoProxy => "klav_no_proxy",
            Self::ProxyUnreachable => "klav_proxy_unreachable",
            Self::Refused { code, .. } => code,
            Self::AnswerLost(_) => "klav_proxy_answer_lost",
            Self::Client(ClientError::Paused(_)) => "klav_agents_paused",
            Self::Client(_) => "klav_error",
        }
    }
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoProxy => f.write_str(
                "This agent has no Klav credential proxy to start sandboxes at: the person turned the account's proxy off or changed it, or stopped letting this agent start sandboxes. A sandbox can't use the API keys without copying them into it.",
            ),
            Self::ProxyUnreachable => f.write_str(
                "Klav's credential proxy did not answer on this machine (is `klav-proxy serve` running, on this port?).",
            ),
            Self::Refused { message, .. } => f.write_str(message),
            Self::AnswerLost(why) => write!(
                f,
                "Klav's credential proxy did not give a usable answer ({why}); a sandbox may have started anyway."
            ),
            Self::Client(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SandboxError {}

impl From<ClientError> for SandboxError {
    fn from(e: ClientError) -> Self {
        Self::Client(e)
    }
}

/// The client for the proxy's listener: no system proxy, no redirects.
fn local_client() -> Result<reqwest::Client, SandboxError> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(TIMEOUT)
        .build()
        .map_err(|e| SandboxError::Client(ClientError::Network(e.to_string())))
}

/// The proxy's error body.
#[derive(Deserialize)]
struct ErrorBody {
    error: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    next: String,
}

/// Sends a signed request to the proxy on `port` and returns the body of a
/// success.
async fn call(
    agent: &Agent,
    port: u16,
    method: Method,
    path: &str,
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SandboxError> {
    // The port goes in the signed query: a proxy on another port refuses
    // the request, so whatever listens on this one cannot relay it there.
    let path = format!("{path}?port={port}");
    let proof = agent.sign_request(&method, &path, body);
    let mut req = local_client()?
        .request(method, format!("http://127.0.0.1:{port}{path}"))
        .header(HEADER_AGENT, agent.id().to_string())
        .header(HEADER_TIMESTAMP, proof.timestamp_ms.to_string())
        .header(HEADER_NONCE, proof.nonce.to_text())
        .header(HEADER_SIGNATURE, proof.signature.to_text());
    if !body.is_empty() {
        req = req
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec());
    }
    let res = req.send().await.map_err(|e| {
        if e.is_connect() {
            SandboxError::ProxyUnreachable
        } else {
            SandboxError::Client(ClientError::Network(api::without_url(&e)))
        }
    })?;
    let status = res.status();
    let bytes = Zeroizing::new(api::read_limited(res, MAX_ANSWER).await?);
    if status.is_success() {
        return Ok(bytes);
    }
    match serde_json::from_slice::<ErrorBody>(&bytes) {
        Ok(b) => Err(SandboxError::Refused {
            code: b.error,
            message: b.message,
            next: b.next,
        }),
        Err(_) => Err(SandboxError::Client(ClientError::Network(format!(
            "the proxy answered {status} without an error body"
        )))),
    }
}

/// The proxy this agent's grant names, and the agent's state, checked
/// before the proxy is asked.
async fn granted_proxy(agent: &mut Agent) -> Result<klav_proto::agent::SandboxProxy, SandboxError> {
    let me = agent.me().await?;
    if me.status != AgentStatus::Active {
        return Err(SandboxError::Refused {
            code: "klav_not_issuer".into(),
            message: format!(
                "Agent {} is {}: the person has not made it a sandbox issuer.",
                agent.name(),
                me.status.as_str()
            ),
            next: format!(
                "Tell the person they can let {} start sandboxes with `klav proxy issuer add {}` in their own terminal, or in the Klav app. Do not run it yourself.",
                agent.name(),
                agent.name()
            ),
        });
    }
    if me.paused.is_some() {
        return Err(SandboxError::Client(ClientError::Paused(me.paused)));
    }
    let grant = agent.verify_grant(&me)?;
    match grant.payload.sandbox {
        Some(klav_proto::agent::IssuerGrant { proxy: Some(proxy) }) => Ok(proxy),
        Some(_) => Err(SandboxError::NoProxy),
        None => Err(SandboxError::Refused {
            code: "klav_not_issuer".into(),
            message: format!(
                "Agent {} may not start sandboxes: the person has not made it a sandbox issuer.",
                agent.name()
            ),
            next: format!(
                "Tell the person they can let {} start sandboxes with `klav proxy issuer add {}` in their own terminal, or in the Klav app. Do not run it yourself.",
                agent.name(),
                agent.name()
            ),
        }),
    }
}

/// The proxy's answer to a start.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartAnswer {
    sandbox_id: SandboxId,
    /// Moved into a zeroizing buffer right after parsing.
    secret: String,
    expires_at: i64,
}

/// Starts a sandbox at the proxy listening on `port` of this machine.
pub async fn start(
    agent: &mut Agent,
    port: u16,
    request: &StartRequest,
) -> Result<Started, SandboxError> {
    let proxy = granted_proxy(agent).await?;
    let public = PublicIdentity::decode(proxy.public_identity.as_bytes())
        .map_err(|_| ClientError::Corrupt("the proxy's identity in the grant".into()))?;
    let body = serde_json::to_vec(request)
        .map_err(|e| ClientError::Invalid(format!("request body: {e}")))?;
    // From here, a broken answer may hide a sandbox that started.
    let lost = |e: SandboxError| match e {
        SandboxError::Client(ClientError::Network(why)) => SandboxError::AnswerLost(why),
        e => e,
    };
    let answer = call(agent, port, Method::POST, API, &body)
        .await
        .map_err(lost)?;
    let answer: StartAnswer = serde_json::from_slice(&answer)
        .map_err(|_| SandboxError::AnswerLost("the answer is not a sandbox".into()))?;
    let secret_text = Zeroizing::new(answer.secret);
    let secret: Zeroizing<[u8; SECRET_LEN]> = Zeroizing::new(
        Blob::from_text(&secret_text)
            .and_then(|b| {
                let bytes = Zeroizing::new(b.into_bytes());
                <[u8; SECRET_LEN]>::try_from(bytes.as_slice()).ok()
            })
            .ok_or_else(|| SandboxError::AnswerLost("the secret is malformed".into()))?,
    );
    let expires_at_ms = u64::try_from(answer.expires_at)
        .ok()
        .filter(|t| *t > 0)
        .ok_or_else(|| SandboxError::AnswerLost("the expiry is not a time".into()))?;
    let package = match klav_core::crypto::sandbox::encode_package(&SandboxPackage {
        sandbox_id: answer.sandbox_id,
        secret: SandboxSecret::from_bytes(&secret),
        expires_at_ms,
        proxy_pin: proxy_pin(&public),
        url: proxy.url,
    }) {
        Ok(package) => package,
        // The sandbox started, and nobody can have its package: end it.
        Err(_) => {
            let id = answer.sandbox_id;
            return Err(match stop(agent, port, id).await {
                Ok(_) => SandboxError::Client(ClientError::Corrupt(format!(
                    "the proxy's address in this agent's grant; sandbox {id} started without a package and was stopped"
                ))),
                Err(_) => SandboxError::AnswerLost(format!(
                    "sandbox {id} started, but the proxy's address in this agent's grant is not valid, so it has no package, and it could not be stopped"
                )),
            });
        }
    };
    Ok(Started {
        package,
        sandbox_id: answer.sandbox_id,
        expires_at: answer.expires_at,
    })
}

/// This issuer's live sandboxes at the proxy on `port`.
///
/// Unlike [`start`], it does not check this agent's state first: the proxy
/// answers an issuer in its grant even during a pause.
pub async fn list(agent: &Agent, port: u16) -> Result<Vec<LiveSandbox>, SandboxError> {
    #[derive(Deserialize)]
    struct Answer {
        sandboxes: Vec<LiveSandbox>,
    }
    let bytes = call(agent, port, Method::GET, API, &[]).await?;
    let answer: Answer = serde_json::from_slice(&bytes)
        .map_err(|_| ClientError::Network("the proxy's list is malformed".into()))?;
    Ok(answer.sandboxes)
}

/// Stops one of this issuer's sandboxes. Returns whether the Klav server
/// already logged the end (otherwise the proxy sends it when it can).
///
/// It works during a pause: ending a sandbox only takes access away.
pub async fn stop(agent: &Agent, port: u16, id: SandboxId) -> Result<bool, SandboxError> {
    #[derive(Deserialize)]
    struct Answer {
        logged: bool,
    }
    let bytes = call(agent, port, Method::POST, &format!("{API}/{id}/stop"), &[]).await?;
    let answer: Answer = serde_json::from_slice(&bytes)
        .map_err(|_| ClientError::Network("the proxy's answer is malformed".into()))?;
    Ok(answer.logged)
}
