//! The issuer's side of sandboxes (ADR 0036 §4, E1.3, E6; layer 5): start,
//! list and stop sandboxes at the account's credential proxy.
//!
//! The issuer talks to its proxy one of two ways, with a request signed
//! like one to the Klav server (spec §13.3):
//!
//! - **A proxy on this machine** (self-hosted, the default): its loopback
//!   listener, `http://127.0.0.1:<port>/_klav/sandboxes?port=<port>` (D3).
//!   It never follows a redirect or an `HTTP_PROXY`: the answer to a start
//!   carries the sandbox's one-time secret.
//! - **Klav Cloud's hosted proxy** (ADR 0051 §6.4), when the grant's proxy
//!   URL is the account's channel, `tls://a<agent_id hex>.<endpoint>:<port>`
//!   with the grant's own proxy `agent_id`: the pinned TLS 1.3 channel,
//!   ended inside the enclave, with `?channel=<name>` signed in the query
//!   ([`klav_forward::issuer`]). Never the hosted proxy's public API, whose
//!   TLS ends at the load balancer: the secret would cross the host in
//!   the clear (threat T276).
//!
//! [`start_routed`] and [`route`] pick the way from the grant; [`start`],
//! [`list`], [`stop`] and [`mcp_endpoints`] keep the loopback listener.
//!
//! The package (`ksb1_`, spec §13.10) is built here, from the proxy's
//! answer (the ID, the secret, the expiry) and from **this agent's own
//! grant**, signed by the account: the proxy's address and its pin. A
//! process that took the proxy's port cannot point a sandbox at another
//! address or key.

use std::time::Duration;

use klav_client::{ClientError, api};
use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::sandbox::{
    PIN_LEN, SECRET_LEN, SandboxPackage, SandboxSecret, URL_SCHEME, proxy_pin,
};
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
/// The environment variable that dials Klav Cloud's channel at another
/// address (`HOST:PORT`) than its name, with the same name and pin: a
/// relay, or a test. It never changes which proxy is trusted: the pin
/// does.
pub const HOSTED_CHANNEL_ADDR_ENV: &str = "KLAV_HOSTED_PROXY_CHANNEL_ADDR";
/// Times a hosted request refused as unsigned is sent again, with a new
/// signature. The enclave starts an account's proxy on its first
/// connection, and the proxy takes nothing signed before it started (its
/// nonces from before are gone), so the first request to an account that
/// was idle is refused once.
const HOSTED_RETRIES: usize = 2;
/// Longest `list` and `stop` wait for the grant to pick the way to the
/// proxy; past it they ask the loopback listener, as before.
const ROUTE_TIMEOUT: Duration = Duration::from_secs(5);

/// Where the issuer reaches its proxy's sandbox API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyRoute {
    /// The proxy's loopback listener on this machine.
    Local {
        /// Its port (`klav-proxy serve --port`).
        port: u16,
    },
    /// Klav Cloud's hosted proxy, on the account's pinned channel.
    Hosted(HostedChannel),
}

/// The account's channel at Klav Cloud's hosted proxy (ADR 0051 §3.4).
/// Nothing in it is secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedChannel {
    /// `a<agent_id hex>.<endpoint>`: the SNI, the `Host` and the signed
    /// `?channel=`.
    pub name: String,
    /// What is dialed: `name:port`, or [`HOSTED_CHANNEL_ADDR_ENV`].
    pub address: String,
    /// The pin of the grant's proxy.
    pub pin: [u8; PIN_LEN],
}

impl ProxyRoute {
    /// The way to the proxy the grant names: its channel when the grant's
    /// URL is Klav Cloud's channel of that very proxy agent
    /// ([`hosted_channel`]), otherwise the loopback listener on `port`.
    /// `channel_addr` dials the channel elsewhere, with the same name and
    /// pin.
    pub fn for_proxy(
        proxy: &klav_proto::agent::SandboxProxy,
        port: u16,
        channel_addr: Option<&str>,
    ) -> Self {
        let Some((name, address)) = hosted_channel(proxy) else {
            return Self::Local { port };
        };
        let Ok(public) = PublicIdentity::decode(proxy.public_identity.as_bytes()) else {
            return Self::Local { port };
        };
        Self::Hosted(HostedChannel {
            name,
            address: channel_addr
                .map(str::trim)
                .filter(|a| !a.is_empty())
                .map_or(address, str::to_owned),
            pin: proxy_pin(&public),
        })
    }
}

/// The channel name and address when `proxy.url` is Klav Cloud's channel
/// of exactly `proxy.agent_id`: `tls://a<agent_id hex>.<domain>:<port>`,
/// the host in lower case, a domain of DNS letters, digits, `-` and `.`,
/// and a port. Anything else (an IP, another agent's channel, a host of a
/// self-hosted proxy) is `None`.
pub fn hosted_channel(proxy: &klav_proto::agent::SandboxProxy) -> Option<(String, String)> {
    let address = proxy.url.strip_prefix(URL_SCHEME)?;
    let (host, port) = address.rsplit_once(':')?;
    let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
    let host = host.to_ascii_lowercase();
    let prefix = format!(
        "a{}.",
        data_encoding::HEXLOWER.encode(proxy.agent_id.as_bytes())
    );
    let domain = host.strip_prefix(&prefix)?;
    let valid = !domain.is_empty()
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
        && domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && domain.bytes().any(|b| b.is_ascii_lowercase());
    valid.then(|| (host.clone(), format!("{host}:{port}")))
}

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
    /// The way it was started: the same proxy lists and stops it.
    pub route: ProxyRoute,
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
    /// Klav Cloud's channel did not answer, or did not present the key the
    /// grant pins (`klav_proxy_unreachable`). Nothing was sent.
    ChannelUnreachable,
    /// The channel answered as a channel without the issuer API (its
    /// fallback refused a key bound to no sandbox): an enclave image from
    /// before ADR 0051 §19, or a self-hosted proxy at an address shaped
    /// like Klav Cloud's (`klav_proxy_unreachable`). Nothing was done.
    ChannelWithoutIssuerApi,
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
            Self::ProxyUnreachable | Self::ChannelUnreachable | Self::ChannelWithoutIssuerApi => {
                "klav_proxy_unreachable"
            }
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
            Self::ChannelUnreachable => f.write_str(
                "Klav Cloud's credential proxy did not answer on this account's channel, or did not present the key this agent's grant pins.",
            ),
            Self::ChannelWithoutIssuerApi => f.write_str(
                "The proxy on this account's channel does not serve the sandbox issuer API: Klav Cloud's proxy may be older than this klav, or this agent's grant names another proxy at that address.",
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

/// Sends a signed request to the proxy the way `route` says and returns
/// the body of a success.
async fn call(
    agent: &Agent,
    route: &ProxyRoute,
    method: Method,
    path: &str,
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SandboxError> {
    match route {
        ProxyRoute::Local { port } => call_local(agent, *port, method, path, body).await,
        ProxyRoute::Hosted(channel) => call_hosted(agent, channel, method, path, body).await,
    }
}

/// Sends a signed request to Klav Cloud's channel (ADR 0051 §6.4): the
/// channel's name goes in the signed query, so no relay can take it to
/// another account's channel. A refusal as unsigned is sent again with a
/// new signature ([`HOSTED_RETRIES`]): nothing was done on it.
async fn call_hosted(
    agent: &Agent,
    channel: &HostedChannel,
    method: Method,
    path: &str,
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SandboxError> {
    let path = format!("{path}?channel={}", channel.name);
    let mut attempt = 0;
    loop {
        let proof = agent.sign_request(&method, &path, body);
        let headers = [
            (HEADER_AGENT, agent.id().to_string()),
            (HEADER_TIMESTAMP, proof.timestamp_ms.to_string()),
            (HEADER_NONCE, proof.nonce.to_text()),
            (HEADER_SIGNATURE, proof.signature.to_text()),
        ];
        let answer = klav_forward::issuer::send(&klav_forward::issuer::IssuerRequest {
            address: &channel.address,
            name: &channel.name,
            pin: channel.pin,
            method: method.as_str(),
            path: &path,
            headers: &headers,
            body,
            wait: TIMEOUT,
        })
        .await
        .map_err(|e| match e {
            klav_forward::issuer::IssuerIoError::Unreachable => SandboxError::ChannelUnreachable,
            klav_forward::issuer::IssuerIoError::Invalid => SandboxError::Client(
                ClientError::Corrupt("the proxy's channel in this agent's grant".into()),
            ),
            klav_forward::issuer::IssuerIoError::Lost => SandboxError::Client(
                ClientError::Network("Klav Cloud's channel gave no whole answer".into()),
            ),
        })?;
        if (200..300).contains(&answer.status) {
            return Ok(answer.body);
        }
        let refused = refusal(answer.status, &answer.body);
        // Only the issuer API's own refusal of a signature: the channel's
        // fallback (an enclave without the issuer API) answers `401` with
        // another code, and trying again changes nothing.
        if answer.status == 401
            && matches!(&refused, SandboxError::Refused { code, .. } if code != "klav_not_allowed")
        {
            return Err(SandboxError::ChannelWithoutIssuerApi);
        }
        if answer.status == 401 && attempt < HOSTED_RETRIES {
            attempt += 1;
            tokio::time::sleep(Duration::from_millis(500 * attempt as u64)).await;
            continue;
        }
        return Err(refused);
    }
}

/// The proxy's refusal, from its error body.
fn refusal(status: u16, bytes: &[u8]) -> SandboxError {
    match serde_json::from_slice::<ErrorBody>(bytes) {
        Ok(b) => SandboxError::Refused {
            code: b.error,
            message: b.message,
            next: b.next,
        },
        Err(_) => SandboxError::Client(ClientError::Network(format!(
            "the proxy answered {status} without an error body"
        ))),
    }
}

/// Sends a signed request to the proxy on `port` and returns the body of a
/// success.
async fn call_local(
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

/// The way to the proxy this agent's grant names, for `list` and `stop`:
/// Klav Cloud's channel when the grant says so ([`ProxyRoute::for_proxy`]),
/// otherwise the loopback listener on `port`. It does not refuse a paused
/// or stopped agent (listing and stopping only take access away), and a
/// grant it cannot read (the Klav server out of reach, an agent that is
/// not an issuer) leaves the loopback listener, which answers as before;
/// so does a server that takes more than 5 seconds to answer.
pub async fn route(agent: &mut Agent, port: u16, channel_addr: Option<&str>) -> ProxyRoute {
    let Ok(Ok(me)) = tokio::time::timeout(ROUTE_TIMEOUT, agent.me()).await else {
        return ProxyRoute::Local { port };
    };
    let Ok(grant) = agent.verify_grant(&me) else {
        return ProxyRoute::Local { port };
    };
    match grant.payload.sandbox {
        Some(klav_proto::agent::IssuerGrant { proxy: Some(proxy) }) => {
            ProxyRoute::for_proxy(&proxy, port, channel_addr)
        }
        _ => ProxyRoute::Local { port },
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
    start_via(agent, port, None, request).await
}

/// Starts a sandbox at the proxy this agent's grant names: Klav Cloud's
/// channel when the grant's URL is the channel of its proxy agent
/// (dialed at `channel_addr` when given), otherwise the loopback listener
/// on `port`. [`Started::route`] says which, for the calls that follow.
pub async fn start_routed(
    agent: &mut Agent,
    port: u16,
    channel_addr: Option<&str>,
    request: &StartRequest,
) -> Result<Started, SandboxError> {
    start_via(agent, port, Some(channel_addr), request).await
}

/// `routed`: `None` keeps the loopback listener whatever the grant says.
async fn start_via(
    agent: &mut Agent,
    port: u16,
    routed: Option<Option<&str>>,
    request: &StartRequest,
) -> Result<Started, SandboxError> {
    let proxy = granted_proxy(agent).await?;
    let route = match routed {
        Some(channel_addr) => ProxyRoute::for_proxy(&proxy, port, channel_addr),
        None => ProxyRoute::Local { port },
    };
    let public = PublicIdentity::decode(proxy.public_identity.as_bytes())
        .map_err(|_| ClientError::Corrupt("the proxy's identity in the grant".into()))?;
    let body = serde_json::to_vec(request)
        .map_err(|e| ClientError::Invalid(format!("request body: {e}")))?;
    // From here, a broken answer may hide a sandbox that started.
    let lost = |e: SandboxError| match e {
        SandboxError::Client(ClientError::Network(why)) => SandboxError::AnswerLost(why),
        e => e,
    };
    let answer = call(agent, &route, Method::POST, API, &body)
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
            return Err(match stop_at(agent, &route, id).await {
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
        route,
    })
}

/// This issuer's live sandboxes at the proxy on `port`.
///
/// Unlike [`start`], it does not check this agent's state first: the proxy
/// answers an issuer in its grant even during a pause.
pub async fn list(agent: &Agent, port: u16) -> Result<Vec<LiveSandbox>, SandboxError> {
    list_at(agent, &ProxyRoute::Local { port }).await
}

/// [`list`], at the proxy `route` names.
pub async fn list_at(agent: &Agent, route: &ProxyRoute) -> Result<Vec<LiveSandbox>, SandboxError> {
    #[derive(Deserialize)]
    struct Answer {
        sandboxes: Vec<LiveSandbox>,
    }
    let bytes = call(agent, route, Method::GET, API, &[]).await?;
    let answer: Answer = serde_json::from_slice(&bytes)
        .map_err(|_| ClientError::Network("the proxy's list is malformed".into()))?;
    Ok(answer.sandboxes)
}

/// An MCP profile this issuer's sandboxes may use, and its endpoint, as
/// the proxy lists it (ADR 0049, layer 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpEndpoint {
    /// The profile.
    pub profile: String,
    /// Its MCP endpoint on the upstream (`/mcp`).
    pub endpoint: String,
}

/// The MCP profiles this issuer's sandboxes may use at the proxy on
/// `port`, with their endpoints. A proxy older than the MCP gateway lists
/// none.
pub async fn mcp_endpoints(agent: &Agent, port: u16) -> Result<Vec<McpEndpoint>, SandboxError> {
    mcp_endpoints_at(agent, &ProxyRoute::Local { port }).await
}

/// [`mcp_endpoints`], at the proxy `route` names.
pub async fn mcp_endpoints_at(
    agent: &Agent,
    route: &ProxyRoute,
) -> Result<Vec<McpEndpoint>, SandboxError> {
    #[derive(Deserialize)]
    struct Answer {
        #[serde(default)]
        mcp: Vec<McpEndpoint>,
    }
    let bytes = call(agent, route, Method::GET, API, &[]).await?;
    let answer: Answer = serde_json::from_slice(&bytes)
        .map_err(|_| ClientError::Network("the proxy's list is malformed".into()))?;
    Ok(answer.mcp)
}

/// Stops one of this issuer's sandboxes. Returns whether the Klav server
/// already logged the end (otherwise the proxy sends it when it can).
///
/// It works during a pause: ending a sandbox only takes access away.
pub async fn stop(agent: &Agent, port: u16, id: SandboxId) -> Result<bool, SandboxError> {
    stop_at(agent, &ProxyRoute::Local { port }, id).await
}

/// [`stop`], at the proxy `route` names.
pub async fn stop_at(
    agent: &Agent,
    route: &ProxyRoute,
    id: SandboxId,
) -> Result<bool, SandboxError> {
    #[derive(Deserialize)]
    struct Answer {
        logged: bool,
    }
    let bytes = call(agent, route, Method::POST, &format!("{API}/{id}/stop"), &[]).await?;
    let answer: Answer = serde_json::from_slice(&bytes)
        .map_err(|_| ClientError::Network("the proxy's answer is malformed".into()))?;
    Ok(answer.logged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use klav_core::crypto::identity::IdentityKeyPair;
    use klav_core::ids::AgentId;
    use klav_proto::agent::SandboxProxy;

    fn proxy(agent: AgentId, url: &str, identity: &IdentityKeyPair) -> SandboxProxy {
        SandboxProxy {
            agent_id: agent,
            public_identity: Blob::new(identity.public().encode().to_vec()),
            url: url.into(),
        }
    }

    fn hex(agent: AgentId) -> String {
        data_encoding::HEXLOWER.encode(agent.as_bytes())
    }

    /// ADR 0051 §6.4: only the channel of the grant's own proxy agent
    /// routes to Klav Cloud; every other URL keeps the loopback listener.
    #[test]
    fn only_the_grants_own_channel_is_hosted() {
        let id = IdentityKeyPair::generate();
        let agent = AgentId::from_bytes([0xab; 16]);
        let other = AgentId::from_bytes([0xcd; 16]);
        let name = format!("a{}.proxy.klav.dev", hex(agent));
        let hosted =
            ProxyRoute::for_proxy(&proxy(agent, &format!("tls://{name}:443"), &id), 8790, None);
        assert_eq!(
            hosted,
            ProxyRoute::Hosted(HostedChannel {
                name: name.clone(),
                address: format!("{name}:443"),
                pin: proxy_pin(id.public()),
            })
        );
        // Upper case in the grant: the same channel, in lower case.
        let upper = format!("tls://{}:443", name.to_ascii_uppercase());
        assert!(matches!(
            ProxyRoute::for_proxy(&proxy(agent, &upper, &id), 8790, None),
            ProxyRoute::Hosted(HostedChannel { name: n, .. }) if n == name
        ));
        // The address can be another; the name and the pin cannot.
        let relayed = ProxyRoute::for_proxy(
            &proxy(agent, &format!("tls://{name}:443"), &id),
            8790,
            Some("127.0.0.1:9443"),
        );
        assert!(matches!(
            relayed,
            ProxyRoute::Hosted(HostedChannel { address, name: n, .. })
                if address == "127.0.0.1:9443" && n == name
        ));
        for url in [
            // Another agent's channel: never this proxy's.
            format!("tls://a{}.proxy.klav.dev:443", hex(other)),
            // A self-hosted proxy.
            "tls://proxy.example.com:8443".into(),
            "tls://127.0.0.1:8443".into(),
            "tls://[::1]:8443".into(),
            // Not quite the channel.
            format!("tls://a{}:443", hex(agent)),
            format!("tls://a{}.:443", hex(agent)),
            format!("tls://a{}..klav.dev:443", hex(agent)),
            format!("tls://a{}.123:443", hex(agent)),
            format!("tls://a{}.proxy.klav.dev", hex(agent)),
            format!("tls://a{}.proxy.klav.dev:0", hex(agent)),
            format!("tls://xa{}.proxy.klav.dev:443", hex(agent)),
            format!("https://a{}.proxy.klav.dev:443", hex(agent)),
            format!("tls://a{}.proxy_klav.dev:443", hex(agent)),
        ] {
            assert_eq!(
                ProxyRoute::for_proxy(&proxy(agent, &url, &id), 8790, Some("127.0.0.1:1")),
                ProxyRoute::Local { port: 8790 },
                "{url}"
            );
        }
    }
}
