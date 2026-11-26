//! The MCP gateway (ADR 0049 §5): an MCP profile's JSON-RPC, read,
//! checked and filtered on its way through the proxy.
//!
//! **The request path** ([`forward`], §5.1), in order, before the server
//! is asked:
//!
//! 1. the caller: a sandbox through the pinned channel, or on loopback a
//!    local client whose `klc1_` token the proxy's grant has for this
//!    profile (§3.2);
//! 2. `POST`, `GET` or `DELETE` on the exact endpoint, without a query;
//! 3. the headers: an `MCP-Session-Id` this caller opened (T266),
//!    `MCP-Protocol-Version` `2025-06-18` or `2025-11-25` on everything but
//!    `initialize`, and `Content-Type: application/json` without
//!    `Content-Encoding` on a `POST`;
//! 4. the body: at most [`MAX_REQUEST`], strict JSON ([`jsonrpc`]);
//! 5. its shape: one object, never a batch (T254);
//! 6. its method: lifecycle, `ping` (answered here), `tools/list`, and
//!    `tools/call` with an `id`, a tool name in the grammar and the tool
//!    rules (§5.3); everything else refused with a JSON-RPC error;
//! 7. one `POST /v1/agent/access` per forwarded message, with
//!    `mcp_tool`/`mcp_args` for a tool call and `local_client` while the
//!    account's switch is on;
//! 8. the bytes received, forwarded as they are (T255).
//!
//! **The answer** (§5.2): after the redactor, a JSON body or each SSE event
//! must be one JSON-RPC message. A response passes only once, and only
//! against a request this caller sent ([`McpState`]); a `tools/list` answer
//! is filtered wherever it arrives (T264); a server `ping` passes, other
//! server requests are dropped (T262); `WWW-Authenticate` never passes
//! (T265).
//!
//! Proxy-made refusals of a request are HTTP `200` with a JSON-RPC error
//! and a `Klav-Error` header, so the client shows them to the model;
//! malformed bodies and refused notifications or responses are `400`.

pub mod jsonrpc;
pub mod sse;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use klav_core::ids::SandboxId;
use klav_core::policy::{self, Effect, Permission, Target};
use serde_json::json;
use serde_json::value::RawValue;

use crate::errors::{Blocked, KLAV_ERROR, NotAllowed, ProxyError};
use crate::profiles::Profile;
use crate::proxy::{BodyTransform, Caller, McpClaims, Outgoing, ProxyState};
use jsonrpc::{ClientMessage, Members, Refused, RpcId, ServerMessage};

/// Largest request body (ADR 0049 §5.1).
pub const MAX_REQUEST: usize = 1024 * 1024;
/// Largest JSON answer, or SSE event (ADR 0049 §5.2).
pub const MAX_ANSWER: usize = sse::MAX_EVENT;
/// The protocol revisions the proxy speaks: none of them has batches.
pub const PROTOCOL_VERSIONS: [&str; 2] = ["2025-06-18", "2025-11-25"];
/// How long a forwarded request waits for its response: the longest a
/// stream lives (M3).
pub const PENDING_TTL: Duration = crate::proxy::STREAM_MAX;
/// Sessions (and callers without one) the proxy keeps at most; the ones
/// used least recently go first.
const MAX_CONVERSATIONS: usize = 1024;
/// Requests waiting for a response, per conversation.
const MAX_PENDING: usize = 256;
/// Tool definitions remembered for rug-pull detection.
const MAX_DEFINITIONS: usize = 8192;
/// Server notifications that pass to the client (ADR 0049 §5.2).
const PASSING_NOTIFICATIONS: [&str; 4] = [
    "notifications/tools/list_changed",
    "notifications/progress",
    "notifications/message",
    "notifications/cancelled",
];

/// Who calls, as the gateway's tables key it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum CallerKey {
    /// A local client, by the name the person signed.
    Local(String),
    /// A sandbox.
    Sandbox(SandboxId),
}

/// One caller's conversation with one profile: its session, or none for a
/// server that keeps none.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Conversation {
    profile: String,
    caller: CallerKey,
    session: Option<String>,
}

/// The gateway's memory (ADR 0049 §5.2): sessions and their callers,
/// requests waiting for their response, server pings waiting for the
/// client's answer, and a digest of each tool definition shown.
#[derive(Default)]
pub struct McpState {
    tables: Mutex<Tables>,
    /// Tool definitions seen to change since start (only a number).
    changed: std::sync::atomic::AtomicU64,
}

#[derive(Default)]
struct Tables {
    /// `(profile, MCP-Session-Id)` → the caller that opened it.
    sessions: HashMap<(String, String), (CallerKey, Instant)>,
    conversations: HashMap<Conversation, Waiting>,
    /// `(profile, tool)` → digest of the definition last shown.
    definitions: HashMap<(String, String), [u8; 32]>,
    next_token: u64,
}

struct Waiting {
    requests: Vec<Expected>,
    pings: Vec<(RpcId, Instant)>,
    last: Instant,
}

struct Expected {
    id: RpcId,
    method: String,
    token: u64,
    at: Instant,
}

impl Tables {
    fn prune(&mut self, now: Instant) {
        for w in self.conversations.values_mut() {
            w.requests
                .retain(|r| now.duration_since(r.at) < PENDING_TTL);
            w.pings
                .retain(|(_, at)| now.duration_since(*at) < PENDING_TTL);
        }
        self.conversations.retain(|_, w| {
            !w.requests.is_empty()
                || !w.pings.is_empty()
                || now.duration_since(w.last) < PENDING_TTL
        });
        while self.conversations.len() > MAX_CONVERSATIONS {
            let Some(oldest) = self
                .conversations
                .iter()
                .min_by_key(|(_, w)| w.last)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.conversations.remove(&oldest);
        }
        while self.sessions.len() > MAX_CONVERSATIONS {
            let Some(oldest) = self
                .sessions
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.sessions.remove(&oldest);
        }
    }

    fn waiting(&mut self, conv: &Conversation, now: Instant) -> &mut Waiting {
        let w = self
            .conversations
            .entry(conv.clone())
            .or_insert_with(|| Waiting {
                requests: Vec::new(),
                pings: Vec::new(),
                last: now,
            });
        w.last = now;
        w
    }
}

/// Whether an `MCP-Session-Id` this caller presents is one it opened.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SessionCheck {
    /// It opened it.
    Own,
    /// Another caller did, or the proxy never saw it opened (a restart
    /// forgets every session): refused alike.
    Unknown,
}

impl McpState {
    fn tables(&self) -> std::sync::MutexGuard<'_, Tables> {
        self.tables.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Tool definitions seen to change behind the same name since start.
    pub fn changed_definitions(&self) -> u64 {
        self.changed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether `caller` opened session `id` on `profile`.
    pub(crate) fn check_session(
        &self,
        profile: &str,
        id: &str,
        caller: &CallerKey,
    ) -> SessionCheck {
        let mut t = self.tables();
        match t.sessions.get_mut(&(profile.to_owned(), id.to_owned())) {
            Some((owner, at)) if owner == caller => {
                *at = Instant::now();
                SessionCheck::Own
            }
            _ => SessionCheck::Unknown,
        }
    }

    /// Binds session `id` to `caller`, from an `initialize` answer: `false`
    /// when another caller holds it (the answer is then refused).
    pub(crate) fn bind_session(&self, profile: &str, id: &str, caller: &CallerKey) -> bool {
        let mut t = self.tables();
        let now = Instant::now();
        t.prune(now);
        match t.sessions.get(&(profile.to_owned(), id.to_owned())) {
            Some((owner, _)) if owner != caller => false,
            _ => {
                t.sessions
                    .insert((profile.to_owned(), id.to_owned()), (caller.clone(), now));
                true
            }
        }
    }

    /// Forgets session `id` and what waits in it (a `DELETE` the server
    /// took).
    pub(crate) fn end_session(&self, profile: &str, id: &str) {
        let mut t = self.tables();
        t.sessions.remove(&(profile.to_owned(), id.to_owned()));
        t.conversations
            .retain(|c, _| !(c.profile == profile && c.session.as_deref() == Some(id)));
    }

    /// Records a request forwarded in `conv`; the token names this one
    /// entry for the answer on its own `POST`.
    pub(crate) fn expect(&self, conv: &Conversation, id: &RpcId, method: &str) -> u64 {
        let mut t = self.tables();
        let now = Instant::now();
        t.prune(now);
        t.next_token += 1;
        let token = t.next_token;
        let w = t.waiting(conv, now);
        if w.requests.len() >= MAX_PENDING {
            w.requests.remove(0);
        }
        w.requests.push(Expected {
            id: id.clone(),
            method: method.to_owned(),
            token,
            at: now,
        });
        token
    }

    /// Forgets the request `token` (it never reached the upstream).
    pub(crate) fn forget(&self, conv: &Conversation, token: u64) {
        let mut t = self.tables();
        if let Some(w) = t.conversations.get_mut(conv) {
            w.requests.retain(|r| r.token != token);
        }
    }

    /// The method of the request a response with `id` answers, taking it:
    /// the `POST`'s own request first (`own`), else any request of `conv`
    /// with that `id`. Several with different methods (clients of one name
    /// that number alike): the oldest is taken, and the answer is read as
    /// a `tools/list` one, which only removes. `None`: nothing waits for
    /// it, and it is dropped.
    pub(crate) fn take_response(
        &self,
        conv: &Conversation,
        own: Option<u64>,
        id: &RpcId,
    ) -> Option<String> {
        let mut t = self.tables();
        let w = t.conversations.get_mut(conv)?;
        if let Some(token) = own
            && let Some(i) = w
                .requests
                .iter()
                .position(|r| r.token == token && &r.id == id)
        {
            return Some(w.requests.remove(i).method);
        }
        let same: Vec<usize> = w
            .requests
            .iter()
            .enumerate()
            .filter(|(_, r)| &r.id == id)
            .map(|(i, _)| i)
            .collect();
        let first = *same.first()?;
        let alike = same
            .iter()
            .all(|i| w.requests[*i].method == w.requests[first].method);
        let taken = w.requests.remove(first);
        Some(if alike {
            taken.method
        } else {
            jsonrpc::TOOLS_LIST.to_owned()
        })
    }

    /// A server `ping` passed to the caller of `conv`.
    pub(crate) fn note_server_ping(&self, conv: &Conversation, id: &RpcId) {
        let mut t = self.tables();
        let now = Instant::now();
        let w = t.waiting(conv, now);
        if w.pings.len() >= MAX_PENDING {
            w.pings.remove(0);
        }
        w.pings.push((id.clone(), now));
    }

    /// Whether the caller's response `id` answers a server `ping` it got,
    /// taking it.
    pub(crate) fn take_server_ping(&self, conv: &Conversation, id: &RpcId) -> bool {
        let mut t = self.tables();
        let Some(w) = t.conversations.get_mut(conv) else {
            return false;
        };
        match w.pings.iter().position(|(p, _)| p == id) {
            Some(i) => {
                w.pings.remove(i);
                true
            }
            None => false,
        }
    }

    /// Remembers the definitions `tools/list` showed for `profile` and
    /// returns the names whose definition changed since the last list
    /// (ADR 0049 §5.2, rug-pull detection).
    fn definitions_changed(&self, profile: &str, shown: &[(String, [u8; 32])]) -> Vec<String> {
        let mut t = self.tables();
        let mut changed = Vec::new();
        for (name, digest) in shown {
            let key = (profile.to_owned(), name.clone());
            match t.definitions.get(&key) {
                Some(old) if old != digest => changed.push(name.clone()),
                Some(_) => continue,
                None if t.definitions.len() >= MAX_DEFINITIONS => continue,
                None => {}
            }
            t.definitions.insert(key, *digest);
        }
        changed
    }
}

/// The policy's view of a tool on this profile, for the `tools/list`
/// filter (ADR 0049 §5.3): the grant's rules and the request of a
/// `tools/call` on this endpoint, the tool set per name.
pub(crate) struct ToolJudge {
    policy: policy::Policy,
    base: Option<policy::Request>,
}

impl ToolJudge {
    fn effect(&self, tool: &str) -> Effect {
        let Some(base) = &self.base else {
            return Effect::Deny;
        };
        let mut request = base.clone();
        request.mcp_tool = Some(tool.to_owned());
        request.now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        policy::evaluate(&self.policy, &request).effect
    }
}

/// What reads an MCP answer: its conversation, the request its own `POST`
/// sent (if any), and the tool rules.
pub(crate) struct Inspector {
    mcp: Arc<McpState>,
    conv: Conversation,
    own: Option<u64>,
    judge: Arc<ToolJudge>,
}

impl Inspector {
    /// What one message from the upstream becomes for the client: itself,
    /// a filtered or refused `tools/list` answer, or nothing (dropped).
    /// `Err` when it is not one JSON-RPC message: the answer is cut.
    fn message(&self, bytes: &[u8]) -> Result<Option<Vec<u8>>, ()> {
        jsonrpc::check_strict(bytes).map_err(|_| ())?;
        match jsonrpc::parse_server(bytes).ok_or(())? {
            ServerMessage::Request { id, method } if method == jsonrpc::PING => {
                self.mcp.note_server_ping(&self.conv, &id);
                Ok(Some(bytes.to_vec()))
            }
            // Sampling, elicitation, roots and the rest: the client never
            // sees them, so it never answers them (T262).
            ServerMessage::Request { .. } => {
                tracing::info!(
                    profile = %self.conv.profile,
                    "dropped a request from the MCP server to the client"
                );
                Ok(None)
            }
            ServerMessage::Notification { method } => Ok(PASSING_NOTIFICATIONS
                .contains(&method.as_str())
                .then(|| bytes.to_vec())),
            ServerMessage::Response { id: None, .. } => Ok(None),
            ServerMessage::Response {
                id: Some(id),
                members,
            } => match self.mcp.take_response(&self.conv, self.own, &id) {
                None => Ok(None),
                Some(m) if m == jsonrpc::TOOLS_LIST => Ok(Some(self.tools_list(&id, &members))),
                Some(_) => Ok(Some(bytes.to_vec())),
            },
        }
    }

    /// A `tools/list` answer with the tools the rules deny and the names
    /// outside the grammar removed, the kept ones byte for byte; a list
    /// with a name twice refused whole (ADR 0049 §5.2).
    fn tools_list(&self, id: &RpcId, members: &Members) -> Vec<u8> {
        let refuse = |why: &str| {
            jsonrpc::error_bytes(
                Some(id),
                jsonrpc::KLAV_REFUSED,
                why,
                json!({ "klav_error": "klav_mcp_tools_refused" }),
            )
        };
        let Some(result) = members.get("result") else {
            // An error answer passes as it is.
            return members.write(&[]);
        };
        let Some(result) = Members::of(result) else {
            return refuse(
                "The MCP server's tool list is not an object; Klav's credential proxy refused it.",
            );
        };
        let Some(Ok(tools)) = result
            .get("tools")
            .map(|t| serde_json::from_str::<Vec<Box<RawValue>>>(t.get()))
        else {
            return refuse(
                "The MCP server's tool list has no list of tools; Klav's credential proxy refused it.",
            );
        };
        let mut names = std::collections::HashSet::new();
        let mut kept = Vec::new();
        let mut shown = Vec::new();
        for tool in &tools {
            let name = Members::of(tool)
                .and_then(|m| m.get("name").map(|n| n.get().to_owned()))
                .and_then(|n| serde_json::from_str::<String>(&n).ok());
            let Some(name) = name else {
                continue;
            };
            if !names.insert(name.clone()) {
                return refuse(
                    "The MCP server listed two tools with the same name; Klav's credential proxy refused the whole list.",
                );
            }
            if !policy::tool_name_ok(&name) || self.judge.effect(&name) == Effect::Deny {
                continue;
            }
            shown.push((
                name,
                klav_core::crypto::mcp::tool_definition_digest(tool.get().as_bytes()),
            ));
            kept.push(tool.get());
        }
        for name in self.mcp.definitions_changed(&self.conv.profile, &shown) {
            self.mcp
                .changed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // The name is in the tool grammar; never the definition.
            tracing::warn!(
                profile = %self.conv.profile,
                tool = %name,
                "an MCP tool's definition changed since the proxy last listed it"
            );
        }
        let list = format!("[{}]", kept.join(","));
        let result = result.write(&[("tools", list.as_bytes())]);
        members.write(&[("result", &result)])
    }
}

/// A JSON answer: held whole (at most [`MAX_ANSWER`]), then one message.
/// `lenient` (an error status): a body that is not a JSON-RPC message is
/// left out instead of cutting the answer.
struct JsonAnswer {
    inspector: Inspector,
    body: Vec<u8>,
    lenient: bool,
}

impl BodyTransform for JsonAnswer {
    fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, ()> {
        if self.body.len() + bytes.len() > MAX_ANSWER {
            return Err(());
        }
        self.body.extend_from_slice(bytes);
        Ok(Vec::new())
    }

    fn finish(&mut self) -> Result<Vec<u8>, ()> {
        if self.body.iter().all(u8::is_ascii_whitespace) {
            return Ok(Vec::new());
        }
        match self.inspector.message(&self.body) {
            Ok(out) => Ok(out.unwrap_or_default()),
            Err(()) if self.lenient => Ok(Vec::new()),
            Err(()) => Err(()),
        }
    }
}

/// An SSE answer, event by event.
struct SseAnswer {
    inspector: Inspector,
    reader: sse::Reader,
}

impl BodyTransform for SseAnswer {
    fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, ()> {
        let mut out = Vec::new();
        for event in self.reader.push(bytes).map_err(|_| ())? {
            let data = match event.data() {
                // Priming, comments, `id` and `retry` alone: as they are.
                None => {
                    out.extend_from_slice(&event.to_bytes());
                    continue;
                }
                Some(d) if d.is_empty() => {
                    out.extend_from_slice(&event.to_bytes());
                    continue;
                }
                Some(d) => d,
            };
            match self.inspector.message(data.as_bytes())? {
                Some(kept) if kept == data.as_bytes() => out.extend_from_slice(&event.to_bytes()),
                Some(changed) => {
                    let changed = String::from_utf8(changed).map_err(|_| ())?;
                    out.extend_from_slice(&event.with_data(changed).to_bytes());
                }
                None => {
                    if let Some(rest) = event.without_data() {
                        out.extend_from_slice(&rest.to_bytes());
                    }
                }
            }
        }
        Ok(out)
    }

    fn finish(&mut self) -> Result<Vec<u8>, ()> {
        // An event without its blank line is discarded, as a client does.
        Ok(Vec::new())
    }
}

/// Anything else (an error page, `202` with a body): left out.
struct Discard;

impl BodyTransform for Discard {
    fn push(&mut self, _: &[u8]) -> Result<Vec<u8>, ()> {
        Ok(Vec::new())
    }
    fn finish(&mut self) -> Result<Vec<u8>, ()> {
        Ok(Vec::new())
    }
}

/// A JSON-RPC error answer made by the proxy, with its `Klav-Error`.
fn rpc_error(
    status: StatusCode,
    id: Option<&RpcId>,
    code: i64,
    klav_error: &'static str,
    message: &str,
    mut data: serde_json::Value,
) -> Response {
    data["klav_error"] = json!(klav_error);
    let mut res = Response::new(Body::from(jsonrpc::error_bytes(id, code, message, data)));
    *res.status_mut() = status;
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    res.headers_mut()
        .insert(KLAV_ERROR, HeaderValue::from_static(klav_error));
    log_refusal(klav_error);
    res
}

fn log_refusal(klav_error: &'static str) {
    tracing::info!(error = klav_error, "refused an MCP message");
}

/// A malformed body or a refused notification or response: `400`, `id`
/// `null`.
fn malformed(refused: Refused) -> Response {
    rpc_error(
        StatusCode::BAD_REQUEST,
        None,
        refused.code,
        "klav_mcp_refused",
        refused.why,
        json!({}),
    )
}

/// What a tool call is about, for the texts of its refusals.
struct ToolCtx<'a> {
    profile: &'a str,
    tool: &'a str,
    sandbox: bool,
}

/// A refusal of the proxy or the server for request `id`, as a JSON-RPC
/// error (HTTP `200`).
fn rpc_from(e: &ProxyError, id: &RpcId, tool: Option<&ToolCtx<'_>>) -> Response {
    let mut data = json!({ "next": e.next() });
    let message: String = match (e, tool) {
        (
            ProxyError::ApprovalPending {
                approval_id,
                expires_at,
            },
            Some(t),
        ) => {
            data["approval_id"] = json!(approval_id.to_string());
            data["expires_at"] = json!(expires_at);
            let wait = if t.sandbox {
                format!(
                    " In this sandbox, run `klav-forward approval wait {approval_id}` in the background and call the tool again when it exits 0."
                )
            } else {
                String::new()
            };
            data["next"] = json!(
                "Tell the person, wait for them to say it's done, then call the same tool again with the same arguments. Don't call it in a loop."
            );
            format!(
                "The person has to approve `{} · {}` on their Mac or iPhone. Tell them, wait for them to say it's done, then call the same tool again with the same arguments. Don't call it in a loop.{wait}",
                t.profile, t.tool
            )
        }
        (
            ProxyError::ApprovalPending {
                approval_id,
                expires_at,
            },
            None,
        ) => {
            data["approval_id"] = json!(approval_id.to_string());
            data["expires_at"] = json!(expires_at);
            e.message().into_owned()
        }
        (ProxyError::ApprovalDenied, Some(t)) => {
            format!(
                "The person denied the call to `{} · {}`.",
                t.profile, t.tool
            )
        }
        (
            ProxyError::NotAllowed(
                NotAllowed::ServerDenied
                | NotAllowed::Policy
                | NotAllowed::OutsidePath
                | NotAllowed::OutsideMethod
                | NotAllowed::OutsideMethodOnPath,
            ),
            Some(t),
        ) => format!(
            "The person's rules for `{}` don't allow the tool `{}`.",
            t.profile, t.tool
        ),
        (ProxyError::RateLimited { retry_after }, _) => {
            data["retry_after"] = json!(retry_after);
            e.message().into_owned()
        }
        _ => e.message().into_owned(),
    };
    rpc_error(
        StatusCode::OK,
        Some(id),
        jsonrpc::KLAV_REFUSED,
        e.code(),
        &message,
        data,
    )
}

/// The one value of header `name`: `Ok(None)` without it, `Err` with
/// several or one that is not visible ASCII.
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ()> {
    let mut all = headers.get_all(name).iter();
    match (all.next(), all.next()) {
        (None, _) => Ok(None),
        (Some(v), None) => {
            let v = v.to_str().map_err(|_| ())?;
            if v.is_empty() || !v.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
                return Err(());
            }
            Ok(Some(v))
        }
        _ => Err(()),
    }
}

/// Whether a `Content-Type` is `application/json` (parameters allowed).
fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
}

/// The local client calling on loopback (ADR 0049 §3.2): the one whose
/// token digest matches the bearer, compared in constant time, allowed
/// this profile.
async fn local_client(
    state: &ProxyState,
    headers: &HeaderMap,
    profile: &str,
) -> Result<String, ProxyError> {
    let mut all = headers.get_all(header::AUTHORIZATION).iter();
    let (Some(value), None) = (all.next(), all.next()) else {
        return Err(ProxyError::LocalClientUnknown);
    };
    let value = value.to_str().map_err(|_| ProxyError::LocalClientUnknown)?;
    let (scheme, token) = value
        .split_once(' ')
        .ok_or(ProxyError::LocalClientUnknown)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(ProxyError::LocalClientUnknown);
    }
    let token = klav_core::crypto::mcp::LocalClientToken::new(token.to_owned());
    let session = state.session().await;
    let proxy = session.agent().id();
    let client = session
        .grant()
        .payload
        .local_clients
        .iter()
        .find(|c| token.matches(proxy, c.token_digest.as_bytes()))
        .ok_or(ProxyError::LocalClientUnknown)?;
    if !client.profiles.iter().any(|p| p == profile) {
        return Err(ProxyError::NotAllowed(NotAllowed::LocalClientProfile));
    }
    Ok(client.name.clone())
}

/// The tool rules of `profile`'s item, read under the session's lock.
async fn judge(state: &ProxyState, profile: &Profile, endpoint: &str) -> ToolJudge {
    let tags = state.seen_tags(profile.item);
    let session = state.session().await;
    let grant = session.grant();
    let base = grant.items.get(&profile.item).map(|g| policy::Request {
        permission: Permission::Proxy,
        vault: Target {
            id: g.ctx.vault,
            name: String::new(),
        },
        project: Target {
            id: g.ctx.project,
            name: String::new(),
        },
        tags,
        domain: Some(profile.upstream.host.clone()),
        item: Some(profile.item),
        method: Some("POST".into()),
        path: Some(endpoint.to_owned()),
        now: 0,
        mcp_tool: None,
    });
    ToolJudge {
        policy: grant.payload.policy.clone(),
        base,
    }
}

/// What a `POST` carries, once checked.
enum Post {
    /// A request to forward: its `id` and method, and for `tools/call` the
    /// tool and its arguments' digest.
    Request {
        id: RpcId,
        method: String,
        tool: Option<(String, String)>,
    },
    /// `notifications/initialized` or `notifications/cancelled`, or the
    /// answer to a server `ping`.
    Other,
}

/// An MCP profile's request, from its caller to its answer.
pub(crate) async fn forward(
    state: &ProxyState,
    parts: Parts,
    body: Body,
    caller: Caller,
    profile: Profile,
) -> Result<Response, ProxyError> {
    let Some(mcp) = profile.mcp.clone() else {
        return Err(ProxyError::NotAllowed(NotAllowed::UnknownProfile));
    };
    // 2. Only the endpoint, and only POST, GET and DELETE.
    let path = crate::proxy::split_profile(parts.uri.path())
        .map(|(_, p)| p)
        .unwrap_or_default();
    let method = parts.method.clone();
    if path != mcp.endpoint
        || parts.uri.query().is_some()
        || !matches!(method, Method::POST | Method::GET | Method::DELETE)
    {
        return Err(ProxyError::NotAllowed(NotAllowed::McpEndpointOnly));
    }
    // 1. Who calls.
    let who = match &caller {
        Caller::Local => {
            CallerKey::Local(local_client(state, &parts.headers, &profile.name).await?)
        }
        Caller::Sandbox { bound, .. } => CallerKey::Sandbox(bound.sandbox_id),
    };
    // 3. The headers.
    let session = single(&parts.headers, "mcp-session-id")
        .map_err(|()| ProxyError::McpRefused("MCP-Session-Id must be one value of visible ASCII"))?
        .map(str::to_owned);
    if let Some(id) = &session
        && state.mcp().check_session(&profile.name, id, &who) != SessionCheck::Own
    {
        return Err(ProxyError::McpSessionUnknown);
    }
    let version = single(&parts.headers, "mcp-protocol-version")
        .ok()
        .flatten()
        .filter(|v| PROTOCOL_VERSIONS.contains(v));
    let refused_version = ProxyError::McpRefused(
        "MCP-Protocol-Version must be 2025-06-18 or 2025-11-25 (older revisions have batches)",
    );
    if method == Method::POST {
        if !is_json(&parts.headers) {
            return Err(ProxyError::McpRefused(
                "a POST must have Content-Type: application/json",
            ));
        }
        if parts.headers.contains_key(header::CONTENT_ENCODING) {
            return Err(ProxyError::McpRefused(
                "a POST must not have a Content-Encoding",
            ));
        }
    } else if version.is_none() {
        return Err(refused_version);
    }
    let conv = Conversation {
        profile: profile.name.clone(),
        caller: who.clone(),
        session: session.clone(),
    };
    let mut permit = state.take_slots(caller.sandbox()).await?;
    let cut = state.register_cut(caller.sandbox());
    let (idle, total) = state.body_waits();
    let max = if method == Method::POST {
        MAX_REQUEST
    } else {
        0
    };
    let body = match crate::proxy::read_body(body, max, idle, total, state.body_budget()).await {
        Ok((body, held)) => {
            permit.hold(held);
            Some(body)
        }
        Err(crate::proxy::BodyError::Budget) => {
            return Err(state.body_refusal(crate::proxy::BodyError::Budget));
        }
        Err(_) => None,
    };
    let Some(body) = body else {
        if method == Method::POST {
            return Ok(malformed(Refused {
                code: jsonrpc::PARSE_ERROR,
                why: "the body is over 1 MiB, or did not arrive in time",
            }));
        }
        return Err(ProxyError::McpRefused("a GET or DELETE has no body"));
    };

    // 4–6. The message.
    let post = if method == Method::POST {
        if let Err(r) = jsonrpc::check_strict(&body) {
            return Ok(malformed(r));
        }
        let message = match jsonrpc::parse_client(&body) {
            Ok(m) => m,
            Err((_, r)) => return Ok(malformed(r)),
        };
        let initialize = matches!(&message, ClientMessage::Request { method, .. } if method == jsonrpc::INITIALIZE);
        if !initialize && version.is_none() {
            return Ok(match &message {
                ClientMessage::Request { id, .. } => rpc_error(
                    StatusCode::BAD_REQUEST,
                    Some(id),
                    jsonrpc::INVALID_REQUEST,
                    "klav_mcp_refused",
                    "MCP-Protocol-Version must be 2025-06-18 or 2025-11-25 (older revisions have batches).",
                    json!({}),
                ),
                _ => malformed(Refused {
                    code: jsonrpc::INVALID_REQUEST,
                    why: "MCP-Protocol-Version must be 2025-06-18 or 2025-11-25 (older revisions have batches).",
                }),
            });
        }
        match message {
            ClientMessage::Request { id, method, .. } if method == jsonrpc::PING => {
                // Answered here: no credential, no server, no audit entry.
                let mut res = Response::new(Body::from(jsonrpc::pong(&id)));
                res.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                return Ok(res);
            }
            ClientMessage::Request { id, method, .. }
                if method == jsonrpc::INITIALIZE || method == jsonrpc::TOOLS_LIST =>
            {
                Post::Request {
                    id,
                    method,
                    tool: None,
                }
            }
            ClientMessage::Request { id, method, params } if method == jsonrpc::TOOLS_CALL => {
                let call = match jsonrpc::parse_tool_call(params.as_deref()) {
                    Ok(c) => c,
                    Err(r) => {
                        return Ok(rpc_error(
                            StatusCode::OK,
                            Some(&id),
                            r.code,
                            "klav_mcp_refused",
                            r.why,
                            json!({}),
                        ));
                    }
                };
                // "No tool claims" mode (ADR 0049 §9).
                if !state.mcp_gateway() {
                    return Ok(rpc_error(
                        StatusCode::OK,
                        Some(&id),
                        jsonrpc::KLAV_REFUSED,
                        "klav_mcp_gateway_off",
                        "The MCP gateway isn't on for this Klav account yet, so Klav's credential proxy can't let a tool call through. The person turns it on in Klav once every device is updated.",
                        json!({ "next": "Tell the person this exact message and stop." }),
                    ));
                }
                let proxy = state.proxy_id().await;
                let args =
                    klav_core::crypto::mcp::digest_text(&klav_core::crypto::mcp::mcp_args_digest(
                        proxy,
                        profile.item,
                        &call.name,
                        &call.arguments,
                    ));
                Post::Request {
                    id,
                    method,
                    tool: Some((call.name, args)),
                }
            }
            ClientMessage::Request { id, .. } => {
                return Ok(rpc_error(
                    StatusCode::OK,
                    Some(&id),
                    jsonrpc::METHOD_NOT_FOUND,
                    "klav_mcp_method_refused",
                    "Klav's MCP gateway forwards only initialize, ping, tools/list and tools/call; resources, prompts, completions and the rest are not supported yet.",
                    json!({ "next": "Use the server's tools instead." }),
                ));
            }
            ClientMessage::Notification { method }
                if method == jsonrpc::INITIALIZED || method == jsonrpc::CANCELLED =>
            {
                Post::Other
            }
            ClientMessage::Notification { method } if method == jsonrpc::TOOLS_CALL => {
                return Ok(malformed(Refused {
                    code: jsonrpc::INVALID_REQUEST,
                    why: "tools/call must be a request with an id, never a notification",
                }));
            }
            ClientMessage::Notification { .. } => {
                return Ok(malformed(Refused {
                    code: jsonrpc::METHOD_NOT_FOUND,
                    why: "Klav's MCP gateway forwards only the notifications initialized and cancelled",
                }));
            }
            ClientMessage::Response { id, empty_result } => {
                if !empty_result || !state.mcp().take_server_ping(&conv, &id) {
                    return Ok(malformed(Refused {
                        code: jsonrpc::INVALID_REQUEST,
                        why: "a response from the client passes only as the {} answer to a ping the server sent it",
                    }));
                }
                Post::Other
            }
        }
    } else {
        Post::Other
    };

    state.check_rates(&profile, caller.sandbox())?;
    let url = reqwest::Url::parse(&format!("{}{}", profile.upstream.origin(), mcp.endpoint))
        .map_err(|_| ProxyError::NotAllowed(NotAllowed::Malformed))?;
    let mut headers = crate::proxy::forwarded_headers(&parts.headers, &profile.header);
    for (name, value) in &mcp.headers {
        headers.insert(name.clone(), value.clone());
    }
    let local = match (&who, state.mcp_gateway()) {
        (CallerKey::Local(name), true) => Some(name.as_str()),
        _ => None,
    };
    let (rpc_id, rpc_method, tool) = match &post {
        Post::Request { id, method, tool } => {
            (Some(id.clone()), Some(method.clone()), tool.clone())
        }
        Post::Other => (None, None, None),
    };
    let claims = McpClaims {
        tool: tool.as_ref().map(|(t, _)| t.as_str()),
        args: tool.as_ref().map(|(_, a)| a.as_str()),
        local_client: local,
    };
    let token = match (&rpc_id, &rpc_method) {
        (Some(id), Some(m)) => Some(state.mcp().expect(&conv, id, m)),
        _ => None,
    };
    let tool_ctx = tool.as_ref().map(|(t, _)| ToolCtx {
        profile: &profile.name,
        tool: t,
        sandbox: caller.sandbox().is_some(),
    });
    let sent = crate::proxy::send_upstream(
        state,
        &profile,
        &caller,
        Outgoing {
            method: method.as_str(),
            path: &mcp.endpoint,
            query: None,
            url,
            headers,
            body,
            mcp: Some(claims),
        },
        permit,
        cut,
    )
    .await;
    let sent = match sent {
        Ok(sent) => sent,
        Err(e) => {
            if let Some(token) = token {
                state.mcp().forget(&conv, token);
            }
            return match &rpc_id {
                Some(id) => Ok(rpc_from(&e, id, tool_ctx.as_ref())),
                None => Err(e),
            };
        }
    };
    // An OAuth-only server (ADR 0049 §4): never its own sign-in.
    if sent.res.status() == reqwest::StatusCode::UNAUTHORIZED {
        drop(sent);
        if let Some(token) = token {
            state.mcp().forget(&conv, token);
        }
        let e = ProxyError::UpstreamBlocked(Blocked::OAuthOnly);
        return match &rpc_id {
            Some(id) => Ok(rpc_from(&e, id, None)),
            None => Err(e),
        };
    }
    let inspector = Inspector {
        mcp: Arc::clone(state.mcp()),
        conv,
        own: token,
        judge: Arc::new(judge(state, &profile, &mcp.endpoint).await),
    };
    let initialize = rpc_method.as_deref() == Some(jsonrpc::INITIALIZE);
    let ending = (method == Method::DELETE)
        .then(|| session.clone())
        .flatten();
    let profile_name = profile.name.clone();
    let read: crate::proxy::McpAnswer = Box::new(move |status, headers| {
        answer(
            status,
            headers,
            inspector,
            initialize,
            ending,
            &profile_name,
            &who,
        )
    });
    crate::proxy::respond(sent, caller.sandbox().is_some(), Some(read))
}

/// How an MCP answer's body is read, and what its headers do: an
/// `initialize` answer binds its session to the caller, a `DELETE` the
/// server took ends it.
fn answer(
    status: reqwest::StatusCode,
    headers: &HeaderMap,
    inspector: Inspector,
    initialize: bool,
    ending: Option<String>,
    profile: &str,
    who: &CallerKey,
) -> Result<Box<dyn BodyTransform>, ProxyError> {
    if initialize && status.is_success() {
        match single(headers, "mcp-session-id") {
            Ok(None) => {}
            Ok(Some(id)) if inspector.mcp.bind_session(profile, id, who) => {}
            // Not visible ASCII, several, or another caller's session.
            _ => return Err(ProxyError::UpstreamBlocked(Blocked::Body)),
        }
    }
    if let Some(id) = ending
        && status.is_success()
    {
        inspector.mcp.end_session(profile, &id);
    }
    Ok(if crate::proxy::is_event_stream(headers) {
        Box::new(SseAnswer {
            inspector,
            reader: sse::Reader::default(),
        })
    } else if is_json(headers) {
        Box::new(JsonAnswer {
            inspector,
            body: Vec::new(),
            lenient: !status.is_success(),
        })
    } else {
        Box::new(Discard)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conv() -> Conversation {
        Conversation {
            profile: "maple".into(),
            caller: CallerKey::Local("claude-code".into()),
            session: Some("s1".into()),
        }
    }

    #[test]
    fn a_response_is_taken_once_and_its_own_request_first() {
        let m = McpState::default();
        let c = conv();
        let one = RpcId::Num(1);
        let a = m.expect(&c, &one, "tools/call");
        let b = m.expect(&c, &one, "tools/list");
        // Its own POST's answer: the entry of that POST.
        assert_eq!(
            m.take_response(&c, Some(b), &one).as_deref(),
            Some("tools/list")
        );
        assert_eq!(
            m.take_response(&c, Some(a), &one).as_deref(),
            Some("tools/call")
        );
        assert_eq!(m.take_response(&c, Some(a), &one), None);
        // On another stream, two alike in id but not in method: read as a
        // tools/list answer.
        m.expect(&c, &one, "tools/call");
        m.expect(&c, &one, "initialize");
        assert_eq!(
            m.take_response(&c, None, &one).as_deref(),
            Some("tools/list")
        );
        assert_eq!(
            m.take_response(&c, None, &one).as_deref(),
            Some("initialize")
        );
        assert_eq!(m.take_response(&c, None, &one), None);
        // Another caller's conversation sees none of it.
        m.expect(&c, &RpcId::Num(2), "tools/list");
        let other = Conversation {
            caller: CallerKey::Local("cursor".into()),
            ..conv()
        };
        assert_eq!(m.take_response(&other, None, &RpcId::Num(2)), None);
    }

    #[test]
    fn sessions_belong_to_the_caller_that_opened_them() {
        let m = McpState::default();
        let ana = CallerKey::Local("claude-code".into());
        let other = CallerKey::Local("cursor".into());
        assert_eq!(m.check_session("maple", "s", &ana), SessionCheck::Unknown);
        assert!(m.bind_session("maple", "s", &ana));
        assert_eq!(m.check_session("maple", "s", &ana), SessionCheck::Own);
        assert_eq!(m.check_session("maple", "s", &other), SessionCheck::Unknown);
        assert_eq!(m.check_session("github", "s", &ana), SessionCheck::Unknown);
        assert!(!m.bind_session("maple", "s", &other));
        m.end_session("maple", "s");
        assert_eq!(m.check_session("maple", "s", &ana), SessionCheck::Unknown);
    }

    #[test]
    fn server_pings_are_answered_once() {
        let m = McpState::default();
        let c = conv();
        m.note_server_ping(&c, &RpcId::Str("p".into()));
        assert!(!m.take_server_ping(&c, &RpcId::Str("q".into())));
        assert!(m.take_server_ping(&c, &RpcId::Str("p".into())));
        assert!(!m.take_server_ping(&c, &RpcId::Str("p".into())));
    }

    /// The filter, outside the proxy: the rules decide, an unlisted tool
    /// is hidden, and a changed definition is logged by name only.
    #[test]
    fn the_filter_keeps_allowed_and_asked_tools_and_logs_changes_by_name() {
        use klav_core::ids::{ItemId, ProjectId, VaultId};
        use klav_core::policy::{Rule, Scope, ToolPattern};
        let item = ItemId::generate();
        let tools = |effect, patterns: &[&str]| Rule {
            scope: Scope {
                items: vec![item],
                mcp_tools: patterns
                    .iter()
                    .map(|p| ToolPattern::parse(p).expect("pattern"))
                    .collect(),
                ..Scope::default()
            },
            ..Rule::new(Permission::Proxy, effect)
        };
        let judge = ToolJudge {
            policy: policy::Policy {
                rules: vec![
                    tools(Effect::Allow, &["query_*"]),
                    tools(Effect::Ask, &["delete_*"]),
                    tools(Effect::Deny, &["query_secret"]),
                ],
                expires_at: None,
            },
            base: Some(policy::Request {
                permission: Permission::Proxy,
                vault: Target {
                    id: VaultId::generate(),
                    name: String::new(),
                },
                project: Target {
                    id: ProjectId::generate(),
                    name: String::new(),
                },
                tags: Vec::new(),
                domain: Some("api.example.com".into()),
                item: Some(item),
                method: Some("POST".into()),
                path: Some("/mcp".into()),
                now: 0,
                mcp_tool: None,
            }),
        };
        let mcp = Arc::new(McpState::default());
        let inspector = Inspector {
            mcp: Arc::clone(&mcp),
            conv: conv(),
            own: None,
            judge: Arc::new(judge),
        };
        let answer = |description: &str| {
            format!(
                r#"{{"jsonrpc":"2.0","id":1,"result":{{"tools":[{{"name":"query_logs","description":"{description}"}},{{"name":"query_secret"}},{{"name":"delete_x"}},{{"name":"other"}}],"nextCursor":"n"}}}}"#
            )
        };
        let filtered = |inspector: &Inspector, body: &str| {
            mcp.expect(&conv(), &RpcId::Num(1), jsonrpc::TOOLS_LIST);
            let out = inspector
                .message(body.as_bytes())
                .expect("a message")
                .expect("kept");
            String::from_utf8(out).expect("utf-8")
        };
        assert_eq!(
            filtered(&inspector, &answer("reads")),
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"query_logs","description":"reads"},{"name":"delete_x"}],"nextCursor":"n"}}"#
        );
        let log = crate::proxy::tests::LogBuffer::default();
        tracing::subscriber::with_default(log.subscriber(), || {
            filtered(&inspector, &answer("SECRET_DEFINITION"));
        });
        let text = log.text();
        assert!(text.contains("query_logs"), "{text}");
        assert!(!text.contains("SECRET_DEFINITION"), "{text}");
        assert_eq!(mcp.changed_definitions(), 1);
        // A response nothing waits for is dropped; a second one too.
        assert_eq!(inspector.message(answer("x").as_bytes()), Ok(None));
    }

    #[test]
    fn a_changed_definition_is_reported_by_name() {
        let m = McpState::default();
        assert!(
            m.definitions_changed("maple", &[("a".into(), [1; 32])])
                .is_empty()
        );
        assert!(
            m.definitions_changed("maple", &[("a".into(), [1; 32])])
                .is_empty()
        );
        assert_eq!(
            m.definitions_changed("maple", &[("a".into(), [2; 32])]),
            vec!["a".to_owned()]
        );
    }
}
