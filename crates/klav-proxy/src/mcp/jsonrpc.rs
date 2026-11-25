//! Strict JSON-RPC 2.0 for the MCP gateway (ADR 0049 §5.1, steps 4–6;
//! T254, T255).
//!
//! Two passes over the same bytes:
//!
//! 1. [`check_strict`]: UTF-8 without a byte order mark, exactly one JSON
//!    value with nothing after it, nesting depth at most [`MAX_DEPTH`], no
//!    key twice in any object (compared after unescaping), and every key
//!    and every string decoded into a real `String`, which refuses invalid
//!    escapes and lone surrogates. `serde_json`'s skipping paths
//!    (`IgnoredAny`, `RawValue`) do not check surrogates, so this pass
//!    never skips.
//! 2. The shape ([`parse_client`], [`parse_server`]), read with
//!    `RawValue`, which keeps each member's exact bytes: the arguments'
//!    digest and the `tools/list` filter work on what was received, never
//!    on a re-serialization.
//!
//! Only the first pass decides what is JSON. Once it passed, an object
//! has no duplicate key, so the second pass reads every member the same
//! way the upstream (or the client) will.

use std::collections::HashSet;
use std::fmt;

use serde::Deserialize;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;

/// Deepest nesting a message may have (objects and arrays).
pub const MAX_DEPTH: usize = 64;

/// Methods v1 governs, compared byte for byte after unescaping.
pub const INITIALIZE: &str = "initialize";
/// `notifications/initialized`.
pub const INITIALIZED: &str = "notifications/initialized";
/// `notifications/cancelled`.
pub const CANCELLED: &str = "notifications/cancelled";
/// `ping`, either way.
pub const PING: &str = "ping";
/// `tools/list`.
pub const TOOLS_LIST: &str = "tools/list";
/// `tools/call`.
pub const TOOLS_CALL: &str = "tools/call";

/// JSON-RPC's parse error.
pub const PARSE_ERROR: i64 = -32700;
/// JSON-RPC's invalid request.
pub const INVALID_REQUEST: i64 = -32600;
/// JSON-RPC's method not found.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// JSON-RPC's invalid params.
pub const INVALID_PARAMS: i64 = -32602;
/// Every other refusal the proxy makes (its `data.klav_error` says which).
pub const KLAV_REFUSED: i64 = -32000;

/// Why a body is not a message the proxy forwards. The texts are fixed:
/// never a byte of the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    /// The JSON-RPC error code.
    pub code: i64,
    /// Why, in fixed words.
    pub why: &'static str,
}

impl Refused {
    const fn parse(why: &'static str) -> Self {
        Self {
            code: PARSE_ERROR,
            why,
        }
    }

    const fn invalid(why: &'static str) -> Self {
        Self {
            code: INVALID_REQUEST,
            why,
        }
    }
}

/// The first pass: whether `bytes` is one strict JSON value.
pub fn check_strict(bytes: &[u8]) -> Result<(), Refused> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(Refused::parse("the body starts with a byte order mark"));
    }
    if std::str::from_utf8(bytes).is_err() {
        return Err(Refused::parse("the body is not UTF-8"));
    }
    let mut de = serde_json::Deserializer::from_slice(bytes);
    Strict { depth: 0 }
        .deserialize(&mut de)
        .map_err(|_| {
            Refused::parse(
                "the body is not strict JSON (a duplicate key, an invalid escape or lone surrogate, nesting deeper than 64, or a syntax error)",
            )
        })?;
    de.end()
        .map_err(|_| Refused::parse("the body has data after its JSON value"))?;
    Ok(())
}

/// Walks a value, decoding every string and key, refusing duplicate keys
/// and nesting past [`MAX_DEPTH`].
#[derive(Clone, Copy)]
struct Strict {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for Strict {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Strict {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("strict JSON")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    // `serde_json` hands strings here only after decoding them into a
    // `str`, which refuses invalid escapes and lone surrogates.
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_borrowed_str<E>(self, _: &'de str) -> Result<(), E> {
        Ok(())
    }
    fn visit_string<E>(self, _: String) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let inner = self.deeper::<A::Error>()?;
        while seq.next_element_seed(inner)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let inner = self.deeper::<A::Error>()?;
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate key"));
            }
            map.next_value_seed(inner)?;
        }
        Ok(())
    }
}

impl Strict {
    fn deeper<E: de::Error>(self) -> Result<Self, E> {
        if self.depth >= MAX_DEPTH {
            return Err(E::custom("too deep"));
        }
        Ok(Self {
            depth: self.depth + 1,
        })
    }
}

/// An object's members in the order received, each with its exact bytes.
/// Only read after [`check_strict`], so no key is there twice.
#[derive(Debug)]
pub struct Members(pub Vec<(String, Box<RawValue>)>);

impl Members {
    /// The member `key`.
    pub fn get(&self, key: &str) -> Option<&RawValue> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| &**v)
    }

    /// Whether every key is one of `allowed`.
    pub fn only(&self, allowed: &[&str]) -> bool {
        self.0.iter().all(|(k, _)| allowed.contains(&k.as_str()))
    }

    /// An object (`{`) as members, or `None` for anything else.
    pub fn of(raw: &RawValue) -> Option<Self> {
        if !raw.get().starts_with('{') {
            return None;
        }
        serde_json::from_str(raw.get()).ok()
    }

    /// The object again, members in the same order and each member's
    /// value exactly as received, with `replace` for the members it names.
    pub fn write(&self, replace: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.push(b'{');
        for (i, (key, value)) in self.0.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            // A key as JSON: its own escaping, the same text it decodes to.
            out.extend_from_slice(
                serde_json::to_string(key)
                    .unwrap_or_else(|_| "\"\"".into())
                    .as_bytes(),
            );
            out.push(b':');
            match replace.iter().find(|(k, _)| k == key) {
                Some((_, bytes)) => out.extend_from_slice(bytes),
                None => out.extend_from_slice(value.get().as_bytes()),
            }
        }
        out.push(b'}');
        out
    }
}

impl<'de> Deserialize<'de> for Members {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Members;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Members, A::Error> {
                let mut out = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    let value: Box<RawValue> = map.next_value()?;
                    out.push((key, value));
                }
                Ok(Members(out))
            }
        }
        d.deserialize_map(V)
    }
}

/// A JSON-RPC `id`: a string, or an integer that fits in an `i64`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RpcId {
    /// An integer.
    Num(i64),
    /// A string (unescaped).
    Str(String),
}

impl RpcId {
    /// The `id` in `raw`: `None` for `null`, a fraction, an exponent, a
    /// number past `i64` or anything else.
    pub fn of(raw: &RawValue) -> Option<Self> {
        let text = raw.get();
        if text.starts_with('"') {
            return serde_json::from_str::<String>(text).ok().map(Self::Str);
        }
        // Digits only (and a sign): `1.0` and `1e0` are not integers here,
        // whatever a lenient parser makes of them.
        let digits = text.strip_prefix('-').unwrap_or(text);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        text.parse::<i64>().ok().map(Self::Num)
    }

    /// As a JSON value, for the proxy's own answers.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Num(n) => serde_json::json!(n),
            Self::Str(s) => serde_json::json!(s),
        }
    }
}

/// A string member, unescaped, or `None` when it is not a string.
fn string(raw: &RawValue) -> Option<String> {
    if !raw.get().starts_with('"') {
        return None;
    }
    serde_json::from_str(raw.get()).ok()
}

/// What a client sent, once its shape checks out.
#[derive(Debug)]
pub enum ClientMessage {
    /// A request: it has an `id`.
    Request {
        /// Its `id`.
        id: RpcId,
        /// Its method, unescaped.
        method: String,
        /// Its `params` (an object) as received.
        params: Option<Box<RawValue>>,
    },
    /// A notification: no `id`.
    Notification {
        /// Its method, unescaped.
        method: String,
    },
    /// A response with `result`: only the answer to a server `ping` the
    /// proxy passed to this caller is ever forwarded.
    Response {
        /// Its `id`.
        id: RpcId,
        /// Whether `result` is exactly an empty object.
        empty_result: bool,
    },
}

/// The shape of a message from the client (ADR 0049 §5.1, step 5), after
/// [`check_strict`]. `Err` carries the `id` when one could be read, so a
/// refusal answers it.
pub fn parse_client(bytes: &[u8]) -> Result<ClientMessage, (Option<RpcId>, Refused)> {
    let first = bytes.iter().find(|b| !b.is_ascii_whitespace());
    if first == Some(&b'[') {
        return Err((
            None,
            Refused::invalid(
                "a batch (an array of messages) is refused: send one message per request",
            ),
        ));
    }
    if first != Some(&b'{') {
        return Err((None, Refused::invalid("a message must be a JSON object")));
    }
    let members: Members = serde_json::from_slice(bytes)
        .map_err(|_| (None, Refused::invalid("a message must be a JSON object")))?;
    let id = match members.get("id") {
        None => None,
        Some(raw) => Some(RpcId::of(raw).ok_or((
            None,
            Refused::invalid("id must be a string or an integer that fits in 64 bits"),
        ))?),
    };
    let refuse = |why| Err((id.clone(), Refused::invalid(why)));
    if members.get("jsonrpc").and_then(string).as_deref() != Some("2.0") {
        return refuse("jsonrpc must be exactly \"2.0\"");
    }
    let Some(method) = members.get("method") else {
        // A response.
        if !members.only(&["jsonrpc", "id", "result", "error"]) {
            return refuse("a response has only jsonrpc, id and result");
        }
        let (Some(id), Some(result)) = (id.clone(), members.get("result")) else {
            return refuse("a response from the client must have an id and a result");
        };
        if members.get("error").is_some() {
            return refuse("a response from the client must have an id and a result");
        }
        let empty_result = Members::of(result).is_some_and(|m| m.0.is_empty());
        return Ok(ClientMessage::Response { id, empty_result });
    };
    if !members.only(&["jsonrpc", "id", "method", "params"]) {
        return refuse("a message has only jsonrpc, id, method and params");
    }
    let Some(method) = string(method) else {
        return refuse("method must be a string");
    };
    let params = match members.0.into_iter().find(|(k, _)| k == "params") {
        Some((_, raw)) if raw.get().starts_with('{') => Some(raw),
        Some(_) => return refuse("params must be an object"),
        None => None,
    };
    Ok(match id {
        Some(id) => ClientMessage::Request { id, method, params },
        None => ClientMessage::Notification { method },
    })
}

/// A `tools/call`'s parameters (ADR 0049 §5.1, step 6).
#[derive(Debug)]
pub struct ToolCall {
    /// The tool's name, in the tool grammar.
    pub name: String,
    /// The exact bytes of `params.arguments` (empty when absent).
    pub arguments: Vec<u8>,
}

/// `params` of a `tools/call`: `name` in the tool grammar, `arguments` an
/// object or absent, and nothing else but `_meta` (so a task-augmented
/// call is refused in v1).
pub fn parse_tool_call(params: Option<&RawValue>) -> Result<ToolCall, Refused> {
    let bad = |why| Refused {
        code: INVALID_PARAMS,
        why,
    };
    let members = params
        .and_then(Members::of)
        .ok_or(bad("tools/call needs params with the tool's name"))?;
    if !members.only(&["name", "arguments", "_meta"]) {
        return Err(bad(
            "tools/call takes only name, arguments and _meta (task-augmented calls are not supported)",
        ));
    }
    let name = members
        .get("name")
        .and_then(string)
        .filter(|n| klav_core::policy::tool_name_ok(n))
        .ok_or(bad(
            "the tool's name must be 1 to 128 of A-Z, a-z, 0-9, _, - and .",
        ))?;
    let arguments = match members.get("arguments") {
        None => Vec::new(),
        Some(raw) if raw.get().starts_with('{') => raw.get().as_bytes().to_vec(),
        Some(_) => return Err(bad("the tool's arguments must be an object")),
    };
    Ok(ToolCall { name, arguments })
}

/// What the upstream sent, once its shape checks out.
#[derive(Debug)]
pub enum ServerMessage {
    /// A request to the client.
    Request {
        /// Its `id`.
        id: RpcId,
        /// Its method.
        method: String,
    },
    /// A notification.
    Notification {
        /// Its method.
        method: String,
    },
    /// A response (`result` or `error`). `id` is `None` when it is `null`
    /// or not one the proxy could have sent: it never matches.
    Response {
        /// Its `id`.
        id: Option<RpcId>,
        /// The whole object, to rebuild it with a filtered `result`.
        members: Members,
    },
}

/// The shape of a message from the upstream, after [`check_strict`];
/// `None` when it is not one JSON-RPC 2.0 object.
pub fn parse_server(bytes: &[u8]) -> Option<ServerMessage> {
    if bytes.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return None;
    }
    let members: Members = serde_json::from_slice(bytes).ok()?;
    if members.get("jsonrpc").and_then(string).as_deref() != Some("2.0") {
        return None;
    }
    match members.get("method") {
        Some(method) => {
            if !members.only(&["jsonrpc", "id", "method", "params"]) {
                return None;
            }
            let method = string(method)?;
            match members.get("id") {
                Some(raw) => Some(ServerMessage::Request {
                    id: RpcId::of(raw)?,
                    method,
                }),
                None => Some(ServerMessage::Notification { method }),
            }
        }
        None => {
            if !members.only(&["jsonrpc", "id", "result", "error"])
                || members.get("result").is_some() == members.get("error").is_some()
            {
                return None;
            }
            let id = members.get("id").and_then(RpcId::of);
            Some(ServerMessage::Response { id, members })
        }
    }
}

/// A JSON-RPC error object as bytes, made by the proxy: `id` (or `null`),
/// a code, a fixed message and `data`.
pub fn error_bytes(
    id: Option<&RpcId>,
    code: i64,
    message: &str,
    data: serde_json::Value,
) -> Vec<u8> {
    let id = id.map_or(serde_json::Value::Null, RpcId::to_json);
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message, "data": data },
    }))
    .unwrap_or_default()
}

/// `{"jsonrpc":"2.0","id":…,"result":{}}`: the proxy's answer to a
/// client's `ping`.
pub fn pong(id: &RpcId) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.to_json(),
        "result": {},
    }))
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict(s: &str) -> bool {
        check_strict(s.as_bytes()).is_ok()
    }

    #[test]
    fn the_strict_pass_refuses_what_parsers_read_differently() {
        assert!(strict(r#"{"a":1,"b":[1,2,{"c":"d"}]}"#));
        assert!(strict(" {\"a\":\"\\ud83d\\ude00\"} \n"));
        for bad in [
            // Duplicate keys, at the top and deep, and only after
            // unescaping.
            r#"{"a":1,"a":2}"#,
            r#"{"p":{"name":"x","name":"y"}}"#,
            r#"{"x":[{"k":1,"k":1}]}"#,
            r#"{"method":"a","m\u0065thod":"b"}"#,
            // Lone surrogates, in values and in keys, deep too.
            r#"{"a":"\ud800"}"#,
            r#"{"a":"\udc00x"}"#,
            r#"{"\ud800":1}"#,
            r#"{"a":{"b":["\udfff"]}}"#,
            // Invalid escapes, trailing data, two values, nothing.
            r#"{"a":"\x"}"#,
            r#"{"a":1} {"b":2}"#,
            r#"{"a":1}x"#,
            "",
            "   ",
        ] {
            assert!(!strict(bad), "{bad}");
        }
        // A byte order mark and invalid UTF-8.
        assert!(check_strict(b"\xEF\xBB\xBF{}").is_err());
        assert!(check_strict(b"{\"a\":\"\xff\"}").is_err());
        // Depth: 64 levels pass, 65 do not.
        let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(strict(&deep(MAX_DEPTH)));
        assert!(!strict(&deep(MAX_DEPTH + 1)));
    }

    #[test]
    fn the_shape_of_a_client_message() {
        let p = |s: &str| parse_client(s.as_bytes());
        assert!(matches!(
            p(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
            Ok(ClientMessage::Request { id: RpcId::Num(1), ref method, params: None }) if method == "tools/list"
        ));
        // Escaped method names are compared after unescaping.
        assert!(matches!(
            p(r#"{"jsonrpc":"2.0","id":"a","method":"tools\/c\u0061ll","params":{}}"#),
            Ok(ClientMessage::Request { ref method, .. }) if method == "tools/call"
        ));
        assert!(matches!(
            p(r#"{"jsonrpc":"2.0","method":"tools/call"}"#),
            Ok(ClientMessage::Notification { .. })
        ));
        assert!(matches!(
            p(r#"{"jsonrpc":"2.0","id":7,"result":{ }}"#),
            Ok(ClientMessage::Response {
                empty_result: true,
                ..
            })
        ));
        assert!(matches!(
            p(r#"{"jsonrpc":"2.0","id":7,"result":{"a":1}}"#),
            Ok(ClientMessage::Response {
                empty_result: false,
                ..
            })
        ));
        for bad in [
            r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#,
            r#""ping""#,
            r#"{"jsonrpc":"2.0 ","id":1,"method":"ping"}"#,
            r#"{"jsonrpc":2.0,"id":1,"method":"ping"}"#,
            r#"{"id":1,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":1e2,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":99999999999999999999,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","extra":1}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":[]}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":7}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"x"}}"#,
        ] {
            assert!(p(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_tool_call_keeps_its_arguments_bytes() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_logs","arguments":{"b":1.50,"a":"\u00e9"}}}"#;
        let Ok(ClientMessage::Request { params, .. }) = parse_client(body) else {
            panic!("request");
        };
        let call = parse_tool_call(params.as_deref()).expect("call");
        assert_eq!(call.name, "query_logs");
        assert_eq!(call.arguments, br#"{"b":1.50,"a":"\u00e9"}"#);
        let raw = RawValue::from_string(r#"{"name":"ping_it"}"#.into()).unwrap();
        let none = parse_tool_call(Some(&raw)).expect("no arguments");
        assert!(none.arguments.is_empty());
        for bad in [
            r#"{"name":"a b"}"#,
            r#"{"name":"x","arguments":[1]}"#,
            r#"{"name":"x","arguments":null}"#,
            r#"{"name":"x","task":{"ttl":1}}"#,
            r#"{"arguments":{}}"#,
        ] {
            let raw = RawValue::from_string(bad.into()).unwrap();
            assert!(parse_tool_call(Some(&raw)).is_err(), "{bad}");
        }
    }

    #[test]
    fn members_are_rewritten_in_order_and_byte_for_byte() {
        let m: Members =
            serde_json::from_str(r#"{"z":1.0, "a" : {"k":"\u0041"},"tools":[]}"#).unwrap();
        assert_eq!(
            m.write(&[("tools", b"[1]")]),
            br#"{"z":1.0,"a":{"k":"\u0041"},"tools":[1]}"#
        );
    }
}
