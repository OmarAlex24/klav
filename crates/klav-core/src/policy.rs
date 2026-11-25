//! Agent policy evaluation (design §5.2 and §5.3).
//!
//! A pure function: [`evaluate`] takes a [`Policy`] and a [`Request`] (which
//! carries the current time) and returns a [`Decision`]. No I/O, no clock.
//!
//! # Semantics
//!
//! 1. If the policy has expired (`now >= expires_at`), everything is `deny`.
//! 2. If the policy has **no rules** for the requested permission, the
//!    default of design §5.2 applies ([`Permission::default_effect`]).
//! 3. If it has rules for the permission, only those rules count:
//!    * a rule applies when it has not expired and its [`Scope`] matches;
//!    * among applicable rules the most restrictive effect wins
//!      (`deny` > `ask` > `allow`), so rule order never matters;
//!    * if none applies, the answer is `deny` (out of scope). Expired rules
//!      still count as "rules for the permission": when a temporary rule
//!      lapses the permission **fails closed** to `deny`; it does not fall
//!      back to the (possibly broader) default.
//!
//! # Scope
//!
//! Each non-empty dimension of a [`Scope`] must match (AND across
//! dimensions, OR within one). Vaults and projects match by ID or by name
//! (case-insensitive); tags match case-insensitively; domains use
//! [`DomainPattern`]; hours use [`TimeWindow`] (weekly windows in a fixed
//! UTC offset, ADR 0014). Items match by ID, HTTP methods exactly and path
//! prefixes on segment boundaries ([`PathPrefix`]): the destinations of the
//! credential proxy (ADR 0036 §2).
//!
//! # What the server can check
//!
//! The server never sees names, tags or URLs (they are encrypted), so it
//! enforces policies with [`evaluate`] on requests whose tags and domain are
//! *claimed* by the agent runtime, and with [`evaluate_upper_bound`] where
//! nothing is claimed (listing a project): the most permissive effect that
//! any combination of tags and domain could get.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ids::{ItemId, ProjectId, VaultId};
use crate::model::reference::Selector;

/// Agent permissions (design §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// See metadata (title, URL, username, type); never secrets.
    List,
    /// Fill a login or card without returning the value to the LLM.
    Fill,
    /// `run` / `inject`: put secrets into a process or a file.
    Inject,
    /// Generate 2FA codes.
    Totp,
    /// Return the value in clear text (the only path into the LLM context).
    Reveal,
    /// Create items.
    Create,
    /// Edit items.
    Update,
    /// Move items to the trash.
    Delete,
    /// Sign in with the person's passkey through the browser (ADR 0020).
    /// Only inside an approved task (ADR 0021 §5): never in a grant.
    Passkey,
    /// Assisted password change (ADR 0022). Only inside an approved task
    /// (ADR 0021 §5): never in a grant.
    Rotate,
    /// Use the value inside an HTTP request the credential proxy builds,
    /// never returning it (ADR 0036 §2). `deny` by default; a grant with a
    /// rule that can allow it must deny `reveal`, `inject` and `fill`
    /// ([`Policy::check_proxy`]).
    Proxy,
}

impl Permission {
    /// Every permission.
    pub const ALL: [Permission; 11] = [
        Permission::List,
        Permission::Fill,
        Permission::Inject,
        Permission::Totp,
        Permission::Reveal,
        Permission::Create,
        Permission::Update,
        Permission::Delete,
        Permission::Passkey,
        Permission::Rotate,
        Permission::Proxy,
    ];

    /// The permissions a grant may have rules for: all but the task-only
    /// ones ([`Permission::requires_task`]).
    pub const GRANTABLE: [Permission; 9] = [
        Permission::List,
        Permission::Fill,
        Permission::Inject,
        Permission::Totp,
        Permission::Reveal,
        Permission::Create,
        Permission::Update,
        Permission::Delete,
        Permission::Proxy,
    ];

    /// Default effect when a policy has no rules for this permission (design §5.2).
    pub const fn default_effect(self) -> Effect {
        match self {
            Permission::List | Permission::Fill | Permission::Inject | Permission::Create => {
                Effect::Allow
            }
            // For that agent, 2FA stops being a second factor.
            Permission::Totp | Permission::Update => Effect::Ask,
            Permission::Reveal | Permission::Delete => Effect::Deny,
            // Only a task can allow them (ADR 0021 §5).
            Permission::Passkey | Permission::Rotate => Effect::Deny,
            // Only a rule the person signed for the proxy (ADR 0036 §2):
            // an agent approved before it existed never gains it.
            Permission::Proxy => Effect::Deny,
        }
    }

    /// Whether only an approved task can allow this permission (`passkey`
    /// and `rotate`, ADR 0021 §5): no grant may have rules for it, and
    /// outside a task it is `deny` ("ask for a task").
    pub const fn requires_task(self) -> bool {
        matches!(self, Permission::Passkey | Permission::Rotate)
    }

    /// Whether the permission acts on a page, so a task checks the claimed
    /// host against the approved ones (ADR 0021 §4): `fill`, `passkey` and
    /// `rotate`. `totp` (without target), `inject` and `update` have no site.
    pub const fn checks_domain(self) -> bool {
        matches!(
            self,
            Permission::Fill | Permission::Passkey | Permission::Rotate
        )
    }

    /// The name used on the wire and in files (`fill`, `totp`…).
    pub const fn as_str(self) -> &'static str {
        match self {
            Permission::List => "list",
            Permission::Fill => "fill",
            Permission::Inject => "inject",
            Permission::Totp => "totp",
            Permission::Reveal => "reveal",
            Permission::Create => "create",
            Permission::Update => "update",
            Permission::Delete => "delete",
            Permission::Passkey => "passkey",
            Permission::Rotate => "rotate",
            Permission::Proxy => "proxy",
        }
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of a rule. Ordered from least to most restrictive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// Proceed.
    Allow,
    /// Ask the human (`pending_approval_id` + push, design §5.3).
    Ask,
    /// Refuse.
    Deny,
}

/// Error parsing a [`DomainPattern`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("invalid domain pattern {0:?}: use host names like example.com or *.example.com")]
pub struct DomainPatternError(pub String);

/// A host-name pattern, compatible with browser extension match patterns:
///
/// * `example.com` matches exactly `example.com`;
/// * `*.example.com` matches `example.com` **and** every subdomain
///   (`a.example.com`, `a.b.example.com`), like Chrome's `*.example.com`;
/// * `*` matches any host.
///
/// Patterns are lowercase ASCII (internationalized names in punycode,
/// `xn--…`), without scheme, port or path. `*` is only allowed as the whole
/// first label, and a wildcard needs at least two labels after it
/// (`*.com` is rejected). Klav does not consult the Public Suffix List:
/// `*.co.uk` is accepted and is as broad as it looks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainPattern {
    wildcard: bool,
    /// Suffix without the `*.` (empty for `*`).
    base: String,
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// Normalizes a host for matching: ASCII-lowercase, without a trailing dot.
/// Returns `None` if it is not a plausible host name.
pub fn normalize_host(host: &str) -> Option<String> {
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    (!host.is_empty() && host.len() <= 253 && host.split('.').all(valid_label)).then_some(host)
}

/// Whether `host` (normalized) is an IPv4 address as a URL parser would
/// read it: its last label is a number (`10.0.0.1`, `127.1`, `2130706433`,
/// `0x7f.1`). No top-level domain is numeric. IPv6 literals never get this
/// far: [`normalize_host`] refuses `:` and `[`.
pub fn is_ip_literal(host: &str) -> bool {
    let last = host.rsplit('.').next().unwrap_or(host);
    (!last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()))
        || last
            .strip_prefix("0x")
            .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

impl DomainPattern {
    /// Whether the pattern names an IP address rather than a host name
    /// ([`is_ip_literal`]).
    pub fn is_ip_literal(&self) -> bool {
        !self.base.is_empty() && is_ip_literal(&self.base)
    }

    /// Parses a pattern.
    pub fn parse(text: &str) -> Result<Self, DomainPatternError> {
        let err = || DomainPatternError(text.to_string());
        if text == "*" {
            return Ok(Self {
                wildcard: true,
                base: String::new(),
            });
        }
        let (wildcard, rest) = match text.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        if rest.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(err());
        }
        let base = normalize_host(rest).ok_or_else(err)?;
        if wildcard && !base.contains('.') {
            return Err(err());
        }
        Ok(Self { wildcard, base })
    }

    /// Whether this is `*`, which matches any host.
    pub fn is_any(&self) -> bool {
        self.wildcard && self.base.is_empty()
    }

    /// Whether `host` (normalized with [`normalize_host`]) matches.
    pub fn matches(&self, host: &str) -> bool {
        let Some(host) = normalize_host(host) else {
            return false;
        };
        if !self.wildcard {
            return host == self.base;
        }
        if self.base.is_empty() {
            return true;
        }
        host == self.base
            || host
                .strip_suffix(&self.base)
                .is_some_and(|prefix| prefix.ends_with('.'))
    }
}

impl FromStr for DomainPattern {
    type Err = DomainPatternError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for DomainPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.wildcard, self.base.is_empty()) {
            (true, true) => f.write_str("*"),
            (true, false) => write!(f, "*.{}", self.base),
            _ => f.write_str(&self.base),
        }
    }
}

impl Serialize for DomainPattern {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DomainPattern {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// Error parsing an [`HttpMethod`] or a [`PathPrefix`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error(
    "invalid HTTP destination {0:?}: methods are upper-case words (GET, POST…), and paths start with / and are written one way only (visible ASCII as itself; only %20, %3F and %23 escaped; no ;, \\, .., or //)"
)]
pub struct HttpTargetError(pub String);

/// Longest HTTP method accepted.
pub const MAX_HTTP_METHOD: usize = 16;
/// Longest path accepted in a rule or a request.
pub const MAX_HTTP_PATH: usize = 2048;

/// An HTTP method in a proxy rule (ADR 0036 §2): upper-case ASCII letters,
/// compared exactly. `get` is rejected rather than folded, so the bytes the
/// person signs are the ones that match.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpMethod(String);

impl HttpMethod {
    /// Parses a method.
    pub fn parse(text: &str) -> Result<Self, HttpTargetError> {
        if is_http_method(text) {
            Ok(Self(text.to_owned()))
        } else {
            Err(HttpTargetError(text.to_owned()))
        }
    }

    /// The method.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether `text` is a method as [`HttpMethod`] accepts it.
pub fn is_http_method(text: &str) -> bool {
    (1..=MAX_HTTP_METHOD).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_uppercase())
}

/// Whether `path` is a path the proxy can declare and a rule can match.
///
/// Every byte has exactly **one** accepted spelling, so that a narrower
/// `deny` or `ask` rule cannot be dodged by writing the same path another
/// way (`/v1/%63harges` for `/v1/charges`); paths are compared byte for
/// byte, case-sensitively, and the proxy sends upstream exactly the bytes
/// it checked (ADR 0036 §8):
///
/// * it starts with `/` and is at most [`MAX_HTTP_PATH`] bytes;
/// * a visible ASCII byte (`0x21`–`0x7e`) other than `?`, `#`, `\`, `;`
///   and `%` appears only as itself: escaping it (`%63`, `%3A`) is refused;
/// * a space, `?` or `#` appears only escaped, with upper-case hex: `%20`,
///   `%3F`, `%23`;
/// * nothing else is accepted: no `;` (path parameters), no `\`, no other
///   escape (`%2F`, `%5C`, `%25`, `%3B`, lower-case hex, control
///   characters, bytes of `0x80` and above, malformed escapes), no
///   non-ASCII byte;
/// * no empty segment (`//`) except a trailing `/`, and no `.` or `..`
///   segment.
///
/// Ambiguous paths are refused rather than normalized: the upstream could
/// read them differently from the rule.
pub fn is_canonical_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.first() != Some(&b'/') || bytes.len() > MAX_HTTP_PATH {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            let escaped = match bytes.get(i + 1..i + 3) {
                Some([hi, lo]) => upper_hex(*hi).zip(upper_hex(*lo)).map(|(h, l)| h << 4 | l),
                _ => None,
            };
            if !matches!(escaped, Some(b' ' | b'?' | b'#')) {
                return false;
            }
            i += 3;
        } else if (0x21..=0x7e).contains(&b) && !matches!(b, b'?' | b'#' | b'\\' | b';') {
            i += 1;
        } else {
            return false;
        }
    }
    let segments: Vec<&str> = path[1..].split('/').collect();
    let last = segments.len() - 1;
    segments
        .iter()
        .enumerate()
        .all(|(n, seg)| !matches!(*seg, "." | "..") && (!seg.is_empty() || n == last))
}

/// The value of an upper-case hex digit.
fn upper_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// A path prefix in a proxy rule (ADR 0036 §2): a canonical path
/// ([`is_canonical_path`]) without a trailing `/` (except `/` itself). It
/// matches the path itself and everything below it on a segment boundary:
/// `/graphql/v2` matches `/graphql/v2` and `/graphql/v2/x`, never
/// `/graphql/v2x`. `/` matches every path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathPrefix(String);

impl PathPrefix {
    /// Parses a prefix.
    pub fn parse(text: &str) -> Result<Self, HttpTargetError> {
        if is_canonical_path(text) && (text == "/" || !text.ends_with('/')) {
            Ok(Self(text.to_owned()))
        } else {
            Err(HttpTargetError(text.to_owned()))
        }
    }

    /// The prefix.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `path` is this prefix or below it. A path that is not
    /// canonical never matches.
    pub fn matches(&self, path: &str) -> bool {
        is_canonical_path(path)
            && (self.0 == "/"
                || path == self.0
                || path
                    .strip_prefix(self.0.as_str())
                    .is_some_and(|rest| rest.starts_with('/')))
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for PathPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for HttpMethod {
    type Err = HttpTargetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl FromStr for PathPrefix {
    type Err = HttpTargetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Day of the week.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Weekday {
    /// Monday.
    Mon,
    /// Tuesday.
    Tue,
    /// Wednesday.
    Wed,
    /// Thursday.
    Thu,
    /// Friday.
    Fri,
    /// Saturday.
    Sat,
    /// Sunday.
    Sun,
}

impl Weekday {
    /// Monday first.
    pub const ALL: [Weekday; 7] = [
        Weekday::Mon,
        Weekday::Tue,
        Weekday::Wed,
        Weekday::Thu,
        Weekday::Fri,
        Weekday::Sat,
        Weekday::Sun,
    ];

    /// The weekday of a day number counted from 1970-01-01 (a Thursday).
    fn from_days(days: i64) -> Self {
        Self::ALL[usize::try_from((days + 3).rem_euclid(7)).unwrap_or(0)]
    }

    fn previous(self) -> Self {
        let index = Self::ALL.iter().position(|d| *d == self).unwrap_or(0);
        Self::ALL[(index + 6) % 7]
    }
}

/// Error parsing a time of day or a UTC offset.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("invalid time {0:?}: use HH:MM (24 h) or ±HH:MM for offsets")]
pub struct TimeError(pub String);

/// A time of day, `HH:MM` (24 h), as minutes since midnight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClockTime(u16);

impl ClockTime {
    /// `hour:minute`, or `None` if out of range.
    pub const fn new(hour: u16, minute: u16) -> Option<Self> {
        if hour < 24 && minute < 60 {
            Some(Self(hour * 60 + minute))
        } else {
            None
        }
    }

    /// Minutes since midnight.
    pub const fn minutes(self) -> u16 {
        self.0
    }
}

fn parse_hhmm(text: &str) -> Option<(u16, u16)> {
    let (h, m) = text.split_once(':')?;
    if h.len() != 2 || m.len() != 2 || !h.bytes().chain(m.bytes()).all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((h.parse().ok()?, m.parse().ok()?))
}

impl FromStr for ClockTime {
    type Err = TimeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_hhmm(s)
            .and_then(|(h, m)| Self::new(h, m))
            .ok_or_else(|| TimeError(s.to_string()))
    }
}

impl fmt::Display for ClockTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02}:{:02}", self.0 / 60, self.0 % 60)
    }
}

/// A fixed offset from UTC, `±HH:MM` (no time-zone database: see ADR 0014).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct UtcOffset(i16);

impl UtcOffset {
    /// Offset in minutes (east of UTC is positive); `None` beyond ±14:00.
    pub const fn from_minutes(minutes: i16) -> Option<Self> {
        if minutes >= -14 * 60 && minutes <= 14 * 60 {
            Some(Self(minutes))
        } else {
            None
        }
    }

    /// Minutes east of UTC.
    pub const fn minutes(self) -> i16 {
        self.0
    }
}

impl FromStr for UtcOffset {
    type Err = TimeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || TimeError(s.to_string());
        if s == "Z" || s == "UTC" {
            return Ok(Self(0));
        }
        let (sign, rest) = match s.as_bytes().first() {
            Some(b'+') => (1, &s[1..]),
            Some(b'-') => (-1, &s[1..]),
            _ => return Err(err()),
        };
        let (h, m) = parse_hhmm(rest).ok_or_else(err)?;
        if m >= 60 {
            return Err(err());
        }
        let minutes = i16::try_from(h * 60 + m).map_err(|_| err())?;
        Self::from_minutes(sign * minutes).ok_or_else(err)
    }
}

impl fmt::Display for UtcOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sign = if self.0 < 0 { '-' } else { '+' };
        let abs = self.0.unsigned_abs();
        write!(f, "{sign}{:02}:{:02}", abs / 60, abs % 60)
    }
}

macro_rules! string_serde {
    ($ty:ty) => {
        impl Serialize for $ty {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                text.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

string_serde!(ClockTime);
string_serde!(UtcOffset);
string_serde!(HttpMethod);
string_serde!(PathPrefix);
string_serde!(ToolPattern);

// ---------------------------------------------------------- MCP tools ----

/// Longest MCP tool name (ADR 0049 §5.1, the spec's SEP-986).
pub const MAX_TOOL_NAME: usize = 128;
/// Longest local client name (ADR 0049 §3.2).
pub const MAX_LOCAL_CLIENT_NAME: usize = 32;
/// Display caps of the signing sheet (ADR 0049 §5.3): the person's
/// confirmation shows every pattern, so the client never signs more. Only
/// the client applies them, so the hand tests can raise them without a
/// server release.
pub const MAX_TOOL_PATTERN_LEN: usize = 64;
/// At most this many patterns in one rule.
pub const MAX_TOOL_PATTERNS_PER_RULE: usize = 24;
/// At most this many patterns over every rule of one profile's item.
pub const MAX_TOOL_PATTERNS_PER_PROFILE: usize = 48;
/// At most this many rules with tools for one profile's item.
pub const MAX_TOOL_RULES_PER_PROFILE: usize = 4;

/// Whether `name` is a tool name the gateway judges (ADR 0049 §5.1,
/// T257, T260): 1–128 bytes of `A-Z a-z 0-9 _ - .`. No space, quote, line
/// break, *bidi* or non-ASCII character, so it can go on an approval card
/// and in a Touch ID prompt as it is. Compared case-sensitively.
pub fn tool_name_ok(name: &str) -> bool {
    (1..=MAX_TOOL_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// Whether `name` is a local client's name (ADR 0049 §3.2, T260): 1–32
/// bytes of `a-z 0-9 -`, such as `claude-code`.
pub fn local_client_name_ok(name: &str) -> bool {
    (1..=MAX_LOCAL_CLIENT_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A pattern that names MCP tools is not one: an exact tool name, a tool
/// name followed by one `*`, or `*` alone.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error(
    "invalid tool pattern {0:?}: an exact tool name (A-Z a-z 0-9 _ - ., at most 128), a name followed by one trailing * (get_*), or * alone"
)]
pub struct ToolPatternError(pub String);

/// Which MCP tools a `proxy` rule is about (ADR 0049 §5.3):
///
/// * an exact name in the tool grammar ([`tool_name_ok`]): `query_logs`;
/// * a prefix in that grammar with one trailing `*`: `get_*`;
/// * `*` alone: any tool.
///
/// Matching is byte for byte and case-sensitive. There is no suffix or
/// infix form: `*_api_key` is not a pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ToolPattern(String);

impl ToolPattern {
    /// Parses a pattern.
    pub fn parse(text: &str) -> Result<Self, ToolPatternError> {
        let ok = match text.strip_suffix('*') {
            Some("") => true,
            Some(prefix) => tool_name_ok(prefix) && prefix.len() < MAX_TOOL_NAME,
            None => tool_name_ok(text),
        };
        if ok {
            Ok(Self(text.to_owned()))
        } else {
            Err(ToolPatternError(text.to_owned()))
        }
    }

    /// The pattern as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `*` alone: any tool (the sheet marks it when it allows).
    pub fn is_any(&self) -> bool {
        self.0 == "*"
    }

    /// Whether `tool` is one of the tools it names. A name outside the
    /// grammar matches nothing.
    pub fn matches(&self, tool: &str) -> bool {
        if !tool_name_ok(tool) {
            return false;
        }
        match self.0.strip_suffix('*') {
            Some(prefix) => tool.starts_with(prefix),
            None => self.0 == tool,
        }
    }
}

impl fmt::Display for ToolPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ToolPattern {
    type Err = ToolPatternError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// A weekly time window (design §5.2 "horario", ADR 0014), in a fixed UTC
/// offset.
///
/// `start` is inclusive and `end` exclusive. When `end <= start` the
/// window crosses midnight and belongs to the day it starts on (`fri
/// 22:00–02:00` covers Friday 22:00 to Saturday 02:00); `start == end`
/// covers the whole day. Empty `days` means every day.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeWindow {
    /// Days the window starts on (empty: every day).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub days: Vec<Weekday>,
    /// Start (inclusive).
    pub start: ClockTime,
    /// End (exclusive).
    pub end: ClockTime,
    /// Offset of the local time the window is written in.
    #[serde(default)]
    pub utc_offset: UtcOffset,
}

impl FromStr for Weekday {
    type Err = TimeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "mon" => Weekday::Mon,
            "tue" => Weekday::Tue,
            "wed" => Weekday::Wed,
            "thu" => Weekday::Thu,
            "fri" => Weekday::Fri,
            "sat" => Weekday::Sat,
            "sun" => Weekday::Sun,
            _ => return Err(TimeError(s.to_string())),
        })
    }
}

/// Parses `DAYS HH:MM-HH:MM OFFSET`, e.g. `mon-fri 09:00-18:00 -06:00`.
/// `DAYS` is `daily`, a range (`mon-fri`) or a list (`mon,wed,fri`); the
/// offset is mandatory (there is no time-zone database, ADR 0014).
impl FromStr for TimeWindow {
    type Err = TimeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || TimeError(s.to_string());
        let parts: Vec<&str> = s.split_whitespace().collect();
        let [days, span, offset] = parts.as_slice() else {
            return Err(err());
        };
        let days = if days.eq_ignore_ascii_case("daily") {
            Vec::new()
        } else if let Some((from, to)) = days.split_once('-') {
            let (from, to): (Weekday, Weekday) = (from.parse()?, to.parse()?);
            let start = Self::index(from);
            let end = Self::index(to);
            let len = (end + 7 - start) % 7 + 1;
            (0..len).map(|i| Weekday::ALL[(start + i) % 7]).collect()
        } else {
            days.split(',')
                .map(str::parse)
                .collect::<Result<Vec<Weekday>, _>>()?
        };
        let (start, end) = span.split_once('-').ok_or_else(err)?;
        Ok(Self {
            days,
            start: start.parse()?,
            end: end.parse()?,
            utc_offset: offset.parse()?,
        })
    }
}

impl TimeWindow {
    fn index(day: Weekday) -> usize {
        Weekday::ALL.iter().position(|d| *d == day).unwrap_or(0)
    }

    fn on(&self, day: Weekday) -> bool {
        self.days.is_empty() || self.days.contains(&day)
    }

    /// Whether the Unix time `now` (seconds) falls inside the window.
    pub fn contains(&self, now: u64) -> bool {
        let local = i64::try_from(now).unwrap_or(i64::MAX) + i64::from(self.utc_offset.0) * 60;
        let day = Weekday::from_days(local.div_euclid(86_400));
        let minute = u16::try_from(local.rem_euclid(86_400) / 60).unwrap_or(0);
        let (start, end) = (self.start.0, self.end.0);
        if start < end {
            self.on(day) && (start..end).contains(&minute)
        } else {
            (minute >= start && self.on(day)) || (minute < end && self.on(day.previous()))
        }
    }
}

/// Where a rule applies. Empty dimensions do not constrain.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    /// Vaults, by ID or name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vaults: Vec<Selector<VaultId>>,
    /// Projects, by ID or name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projects: Vec<Selector<ProjectId>>,
    /// Item tags (the item needs at least one of them).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Host patterns (the request needs a domain matching one of them).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<DomainPattern>,
    /// Weekly time windows (the request time must fall in one of them).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hours: Vec<TimeWindow>,
    /// Items, by ID (the request's item must be one of them). Only in
    /// `proxy` rules for now (ADR 0036 §2; ADR 0032 §4.1 defines the
    /// dimension for every permission).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<ItemId>,
    /// HTTP methods (the proxied request's method must be one of them).
    /// Only in `proxy` rules (ADR 0036 §2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<HttpMethod>,
    /// HTTP path prefixes (the proxied request's path must be under one of
    /// them). Only in `proxy` rules (ADR 0036 §2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_prefixes: Vec<PathPrefix>,
    /// MCP tools (the call's tool must match one of them). Only in `proxy`
    /// rules on an MCP profile's item (ADR 0049 §5.3). A request that names
    /// a tool is matched by a rule without `mcp_tools` only if that rule
    /// denies ([`evaluate`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp_tools: Vec<ToolPattern>,
}

fn selects<I: PartialEq>(selector: &Selector<I>, target: &Target<I>) -> bool {
    match selector {
        Selector::Id(id) => *id == target.id,
        Selector::Name(name) => name.to_lowercase() == target.name.to_lowercase(),
    }
}

impl Scope {
    /// Whether the dimensions the server can always see (vault, project,
    /// time) match.
    fn matches_location(&self, request: &Request) -> bool {
        (self.vaults.is_empty() || self.vaults.iter().any(|s| selects(s, &request.vault)))
            && (self.projects.is_empty()
                || self.projects.iter().any(|s| selects(s, &request.project)))
            && (self.hours.is_empty() || self.hours.iter().any(|w| w.contains(request.now)))
    }

    /// Whether the scope constrains what only a request about one item
    /// says: its tags, host, item, method or path.
    fn needs_claims(&self) -> bool {
        !self.tags.is_empty()
            || !self.domains.is_empty()
            || !self.items.is_empty()
            || !self.methods.is_empty()
            || !self.path_prefixes.is_empty()
            || !self.mcp_tools.is_empty()
    }

    /// Whether the scope uses a dimension of the proxy (items, methods or
    /// path prefixes): only a grant payload `v: 2` may carry one.
    pub fn uses_http(&self) -> bool {
        !self.items.is_empty() || !self.methods.is_empty() || !self.path_prefixes.is_empty()
    }

    /// Whether the scope names MCP tools: only a grant payload `v: 4` may
    /// carry them (ADR 0049 §2.1).
    pub fn uses_mcp(&self) -> bool {
        !self.mcp_tools.is_empty()
    }

    /// Whether the scope names vaults or projects only by ID (what the
    /// server can match: it never sees names).
    pub fn uses_ids_only(&self) -> bool {
        self.vaults.iter().all(|s| matches!(s, Selector::Id(_)))
            && self.projects.iter().all(|s| matches!(s, Selector::Id(_)))
    }

    /// Whether the request falls inside this scope.
    pub fn matches(&self, request: &Request) -> bool {
        self.matches_location(request)
            && (self.tags.is_empty()
                || self.tags.iter().any(|tag| {
                    let tag = tag.to_lowercase();
                    request.tags.iter().any(|t| t.to_lowercase() == tag)
                }))
            && (self.domains.is_empty()
                || request
                    .domain
                    .as_deref()
                    .is_some_and(|host| self.domains.iter().any(|p| p.matches(host))))
            && (self.items.is_empty() || request.item.is_some_and(|i| self.items.contains(&i)))
            && (self.methods.is_empty()
                || request
                    .method
                    .as_deref()
                    .is_some_and(|m| self.methods.iter().any(|x| x.as_str() == m)))
            && (self.path_prefixes.is_empty()
                || request
                    .path
                    .as_deref()
                    .is_some_and(|path| self.path_prefixes.iter().any(|p| p.matches(path))))
            && (self.mcp_tools.is_empty()
                || request
                    .mcp_tool
                    .as_deref()
                    .is_some_and(|tool| self.mcp_tools.iter().any(|p| p.matches(tool))))
    }
}

/// A rule: `permission → effect` inside a scope, optionally until a time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Permission the rule is about.
    pub permission: Permission,
    /// Effect when it applies.
    pub effect: Effect,
    /// Where it applies.
    #[serde(default)]
    pub scope: Scope,
    /// Unix time (seconds) from which the rule no longer applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl Rule {
    /// A rule with an empty scope and no expiry.
    pub fn new(permission: Permission, effect: Effect) -> Self {
        Self {
            permission,
            effect,
            scope: Scope::default(),
            expires_at: None,
        }
    }

    fn expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|t| now >= t)
    }
}

/// An agent's policy (part of its grant).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Rules; permissions without rules use the defaults.
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Unix time (seconds) from which the whole policy denies everything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

/// A grant policy with a rule for a task-only permission (ADR 0021 §5).
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error(
    "a grant cannot have rules for `{0}`: it only exists inside an approved task (request_task)"
)]
pub struct TaskOnlyRule(pub Permission);

/// A grant policy that breaks the rules of the proxy (ADR 0036 §2).
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProxyRuleError {
    /// Items, methods or path prefixes in a rule that is not `proxy`.
    #[error("only `proxy` rules may name items, HTTP methods or path prefixes, not `{0}` rules")]
    HttpOutsideProxy(Permission),
    /// A `proxy` rule that can allow without naming its items.
    #[error("a `proxy` rule that allows or asks must name its items")]
    NoItems,
    /// A `proxy` rule that can allow without naming its hosts, or with `*`.
    #[error("a `proxy` rule that allows or asks must name its hosts, and `*` is not a host")]
    NoHosts,
    /// A `proxy` rule that can allow an IP address instead of a host name.
    #[error("a `proxy` rule names hosts, never IP addresses")]
    IpHost,
    /// A proxy grant that does not deny a permission that hands out values.
    #[error("a grant with `proxy` must deny `{0}`: the proxy uses values, it never hands them out")]
    HandsOutValues(Permission),
    /// MCP tools in a rule that is not `proxy` (ADR 0049 §5.3).
    #[error("only `proxy` rules may name MCP tools, not `{0}` rules")]
    ToolsOutsideProxy(Permission),
}

impl Policy {
    /// Whether the policy needs a grant payload `v: 2` (ADR 0036 §2): a
    /// `proxy` rule, or a rule with items, methods or path prefixes. Old
    /// runtimes fail closed on such a policy, because [`Scope`] and
    /// [`Permission`] reject what they do not know.
    pub fn needs_v2(&self) -> bool {
        self.rules
            .iter()
            .any(|r| r.permission == Permission::Proxy || r.scope.uses_http())
    }

    /// Whether the policy needs a grant payload `v: 4` (ADR 0049 §2.1): a
    /// rule that names MCP tools.
    pub fn needs_v4(&self) -> bool {
        self.rules.iter().any(|r| r.scope.uses_mcp())
    }

    /// Whether some rule can let `proxy` through.
    pub fn may_proxy(&self) -> bool {
        self.rules
            .iter()
            .any(|r| r.permission == Permission::Proxy && r.effect != Effect::Deny)
    }

    /// Checks the rules of the proxy (ADR 0036 §2). The person's client
    /// does not sign a grant that breaks them, and the server and the
    /// proxy reject it:
    ///
    /// * only `proxy` rules name items, methods or path prefixes;
    /// * a `proxy` rule that allows or asks names its items and its hosts,
    ///   none of them `*` or an IP address ([`is_ip_literal`]);
    /// * with such a rule, `reveal`, `inject` and `fill` are always `deny`:
    ///   they have rules and every one of them denies. Their defaults are
    ///   not enough, since `inject` and `fill` allow by default.
    pub fn check_proxy(&self) -> Result<(), ProxyRuleError> {
        for rule in &self.rules {
            if rule.permission != Permission::Proxy && rule.scope.uses_http() {
                return Err(ProxyRuleError::HttpOutsideProxy(rule.permission));
            }
            if rule.permission != Permission::Proxy && rule.scope.uses_mcp() {
                return Err(ProxyRuleError::ToolsOutsideProxy(rule.permission));
            }
            if rule.permission == Permission::Proxy && rule.effect != Effect::Deny {
                if rule.scope.items.is_empty() {
                    return Err(ProxyRuleError::NoItems);
                }
                if rule.scope.domains.is_empty() || rule.scope.domains.iter().any(|d| d.is_any()) {
                    return Err(ProxyRuleError::NoHosts);
                }
                if rule.scope.domains.iter().any(DomainPattern::is_ip_literal) {
                    return Err(ProxyRuleError::IpHost);
                }
            }
        }
        if self.may_proxy() {
            for permission in [Permission::Reveal, Permission::Inject, Permission::Fill] {
                let mut rules = self.rules.iter().filter(|r| r.permission == permission);
                let mut any = false;
                if !rules.all(|r| {
                    any = true;
                    r.effect == Effect::Deny
                }) || !any
                {
                    return Err(ProxyRuleError::HandsOutValues(permission));
                }
            }
        }
        Ok(())
    }

    /// Checks the rule every grant must follow (ADR 0021 §5): no rules for
    /// `passkey` or `rotate`. The person's client does not sign such a
    /// grant and the server rejects it with `400`.
    pub fn check_grantable(&self) -> Result<(), TaskOnlyRule> {
        match self.rules.iter().find(|r| r.permission.requires_task()) {
            Some(rule) => Err(TaskOnlyRule(rule.permission)),
            None => Ok(()),
        }
    }
}

/// A vault or project as seen by the request: ID and current name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target<I> {
    /// ID.
    pub id: I,
    /// Current (decrypted) name.
    pub name: String,
}

/// What an agent wants to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Permission needed.
    pub permission: Permission,
    /// Vault of the target item (or where an item is created).
    pub vault: Target<VaultId>,
    /// Project of the target item (or where an item is created).
    pub project: Target<ProjectId>,
    /// Tags of the target item (of the new item for `create`).
    pub tags: Vec<String>,
    /// Host the action is for (`fill`, `proxy`), if any.
    pub domain: Option<String>,
    /// The item acted on, if any (`None` when creating or listing).
    pub item: Option<ItemId>,
    /// HTTP method of a proxied request (`proxy`).
    pub method: Option<String>,
    /// HTTP path of a proxied request, without query (`proxy`).
    pub path: Option<String>,
    /// The MCP tool a proxied `tools/call` names, or one the proxy checks
    /// while filtering `tools/list` (ADR 0049 §5.3).
    pub mcp_tool: Option<String>,
    /// Current Unix time in seconds.
    pub now: u64,
}

/// Why a decision was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// The policy expired.
    PolicyExpired,
    /// No rules for the permission: design §5.2 default.
    Default,
    /// Decided by the rule at this index (the first one with the winning effect).
    Rule(usize),
    /// There are rules for the permission but none applies, or the
    /// request names an MCP tool and no rule for it allows or asks
    /// (ADR 0049 §5.3: no default lets a tool call through).
    OutOfScope,
    /// The permission only exists inside an approved task (`passkey`,
    /// `rotate`, ADR 0021 §5): ask for one with `request_task`.
    TaskOnly,
}

/// Result of [`evaluate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Decision {
    /// What to do.
    pub effect: Effect,
    /// Why.
    pub reason: Reason,
}

/// Evaluates `request` against `policy`. See the module docs for the semantics.
///
/// `passkey` and `rotate` are always `deny` here ([`Reason::TaskOnly`]),
/// whatever the rules say: only an approved task allows them
/// (`crate::task`).
pub fn evaluate(policy: &Policy, request: &Request) -> Decision {
    let deny = |reason| Decision {
        effect: Effect::Deny,
        reason,
    };
    if policy.expires_at.is_some_and(|t| request.now >= t) {
        return deny(Reason::PolicyExpired);
    }
    if request.permission.requires_task() {
        return deny(Reason::TaskOnly);
    }
    // A `proxy` request whose method or path the policy cannot judge is
    // never let through by a rule: only `deny` rules apply to it (and
    // `proxy` defaults to deny).
    // A tool call that is not a `proxy` call, or whose tool is outside the
    // grammar, is not judgeable either.
    let unjudgeable = (request.permission == Permission::Proxy && !proxy_request_ok(request))
        || request
            .mcp_tool
            .as_deref()
            .is_some_and(|tool| request.permission != Permission::Proxy || !tool_name_ok(tool));
    // ADR 0049 §5.3 (Q3): a request that names an MCP tool is matched by a
    // rule without `mcp_tools` only if that rule denies, so the rule that
    // lets the MCP session through never allows a tool by itself, and a
    // tool no rule names is denied.
    let tool_call = request.mcp_tool.is_some();
    let mut has_rules = false;
    let mut best: Option<(Effect, usize)> = None;
    for (index, rule) in policy.rules.iter().enumerate() {
        if rule.permission != request.permission {
            continue;
        }
        has_rules = true;
        if rule.expired(request.now)
            || !rule.scope.matches(request)
            || (unjudgeable && rule.effect != Effect::Deny)
            || (tool_call && rule.scope.mcp_tools.is_empty() && rule.effect != Effect::Deny)
        {
            continue;
        }
        if best.is_none_or(|(effect, _)| rule.effect > effect) {
            best = Some((rule.effect, index));
        }
    }
    match (has_rules, best) {
        // No default ever lets a tool call through: only a rule that
        // names it does.
        (false, _) if tool_call => deny(Reason::OutOfScope),
        (false, _) => Decision {
            effect: request.permission.default_effect(),
            reason: Reason::Default,
        },
        (true, Some((effect, index))) => Decision {
            effect,
            reason: Reason::Rule(index),
        },
        (true, None) => deny(Reason::OutOfScope),
    }
}

/// Methods `proxy` never forwards, whatever the rules say: `CONNECT` would
/// open a tunnel past the profile, and `TRACE` echoes the request headers
/// back, the injected credential among them.
pub const PROXY_REFUSED_METHODS: [&str; 2] = ["CONNECT", "TRACE"];

/// Whether a `proxy` request says a method and a path the policy can judge
/// (ADR 0036 §2): a method as [`HttpMethod`] accepts it and not one of
/// [`PROXY_REFUSED_METHODS`], and a canonical path ([`is_canonical_path`]).
/// A rule without `methods` or `path_prefixes` does not look at them, so
/// this check runs before any rule.
fn proxy_request_ok(request: &Request) -> bool {
    request
        .method
        .as_deref()
        .is_some_and(|m| is_http_method(m) && !PROXY_REFUSED_METHODS.contains(&m))
        && request.path.as_deref().is_some_and(is_canonical_path)
}

/// The most permissive effect `request` could get for **some** tags and
/// domain: `request.tags` and `request.domain` are ignored.
///
/// The server uses it where the agent claims nothing (listing a project's
/// items, whose tags it cannot read): it never answers more restrictively
/// than [`evaluate`] would for any concrete tags and domain, so a project
/// the agent may use is never hidden, and the runtime then applies the
/// exact policy. Computed as `max(forced, min(possible))`, where *possible*
/// are the live rules whose vault, project and hours match, and *forced*
/// the subset without tag or domain constraints (they apply whatever the
/// claims).
pub fn evaluate_upper_bound(policy: &Policy, request: &Request) -> Decision {
    let deny = |reason| Decision {
        effect: Effect::Deny,
        reason,
    };
    if policy.expires_at.is_some_and(|t| request.now >= t) {
        return deny(Reason::PolicyExpired);
    }
    if request.permission.requires_task() {
        return deny(Reason::TaskOnly);
    }
    let mut has_rules = false;
    let mut most_permissive: Option<(Effect, usize)> = None;
    let mut forced: Option<(Effect, usize)> = None;
    for (index, rule) in policy.rules.iter().enumerate() {
        if rule.permission != request.permission {
            continue;
        }
        has_rules = true;
        if rule.expired(request.now) || !rule.scope.matches_location(request) {
            continue;
        }
        if most_permissive.is_none_or(|(effect, _)| rule.effect < effect) {
            most_permissive = Some((rule.effect, index));
        }
        if !rule.scope.needs_claims() && forced.is_none_or(|(effect, _)| rule.effect > effect) {
            forced = Some((rule.effect, index));
        }
    }
    match (has_rules, most_permissive, forced) {
        (false, _, _) => Decision {
            effect: request.permission.default_effect(),
            reason: Reason::Default,
        },
        (true, None, _) => deny(Reason::OutOfScope),
        (true, Some((loose, _)), Some((strict, j))) if strict > loose => Decision {
            effect: strict,
            reason: Reason::Rule(j),
        },
        (true, Some((effect, index)), _) => Decision {
            effect,
            reason: Reason::Rule(index),
        },
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const NOW: u64 = 1_800_000_000;

    struct World {
        trabajo: VaultId,
        personal: VaultId,
        acme: ProjectId,
        redes: ProjectId,
    }

    impl World {
        fn new() -> Self {
            Self {
                trabajo: VaultId::from_bytes([1; 16]),
                personal: VaultId::from_bytes([2; 16]),
                acme: ProjectId::from_bytes([3; 16]),
                redes: ProjectId::from_bytes([4; 16]),
            }
        }

        fn request(&self, permission: Permission) -> Request {
            Request {
                permission,
                vault: Target {
                    id: self.trabajo,
                    name: "Trabajo".into(),
                },
                project: Target {
                    id: self.acme,
                    name: "acme-api".into(),
                },
                tags: vec!["prod".into()],
                domain: Some("github.com".into()),
                item: None,
                method: None,
                path: None,
                mcp_tool: None,
                now: NOW,
            }
        }
    }

    fn scoped(permission: Permission, effect: Effect, scope: Scope) -> Rule {
        Rule {
            scope,
            ..Rule::new(permission, effect)
        }
    }

    fn domains(patterns: &[&str]) -> Scope {
        Scope {
            domains: patterns.iter().map(|p| p.parse().unwrap()).collect(),
            ..Scope::default()
        }
    }

    fn proxy_rule(effect: Effect, item: ItemId) -> Rule {
        scoped(
            Permission::Proxy,
            effect,
            Scope {
                items: vec![item],
                domains: vec!["api.northflank.com".parse().unwrap()],
                methods: vec!["GET".parse().unwrap(), "POST".parse().unwrap()],
                path_prefixes: vec!["/v1/projects".parse().unwrap()],
                ..Scope::default()
            },
        )
    }

    fn deny_values() -> Vec<Rule> {
        [Permission::Reveal, Permission::Inject, Permission::Fill]
            .into_iter()
            .map(|p| Rule::new(p, Effect::Deny))
            .collect()
    }

    fn proxied(w: &World, item: ItemId, method: &str, host: &str, path: &str) -> Request {
        Request {
            item: Some(item),
            method: Some(method.into()),
            path: Some(path.into()),
            domain: Some(host.into()),
            ..w.request(Permission::Proxy)
        }
    }

    #[test]
    fn proxy_rules_bind_item_host_method_and_path() {
        let w = World::new();
        let token = ItemId::from_bytes([9; 16]);
        let other = ItemId::from_bytes([10; 16]);
        let mut rules = deny_values();
        rules.push(proxy_rule(Effect::Allow, token));
        let policy = Policy {
            rules,
            expires_at: None,
        };
        assert_eq!(policy.check_proxy(), Ok(()));
        assert!(policy.needs_v2());
        let ok = proxied(&w, token, "GET", "api.northflank.com", "/v1/projects/p1");
        assert_eq!(evaluate(&policy, &ok).effect, Effect::Allow);
        assert_eq!(
            evaluate(
                &policy,
                &proxied(&w, token, "POST", "api.northflank.com", "/v1/projects")
            )
            .effect,
            Effect::Allow
        );
        for denied in [
            // Another item: the rule binds the Northflank token only.
            proxied(&w, other, "GET", "api.northflank.com", "/v1/projects/p1"),
            proxied(&w, token, "DELETE", "api.northflank.com", "/v1/projects/p1"),
            proxied(&w, token, "get", "api.northflank.com", "/v1/projects/p1"),
            proxied(&w, token, "GET", "evil.example", "/v1/projects/p1"),
            proxied(&w, token, "GET", "api.northflank.com", "/v1/projectsx"),
            proxied(
                &w,
                token,
                "GET",
                "api.northflank.com",
                "/v1/projects/../tokens",
            ),
            proxied(
                &w,
                token,
                "GET",
                "api.northflank.com",
                "/v1/projects/%2e%2e/tokens",
            ),
            proxied(
                &w,
                token,
                "GET",
                "api.northflank.com",
                "/v1/projects/%2F..%2Ftokens",
            ),
            proxied(&w, token, "GET", "api.northflank.com", "/v1/projects//x"),
            proxied(&w, token, "GET", "api.northflank.com", "/v1/projects/a?b=c"),
            Request {
                path: None,
                ..ok.clone()
            },
            Request {
                method: None,
                ..ok.clone()
            },
            Request {
                item: None,
                ..ok.clone()
            },
        ] {
            assert_eq!(
                evaluate(&policy, &denied).effect,
                Effect::Deny,
                "{denied:?}"
            );
        }
        // A proxy grant denies everything that hands out values.
        for permission in [Permission::Reveal, Permission::Inject, Permission::Fill] {
            assert_eq!(
                evaluate(&policy, &w.request(permission)).effect,
                Effect::Deny
            );
        }
        // Proxy defaults to deny: an agent approved before it existed
        // never gains it.
        assert_eq!(evaluate(&Policy::default(), &ok).effect, Effect::Deny);
    }

    #[test]
    fn proxy_grants_must_deny_values_and_name_items_and_hosts() {
        let token = ItemId::from_bytes([9; 16]);
        let with = |rules: Vec<Rule>| Policy {
            rules,
            expires_at: None,
        };
        // Without denying reveal, inject and fill (inject and fill allow by
        // default).
        assert_eq!(
            with(vec![proxy_rule(Effect::Allow, token)]).check_proxy(),
            Err(ProxyRuleError::HandsOutValues(Permission::Reveal))
        );
        let mut rules = deny_values();
        rules.push(Rule::new(Permission::Inject, Effect::Allow));
        rules.push(proxy_rule(Effect::Ask, token));
        assert_eq!(
            with(rules).check_proxy(),
            Err(ProxyRuleError::HandsOutValues(Permission::Inject))
        );
        let mut rules = deny_values();
        let mut no_items = proxy_rule(Effect::Allow, token);
        no_items.scope.items.clear();
        rules.push(no_items);
        assert_eq!(with(rules).check_proxy(), Err(ProxyRuleError::NoItems));
        for hosts in [vec![], vec!["*".parse().unwrap()]] {
            let mut rules = deny_values();
            let mut any_host = proxy_rule(Effect::Allow, token);
            any_host.scope.domains = hosts;
            rules.push(any_host);
            assert_eq!(with(rules).check_proxy(), Err(ProxyRuleError::NoHosts));
        }
        // HTTP dimensions only in proxy rules.
        let mut fill = scoped(Permission::Fill, Effect::Allow, Scope::default());
        fill.scope.methods = vec!["GET".parse().unwrap()];
        assert_eq!(
            with(vec![fill]).check_proxy(),
            Err(ProxyRuleError::HttpOutsideProxy(Permission::Fill))
        );
        // A deny-only proxy rule needs nothing else, and a v1 policy is not
        // v2.
        assert_eq!(
            with(vec![Rule::new(Permission::Proxy, Effect::Deny)]).check_proxy(),
            Ok(())
        );
        assert!(!with(vec![Rule::new(Permission::Reveal, Effect::Allow)]).needs_v2());
    }

    /// A broad allow with a narrower deny below it: no other spelling of
    /// the denied path falls through to the allow.
    #[test]
    fn a_narrower_deny_cannot_be_dodged_by_another_spelling() {
        let w = World::new();
        let token = ItemId::from_bytes([9; 16]);
        let rule = |effect, prefix: &str| {
            scoped(
                Permission::Proxy,
                effect,
                Scope {
                    items: vec![token],
                    domains: vec!["api.stripe.com".parse().unwrap()],
                    path_prefixes: vec![prefix.parse().unwrap()],
                    ..Scope::default()
                },
            )
        };
        let mut rules = deny_values();
        rules.push(rule(Effect::Allow, "/v1"));
        rules.push(rule(Effect::Deny, "/v1/charges"));
        let policy = Policy {
            rules,
            expires_at: None,
        };
        assert_eq!(policy.check_proxy(), Ok(()));
        let at = |path: &str| evaluate(&policy, &proxied(&w, token, "GET", "api.stripe.com", path));
        assert_eq!(at("/v1/customers").effect, Effect::Allow);
        assert_eq!(at("/v1/a%20b").effect, Effect::Allow);
        assert_eq!(at("/v1/charges").effect, Effect::Deny);
        for spelling in [
            "/v1/%63harges",
            "/v1/ch%61rges",
            "/v1/%43harges",
            "/v1/charges;x=1",
            "/v1;x/charges",
            "/v1/charges%3Bx",
            "/v1/charges%3a1",
            "/v1/charges%3A1",
            "/v1/%2Fcharges",
            "/v1/%2E/charges",
            "/v1/charges%C3%A9",
            "/v1/charge%73",
            "/v1/charges%7E",
        ] {
            assert_eq!(at(spelling).effect, Effect::Deny, "{spelling}");
        }
    }

    /// The method is checked before any rule: a rule without `methods`
    /// still never lets through a malformed method, `CONNECT` or `TRACE`.
    #[test]
    fn proxy_requests_need_a_plain_method_and_never_tunnel_or_trace() {
        let w = World::new();
        let token = ItemId::from_bytes([9; 16]);
        let mut rules = deny_values();
        rules.push(scoped(
            Permission::Proxy,
            Effect::Allow,
            Scope {
                items: vec![token],
                domains: vec!["api.northflank.com".parse().unwrap()],
                ..Scope::default()
            },
        ));
        let policy = Policy {
            rules,
            expires_at: None,
        };
        let with = |m: &str, path: &str| {
            evaluate(&policy, &proxied(&w, token, m, "api.northflank.com", path)).effect
        };
        assert_eq!(with("PATCH", "/v1"), Effect::Allow);
        for method in [
            "CONNECT",
            "TRACE",
            "get",
            "G-T",
            "",
            "AVERYLONGMETHODNAME",
            "GET ",
        ] {
            assert_eq!(with(method, "/v1"), Effect::Deny, "{method:?}");
        }
        // A rule without `path_prefixes` still never matches an ambiguous
        // path.
        for path in ["/v1/../x", "/v1/%63", "/v1;x", "v1"] {
            assert_eq!(with("GET", path), Effect::Deny, "{path:?}");
        }
    }

    #[test]
    fn proxy_rules_name_hosts_not_ip_addresses() {
        let token = ItemId::from_bytes([9; 16]);
        for ip in [
            "10.0.0.1",
            "127.1",
            "2130706433",
            "0x7f.1",
            "*.0.0.1",
            "169.254.169.254",
        ] {
            let Ok(pattern) = ip.parse::<DomainPattern>() else {
                continue;
            };
            assert!(pattern.is_ip_literal(), "{ip}");
            let mut rules = deny_values();
            let mut r = proxy_rule(Effect::Allow, token);
            r.scope.domains = vec![pattern];
            rules.push(r);
            let policy = Policy {
                rules,
                expires_at: None,
            };
            assert_eq!(policy.check_proxy(), Err(ProxyRuleError::IpHost), "{ip}");
        }
        for host in ["api.northflank.com", "x1.example", "a.b0x1"] {
            assert!(!is_ip_literal(host), "{host}");
        }
        // A deny rule may name anything.
        let mut rules = deny_values();
        rules.push(proxy_rule(Effect::Allow, token));
        let mut deny = proxy_rule(Effect::Deny, token);
        deny.scope.domains = vec!["10.0.0.1".parse().unwrap()];
        rules.push(deny);
        assert_eq!(
            Policy {
                rules,
                expires_at: None
            }
            .check_proxy(),
            Ok(())
        );
    }

    #[test]
    fn http_targets_parse_strictly() {
        for ok in ["GET", "POST", "DELETE", "PROPFIND"] {
            assert_eq!(HttpMethod::parse(ok).unwrap().as_str(), ok);
        }
        for bad in ["", "get", "GE T", "G3T", "AVERYLONGMETHODNAME"] {
            assert!(HttpMethod::parse(bad).is_err(), "{bad}");
        }
        for ok in [
            "/",
            "/v1",
            "/graphql/v2",
            "/a%20b",
            "/a%3Fb%23c",
            "/~user/x-y_z",
            "/a:b@c+d$e!f",
        ] {
            assert_eq!(PathPrefix::parse(ok).unwrap().as_str(), ok);
        }
        for bad in [
            "",
            "v1",
            "/v1/",
            "//",
            "/a//b",
            "/./a",
            "/a/..",
            "/a/%2e%2e",
            "/a%2Fb",
            "/a%5cb",
            "/a%25",
            "/a%0a",
            "/a%",
            "/a%zz",
            "/a?b",
            "/a#b",
            "/a b",
            "/a\\b",
            "/é",
            // One spelling per byte: no escape of what may be written as
            // itself, upper-case hex only, no `;`, nothing above 0x7f.
            "/%63harges",
            "/a%7E",
            "/a%2D",
            "/a%3A",
            "/a%3a",
            "/a%20%3f",
            "/a;b",
            "/a%3B",
            "/a%2f",
            "/a%C3%A9",
            "/a%7F",
            "/a%00",
        ] {
            assert!(PathPrefix::parse(bad).is_err(), "{bad}");
        }
        // A trailing slash is a path, not a prefix.
        assert!(is_canonical_path("/v1/"));
        let prefix = PathPrefix::parse("/v1").unwrap();
        assert!(prefix.matches("/v1") && prefix.matches("/v1/") && prefix.matches("/v1/a"));
        assert!(!prefix.matches("/v10") && !prefix.matches("/v") && !prefix.matches("/V1"));
        assert!(PathPrefix::parse("/").unwrap().matches("/anything/at/all"));
        // Serde goes through the same parser.
        let scope = Scope {
            items: vec![ItemId::from_bytes([5; 16])],
            methods: vec!["GET".parse().unwrap()],
            path_prefixes: vec!["/v1".parse().unwrap()],
            ..Scope::default()
        };
        let text = serde_json::to_string(&scope).unwrap();
        assert_eq!(serde_json::from_str::<Scope>(&text).unwrap(), scope);
        assert!(serde_json::from_str::<Scope>(r#"{"methods":["get"]}"#).is_err());
        assert!(serde_json::from_str::<Scope>(r#"{"path_prefixes":["/../x"]}"#).is_err());
        // A v1 scope serializes exactly as before.
        assert_eq!(
            serde_json::to_string(&domains(&["github.com"])).unwrap(),
            r#"{"domains":["github.com"]}"#
        );
    }

    #[test]
    fn defaults_follow_the_design_table() {
        let w = World::new();
        let expected = [
            (Permission::List, Effect::Allow),
            (Permission::Fill, Effect::Allow),
            (Permission::Inject, Effect::Allow),
            (Permission::Totp, Effect::Ask),
            (Permission::Reveal, Effect::Deny),
            (Permission::Create, Effect::Allow),
            (Permission::Update, Effect::Ask),
            (Permission::Delete, Effect::Deny),
            (Permission::Proxy, Effect::Deny),
        ];
        assert_eq!(expected.len(), Permission::GRANTABLE.len());
        for (permission, effect) in expected {
            assert_eq!(permission.default_effect(), effect);
            assert_eq!(
                evaluate(&Policy::default(), &w.request(permission)),
                Decision {
                    effect,
                    reason: Reason::Default
                }
            );
        }
    }

    #[test]
    fn task_only_permissions_are_denied_by_any_policy() {
        let w = World::new();
        assert_eq!(
            Permission::ALL.len(),
            Permission::GRANTABLE.len() + 2,
            "every permission is grantable or task-only"
        );
        for permission in [Permission::Passkey, Permission::Rotate] {
            assert!(permission.requires_task());
            assert!(!Permission::GRANTABLE.contains(&permission));
            assert_eq!(permission.default_effect(), Effect::Deny);
            // Even a (forbidden) allow rule does not open them.
            let policy = Policy {
                rules: vec![Rule::new(permission, Effect::Allow)],
                expires_at: None,
            };
            let deny = Decision {
                effect: Effect::Deny,
                reason: Reason::TaskOnly,
            };
            assert_eq!(evaluate(&policy, &w.request(permission)), deny);
            assert_eq!(evaluate_upper_bound(&policy, &w.request(permission)), deny);
            assert_eq!(evaluate(&Policy::default(), &w.request(permission)), deny);
            assert_eq!(policy.check_grantable(), Err(TaskOnlyRule(permission)));
        }
        for permission in Permission::GRANTABLE {
            assert!(!permission.requires_task());
            let policy = Policy {
                rules: vec![Rule::new(permission, Effect::Allow)],
                expires_at: None,
            };
            assert_eq!(policy.check_grantable(), Ok(()));
        }
    }

    #[test]
    fn permission_names_match_serde() {
        for permission in Permission::ALL {
            assert_eq!(
                serde_json::to_value(permission).unwrap(),
                serde_json::Value::String(permission.as_str().into())
            );
            assert_eq!(permission.to_string(), permission.as_str());
        }
        assert!(Permission::Fill.checks_domain());
        assert!(Permission::Passkey.checks_domain());
        assert!(!Permission::Totp.checks_domain());
        assert!(!Permission::Inject.checks_domain());
    }

    #[test]
    fn expired_policy_denies_everything() {
        let w = World::new();
        let policy = Policy {
            rules: vec![Rule::new(Permission::Reveal, Effect::Allow)],
            expires_at: Some(NOW),
        };
        for permission in Permission::ALL {
            assert_eq!(
                evaluate(&policy, &w.request(permission)),
                Decision {
                    effect: Effect::Deny,
                    reason: Reason::PolicyExpired
                }
            );
        }
        let alive = Policy {
            expires_at: Some(NOW + 1),
            ..policy
        };
        assert_eq!(
            evaluate(&alive, &w.request(Permission::Reveal)).effect,
            Effect::Allow
        );
    }

    #[test]
    fn explicit_rules_replace_the_default() {
        let w = World::new();
        let policy = Policy {
            rules: vec![
                Rule::new(Permission::Reveal, Effect::Ask),
                scoped(Permission::Fill, Effect::Allow, domains(&["*.github.com"])),
            ],
            expires_at: None,
        };
        assert_eq!(
            evaluate(&policy, &w.request(Permission::Reveal)),
            Decision {
                effect: Effect::Ask,
                reason: Reason::Rule(0)
            }
        );
        assert_eq!(
            evaluate(&policy, &w.request(Permission::Fill)).reason,
            Reason::Rule(1)
        );
        // `fill` is now limited to github: other domains are out of scope.
        let mut elsewhere = w.request(Permission::Fill);
        elsewhere.domain = Some("evil.example".into());
        assert_eq!(
            evaluate(&policy, &elsewhere),
            Decision {
                effect: Effect::Deny,
                reason: Reason::OutOfScope
            }
        );
        elsewhere.domain = None;
        assert_eq!(evaluate(&policy, &elsewhere).effect, Effect::Deny);
        // Other permissions keep their defaults.
        assert_eq!(
            evaluate(&policy, &w.request(Permission::Inject)).reason,
            Reason::Default
        );
    }

    #[test]
    fn most_restrictive_applicable_rule_wins() {
        let w = World::new();
        let policy = Policy {
            rules: vec![
                Rule::new(Permission::Inject, Effect::Allow),
                scoped(
                    Permission::Inject,
                    Effect::Deny,
                    Scope {
                        tags: vec!["PROD".into()],
                        ..Scope::default()
                    },
                ),
                scoped(
                    Permission::Inject,
                    Effect::Ask,
                    Scope {
                        vaults: vec![Selector::Id(w.trabajo)],
                        ..Scope::default()
                    },
                ),
            ],
            expires_at: None,
        };
        assert_eq!(
            evaluate(&policy, &w.request(Permission::Inject)),
            Decision {
                effect: Effect::Deny,
                reason: Reason::Rule(1)
            }
        );
        let mut staging = w.request(Permission::Inject);
        staging.tags = vec!["staging".into()];
        assert_eq!(
            evaluate(&policy, &staging),
            Decision {
                effect: Effect::Ask,
                reason: Reason::Rule(2)
            }
        );
        staging.vault = Target {
            id: w.personal,
            name: "Personal".into(),
        };
        assert_eq!(
            evaluate(&policy, &staging),
            Decision {
                effect: Effect::Allow,
                reason: Reason::Rule(0)
            }
        );
    }

    #[test]
    fn scope_dimensions() {
        let w = World::new();
        let req = w.request(Permission::List);
        let check = |scope: Scope| scope.matches(&req);
        assert!(check(Scope::default()));
        assert!(check(Scope {
            vaults: vec![Selector::Name("TRABAJO".into())],
            ..Scope::default()
        }));
        assert!(check(Scope {
            vaults: vec![Selector::Id(w.trabajo)],
            ..Scope::default()
        }));
        assert!(!check(Scope {
            vaults: vec![Selector::Id(w.personal)],
            ..Scope::default()
        }));
        assert!(check(Scope {
            projects: vec![Selector::Name("acme-api".into())],
            ..Scope::default()
        }));
        assert!(!check(Scope {
            projects: vec![Selector::Id(w.redes)],
            ..Scope::default()
        }));
        assert!(check(Scope {
            projects: vec![Selector::Id(w.redes), Selector::Id(w.acme)],
            ..Scope::default()
        }));
        assert!(check(Scope {
            tags: vec!["Prod".into()],
            ..Scope::default()
        }));
        assert!(!check(Scope {
            tags: vec!["dev".into()],
            ..Scope::default()
        }));
        assert!(check(domains(&["github.com"])));
        assert!(!check(domains(&["gitlab.com"])));
        // AND across dimensions.
        assert!(!check(Scope {
            vaults: vec![Selector::Id(w.trabajo)],
            tags: vec!["dev".into()],
            ..Scope::default()
        }));
    }

    #[test]
    fn rule_expiry_fails_closed() {
        let w = World::new();
        let temporary = Policy {
            rules: vec![Rule {
                expires_at: Some(NOW),
                ..Rule::new(Permission::Update, Effect::Allow)
            }],
            expires_at: None,
        };
        let mut before = w.request(Permission::Update);
        before.now = NOW - 1;
        assert_eq!(evaluate(&temporary, &before).effect, Effect::Allow);
        // At expiry it does not fall back to the default (`ask`): it denies.
        assert_eq!(
            evaluate(&temporary, &w.request(Permission::Update)),
            Decision {
                effect: Effect::Deny,
                reason: Reason::OutOfScope
            }
        );

        // A lapsed temporary block lets the remaining rules apply again.
        let block = Policy {
            rules: vec![
                Rule::new(Permission::Fill, Effect::Allow),
                Rule {
                    expires_at: Some(NOW),
                    ..scoped(Permission::Fill, Effect::Deny, domains(&["github.com"]))
                },
            ],
            expires_at: None,
        };
        let mut fill_before = w.request(Permission::Fill);
        fill_before.now = NOW - 1;
        assert_eq!(evaluate(&block, &fill_before).effect, Effect::Deny);
        assert_eq!(
            evaluate(&block, &w.request(Permission::Fill)).effect,
            Effect::Allow
        );
    }

    #[test]
    fn domain_patterns() {
        let p = |s: &str| DomainPattern::parse(s).unwrap();
        assert!(p("github.com").matches("github.com"));
        assert!(p("github.com").matches("GitHub.com."));
        assert!(!p("github.com").matches("api.github.com"));
        assert!(p("*.github.com").matches("github.com"));
        assert!(p("*.github.com").matches("api.github.com"));
        assert!(p("*.github.com").matches("a.b.github.com"));
        assert!(!p("*.github.com").matches("evilgithub.com"));
        assert!(!p("*.github.com").matches("github.com.evil.io"));
        assert!(p("*").matches("anything.example"));
        assert!(p("xn--bcher-kva.example").matches("XN--BCHER-KVA.example"));
        assert!(!p("*").matches("not a host"));
        for bad in [
            "",
            "*.",
            "*.com",
            "a.*.com",
            "*github.com",
            "https://github.com",
            "github.com:443",
            "github.com/x",
            "GitHub.com",
            "bücher.example",
            "-a.com",
            "a..com",
            "**.a.com",
        ] {
            assert!(DomainPattern::parse(bad).is_err(), "{bad}");
        }
        for text in ["*", "*.github.com", "github.com"] {
            assert_eq!(p(text).to_string(), text);
        }
    }

    #[test]
    fn policies_roundtrip_through_json() {
        let json = r#"{
            "rules": [
                {"permission": "fill", "effect": "allow", "scope": {"domains": ["*.github.com"]}},
                {"permission": "reveal", "effect": "ask",
                 "scope": {"vaults": ["trabajo"], "projects": ["03030303-0303-0303-0303-030303030303"], "tags": ["prod"]},
                 "expires_at": 1800000900}
            ],
            "expires_at": 1900000000
        }"#;
        let policy: Policy = serde_json::from_str(json).unwrap();
        assert_eq!(
            policy.rules[1].scope.projects,
            vec![Selector::Id(ProjectId::from_bytes([3; 16]))]
        );
        assert_eq!(
            policy.rules[1].scope.vaults,
            vec![Selector::Name("trabajo".into())]
        );
        let again: Policy = serde_json::from_str(&serde_json::to_string(&policy).unwrap()).unwrap();
        assert_eq!(again, policy);
        let w = World::new();
        assert_eq!(
            evaluate(&policy, &w.request(Permission::Reveal)).effect,
            Effect::Ask
        );
        for bad in [
            r#"{"rules": [{"permission": "sudo", "effect": "allow"}]}"#,
            r#"{"rules": [{"permission": "fill", "effect": "maybe"}]}"#,
            r#"{"rules": [{"permission": "fill", "effect": "allow", "scope": {"domains": ["*.com"]}}]}"#,
            r#"{"rules": [], "extra": 1}"#,
            r#"{"rules": [{"permission": "fill", "effect": "allow", "scope": {"vaults": [""]}}]}"#,
        ] {
            assert!(serde_json::from_str::<Policy>(bad).is_err(), "{bad}");
        }
    }

    /// 2027-01-15 (a Friday) at `hh:mm` UTC.
    fn friday_utc(hh: u64, mm: u64) -> u64 {
        1_800_000_000 - 1_800_000_000 % 86_400 + 7 * 86_400 + hh * 3600 + mm * 60
    }

    #[test]
    fn time_window_syntax() {
        let w: TimeWindow = "mon-fri 09:00-18:00 -06:00".parse().unwrap();
        assert_eq!(w.days.len(), 5);
        assert_eq!(w.days[0], Weekday::Mon);
        assert_eq!(w.utc_offset.minutes(), -360);
        let w: TimeWindow = "fri-mon 22:00-02:00 Z".parse().unwrap();
        assert_eq!(
            w.days,
            vec![Weekday::Fri, Weekday::Sat, Weekday::Sun, Weekday::Mon]
        );
        let w: TimeWindow = "daily 00:00-00:00 +01:00".parse().unwrap();
        assert!(w.days.is_empty());
        let w: TimeWindow = "sat,sun 10:00-12:00 UTC".parse().unwrap();
        assert_eq!(w.days, vec![Weekday::Sat, Weekday::Sun]);
        for bad in [
            "mon-fri 09:00-18:00",
            "mon-fri 9:00-18:00 Z",
            "lun 09:00-18:00 Z",
            "mon 09:00 Z",
            "",
        ] {
            assert!(bad.parse::<TimeWindow>().is_err(), "{bad}");
        }
    }

    #[test]
    fn time_windows() {
        let at = friday_utc(0, 0);
        assert_eq!(
            Weekday::from_days(i64::try_from(at / 86_400).unwrap()),
            Weekday::Fri
        );
        let office: TimeWindow = serde_json::from_str(
            r#"{"days": ["mon", "tue", "wed", "thu", "fri"], "start": "09:00", "end": "18:00", "utc_offset": "-06:00"}"#,
        )
        .unwrap();
        // 15:00 UTC is 09:00 in UTC-6.
        assert!(office.contains(friday_utc(15, 0)));
        assert!(!office.contains(friday_utc(14, 59)));
        assert!(office.contains(friday_utc(23, 59)));
        // 00:00 UTC Saturday is still Friday 18:00 local: end is exclusive.
        assert!(!office.contains(friday_utc(24, 0)));
        // Saturday 15:00 UTC: weekend.
        assert!(!office.contains(friday_utc(24 + 15, 0)));

        let night = TimeWindow {
            days: vec![Weekday::Fri],
            start: "22:00".parse().unwrap(),
            end: "02:00".parse().unwrap(),
            utc_offset: UtcOffset::default(),
        };
        assert!(night.contains(friday_utc(23, 0)));
        assert!(night.contains(friday_utc(24 + 1, 59)));
        assert!(!night.contains(friday_utc(24 + 2, 0)));
        assert!(
            !night.contains(friday_utc(1, 0)),
            "Friday 01:00 belongs to Thursday's window"
        );
        let all_day = TimeWindow {
            days: Vec::new(),
            start: "00:00".parse().unwrap(),
            end: "00:00".parse().unwrap(),
            utc_offset: UtcOffset::default(),
        };
        assert!(all_day.contains(at) && all_day.contains(friday_utc(12, 34)));

        for bad in ["24:00", "9:00", "09:60", "0900", ""] {
            assert!(bad.parse::<ClockTime>().is_err(), "{bad}");
        }
        for (text, minutes) in [("+05:30", 330), ("-06:00", -360), ("Z", 0), ("+00:00", 0)] {
            assert_eq!(text.parse::<UtcOffset>().unwrap().minutes(), minutes);
        }
        for bad in ["05:30", "+15:00", "-6", "+05:60"] {
            assert!(bad.parse::<UtcOffset>().is_err(), "{bad}");
        }
        assert_eq!(UtcOffset::from_minutes(-360).unwrap().to_string(), "-06:00");
    }

    #[test]
    fn hours_scope_a_rule() {
        let w = World::new();
        let window = TimeWindow {
            days: Vec::new(),
            start: "09:00".parse().unwrap(),
            end: "18:00".parse().unwrap(),
            utc_offset: UtcOffset::default(),
        };
        let policy = Policy {
            rules: vec![scoped(
                Permission::Fill,
                Effect::Allow,
                Scope {
                    hours: vec![window],
                    ..Scope::default()
                },
            )],
            expires_at: None,
        };
        let mut request = w.request(Permission::Fill);
        request.now = friday_utc(10, 0);
        assert_eq!(evaluate(&policy, &request).effect, Effect::Allow);
        request.now = friday_utc(20, 0);
        assert_eq!(
            evaluate(&policy, &request),
            Decision {
                effect: Effect::Deny,
                reason: Reason::OutOfScope
            }
        );
    }

    #[test]
    fn upper_bound_ignores_unknown_claims() {
        let w = World::new();
        let policy = Policy {
            rules: vec![
                scoped(
                    Permission::List,
                    Effect::Allow,
                    Scope {
                        tags: vec!["dev".into()],
                        ..Scope::default()
                    },
                ),
                scoped(
                    Permission::List,
                    Effect::Deny,
                    Scope {
                        tags: vec!["prod".into()],
                        ..Scope::default()
                    },
                ),
            ],
            expires_at: None,
        };
        // The request carries the "prod" tag: exact evaluation denies, but
        // a project may hold dev items, so the server lets the listing
        // through and the runtime filters.
        let request = w.request(Permission::List);
        assert_eq!(evaluate(&policy, &request).effect, Effect::Deny);
        assert_eq!(
            evaluate_upper_bound(&policy, &request).effect,
            Effect::Allow
        );
        // An unconditional deny always wins.
        let mut blocked = policy.clone();
        blocked
            .rules
            .push(Rule::new(Permission::List, Effect::Deny));
        assert_eq!(
            evaluate_upper_bound(&blocked, &request).effect,
            Effect::Deny
        );
        // Out of the project: nothing can apply.
        let other_project = Policy {
            rules: vec![scoped(
                Permission::List,
                Effect::Allow,
                Scope {
                    projects: vec![Selector::Id(w.redes)],
                    ..Scope::default()
                },
            )],
            expires_at: None,
        };
        assert_eq!(
            evaluate_upper_bound(&other_project, &request),
            Decision {
                effect: Effect::Deny,
                reason: Reason::OutOfScope
            }
        );
        assert!(
            !Scope {
                vaults: vec![Selector::Name("x".into())],
                ..Scope::default()
            }
            .uses_ids_only()
        );
    }

    // ------------------------------------------------------------ proptest --

    fn permission() -> impl Strategy<Value = Permission> {
        prop::sample::select(Permission::ALL.to_vec())
    }

    fn effect() -> impl Strategy<Value = Effect> {
        prop::sample::select(vec![Effect::Allow, Effect::Ask, Effect::Deny])
    }

    fn scope() -> impl Strategy<Value = Scope> {
        let vault = prop::sample::select(vec![
            Selector::Id(VaultId::from_bytes([1; 16])),
            Selector::Id(VaultId::from_bytes([2; 16])),
            Selector::Name("trabajo".into()),
            Selector::Name("personal".into()),
        ]);
        let project = prop::sample::select(vec![
            Selector::Id(ProjectId::from_bytes([3; 16])),
            Selector::Name("redes".into()),
        ]);
        let tag = prop::sample::select(vec!["prod".to_string(), "dev".to_string()]);
        let domain = prop::sample::select(vec!["*.github.com", "github.com", "example.org", "*"])
            .prop_map(|d| d.parse::<DomainPattern>().unwrap());
        (
            prop::collection::vec(vault, 0..2),
            prop::collection::vec(project, 0..2),
            prop::collection::vec(tag, 0..2),
            prop::collection::vec(domain, 0..2),
            prop::collection::vec(window(), 0..2),
            http_scope(),
        )
            .prop_map(
                |(vaults, projects, tags, domains, hours, (items, methods, path_prefixes))| Scope {
                    vaults,
                    projects,
                    tags,
                    domains,
                    hours,
                    items,
                    methods,
                    path_prefixes,
                    mcp_tools: Vec::new(),
                },
            )
    }

    fn http_scope() -> impl Strategy<Value = (Vec<ItemId>, Vec<HttpMethod>, Vec<PathPrefix>)> {
        let item = prop::sample::select(vec![
            ItemId::from_bytes([5; 16]),
            ItemId::from_bytes([6; 16]),
        ]);
        let method = prop::sample::select(vec!["GET", "POST", "DELETE"])
            .prop_map(|m| HttpMethod::parse(m).unwrap());
        let prefix = prop::sample::select(vec!["/", "/v1", "/v1/projects", "/graphql/v2"])
            .prop_map(|p| PathPrefix::parse(p).unwrap());
        (
            prop::collection::vec(item, 0..2),
            prop::collection::vec(method, 0..2),
            prop::collection::vec(prefix, 0..2),
        )
    }

    fn window() -> impl Strategy<Value = TimeWindow> {
        let clock = (0u16..24, prop::sample::select(vec![0u16, 30]))
            .prop_map(|(h, m)| ClockTime::new(h, m).unwrap());
        (
            prop::sample::subsequence(Weekday::ALL.to_vec(), 0..3),
            clock.clone(),
            clock,
            prop::sample::select(vec![-360i16, 0, 60, 330]),
        )
            .prop_map(|(days, start, end, offset)| TimeWindow {
                days,
                start,
                end,
                utc_offset: UtcOffset::from_minutes(offset).unwrap(),
            })
    }

    fn rule() -> impl Strategy<Value = Rule> {
        (
            permission(),
            effect(),
            scope(),
            prop::option::of(NOW - 5..NOW + 5),
        )
            .prop_map(|(permission, effect, scope, expires_at)| Rule {
                permission,
                effect,
                scope,
                expires_at,
            })
    }

    fn policy() -> impl Strategy<Value = Policy> {
        (
            prop::collection::vec(rule(), 0..6),
            prop::option::of(NOW - 5..NOW + 5),
        )
            .prop_map(|(rules, expires_at)| Policy { rules, expires_at })
    }

    /// A policy that passes `check_proxy` and can allow `proxy`, by
    /// construction: an allowing or asking proxy rule with items and hosts,
    /// one or more denies for each of `reveal`, `inject` and `fill` (random
    /// scopes), and random extra rules for the other permissions without
    /// HTTP dimensions.
    fn proxy_policy() -> impl Strategy<Value = Policy> {
        let proxy = (
            prop::sample::select(vec![Effect::Allow, Effect::Ask]),
            prop::collection::vec(
                prop::sample::select(vec![
                    ItemId::from_bytes([5; 16]),
                    ItemId::from_bytes([7; 16]),
                ]),
                1..3,
            ),
            prop::collection::vec(
                prop::sample::select(vec!["github.com", "*.github.com", "example.org"])
                    .prop_map(|d| d.parse::<DomainPattern>().unwrap()),
                1..3,
            ),
            scope(),
        )
            .prop_map(|(effect, items, domains, scope)| Rule {
                permission: Permission::Proxy,
                effect,
                scope: Scope {
                    items,
                    domains,
                    ..scope
                },
                expires_at: None,
            });
        let denies = prop::collection::vec(scope(), 3..6).prop_map(|scopes| {
            scopes
                .into_iter()
                .enumerate()
                .map(|(n, mut scope)| {
                    scope.items.clear();
                    scope.methods.clear();
                    scope.path_prefixes.clear();
                    Rule {
                        permission: [Permission::Reveal, Permission::Inject, Permission::Fill]
                            [n % 3],
                        effect: Effect::Deny,
                        scope,
                        expires_at: None,
                    }
                })
                .collect::<Vec<_>>()
        });
        let extra = prop::collection::vec(rule(), 0..4).prop_map(|rules| {
            rules
                .into_iter()
                .filter(|r| {
                    !matches!(
                        r.permission,
                        Permission::Proxy
                            | Permission::Reveal
                            | Permission::Inject
                            | Permission::Fill
                    )
                })
                .map(|mut r| {
                    r.scope.items.clear();
                    r.scope.methods.clear();
                    r.scope.path_prefixes.clear();
                    r
                })
                .collect::<Vec<_>>()
        });
        (proxy, denies, extra, Just(())).prop_shuffle_rules()
    }

    trait ShuffleRules {
        fn prop_shuffle_rules(self) -> BoxedStrategy<Policy>;
    }

    impl<S: Strategy<Value = (Rule, Vec<Rule>, Vec<Rule>, ())> + 'static> ShuffleRules for S {
        fn prop_shuffle_rules(self) -> BoxedStrategy<Policy> {
            self.prop_flat_map(|(proxy, denies, extra, ())| {
                let mut rules = vec![proxy];
                rules.extend(denies);
                rules.extend(extra);
                Just(rules).prop_shuffle()
            })
            .prop_map(|rules| Policy {
                rules,
                expires_at: None,
            })
            .boxed()
        }
    }

    fn request() -> impl Strategy<Value = Request> {
        let vault = prop::sample::select(vec![
            Target {
                id: VaultId::from_bytes([1; 16]),
                name: "Trabajo".to_string(),
            },
            Target {
                id: VaultId::from_bytes([2; 16]),
                name: "Personal".to_string(),
            },
        ]);
        let project = prop::sample::select(vec![
            Target {
                id: ProjectId::from_bytes([3; 16]),
                name: "acme-api".to_string(),
            },
            Target {
                id: ProjectId::from_bytes([4; 16]),
                name: "redes".to_string(),
            },
        ]);
        let tags = prop::collection::vec(
            prop::sample::select(vec!["prod".to_string(), "DEV".to_string()]),
            0..2,
        );
        let domain = prop::option::of(prop::sample::select(vec![
            "github.com".to_string(),
            "api.github.com".to_string(),
            "example.org".to_string(),
        ]));
        let item = prop::option::of(prop::sample::select(vec![
            ItemId::from_bytes([5; 16]),
            ItemId::from_bytes([7; 16]),
        ]));
        let method = prop::option::of(prop::sample::select(vec![
            "GET".to_string(),
            "DELETE".to_string(),
            "get".to_string(),
        ]));
        let path = prop::option::of(prop::sample::select(vec![
            "/v1/projects/a".to_string(),
            "/v1".to_string(),
            "/v1x".to_string(),
            "/graphql/v2".to_string(),
            "/v1/../admin".to_string(),
            "/v1/%2e%2e/admin".to_string(),
        ]));
        (
            (permission(), vault, project, tags, domain),
            (item, method, path),
            NOW - 6..NOW + 6,
        )
            .prop_map(
                |((permission, vault, project, tags, domain), (item, method, path), now)| Request {
                    permission,
                    vault,
                    project,
                    tags,
                    domain,
                    item,
                    method,
                    path,
                    mcp_tool: None,
                    now,
                },
            )
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

        #[test]
        fn prop_expired_policy_always_denies(policy in policy(), request in request()) {
            let expired = Policy { expires_at: Some(request.now), ..policy };
            prop_assert_eq!(evaluate(&expired, &request).effect, Effect::Deny);
        }

        #[test]
        fn prop_adding_a_deny_rule_never_loosens(policy in policy(), request in request(), scope in scope(), expires_at in prop::option::of(NOW - 5..NOW + 5)) {
            let before = evaluate(&policy, &request).effect;
            let mut stricter = policy.clone();
            stricter.rules.push(Rule { permission: request.permission, effect: Effect::Deny, scope, expires_at });
            prop_assert!(evaluate(&stricter, &request).effect >= before);
        }

        #[test]
        fn prop_rule_order_is_irrelevant(policy in policy(), request in request()) {
            let mut reversed = policy.clone();
            reversed.rules.reverse();
            prop_assert_eq!(evaluate(&policy, &request).effect, evaluate(&reversed, &request).effect);
        }

        #[test]
        fn prop_rules_for_other_permissions_are_ignored(policy in policy(), request in request()) {
            let only_this = Policy {
                rules: policy.rules.iter().filter(|r| r.permission == request.permission).cloned().collect(),
                ..policy.clone()
            };
            let (all, filtered) = (evaluate(&policy, &request), evaluate(&only_this, &request));
            // Rule indices shift after filtering; effect and kind of reason must not.
            prop_assert_eq!(all.effect, filtered.effect);
            prop_assert_eq!(std::mem::discriminant(&all.reason), std::mem::discriminant(&filtered.reason));
        }

        #[test]
        fn prop_allow_requires_an_applicable_allow_rule_or_default(policy in policy(), request in request()) {
            let decision = evaluate(&policy, &request);
            if decision.effect == Effect::Allow {
                match decision.reason {
                    Reason::Default => prop_assert_eq!(request.permission.default_effect(), Effect::Allow),
                    Reason::Rule(i) => {
                        let rule = &policy.rules[i];
                        prop_assert_eq!(rule.permission, request.permission);
                        prop_assert_eq!(rule.effect, Effect::Allow);
                        prop_assert!(!rule.expired(request.now) && rule.scope.matches(&request));
                    }
                    other => prop_assert!(false, "allow with reason {:?}", other),
                }
            }
        }

        #[test]
        fn prop_upper_bound_is_never_stricter(policy in policy(), request in request()) {
            // Whatever tags and domain the request turns out to have, the
            // upper bound is at least as permissive as the exact decision.
            prop_assert!(evaluate_upper_bound(&policy, &request).effect <= evaluate(&policy, &request).effect);
        }

        #[test]
        fn prop_upper_bound_is_exact_without_claims(policy in policy(), request in request()) {
            // With no tag or domain constraints the bound is the decision
            // (for `proxy`, once the request says a method and path the
            // policy can judge: the bound ignores claims).
            prop_assume!(request.permission != Permission::Proxy || proxy_request_ok(&request));
            let plain = Policy {
                rules: policy.rules.iter().cloned().map(|mut r| {
                    r.scope.tags.clear();
                    r.scope.domains.clear();
                    r.scope.items.clear();
                    r.scope.methods.clear();
                    r.scope.path_prefixes.clear();
                    r
                }).collect(),
                ..policy
            };
            prop_assert_eq!(evaluate_upper_bound(&plain, &request).effect, evaluate(&plain, &request).effect);
        }

        #[test]
        fn prop_a_path_matches_only_when_canonical(prefix in prop::sample::select(vec!["/", "/v1", "/graphql/v2"]), path in "[/a-z0-9.%]{0,12}") {
            let prefix = PathPrefix::parse(prefix).unwrap();
            if prefix.matches(&path) {
                prop_assert!(is_canonical_path(&path));
                prop_assert!(path.starts_with(prefix.as_str()));
                prop_assert!(!path.split('/').any(|seg| seg == ".." || seg == "."));
            }
        }

        #[test]
        fn prop_a_proxy_policy_that_checks_never_hands_out_values(policy in proxy_policy(), request in request()) {
            // Whatever else it says, a policy that passes `check_proxy` and
            // can allow `proxy` denies the permissions that return values.
            // The strategy builds only such policies, so this runs every case.
            prop_assert_eq!(policy.check_proxy(), Ok(()));
            prop_assert!(policy.may_proxy());
            for permission in [Permission::Reveal, Permission::Inject, Permission::Fill] {
                let request = Request { permission, ..request.clone() };
                prop_assert_eq!(evaluate(&policy, &request).effect, Effect::Deny);
            }
        }

        #[test]
        fn prop_proxy_is_never_allowed_without_a_rule(policy in policy(), request in request()) {
            let request = Request { permission: Permission::Proxy, ..request };
            let decision = evaluate(&policy, &request);
            if decision.effect != Effect::Deny {
                let Reason::Rule(i) = decision.reason else {
                    return Err(TestCaseError::fail("proxy passed without a rule"));
                };
                prop_assert_eq!(policy.rules[i].permission, Permission::Proxy);
            }
        }

        #[test]
        fn prop_reveal_and_delete_are_never_allowed_by_default(request in request()) {
            for permission in [Permission::Reveal, Permission::Delete, Permission::Proxy] {
                let request = Request { permission, ..request.clone() };
                prop_assert_eq!(evaluate(&Policy::default(), &request).effect, Effect::Deny);
            }
        }

        #[test]
        fn prop_decision_reason_is_consistent(policy in policy(), request in request()) {
            let decision = evaluate(&policy, &request);
            let has_rules = policy.rules.iter().any(|r| r.permission == request.permission);
            let expired = policy.expires_at.is_some_and(|t| request.now >= t);
            match decision.reason {
                Reason::PolicyExpired => prop_assert!(expired),
                Reason::TaskOnly => prop_assert!(
                    !expired && request.permission.requires_task() && decision.effect == Effect::Deny
                ),
                Reason::Default => prop_assert!(!expired && !has_rules),
                Reason::OutOfScope => prop_assert!(!expired && has_rules && decision.effect == Effect::Deny),
                Reason::Rule(i) => {
                    prop_assert!(!expired);
                    prop_assert_eq!(policy.rules[i].effect, decision.effect);
                    // No applicable rule is more restrictive than the winner.
                    prop_assert!(policy.rules.iter().all(|r| r.permission != request.permission
                        || r.expired(request.now)
                        || !r.scope.matches(&request)
                        || r.effect <= decision.effect));
                }
            }
        }
    }

    // ------------------------------------------------------ MCP tools ----

    fn tools(patterns: &[&str]) -> Vec<ToolPattern> {
        patterns.iter().map(|p| p.parse().unwrap()).collect()
    }

    #[test]
    fn tool_names_and_patterns_follow_their_grammar() {
        for good in ["query_logs", "a", "get.logs-v2", "X_Y", &"a".repeat(128)] {
            assert!(tool_name_ok(good), "{good}");
            assert!(ToolPattern::parse(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "query logs",
            "query\nlogs",
            "q\u{202e}l",
            "quéry",
            "a\"b",
            "a/b",
            "a*b",
            &"a".repeat(129),
        ] {
            assert!(!tool_name_ok(bad), "{bad:?}");
            assert!(ToolPattern::parse(bad).is_err(), "{bad:?}");
        }
        for good in ["*", "get_*", "G*", &format!("{}*", "a".repeat(127))] {
            assert!(ToolPattern::parse(good).is_ok(), "{good}");
        }
        for bad in [
            "**",
            "*get",
            "get_**",
            "*_api_key",
            "ge*t",
            " get_*",
            &format!("{}*", "a".repeat(128)),
        ] {
            assert!(ToolPattern::parse(bad).is_err(), "{bad:?}");
        }
        for good in ["claude-code", "cursor", "a", "vs-code-2", &"a".repeat(32)] {
            assert!(local_client_name_ok(good), "{good}");
        }
        for bad in [
            "",
            "Claude",
            "claude code",
            "claude_code",
            "é",
            &"a".repeat(33),
        ] {
            assert!(!local_client_name_ok(bad), "{bad:?}");
        }
    }

    #[test]
    fn tool_patterns_match_case_sensitively_and_by_prefix_only() {
        let p = |t: &str| t.parse::<ToolPattern>().unwrap();
        assert!(p("get_*").matches("get_logs"));
        assert!(p("get_*").matches("get_"));
        assert!(p("get_*").matches("get_and_delete_all"));
        assert!(!p("get_*").matches("Get_logs"));
        assert!(!p("get_*").matches("forget_logs"));
        assert!(!p("delete_*").matches("DeleteService"));
        assert!(p("query_logs").matches("query_logs"));
        assert!(!p("query_logs").matches("query_logs2"));
        assert!(!p("query_logs").matches("Query_logs"));
        assert!(p("*").matches("anything.at-all_9"));
        assert!(p("*").is_any());
        // A name outside the grammar matches nothing, not even `*`.
        assert!(!p("*").matches("bad name"));
        assert!(!p("*").matches(""));
        assert!(!p("get_*").matches("get_\u{202e}"));
        // As JSON, a pattern is its text, checked on the way in.
        assert_eq!(serde_json::to_string(&p("get_*")).unwrap(), "\"get_*\"");
        assert!(serde_json::from_str::<ToolPattern>("\"*_key\"").is_err());
    }

    /// Four `proxy` rules on one item, as ADR 0049 §5.3's Maple example.
    fn maple_policy() -> Policy {
        let item = ItemId::from_bytes([5; 16]);
        let base = Scope {
            items: vec![item],
            domains: vec!["api.maple.dev".parse().unwrap()],
            path_prefixes: vec![PathPrefix::parse("/mcp").unwrap()],
            ..Scope::default()
        };
        let with = |effect, mcp_tools| Rule {
            permission: Permission::Proxy,
            effect,
            scope: Scope {
                mcp_tools,
                ..base.clone()
            },
            expires_at: None,
        };
        Policy {
            rules: vec![
                Rule {
                    permission: Permission::Proxy,
                    effect: Effect::Allow,
                    scope: Scope {
                        methods: vec![
                            HttpMethod::parse("POST").unwrap(),
                            HttpMethod::parse("GET").unwrap(),
                            HttpMethod::parse("DELETE").unwrap(),
                        ],
                        ..base.clone()
                    },
                    expires_at: None,
                },
                with(Effect::Allow, tools(&["get_*", "list_*", "query_*"])),
                with(Effect::Ask, tools(&["create_*", "update_*", "delete_*"])),
                with(Effect::Deny, tools(&["create_api_key", "get_api_key"])),
            ],
            expires_at: None,
        }
    }

    fn mcp_request(tool: Option<&str>) -> Request {
        let w = World::new();
        Request {
            domain: Some("api.maple.dev".into()),
            item: Some(ItemId::from_bytes([5; 16])),
            method: Some("POST".into()),
            path: Some("/mcp".into()),
            mcp_tool: tool.map(str::to_owned),
            tags: Vec::new(),
            ..w.request(Permission::Proxy)
        }
    }

    #[test]
    fn unlisted_tools_are_denied_and_the_session_rule_allows_no_tool() {
        let policy = maple_policy();
        let effect = |tool| evaluate(&policy, &mcp_request(tool)).effect;
        // The session itself (initialize, tools/list): no tool.
        assert_eq!(effect(None), Effect::Allow);
        assert_eq!(effect(Some("query_logs")), Effect::Allow);
        assert_eq!(effect(Some("get_dashboard")), Effect::Allow);
        assert_eq!(effect(Some("delete_dashboard")), Effect::Ask);
        // The most restrictive wins: `allow get_*` and `deny get_api_key`.
        assert_eq!(effect(Some("get_api_key")), Effect::Deny);
        assert_eq!(effect(Some("create_api_key")), Effect::Deny);
        // A tool no rule names, a case variant, and a name outside the
        // grammar: denied, never by the session rule.
        for tool in ["run_query", "Get_logs", "DeleteService", "get logs", ""] {
            assert_eq!(effect(Some(tool)), Effect::Deny, "{tool:?}");
        }
        // Only the session rule: no tool at all.
        let session_only = Policy {
            rules: vec![policy.rules[0].clone()],
            expires_at: None,
        };
        assert_eq!(
            evaluate(&session_only, &mcp_request(Some("query_logs"))),
            Decision {
                effect: Effect::Deny,
                reason: Reason::OutOfScope
            }
        );
        // A deny rule without tools still denies a tool call.
        let mut closed = policy.clone();
        closed.rules.push(Rule {
            permission: Permission::Proxy,
            effect: Effect::Deny,
            scope: Scope::default(),
            expires_at: None,
        });
        assert_eq!(
            evaluate(&closed, &mcp_request(Some("query_logs"))).effect,
            Effect::Deny
        );
        // An `ask` without tools does not make a tool call ask.
        let mut asks = policy.clone();
        asks.rules[0].effect = Effect::Ask;
        assert_eq!(
            evaluate(&asks, &mcp_request(Some("query_logs"))).effect,
            Effect::Allow
        );
    }

    #[test]
    fn no_default_lets_a_tool_through() {
        let w = World::new();
        // `inject` and `fill` allow by default; with a tool named, never.
        for permission in [Permission::Inject, Permission::Fill, Permission::Proxy] {
            let request = Request {
                mcp_tool: Some("query_logs".into()),
                ..w.request(permission)
            };
            assert_eq!(
                evaluate(&Policy::default(), &request).effect,
                Effect::Deny,
                "{permission}"
            );
        }
        // A tool on anything but `proxy` is not judgeable, even when a rule
        // would allow everything.
        let request = Request {
            mcp_tool: Some("query_logs".into()),
            ..w.request(Permission::Inject)
        };
        let open = Policy {
            rules: vec![Rule::new(Permission::Inject, Effect::Allow)],
            expires_at: None,
        };
        assert_eq!(evaluate(&open, &request).effect, Effect::Deny);
    }

    #[test]
    fn tools_only_in_proxy_rules_and_only_in_version_4() {
        let mut policy = maple_policy();
        assert!(policy.needs_v4() && policy.needs_v2());
        for p in [
            Permission::Proxy,
            Permission::Reveal,
            Permission::Inject,
            Permission::Fill,
        ] {
            if p != Permission::Proxy {
                policy.rules.push(Rule::new(p, Effect::Deny));
            }
        }
        policy.check_proxy().expect("valid");
        let mut outside = policy.clone();
        outside.rules.push(Rule {
            permission: Permission::Inject,
            effect: Effect::Deny,
            scope: Scope {
                mcp_tools: tools(&["*"]),
                ..Scope::default()
            },
            expires_at: None,
        });
        assert_eq!(
            outside.check_proxy(),
            Err(ProxyRuleError::ToolsOutsideProxy(Permission::Inject))
        );
        let mut none = maple_policy();
        for r in &mut none.rules {
            r.scope.mcp_tools.clear();
        }
        assert!(!none.needs_v4());
    }

    /// `evaluate` as it was before ADR 0049: the oracle the proptests hold
    /// the new one to wherever no tool is named.
    fn evaluate_before_0049(policy: &Policy, request: &Request) -> Decision {
        let deny = |reason| Decision {
            effect: Effect::Deny,
            reason,
        };
        if policy.expires_at.is_some_and(|t| request.now >= t) {
            return deny(Reason::PolicyExpired);
        }
        if request.permission.requires_task() {
            return deny(Reason::TaskOnly);
        }
        let unjudgeable = request.permission == Permission::Proxy && !proxy_request_ok(request);
        let mut has_rules = false;
        let mut best: Option<(Effect, usize)> = None;
        for (index, rule) in policy.rules.iter().enumerate() {
            if rule.permission != request.permission {
                continue;
            }
            has_rules = true;
            if rule.expired(request.now)
                || !rule.scope.matches(request)
                || (unjudgeable && rule.effect != Effect::Deny)
            {
                continue;
            }
            if best.is_none_or(|(effect, _)| rule.effect > effect) {
                best = Some((rule.effect, index));
            }
        }
        match (has_rules, best) {
            (false, _) => Decision {
                effect: request.permission.default_effect(),
                reason: Reason::Default,
            },
            (true, Some((effect, index))) => Decision {
                effect,
                reason: Reason::Rule(index),
            },
            (true, None) => deny(Reason::OutOfScope),
        }
    }

    fn tool_patterns() -> impl Strategy<Value = Vec<ToolPattern>> {
        prop::collection::vec(
            prop::sample::select(vec!["get_*", "get_logs", "*", "Get_*", "delete_*"])
                .prop_map(|t| t.parse::<ToolPattern>().unwrap()),
            0..3,
        )
    }

    /// [`policy`] with tools on some rules (whatever their permission:
    /// `evaluate` must hold even on a policy `check_proxy` refuses).
    fn tool_policy() -> impl Strategy<Value = Policy> {
        (policy(), prop::collection::vec(tool_patterns(), 6)).prop_map(|(mut policy, tools)| {
            for (rule, t) in policy.rules.iter_mut().zip(tools) {
                rule.scope.mcp_tools = t;
            }
            policy
        })
    }

    fn tool() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "get_logs".to_string(),
            "get_x".to_string(),
            "Get_logs".to_string(),
            "delete_x".to_string(),
            "bad name".to_string(),
            String::new(),
            "a".repeat(129),
        ])
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 1024, ..ProptestConfig::default() })]

        /// ADR 0049 changes nothing for a request that names no tool, with
        /// or without tool rules in the policy.
        #[test]
        fn prop_without_a_tool_nothing_changes(policy in tool_policy(), request in request()) {
            prop_assert!(request.mcp_tool.is_none());
            prop_assert_eq!(evaluate(&policy, &request), evaluate_before_0049(&policy, &request));
        }

        /// A tool call passes only through a live `proxy` rule that names
        /// it, with a tool in the grammar; never by a default.
        #[test]
        fn prop_a_tool_passes_only_by_a_rule_that_names_it(policy in tool_policy(), request in request(), tool in tool()) {
            let request = Request { mcp_tool: Some(tool.clone()), ..request };
            let decision = evaluate(&policy, &request);
            if decision.effect != Effect::Deny {
                let Reason::Rule(i) = decision.reason else {
                    return Err(TestCaseError::fail(format!("{decision:?} without a rule")));
                };
                let rule = &policy.rules[i];
                prop_assert_eq!(request.permission, Permission::Proxy);
                prop_assert!(tool_name_ok(&tool));
                prop_assert!(rule.scope.mcp_tools.iter().any(|p| p.matches(&tool)));
                prop_assert!(rule.scope.matches(&request) && !rule.expired(request.now));
            }
        }

        /// A live deny rule that matches denies a tool call, tools or not.
        #[test]
        fn prop_a_matching_deny_always_denies_a_tool(policy in tool_policy(), request in request(), tool in tool()) {
            let request = Request { mcp_tool: Some(tool), ..request };
            let denied = policy.expires_at.is_none_or(|t| request.now < t)
                && policy.rules.iter().any(|r| r.permission == request.permission
                    && r.effect == Effect::Deny
                    && !r.expired(request.now)
                    && r.scope.matches(&request));
            if denied {
                prop_assert_eq!(evaluate(&policy, &request).effect, Effect::Deny);
            }
        }

        /// Naming a tool never loosens what the same request gets from the
        /// rules without tools: the session rule cannot allow a tool.
        #[test]
        fn prop_rules_without_tools_never_allow_a_tool(policy in policy(), request in request(), tool in tool()) {
            let request = Request { mcp_tool: Some(tool), ..request };
            prop_assert_eq!(evaluate(&policy, &request).effect, Effect::Deny);
        }
    }
}
