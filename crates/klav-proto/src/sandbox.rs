//! A sandbox's life as the credential proxy reports it to the server
//! (ADR 0036 §4, §9, E3.3; `docs/api.md` §8).
//!
//! The proxy, an agent, signs each step like any agent request (spec
//! §13.3) and the server logs it with its body, so `klav log verify` can
//! check what the proxy said: `sandbox.issued` before the issuer gets the
//! package, `sandbox.claimed` before the secret counts as spent, and
//! `sandbox.revoked` with its reason. None of these bodies carries the
//! sandbox's secret, its digest or the package.

use klav_core::ids::{AgentId, SandboxId};
use serde::{Deserialize, Serialize};

use crate::Blob;

/// `POST /v1/agent/sandboxes`.
pub const PATH_SANDBOXES: &str = "/v1/agent/sandboxes";
/// Suffix of `POST /v1/agent/sandboxes/{sandbox_id}/claimed`.
pub const SUFFIX_CLAIMED: &str = "/claimed";
/// Suffix of `POST /v1/agent/sandboxes/{sandbox_id}/revoked`.
pub const SUFFIX_REVOKED: &str = "/revoked";
/// Longest label, in characters.
pub const MAX_SANDBOX_LABEL: usize = 64;
/// Most profiles one sandbox may use (as many as an issuer may get).
pub const MAX_SANDBOX_PROFILES: usize = crate::agent::MAX_ISSUER_PROFILES;
/// Latest `expires_at` any reader accepts (Unix ms, 9999-12-31): a
/// package's `vence_ms` is a `u64` (spec §13.10), and a time past this is
/// refused, never cast or added to until it overflows.
pub const MAX_SANDBOX_EXPIRES_AT: i64 = 253_402_300_799_999;
/// Length of [`SandboxClaimed::channel_key_sha256`].
pub const CHANNEL_KEY_DIGEST_LEN: usize = 32;
/// `POST /v1/sandboxes/revoke`: the person revokes sandboxes.
pub const PATH_PERSON_REVOKE: &str = "/v1/sandboxes/revoke";
/// `GET /v1/agent/sandboxes/revocations?since=`: the proxy reads them.
pub const PATH_REVOCATIONS: &str = "/v1/agent/sandboxes/revocations";
/// The `scope` of a revocation of every sandbox of a proxy.
pub const SCOPE_ALL: &str = "all";
/// Most revocations in one page of [`PATH_REVOCATIONS`].
pub const MAX_REVOCATIONS_PAGE: usize = 100;
/// `POST /v1/agent/sandboxes/epochs`: the proxy logs a new store epoch
/// (`sandbox.store_reset`, ADR 0036 E3.3). Signed for exactly this path,
/// with no query string: the person's verifier checks it.
pub const PATH_STORE_RESET: &str = "/v1/agent/sandboxes/epochs";
/// `PUT /v1/agent/sandboxes/state`: the proxy's heartbeat (ADR 0036 E3.3),
/// signed for exactly this path too.
pub const PATH_SANDBOX_STATE: &str = "/v1/agent/sandboxes/state";
/// Length of a store epoch (random bytes).
pub const STORE_EPOCH_LEN: usize = 16;
/// Format version of [`SandboxHeartbeat`].
pub const HEARTBEAT_VERSION: u32 = 1;
/// Most sandboxes one heartbeat names: their body stays well under the
/// 16 KiB of a logged request (`crate::audit::MAX_PROOF_BODY`), so a device
/// can always check the stored request whole. A proxy with more names the
/// connected ones first, then the most recently seen. Decided by the owner
/// on 2026-11-13; raising it later is costly, because a device that reads
/// more than this many refuses the heartbeat as not one.
pub const MAX_HEARTBEAT_SANDBOXES: usize = 100;

/// The path of a step of `sandbox`: `/v1/agent/sandboxes/{id}{suffix}`.
pub fn sandbox_path(sandbox: SandboxId, suffix: &str) -> String {
    format!("{PATH_SANDBOXES}/{sandbox}{suffix}")
}

/// `POST /v1/agent/sandboxes`: the proxy started a sandbox for an issuer
/// (`sandbox.issued`). It sends this before it hands the issuer the
/// package; if the server refuses, there is no package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxIssue {
    /// Chosen by the proxy (16 random bytes).
    pub sandbox_id: SandboxId,
    /// The issuer that asked for it, as the proxy verified its request.
    pub issuer_id: AgentId,
    /// The issuer's label (shown "per the issuer", T136).
    pub label: String,
    /// Names of the proxy's profiles the sandbox may use.
    pub profiles: Vec<String>,
    /// When it ends (Unix ms), the `vence_ms` of the package.
    pub expires_at: i64,
}

impl SandboxIssue {
    /// The rules every reader applies to what it parses: a label of 1 to
    /// [`MAX_SANDBOX_LABEL`] characters with no spaces around it and no
    /// hidden characters, 1 to [`MAX_SANDBOX_PROFILES`] distinct profiles
    /// whose names follow the grant's rule ([`crate::agent::profile_name_ok`]),
    /// an issuer that is not `proxy`, and an end after 0 and no later than
    /// [`MAX_SANDBOX_EXPIRES_AT`].
    pub fn check_format(&self, proxy: AgentId) -> Result<(), String> {
        let label = self.label.as_str();
        if label.is_empty()
            || label.trim() != label
            || label.chars().count() > MAX_SANDBOX_LABEL
            || label.chars().any(klav_core::text::is_hidden)
        {
            return Err(format!(
                "the label must be 1–{MAX_SANDBOX_LABEL} characters, with no spaces around it \
                 and no control or invisible characters"
            ));
        }
        if self.profiles.is_empty() || self.profiles.len() > MAX_SANDBOX_PROFILES {
            return Err(format!("a sandbox uses 1–{MAX_SANDBOX_PROFILES} profiles"));
        }
        let mut seen = std::collections::HashSet::new();
        if !self.profiles.iter().all(|p| seen.insert(p.as_str())) {
            return Err("a profile appears twice".into());
        }
        if let Some(bad) = self
            .profiles
            .iter()
            .find(|p| !crate::agent::profile_name_ok(p))
        {
            return Err(format!(
                "profile name {bad:?}: 1–32 lower-case letters, digits or -, starting with a letter"
            ));
        }
        if self.issuer_id == proxy {
            return Err("the proxy cannot be its own issuer".into());
        }
        if !(1..=MAX_SANDBOX_EXPIRES_AT).contains(&self.expires_at) {
            return Err("expires_at must be a time".into());
        }
        Ok(())
    }
}

/// `POST /v1/agent/sandboxes/{sandbox_id}/claimed`: a forwarder claimed
/// the sandbox with its secret, from the channel key it presented
/// (`sandbox.claimed`, ADR 0036 §5, E3.3). The proxy sends this before it
/// counts the secret as spent. The proxy that calls it arrives with layer 6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxClaimed {
    /// SHA-256 of the DER `SubjectPublicKeyInfo` of the channel's Ed25519
    /// key (spec §13.10, the same construction as the proxy pin).
    pub channel_key_sha256: Blob,
}

/// Why the proxy ended a sandbox (`sandbox.revoked`, ADR 0036 §9, E3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxEnd {
    /// Its issuer stopped it (`klav sandbox stop`).
    Stop,
    /// It reached its `expires_at`.
    Ttl,
    /// An hour without a connection (from its issue while unclaimed).
    Inactivity,
    /// A second claim with the same secret: the theft signal. Only after a
    /// claim.
    Theft,
    /// Its forwarder released it when shutting down. Only after a claim.
    Released,
    /// The person removed or revoked its issuer.
    IssuerRemoved,
    /// The person revoked it with a signed revocation the server keeps
    /// (`sandbox.revoke_requested`); the body's `at` is that revocation's.
    Person,
    /// The person revoked it through the proxy's local socket, with no
    /// signature (ADR 0036 E3.5).
    PersonLocal,
}

impl SandboxEnd {
    /// The reason as written in the body and in the event's `outcome`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Ttl => "ttl",
            Self::Inactivity => "inactivity",
            Self::Theft => "theft",
            Self::Released => "released",
            Self::IssuerRemoved => "issuer_removed",
            Self::Person => "person",
            Self::PersonLocal => "person_local",
        }
    }

    /// Whether only a claimed sandbox can end this way.
    pub fn needs_claim(self) -> bool {
        matches!(self, Self::Theft | Self::Released)
    }
}

/// `POST /v1/agent/sandboxes/{sandbox_id}/revoked`: the proxy ended a
/// sandbox (`sandbox.revoked`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxRevoked {
    /// Why.
    pub reason: SandboxEnd,
    /// With `person`, and only then: the `at` (Unix ms) of the person's
    /// revocation it answers. Absent otherwise, so the other bodies are
    /// byte for byte what they were. A present `at` must be a number: an
    /// explicit `null` does not read as absent ([`present_at`]).
    #[serde(
        default,
        deserialize_with = "present_at",
        skip_serializing_if = "Option::is_none"
    )]
    pub at: Option<i64>,
}

/// Reads a present `at` as a plain number. A missing `at` stays `None`
/// (`serde(default)`), but `"at": null` is an error: otherwise a body that
/// released servers refused (an `at` they do not know) would be accepted
/// and logged, and released verifiers would reject the entry.
fn present_at<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<i64>, D::Error> {
    i64::deserialize(d).map(Some)
}

impl SandboxRevoked {
    /// An end for `reason` with no `at`.
    pub fn new(reason: SandboxEnd) -> Self {
        Self { reason, at: None }
    }

    /// `at` with `person`, and only with it.
    pub fn check_format(&self) -> Result<(), String> {
        match (self.reason, self.at) {
            (SandboxEnd::Person, Some(at)) if at > 0 => Ok(()),
            (SandboxEnd::Person, _) => Err("person needs the at of the revocation".into()),
            (_, Some(_)) => Err("only person takes an at".into()),
            (_, None) => Ok(()),
        }
    }
}

/// Whether `body` (already parsed as JSON) is an object. Serde also reads
/// a struct from an array (`["stop"]`), which no proxy sends: the server
/// refuses that form of a sandbox's end, and the verifier refuses it for
/// the person's reasons, so an entry for them only ever has one shape.
pub fn is_json_object(body: &[u8]) -> bool {
    body.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{')
}

/// `POST /v1/sandboxes/revoke`: the person revokes one sandbox of the
/// proxy, or all of them, with the account's signature (spec §13.11,
/// ADR 0036 E3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxRevoke {
    /// The proxy (an agent of the account).
    pub proxy_id: AgentId,
    /// A sandbox ID, or [`SCOPE_ALL`].
    pub scope: String,
    /// When the person revoked, Unix ms, as signed.
    pub at: i64,
    /// The account's signature (64 bytes).
    pub signature: Blob,
}

/// What [`SandboxRevoke::scope`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeTarget {
    /// Every sandbox of the proxy the log issued before the revocation.
    All,
    /// One sandbox.
    One(SandboxId),
}

/// How far a revocation's signed `at` may be from the server's clock (and
/// the event's own time from it): the window of every signed request
/// (spec §13.3, §13.11).
pub const REVOKE_CLOCK_WINDOW_MS: i64 = 5 * 60 * 1000;

/// Whether an `all` revocation signed at `at` (Unix ms, as the person
/// signed it) covers a sandbox issued before it that expires at
/// `expires_at`: the one rule the server, the verifier and anyone checking
/// an `all` share (spec §13.11). It reads only signed times, so the
/// server's clock decides nothing, and it is over-inclusive by the clock
/// window: a device whose clock runs up to 5 min ahead of the server's
/// still covers every sandbox the server counts as live. A sandbox already
/// expired within the window is listed too; it is barred either way.
pub fn all_covers(expires_at: i64, at: i64) -> bool {
    expires_at > at.saturating_sub(REVOKE_CLOCK_WINDOW_MS)
}

/// `POST /v1/agent/sandboxes/epochs`: a new store of the proxy, logged as
/// `sandbox.store_reset` before its first heartbeat (ADR 0036 E3.3). Each
/// store, the first one too, has its own epoch, and a proxy never uses one
/// twice: a heartbeat from before a reset carries the old epoch and no
/// device takes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxStoreReset {
    /// The new epoch ([`STORE_EPOCH_LEN`] random bytes).
    pub store_epoch: Blob,
}

impl SandboxStoreReset {
    /// The epoch's length.
    pub fn check_format(&self) -> Result<(), String> {
        if self.store_epoch.as_bytes().len() == STORE_EPOCH_LEN {
            Ok(())
        } else {
            Err(format!("store_epoch must be {STORE_EPOCH_LEN} bytes"))
        }
    }
}

/// One sandbox in a heartbeat, as the proxy sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxLink {
    /// The sandbox.
    pub id: SandboxId,
    /// Whether its forwarder holds a connection to the proxy now.
    pub connected: bool,
    /// When the proxy last heard from it (the proxy's clock, Unix ms);
    /// absent if never.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<i64>,
}

/// `PUT /v1/agent/sandboxes/state`: the proxy's heartbeat (ADR 0036 E3.3,
/// spec §13.12). A signed request, kept by the server out of the log (only
/// the last one of each proxy), and checked by each device: the proxy's
/// signature, the epoch of the proxy's last `sandbox.store_reset` in the
/// verified chain, a `seq` that never goes down within it, and its age from
/// `sent_at_ms`. It never makes a sandbox live: the chain does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxHeartbeat {
    /// [`HEARTBEAT_VERSION`].
    pub v: u32,
    /// The epoch of the proxy's store ([`SandboxStoreReset`]).
    pub store_epoch: Blob,
    /// Grows with each heartbeat of this store; kept in the store, and
    /// saved before the heartbeat is sent.
    pub seq: u64,
    /// The proxy's clock when it signed it (Unix ms): the age a device
    /// shows comes from here, never from the server.
    pub sent_at_ms: i64,
    /// Its live sandboxes, at most [`MAX_HEARTBEAT_SANDBOXES`].
    pub sandboxes: Vec<SandboxLink>,
}

impl SandboxHeartbeat {
    /// The version, the epoch's length, a `seq` from 1, a time, at most
    /// [`MAX_HEARTBEAT_SANDBOXES`] sandboxes with no repeats, and no
    /// `last_seen_at` after the heartbeat itself.
    pub fn check_format(&self) -> Result<(), String> {
        if self.v != HEARTBEAT_VERSION {
            return Err(format!(
                "heartbeat version {} is not {HEARTBEAT_VERSION}",
                self.v
            ));
        }
        if self.store_epoch.as_bytes().len() != STORE_EPOCH_LEN {
            return Err(format!("store_epoch must be {STORE_EPOCH_LEN} bytes"));
        }
        if self.seq == 0 {
            return Err("seq starts at 1".into());
        }
        if self.sent_at_ms <= 0 {
            return Err("sent_at_ms must be a time".into());
        }
        if self.sandboxes.len() > MAX_HEARTBEAT_SANDBOXES {
            return Err(format!(
                "a heartbeat names at most {MAX_HEARTBEAT_SANDBOXES} sandboxes"
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for link in &self.sandboxes {
            if !seen.insert(link.id) {
                return Err(format!("sandbox {} is named twice", link.id));
            }
            if link
                .last_seen_at
                .is_some_and(|t| t <= 0 || t > self.sent_at_ms)
            {
                return Err(format!(
                    "sandbox {}: last_seen_at must be a time no later than sent_at_ms",
                    link.id
                ));
            }
        }
        Ok(())
    }
}

/// Reads a revocation's `scope`: [`SCOPE_ALL`] or a sandbox ID.
pub fn parse_scope(scope: &str) -> Result<RevokeTarget, String> {
    if scope == SCOPE_ALL {
        return Ok(RevokeTarget::All);
    }
    scope
        .parse::<SandboxId>()
        .map(RevokeTarget::One)
        .map_err(|_| format!("scope must be {SCOPE_ALL} or a sandbox ID"))
}

/// The last heartbeat of one proxy of the account, as `GET /v1/sync`
/// gives it (ADR 0036 E3.3, spec §13.12): the proxy's signed
/// `PUT /v1/agent/sandboxes/state`, body included, for each device to check
/// against the proxy's key and the verified chain. The server only keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxState {
    /// The proxy.
    pub proxy_id: AgentId,
    /// Its signed request, with the [`SandboxHeartbeat`] as the body.
    pub proof: crate::audit::AgentProof,
    /// When the server took it (server clock, Unix ms). Not signed: the
    /// heartbeat's age comes from its `sent_at_ms`.
    pub received_at: i64,
}

/// A person's revocation as the server keeps it: the answer to
/// [`PATH_PERSON_REVOKE`] and an entry of [`PATH_REVOCATIONS`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxRevocation {
    /// The position of its `sandbox.revoke_requested` in the account's
    /// log; the cursor of [`PATH_REVOCATIONS`].
    pub seq: u64,
    /// The proxy.
    pub proxy_id: AgentId,
    /// A sandbox ID, or [`SCOPE_ALL`], as signed.
    pub scope: String,
    /// When the person revoked, Unix ms, as signed.
    pub at: i64,
    /// The account's signature.
    pub signature: Blob,
    /// The sandboxes it covers: the one, or those of an `all` (not signed
    /// by the account; the log orders them).
    pub sandbox_ids: Vec<SandboxId>,
}

/// `GET /v1/agent/sandboxes/revocations?since=`: the proxy's revocations
/// after `since`, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxRevocations {
    /// At most [`MAX_REVOCATIONS_PAGE`].
    pub revocations: Vec<SandboxRevocation>,
    /// More after the last one: ask again from its `seq`.
    pub more: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bodies of `docs/vectores/sandbox-heartbeat.json` read as the
    /// routes' requests, for the paths and methods they take.
    #[test]
    fn the_heartbeat_vectors_are_the_routes_requests() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/vectores/sandbox-heartbeat.json"
        ))
        .expect("vector file");
        let file: serde_json::Value = serde_json::from_str(&text).expect("json");
        let cases = file["cases"].as_array().expect("cases");
        let body = |i: usize| cases[i]["body"].as_str().expect("body");
        let reset: SandboxStoreReset = serde_json::from_str(body(0)).expect("reset");
        reset.check_format().expect("valid");
        assert_eq!(
            (&cases[0]["method"], &cases[0]["path"]),
            (&"POST".into(), &PATH_STORE_RESET.into())
        );
        let beat: SandboxHeartbeat = serde_json::from_str(body(1)).expect("heartbeat");
        beat.check_format().expect("valid");
        assert_eq!(beat.store_epoch, reset.store_epoch);
        assert_eq!(
            (&cases[1]["method"], &cases[1]["path"]),
            (&"PUT".into(), &PATH_SANDBOX_STATE.into())
        );
    }

    fn heartbeat(n: usize) -> SandboxHeartbeat {
        SandboxHeartbeat {
            v: HEARTBEAT_VERSION,
            store_epoch: Blob::new(vec![9; STORE_EPOCH_LEN]),
            seq: u64::MAX,
            sent_at_ms: MAX_SANDBOX_EXPIRES_AT,
            sandboxes: (0..n)
                .map(|_| SandboxLink {
                    id: SandboxId::generate(),
                    connected: false,
                    last_seen_at: Some(MAX_SANDBOX_EXPIRES_AT),
                })
                .collect(),
        }
    }

    /// The largest heartbeat fits a logged request whole, so every device
    /// can check the one the server keeps.
    #[test]
    fn the_largest_heartbeat_fits_a_logged_request() {
        let body = serde_json::to_vec(&heartbeat(MAX_HEARTBEAT_SANDBOXES)).expect("json");
        assert!(body.len() < crate::audit::MAX_PROOF_BODY, "{}", body.len());
    }

    #[test]
    fn a_heartbeat_or_reset_out_of_shape_is_refused() {
        assert!(heartbeat(MAX_HEARTBEAT_SANDBOXES).check_format().is_ok());
        let fails = |h: SandboxHeartbeat, why: &str| {
            let e = h.check_format().expect_err(why);
            assert!(e.contains(why), "{e}");
        };
        fails(heartbeat(MAX_HEARTBEAT_SANDBOXES + 1), "at most");
        let mut h = heartbeat(1);
        h.v = 2;
        fails(h, "version");
        let mut h = heartbeat(1);
        h.store_epoch = Blob::new(vec![9; 15]);
        fails(h, "16 bytes");
        let mut h = heartbeat(1);
        h.seq = 0;
        fails(h, "starts at 1");
        let mut h = heartbeat(1);
        h.sent_at_ms = 0;
        fails(h, "a time");
        let mut h = heartbeat(1);
        h.sandboxes.push(h.sandboxes[0].clone());
        fails(h, "twice");
        let mut h = heartbeat(1);
        h.sent_at_ms = 1_000;
        fails(h, "no later than");
        // Unknown fields are not a heartbeat.
        let mut v = serde_json::to_value(heartbeat(1)).expect("json");
        v["extra"] = 1.into();
        assert!(serde_json::from_value::<SandboxHeartbeat>(v).is_err());
        assert!(
            SandboxStoreReset {
                store_epoch: Blob::new(vec![1; 17])
            }
            .check_format()
            .is_err()
        );
    }

    #[test]
    fn an_all_covers_by_the_signed_time_with_the_clock_window() {
        let at = 1_800_000_000_000;
        let w = REVOKE_CLOCK_WINDOW_MS;
        assert!(all_covers(at + 1, at), "live at the signed time");
        assert!(all_covers(at, at), "expiring at the signed time");
        assert!(all_covers(at - w + 1, at), "expired within the window");
        assert!(!all_covers(at - w, at), "expired before the window");
        assert!(!all_covers(i64::MIN, 0), "no overflow");
    }

    fn issue() -> SandboxIssue {
        SandboxIssue {
            sandbox_id: SandboxId::generate(),
            issuer_id: AgentId::generate(),
            label: "chat-123".into(),
            profiles: vec!["northflank".into(), "maple".into()],
            expires_at: 1_800_000_000_000,
        }
    }

    #[test]
    fn an_issue_is_checked_before_anyone_trusts_it() {
        let proxy = AgentId::generate();
        assert!(issue().check_format(proxy).is_ok());
        for label in ["", " chat", "chat ", "a\u{202e}b", "a\nb", &"x".repeat(65)] {
            let bad = SandboxIssue {
                label: label.into(),
                ..issue()
            };
            assert!(bad.check_format(proxy).is_err(), "{label:?}");
        }
        let ok = SandboxIssue {
            label: "é".repeat(64),
            ..issue()
        };
        assert!(ok.check_format(proxy).is_ok());
        for profiles in [vec![], vec!["a".to_owned(); 2], vec!["p".to_owned(); 7]] {
            let bad = SandboxIssue {
                profiles,
                ..issue()
            };
            assert!(bad.check_format(proxy).is_err());
        }
        // The grant's profile-name rule: a name no grant can hold is
        // refused here too.
        for name in ["_klav", "Northflank", "9lives", "", "a b", &"p".repeat(33)] {
            let bad = SandboxIssue {
                profiles: vec![name.to_owned()],
                ..issue()
            };
            assert!(bad.check_format(proxy).is_err(), "{name:?}");
        }
        let own = SandboxIssue {
            issuer_id: proxy,
            ..issue()
        };
        assert!(own.check_format(proxy).is_err());
        for expires_at in [0, -1, MAX_SANDBOX_EXPIRES_AT + 1, i64::MAX] {
            let never = SandboxIssue {
                expires_at,
                ..issue()
            };
            assert!(never.check_format(proxy).is_err(), "{expires_at}");
        }
        let last = SandboxIssue {
            expires_at: MAX_SANDBOX_EXPIRES_AT,
            ..issue()
        };
        assert!(last.check_format(proxy).is_ok());
    }

    /// The bodies of `docs/vectores/sandbox-events.json` are the routes'
    /// requests, signed for the paths the routes take.
    #[test]
    fn the_vector_bodies_are_the_routes_requests() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/vectores/sandbox-events.json"
        ))
        .expect("vector file");
        let file: serde_json::Value = serde_json::from_str(&text).expect("json");
        let cases = file["cases"].as_array().expect("cases");
        let body = |i: usize| cases[i]["body"].as_str().expect("body");
        let proxy =
            AgentId::from_bytes(hex_16(cases[0]["proxy_agent_id"].as_str().expect("proxy")));
        let issued: SandboxIssue = serde_json::from_str(body(0)).expect("issue");
        issued.check_format(proxy).expect("valid");
        assert_eq!(cases[0]["path"], PATH_SANDBOXES);
        let claimed: SandboxClaimed = serde_json::from_str(body(1)).expect("claim");
        assert_eq!(
            claimed.channel_key_sha256.as_bytes().len(),
            CHANNEL_KEY_DIGEST_LEN
        );
        assert_eq!(
            cases[1]["path"],
            sandbox_path(issued.sandbox_id, SUFFIX_CLAIMED)
        );
        let revoked: SandboxRevoked = serde_json::from_str(body(2)).expect("end");
        revoked.check_format().expect("valid");
        assert_eq!(revoked.reason, SandboxEnd::Stop);
        assert_eq!(
            cases[2]["path"],
            sandbox_path(issued.sandbox_id, SUFFIX_REVOKED)
        );
    }

    fn hex_16(text: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex");
        }
        out
    }

    #[test]
    fn the_reasons_are_a_closed_set() {
        for (end, text) in [
            (SandboxEnd::Stop, "stop"),
            (SandboxEnd::Ttl, "ttl"),
            (SandboxEnd::Inactivity, "inactivity"),
            (SandboxEnd::Theft, "theft"),
            (SandboxEnd::Released, "released"),
            (SandboxEnd::IssuerRemoved, "issuer_removed"),
            (SandboxEnd::PersonLocal, "person_local"),
        ] {
            assert_eq!(end.as_str(), text);
            let body = format!(r#"{{"reason":"{text}"}}"#);
            let parsed: SandboxRevoked = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed.reason, end);
            assert_eq!(serde_json::to_string(&parsed).unwrap(), body);
        }
        for bad in [
            r#"{"reason":"Stop"}"#,
            r#"{"reason":"stop","extra":1}"#,
            r#"{"reason":"person_remote"}"#,
        ] {
            assert!(
                serde_json::from_str::<SandboxRevoked>(bad).is_err(),
                "{bad}"
            );
        }
        // `at` with `person`, and only with it.
        let person: SandboxRevoked =
            serde_json::from_str(r#"{"reason":"person","at":1800000000000}"#).unwrap();
        assert_eq!(person.reason, SandboxEnd::Person);
        assert!(person.check_format().is_ok());
        for bad in [
            r#"{"reason":"person"}"#,
            r#"{"reason":"person","at":0}"#,
            r#"{"reason":"stop","at":1}"#,
            r#"{"reason":"person_local","at":1}"#,
        ] {
            let parsed: SandboxRevoked = serde_json::from_str(bad).unwrap();
            assert!(parsed.check_format().is_err(), "{bad}");
        }
        assert_eq!(
            serde_json::to_string(&SandboxRevoked::new(SandboxEnd::Stop)).unwrap(),
            r#"{"reason":"stop"}"#
        );
        // A missing `at` is `None`, a number is `Some`, and an explicit
        // `null` does not parse (so it never reads as absent).
        let missing: SandboxRevoked = serde_json::from_str(r#"{"reason":"stop"}"#).unwrap();
        assert_eq!(missing.at, None);
        let number: SandboxRevoked = serde_json::from_str(r#"{"reason":"stop","at":1}"#).unwrap();
        assert_eq!(number.at, Some(1));
        // The array form parses (serde reads a struct from a sequence);
        // `is_json_object` tells it apart, and a float `at` does not parse.
        let array: SandboxRevoked = serde_json::from_str(r#"["person",1]"#).unwrap();
        assert_eq!((array.reason, array.at), (SandboxEnd::Person, Some(1)));
        assert!(!is_json_object(br#"["person",1]"#));
        assert!(!is_json_object(br#" ["stop"]"#));
        assert!(is_json_object(b" \n{\"reason\":\"stop\"}"));
        assert!(serde_json::from_str::<SandboxRevoked>(r#"{"reason":"stop","at":1.0}"#).is_err());
        for null in [
            r#"{"reason":"stop","at":null}"#,
            r#"{"reason":"person","at":null}"#,
        ] {
            assert!(
                serde_json::from_str::<SandboxRevoked>(null).is_err(),
                "{null}"
            );
        }
        assert!(
            serde_json::from_str::<SandboxIssue>(
                r#"{"sandbox_id":"00000000-0000-0000-0000-000000000001","issuer_id":"00000000-0000-0000-0000-000000000002","label":"x","profiles":["a"],"expires_at":1,"secret":"x"}"#
            )
            .is_err(),
            "unknown fields, a secret above all, are refused"
        );
    }
}
