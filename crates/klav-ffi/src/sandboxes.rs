//! The person's sandboxes (ADR 0036 E2.1, E2.3) as both apps see them: the
//! list from the verified chain with the proxy's last heartbeat, and the
//! revocation of one sandbox or of all of a proxy's. The Mac reads them
//! from `klavd` (`DaemonEngine`), the iPhone from its own client
//! (`KlavCore`); both come from `klav-client`, which verifies and signs.
//!
//! A sandbox holds no secret here. The label is the issuer's words and the
//! names are the server's: one line each, nothing hidden (T136).

use klav_client::sandbox_revoke::RevokeOutcome;
#[cfg(feature = "daemon")]
use klav_client::sandboxes::CheckedList;
use klav_client::sandboxes::{
    EndReason, ListCheck, ListRefusal, NoSigns, ProxyView, SandboxList, SandboxRow, SandboxStatus,
    SecurityFlag,
};
use klav_core::ids::SandboxId;
use klav_proto::sandbox::RevokeTarget;

use crate::{KlavError, KlavResult};

/// Longest label or name handed to the app.
const MAX_SANDBOX_TEXT: usize = 64;

/// Where a sandbox stands, from the verified chain alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SandboxStatusInfo {
    /// Issued, not claimed yet.
    Waiting,
    /// Claimed, not revoked and not expired.
    Active,
    /// The person revoked it and the server says it denies it access; the
    /// proxy has not logged its end yet, which is what proves it stopped.
    Revoking,
    /// Past its expiry, its end not logged yet. The server already denies
    /// it access.
    Expired,
    /// The proxy logged its end (`end_reason`).
    Ended,
    /// A status this build does not know (a newer `klavd`). Treat it as
    /// live: never as ended, never left out of a count of live sandboxes.
    Unknown,
}

/// Why a sandbox ended, as its proxy logged it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SandboxEndInfo {
    /// The issuer stopped it.
    Stop,
    /// It expired.
    Ttl,
    /// An hour without a connection.
    Inactivity,
    /// Someone claimed it a second time: the theft signal.
    Theft,
    /// Its forwarder let it go when it shut down.
    Released,
    /// The person removed or revoked its issuer.
    IssuerRemoved,
    /// The person revoked it.
    Person,
    /// The person revoked it through the proxy's socket on this Mac.
    PersonLocal,
    /// A reason this build does not know (a newer `klavd`); the sandbox
    /// still ended.
    Unknown,
}

/// Why no heartbeat of the proxy counts: the app says it gives no signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ProxyNoSigns {
    /// The server has none from it.
    NoHeartbeat,
    /// The verified log has no store epoch of it.
    NoEpoch,
    /// Under another epoch than the log's last one.
    OtherEpoch,
    /// Signed more than 5 minutes ahead of this device's clock.
    Ahead,
    /// A heartbeat version this app does not know (a newer proxy): no
    /// signs, never a security problem.
    Version,
    /// Older than one this device already accepted under the same epoch:
    /// the server held the latest back (a rollback). Also in `warnings`.
    Rollback,
    /// A reason this build does not know (a newer `klavd`): no signs.
    Unknown,
}

/// A security problem the list shows with its rows (only
/// `sandbox_list_flagged`): the app shows it as one, never as an ordinary
/// warning, and trusts no proxy.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SandboxSecurityInfo {
    /// An agent wrote the account's preferences, which no agent may write:
    /// no proxy is trusted until the person sets it again, which replaces
    /// them. The rows are every proxy's.
    PreferencesByAgent {
        /// The agent the server says wrote them.
        agent_id: String,
        /// What to tell the person, and what to do.
        message: String,
    },
    /// A problem this build does not know (a newer `klavd`): still a
    /// security problem; say to update Klav.
    Unknown {
        /// What to tell the person.
        message: String,
    },
}

/// Which check refused the sandbox list, so the app says it in its own
/// words, in the person's language.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SandboxCheckInfo {
    /// The account's proxy setting names an agent the server does not list
    /// among the account's agents.
    UnlistedProxy {
        /// The agent the setting names.
        agent_id: String,
    },
    /// The server sent a heartbeat of the account's proxy that the proxy
    /// did not sign, or that is not a heartbeat.
    ProxyHeartbeat {
        /// The account's proxy.
        agent_id: String,
    },
    /// The account's log did not verify.
    Log,
    /// A check this build does not know (a newer `klavd`): say it in
    /// general words, with `message` apart.
    Unknown,
}

/// The sandbox list, or the check that refused it
/// (`sandbox_list_checked`). Any other failure is an error, as with
/// `sandbox_list_flagged`.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum SandboxListCheckedInfo {
    /// Every check passed.
    Listed {
        /// The list.
        list: SandboxListInfo,
    },
    /// A check refused it: show no list.
    Refused {
        /// Which one.
        check: SandboxCheckInfo,
        /// `klav-client`'s words, in English: for a check the app does not
        /// know, and nothing else.
        message: String,
    },
}

/// One sandbox of the account.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SandboxInfo {
    /// The sandbox.
    pub sandbox_id: String,
    /// The proxy that issued it.
    pub proxy_id: String,
    /// The issuer, as the proxy signed it.
    pub issuer_id: String,
    /// The issuer's name, as the server lists it.
    pub issuer_name: Option<String>,
    /// The issuer's label: shown "per the issuer".
    pub label: String,
    /// The profiles it may use.
    pub profiles: Vec<String>,
    /// When it was issued (Unix ms).
    pub issued_ms: i64,
    /// When it expires, as the proxy signed it (Unix ms).
    pub expires_ms: i64,
    /// When it was claimed (Unix ms).
    pub claimed_ms: Option<i64>,
    /// Where it stands.
    pub status: SandboxStatusInfo,
    /// With `Ended`: why.
    pub end_reason: Option<SandboxEndInfo>,
    /// With `Ended`: when the end was logged (Unix ms).
    pub ended_ms: Option<i64>,
    /// The signed time of the person's last revocation that covered it.
    pub revoked_by_person_ms: Option<i64>,
    /// Per the proxy's heartbeat, only for a live sandbox it names.
    pub connected: Option<bool>,
    /// Per the same heartbeat: the proxy's last word from it (proxy clock).
    pub last_seen_ms: Option<i64>,
}

/// The account's proxy, as this device sees it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SandboxProxyInfo {
    /// The proxy the account's setting names.
    pub agent_id: String,
    /// Its name, as the server lists it.
    pub name: Option<String>,
    /// A pause the account signed holds it: the app says «Paused» instead
    /// of «no signs».
    pub paused: bool,
    /// When it signed its last heartbeat that counts (proxy clock).
    pub heartbeat_sent_ms: Option<i64>,
    /// How old that heartbeat is by this device's clock (ms).
    pub heartbeat_age_ms: Option<i64>,
    /// The proxy gives no signs (10 minutes with live sandboxes, 40
    /// without, or no heartbeat that counts).
    pub quiet: bool,
    /// Why no heartbeat counts, when none does.
    pub no_signs: Option<ProxyNoSigns>,
}

/// The person's list (ADR 0036 E2.1).
#[derive(Debug, Clone, uniffi::Record)]
pub struct SandboxListInfo {
    /// The account's own proxy; none without one.
    pub proxy: Option<SandboxProxyInfo>,
    /// The sandboxes in the verified log, oldest first: those of the
    /// account's proxy, or of every proxy when asked for all of them or
    /// when the account has no proxy.
    pub sandboxes: Vec<SandboxInfo>,
    /// The list holds every sandbox up to this event of the log.
    pub verified_events: u64,
    /// What the verification could not check, without being tampering; a
    /// rollback of the heartbeat; and a marks file that could not be used.
    pub warnings: Vec<String>,
    /// This device's heartbeat watermarks could not be used (damaged, or
    /// of a newer version): the heartbeat was checked without them. Also
    /// in `warnings`.
    pub marks_unreadable: bool,
    /// A security problem shown with the rows; never in `warnings`. Only
    /// `sandbox_list_flagged` gives one: `sandbox_list` fails instead.
    pub security: Option<SandboxSecurityInfo>,
}

/// What a revocation did.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SandboxRevokeInfo {
    /// The server took it: the sandboxes it covers get no access from now
    /// on, and the list says «Revoking…» until the proxy logs their end.
    Revoked {
        /// A sandbox ID, or `all`.
        scope: String,
        /// When it was signed (Unix ms).
        at_ms: i64,
        /// The sandboxes the server says it covers. For one sandbox this
        /// device checked that it is exactly that one; for `all` it is the
        /// server's word, not checked here: the next `sandbox_list` (the
        /// verified log) shows each one it covers as `Revoking`.
        sandbox_ids: Vec<String>,
    },
    /// Not applied: the server answered that it has a revocation of the same
    /// proxy and scope signed later, too far ahead of this device's clock.
    /// That is the server's word: list again; a sandbox that revocation
    /// covers shows as `Revoking`. For `all`, sandboxes issued after it are
    /// not covered.
    NotApplied {
        /// A sandbox ID, or `all`.
        scope: String,
        /// When the later revocation was signed (Unix ms).
        later_ms: i64,
    },
}

fn text(s: &str) -> String {
    klav_core::text::shown(s, MAX_SANDBOX_TEXT)
}

fn status_info(s: SandboxStatus) -> SandboxStatusInfo {
    match s {
        SandboxStatus::Waiting => SandboxStatusInfo::Waiting,
        SandboxStatus::Active => SandboxStatusInfo::Active,
        SandboxStatus::Revoking => SandboxStatusInfo::Revoking,
        SandboxStatus::Expired => SandboxStatusInfo::Expired,
        SandboxStatus::Ended => SandboxStatusInfo::Ended,
        // A row with its proxy revoked goes through [`row_status`]; only a
        // status this build does not know gets here.
        SandboxStatus::ProxyRevoked | SandboxStatus::Unknown => SandboxStatusInfo::Unknown,
    }
}

/// A row's status for the apps at `now`. No case of this interface names
/// [`SandboxStatus::ProxyRevoked`], so such a row crosses as the status it
/// had before its proxy was revoked, the one an older `klavd` still gives
/// it: revoking if the person revoked it, else expired past its expiry,
/// else active if claimed, else waiting. Never ended, and never unknown,
/// which would ask the person to update to words no build has yet.
fn row_status(r: &SandboxRow, now: i64) -> SandboxStatusInfo {
    match r.status {
        SandboxStatus::ProxyRevoked if r.revoked_by_person_at.is_some() => {
            SandboxStatusInfo::Revoking
        }
        SandboxStatus::ProxyRevoked if r.expires_at <= now => SandboxStatusInfo::Expired,
        SandboxStatus::ProxyRevoked if r.claimed_at.is_some() => SandboxStatusInfo::Active,
        SandboxStatus::ProxyRevoked => SandboxStatusInfo::Waiting,
        s => status_info(s),
    }
}

fn end_info(e: EndReason) -> SandboxEndInfo {
    match e {
        EndReason::Stop => SandboxEndInfo::Stop,
        EndReason::Ttl => SandboxEndInfo::Ttl,
        EndReason::Inactivity => SandboxEndInfo::Inactivity,
        EndReason::Theft => SandboxEndInfo::Theft,
        EndReason::Released => SandboxEndInfo::Released,
        EndReason::IssuerRemoved => SandboxEndInfo::IssuerRemoved,
        EndReason::Person => SandboxEndInfo::Person,
        EndReason::PersonLocal => SandboxEndInfo::PersonLocal,
        EndReason::Unknown => SandboxEndInfo::Unknown,
    }
}

fn no_signs_info(n: NoSigns) -> ProxyNoSigns {
    match n {
        NoSigns::NoHeartbeat => ProxyNoSigns::NoHeartbeat,
        NoSigns::NoEpoch => ProxyNoSigns::NoEpoch,
        NoSigns::OtherEpoch => ProxyNoSigns::OtherEpoch,
        NoSigns::Ahead => ProxyNoSigns::Ahead,
        NoSigns::Version => ProxyNoSigns::Version,
        NoSigns::Rollback => ProxyNoSigns::Rollback,
        NoSigns::Unknown => ProxyNoSigns::Unknown,
    }
}

fn security_info(f: &SecurityFlag) -> SandboxSecurityInfo {
    let message = crate::grants::report_text(&f.message());
    match f {
        SecurityFlag::PreferencesByAgent { agent_id } => SandboxSecurityInfo::PreferencesByAgent {
            agent_id: agent_id.to_string(),
            message,
        },
        SecurityFlag::Unknown => SandboxSecurityInfo::Unknown { message },
    }
}

fn sandbox_info(r: SandboxRow, now: i64) -> SandboxInfo {
    SandboxInfo {
        status: row_status(&r, now),
        sandbox_id: r.sandbox_id.to_string(),
        proxy_id: r.proxy_id.to_string(),
        issuer_id: r.issuer_id.to_string(),
        issuer_name: r.issuer_name.as_deref().map(text),
        label: text(&r.label),
        profiles: r.profiles.iter().map(|p| text(p)).collect(),
        issued_ms: r.issued_at,
        expires_ms: r.expires_at,
        claimed_ms: r.claimed_at,
        end_reason: r.end_reason.map(end_info),
        ended_ms: r.ended_at,
        revoked_by_person_ms: r.revoked_by_person_at,
        connected: r.connected,
        last_seen_ms: r.last_seen_at,
    }
}

fn proxy_info(p: ProxyView) -> SandboxProxyInfo {
    SandboxProxyInfo {
        agent_id: p.agent_id.to_string(),
        name: p.name.as_deref().map(text),
        paused: p.paused,
        heartbeat_sent_ms: p.heartbeat_sent_at,
        heartbeat_age_ms: p.heartbeat_age_ms,
        quiet: p.quiet,
        no_signs: p.no_signs.map(no_signs_info),
    }
}

/// The list for the app: the account's proxy's rows, or every proxy's
/// with `all_proxies` ([`SandboxList::of_account_proxy`]).
pub(crate) fn sandbox_list_info(list: SandboxList, all_proxies: bool) -> SandboxListInfo {
    let list = if all_proxies {
        list
    } else {
        list.of_account_proxy()
    };
    SandboxListInfo {
        proxy: list.proxy.map(proxy_info),
        sandboxes: {
            let now = crate::health::now_ms();
            list.sandboxes
                .into_iter()
                .map(|r| sandbox_info(r, now))
                .collect()
        },
        verified_events: list.verified_events,
        warnings: list
            .warnings
            .iter()
            .map(|w| crate::grants::report_text(w))
            .collect(),
        marks_unreadable: list.marks_unreadable,
        security: list.security.as_ref().map(security_info),
    }
}

/// The list or its refusal, for the app.
pub(crate) fn checked_info(
    checked: Result<SandboxList, ListRefusal>,
    all_proxies: bool,
) -> SandboxListCheckedInfo {
    match checked {
        Ok(list) => SandboxListCheckedInfo::Listed {
            list: sandbox_list_info(list, all_proxies),
        },
        Err(refusal) => SandboxListCheckedInfo::Refused {
            check: match refusal.check {
                ListCheck::UnlistedProxy { agent_id } => SandboxCheckInfo::UnlistedProxy {
                    agent_id: agent_id.to_string(),
                },
                ListCheck::ProxyHeartbeat { agent_id } => SandboxCheckInfo::ProxyHeartbeat {
                    agent_id: agent_id.to_string(),
                },
                ListCheck::Log => SandboxCheckInfo::Log,
                ListCheck::Unknown => SandboxCheckInfo::Unknown,
            },
            message: crate::grants::report_text(&refusal.message),
        },
    }
}

/// `klavd`'s answer: a refusal wins over a list sent with it, and an answer
/// with neither (a newer `klavd` that says it otherwise) is a refusal, never
/// a list.
#[cfg(feature = "daemon")]
pub(crate) fn checked_answer(answer: CheckedList, all_proxies: bool) -> SandboxListCheckedInfo {
    let checked = match answer {
        CheckedList {
            refused: Some(refusal),
            ..
        } => Err(refusal),
        CheckedList {
            list: Some(list), ..
        } => Ok(list),
        CheckedList { .. } => Err(ListRefusal {
            check: ListCheck::Unknown,
            message: "klavd answered the sandbox list with neither the list nor its check".into(),
        }),
    };
    checked_info(checked, all_proxies)
}

pub(crate) fn revoke_info(outcome: RevokeOutcome) -> SandboxRevokeInfo {
    match outcome {
        RevokeOutcome::Revoked { revocation } => SandboxRevokeInfo::Revoked {
            scope: revocation.scope,
            at_ms: revocation.at,
            sandbox_ids: revocation
                .sandbox_ids
                .iter()
                .map(ToString::to_string)
                .collect(),
        },
        RevokeOutcome::NotApplied {
            scope, later_at, ..
        } => SandboxRevokeInfo::NotApplied {
            scope,
            later_ms: later_at,
        },
    }
}

/// The target of a revocation: one sandbox, or none for all.
pub(crate) fn revoke_target(sandbox_id: Option<String>) -> KlavResult<RevokeTarget> {
    match sandbox_id {
        None => Ok(RevokeTarget::All),
        Some(id) => id
            .trim()
            .parse::<SandboxId>()
            .map(RevokeTarget::One)
            .map_err(|_| KlavError::invalid("not a sandbox ID")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use klav_core::ids::AgentId;
    use klav_proto::Blob;
    use klav_proto::sandbox::SandboxRevocation;

    /// Every status, end reason and «no signs» reason crosses as its own
    /// case (a new one in `klav-client` fails to compile here), and the
    /// issuer's words are one clean line.
    #[test]
    fn a_list_crosses_with_its_cases_and_clean_text() {
        let row = SandboxRow {
            sandbox_id: SandboxId::generate(),
            proxy_id: AgentId::generate(),
            issuer_id: AgentId::generate(),
            issuer_name: Some("t3\u{202e}code".into()),
            label: "chat\n123".into(),
            profiles: vec!["railway".into()],
            issued_at: 1,
            expires_at: 2,
            claimed_at: None,
            status: SandboxStatus::Ended,
            end_reason: Some(EndReason::Theft),
            ended_at: Some(3),
            revoked_by_person_at: None,
            proxy_revoked_at: None,
            connected: None,
            last_seen_at: None,
        };
        let list = SandboxList {
            proxy: Some(ProxyView {
                agent_id: row.proxy_id,
                name: Some("proxy".into()),
                paused: true,
                heartbeat_sent_at: None,
                heartbeat_age_ms: None,
                quiet: true,
                no_signs: Some(NoSigns::Version),
            }),
            sandboxes: vec![row.clone(), other_proxys(&row)],
            verified_events: 9,
            warnings: vec!["w".into()],
            marks_unreadable: true,
            security: None,
        };
        // Every proxy's rows when asked; only the account's proxy's by
        // default.
        assert_eq!(sandbox_list_info(list.clone(), true).sandboxes.len(), 2);
        let info = sandbox_list_info(list, false);
        assert_eq!(info.sandboxes.len(), 1);
        assert_eq!(info.sandboxes[0].proxy_id, row.proxy_id.to_string());
        let proxy = info.proxy.expect("proxy");
        assert_eq!(proxy.no_signs, Some(ProxyNoSigns::Version));
        assert!(proxy.paused && proxy.quiet && info.marks_unreadable);
        let s = &info.sandboxes[0];
        assert_eq!(
            (s.status, s.end_reason, s.ended_ms),
            (
                SandboxStatusInfo::Ended,
                Some(SandboxEndInfo::Theft),
                Some(3)
            )
        );
        assert!(!s.label.contains('\n'));
        assert!(!s.issuer_name.as_deref().unwrap_or("").contains('\u{202e}'));
        assert_eq!(info.verified_events, 9);
        for (n, want) in [
            (NoSigns::NoHeartbeat, ProxyNoSigns::NoHeartbeat),
            (NoSigns::NoEpoch, ProxyNoSigns::NoEpoch),
            (NoSigns::OtherEpoch, ProxyNoSigns::OtherEpoch),
            (NoSigns::Ahead, ProxyNoSigns::Ahead),
            (NoSigns::Version, ProxyNoSigns::Version),
            (NoSigns::Rollback, ProxyNoSigns::Rollback),
            (NoSigns::Unknown, ProxyNoSigns::Unknown),
        ] {
            assert_eq!(no_signs_info(n), want);
        }
        for (s, want) in [
            (SandboxStatus::Waiting, SandboxStatusInfo::Waiting),
            (SandboxStatus::Active, SandboxStatusInfo::Active),
            (SandboxStatus::Revoking, SandboxStatusInfo::Revoking),
            (SandboxStatus::Expired, SandboxStatusInfo::Expired),
            (SandboxStatus::Ended, SandboxStatusInfo::Ended),
            (SandboxStatus::Unknown, SandboxStatusInfo::Unknown),
        ] {
            assert_eq!(status_info(s), want);
        }
    }

    /// A row whose proxy was revoked crosses as the status it had before,
    /// as an older `klavd` gives it: revoking when the person revoked it
    /// (expired or not), else expired from its expiry on, else active if
    /// claimed, else waiting; never ended or unknown.
    #[test]
    fn a_revoked_proxys_row_crosses_as_its_status_before() {
        let row = |revoked: bool, claimed: bool| SandboxRow {
            sandbox_id: SandboxId::generate(),
            proxy_id: AgentId::generate(),
            issuer_id: AgentId::generate(),
            issuer_name: None,
            label: "chat".into(),
            profiles: vec![],
            issued_at: 1,
            expires_at: 100,
            claimed_at: claimed.then_some(2),
            status: SandboxStatus::ProxyRevoked,
            end_reason: None,
            ended_at: None,
            revoked_by_person_at: revoked.then_some(3),
            proxy_revoked_at: Some(4),
            connected: None,
            last_seen_at: None,
        };
        for (r, now, want) in [
            (row(true, true), 50, SandboxStatusInfo::Revoking),
            (row(true, false), 150, SandboxStatusInfo::Revoking),
            (row(false, true), 100, SandboxStatusInfo::Expired),
            (row(false, false), 150, SandboxStatusInfo::Expired),
            (row(false, true), 99, SandboxStatusInfo::Active),
            (row(false, false), 99, SandboxStatusInfo::Waiting),
        ] {
            assert_eq!(sandbox_info(r, now).status, want);
        }
    }

    /// A list from a newer `klavd`, with a status, an end reason and a «no
    /// signs» reason this build does not know, crosses with `Unknown` in
    /// each, and the row stays in the default view of the proxy's rows.
    #[test]
    fn a_list_with_what_this_build_does_not_know_crosses_as_unknown() {
        let proxy = AgentId::generate();
        let json = serde_json::json!({
            "proxy": {
                "agent_id": proxy, "paused": false, "quiet": true, "no_signs": "asleep",
            },
            "sandboxes": [{
                "sandbox_id": SandboxId::generate(), "proxy_id": proxy,
                "issuer_id": AgentId::generate(), "label": "chat", "profiles": [],
                "issued_at": 1, "expires_at": 2, "status": "parked",
                "end_reason": "recycled",
            }],
            "verified_events": 3,
        });
        let list: SandboxList = serde_json::from_value(json).expect("a newer klavd's list");
        let info = sandbox_list_info(list, false);
        assert_eq!(info.sandboxes.len(), 1);
        let s = &info.sandboxes[0];
        assert_eq!(
            (s.status, s.end_reason),
            (SandboxStatusInfo::Unknown, Some(SandboxEndInfo::Unknown))
        );
        assert_eq!(
            info.proxy.expect("proxy").no_signs,
            Some(ProxyNoSigns::Unknown)
        );
    }

    /// The flag crosses as its own case, apart from the warnings, with
    /// the agent; one this build does not know, even with fields beside
    /// its kind, crosses as `Unknown`, which the app shows as a security
    /// problem too.
    #[test]
    fn a_security_flag_crosses_as_its_case_and_an_unknown_one_as_unknown() {
        let agent = AgentId::generate();
        // Rows of two proxies, as the chain verified them: with the flag
        // there is no proxy, so the default view keeps both, each with its
        // status.
        let revoking = SandboxRow {
            sandbox_id: SandboxId::generate(),
            proxy_id: AgentId::generate(),
            issuer_id: AgentId::generate(),
            issuer_name: None,
            label: "chat".into(),
            profiles: vec!["railway".into()],
            issued_at: 1,
            expires_at: 9,
            claimed_at: Some(2),
            status: SandboxStatus::Revoking,
            end_reason: None,
            ended_at: None,
            revoked_by_person_at: Some(5),
            proxy_revoked_at: None,
            connected: None,
            last_seen_at: None,
        };
        let active = SandboxRow {
            status: SandboxStatus::Active,
            revoked_by_person_at: None,
            proxy_revoked_at: None,
            ..other_proxys(&revoking)
        };
        let rows = serde_json::to_value([&revoking, &active]).expect("rows");
        let flagged = |security: serde_json::Value| {
            let list: SandboxList = serde_json::from_value(serde_json::json!({
                "sandboxes": rows, "verified_events": 3, "warnings": ["w"],
                "security": security,
            }))
            .expect("a flagged list");
            sandbox_list_info(list, false)
        };
        let info = flagged(serde_json::json!({"kind": "preferences_by_agent", "agent_id": agent}));
        assert_eq!(info.warnings, ["w"]);
        assert!(info.proxy.is_none());
        let shown: Vec<_> = info
            .sandboxes
            .iter()
            .map(|s| (s.sandbox_id.clone(), s.status, s.revoked_by_person_ms))
            .collect();
        assert_eq!(
            shown,
            [
                (
                    revoking.sandbox_id.to_string(),
                    SandboxStatusInfo::Revoking,
                    Some(5)
                ),
                (
                    active.sandbox_id.to_string(),
                    SandboxStatusInfo::Active,
                    None
                ),
            ]
        );
        match info.security {
            Some(SandboxSecurityInfo::PreferencesByAgent { agent_id, message }) => {
                assert_eq!(agent_id, agent.to_string());
                assert!(message.contains(&agent.to_string()) && message.contains("klav proxy use"));
            }
            other => panic!("{other:?}"),
        }
        let newer =
            flagged(serde_json::json!({"kind": "keys_by_server", "agent_id": agent, "n": 1}));
        assert!(matches!(
            newer.security,
            Some(SandboxSecurityInfo::Unknown { message }) if message.contains("update klav")
        ));
    }

    /// The same sandbox under another proxy.
    fn other_proxys(row: &SandboxRow) -> SandboxRow {
        SandboxRow {
            sandbox_id: SandboxId::generate(),
            proxy_id: AgentId::generate(),
            ..row.clone()
        }
    }

    /// A revocation crosses with its scope and sandboxes; a later one of
    /// the same scope is `NotApplied`, with when it was signed.
    #[test]
    fn a_revocation_crosses_as_revoked_or_not_applied() {
        let proxy = AgentId::generate();
        let id = SandboxId::generate();
        let revoked = revoke_info(RevokeOutcome::Revoked {
            revocation: SandboxRevocation {
                seq: 4,
                proxy_id: proxy,
                scope: "all".into(),
                at: 10,
                signature: Blob::new(vec![0; 64]),
                sandbox_ids: vec![id],
            },
        });
        assert_eq!(
            revoked,
            SandboxRevokeInfo::Revoked {
                scope: "all".into(),
                at_ms: 10,
                sandbox_ids: vec![id.to_string()]
            }
        );
        let later = revoke_info(RevokeOutcome::NotApplied {
            proxy_id: proxy,
            scope: id.to_string(),
            later_at: 20,
        });
        assert_eq!(
            later,
            SandboxRevokeInfo::NotApplied {
                scope: id.to_string(),
                later_ms: 20
            }
        );
        assert!(matches!(revoke_target(None), Ok(RevokeTarget::All)));
        assert_eq!(
            revoke_target(Some(format!(" {id} "))).ok(),
            Some(RevokeTarget::One(id))
        );
        assert!(matches!(
            revoke_target(Some("nope".into())),
            Err(KlavError::Invalid { .. })
        ));
    }
}
