//! The audit log for «Activity» and «Who used it» (ADR 0033 §8, §9): flat
//! records of what `klav-client` answers to `audit_log`, `item_activity`,
//! `audit_status` and `verify_audit`, through `klavd` on the Mac and in the
//! app's own process on the iPhone.
//!
//! The log holds no values: these records cross as plain strings. An
//! agent's reason, site and task title are its own words; the app shows
//! them as such (T136).

use klav_client::activity::{How, ItemActivity, ItemUse};
use klav_client::audit::{ChainStatus, LogFilter, LogLine, Unpinned, VerifyReport};
use klav_core::policy::Permission;

use crate::{KlavError, KlavResult};

/// Which events «Activity» shows. Every field narrows; empty lists and
/// `None` keep everything.
#[derive(Debug, Clone, Default, uniffi::Record)]
pub struct LogFilterInput {
    /// An item (its reference, or a search, resolved in `klavd`).
    pub item: Option<String>,
    /// An agent (name or ID).
    pub agent: Option<String>,
    /// A vault (name or ID).
    pub vault: Option<String>,
    /// From this time (Unix ms).
    pub since_ms: Option<i64>,
    /// Until this time (Unix ms).
    pub until_ms: Option<i64>,
    /// Only events with alerts.
    pub alerts: bool,
    /// Only these permissions (`fill`, `inject`, `totp`, `reveal`…).
    pub permissions: Vec<String>,
    /// Only these outcomes: `allow`, `ask`, `deny`, `approve`.
    pub outcomes: Vec<String>,
    /// Only events whose item, agent, reason or site contain this text.
    pub text: Option<String>,
    /// At most this many events, newest first.
    pub limit: Option<u32>,
}

/// One event of the log, as `klav log --json` has it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct LogEntryInfo {
    /// Position in the chain.
    pub seq: u64,
    /// When (Unix ms).
    pub at_ms: i64,
    /// `you`, or the agent's name. Tell them apart by `by_agent`, never by
    /// this text: an agent may be called `you`.
    pub actor: String,
    /// An agent wrote the event, not the person: its use of an item, its
    /// registration. The person's decisions about an agent (a pause, an
    /// approval) carry `agent_id` too, with `by_agent` false.
    pub by_agent: bool,
    /// The agent involved.
    pub agent_id: Option<String>,
    /// What happened (`agent.access`, `approval.decided`…).
    pub action: String,
    /// The permission used.
    pub permission: Option<String>,
    /// The policy's outcome or the person's decision.
    pub outcome: Option<String>,
    /// The item's reference with its title (`klav://…`), when this device
    /// knows it.
    pub item: Option<String>,
    /// The item's ID.
    pub item_id: Option<String>,
    /// The vault's name, when known.
    pub vault: Option<String>,
    /// The agent's reason, in its words.
    pub reason: Option<String>,
    /// The site the agent claimed.
    pub domain: Option<String>,
    /// The task the event belongs to.
    pub task_id: Option<String>,
    /// The approval used or decided.
    pub approval_id: Option<String>,
    /// In `agents.paused`: when the pause ends by itself (Unix ms).
    pub until_ms: Option<i64>,
    /// Attachments delivered with the event.
    pub attachments: u32,
    /// Alerts (`first_use`, `burst`, `denied`…).
    pub alerts: Vec<String>,
    /// At or before the last event this device verified.
    pub verified: bool,
}

/// How an agent's use went, for the app to say in words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum UseHow {
    /// «Allowed by your policy».
    Policy,
    /// «Approved once».
    ApprovedOnce,
    /// «Approved for 15 min» (`lease_until_ms - approved_at_ms`).
    ApprovedFor,
    /// «Inside the task “…”».
    Task,
    /// «Asked you».
    Asked,
    /// «Denied».
    Denied,
    /// An action of a later version.
    Other,
}

/// One agent event about an item («Who used it»).
#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemUseInfo {
    /// The event.
    pub entry: LogEntryInfo,
    /// How it went.
    pub how: UseHow,
    /// With `ApprovedFor`: when the approval ran out (Unix ms).
    pub lease_until_ms: Option<i64>,
    /// With an approval: when the person decided it (Unix ms).
    pub approved_at_ms: Option<i64>,
    /// With `Task`: the task's title, in the agent's words.
    pub task: Option<String>,
}

/// «Who used it» for one item.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemActivityInfo {
    /// The item's ID.
    pub item_id: String,
    /// Its reference on this device, if this device has it.
    pub reference: Option<String>,
    /// In the trash.
    pub trashed: bool,
    /// Not on this device any more: shown as «(deleted)».
    pub deleted: bool,
    /// The agents' events about it, newest first.
    pub uses: Vec<ItemUseInfo>,
}

/// How much of the log this device has downloaded and verified.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AuditStatusInfo {
    /// The last event downloaded (0: none yet).
    pub events: u64,
    /// The last event verified, if any.
    pub verified: Option<u64>,
    /// Downloaded events after the last verified one («not verified yet»).
    pub unverified: u64,
}

/// What «Verify» checked (`klav log verify`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct VerifyInfo {
    /// Events in the chain.
    pub events: u64,
    /// Agent signatures checked.
    pub agent_signatures: u64,
    /// Account signatures checked.
    pub account_signatures: u64,
    /// Heads signed by devices that matched.
    pub heads: u64,
    /// The head this device has signed: now, or in an earlier verification
    /// if the log has not grown since.
    pub signed_head: Option<u64>,
    /// What could not be checked, without being a sign of tampering, in
    /// `klav-client`'s words. Without the warning of `unpinned`, which the
    /// app says in its own language.
    pub warnings: Vec<String>,
    /// Why this device had no head of its own to hold the chain against
    /// (the first verification on it, most of the time).
    pub unpinned: Option<UnpinnedHead>,
}

/// Why this device had no pinned head to hold the chain against
/// (ADR 0030 §4.8): the events up to now are trusted as the server sent
/// them, checked only against heads signed by other devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum UnpinnedHead {
    /// None yet: the first verification on this device.
    Missing,
    /// The pinned head could not be read.
    Unreadable,
    /// The pinned head belongs to another account.
    OtherAccount,
}

/// The input as the protocol's filter. An unknown permission is an error,
/// not a filter that keeps nothing.
pub(crate) fn log_filter(input: LogFilterInput) -> KlavResult<LogFilter> {
    let permissions = input
        .permissions
        .iter()
        .map(|p| {
            serde_json::from_value::<Permission>(serde_json::Value::String(p.trim().to_lowercase()))
                .map_err(|_| KlavError::invalid(format!("unknown permission {p:?}")))
        })
        .collect::<KlavResult<Vec<_>>>()?;
    Ok(LogFilter {
        item: input.item,
        agent: input.agent,
        vault: input.vault,
        since: input.since_ms,
        until: input.until_ms,
        alerts: input.alerts,
        task: None,
        permissions,
        outcomes: input.outcomes,
        text: input.text,
        // `klavd` stops there; the caller cuts again for an older one.
        limit: input
            .limit
            .map(|l| usize::try_from(l).unwrap_or(usize::MAX)),
    })
}

pub(crate) fn log_entry(l: LogLine) -> LogEntryInfo {
    LogEntryInfo {
        seq: l.seq,
        at_ms: l.at,
        actor: l.actor,
        by_agent: l.by_agent,
        agent_id: l.agent_id.map(|a| a.to_string()),
        action: l.action,
        permission: l.permission,
        outcome: l.outcome,
        item: l.item,
        item_id: l.item_id.map(|i| i.to_string()),
        vault: l.vault,
        reason: l.reason,
        domain: l.domain,
        task_id: l.task_id.map(|t| t.to_string()),
        approval_id: l.approval_id.map(|a| a.to_string()),
        until_ms: l.until,
        attachments: u32::try_from(l.attachments.len()).unwrap_or(u32::MAX),
        alerts: l.alerts,
        verified: l.verified,
    }
}

fn use_how(how: How) -> UseHow {
    match how {
        How::Policy => UseHow::Policy,
        How::ApprovedOnce => UseHow::ApprovedOnce,
        How::ApprovedFor => UseHow::ApprovedFor,
        How::Task => UseHow::Task,
        How::Asked => UseHow::Asked,
        How::Denied => UseHow::Denied,
        How::Other => UseHow::Other,
    }
}

fn item_use(u: ItemUse) -> ItemUseInfo {
    ItemUseInfo {
        entry: log_entry(u.line),
        how: use_how(u.how),
        lease_until_ms: u.lease_until,
        approved_at_ms: u.approved_at,
        task: u.task,
    }
}

pub(crate) fn item_activity_info(a: ItemActivity) -> ItemActivityInfo {
    ItemActivityInfo {
        item_id: a.item_id.to_string(),
        reference: a.reference,
        trashed: a.trashed,
        deleted: a.deleted,
        uses: a.uses.into_iter().map(item_use).collect(),
    }
}

pub(crate) fn audit_status_info(s: &ChainStatus) -> AuditStatusInfo {
    AuditStatusInfo {
        events: s.events,
        verified: s.verified,
        unverified: s.unverified(),
    }
}

/// The report for the apps. The warning of `unpinned` leaves `warnings`:
/// the app says it from the code, in the person's language. A `klavd`
/// older than `unpinned` sends none, and its warning stays as text.
pub(crate) fn verify_info(r: VerifyReport) -> VerifyInfo {
    let said = r.unpinned.map(Unpinned::warning);
    VerifyInfo {
        events: r.events,
        agent_signatures: r.agent_signatures,
        account_signatures: r.account_signatures,
        heads: r.heads,
        signed_head: r.signed_head,
        warnings: r
            .warnings
            .into_iter()
            .filter(|w| Some(w) != said.as_ref())
            .collect(),
        unpinned: r.unpinned.map(|u| match u {
            Unpinned::Missing => UnpinnedHead::Missing,
            Unpinned::Unreadable => UnpinnedHead::Unreadable,
            Unpinned::OtherAccount => UnpinnedHead::OtherAccount,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(actor: &str, by_agent: bool) -> LogLine {
        LogLine {
            seq: 7,
            at: 1_000,
            actor: actor.into(),
            by_agent,
            agent_id: Some(klav_core::ids::AgentId::generate()),
            agent_name: None,
            action: "agents.paused".into(),
            permission: None,
            outcome: None,
            item: None,
            item_id: None,
            vault: None,
            reason: None,
            domain: None,
            attachments: Vec::new(),
            task_id: None,
            approval_id: None,
            until: None,
            alerts: Vec::new(),
            verified: false,
        }
    }

    #[test]
    fn who_wrote_an_event_crosses_apart_from_the_actor_text() {
        // The person paused an agent: the agent is named, the person wrote it.
        let person = log_entry(line("you", false));
        assert!(!person.by_agent && person.agent_id.is_some());
        // An agent the person called «you» is still an agent.
        let agent = log_entry(line("you", true));
        assert!(agent.by_agent);
        assert_eq!(agent.actor, "you");
    }

    #[test]
    fn the_unpinned_warning_crosses_as_a_code_not_as_english() {
        let report = VerifyReport {
            events: 3,
            warnings: vec![
                "agent 0192 is no longer listed".into(),
                Unpinned::Unreadable.warning(),
            ],
            unpinned: Some(Unpinned::Unreadable),
            ..VerifyReport::default()
        };
        let info = verify_info(report);
        assert_eq!(info.unpinned, Some(UnpinnedHead::Unreadable));
        assert_eq!(info.warnings, vec!["agent 0192 is no longer listed"]);
        // A klavd older than `unpinned`: its warning stays, as text.
        let older = verify_info(VerifyReport {
            warnings: vec![Unpinned::Missing.warning()],
            ..VerifyReport::default()
        });
        assert_eq!(older.unpinned, None);
        assert_eq!(older.warnings, vec![Unpinned::Missing.warning()]);
    }

    #[test]
    fn an_unknown_permission_is_refused_rather_than_keeping_nothing() {
        let ok = log_filter(LogFilterInput {
            permissions: vec!["Fill".into(), " reveal ".into()],
            ..LogFilterInput::default()
        })
        .unwrap();
        assert_eq!(ok.permissions, vec![Permission::Fill, Permission::Reveal]);
        let err = log_filter(LogFilterInput {
            permissions: vec!["peek".into()],
            ..LogFilterInput::default()
        })
        .unwrap_err();
        assert!(matches!(err, KlavError::Invalid { .. }));
    }
}
