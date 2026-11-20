//! «Pause agents» (ADR 0033 §7) as both apps see it: the pauses in effect
//! and every agent with its own. The Mac reads them from `klavd`
//! (`DaemonEngine`); the iPhone from its own sync (`KlavCore`, §9).
//!
//! A pause holds no secret. Pausing asks for nothing; resuming asks for
//! presence, which each app checks before calling.

use klav_client::agents::AgentView;
use klav_core::ids::AgentId;
use klav_proto::agent::{AgentPause, PauseScope};

use crate::types::AgentItem;
use crate::{KlavError, KlavResult, agent_item};

/// A pause of agents in effect.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PauseInfo {
    /// The agent; none: every agent.
    pub agent_id: Option<String>,
    /// When the person paused (Unix ms).
    pub since_ms: i64,
    /// When it ends by itself (Unix ms); none: until the person resumes.
    pub until_ms: Option<i64>,
    /// Only on this Mac for now: `klavd` signs and sends it as soon as it
    /// can, and meanwhile refuses only what it mediates. Never on the
    /// iPhone, which signs and sends a pause at once or fails.
    pub local: bool,
    /// With `local`: the server is older than the pauses («Paused on this
    /// Mac only: update the server»).
    pub server_unsupported: bool,
}

/// An agent for Development › Agents on the Mac and Agents on the iPhone:
/// the `AgentItem` the request cards use, its last use and its pause.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DevAgentInfo {
    /// The agent.
    pub agent: AgentItem,
    /// When the server last saw it (Unix ms).
    pub last_seen_ms: Option<i64>,
    /// When the person approved it (Unix ms).
    pub approved_ms: Option<i64>,
    /// A pause that stops it now, its own or every agent's, as the server
    /// listed it at the last sync.
    pub paused: Option<AgentPauseInfo>,
}

/// A pause as it stops one agent.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AgentPauseInfo {
    /// Every agent's pause (`true`) or this agent's own.
    pub everyone: bool,
    /// When the person paused (Unix ms).
    pub since_ms: i64,
    /// When it ends by itself (Unix ms).
    pub until_ms: Option<i64>,
}

/// A signed pause this device keeps (the iPhone's own list): never local.
pub(crate) fn signed_pause_info(p: &AgentPause) -> PauseInfo {
    PauseInfo {
        agent_id: p.agent_id.map(|a| a.to_string()),
        since_ms: p.at,
        until_ms: (p.until > 0).then_some(p.until),
        local: false,
        server_unsupported: false,
    }
}

pub(crate) fn dev_agent(view: AgentView) -> DevAgentInfo {
    let last_seen_ms = view.last_seen_at;
    let approved_ms = view.approved_at;
    let paused = view.paused.as_ref().map(|p| AgentPauseInfo {
        everyone: p.scope == PauseScope::All,
        since_ms: p.since,
        until_ms: p.until,
    });
    DevAgentInfo {
        agent: agent_item(view),
        last_seen_ms,
        approved_ms,
        paused,
    }
}

/// Pending registrations first, then newest: the order of `agents`.
pub(crate) fn dev_agents(list: Vec<AgentView>) -> Vec<DevAgentInfo> {
    let mut items: Vec<DevAgentInfo> = list.into_iter().map(dev_agent).collect();
    items.sort_by_key(|a| {
        (
            a.agent.status != "pending",
            std::cmp::Reverse(a.agent.created_at),
        )
    });
    items
}

pub(crate) fn optional_agent(id: Option<String>) -> KlavResult<Option<AgentId>> {
    id.filter(|i| !i.trim().is_empty())
        .map(|i| agent_id(&i))
        .transpose()
}

pub(crate) fn agent_id(id: &str) -> KlavResult<AgentId> {
    id.trim()
        .parse()
        .map_err(|_| KlavError::invalid("not an agent ID"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use klav_proto::Blob;

    #[test]
    fn a_signed_pause_without_an_end_has_no_until_and_is_never_local() {
        let agent = AgentId::generate();
        let pause = AgentPause {
            agent_id: Some(agent),
            at: 1_000,
            until: 0,
            signature: Blob::new(vec![0; 64]),
        };
        let info = signed_pause_info(&pause);
        assert_eq!(info.agent_id, Some(agent.to_string()));
        assert_eq!((info.since_ms, info.until_ms), (1_000, None));
        assert!(!info.local && !info.server_unsupported);
        let timed = signed_pause_info(&AgentPause {
            agent_id: None,
            until: 61_000,
            ..pause
        });
        assert_eq!((timed.agent_id, timed.until_ms), (None, Some(61_000)));
    }

    #[test]
    fn an_empty_agent_is_every_agent_and_a_bad_one_is_refused() {
        assert_eq!(optional_agent(None).unwrap(), None);
        assert_eq!(optional_agent(Some("  ".into())).unwrap(), None);
        assert!(matches!(
            optional_agent(Some("not-an-id".into())),
            Err(KlavError::Invalid { .. })
        ));
    }
}
