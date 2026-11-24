//! «Pause agents» (ADR 0033 §7) as both apps see it: the pauses in effect
//! and every agent with its own. The Mac reads them from `klavd`
//! (`DaemonEngine`); the iPhone from its own sync (`KlavCore`, §9).
//!
//! A pause holds no secret. Pausing asks for nothing; resuming asks for
//! presence, which each app checks before calling.

use std::collections::{BTreeMap, BTreeSet};

use klav_client::agents::{AgentView, GrantView};
use klav_core::ids::AgentId;
use klav_core::policy::Permission;
use klav_proto::agent::{AgentPause, PauseScope};

use crate::types::AgentItem;
use crate::{KlavError, KlavResult, agent_item};

/// What role an agent holds, derived exclusively from the account-signed
/// grants (never from the agent's self-chosen name).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AgentRole {
    /// A credential proxy (`klav-proxy`) holding per-item proxy profiles or
    /// sandbox issuers (ADR 0036).
    Proxy,
    /// A sandbox issuer authorized to start sandboxes at a proxy (ADR 0036).
    SandboxIssuer,
    /// Any other agent (MCP client, CLI, SDK, custom automation).
    Standard,
}

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
/// the `AgentItem` the request cards use, its verified grant role, its last
/// use and its pause.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DevAgentInfo {
    /// The agent.
    pub agent: AgentItem,
    /// Verified role from the signed grant (`Proxy`, `SandboxIssuer`, `Standard`).
    pub role: AgentRole,
    /// For a `Proxy`: sorted profile names in its signed grant (e.g. `["northflank"]`).
    pub proxy_profiles: Vec<String>,
    /// Host extracted from a signed proxy URL (`tls://host:port`): on an issuer
    /// from its `sandbox.proxy.url`, and on a proxy cross-referenced from its
    /// issuers' signed grants (e.g. `pve-home` or `pve-home.ts.net`).
    pub proxy_host: Option<String>,
    /// On a `SandboxIssuer`: the name of the proxy agent it points to.
    pub target_proxy_name: Option<String>,
    /// On a `Proxy`: how many sandbox issuers are listed in its grant.
    pub issuer_count: u32,
    /// Number of per-item grants held by this agent.
    pub item_count: u32,
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

/// Extracts the host from a proxy channel URL like `tls://pve-home:9443` or
/// `tls://[::1]:9443`.
pub(crate) fn host_from_proxy_url(url: &str) -> Option<String> {
    let trimmed = url.trim();
    let after_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let authority = after_scheme.split('/').next().unwrap_or("");
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    if host_port.is_empty() {
        return None;
    }
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split(']').next()?
    } else {
        host_port.split(':').next()?
    };
    let host = host.trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_owned())
    }
}

fn is_proxy_grant(grant: &GrantView) -> bool {
    !grant.profiles.is_empty()
        || !grant.issuers.is_empty()
        || grant
            .policy
            .rules
            .iter()
            .any(|r| r.permission == Permission::Proxy)
}

/// Pending registrations first, then newest: the order of `agents`.
pub(crate) fn dev_agents(list: Vec<AgentView>) -> Vec<DevAgentInfo> {
    let names_by_id: BTreeMap<AgentId, String> =
        list.iter().map(|a| (a.id, a.name.clone())).collect();
    // Cross-reference issuer grants so each proxy learns the host its issuers
    // reach it at (e.g. `pve-home` from `tls://pve-home:9443`).
    let mut referenced_proxies = BTreeSet::new();
    let mut host_by_proxy: BTreeMap<AgentId, String> = BTreeMap::new();
    for view in &list {
        if let Some(proxy) = view
            .grant
            .as_ref()
            .and_then(|g| g.sandbox.as_ref())
            .and_then(|s| s.proxy.as_ref())
        {
            referenced_proxies.insert(proxy.agent_id);
            if let Some(host) = host_from_proxy_url(&proxy.url) {
                host_by_proxy.entry(proxy.agent_id).or_insert(host);
            }
        }
    }

    let mut items: Vec<DevAgentInfo> = list
        .into_iter()
        .map(|view| {
            let last_seen_ms = view.last_seen_at;
            let approved_ms = view.approved_at;
            let paused = view.paused.as_ref().map(|p| AgentPauseInfo {
                everyone: p.scope == PauseScope::All,
                since_ms: p.since,
                until_ms: p.until,
            });
            let (role, proxy_profiles, proxy_host, target_proxy_name, issuer_count, item_count) =
                match view.grant.as_ref() {
                    Some(grant)
                        if is_proxy_grant(grant) || referenced_proxies.contains(&view.id) =>
                    {
                        let mut profiles: Vec<String> =
                            grant.profiles.iter().map(|p| p.name.clone()).collect();
                        profiles.sort();
                        let host = host_by_proxy.get(&view.id).cloned();
                        let issuers = u32::try_from(grant.issuers.len()).unwrap_or(u32::MAX);
                        let items_n = u32::try_from(grant.items.len()).unwrap_or(u32::MAX);
                        (AgentRole::Proxy, profiles, host, None, issuers, items_n)
                    }
                    Some(grant) if grant.sandbox.is_some() => {
                        let proxy_ref = grant.sandbox.as_ref().and_then(|s| s.proxy.as_ref());
                        let host = proxy_ref.and_then(|p| host_from_proxy_url(&p.url));
                        let target_name =
                            proxy_ref.and_then(|p| names_by_id.get(&p.agent_id).cloned());
                        let items_n = u32::try_from(grant.items.len()).unwrap_or(u32::MAX);
                        (
                            AgentRole::SandboxIssuer,
                            Vec::new(),
                            host,
                            target_name,
                            0,
                            items_n,
                        )
                    }
                    Some(grant) => {
                        let items_n = u32::try_from(grant.items.len()).unwrap_or(u32::MAX);
                        (AgentRole::Standard, Vec::new(), None, None, 0, items_n)
                    }
                    None if referenced_proxies.contains(&view.id) => (
                        AgentRole::Proxy,
                        Vec::new(),
                        host_by_proxy.get(&view.id).cloned(),
                        None,
                        0,
                        0,
                    ),
                    None => (AgentRole::Standard, Vec::new(), None, None, 0, 0),
                };

            DevAgentInfo {
                agent: agent_item(view),
                role,
                proxy_profiles,
                proxy_host,
                target_proxy_name,
                issuer_count,
                item_count,
                last_seen_ms,
                approved_ms,
                paused,
            }
        })
        .collect();
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

    #[test]
    fn host_from_proxy_url_extracts_hostname() {
        assert_eq!(
            host_from_proxy_url("tls://pve-home:9443").as_deref(),
            Some("pve-home")
        );
        assert_eq!(
            host_from_proxy_url("tls://pve-home.tail123.ts.net:9443/path").as_deref(),
            Some("pve-home.tail123.ts.net")
        );
        assert_eq!(
            host_from_proxy_url("tls://[::1]:9443").as_deref(),
            Some("::1")
        );
        assert_eq!(host_from_proxy_url("  "), None);
    }

    #[test]
    fn dev_agents_classifies_proxy_issuer_and_links_host() {
        use klav_core::ids::ItemId;
        use klav_core::policy::Policy;
        use klav_proto::agent::{
            AgentStatus, IssuerGrant, ProxyProfile, SandboxIssuer, SandboxProxy,
        };

        let proxy_id = AgentId::generate();
        let issuer_id = AgentId::generate();
        let cli_id = AgentId::generate();

        let proxy = AgentView {
            id: proxy_id,
            name: "klav-proxy".into(),
            note: None,
            status: AgentStatus::Active,
            pairing_code: "a b c d e f".into(),
            created_at: 10,
            expires_at: 20,
            approved_at: Some(15),
            revoked_at: None,
            last_seen_at: Some(30),
            grant: Some(GrantView {
                version: 2,
                issued_at: 15,
                projects: vec![],
                items: vec![],
                profiles: vec![ProxyProfile {
                    name: "northflank".into(),
                    item_id: ItemId::generate(),
                    field: None,
                    header: "authorization".into(),
                    prefix: "Bearer ".into(),
                    upstream: "https://api.northflank.com".into(),
                    rate_per_minute: None,
                }],
                policy: Policy::default(),
                v: 3,
                issuers: vec![SandboxIssuer {
                    agent_id: issuer_id,
                    public_identity: Blob::new(vec![0; 66]),
                    profiles: vec!["northflank".into()],
                    max_ttl_secs: 3600,
                    max_live: 4,
                }],
                sandbox: None,
            }),
            grant_error: None,
            paused: None,
        };

        let issuer = AgentView {
            id: issuer_id,
            name: "sandbox-issuer".into(),
            note: Some("Boat launcher".into()),
            status: AgentStatus::Active,
            pairing_code: "g h i j k l".into(),
            created_at: 12,
            expires_at: 22,
            approved_at: Some(16),
            revoked_at: None,
            last_seen_at: None,
            grant: Some(GrantView {
                version: 1,
                issued_at: 16,
                projects: vec![],
                items: vec![],
                profiles: vec![],
                policy: Policy::default(),
                v: 3,
                issuers: vec![],
                sandbox: Some(IssuerGrant {
                    proxy: Some(SandboxProxy {
                        agent_id: proxy_id,
                        public_identity: Blob::new(vec![0; 66]),
                        url: "tls://pve-home.ts.net:9443".into(),
                    }),
                }),
            }),
            grant_error: None,
            paused: None,
        };

        let cli = AgentView {
            id: cli_id,
            name: "claude-code".into(),
            note: None,
            status: AgentStatus::Active,
            pairing_code: "m n o p q r".into(),
            created_at: 14,
            expires_at: 24,
            approved_at: Some(17),
            revoked_at: None,
            last_seen_at: None,
            grant: Some(GrantView {
                version: 1,
                issued_at: 17,
                projects: vec![],
                items: vec![],
                profiles: vec![],
                policy: Policy::default(),
                v: 1,
                issuers: vec![],
                sandbox: None,
            }),
            grant_error: None,
            paused: None,
        };

        let out = dev_agents(vec![proxy, issuer, cli]);
        let p = out
            .iter()
            .find(|a| a.agent.id == proxy_id.to_string())
            .unwrap();
        assert_eq!(p.role, AgentRole::Proxy);
        assert_eq!(p.proxy_profiles, vec!["northflank"]);
        assert_eq!(p.proxy_host.as_deref(), Some("pve-home.ts.net"));
        assert_eq!(p.issuer_count, 1);

        let i = out
            .iter()
            .find(|a| a.agent.id == issuer_id.to_string())
            .unwrap();
        assert_eq!(i.role, AgentRole::SandboxIssuer);
        assert_eq!(i.target_proxy_name.as_deref(), Some("klav-proxy"));
        assert_eq!(i.proxy_host.as_deref(), Some("pve-home.ts.net"));

        let c = out
            .iter()
            .find(|a| a.agent.id == cli_id.to_string())
            .unwrap();
        assert_eq!(c.role, AgentRole::Standard);
        assert!(c.proxy_host.is_none());
    }
}
