//! The MCP gateway in the apps (ADR 0049, layer 6): the profile a tool
//! call goes through, on the approval card and in Activity, folded session
//! rows, and the Mac's «Development › MCP servers».
//!
//! What crosses here passed `klav-client`'s checks first: a tool or a
//! local client outside its grammar never reaches the apps (the card gets
//! `security` instead, T260), and a profile's name comes from the proxy's
//! grant as this device verified it against the account identity.

use std::collections::HashMap;

use klav_client::proxy_admin::{ProxyStatus, mcp_profile_names};
use klav_core::ids::{AgentId, ItemId};

use crate::activity::{ItemUseInfo, LogEntryInfo};

/// `klav-proxy`'s port on the person's Mac unless it was started with
/// another (`klav_proxy::app::DEFAULT_PORT`): what `klav client connect`
/// writes by default.
#[cfg(feature = "daemon")]
pub(crate) const DEFAULT_PROXY_PORT: u16 = 8790;

/// The MCP profiles of the account's proxy, by item, and which agent the
/// proxy is: a profile names only what the proxy itself asked or logged.
#[derive(Debug, Default)]
pub(crate) struct McpNames {
    proxy: Option<AgentId>,
    profiles: HashMap<ItemId, String>,
}

impl McpNames {
    /// From `klav proxy status`; nothing when it could not be read (best
    /// effort: a card or a row without its profile still shows).
    pub(crate) fn from_status(status: Option<&ProxyStatus>) -> Self {
        match status {
            Some(s) => Self {
                proxy: s.agent_id,
                profiles: mcp_profile_names(s, s.agent_id),
            },
            None => Self::default(),
        }
    }

    /// The MCP profile of `item`, when `agent` is the account's proxy.
    pub(crate) fn profile(&self, agent: Option<AgentId>, item: Option<ItemId>) -> Option<String> {
        if agent.is_none() || agent != self.proxy {
            return None;
        }
        self.profiles.get(&item?).cloned()
    }
}

/// Some approval names an MCP tool: worth asking for the proxy's profiles.
pub(crate) fn approvals_need_names(list: &[klav_client::agents::ApprovalView]) -> bool {
    list.iter().any(|a| a.mcp_tool.is_some())
}

/// Some line is a proxied call: it may be an MCP one.
pub(crate) fn lines_need_names(lines: &[klav_client::audit::LogLine]) -> bool {
    lines
        .iter()
        .any(|l| l.permission.as_deref() == Some("proxy"))
}

/// Whether `b` folds into `a`, the row above it (newest first): both are
/// session messages of one MCP profile from one caller, with the same
/// outcome and verification, and `b` raised no alert (ADR 0049 §6).
fn folds(a: &LogEntryInfo, b: &LogEntryInfo) -> bool {
    a.mcp_session
        && b.mcp_session
        && b.alerts.is_empty()
        && a.agent_id == b.agent_id
        && a.item_id == b.item_id
        && a.mcp_profile == b.mcp_profile
        && a.local_client == b.local_client
        && a.sandbox_id == b.sandbox_id
        && a.outcome == b.outcome
        && a.verified == b.verified
}

/// «claude-code connected to maple» once, not once per `initialize` and
/// `tools/list`: consecutive session rows of one caller and profile fold
/// into the newest, which counts the rest in `folded`.
pub(crate) fn fold_sessions(lines: Vec<LogEntryInfo>) -> Vec<LogEntryInfo> {
    let mut out: Vec<LogEntryInfo> = Vec::with_capacity(lines.len());
    for line in lines {
        if let Some(last) = out.last_mut()
            && folds(last, &line)
        {
            last.folded = last.folded.saturating_add(1 + line.folded);
            continue;
        }
        out.push(line);
    }
    out
}

/// [`fold_sessions`] for «Who used it»: the uses must also have gone
/// through the same way.
pub(crate) fn fold_uses(uses: Vec<ItemUseInfo>) -> Vec<ItemUseInfo> {
    let mut out: Vec<ItemUseInfo> = Vec::with_capacity(uses.len());
    for u in uses {
        if let Some(last) = out.last_mut()
            && last.how == u.how
            && last.task == u.task
            && last.lease_until_ms == u.lease_until_ms
            && folds(&last.entry, &u.entry)
        {
            last.entry.folded = last.entry.folded.saturating_add(1 + u.entry.folded);
            continue;
        }
        out.push(u);
    }
    out
}

/// The account's MCP gateway as the Mac's «Development › MCP servers»
/// shows it (ADR 0049 §3, §9). Names, hosts and patterns: never a value,
/// a token or a token's digest.
#[derive(Debug, Clone, uniffi::Record)]
pub struct McpServersInfo {
    /// The account's switch: on or off, or `None` from a server older
    /// than the gateway, which can't turn it on.
    pub gateway_on: Option<bool>,
    /// While the switch is off: turning it on needs the person's word that
    /// every device and `klav-proxy` are updated, because the account has
    /// another device or a proxy of its own, or `klavd` can't tell (ADR
    /// 0049, amendment of 2026-11-27). `false` when the switch is on or
    /// the server is older than the gateway.
    pub needs_update_warning: bool,
    /// The account's own proxy, by the name the server lists; `None`
    /// without one.
    pub proxy: Option<String>,
    /// Its MCP profiles, in the grant's order.
    pub servers: Vec<McpServerInfo>,
    /// The local MCP clients its grant names (ADR 0049 §3.2).
    pub local_clients: Vec<McpLocalClientInfo>,
    /// What is wrong with the proxy setting, in `klav-client`'s words.
    pub problems: Vec<String>,
}

/// One MCP profile of the proxy (ADR 0049 §2.1).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct McpServerInfo {
    /// The profile's name (`maple`): the first segment of its local URL.
    pub profile: String,
    /// The item whose key it uses.
    pub item_id: String,
    /// That item's title (empty if this device no longer sees it).
    pub title: String,
    /// The MCP server: `https://host`, or with its port.
    pub upstream: String,
    /// The endpoint's path on it (`/mcp`).
    pub endpoint: String,
    /// What a client on this Mac connects to, at the proxy's default port.
    pub local_url: String,
    /// Tool patterns that go through (`get_*`, `query_logs`).
    pub tools_allow: Vec<String>,
    /// Tool patterns each call of which asks the person first.
    pub tools_ask: Vec<String>,
    /// Tool patterns refused and hidden. Any tool no pattern names is
    /// refused and hidden too (Q3).
    pub tools_deny: Vec<String>,
    /// The local clients that may use it (`claude-code`, `cursor`).
    pub clients: Vec<String>,
}

/// A local MCP client the proxy's grant names: never its token.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct McpLocalClientInfo {
    /// Its name (`claude-code`).
    pub name: String,
    /// The MCP profiles it may use.
    pub profiles: Vec<String>,
}

/// «Development › MCP servers» from `klav proxy status` and the switch.
#[cfg(feature = "daemon")]
pub(crate) fn mcp_servers_info(
    status: ProxyStatus,
    gateway_on: Option<bool>,
    needs_update_warning: bool,
) -> McpServersInfo {
    use klav_core::policy::Effect;
    let clients_of = |profile: &str| -> Vec<String> {
        status
            .local_clients
            .iter()
            .filter(|c| c.profiles.iter().any(|p| p == profile))
            .map(|c| c.name.clone())
            .collect()
    };
    let servers = status
        .credentials
        .iter()
        .filter_map(|c| {
            let profile = c.profile.as_ref()?;
            let mcp = profile.mcp.as_ref()?;
            let mut tools = [Vec::new(), Vec::new(), Vec::new()];
            for rule in &c.rules {
                let at = match rule.effect {
                    Effect::Allow => 0,
                    Effect::Ask => 1,
                    Effect::Deny => 2,
                };
                for pattern in &rule.mcp_tools {
                    if !tools[at].contains(pattern) {
                        tools[at].push(pattern.clone());
                    }
                }
            }
            let [tools_allow, tools_ask, tools_deny] = tools;
            Some(McpServerInfo {
                profile: profile.name.clone(),
                item_id: c.item_id.to_string(),
                title: c.title.clone(),
                upstream: profile.upstream.clone(),
                endpoint: mcp.endpoint.clone(),
                local_url: format!(
                    "http://127.0.0.1:{DEFAULT_PROXY_PORT}/{}{}",
                    profile.name, mcp.endpoint
                ),
                tools_allow,
                tools_ask,
                tools_deny,
                clients: clients_of(&profile.name),
            })
        })
        .collect();
    McpServersInfo {
        gateway_on,
        needs_update_warning: gateway_on == Some(false) && needs_update_warning,
        proxy: status.agent.as_ref().map(|a| a.name.clone()),
        servers,
        local_clients: status
            .local_clients
            .iter()
            .map(|c| McpLocalClientInfo {
                name: c.name.clone(),
                profiles: c.profiles.clone(),
            })
            .collect(),
        problems: status.problems,
    }
}

#[cfg(test)]
mod tests {
    use klav_client::agents::{ApprovalView, MCP_SECURITY_CARD};
    use klav_client::audit::LogLine;
    use klav_client::proxy_admin::{LocalClientView, ProxyCredentialView, ProxyRuleView};
    use klav_core::ids::ApprovalId;
    use klav_core::model::preferences::ProxyMode;
    use klav_core::policy::{Effect, Permission};
    use klav_proto::agent::{ApprovalStatus, McpProfile, ProxyProfile};

    use super::*;
    use crate::activity::log_entry;

    fn status(proxy: AgentId, item: ItemId) -> ProxyStatus {
        let rule = |effect, tools: &[&str]| ProxyRuleView {
            effect,
            methods: vec!["POST".into()],
            hosts: vec!["api.maple.dev".into()],
            path_prefixes: vec!["/mcp".into()],
            mcp_tools: tools.iter().map(|t| (*t).to_owned()).collect(),
        };
        ProxyStatus {
            mode: ProxyMode::Own,
            agent_id: Some(proxy),
            agent: None,
            credentials: vec![ProxyCredentialView {
                item_id: item,
                title: "Maple".into(),
                profile: Some(ProxyProfile {
                    name: "maple".into(),
                    item_id: item,
                    field: None,
                    header: "authorization".into(),
                    prefix: "Bearer ".into(),
                    upstream: "https://api.maple.dev".into(),
                    rate_per_minute: None,
                    mcp: Some(McpProfile {
                        endpoint: "/mcp".into(),
                        headers: Vec::new(),
                    }),
                }),
                rules: vec![
                    rule(Effect::Allow, &[]),
                    rule(Effect::Allow, &["query_*", "get_*"]),
                    rule(Effect::Ask, &["delete_*"]),
                    rule(Effect::Allow, &["get_*"]),
                    rule(Effect::Deny, &["create_api_key"]),
                ],
            }],
            problems: Vec::new(),
            lost: Vec::new(),
            issuers: None,
            local_clients: vec![
                LocalClientView {
                    name: "claude-code".into(),
                    profiles: vec!["maple".into()],
                },
                LocalClientView {
                    name: "cursor".into(),
                    profiles: vec!["github".into()],
                },
            ],
            hosted: None,
        }
    }

    fn approval(agent: AgentId, item: ItemId) -> ApprovalView {
        ApprovalView {
            id: ApprovalId::generate(),
            status: ApprovalStatus::Pending,
            agent_id: agent,
            agent: "klav-proxy".into(),
            permission: Permission::Proxy,
            target: "klav://Personal/General/Maple".into(),
            target_name: Some("Maple".into()),
            reason: "MCP call".into(),
            domain: Some("api.maple.dev".into()),
            created_at: 0,
            expires_at: 0,
            lease_until: None,
            task: None,
            request_digest: "d".into(),
            mcp_tool: Some("delete_service".into()),
            sandbox: None,
            local_client: Some("claude-code".into()),
            security: None,
            item_id: Some(item),
            items: Vec::new(),
            items_warning: None,
            always_asks: false,
        }
    }

    fn proxied(agent: AgentId, item: ItemId, tool: Option<&str>) -> LogLine {
        LogLine {
            seq: 1,
            at: 1_000,
            actor: "klav-proxy".into(),
            by_agent: true,
            agent_id: Some(agent),
            agent_name: None,
            action: "agent.access".into(),
            permission: Some("proxy".into()),
            outcome: Some("allow".into()),
            item: None,
            item_id: Some(item),
            vault: None,
            reason: None,
            domain: None,
            attachments: Vec::new(),
            task_id: None,
            approval_id: None,
            until: None,
            alerts: Vec::new(),
            verified: true,
            mcp_tool: tool.map(str::to_owned),
            local_client: Some("claude-code".into()),
            sandbox: None,
        }
    }

    /// ADR 0049 §5.4: the card gets the profile only for the proxy's own
    /// request; a security card crosses as a flag, with nothing of the
    /// offending field (`klav-client` already dropped it).
    #[test]
    fn an_approval_names_its_profile_only_for_the_proxy() {
        let (proxy, item) = (AgentId::generate(), ItemId::generate());
        let names = McpNames::from_status(Some(&status(proxy, item)));
        let card = crate::approval_item(approval(proxy, item), &names);
        assert_eq!(card.mcp_tool.as_deref(), Some("delete_service"));
        assert_eq!(card.mcp_profile.as_deref(), Some("maple"));
        assert_eq!(card.local_client.as_deref(), Some("claude-code"));
        assert!(!card.security);

        // Another agent naming the same item gets no profile.
        let other = crate::approval_item(approval(AgentId::generate(), item), &names);
        assert_eq!(other.mcp_profile, None);
        // Without the proxy's status, nothing is named.
        let unknown = crate::approval_item(approval(proxy, item), &McpNames::default());
        assert_eq!(unknown.mcp_profile, None);

        // A request outside the grammars: `klav-client` keeps none of the
        // MCP fields and sets its fixed text; the apps get the flag.
        let mut bad = approval(proxy, item);
        bad.mcp_tool = None;
        bad.local_client = None;
        bad.security = Some(MCP_SECURITY_CARD.into());
        let card = crate::approval_item(bad, &names);
        assert!(card.security);
        assert_eq!(
            (card.mcp_tool, card.mcp_profile, card.local_client),
            (None, None, None)
        );
    }

    /// ADR 0049 §6: a call names its tool; session messages of one caller
    /// fold into one row, and an alert or another caller breaks the fold.
    #[test]
    fn session_rows_fold_per_caller_and_profile() {
        let (proxy, item) = (AgentId::generate(), ItemId::generate());
        let names = McpNames::from_status(Some(&status(proxy, item)));
        let entry = |l: LogLine| log_entry(l, &names);
        let call = entry(proxied(proxy, item, Some("query_logs")));
        assert!(!call.mcp_session);
        assert_eq!(call.mcp_profile.as_deref(), Some("maple"));
        let session = entry(proxied(proxy, item, None));
        assert!(session.mcp_session);
        let mut alert = proxied(proxy, item, None);
        alert.alerts = vec!["burst".into()];
        let mut cursor = proxied(proxy, item, None);
        cursor.local_client = Some("cursor".into());
        let folded = fold_sessions(vec![
            call.clone(),
            session.clone(),
            session.clone(),
            session.clone(),
            entry(alert),
            entry(cursor),
            session.clone(),
        ]);
        let shape: Vec<_> = folded
            .iter()
            .map(|e| (e.mcp_session, e.folded, e.local_client.clone()))
            .collect();
        let cc = Some("claude-code".to_owned());
        assert_eq!(
            shape,
            [
                (false, 0, cc.clone()),
                (true, 2, cc.clone()),
                (true, 0, cc.clone()),
                (true, 0, Some("cursor".to_owned())),
                (true, 0, cc),
            ]
        );
        // A plain proxied request of another agent, without a local client,
        // is no MCP session.
        let mut plain = proxied(AgentId::generate(), item, None);
        plain.local_client = None;
        assert!(!entry(plain).mcp_session);
    }

    #[cfg(feature = "daemon")]
    #[test]
    fn the_servers_list_groups_patterns_by_effect_and_names_clients() {
        let (proxy, item) = (AgentId::generate(), ItemId::generate());
        let info = mcp_servers_info(status(proxy, item), Some(true), true);
        assert_eq!(info.gateway_on, Some(true));
        // On already: nothing to warn about.
        assert!(!info.needs_update_warning);
        let maple = &info.servers[0];
        assert_eq!(maple.tools_allow, ["query_*", "get_*"]);
        assert_eq!(maple.tools_ask, ["delete_*"]);
        assert_eq!(maple.tools_deny, ["create_api_key"]);
        assert_eq!(maple.clients, ["claude-code"]);
        assert_eq!(maple.local_url, "http://127.0.0.1:8790/maple/mcp");
        assert_eq!(info.local_clients.len(), 2);
    }
}
