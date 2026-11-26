//! The person's side of the credential proxy (ADR 0036 §3, §13, §14):
//! which agent is the account's proxy (`klav proxy use`), what it holds
//! (`klav proxy status`), and granting or taking away one credential at a
//! time (`klav proxy grant|revoke`).
//!
//! Nothing here returns a value, a key or a piece of one: names, hosts,
//! the proxy's 6 words and the profiles' recipes.
//!
//! Granting and revoking are prepared first and committed after the
//! person's presence: [`Unlocked::prepare_proxy_grant`] builds the whole
//! new grant from the proxy's current one and checks it, and
//! [`Unlocked::commit_proxy_grant`] signs it only if the proxy's grant is
//! still the version it was built from. Another device's change in
//! between is never dropped.

use klav_core::ids::{AgentId, ItemId};
use klav_core::model::preferences::{ProxyMode, ProxySetting};
use klav_core::policy::{
    DomainPattern, Effect, HttpMethod, MAX_TOOL_PATTERN_LEN, MAX_TOOL_PATTERNS_PER_PROFILE,
    MAX_TOOL_PATTERNS_PER_RULE, MAX_TOOL_RULES_PER_PROFILE, PathPrefix, Permission, Policy, Rule,
    Scope, ToolPattern,
};
use klav_proto::Blob;
use klav_proto::agent::{
    AgentStatus, GRANT_PAYLOAD_VERSION_ITEMS, GRANT_PAYLOAD_VERSION_MCP, GrantPayload, GrantedItem,
    LocalClient, McpHeader, McpProfile, ProxyProfile,
};
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, ClientResult};
use crate::item_grants::{ItemGrantReport, ItemGrantRequest};
use crate::preferences::PreferencesRead;
use crate::session::{ItemLocation, Unlocked};

/// What the account loses without a proxy (ADR 0036 §13), for `status`
/// and the apps.
pub const LOST_WITHOUT_PROXY: [&str; 5] = [
    "klav sandbox: per-sandbox credentials that are not Klav keys, end when the sandbox stops and can be revoked at once",
    "using Northflank, Railway, Maple and the other presets from a sandbox without the token entering it",
    "approvals per call, and an audit entry for each call with its method, host and path",
    "the MCP gate for remote MCP servers without putting the bearer token in the client",
    "the theft signal when a sandbox is claimed twice",
];

/// What breaks on a device with a Klav older than per-item grants once the
/// account has its first one (ADR 0036 §2): `klavd` refuses that grant
/// unless the person says every device is updated.
pub const OLDER_CLIENTS: &str = "Once a credential proxy holds its first credential, devices with a Klav older than per-item grants break: their CLI and klavd can no longer list agents; the iPhone app stops loading requests, and the Mac app stops loading requests and tasks (even behind a new klavd); and revoking another agent with --rotate on them stops at the proxy's grant after the rotation, so the agents listed after it lose access. This lasts: revoking the proxy later does not end it, since the server keeps a revoked agent's grant and those devices open every agent's grant. Devices do not report their Klav version, so nothing can check this for you: update Klav on every device (apps, CLI and klavd) first";

/// What a device older than the account's preferences does once the
/// preferences item exists (ADR 0036 §3), shown before the first `use`.
pub const OLDER_CLIENTS_PREFERENCES: &str = "Devices with a Klav older than the account's preferences print that an item does not decrypt on every command, and do not know which agent is the proxy, so they would still let you give it whole projects. Update Klav on every device first";

/// What `klav proxy use` does to preferences an agent wrote, and what it
/// cannot check. Said before presence on every path: the CLI prints it
/// with the security error it gets before asking, and filters it out of
/// what comes back after; [`PreparedProxyUse::warnings`] and `klavd`'s
/// reply still carry it, for a caller that did not print it.
pub const REPLACES_AGENT_PREFERENCES: &str = "`klav proxy use` replaces them whole with the setting you choose, and uses nothing in them: the developer switch goes back to its default. Their proxy is not trusted, so this cannot check whether a former proxy still holds credentials: `klav agent list` shows your agents, and `klav agent revoke` revokes one";

/// Before presence, when an agent wrote the account's preferences.
pub(crate) fn replace_warning(agent: AgentId) -> String {
    format!(
        "An agent ({agent}) wrote the account's preferences, which no agent may write. {REPLACES_AGENT_PREFERENCES}"
    )
}

/// Most HTTP methods one credential may carry: the confirmation shows
/// each one, so what is granted is never cut.
pub const MAX_GRANT_METHODS: usize = 4;
/// Most path prefixes one credential may carry.
pub const MAX_GRANT_PATHS: usize = 3;
/// Longest path prefix, in bytes.
pub const MAX_GRANT_PATH_LEN: usize = 32;
/// Longest upstream host name, in bytes.
pub const MAX_GRANT_HOST_LEN: usize = 64;
/// Longest header name and field name, in characters: the confirmation
/// shows a header other than `authorization` and a field other than the
/// main secret in full.
pub const MAX_GRANT_HEADER_LEN: usize = 32;

/// Hosts that belong to providers that also host apps, with the
/// provider's name: a token for one of them could reach the proxy itself
/// if the proxy runs there (ADR 0036 §11, T151).
const HOSTING_PROVIDERS: [(&str, &str); 10] = [
    ("railway.app", "Railway"),
    ("railway.com", "Railway"),
    ("northflank.com", "Northflank"),
    ("fly.io", "Fly.io"),
    ("fly.dev", "Fly.io"),
    ("render.com", "Render"),
    ("heroku.com", "Heroku"),
    ("vercel.com", "Vercel"),
    ("digitalocean.com", "DigitalOcean"),
    ("koyeb.com", "Koyeb"),
];

/// The hosting provider `host` belongs to, if it is a known one.
pub fn hosting_provider(host: &str) -> Option<&'static str> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    HOSTING_PROVIDERS.iter().find_map(|(domain, name)| {
        (host == *domain || host.ends_with(&format!(".{domain}"))).then_some(*name)
    })
}

/// How a credential may be used through the proxy: its profile and the
/// rules for it. A caller with a preset (ADR 0036 §7, `klav proxy grant
/// --preset`) fills it in before it gets here: every part is explicit, and
/// the same spec makes the same profile and rules ([`credential_profile`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyCredentialSpec {
    /// Profile name: the first segment of the proxy's local URL.
    pub profile: String,
    /// Where requests go: `https://host[:port]`.
    pub upstream: String,
    /// The header the value goes in.
    pub header: String,
    /// Text before the value (`Bearer `).
    #[serde(default)]
    pub prefix: String,
    /// The field holding the value; none: the item's main secret.
    #[serde(default)]
    pub field: Option<String>,
    /// HTTP methods let through (at least one).
    pub methods: Vec<String>,
    /// Path prefixes let through (at least one; `/` for every path).
    pub path_prefixes: Vec<String>,
    /// Every call asks the person first, instead of going through.
    #[serde(default)]
    pub ask: bool,
    /// More methods, each call of which asks the person first.
    #[serde(default)]
    pub ask_methods: Vec<String>,
    /// Most calls per minute.
    #[serde(default)]
    pub rate_per_minute: Option<u32>,
    /// An MCP profile (ADR 0049 §2): its endpoint, fixed headers and tool
    /// rules. Absent for every other profile, so a spec without it is the
    /// bytes an older `klavd` takes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpSpec>,
}

/// What makes a credential an MCP profile (ADR 0049 §2.1, §5.3): the
/// upstream's MCP endpoint, its fixed headers, and which tools are
/// allowed, asked for or denied. A tool none of them names is denied and
/// hidden from `tools/list` (Q3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpSpec {
    /// The endpoint's path on the upstream (`/mcp`).
    pub endpoint: String,
    /// Fixed, non-secret headers sent on every request.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<McpHeader>,
    /// Tool patterns that go through.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools_allow: Vec<String>,
    /// Tool patterns each call of which asks the person first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools_ask: Vec<String>,
    /// Tool patterns refused (and hidden from the list).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools_deny: Vec<String>,
}

/// What a device or a proxy older than the MCP gateway does once the
/// account turns it on or the proxy holds its first MCP profile (ADR 0049
/// §9), said before presence.
pub const OLDER_CLIENTS_MCP: &str = "This is the account's first MCP profile or turns the account's MCP gateway on. Devices with a Klav older than the MCP gateway then fail to load their approvals list and report tampering in `klav log verify` as soon as an MCP tool call is approved or logged, and a klav-proxy older than it refuses the new grant and stops serving every profile until it is updated. Devices do not report their Klav version, so nothing can check this for you: update Klav on every device (apps, CLI and klavd) and klav-proxy first";

/// A rule of the proxy's grant, as the person reads it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRuleView {
    /// `allow`, `ask` or `deny`.
    pub effect: Effect,
    /// Methods (empty: any).
    pub methods: Vec<String>,
    /// Hosts.
    pub hosts: Vec<String>,
    /// Path prefixes (empty: any).
    pub path_prefixes: Vec<String>,
    /// The MCP tool patterns it names (ADR 0049 §5.3; empty: none).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp_tools: Vec<String>,
}

/// A local MCP client the proxy's grant names (ADR 0049 §3.2): never its
/// token, nor its token's digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalClientView {
    /// Its name (`claude-code`).
    pub name: String,
    /// The MCP profiles it may use.
    pub profiles: Vec<String>,
}
/// The MCP profiles of the account's proxy, by item, from its verified
/// grant (ADR 0049 §5.4, §6): what names a tool call's profile on the
/// approval card, in Activity and in the Touch ID prompt. Only for
/// `agent`, the agent that asked or logged: the proxy's profiles name
/// nothing another agent did.
pub fn mcp_profile_names(
    status: &ProxyStatus,
    agent: Option<AgentId>,
) -> std::collections::HashMap<ItemId, String> {
    if agent.is_none() || status.agent_id != agent {
        return std::collections::HashMap::new();
    }
    status
        .credentials
        .iter()
        .filter_map(|c| {
            c.profile
                .as_ref()
                .filter(|p| p.mcp.is_some())
                .map(|p| (c.item_id, p.name.clone()))
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyCredentialView {
    /// Item.
    pub item_id: ItemId,
    /// Its title (empty if this device no longer sees it).
    pub title: String,
    /// Its profile (none in a grant someone wrote by hand).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProxyProfile>,
    /// The `proxy` rules that name it.
    pub rules: Vec<ProxyRuleView>,
}

/// The proxy's agent, as the server reports it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyAgentView {
    /// Agent ID.
    pub id: AgentId,
    /// Its name.
    pub name: String,
    /// Its state.
    pub status: AgentStatus,
    /// Its 6 pairing words.
    pub pairing_code: String,
    /// Paused by the person.
    pub paused: bool,
    /// Last signed request (Unix ms, minute precision).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<i64>,
}

/// `klav proxy status`: never a value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStatus {
    /// The account's setting.
    pub mode: ProxyMode,
    /// The proxy's agent ID, with `own`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<AgentId>,
    /// The proxy's agent, if the server still has it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<ProxyAgentView>,
    /// The credentials it holds.
    pub credentials: Vec<ProxyCredentialView>,
    /// What is wrong with the setting, if anything.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub problems: Vec<String>,
    /// What the account loses without a proxy (empty with one that works).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lost: Vec<String>,
    /// The agents the proxy's grant lets start sandboxes (ADR 0036 §4),
    /// from that grant as verified against the account identity: empty
    /// when it lets none. Absent when it is not known: without a proxy of
    /// the account, when this device cannot read the proxy's grant, and
    /// from a `klavd` older than this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuers: Option<Vec<ProxyIssuerView>>,
    /// The local MCP clients the proxy's verified grant names (ADR 0049
    /// §3.2). Empty when it names none or is not known.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_clients: Vec<LocalClientView>,
    /// Klav Cloud's proxy, as this device checked it just now (ADR 0051
    /// §6.3): with `mode: "klav"` only. Absent from an older `klavd`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosted: Option<crate::hosted_proxy::HostedProxyView>,
}

/// One agent the proxy's verified grant lets start sandboxes. Its ID,
/// profiles and limits are what the account signed; its name and state
/// are the server's word, as in `klav agent ls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyIssuerView {
    /// The issuer.
    pub agent_id: AgentId,
    /// Its name, as the server lists it (absent when it no longer does).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Its state, as the server lists it (absent when it no longer does):
    /// `pending` until its own grant approves it (`klav proxy issuer add`
    /// again, with its words, finishes a change that stopped halfway).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<AgentStatus>,
    /// The proxy's profiles its sandboxes may use.
    pub profiles: Vec<String>,
    /// Longest TTL it may give a sandbox, in seconds.
    pub max_ttl_secs: u64,
    /// Most of its sandboxes alive at once.
    pub max_live: u32,
}

/// What `klav proxy grant` or `revoke` will sign, shown before presence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyChangeView {
    /// The proxy's agent.
    pub agent_id: AgentId,
    /// Its name.
    pub agent: String,
    /// It has no grant yet: the person compares its 6 words now.
    pub first: bool,
    /// Its 6 words.
    pub pairing_code: String,
    /// The grant version this change starts from (0: none).
    pub base_version: u64,
    /// The item granted or taken away.
    pub item_id: ItemId,
    /// Its title.
    pub title: String,
    /// Its vault and project, `Vault/Project` (empty if this device no
    /// longer sees it). The dialog shows it next to the title, which any
    /// caller of `klavd` can change without presence.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub place: String,
    /// The host of its first website, if it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    /// With `reissue_only`: the other agents whose grants it re-issues.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub holders: Vec<String>,
    /// Granted: the profile and rules it gets (none when taken away).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<ProxyCredentialView>,
    /// The item already had a profile, which this replaces.
    #[serde(default)]
    pub replaces: bool,
    /// Items the grant held that this device no longer sees where the
    /// grant names them (purged, or moved to another project): they drop
    /// out with their profile and rules, and get a new key if still here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dropped: Vec<ItemId>,
    /// What the person should know before confirming.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// No agent of the account holds a per-item grant yet: this one breaks
    /// devices older than them ([`OLDER_CLIENTS`]), so it needs the
    /// person's word that every device is updated.
    #[serde(default)]
    pub first_on_account: bool,
    /// The item is no longer the proxy's: this only re-issues the grants
    /// of other agents that still hold it, after an earlier key change
    /// could not re-issue them.
    #[serde(default)]
    pub reissue_only: bool,
    /// Issuers that lose a profile with this change (and, with none left,
    /// stop being issuers): their names, for the dialog. The warnings say
    /// which profile each loses. Absent from an older client: none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuers_losing: Vec<String>,
    /// Issuers that keep the profile this grant writes, under the rules it
    /// signs: their names. A re-grant under the same name keeps the
    /// issuers on it whatever its rules become, so the person is told
    /// whenever one keeps it, changed rules or not. Absent from an older
    /// client: none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuers_keeping: Vec<String>,
    /// Local MCP clients that lose a profile with this change (ADR 0049
    /// §3.2): their names. Absent from an older client: none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_clients_losing: Vec<String>,
    /// The account's MCP gateway switch is off and this grant turns it on
    /// before it signs (ADR 0049 §9). Absent from an older client: no.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub turns_mcp_gateway_on: bool,
    /// This writes an MCP profile while the switch is off or the proxy's
    /// grant is older than `v: 4`: older devices and proxies break
    /// ([`OLDER_CLIENTS_MCP`]), so it needs the person's word that every
    /// device is updated. Absent from an older client: no.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mcp_first: bool,
}

/// How the proxy's six words are checked on its first credential.
#[derive(Debug, Clone, Copy)]
pub enum PairingCheck<'a> {
    /// The words the person typed or confirmed (`--words`, or y/N in the
    /// CLI without `klavd`).
    Typed(Option<&'a str>),
    /// The caller shows [`ProxyChangeView::pairing_code`] in the presence
    /// prompt before committing (`klavd`): the person reads them there.
    InPrompt,
}

/// A grant change checked by [`Unlocked::prepare_proxy_grant`] or
/// [`Unlocked::prepare_proxy_revoke`], ready to sign. No secrets.
#[derive(Debug, Clone)]
pub struct PreparedProxyChange {
    view: ProxyChangeView,
    request: ItemGrantRequest,
    /// The profile a grant writes (none for a revoke).
    profile: Option<String>,
}

impl PreparedProxyChange {
    /// What it will sign.
    #[must_use]
    pub fn view(&self) -> &ProxyChangeView {
        &self.view
    }

    /// How many issuers keep the profile this grant writes, counted in
    /// the request it signs (not the view): what `klavd`'s dialog says.
    #[must_use]
    pub fn issuers_keeping(&self) -> usize {
        self.profile.as_ref().map_or(0, |name| {
            self.request
                .issuers
                .iter()
                .filter(|i| i.profiles.contains(name))
                .count()
        })
    }

    /// Refuses the account's first per-item grant unless the person said
    /// every device runs a Klav that knows them.
    pub fn require_updated_devices(&self, every_device_updated: bool) -> ClientResult<()> {
        if self.view.first_on_account && !every_device_updated {
            return Err(ClientError::Invalid(format!(
                "this is the account's first per-item grant. {OLDER_CLIENTS}, then run it again with --every-device-is-updated"
            )));
        }
        if self.view.mcp_first && !every_device_updated {
            return Err(ClientError::Invalid(format!(
                "{OLDER_CLIENTS_MCP}, then run it again with --every-device-is-updated"
            )));
        }
        Ok(())
    }
}

/// `klav proxy use`, checked: the setting to write and the proxy's name.
#[derive(Debug, Clone)]
pub struct PreparedProxyUse {
    setting: ProxySetting,
    /// The preferences items an agent wrote, which the commit replaces
    /// whole, using nothing in them; empty when the person wrote them all.
    replaces: Vec<ItemLocation>,
    /// The proxy's name, with `own`.
    pub agent: Option<String>,
    /// The agent that wrote the preferences this replaces, if one did:
    /// the confirmation says so.
    pub replaces_agent: Option<AgentId>,
    /// Warnings to show before presence.
    pub warnings: Vec<String>,
}

impl PreparedProxyUse {
    /// Whether `other` would write the same setting over the same items.
    #[must_use]
    pub fn same_setting(&self, other: &Self) -> bool {
        self.setting == other.setting && self.replaces == other.replaces
    }
}

/// The proxy's current grant, opened.
pub(crate) struct ProxyGrant {
    pub(crate) id: AgentId,
    pub(crate) name: String,
    pub(crate) public: klav_core::crypto::identity::PublicIdentity,
    pub(crate) pairing_code: String,
    pub(crate) payload: Option<GrantPayload>,
    /// Klav Cloud's proxy (`mode: "klav"`): no words, an attestation.
    pub(crate) hosted: bool,
}

impl Unlocked {
    /// Turns the account's MCP gateway switch on (ADR 0049 §9): the server
    /// then takes the gateway's claims and `local_client`, and
    /// `GET /v1/agent/me` advertises it to the proxy. Nothing turns it off.
    /// Only the request: the sheet that first asks the person to update
    /// every device is the client's (ADR 0049, layer 5). An older server
    /// answers `404`.
    pub async fn turn_mcp_gateway_on(
        &mut self,
    ) -> ClientResult<klav_proto::agent::McpGatewaySwitch> {
        self.send_json(
            reqwest::Method::POST,
            "/v1/account/mcp-gateway",
            &serde_json::json!({}),
        )
        .await
    }

    /// Whether the account's MCP gateway switch is on (ADR 0049 §9). An
    /// older server, which answers `404`, has no gateway: refused with a
    /// message that says so.
    pub async fn mcp_gateway_switch(&mut self) -> ClientResult<bool> {
        self.mcp_gateway_state().await?.ok_or_else(|| {
            ClientError::Invalid(
                "this Klav server is older than the MCP gateway (ADR 0049): update the server before granting an MCP profile".into(),
            )
        })
    }

    /// The account's MCP gateway switch (ADR 0049 §9): `None` from a
    /// server older than the gateway (it answers `404`), which the apps say
    /// in their own words.
    pub async fn mcp_gateway_state(&mut self) -> ClientResult<Option<bool>> {
        let res = self
            .authed(
                reqwest::Method::GET,
                "/v1/account/mcp-gateway",
                &crate::api::Body::Empty,
            )
            .await;
        match res {
            Ok(res) => {
                let switch: klav_proto::agent::McpGatewaySwitch = crate::api::json(res).await?;
                Ok(Some(switch.mcp_gateway))
            }
            Err(ClientError::Api { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The account's proxy setting, its agent and what it holds.
    pub async fn proxy_status(&mut self) -> ClientResult<ProxyStatus> {
        self.sync().await?;
        let setting = self.preferences()?.proxy();
        let mut status = ProxyStatus {
            mode: setting.mode,
            agent_id: setting.agent_id,
            agent: None,
            credentials: Vec::new(),
            problems: Vec::new(),
            lost: Vec::new(),
            issuers: None,
            local_clients: Vec::new(),
            hosted: None,
        };
        let hosted_supported = cfg!(feature = "hosted-proxy");
        match (setting.mode, setting.agent_id) {
            (ProxyMode::Klav, _) if !hosted_supported => status
                .problems
                .push(crate::hosted_proxy::UNSUPPORTED.into()),
            (ProxyMode::Klav, None) => status.problems.push(
                "the account's setting names Klav Cloud's proxy without its agent: set it up again with `klav proxy use klav`".into(),
            ),
            (ProxyMode::Own | ProxyMode::Klav, Some(id)) => {
                let agents = self.agents().await?;
                match agents.iter().find(|a| a.id == id).cloned() {
                    Some(agent) => {
                        if agent.status != AgentStatus::Active
                            && agent.status != AgentStatus::Pending
                        {
                            status.problems.push(format!(
                                "the proxy's agent {:?} is {}: set another with `klav proxy use own`",
                                agent.name,
                                agent.status.as_str()
                            ));
                        }
                        if let Some(grant) = &agent.grant {
                            if !grant.projects.is_empty() {
                                status.problems.push(format!(
                                    "the proxy's agent {:?} holds whole projects: revoke it and pair a new proxy",
                                    agent.name
                                ));
                            }
                            status.credentials = grant
                                .items
                                .iter()
                                .map(|i| {
                                    credential_view(
                                        i.item_id,
                                        i.title.clone(),
                                        &grant.profiles,
                                        &grant.policy,
                                    )
                                })
                                .collect();
                        }
                        status.issuers = match (&agent.grant, &agent.grant_error) {
                            (Some(grant), _) => Some(issuer_views(&grant.issuers, &agents)),
                            // A grant this device cannot read: not known.
                            (None, Some(_)) => None,
                            (None, None) => Some(Vec::new()),
                        };
                        status.agent = Some(ProxyAgentView {
                            id: agent.id,
                            name: agent.name,
                            status: agent.status,
                            pairing_code: agent.pairing_code,
                            paused: agent.paused.is_some(),
                            last_seen_at: agent.last_seen_at,
                        });
                    }
                    None => status.problems.push(format!(
                        "the server no longer has the proxy's agent {id}: set another with `klav proxy use own`"
                    )),
                }
            }
            _ => {}
        }
        // Klav Cloud's proxy, checked now (ADR 0051 §6.3): never a reason
        // for the status to fail.
        #[cfg(feature = "hosted-proxy")]
        if status.mode == ProxyMode::Klav {
            status.hosted = Some(self.hosted_view(status.agent_id).await);
        }
        let usable = match status.mode {
            ProxyMode::Own => true,
            ProxyMode::Klav => hosted_supported,
            ProxyMode::None => false,
        };
        if !usable || !status.problems.is_empty() {
            status.lost = LOST_WITHOUT_PROXY.iter().map(|s| (*s).to_owned()).collect();
        }
        // The local MCP clients (ADR 0049 §3.2), from the grant as verified:
        // best effort, never a reason for the status to fail.
        if status.agent.is_some()
            && let Ok(ProxyGrant {
                payload: Some(payload),
                ..
            }) = self.current_proxy().await
        {
            status.local_clients = local_client_views(&payload.local_clients);
        }
        Ok(status)
    }

    /// Checks `klav proxy use own <agent>` (`Some`) or `use none`.
    ///
    /// The new proxy must be pending or active, never revoked, and hold no
    /// whole project. A previous proxy that still holds credentials is
    /// revoked first (`klav agent revoke`): switching does not move them
    /// (ADR 0036 §3 asks for that; it comes with the apps' switch).
    ///
    /// Nothing in preferences an agent wrote is used: the commit replaces them
    /// whole with the setting chosen here, and the previous proxy is not
    /// known, so a warning says to check for one that still holds
    /// credentials.
    pub async fn prepare_proxy_use(
        &mut self,
        agent: Option<&str>,
    ) -> ClientResult<PreparedProxyUse> {
        self.sync().await?;
        let mut warnings = Vec::new();
        let (current, replaces) = match self.read_preferences()? {
            PreferencesRead::Read(p) => (Some(p.proxy()), Vec::new()),
            PreferencesRead::ByAgent(items) => (None, items),
        };
        let replaces_agent = replaces.first().map(|(_, agent)| *agent);
        if let Some(by) = replaces_agent {
            warnings.push(replace_warning(by));
        }
        if current.is_some_and(|c| c.mode == ProxyMode::None) {
            warnings.push(OLDER_CLIENTS_PREFERENCES.to_owned());
        }
        let (setting, name) = match agent {
            Some(wanted) => {
                let found = self.agent(wanted).await?;
                match found.status {
                    AgentStatus::Pending | AgentStatus::Active => {}
                    other => {
                        return Err(ClientError::Invalid(format!(
                            "agent {:?} is {}; it cannot be the credential proxy",
                            found.name,
                            other.as_str()
                        )));
                    }
                }
                if self.cache.revocations.contains_key(&found.id) {
                    return Err(ClientError::Security(format!(
                        "agent {:?} was revoked from this device; it is never the credential proxy",
                        found.name
                    )));
                }
                if found.grant.as_ref().is_some_and(|g| !g.projects.is_empty()) {
                    return Err(ClientError::Invalid(format!(
                        "agent {:?} holds the keys of whole projects; a credential proxy gets credentials one by one, so pair the proxy as a new agent (`klav-proxy init`)",
                        found.name
                    )));
                }
                (ProxySetting::own(found.id), Some(found.name))
            }
            None => (ProxySetting::NONE, None),
        };
        if let Some(old) = current
            .and_then(|c| c.agent_id)
            .filter(|old| Some(*old) != setting.agent_id)
        {
            let holding = self
                .agents()
                .await?
                .into_iter()
                .find(|a| a.id == old)
                .filter(|a| {
                    a.status == AgentStatus::Active
                        && a.grant.as_ref().is_some_and(|g| !g.items.is_empty())
                });
            if let Some(old) = holding {
                return Err(ClientError::Invalid(format!(
                    "the current proxy, {:?}, still holds credentials: revoke it first with `klav agent revoke {}` (that also changes the keys of what it held)",
                    old.name, old.id
                )));
            }
        }
        Ok(PreparedProxyUse {
            setting,
            replaces: replaces.into_iter().map(|(loc, _)| loc).collect(),
            agent: name,
            replaces_agent,
            warnings,
        })
    }

    /// Writes a setting checked by [`Self::prepare_proxy_use`].
    ///
    /// Then every issuer whose grant names another proxy is re-signed with
    /// no proxy (ADR 0036 §3): the person makes it an issuer of the new
    /// one. The setting stays written if a re-sign fails; running the same
    /// `use` again finishes them.
    pub async fn commit_proxy_use(
        &mut self,
        prepared: PreparedProxyUse,
    ) -> ClientResult<crate::issuers::IssuerResign> {
        let now = prepared.setting.agent_id;
        self.set_proxy_setting_replacing(prepared.setting, &prepared.replaces)
            .await?;
        self.resign_issuers(now).await
    }

    /// Checks `klav proxy grant <item>`: the account's proxy gets the item
    /// with `spec`'s profile and rules, added to what it holds (or
    /// replacing the item's profile and rules if it already holds it).
    ///
    /// `words` are the 6 words the person compared: needed when the proxy
    /// has no grant yet. With a grant this account signed, its key is the
    /// one the person already approved.
    pub async fn prepare_proxy_grant(
        &mut self,
        item: &str,
        spec: &ProxyCredentialSpec,
        check: PairingCheck<'_>,
    ) -> ClientResult<PreparedProxyChange> {
        let (grant, prepared) = self.build_proxy_grant(item, spec).await?;
        if let PairingCheck::Typed(words) = check {
            self.check_words(&grant, words)?;
        }
        Ok(prepared)
    }

    /// What [`Self::prepare_proxy_grant`] would sign, with every check but
    /// the words: the person compares the words this shows.
    pub async fn preview_proxy_grant(
        &mut self,
        item: &str,
        spec: &ProxyCredentialSpec,
    ) -> ClientResult<ProxyChangeView> {
        Ok(self.build_proxy_grant(item, spec).await?.1.view)
    }

    async fn build_proxy_grant(
        &mut self,
        item: &str,
        spec: &ProxyCredentialSpec,
    ) -> ClientResult<(ProxyGrant, PreparedProxyChange)> {
        let grant = self.current_proxy().await?;
        let loc = self.find_item(item)?;
        if klav_core::model::history::is_system_project(loc.vault, loc.project) {
            return Err(ClientError::Invalid(
                "items of Klav's own project cannot be granted".into(),
            ));
        }
        let summary = self.item_summary(loc)?;
        let (place, site) = place_and_site(&summary);
        let title = summary.title;
        // The proxy only knows a main secret for these two (spec §13.4):
        // anything else must name its field, or every call would fail.
        if spec.field.is_none()
            && !matches!(
                summary.kind,
                klav_core::model::item::ItemKind::Login | klav_core::model::item::ItemKind::ApiKey
            )
        {
            return Err(ClientError::Invalid(format!(
                "{title:?} is neither a login nor an API key, so it has no main secret: name the field that holds the value with --field"
            )));
        }
        let (profile, rules) = credential_profile(loc.item, spec)?;
        // Before any strip, `held_request`'s included: an item that dropped
        // out takes its profile from the issuers too, and that counts.
        let issuers_before = grant
            .payload
            .as_ref()
            .map(|p| p.issuers.clone())
            .unwrap_or_default();
        let (mut request, dropped) = self.held_request(&grant)?;
        // As for issuers: a local client keeps an MCP profile replaced
        // under the same name (ADR 0049 §3.2), so changing tool rules does
        // not cut the clients connected to it.
        let clients_before = request.local_clients.clone();
        let replaces = request.items.iter().any(|l| l.item == loc.item);
        strip_item(&mut request, loc.item);
        request.items.push(loc);
        request.profiles.push(profile.clone());
        // A profile replaced under the same name stays the issuers'.
        let losses = keep_issuers(&mut request, issuers_before);
        request.local_clients = clients_before.clone();
        keep_local_clients(&mut request);
        request.policy.rules.extend(rules);
        ensure_value_denies(&mut request.policy);
        let mut warnings = Vec::new();
        let agents = self.agents().await?;
        let issuers_losing = issuer_loss_warnings(&losses, &agents, &mut warnings);
        let local_clients_losing =
            local_client_loss_warnings(&clients_before, &request.local_clients, &mut warnings);
        // The MCP gateway (ADR 0049 §9): an MCP profile needs the server's
        // switch, which this turns on, and a `v: 4` grant, which an older
        // proxy refuses. Either is the person's word that every device and
        // the proxy are updated.
        let (turns_mcp_gateway_on, mcp_first) = if profile.mcp.is_some() {
            let on = self.mcp_gateway_switch().await?;
            let proxy_v4 = grant
                .payload
                .as_ref()
                .is_some_and(|p| p.v >= GRANT_PAYLOAD_VERSION_MCP);
            (!on, !on || !proxy_v4)
        } else {
            (false, false)
        };
        if mcp_first {
            warnings.push(OLDER_CLIENTS_MCP.to_owned());
        }
        if let Some(mcp) = &spec.mcp {
            warnings.extend(tool_warnings(mcp));
        }
        let issuers_keeping = issuers_keeping(&request, &profile.name, &agents);
        if !issuers_keeping.is_empty() {
            warnings.push(format!(
                "{} keep{} the profile {}, with the rules above: {} sandboxes use it as this grant says",
                issuers_keeping.join(", "),
                if issuers_keeping.len() == 1 { "s" } else { "" },
                profile.name,
                if issuers_keeping.len() == 1 { "its" } else { "their" },
            ));
        }
        // The account's first per-item grant breaks older devices.
        let first_on_account = !agents.iter().any(|a| {
            a.grant
                .as_ref()
                .is_some_and(|g| !g.items.is_empty() || !g.profiles.is_empty())
        });
        if first_on_account {
            warnings.push(OLDER_CLIENTS.to_owned());
        }
        let hosts = proxy_hosts(&request.policy, loc.item);
        for host in &hosts {
            if let Some(provider) = hosting_provider(host) {
                warnings.push(format!(
                    "{host} belongs to {provider}, which also hosts apps: if klav-proxy runs on {provider}, this token could reach the proxy's own service and its key (ADR 0036 §11). Run the proxy elsewhere, or use a token that cannot reach the proxy's project"
                ));
            }
        }
        // Klav Cloud's proxy has no words to compare: its attestation,
        // checked again before the grant is uploaded, proves its keys
        // (ADR 0051 §6.1 step 4).
        let first = grant.payload.is_none() && !grant.hosted;
        let view = ProxyChangeView {
            agent_id: grant.id,
            agent: grant.name.clone(),
            first,
            pairing_code: grant.pairing_code.clone(),
            base_version: grant.payload.as_ref().map_or(0, |p| p.version),
            item_id: loc.item,
            title: title.clone(),
            place,
            site,
            holders: Vec::new(),
            credential: Some(credential_view(
                loc.item,
                title,
                std::slice::from_ref(&profile),
                &request.policy,
            )),
            replaces,
            dropped,
            warnings,
            first_on_account,
            reissue_only: false,
            issuers_losing,
            issuers_keeping,
            local_clients_losing,
            turns_mcp_gateway_on,
            mcp_first,
        };
        check_candidate(&grant, &request)?;
        Ok((
            grant,
            PreparedProxyChange {
                view,
                request,
                profile: Some(profile.name),
            },
        ))
    }

    /// Checks `klav proxy revoke <item>`: the proxy loses the item, its
    /// profile and its rules, and the item gets a new key when the change
    /// is committed (ADR 0036 §18). The last item is not taken away here:
    /// that is revoking the proxy (`klav agent revoke`).
    pub async fn prepare_proxy_revoke(&mut self, item: &str) -> ClientResult<PreparedProxyChange> {
        let grant = self.current_proxy().await?;
        let Some(payload) = &grant.payload else {
            return Err(ClientError::Invalid(format!(
                "the proxy {:?} holds no credentials",
                grant.name
            )));
        };
        // By the grant's own list first: a purged item is no longer found
        // by title, but its ID still names it.
        let wanted = item.trim();
        let id = match payload
            .items
            .iter()
            .find(|i| i.item_id.to_string() == wanted)
        {
            Some(i) => i.item_id,
            None => self.find_item(wanted)?.item,
        };
        if !payload.items.iter().any(|i| i.item_id == id) {
            // Taken away before, but a re-issue of the other agents that
            // hold it may have failed then: they cannot open it until they
            // get its new key. Running the revoke again finishes that.
            let holders = self.holders_of(&[id], Some(grant.id)).await?;
            if holders.is_empty() {
                return Err(ClientError::NotFound(format!(
                    "{wanted:?} among the credentials of the proxy {:?}, and no other agent holds it",
                    grant.name
                )));
            }
            let (title, place, site) = self.item_names(id);
            return Ok(PreparedProxyChange {
                view: ProxyChangeView {
                    agent_id: grant.id,
                    agent: grant.name.clone(),
                    first: false,
                    pairing_code: grant.pairing_code.clone(),
                    base_version: payload.version,
                    item_id: id,
                    title,
                    place,
                    site,
                    holders: holders.clone(),
                    credential: None,
                    replaces: false,
                    dropped: Vec::new(),
                    warnings: vec![format!(
                        "the proxy no longer holds it; this re-issues the grants of {}, which still name it",
                        holders
                            .iter()
                            .map(|h| format!("{h:?}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )],
                    first_on_account: false,
                    reissue_only: true,
                    issuers_losing: Vec::new(),
                    issuers_keeping: Vec::new(),
                    local_clients_losing: Vec::new(),
                    turns_mcp_gateway_on: false,
                    mcp_first: false,
                },
                request: ItemGrantRequest::default(),
                profile: None,
            });
        }
        let (title, place, site) = self.item_names(id);
        // Before any strip, as for a grant.
        let issuers_before = payload.issuers.clone();
        let (mut request, dropped) = self.held_request(&grant)?;
        let clients_before = request.local_clients.clone();
        strip_item(&mut request, id);
        let losses = keep_issuers(&mut request, issuers_before);
        let mut warnings = Vec::new();
        let local_clients_losing =
            local_client_loss_warnings(&clients_before, &request.local_clients, &mut warnings);
        let issuers_losing = if losses.is_empty() {
            Vec::new()
        } else {
            let agents = self.agents().await?;
            issuer_loss_warnings(&losses, &agents, &mut warnings)
        };
        if request.items.is_empty() {
            return Err(ClientError::Invalid(format!(
                "{:?} is the last credential of the proxy {:?}: revoke the proxy with `klav agent revoke {}`, which also changes the key of what it held",
                if title.is_empty() {
                    id.to_string()
                } else {
                    title
                },
                grant.name,
                grant.id
            )));
        }
        let view = ProxyChangeView {
            agent_id: grant.id,
            agent: grant.name.clone(),
            first: false,
            pairing_code: grant.pairing_code.clone(),
            base_version: payload.version,
            item_id: id,
            title,
            place,
            site,
            holders: Vec::new(),
            credential: None,
            replaces: false,
            dropped,
            warnings,
            first_on_account: false,
            reissue_only: false,
            issuers_losing,
            issuers_keeping: Vec::new(),
            local_clients_losing,
            turns_mcp_gateway_on: false,
            mcp_first: false,
        };
        check_candidate(&grant, &request)?;
        Ok(PreparedProxyChange {
            view,
            request,
            profile: None,
        })
    }

    /// Signs a change checked by [`Self::prepare_proxy_grant`] or
    /// [`Self::prepare_proxy_revoke`], if the proxy's grant is still the
    /// version it was built from. Items it no longer holds get a new key.
    pub async fn commit_proxy_change(
        &mut self,
        prepared: PreparedProxyChange,
    ) -> ClientResult<ItemGrantReport> {
        let PreparedProxyChange { view, request, .. } = prepared;
        if view.reissue_only {
            let agent = self.agent_view(view.agent_id).await?;
            let regrants = self
                .regrant_agents(&[], &[view.item_id], Some(view.agent_id))
                .await?;
            return Ok(ItemGrantReport {
                agent,
                granted: true,
                rekeyed: Vec::new(),
                failed: regrants.failure(),
                regranted: regrants.done,
                not_regranted: regrants.failed,
                pending: Vec::new(),
                unconfirmed: Vec::new(),
                to_reissue: Vec::new(),
                gone: Vec::new(),
                reissue_only: true,
            });
        }
        // After presence and before signing: the proxy reads the switch
        // to send tool claims, and a grant signed first would serve MCP
        // profiles with tool calls refused until it is on.
        if view.turns_mcp_gateway_on {
            self.turn_mcp_gateway_on().await?;
        }
        self.grant_items_at(
            view.agent_id,
            request,
            &view.pairing_code,
            Some(view.base_version),
        )
        .await
    }

    /// The title, `Vault/Project` and site of `item`, empty if this device
    /// no longer sees it.
    fn item_names(&self, item: ItemId) -> (String, String, Option<String>) {
        match self
            .locate_item(item)
            .and_then(|loc| self.item_summary(loc).ok())
        {
            Some(summary) => {
                let (place, site) = place_and_site(&summary);
                (summary.title, place, site)
            }
            None => (String::new(), String::new(), None),
        }
    }

    /// One agent of the account, as the person sees it.
    async fn agent_view(&mut self, id: AgentId) -> ClientResult<crate::agents::AgentView> {
        self.agents()
            .await?
            .into_iter()
            .find(|a| a.id == id)
            .ok_or_else(|| ClientError::NotFound(format!("agent {id}")))
    }

    /// The account's proxy and its grant, opened (verified as this
    /// account's).
    pub(crate) async fn current_proxy(&mut self) -> ClientResult<ProxyGrant> {
        self.sync().await?;
        let setting = self.preferences()?.proxy();
        let id = match (setting.mode, setting.agent_id) {
            (ProxyMode::Own, Some(id)) => id,
            (ProxyMode::Klav, Some(id)) if cfg!(feature = "hosted-proxy") => id,
            (ProxyMode::Klav, Some(_)) => {
                return Err(ClientError::Invalid(
                    crate::hosted_proxy::UNSUPPORTED.into(),
                ));
            }
            (ProxyMode::Klav, None) => {
                return Err(ClientError::Invalid(
                    "the account's setting names Klav Cloud's proxy without its agent: set it up again with `klav proxy use klav`".into(),
                ));
            }
            _ => {
                return Err(ClientError::Invalid(
                    "the account has no credential proxy: pair one with `klav-proxy init`, then run `klav proxy use own <agent>`".into(),
                ));
            }
        };
        if self.cache.revocations.contains_key(&id) {
            return Err(ClientError::Security(format!(
                "the proxy's agent {id} was revoked from this device; set another with `klav proxy use own`"
            )));
        }
        let info = self.agent_info(id).await?;
        match info.status {
            AgentStatus::Pending | AgentStatus::Active => {}
            other => {
                return Err(ClientError::Invalid(format!(
                    "the proxy's agent {:?} is {}; set another with `klav proxy use own`",
                    info.name,
                    other.as_str()
                )));
            }
        }
        let public =
            klav_core::crypto::identity::PublicIdentity::decode(info.public_identity.as_bytes())?;
        let payload = match &info.grant {
            Some(g) => Some(self.open_grant(id, &public, g)?),
            None => None,
        };
        if payload.as_ref().is_some_and(|p| !p.projects.is_empty()) {
            return Err(ClientError::Invalid(format!(
                "the proxy's agent {:?} holds the keys of whole projects; revoke it and pair the proxy as a new agent",
                info.name
            )));
        }
        Ok(ProxyGrant {
            id,
            name: info.name,
            pairing_code: klav_core::crypto::agent::pairing_code(&public),
            public,
            payload,
            hosted: setting.mode == ProxyMode::Klav,
        })
    }

    /// The proxy's current grant as a request (items it still has, their
    /// profiles and the policy as signed), and the items left out because
    /// this device no longer sees them (purged): their profiles and rule
    /// entries go too.
    pub(crate) fn held_request(
        &self,
        grant: &ProxyGrant,
    ) -> ClientResult<(ItemGrantRequest, Vec<ItemId>)> {
        let Some(payload) = &grant.payload else {
            return Ok((ItemGrantRequest::default(), Vec::new()));
        };
        let mut request = ItemGrantRequest {
            items: Vec::new(),
            profiles: payload.profiles.clone(),
            policy: payload.policy.clone(),
            issuers: payload.issuers.clone(),
            local_clients: payload.local_clients.clone(),
        };
        let mut gone = Vec::new();
        for GrantedItem {
            vault_id,
            project_id,
            item_id,
            ..
        } in &payload.items
        {
            match self.locate_item(*item_id) {
                Some(loc) if loc.vault == *vault_id && loc.project == *project_id => {
                    request.items.push(loc);
                }
                // Moved to another project: still granted where it was
                // signed, which `reshare_item` refuses; it drops out.
                _ => gone.push(*item_id),
            }
        }
        for id in &gone {
            strip_item(&mut request, *id);
        }
        Ok((request, gone))
    }

    /// The words the person compared, when the proxy has no grant yet.
    fn check_words(&self, grant: &ProxyGrant, words: Option<&str>) -> ClientResult<()> {
        // Klav Cloud's proxy: its attestation stands for the words, and
        // `upload_grant` checks it again before anything leaves.
        if grant.payload.is_some() || grant.hosted {
            return Ok(());
        }
        match words {
            Some(w) if klav_core::crypto::agent::pairing_code_matches(&grant.public, w) => Ok(()),
            Some(_) => Err(ClientError::Security(format!(
                "the pairing words of the proxy {:?} do not match; do not grant it anything",
                grant.name
            ))),
            None => Err(ClientError::Invalid(format!(
                "the proxy {:?} has no credentials yet: compare its 6 pairing words first",
                grant.name
            ))),
        }
    }
}

/// A change to one local MCP client of the proxy's grant (ADR 0049 §3.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalClientChange {
    /// Add the client, or replace its profiles. `token_digest`: the
    /// digest of a new token, made with the proxy's ID by the caller, who
    /// keeps the token (none: keep the client's current one).
    Set {
        /// The MCP profiles it may use.
        profiles: Vec<String>,
        /// `SHA-256(tuple("klav/v1/proxy/local-client", proxy, token))`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token_digest: Option<Blob>,
    },
    /// Take the client out of the grant: its token stops working at the
    /// proxy's next grant refresh.
    Remove,
}

/// What a local client change will sign, shown before presence. Never a
/// token or a digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalClientChangeView {
    /// The proxy's agent.
    pub agent_id: AgentId,
    /// Its name.
    pub agent: String,
    /// The grant version this change starts from.
    pub base_version: u64,
    /// The client's name (`claude-code`).
    pub name: String,
    /// Its profiles before (absent: a new client).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Vec<String>>,
    /// Its profiles after (empty: removed).
    pub profiles: Vec<String>,
    /// Each of those profiles' MCP endpoint, as signed: the client's URL is
    /// `http://127.0.0.1:<port>/<profile><endpoint>`.
    pub endpoints: Vec<(String, String)>,
    /// A new token is signed: the old one, if any, stops working.
    pub new_token: bool,
    /// What the person should know before confirming.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// A local client change checked by [`Unlocked::prepare_local_client`],
/// ready to sign.
#[derive(Debug, Clone)]
pub struct PreparedLocalClientChange {
    view: LocalClientChangeView,
    request: ItemGrantRequest,
    pairing_code: String,
}

impl PreparedLocalClientChange {
    /// What it will sign.
    #[must_use]
    pub fn view(&self) -> &LocalClientChangeView {
        &self.view
    }
}

impl Unlocked {
    /// Checks a change to the local MCP client `name` of the account's
    /// proxy (ADR 0049 §3.2): every profile must be one of the grant's MCP
    /// profiles. With [`LocalClientChange::Set`] and no digest, the
    /// client's current token is kept; a new client needs one (a preview
    /// passes none and gets the same checks).
    pub async fn prepare_local_client(
        &mut self,
        name: &str,
        change: &LocalClientChange,
    ) -> ClientResult<PreparedLocalClientChange> {
        if !klav_core::policy::local_client_name_ok(name) {
            return Err(ClientError::Invalid(format!(
                "{name:?} is not a local client name: 1–32 of a-z, 0-9 and -"
            )));
        }
        let grant = self.current_proxy().await?;
        let Some(payload) = &grant.payload else {
            return Err(ClientError::Invalid(format!(
                "the proxy {:?} holds no credentials: grant it an MCP profile first (`klav proxy grant ITEM --profile NAME --mcp-url …`)",
                grant.name
            )));
        };
        let base_version = payload.version;
        let (mut request, _) = self.held_request(&grant)?;
        let before = request
            .local_clients
            .iter()
            .find(|c| c.name == name)
            .cloned();
        let mut warnings = Vec::new();
        let (profiles, new_token) = match change {
            LocalClientChange::Remove => {
                if before.is_none() {
                    return Err(ClientError::NotFound(format!(
                        "local client {name:?} in the grant of the proxy {:?}",
                        grant.name
                    )));
                }
                request.local_clients.retain(|c| c.name != name);
                (Vec::new(), false)
            }
            LocalClientChange::Set {
                profiles,
                token_digest,
            } => {
                let mut wanted: Vec<String> = Vec::new();
                for p in profiles {
                    let p = p.trim().to_owned();
                    if !wanted.contains(&p) {
                        wanted.push(p);
                    }
                }
                if wanted.is_empty() {
                    return Err(ClientError::Invalid(
                        "name the MCP profiles the client may use (--mcp maple)".into(),
                    ));
                }
                for p in &wanted {
                    if !request
                        .profiles
                        .iter()
                        .any(|q| q.name == *p && q.mcp.is_some())
                    {
                        let mcp: Vec<&str> = request
                            .profiles
                            .iter()
                            .filter(|q| q.mcp.is_some())
                            .map(|q| q.name.as_str())
                            .collect();
                        return Err(ClientError::Invalid(format!(
                            "{p:?} is not an MCP profile of the proxy {:?}{}",
                            grant.name,
                            if mcp.is_empty() {
                                ": it has none yet (`klav proxy grant ITEM --profile NAME --mcp-url …`)".to_owned()
                            } else {
                                format!(" (its MCP profiles: {})", mcp.join(", "))
                            }
                        )));
                    }
                }
                let digest = match (token_digest, &before) {
                    (Some(d), _) => d.clone(),
                    (None, Some(b)) => b.token_digest.clone(),
                    // A preview of a new client: a stand-in, for the checks.
                    (None, None) => Blob::new(vec![0u8; 32]),
                };
                let client = LocalClient {
                    name: name.to_owned(),
                    token_digest: digest,
                    profiles: wanted.clone(),
                };
                match request.local_clients.iter_mut().find(|c| c.name == name) {
                    Some(existing) => *existing = client,
                    None => request.local_clients.push(client),
                }
                let new_token = token_digest.is_some() || before.is_none();
                if new_token && before.is_some() {
                    warnings.push(format!(
                        "{name} gets a new token: the one in its configuration now stops working at the proxy's next grant refresh (30 s)"
                    ));
                }
                (wanted, new_token)
            }
        };
        let endpoints = profiles
            .iter()
            .filter_map(|p| {
                request
                    .profiles
                    .iter()
                    .find(|q| q.name == *p)
                    .and_then(|q| q.mcp.as_ref())
                    .map(|m| (p.clone(), m.endpoint.clone()))
            })
            .collect();
        check_candidate(&grant, &request)?;
        Ok(PreparedLocalClientChange {
            view: LocalClientChangeView {
                agent_id: grant.id,
                agent: grant.name.clone(),
                base_version,
                name: name.to_owned(),
                before: before.map(|b| b.profiles),
                profiles,
                endpoints,
                new_token,
                warnings,
            },
            request,
            pairing_code: grant.pairing_code,
        })
    }

    /// Signs a change checked by [`Self::prepare_local_client`], if the
    /// proxy's grant is still the version it was built from.
    pub async fn commit_local_client(
        &mut self,
        prepared: PreparedLocalClientChange,
    ) -> ClientResult<ItemGrantReport> {
        let PreparedLocalClientChange {
            view,
            request,
            pairing_code,
        } = prepared;
        self.grant_items_at(
            view.agent_id,
            request,
            &pairing_code,
            Some(view.base_version),
        )
        .await
    }
}

/// Checks the grant a change would sign, before any presence: the same
/// checks the signer makes, with a placeholder for each shared key.
fn check_candidate(grant: &ProxyGrant, request: &ItemGrantRequest) -> ClientResult<()> {
    let payload = GrantPayload {
        v: GRANT_PAYLOAD_VERSION_ITEMS,
        account_id: klav_core::ids::AccountId::generate(),
        agent_id: grant.id,
        version: grant.payload.as_ref().map_or(0, |p| p.version) + 1,
        issued_at: 0,
        policy: request.policy.clone(),
        projects: Vec::new(),
        items: request
            .items
            .iter()
            .map(|loc| GrantedItem {
                vault_id: loc.vault,
                owner_account_id: klav_core::ids::AccountId::generate(),
                project_id: loc.project,
                item_id: loc.item,
                shared_key: Blob::new(Vec::new()),
            })
            .collect(),
        profiles: request.profiles.clone(),
        issuers: request.issuers.clone(),
        sandbox: None,
        local_clients: request.local_clients.clone(),
        released: Vec::new(),
    };
    // The `v` the signer writes: 3 while issuers remain (a candidate
    // labelled 2 with issuers was refused before any re-grant of an item).
    let payload = GrantPayload {
        v: payload.version_after(GRANT_PAYLOAD_VERSION_ITEMS),
        ..payload
    };
    payload
        .policy
        .check_grantable()
        .map_err(|e| ClientError::Invalid(e.to_string()))?;
    payload.check_format().map_err(ClientError::Invalid)
}

/// The profile and the rules `spec` gives `item` in the proxy's grant,
/// exactly what [`Unlocked::prepare_proxy_grant`] signs for it. It checks
/// the upstream's form, the host (at most [`MAX_GRANT_HOST_LEN`] characters,
/// never `*` or an IP address), the header's and the field's lengths, that
/// there is at least one method and at most [`MAX_GRANT_METHODS`], and the
/// path prefixes' count and length. The payload's format, the profile's
/// name and the header's characters among it, is checked later, in
/// `check_candidate`, against the whole grant.
pub fn credential_profile(
    item: ItemId,
    spec: &ProxyCredentialSpec,
) -> ClientResult<(ProxyProfile, Vec<Rule>)> {
    let profile = ProxyProfile {
        name: spec.profile.clone(),
        item_id: item,
        field: spec.field.clone(),
        header: spec.header.trim().to_ascii_lowercase(),
        prefix: spec.prefix.clone(),
        upstream: spec.upstream.clone(),
        rate_per_minute: spec.rate_per_minute,
        mcp: spec.mcp.as_ref().map(|m| McpProfile {
            endpoint: m.endpoint.clone(),
            headers: m.headers.clone(),
        }),
    };
    let (upstream_host, _) = profile.upstream_host().ok_or_else(|| {
        ClientError::Invalid(format!(
            "upstream {:?}: write it as https://host or https://host:port, without a path",
            spec.upstream
        ))
    })?;
    let mut rules = credential_rules(item, &upstream_host, spec)?;
    if let Some(mcp) = &spec.mcp {
        rules.extend(tool_rules(item, &rules, mcp)?);
    }
    Ok((profile, rules))
}

/// The tool rules of an MCP profile (ADR 0049 §5.3): one rule per effect
/// that has patterns, on the profile's item, host and endpoint, for `POST`
/// (every `tools/call` is one). The display caps are applied here, so the
/// sheet shows every pattern it signs: at most
/// [`MAX_TOOL_PATTERNS_PER_RULE`] per rule, [`MAX_TOOL_PATTERNS_PER_PROFILE`]
/// in all, each of [`MAX_TOOL_PATTERN_LEN`] bytes at most.
fn tool_rules(item: ItemId, session: &[Rule], mcp: &McpSpec) -> ClientResult<Vec<Rule>> {
    let Some(first) = session.first() else {
        return Ok(Vec::new());
    };
    let mut rules = Vec::new();
    let mut total = 0;
    for (effect, list, flag) in [
        (Effect::Allow, &mcp.tools_allow, "--tools-allow"),
        (Effect::Ask, &mcp.tools_ask, "--tools-ask"),
        (Effect::Deny, &mcp.tools_deny, "--tools-deny"),
    ] {
        let mut patterns: Vec<ToolPattern> = Vec::new();
        for text in list {
            let text = text.trim();
            if text.len() > MAX_TOOL_PATTERN_LEN {
                return Err(ClientError::Invalid(format!(
                    "{flag}: a tool pattern takes at most {MAX_TOOL_PATTERN_LEN} bytes, so the confirmation can show it in full"
                )));
            }
            let pattern = ToolPattern::parse(text)
                .map_err(|e| ClientError::Invalid(format!("{flag}: {e}")))?;
            if !patterns.contains(&pattern) {
                patterns.push(pattern);
            }
        }
        if patterns.is_empty() {
            continue;
        }
        if patterns.len() > MAX_TOOL_PATTERNS_PER_RULE {
            return Err(ClientError::Invalid(format!(
                "{flag}: at most {MAX_TOOL_PATTERNS_PER_RULE} tool patterns per rule, so the confirmation can show them all: use broader prefixes (get_*)"
            )));
        }
        total += patterns.len();
        rules.push(Rule {
            permission: Permission::Proxy,
            effect,
            scope: Scope {
                items: vec![item],
                domains: first.scope.domains.clone(),
                methods: vec![
                    HttpMethod::parse("POST").map_err(|e| ClientError::Invalid(e.to_string()))?,
                ],
                path_prefixes: first.scope.path_prefixes.clone(),
                mcp_tools: patterns,
                ..Scope::default()
            },
            expires_at: None,
            once: false,
            origin: None,
        });
    }
    if total > MAX_TOOL_PATTERNS_PER_PROFILE {
        return Err(ClientError::Invalid(format!(
            "at most {MAX_TOOL_PATTERNS_PER_PROFILE} tool patterns per MCP profile, so the confirmation can show them all: use broader prefixes (get_*)"
        )));
    }
    if rules.len() > MAX_TOOL_RULES_PER_PROFILE {
        return Err(ClientError::Invalid(format!(
            "at most {MAX_TOOL_RULES_PER_PROFILE} tool rules per MCP profile"
        )));
    }
    Ok(rules)
}

/// What the person should know about an MCP profile's tool rules before
/// signing (ADR 0049 §5.3).
pub fn tool_warnings(mcp: &McpSpec) -> Vec<String> {
    let mut warnings = Vec::new();
    if mcp.tools_allow.iter().any(|p| p.trim() == "*") {
        warnings.push(
            "--tools-allow * lets every tool through, also the ones the MCP server adds later; only --tools-deny and --tools-ask narrow it".to_owned(),
        );
    }
    if mcp.tools_allow.is_empty() && mcp.tools_ask.is_empty() {
        warnings.push(
            "no tool is allowed or asked for (--tools-allow, --tools-ask): agents can connect and list nothing, and every tool call is refused".to_owned(),
        );
    }
    warnings
}

/// The local clients of a grant, as the person reads them.
fn local_client_views(clients: &[LocalClient]) -> Vec<LocalClientView> {
    clients
        .iter()
        .map(|c| LocalClientView {
            name: c.name.clone(),
            profiles: c.profiles.clone(),
        })
        .collect()
}

/// A warning per local client that loses a profile between `before` and
/// `after`; returns their names.
fn local_client_loss_warnings(
    before: &[LocalClient],
    after: &[LocalClient],
    warnings: &mut Vec<String>,
) -> Vec<String> {
    let mut names = Vec::new();
    for client in before {
        let kept = after.iter().find(|c| c.name == client.name);
        let gone: Vec<&str> = client
            .profiles
            .iter()
            .filter(|p| !kept.is_some_and(|k| k.profiles.contains(p)))
            .map(String::as_str)
            .collect();
        if gone.is_empty() {
            continue;
        }
        warnings.push(if kept.is_none() {
            format!(
                "the local client {} loses its only MCP profiles ({}) and its token stops working; `klav client disconnect {} --mcp` removes its entries",
                client.name,
                gone.join(", "),
                client.name
            )
        } else {
            format!(
                "the local client {} loses the MCP profile {}",
                client.name,
                gone.join(", ")
            )
        });
        names.push(client.name.clone());
    }
    names
}

/// The rules for one credential: `allow` (or `ask`) for its methods, hosts
/// and path prefixes, and `ask` for `ask_methods`. The most restrictive
/// rule that matches wins, so a method in both asks.
/// `Vault/Project` and the host of the first website of an item.
fn place_and_site(summary: &crate::session::ItemSummary) -> (String, Option<String>) {
    (
        format!("{}/{}", summary.vault, summary.project),
        summary
            .urls
            .iter()
            .find_map(|u| klav_core::site::item_host(u)),
    )
}

fn credential_rules(
    item: ItemId,
    upstream_host: &str,
    spec: &ProxyCredentialSpec,
) -> ClientResult<Vec<Rule>> {
    let invalid = |e: &dyn std::fmt::Display| ClientError::Invalid(e.to_string());
    // Mode (a) only connects to the upstream, so its host is the only one
    // a rule names. More hosts come with mode (b) (ADR 0036 §7).
    if upstream_host.len() > MAX_GRANT_HOST_LEN {
        return Err(ClientError::Invalid(format!(
            "the upstream's host is longer than {MAX_GRANT_HOST_LEN} characters, which the confirmation could not show in full"
        )));
    }
    if spec.header.trim().chars().count() > MAX_GRANT_HEADER_LEN
        || spec
            .field
            .as_ref()
            .is_some_and(|f| f.chars().count() > MAX_GRANT_HEADER_LEN)
    {
        return Err(ClientError::Invalid(format!(
            "the header and the field each take at most {MAX_GRANT_HEADER_LEN} characters, so the confirmation can show them in full"
        )));
    }
    let hosts = vec![DomainPattern::parse(upstream_host).map_err(|e| invalid(&e))?];
    if hosts.iter().any(|h| h.is_any() || h.is_ip_literal()) {
        return Err(ClientError::Invalid(
            "the credential's hosts are host names: never `*` or an IP address".into(),
        ));
    }
    let methods = |list: &[String]| -> ClientResult<Vec<HttpMethod>> {
        list.iter()
            .map(|m| HttpMethod::parse(&m.trim().to_ascii_uppercase()).map_err(|e| invalid(&e)))
            .collect()
    };
    let mut allowed = methods(&spec.methods)?;
    let mut asked = methods(&spec.ask_methods)?;
    allowed.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    allowed.dedup();
    asked.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    asked.dedup();
    let mut every: Vec<&str> = allowed
        .iter()
        .chain(&asked)
        .map(HttpMethod::as_str)
        .collect();
    every.sort_unstable();
    every.dedup();
    if every.len() > MAX_GRANT_METHODS {
        return Err(ClientError::Invalid(format!(
            "one credential carries at most {MAX_GRANT_METHODS} HTTP methods, so the confirmation can show them all: grant fewer"
        )));
    }
    if allowed.is_empty() && asked.is_empty() {
        return Err(ClientError::Invalid(
            "name the HTTP methods the credential may be used with (--method GET, --method POST…)"
                .into(),
        ));
    }
    if spec.path_prefixes.is_empty() {
        return Err(ClientError::Invalid(
            "name the paths the credential may be used on (--path-prefix /v1, or --path-prefix / for every path)".into(),
        ));
    }
    // An MCP profile reaches its endpoint and nothing else (ADR 0049
    // §2.1): the endpoint is its one path prefix, shown in full up to
    // the endpoint's own cap, and nothing asks by method (tools ask).
    if let Some(mcp) = &spec.mcp {
        if spec.ask || !asked.is_empty() {
            return Err(ClientError::Invalid(
                "an MCP profile asks per tool (--tools-ask), not per method: drop --ask and --ask-method".into(),
            ));
        }
        if spec.path_prefixes.len() != 1 || spec.path_prefixes[0].trim() != mcp.endpoint {
            return Err(ClientError::Invalid(
                "an MCP profile's only path is its endpoint (--mcp-url): drop --path-prefix".into(),
            ));
        }
        if mcp.endpoint.len() > klav_proto::agent::MAX_MCP_ENDPOINT
            || !klav_core::policy::is_canonical_path(&mcp.endpoint)
            || !shell_safe_path(&mcp.endpoint)
        {
            return Err(ClientError::Invalid(format!(
                "the MCP endpoint must be a canonical path of at most {} bytes, of letters, digits and / . _ - ~ only",
                klav_proto::agent::MAX_MCP_ENDPOINT
            )));
        }
    }
    let mut paths: Vec<PathPrefix> = spec
        .path_prefixes
        .iter()
        .map(|p| PathPrefix::parse(p.trim()).map_err(|e| invalid(&e)))
        .collect::<ClientResult<_>>()?;
    paths.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    paths.dedup_by(|a, b| a.as_str() == b.as_str());
    let path_len = if spec.mcp.is_some() {
        klav_proto::agent::MAX_MCP_ENDPOINT
    } else {
        MAX_GRANT_PATH_LEN
    };
    if paths.len() > MAX_GRANT_PATHS || paths.iter().any(|p| p.as_str().len() > path_len) {
        return Err(ClientError::Invalid(format!(
            "one credential carries at most {MAX_GRANT_PATHS} path prefixes of {MAX_GRANT_PATH_LEN} characters each, so the confirmation can show them in full: use fewer, broader prefixes"
        )));
    }
    let rule = |effect, methods: Vec<HttpMethod>| Rule {
        permission: Permission::Proxy,
        effect,
        scope: Scope {
            items: vec![item],
            domains: hosts.clone(),
            methods,
            path_prefixes: paths.clone(),
            ..Scope::default()
        },
        expires_at: None,
        once: false,
        origin: None,
    };
    let mut rules = Vec::new();
    if !allowed.is_empty() {
        rules.push(rule(
            if spec.ask { Effect::Ask } else { Effect::Allow },
            allowed,
        ));
    }
    if !asked.is_empty() {
        rules.push(rule(Effect::Ask, asked));
    }
    Ok(rules)
}

/// Whether an MCP endpoint is written only with characters that need no
/// quoting in a shell line or a URL: `klav sandbox start` and `klav client
/// connect` put it in both.
pub fn shell_safe_path(path: &str) -> bool {
    path.starts_with('/')
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b'~'))
}

/// Removes `item` from the request: the item, its profile, and its ID from
/// every rule; a rule left naming no item is dropped (an empty `items`
/// would apply to every item).
fn strip_item(request: &mut ItemGrantRequest, item: ItemId) {
    request.items.retain(|l| l.item != item);
    let gone: Vec<String> = request
        .profiles
        .iter()
        .filter(|p| p.item_id == item)
        .map(|p| p.name.clone())
        .collect();
    request.profiles.retain(|p| p.item_id != item);
    // An issuer loses the profiles that went with the item, and an issuer
    // left with none goes too: nothing it could start would work.
    for issuer in &mut request.issuers {
        issuer.profiles.retain(|p| !gone.contains(p));
    }
    request.issuers.retain(|i| !i.profiles.is_empty());
    request.policy.rules.retain_mut(|rule| {
        if !rule.scope.items.contains(&item) {
            return true;
        }
        rule.scope.items.retain(|i| *i != item);
        !rule.scope.items.is_empty()
    });
    keep_local_clients(request);
}

/// A local client keeps the profiles of the request that are still MCP
/// profiles (ADR 0049 §3.2), and a client left with none goes: the grant
/// would refuse it, and nothing it called would work.
fn keep_local_clients(request: &mut ItemGrantRequest) {
    let mcp: std::collections::HashSet<&str> = request
        .profiles
        .iter()
        .filter(|p| p.mcp.is_some())
        .map(|p| p.name.as_str())
        .collect();
    for client in &mut request.local_clients {
        client.profiles.retain(|p| mcp.contains(p.as_str()));
    }
    request.local_clients.retain(|c| !c.profiles.is_empty());
}

/// One issuer's loss in a change: its ID, the profiles it loses, and
/// whether it is left with none (and stops being an issuer).
type IssuerLoss = (AgentId, Vec<String>, bool);

/// Rebuilds the issuers from what they had `before`, keeping each profile
/// whose name the request still has: a profile replaced under the same
/// name stays theirs. An issuer left with none goes, since nothing it
/// could start would work. Returns what each issuer lost.
fn keep_issuers(
    request: &mut ItemGrantRequest,
    before: Vec<klav_proto::agent::SandboxIssuer>,
) -> Vec<IssuerLoss> {
    let names: std::collections::HashSet<String> =
        request.profiles.iter().map(|p| p.name.clone()).collect();
    let mut losses = Vec::new();
    request.issuers = before
        .into_iter()
        .filter_map(|mut issuer| {
            let gone: Vec<String> = issuer
                .profiles
                .iter()
                .filter(|p| !names.contains(*p))
                .cloned()
                .collect();
            issuer.profiles.retain(|p| names.contains(p));
            if !gone.is_empty() {
                losses.push((issuer.agent_id, gone, issuer.profiles.is_empty()));
            }
            (!issuer.profiles.is_empty()).then_some(issuer)
        })
        .collect();
    losses
}

/// The names of the issuers `request` leaves on `profile`.
fn issuers_keeping(
    request: &ItemGrantRequest,
    profile: &str,
    agents: &[crate::agents::AgentView],
) -> Vec<String> {
    request
        .issuers
        .iter()
        .filter(|i| i.profiles.iter().any(|p| p == profile))
        .map(|i| {
            agents
                .iter()
                .find(|a| a.id == i.agent_id)
                .map_or_else(|| i.agent_id.to_string(), |a| a.name.clone())
        })
        .collect()
}

/// A warning per issuer that loses a profile; returns their names.
fn issuer_loss_warnings(
    losses: &[IssuerLoss],
    agents: &[crate::agents::AgentView],
    warnings: &mut Vec<String>,
) -> Vec<String> {
    losses
        .iter()
        .map(|(id, gone, none_left)| {
            let name = agents
                .iter()
                .find(|a| a.id == *id)
                .map_or_else(|| id.to_string(), |a| a.name.clone());
            let profiles = gone.join(", ");
            warnings.push(if *none_left {
                format!(
                    "{name} stops being a sandbox issuer: its only profiles ({profiles}) go away, and its sandboxes can no longer use them"
                )
            } else {
                format!(
                    "{name} loses the profile {profiles}: its sandboxes can no longer use it"
                )
            });
            name
        })
        .collect()
}

/// `reveal`, `inject` and `fill` denied, as every proxy grant must
/// (ADR 0036 §2): a rule that lets one through is replaced by a deny.
fn ensure_value_denies(policy: &mut Policy) {
    for permission in [Permission::Reveal, Permission::Inject, Permission::Fill] {
        policy
            .rules
            .retain(|r| r.permission != permission || r.effect == Effect::Deny);
        if !policy.rules.iter().any(|r| r.permission == permission) {
            policy.rules.push(Rule::new(permission, Effect::Deny));
        }
    }
}

/// The hosts the `proxy` rules let `item` reach.
fn proxy_hosts(policy: &Policy, item: ItemId) -> Vec<String> {
    let mut hosts: Vec<String> = policy
        .rules
        .iter()
        .filter(|r| r.permission == Permission::Proxy && r.effect != Effect::Deny)
        .filter(|r| r.scope.items.contains(&item))
        .flat_map(|r| r.scope.domains.iter().map(ToString::to_string))
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// The issuers of the proxy's verified grant, with the server's name and
/// state of each ([`ProxyIssuerView`]).
fn issuer_views(
    issuers: &[klav_proto::agent::SandboxIssuer],
    agents: &[crate::agents::AgentView],
) -> Vec<ProxyIssuerView> {
    issuers
        .iter()
        .map(|i| {
            let listed = agents.iter().find(|a| a.id == i.agent_id);
            ProxyIssuerView {
                agent_id: i.agent_id,
                name: listed.map(|a| a.name.clone()),
                status: listed.map(|a| a.status),
                profiles: i.profiles.clone(),
                max_ttl_secs: i.max_ttl_secs,
                max_live: i.max_live,
            }
        })
        .collect()
}

fn credential_view(
    item: ItemId,
    title: String,
    profiles: &[ProxyProfile],
    policy: &Policy,
) -> ProxyCredentialView {
    ProxyCredentialView {
        item_id: item,
        title,
        profile: profiles.iter().find(|p| p.item_id == item).cloned(),
        rules: policy
            .rules
            .iter()
            .filter(|r| r.permission == Permission::Proxy && r.scope.items.contains(&item))
            .map(|r| ProxyRuleView {
                effect: r.effect,
                methods: r
                    .scope
                    .methods
                    .iter()
                    .map(|m| m.as_str().to_owned())
                    .collect(),
                hosts: r.scope.domains.iter().map(ToString::to_string).collect(),
                path_prefixes: r
                    .scope
                    .path_prefixes
                    .iter()
                    .map(|p| p.as_str().to_owned())
                    .collect(),
                mcp_tools: r
                    .scope
                    .mcp_tools
                    .iter()
                    .map(|p| p.as_str().to_owned())
                    .collect(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use klav_core::policy::{Request, Target, evaluate};

    fn spec() -> ProxyCredentialSpec {
        ProxyCredentialSpec {
            profile: "up".into(),
            upstream: "https://api.example.com".into(),
            header: "authorization".into(),
            prefix: "Bearer ".into(),
            methods: vec!["get".into(), "POST".into(), "DELETE".into()],
            path_prefixes: vec!["/v1".into()],
            ask_methods: vec!["DELETE".into(), "PATCH".into()],
            ..ProxyCredentialSpec::default()
        }
    }

    fn call(item: ItemId, method: &str, host: &str, path: &str) -> Request {
        Request {
            permission: Permission::Proxy,
            vault: Target {
                id: klav_core::ids::VaultId::generate(),
                name: String::new(),
            },
            project: Target {
                id: klav_core::ids::ProjectId::generate(),
                name: String::new(),
            },
            tags: Vec::new(),
            domain: Some(host.into()),
            item: Some(item),
            method: Some(method.into()),
            path: Some(path.into()),
            mcp_tool: None,
            now: 0,
        }
    }

    #[test]
    fn the_flags_give_the_effects_they_say() {
        let item = ItemId::generate();
        let other = ItemId::generate();
        let policy = Policy {
            rules: credential_rules(item, "api.example.com", &spec()).unwrap(),
            expires_at: None,
        };
        let effect = |r: &Request| evaluate(&policy, r).effect;
        assert_eq!(
            effect(&call(item, "GET", "api.example.com", "/v1/x")),
            Effect::Allow
        );
        assert_eq!(
            effect(&call(item, "POST", "api.example.com", "/v1")),
            Effect::Allow
        );
        // In both lists: the stricter one wins.
        assert_eq!(
            effect(&call(item, "DELETE", "api.example.com", "/v1/x")),
            Effect::Ask
        );
        // Only asked.
        assert_eq!(
            effect(&call(item, "PATCH", "api.example.com", "/v1/x")),
            Effect::Ask
        );
        // Outside: method, path, host, item.
        assert_eq!(
            effect(&call(item, "PUT", "api.example.com", "/v1/x")),
            Effect::Deny
        );
        assert_eq!(
            effect(&call(item, "GET", "api.example.com", "/v2")),
            Effect::Deny
        );
        assert_eq!(
            effect(&call(item, "GET", "evil.example.com", "/v1")),
            Effect::Deny
        );
        assert_eq!(
            effect(&call(other, "GET", "api.example.com", "/v1")),
            Effect::Deny
        );
        // `--ask`: everything asks.
        let all_ask = Policy {
            rules: credential_rules(
                item,
                "api.example.com",
                &ProxyCredentialSpec {
                    ask: true,
                    ask_methods: Vec::new(),
                    ..spec()
                },
            )
            .unwrap(),
            expires_at: None,
        };
        assert_eq!(
            evaluate(&all_ask, &call(item, "GET", "api.example.com", "/v1")).effect,
            Effect::Ask
        );
    }

    #[test]
    fn a_credential_needs_methods_paths_and_its_upstream_host() {
        let item = ItemId::generate();
        for bad in [
            ProxyCredentialSpec {
                methods: Vec::new(),
                ask_methods: Vec::new(),
                ..spec()
            },
            ProxyCredentialSpec {
                path_prefixes: Vec::new(),
                ..spec()
            },
        ] {
            assert!(credential_rules(item, "api.example.com", &bad).is_err());
        }
        // The upstream's host is the only host, and a name.
        for host in ["*", "10.0.0.1", &format!("{}.example.com", "a".repeat(60))] {
            assert!(credential_rules(item, host, &spec()).is_err(), "{host}");
        }
    }

    #[test]
    fn one_grant_carries_only_what_the_prompt_shows_in_full() {
        let item = ItemId::generate();
        let many = |n: usize| (0..n).map(|i| format!("/p{i}")).collect::<Vec<_>>();
        // At the caps: fine. Repeats count once.
        let at_caps = ProxyCredentialSpec {
            methods: vec!["GET".into(), "POST".into(), "GET".into()],
            ask_methods: vec!["DELETE".into(), "PATCH".into(), "POST".into()],
            path_prefixes: many(MAX_GRANT_PATHS),
            ..spec()
        };
        assert!(credential_rules(item, "api.example.com", &at_caps).is_ok());
        let long_names = ProxyCredentialSpec {
            header: "x".repeat(MAX_GRANT_HEADER_LEN),
            field: Some("é".repeat(MAX_GRANT_HEADER_LEN)),
            ..spec()
        };
        assert!(credential_rules(item, "api.example.com", &long_names).is_ok());
        for over in [
            ProxyCredentialSpec {
                methods: vec!["GET".into(), "POST".into(), "PUT".into()],
                ask_methods: vec!["DELETE".into(), "PATCH".into()],
                ..spec()
            },
            ProxyCredentialSpec {
                path_prefixes: many(MAX_GRANT_PATHS + 1),
                ..spec()
            },
            ProxyCredentialSpec {
                path_prefixes: vec![format!("/{}", "a".repeat(MAX_GRANT_PATH_LEN))],
                ..spec()
            },
            ProxyCredentialSpec {
                header: "x".repeat(MAX_GRANT_HEADER_LEN + 1),
                ..spec()
            },
            ProxyCredentialSpec {
                field: Some("é".repeat(MAX_GRANT_HEADER_LEN + 1)),
                ..spec()
            },
        ] {
            let err = credential_rules(item, "api.example.com", &over).unwrap_err();
            assert!(err.to_string().contains("at most"), "{err}");
        }
    }

    #[test]
    fn taking_an_item_away_never_leaves_a_rule_without_items() {
        let a = ItemId::generate();
        let b = ItemId::generate();
        let mut shared = credential_rules(a, "api.example.com", &spec()).unwrap();
        shared[0].scope.items.push(b);
        let mut request = ItemGrantRequest {
            items: Vec::new(),
            profiles: Vec::new(),
            issuers: Vec::new(),
            local_clients: Vec::new(),
            policy: Policy {
                rules: shared
                    .into_iter()
                    .chain(credential_rules(b, "api.example.com", &spec()).unwrap())
                    .collect(),
                expires_at: None,
            },
        };
        ensure_value_denies(&mut request.policy);
        strip_item(&mut request, b);
        for rule in &request.policy.rules {
            if rule.permission == Permission::Proxy {
                assert_eq!(rule.scope.items, vec![a]);
            }
        }
        strip_item(&mut request, a);
        assert!(
            request
                .policy
                .rules
                .iter()
                .all(|r| r.permission != Permission::Proxy)
        );
        // The denies stay.
        assert_eq!(request.policy.rules.len(), 3);
    }

    #[test]
    fn a_rule_that_hands_out_values_is_replaced_by_a_deny() {
        let mut policy = Policy {
            rules: vec![Rule::new(Permission::Inject, Effect::Allow)],
            expires_at: None,
        };
        ensure_value_denies(&mut policy);
        for p in [Permission::Reveal, Permission::Inject, Permission::Fill] {
            let rules: Vec<_> = policy.rules.iter().filter(|r| r.permission == p).collect();
            assert_eq!(rules.len(), 1);
            assert_eq!(rules[0].effect, Effect::Deny);
        }
    }

    #[test]
    fn hosting_providers_are_named() {
        assert_eq!(hosting_provider("backboard.railway.com"), Some("Railway"));
        assert_eq!(hosting_provider("api.northflank.com"), Some("Northflank"));
        assert_eq!(hosting_provider("API.Fly.io."), Some("Fly.io"));
        assert_eq!(hosting_provider("notrailway.com"), None);
        assert_eq!(hosting_provider("api.github.com"), None);
    }

    fn mcp_spec(allow: &[&str], ask: &[&str], deny: &[&str]) -> ProxyCredentialSpec {
        let list = |l: &[&str]| l.iter().map(|p| (*p).to_owned()).collect();
        ProxyCredentialSpec {
            profile: "maple".into(),
            upstream: "https://api.maple.dev".into(),
            header: "authorization".into(),
            prefix: "Bearer ".into(),
            methods: vec!["POST".into(), "GET".into(), "DELETE".into()],
            path_prefixes: vec!["/mcp".into()],
            mcp: Some(McpSpec {
                endpoint: "/mcp".into(),
                headers: Vec::new(),
                tools_allow: list(allow),
                tools_ask: list(ask),
                tools_deny: list(deny),
            }),
            ..ProxyCredentialSpec::default()
        }
    }

    fn tool_call(item: ItemId, tool: &str) -> Request {
        Request {
            mcp_tool: Some(tool.into()),
            ..call(item, "POST", "api.maple.dev", "/mcp")
        }
    }

    /// ADR 0049 §5.3: the session rule never lets a tool call through,
    /// tool rules do what their effect says, the strictest wins, and a
    /// tool no rule names is denied.
    #[test]
    fn an_mcp_profile_signs_its_tool_rules_and_denies_the_rest() {
        let item = ItemId::generate();
        let spec = mcp_spec(
            &["get_*", "query_logs", "get_*"],
            &["delete_*"],
            &["get_api_key"],
        );
        let (profile, rules) = credential_profile(item, &spec).unwrap();
        assert_eq!(
            profile.mcp,
            Some(McpProfile {
                endpoint: "/mcp".into(),
                headers: Vec::new()
            })
        );
        // The session, then one rule per effect; repeats count once.
        assert_eq!(rules.len(), 4);
        assert!(rules[0].scope.mcp_tools.is_empty());
        assert_eq!(rules[1].scope.mcp_tools.len(), 2);
        let policy = Policy {
            rules,
            expires_at: None,
        };
        let effect = |r: &Request| evaluate(&policy, r).effect;
        assert_eq!(effect(&tool_call(item, "get_dashboard")), Effect::Allow);
        assert_eq!(effect(&tool_call(item, "query_logs")), Effect::Allow);
        assert_eq!(effect(&tool_call(item, "delete_dashboard")), Effect::Ask);
        assert_eq!(effect(&tool_call(item, "get_api_key")), Effect::Deny);
        assert_eq!(effect(&tool_call(item, "create_api_key")), Effect::Deny);
        // Case-sensitive: `Get_x` is not `get_*`.
        assert_eq!(effect(&tool_call(item, "Get_x")), Effect::Deny);
        // The session itself (initialize, tools/list) goes through.
        assert_eq!(
            effect(&call(item, "POST", "api.maple.dev", "/mcp")),
            Effect::Allow
        );
        // And the shape the grant checks: the endpoint only.
        assert_eq!(
            effect(&call(item, "GET", "api.maple.dev", "/.well-known/oauth")),
            Effect::Deny
        );
    }

    /// The display caps (ADR 0049 §5.3): every pattern the sheet shows, and
    /// never more; bad patterns and method asks are refused.
    #[test]
    fn tool_rules_keep_to_what_the_sheet_shows() {
        let item = ItemId::generate();
        let many = |n: usize, p: &str| (0..n).map(|i| format!("{p}{i}_*")).collect::<Vec<_>>();
        fn names(v: &[String]) -> Vec<&str> {
            v.iter().map(String::as_str).collect()
        }
        let at_cap = many(MAX_TOOL_PATTERNS_PER_RULE, "a");
        assert!(credential_profile(item, &mcp_spec(&names(&at_cap), &[], &[])).is_ok());
        let over = many(MAX_TOOL_PATTERNS_PER_RULE + 1, "a");
        let err = credential_profile(item, &mcp_spec(&names(&over), &[], &[])).unwrap_err();
        assert!(err.to_string().contains("per rule"), "{err}");
        let a = many(MAX_TOOL_PATTERNS_PER_RULE, "a");
        let b = many(MAX_TOOL_PATTERNS_PER_RULE, "b");
        let c = many(1, "c");
        let err =
            credential_profile(item, &mcp_spec(&names(&a), &names(&b), &names(&c))).unwrap_err();
        assert!(err.to_string().contains("per MCP profile"), "{err}");
        let long = format!("{}*", "a".repeat(MAX_TOOL_PATTERN_LEN));
        let err = credential_profile(item, &mcp_spec(&[&long], &[], &[])).unwrap_err();
        assert!(err.to_string().contains("at most"), "{err}");
        for bad in ["*_api_key", "get logs", "get_*_x", "q\u{202e}l", ""] {
            assert!(
                credential_profile(item, &mcp_spec(&[bad], &[], &[])).is_err(),
                "{bad:?}"
            );
        }
        let mut asks = mcp_spec(&["get_*"], &[], &[]);
        asks.ask_methods = vec!["DELETE".into()];
        assert!(credential_profile(item, &asks).is_err());
        let mut other_path = mcp_spec(&["get_*"], &[], &[]);
        other_path.path_prefixes = vec!["/".into()];
        assert!(credential_profile(item, &other_path).is_err());
        let mut shelly = mcp_spec(&["get_*"], &[], &[]);
        shelly.path_prefixes = vec!["/m$x".into()];
        shelly.mcp.as_mut().unwrap().endpoint = "/m$x".into();
        assert!(credential_profile(item, &shelly).is_err());
    }

    /// A spec without `mcp` serializes as before, so an older `klavd`
    /// still takes it.
    #[test]
    fn a_spec_without_mcp_is_the_bytes_an_older_klavd_takes() {
        let json = serde_json::to_value(spec()).unwrap();
        assert!(json.get("mcp").is_none(), "{json}");
        assert!(tool_warnings(&McpSpec::default())[0].contains("every tool call is refused"));
        let every = McpSpec {
            tools_allow: vec!["*".into()],
            ..McpSpec::default()
        };
        assert!(tool_warnings(&every)[0].contains("every tool through"));
    }

    /// A re-grant keeps the clients on the profiles that stay MCP
    /// profiles, and says who loses what.
    #[test]
    fn local_clients_lose_only_the_profiles_that_go() {
        let client = |name: &str, profiles: &[&str]| LocalClient {
            name: name.into(),
            token_digest: Blob::new(vec![1; 32]),
            profiles: profiles.iter().map(|p| (*p).to_owned()).collect(),
        };
        let before = vec![
            client("claude-code", &["maple", "linear"]),
            client("cursor", &["linear"]),
        ];
        let after = vec![client("claude-code", &["maple"])];
        let mut warnings = Vec::new();
        let names = local_client_loss_warnings(&before, &after, &mut warnings);
        assert_eq!(names, ["claude-code", "cursor"]);
        assert!(
            warnings[0].contains("loses the MCP profile linear"),
            "{warnings:?}"
        );
        assert!(warnings[1].contains("token stops working"), "{warnings:?}");
    }
}
