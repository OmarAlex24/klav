//! Agents as the person sees them (design §5.1, ADR 0014): pending
//! registrations, approval with a signed grant, denial.
//!
//! Approving an agent wraps the key of every granted project for the
//! agent's X25519 key (HPKE, kind `0x21`), puts the keys and the policy in a
//! [`GrantPayload`] and signs its exact bytes with the account identity.
//! The server only stores that grant: it never sees a key in clear and
//! cannot change the policy without breaking the signature.

use klav_core::crypto::agent::{self, GrantToSign, pairing_code};
use klav_core::crypto::context::ProjectContext;
use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::share::share_project_key;
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::ids::{AgentId, ApprovalId, ItemId, ProjectId, VaultId};
use klav_core::model::Selector;
use klav_core::policy::{Permission, Policy, Scope};
use klav_proto::Blob;
use klav_proto::agent::{
    AgentInfo, AgentList, AgentStatus, ApprovalInfo, ApprovalList, ApprovalRequest, ApprovalStatus,
    DecideApproval, GRANT_PAYLOAD_VERSION, GrantLabels, GrantPayload, GrantedProject, IssuerGrant,
    SignedGrant,
};
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::api::Body;
use crate::error::{ClientError, ClientResult};
use crate::session::{Unlocked, now_ms};

/// An agent of the account, with what the person needs to decide.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentView {
    /// Agent ID.
    pub id: AgentId,
    /// Name the agent gave itself.
    pub name: String,
    /// Free-form note from the registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// State.
    pub status: AgentStatus,
    /// The six pairing words of its public key (spec §13.1).
    pub pairing_code: String,
    /// Registration time (Unix ms).
    pub created_at: i64,
    /// Until when a pending registration can be approved (Unix ms).
    pub expires_at: i64,
    /// Approval time (Unix ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<i64>,
    /// Revocation time (Unix ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
    /// Last signed request (Unix ms, minute precision).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<i64>,
    /// The current grant, verified against the account identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<GrantView>,
    /// Why the agent has a grant but `grant` is empty: this device cannot
    /// read it (a format it does not know, or a signature that does not
    /// check out). One such grant never hides the other agents, and never
    /// stops a revocation (ADR 0033, amendment of 2026-11-10, F1 gap 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_error: Option<String>,
    /// The pause in effect on it, its own or the account-wide one, as the
    /// server says (ADR 0033 §7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused: Option<klav_proto::agent::AgentPaused>,
}

/// A verified grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantView {
    /// Grant version (1 for the first approval).
    pub version: u64,
    /// When it was signed (Unix ms).
    pub issued_at: i64,
    /// Granted projects.
    pub projects: Vec<GrantedProjectView>,
    /// Items granted one by one (a per-item grant, ADR 0036 §2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<GrantedItemView>,
    /// Where each item's value may go (the proxy's profiles).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<klav_proto::agent::ProxyProfile>,
    /// The policy (selectors by ID, as signed).
    pub policy: Policy,
    /// The payload format (`v`): 3 with sandbox issuers or a sandbox proxy.
    #[serde(default)]
    pub v: u32,
    /// On the credential proxy's grant: the agents that may start
    /// sandboxes through it (ADR 0036 §4).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuers: Vec<klav_proto::agent::SandboxIssuer>,
    /// On an issuer's grant: the proxy it starts sandboxes at (`proxy:
    /// null` when the account has none it may use).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<IssuerGrant>,
}

/// An item granted one by one, with its current title.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantedItemView {
    /// Vault ID.
    pub vault_id: VaultId,
    /// Project ID, as signed.
    pub project_id: ProjectId,
    /// Item ID.
    pub item_id: ItemId,
    /// Item title (empty if this device no longer sees it).
    pub title: String,
}

/// A granted project with its current names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantedProjectView {
    /// Vault ID.
    pub vault_id: VaultId,
    /// Vault name (empty if this device no longer sees it).
    pub vault: String,
    /// Project ID.
    pub project_id: ProjectId,
    /// Project name (empty if this device no longer sees it).
    pub project: String,
}

/// What to grant.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GrantRequest {
    /// Projects whose keys the agent receives: `vault/project`, a project
    /// name unique across vaults, or an ID.
    #[serde(default)]
    pub projects: Vec<String>,
    /// Vaults whose current projects are all granted.
    #[serde(default)]
    pub vaults: Vec<String>,
    /// The policy. Vault and project selectors may use names: they are
    /// resolved to IDs before signing (the server never sees names).
    pub policy: Policy,
}

/// An approval checked by [`Unlocked::prepare_grant`], ready to sign. No
/// secrets.
#[derive(Debug, Clone)]
pub struct PreparedGrant {
    agent: AgentId,
    agent_name: String,
    public: PublicIdentity,
    version: u64,
    /// The `v` of the grant it replaces: never lowered.
    floor: u32,
    policy: Policy,
    wanted: Vec<ProjectId>,
    places: Vec<String>,
    warnings: Vec<String>,
    /// The sandbox proxy its current grant names (an issuer, ADR 0036
    /// §4): an approval keeps it, so changing projects never drops it.
    sandbox: Option<IssuerGrant>,
    /// The agent was pending: this is its first grant.
    first: bool,
}

impl PreparedGrant {
    /// Whether this approves a pending registration (its first grant),
    /// rather than replacing an active agent's grant. `klavd`'s
    /// `approve_agent` takes only the first kind: an active agent's grant
    /// changes through the sheet of differences (ADR 0033, amendment of
    /// 2026-11-10, F4).
    #[must_use]
    pub fn first(&self) -> bool {
        self.first
    }

    /// The name the agent gave itself.
    #[must_use]
    pub fn agent_name(&self) -> &str {
        &self.agent_name
    }

    /// The granted projects as `vault/project`, in the order asked,
    /// without repeats.
    #[must_use]
    pub fn places(&self) -> &[String] {
        &self.places
    }

    /// What could not be checked: say it to the person, the approval goes
    /// on.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

impl Unlocked {
    /// The account's pairing code, so an agent can check it is talking to
    /// the right account.
    pub fn account_pairing_code(&self) -> String {
        pairing_code(self.identity.public())
    }

    /// The agents of the account (pending, active, denied and revoked).
    /// An agent whose grant this device cannot read is listed with
    /// [`AgentView::grant_error`], not dropped, and does not fail the list.
    pub async fn agents(&mut self) -> ClientResult<Vec<AgentView>> {
        let res = self.authed(Method::GET, "/v1/agents", &Body::Empty).await?;
        let list: AgentList = crate::api::json(res).await?;
        Ok(list
            .agents
            .into_iter()
            .map(|a| self.view_lenient(a))
            .collect())
    }

    /// One agent, by ID, name or a unique prefix of its ID.
    pub async fn agent(&mut self, wanted: &str) -> ClientResult<AgentView> {
        let agents = self.agents().await?;
        find_agent(agents, wanted)
    }

    pub(crate) async fn agent_info(&mut self, id: AgentId) -> ClientResult<AgentInfo> {
        let res = self
            .authed(Method::GET, &format!("/v1/agents/{id}"), &Body::Empty)
            .await?;
        crate::api::json(res).await
    }

    pub(crate) fn view(&self, info: AgentInfo) -> ClientResult<AgentView> {
        let public = PublicIdentity::decode(info.public_identity.as_bytes())?;
        let grant = info
            .grant
            .as_ref()
            .map(|g| {
                self.open_grant(info.id, &public, g)
                    .map(|p| self.grant_view(p))
            })
            .transpose()?;
        Ok(Self::view_with(info, &public, grant, None))
    }

    /// [`Self::view`], but a grant this device cannot read (or an identity
    /// that does not decode) leaves `grant` empty and says why in
    /// [`AgentView::grant_error`] instead of failing.
    pub(crate) fn view_lenient(&self, info: AgentInfo) -> AgentView {
        let public = match PublicIdentity::decode(info.public_identity.as_bytes()) {
            Ok(public) => public,
            Err(e) => {
                let why = format!("the agent's public key does not decode: {e}");
                return AgentView {
                    id: info.id,
                    name: info.name,
                    note: info.note,
                    status: info.status,
                    pairing_code: String::new(),
                    created_at: info.created_at,
                    expires_at: info.expires_at,
                    approved_at: info.approved_at,
                    revoked_at: info.revoked_at,
                    last_seen_at: info.last_seen_at,
                    grant: None,
                    grant_error: Some(why),
                    paused: info.paused,
                };
            }
        };
        let (grant, error) = match info
            .grant
            .as_ref()
            .map(|g| self.open_grant(info.id, &public, g))
        {
            None => (None, None),
            Some(Ok(payload)) => (Some(self.grant_view(payload)), None),
            Some(Err(e)) => (
                None,
                Some(format!("this device cannot read its grant: {e}")),
            ),
        };
        Self::view_with(info, &public, grant, error)
    }

    fn view_with(
        info: AgentInfo,
        public: &PublicIdentity,
        grant: Option<GrantView>,
        grant_error: Option<String>,
    ) -> AgentView {
        AgentView {
            id: info.id,
            name: info.name,
            note: info.note,
            status: info.status,
            pairing_code: pairing_code(public),
            created_at: info.created_at,
            expires_at: info.expires_at,
            approved_at: info.approved_at,
            revoked_at: info.revoked_at,
            last_seen_at: info.last_seen_at,
            grant,
            grant_error,
            paused: info.paused,
        }
    }

    /// Verifies a stored grant: signed by this account, for this agent.
    pub(crate) fn open_grant(
        &self,
        agent_id: AgentId,
        public: &PublicIdentity,
        grant: &SignedGrant,
    ) -> ClientResult<GrantPayload> {
        let signature: [u8; SIGNATURE_LEN] =
            grant.signature.as_bytes().try_into().map_err(|_| {
                ClientError::Corrupt(format!("grant of agent {agent_id}: signature"))
            })?;
        let signature = Signature::from_bytes(signature);
        agent::verify_grant(
            self.identity.public(),
            &GrantToSign {
                account: self.account.account_id,
                agent: agent_id,
                agent_public: public,
                payload: grant.payload.as_bytes(),
            },
            &signature,
        )
        .map_err(|_| {
            ClientError::Security(format!(
                "the grant of agent {agent_id} is not signed by this account; the server may have altered it"
            ))
        })?;
        let payload: GrantPayload = serde_json::from_slice(grant.payload.as_bytes())
            .map_err(|e| ClientError::Corrupt(format!("grant of agent {agent_id}: {e}")))?;
        if payload.agent_id != agent_id || payload.account_id != self.account.account_id {
            return Err(ClientError::Security(format!(
                "the grant of agent {agent_id} names another agent or account"
            )));
        }
        // A version this client does not know fails here (closed), never
        // read as an older one.
        payload
            .check_format()
            .map_err(|e| ClientError::Corrupt(format!("grant of agent {agent_id}: {e}")))?;
        Ok(payload)
    }

    pub(crate) fn grant_view(&self, payload: GrantPayload) -> GrantView {
        GrantView {
            version: payload.version,
            issued_at: payload.issued_at,
            projects: payload
                .projects
                .iter()
                .map(|p| GrantedProjectView {
                    vault_id: p.vault_id,
                    vault: self
                        .vaults
                        .get(&p.vault_id)
                        .map(|v| v.meta.name().to_owned())
                        .unwrap_or_default(),
                    project_id: p.project_id,
                    project: self
                        .projects
                        .get(&p.project_id)
                        .map(|e| e.meta.name().to_owned())
                        .unwrap_or_default(),
                })
                .collect(),
            items: payload
                .items
                .iter()
                .map(|i| GrantedItemView {
                    vault_id: i.vault_id,
                    project_id: i.project_id,
                    item_id: i.item_id,
                    title: self
                        .locate_item(i.item_id)
                        .and_then(|loc| self.item_summary(loc).ok())
                        .map(|s| s.title)
                        .unwrap_or_default(),
                })
                .collect(),
            profiles: payload.profiles,
            policy: payload.policy,
            v: payload.v,
            issuers: payload.issuers,
            sandbox: payload.sandbox,
        }
    }

    /// Approves an agent (or replaces its grant): signs a grant with the
    /// keys of the requested projects and the policy. `pairing_code` is
    /// what the person compared with the agent's screen: the agent's key
    /// must still produce it (the server cannot swap the key in between).
    pub async fn approve_agent(
        &mut self,
        id: AgentId,
        request: GrantRequest,
        pairing_code: &str,
    ) -> ClientResult<AgentView> {
        let prepared = self.prepare_grant(id, request, pairing_code).await?;
        self.grant_prepared(prepared).await
    }

    /// The checks of [`Self::approve_agent`], without signing: the
    /// projects, the agent's state and its pairing words. `klavd` asks for
    /// presence in between, with the names this returns.
    pub async fn prepare_grant(
        &mut self,
        id: AgentId,
        request: GrantRequest,
        pairing_code: &str,
    ) -> ClientResult<PreparedGrant> {
        let mut wanted = Vec::new();
        for project in &request.projects {
            wanted.push(self.find_project_anywhere(project)?);
        }
        for vault in &request.vaults {
            let vault = self.find_vault(vault)?;
            wanted.extend(self.projects(Some(vault)).into_iter().map(|p| p.id));
        }
        if wanted.is_empty() {
            return Err(ClientError::Invalid(
                "grant at least one project (--project or --vault)".into(),
            ));
        }
        let info = self.agent_info(id).await?;
        match info.status {
            AgentStatus::Pending | AgentStatus::Active => {}
            other => {
                return Err(ClientError::Invalid(format!(
                    "agent {} is {}; it cannot be approved",
                    info.name,
                    other.as_str()
                )));
            }
        }
        // The account's credential proxy only ever gets credentials one by
        // one (ADR 0036 §2): `klav proxy use` recorded it, so no project
        // grant reaches it from any client. Synced first, so a `use` from
        // another device counts. When the setting cannot be checked, the
        // approval goes on as before the proxy existed, with a warning:
        // only a readable setting that names this agent refuses.
        let synced = self.sync().await.map(|_| ());
        let warnings = proxy_check(id, &info.name, synced, self.preferences())?;
        let public = PublicIdentity::decode(info.public_identity.as_bytes())?;
        if !agent::pairing_code_matches(&public, pairing_code) {
            return Err(ClientError::Security(format!(
                "the pairing words of agent {} do not match; do not approve it",
                info.name
            )));
        }
        let mut sandbox = None;
        let (current, floor) = match &info.grant {
            Some(g) => {
                let payload = self.open_grant(id, &public, g)?;
                sandbox.clone_from(&payload.sandbox);
                // A per-item grant is changed with `grant_items`: a project
                // grant written over it would drop its items and profiles.
                if !payload.items.is_empty() || !payload.profiles.is_empty() {
                    return Err(ClientError::Invalid(format!(
                        "agent {} has a per-item grant; change it as one, not with projects",
                        info.name
                    )));
                }
                (payload.version, payload.v)
            }
            None => (0, GRANT_PAYLOAD_VERSION),
        };
        let policy = self.resolve_policy(request.policy)?;
        let mut warnings = warnings;
        // An issuer's grant keeps `sandbox`, but its policy is the one this
        // approval is given: an `inject: ask` from `issuer add
        // --inject-ask` does not carry over.
        if sandbox.is_some() && crate::issuers::inject_allowed(&policy) {
            warnings.push(format!(
                "agent {} starts sandboxes, and this policy lets it `inject` without asking: it could pass a provider's token to the command that creates a sandbox (T171). An `inject: ask` it had is not kept by an approval; run it with `--ask inject` to keep each `inject` asking you",
                info.name
            ));
        }
        let mut places = Vec::new();
        for project in &wanted {
            let Some(entry) = self.projects.get(project) else {
                continue;
            };
            let vault = self
                .vaults
                .get(&entry.vault)
                .map(|v| v.meta.name().to_owned())
                .unwrap_or_default();
            let place = format!("{vault}/{}", entry.meta.name());
            if !places.contains(&place) {
                places.push(place);
            }
        }
        Ok(PreparedGrant {
            agent: id,
            agent_name: info.name,
            public,
            version: current + 1,
            floor,
            policy,
            wanted,
            places,
            warnings,
            sandbox,
            first: info.status == AgentStatus::Pending,
        })
    }

    /// Signs and uploads a grant checked by [`Self::prepare_grant`]. The
    /// server refuses it if the agent's grant or state changed meanwhile.
    pub async fn grant_prepared(&mut self, prepared: PreparedGrant) -> ClientResult<AgentView> {
        let PreparedGrant {
            agent,
            public,
            version,
            floor,
            policy,
            wanted,
            sandbox,
            ..
        } = prepared;
        self.issue_grant(
            agent,
            &public,
            GrantSlot { version, floor },
            policy,
            wanted,
            sandbox,
        )
        .await
    }

    /// Signs and uploads grant `slot.version` for an agent whose key the
    /// person approved: the keys of `wanted` (current ones) and `policy`.
    /// Its `v` is what it carries ([`GrantPayload::version_after`]
    /// `slot.floor`, the `v` of the grant it replaces).
    pub(crate) async fn issue_grant(
        &mut self,
        id: AgentId,
        public: &PublicIdentity,
        slot: GrantSlot,
        policy: Policy,
        wanted: Vec<ProjectId>,
        sandbox: Option<IssuerGrant>,
    ) -> ClientResult<AgentView> {
        // `passkey` and `rotate` only exist inside a task (ADR 0021 §5):
        // the client never signs a grant with rules for them.
        policy
            .check_grantable()
            .map_err(|e| ClientError::Invalid(e.to_string()))?;
        let projects = self.granted_projects(id, public, wanted)?;
        let mut payload = GrantPayload {
            v: GRANT_PAYLOAD_VERSION,
            account_id: self.account.account_id,
            agent_id: id,
            version: slot.version,
            issued_at: now_ms(),
            policy,
            projects,
            items: Vec::new(),
            profiles: Vec::new(),
            issuers: Vec::new(),
            sandbox,
        };
        payload.v = payload.version_after(slot.floor);
        self.upload_grant(id, public, payload).await
    }

    /// The keys of `wanted` (current ones, without repeats) shared with an
    /// agent, as a grant carries them. Klav's system project never goes to
    /// an agent (ADR 0022 §2).
    pub(crate) fn granted_projects(
        &self,
        id: AgentId,
        public: &PublicIdentity,
        wanted: Vec<ProjectId>,
    ) -> ClientResult<Vec<GrantedProject>> {
        let mut projects = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for project in wanted {
            if !seen.insert(project) {
                continue;
            }
            let entry = self
                .projects
                .get(&project)
                .ok_or_else(|| ClientError::NotFound(format!("project {project}")))?;
            // Klav's own project (the generator history) never goes to an
            // agent (ADR 0022 §2).
            if klav_core::model::history::is_system_project(entry.vault, project) {
                return Err(ClientError::Invalid(
                    "Klav's system project cannot be granted to an agent".into(),
                ));
            }
            let vault = self
                .vaults
                .get(&entry.vault)
                .ok_or_else(|| ClientError::NotFound(format!("vault {}", entry.vault)))?;
            let owner = vault.owner;
            let vault_name = vault.meta.name().to_owned();
            let ctx = ProjectContext {
                account: owner,
                vault: entry.vault,
                project,
            };
            projects.push(GrantedProject {
                vault_id: entry.vault,
                owner_account_id: owner,
                project_id: project,
                shared_key: Blob::new(share_project_key(public, &ctx, &entry.key)?),
                labels: Blob::new(agent::seal_grant_labels(
                    &entry.key,
                    &ctx,
                    id,
                    &serde_json::to_vec(&GrantLabels {
                        vault: vault_name,
                        project: entry.meta.name().to_owned(),
                    })
                    .map_err(|e| ClientError::Invalid(format!("grant labels: {e}")))?,
                )),
            });
        }
        Ok(projects)
    }

    /// Denies a pending registration.
    pub async fn deny_agent(&mut self, id: AgentId) -> ClientResult<()> {
        let res = self
            .authed(Method::POST, &format!("/v1/agents/{id}/deny"), &Body::Empty)
            .await?;
        crate::api::empty(res).await
    }

    /// Replaces vault and project names in the policy by IDs.
    pub(crate) fn resolve_policy(&self, mut policy: Policy) -> ClientResult<Policy> {
        for rule in &mut policy.rules {
            self.resolve_scope(&mut rule.scope)?;
        }
        Ok(policy)
    }

    fn resolve_scope(&self, scope: &mut Scope) -> ClientResult<()> {
        for selector in &mut scope.vaults {
            if let Selector::Name(name) = selector {
                *selector = Selector::Id(self.find_vault(name)?);
            }
        }
        for selector in &mut scope.projects {
            if let Selector::Name(name) = selector {
                *selector = Selector::Id(self.find_project_anywhere(name)?);
            }
        }
        Ok(())
    }

    /// A project by `vault/project`, or by a project name unique across
    /// vaults.
    pub fn find_project_anywhere(&self, wanted: &str) -> ClientResult<ProjectId> {
        if let Some((vault, project)) = wanted.split_once('/') {
            let vault = self.find_vault(vault)?;
            return self.find_project(vault, project);
        }
        let mut found = Vec::new();
        for vault in self.vaults().into_iter().filter(|v| !v.deleted) {
            if let Ok(project) = self.find_project(vault.id, wanted) {
                found.push(project);
            }
        }
        match found.as_slice() {
            [one] => Ok(*one),
            [] => Err(ClientError::NotFound(format!("project {wanted:?}"))),
            _ => Err(ClientError::Ambiguous(format!(
                "several vaults have a project {wanted:?}; write it as vault/project"
            ))),
        }
    }
}

/// Picks an agent by ID, unique ID prefix or unique name.
pub fn find_agent(agents: Vec<AgentView>, wanted: &str) -> ClientResult<AgentView> {
    if let Some(a) = agents.iter().find(|a| a.id.to_string() == wanted) {
        return Ok(a.clone());
    }
    let mut by_name: Vec<&AgentView> = agents
        .iter()
        .filter(|a| a.name.eq_ignore_ascii_case(wanted))
        .collect();
    // Prefer live registrations over old denied or revoked ones.
    if by_name.len() > 1 {
        let live: Vec<&AgentView> = by_name
            .iter()
            .copied()
            .filter(|a| matches!(a.status, AgentStatus::Pending | AgentStatus::Active))
            .collect();
        if !live.is_empty() {
            by_name = live;
        }
    }
    let by_prefix: Vec<&AgentView> = agents
        .iter()
        .filter(|a| wanted.len() >= 6 && a.id.to_string().starts_with(wanted))
        .collect();
    match (by_name.as_slice(), by_prefix.as_slice()) {
        ([one], _) | ([], [one]) => Ok((*one).clone()),
        ([], []) => Err(ClientError::NotFound(format!("agent {wanted:?}"))),
        _ => Err(ClientError::Ambiguous(format!(
            "several agents match {wanted:?}; use the agent ID"
        ))),
    }
}

/// An approval request as the person sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalView {
    /// ID.
    pub id: ApprovalId,
    /// State.
    pub status: ApprovalStatus,
    /// The agent.
    pub agent_id: AgentId,
    /// Its name.
    pub agent: String,
    /// What it wants to do.
    pub permission: Permission,
    /// The item (`klav://…`), or the project for `create`.
    pub target: String,
    /// The target's name for one-line texts such as the Touch ID prompt:
    /// the item's title, or `vault/project` without an item. `None` when
    /// this device does not have the item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_name: Option<String>,
    /// Why, in the agent's words.
    pub reason: String,
    /// Host it claims the value is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Asked at (Unix ms).
    pub created_at: i64,
    /// Decide before (Unix ms).
    pub expires_at: i64,
    /// Approved until (Unix ms; `0`: once).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_until: Option<i64>,
    /// The agent's running task this request falls outside of («Outside
    /// the task», ADR 0021 §6), if it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<crate::tasks::OutsideTask>,
    /// `SHA-256` (hex) of the exact request bytes this view was built from
    /// (ADR 0030 §5): deciding passes it back, and nothing is signed if
    /// the request changed in between.
    pub request_digest: String,
}

/// Picks an approval among `views` by ID or a unique ID prefix (6+
/// characters).
pub fn pick_approval(views: Vec<ApprovalView>, wanted: &str) -> ClientResult<ApprovalView> {
    let wanted = wanted.trim();
    let mut found: Vec<ApprovalView> = views
        .into_iter()
        .filter(|a| {
            let id = a.id.to_string();
            id == wanted || (wanted.len() >= 6 && id.starts_with(wanted))
        })
        .collect();
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(ClientError::NotFound(format!(
            "approval request {wanted:?}"
        ))),
        _ => Err(ClientError::Ambiguous(format!(
            "several approval requests start with {wanted:?}"
        ))),
    }
}

/// Refuses to sign `request` unless it is the one the person was shown
/// (ADR 0030 §5): `shown` is the digest the card carried.
pub(crate) fn check_shown(what: &str, request: &[u8], shown: &str) -> ClientResult<()> {
    if agent::shown_matches(request, shown) {
        Ok(())
    } else {
        Err(ClientError::Security(format!(
            "the {what} changed while you were looking at it: nothing was signed; open it again"
        )))
    }
}

impl Unlocked {
    pub(crate) fn approval_view(
        &self,
        info: &ApprovalInfo,
    ) -> ClientResult<(ApprovalView, ApprovalRequest)> {
        let request: ApprovalRequest = serde_json::from_slice(info.request.as_bytes())
            .map_err(|e| ClientError::Corrupt(format!("approval {}: {e}", info.id)))?;
        if request.approval_id != info.id || request.agent_id != info.agent_id {
            return Err(ClientError::Security(format!(
                "approval {} does not match its request",
                info.id
            )));
        }
        let project = self
            .projects
            .get(&request.project_id)
            .map(|p| p.meta.name().to_owned())
            .unwrap_or_else(|| request.project_id.to_string());
        let vault = self
            .vaults
            .get(&request.vault_id)
            .map(|v| v.meta.name().to_owned())
            .unwrap_or_else(|| request.vault_id.to_string());
        let (target, target_name) = match request.item_id {
            Some(item) => {
                let summary = self
                    .item_summary(crate::ItemLocation {
                        vault: request.vault_id,
                        project: request.project_id,
                        item,
                    })
                    .ok();
                match summary {
                    Some(s) => (s.reference, Some(s.title)),
                    None => (format!("item {item}"), None),
                }
            }
            None => {
                let place = format!("{vault}/{project}");
                (place.clone(), Some(place))
            }
        };
        Ok((
            ApprovalView {
                id: info.id,
                status: info.status,
                agent_id: request.agent_id,
                agent: request.agent_name.clone(),
                permission: request.permission,
                target,
                target_name,
                reason: request.reason.clone(),
                domain: request.claims.domain.clone(),
                created_at: info.created_at,
                expires_at: info.expires_at,
                lease_until: info.lease_until,
                task: None,
                request_digest: agent::request_digest(info.request.as_bytes()),
            },
            request,
        ))
    }

    /// Approval requests: pending ones (or all recent ones), newest first.
    pub async fn approvals(&mut self, all: bool) -> ClientResult<Vec<ApprovalView>> {
        let res = self
            .authed(Method::GET, "/v1/approvals", &Body::Empty)
            .await?;
        let list: ApprovalList = crate::api::json(res).await?;
        let views: Vec<(ApprovalView, ApprovalRequest)> = list
            .approvals
            .iter()
            .filter(|a| all || a.status == ApprovalStatus::Pending)
            .map(|a| self.approval_view(a))
            .collect::<ClientResult<_>>()?;
        let live = if views
            .iter()
            .any(|(v, _)| v.status == ApprovalStatus::Pending)
        {
            self.live_tasks().await?
        } else {
            Vec::new()
        };
        Ok(views
            .into_iter()
            .map(|(mut view, request)| {
                if view.status == ApprovalStatus::Pending {
                    view.task = self.outside_task(&live, &request);
                }
                view
            })
            .collect())
    }

    /// Finds a pending approval by ID or a unique ID prefix (6+ characters),
    /// as the person sees it (with the digest to decide on it).
    pub async fn find_approval(&mut self, wanted: &str) -> ClientResult<ApprovalView> {
        let pending = self.approvals(false).await?;
        pick_approval(pending, wanted)
    }

    /// Signs a decision on approval `id`: approve once (`lease = None`),
    /// approve for a while, or deny. `shown` is the
    /// [`ApprovalView::request_digest`] of the card the person decided on:
    /// if the request the server returns now is another, nothing is signed
    /// (ADR 0030 §5).
    pub async fn decide_approval(
        &mut self,
        id: ApprovalId,
        approve: bool,
        lease: Option<std::time::Duration>,
        shown: &str,
    ) -> ClientResult<ApprovalView> {
        self.decide_approval_in(id, approve, lease, shown, None)
            .await
    }

    /// [`Self::decide_approval`]; with `task`, «Add to the task»: the
    /// server binds the approval to that task (ADR 0021 §6).
    pub(crate) async fn decide_approval_in(
        &mut self,
        id: ApprovalId,
        approve: bool,
        lease: Option<std::time::Duration>,
        shown: &str,
        task: Option<klav_core::ids::TaskId>,
    ) -> ClientResult<ApprovalView> {
        let res = self
            .authed(Method::GET, &format!("/v1/approvals/{id}"), &Body::Empty)
            .await?;
        let info: ApprovalInfo = crate::api::json(res).await?;
        if info.id != id {
            return Err(ClientError::Security(format!(
                "the server answered with another approval than {id}"
            )));
        }
        check_shown("request", info.request.as_bytes(), shown)?;
        // Parse and check what the person is about to sign.
        self.approval_view(&info)?;
        let decided_at = now_ms();
        let lease_until = match (approve, lease) {
            (true, Some(d)) => decided_at + i64::try_from(d.as_millis()).unwrap_or(i64::MAX / 2),
            _ => 0,
        };
        let signature = agent::sign_approval(
            &self.identity,
            &agent::ApprovalToSign {
                approval: id,
                agent: info.agent_id,
                request: info.request.as_bytes(),
                approve,
                lease_until_ms: u64::try_from(lease_until).unwrap_or(0),
                decided_at_ms: u64::try_from(decided_at).unwrap_or(0),
            },
        );
        let decided: ApprovalInfo = self
            .send_json(
                Method::POST,
                &format!("/v1/approvals/{id}/decide"),
                &DecideApproval {
                    approve,
                    lease_until,
                    decided_at,
                    signature: Blob::new(signature.to_bytes().to_vec()),
                    task_id: task,
                },
            )
            .await?;
        self.approval_view(&decided).map(|(v, _)| v)
    }
}

/// Whether the account's proxy setting refuses a project grant for agent
/// `id` (ADR 0036 §2). Only a setting that reads and names it refuses; a
/// failed sync or an unreadable setting gives warnings instead, so every
/// other agent is approved exactly as before the setting existed.
pub(crate) fn proxy_check(
    id: AgentId,
    name: &str,
    synced: ClientResult<()>,
    setting: ClientResult<klav_core::model::preferences::Preferences>,
) -> ClientResult<Vec<String>> {
    let mut warnings = Vec::new();
    if let Err(e) = synced {
        warnings.push(format!(
            "could not sync before checking whether this agent is the account's credential proxy: {e}"
        ));
    }
    match setting {
        Ok(p) if p.proxy().agent_id == Some(id) => Err(ClientError::Invalid(format!(
            "agent {name:?} is the account's credential proxy: it gets credentials one by one with `klav proxy grant`, never whole projects"
        ))),
        Ok(_) => Ok(warnings),
        Err(e) => {
            warnings.push(format!(
                "could not check whether this agent is the account's credential proxy: {e}"
            ));
            Ok(warnings)
        }
    }
}

/// Where a new grant goes: its `version`, and the `v` of the grant it
/// replaces (`floor`; 1 for none).
#[derive(Debug, Clone, Copy)]
pub(crate) struct GrantSlot {
    pub(crate) version: u64,
    pub(crate) floor: u32,
}

#[cfg(test)]
mod tests {
    use klav_core::model::preferences::{Preferences, ProxySetting};

    use super::*;

    fn naming(id: AgentId) -> Preferences {
        Preferences {
            developer: None,
            proxy: Some(ProxySetting::own(id)),
        }
    }

    #[test]
    fn an_ordinary_agent_is_approved_when_the_setting_cannot_be_checked() {
        let me = AgentId::from_bytes([1; 16]);
        let proxy = AgentId::from_bytes([2; 16]);
        // As on main: approved, with no warning.
        assert!(
            proxy_check(me, "a", Ok(()), Ok(naming(proxy)))
                .unwrap()
                .is_empty()
        );
        assert!(
            proxy_check(me, "a", Ok(()), Ok(Preferences::default()))
                .unwrap()
                .is_empty()
        );
        // The sync failed: approved, with a warning.
        let w = proxy_check(
            me,
            "a",
            Err(ClientError::Network("down".into())),
            Ok(Preferences::default()),
        )
        .unwrap();
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("credential proxy"), "{w:?}");
        // The setting does not read (an unopenable system item, copies that
        // disagree): approved, with a warning.
        let w = proxy_check(
            me,
            "a",
            Err(ClientError::Network("down".into())),
            Err(ClientError::Invalid("copies disagree".into())),
        )
        .unwrap();
        assert_eq!(w.len(), 2);
        assert!(w[1].contains("could not check whether this agent"), "{w:?}");
    }

    #[test]
    fn the_proxy_a_readable_setting_names_is_refused_on_every_path() {
        let proxy = AgentId::from_bytes([1; 16]);
        for synced in [Ok(()), Err(ClientError::Network("down".into()))] {
            let err = proxy_check(proxy, "p", synced, Ok(naming(proxy))).unwrap_err();
            assert!(err.to_string().contains("klav proxy grant"), "{err}");
        }
    }
}
