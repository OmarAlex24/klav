//! Task requests as the person sees them (ADR 0021 §3–4, §8).
//!
//! The card never repeats what the agent said about an item: titles, user
//! names and hosts come from the person's own vault, and the client
//! completes the proposal (`totp` added to a `fill` on a login with TOTP, a
//! site that does not match left unchecked, what the policy denies struck
//! through) with [`klav_core::task::propose`]. Approving signs the exact
//! decision (spec §13.8) with the account identity; ending a task signs
//! `task-end`.

use std::collections::HashMap;

use klav_core::crypto::agent::{self, TaskDecisionToSign};
use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::ids::{AgentId, ApprovalId, ItemId, ProjectId, TaskId, VaultId};
use klav_core::model::{FieldKind, ItemKind};
use klav_core::policy::{self, Decision, Effect, Permission, Target};
use klav_core::task::TaskAccessDecision;
use klav_core::task::{self, ItemFacts, Proposal, TaskAccessRequest, TaskDecision, TaskRequest};
use klav_proto::Blob;
use klav_proto::agent::{ApprovalInfo, ApprovalRequest, ApprovalStatus};
use klav_proto::task::{DecideTask, EndTask, TaskEndedBy, TaskInfo, TaskList, TaskStatus};
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::agents::{ApprovalView, GrantView, check_shown};
use crate::api::Body;
use crate::audit::{LogFilter, LogLine, log_unreadable};
use crate::error::{ClientError, ClientResult};
use crate::session::{ItemLocation, Unlocked, now_ms};

/// Agents whose grant one task listing asks the server for.
const MAX_GRANT_LOOKUPS: usize = 64;

/// One permission on a task card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskCardPermission {
    /// The permission.
    pub permission: Permission,
    /// Checked: approved if the person leaves it (or approved, once decided).
    pub checked: bool,
    /// The agent asked for it.
    pub asked: bool,
    /// Added by Klav («Added by Klav»), not by the agent.
    pub added_by_klav: bool,
    /// The person's policy denies it: struck through, cannot be checked.
    pub denied_by_policy: bool,
    /// It checks the site and the item has none («No site», ADR 0030 §6):
    /// cannot be checked.
    #[serde(default)]
    pub no_site: bool,
    /// The grant says `ask once` for it (ADR 0032 §4.2): «Always asks for
    /// approval», unchecked, and it cannot be checked. Omitted when false,
    /// so the card's JSON stays what the apps read.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub always_asks: bool,
}

/// One item on a task card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskCardRow {
    /// Vault.
    pub vault_id: VaultId,
    /// Project.
    pub project_id: ProjectId,
    /// Item.
    pub item_id: ItemId,
    /// `klav://vault/project/item` from the vault, or `item <id>` when this
    /// device does not have it.
    pub reference: String,
    /// Title, from the vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// User name, from the vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// The item is not in the vault, is in the trash, or is outside the
    /// agent's grant: it cannot be approved.
    pub missing: bool,
    /// The host the agent gave, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked_domain: Option<String>,
    /// The agent's host matches none of the item's URLs («The site does not
    /// match the item»): the row is unchecked and cannot be checked (T92).
    pub domain_mismatch: bool,
    /// The item has no valid host and a permission on the row checks the
    /// site («No site», ADR 0030 §6).
    #[serde(default)]
    pub no_site: bool,
    /// `domains` is the host the agent asked for, on a card or an identity
    /// (no URL by nature): shown «according to the agent».
    #[serde(default)]
    pub domain_claimed: bool,
    /// The hosts that are (or will be) approved.
    pub domains: Vec<String>,
    /// Permissions, in order.
    pub permissions: Vec<TaskCardPermission>,
}

/// A task as the person sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskCard {
    /// ID.
    pub id: TaskId,
    /// State.
    pub status: TaskStatus,
    /// The agent.
    pub agent_id: AgentId,
    /// Its name.
    pub agent: String,
    /// Title, in the agent's words (the person's, if [`Self::offered`]).
    pub task: String,
    /// Why, in the agent's words (the person's, if [`Self::offered`]).
    pub reason: String,
    /// Offered by the person, without a request from the agent (ADR 0022
    /// §6).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub offered: bool,
    /// Requested duration (seconds), counted from the approval.
    pub duration_secs: u64,
    /// Asked at (Unix ms).
    pub created_at: i64,
    /// Decide before (Unix ms).
    pub decide_by: i64,
    /// Decided at (Unix ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<i64>,
    /// Revision of the decision in force (0 while pending).
    pub revision: u64,
    /// When an approved task ends (Unix ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// When it ended (Unix ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<i64>,
    /// Who ended it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_by: Option<TaskEndedBy>,
    /// One row per item: the proposal while pending, what was approved
    /// (and what was left out, unchecked) once decided.
    pub rows: Vec<TaskCardRow>,
    /// `SHA-256` (hex) of the exact request bytes this card was built from
    /// (ADR 0030 §5): deciding passes it back, and nothing is signed if
    /// the request changed in between.
    pub request_digest: String,
}

impl TaskCard {
    /// Whether the person can still approve or deny it.
    pub fn is_pending(&self) -> bool {
        self.status == TaskStatus::Pending
    }

    /// Whether it is running.
    pub fn is_live(&self) -> bool {
        self.status == TaskStatus::Approved
    }

    /// How many items approving with `choice` would give access to: the
    /// rows left with a permission checked, by the same rules as
    /// [`Unlocked::decide_task`] (a checked box the rules refuse stays
    /// unchecked). Only a count for the Touch ID prompt: deciding still
    /// checks the choice.
    #[must_use]
    pub fn approved_items(&self, choice: &TaskChoice) -> usize {
        let mut rows: Vec<task::ProposalRow> =
            self.rows.iter().map(TaskCardRow::proposal).collect();
        for (marks, checked) in [(&choice.with, true), (&choice.without, false)] {
            for (item, permission) in marks {
                if let Some(row) = rows.iter_mut().find(|r| r.item_id == *item) {
                    row.set(*permission, checked);
                }
            }
        }
        rows.iter()
            .filter(|r| !r.missing && r.any_checked())
            .count()
    }
}

impl TaskCardRow {
    /// The row as `klav-core` checks it.
    fn proposal(&self) -> task::ProposalRow {
        task::ProposalRow {
            vault_id: self.vault_id,
            project_id: self.project_id,
            item_id: self.item_id,
            missing: self.missing,
            domain_mismatch: self.domain_mismatch,
            no_site: self.no_site,
            domain_claimed: self.domain_claimed,
            domains: self.domains.clone(),
            permissions: self
                .permissions
                .iter()
                .map(|p| task::ProposedPermission {
                    permission: p.permission,
                    checked: p.checked,
                    added_by_klav: p.added_by_klav,
                    denied_by_policy: p.denied_by_policy,
                    no_site: p.no_site,
                    always_asks: p.always_asks,
                })
                .collect(),
        }
    }
}

/// What the person changed on the card before approving.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskChoice {
    /// Unchecked: a whole item (`None`) or one of its permissions.
    #[serde(default)]
    pub without: Vec<(ItemId, Option<Permission>)>,
    /// Checked by hand: what Klav offered unchecked (a `passkey`). Never
    /// what the policy denies, a permission without a site or a row whose
    /// site does not match (T92).
    #[serde(default)]
    pub with: Vec<(ItemId, Option<Permission>)>,
    /// A shorter duration (seconds); never longer than requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_secs: Option<u64>,
}

/// `klav log --task` (ADR 0021 §9): the task, its events and what the
/// agent got approved outside it while it ran.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskLog {
    /// The task.
    pub task_id: TaskId,
    /// Its card, while the server still lists it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<TaskCard>,
    /// Its events, oldest first: requested, decided (and each revision),
    /// every use, ended.
    pub events: Vec<LogLine>,
    /// The agent's requests and uses with an approval of their own while
    /// the task ran («Outside the task»), oldest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outside: Vec<LogLine>,
    /// In a task with `rotate` (ADR 0022 §6): each site, changed, pending
    /// or failed according to its `rotate.*` events.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sites: Vec<crate::offer::SiteProgress>,
    /// Why there are no events: the audit log could not be read as this
    /// device holds it (ADR 0033 §8.4). The card still comes from the
    /// server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_warning: Option<String>,
}

/// The running task an approval request falls outside of (ADR 0021 §6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutsideTask {
    /// The task.
    pub id: TaskId,
    /// Its title, in the agent's words.
    pub task: String,
    /// When it ends (Unix ms).
    pub expires_at: i64,
    /// «Add to the task» is offered: a permission a task can hold (`fill`,
    /// `totp`, `inject`, `update`) on an item, and for `fill` a site that
    /// matches the item. `reveal` and `delete` only get «Approve once».
    pub can_add: bool,
}

/// A running task with its verified decision.
pub(crate) struct LiveTask {
    info: TaskInfo,
    title: String,
    decision: TaskDecision,
}

/// The hosts of an item's URLs, normalized and deduplicated.
pub(crate) fn hosts_of(urls: &[String]) -> Vec<String> {
    let mut hosts = Vec::new();
    for host in urls.iter().filter_map(|u| klav_core::site::item_host(u)) {
        if let Some(host) = policy::normalize_host(&host)
            && !hosts.contains(&host)
        {
            hosts.push(host);
        }
    }
    hosts
}

/// A card or an identity: no URL by nature (ADR 0030 §6).
fn is_siteless(kind: ItemKind) -> bool {
    matches!(kind, ItemKind::Card | ItemKind::Identity)
}

/// What the person's vault says about an item, for the proposal: only
/// the sites the person confirmed count (ADR 0030 §7).
pub(crate) fn facts_of(item: &klav_core::model::Item, summary: &crate::ItemSummary) -> ItemFacts {
    let has = |kind: FieldKind| {
        item.fields()
            .iter()
            .any(|f| f.kind() == kind && !f.is_empty())
    };
    ItemFacts {
        is_login: item.kind() == ItemKind::Login,
        siteless: is_siteless(item.kind()),
        urls: summary.confirmed_urls.clone(),
        pending_urls: summary.pending_urls.clone(),
        has_totp: has(FieldKind::Totp),
        has_password: has(FieldKind::Password),
        has_passkey: item.passkey().is_some(),
    }
}

fn signature(blob: &Blob, what: &str) -> ClientResult<Signature> {
    let bytes: [u8; SIGNATURE_LEN] = blob
        .as_bytes()
        .try_into()
        .map_err(|_| ClientError::Corrupt(format!("{what}: signature length")))?;
    Ok(Signature::from_bytes(bytes))
}

/// Parses the stored request of `info` and checks it belongs to the task.
/// An offered task (ADR 0022 §6) has no request: see [`request_of`].
pub fn parse_request(info: &TaskInfo) -> ClientResult<TaskRequest> {
    let request: TaskRequest = serde_json::from_slice(info.request.as_bytes())
        .map_err(|e| ClientError::Corrupt(format!("task {}: request: {e}", info.id)))?;
    request
        .validate()
        .map_err(|e| ClientError::Corrupt(format!("task {}: request: {e}", info.id)))?;
    Ok(request)
}

/// The request of `info`, or, for a task the person offered (empty request,
/// ADR 0022 §6), the one its verified `decision` stands for: the person's
/// title and reason, and no accesses.
pub fn request_of(info: &TaskInfo, decision: Option<&TaskDecision>) -> ClientResult<TaskRequest> {
    if !info.request.as_bytes().is_empty() {
        return parse_request(info);
    }
    decision
        .zip(info.decided_at)
        .and_then(|(d, at)| d.offered_request(u64::try_from(at).unwrap_or(0)))
        .ok_or_else(|| {
            ClientError::Corrupt(format!(
                "task {}: no request and no offer signed by the person",
                info.id
            ))
        })
}

/// Verifies the account's signature on the decision of `info` and
/// parses it (`None` while pending or expired undecided).
pub(crate) fn verify_decision(
    account: &PublicIdentity,
    info: &TaskInfo,
) -> ClientResult<Option<TaskDecision>> {
    let (Some(decision), Some(sig), Some(decided_at)) =
        (&info.decision, &info.signature, info.decided_at)
    else {
        return Ok(None);
    };
    let parsed: TaskDecision = serde_json::from_slice(decision.as_bytes())
        .map_err(|e| ClientError::Corrupt(format!("task {}: decision: {e}", info.id)))?;
    let approve = !parsed.access.is_empty();
    agent::verify_task_decision(
        account,
        &TaskDecisionToSign {
            task: info.id,
            agent: info.agent_id,
            request: info.request.as_bytes(),
            decision: decision.as_bytes(),
            approve,
            decided_at_ms: u64::try_from(decided_at).unwrap_or(0),
        },
        &signature(sig, "task decision")?,
    )
    .map_err(|_| {
        ClientError::Security(format!(
            "the decision of task {} is not signed by this account; the server may have altered it",
            info.id
        ))
    })?;
    if parsed.task_id != info.id
        || parsed.agent_id != info.agent_id
        || parsed.revision != info.revision
    {
        return Err(ClientError::Security(format!(
            "the decision of task {} names another task, agent or revision",
            info.id
        )));
    }
    parsed
        .validate(approve)
        .map_err(|e| ClientError::Corrupt(format!("task {}: decision: {e}", info.id)))?;
    // No request: the person offered it (ADR 0022 §6), and the decision
    // carries their title and reason.
    if info.request.as_bytes().is_empty() {
        let offered = if parsed.revision == 1 {
            parsed
                .check_offered(u64::try_from(decided_at).unwrap_or(0))
                .is_ok()
        } else {
            parsed.offer.is_some()
        };
        if !approve || !offered {
            return Err(ClientError::Security(format!(
                "task {} has no request and its decision is not an offer",
                info.id
            )));
        }
    }
    Ok(Some(parsed))
}

/// Finds a task among `cards` by ID or a unique prefix (6+ characters).
pub fn find_task<'a>(cards: &'a [TaskCard], wanted: &str) -> ClientResult<&'a TaskCard> {
    let wanted = wanted.trim();
    let found: Vec<&TaskCard> = cards
        .iter()
        .filter(|c| {
            let id = c.id.to_string();
            id == wanted || (wanted.len() >= 6 && id.starts_with(wanted))
        })
        .collect();
    match found.as_slice() {
        [one] => Ok(one),
        [] => Err(ClientError::NotFound(format!("task {wanted:?}"))),
        _ => Err(ClientError::Ambiguous(format!(
            "several tasks start with {wanted:?}; use more of the ID"
        ))),
    }
}

impl Unlocked {
    /// Verifies the account's signature on the decision of `info` and
    /// parses it (`None` while pending or expired undecided).
    fn verified_decision(&self, info: &TaskInfo) -> ClientResult<Option<TaskDecision>> {
        verify_decision(self.identity.public(), info)
    }

    /// The vault's facts about a requested item, if it is there, not in
    /// the trash, and in a project of the agent's grant.
    fn task_item_facts(&self, asked: &TaskAccessRequest, grant: &GrantView) -> Option<ItemFacts> {
        if !grant
            .projects
            .iter()
            .any(|p| p.project_id == asked.project_id && p.vault_id == asked.vault_id)
        {
            return None;
        }
        let loc = ItemLocation {
            vault: asked.vault_id,
            project: asked.project_id,
            item: asked.item_id,
        };
        let summary = self.item_summary(loc).ok()?;
        if summary.trashed || summary.project_id != asked.project_id {
            return None;
        }
        self.open_item(loc)
            .ok()
            .map(|item| facts_of(&item, &summary))
    }

    /// The grant policy's decision for `permission` on a requested item.
    /// Its `once` also says, without trusting the claims, whether the target
    /// may always ask ([`policy::Policy::may_require_once`], ADR 0032 §4.2):
    /// such a target never goes in a task.
    pub(crate) fn task_effect(
        &self,
        grant: &GrantView,
        asked: &TaskAccessRequest,
        permission: Permission,
        domain: Option<&str>,
    ) -> Decision {
        let loc = ItemLocation {
            vault: asked.vault_id,
            project: asked.project_id,
            item: asked.item_id,
        };
        let Ok(summary) = self.item_summary(loc) else {
            return Decision {
                effect: Effect::Deny,
                reason: policy::Reason::OutOfScope,
                once: false,
            };
        };
        let request = policy::Request {
            permission,
            vault: Target {
                id: summary.vault_id,
                name: summary.vault,
            },
            project: Target {
                id: summary.project_id,
                name: summary.project,
            },
            tags: summary.tags,
            domain: domain.map(str::to_owned),
            item: Some(loc.item),
            method: None,
            path: None,
            mcp_tool: None,
            now: u64::try_from(now_ms() / 1000).unwrap_or(0),
        };
        let decision = policy::evaluate(&grant.policy, &request);
        Decision {
            once: grant.policy.may_require_once(&request),
            ..decision
        }
    }

    /// The proposal for a pending request (ADR 0021 §3), against the
    /// agent's current grant.
    fn proposal(&self, request: &TaskRequest, grant: Option<&GrantView>) -> Proposal {
        match grant {
            Some(grant) => task::propose(
                request,
                |asked| self.task_item_facts(asked, grant),
                |asked, permission, domain| self.task_effect(grant, asked, permission, domain),
            ),
            None => task::propose(
                request,
                |_| None,
                |_, _, _| Decision {
                    effect: Effect::Deny,
                    reason: policy::Reason::OutOfScope,
                    once: false,
                },
            ),
        }
    }

    fn row_names(&self, vault: VaultId, project: ProjectId, item: ItemId) -> TaskCardRow {
        let summary = self
            .item_summary(ItemLocation {
                vault,
                project,
                item,
            })
            .ok();
        TaskCardRow {
            vault_id: vault,
            project_id: project,
            item_id: item,
            reference: summary
                .as_ref()
                .map_or_else(|| format!("item {item}"), |s| s.reference.clone()),
            title: summary.as_ref().map(|s| s.title.clone()),
            username: summary.as_ref().and_then(|s| s.username.clone()),
            missing: false,
            asked_domain: None,
            domain_mismatch: false,
            no_site: false,
            domain_claimed: false,
            domains: Vec::new(),
            permissions: Vec::new(),
        }
    }

    fn proposal_rows(&self, request: &TaskRequest, proposal: &Proposal) -> Vec<TaskCardRow> {
        proposal
            .rows
            .iter()
            .map(|row| {
                let asked = request.access_for(row.item_id);
                let mut card = self.row_names(row.vault_id, row.project_id, row.item_id);
                card.missing = row.missing;
                card.asked_domain = asked.and_then(|a| a.domain.clone());
                card.domain_mismatch = row.domain_mismatch;
                card.no_site = row.no_site;
                card.domain_claimed = row.domain_claimed;
                card.domains.clone_from(&row.domains);
                card.permissions = row
                    .permissions
                    .iter()
                    .map(|p| TaskCardPermission {
                        permission: p.permission,
                        checked: p.checked,
                        asked: asked.is_some_and(|a| a.permissions.contains(&p.permission)),
                        added_by_klav: p.added_by_klav,
                        denied_by_policy: p.denied_by_policy,
                        no_site: p.no_site,
                        always_asks: p.always_asks,
                    })
                    .collect();
                card
            })
            .collect()
    }

    fn decision_rows(&self, request: &TaskRequest, decision: &TaskDecision) -> Vec<TaskCardRow> {
        let mut rows: Vec<TaskCardRow> = decision
            .access
            .iter()
            .map(|a| {
                let asked = request.access_for(a.item_id);
                let mut card = self.row_names(a.vault_id, a.project_id, a.item_id);
                card.asked_domain = asked.and_then(|r| r.domain.clone());
                card.domains.clone_from(&a.domains);
                card.domain_claimed = self.siteless_item(a.vault_id, a.project_id, a.item_id);
                card.permissions = a
                    .permissions
                    .iter()
                    .map(|&permission| TaskCardPermission {
                        permission,
                        checked: true,
                        asked: asked.is_some_and(|r| r.permissions.contains(&permission)),
                        added_by_klav: a.added_by_klav.contains(&permission),
                        denied_by_policy: false,
                        no_site: false,
                        always_asks: false,
                    })
                    .collect();
                card
            })
            .collect();
        // What the agent asked for and the person left out.
        for removed in decision.removed_from(request) {
            let row = match rows.iter_mut().find(|r| r.item_id == removed.item_id) {
                Some(row) => row,
                None => {
                    let mut card =
                        self.row_names(removed.vault_id, removed.project_id, removed.item_id);
                    card.asked_domain.clone_from(&removed.domain);
                    rows.push(card);
                    rows.last_mut().expect("just pushed")
                }
            };
            for permission in removed.permissions {
                row.permissions.push(TaskCardPermission {
                    permission,
                    checked: false,
                    asked: true,
                    added_by_klav: false,
                    denied_by_policy: false,
                    no_site: false,
                    always_asks: false,
                });
            }
        }
        rows
    }

    pub(crate) async fn grant_of(&mut self, agent: AgentId) -> ClientResult<Option<GrantView>> {
        let info = self.agent_info(agent).await?;
        Ok(self.view(info)?.grant)
    }

    pub(crate) async fn card(&mut self, info: &TaskInfo) -> ClientResult<TaskCard> {
        self.card_with(info, &mut HashMap::new()).await
    }

    /// [`Self::card`], asking the server for each agent's grant once per
    /// listing (`grants`), not once per task.
    async fn card_with(
        &mut self,
        info: &TaskInfo,
        grants: &mut HashMap<AgentId, Option<GrantView>>,
    ) -> ClientResult<TaskCard> {
        let decision = self.verified_decision(info)?;
        let request = request_of(info, decision.as_ref())?;
        let rows = match (&decision, info.status) {
            (Some(decision), _) => self.decision_rows(&request, decision),
            (None, TaskStatus::Pending) => {
                let grant = match grants.get(&info.agent_id) {
                    Some(g) => g.clone(),
                    None => {
                        // A hostile server must not turn one listing into
                        // thousands of requests.
                        if grants.len() >= MAX_GRANT_LOOKUPS {
                            return Err(ClientError::Security(format!(
                                "the server lists pending tasks of more than \
                                 {MAX_GRANT_LOOKUPS} agents"
                            )));
                        }
                        let g = self.grant_of(info.agent_id).await?;
                        grants.insert(info.agent_id, g.clone());
                        g
                    }
                };
                let proposal = self.proposal(&request, grant.as_ref());
                self.proposal_rows(&request, &proposal)
            }
            (None, _) => {
                let proposal = self.proposal(&request, None);
                let mut rows = self.proposal_rows(&request, &proposal);
                for row in &mut rows {
                    row.missing = false;
                }
                rows
            }
        };
        Ok(TaskCard {
            id: info.id,
            status: info.status,
            agent_id: info.agent_id,
            agent: info.agent_name.clone(),
            task: request.task,
            reason: request.reason,
            offered: info.request.as_bytes().is_empty(),
            duration_secs: request.duration_secs,
            created_at: info.created_at,
            decide_by: info.decide_by,
            decided_at: info.decided_at,
            revision: info.revision,
            expires_at: info.expires_at,
            ended_at: info.ended_at,
            ended_by: info.ended_by,
            rows,
            request_digest: agent::request_digest(info.request.as_bytes()),
        })
    }

    pub(crate) async fn task_info(&mut self, id: TaskId) -> ClientResult<TaskInfo> {
        let res = self
            .authed(Method::GET, &format!("/v1/tasks/{id}"), &Body::Empty)
            .await?;
        crate::api::json(res).await
    }

    /// The account's tasks, newest first: pending and running ones, or all
    /// recent ones.
    pub async fn tasks(&mut self, all: bool) -> ClientResult<Vec<TaskCard>> {
        let res = self.authed(Method::GET, "/v1/tasks", &Body::Empty).await?;
        let list: TaskList = crate::api::json(res).await?;
        let shown: Vec<&TaskInfo> = list
            .tasks
            .iter()
            .filter(|t| all || matches!(t.status, TaskStatus::Pending | TaskStatus::Approved))
            .collect();
        let mut grants = HashMap::new();
        let mut cards = Vec::new();
        for info in shown {
            cards.push(self.card_with(info, &mut grants).await?);
        }
        Ok(cards)
    }

    /// One task, by ID or a unique ID prefix (6+ characters).
    pub async fn task(&mut self, wanted: &str) -> ClientResult<TaskCard> {
        let cards = self.tasks(true).await?;
        find_task(&cards, wanted).cloned()
    }

    /// The proposal for pending task `id` with the person's changes.
    fn chosen(
        &self,
        request: &TaskRequest,
        grant: Option<&GrantView>,
        choice: &TaskChoice,
    ) -> ClientResult<Proposal> {
        let mut proposal = self.proposal(request, grant);
        for (item, permission) in &choice.with {
            let row = proposal
                .row_mut(*item)
                .ok_or_else(|| ClientError::NotFound(format!("item {item} in the task")))?;
            if row.missing {
                return Err(ClientError::Invalid(format!(
                    "item {item} is not in the vault or not in the agent's grant"
                )));
            }
            if row.domain_mismatch {
                return Err(ClientError::Denied(format!(
                    "the site the agent gave does not match item {item}: it cannot be approved"
                )));
            }
            if let Some(p) = permission
                && row
                    .permissions
                    .iter()
                    .any(|x| x.permission == *p && x.no_site)
            {
                return Err(ClientError::Denied(format!(
                    "item {item} has no site: `{p}` cannot go in a task without one"
                )));
            }
            if let Some(p) = permission
                && !row.permissions.iter().any(|x| x.permission == *p)
            {
                return Err(ClientError::Invalid(format!(
                    "`{p}` is not on the card for item {item}"
                )));
            }
            if let Some(p) = permission
                && row
                    .permissions
                    .iter()
                    .any(|x| x.permission == *p && x.always_asks)
            {
                return Err(ClientError::Denied(format!(
                    "`{p}` on item {item} always asks for approval (a protected environment or an item it uses): it cannot go in a task"
                )));
            }
            if let Some(p) = permission
                && row
                    .permissions
                    .iter()
                    .any(|x| x.permission == *p && x.denied_by_policy)
            {
                return Err(ClientError::Denied(format!(
                    "your policy denies `{p}` on item {item}: a task never widens a deny rule"
                )));
            }
            row.set(*permission, true);
        }
        for (item, permission) in &choice.without {
            let row = proposal
                .row_mut(*item)
                .ok_or_else(|| ClientError::NotFound(format!("item {item} in the task")))?;
            if let Some(p) = permission
                && !row.permissions.iter().any(|x| x.permission == *p)
            {
                return Err(ClientError::Invalid(format!(
                    "`{p}` is not on the card for item {item}"
                )));
            }
            row.set(*permission, false);
        }
        Ok(proposal)
    }

    /// Approves (with the person's changes) or denies pending task `id`,
    /// and signs the decision (spec §13.8). `shown` is the
    /// [`TaskCard::request_digest`] of the card the person decided on: if
    /// the request the server returns now is another, nothing is signed
    /// (ADR 0030 §5).
    pub async fn decide_task(
        &mut self,
        id: TaskId,
        approve: bool,
        choice: &TaskChoice,
        shown: &str,
    ) -> ClientResult<TaskCard> {
        let info = self.task_info(id).await?;
        if info.id != id {
            return Err(ClientError::Security(format!(
                "the server answered with another task than {id}"
            )));
        }
        check_shown("task", info.request.as_bytes(), shown)?;
        if info.status != TaskStatus::Pending {
            return Err(ClientError::Invalid(format!(
                "task {id} is {}, not pending",
                info.status.as_str()
            )));
        }
        let request = parse_request(&info)?;
        let decided_at = now_ms();
        let decided_at_ms = u64::try_from(decided_at).unwrap_or(0);
        let decision = if approve {
            if choice
                .for_secs
                .is_some_and(|s| s < task::MIN_TASK_DURATION_SECS)
            {
                return Err(ClientError::Invalid(
                    "a task lasts at least 5 minutes".into(),
                ));
            }
            let grant = self.grant_of(info.agent_id).await?.ok_or_else(|| {
                ClientError::Denied(format!("agent {} has no grant", info.agent_name))
            })?;
            let proposal = self.chosen(&request, Some(&grant), choice)?;
            if !proposal.any_checked() {
                return Err(ClientError::Invalid(
                    "nothing left to approve: deny the task instead".into(),
                ));
            }
            let expires = task::expiry(decided_at_ms, request.duration_secs, choice.for_secs);
            let decision = proposal.decision(id, info.agent_id, expires);
            decision
                .check_first(&request, decided_at_ms)
                .map_err(|e| ClientError::Invalid(e.to_string()))?;
            decision
        } else {
            task::denial(id, info.agent_id)
        };
        let bytes = serde_json::to_vec(&decision)
            .map_err(|e| ClientError::Invalid(format!("decision: {e}")))?;
        let signature = agent::sign_task_decision(
            &self.identity,
            &TaskDecisionToSign {
                task: id,
                agent: info.agent_id,
                request: info.request.as_bytes(),
                decision: &bytes,
                approve,
                decided_at_ms,
            },
        );
        let decided: TaskInfo = self
            .send_json(
                Method::POST,
                &format!("/v1/tasks/{id}/decide"),
                &DecideTask {
                    approve,
                    decision: Blob::new(bytes),
                    decided_at,
                    signature: Blob::new(signature.to_bytes().to_vec()),
                },
            )
            .await?;
        self.card(&decided).await
    }

    /// The audit summary of a task (ID or unique prefix), `klav log --task`.
    /// A log that does not check out ([`ClientError::Security`]) leaves the
    /// card the server lists, with no events and
    /// [`TaskLog::log_warning`] saying why.
    pub async fn task_log(&mut self, wanted: &str) -> ClientResult<TaskLog> {
        let mut events = match self
            .audit_log(&LogFilter {
                task: Some(wanted.to_owned()),
                ..LogFilter::default()
            })
            .await
        {
            Ok(events) => events,
            Err(e @ ClientError::Security(_)) => return self.task_log_without_log(wanted, e).await,
            Err(e) => return Err(e),
        };
        events.reverse();
        let task_id = events
            .iter()
            .find_map(|l| l.task_id)
            .ok_or_else(|| ClientError::NotFound(format!("task {wanted:?} in the audit log")))?;
        let (card, decision) = match self.task_info(task_id).await.ok() {
            Some(info) => (
                Some(self.card(&info).await?),
                self.verified_decision(&info)?,
            ),
            None => (None, None),
        };
        let sites = self.sites_of(card.as_ref(), decision.as_ref(), &events);
        let agent = events.iter().find_map(|l| l.agent_id);
        let started = events
            .iter()
            .find(|l| l.action == "task.decided")
            .map(|l| l.at);
        let ended = events
            .iter()
            .rev()
            .find(|l| l.action == "task.ended")
            .map(|l| l.at);
        let mut log_warning = None;
        let outside = match (agent, started) {
            (Some(agent), Some(since)) => {
                match self
                    .audit_log(&LogFilter {
                        agent: Some(agent.to_string()),
                        since: Some(since),
                        until: ended,
                        ..LogFilter::default()
                    })
                    .await
                {
                    Ok(mut lines) => {
                        lines.retain(|l| {
                            l.task_id.is_none()
                                && l.approval_id.is_some()
                                && l.action.starts_with("agent.")
                        });
                        lines.reverse();
                        lines
                    }
                    Err(e @ ClientError::Security(_)) => {
                        log_warning = Some(log_unreadable(
                            "The task's events are shown, but not what it asked for outside it,",
                            &e,
                        ));
                        Vec::new()
                    }
                    Err(e) => return Err(e),
                }
            }
            _ => Vec::new(),
        };
        Ok(TaskLog {
            task_id,
            card,
            events,
            outside,
            sites,
            log_warning,
        })
    }

    /// [`Self::task_log`] when the log does not check out (`why`): the
    /// card of the task the server lists, and no events. A task the server
    /// does not list either fails with `why`.
    async fn task_log_without_log(
        &mut self,
        wanted: &str,
        why: ClientError,
    ) -> ClientResult<TaskLog> {
        let Ok(card) = self.task(wanted).await else {
            return Err(why);
        };
        Ok(TaskLog {
            task_id: card.id,
            card: Some(card),
            events: Vec::new(),
            outside: Vec::new(),
            sites: Vec::new(),
            log_warning: Some(log_unreadable("The task is shown", &why)),
        })
    }

    /// The account's running tasks, newest first, with their decisions
    /// verified.
    pub(crate) async fn live_tasks(&mut self) -> ClientResult<Vec<LiveTask>> {
        let res = self.authed(Method::GET, "/v1/tasks", &Body::Empty).await?;
        let list: TaskList = crate::api::json(res).await?;
        let now = now_ms();
        let mut live = Vec::new();
        for info in list.tasks {
            if info.status != TaskStatus::Approved || info.expires_at.is_none_or(|e| e <= now) {
                continue;
            }
            if let Some(decision) = self.verified_decision(&info)? {
                let request = request_of(&info, Some(&decision))?;
                live.push(LiveTask {
                    title: request.task,
                    decision,
                    info,
                });
            }
        }
        Ok(live)
    }

    /// Whether `request` can be added to `task` (ADR 0021 §2, §6).
    fn addable(&self, request: &ApprovalRequest) -> bool {
        let Some(item) = request.item_id else {
            return false;
        };
        if !matches!(
            request.permission,
            Permission::Fill | Permission::Totp | Permission::Inject | Permission::Update
        ) {
            return false;
        }
        if !request.permission.checks_domain() {
            return true;
        }
        let Ok(summary) = self.item_summary(ItemLocation {
            vault: request.vault_id,
            project: request.project_id,
            item,
        }) else {
            return false;
        };
        // ADR 0030 §6: never without a site. A card or an identity is tied
        // to the host the agent named; anything else must have it among
        // its own hosts.
        let hosts = hosts_of(&summary.confirmed_urls);
        match request.claims.domain.as_deref() {
            None => false,
            Some(_) if hosts.is_empty() => is_siteless(summary.kind),
            Some(domain) => klav_core::site::host_matches(domain, &summary.confirmed_urls),
        }
    }

    /// Whether the item has no URL by nature (a card, an identity).
    fn siteless_item(&self, vault: VaultId, project: ProjectId, item: ItemId) -> bool {
        self.item_summary(ItemLocation {
            vault,
            project,
            item,
        })
        .is_ok_and(|s| is_siteless(s.kind))
    }

    /// The newest running task of the agent that asked, for «Outside the
    /// task».
    pub(crate) fn outside_task(
        &self,
        live: &[LiveTask],
        request: &ApprovalRequest,
    ) -> Option<OutsideTask> {
        let task = live.iter().find(|t| t.info.agent_id == request.agent_id)?;
        Some(OutsideTask {
            id: task.info.id,
            task: task.title.clone(),
            expires_at: task.info.expires_at.unwrap_or(0),
            can_add: self.addable(request),
        })
    }

    /// «Add to the task» (ADR 0021 §6): signs the next revision of the
    /// agent's running task with this request's item, permission and site
    /// (same expiry), then approves the request once so the agent's
    /// waiting `approval wait` wakes and its retry goes through. `shown` is
    /// the [`ApprovalView::request_digest`] of the card the person decided
    /// on (ADR 0030 §5).
    pub async fn add_to_task(
        &mut self,
        approval: ApprovalId,
        shown: &str,
    ) -> ClientResult<TaskCard> {
        let res = self
            .authed(
                Method::GET,
                &format!("/v1/approvals/{approval}"),
                &Body::Empty,
            )
            .await?;
        let info: ApprovalInfo = crate::api::json(res).await?;
        if info.id != approval {
            return Err(ClientError::Security(format!(
                "the server answered with another approval than {approval}"
            )));
        }
        check_shown("request", info.request.as_bytes(), shown)?;
        if info.status != ApprovalStatus::Pending {
            return Err(ClientError::Invalid(format!(
                "request {approval} is {}, not pending",
                info.status.as_str()
            )));
        }
        let (view, request) = self.approval_view(&info)?;
        crate::agents::refuse_security_card(&view)?;
        let live = self.live_tasks().await?;
        let outside = self.outside_task(&live, &request).ok_or_else(|| {
            ClientError::Invalid(format!(
                "{} has no running task to add this to: approve it once instead",
                request.agent_name
            ))
        })?;
        if !outside.can_add {
            return Err(ClientError::Invalid(format!(
                "`{}` cannot go in a task here: approve it once or deny it",
                request.permission
            )));
        }
        let task = live
            .into_iter()
            .find(|t| t.info.id == outside.id)
            .ok_or_else(|| ClientError::NotFound(format!("task {}", outside.id)))?;
        let item = request
            .item_id
            .ok_or_else(|| ClientError::Invalid("the request has no item".into()))?;
        let previous = task.decision;
        let mut next = previous.clone();
        next.revision = previous.revision + 1;
        let domain = request
            .claims
            .domain
            .as_deref()
            .and_then(policy::normalize_host);
        match next.access.iter_mut().find(|a| a.item_id == item) {
            Some(row) => {
                if row.vault_id != request.vault_id || row.project_id != request.project_id {
                    return Err(ClientError::Security(
                        "the request names the item in another project than the task".into(),
                    ));
                }
                if !row.permissions.contains(&request.permission) {
                    row.permissions.push(request.permission);
                }
                if let Some(host) = &domain
                    && !row.allows(request.permission, Some(host))
                {
                    row.domains.push(host.clone());
                }
            }
            None => {
                let summary = self.item_summary(ItemLocation {
                    vault: request.vault_id,
                    project: request.project_id,
                    item,
                })?;
                let mut domains = hosts_of(&summary.confirmed_urls);
                if let Some(host) = &domain
                    && request.permission.checks_domain()
                    && domains.is_empty()
                    && is_siteless(summary.kind)
                {
                    domains.push(host.clone());
                }
                next.access.push(TaskAccessDecision {
                    vault_id: request.vault_id,
                    project_id: request.project_id,
                    item_id: item,
                    permissions: vec![request.permission],
                    domains,
                    added_by_klav: Vec::new(),
                });
            }
        }
        next.validate(true)
            .and_then(|()| next.check_extends(&previous))
            .map_err(|e| ClientError::Invalid(e.to_string()))?;
        let bytes = serde_json::to_vec(&next)
            .map_err(|e| ClientError::Invalid(format!("decision: {e}")))?;
        let decided_at = now_ms();
        let signature = agent::sign_task_decision(
            &self.identity,
            &TaskDecisionToSign {
                task: task.info.id,
                agent: task.info.agent_id,
                request: task.info.request.as_bytes(),
                decision: &bytes,
                approve: true,
                decided_at_ms: u64::try_from(decided_at).unwrap_or(0),
            },
        );
        let revised: TaskInfo = self
            .send_json(
                Method::POST,
                &format!("/v1/tasks/{}/decide", task.info.id),
                &DecideTask {
                    approve: true,
                    decision: Blob::new(bytes),
                    decided_at,
                    signature: Blob::new(signature.to_bytes().to_vec()),
                },
            )
            .await?;
        // Approved once so the agent's waiter exits, bound to the task: it
        // never serves after the task ends.
        let _: ApprovalView = self
            .decide_approval_in(approval, true, None, shown, Some(task.info.id))
            .await?;
        self.card(&revised).await
    }

    /// Ends running task `id` («End task»), signed with `task-end`.
    pub async fn end_task(&mut self, id: TaskId) -> ClientResult<TaskCard> {
        let info = self.task_info(id).await?;
        if info.status != TaskStatus::Approved {
            return Err(ClientError::Invalid(format!(
                "task {id} is {}, not running",
                info.status.as_str()
            )));
        }
        let ended_at = now_ms();
        let signature = agent::sign_task_end(
            &self.identity,
            self.account.account_id,
            id,
            info.agent_id,
            u64::try_from(ended_at).unwrap_or(0),
        );
        let ended: TaskInfo = self
            .send_json(
                Method::POST,
                &format!("/v1/tasks/{id}/end"),
                &EndTask {
                    ended_at,
                    signature: Blob::new(signature.to_bytes().to_vec()),
                },
            )
            .await?;
        self.card(&ended).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent::sign_task_decision as agent_sign;
    use klav_core::crypto::identity::IdentityKeyPair;
    use klav_core::ids::{ItemId, ProjectId, VaultId};
    use klav_core::task::{TASK_FORMAT_VERSION as V, TaskAccessDecision, TaskOffer};

    const NOW: i64 = 1_800_000_000_000;

    fn offered(agent: AgentId) -> TaskDecision {
        TaskDecision {
            v: V,
            task_id: TaskId::generate(),
            agent_id: agent,
            revision: 1,
            expires_at_ms: u64::try_from(NOW + 3_600_000).unwrap(),
            access: vec![TaskAccessDecision {
                vault_id: VaultId::generate(),
                project_id: ProjectId::generate(),
                item_id: ItemId::generate(),
                permissions: vec![Permission::Rotate],
                domains: vec!["bank.example".into()],
                added_by_klav: Vec::new(),
            }],
            offer: Some(TaskOffer {
                task: "Fix my reused passwords".into(),
                reason: "One password per site".into(),
            }),
        }
    }

    /// `decision`, signed by `account` over `request`, as the server
    /// returns it.
    fn info(account: &IdentityKeyPair, decision: &TaskDecision, request: &[u8]) -> TaskInfo {
        let bytes = serde_json::to_vec(decision).unwrap();
        let signature = agent_sign(
            account,
            &TaskDecisionToSign {
                task: decision.task_id,
                agent: decision.agent_id,
                request,
                decision: &bytes,
                approve: true,
                decided_at_ms: u64::try_from(NOW).unwrap(),
            },
        );
        TaskInfo {
            id: decision.task_id,
            agent_id: decision.agent_id,
            agent_name: "bot".into(),
            status: TaskStatus::Approved,
            request: Blob::new(request.to_vec()),
            created_at: NOW,
            decide_by: NOW,
            decided_at: Some(NOW),
            decision: Some(Blob::new(bytes)),
            signature: Some(Blob::new(signature.to_bytes().to_vec())),
            revision: decision.revision,
            expires_at: Some(i64::try_from(decision.expires_at_ms).unwrap()),
            ended_at: None,
            ended_by: None,
        }
    }

    fn row(permissions: &[(Permission, bool)]) -> TaskCardRow {
        TaskCardRow {
            vault_id: VaultId::generate(),
            project_id: ProjectId::generate(),
            item_id: ItemId::generate(),
            reference: "klav://Personal/General/GitHub".into(),
            title: Some("GitHub".into()),
            username: None,
            missing: false,
            asked_domain: None,
            domain_mismatch: false,
            no_site: false,
            domain_claimed: false,
            domains: vec!["github.com".into()],
            permissions: permissions
                .iter()
                .map(|&(permission, checked)| TaskCardPermission {
                    permission,
                    checked,
                    asked: true,
                    added_by_klav: false,
                    denied_by_policy: false,
                    no_site: false,
                    always_asks: false,
                })
                .collect(),
        }
    }

    #[test]
    fn the_prompt_counts_the_items_left_checked() {
        let fill = row(&[(Permission::Fill, true), (Permission::Totp, true)]);
        let inject = row(&[(Permission::Inject, true)]);
        let mut gone = row(&[(Permission::Fill, true)]);
        gone.missing = true;
        let mut other_site = row(&[(Permission::Fill, false)]);
        other_site.domain_mismatch = true;
        let passkey = row(&[(Permission::Passkey, false)]);
        let card = TaskCard {
            id: TaskId::generate(),
            status: TaskStatus::Pending,
            agent_id: AgentId::generate(),
            agent: "bot".into(),
            task: "Deploy".into(),
            reason: "Release".into(),
            offered: false,
            duration_secs: 3600,
            created_at: NOW,
            decide_by: NOW,
            decided_at: None,
            revision: 0,
            expires_at: None,
            ended_at: None,
            ended_by: None,
            rows: vec![
                fill.clone(),
                inject.clone(),
                gone.clone(),
                other_site.clone(),
                passkey.clone(),
            ],
            request_digest: String::new(),
        };
        // As proposed: `fill` and `inject` (a missing item never counts).
        assert_eq!(card.approved_items(&TaskChoice::default()), 2);
        // One permission off keeps the item; all of them drop it.
        let mut choice = TaskChoice {
            without: vec![(fill.item_id, Some(Permission::Totp))],
            ..TaskChoice::default()
        };
        assert_eq!(card.approved_items(&choice), 2);
        choice.without.push((inject.item_id, None));
        assert_eq!(card.approved_items(&choice), 1);
        // Checking what Klav offered unchecked adds it; a site that does
        // not match or a missing item stays out, as when deciding (T92).
        choice.with = vec![
            (passkey.item_id, Some(Permission::Passkey)),
            (other_site.item_id, None),
            (gone.item_id, None),
            (ItemId::generate(), None),
        ];
        assert_eq!(card.approved_items(&choice), 2);
    }

    #[test]
    fn an_offered_task_shows_the_persons_title() {
        let account = IdentityKeyPair::generate();
        let decision = offered(AgentId::generate());
        let task = info(&account, &decision, &[]);
        let verified = verify_decision(account.public(), &task)
            .unwrap()
            .expect("decided");
        assert_eq!(verified, decision);
        let request = request_of(&task, Some(&verified)).unwrap();
        assert_eq!(request.task, "Fix my reused passwords");
        assert_eq!(request.reason, "One password per site");
        assert_eq!(request.duration_secs, 3600);
        assert!(request.access.is_empty());
        // Without the verified decision there is nothing to show.
        assert!(request_of(&task, None).is_err());

        // «Add to the task» keeps the offer: revision 2 verifies too.
        let mut added = decision.clone();
        added.revision = 2;
        added.access[0].domains.push("www.bank.example".into());
        assert!(verify_decision(account.public(), &info(&account, &added, &[])).is_ok());
    }

    #[test]
    fn an_empty_request_needs_a_signed_offer() {
        let account = IdentityKeyPair::generate();
        let agent = AgentId::generate();
        // A decision on a request, replayed by the server with the request
        // removed: the signature covers the request, so it fails.
        let mut answered = offered(agent);
        answered.offer = None;
        let mut tampered = info(&account, &answered, b"{}");
        tampered.request = Blob::new(Vec::new());
        assert!(matches!(
            verify_decision(account.public(), &tampered),
            Err(ClientError::Security(_))
        ));
        // Signed over an empty request but without an offer: not an
        // offered task either.
        assert!(matches!(
            verify_decision(account.public(), &info(&account, &answered, &[])),
            Err(ClientError::Security(_))
        ));
        // An offer longer than a day.
        let mut long = offered(agent);
        long.expires_at_ms = u64::try_from(NOW + 25 * 3_600_000).unwrap();
        assert!(verify_decision(account.public(), &info(&account, &long, &[])).is_err());
        // Signed by another account.
        let other = IdentityKeyPair::generate();
        assert!(verify_decision(account.public(), &info(&other, &offered(agent), &[])).is_err());
    }
}
