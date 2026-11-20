//! Agents using the person's passkeys (ADR 0020 §9), `klavd`'s half: the
//! checks it makes on its own before arming one use, without trusting the
//! agent's runtime (a double barrier with the server, like T22). The task
//! and the agent's key are checked against what the person's account
//! signed, not the server's word; the last check (the server logged the
//! request) reads the server's log, so it keeps an agent from skipping the
//! server, not a malicious server from hiding a use.
//!
//! The agent asked the server first (`POST /v1/agent/access` with
//! `passkey`, the tab's host as `claims.domain` and the task), which logged
//! it. It hands that signed request to `klavd` (`agent_passkey_arm`).
//! [`Unlocked::passkey_arm`] checks:
//!
//! - the request: `POST /v1/agent/access`, signed by the agent the account
//!   approved, less than 5 minutes old and not seen before;
//! - what it asks: `passkey` on this login, under this task;
//! - the login: it holds a passkey, and the tab's host may use its rpId;
//! - the task, as the person's account signed it: approved, live, of this
//!   agent, with `passkey` on the login and the host among its domains;
//! - the server's log: it holds an allowed `agent.access` by this agent
//!   for this signed request (same nonce and signature), so an agent cannot
//!   skip the server and arm a use the log never saw (T139).
//!
//! Then `klavd` arms one use in that tab (its own state, not here). The
//! key never leaves `klavd`: the page gets the assertion, the agent only
//! learns whether it was used.

use klav_core::ids::{AgentId, ItemId, TaskId};
use klav_core::model::item::ItemKind;
use klav_core::passkey::rp;
use klav_core::policy::{Permission, normalize_host};
use klav_proto::agent::AccessRequest;
use klav_proto::audit::{ActorKind, AuditEvent, AuditPage};
use klav_proto::rotate::AgentRequestProof;
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::api::Body;
use crate::session::Unlocked;
use crate::{ClientError, ClientResult};

/// The path the agent's signed request must be for.
pub const ACCESS_PATH: &str = "/v1/agent/access";

/// How many of the log's latest events `klavd` looks through for the
/// agent's request. The request is less than 5 minutes old, and the server
/// raises a `burst` alert past 20 uses a minute: far fewer than this.
const RECORD_WINDOW: u64 = 1000;

/// What the agent hands to `klavd` (`agent_passkey_arm`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyArmStep {
    /// The agent.
    pub agent_id: AgentId,
    /// The task the server said covers it.
    pub task_id: TaskId,
    /// The login.
    pub item_id: ItemId,
    /// The request the agent signed (`POST /v1/agent/access`).
    pub request: AgentRequestProof,
}

/// A use whose checks passed. No secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyArmPlan {
    /// The login.
    pub item: ItemId,
    /// Its title, for the notice on the page.
    pub title: String,
    /// The passkey's rpId.
    pub rp_id: String,
    /// The host the use is for (the tab's, as the agent claimed it).
    pub host: String,
    /// The agent.
    pub agent_id: AgentId,
    /// Its name, from the task.
    pub agent_name: String,
    /// Why, as the agent said it (control characters removed).
    pub reason: String,
    /// The task.
    pub task_id: TaskId,
}

/// Whether a page at `origin` may use a passkey for `rp_id` (the checks of
/// ADR 0020 §7: a secure origin, and `rp_id` its host or a registrable
/// suffix of it, not a public suffix).
pub fn serves(origin: &str, rp_id: &str) -> bool {
    rp::validate(origin, Some(rp_id)).is_ok_and(|rp| rp.rp_id == rp_id)
}

fn denied(message: impl Into<String>) -> ClientError {
    ClientError::Denied(message.into())
}

impl Unlocked {
    /// Checks `agent_passkey_arm` (ADR 0020 §9, step 3). Nothing is armed
    /// here: `klavd` does that with what this returns.
    pub async fn passkey_arm(&mut self, step: &PasskeyArmStep) -> ClientResult<PasskeyArmPlan> {
        let body = self
            .check_proof(step.agent_id, &step.request, ACCESS_PATH)
            .await?;
        let asked: AccessRequest = serde_json::from_slice(body)
            .map_err(|_| ClientError::Invalid("the agent's request: body".into()))?;
        if asked.permission != Permission::Passkey
            || asked.item_id != step.item_id
            || asked.task_id != Some(step.task_id)
        {
            return Err(denied(
                "the agent's request asks for something else (another permission, item or task): it does not prove this use",
            ));
        }
        let host = asked
            .claims
            .domain
            .as_deref()
            .and_then(normalize_host)
            .ok_or_else(|| ClientError::Invalid("the agent's request has no host".into()))?;
        let loc = self.find_item(&step.item_id.to_string())?;
        let summary = self.item_summary(loc)?;
        let passkey = summary
            .passkey
            .as_ref()
            .filter(|_| summary.kind == ItemKind::Login)
            .ok_or_else(|| ClientError::Invalid(format!("{} has no passkey", summary.title)))?;
        if !serves(&format!("https://{host}"), &passkey.rp_id) {
            return Err(denied(format!(
                "{host} cannot use the passkey of {} (it is for {}): Klav does not sign there",
                summary.title, passkey.rp_id
            )));
        }
        let (agent_name, _) = self
            .task_using(
                step.task_id,
                step.agent_id,
                loc,
                Permission::Passkey,
                Some(&host),
            )
            .await?;
        self.server_recorded(step).await?;
        Ok(PasskeyArmPlan {
            item: loc.item,
            title: summary.title,
            rp_id: passkey.rp_id.clone(),
            host,
            agent_id: step.agent_id,
            agent_name,
            reason: asked
                .reason
                .chars()
                .filter(|c| !c.is_control())
                .take(500)
                .collect(),
            task_id: step.task_id,
        })
    }

    async fn audit_page(&mut self, after: u64, limit: u64) -> ClientResult<AuditPage> {
        let res = self
            .authed(
                Method::GET,
                &format!("/v1/audit?after={after}&limit={limit}"),
                &Body::Empty,
            )
            .await?;
        crate::api::json(res).await
    }

    /// Whether the server logged this signed request as an allowed
    /// `agent.access` (it logs before it answers): the agent asked it, and
    /// the person's log shows the use. A request signed but never sent, or
    /// one the server refused, arms nothing.
    async fn server_recorded(&mut self, step: &PasskeyArmStep) -> ClientResult<()> {
        let head = self.audit_page(0, 1).await?;
        let after = head.head_seq.saturating_sub(RECORD_WINDOW);
        let page = self.audit_page(after, RECORD_WINDOW).await?;
        let found = page.entries.iter().rev().any(|entry| {
            serde_json::from_slice::<AuditEvent>(entry.event.as_bytes()).is_ok_and(|e| {
                e.action == "agent.access"
                    && e.actor == ActorKind::Agent
                    && e.outcome.as_deref() == Some("allow")
                    && e.agent_id == Some(step.agent_id)
                    && e.item_id == Some(step.item_id)
                    && e.task_id == Some(step.task_id)
                    && e.permission == Some(Permission::Passkey)
                    && e.agent_proof.as_ref().is_some_and(|p| {
                        p.nonce == step.request.nonce && p.signature == step.request.signature
                    })
            })
        });
        if found {
            Ok(())
        } else {
            Err(denied(
                "the server has no record of this request: ask it first (POST /v1/agent/access), then hand Klav that request",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::serves;

    #[test]
    fn a_host_serves_its_own_rp_id_and_a_registrable_parent_only() {
        assert!(serves("https://shop.example.com", "shop.example.com"));
        assert!(serves("https://login.shop.example.com", "shop.example.com"));
        assert!(serves("https://a.b.example.co.uk", "b.example.co.uk"));
        assert!(serves("http://localhost:8443", "localhost"));
        // A child rpId, a sibling, another site.
        assert!(!serves(
            "https://shop.example.com",
            "login.shop.example.com"
        ));
        assert!(!serves("https://evil.example.com", "shop.example.com"));
        assert!(!serves(
            "https://shop.example.com.evil.net",
            "shop.example.com"
        ));
        // Public suffixes, ICANN and private sections: never an rpId.
        assert!(!serves("https://shop.co.uk", "co.uk"));
        assert!(!serves("https://ana.github.io", "github.io"));
        // Plain http off localhost.
        assert!(!serves("http://shop.example.com", "shop.example.com"));
    }
}
