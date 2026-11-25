//! Signing in with the person's passkeys (ADR 0020 §9), the agent's half.
//!
//! The private key never reaches the agent: it stays sealed with the vault
//! key, which no agent gets, and only the person's `klavd` opens it. The
//! agent asks for the **use**:
//!
//! 1. `POST /v1/agent/access` with `passkey`, the host of the person's
//!    tab as `claims.domain` and the task. The server checks the task and
//!    logs the use before answering, with no details.
//! 2. `agent_passkey_arm` in `klavd`, with that signed request. `klavd`
//!    checks it and the task on its own and arms one use in the tab: if
//!    the page already waits for a passkey of the site, it signs at once;
//!    if not, the next sign-in of the site in that tab within 60 s gets it
//!    (the agent clicks the site's button).
//!
//! Only the `extension` target: with `sdk:` (or CDP) the page's origin and
//! `clientDataJSON` would come from the agent's runtime. `passkey` only
//! exists inside a task (ADR 0021 §5): no grant holds it.

use klav_client::agent_passkeys::{ACCESS_PATH, PasskeyArmStep, serves};
use klav_client::{ClientError, ClientResult};
use klav_core::ids::{ItemId, TaskId};
use klav_core::policy::Permission;
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{self, PasskeyArmed, Request};
use klav_proto::agent::{AccessRequest, Claims, PasskeyAccess};

use crate::browser::{Target, daemon_error, fillable_host};
use crate::session::Session;

/// Why `target` cannot carry a passkey sign-in, if it cannot.
pub fn refuse_target(target: &str) -> Option<String> {
    let target = target.trim();
    (target != "extension").then(|| {
        if target.starts_with("sdk:") {
            format!(
                "{target:?}: a passkey only signs in the person's browser (target \"extension\"), never in a browser of your runtime: there the page's origin would come from you (ADR 0020 §9)"
            )
        } else {
            format!("unknown target {target:?}: a passkey sign-in only takes \"extension\"")
        }
    })
}

impl Session {
    /// The task that covers `passkey` on `item` at `host`: the one named
    /// with [`Session::use_task`], or the only running one that covers it.
    fn passkey_task(&self, item: ItemId, host: &str) -> ClientResult<TaskId> {
        if let Some(task) = self.task {
            return Ok(task);
        }
        let entry = self
            .items
            .get(&item)
            .ok_or_else(|| ClientError::NotFound(format!("item {item}")))?;
        let now = crate::agent::now_ms();
        let covering: Vec<TaskId> = self
            .tasks
            .iter()
            .filter(|t| {
                t.expires_at > now
                    && t.decision.covers(
                        entry.vault,
                        entry.project,
                        item,
                        Permission::Passkey,
                        Some(host),
                    )
            })
            .map(|t| t.id)
            .collect();
        match covering.as_slice() {
            [one] => Ok(*one),
            [] => Err(ClientError::Denied(format!(
                "no running task covers `passkey` on this item at {host}. passkey only exists inside a task: use the one the person offered you (list_tasks), or ask for one with request_task and permissions [\"passkey\"]"
            ))),
            _ => Err(ClientError::Invalid(format!(
                "several running tasks cover `passkey` on this item at {host}: pass task_id"
            ))),
        }
    }

    /// Signs in with `item`'s passkey in the active tab of the person's
    /// browser (ADR 0020 §9). The answer says whether the page already
    /// waited and got it (`used`), or the use is armed for the next sign-in
    /// of the site in that tab (`expires_in_s`).
    pub async fn passkey_sign_in(
        &mut self,
        target: &Target,
        item: ItemId,
        reason: &str,
    ) -> ClientResult<PasskeyArmed> {
        let Target::Extension { home } = target else {
            return Err(ClientError::Denied(
                "a passkey only signs in the person's browser (target \"extension\"), never in a browser of your runtime".into(),
            ));
        };
        let info = self.item_info(item)?;
        let rp_id = self
            .items
            .get(&item)
            .and_then(|e| e.overview.passkey.as_ref())
            .map(|p| p.rp_id.clone())
            .ok_or_else(|| {
                ClientError::Invalid(format!("{} has no passkey in Klav", info.reference))
            })?;
        let mut daemon = DaemonClient::connect(home).await.ok_or_else(|| {
            ClientError::NotFound(
                "klavd, with the person's browser attached (open the browser with Klav's extension)"
                    .into(),
            )
        })?;
        let (tab, _): (protocol::BrowserTab, _) = daemon
            .call(Request::BrowserTab)
            .await
            .map_err(daemon_error)?;
        let host = fillable_host(&tab.url)?;
        if !serves(&tab.url, &rp_id) {
            return Err(ClientError::Denied(format!(
                "the active tab is on {host}, and the passkey of {} is for {rp_id}: Klav does not sign there (phishing protection). Open the item's site in the person's browser",
                info.reference
            )));
        }
        let task = self.passkey_task(item, &host)?;
        let (granted, request): (PasskeyAccess, _) = self
            .agent
            .call_proved(
                ACCESS_PATH,
                &AccessRequest {
                    item_id: item,
                    permission: Permission::Passkey,
                    reason: reason.trim().to_owned(),
                    claims: Claims {
                        tags: Vec::new(),
                        domain: Some(host),
                        ..Claims::default()
                    },
                    approval_id: None,
                    task_id: Some(task),
                    include_attachments: false,
                    sandbox: None,
                    local_client: None,
                },
            )
            .await?;
        let step = PasskeyArmStep {
            agent_id: self.agent.id(),
            task_id: granted.task_id,
            item_id: item,
            request,
        };
        let (armed, _): (PasskeyArmed, _) = daemon
            .call(Request::AgentPasskeyArm { tab: tab.tab, step })
            .await
            .map_err(daemon_error)?;
        Ok(armed)
    }
}
