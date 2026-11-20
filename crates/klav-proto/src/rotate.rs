//! Assisted password changes (ADR 0022 §5), the server's half: an agent
//! with a live task that covers `rotate` on an item marks the start, the
//! confirmation or the cancellation of one change. The server checks the
//! task on each step and logs `rotate.started`, `rotate.confirmed` and
//! `rotate.cancelled` with the item and the host. No password ever goes
//! through these routes: the person's `klavd` generates, stores and fills
//! them.

use klav_core::ids::{ItemId, ProjectId, RotationId, TaskId, VaultId};
use serde::{Deserialize, Serialize};

use crate::agent::Claims;
use crate::task::TaskInfo;

/// `POST /v1/agent/rotations`: the agent starts changing an item's
/// password (`rotate_password`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRotateStart {
    /// The item.
    pub item_id: ItemId,
    /// Why (mandatory, like every agent reason).
    pub reason: String,
    /// `domain` is mandatory: the host of the change page, which the task
    /// must approve for this item.
    #[serde(default)]
    pub claims: Claims,
    /// The task this change belongs to; the server finds one if absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<TaskId>,
}

/// `POST /v1/agent/rotations/{id}/confirm` and `…/cancel`: the agent says
/// whether the site took the new password (`rotate_confirm`,
/// `rotate_cancel`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRotateFinish {
    /// The item, as when the change started (signed again, so the audit
    /// event proves it on its own).
    pub item_id: ItemId,
    /// Why.
    pub reason: String,
}

/// Where a change stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    /// Started; the new password is pending.
    Started,
    /// The agent confirmed the site took the new password.
    Confirmed,
    /// The agent cancelled it (the site refused it, or it gave up).
    Cancelled,
    /// Left started when its task ended: the person decides with the
    /// pending password in the item (ADR 0022 §5, T100).
    Abandoned,
}

impl RotationStatus {
    /// Wire and database name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Confirmed => "confirmed",
            Self::Cancelled => "cancelled",
            Self::Abandoned => "abandoned",
        }
    }

    /// Parses [`Self::as_str`].
    pub fn parse(text: &str) -> Option<Self> {
        [
            Self::Started,
            Self::Confirmed,
            Self::Cancelled,
            Self::Abandoned,
        ]
        .into_iter()
        .find(|s| s.as_str() == text)
    }
}

/// One change, as the server keeps it: IDs, host and times, never values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationInfo {
    /// The change (the agent's `pending_id`).
    pub id: RotationId,
    /// The task that covers it.
    pub task_id: TaskId,
    /// Vault of the item.
    pub vault_id: VaultId,
    /// Project of the item.
    pub project_id: ProjectId,
    /// The item.
    pub item_id: ItemId,
    /// Host of the change page.
    pub host: String,
    /// Where it stands.
    pub status: RotationStatus,
    /// Started (Unix ms).
    pub started_at: i64,
    /// Confirmed, cancelled or abandoned (Unix ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<i64>,
}

/// `POST /v1/agent/rotations` → `201`: the change and the task that covers
/// it, whose signed decision `klavd` verifies before it fills anything
/// (ADR 0022 §5, step 2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationStarted {
    /// The change.
    pub rotation: RotationInfo,
    /// Its task, with the decision in force and its signature.
    pub task: TaskInfo,
}

/// An agent's signed request, as it went to the server (spec §13.3), handed
/// to the person's `klavd` as proof that this agent asked for this step
/// (ADR 0020 §9, step 3, applied to ADR 0022 §5): `klavd` checks the
/// signature with the agent's identity from its verified grant, the path,
/// the body and the time before it fills or writes anything. It carries no
/// secret: the body is the step's JSON (IDs and a reason).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRequestProof {
    /// HTTP method, upper case.
    pub method: String,
    /// Path exactly as signed (`/v1/agent/rotations`).
    pub path: String,
    /// `Klav-Timestamp` (Unix ms).
    pub timestamp_ms: u64,
    /// `Klav-Nonce` (16 bytes).
    pub nonce: crate::Blob,
    /// The exact body bytes.
    pub body: crate::Blob,
    /// `Klav-Signature` (64 bytes).
    pub signature: crate::Blob,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_roundtrip() {
        for status in [
            RotationStatus::Started,
            RotationStatus::Confirmed,
            RotationStatus::Cancelled,
            RotationStatus::Abandoned,
        ] {
            assert_eq!(RotationStatus::parse(status.as_str()), Some(status));
            assert_eq!(
                serde_json::to_value(status).unwrap(),
                serde_json::Value::String(status.as_str().into())
            );
        }
        assert_eq!(RotationStatus::parse("nope"), None);
    }
}
