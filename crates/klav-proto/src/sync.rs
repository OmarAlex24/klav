//! Delta synchronisation, change notifications and attachments.
//!
//! A client keeps, per vault, the highest revision it has applied. It asks
//! for everything that changed after it (`GET /v1/vaults/{id}/changes?since=`)
//! and stores the returned `revision` as its new high-water mark. If the
//! server ever reports a revision lower than one the client already saw, or
//! an item version lower than a known one, the client must treat it as a
//! rollback (threat T7) and refuse it.

use klav_core::ids::{AttachmentId, ItemId, SecretRequestId, VaultId};
use serde::{Deserialize, Serialize};

use crate::Blob;
use crate::secret_request::SecretRequestState;
use crate::vault::{Item, Member, Project, Vault};

/// Revision of one vault (`GET /v1/sync`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRevision {
    /// Vault ID.
    pub vault_id: VaultId,
    /// Current revision.
    pub revision: u64,
    /// Set when the vault is deleted (pending purge).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
}

/// `GET /v1/sync`: every vault the caller belongs to, with its revision.
/// A vault that disappears from this list was purged or the caller lost
/// access to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncState {
    /// Vaults, including deleted ones not yet purged.
    pub vaults: Vec<VaultRevision>,
    /// Pauses of the account's agents in effect, signed by the account
    /// (ADR 0033 §7.2): every device of the person learns them on sync.
    /// Absent from older servers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_pauses: Vec<crate::agent::AgentPause>,
    /// The deletion of the account the person asked for (ADR 0037 §3):
    /// every device learns it on sync and says so. Absent when there is
    /// none, and on older servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion: Option<crate::auth::AccountDeletion>,
    /// The last heartbeat of each proxy of the account that is still an
    /// active agent, a paused one included (ADR 0036 E3.3, spec §13.12),
    /// as signed. Absent when there is none, and on older
    /// servers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sandbox_state: Vec<crate::sandbox::SandboxState>,
}

/// Query of `GET /v1/vaults/{vault_id}/changes`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangesQuery {
    /// Last revision the client has applied (0 for a full download).
    #[serde(default)]
    pub since: u64,
}

/// Everything in a vault that changed after `since`, up to `revision`.
/// Deleted projects and purged items come as tombstones (`deleted_at` /
/// `purged_at` set, no blobs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Changes {
    /// Vault ID.
    pub vault_id: VaultId,
    /// The `since` of the request.
    pub since: u64,
    /// Current revision: the client's new high-water mark.
    pub revision: u64,
    /// The vault itself, if its metadata changed (or it was deleted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<Vault>,
    /// Memberships that changed.
    pub members: Vec<Member>,
    /// Projects that changed.
    pub projects: Vec<Project>,
    /// Items that changed (with both sections).
    pub items: Vec<Item>,
    /// Attachments that were completed or deleted.
    pub attachments: Vec<Attachment>,
}

/// Payload of a `change` server-sent event on `GET /v1/events`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeEvent {
    /// Vault that changed.
    pub vault_id: VaultId,
    /// Revision it reached.
    pub revision: u64,
}

/// Payload of a `secret_request` server-sent event on `GET /v1/events`
/// (ADR 0046 §1). Carries only the request ID and its current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRequestEvent {
    /// Secret request that was created, decided or expired.
    pub request_id: SecretRequestId,
    /// Current state.
    pub status: SecretRequestState,
}

/// `POST /v1/vaults/{vault_id}/items/{item_id}/attachments`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAttachment {
    /// Client-generated attachment ID (part of the AAD).
    pub id: AttachmentId,
    /// Exact size of the encrypted attachment (kind `0x30`), in bytes.
    pub size: u64,
    /// Attachment key wrapped with the item key (kind `0x04`).
    pub wrapped_key: Blob,
    /// The item version the client saw, whose key wrapped `wrapped_key`.
    /// When present and not the current version, the server answers `409`
    /// (sync and try again), checked under the vault's lock so that a new
    /// item key (ADR 0036 §18) and an upload declared at the same moment
    /// are serialized. Klav's clients always send it; absent, nothing is
    /// checked, as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_version: Option<u64>,
}

/// An encrypted attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    /// Attachment ID.
    pub id: AttachmentId,
    /// Vault.
    pub vault_id: VaultId,
    /// Item it belongs to.
    pub item_id: ItemId,
    /// Size of the ciphertext in bytes.
    pub size: u64,
    /// Bytes uploaded so far (equals `size` once complete).
    pub received: u64,
    /// Attachment key wrapped with the item key (kind `0x04`); absent once
    /// deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_key: Option<Blob>,
    /// Revision of the last change (0 while the upload is in progress).
    pub revision: u64,
    /// Creation time (Unix milliseconds).
    pub created_at: i64,
    /// Upload completion time; until then the attachment is invisible to sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<i64>,
    /// Deletion time (tombstone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
}

/// Query of `PUT /v1/vaults/{vault_id}/attachments/{attachment_id}/content`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadQuery {
    /// Where this chunk starts; must equal the bytes received so far.
    pub offset: u64,
}

/// Response to an uploaded chunk.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct UploadProgress {
    /// Bytes received so far (the next `offset`).
    pub received: u64,
    /// Declared total size.
    pub size: u64,
}
