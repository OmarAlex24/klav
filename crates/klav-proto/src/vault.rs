//! Vaults, members, projects and items (all payloads encrypted by clients).
//!
//! Concurrency and rollback rules (see `docs/api.md`):
//!
//! * every change inside a vault increments the vault **revision** (strictly
//!   monotonic, never reused); every entity reports the revision of its last
//!   change;
//! * vaults, projects and items carry a **version** that the client bumps on
//!   each edit: an update must send `current + 1` (blobs encrypted for that
//!   version) or it is rejected with 409 and `current_version`;
//! * clients remember the highest revision and versions they have seen and
//!   reject anything lower (threat T7).

use klav_core::ids::{AccountId, AgentId, ItemId, ProjectId, VaultId};
use serde::{Deserialize, Serialize};

use crate::Blob;

/// Role of a member in a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Created the vault; can delete it and manage members.
    Owner,
    /// Can read and write items (sharing arrives after the MVP).
    Member,
}

/// Kind of vault member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberType {
    /// A person's account.
    Account,
    /// An agent identity (fase 4).
    Agent,
}

/// `POST /v1/vaults`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateVault {
    /// Client-generated vault ID.
    pub id: VaultId,
    /// Vault metadata encrypted by the client (opaque to the server).
    pub meta: Blob,
    /// The vault key shared with the creator's own identity (kind `0x20`).
    pub shared_key: Blob,
    /// The creator's Ed25519 signature over `shared_key` (64 bytes,
    /// `klav/v1/sig/vault-key`, spec §8.3). Required: without it the server
    /// answers 400.
    pub shared_key_signature: Blob,
}

/// `PUT /v1/vaults/{vault_id}/signature`: the owner signs the vault key of a
/// vault created before the signature existed (TOFU, ADR 0030 §1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignVaultKey {
    /// Ed25519 signature over the caller's `shared_key` (64 bytes, spec §8.3).
    pub shared_key_signature: Blob,
}

/// `PUT /v1/vaults/{vault_id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateVault {
    /// New version: must be the current version plus one.
    pub version: u64,
    /// New encrypted metadata.
    pub meta: Blob,
}

/// A vault as seen by one of its members.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    /// Vault ID.
    pub id: VaultId,
    /// Account that owns the vault (part of the AAD of everything inside).
    pub owner_account_id: AccountId,
    /// Caller's role.
    pub role: Role,
    /// Current revision of the vault (highest revision of anything in it).
    pub revision: u64,
    /// Version of the vault metadata.
    pub version: u64,
    /// Encrypted metadata.
    pub meta: Blob,
    /// The vault key shared with the caller (kind `0x20`).
    pub shared_key: Blob,
    /// The owner's signature over `shared_key` (spec §8.3). Absent only on
    /// vaults created before it existed, until a device signs them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_key_signature: Option<Blob>,
    /// Creation time (Unix milliseconds).
    pub created_at: i64,
    /// Last change of the metadata (Unix milliseconds).
    pub updated_at: i64,
    /// Deletion time; deleted vaults are purged after the retention period.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
}

/// `GET /v1/vaults`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultList {
    /// Vaults the caller is a member of (deleted ones excluded).
    pub vaults: Vec<Vault>,
}

/// A member of a vault and the vault key shared with it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    /// Kind of member.
    pub member_type: MemberType,
    /// Account or agent ID (canonical UUID).
    pub member_id: String,
    /// Role.
    pub role: Role,
    /// The vault key shared with this member (kind `0x20`).
    pub shared_key: Blob,
    /// Revision of the last change to this membership.
    pub revision: u64,
    /// Revocation time, if revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
}

/// `GET /v1/vaults/{vault_id}/members`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberList {
    /// Members (revoked ones included).
    pub members: Vec<Member>,
}

/// `POST /v1/vaults/{vault_id}/projects`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateProject {
    /// Client-generated project ID.
    pub id: ProjectId,
    /// Project key wrapped with the vault key (kind `0x02`).
    pub wrapped_key: Blob,
    /// Project metadata encrypted by the client (opaque to the server).
    pub meta: Blob,
}

/// `PUT /v1/vaults/{vault_id}/projects/{project_id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateProject {
    /// New version: must be the current version plus one.
    pub version: u64,
    /// Project key wrapped with the vault key (kind `0x02`); changes when the
    /// vault key or the project key rotates.
    pub wrapped_key: Blob,
    /// New encrypted metadata.
    pub meta: Blob,
}

/// An item key wrapped with a project key (kind `0x03`), in the current
/// row of an item or in one of its stored versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedItemKey {
    /// The item.
    pub item_id: ItemId,
    /// `None` for the current row; the version for a stored one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    /// The wrapped key.
    pub wrapped_key: Blob,
}

/// `GET /v1/vaults/{vault_id}/projects/{project_id}/keys`: every item key
/// wrapped with the project key, to rotate it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectKeys {
    /// Current version of the project.
    pub version: u64,
    /// Current rows (not purged) and stored versions.
    pub keys: Vec<WrappedItemKey>,
}

/// `POST /v1/vaults/{vault_id}/projects/{project_id}/rotate`: a new project
/// key, and every item key of [`ProjectKeys`] wrapped with it, applied in
/// one transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateProject {
    /// New version: the current one plus one.
    pub version: u64,
    /// The new project key wrapped with the vault key (kind `0x02`).
    pub wrapped_key: Blob,
    /// The metadata sealed with the new key for `version`.
    pub meta: Blob,
    /// Exactly the keys of [`ProjectKeys`], re-wrapped (409 if the project
    /// changed in between).
    pub keys: Vec<WrappedItemKey>,
}

/// A project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    /// Project ID.
    pub id: ProjectId,
    /// Vault it belongs to.
    pub vault_id: VaultId,
    /// Version of the project row.
    pub version: u64,
    /// Revision of the last change.
    pub revision: u64,
    /// Project key wrapped with the vault key (kind `0x02`); absent once deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_key: Option<Blob>,
    /// Encrypted metadata; absent once deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Blob>,
    /// Creation time (Unix milliseconds).
    pub created_at: i64,
    /// Last change (Unix milliseconds).
    pub updated_at: i64,
    /// Deletion time (tombstone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
}

/// `GET /v1/vaults/{vault_id}/projects`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectList {
    /// Projects (deleted ones excluded).
    pub projects: Vec<Project>,
}

/// `POST /v1/vaults/{vault_id}/items`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateItem {
    /// Client-generated item ID.
    pub id: ItemId,
    /// Project the item belongs to (part of the AAD; cannot change later).
    pub project_id: ProjectId,
    /// Must be 1.
    pub version: u64,
    /// Item key wrapped with the project key (kind `0x03`).
    pub wrapped_key: Blob,
    /// Version of the project whose key wrapped `wrapped_key`: `409` if it
    /// is not the current one (the project key rotated in between, ADR
    /// 0014 §7). Sync and wrap again.
    pub project_version: u64,
    /// Overview section (kind `0x10`).
    pub overview: Blob,
    /// Details section (kind `0x11`).
    pub details: Blob,
}

/// `PUT /v1/vaults/{vault_id}/items/{item_id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateItem {
    /// New version: must be the current version plus one; both sections
    /// must be encrypted for this version.
    pub version: u64,
    /// Item key wrapped with the project key (kind `0x03`).
    pub wrapped_key: Blob,
    /// Version of the project whose key wrapped `wrapped_key`, as in
    /// [`CreateItem::project_version`].
    pub project_version: u64,
    /// Overview section (kind `0x10`).
    pub overview: Blob,
    /// Details section (kind `0x11`).
    pub details: Blob,
    /// Present when the write gives the item a new key (ADR 0036 §18):
    /// every completed attachment of the item that is not deleted, with its
    /// key wrapped again with the new item key (kind `0x04`), possibly
    /// none. The server stores them with this version, in the same
    /// transaction, or rejects the write (`409`) if the list is not exactly
    /// the item's attachments or one is still uploading. Absent for an
    /// edit that keeps the key. Older servers reject the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment_keys: Option<Vec<RewrappedAttachmentKey>>,
}

/// An attachment key wrapped again for a new item key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewrappedAttachmentKey {
    /// The attachment.
    pub attachment_id: klav_core::ids::AttachmentId,
    /// Its key wrapped with the new item key (kind `0x04`).
    pub wrapped_key: Blob,
}

/// An item. Lists carry only the overview; `details` comes with a single
/// item. Purged items are tombstones without blobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    /// Item ID.
    pub id: ItemId,
    /// Vault it belongs to.
    pub vault_id: VaultId,
    /// Project it belongs to.
    pub project_id: ProjectId,
    /// Current version (also in the AAD of both sections).
    pub version: u64,
    /// Revision of the last change.
    pub revision: u64,
    /// Item key wrapped with the project key (kind `0x03`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_key: Option<Blob>,
    /// Overview section (kind `0x10`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overview: Option<Blob>,
    /// Details section (kind `0x11`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Blob>,
    /// Creation time (Unix milliseconds).
    pub created_at: i64,
    /// Last change of the content (Unix milliseconds).
    pub updated_at: i64,
    /// In the trash since (purged automatically after the retention period).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trashed_at: Option<i64>,
    /// Permanently deleted (tombstone kept for sync).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purged_at: Option<i64>,
    /// Who wrote the current version: the agent, or (absent) the person
    /// (ADR 0030 §7). Versions from before authorship was kept count as
    /// the person's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_agent_id: Option<AgentId>,
}

/// `GET /v1/vaults/{vault_id}/items`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemList {
    /// Items with their overview (no details).
    pub items: Vec<Item>,
}

/// One entry of an item's history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemVersionInfo {
    /// Version number.
    pub version: u64,
    /// When this version was written (Unix milliseconds).
    pub created_at: i64,
    /// The agent that wrote it, or (absent) the person (ADR 0030 §7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_agent_id: Option<AgentId>,
}

/// `GET /v1/vaults/{vault_id}/items/{item_id}/versions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemHistory {
    /// Available versions, newest first (the current one included).
    pub versions: Vec<ItemVersionInfo>,
}

/// `GET /v1/vaults/{vault_id}/items/{item_id}/versions/{version}`.
///
/// To restore it, a client decrypts it and writes it again as a new version
/// (`PUT …/items/{item_id}` with `current + 1`): the version is in the AAD,
/// so the server cannot do that by itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemVersion {
    /// Item ID.
    pub item_id: ItemId,
    /// Project at that version.
    pub project_id: ProjectId,
    /// Version number.
    pub version: u64,
    /// Item key wrapped with the project key (kind `0x03`).
    pub wrapped_key: Blob,
    /// Overview section (kind `0x10`).
    pub overview: Blob,
    /// Details section (kind `0x11`).
    pub details: Blob,
    /// When this version was written (Unix milliseconds).
    pub created_at: i64,
    /// The agent that wrote it, or (absent) the person (ADR 0030 §7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_agent_id: Option<AgentId>,
}

/// Query of `GET /v1/vaults/{vault_id}/items`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemQuery {
    /// Only items of this project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<ProjectId>,
    /// Which items to list with respect to the trash.
    #[serde(default)]
    pub trash: TrashFilter,
}

/// Trash filter for listings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrashFilter {
    /// Items not in the trash (default).
    #[default]
    Exclude,
    /// Only items in the trash.
    Only,
    /// Both.
    Include,
}
