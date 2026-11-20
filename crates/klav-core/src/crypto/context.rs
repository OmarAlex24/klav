//! Where a ciphertext lives. Contexts are bound into AAD (or HPKE `info`) so
//! that the server cannot move a blob to another account, vault, project,
//! item or attachment without detection.

use crate::ids::{AccountId, AttachmentId, ItemId, ProjectId, VaultId};

/// A vault of an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VaultContext {
    /// Owning account.
    pub account: AccountId,
    /// Vault.
    pub vault: VaultId,
}

/// A project inside a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProjectContext {
    /// Owning account.
    pub account: AccountId,
    /// Vault.
    pub vault: VaultId,
    /// Project.
    pub project: ProjectId,
}

/// An item inside a project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ItemContext {
    /// Owning account.
    pub account: AccountId,
    /// Vault.
    pub vault: VaultId,
    /// Project.
    pub project: ProjectId,
    /// Item.
    pub item: ItemId,
}

/// An attachment of an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttachmentContext {
    /// Owning account.
    pub account: AccountId,
    /// Vault.
    pub vault: VaultId,
    /// Project.
    pub project: ProjectId,
    /// Item.
    pub item: ItemId,
    /// Attachment.
    pub attachment: AttachmentId,
}

impl ProjectContext {
    /// The vault this project belongs to.
    pub fn vault_context(&self) -> VaultContext {
        VaultContext {
            account: self.account,
            vault: self.vault,
        }
    }
}

impl ItemContext {
    /// The project this item belongs to.
    pub fn project_context(&self) -> ProjectContext {
        ProjectContext {
            account: self.account,
            vault: self.vault,
            project: self.project,
        }
    }

    /// Context of an attachment of this item.
    pub fn attachment(&self, attachment: AttachmentId) -> AttachmentContext {
        AttachmentContext {
            account: self.account,
            vault: self.vault,
            project: self.project,
            item: self.item,
            attachment,
        }
    }
}
