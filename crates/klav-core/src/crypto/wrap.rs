//! Symmetric key wrapping down the hierarchy (spec §5.2):
//! vault key → project key → item key → attachment key.
//!
//! Each wrapped key is an XChaCha20-Poly1305 envelope whose AAD binds the full
//! location of the wrapped key, so the server cannot move it elsewhere.

use secrecy::SecretBox;

use super::context::{AttachmentContext, ItemContext, ProjectContext};
use super::encoding::{Kind, Tuple};
use super::keys::{
    AttachmentKey, ItemKey, KEY_LEN, ProjectKey, SymmetricKey, VaultKey, sealed::Sealed,
};
use super::{CryptoError, aead};

/// Label of a project key wrapped under a vault key.
pub const LABEL_PROJECT_KEY: &str = "klav/v1/wrap/project-key";
/// Label of an item key wrapped under a project key.
pub const LABEL_ITEM_KEY: &str = "klav/v1/wrap/item-key";
/// Label of an attachment key wrapped under an item key.
pub const LABEL_ATTACHMENT_KEY: &str = "klav/v1/wrap/attachment-key";
/// Length of every wrapped key blob: header(2) ‖ nonce(24) ‖ key(32) ‖ tag(16).
pub const WRAPPED_KEY_LEN: usize = aead::OVERHEAD + KEY_LEN;

pub(crate) fn project_tuple(ctx: &ProjectContext) -> Tuple {
    let mut t = Tuple::new(LABEL_PROJECT_KEY);
    t.push(ctx.account.as_bytes())
        .push(ctx.vault.as_bytes())
        .push(ctx.project.as_bytes());
    t
}

pub(crate) fn item_tuple(ctx: &ItemContext) -> Tuple {
    let mut t = Tuple::new(LABEL_ITEM_KEY);
    t.push(ctx.account.as_bytes())
        .push(ctx.vault.as_bytes())
        .push(ctx.project.as_bytes())
        .push(ctx.item.as_bytes());
    t
}

pub(crate) fn attachment_tuple(ctx: &AttachmentContext) -> Tuple {
    let mut t = Tuple::new(LABEL_ATTACHMENT_KEY);
    t.push(ctx.account.as_bytes())
        .push(ctx.vault.as_bytes())
        .push(ctx.project.as_bytes())
        .push(ctx.item.as_bytes())
        .push(ctx.attachment.as_bytes());
    t
}

fn unwrap_key<K: SymmetricKey>(
    wrapping: &[u8; KEY_LEN],
    kind: Kind,
    tuple: &Tuple,
    blob: &[u8],
) -> Result<K, CryptoError> {
    if blob.len() != WRAPPED_KEY_LEN {
        return Err(CryptoError::Malformed("wrapped key length"));
    }
    let plaintext = aead::open(wrapping, kind, tuple, blob)?;
    let bytes: [u8; KEY_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Malformed("wrapped key length"))?;
    Ok(K::from_secret(SecretBox::new(Box::new(bytes))))
}

/// Wraps a project key under its vault key (kind `0x02`).
pub fn wrap_project_key(vault_key: &VaultKey, ctx: &ProjectContext, key: &ProjectKey) -> Vec<u8> {
    aead::seal(
        vault_key.secret_bytes(),
        Kind::ProjectKeyWrap,
        &project_tuple(ctx),
        key.secret_bytes(),
    )
}

/// Unwraps a project key.
pub fn unwrap_project_key(
    vault_key: &VaultKey,
    ctx: &ProjectContext,
    blob: &[u8],
) -> Result<ProjectKey, CryptoError> {
    unwrap_key(
        vault_key.secret_bytes(),
        Kind::ProjectKeyWrap,
        &project_tuple(ctx),
        blob,
    )
}

/// Wraps an item key under its project key (kind `0x03`).
pub fn wrap_item_key(project_key: &ProjectKey, ctx: &ItemContext, key: &ItemKey) -> Vec<u8> {
    aead::seal(
        project_key.secret_bytes(),
        Kind::ItemKeyWrap,
        &item_tuple(ctx),
        key.secret_bytes(),
    )
}

/// Unwraps an item key.
pub fn unwrap_item_key(
    project_key: &ProjectKey,
    ctx: &ItemContext,
    blob: &[u8],
) -> Result<ItemKey, CryptoError> {
    unwrap_key(
        project_key.secret_bytes(),
        Kind::ItemKeyWrap,
        &item_tuple(ctx),
        blob,
    )
}

/// Wraps an attachment key under its item key (kind `0x04`).
pub fn wrap_attachment_key(
    item_key: &ItemKey,
    ctx: &AttachmentContext,
    key: &AttachmentKey,
) -> Vec<u8> {
    aead::seal(
        item_key.secret_bytes(),
        Kind::AttachmentKeyWrap,
        &attachment_tuple(ctx),
        key.secret_bytes(),
    )
}

/// Unwraps an attachment key.
pub fn unwrap_attachment_key(
    item_key: &ItemKey,
    ctx: &AttachmentContext,
    blob: &[u8],
) -> Result<AttachmentKey, CryptoError> {
    unwrap_key(
        item_key.secret_bytes(),
        Kind::AttachmentKeyWrap,
        &attachment_tuple(ctx),
        blob,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{AccountId, AttachmentId, ItemId, ProjectId, VaultId};

    fn item_ctx() -> ItemContext {
        ItemContext {
            account: AccountId::generate(),
            vault: VaultId::generate(),
            project: ProjectId::generate(),
            item: ItemId::generate(),
        }
    }

    #[test]
    fn full_hierarchy_roundtrip() {
        let ctx = item_ctx();
        let attachment_ctx = ctx.attachment(AttachmentId::generate());
        let vault_key = VaultKey::generate();
        let project_key = ProjectKey::generate();
        let item_key = ItemKey::generate();
        let attachment_key = AttachmentKey::generate();

        let wp = wrap_project_key(&vault_key, &ctx.project_context(), &project_key);
        let wi = wrap_item_key(&project_key, &ctx, &item_key);
        let wa = wrap_attachment_key(&item_key, &attachment_ctx, &attachment_key);
        assert_eq!(wp.len(), WRAPPED_KEY_LEN);

        let p = unwrap_project_key(&vault_key, &ctx.project_context(), &wp).unwrap();
        let i = unwrap_item_key(&p, &ctx, &wi).unwrap();
        let a = unwrap_attachment_key(&i, &attachment_ctx, &wa).unwrap();
        assert_eq!(p.secret_bytes(), project_key.secret_bytes());
        assert_eq!(i.secret_bytes(), item_key.secret_bytes());
        assert_eq!(a.secret_bytes(), attachment_key.secret_bytes());
    }

    #[test]
    fn moving_a_wrapped_key_is_detected() {
        let ctx = item_ctx();
        let project_key = ProjectKey::generate();
        let wi = wrap_item_key(&project_key, &ctx, &ItemKey::generate());
        let moved = [
            ItemContext {
                item: ItemId::generate(),
                ..ctx
            },
            ItemContext {
                project: ProjectId::generate(),
                ..ctx
            },
            ItemContext {
                vault: VaultId::generate(),
                ..ctx
            },
            ItemContext {
                account: AccountId::generate(),
                ..ctx
            },
        ];
        for other in moved {
            assert_eq!(
                unwrap_item_key(&project_key, &other, &wi).err(),
                Some(CryptoError::Decryption)
            );
        }
    }

    #[test]
    fn kind_confusion_is_rejected() {
        let ctx = item_ctx();
        let vault_key = VaultKey::generate();
        let wp = wrap_project_key(&vault_key, &ctx.project_context(), &ProjectKey::generate());
        // Same 32-byte key material used as a project key to open an item-key blob.
        let as_project = ProjectKey::from_bytes(*vault_key.secret_bytes());
        assert!(matches!(
            unwrap_item_key(&as_project, &ctx, &wp),
            Err(CryptoError::UnexpectedKind { .. })
        ));
    }
}
