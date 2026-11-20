//! Password record of an item (spec §7.3, ADR 0022 §3): its previous
//! passwords, sealed with the **vault key** so that an agent that receives
//! the item's details (with `fill` or `update`) cannot read them.
//!
//! ```text
//! kind 0x16, key = vault key,
//! AAD = header ‖ tuple("klav/v1/item/password-record", account, vault, item)
//! ```
//!
//! The item version is not in the AAD: the record is copied unchanged
//! between versions when it does not change. The project is not either:
//! moving the item to another project of the vault keeps it readable.

use zeroize::Zeroizing;

use super::context::VaultContext;
use super::encoding::{Kind, Tuple};
use super::keys::{VaultKey, sealed::Sealed};
use super::{CryptoError, aead};
use crate::ids::ItemId;

/// AAD label of a password record.
pub const LABEL_PASSWORD_RECORD: &str = "klav/v1/item/password-record";

pub(crate) fn record_tuple(ctx: &VaultContext, item: ItemId) -> Tuple {
    let mut tuple = Tuple::new(LABEL_PASSWORD_RECORD);
    tuple
        .push(ctx.account.as_bytes())
        .push(ctx.vault.as_bytes())
        .push(item.as_bytes());
    tuple
}

/// Seals a password record of `item` (kind `0x16`).
pub fn encrypt_password_record(
    key: &VaultKey,
    ctx: &VaultContext,
    item: ItemId,
    plaintext: &[u8],
) -> Vec<u8> {
    aead::seal(
        key.secret_bytes(),
        Kind::PasswordRecord,
        &record_tuple(ctx, item),
        plaintext,
    )
}

/// Opens the password record of `item`.
pub fn decrypt_password_record(
    key: &VaultKey,
    ctx: &VaultContext,
    item: ItemId,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    aead::open(
        key.secret_bytes(),
        Kind::PasswordRecord,
        &record_tuple(ctx, item),
        blob,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::ProjectKey;
    use crate::ids::{AccountId, VaultId};

    #[test]
    fn bound_to_vault_key_account_vault_and_item() {
        let ctx = VaultContext {
            account: AccountId::generate(),
            vault: VaultId::generate(),
        };
        let key = VaultKey::generate();
        let item = ItemId::generate();
        let blob = encrypt_password_record(&key, &ctx, item, b"{\"v\":1}");
        assert_eq!(&blob[..2], &[0x01, 0x16]);
        assert_eq!(
            &*decrypt_password_record(&key, &ctx, item, &blob).unwrap(),
            b"{\"v\":1}"
        );
        // Another item, vault, account or key: rejected.
        assert!(decrypt_password_record(&key, &ctx, ItemId::generate(), &blob).is_err());
        let other_vault = VaultContext {
            vault: VaultId::generate(),
            ..ctx
        };
        assert!(decrypt_password_record(&key, &other_vault, item, &blob).is_err());
        let other_account = VaultContext {
            account: AccountId::generate(),
            ..ctx
        };
        assert!(decrypt_password_record(&key, &other_account, item, &blob).is_err());
        assert!(decrypt_password_record(&VaultKey::generate(), &ctx, item, &blob).is_err());
        // The same bytes under a project key (what an agent holds) do not open.
        let project = ProjectKey::generate();
        assert!(
            aead::open(
                project.secret_bytes(),
                Kind::PasswordRecord,
                &record_tuple(&ctx, item),
                &blob
            )
            .is_err()
        );
        // Another kind byte: rejected before decryption.
        let mut swapped = blob.clone();
        swapped[1] = Kind::VaultMeta as u8;
        assert!(decrypt_password_record(&key, &ctx, item, &swapped).is_err());
    }
}
