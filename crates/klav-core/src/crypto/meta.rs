//! Vault and project metadata (spec §7.2): names and descriptions, sealed so
//! the server never sees them.
//!
//! ```text
//! vault   meta: kind 0x12, key = vault key,
//!               AAD = header ‖ tuple("klav/v1/vault/meta", account, vault, u64(version))
//! project meta: kind 0x13, key = project key,
//!               AAD = header ‖ tuple("klav/v1/project/meta", account, vault, project, u64(version))
//! ```
//!
//! Project metadata uses the project key (not the vault key) so that an agent
//! granted only a project can still read its name.

use zeroize::Zeroizing;

use super::context::{ProjectContext, VaultContext};
use super::encoding::{Kind, Tuple};
use super::keys::{ProjectKey, VaultKey, sealed::Sealed};
use super::{CryptoError, aead};

/// AAD label of vault metadata.
pub const LABEL_VAULT_META: &str = "klav/v1/vault/meta";
/// AAD label of project metadata.
pub const LABEL_PROJECT_META: &str = "klav/v1/project/meta";

pub(crate) fn vault_tuple(ctx: &VaultContext, version: u64) -> Tuple {
    let mut tuple = Tuple::new(LABEL_VAULT_META);
    tuple
        .push(ctx.account.as_bytes())
        .push(ctx.vault.as_bytes())
        .push_u64(version);
    tuple
}

pub(crate) fn project_tuple(ctx: &ProjectContext, version: u64) -> Tuple {
    let mut tuple = Tuple::new(LABEL_PROJECT_META);
    tuple
        .push(ctx.account.as_bytes())
        .push(ctx.vault.as_bytes())
        .push(ctx.project.as_bytes())
        .push_u64(version);
    tuple
}

/// Seals vault metadata at `version` (kind `0x12`).
pub fn encrypt_vault_meta(
    key: &VaultKey,
    ctx: &VaultContext,
    version: u64,
    plaintext: &[u8],
) -> Vec<u8> {
    aead::seal(
        key.secret_bytes(),
        Kind::VaultMeta,
        &vault_tuple(ctx, version),
        plaintext,
    )
}

/// Opens vault metadata sealed for `version`.
pub fn decrypt_vault_meta(
    key: &VaultKey,
    ctx: &VaultContext,
    version: u64,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    aead::open(
        key.secret_bytes(),
        Kind::VaultMeta,
        &vault_tuple(ctx, version),
        blob,
    )
}

/// Seals project metadata at `version` (kind `0x13`).
pub fn encrypt_project_meta(
    key: &ProjectKey,
    ctx: &ProjectContext,
    version: u64,
    plaintext: &[u8],
) -> Vec<u8> {
    aead::seal(
        key.secret_bytes(),
        Kind::ProjectMeta,
        &project_tuple(ctx, version),
        plaintext,
    )
}

/// Opens project metadata sealed for `version`.
pub fn decrypt_project_meta(
    key: &ProjectKey,
    ctx: &ProjectContext,
    version: u64,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    aead::open(
        key.secret_bytes(),
        Kind::ProjectMeta,
        &project_tuple(ctx, version),
        blob,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{AccountId, ProjectId, VaultId};

    fn ctx() -> ProjectContext {
        ProjectContext {
            account: AccountId::generate(),
            vault: VaultId::generate(),
            project: ProjectId::generate(),
        }
    }

    #[test]
    fn roundtrip_and_binding() {
        let p = ctx();
        let v = p.vault_context();
        let vk = VaultKey::generate();
        let blob = encrypt_vault_meta(&vk, &v, 1, b"{\"v\":1}");
        assert_eq!(
            &*decrypt_vault_meta(&vk, &v, 1, &blob).unwrap(),
            b"{\"v\":1}"
        );
        // Another version, vault, key or kind: rejected.
        assert!(decrypt_vault_meta(&vk, &v, 2, &blob).is_err());
        let other = VaultContext {
            vault: VaultId::generate(),
            ..v
        };
        assert!(decrypt_vault_meta(&vk, &other, 1, &blob).is_err());
        assert!(decrypt_vault_meta(&VaultKey::generate(), &v, 1, &blob).is_err());

        let pk = ProjectKey::generate();
        let blob = encrypt_project_meta(&pk, &p, 3, b"x");
        assert_eq!(&*decrypt_project_meta(&pk, &p, 3, &blob).unwrap(), b"x");
        assert!(decrypt_project_meta(&pk, &p, 2, &blob).is_err());
        let mut swapped = blob.clone();
        swapped[1] = Kind::VaultMeta as u8;
        assert!(decrypt_project_meta(&pk, &p, 3, &swapped).is_err());
    }
}
