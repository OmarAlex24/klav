//! Who chose a vault key (ADR 0030 §1, spec §8.3).
//!
//! HPKE only proves the shared vault key was sealed **for** this account,
//! and the server knows the account's public identity. So the account signs
//! its own shared key and the client only uses a vault whose key:
//!
//! * belongs to this account (`owner_account_id == account_id`, while
//!   sharing with people does not exist);
//! * carries a signature that verifies with this account's identity (the
//!   one sealed with the KEK, never one the server hands out);
//! * or, for vaults created before the signature, is unsigned **and** this
//!   device has not finished its one-time signing pass (TOFU) nor ever seen
//!   that vault signed.

use klav_core::crypto::context::VaultContext;
use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::share::verify_vault_key;
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::ids::{AccountId, VaultId};
use klav_proto::vault::Vault;

use crate::state::Marks;

/// Why a vault key may be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyTrust {
    /// Signed by this account.
    Signed,
    /// Created before the signature: usable until this device signs it.
    Unsigned,
}

/// Checks the owner and the signature of a vault's shared key. `Err` is the
/// reason to refuse the vault.
pub(crate) fn check(
    account: &PublicIdentity,
    account_id: AccountId,
    vault_id: VaultId,
    vault: &Vault,
    marks: &Marks,
) -> Result<KeyTrust, String> {
    if vault.id != vault_id {
        return Err(format!("the server answered for vault {}", vault.id));
    }
    if vault.owner_account_id != account_id {
        return Err(format!(
            "it belongs to account {}, not to this account",
            vault.owner_account_id
        ));
    }
    match &vault.shared_key_signature {
        Some(sig) => {
            let bytes: [u8; SIGNATURE_LEN] = sig
                .as_bytes()
                .try_into()
                .map_err(|_| "its key signature is not 64 bytes".to_owned())?;
            let ctx = VaultContext {
                account: account_id,
                vault: vault_id,
            };
            verify_vault_key(
                account,
                &ctx,
                vault.shared_key.as_bytes(),
                &Signature::from_bytes(bytes),
            )
            .map(|()| KeyTrust::Signed)
            .map_err(|_| "its key is not signed by this account".to_owned())
        }
        None if marks.signed_vaults.contains(&vault_id) => {
            Err("its key was signed and now comes without a signature".to_owned())
        }
        None if marks.vault_keys_signed => Err("its key is not signed by this account".to_owned()),
        None => Ok(KeyTrust::Unsigned),
    }
}

/// TOFU (ADR 0030 §1): may this device sign the key of an unsigned vault?
/// `previous` is the vault record in this device's sealed cache before the
/// sync. If there was one, the listed key must be that one byte for byte:
/// there the device does not trust the server. `Ok(true)` if it matched
/// this device's copy, `Ok(false)` if the vault is new to this device
/// (trusted as listed: residual risk 32).
pub(crate) fn tofu(previous: Option<&Vault>, listed: &Vault) -> Result<bool, String> {
    match previous {
        Some(p) if p.shared_key.as_bytes() == listed.shared_key.as_bytes() => Ok(true),
        Some(_) => Err(format!(
            "vault {}: the server lists another key than the one this device had; \
             it was not signed and will not be used",
            listed.id
        )),
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use klav_core::crypto::identity::IdentityKeyPair;
    use klav_core::crypto::keys::VaultKey;
    use klav_core::crypto::share::{share_vault_key, sign_vault_key};
    use klav_proto::Blob;
    use klav_proto::vault::Role;

    use super::*;

    fn vault(account: &IdentityKeyPair, account_id: AccountId, id: VaultId, sign: bool) -> Vault {
        let ctx = VaultContext {
            account: account_id,
            vault: id,
        };
        let shared = share_vault_key(account.public(), &ctx, &VaultKey::generate()).unwrap();
        let sig = sign.then(|| {
            Blob::new(
                sign_vault_key(account, &ctx, &shared)
                    .unwrap()
                    .to_bytes()
                    .to_vec(),
            )
        });
        Vault {
            id,
            owner_account_id: account_id,
            role: Role::Owner,
            revision: 1,
            version: 1,
            meta: Blob::new(vec![1]),
            shared_key: Blob::new(shared),
            shared_key_signature: sig,
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        }
    }

    #[test]
    fn only_this_accounts_signature_and_owner_are_accepted() {
        let me = IdentityKeyPair::generate();
        let server = IdentityKeyPair::generate();
        let account = AccountId::generate();
        let id = VaultId::generate();
        let marks = Marks::default();
        let good = vault(&me, account, id, true);
        assert_eq!(
            check(me.public(), account, id, &good, &marks),
            Ok(KeyTrust::Signed)
        );

        // A key the server chose and sealed for this account, signed by
        // the server or with a signature copied from another vault.
        let mut forged = vault(&me, account, id, false);
        forged.shared_key_signature = Some(Blob::new(
            sign_vault_key(
                &server,
                &VaultContext { account, vault: id },
                forged.shared_key.as_bytes(),
            )
            .unwrap()
            .to_bytes()
            .to_vec(),
        ));
        assert!(check(me.public(), account, id, &forged, &marks).is_err());
        forged.shared_key_signature = good.shared_key_signature.clone();
        assert!(check(me.public(), account, id, &forged, &marks).is_err());

        // Another owner, even with a valid signature by that owner.
        let other = AccountId::generate();
        let theirs = vault(&me, other, id, true);
        assert!(check(me.public(), account, id, &theirs, &marks).is_err());
        // A record for another vault.
        assert!(check(me.public(), account, VaultId::generate(), &good, &marks).is_err());
    }

    #[test]
    fn unsigned_vaults_only_before_the_signing_pass() {
        let me = IdentityKeyPair::generate();
        let account = AccountId::generate();
        let id = VaultId::generate();
        let legacy = vault(&me, account, id, false);
        let mut marks = Marks::default();
        assert_eq!(
            check(me.public(), account, id, &legacy, &marks),
            Ok(KeyTrust::Unsigned)
        );
        // Seen signed once: never again without a signature.
        marks.signed_vaults.insert(id);
        assert!(check(me.public(), account, id, &legacy, &marks).is_err());
        // After the signing pass, no unsigned vault at all.
        let mut marks = Marks {
            vault_keys_signed: true,
            ..Marks::default()
        };
        assert!(check(me.public(), account, id, &legacy, &marks).is_err());
        marks.vault_keys_signed = false;
        assert!(check(me.public(), account, id, &legacy, &marks).is_ok());
    }

    #[test]
    fn tofu_only_signs_the_key_this_device_had() {
        let me = IdentityKeyPair::generate();
        let account = AccountId::generate();
        let id = VaultId::generate();
        let cached = vault(&me, account, id, false);
        // Same bytes as in the sealed cache.
        assert_eq!(tofu(Some(&cached), &cached.clone()), Ok(true));
        // The server swapped the key for one it chose (sealed for us too).
        let swapped = vault(&me, account, id, false);
        assert!(tofu(Some(&cached), &swapped).is_err());
        // A device that never had it: trusted as listed (residual risk 32).
        assert_eq!(tofu(None, &swapped), Ok(false));
    }
}
