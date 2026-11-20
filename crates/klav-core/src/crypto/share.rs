//! Sharing vault, project and item keys with members (people or agents)
//! via HPKE (RFC 9180), spec §8.
//!
//! Suite: DHKEM(X25519, HKDF-SHA256) `0x0020`, HKDF-SHA256 `0x0001`,
//! ChaCha20-Poly1305 `0x0003`, mode `base`.
//!
//! Blob: `header(2) ‖ enc(32) ‖ ciphertext(32) ‖ tag(16)`.
//! `info = tuple(label, account_id, vault_id, [project_id, [item_id,]] recipient_fingerprint)`,
//! `aad = header`.

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::rand_core::CryptoRng;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use secrecy::SecretBox;
use zeroize::Zeroizing;

use super::CryptoError;
use super::context::{ItemContext, ProjectContext, VaultContext};
use super::encoding::{Kind, Tuple, strip_header};
use super::identity::{IdentityKeyPair, PublicIdentity};
use super::keys::{ItemKey, KEY_LEN, ProjectKey, SymmetricKey, VaultKey, sealed::Sealed};
use super::sign::{self, Signature};

/// Label of a vault key shared with a member.
pub const LABEL_VAULT_KEY: &str = "klav/v1/share/vault-key";
/// Label of a project key shared with a member.
pub const LABEL_PROJECT_KEY: &str = "klav/v1/share/project-key";
/// Label of an item key shared with an agent (a per-item grant, ADR 0036 §2).
pub const LABEL_ITEM_KEY: &str = "klav/v1/share/item-key";
/// Length of the HPKE encapsulated key.
pub const ENC_LEN: usize = 32;
/// Length of every shared-key blob: header(2) ‖ enc(32) ‖ key(32) ‖ tag(16).
pub const SHARED_KEY_LEN: usize = 2 + ENC_LEN + KEY_LEN + 16;

type EncappedKey = <X25519HkdfSha256 as Kem>::EncappedKey;
type HpkePublicKey = <X25519HkdfSha256 as Kem>::PublicKey;
pub(crate) type HpkePrivateKey = <X25519HkdfSha256 as Kem>::PrivateKey;

pub(crate) fn vault_info(ctx: &VaultContext, recipient: &PublicIdentity) -> Tuple {
    let mut t = Tuple::new(LABEL_VAULT_KEY);
    t.push(ctx.account.as_bytes())
        .push(ctx.vault.as_bytes())
        .push(&recipient.fingerprint());
    t
}

pub(crate) fn project_info(ctx: &ProjectContext, recipient: &PublicIdentity) -> Tuple {
    let mut t = Tuple::new(LABEL_PROJECT_KEY);
    t.push(ctx.account.as_bytes())
        .push(ctx.vault.as_bytes())
        .push(ctx.project.as_bytes())
        .push(&recipient.fingerprint());
    t
}

pub(crate) fn item_info(ctx: &ItemContext, recipient: &PublicIdentity) -> Tuple {
    let mut t = Tuple::new(LABEL_ITEM_KEY);
    t.push(ctx.account.as_bytes())
        .push(ctx.vault.as_bytes())
        .push(ctx.project.as_bytes())
        .push(ctx.item.as_bytes())
        .push(&recipient.fingerprint());
    t
}

/// Raw HPKE single-shot seal for the Klav suite: returns `(enc, ciphertext ‖ tag)`.
pub(crate) fn hpke_seal(
    recipient_pk: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let pk = HpkePublicKey::from_bytes(recipient_pk).map_err(|_| CryptoError::InvalidPublicKey)?;
    let (enc, ciphertext) = hpke::single_shot_seal_with_rng::<
        ChaCha20Poly1305,
        HkdfSha256,
        X25519HkdfSha256,
    >(&OpModeS::Base, &pk, info, plaintext, aad, rng)
    .map_err(|_| CryptoError::Encapsulation)?;
    Ok((enc.to_bytes().to_vec(), ciphertext))
}

/// Raw HPKE single-shot open for the Klav suite.
pub(crate) fn hpke_open(
    recipient_sk: &HpkePrivateKey,
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let enc =
        EncappedKey::from_bytes(enc).map_err(|_| CryptoError::Malformed("encapsulated key"))?;
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        recipient_sk,
        &enc,
        info,
        ciphertext,
        aad,
    )
    .map(Zeroizing::new)
    .map_err(|_| CryptoError::Decryption)
}

pub(crate) fn seal_with_rng(
    recipient: &PublicIdentity,
    kind: Kind,
    info: &Tuple,
    key: &[u8; KEY_LEN],
    rng: &mut impl CryptoRng,
) -> Result<Vec<u8>, CryptoError> {
    recipient.hpke_public_key()?;
    let header = kind.header();
    let (enc, ciphertext) = hpke_seal(recipient.x25519(), info.as_bytes(), &header, key, rng)?;
    let mut out = Vec::with_capacity(SHARED_KEY_LEN);
    out.extend_from_slice(&header);
    out.extend_from_slice(&enc);
    out.extend_from_slice(&ciphertext);
    debug_assert_eq!(out.len(), SHARED_KEY_LEN);
    Ok(out)
}

fn open<K: SymmetricKey>(
    recipient: &IdentityKeyPair,
    kind: Kind,
    info: &Tuple,
    blob: &[u8],
) -> Result<K, CryptoError> {
    if blob.len() != SHARED_KEY_LEN {
        return Err(CryptoError::Malformed("shared key length"));
    }
    let body = strip_header(blob, kind)?;
    let (enc, ciphertext) = body.split_at(ENC_LEN);
    let plaintext = hpke_open(
        &recipient.hpke_private_key(),
        enc,
        info.as_bytes(),
        &kind.header(),
        ciphertext,
    )?;
    let bytes: [u8; KEY_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Malformed("shared key length"))?;
    Ok(K::from_secret(SecretBox::new(Box::new(bytes))))
}

/// Shares a vault key with `recipient` (kind `0x20`).
pub fn share_vault_key(
    recipient: &PublicIdentity,
    ctx: &VaultContext,
    key: &VaultKey,
) -> Result<Vec<u8>, CryptoError> {
    seal_with_rng(
        recipient,
        Kind::SharedVaultKey,
        &vault_info(ctx, recipient),
        key.secret_bytes(),
        &mut hpke::rand_core::UnwrapErr(getrandom::SysRng),
    )
}

/// Opens a vault key shared with `recipient`.
pub fn open_shared_vault_key(
    recipient: &IdentityKeyPair,
    ctx: &VaultContext,
    blob: &[u8],
) -> Result<VaultKey, CryptoError> {
    open(
        recipient,
        Kind::SharedVaultKey,
        &vault_info(ctx, recipient.public()),
        blob,
    )
}

/// Label of the owner account's signature over its shared vault key
/// (spec §8.3, ADR 0030 §1).
pub const LABEL_VAULT_KEY_SIGNATURE: &str = "klav/v1/sig/vault-key";

fn vault_key_fields<'a>(ctx: &'a VaultContext, shared: &'a [u8]) -> [&'a [u8]; 3] {
    [ctx.account.as_bytes(), ctx.vault.as_bytes(), shared]
}

/// Signs the exact bytes of a shared vault key blob (kind `0x20`) with the
/// owner account identity:
/// `tuple("klav/v1/sig/vault-key", account_id, vault_id, shared_key)`.
///
/// HPKE only proves the blob was sealed **for** the account, whose public
/// identity the server knows; this signature proves the account itself
/// chose the key.
pub fn sign_vault_key(
    account: &IdentityKeyPair,
    ctx: &VaultContext,
    shared: &[u8],
) -> Result<Signature, CryptoError> {
    sign::sign(
        account,
        LABEL_VAULT_KEY_SIGNATURE,
        &vault_key_fields(ctx, shared),
    )
}

/// Verifies a signature made by [`sign_vault_key`].
pub fn verify_vault_key(
    account: &PublicIdentity,
    ctx: &VaultContext,
    shared: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    sign::verify(
        account,
        LABEL_VAULT_KEY_SIGNATURE,
        &vault_key_fields(ctx, shared),
        signature,
    )
}

/// Shares a project key with `recipient` (kind `0x21`), e.g. an agent grant.
pub fn share_project_key(
    recipient: &PublicIdentity,
    ctx: &ProjectContext,
    key: &ProjectKey,
) -> Result<Vec<u8>, CryptoError> {
    seal_with_rng(
        recipient,
        Kind::SharedProjectKey,
        &project_info(ctx, recipient),
        key.secret_bytes(),
        &mut hpke::rand_core::UnwrapErr(getrandom::SysRng),
    )
}

/// Opens a project key shared with `recipient`.
pub fn open_shared_project_key(
    recipient: &IdentityKeyPair,
    ctx: &ProjectContext,
    blob: &[u8],
) -> Result<ProjectKey, CryptoError> {
    open(
        recipient,
        Kind::SharedProjectKey,
        &project_info(ctx, recipient.public()),
        blob,
    )
}

/// Shares one item key with `recipient` (kind `0x23`): a per-item grant
/// (ADR 0036 §2). Unlike a project key, it opens that item only, never the
/// items added to the project later.
pub fn share_item_key(
    recipient: &PublicIdentity,
    ctx: &ItemContext,
    key: &ItemKey,
) -> Result<Vec<u8>, CryptoError> {
    seal_with_rng(
        recipient,
        Kind::SharedItemKey,
        &item_info(ctx, recipient),
        key.secret_bytes(),
        &mut hpke::rand_core::UnwrapErr(getrandom::SysRng),
    )
}

/// Opens an item key shared with `recipient`.
pub fn open_shared_item_key(
    recipient: &IdentityKeyPair,
    ctx: &ItemContext,
    blob: &[u8],
) -> Result<ItemKey, CryptoError> {
    open(
        recipient,
        Kind::SharedItemKey,
        &item_info(ctx, recipient.public()),
        blob,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{AccountId, ItemId, ProjectId, VaultId};

    fn ctx() -> ItemContext {
        ItemContext {
            account: AccountId::generate(),
            vault: VaultId::generate(),
            project: ProjectId::generate(),
            item: ItemId::generate(),
        }
    }

    #[test]
    fn an_item_key_opens_only_for_its_item_and_recipient() {
        let agent = IdentityKeyPair::generate();
        let ctx = ctx();
        let key = ItemKey::generate();
        let blob = share_item_key(agent.public(), &ctx, &key).unwrap();
        assert_eq!(blob.len(), SHARED_KEY_LEN);
        assert_eq!(&blob[..2], &[0x01, 0x23]);
        let opened = open_shared_item_key(&agent, &ctx, &blob).unwrap();
        assert_eq!(opened.secret_bytes(), key.secret_bytes());

        // Another item, project, vault or account: the info differs.
        for other in [
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
        ] {
            assert!(open_shared_item_key(&agent, &other, &blob).is_err());
        }
        // Another recipient.
        assert!(open_shared_item_key(&IdentityKeyPair::generate(), &ctx, &blob).is_err());
        // Not a project key, even with the same bytes after the header.
        let project = ProjectContext {
            account: ctx.account,
            vault: ctx.vault,
            project: ctx.project,
        };
        assert!(matches!(
            open_shared_project_key(&agent, &project, &blob),
            Err(CryptoError::UnexpectedKind {
                expected: 0x21,
                found: 0x23
            })
        ));
        let mut relabeled = blob.clone();
        relabeled[1] = Kind::SharedProjectKey as u8;
        assert!(open_shared_project_key(&agent, &project, &relabeled).is_err());
    }
}
