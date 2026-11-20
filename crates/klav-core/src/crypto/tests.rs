//! Cross-module tests: roundtrips, tamper detection and property tests.

use proptest::prelude::*;

use super::CryptoError;
use super::attachment::{self, decrypt_attachment_bytes, encrypt_attachment_bytes};
use super::context::{AttachmentContext, ItemContext, ProjectContext, VaultContext};
use super::identity::IdentityKeyPair;
use super::item::{Section, decrypt_item_section, encrypt_item_section};
use super::keys::{AttachmentKey, ItemKey, ProjectKey, VaultKey, sealed::Sealed};
use super::share;
use crate::ids::{AccountId, AttachmentId, ItemId, ProjectId, VaultId};

fn ctx_from(seed: [[u8; 16]; 4]) -> ItemContext {
    ItemContext {
        account: AccountId::from_bytes(seed[0]),
        vault: VaultId::from_bytes(seed[1]),
        project: ProjectId::from_bytes(seed[2]),
        item: ItemId::from_bytes(seed[3]),
    }
}

fn random_ctx() -> ItemContext {
    ItemContext {
        account: AccountId::generate(),
        vault: VaultId::generate(),
        project: ProjectId::generate(),
        item: ItemId::generate(),
    }
}

/// Every way of moving an item to a different location.
fn moved(ctx: &ItemContext) -> Vec<ItemContext> {
    vec![
        ItemContext {
            account: AccountId::generate(),
            ..*ctx
        },
        ItemContext {
            vault: VaultId::generate(),
            ..*ctx
        },
        ItemContext {
            project: ProjectId::generate(),
            ..*ctx
        },
        ItemContext {
            item: ItemId::generate(),
            ..*ctx
        },
        // Swap two fields: same bytes, different positions.
        ItemContext {
            vault: VaultId::from_bytes(*ctx.project.as_bytes()),
            project: ProjectId::from_bytes(*ctx.vault.as_bytes()),
            ..*ctx
        },
    ]
}

#[test]
fn item_rollback_is_detected() {
    let key = ItemKey::generate();
    let ctx = random_ctx();
    let v4 = encrypt_item_section(&key, &ctx, 4, Section::Details, b"old password");
    let v5 = encrypt_item_section(&key, &ctx, 5, Section::Details, b"new password");
    assert_eq!(
        &**decrypt_item_section(&key, &ctx, 5, Section::Details, &v5).unwrap(),
        b"new password"
    );
    // The server serves the v4 ciphertext while claiming version 5.
    assert_eq!(
        decrypt_item_section(&key, &ctx, 5, Section::Details, &v4).err(),
        Some(CryptoError::Decryption)
    );
}

#[test]
fn item_sections_are_not_interchangeable() {
    let key = ItemKey::generate();
    let ctx = random_ctx();
    let overview = encrypt_item_section(&key, &ctx, 1, Section::Overview, b"{}");
    assert!(matches!(
        decrypt_item_section(&key, &ctx, 1, Section::Details, &overview),
        Err(CryptoError::UnexpectedKind { .. })
    ));
    // Even with the kind byte rewritten, the label in the AAD differs.
    let mut relabeled = overview.clone();
    relabeled[1] = 0x11;
    assert_eq!(
        decrypt_item_section(&key, &ctx, 1, Section::Details, &relabeled).err(),
        Some(CryptoError::Decryption)
    );
}

#[test]
fn share_roundtrip_and_binding() {
    let member = IdentityKeyPair::generate();
    let outsider = IdentityKeyPair::generate();
    let ctx = random_ctx();
    let vault_ctx = VaultContext {
        account: ctx.account,
        vault: ctx.vault,
    };
    let project_ctx = ctx.project_context();

    let vault_key = VaultKey::generate();
    let blob = share::share_vault_key(member.public(), &vault_ctx, &vault_key).unwrap();
    assert_eq!(blob.len(), share::SHARED_KEY_LEN);
    let opened = share::open_shared_vault_key(&member, &vault_ctx, &blob).unwrap();
    assert_eq!(opened.secret_bytes(), vault_key.secret_bytes());
    assert!(share::open_shared_vault_key(&outsider, &vault_ctx, &blob).is_err());
    let other_vault = VaultContext {
        vault: VaultId::generate(),
        ..vault_ctx
    };
    assert!(share::open_shared_vault_key(&member, &other_vault, &blob).is_err());

    let project_key = ProjectKey::generate();
    let blob = share::share_project_key(member.public(), &project_ctx, &project_key).unwrap();
    let opened = share::open_shared_project_key(&member, &project_ctx, &blob).unwrap();
    assert_eq!(opened.secret_bytes(), project_key.secret_bytes());
    let other_project = ProjectContext {
        project: ProjectId::generate(),
        ..project_ctx
    };
    assert!(share::open_shared_project_key(&member, &other_project, &blob).is_err());
    // A vault-key blob is not a project-key blob.
    let vault_blob = share::share_vault_key(member.public(), &vault_ctx, &vault_key).unwrap();
    assert!(share::open_shared_project_key(&member, &project_ctx, &vault_blob).is_err());
}

#[test]
fn vault_key_signature_binds_account_vault_and_blob() {
    let account = IdentityKeyPair::generate();
    let server = IdentityKeyPair::generate();
    let ctx = random_ctx();
    let vault_ctx = ctx.project_context().vault_context();
    let blob = share::share_vault_key(account.public(), &vault_ctx, &VaultKey::generate()).unwrap();
    let sig = share::sign_vault_key(&account, &vault_ctx, &blob).unwrap();
    share::verify_vault_key(account.public(), &vault_ctx, &blob, &sig).unwrap();

    // A key the server chose, sealed for the same account: no valid signature.
    let forged =
        share::share_vault_key(account.public(), &vault_ctx, &VaultKey::generate()).unwrap();
    assert!(share::verify_vault_key(account.public(), &vault_ctx, &forged, &sig).is_err());
    let forged_sig = share::sign_vault_key(&server, &vault_ctx, &forged).unwrap();
    assert!(share::verify_vault_key(account.public(), &vault_ctx, &forged, &forged_sig).is_err());
    // Bound to the vault and the account.
    let other_vault = VaultContext {
        vault: VaultId::generate(),
        ..vault_ctx
    };
    assert!(share::verify_vault_key(account.public(), &other_vault, &blob, &sig).is_err());
    let other_account = VaultContext {
        account: AccountId::generate(),
        ..vault_ctx
    };
    assert!(share::verify_vault_key(account.public(), &other_account, &blob, &sig).is_err());
}

#[test]
fn attachment_rejects_truncation_reordering_and_extension() {
    let key = AttachmentKey::generate();
    let ctx = random_ctx().attachment(AttachmentId::generate());
    let plaintext: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
    let mut blob = Vec::new();
    attachment::encrypt_with(&key, &ctx, 64, &[9; 19], &plaintext[..], &mut blob).unwrap();
    let decrypt = |b: &[u8]| decrypt_attachment_bytes(&key, &ctx, b);
    assert_eq!(&**decrypt(&blob).unwrap(), &plaintext[..]);

    let h = attachment::HEADER_LEN;
    let seg = 64 + attachment::TAG_LEN;
    // Drop the final chunk: the new last chunk was not sealed as final.
    assert!(decrypt(&blob[..h + 4 * seg]).is_err());
    // Drop a middle chunk.
    let dropped = [&blob[..h + seg], &blob[h + 2 * seg..]].concat();
    assert!(decrypt(&dropped).is_err());
    // Swap two chunks.
    let swapped = [
        &blob[..h],
        &blob[h + seg..h + 2 * seg],
        &blob[h..h + seg],
        &blob[h + 2 * seg..],
    ]
    .concat();
    assert!(decrypt(&swapped).is_err());
    // Append garbage.
    let extended = [&blob[..], &[0u8; 20][..]].concat();
    assert!(decrypt(&extended).is_err());
    // Truncate inside the header or body.
    assert!(decrypt(&blob[..h - 1]).is_err());
    assert!(decrypt(&blob[..h + 3]).is_err());
    // Another attachment context.
    let other = AttachmentContext {
        attachment: AttachmentId::generate(),
        ..ctx
    };
    assert!(decrypt_attachment_bytes(&key, &other, &blob).is_err());
    // Chunk size outside the accepted range.
    let mut tiny = blob.clone();
    tiny[2..6].copy_from_slice(&8u32.to_be_bytes());
    assert!(matches!(decrypt(&tiny), Err(CryptoError::Malformed(_))));
}

#[test]
fn attachment_exact_multiple_and_empty() {
    let key = AttachmentKey::generate();
    let ctx = random_ctx().attachment(AttachmentId::generate());
    for len in [0usize, 1, 63, 64, 65, 128, 129] {
        let plaintext = vec![0xAB; len];
        let mut blob = Vec::new();
        attachment::encrypt_with(&key, &ctx, 64, &[1; 19], &plaintext[..], &mut blob).unwrap();
        let chunks = if len == 0 { 1 } else { len.div_ceil(64) };
        assert_eq!(
            blob.len(),
            attachment::HEADER_LEN + len + chunks * attachment::TAG_LEN,
            "len {len}"
        );
        assert_eq!(
            &**decrypt_attachment_bytes(&key, &ctx, &blob).unwrap(),
            &plaintext[..]
        );
    }
}

#[test]
fn attachment_default_chunking_roundtrip() {
    let key = AttachmentKey::generate();
    let ctx = random_ctx().attachment(AttachmentId::generate());
    let plaintext = vec![7u8; attachment::DEFAULT_CHUNK_SIZE as usize * 2 + 5];
    let blob = encrypt_attachment_bytes(&key, &ctx, &plaintext);
    assert_eq!(
        &**decrypt_attachment_bytes(&key, &ctx, &blob).unwrap(),
        &plaintext[..]
    );
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn prop_item_roundtrip(
        key in any::<[u8; 32]>(),
        ids in any::<[[u8; 16]; 4]>(),
        version in any::<u64>(),
        details in any::<bool>(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let key = ItemKey::from_bytes(key);
        let ctx = ctx_from(ids);
        let section = if details { Section::Details } else { Section::Overview };
        let blob = encrypt_item_section(&key, &ctx, version, section, &plaintext);
        prop_assert_eq!(blob.len(), super::aead::OVERHEAD + plaintext.len());
        let opened = decrypt_item_section(&key, &ctx, version, section, &blob).unwrap();
        prop_assert_eq!(&**opened, &plaintext[..]);
    }

    #[test]
    fn prop_item_tamper_is_detected(
        plaintext in proptest::collection::vec(any::<u8>(), 0..256),
        version in 0u64..u64::MAX,
        bit in any::<prop::sample::Index>(),
    ) {
        let key = ItemKey::generate();
        let ctx = random_ctx();
        let blob = encrypt_item_section(&key, &ctx, version, Section::Details, &plaintext);

        // Flip any single bit of the blob.
        let i = bit.index(blob.len() * 8);
        let mut flipped = blob.clone();
        flipped[i / 8] ^= 1 << (i % 8);
        prop_assert!(decrypt_item_section(&key, &ctx, version, Section::Details, &flipped).is_err());

        // Any other location or version.
        for other in moved(&ctx) {
            prop_assert_eq!(
                decrypt_item_section(&key, &other, version, Section::Details, &blob).err(),
                Some(CryptoError::Decryption)
            );
        }
        prop_assert!(decrypt_item_section(&key, &ctx, version + 1, Section::Details, &blob).is_err());

        // Wrong key.
        prop_assert!(decrypt_item_section(&ItemKey::generate(), &ctx, version, Section::Details, &blob).is_err());

        // Truncation.
        let cut = bit.index(blob.len());
        prop_assert!(decrypt_item_section(&key, &ctx, version, Section::Details, &blob[..cut]).is_err());
    }

    #[test]
    fn prop_attachment_roundtrip_and_tamper(
        plaintext in proptest::collection::vec(any::<u8>(), 0..700),
        chunk_size in 64u32..200,
        bit in any::<prop::sample::Index>(),
    ) {
        let key = AttachmentKey::generate();
        let ctx = random_ctx().attachment(AttachmentId::generate());
        let mut blob = Vec::new();
        attachment::encrypt_with(&key, &ctx, chunk_size, &super::random::array(), &plaintext[..], &mut blob).unwrap();
        prop_assert_eq!(&**decrypt_attachment_bytes(&key, &ctx, &blob).unwrap(), &plaintext[..]);

        let i = bit.index(blob.len() * 8);
        let mut flipped = blob.clone();
        flipped[i / 8] ^= 1 << (i % 8);
        prop_assert!(decrypt_attachment_bytes(&key, &ctx, &flipped).is_err());

        let cut = bit.index(blob.len());
        prop_assert!(decrypt_attachment_bytes(&key, &ctx, &blob[..cut]).is_err());
    }

    #[test]
    fn prop_attachment_chunks_cannot_be_reordered_duplicated_or_dropped(
        extra in 1usize..64,
        a in 0usize..3,
        b in 0usize..3,
    ) {
        use super::attachment::{HEADER_LEN, TAG_LEN};
        // Three full chunks and a last partial one (T42).
        let chunk = 64usize;
        let plaintext: Vec<u8> = (0..3 * chunk + extra).map(|i| (i % 251) as u8).collect();
        let key = AttachmentKey::generate();
        let ctx = random_ctx().attachment(AttachmentId::generate());
        let mut blob = Vec::new();
        attachment::encrypt_with(&key, &ctx, 64, &super::random::array(), &plaintext[..], &mut blob).unwrap();
        let sealed = chunk + TAG_LEN;
        let span = |i: usize| HEADER_LEN + i * sealed..HEADER_LEN + (i + 1) * sealed;
        let piece = |i: usize| blob[span(i)].to_vec();

        // Swap two full chunks.
        if a != b {
            let mut swapped = blob.clone();
            swapped[span(a)].copy_from_slice(&piece(b));
            swapped[span(b)].copy_from_slice(&piece(a));
            prop_assert!(decrypt_attachment_bytes(&key, &ctx, &swapped).is_err());
        }
        // One full chunk in the place of another (a duplicate).
        if a != b {
            let mut duplicated = blob.clone();
            duplicated[span(b)].copy_from_slice(&piece(a));
            prop_assert!(decrypt_attachment_bytes(&key, &ctx, &duplicated).is_err());
        }
        // A full chunk repeated (one more chunk), or dropped.
        let mut repeated = blob[..span(a).end].to_vec();
        repeated.extend_from_slice(&piece(a));
        repeated.extend_from_slice(&blob[span(a).end..]);
        prop_assert!(decrypt_attachment_bytes(&key, &ctx, &repeated).is_err());
        let mut dropped = blob[..span(a).start].to_vec();
        dropped.extend_from_slice(&blob[span(a).end..]);
        prop_assert!(decrypt_attachment_bytes(&key, &ctx, &dropped).is_err());
        // The last chunk moved to the front.
        let last = blob[HEADER_LEN + 3 * sealed..].to_vec();
        let mut moved = blob[..HEADER_LEN].to_vec();
        moved.extend_from_slice(&last);
        moved.extend_from_slice(&blob[HEADER_LEN..HEADER_LEN + 3 * sealed]);
        prop_assert!(decrypt_attachment_bytes(&key, &ctx, &moved).is_err());
    }

    #[test]
    fn prop_wrapped_key_tamper_is_detected(bit in any::<prop::sample::Index>()) {
        let ctx = random_ctx();
        let project_key = ProjectKey::generate();
        let blob = super::wrap::wrap_item_key(&project_key, &ctx, &ItemKey::generate());
        let i = bit.index(blob.len() * 8);
        let mut flipped = blob.clone();
        flipped[i / 8] ^= 1 << (i % 8);
        prop_assert!(super::wrap::unwrap_item_key(&project_key, &ctx, &flipped).is_err());
    }

    #[test]
    fn prop_shared_key_tamper_is_detected(bit in any::<prop::sample::Index>()) {
        let member = IdentityKeyPair::generate();
        let ctx = random_ctx().project_context();
        let blob = share::share_project_key(member.public(), &ctx, &ProjectKey::generate()).unwrap();
        let i = bit.index(blob.len() * 8);
        let mut flipped = blob.clone();
        flipped[i / 8] ^= 1 << (i % 8);
        prop_assert!(share::open_shared_project_key(&member, &ctx, &flipped).is_err());
    }

    #[test]
    fn prop_tuple_encoding_is_injective(
        a in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..8), 0..5),
        b in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..8), 0..5),
    ) {
        let encode = |fields: &[Vec<u8>]| {
            let mut t = super::encoding::Tuple::new("klav/v1/test");
            for f in fields {
                t.push(f);
            }
            t.into_bytes()
        };
        prop_assert_eq!(a == b, encode(&a) == encode(&b));
    }
}
