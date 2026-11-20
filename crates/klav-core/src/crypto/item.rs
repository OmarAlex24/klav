//! Item encryption (spec §7).
//!
//! An item is stored as two independent ciphertexts under its item key:
//!
//! * **overview** (kind `0x10`): metadata visible with the `list` permission
//!   (title, type, URLs, username, tags);
//! * **details** (kind `0x11`): fields and notes.
//!
//! `AAD = header ‖ tuple(label, account_id, vault_id, project_id, item_id,
//! u64_be(version))`, so the server can neither move a section to another item
//! nor serve an older version under a newer version number.

use zeroize::Zeroizing;

use super::context::ItemContext;
use super::encoding::{Kind, Tuple};
use super::keys::{ItemKey, sealed::Sealed};
use super::{CryptoError, aead};

/// Label of the overview section.
pub const LABEL_OVERVIEW: &str = "klav/v1/item/overview";
/// Label of the details section.
pub const LABEL_DETAILS: &str = "klav/v1/item/details";

/// Which section of an item a ciphertext holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    /// Metadata visible with `list`.
    Overview,
    /// Fields and notes.
    Details,
}

impl Section {
    fn kind(self) -> Kind {
        match self {
            Section::Overview => Kind::ItemOverview,
            Section::Details => Kind::ItemDetails,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Section::Overview => LABEL_OVERVIEW,
            Section::Details => LABEL_DETAILS,
        }
    }
}

pub(crate) fn item_tuple(section: Section, ctx: &ItemContext, version: u64) -> Tuple {
    let mut t = Tuple::new(section.label());
    t.push(ctx.account.as_bytes())
        .push(ctx.vault.as_bytes())
        .push(ctx.project.as_bytes())
        .push(ctx.item.as_bytes())
        .push_u64(version);
    t
}

/// Encrypts one section of an item at `version`.
pub fn encrypt_item_section(
    key: &ItemKey,
    ctx: &ItemContext,
    version: u64,
    section: Section,
    plaintext: &[u8],
) -> Vec<u8> {
    aead::seal(
        key.secret_bytes(),
        section.kind(),
        &item_tuple(section, ctx, version),
        plaintext,
    )
}

#[cfg(test)]
pub(crate) fn encrypt_item_section_with_nonce(
    key: &ItemKey,
    ctx: &ItemContext,
    version: u64,
    section: Section,
    nonce: &[u8; aead::NONCE_LEN],
    plaintext: &[u8],
) -> Vec<u8> {
    aead::seal_with_nonce(
        key.secret_bytes(),
        section.kind(),
        &item_tuple(section, ctx, version),
        nonce,
        plaintext,
    )
}

/// Decrypts one section of an item. `version` is the version the caller
/// expects (from sync metadata); a ciphertext from any other version fails.
pub fn decrypt_item_section(
    key: &ItemKey,
    ctx: &ItemContext,
    version: u64,
    section: Section,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    aead::open(
        key.secret_bytes(),
        section.kind(),
        &item_tuple(section, ctx, version),
        blob,
    )
}
