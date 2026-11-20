//! XChaCha20-Poly1305 envelope used by every symmetric blob (spec §3.1):
//!
//! `header(2) ‖ nonce(24) ‖ ciphertext ‖ tag(16)` with
//! `AAD = header ‖ tuple(label, context…)`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use super::encoding::{Kind, Tuple, aad, strip_header};
use super::keys::KEY_LEN;
use super::{CryptoError, random};

/// XChaCha20 nonce length.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Bytes added by the envelope: header, nonce and tag.
pub const OVERHEAD: usize = 2 + NONCE_LEN + TAG_LEN;

/// Seals `plaintext` with a fresh random nonce.
pub(crate) fn seal(key: &[u8; KEY_LEN], kind: Kind, context: &Tuple, plaintext: &[u8]) -> Vec<u8> {
    seal_with_nonce(key, kind, context, &random::array::<NONCE_LEN>(), plaintext)
}

/// Seals `plaintext` with an explicit nonce. Only tests and vector generation
/// pass a fixed nonce; production code always goes through [`seal`].
pub(crate) fn seal_with_nonce(
    key: &[u8; KEY_LEN],
    kind: Kind,
    context: &Tuple,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Vec<u8> {
    let header = kind.header();
    let aad = aad(&header, context);
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption cannot fail for in-memory buffers");
    let mut out = Vec::with_capacity(OVERHEAD + plaintext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Opens a blob produced by [`seal`] for the given `kind` and `context`.
pub(crate) fn open(
    key: &[u8; KEY_LEN],
    kind: Kind,
    context: &Tuple,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let body = strip_header(blob, kind)?;
    if body.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::Malformed("ciphertext too short"));
    }
    let (nonce, ciphertext) = body.split_at(NONCE_LEN);
    let nonce = XNonce::try_from(nonce).map_err(|_| CryptoError::Malformed("nonce"))?;
    let aad = aad(&kind.header(), context);
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decryption)
}
