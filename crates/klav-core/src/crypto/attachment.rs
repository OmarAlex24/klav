//! Attachment encryption with STREAM (spec §10), Hoang–Reyhanitabar–Rogaway–
//! Vizár "online AE", as implemented by RustCrypto `aead-stream`
//! (`StreamBE32`) over XChaCha20-Poly1305.
//!
//! ```text
//! header  = 0x01 ‖ 0x30 ‖ u32_be(chunk_size) ‖ nonce_prefix(19)      (25 bytes)
//! nonce_i = nonce_prefix ‖ u32_be(i) ‖ last_flag(0x00 | 0x01)
//! aad     = header ‖ tuple("klav/v1/attachment", account, vault, project, item, attachment)
//! body    = chunk_0 ‖ … ‖ chunk_n      chunk = ciphertext ‖ tag(16)
//! ```
//!
//! Every chunk but the last carries exactly `chunk_size` plaintext bytes; the
//! last carries `1..=chunk_size` bytes (or `0` for an empty attachment) and is
//! sealed with `last_flag = 1`. Reordering, dropping or appending chunks, and
//! truncating the stream, all fail authentication.

use std::io::{Read, Write};

use aead_stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{KeyInit, Payload};
use zeroize::Zeroizing;

use super::context::AttachmentContext;
use super::encoding::{FORMAT_V1, Kind, Tuple, aad};
use super::keys::{AttachmentKey, sealed::Sealed};
use super::{CryptoError, random};

/// Label of the attachment AAD tuple.
pub const LABEL_ATTACHMENT: &str = "klav/v1/attachment";
/// Default plaintext bytes per chunk (64 KiB).
pub const DEFAULT_CHUNK_SIZE: u32 = 64 * 1024;
/// Smallest chunk size accepted when decrypting.
pub const MIN_CHUNK_SIZE: u32 = 64;
/// Largest chunk size accepted when decrypting (1 MiB).
pub const MAX_CHUNK_SIZE: u32 = 1024 * 1024;
/// STREAM nonce prefix length (24-byte XChaCha20 nonce minus 5).
pub const NONCE_PREFIX_LEN: usize = 19;
/// Header length.
pub const HEADER_LEN: usize = 2 + 4 + NONCE_PREFIX_LEN;
/// Tag length per chunk.
pub const TAG_LEN: usize = 16;

fn attachment_aad(header: &[u8; HEADER_LEN], ctx: &AttachmentContext) -> Vec<u8> {
    let mut t = Tuple::new(LABEL_ATTACHMENT);
    t.push(ctx.account.as_bytes())
        .push(ctx.vault.as_bytes())
        .push(ctx.project.as_bytes())
        .push(ctx.item.as_bytes())
        .push(ctx.attachment.as_bytes());
    aad(header, &t)
}

/// Reads until `buf` is full or the reader is exhausted; returns bytes read.
fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> Result<usize, CryptoError> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(filled)
}

/// Encrypts everything `reader` yields into `writer`, with the default chunk size.
pub fn encrypt_attachment(
    key: &AttachmentKey,
    ctx: &AttachmentContext,
    reader: impl Read,
    writer: impl Write,
) -> Result<(), CryptoError> {
    encrypt_with(
        key,
        ctx,
        DEFAULT_CHUNK_SIZE,
        &random::array(),
        reader,
        writer,
    )
}

pub(crate) fn encrypt_with(
    key: &AttachmentKey,
    ctx: &AttachmentContext,
    chunk_size: u32,
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    mut reader: impl Read,
    mut writer: impl Write,
) -> Result<(), CryptoError> {
    let mut header = [0u8; HEADER_LEN];
    header[0] = FORMAT_V1;
    header[1] = Kind::Attachment as u8;
    header[2..6].copy_from_slice(&chunk_size.to_be_bytes());
    header[6..].copy_from_slice(nonce_prefix);
    writer.write_all(&header)?;
    let aad = attachment_aad(&header, ctx);

    let cipher = XChaCha20Poly1305::new(&(*key.secret_bytes()).into());
    let mut stream = EncryptorBE32::from_aead(cipher, &(*nonce_prefix).into());

    let size = chunk_size as usize;
    let mut current = Zeroizing::new(vec![0u8; size]);
    let mut next = Zeroizing::new(vec![0u8; size]);
    let mut current_len = read_full(&mut reader, &mut current)?;
    loop {
        let next_len = read_full(&mut reader, &mut next)?;
        if next_len == 0 {
            let chunk = stream
                .encrypt_last(Payload {
                    msg: &current[..current_len],
                    aad: &aad,
                })
                .map_err(|_| CryptoError::Malformed("attachment too large"))?;
            writer.write_all(&chunk)?;
            writer.flush()?;
            return Ok(());
        }
        let chunk = stream
            .encrypt_next(Payload {
                msg: &current[..current_len],
                aad: &aad,
            })
            .map_err(|_| CryptoError::Malformed("attachment too large"))?;
        writer.write_all(&chunk)?;
        std::mem::swap(&mut current, &mut next);
        current_len = next_len;
    }
}

/// Decrypts an attachment from `reader` into `writer`.
///
/// Plaintext is written chunk by chunk as each chunk authenticates. If this
/// returns an error, **discard everything written so far**: the stream was
/// truncated or tampered with.
pub fn decrypt_attachment(
    key: &AttachmentKey,
    ctx: &AttachmentContext,
    mut reader: impl Read,
    mut writer: impl Write,
) -> Result<(), CryptoError> {
    let mut header = [0u8; HEADER_LEN];
    if read_full(&mut reader, &mut header)? != HEADER_LEN {
        return Err(CryptoError::Malformed("attachment header truncated"));
    }
    if header[0] != FORMAT_V1 {
        return Err(CryptoError::UnsupportedVersion(header[0]));
    }
    if header[1] != Kind::Attachment as u8 {
        return Err(CryptoError::UnexpectedKind {
            expected: Kind::Attachment as u8,
            found: header[1],
        });
    }
    let chunk_size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]);
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(CryptoError::Malformed("attachment chunk size out of range"));
    }
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    nonce_prefix.copy_from_slice(&header[6..]);
    let aad = attachment_aad(&header, ctx);

    let cipher = XChaCha20Poly1305::new(&(*key.secret_bytes()).into());
    let mut stream = DecryptorBE32::from_aead(cipher, &nonce_prefix.into());

    let segment = chunk_size as usize + TAG_LEN;
    let mut current = vec![0u8; segment];
    let mut next = vec![0u8; segment];
    let mut current_len = read_full(&mut reader, &mut current)?;
    if current_len < TAG_LEN {
        return Err(CryptoError::Malformed("attachment body truncated"));
    }
    loop {
        let next_len = read_full(&mut reader, &mut next)?;
        if next_len == 0 {
            let plaintext = Zeroizing::new(
                stream
                    .decrypt_last(Payload {
                        msg: &current[..current_len],
                        aad: &aad,
                    })
                    .map_err(|_| CryptoError::Decryption)?,
            );
            writer.write_all(&plaintext)?;
            writer.flush()?;
            return Ok(());
        }
        if current_len != segment {
            return Err(CryptoError::Decryption);
        }
        let plaintext = Zeroizing::new(
            stream
                .decrypt_next(Payload {
                    msg: &current[..],
                    aad: &aad,
                })
                .map_err(|_| CryptoError::Decryption)?,
        );
        writer.write_all(&plaintext)?;
        std::mem::swap(&mut current, &mut next);
        current_len = next_len;
    }
}

/// In-memory convenience wrapper around [`encrypt_attachment`].
pub fn encrypt_attachment_bytes(
    key: &AttachmentKey,
    ctx: &AttachmentContext,
    plaintext: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        HEADER_LEN
            + plaintext.len()
            + TAG_LEN * (plaintext.len() / DEFAULT_CHUNK_SIZE as usize + 1),
    );
    encrypt_attachment(key, ctx, plaintext, &mut out)
        .expect("in-memory I/O cannot fail and attachments fit in 2^32 chunks");
    out
}

/// In-memory convenience wrapper around [`decrypt_attachment`].
pub fn decrypt_attachment_bytes(
    key: &AttachmentKey,
    ctx: &AttachmentContext,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut out = Zeroizing::new(Vec::with_capacity(blob.len()));
    decrypt_attachment(key, ctx, blob, &mut *out)?;
    Ok(out)
}
