//! Attachments (api.md §6, spec §10): encrypted with STREAM under a fresh
//! attachment key, which is wrapped with the item key. Used by `File`
//! fields, e.g. an Apple `.p8` that `klav inject` writes to disk.

use klav_core::crypto::attachment::{decrypt_attachment_bytes, encrypt_attachment_bytes};
use klav_core::crypto::context::AttachmentContext;
use klav_core::crypto::keys::AttachmentKey;
use klav_core::crypto::wrap::{unwrap_attachment_key, wrap_attachment_key};
use klav_core::ids::AttachmentId;
use klav_core::model::item::{AttachmentMeta, Field, FieldKind, FieldValue};
use klav_proto::Blob;
use klav_proto::sync::{Attachment, CreateAttachment, UploadProgress};
use reqwest::Method;
use zeroize::Zeroizing;

use crate::api::{self, Body};
use crate::error::{ClientError, ClientResult};
use crate::session::{ItemLocation, ItemSummary, Unlocked};

/// Largest chunk sent in one request (the server accepts up to 8 MiB).
const UPLOAD_CHUNK: usize = 4 * 1024 * 1024;

/// Largest plaintext accepted (the server limit is 100 MiB of ciphertext).
pub const MAX_ATTACHMENT_BYTES: usize = 64 * 1024 * 1024;

/// Ciphertext size of the largest attachment: header, plus one tag per
/// chunk of the smallest chunk size (a peer may choose it).
fn max_ciphertext() -> u64 {
    use klav_core::crypto::attachment::{HEADER_LEN, MIN_CHUNK_SIZE, TAG_LEN};
    let plain = MAX_ATTACHMENT_BYTES as u64;
    let chunks = plain / u64::from(MIN_CHUNK_SIZE) + 1;
    HEADER_LEN as u64 + plain + chunks * TAG_LEN as u64
}

impl Unlocked {
    fn attachment_ctx(
        &self,
        loc: ItemLocation,
        id: AttachmentId,
    ) -> ClientResult<AttachmentContext> {
        let (ctx, _, _) = self.item_parts(loc)?;
        Ok(AttachmentContext {
            account: ctx.account,
            vault: ctx.vault,
            project: ctx.project,
            item: ctx.item,
            attachment: id,
        })
    }

    /// Encrypts and uploads `plaintext` as a new attachment of `loc`
    /// (create, chunked upload, complete). Does not change the item.
    async fn upload_attachment(
        &mut self,
        loc: ItemLocation,
        plaintext: &[u8],
    ) -> ClientResult<AttachmentId> {
        if plaintext.len() > MAX_ATTACHMENT_BYTES {
            return Err(ClientError::Invalid(format!(
                "attachments are limited to {} MiB",
                MAX_ATTACHMENT_BYTES / (1024 * 1024)
            )));
        }
        let id = AttachmentId::generate();
        let actx = self.attachment_ctx(loc, id)?;
        let (_, item_key, wire) = self.item_parts(loc)?;
        // The version whose key wraps the attachment key: if the item got a
        // new key meanwhile, the server refuses the upload (409).
        let item_version = wire.version;
        let key = AttachmentKey::generate();
        let wrapped = wrap_attachment_key(&item_key, &actx, &key);
        drop(item_key);
        let blob = encrypt_attachment_bytes(&key, &actx, plaintext);
        let vault = loc.vault;
        let declare_path = format!("/v1/vaults/{vault}/items/{}/attachments", loc.item);
        let mut declare = CreateAttachment {
            id,
            size: blob.len() as u64,
            wrapped_key: Blob::new(wrapped),
            item_version: Some(item_version),
        };
        let declared: ClientResult<Attachment> =
            self.send_json(Method::POST, &declare_path, &declare).await;
        match declared {
            Ok(_) => {}
            // A server older than `item_version` refuses the unknown field
            // with a 400 that names it: declare once more without it. Only
            // that 400, so a newer server never gets the declaration
            // without the field for another reason. This opens nothing:
            // the check only ever protected against a server that knows the
            // field, and a server that skips it could already accept an
            // upload under an old item key. The attachment key is still
            // wrapped with the key of the version this client read.
            Err(ClientError::Api {
                status: 400,
                ref message,
                ..
            }) if message.contains("item_version") => {
                declare.item_version = None;
                let _: Attachment = self
                    .send_json(Method::POST, &declare_path, &declare)
                    .await?;
            }
            Err(e) => return Err(e),
        }
        let mut offset = 0usize;
        while offset < blob.len() {
            let end = (offset + UPLOAD_CHUNK).min(blob.len());
            let res = self
                .authed(
                    Method::PUT,
                    &format!("/v1/vaults/{vault}/attachments/{id}/content?offset={offset}"),
                    &Body::Bytes(&blob[offset..end]),
                )
                .await?;
            let progress: UploadProgress = api::json(res).await?;
            if progress.received != end as u64 {
                return Err(ClientError::Corrupt(format!(
                    "upload of attachment {id}: server reports {} bytes, sent {end}",
                    progress.received
                )));
            }
            offset = end;
        }
        let res = self
            .authed(
                Method::POST,
                &format!("/v1/vaults/{vault}/attachments/{id}/complete"),
                &Body::Empty,
            )
            .await?;
        let _: Attachment = api::json(res).await?;
        Ok(id)
    }

    /// Stores `content` in the `File` field `field` of the item `query`
    /// (created if missing, replaced if present) and uploads the next item
    /// version. The previous attachment of that field, if any, is deleted.
    pub async fn attach(
        &mut self,
        query: &str,
        field: &str,
        file_name: &str,
        media_type: Option<&str>,
        content: &[u8],
    ) -> ClientResult<ItemSummary> {
        let loc = self.find_item(query)?;
        let mut item = self.open_item(loc)?;
        let previous = match item.field(field) {
            Some(f) if f.kind() != FieldKind::File => {
                return Err(ClientError::Invalid(format!(
                    "field {field:?} is not a file field"
                )));
            }
            Some(f) => match f.value() {
                FieldValue::File(id) => Some(*id),
                _ => None,
            },
            None => None,
        };
        let id = self.upload_attachment(loc, content).await?;
        let meta = AttachmentMeta {
            id,
            file_name: file_name.to_owned(),
            size: content.len() as u64,
            media_type: media_type.map(str::to_owned),
        };
        item.add_attachment(meta)?;
        match item.field_mut(field) {
            Some(f) => f.set_value(&id.to_string())?,
            None => item.add_field(Field::new(field, "", FieldKind::File, &id.to_string())?)?,
        }
        if let Some(old) = previous {
            item.remove_attachment(old);
        }
        self.update_item(loc, &item).await?;
        if let Some(old) = previous {
            // Best effort: the item no longer references it.
            let _ = self.delete_attachment(loc, old).await;
        }
        self.item_summary(loc)
    }

    /// Deletes an attachment on the server (the item must already have
    /// stopped referencing it).
    pub(crate) async fn delete_attachment(
        &mut self,
        loc: ItemLocation,
        id: AttachmentId,
    ) -> ClientResult<()> {
        let res = self
            .authed(
                Method::DELETE,
                &format!("/v1/vaults/{}/attachments/{id}", loc.vault),
                &Body::Empty,
            )
            .await?;
        api::empty(res).await
    }

    /// Downloads and decrypts the attachment `id` of the item at `loc`.
    pub async fn download_attachment(
        &mut self,
        loc: ItemLocation,
        id: AttachmentId,
    ) -> ClientResult<Zeroizing<Vec<u8>>> {
        let wire = self
            .cached_attachment(loc.vault, id)
            .filter(|a| a.item_id == loc.item)
            .ok_or_else(|| ClientError::NotFound(format!("attachment {id}")))?;
        let size = wire.size;
        // The size is the server's word: never ask for more than the
        // largest attachment this client uploads, encrypted.
        if size > max_ciphertext() {
            return Err(ClientError::Security(format!(
                "attachment {id}: the server lists {size} bytes, more than any attachment can have"
            )));
        }
        let wrapped = wire
            .wrapped_key
            .clone()
            .ok_or_else(|| ClientError::Corrupt(format!("attachment {id} without key")))?;
        let actx = self.attachment_ctx(loc, id)?;
        let (_, item_key, _) = self.item_parts(loc)?;
        let key = unwrap_attachment_key(&item_key, &actx, wrapped.as_bytes())?;
        drop(item_key);
        let res = self
            .authed(
                Method::GET,
                &format!("/v1/vaults/{}/attachments/{id}/content", loc.vault),
                &Body::Empty,
            )
            .await?;
        if !res.status().is_success() {
            return Err(api::error(res).await);
        }
        let blob = api::read_limited(res, usize::try_from(size).unwrap_or(usize::MAX)).await?;
        if blob.len() as u64 != size {
            return Err(ClientError::Corrupt(format!(
                "attachment {id}: {} bytes received, {size} expected",
                blob.len()
            )));
        }
        Ok(decrypt_attachment_bytes(&key, &actx, &blob)?)
    }
}
