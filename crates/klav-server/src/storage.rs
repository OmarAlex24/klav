//! On-disk storage of encrypted attachments:
//! `<data_dir>/attachments/<vault_id>/<attachment_id>` once complete, with a
//! `.part` suffix while the upload is in progress. Paths are built only from
//! parsed UUIDs, never from client strings.

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use klav_core::ids::{AttachmentId, VaultId};
use tokio::io::AsyncWriteExt;

/// How long [`AttachmentStore::lock_wait`] waits for a busy upload.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// Attachment files plus the set of uploads currently writing.
pub(crate) struct AttachmentStore {
    root: PathBuf,
    busy: Arc<Mutex<HashSet<AttachmentId>>>,
}

/// Exclusive right to write one attachment; released on drop.
pub(crate) struct UploadGuard {
    id: AttachmentId,
    busy: Arc<Mutex<HashSet<AttachmentId>>>,
}

impl Drop for UploadGuard {
    fn drop(&mut self) {
        self.busy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.id);
    }
}

impl AttachmentStore {
    pub(crate) fn new(data_dir: &Path) -> Self {
        Self {
            root: data_dir.join("attachments"),
            busy: Arc::default(),
        }
    }

    fn vault_dir(&self, vault: VaultId) -> PathBuf {
        self.root.join(vault.to_string())
    }

    /// Path of a completed attachment.
    pub(crate) fn path(&self, vault: VaultId, id: AttachmentId) -> PathBuf {
        self.vault_dir(vault).join(id.to_string())
    }

    fn part_path(&self, vault: VaultId, id: AttachmentId) -> PathBuf {
        self.vault_dir(vault).join(format!("{id}.part"))
    }

    /// Claims the attachment for writing, or `None` if another request is
    /// writing it right now.
    pub(crate) fn lock(&self, id: AttachmentId) -> Option<UploadGuard> {
        let mut busy = self
            .busy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        busy.insert(id).then(|| UploadGuard {
            id,
            busy: self.busy.clone(),
        })
    }

    /// Like [`Self::lock`], but waits (polling) until the current writer
    /// is done. For the purge, which has no client to retry: an upload
    /// that took the guard before the purge committed finishes its chunk,
    /// then the files go. Gives up waiting after [`LOCK_WAIT`] (the guard
    /// is only held while one chunk is written) and proceeds without it.
    pub(crate) async fn lock_wait(&self, id: AttachmentId) -> Option<UploadGuard> {
        let deadline = tokio::time::Instant::now() + LOCK_WAIT;
        loop {
            if let Some(guard) = self.lock(id) {
                return Some(guard);
            }
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(attachment = %id, "attachment still busy; removing its files anyway");
                return None;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    /// Bytes written so far to an unfinished upload.
    pub(crate) async fn received(&self, vault: VaultId, id: AttachmentId) -> io::Result<u64> {
        match tokio::fs::metadata(self.part_path(vault, id)).await {
            Ok(meta) => Ok(meta.len()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(e),
        }
    }

    /// Appends a chunk to an unfinished upload (caller holds the guard and
    /// has checked the offset).
    pub(crate) async fn append(
        &self,
        _guard: &UploadGuard,
        vault: VaultId,
        id: AttachmentId,
        chunk: &[u8],
    ) -> io::Result<()> {
        tokio::fs::create_dir_all(self.vault_dir(vault)).await?;
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.part_path(vault, id))
            .await?;
        file.write_all(chunk).await?;
        file.sync_data().await?;
        Ok(())
    }

    /// Moves a fully uploaded attachment into place.
    pub(crate) async fn finish(
        &self,
        _guard: &UploadGuard,
        vault: VaultId,
        id: AttachmentId,
    ) -> io::Result<()> {
        tokio::fs::rename(self.part_path(vault, id), self.path(vault, id)).await
    }

    /// Undoes [`Self::finish`] when the transaction that completes the
    /// upload fails, so the upload can be completed again.
    pub(crate) async fn unfinish(
        &self,
        _guard: &UploadGuard,
        vault: VaultId,
        id: AttachmentId,
    ) -> io::Result<()> {
        tokio::fs::rename(self.path(vault, id), self.part_path(vault, id)).await
    }

    /// Every vault directory and the attachment files in it, as
    /// `(vault, attachment, is_part)`; names that are not ours are skipped
    /// (and kept). Used by the orphan sweep.
    pub(crate) async fn list(&self) -> io::Result<Vec<(VaultId, Option<(AttachmentId, bool)>)>> {
        let mut out = Vec::new();
        let mut vaults = match tokio::fs::read_dir(&self.root).await {
            Ok(dir) => dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e),
        };
        while let Some(entry) = vaults.next_entry().await? {
            let Some(vault) = entry.file_name().to_str().and_then(|n| n.parse().ok()) else {
                continue;
            };
            if !entry.file_type().await?.is_dir() {
                continue;
            }
            out.push((vault, None));
            let mut files = tokio::fs::read_dir(entry.path()).await?;
            while let Some(file) = files.next_entry().await? {
                let name = file.file_name();
                let Some(name) = name.to_str() else { continue };
                let (stem, part) = match name.strip_suffix(".part") {
                    Some(stem) => (stem, true),
                    None => (name, false),
                };
                if let Ok(id) = stem.parse() {
                    out.push((vault, Some((id, part))));
                }
            }
        }
        Ok(out)
    }

    /// Deletes one file of an attachment: the completed one or the `.part`.
    pub(crate) async fn remove_one(&self, vault: VaultId, id: AttachmentId, part: bool) {
        let path = if part {
            self.part_path(vault, id)
        } else {
            self.path(vault, id)
        };
        if let Err(e) = tokio::fs::remove_file(&path).await
            && e.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(error = %e, "cannot remove attachment file");
        }
    }

    /// Deletes an attachment's files (best effort; missing files are fine).
    pub(crate) async fn remove(&self, vault: VaultId, id: AttachmentId) {
        for path in [self.path(vault, id), self.part_path(vault, id)] {
            if let Err(e) = tokio::fs::remove_file(&path).await
                && e.kind() != io::ErrorKind::NotFound
            {
                tracing::warn!(error = %e, "cannot remove attachment file");
            }
        }
    }

    /// Deletes every attachment file of a vault.
    pub(crate) async fn remove_vault(&self, vault: VaultId) {
        if let Err(e) = tokio::fs::remove_dir_all(self.vault_dir(vault)).await
            && e.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(error = %e, "cannot remove vault attachment directory");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn append_finish_remove() {
        let dir = tempfile::tempdir().unwrap();
        let store = AttachmentStore::new(dir.path());
        let (vault, id) = (VaultId::generate(), AttachmentId::generate());
        let guard = store.lock(id).unwrap();
        assert!(store.lock(id).is_none(), "one writer at a time");
        assert_eq!(store.received(vault, id).await.unwrap(), 0);
        store.append(&guard, vault, id, b"abc").await.unwrap();
        store.append(&guard, vault, id, b"de").await.unwrap();
        assert_eq!(store.received(vault, id).await.unwrap(), 5);
        store.finish(&guard, vault, id).await.unwrap();
        assert_eq!(std::fs::read(store.path(vault, id)).unwrap(), b"abcde");
        drop(guard);
        assert!(store.lock(id).is_some());
        store.remove(vault, id).await;
        assert!(!store.path(vault, id).exists());
        store.remove_vault(vault).await;
    }
}
