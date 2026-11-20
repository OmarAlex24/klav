//! Imports from other password managers (ADR 0024) for the iOS wizard.
//! An [`ImportSession`] holds the files read so far; [`KlavCore`] previews
//! and applies it. Google Authenticator's QR codes are read by the app
//! (AVFoundation, Core Image) and come in as their `otpauth-migration://`
//! text: this library reads no images.

use std::sync::{Arc, Mutex, MutexGuard};

use klav_client::klav_import::{ImportSet, MissingBatch, Remark, Row, Source};
use serde::Serialize;

use crate::{
    ImportFileInfo, ImportMissingInfo, ImportPreviewInfo, ImportRemarkInfo, ImportResultInfo,
    ImportRowInfo, ImportStateInfo, KlavCore, KlavError, KlavResult,
};

/// Rows in a preview.
const PREVIEW_ROWS: usize = 1000;

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn wire<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn remarks(list: &[Remark]) -> Vec<ImportRemarkInfo> {
    list.iter()
        .map(|r| ImportRemarkInfo {
            at: r.at.clone(),
            reason: r.reason.clone(),
        })
        .collect()
}

fn missing(list: Vec<MissingBatch>) -> Vec<ImportMissingInfo> {
    list.into_iter()
        .map(|m| ImportMissingInfo {
            size: m.size,
            missing: m.missing,
        })
        .collect()
}

fn row(r: Row) -> ImportRowInfo {
    ImportRowInfo {
        kind: r.kind.into(),
        action: wire(&r.action),
        changes: r.changes.iter().map(wire).collect(),
        title: r.title,
        username: r.username,
        host: r.host,
        target: r.target,
        sites_added: r.sites_added,
    }
}

/// The files of one import, read in memory and forgotten with the object.
#[derive(uniffi::Object)]
pub struct ImportSession {
    set: Mutex<ImportSet>,
}

impl ImportSession {
    fn set(&self) -> MutexGuard<'_, ImportSet> {
        self.set
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[uniffi::export]
impl ImportSession {
    /// An empty import.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            set: Mutex::new(ImportSet::new()),
        })
    }

    /// Reads a file (or the text of a QR code) and adds what it holds.
    /// `from` is what the person chose (`bitwarden`, `google`…); the
    /// content is checked against it. Errors carry no values.
    pub fn add(&self, name: String, data: Vec<u8>, from: Option<String>) -> KlavResult<()> {
        let source = from
            .as_deref()
            .map(|f| {
                Source::parse(f).ok_or_else(|| KlavError::invalid(format!("unknown source {f}")))
            })
            .transpose()?;
        let data = zeroize::Zeroizing::new(data);
        self.set()
            .add(&name, &data, source)
            .map(|_| ())
            .map_err(|e| KlavError::invalid(format!("{name}: {e}")))
    }

    /// The files so far.
    pub fn state(&self) -> ImportStateInfo {
        let set = self.set();
        ImportStateInfo {
            files: set
                .sources()
                .iter()
                .map(|s| ImportFileInfo {
                    name: s.name.clone(),
                    format: s.format.name().to_owned(),
                    items: count(s.items),
                    skipped: remarks(&s.skipped),
                    notes: remarks(&s.notes),
                    more_remarks: count(s.more_remarks),
                    passkeys: count(s.passkeys),
                })
                .collect(),
            entries: count(set.entries().len()),
            passkeys: count(set.passkeys()),
            missing: missing(set.missing_batches()),
        }
    }
}

#[uniffi::export]
impl KlavCore {
    /// What importing `session` into `vault` / `project` (names; the
    /// default ones when absent) would do. Changes nothing.
    pub fn import_preview(
        &self,
        session: Arc<ImportSession>,
        vault: Option<String>,
        project: Option<String>,
    ) -> KlavResult<ImportPreviewInfo> {
        let set = session.set();
        self.with(|u| {
            let p = u.import_preview(&set, vault.as_deref(), project.as_deref(), PREVIEW_ROWS)?;
            Ok(ImportPreviewInfo {
                vault: p.vault,
                project: p.project,
                new: count(p.totals.new),
                merged: count(p.totals.merged),
                duplicates: count(p.totals.duplicates),
                rows: p.rows.into_iter().map(row).collect(),
                rows_total: count(p.rows_total),
                passkeys: count(p.passkeys),
                missing: missing(p.missing),
            })
        })
    }

    /// Imports `session`: creates the new items, merges into the existing
    /// ones (replaced passwords go to their history) and syncs.
    pub fn import_apply(
        &self,
        session: Arc<ImportSession>,
        vault: Option<String>,
        project: Option<String>,
    ) -> KlavResult<ImportResultInfo> {
        let set = session.set();
        self.writing(|u| {
            let r = self.runtime.block_on(u.import_apply(
                &set,
                vault.as_deref(),
                project.as_deref(),
            ))?;
            Ok(ImportResultInfo {
                vault: r.vault,
                project: r.project,
                created: count(r.created),
                updated: count(r.updated),
                duplicates: count(r.totals.duplicates),
                passkeys: count(r.passkeys),
                passkeys_failed: r.passkeys_failed,
            })
        })
    }
}
