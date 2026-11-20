//! Generator history and password history (ADR 0022 §2 and §3).
//!
//! **Generator history.** Every generated password is written first to a
//! local outbox (`generator-outbox.bin`, blob `0x43` sealed with the local
//! key, never sent anywhere) and only then handed to the page. The outbox
//! is flushed in the background into one `generator_history` item of the
//! default vault's system project, which syncs like any other item. Without
//! network the password stays in the outbox.
//!
//! **Password history.** The previous values of an item's `password` and
//! `concealed` fields, from its record (`0x16`, sealed with the vault key,
//! written by `Unlocked::update_item`).

use klav_core::crypto::context::VaultContext;
use klav_core::crypto::local::{open_local_outbox, seal_local_outbox};
use klav_core::ids::ItemId;
use klav_core::model::history::{self, GENERATOR_HISTORY_TITLE, GeneratedEntry};
use klav_core::model::item::{FieldValue, ItemKind};
use klav_core::model::record::PasswordRecord;
use klav_core::model::{Item, SecretValue};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{ClientError, ClientResult};
use crate::home::write_private;
use crate::ops::SecretText;
use crate::session::{ItemLocation, Unlocked, now_ms};

/// File of the local outbox, in the home directory.
pub const OUTBOX_FILE: &str = "generator-outbox.bin";
const OUTBOX_VERSION: u32 = 1;
/// Longest password the history accepts (the generator's maximum).
const MAX_VALUE_LEN: usize = 256;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOutboxEntry {
    value: String,
    created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    saved_in: Option<ItemId>,
}

impl Drop for RawOutboxEntry {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.value);
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOutbox {
    v: u32,
    #[serde(default)]
    generated: Vec<RawOutboxEntry>,
}

/// A generator history entry as shown: no value (see
/// [`Unlocked::generated_value`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedView {
    /// When it was generated (Unix ms); also its ID.
    pub created_at: i64,
    /// The site it was generated for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The login it was saved in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_in: Option<ItemId>,
    /// Title of that login, if this device has it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_in_title: Option<String>,
    /// Still only in this device's outbox (not synced yet).
    pub pending: bool,
}

/// A previous password of an item as shown: no value (see
/// [`Unlocked::previous_password`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviousPasswordView {
    /// Position, newest first: what `previous_password` takes.
    pub index: usize,
    /// Field name.
    pub field: String,
    /// Field label.
    pub label: String,
    /// Since when it was current (Unix ms), if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_ms: Option<i64>,
    /// Until when it was current (Unix ms).
    pub to_ms: i64,
    /// Generated for an assisted change that was never confirmed (ADR 0022
    /// §5): the site may or may not have it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unconfirmed: bool,
}

/// The password history of an item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordHistoryView {
    /// Previous passwords, newest first.
    pub entries: Vec<PreviousPasswordView>,
    /// A new password generated but not confirmed yet (assisted change).
    pub pending: bool,
    /// When that pending password was generated (Unix ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_since: Option<i64>,
}

/// Which generator history entries to delete.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedSelection {
    /// The entries generated at these instants.
    Some(Vec<i64>),
    /// Everything.
    All,
}

fn entry_of(raw: &RawOutboxEntry) -> GeneratedEntry {
    GeneratedEntry {
        value: SecretValue::new(raw.value.as_str()),
        created_at: raw.created_at,
        host: raw.host.clone(),
        saved_in: raw.saved_in,
    }
}

fn raw_of(e: &GeneratedEntry) -> RawOutboxEntry {
    RawOutboxEntry {
        value: e.value.expose().to_owned(),
        created_at: e.created_at,
        host: e.host.clone(),
        saved_in: e.saved_in,
    }
}

impl Unlocked {
    // ---------------------------------------------------------- outbox --

    fn outbox_path(&self) -> std::path::PathBuf {
        self.home().file(OUTBOX_FILE)
    }

    fn load_outbox(&self) -> ClientResult<Vec<GeneratedEntry>> {
        let blob = match std::fs::read(self.outbox_path()) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let plain = open_local_outbox(self.local_key(), &self.ctx, &blob)?;
        let raw: RawOutbox = serde_json::from_slice(&plain)
            .map_err(|_| ClientError::Corrupt("generator outbox".into()))?;
        if raw.v != OUTBOX_VERSION {
            return Err(ClientError::Corrupt("generator outbox version".into()));
        }
        Ok(raw.generated.iter().map(entry_of).collect())
    }

    fn save_outbox(&self, entries: &[GeneratedEntry]) -> ClientResult<()> {
        if entries.is_empty() {
            return match std::fs::remove_file(self.outbox_path()) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
                _ => Ok(()),
            };
        }
        let raw = RawOutbox {
            v: OUTBOX_VERSION,
            generated: entries.iter().map(raw_of).collect(),
        };
        let json = Zeroizing::new(serde_json::to_vec(&raw).expect("outbox serializes"));
        write_private(
            &self.outbox_path(),
            &seal_local_outbox(self.local_key(), &self.ctx, &json),
        )
    }

    /// Records a generated password in the local outbox, durably (the file
    /// is written and synced to disk) before returning: only then may the
    /// caller type it into a page. Works offline.
    pub fn record_generated(&self, value: &str, host: Option<&str>) -> ClientResult<i64> {
        if value.is_empty() || value.chars().count() > MAX_VALUE_LEN {
            return Err(ClientError::Invalid("not a generated password".into()));
        }
        let host = host
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_ascii_lowercase);
        let mut entries = self.load_outbox()?;
        // Unique, increasing instants: the instant is the entry's ID.
        let mut created_at = now_ms();
        while entries.iter().any(|e| e.created_at >= created_at) {
            created_at += 1;
        }
        let entry = GeneratedEntry {
            value: SecretValue::new(value),
            created_at,
            host,
            saved_in: None,
        };
        entry.validate_public()?;
        entries.push(entry);
        self.save_outbox(&entries)?;
        Ok(created_at)
    }

    /// Entries still waiting in the outbox.
    pub fn pending_generated(&self) -> usize {
        self.load_outbox().map_or(0, |e| e.len())
    }

    /// [`Self::pending_generated`] for deciding whether this device's copy
    /// may go: an outbox that cannot be read is an error, not «none».
    pub fn unsent_generated(&self) -> ClientResult<usize> {
        Ok(self.load_outbox()?.len())
    }

    // ------------------------------------------------- history item --

    /// The vault of the generator history: the default one.
    fn history_vault(&self) -> ClientResult<klav_core::ids::VaultId> {
        let (vault, _) = self.destination(None, None)?;
        Ok(vault)
    }

    /// Every generator history item this device has (normally one; two
    /// devices that created it at once leave two, and both are read).
    fn history_items(&self) -> ClientResult<Vec<(ItemLocation, Item)>> {
        let vault = self.history_vault()?;
        let mut out = Vec::new();
        for loc in self.system_items(vault, ItemKind::GeneratorHistory) {
            out.push((loc, self.open_item(loc)?));
        }
        Ok(out)
    }

    /// Every generated password this account knows: the synced history
    /// and the local outbox. What cannot be read is left out.
    #[cfg_attr(not(feature = "health"), allow(dead_code))]
    pub(crate) fn all_generated(&self) -> Vec<GeneratedEntry> {
        let mut all = self.synced_generated().unwrap_or_default();
        all.extend(self.load_outbox().unwrap_or_default());
        all
    }

    fn synced_generated(&self) -> ClientResult<Vec<GeneratedEntry>> {
        let mut all = Vec::new();
        for (_, item) in self.history_items()? {
            history::merge(&mut all, item.generated().iter().cloned());
        }
        Ok(all)
    }

    /// Writes `entries` (after retention) as the generator history,
    /// creating the system project and the item when needed.
    async fn write_generated(
        &mut self,
        mut entries: Vec<GeneratedEntry>,
    ) -> ClientResult<ItemLocation> {
        history::prune(&mut entries, now_ms());
        let items = self.history_items()?;
        match items.first() {
            Some((loc, item)) => {
                let mut first = item.clone();
                first.set_generated(entries)?;
                self.update_item(*loc, &first).await?;
                // Two devices that created the history at once left two
                // items: everything now lives in the first (merged and
                // pruned), so the others are emptied, or their old entries
                // would never expire.
                for (other, item) in items.iter().skip(1) {
                    if item.generated().is_empty() {
                        continue;
                    }
                    let mut emptied = item.clone();
                    emptied.set_generated(Vec::new())?;
                    self.update_item(*other, &emptied).await?;
                }
                Ok(*loc)
            }
            None => {
                let vault = self.history_vault()?;
                let project = self.ensure_system_project(vault).await?;
                let mut item = Item::new(ItemKind::GeneratorHistory, GENERATOR_HISTORY_TITLE)?;
                item.set_generated(entries)?;
                self.add_item(vault, project, &item).await
            }
        }
    }

    /// Moves the outbox into the generator history item. Returns how many
    /// entries went. On failure (offline) the outbox stays as it was.
    pub async fn flush_generated(&mut self) -> ClientResult<usize> {
        let outbox = self.load_outbox()?;
        if outbox.is_empty() {
            return Ok(0);
        }
        // Another device may have written the history since the last sync:
        // `update_item` syncs on a conflict, so one retry merges with theirs.
        let mut attempt = 0;
        loop {
            let mut entries = self.synced_generated()?;
            history::merge(&mut entries, outbox.iter().cloned());
            match self.write_generated(entries).await {
                Err(ClientError::Conflict(_)) if attempt == 0 => attempt += 1,
                other => {
                    other?;
                    break;
                }
            }
        }
        // Entries recorded while uploading stay for the next flush.
        let now = self.load_outbox()?;
        let left: Vec<GeneratedEntry> = now
            .into_iter()
            .filter(|e| {
                !outbox
                    .iter()
                    .any(|o| o.created_at == e.created_at && o.value == e.value)
            })
            .collect();
        self.save_outbox(&left)?;
        Ok(outbox.len())
    }

    /// The generator history, newest first, without values: synced
    /// entries and the ones still in this device's outbox.
    pub fn generator_history(&self) -> ClientResult<Vec<GeneratedView>> {
        let synced = self.synced_generated()?;
        let outbox = self.load_outbox()?;
        let mut all = synced.clone();
        history::merge(&mut all, outbox.iter().cloned());
        history::prune(&mut all, now_ms());
        Ok(all
            .iter()
            .map(|e| GeneratedView {
                created_at: e.created_at,
                host: e.host.clone(),
                saved_in: e.saved_in,
                saved_in_title: e.saved_in.and_then(|id| {
                    self.find_item(&id.to_string())
                        .ok()
                        .and_then(|loc| self.item_summary(loc).ok())
                        .map(|s| s.title)
                }),
                pending: !synced
                    .iter()
                    .any(|s| s.created_at == e.created_at && s.value == e.value),
            })
            .collect())
    }

    /// The value of the generator history entry generated at `created_at`.
    pub fn generated_value(&self, created_at: i64) -> ClientResult<SecretText> {
        let mut all = self.synced_generated()?;
        history::merge(&mut all, self.load_outbox()?);
        // What retention drops is gone, even before the next write.
        history::prune(&mut all, now_ms());
        all.iter()
            .find(|e| e.created_at == created_at)
            .map(|e| SecretText::from(&e.value))
            .ok_or_else(|| ClientError::NotFound("generator history entry".into()))
    }

    /// Deletes generator history entries: writes a new version without them
    /// and then purges the item's stored versions, which would still hold
    /// them. Returns how many went.
    pub async fn delete_generated(&mut self, which: &GeneratedSelection) -> ClientResult<usize> {
        // IDs are the instants of the merged view (see `history::merge`):
        // what they name is found there, and removed wherever its value is.
        let mut all = self.synced_generated()?;
        history::merge(&mut all, self.load_outbox()?);
        let chosen: Vec<SecretValue> = all
            .iter()
            .filter(|e| match which {
                GeneratedSelection::All => true,
                GeneratedSelection::Some(ids) => ids.contains(&e.created_at),
            })
            .map(|e| e.value.clone())
            .collect();
        let hit = |e: &GeneratedEntry| chosen.contains(&e.value);
        let outbox = self.load_outbox()?;
        let kept_outbox: Vec<GeneratedEntry> = outbox.iter().filter(|e| !hit(e)).cloned().collect();
        let mut removed = outbox.len() - kept_outbox.len();
        self.save_outbox(&kept_outbox)?;
        let items = self.history_items()?;
        for (loc, item) in items {
            let before = item.generated().len();
            let kept: Vec<GeneratedEntry> = item
                .generated()
                .iter()
                .filter(|e| !hit(e))
                .cloned()
                .collect();
            if kept.len() == before {
                continue;
            }
            removed += before - kept.len();
            let mut item = item.clone();
            item.set_generated(kept)?;
            self.update_item(loc, &item).await?;
            self.purge_item_versions(loc).await?;
        }
        Ok(removed)
    }

    /// Notes that `item` now holds `value`: the matching generator history
    /// entry gets `saved_in` (and is then kept 30 days instead of 365).
    /// Best effort: a failure never undoes the save.
    pub async fn link_generated(&mut self, item: ItemId, value: &SecretValue) {
        if value.expose().is_empty() {
            return;
        }
        let mut outbox = match self.load_outbox() {
            Ok(o) => o,
            Err(_) => return,
        };
        if let Some(e) = outbox
            .iter_mut()
            .find(|e| &e.value == value && e.saved_in.is_none())
        {
            e.saved_in = Some(item);
            let _ = self.save_outbox(&outbox);
            return;
        }
        let Ok(mut entries) = self.synced_generated() else {
            return;
        };
        let Some(e) = entries
            .iter_mut()
            .find(|e| &e.value == value && e.saved_in.is_none())
        else {
            return;
        };
        e.saved_in = Some(item);
        if let Err(e) = self.write_generated(entries).await {
            self.push_warning(format!("the generator history was not updated ({e})"));
        }
    }

    /// Links a just-saved login to the generator history, if its password
    /// came from the generator.
    pub(crate) async fn link_saved_login(&mut self, loc: ItemLocation) {
        let Ok(item) = self.open_item(loc) else {
            return;
        };
        let password = item
            .fields()
            .iter()
            .find(|f| f.kind() == klav_core::model::FieldKind::Password)
            .and_then(|f| match f.value() {
                FieldValue::Secret(s) => Some(s.clone()),
                _ => None,
            });
        if let Some(password) = password {
            self.link_generated(loc.item, &password).await;
        }
    }

    // ------------------------------------------------ password history --

    fn open_record(&self, loc: ItemLocation) -> ClientResult<(Item, PasswordRecord)> {
        let item = self.open_item(loc)?;
        let record = self.record_of(loc, &item)?;
        Ok((item, record))
    }

    /// The password record of `item` (at `loc`), or an empty one if it has
    /// none yet.
    pub(crate) fn record_of(&self, loc: ItemLocation, item: &Item) -> ClientResult<PasswordRecord> {
        let Some(blob) = item.password_record() else {
            return Ok(PasswordRecord::new());
        };
        let vault = self
            .vaults
            .get(&loc.vault)
            .ok_or_else(|| ClientError::NotFound(format!("vault {}", loc.vault)))?;
        let ctx = VaultContext {
            account: vault.owner,
            vault: loc.vault,
        };
        Ok(PasswordRecord::open(&vault.key, &ctx, loc.item, blob)?)
    }

    /// The previous passwords of an item, newest first, without values.
    pub fn password_history(&self, loc: ItemLocation) -> ClientResult<PasswordHistoryView> {
        let (item, record) = self.open_record(loc)?;
        let entries = record
            .history()
            .iter()
            .rev()
            .enumerate()
            .map(|(index, p)| PreviousPasswordView {
                index,
                field: p.field.clone(),
                label: item
                    .field(&p.field)
                    .map(|f| f.label().to_owned())
                    .filter(|l| !l.is_empty())
                    .unwrap_or_else(|| p.field.clone()),
                from_ms: p.from_ms,
                to_ms: p.to_ms,
                unconfirmed: p.unconfirmed,
            })
            .collect();
        Ok(PasswordHistoryView {
            entries,
            pending: record.pending().is_some(),
            pending_since: record.pending().map(|p| p.created_at_ms),
        })
    }

    /// One previous password (`index` from [`Self::password_history`]).
    pub fn previous_password(&self, loc: ItemLocation, index: usize) -> ClientResult<SecretText> {
        let (_, record) = self.open_record(loc)?;
        record
            .history()
            .iter()
            .rev()
            .nth(index)
            .map(|p| SecretText::from(&p.value))
            .ok_or_else(|| ClientError::NotFound(format!("previous password {index}")))
    }
}

trait ValidatePublic {
    fn validate_public(&self) -> ClientResult<()>;
}

impl ValidatePublic for GeneratedEntry {
    /// The same checks `Item::set_generated` makes, before the entry is
    /// stored anywhere.
    fn validate_public(&self) -> ClientResult<()> {
        let mut probe = Item::new(ItemKind::GeneratorHistory, GENERATOR_HISTORY_TITLE)?;
        probe.set_generated(vec![self.clone()])?;
        Ok(())
    }
}
