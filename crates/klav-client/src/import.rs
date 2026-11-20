//! Imports from other password managers (ADR 0024): the preview, without
//! values, and the import itself, which creates the new items, merges into
//! the existing ones and keeps every replaced password in the history.
//! The parsing and the merge rules live in `klav-import`. An imported
//! passkey's key is sealed with the vault key (`0x15`) here, as the login
//! is saved (ADR 0020).

use klav_core::ids::VaultId;
use klav_core::model::Item;
use klav_core::model::item::SecretValue;
use klav_core::model::passkey::Passkey;
use klav_import::{
    Existing, ImportSet, ImportedPasskey, MissingBatch, Row, SourceReport, Totals, plan,
};
use serde::{Deserialize, Serialize};

use crate::ItemFilter;
use crate::error::{ClientError, ClientResult};
use crate::session::{ItemLocation, Unlocked, now_ms};

/// What an import would do. No secret values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportPreview {
    /// Destination vault (name).
    pub vault: String,
    /// Destination project (name).
    pub project: String,
    /// What each file contributed.
    pub sources: Vec<SourceReport>,
    /// Counts.
    pub totals: Totals,
    /// One row per entry, the first `max_rows`.
    pub rows: Vec<Row>,
    /// How many rows there are in all.
    pub rows_total: usize,
    /// Passkeys that will not be imported.
    pub passkeys: usize,
    /// Google Authenticator codes still missing.
    pub missing: Vec<MissingBatch>,
}

/// What an import did.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportResult {
    /// Destination vault (name).
    pub vault: String,
    /// Destination project (name).
    pub project: String,
    /// Items created.
    pub created: usize,
    /// Items of the project updated.
    pub updated: usize,
    /// Counts per entry.
    pub totals: Totals,
    /// Passkeys not imported.
    pub passkeys: usize,
    /// Passkeys of the file that could not be saved, as `"<title>: <why>"`:
    /// their login was imported without them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passkeys_failed: Vec<String>,
}

impl Unlocked {
    /// The live items of a project, opened.
    fn project_items(
        &self,
        vault: &str,
        project: &str,
    ) -> ClientResult<Vec<(ItemLocation, Existing)>> {
        let filter = ItemFilter {
            vault: Some(vault.to_owned()),
            project: Some(project.to_owned()),
            ..ItemFilter::default()
        };
        let mut out = Vec::new();
        for s in self.list_items(&filter)? {
            let loc = ItemLocation {
                vault: s.vault_id,
                project: s.project_id,
                item: s.id,
            };
            // An item this device cannot open is left alone.
            let Ok(mut item) = self.open_item(loc) else {
                continue;
            };
            // URLs an agent added and nobody confirmed are not sites of the
            // login: an import neither matches nor merges by them, and the
            // version it saves leaves them out instead of confirming them
            // (ADR 0030 §7, as a passkey saved into a login does).
            for url in &s.pending_urls {
                item.remove_url(url);
            }
            let history = self
                .password_history(loc)
                .map(|h| h.entries)
                .unwrap_or_default();
            let password_since = history
                .iter()
                .filter(|h| h.field == "password")
                .map(|h| h.to_ms)
                .max();
            let previous = history
                .iter()
                .filter_map(|h| self.previous_password(loc, h.index).ok())
                .map(|v| SecretValue::new(v.expose()))
                .collect();
            out.push((
                loc,
                Existing {
                    id: s.id,
                    item,
                    password_since,
                    previous,
                },
            ));
        }
        Ok(out)
    }

    /// Names of the destination (default: Personal / General).
    fn import_destination(
        &self,
        vault: Option<&str>,
        project: Option<&str>,
    ) -> ClientResult<(
        klav_core::ids::VaultId,
        klav_core::ids::ProjectId,
        String,
        String,
    )> {
        let (v, p) = self.destination(vault, project)?;
        let names = self
            .projects(Some(v))
            .into_iter()
            .find(|x| x.id == p)
            .map(|x| (x.vault, x.name))
            .ok_or_else(|| ClientError::NotFound(format!("project {p}")))?;
        Ok((v, p, names.0, names.1))
    }

    /// What importing `set` into the destination would do, without
    /// changing anything. At most `max_rows` rows.
    pub fn import_preview(
        &self,
        set: &ImportSet,
        vault: Option<&str>,
        project: Option<&str>,
        max_rows: usize,
    ) -> ClientResult<ImportPreview> {
        let (v, p, vault_name, project_name) = self.import_destination(vault, project)?;
        let existing: Vec<Existing> = self
            .project_items(&v.to_string(), &p.to_string())?
            .into_iter()
            .map(|(_, e)| e)
            .collect();
        let plan = plan(set.entries(), &existing, now_ms());
        let rows_total = plan.rows.len();
        Ok(ImportPreview {
            vault: vault_name,
            project: project_name,
            sources: set.sources().to_vec(),
            totals: plan.totals,
            rows: plan.rows.into_iter().take(max_rows).collect(),
            rows_total,
            passkeys: set.passkeys(),
            missing: set.missing_batches(),
        })
    }

    /// Seals an imported passkey for `item` and puts it there. The plan
    /// already added the passkey's site to the item when it had none, so
    /// the preview showed it: one that would add another is refused.
    fn put_passkey(
        &self,
        vault: VaultId,
        item: &mut Item,
        passkey: &ImportedPasskey,
    ) -> ClientResult<()> {
        let sealed = Passkey::import(
            self.vault_key(vault)?.0,
            &self.vault_ctx(vault)?,
            item.id(),
            passkey.credential_id(),
            &passkey.account(),
            passkey.key(),
        )?;
        let mut with = item.clone();
        with.set_passkey(sealed)?;
        if with.urls() != item.urls() {
            return Err(ClientError::Invalid(
                "its site was not in the preview".into(),
            ));
        }
        *item = with;
        Ok(())
    }

    /// [`Self::put_passkey`], or the reason it failed in `failed`: the
    /// rest of the item is imported all the same.
    fn try_put_passkey(
        &self,
        vault: VaultId,
        item: &mut Item,
        passkey: &ImportedPasskey,
        failed: &mut Vec<String>,
    ) {
        if let Err(e) = self.put_passkey(vault, item, passkey) {
            failed.push(format!("{}: {e}", item.title()));
        }
    }

    /// Imports `set` into the destination: creates the new items, updates
    /// the ones it merges into (their replaced passwords go to the
    /// history) and syncs once. Importing the same files again adds
    /// nothing. If it stops halfway (network), running it again finishes
    /// the rest.
    pub async fn import_apply(
        &mut self,
        set: &ImportSet,
        vault: Option<&str>,
        project: Option<&str>,
    ) -> ClientResult<ImportResult> {
        if set.is_empty() {
            return Err(ClientError::Invalid("nothing to import".into()));
        }
        let (v, p, vault_name, project_name) = self.import_destination(vault, project)?;
        let items = self.project_items(&v.to_string(), &p.to_string())?;
        let locations: Vec<ItemLocation> = items.iter().map(|(l, _)| *l).collect();
        let existing: Vec<Existing> = items.into_iter().map(|(_, e)| e).collect();
        let plan = plan(set.entries(), &existing, now_ms());
        let mut result = ImportResult {
            vault: vault_name,
            project: project_name,
            totals: plan.totals,
            passkeys: set.passkeys(),
            ..ImportResult::default()
        };
        let outcome = async {
            for create in &plan.creates {
                let mut item = create.item.clone();
                if let Some(passkey) = &create.passkey {
                    self.try_put_passkey(v, &mut item, passkey, &mut result.passkeys_failed);
                }
                if let Some(record) = self.new_record(v, &item, &create.history)? {
                    item.set_password_record(Some(record))?;
                }
                self.post_item(v, p, &item).await?;
                result.created += 1;
            }
            for update in &plan.updates {
                let loc = locations
                    .iter()
                    .copied()
                    .find(|l| l.item == update.id)
                    .ok_or_else(|| ClientError::NotFound(format!("item {}", update.id)))?;
                let mut item = update.item.clone();
                if let Some(passkey) = &update.passkey {
                    self.try_put_passkey(v, &mut item, passkey, &mut result.passkeys_failed);
                }
                // The passkey was all this entry changed: nothing to save.
                let unchanged = update.history.is_empty()
                    && existing.iter().any(|e| e.id == update.id && e.item == item);
                if unchanged {
                    continue;
                }
                self.put_item(loc, &item, &update.history).await?;
                result.updated += 1;
            }
            Ok::<(), ClientError>(())
        }
        .await;
        self.sync().await?;
        outcome?;
        Ok(result)
    }
}
