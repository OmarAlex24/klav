//! Person-owned labels and machine/host notes for agents (ADR 0047 §1):
//! stored in the dedicated `agent_labels` system item in the personal vault's
//! system project.
//!
//! Security boundary (T240): any `agent_labels` item authored by an agent
//! (`author_agent_id.is_some()`) is ignored when reading and never trusted.
//! Only person-authored items in vaults owned by this account are read and
//! updated.

use klav_core::ids::{AgentId, VaultId};
use klav_core::model::agent_labels::{AGENT_LABELS_TITLE, AgentLabel, AgentLabels};
use klav_core::model::item::{Item, ItemKind};

use crate::error::{ClientError, ClientResult};
use crate::session::{ItemLocation, Unlocked};

impl Unlocked {
    /// Returns all person-owned agent labels from the account's own vaults.
    /// Items written by an agent are ignored (T240).
    pub fn agent_labels(&self) -> ClientResult<AgentLabels> {
        let mut merged = AgentLabels::default();
        let mut entries: Vec<(i64, Item)> = Vec::new();
        for (loc, updated_at, item) in self.person_agent_label_items()? {
            let _ = loc;
            entries.push((updated_at, item));
        }
        // Apply oldest first so the most recently updated item wins on any
        // concurrent creation across devices.
        entries.sort_by_key(|(updated_at, _)| *updated_at);
        for (_, item) in entries {
            if let Some(book) = item.agent_labels() {
                for (agent, label) in &book.labels {
                    merged.labels.insert(*agent, label.clone());
                }
            }
        }
        Ok(merged)
    }

    /// Sets or clears the person-owned label and/or machine host for `agent`.
    /// Passing `None` or an all-empty [`AgentLabel`] removes the entry.
    pub async fn set_agent_label(
        &mut self,
        agent: AgentId,
        label: Option<AgentLabel>,
    ) -> ClientResult<AgentLabels> {
        let normalized = label.map(AgentLabel::normalized).filter(|l| !l.is_empty());
        if let Some(entry) = &normalized {
            entry
                .validate()
                .map_err(|e| ClientError::Invalid(e.to_string()))?;
        }
        let mut attempt = 0;
        loop {
            match self.write_agent_label(agent, normalized.clone()).await {
                Err(ClientError::Conflict(_)) if attempt == 0 => attempt += 1,
                other => return other,
            }
        }
    }

    async fn write_agent_label(
        &mut self,
        agent: AgentId,
        label: Option<AgentLabel>,
    ) -> ClientResult<AgentLabels> {
        let existing = self.person_agent_label_items()?;
        if existing.is_empty() {
            let Some(entry) = label else {
                return Ok(AgentLabels::default());
            };
            let vault = self.default_vault()?;
            self.require_owned_vault(vault)?;
            let project = self.ensure_system_project(vault).await?;
            let mut book = AgentLabels::default();
            book.set(agent, Some(entry))?;
            let mut item = Item::new(ItemKind::AgentLabels, AGENT_LABELS_TITLE)?;
            item.set_agent_labels(Some(book.clone()))?;
            self.add_item(vault, project, &item).await?;
            return Ok(book);
        }
        for (loc, _, item) in existing {
            let mut book = item.agent_labels().cloned().unwrap_or_default();
            let before = book.get(&agent).cloned();
            if before == label {
                continue;
            }
            book.set(agent, label.clone())?;
            let mut changed = item.clone();
            changed.set_agent_labels(Some(book))?;
            self.update_item(loc, &changed).await?;
        }
        self.agent_labels()
    }

    fn person_agent_label_items(&self) -> ClientResult<Vec<(ItemLocation, i64, Item)>> {
        let account = self.account.account_id;
        let mut found = Vec::new();
        for vault in self.owned_vaults(account) {
            for loc in self.system_items(vault, ItemKind::AgentLabels) {
                let summary = self.item_summary(loc)?;
                // T240: never read or trust agent-authored label items.
                if summary.author_agent_id.is_some() {
                    continue;
                }
                found.push((loc, summary.updated_at, self.open_item(loc)?));
            }
        }
        Ok(found)
    }

    fn require_owned_vault(&self, vault: VaultId) -> ClientResult<()> {
        match self.vaults.get(&vault) {
            Some(v) if v.owner == self.account.account_id => Ok(()),
            _ => Err(ClientError::Invalid(
                "agent labels live in a vault of this account".into(),
            )),
        }
    }
}
