//! Person-owned labels and machine/host notes for agents (ADR 0047 §1): one
//! system item of kind `agent_labels` in the system project of the personal
//! vault ([`super::history::system_project_id`]), synced and encrypted E2E like
//! any item. No grant includes the system project, so no agent reads or
//! changes it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::item::ModelError;
use crate::ids::AgentId;

/// Title of the agent labels system item.
pub const AGENT_LABELS_TITLE: &str = "Agent Labels";

/// Maximum length of a person-owned agent label or host name, in characters.
pub const MAX_AGENT_LABEL_LEN: usize = 128;

/// Person-owned metadata for a single agent: an optional friendly alias
/// (`label`, e.g. `"Proxmox proxy"`), an optional machine/host name (`host`,
/// e.g. `"pve-home"` or `"Omar's MacBook Pro"`), and an optional role hint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLabel {
    /// Human alias chosen by the person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Machine, server or sandbox host chosen by the person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Optional role hint (reserved for future use).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_hint: Option<String>,
}

impl AgentLabel {
    /// Trims whitespace and drops empty strings.
    pub fn normalized(self) -> Self {
        let clean = |s: Option<String>| -> Option<String> {
            s.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
        };
        Self {
            label: clean(self.label),
            host: clean(self.host),
            role_hint: clean(self.role_hint),
        }
    }

    /// Whether every field is empty.
    pub fn is_empty(&self) -> bool {
        self.label.is_none() && self.host.is_none() && self.role_hint.is_none()
    }

    /// Validates lengths and forbids control characters.
    pub fn validate(&self) -> Result<(), ModelError> {
        for (value, what) in [
            (&self.label, "agent label"),
            (&self.host, "agent host"),
            (&self.role_hint, "agent role hint"),
        ] {
            if let Some(text) = value
                && (text.trim().is_empty()
                    || text.chars().count() > MAX_AGENT_LABEL_LEN
                    || text.chars().any(char::is_control))
            {
                return Err(ModelError::InvalidText(what));
            }
        }
        Ok(())
    }
}

/// Map of agent IDs to person-owned labels (ADR 0047 §1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLabels {
    /// Labels keyed by agent ID.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<AgentId, AgentLabel>,
}

impl AgentLabels {
    /// Looks up the person-owned label for `agent`.
    pub fn get(&self, agent: &AgentId) -> Option<&AgentLabel> {
        self.labels.get(agent)
    }

    /// Inserts or removes an entry, normalizing whitespace first.
    pub fn set(&mut self, agent: AgentId, label: Option<AgentLabel>) -> Result<(), ModelError> {
        match label.map(AgentLabel::normalized) {
            Some(entry) if !entry.is_empty() => {
                entry.validate()?;
                self.labels.insert(agent, entry);
            }
            _ => {
                self.labels.remove(&agent);
            }
        }
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        for entry in self.labels.values() {
            entry.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_roundtrips_cleanly() {
        let empty: AgentLabels = serde_json::from_str("{}").unwrap();
        assert!(empty.labels.is_empty());
        assert_eq!(serde_json::to_string(&empty).unwrap(), "{}");
    }

    #[test]
    fn normalizes_and_validates_entries() {
        let id = AgentId::generate();
        let mut book = AgentLabels::default();
        book.set(
            id,
            Some(AgentLabel {
                label: Some("  Proxmox proxy  ".into()),
                host: Some(" pve-home ".into()),
                role_hint: None,
            }),
        )
        .unwrap();
        let stored = book.get(&id).unwrap();
        assert_eq!(stored.label.as_deref(), Some("Proxmox proxy"));
        assert_eq!(stored.host.as_deref(), Some("pve-home"));

        // Clearing via empty fields removes the entry.
        book.set(
            id,
            Some(AgentLabel {
                label: Some("   ".into()),
                host: None,
                role_hint: None,
            }),
        )
        .unwrap();
        assert!(book.get(&id).is_none());

        // Control characters and overlong values are rejected.
        assert!(
            book.set(
                id,
                Some(AgentLabel {
                    label: None,
                    host: Some("bad\nhost".into()),
                    role_hint: None,
                })
            )
            .is_err()
        );
        assert!(
            book.set(
                id,
                Some(AgentLabel {
                    label: Some("x".repeat(MAX_AGENT_LABEL_LEN + 1)),
                    host: None,
                    role_hint: None,
                })
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_unknown_fields() {
        let id = AgentId::generate();
        let bad = format!(r#"{{"labels":{{"{id}":{{"host":"pve","extra":1}}}}}}"#);
        assert!(serde_json::from_str::<AgentLabels>(&bad).is_err());
    }
}
