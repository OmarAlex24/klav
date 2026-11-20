//! The generator history (ADR 0022 §2): every password Klav generated,
//! kept in one item of kind `generator_history` in the account's system
//! project, so a password typed into a form that then failed is never lost.
//!
//! The system project of a vault has a fixed ID derived from the vault ID
//! ([`system_project_id`]): any client recognises it without reading its
//! name, and clients never put it in an agent grant.

use sha2::{Digest, Sha256};

use super::item::{MAX_TEXT_LEN, ModelError, SecretValue};
use crate::crypto::encoding::Tuple;
use crate::ids::{ItemId, ProjectId, VaultId};

/// Name of the system project.
pub const SYSTEM_PROJECT_NAME: &str = "Klav";
/// Title of the generator history item.
pub const GENERATOR_HISTORY_TITLE: &str = "Generator history";
/// Entries kept at most (G4).
pub const MAX_GENERATED: usize = 200;
/// How long an entry is kept (G4): 365 days.
pub const KEEP_MS: i64 = 365 * 24 * 3600 * 1000;
/// How long an entry already saved in a login is kept (G4): 30 days.
pub const KEEP_SAVED_MS: i64 = 30 * 24 * 3600 * 1000;
/// Label of the system project ID derivation.
pub const LABEL_SYSTEM_PROJECT: &str = "klav/v1/id/system-project";

/// The ID of `vault`'s system project:
/// `SHA-256(tuple("klav/v1/id/system-project", vault_id))[..16]` with the
/// UUID version set to 8 and the RFC 9562 variant.
pub fn system_project_id(vault: VaultId) -> ProjectId {
    let mut tuple = Tuple::new(LABEL_SYSTEM_PROJECT);
    tuple.push(vault.as_bytes());
    let digest = Sha256::digest(tuple.as_bytes());
    let mut bytes: [u8; 16] = digest[..16].try_into().expect("16 bytes");
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    ProjectId::from_bytes(bytes)
}

/// Whether `project` is the system project of `vault`.
pub fn is_system_project(vault: VaultId, project: ProjectId) -> bool {
    system_project_id(vault) == project
}

/// One generated password. Not `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct GeneratedEntry {
    /// The password.
    pub value: SecretValue,
    /// When it was generated (Unix ms).
    pub created_at: i64,
    /// The site it was generated for.
    pub host: Option<String>,
    /// The login it was saved in, once it was.
    pub saved_in: Option<ItemId>,
}

impl GeneratedEntry {
    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        if let Some(host) = &self.host
            && (host.is_empty() || host.len() > MAX_TEXT_LEN || host.chars().any(char::is_control))
        {
            return Err(ModelError::InvalidText("host"));
        }
        Ok(())
    }
}

/// Applies the retention of G4 at `now_ms`: drops entries older than a
/// year, or than 30 days once saved in a login, and keeps the newest
/// [`MAX_GENERATED`]. Entries end up newest first. Returns whether any went.
pub fn prune(entries: &mut Vec<GeneratedEntry>, now_ms: i64) -> bool {
    let before = entries.len();
    entries.retain(|e| {
        let age = now_ms.saturating_sub(e.created_at);
        age <= KEEP_MS && (e.saved_in.is_none() || age <= KEEP_SAVED_MS)
    });
    entries.sort_by_key(|e| std::cmp::Reverse(e.created_at));
    entries.truncate(MAX_GENERATED);
    entries.len() != before
}

/// Adds `new` entries that `entries` does not have yet (same value and
/// date), keeping the `saved_in` of either. Returns whether any was added.
///
/// The instant of an entry is its ID (`klav generated show`, `klavd`). Two
/// devices can generate in the same millisecond: an added entry whose
/// instant another value already has moves to the next free millisecond,
/// so every ID names one entry. The result depends only on the order of
/// the inputs, and the moved instant is the one written back.
pub fn merge(
    entries: &mut Vec<GeneratedEntry>,
    new: impl IntoIterator<Item = GeneratedEntry>,
) -> bool {
    let mut added = false;
    for entry in new {
        match entries
            .iter_mut()
            .find(|e| e.created_at == entry.created_at && e.value == entry.value)
        {
            Some(existing) => {
                if existing.saved_in.is_none() && entry.saved_in.is_some() {
                    existing.saved_in = entry.saved_in;
                    added = true;
                }
            }
            None => {
                let mut entry = entry;
                while entries.iter().any(|e| e.created_at == entry.created_at) {
                    entry.created_at = entry.created_at.saturating_add(1);
                }
                entries.push(entry);
                added = true;
            }
        }
    }
    added
}

#[cfg(test)]
mod tests {
    use super::*;

    // T34: a generated password never prints.
    static_assertions::assert_not_impl_any!(GeneratedEntry: std::fmt::Debug, std::fmt::Display);

    fn entry(value: &str, created_at: i64) -> GeneratedEntry {
        GeneratedEntry {
            value: SecretValue::new(value),
            created_at,
            host: Some("a.example".into()),
            saved_in: None,
        }
    }

    #[test]
    fn merged_entries_never_share_an_instant() {
        let mut all = vec![entry("from-laptop", 10), entry("other", 11)];
        // The phone generated another password in the same millisecond.
        assert!(merge(&mut all, [entry("from-phone", 10)]));
        let mut ids: Vec<i64> = all.iter().map(|e| e.created_at).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 3, "one ID per entry");
        let phone = all
            .iter()
            .find(|e| e.value.expose() == "from-phone")
            .unwrap();
        assert_eq!(phone.created_at, 12);
        // The same entry again adds nothing.
        assert!(!merge(&mut all, [entry("from-laptop", 10)]));
    }

    #[test]
    fn system_project_is_fixed_per_vault() {
        let vault = VaultId::from_bytes([7; 16]);
        let id = system_project_id(vault);
        assert_eq!(id, system_project_id(vault));
        assert_ne!(id, system_project_id(VaultId::from_bytes([8; 16])));
        assert!(is_system_project(vault, id));
        assert!(!is_system_project(vault, ProjectId::generate()));
        let text = id.to_string();
        assert_eq!(&text[14..15], "8", "UUID version 8: {text}");
        assert!(
            matches!(&text[19..20], "8" | "9" | "a" | "b"),
            "RFC 9562 variant: {text}"
        );
    }

    #[test]
    fn retention() {
        let day = 24 * 3600 * 1000;
        let now = 400 * day;
        let mut saved = entry("saved", now - 31 * day);
        saved.saved_in = Some(ItemId::generate());
        let mut recent_saved = entry("recent-saved", now - 29 * day);
        recent_saved.saved_in = Some(ItemId::generate());
        let mut entries = vec![
            entry("old", now - 366 * day),
            entry("kept", now - 364 * day),
            saved,
            recent_saved,
        ];
        assert!(prune(&mut entries, now));
        let left: Vec<&str> = entries.iter().map(|e| e.value.expose()).collect();
        assert_eq!(left, ["recent-saved", "kept"]);

        let mut many: Vec<GeneratedEntry> =
            (0..250).map(|i| entry(&format!("p{i}"), now - i)).collect();
        prune(&mut many, now);
        assert_eq!(many.len(), MAX_GENERATED);
        assert_eq!(many[0].value.expose(), "p0");
    }

    #[test]
    fn merging_is_idempotent() {
        let mut entries = vec![entry("a", 1)];
        assert!(merge(&mut entries, [entry("a", 1), entry("b", 2)]));
        assert_eq!(entries.len(), 2);
        assert!(!merge(&mut entries, [entry("a", 1)]));
        let mut saved = entry("a", 1);
        saved.saved_in = Some(ItemId::generate());
        assert!(merge(&mut entries, [saved]));
        assert!(entries[0].saved_in.is_some());
    }
}
