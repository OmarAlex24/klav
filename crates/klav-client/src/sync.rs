//! Applying server deltas to the local cache, with rollback detection
//! (threat T7, `docs/api.md` §5.3).
//!
//! The rules, checked **before** anything is written:
//!
//! * the revision of a vault never goes below the highest one this device
//!   has seen (in `GET /v1/sync` and in `changes`);
//! * `changes` answers exactly the `since` that was asked and covers at
//!   least the revision `GET /v1/sync` announced;
//! * vault, project and item versions never go down;
//! * purged items and deleted projects never come back.
//!
//! Any violation aborts the whole sync with [`ClientError::Rollback`] and
//! leaves the cache untouched.
//!
//! A hostile server must not be able to lock the person out of the copy
//! they already have either (ADR 0030, layer 10): revisions and versions
//! beyond what a real server can store (`i64::MAX`) are refused before they
//! become marks, every list and blob has a ceiling, and a vault the server
//! stops listing keeps its local copy, marked as unlisted (T14).

use std::collections::{BTreeMap, BTreeSet};

use klav_core::ids::VaultId;
use klav_proto::sync::{Changes, SyncState};
use serde::Serialize;

use crate::error::{ClientError, ClientResult};
use crate::state::Cache;
#[cfg(test)]
use crate::state::CachedVault;

/// The largest revision or version a server can hand out: it stores them
/// as signed 64-bit integers. Anything above is a lie meant to poison the
/// high-water marks (every later sync would look like a rollback).
pub(crate) const MAX_COUNTER: u64 = i64::MAX as u64;
/// Vaults in one `GET /v1/sync` (one `changes` request each).
pub(crate) const MAX_VAULTS: usize = 1_000;
/// Records in one `changes` response (projects, items or attachments).
pub(crate) const MAX_RECORDS: usize = 100_000;
/// High-water marks this device keeps in total. Marks are never pruned
/// (T7), so a server inventing IDs must not make `cache.bin` grow without
/// bound: past this, its changes are refused.
pub(crate) const MAX_MARKS: usize = 500_000;
/// Largest single blob accepted from the server (the server's default
/// request limit is 4 MiB for a whole item).
pub(crate) const MAX_BLOB: usize = 16 * 1024 * 1024;

fn out_of_range(what: String) -> ClientError {
    ClientError::Security(format!("the server sent {what}"))
}

fn check_counter(what: &str, value: u64) -> ClientResult<()> {
    if value > MAX_COUNTER {
        return Err(out_of_range(format!(
            "an impossible {what} ({value}); it is not recorded"
        )));
    }
    Ok(())
}

fn check_blob(what: &str, blob: Option<&klav_proto::Blob>) -> ClientResult<()> {
    if blob.is_some_and(|b| b.as_bytes().len() > MAX_BLOB) {
        return Err(out_of_range(format!(
            "a {what} larger than {} MiB",
            MAX_BLOB / (1024 * 1024)
        )));
    }
    Ok(())
}

/// What a sync did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct SyncReport {
    /// Vaults whose revision moved.
    pub vaults_updated: usize,
    /// Items received (created, edited, trashed or purged).
    pub items_received: usize,
    /// Vaults no longer listed by the server (purged or access lost).
    pub vaults_removed: usize,
    /// Vaults created before vault keys were signed that this device
    /// signed now (once per device, ADR 0030 §1).
    #[serde(default)]
    pub vaults_signed: usize,
}

/// Checks the shape of `GET /v1/sync` on its own, before anything is
/// fetched for it: how many vaults (one `changes` request each), counters
/// a real server can store, no vault listed twice. A sync planned without
/// the cache ([`crate::SyncPlan::fetch`]) runs this before its `changes`
/// requests, so a hostile listing cannot fan out into millions of them.
pub(crate) fn check_shape(state: &SyncState) -> ClientResult<()> {
    if state.vaults.len() > MAX_VAULTS {
        return Err(out_of_range(format!(
            "{} vaults (at most {MAX_VAULTS} are accepted)",
            state.vaults.len()
        )));
    }
    let mut seen = BTreeSet::new();
    for v in &state.vaults {
        check_counter(&format!("revision for vault {}", v.vault_id), v.revision)?;
        if !seen.insert(v.vault_id) {
            return Err(ClientError::Rollback(format!(
                "vault {} listed twice",
                v.vault_id
            )));
        }
    }
    Ok(())
}

/// Checks `GET /v1/sync` against the high-water marks.
pub(crate) fn check_listing(cache: &Cache, state: &SyncState) -> ClientResult<()> {
    check_shape(state)?;
    for v in &state.vaults {
        if let Some(&mark) = cache.marks.vault_revisions.get(&v.vault_id)
            && v.revision < mark
        {
            return Err(ClientError::Rollback(format!(
                "vault {} is at revision {} but this device already saw revision {mark}",
                v.vault_id, v.revision
            )));
        }
    }
    Ok(())
}

/// The vaults that need a `changes` request: `(vault, since, listed)`.
pub(crate) fn pending(cache: &Cache, state: &SyncState) -> Vec<(VaultId, u64, u64)> {
    pending_from(&revisions(cache), state)
}

/// The revision of each cached vault: all [`pending`] needs, so a sync can
/// be planned from a snapshot without holding the cache.
pub(crate) fn revisions(cache: &Cache) -> BTreeMap<VaultId, u64> {
    cache
        .vaults
        .iter()
        .map(|(id, v)| (*id, v.revision))
        .collect()
}

/// [`pending`] against a snapshot of [`revisions`].
pub(crate) fn pending_from(
    revisions: &BTreeMap<VaultId, u64>,
    state: &SyncState,
) -> Vec<(VaultId, u64, u64)> {
    state
        .vaults
        .iter()
        .filter_map(|v| match revisions.get(&v.vault_id) {
            Some(&since) if v.revision <= since => None,
            Some(&since) => Some((v.vault_id, since, v.revision)),
            None => Some((v.vault_id, 0, v.revision)),
        })
        .collect()
}

/// Applies one `changes` response. `listed` is the revision announced by
/// `GET /v1/sync` for this vault. Returns the number of items received.
pub(crate) fn apply(
    cache: &mut Cache,
    vault_id: VaultId,
    since: u64,
    listed: u64,
    changes: Changes,
) -> ClientResult<usize> {
    let rollback = |what: String| Err(ClientError::Rollback(format!("vault {vault_id}: {what}")));
    if changes.vault_id != vault_id {
        return rollback(format!("changes answered for vault {}", changes.vault_id));
    }
    if changes.since != since {
        return rollback(format!(
            "asked for changes since {since}, got since {}",
            changes.since
        ));
    }
    check_counter("vault revision", changes.revision)?;
    let records = changes.projects.len() + changes.items.len() + changes.attachments.len();
    if records > MAX_RECORDS {
        return Err(out_of_range(format!(
            "{records} records for vault {vault_id} (at most {MAX_RECORDS})"
        )));
    }
    let mark = cache
        .marks
        .vault_revisions
        .get(&vault_id)
        .copied()
        .unwrap_or(0);
    let floor = since.max(mark).max(listed);
    if changes.revision < floor {
        return rollback(format!(
            "changes reach revision {} but revision {floor} was already seen",
            changes.revision
        ));
    }

    // Work on copies; commit only if every check passes.
    let mut entry = cache.vaults.get(&vault_id).cloned().unwrap_or_default();
    let mut marks = cache.marks.clone();
    let mut items = 0;

    if let Some(vault) = changes.vault {
        if vault.id != vault_id {
            return rollback("vault record with another ID".into());
        }
        check_counter("vault version", vault.version)?;
        check_blob("vault record", Some(&vault.meta))?;
        check_blob("vault key", Some(&vault.shared_key))?;
        let known = marks.vault_versions.get(&vault_id).copied().unwrap_or(0);
        if vault.version < known {
            return rollback(format!(
                "vault metadata version {} is older than version {known}",
                vault.version
            ));
        }
        marks.vault_versions.insert(vault_id, vault.version);
        entry.vault = Some(vault);
    } else if entry.vault.is_none() {
        return rollback("first sync without the vault record".into());
    }

    for project in changes.projects {
        if project.vault_id != vault_id {
            return rollback(format!("project {} belongs to another vault", project.id));
        }
        check_counter("project version", project.version)?;
        check_blob("project key", project.wrapped_key.as_ref())?;
        check_blob("project record", project.meta.as_ref())?;
        let known = marks
            .project_versions
            .get(&project.id)
            .copied()
            .unwrap_or(0);
        if project.version < known {
            return rollback(format!(
                "project {} at version {} but version {known} was already seen",
                project.id, project.version
            ));
        }
        marks.project_versions.insert(project.id, project.version);
        if project.deleted_at.is_some() {
            marks.deleted_projects.insert(project.id);
            entry.projects.remove(&project.id);
        } else {
            if marks.deleted_projects.contains(&project.id) {
                return rollback(format!("deleted project {} came back", project.id));
            }
            entry.projects.insert(project.id, project);
        }
    }

    for item in changes.items {
        items += 1;
        if item.vault_id != vault_id {
            return rollback(format!("item {} belongs to another vault", item.id));
        }
        check_counter("item version", item.version)?;
        check_blob("item key", item.wrapped_key.as_ref())?;
        check_blob("item overview", item.overview.as_ref())?;
        check_blob("item details", item.details.as_ref())?;
        let known = marks.item_versions.get(&item.id).copied().unwrap_or(0);
        if item.version < known {
            return rollback(format!(
                "item {} at version {} but version {known} was already seen",
                item.id, item.version
            ));
        }
        marks.item_versions.insert(item.id, item.version);
        if item.purged_at.is_some() {
            marks.purged_items.insert(item.id);
            entry.items.remove(&item.id);
        } else {
            if marks.purged_items.contains(&item.id) {
                return rollback(format!("purged item {} came back", item.id));
            }
            entry.items.insert(item.id, item);
        }
    }

    for attachment in changes.attachments {
        if attachment.vault_id != vault_id {
            return rollback(format!(
                "attachment {} belongs to another vault",
                attachment.id
            ));
        }
        check_blob("attachment key", attachment.wrapped_key.as_ref())?;
        if attachment.deleted_at.is_none()
            && (attachment.completed_at.is_none()
                || attachment.wrapped_key.is_none()
                || attachment.received != attachment.size)
        {
            return rollback(format!(
                "attachment {} is neither complete nor deleted",
                attachment.id
            ));
        }
        if attachment.deleted_at.is_some() {
            entry.attachments.remove(&attachment.id);
        } else {
            entry.attachments.insert(attachment.id, attachment);
        }
    }

    entry.revision = changes.revision;
    entry.unlisted = false;
    marks.vault_revisions.insert(vault_id, changes.revision);
    if marks.len() > MAX_MARKS {
        return Err(out_of_range(format!(
            "so many records that this device would keep more than {MAX_MARKS} marks"
        )));
    }
    cache.vaults.insert(vault_id, entry);
    cache.marks = marks;
    Ok(items)
}

/// Marks the vaults the server no longer lists (purged, or access lost).
/// Their local copy stays, read-only, until the person drops it
/// (`klav sync --reset-cache`): the server alone cannot erase what this
/// device has (T14). Their marks stay too. Returns how many vaults became
/// unlisted in this sync.
pub(crate) fn mark_unlisted(cache: &mut Cache, state: &SyncState) -> usize {
    let listed: BTreeSet<VaultId> = state.vaults.iter().map(|v| v.vault_id).collect();
    let mut newly = 0;
    for (id, vault) in &mut cache.vaults {
        if !listed.contains(id) && !vault.unlisted {
            vault.unlisted = true;
            newly += 1;
        }
    }
    newly
}

/// A fresh, empty vault entry (used in tests).
#[cfg(test)]
pub(crate) fn empty_vault() -> CachedVault {
    CachedVault::default()
}

#[cfg(test)]
mod tests {
    use klav_core::ids::{AccountId, ItemId, ProjectId};
    use klav_proto::Blob;
    use klav_proto::sync::VaultRevision;
    use klav_proto::vault::{Item, Project, Role, Vault};

    use super::*;

    fn vault(id: VaultId, version: u64, revision: u64) -> Vault {
        Vault {
            id,
            owner_account_id: AccountId::from_bytes([1; 16]),
            role: Role::Owner,
            revision,
            version,
            meta: Blob::new(vec![1]),
            shared_key: Blob::new(vec![2]),
            shared_key_signature: None,
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        }
    }

    fn item(id: ItemId, vault_id: VaultId, version: u64, revision: u64) -> Item {
        Item {
            id,
            vault_id,
            project_id: ProjectId::from_bytes([3; 16]),
            version,
            revision,
            wrapped_key: Some(Blob::new(vec![4])),
            overview: Some(Blob::new(vec![5])),
            details: Some(Blob::new(vec![6])),
            created_at: 0,
            updated_at: 0,
            trashed_at: None,
            purged_at: None,
            author_agent_id: None,
        }
    }

    fn changes(v: VaultId, since: u64, revision: u64) -> Changes {
        Changes {
            vault_id: v,
            since,
            revision,
            vault: None,
            members: vec![],
            projects: vec![],
            items: vec![],
            attachments: vec![],
        }
    }

    fn listing(v: VaultId, revision: u64) -> SyncState {
        SyncState {
            vaults: vec![VaultRevision {
                vault_id: v,
                revision,
                deleted_at: None,
            }],
            agent_pauses: vec![],
            deletion: None,
            sandbox_state: vec![],
        }
    }

    /// A cache that has seen vault `v` at revision 5 and item `i` at version 3.
    fn seeded() -> (Cache, VaultId, ItemId) {
        let v = VaultId::generate();
        let i = ItemId::generate();
        let mut cache = Cache::empty();
        let mut first = changes(v, 0, 5);
        first.vault = Some(vault(v, 1, 1));
        first.items = vec![item(i, v, 3, 5)];
        apply(&mut cache, v, 0, 5, first).unwrap();
        (cache, v, i)
    }

    #[test]
    fn forward_progress_is_accepted() {
        let (mut cache, v, i) = seeded();
        assert_eq!(pending(&cache, &listing(v, 5)), vec![]);
        assert_eq!(pending(&cache, &listing(v, 7)), vec![(v, 5, 7)]);
        let mut next = changes(v, 5, 7);
        next.items = vec![item(i, v, 4, 7)];
        assert_eq!(apply(&mut cache, v, 5, 7, next).unwrap(), 1);
        assert_eq!(cache.marks.vault_revisions[&v], 7);
        assert_eq!(cache.marks.item_versions[&i], 4);
        let _ = empty_vault();
    }

    #[test]
    fn revision_rollbacks_are_rejected() {
        let (cache, v, _) = seeded();
        assert!(
            check_listing(&cache, &listing(v, 4))
                .unwrap_err()
                .is_rollback()
        );
        assert!(check_listing(&cache, &listing(v, 5)).is_ok());

        let mut c = cache.clone();
        // `changes` reporting less than what /v1/sync announced or already seen.
        assert!(
            apply(&mut c, v, 5, 6, changes(v, 5, 5))
                .unwrap_err()
                .is_rollback()
        );
        assert!(
            apply(&mut c, v, 0, 0, changes(v, 0, 4))
                .unwrap_err()
                .is_rollback()
        );
        // Answering another `since` or another vault.
        assert!(
            apply(&mut c, v, 5, 6, changes(v, 4, 6))
                .unwrap_err()
                .is_rollback()
        );
        assert!(
            apply(&mut c, v, 5, 6, changes(VaultId::generate(), 5, 6))
                .unwrap_err()
                .is_rollback()
        );
        // Nothing was modified by the failed attempts.
        assert_eq!(c.marks, cache.marks);
    }

    #[test]
    fn version_rollbacks_are_rejected_atomically() {
        let (cache, v, i) = seeded();
        let mut c = cache.clone();
        let new_item = ItemId::generate();
        let mut stale = changes(v, 5, 6);
        // A new item first (would be accepted), then the stale one.
        stale.items = vec![item(new_item, v, 1, 6), item(i, v, 2, 6)];
        assert!(apply(&mut c, v, 5, 6, stale).unwrap_err().is_rollback());
        assert!(!c.vaults[&v].items.contains_key(&new_item), "not committed");
        assert_eq!(c.marks, cache.marks);

        let mut old_meta = changes(v, 5, 6);
        old_meta.vault = Some(vault(v, 0, 6));
        assert!(apply(&mut c, v, 5, 6, old_meta).unwrap_err().is_rollback());
    }

    #[test]
    fn purged_items_and_deleted_projects_stay_gone() {
        let (mut cache, v, i) = seeded();
        let mut purge = changes(v, 5, 6);
        let mut gone = item(i, v, 3, 6);
        gone.purged_at = Some(1);
        purge.items = vec![gone];
        apply(&mut cache, v, 5, 6, purge).unwrap();
        assert!(!cache.vaults[&v].items.contains_key(&i));

        let mut back = changes(v, 6, 7);
        back.items = vec![item(i, v, 3, 7)];
        assert!(apply(&mut cache, v, 6, 7, back).unwrap_err().is_rollback());

        let p = ProjectId::generate();
        let project = |deleted: bool| Project {
            id: p,
            vault_id: v,
            version: 1,
            revision: 7,
            wrapped_key: None,
            meta: None,
            created_at: 0,
            updated_at: 0,
            deleted_at: deleted.then_some(1),
        };
        let mut del = changes(v, 6, 7);
        del.projects = vec![project(true)];
        apply(&mut cache, v, 6, 7, del).unwrap();
        let mut again = changes(v, 7, 8);
        again.projects = vec![project(false)];
        assert!(apply(&mut cache, v, 7, 8, again).unwrap_err().is_rollback());
    }

    #[test]
    fn unlisted_vaults_keep_their_local_copy() {
        let (mut cache, v, i) = seeded();
        let none = SyncState {
            vaults: vec![],
            agent_pauses: vec![],
            deletion: None,
            sandbox_state: vec![],
        };
        assert_eq!(mark_unlisted(&mut cache, &none), 1);
        assert_eq!(mark_unlisted(&mut cache, &none), 0, "counted once");
        assert!(cache.vaults[&v].unlisted);
        assert!(cache.vaults[&v].items.contains_key(&i), "copy kept");
        // Listed again: back to normal.
        assert!(pending(&cache, &listing(v, 5)).is_empty());
        apply(&mut cache, v, 5, 6, changes(v, 5, 6)).unwrap();
        assert!(!cache.vaults[&v].unlisted);
    }

    #[test]
    fn impossible_counters_never_become_marks() {
        let (cache, v, i) = seeded();
        let huge = u64::MAX;
        // In the listing…
        let err = check_listing(&cache, &listing(v, huge)).unwrap_err();
        assert!(matches!(err, ClientError::Security(_)));
        // …and in every counter of `changes`.
        type Poison = Box<dyn Fn(&mut Changes)>;
        let tries: Vec<Poison> = vec![
            Box::new(move |c: &mut Changes| c.revision = huge),
            Box::new(move |c: &mut Changes| c.vault = Some(vault(v, huge, 6))),
            Box::new(move |c: &mut Changes| c.items = vec![item(i, v, huge, 6)]),
            Box::new(move |c: &mut Changes| {
                c.projects = vec![Project {
                    id: ProjectId::generate(),
                    vault_id: v,
                    version: MAX_COUNTER + 1,
                    revision: 6,
                    wrapped_key: None,
                    meta: None,
                    created_at: 0,
                    updated_at: 0,
                    deleted_at: None,
                }]
            }),
        ];
        for poison in tries {
            let mut c = cache.clone();
            let mut next = changes(v, 5, 6);
            poison(&mut next);
            let listed = next.revision;
            let err = apply(&mut c, v, 5, listed.min(6), next).unwrap_err();
            assert!(matches!(err, ClientError::Security(_)), "{err}");
            assert_eq!(c.marks, cache.marks, "nothing recorded");
        }
        // The largest real value is fine.
        let mut c = cache.clone();
        let mut next = changes(v, 5, MAX_COUNTER);
        next.items = vec![item(i, v, MAX_COUNTER, MAX_COUNTER)];
        apply(&mut c, v, 5, 6, next).unwrap();
    }

    #[test]
    fn oversized_blobs_and_lists_are_refused() {
        let (cache, v, i) = seeded();
        let mut c = cache.clone();
        let mut big = item(i, v, 4, 6);
        big.details = Some(Blob::new(vec![0; MAX_BLOB + 1]));
        let mut next = changes(v, 5, 6);
        next.items = vec![big];
        assert!(matches!(
            apply(&mut c, v, 5, 6, next).unwrap_err(),
            ClientError::Security(_)
        ));
        let many = SyncState {
            vaults: (0..=MAX_VAULTS)
                .map(|_| VaultRevision {
                    vault_id: VaultId::generate(),
                    revision: 1,
                    deleted_at: None,
                })
                .collect(),
            agent_pauses: vec![],
            deletion: None,
            sandbox_state: vec![],
        };
        assert!(check_listing(&cache, &many).is_err());
    }

    #[test]
    fn marks_survive_vault_removal() {
        let (mut cache, v, _) = seeded();
        assert_eq!(
            mark_unlisted(
                &mut cache,
                &SyncState {
                    vaults: vec![],
                    agent_pauses: vec![],
                    deletion: None,
                    sandbox_state: vec![],
                }
            ),
            1
        );
        cache.vaults.clear();
        // The vault comes back from an old backup: still detected.
        assert!(
            check_listing(&cache, &listing(v, 2))
                .unwrap_err()
                .is_rollback()
        );
        let mut c = cache.clone();
        let mut full = changes(v, 0, 3);
        full.vault = Some(vault(v, 1, 1));
        assert!(apply(&mut c, v, 0, 3, full).unwrap_err().is_rollback());
    }

    #[test]
    fn attachments_must_belong_to_the_vault_and_be_complete_or_deleted() {
        use klav_core::ids::AttachmentId;
        use klav_proto::sync::Attachment;
        let (cache, v, i) = seeded();
        let attachment = |vault_id: VaultId, complete: bool| Attachment {
            id: AttachmentId::generate(),
            vault_id,
            item_id: i,
            size: 10,
            received: if complete { 10 } else { 4 },
            wrapped_key: Some(Blob::new(vec![7])),
            revision: 6,
            created_at: 0,
            completed_at: complete.then_some(1),
            deleted_at: None,
        };
        let try_one = |a: Attachment| {
            let mut c = cache.clone();
            let mut next = changes(v, 5, 6);
            next.attachments = vec![a];
            let res = apply(&mut c, v, 5, 6, next);
            (res, c)
        };
        let (res, c) = try_one(attachment(v, true));
        res.unwrap();
        assert_eq!(c.vaults[&v].attachments.len(), 1);
        let (res, c) = try_one(attachment(VaultId::generate(), true));
        assert!(res.unwrap_err().is_rollback());
        assert!(c.vaults[&v].attachments.is_empty(), "not committed");
        assert!(try_one(attachment(v, false)).0.unwrap_err().is_rollback());
        let mut keyless = attachment(v, true);
        keyless.wrapped_key = None;
        assert!(try_one(keyless).0.unwrap_err().is_rollback());
        // A tombstone needs neither.
        let mut gone = attachment(v, false);
        gone.wrapped_key = None;
        gone.deleted_at = Some(2);
        try_one(gone).0.unwrap();
    }
}
