//! Retention: deletes the accounts whose deletion is due (ADR 0037, in
//! `crate::deletion`), purges items that have been in the trash, and vaults
//! that have been deleted, for longer than `retention.trash_days`, and
//! drops dead sessions. Runs periodically from [`crate::Server::serve`] and can be
//! called directly with an explicit clock ([`crate::Server::purge_expired`]).
//!
//! Every purge re-checks, inside its own transaction and under the lock a
//! restore also takes, that the thing is still due: an item or a vault the
//! person restored a moment ago is never purged (layer 07 of the 2026-11
//! round). It also removes uploads left unfinished for a day and files no
//! row points to.

use klav_core::ids::{AttachmentId, ItemId, VaultId};

use crate::error::ApiResult;
use crate::session::parse_id;
use crate::state::AppState;
use crate::vaultdb::VaultWrite;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
/// Sessions are dropped this long after they expire or are revoked.
const SESSION_GRACE_MS: i64 = 7 * DAY_MS;
/// Items purged per run (the rest waits for the next run).
const BATCH: i64 = 500;
/// Unfinished uploads idle for longer than this are removed.
const UPLOAD_IDLE_MS: i64 = DAY_MS;

/// What a purge run removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeReport {
    /// Accounts deleted 7 days after the person asked (ADR 0037).
    pub accounts: u64,
    /// Items purged from the trash (tombstones remain for sync).
    pub items: u64,
    /// Deleted vaults removed with everything inside.
    pub vaults: u64,
    /// Expired or revoked sessions removed.
    pub sessions: u64,
    /// Unfinished uploads idle for a day, removed.
    pub uploads: u64,
}

/// Turns a trashed item into a tombstone inside an open vault write: drops
/// its history and blobs, keeps ID, version and the new revision so other
/// devices learn about the deletion. Its attachments become tombstones too;
/// the returned IDs are the files to delete once the write commits.
pub(crate) async fn purge_item(
    w: &mut VaultWrite,
    item_id: ItemId,
) -> ApiResult<Vec<AttachmentId>> {
    let id = item_id.to_string();
    let attachments: Vec<String> =
        sqlx::query_scalar("SELECT id FROM attachments WHERE item_id = $1 AND deleted_at IS NULL")
            .bind(&id)
            .fetch_all(&mut *w.tx)
            .await?;
    sqlx::query(
        "UPDATE attachments SET deleted_at = $1, wrapped_key = NULL, revision = $2 \
         WHERE item_id = $3 AND deleted_at IS NULL",
    )
    .bind(w.now)
    .bind(w.revision)
    .bind(&id)
    .execute(&mut *w.tx)
    .await?;
    sqlx::query("DELETE FROM item_versions WHERE item_id = $1")
        .bind(&id)
        .execute(&mut *w.tx)
        .await?;
    // Assisted changes of the item keep its host in the clear: they go too.
    sqlx::query("DELETE FROM rotations WHERE item_id = $1")
        .bind(&id)
        .execute(&mut *w.tx)
        .await?;
    sqlx::query(
        "UPDATE items SET wrapped_key = NULL, overview = NULL, details = NULL, purged_at = $1, \
         revision = $2 WHERE id = $3",
    )
    .bind(w.now)
    .bind(w.revision)
    .bind(&id)
    .execute(&mut *w.tx)
    .await?;
    attachments.iter().map(|a| parse_id(a)).collect()
}

/// Deletes attachment files after the purge that tombstoned them committed.
/// Waits for an upload still writing a chunk of one of them (it read the
/// row before the commit), so the chunk does not land after the delete.
pub(crate) async fn remove_files(state: &AppState, vault_id: VaultId, ids: &[AttachmentId]) {
    for id in ids {
        let guard = state.attachments().lock_wait(*id).await;
        state.attachments().remove(vault_id, *id).await;
        drop(guard);
    }
}

/// Runs one purge pass as if the current time were `now` (Unix ms).
pub(crate) async fn purge_expired(state: &AppState, now: i64) -> ApiResult<PurgeReport> {
    let cutoff = now - i64::from(state.config().retention.trash_days) * DAY_MS;
    let pool = &state.db().pool;
    // Accounts first: whatever they had is gone before the rest looks.
    let mut report = PurgeReport {
        accounts: crate::deletion::purge_due(state, now).await?,
        ..PurgeReport::default()
    };

    let expired: Vec<(String, String)> = sqlx::query_as(
        "SELECT i.id, i.vault_id FROM items i JOIN vaults v ON v.id = i.vault_id \
         WHERE i.trashed_at IS NOT NULL AND i.trashed_at <= $1 AND i.purged_at IS NULL \
         AND v.deleted_at IS NULL ORDER BY i.trashed_at LIMIT $2",
    )
    .bind(cutoff)
    .bind(BATCH)
    .fetch_all(pool)
    .await?;
    for (item_id, vault_id) in expired {
        let vault_id: VaultId = parse_id(&vault_id)?;
        let item_id: ItemId = parse_id(&item_id)?;
        let mut w = match VaultWrite::begin(state, vault_id).await {
            Ok(w) => w,
            // The vault was deleted meanwhile: its own purge takes the item.
            Err(crate::error::ApiError::NotFound) => continue,
            Err(e) => return Err(e),
        };
        // Still in the trash, long enough, and not purged? Read under the
        // vault lock that `restore` takes too: a restore that committed
        // first is seen here, and one that comes later finds the tombstone.
        let due: Option<String> = sqlx::query_scalar(
            "SELECT id FROM items WHERE id = $1 AND vault_id = $2 AND trashed_at IS NOT NULL \
             AND trashed_at <= $3 AND purged_at IS NULL",
        )
        .bind(item_id.to_string())
        .bind(vault_id.to_string())
        .bind(cutoff)
        .fetch_optional(&mut *w.tx)
        .await?;
        if due.is_none() {
            continue;
        }
        let files = purge_item(&mut w, item_id).await?;
        let revision = w.commit().await?;
        state.notify(vault_id, revision);
        remove_files(state, vault_id, &files).await;
        report.items += 1;
    }

    let vaults: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM vaults WHERE deleted_at IS NOT NULL AND deleted_at <= $1",
    )
    .bind(cutoff)
    .fetch_all(pool)
    .await?;
    for vault_id in vaults {
        let vault_id: VaultId = parse_id(&vault_id)?;
        if delete_vault_data(state, vault_id, cutoff).await? {
            report.vaults += 1;
        }
    }
    report.uploads = remove_idle_uploads(state, now).await?;

    let sessions = sqlx::query(
        "DELETE FROM sessions WHERE refresh_expires_at <= $1 \
         OR (revoked_at IS NOT NULL AND revoked_at <= $2)",
    )
    .bind(now - SESSION_GRACE_MS)
    .bind(now - SESSION_GRACE_MS)
    .execute(pool)
    .await?;
    report.sessions = sessions.rows_affected();
    crate::agentauth::purge_nonces(state, now).await?;
    // Tasks past their expiry end here if nobody looked at them (ADR 0021 §9).
    let tasks = crate::routes::tasks::sweep(state, crate::routes::tasks::Sweep::All, now).await?;
    if tasks > 0 {
        tracing::info!(tasks, "tasks ended by expiry");
    }

    if let Err(e) = remove_orphan_files(state).await {
        tracing::warn!(error = ?e, "orphan attachment sweep failed");
    }

    if report != PurgeReport::default() {
        tracing::info!(
            accounts = report.accounts,
            items = report.items,
            vaults = report.vaults,
            sessions = report.sessions,
            uploads = report.uploads,
            "purge"
        );
    }
    Ok(report)
}

/// Removes uploads that were declared but not completed, with no chunk for
/// [`UPLOAD_IDLE_MS`]: the row (revision 0, never synced) and its `.part`.
/// One being written right now is skipped.
async fn remove_idle_uploads(state: &AppState, now: i64) -> ApiResult<u64> {
    let idle: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, vault_id FROM attachments WHERE completed_at IS NULL \
         AND deleted_at IS NULL AND COALESCE(updated_at, created_at) <= $1 LIMIT $2",
    )
    .bind(now - UPLOAD_IDLE_MS)
    .bind(BATCH)
    .fetch_all(&state.db().pool)
    .await?;
    let mut removed = 0;
    for (id, vault) in idle {
        let id: AttachmentId = parse_id(&id)?;
        let vault: VaultId = parse_id(&vault)?;
        let Some(guard) = state.attachments().lock(id) else {
            continue;
        };
        let done = sqlx::query(
            "DELETE FROM attachments WHERE id = $1 AND completed_at IS NULL \
             AND deleted_at IS NULL AND COALESCE(updated_at, created_at) <= $2",
        )
        .bind(id.to_string())
        .bind(now - UPLOAD_IDLE_MS)
        .execute(&state.db().pool)
        .await?;
        if done.rows_affected() == 1 {
            state.attachments().remove(vault, id).await;
            removed += 1;
        }
        drop(guard);
    }
    Ok(removed)
}

/// Deletes attachment files and vault directories that no row needs: a
/// vault directory without a vault, a completed file whose row is deleted
/// or gone, a `.part` whose upload is no longer pending. Files are listed
/// before the rows are read: a row always exists before its file, so a new
/// upload is never taken for an orphan.
///
/// A file its row needs is left without taking its upload guard: a client
/// writing a chunk, completing or deleting that attachment right then
/// must never get a 409 because the sweep held the guard for a lookup.
/// Only a file to remove is locked (one being written is skipped), and its
/// row is read again under the guard before it goes.
async fn remove_orphan_files(state: &AppState) -> ApiResult<()> {
    let files = state.attachments().list().await?;
    for (vault, file) in files {
        match file {
            None => {
                let exists: Option<String> =
                    sqlx::query_scalar("SELECT id FROM vaults WHERE id = $1")
                        .bind(vault.to_string())
                        .fetch_optional(&state.db().pool)
                        .await?;
                if exists.is_none() {
                    state.attachments().remove_vault(vault).await;
                }
            }
            Some((id, part)) => {
                if needed(state, vault, id, part).await? {
                    continue;
                }
                let Some(guard) = state.attachments().lock(id) else {
                    continue;
                };
                // Not a repeat of the read above: a completion may have
                // committed, and dropped its guard, after that read. Only
                // this read, under the guard, may decide to remove a file.
                if !needed(state, vault, id, part).await? {
                    state.attachments().remove_one(vault, id, part).await;
                }
                drop(guard);
            }
        }
    }
    Ok(())
}

/// Whether a row needs the file of attachment `id` in `vault` (its `.part`
/// when `part`): a pending upload's `.part`, or a live completed
/// attachment's file.
async fn needed(state: &AppState, vault: VaultId, id: AttachmentId, part: bool) -> ApiResult<bool> {
    let row: Option<(Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT completed_at, deleted_at FROM attachments WHERE id = $1 AND vault_id = $2",
    )
    .bind(id.to_string())
    .bind(vault.to_string())
    .fetch_optional(&state.db().pool)
    .await?;
    Ok(match row {
        Some((completed, None)) => completed.is_some() != part,
        _ => false,
    })
}

/// Removes a vault deleted before `cutoff` and everything in it, children
/// first, plus what the server kept about it for agents: approvals, task
/// targets, and the tasks that were only about this vault. Returns `false`
/// (and changes nothing) if the vault was restored meanwhile.
async fn delete_vault_data(state: &AppState, vault_id: VaultId, cutoff: i64) -> ApiResult<bool> {
    let id = vault_id.to_string();
    let mut tx = state.db().pool.begin().await?;
    // The vault row's lock, and the check that it is still due: a restore
    // (which updates the same row) either committed before and is seen
    // here, or waits and then finds no vault (404).
    let due = sqlx::query(
        "UPDATE vaults SET revision = revision WHERE id = $1 \
         AND deleted_at IS NOT NULL AND deleted_at <= $2",
    )
    .bind(&id)
    .bind(cutoff)
    .execute(&mut *tx)
    .await?;
    if due.rows_affected() == 0 {
        return Ok(false);
    }
    let owner: String = sqlx::query_scalar("SELECT owner_account_id FROM vaults WHERE id = $1")
        .bind(&id)
        .fetch_one(&mut *tx)
        .await?;
    let attachments: Vec<String> =
        sqlx::query_scalar("SELECT id FROM attachments WHERE vault_id = $1")
            .bind(&id)
            .fetch_all(&mut *tx)
            .await?;
    // Tasks of the owner's agents that name only this vault go; a task
    // that also names another vault keeps its row (its targets here go).
    let tasks: Vec<(String, Vec<u8>, Option<Vec<u8>>)> =
        sqlx::query_as("SELECT id, request, decision FROM tasks WHERE account_id = $1")
            .bind(&owner)
            .fetch_all(&mut *tx)
            .await?;
    for (task, request, decision) in tasks {
        let only_here = if request.is_empty() {
            // A task the person offered (ADR 0022 §6) has no request: its
            // accesses are in the signed decision.
            decision
                .and_then(|d| serde_json::from_slice::<klav_core::task::TaskDecision>(&d).ok())
                .is_some_and(|d| d.access.iter().all(|a| a.vault_id == vault_id))
        } else {
            serde_json::from_slice::<klav_core::task::TaskRequest>(&request)
                .is_ok_and(|r| r.access.iter().all(|a| a.vault_id == vault_id))
        };
        if only_here {
            sqlx::query("DELETE FROM task_targets WHERE task_id = $1")
                .bind(&task)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM tasks WHERE id = $1")
                .bind(&task)
                .execute(&mut *tx)
                .await?;
        }
    }
    // Target keys are JSON arrays with the vault ID as a quoted string.
    sqlx::query("DELETE FROM task_targets WHERE target_key LIKE $1")
        .bind(format!("%\"{id}\"%"))
        .execute(&mut *tx)
        .await?;
    for sql in [
        // Assisted changes keep the item's host in the clear.
        "DELETE FROM rotations WHERE vault_id = $1",
        "DELETE FROM approvals WHERE vault_id = $1",
        "DELETE FROM attachments WHERE vault_id = $1",
        "DELETE FROM item_versions WHERE item_id IN (SELECT id FROM items WHERE vault_id = $1)",
        "DELETE FROM items WHERE vault_id = $1",
        "DELETE FROM agent_projects WHERE vault_id = $1",
        "DELETE FROM projects WHERE vault_id = $1",
        "DELETE FROM vault_members WHERE vault_id = $1",
        "DELETE FROM vaults WHERE id = $1",
    ] {
        sqlx::query(sql).bind(&id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    // Uploads still writing a chunk read their row before the commit:
    // let them finish, then remove everything.
    for attachment in &attachments {
        if let Ok(attachment) = parse_id::<AttachmentId>(attachment) {
            drop(state.attachments().lock_wait(attachment).await);
        }
    }
    state.attachments().remove_vault(vault_id).await;
    Ok(true)
}
