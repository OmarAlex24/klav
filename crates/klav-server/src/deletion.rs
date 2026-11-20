//! Deleting an account (ADR 0037).
//!
//! The person asks with the master password (an OPAQUE exchange inside the
//! session, `routes/account.rs`), and the server stores one row in
//! `account_deletions`: the account is deleted 7 days later by the hourly
//! purge, unless a device cancels it first. Meanwhile every signed agent
//! request is refused with `403 account_deleting` (in the request
//! extractor, and again under the account's lock when an allowed action is
//! logged), and new agent registrations are dropped without a word.
//!
//! Asking, canceling and the purge all take the account row's lock first
//! (`UPDATE accounts SET updated_at = updated_at`), so a cancel that
//! committed a moment before the purge always wins.

use std::collections::HashMap;
use std::sync::Mutex;

use klav_core::ids::{AccountId, AttachmentId, VaultId};
use klav_proto::auth::AccountDeletion;
use sqlx::Row;

use crate::error::{ApiError, ApiResult};
use crate::push::PushKind;
use crate::session::parse_id;
use crate::state::AppState;
use crate::vaultdb::MEMBER_ACCOUNT;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const HOUR_MS: i64 = 60 * 60 * 1000;
/// Time between asking and the deletion (ADR 0037 §2).
pub(crate) const DELETION_DELAY_MS: i64 = 7 * DAY_MS;
/// Reauthentications (`start`) per account and hour, whatever their outcome
/// (ADR 0037 §5.6).
const STARTS_PER_HOUR: usize = 5;
/// Deletions asked per account in [`REQUEST_WINDOW_MS`], so asking and
/// canceling over and over cannot flood the phones (ADR 0037 §5.6, T163).
const REQUESTS_PER_WINDOW: usize = 3;
const REQUEST_WINDOW_MS: i64 = 7 * DAY_MS;
/// Accounts deleted per purge run (the rest waits for the next run).
const BATCH: i64 = 100;

/// Takes the account row's lock inside `tx`. Also turns a SQLite
/// transaction into a writer before it reads anything.
pub(crate) async fn lock_account(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    account: AccountId,
) -> ApiResult<bool> {
    let locked = sqlx::query("UPDATE accounts SET updated_at = updated_at WHERE id = $1")
        .bind(account.to_string())
        .execute(&mut **tx)
        .await?;
    Ok(locked.rows_affected() == 1)
}

/// When `account` is deleted, if the person asked for it.
pub(crate) async fn delete_at<'e, E>(exec: E, account: AccountId) -> ApiResult<Option<i64>>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    Ok(
        sqlx::query_scalar("SELECT delete_at FROM account_deletions WHERE account_id = $1")
            .bind(account.to_string())
            .fetch_optional(exec)
            .await?,
    )
}

/// Refuses with `403 account_deleting` while a deletion of `account` is
/// asked for.
pub(crate) async fn refuse_if_deleting<'e, E>(exec: E, account: AccountId) -> ApiResult<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    match delete_at(exec, account).await? {
        Some(at) => Err(ApiError::AccountDeleting(at)),
        None => Ok(()),
    }
}

/// The deletion of `account` the person asked for, with the asking
/// device's name.
pub(crate) async fn pending<'e, E>(
    exec: E,
    account: AccountId,
) -> ApiResult<Option<AccountDeletion>>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    let row = sqlx::query(
        "SELECT x.requested_at, x.delete_at, x.device_id, d.name FROM account_deletions x \
         LEFT JOIN devices d ON d.id = x.device_id WHERE x.account_id = $1",
    )
    .bind(account.to_string())
    .fetch_optional(exec)
    .await?;
    row.map(|row| {
        Ok(AccountDeletion {
            requested_at: row.try_get("requested_at")?,
            delete_at: row.try_get("delete_at")?,
            device_id: parse_id(&row.try_get::<String, _>("device_id")?)?,
            device_name: row
                .try_get::<Option<String>, _>("name")?
                .unwrap_or_default(),
        })
    })
    .transpose()
}

/// Per-account limits of asking for a deletion (ADR 0037 §5.6). They live
/// in memory, like every rate limit of this server: a restart resets them
/// (docs/self-hosting.md).
#[derive(Default)]
pub(crate) struct DeletionLimits {
    starts: Mutex<HashMap<AccountId, Vec<i64>>>,
    requests: Mutex<HashMap<AccountId, Vec<i64>>>,
}

/// Keeps the times of `account` inside `window` and, if fewer than `max`
/// remain, records `now` when `record`. Otherwise answers `429` with the
/// seconds until the oldest leaves the window.
fn take(
    map: &Mutex<HashMap<AccountId, Vec<i64>>>,
    account: AccountId,
    now: i64,
    (max, window): (usize, i64),
    record: bool,
) -> ApiResult<()> {
    let mut map = map
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let times = map.entry(account).or_default();
    times.retain(|t| now - t < window);
    if times.len() >= max {
        let oldest = times.iter().min().copied().unwrap_or(now);
        let wait_ms = (oldest + window - now).max(1000);
        return Err(ApiError::TooManyRequests {
            retry_after_secs: u64::try_from((wait_ms + 999) / 1000).unwrap_or(1),
        });
    }
    if record {
        times.push(now);
    }
    Ok(())
}

impl DeletionLimits {
    /// Takes one reauthentication from the account's hourly budget.
    pub(crate) fn start(&self, account: AccountId, now: i64) -> ApiResult<()> {
        take(&self.starts, account, now, (STARTS_PER_HOUR, HOUR_MS), true)
    }

    /// Fails if the account already asked [`REQUESTS_PER_WINDOW`] times in
    /// the window, without counting this one (checked in `start`, before
    /// any OPAQUE work here).
    pub(crate) fn may_request(&self, account: AccountId, now: i64) -> ApiResult<()> {
        take(
            &self.requests,
            account,
            now,
            (REQUESTS_PER_WINDOW, REQUEST_WINDOW_MS),
            false,
        )
    }

    /// Counts a scheduled deletion; fails over the limit.
    pub(crate) fn request(&self, account: AccountId, now: i64) -> ApiResult<()> {
        take(
            &self.requests,
            account,
            now,
            (REQUESTS_PER_WINDOW, REQUEST_WINDOW_MS),
            true,
        )
    }

    /// Forgets a deleted account.
    pub(crate) fn forget(&self, account: AccountId) {
        for map in [&self.starts, &self.requests] {
            map.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&account);
        }
    }
}

/// Deletes the accounts whose `delete_at` is at or before `now`. Returns
/// how many it deleted.
///
/// One account that fails (a database error, a row that does not parse)
/// is logged and left for the next run: it never stops the deletion of
/// the others, nor the rest of the purge (the trash, deleted vaults and
/// session retention run after this). Its row stays, so the next run
/// tries it again. Should [`BATCH`] accounts fail every run, the ones due
/// later would wait behind them; the log says which.
pub(crate) async fn purge_due(state: &AppState, now: i64) -> ApiResult<u64> {
    let due: Vec<String> = sqlx::query_scalar(
        "SELECT account_id FROM account_deletions WHERE delete_at <= $1 \
         ORDER BY delete_at LIMIT $2",
    )
    .bind(now)
    .bind(BATCH)
    .fetch_all(&state.db().pool)
    .await?;
    let mut deleted = 0;
    for account in due {
        let result = match parse_id::<AccountId>(&account) {
            Ok(id) => delete_account(state, id, now).await,
            Err(e) => Err(e),
        };
        match result {
            Ok(true) => deleted += 1,
            Ok(false) => {}
            Err(e) => tracing::error!(
                account = %account,
                error = ?e,
                "account deletion failed; the next purge tries again"
            ),
        }
    }
    Ok(deleted)
}

/// Deletes `account` and everything it has (ADR 0037 §5.2), if its
/// deletion is still asked for and due at `now`: a cancel that committed
/// first is seen here, under the same lock, and one that comes later finds
/// no account. Returns `false` (and changes nothing) otherwise. On an
/// error the transaction is rolled back before returning, so the account's
/// lock is free for whoever comes next.
pub(crate) async fn delete_account(
    state: &AppState,
    account: AccountId,
    now: i64,
) -> ApiResult<bool> {
    let mut tx = state.db().pool.begin().await?;
    let doomed = match delete_in(&mut tx, account, now).await {
        Ok(Some(doomed)) => doomed,
        Ok(None) => return Ok(false),
        Err(e) => {
            let _ = tx.rollback().await;
            return Err(e);
        }
    };
    tx.commit().await?;

    // The files, now (the hourly orphan sweep stays as the fallback).
    // Uploads still writing a chunk read their row before the commit: let
    // them finish, then remove everything.
    for attachment in &doomed.attachments {
        if let Ok(attachment) = parse_id::<AttachmentId>(attachment) {
            drop(state.attachments().lock_wait(attachment).await);
        }
    }
    for vault in &doomed.vaults {
        if let Ok(vault) = parse_id::<VaultId>(vault) {
            state.attachments().remove_vault(vault).await;
        }
    }
    state.logins().forget_account(account);
    state.deletion_limits().forget(account);
    state.account_deleted(account);
    state.push_to(account, PushKind::AccountDeleted, doomed.phones);
    // The only trace the server keeps, so whoever restores an older backup
    // can delete the account again (ADR 0037 §5.5). Never the e-mail.
    tracing::info!(account = %account, "account deleted");
    Ok(true)
}

/// What has to go after the commit: the files of its vaults, and the
/// phones to tell (the cascade deletes their tokens).
struct Doomed {
    vaults: Vec<String>,
    attachments: Vec<String>,
    phones: Vec<crate::push::Phone>,
}

/// The deletion inside `tx`, if still asked for and due: `None` otherwise.
async fn delete_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    account: AccountId,
    now: i64,
) -> ApiResult<Option<Doomed>> {
    let id = account.to_string();
    if !lock_account(tx, account).await? {
        return Ok(None);
    }
    let due: Option<i64> = sqlx::query_scalar(
        "SELECT delete_at FROM account_deletions WHERE account_id = $1 AND delete_at <= $2",
    )
    .bind(&id)
    .bind(now)
    .fetch_optional(&mut **tx)
    .await?;
    if due.is_none() {
        return Ok(None);
    }
    let vaults: Vec<String> =
        sqlx::query_scalar("SELECT id FROM vaults WHERE owner_account_id = $1")
            .bind(&id)
            .fetch_all(&mut **tx)
            .await?;
    let attachments: Vec<String> = sqlx::query_scalar(
        "SELECT a.id FROM attachments a JOIN vaults v ON v.id = a.vault_id \
         WHERE v.owner_account_id = $1",
    )
    .bind(&id)
    .fetch_all(&mut **tx)
    .await?;
    let phones = crate::push::phones(&mut **tx, account).await?;
    // `member_id` names the account without a foreign key: its rows in
    // other people's vaults do not go with the cascade. (Today there are
    // none: every vault has one owner and no other member. What happens to
    // a shared vault whose owner deletes the account is for the sharing
    // ADR.)
    sqlx::query("DELETE FROM vault_members WHERE member_type = $1 AND member_id = $2")
        .bind(MEMBER_ACCOUNT)
        .bind(&id)
        .execute(&mut **tx)
        .await?;
    // Everything else references the account through `ON DELETE CASCADE`
    // (SQLite needs `PRAGMA foreign_keys = ON`, set on every connection in
    // `db.rs`): devices, sessions, push tokens, vaults and their contents,
    // agents and what they asked for, the audit log, the pauses and the
    // deletion's own row.
    sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(&id)
        .execute(&mut **tx)
        .await?;
    Ok(Some(Doomed {
        vaults,
        attachments,
        phones,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_are_limited_per_account_and_hour() {
        let limits = DeletionLimits::default();
        let ana = AccountId::generate();
        let bob = AccountId::generate();
        let now = 1_000_000_000;
        for _ in 0..STARTS_PER_HOUR {
            limits.start(ana, now).unwrap();
        }
        assert!(matches!(
            limits.start(ana, now + 1),
            Err(ApiError::TooManyRequests { retry_after_secs }) if retry_after_secs == 3600
        ));
        limits.start(bob, now).unwrap();
        limits.start(ana, now + HOUR_MS).unwrap();
    }

    #[test]
    fn three_requests_per_week() {
        let limits = DeletionLimits::default();
        let ana = AccountId::generate();
        let now = 1_000_000_000;
        for i in 0..REQUESTS_PER_WINDOW {
            // Checking does not count.
            limits.may_request(ana, now).unwrap();
            limits.may_request(ana, now).unwrap();
            limits
                .request(ana, now + i64::try_from(i).unwrap())
                .unwrap();
        }
        assert!(limits.may_request(ana, now + 10).is_err());
        assert!(limits.request(ana, now + 10).is_err());
        // The first leaves the window 7 days after it.
        limits.may_request(ana, now + REQUEST_WINDOW_MS).unwrap();
        // A deleted account starts over (its ID is never reused anyway).
        limits.forget(ana);
        limits.request(ana, now + 10).unwrap();
    }
}
