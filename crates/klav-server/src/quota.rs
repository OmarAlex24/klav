//! Per-account quotas (ADR 0048 §3): attachments, vault data, items and
//! vaults, counted over the vaults an account owns (the owner pays; today
//! only the owner is a member).
//!
//! Every check runs inside the write's transaction, which already holds
//! the owner's account lock (`deletion::lock_account`), so two writes at
//! once can't both fit in the last free space (T248). Usage is measured
//! with `SUM`/`COUNT` under that lock: writes are rare, so this is cheap.
//!
//! What is never refused: a write that doesn't grow the account (a
//! non-positive delta), deleting or trashing anything, and reading. An
//! account over a quota that was lowered later keeps everything and can
//! still clean up.

use sqlx::{Any, Transaction};

use crate::config::Limits;
use crate::error::{ApiError, ApiResult};

type Tx<'a> = Transaction<'a, Any>;

/// What a write adds to its owner's account. Zero or negative fields are
/// never checked.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Delta {
    /// Declared bytes of new attachments.
    pub(crate) attachment_bytes: i64,
    /// Encrypted bytes of items, kept versions and `meta`.
    pub(crate) vault_bytes: i64,
    /// New items.
    pub(crate) items: i64,
    /// New vaults.
    pub(crate) vaults: i64,
}

/// Refuses with `403 quota_exceeded` if `delta` takes `owner` over one of
/// its limits. Call it after the owner's account lock, before committing.
pub(crate) async fn check(
    tx: &mut Tx<'_>,
    limits: &Limits,
    owner: &str,
    delta: Delta,
) -> ApiResult<()> {
    if delta.attachment_bytes > 0 && limits.max_account_attachment_bytes != 0 {
        let used = attachment_bytes(tx, owner).await?;
        refuse_over(
            used,
            delta.attachment_bytes,
            limits.max_account_attachment_bytes,
            |used, max| {
                format!(
                    "Attachments for this account are limited to {} ({} used). Delete some, or \
                     empty the trash.",
                    bytes(max),
                    bytes(used)
                )
            },
        )?;
    }
    if delta.vault_bytes > 0 && limits.max_account_vault_bytes != 0 {
        let used = vault_bytes(tx, owner).await?;
        refuse_over(
            used,
            delta.vault_bytes,
            limits.max_account_vault_bytes,
            vault_message,
        )?;
    }
    if delta.items > 0 && limits.max_items_per_account != 0 {
        let used = items(tx, owner).await?;
        refuse_over(
            used,
            delta.items,
            limits.max_items_per_account,
            |used, max| {
                format!(
                    "This account is limited to {max} items ({used} used, the trash included). \
                 Delete some, or empty the trash."
                )
            },
        )?;
    }
    if delta.vaults > 0 && limits.max_vaults_per_account != 0 {
        let used = vaults(tx, owner).await?;
        refuse_over(
            used,
            delta.vaults,
            limits.max_vaults_per_account,
            |used, max| {
                format!(
                    "This account is limited to {max} vaults ({used} used; deleted vaults count \
                 until they are purged)."
                )
            },
        )?;
    }
    Ok(())
}

/// For a write whose growth is easier to measure than to predict (a new
/// item version moves the old one to the history and may drop older
/// ones): `before` is [`vault_bytes`] taken under the lock before the
/// write, and this refuses only if the account grew and is now over the
/// limit.
pub(crate) async fn check_growth(
    tx: &mut Tx<'_>,
    limits: &Limits,
    owner: &str,
    before: i64,
) -> ApiResult<()> {
    if limits.max_account_vault_bytes == 0 {
        return Ok(());
    }
    let after = vault_bytes(tx, owner).await?;
    if after > before {
        refuse_over(
            before,
            after - before,
            limits.max_account_vault_bytes,
            vault_message,
        )?;
    }
    Ok(())
}

/// Whether [`check_growth`] has anything to measure (skips the first
/// measurement when the vault-data quota is off).
pub(crate) fn measures_vault_bytes(limits: &Limits) -> bool {
    limits.max_account_vault_bytes != 0
}

fn vault_message(used: u64, max: u64) -> String {
    format!(
        "Vault data for this account is limited to {} ({} used, kept item versions included). \
         Delete items, empty the trash, or forget old versions.",
        bytes(max),
        bytes(used)
    )
}

fn refuse_over(
    used: i64,
    delta: i64,
    max: u64,
    message: impl FnOnce(u64, u64) -> String,
) -> ApiResult<()> {
    let used = u64::try_from(used).unwrap_or(0);
    let delta = u64::try_from(delta).unwrap_or(0);
    if used.saturating_add(delta) > max {
        Err(ApiError::quota_exceeded(message(used, max)))
    } else {
        Ok(())
    }
}

/// Declared size of every attachment of the owner's vaults that is not
/// purged: finished, pending, and those of trashed items or deleted vaults.
pub(crate) async fn attachment_bytes(tx: &mut Tx<'_>, owner: &str) -> ApiResult<i64> {
    // Postgres sums BIGINT into NUMERIC, which `sqlx::Any` cannot decode.
    Ok(sqlx::query_scalar(
        "SELECT CAST(COALESCE(SUM(a.size), 0) AS BIGINT) \
         FROM attachments a JOIN vaults v ON v.id = a.vault_id \
         WHERE v.owner_account_id = $1 AND a.deleted_at IS NULL",
    )
    .bind(owner)
    .fetch_one(&mut **tx)
    .await?)
}

/// Encrypted bytes of the owner's vaults, attachments aside: `overview`,
/// `details` and `wrapped_key` of every item not purged and of its kept
/// versions, and the `meta` of every vault and project.
pub(crate) async fn vault_bytes(tx: &mut Tx<'_>, owner: &str) -> ApiResult<i64> {
    Ok(sqlx::query_scalar(
        "SELECT CAST(\
           COALESCE((SELECT SUM(COALESCE(LENGTH(i.overview), 0) + COALESCE(LENGTH(i.details), 0) \
                     + COALESCE(LENGTH(i.wrapped_key), 0)) \
                     FROM items i JOIN vaults v ON v.id = i.vault_id \
                     WHERE v.owner_account_id = $1 AND i.purged_at IS NULL), 0) \
         + COALESCE((SELECT SUM(COALESCE(LENGTH(iv.overview), 0) + COALESCE(LENGTH(iv.details), 0) \
                     + COALESCE(LENGTH(iv.wrapped_key), 0)) \
                     FROM item_versions iv JOIN items i ON i.id = iv.item_id \
                     JOIN vaults v ON v.id = i.vault_id \
                     WHERE v.owner_account_id = $1 AND i.purged_at IS NULL), 0) \
         + COALESCE((SELECT SUM(COALESCE(LENGTH(v.meta), 0)) FROM vaults v \
                     WHERE v.owner_account_id = $1), 0) \
         + COALESCE((SELECT SUM(COALESCE(LENGTH(p.meta), 0)) \
                     FROM projects p JOIN vaults v ON v.id = p.vault_id \
                     WHERE v.owner_account_id = $1), 0) \
         AS BIGINT)",
    )
    .bind(owner)
    .fetch_one(&mut **tx)
    .await?)
}

/// Items of the owner's vaults that are not purged (the trash counts).
pub(crate) async fn items(tx: &mut Tx<'_>, owner: &str) -> ApiResult<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM items i JOIN vaults v ON v.id = i.vault_id \
         WHERE v.owner_account_id = $1 AND i.purged_at IS NULL",
    )
    .bind(owner)
    .fetch_one(&mut **tx)
    .await?)
}

/// Vaults the owner has, deleted ones until they are purged.
pub(crate) async fn vaults(tx: &mut Tx<'_>, owner: &str) -> ApiResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT COUNT(*) FROM vaults WHERE owner_account_id = $1")
            .bind(owner)
            .fetch_one(&mut **tx)
            .await?,
    )
}

/// The owner of a vault, read inside a write.
pub(crate) async fn owner_of(tx: &mut Tx<'_>, vault_id: &str) -> ApiResult<String> {
    sqlx::query_scalar("SELECT owner_account_id FROM vaults WHERE id = $1")
        .bind(vault_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ApiError::NotFound)
}

/// Length of a stored blob column (0 when `NULL` or missing), for the
/// delta of a `meta` change.
pub(crate) async fn stored_len(tx: &mut Tx<'_>, sql: &'static str, id: &str) -> ApiResult<i64> {
    let len: Option<Option<i64>> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(len.flatten().unwrap_or(0))
}

/// A byte count as people read it: `250 MiB`, `248.3 MiB`, `10 GiB`.
fn bytes(n: u64) -> String {
    const UNITS: [(&str, u64); 3] = [("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)];
    for (unit, size) in UNITS {
        if n >= size {
            #[allow(clippy::cast_precision_loss)]
            let value = n as f64 / size as f64;
            let text = format!("{value:.1}");
            return format!("{} {unit}", text.strip_suffix(".0").unwrap_or(&text));
        }
    }
    format!("{n} bytes")
}

/// `i64` length of a blob about to be stored.
pub(crate) fn len(blob: &[u8]) -> i64 {
    i64::try_from(blob.len()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_counts_read_well() {
        assert_eq!(bytes(250 << 20), "250 MiB");
        assert_eq!(bytes((248 << 20) + (3 << 20) / 10 + 1), "248.3 MiB");
        assert_eq!(bytes(10 << 30), "10 GiB");
        assert_eq!(bytes(1536), "1.5 KiB");
        assert_eq!(bytes(12), "12 bytes");
    }

    #[test]
    fn only_growth_past_the_limit_is_refused() {
        let msg = |u: u64, m: u64| format!("{u}/{m}");
        assert!(refuse_over(90, 10, 100, msg).is_ok());
        assert!(refuse_over(90, 11, 100, msg).is_err());
        // Already over a lowered limit: still refused to grow.
        assert!(refuse_over(150, 1, 100, msg).is_err());
    }
}
