//! Helpers shared by every vault-scoped route: membership checks, the vault
//! write transaction (which assigns the next revision) and number conversions.

use std::str::FromStr;

use klav_core::ids::{AccountId, AgentId, VaultId};
use klav_proto::vault::Role;
use sqlx::{Any, Transaction};

use crate::db::now_ms;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Member type of person accounts in `vault_members`.
pub(crate) const MEMBER_ACCOUNT: &str = "account";

/// Revisions and versions are `BIGINT` in the database and `u64` on the wire.
pub(crate) fn to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

/// Converts a client-supplied number for storage.
pub(crate) fn to_i64(value: u64) -> ApiResult<i64> {
    i64::try_from(value).map_err(|_| ApiError::bad_request("number out of range"))
}

/// Parses an ID from the URL path; anything malformed is simply not found.
pub(crate) fn path_id<T: FromStr>(text: &str) -> ApiResult<T> {
    text.parse().map_err(|_| ApiError::NotFound)
}

pub(crate) fn role_from_db(text: &str) -> Role {
    match text {
        "owner" => Role::Owner,
        _ => Role::Member,
    }
}

pub(crate) fn role_to_db(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Member => "member",
    }
}

/// The caller's role in a vault, or 404 if they are not an active member.
/// Non-members cannot tell a vault that exists from one that does not.
pub(crate) async fn require_member(
    state: &AppState,
    vault_id: VaultId,
    account_id: AccountId,
) -> ApiResult<Role> {
    let role: Option<String> = sqlx::query_scalar(
        "SELECT role FROM vault_members WHERE vault_id = $1 AND member_type = $2 \
         AND member_id = $3 AND revoked_at IS NULL",
    )
    .bind(vault_id.to_string())
    .bind(MEMBER_ACCOUNT)
    .bind(account_id.to_string())
    .fetch_optional(&state.db().pool)
    .await?;
    role.map(|r| role_from_db(&r)).ok_or(ApiError::NotFound)
}

/// Like [`require_member`] but only the owner passes (others get 403).
pub(crate) async fn require_owner(
    state: &AppState,
    vault_id: VaultId,
    account_id: AccountId,
) -> ApiResult<()> {
    match require_member(state, vault_id, account_id).await? {
        Role::Owner => Ok(()),
        Role::Member => Err(ApiError::Forbidden),
    }
}

/// An open write transaction on a vault, holding its next revision.
///
/// The first statement increments the vault revision, which takes the vault
/// row lock (Postgres) or the database write lock (SQLite) right away. Writers
/// of the same vault are therefore serialised and revisions are assigned in
/// commit order: a reader that sees revision `r` has also seen every change
/// with a revision `≤ r`. If the handler returns an error before
/// [`VaultWrite::commit`], dropping the transaction rolls the increment back.
pub(crate) struct VaultWrite {
    pub(crate) tx: Transaction<'static, Any>,
    pub(crate) revision: i64,
    pub(crate) now: i64,
}

impl VaultWrite {
    /// Starts a write on a vault that is not deleted (404 otherwise).
    pub(crate) async fn begin(state: &AppState, vault_id: VaultId) -> ApiResult<Self> {
        Self::begin_for(state, vault_id, None).await
    }

    /// [`Self::begin`] for a write that `account`'s person makes and logs in
    /// its own transaction: the account's row is locked before the vault's,
    /// as every transaction that logs in itself takes it first.
    pub(crate) async fn begin_for(
        state: &AppState,
        vault_id: VaultId,
        account: Option<AccountId>,
    ) -> ApiResult<Self> {
        let mut tx = state.db().pool.begin().await?;
        if let Some(account) = account {
            crate::deletion::lock_account(&mut tx, account).await?;
        }
        Self::bump(tx, vault_id, now_ms()).await
    }

    /// [`Self::begin`] for a write that may grow the vault owner's account
    /// (ADR 0048 §3.2): the owner's account row is locked first, as every
    /// write that logs in its own transaction takes it, then the vault's.
    /// Returns the owner, whose quotas the write is checked against.
    pub(crate) async fn begin_owner(
        state: &AppState,
        vault_id: VaultId,
    ) -> ApiResult<(Self, String)> {
        let mut tx = state.db().pool.begin().await?;
        let locked = sqlx::query(
            "UPDATE accounts SET updated_at = updated_at WHERE id = \
             (SELECT owner_account_id FROM vaults WHERE id = $1 AND deleted_at IS NULL)",
        )
        .bind(vault_id.to_string())
        .execute(&mut *tx)
        .await?;
        if locked.rows_affected() == 0 {
            return Err(ApiError::NotFound);
        }
        let owner = crate::quota::owner_of(&mut tx, &vault_id.to_string()).await?;
        Ok((Self::bump(tx, vault_id, now_ms()).await?, owner))
    }

    /// [`Self::begin`] for an agent's write on `account`'s vault: the
    /// account's row is locked first, as for the person, and the agent must
    /// still be active under that lock ([`crate::agentauth::still_active`],
    /// `403 forbidden` otherwise), the person must not have asked to delete
    /// the account (`403 account_deleting`), and the agent must not be
    /// paused (`403 agents_paused`), in the order `audit::append_in` checks
    /// them. The agent's route logs its event before this write, in its own
    /// transaction; a revocation, a deletion request or a pause committed in
    /// between is seen here, and nothing is written after it.
    pub(crate) async fn begin_for_agent(
        state: &AppState,
        vault_id: VaultId,
        account: AccountId,
        agent: AgentId,
    ) -> ApiResult<Self> {
        let mut tx = state.db().pool.begin().await?;
        crate::deletion::lock_account(&mut tx, account).await?;
        let now = now_ms();
        crate::agentauth::still_active(&mut *tx, agent, account, now).await?;
        crate::deletion::refuse_if_deleting(&mut *tx, account).await?;
        crate::pause::refuse_if_paused(&mut *tx, account, agent, now).await?;
        Self::bump(tx, vault_id, now).await
    }

    /// Takes the vault's next revision in `tx` (the vault's lock).
    async fn bump(
        mut tx: Transaction<'static, Any>,
        vault_id: VaultId,
        now: i64,
    ) -> ApiResult<Self> {
        let revision: Option<i64> = sqlx::query_scalar(
            "UPDATE vaults SET revision = revision + 1 \
             WHERE id = $1 AND deleted_at IS NULL RETURNING revision",
        )
        .bind(vault_id.to_string())
        .fetch_optional(&mut *tx)
        .await?;
        let revision = revision.ok_or(ApiError::NotFound)?;
        Ok(Self { tx, revision, now })
    }

    /// Commits and returns the revision the change got.
    pub(crate) async fn commit(self) -> ApiResult<u64> {
        self.tx.commit().await?;
        Ok(to_u64(self.revision))
    }
}
