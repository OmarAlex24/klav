//! Delta synchronisation and server-sent change notifications.

use std::collections::HashSet;
use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::get;
use axum::{Json, Router};
use klav_core::ids::VaultId;
use klav_proto::sync::{
    ChangeEvent, Changes, ChangesQuery, SecretRequestEvent, SyncState, VaultRevision,
};
use sqlx::Row;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;

use super::attachments::{ATTACHMENT_COLUMNS, attachment_from_row};
use super::items::{ITEM_COLUMNS, item_from_row};
use super::vaults::{
    MEMBER_COLUMNS, PROJECT_COLUMNS, fetch_vault, member_from_row, project_from_row,
};
use crate::db::now_ms;
use crate::error::{ApiError, ApiQuery, ApiResult};
use crate::session::{self, Auth, parse_id};
use crate::state::AppState;
use crate::vaultdb::{MEMBER_ACCOUNT, path_id, require_member, to_i64, to_u64};

/// How often an open event stream re-checks that its session is still valid.
const SESSION_CHECK: Duration = Duration::from_secs(30);
/// Keep-alive comment interval on the event stream.
const KEEP_ALIVE: Duration = Duration::from_secs(15);

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/sync", get(sync_state))
        .route("/v1/vaults/{vault_id}/changes", get(changes))
        .route("/v1/events", get(events))
}

async fn sync_state(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<SyncState>> {
    let rows = sqlx::query(
        "SELECT v.id, v.revision, v.deleted_at FROM vaults v \
         JOIN vault_members m ON m.vault_id = v.id \
         WHERE m.member_type = $1 AND m.member_id = $2 AND m.revoked_at IS NULL \
         ORDER BY v.created_at, v.id",
    )
    .bind(MEMBER_ACCOUNT)
    .bind(auth.account_id.to_string())
    .fetch_all(&state.db().pool)
    .await?;
    let vaults = rows
        .iter()
        .map(|row| {
            Ok(VaultRevision {
                vault_id: parse_id(&row.try_get::<String, _>("id")?)?,
                revision: to_u64(row.try_get("revision")?),
                deleted_at: row.try_get("deleted_at")?,
            })
        })
        .collect::<ApiResult<_>>()?;
    let agent_pauses = crate::pause::in_effect(&state.db().pool, auth.account_id, now_ms()).await?;
    // Every device learns a deletion the person asked for (ADR 0037 §3).
    let deletion = crate::deletion::pending(&state.db().pool, auth.account_id).await?;
    // The last heartbeat of each active proxy, as signed (ADR 0036 E3.3).
    let sandbox_state =
        crate::routes::sandboxes::heartbeats(&state.db().pool, auth.account_id).await?;
    Ok(Json(SyncState {
        vaults,
        agent_pauses,
        deletion,
        sandbox_state,
    }))
}

/// Everything in the vault with `since < revision ≤ current`.
///
/// The current revision is read **first**. Revisions are assigned under the
/// vault row lock and committed atomically with the rows they label, so
/// every row with a revision `≤ current` is already visible: nothing can be
/// skipped, and a change committed meanwhile shows up in the next call.
async fn changes(
    State(state): State<AppState>,
    auth: Auth,
    Path(vault_id): Path<String>,
    ApiQuery(query): ApiQuery<ChangesQuery>,
) -> ApiResult<Json<Changes>> {
    let vault_id: VaultId = path_id(&vault_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    let pool = &state.db().pool;
    let since = to_i64(query.since)?;
    let row = sqlx::query("SELECT revision, meta_revision FROM vaults WHERE id = $1")
        .bind(vault_id.to_string())
        .fetch_optional(pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    let current: i64 = row.try_get("revision")?;
    let meta_revision: i64 = row.try_get("meta_revision")?;

    let vault = if meta_revision > since {
        Some(fetch_vault(&state, &auth, vault_id).await?)
    } else {
        None
    };
    let window = |table: &str, columns: &str| {
        format!(
            "SELECT {columns} FROM {table} WHERE vault_id = $1 AND revision > $2 \
             AND revision <= $3 ORDER BY revision"
        )
    };
    let id = vault_id.to_string();
    let members = sqlx::query(sqlx::AssertSqlSafe(window("vault_members", MEMBER_COLUMNS)))
        .bind(&id)
        .bind(since)
        .bind(current)
        .fetch_all(pool)
        .await?;
    let projects = sqlx::query(sqlx::AssertSqlSafe(window("projects", PROJECT_COLUMNS)))
        .bind(&id)
        .bind(since)
        .bind(current)
        .fetch_all(pool)
        .await?;
    let items = sqlx::query(sqlx::AssertSqlSafe(window("items", ITEM_COLUMNS)))
        .bind(&id)
        .bind(since)
        .bind(current)
        .fetch_all(pool)
        .await?;
    let attachments = sqlx::query(sqlx::AssertSqlSafe(window(
        "attachments",
        ATTACHMENT_COLUMNS,
    )))
    .bind(&id)
    .bind(since)
    .bind(current)
    .fetch_all(pool)
    .await?;

    Ok(Json(Changes {
        vault_id,
        since: query.since,
        revision: to_u64(current),
        vault,
        members: members
            .iter()
            .map(member_from_row)
            .collect::<ApiResult<_>>()?,
        projects: projects
            .iter()
            .map(project_from_row)
            .collect::<ApiResult<_>>()?,
        items: items
            .iter()
            .map(|row| item_from_row(row, true))
            .collect::<ApiResult<_>>()?,
        attachments: attachments
            .iter()
            .map(attachment_from_row)
            .collect::<ApiResult<_>>()?,
    }))
}

/// `GET /v1/events`: server-sent events.
///
/// * `ready` once subscribed (sync with `/v1/sync` after it, so nothing
///   committed in between is missed);
/// * `change` with a [`ChangeEvent`] for every committed change in a vault
///   the caller belongs to;
/// * `secret_request` with a [`SecretRequestEvent`] when an agent secret
///   request for this account is created, decided or expired (ADR 0046);
/// * `resync` if the stream fell behind and events were dropped.
///
/// Events carry IDs and revisions only. The stream closes when the access
/// token expires or the session or device is revoked; reconnect with a
/// fresh token. Vault membership is re-checked every `SESSION_CHECK`. It
/// closes at once when the account is deleted (ADR 0037 §5.2).
async fn events(
    State(state): State<AppState>,
    auth: Auth,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let (tx, rx) = mpsc::channel(64);
    let changes = state.subscribe();
    let secret_requests = state.subscribe_secret_requests();
    let deleted = state.subscribe_deleted_accounts();
    tokio::spawn(forward(state, auth, changes, secret_requests, deleted, tx));
    Sse::new(ReceiverStream::new(rx)).keep_alive(KeepAlive::new().interval(KEEP_ALIVE))
}

async fn forward(
    state: AppState,
    auth: Auth,
    mut changes: broadcast::Receiver<crate::state::VaultChange>,
    mut secret_requests: broadcast::Receiver<crate::state::SecretRequestChange>,
    mut deleted: broadcast::Receiver<klav_core::ids::AccountId>,
    tx: mpsc::Sender<Result<Event, Infallible>>,
) {
    let expiry = Duration::from_millis(u64::try_from(auth.expires_at - now_ms()).unwrap_or(0));
    let deadline = tokio::time::sleep(expiry);
    tokio::pin!(deadline);
    let mut check = tokio::time::interval(SESSION_CHECK);
    check.tick().await;
    let mut member_of: HashSet<VaultId> = HashSet::new();
    if tx
        .send(Ok(Event::default().event("ready").data("{}")))
        .await
        .is_err()
    {
        return;
    }
    loop {
        let event = tokio::select! {
            () = &mut deadline => return,
            () = tx.closed() => return,
            gone = deleted.recv() => match gone {
                Ok(account) if account == auth.account_id => return,
                // Another account, or a missed one: the session check
                // below still ends the stream within one period.
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return,
            },
            _ = check.tick() => {
                if !matches!(session::is_active(&state, &auth.session_id).await, Ok(true)) {
                    return;
                }
                // Membership is re-read after every check: a vault the
                // account left (or that was purged) stops sending events
                // within one period instead of for the life of the stream.
                member_of.clear();
                continue;
            }
            sr = secret_requests.recv() => match sr {
                Ok(change) if change.account == auth.account_id => {
                    let payload = SecretRequestEvent {
                        request_id: change.request_id,
                        status: change.status,
                    };
                    match Event::default().event("secret_request").json_data(payload) {
                        Ok(event) => event,
                        Err(_) => continue,
                    }
                }
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => Event::default().event("resync").data("{}"),
                Err(broadcast::error::RecvError::Closed) => return,
            },
            received = changes.recv() => match received {
                Ok(change) => {
                    if !member_of.contains(&change.vault) {
                        if require_member(&state, change.vault, auth.account_id).await.is_err() {
                            continue;
                        }
                        member_of.insert(change.vault);
                    }
                    let payload = ChangeEvent { vault_id: change.vault, revision: change.revision };
                    match Event::default().event("change").json_data(payload) {
                        Ok(event) => event,
                        Err(_) => continue,
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => Event::default().event("resync").data("{}"),
                Err(broadcast::error::RecvError::Closed) => return,
            },
        };
        if tx.send(Ok(event)).await.is_err() {
            return;
        }
    }
}
