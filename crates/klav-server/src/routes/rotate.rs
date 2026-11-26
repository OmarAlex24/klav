//! Assisted password changes (ADR 0022 §5), the server's half. An agent
//! marks the start of one item's change (`rotate_password`), and later its
//! confirmation or cancellation (`rotate_confirm`, `rotate_cancel`).
//!
//! `rotate` only exists inside a task (ADR 0021 §5): every step goes
//! through [`gate`](crate::routes::agent_access) like any agent action,
//! needs a live task that covers `rotate` on the item and the change
//! page's host, and logs `rotate.started`, `rotate.confirmed` or
//! `rotate.cancelled` under that task, with the item and the host. No
//! password goes through here: the person's `klavd` generates the new one,
//! stores it as pending in the item's sealed record and fills the form.
//!
//! One change per item at a time. A change left started when its task
//! ended is marked `abandoned` the next time a change of that item starts;
//! the pending password stays in the item for the person to resolve
//! (T100).
//!
//! The person closes a change too (`/v1/rotations/{id}/confirm` and
//! `/cancel`): when they decide from the item's «Cambio pendiente» card,
//! their `klavd` records it here, under the person, so an agent's later
//! step finds the change closed and nothing false gets logged.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use klav_core::ids::{ItemId, RotationId, TaskId};
use klav_core::policy::{Permission, normalize_host};
use klav_proto::agent::Claims;
use klav_proto::audit::{ActorKind, AuditEvent};
use klav_proto::rotate::{
    AgentRotateFinish, AgentRotateStart, RotationInfo, RotationStarted, RotationStatus,
};
use klav_proto::task::TaskStatus;
use sqlx::Row;
use sqlx::any::AnyRow;

use crate::agentauth::AgentAuth;
use crate::audit;
use crate::db::now_ms;
use crate::error::{ApiError, ApiResult};
use crate::routes::agent_access::{Action, Gate, check_reason, checked, granted_item, load_grant};
use crate::routes::tasks::agent_task_info;
use crate::session::{Auth, parse_id};
use crate::state::AppState;
use crate::vaultdb::path_id;

const ROTATION_COLUMNS: &str =
    "id, task_id, vault_id, project_id, item_id, host, status, started_at, finished_at";

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/agent/rotations", post(start))
        .route("/v1/agent/rotations/{rotation_id}/confirm", post(confirm))
        .route("/v1/agent/rotations/{rotation_id}/cancel", post(cancel))
        .route("/v1/rotations/{rotation_id}/confirm", post(person_confirm))
        .route("/v1/rotations/{rotation_id}/cancel", post(person_cancel))
}

fn rotation_from_row(row: &AnyRow) -> ApiResult<RotationInfo> {
    let status: String = row.try_get("status")?;
    Ok(RotationInfo {
        id: parse_id(&row.try_get::<String, _>("id")?)?,
        task_id: parse_id(&row.try_get::<String, _>("task_id")?)?,
        vault_id: parse_id(&row.try_get::<String, _>("vault_id")?)?,
        project_id: parse_id(&row.try_get::<String, _>("project_id")?)?,
        item_id: parse_id(&row.try_get::<String, _>("item_id")?)?,
        host: row.try_get("host")?,
        status: RotationStatus::parse(&status)
            .ok_or_else(|| ApiError::Internal("corrupt rotation status".into()))?,
        started_at: row.try_get("started_at")?,
        finished_at: row.try_get("finished_at")?,
    })
}

async fn fetch(state: &AppState, auth: &AgentAuth, id: RotationId) -> ApiResult<RotationInfo> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {ROTATION_COLUMNS} FROM rotations WHERE id = $1 AND agent_id = $2"
    )))
    .bind(id.to_string())
    .bind(auth.agent_id.to_string())
    .fetch_optional(&state.db().pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    rotation_from_row(&row)
}

/// Marks as abandoned the started changes of `item` whose task is no
/// longer running (ended, expired or revoked).
async fn abandon_stale(state: &AppState, item: ItemId, now: i64) -> ApiResult<()> {
    sqlx::query(
        "UPDATE rotations SET status = $1, finished_at = $2 \
         WHERE item_id = $3 AND status = $4 AND task_id NOT IN \
         (SELECT id FROM tasks WHERE status = $5 AND expires_at > $6)",
    )
    .bind(RotationStatus::Abandoned.as_str())
    .bind(now)
    .bind(item.to_string())
    .bind(RotationStatus::Started.as_str())
    .bind(TaskStatus::Approved.as_str())
    .bind(now)
    .execute(&state.db().pool)
    .await?;
    Ok(())
}

fn in_progress(id: &str) -> ApiError {
    ApiError::conflict(format!(
        "a password change of this item is already in progress (pending_id {id}): confirm or cancel it first"
    ))
}

/// The step whose row [`agent_write`] writes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    /// `rotate_password`: the change's row is inserted.
    Start,
    /// `rotate_confirm` or `rotate_cancel`: the row is closed.
    Finish,
}

/// The transaction of the agent's own write to `rotations`, after its
/// event was logged in another: the account's lock first, then the
/// agent's status under it ([`crate::agentauth::still_active`],
/// `403 forbidden`), so a revocation committed since the event was logged
/// is seen and nothing is written after it.
///
/// A start also checks, as `audit::append_in` does, a deletion request
/// (`403 account_deleting`) and a pause (`403 agents_paused`) committed
/// since its event: nothing has been generated or filled yet, so refusing
/// it strands nothing.
///
/// A finish does not: an older client's `klavd` has already settled the
/// item before the finish reaches the server (the new password became
/// current, or went to the history), and the finish's event is logged, so
/// refusing the row's update for a pause or a deletion request would
/// strand a change nobody can close. The item has nothing pending, so the
/// person has no card to close it from, and a pause does not end the
/// task, so a new start gets `409` until the task ends. (A current client
/// sends the step here first and to `klavd` only after this answers.) A
/// finish refused here for a revocation leaves the row `started`; after
/// an older client the item has nothing pending, as above, and the
/// revocation ended the agent's tasks in its own transaction, so
/// [`abandon_stale`] marks the row `abandoned` at the item's next start.
async fn agent_write(
    state: &AppState,
    auth: &AgentAuth,
    step: Step,
) -> ApiResult<sqlx::Transaction<'static, sqlx::Any>> {
    let mut tx = state.db().pool.begin().await?;
    crate::deletion::lock_account(&mut tx, auth.account_id).await?;
    let now = now_ms();
    crate::agentauth::still_active(&mut *tx, auth.agent_id, auth.account_id, now).await?;
    if step == Step::Start {
        crate::deletion::refuse_if_deleting(&mut *tx, auth.account_id).await?;
        crate::pause::refuse_if_paused(&mut *tx, auth.account_id, auth.agent_id, now).await?;
    }
    Ok(tx)
}

/// `POST /v1/agent/rotations`: `rotate_password` (ADR 0022 §5, step 2).
async fn start(
    State(state): State<AppState>,
    auth: AgentAuth,
) -> ApiResult<(StatusCode, Json<RotationStarted>)> {
    let req: AgentRotateStart = auth.logged_json()?;
    // Only tags are taken from what the agent claims; a method or a path
    // (proxy only) is refused like on every other route, before anything
    // is read or written (before ADR 0036 this body was a 400 at parse
    // time).
    crate::routes::agent_access::check_http_claims(Permission::Rotate, &req.claims)?;
    let reason = check_reason(&req.reason)?;
    let host = req
        .claims
        .domain
        .as_deref()
        .and_then(normalize_host)
        .ok_or_else(|| {
            ApiError::bad_request(
                "claims.domain is mandatory: the host of the site's password change page",
            )
        })?;
    let grant = load_grant(&state, &auth).await?;
    let item = granted_item(&state, &grant, req.item_id).await?;
    let now = now_ms();
    abandon_stale(&state, item.id, now).await?;
    let running: Option<String> =
        sqlx::query_scalar("SELECT id FROM rotations WHERE item_id = $1 AND status = $2")
            .bind(item.id.to_string())
            .bind(RotationStatus::Started.as_str())
            .fetch_optional(&state.db().pool)
            .await?;
    if let Some(id) = running {
        return Err(in_progress(&id));
    }
    let claims = Claims {
        tags: req.claims.tags.clone(),
        domain: Some(host.clone()),
        ..Claims::default()
    };
    let action = Action {
        permission: Permission::Rotate,
        vault: item.vault_id,
        project: item.project_id,
        item: Some(item.id),
        claims: &claims,
        reason: &reason,
        attachments: &[],
        sandbox: None,
        local_client: None,
        items: &[],
    };
    let task = match checked(
        &state,
        &auth,
        &grant,
        &action,
        "rotate.started",
        None,
        req.task_id,
        false,
    )
    .await?
    {
        Gate::Allow {
            task: Some(task), ..
        } => task,
        // `rotate` is never asked for one by one: only a task lets it pass.
        _ => return Err(ApiError::Internal("rotate passed without a task".into())),
    };
    let id = RotationId::generate();
    let mut tx = agent_write(&state, &auth, Step::Start).await?;
    let inserted = sqlx::query(
        "INSERT INTO rotations (id, account_id, agent_id, task_id, vault_id, project_id, \
         item_id, host, status, started_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(id.to_string())
    .bind(auth.account_id.to_string())
    .bind(auth.agent_id.to_string())
    .bind(task.to_string())
    .bind(item.vault_id.to_string())
    .bind(item.project_id.to_string())
    .bind(item.id.to_string())
    .bind(&host)
    .bind(RotationStatus::Started.as_str())
    .bind(now)
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => tx.commit().await?,
        // A concurrent start of the same item won.
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(in_progress("unknown"));
        }
        Err(e) => return Err(e.into()),
    }
    Ok((
        StatusCode::CREATED,
        Json(RotationStarted {
            rotation: fetch(&state, &auth, id).await?,
            task: agent_task_info(&state, auth.agent_id, task).await?,
        }),
    ))
}

/// Confirms or cancels a started change, under the same task and host.
async fn finish(
    state: &AppState,
    auth: &AgentAuth,
    rotation_id: &str,
    to: RotationStatus,
) -> ApiResult<Json<RotationInfo>> {
    let id: RotationId = path_id(rotation_id)?;
    let req: AgentRotateFinish = auth.logged_json()?;
    let reason = check_reason(&req.reason)?;
    let rotation = fetch(state, auth, id).await?;
    if rotation.item_id != req.item_id {
        return Err(ApiError::bad_request(
            "item_id is not the item of this password change",
        ));
    }
    if rotation.status != RotationStatus::Started {
        return Err(ApiError::conflict(format!(
            "the password change is already {}",
            rotation.status.as_str()
        )));
    }
    // A deleted vault is out of reach until restored (layer 07), like the
    // start's `granted_item`.
    let live: Option<String> =
        sqlx::query_scalar("SELECT id FROM vaults WHERE id = $1 AND deleted_at IS NULL")
            .bind(rotation.vault_id.to_string())
            .fetch_optional(&state.db().pool)
            .await?;
    if live.is_none() {
        return Err(ApiError::NotFound);
    }
    let grant = load_grant(state, auth).await?;
    let claims = Claims {
        tags: Vec::new(),
        domain: Some(rotation.host.clone()),
        ..Claims::default()
    };
    let action = Action {
        permission: Permission::Rotate,
        vault: rotation.vault_id,
        project: rotation.project_id,
        item: Some(rotation.item_id),
        claims: &claims,
        reason: &reason,
        attachments: &[],
        sandbox: None,
        local_client: None,
        items: &[],
    };
    let kind = match to {
        RotationStatus::Confirmed => "rotate.confirmed",
        _ => "rotate.cancelled",
    };
    let only: Option<TaskId> = Some(rotation.task_id);
    if !matches!(
        checked(state, auth, &grant, &action, kind, None, only, false).await?,
        Gate::Allow { task: Some(_), .. }
    ) {
        return Err(ApiError::Internal("rotate passed without a task".into()));
    }
    let mut tx = agent_write(state, auth, Step::Finish).await?;
    let updated = sqlx::query(
        "UPDATE rotations SET status = $1, finished_at = $2 WHERE id = $3 AND status = $4",
    )
    .bind(to.as_str())
    .bind(now_ms())
    .bind(id.to_string())
    .bind(RotationStatus::Started.as_str())
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "the password change was confirmed or cancelled meanwhile",
        ));
    }
    tx.commit().await?;
    fetch(state, auth, id).await.map(Json)
}

/// `POST /v1/agent/rotations/{id}/confirm`: `rotate_confirm` (step 7).
async fn confirm(
    State(state): State<AppState>,
    Path(rotation_id): Path<String>,
    auth: AgentAuth,
) -> ApiResult<Json<RotationInfo>> {
    finish(&state, &auth, &rotation_id, RotationStatus::Confirmed).await
}

/// `POST /v1/agent/rotations/{id}/cancel`: `rotate_cancel`.
async fn cancel(
    State(state): State<AppState>,
    Path(rotation_id): Path<String>,
    auth: AgentAuth,
) -> ApiResult<Json<RotationInfo>> {
    finish(&state, &auth, &rotation_id, RotationStatus::Cancelled).await
}

// --------------------------------------------------------------- person --

/// The person settles a started change from the item's card (ADR 0022 §5):
/// «Usar la nueva» confirms it, «Mantener la actual» cancels it. Logged
/// under the person; the agent's later step then gets a `409`.
async fn person_finish(
    state: &AppState,
    auth: &Auth,
    rotation_id: &str,
    to: RotationStatus,
) -> ApiResult<Json<RotationInfo>> {
    let id: RotationId = path_id(rotation_id)?;
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {ROTATION_COLUMNS}, agent_id FROM rotations WHERE id = $1 AND account_id = $2"
    )))
    .bind(id.to_string())
    .bind(auth.account_id.to_string())
    .fetch_optional(&state.db().pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let rotation = rotation_from_row(&row)?;
    let agent = parse_id(&row.try_get::<String, _>("agent_id")?)?;
    if rotation.status != RotationStatus::Started {
        return Err(ApiError::conflict(format!(
            "the password change is already {}",
            rotation.status.as_str()
        )));
    }
    let now = now_ms();
    // The step and its event in one transaction, under the account's lock
    // first as every transaction that logs in itself takes it: the change
    // is never settled without its event, even if the client goes away.
    let mut tx = state.db().pool.begin().await?;
    crate::deletion::lock_account(&mut tx, auth.account_id).await?;
    let updated = sqlx::query(
        "UPDATE rotations SET status = $1, finished_at = $2 WHERE id = $3 AND status = $4",
    )
    .bind(to.as_str())
    .bind(now)
    .bind(id.to_string())
    .bind(RotationStatus::Started.as_str())
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "the password change was confirmed or cancelled meanwhile",
        ));
    }
    let mut event = AuditEvent::new(
        ActorKind::Person,
        match to {
            RotationStatus::Confirmed => "rotate.confirmed",
            _ => "rotate.cancelled",
        },
    );
    event.device_id = Some(auth.device_id);
    event.agent_id = Some(agent);
    event.task_id = Some(rotation.task_id);
    event.vault_id = Some(rotation.vault_id);
    event.project_id = Some(rotation.project_id);
    event.item_id = Some(rotation.item_id);
    event.domain = Some(rotation.host.clone());
    // No `alerts`: they are only for an agent's access events. Stamped
    // when it is logged, as `audit::append` does.
    audit::append_in(&mut tx, auth.account_id, &mut event, now_ms()).await?;
    tx.commit().await?;
    Ok(Json(RotationInfo {
        status: to,
        finished_at: Some(now),
        ..rotation
    }))
}

/// `POST /v1/rotations/{id}/confirm`: the person used the new password.
async fn person_confirm(
    State(state): State<AppState>,
    auth: Auth,
    Path(rotation_id): Path<String>,
) -> ApiResult<Json<RotationInfo>> {
    person_finish(&state, &auth, &rotation_id, RotationStatus::Confirmed).await
}

/// `POST /v1/rotations/{id}/cancel`: the person kept the current password.
async fn person_cancel(
    State(state): State<AppState>,
    auth: Auth,
    Path(rotation_id): Path<String>,
) -> ApiResult<Json<RotationInfo>> {
    person_finish(&state, &auth, &rotation_id, RotationStatus::Cancelled).await
}
