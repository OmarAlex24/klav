//! Rotating a project key (ADR 0014 §7): the client re-wraps every item key
//! of the project with a new project key and the server swaps them all in
//! one transaction. Item keys and ciphertexts do not change.

use std::collections::BTreeMap;

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use klav_core::crypto::encoding::Kind;
use klav_core::crypto::wrap;
use klav_core::ids::{ItemId, ProjectId, VaultId};
use klav_proto::Blob;
use klav_proto::audit::{ActorKind, AuditEvent};
use klav_proto::vault::{Project, ProjectKeys, RotateProject, WrappedItemKey};
use sqlx::Row;

use crate::audit;
use crate::db::now_ms;
use crate::error::{ApiError, ApiJson, ApiResult};
use crate::routes::vaults::{check_meta, check_project_key, fetch_project, live_project_version};
use crate::session::{Auth, parse_id};
use crate::state::AppState;
use crate::validate;
use crate::vaultdb::{VaultWrite, path_id, require_owner, to_i64, to_u64};

/// A rotation carries every item key of the project: up to 51 per item
/// (the current row and 50 stored versions).
const MAX_ROTATION_BODY: usize = 64 * 1024 * 1024;

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/vaults/{vault_id}/projects/{project_id}/keys",
            get(keys),
        )
        .route(
            "/v1/vaults/{vault_id}/projects/{project_id}/rotate",
            post(rotate).layer(DefaultBodyLimit::max(MAX_ROTATION_BODY)),
        )
}

/// `(item, version)` → wrapped key; version `None` is the current row.
type KeyMap = BTreeMap<(ItemId, Option<u64>), Vec<u8>>;

async fn load_keys(conn: &mut sqlx::AnyConnection, project_id: ProjectId) -> ApiResult<KeyMap> {
    let mut keys = KeyMap::new();
    let rows = sqlx::query(
        "SELECT id, wrapped_key FROM items WHERE project_id = $1 AND purged_at IS NULL \
         AND wrapped_key IS NOT NULL",
    )
    .bind(project_id.to_string())
    .fetch_all(&mut *conn)
    .await?;
    for row in &rows {
        let id: ItemId = parse_id(&row.try_get::<String, _>("id")?)?;
        keys.insert((id, None), row.try_get("wrapped_key")?);
    }
    let rows = sqlx::query(
        "SELECT item_id, version, wrapped_key FROM item_versions WHERE project_id = $1",
    )
    .bind(project_id.to_string())
    .fetch_all(&mut *conn)
    .await?;
    for row in &rows {
        let id: ItemId = parse_id(&row.try_get::<String, _>("item_id")?)?;
        let version = to_u64(row.try_get("version")?);
        keys.insert((id, Some(version)), row.try_get("wrapped_key")?);
    }
    Ok(keys)
}

/// `GET …/keys`: every item key of the project, wrapped with its key.
async fn keys(
    State(state): State<AppState>,
    auth: Auth,
    Path((vault_id, project_id)): Path<(String, String)>,
) -> ApiResult<Json<ProjectKeys>> {
    let vault_id: VaultId = path_id(&vault_id)?;
    let project_id: ProjectId = path_id(&project_id)?;
    // Only the owner rotates (ADR 0014 §7), so only the owner reads the
    // keys to rotate.
    require_owner(&state, vault_id, auth.account_id).await?;
    let project = fetch_project(&state, vault_id, project_id).await?;
    if project.deleted_at.is_some() {
        return Err(ApiError::NotFound);
    }
    // One transaction: current rows and versions from the same snapshot.
    let mut tx = state.db().pool.begin().await?;
    let map = load_keys(&mut tx, project_id).await?;
    tx.commit().await?;
    Ok(Json(ProjectKeys {
        version: project.version,
        keys: map
            .into_iter()
            .map(|((item_id, version), key)| WrappedItemKey {
                item_id,
                version,
                wrapped_key: Blob::new(key),
            })
            .collect(),
    }))
}

/// `POST …/rotate`: the new project key and every item key re-wrapped.
async fn rotate(
    State(state): State<AppState>,
    auth: Auth,
    Path((vault_id, project_id)): Path<(String, String)>,
    ApiJson(req): ApiJson<RotateProject>,
) -> ApiResult<Json<Project>> {
    let vault_id: VaultId = path_id(&vault_id)?;
    let project_id: ProjectId = path_id(&project_id)?;
    // Hardening: today every member of a vault is its owner (no sharing
    // with people yet), but rotating replaces the key every member and
    // agent uses, so it is the owner's call.
    require_owner(&state, vault_id, auth.account_id).await?;
    check_project_key(&req.wrapped_key)?;
    check_meta(&state, &req.meta)?;
    let mut submitted = KeyMap::new();
    for key in req.keys {
        validate::exact(
            &key.wrapped_key,
            Kind::ItemKeyWrap,
            wrap::WRAPPED_KEY_LEN,
            "keys.wrapped_key",
        )?;
        if submitted
            .insert((key.item_id, key.version), key.wrapped_key.into_bytes())
            .is_some()
        {
            return Err(ApiError::bad_request("a key is listed twice"));
        }
    }
    let new_version = to_i64(req.version)?;
    // The account's lock first, then the vault's: the rotation logs its
    // event in its own transaction, as every person's vault write does.
    let mut w = VaultWrite::begin_for(&state, vault_id, Some(auth.account_id)).await?;
    let current = live_project_version(&mut w, vault_id, project_id).await?;
    if new_version != current + 1 {
        return Err(ApiError::stale(current));
    }
    // The caller is the owner (`require_owner`), whose lock `begin_for`
    // took first.
    super::vaults::check_project_meta_growth(
        &state,
        &mut w,
        &auth.account_id.to_string(),
        project_id,
        &req.meta,
    )
    .await?;
    let stored = load_keys(&mut w.tx, project_id).await?;
    if !stored.keys().eq(submitted.keys()) {
        return Err(ApiError::conflict(
            "the project changed while rotating its key: try again",
        ));
    }
    sqlx::query(
        "UPDATE projects SET version = $1, wrapped_key = $2, meta = $3, revision = $4, \
         updated_at = $5 WHERE id = $6",
    )
    .bind(new_version)
    .bind(req.wrapped_key.into_bytes())
    .bind(req.meta.into_bytes())
    .bind(w.revision)
    .bind(w.now)
    .bind(project_id.to_string())
    .execute(&mut *w.tx)
    .await?;
    let items = submitted.keys().filter(|(_, v)| v.is_none()).count();
    for ((item_id, version), key) in submitted {
        match version {
            // A new revision makes every device fetch the new wrapped key.
            None => {
                sqlx::query("UPDATE items SET wrapped_key = $1, revision = $2 WHERE id = $3")
                    .bind(key)
                    .bind(w.revision)
                    .bind(item_id.to_string())
                    .execute(&mut *w.tx)
                    .await?
            }
            Some(v) => {
                sqlx::query(
                    "UPDATE item_versions SET wrapped_key = $1 WHERE item_id = $2 AND version = $3",
                )
                .bind(key)
                .bind(item_id.to_string())
                .bind(to_i64(v)?)
                .execute(&mut *w.tx)
                .await?
            }
        };
    }
    // Logged in the owner's chain (`require_owner` made the caller the
    // owner), in the rotation's own transaction: the new key is never
    // stored without its event, even if the client goes away.
    let mut event = AuditEvent::new(ActorKind::Person, "project.rotated");
    event.device_id = Some(auth.device_id);
    event.vault_id = Some(vault_id);
    event.project_id = Some(project_id);
    event.outcome = Some(format!("{items} items"));
    // No `alerts`: they are only for an agent's access events. Stamped
    // when it is logged, as `audit::append` does.
    audit::append_in(&mut w.tx, auth.account_id, &mut event, now_ms()).await?;
    let revision = w.commit().await?;
    state.notify(vault_id, revision);
    fetch_project(&state, vault_id, project_id).await.map(Json)
}
