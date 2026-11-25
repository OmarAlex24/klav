//! Items: encrypted CRUD with optimistic concurrency, trash and history.
//!
//! The server stores `wrapped_key`, `overview` and `details` exactly as
//! received (after checking their header and size) and returns them
//! byte-for-byte; it cannot decrypt them.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use klav_core::crypto::encoding::Kind;
use klav_core::crypto::{aead, wrap};
use klav_core::ids::{AccountId, AgentId, ItemId, ProjectId, VaultId};
use klav_proto::Blob;
use klav_proto::audit::{ActorKind, AuditEvent};
use klav_proto::vault::{
    CreateItem, Item, ItemHistory, ItemList, ItemQuery, ItemVersion, ItemVersionInfo, TrashFilter,
    UpdateItem,
};
use sqlx::Row;
use sqlx::any::AnyRow;

use crate::audit;
use crate::db::now_ms;
use crate::error::{ApiError, ApiJson, ApiQuery, ApiResult};
use crate::purge;
use crate::session::{Auth, parse_id};
use crate::state::AppState;
use crate::validate;
use crate::vaultdb::{VaultWrite, path_id, require_member, to_i64, to_u64};

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/vaults/{vault_id}/items",
            get(list_items).post(create_item),
        )
        .route(
            "/v1/vaults/{vault_id}/items/{item_id}",
            get(get_item).put(update_item).delete(trash_item),
        )
        .route(
            "/v1/vaults/{vault_id}/items/{item_id}/restore",
            post(restore_item),
        )
        .route(
            "/v1/vaults/{vault_id}/items/{item_id}/purge",
            post(purge_item),
        )
        .route(
            "/v1/vaults/{vault_id}/items/{item_id}/versions",
            get(list_versions).delete(purge_versions),
        )
        .route(
            "/v1/vaults/{vault_id}/items/{item_id}/versions/{version}",
            get(get_version),
        )
}

pub(crate) const ITEM_COLUMNS: &str = "id, vault_id, project_id, version, revision, wrapped_key, \
     overview, details, created_at, updated_at, trashed_at, purged_at, author_agent_id";

/// Builds an [`Item`]; `with_details = false` leaves the details out.
pub(crate) fn item_from_row(row: &AnyRow, with_details: bool) -> ApiResult<Item> {
    let blob = |col: &str| -> ApiResult<Option<Blob>> {
        Ok(row.try_get::<Option<Vec<u8>>, _>(col)?.map(Blob::new))
    };
    Ok(Item {
        id: parse_id(&row.try_get::<String, _>("id")?)?,
        vault_id: parse_id(&row.try_get::<String, _>("vault_id")?)?,
        project_id: parse_id(&row.try_get::<String, _>("project_id")?)?,
        version: to_u64(row.try_get("version")?),
        revision: to_u64(row.try_get("revision")?),
        wrapped_key: blob("wrapped_key")?,
        overview: blob("overview")?,
        details: if with_details { blob("details")? } else { None },
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        trashed_at: row.try_get("trashed_at")?,
        purged_at: row.try_get("purged_at")?,
        author_agent_id: author(row)?,
    })
}

/// The `author_agent_id` column: an agent, or `None` for the person.
fn author(row: &AnyRow) -> ApiResult<Option<AgentId>> {
    row.try_get::<Option<String>, _>("author_agent_id")?
        .map(|id| parse_id(&id))
        .transpose()
}

pub(crate) async fn fetch_item(
    state: &AppState,
    vault_id: VaultId,
    item_id: ItemId,
) -> ApiResult<Item> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {ITEM_COLUMNS} FROM items WHERE id = $1 AND vault_id = $2 AND purged_at IS NULL"
    )))
    .bind(item_id.to_string())
    .bind(vault_id.to_string())
    .fetch_optional(&state.db().pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    item_from_row(&row, true)
}

/// Header and size checks for the three blobs of an item.
fn check_blobs(
    state: &AppState,
    wrapped_key: &Blob,
    overview: &Blob,
    details: &Blob,
) -> ApiResult<()> {
    let limits = &state.config().limits;
    validate::exact(
        wrapped_key,
        Kind::ItemKeyWrap,
        wrap::WRAPPED_KEY_LEN,
        "wrapped_key",
    )?;
    validate::sized(
        overview,
        Kind::ItemOverview,
        aead::OVERHEAD,
        limits.max_overview_bytes,
        "overview",
    )?;
    validate::sized(
        details,
        Kind::ItemDetails,
        aead::OVERHEAD,
        limits.max_details_bytes,
        "details",
    )
}

async fn list_items(
    State(state): State<AppState>,
    auth: Auth,
    Path(vault_id): Path<String>,
    ApiQuery(query): ApiQuery<ItemQuery>,
) -> ApiResult<Json<ItemList>> {
    let vault_id: VaultId = path_id(&vault_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    let trash = match query.trash {
        TrashFilter::Exclude => " AND trashed_at IS NULL",
        TrashFilter::Only => " AND trashed_at IS NOT NULL",
        TrashFilter::Include => "",
    };
    let project = if query.project_id.is_some() {
        " AND project_id = $2"
    } else {
        ""
    };
    let mut q = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {ITEM_COLUMNS} FROM items WHERE vault_id = $1 AND purged_at IS NULL\
         {project}{trash} ORDER BY created_at, id"
    )))
    .bind(vault_id.to_string());
    if let Some(project_id) = query.project_id {
        q = q.bind(project_id.to_string());
    }
    let rows = q.fetch_all(&state.db().pool).await?;
    let items = rows
        .iter()
        .map(|row| item_from_row(row, false))
        .collect::<ApiResult<_>>()?;
    Ok(Json(ItemList { items }))
}

async fn create_item(
    State(state): State<AppState>,
    auth: Auth,
    Path(vault_id): Path<String>,
    ApiJson(req): ApiJson<CreateItem>,
) -> ApiResult<(StatusCode, Json<Item>)> {
    let vault_id: VaultId = path_id(&vault_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    let item = insert_item(&state, vault_id, req, Writer::Person(&auth)).await?;
    Ok((StatusCode::CREATED, Json(item)))
}

/// Who writes an item.
#[derive(Clone, Copy)]
pub(crate) enum Writer<'a> {
    /// An agent of `account`: the item records it as the author (ADR 0030
    /// §7), and the agent's route logs its own event before the write.
    Agent { agent: AgentId, account: AccountId },
    /// The person: their change is logged in its own transaction, see
    /// [`log_item`].
    Person(&'a Auth),
}

impl Writer<'_> {
    fn author(self) -> Option<AgentId> {
        match self {
            Writer::Agent { agent, .. } => Some(agent),
            Writer::Person(_) => None,
        }
    }

    /// Starts the write: the account is locked first, and an agent must
    /// still be active under that lock.
    async fn begin(self, state: &AppState, vault_id: VaultId) -> ApiResult<VaultWrite> {
        match self {
            Writer::Agent { agent, account } => {
                VaultWrite::begin_for_agent(state, vault_id, account, agent).await
            }
            Writer::Person(auth) => {
                VaultWrite::begin_for(state, vault_id, Some(auth.account_id)).await
            }
        }
    }

    /// Logs the person's `action` on the item inside the write, before its
    /// commit. Nothing for an agent.
    async fn log(
        self,
        w: &mut VaultWrite,
        action: &str,
        vault_id: VaultId,
        project_id: ProjectId,
        item_id: ItemId,
    ) -> ApiResult<()> {
        match self {
            Writer::Agent { .. } => Ok(()),
            Writer::Person(auth) => log_item(w, auth, action, vault_id, project_id, item_id).await,
        }
    }
}

/// Logs a change the person made to an item (attested by the server, ADR
/// 0014 §6) in the change's own transaction, which took the account's lock
/// first ([`VaultWrite::begin_for`]): the change is never stored without
/// its event, even if the client goes away before the handler logs it.
async fn log_item(
    w: &mut VaultWrite,
    auth: &Auth,
    action: &str,
    vault_id: VaultId,
    project_id: ProjectId,
    item_id: ItemId,
) -> ApiResult<()> {
    // No `alerts`: they are only for an agent's events.
    let mut event = AuditEvent::new(ActorKind::Person, action);
    event.device_id = Some(auth.device_id);
    event.vault_id = Some(vault_id);
    event.project_id = Some(project_id);
    event.item_id = Some(item_id);
    audit::append_in(&mut w.tx, auth.account_id, &mut event, now_ms()).await
}

/// Creates an item (people and agents; the caller checked access).
pub(crate) async fn insert_item(
    state: &AppState,
    vault_id: VaultId,
    req: CreateItem,
    writer: Writer<'_>,
) -> ApiResult<Item> {
    let state = state.clone();
    if req.version != 1 {
        return Err(ApiError::bad_request("a new item must have version 1"));
    }
    check_blobs(&state, &req.wrapped_key, &req.overview, &req.details)?;
    let mut w = writer.begin(&state, vault_id).await?;
    let project: Option<i64> = sqlx::query_scalar(
        "SELECT version FROM projects WHERE id = $1 AND vault_id = $2 AND deleted_at IS NULL",
    )
    .bind(req.project_id.to_string())
    .bind(vault_id.to_string())
    .fetch_optional(&mut *w.tx)
    .await?;
    let Some(project_version) = project else {
        return Err(ApiError::bad_request(
            "project_id: no such project in this vault",
        ));
    };
    check_project_version(project_version, req.project_version)?;
    // Quotas of the vault's owner (ADR 0048 §3.2). `writer.begin` locked
    // the writer's account, which is the owner: today only the owner is a
    // member, and an agent writes for the account that granted it.
    let owner = crate::quota::owner_of(&mut w.tx, &vault_id.to_string()).await?;
    crate::quota::check(
        &mut w.tx,
        &state.config().limits,
        &owner,
        crate::quota::Delta {
            items: 1,
            vault_bytes: crate::quota::len(req.wrapped_key.as_bytes())
                + crate::quota::len(req.overview.as_bytes())
                + crate::quota::len(req.details.as_bytes()),
            ..Default::default()
        },
    )
    .await?;
    let inserted = sqlx::query(
        "INSERT INTO items (id, vault_id, project_id, version, wrapped_key, overview, details, \
         revision, created_at, updated_at, author_agent_id) \
         VALUES ($1, $2, $3, 1, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT DO NOTHING",
    )
    .bind(req.id.to_string())
    .bind(vault_id.to_string())
    .bind(req.project_id.to_string())
    .bind(req.wrapped_key.into_bytes())
    .bind(req.overview.into_bytes())
    .bind(req.details.into_bytes())
    .bind(w.revision)
    .bind(w.now)
    .bind(w.now)
    .bind(writer.author().map(|a| a.to_string()))
    .execute(&mut *w.tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict("item ID already exists"));
    }
    writer
        .log(&mut w, "item.created", vault_id, req.project_id, req.id)
        .await?;
    let revision = w.commit().await?;
    state.notify(vault_id, revision);
    fetch_item(&state, vault_id, req.id).await
}

async fn get_item(
    State(state): State<AppState>,
    auth: Auth,
    Path((vault_id, item_id)): Path<(String, String)>,
) -> ApiResult<Json<Item>> {
    let vault_id: VaultId = path_id(&vault_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    fetch_item(&state, vault_id, path_id(&item_id)?)
        .await
        .map(Json)
}

/// State of a live (not purged) item, read inside a write.
struct Current {
    version: i64,
    trashed: bool,
    project_id: ProjectId,
    /// Version of its project (the key its item key is wrapped with).
    project_version: i64,
}

async fn current(w: &mut VaultWrite, vault_id: VaultId, item_id: ItemId) -> ApiResult<Current> {
    let row = sqlx::query(
        "SELECT i.version, i.trashed_at, i.project_id, p.version AS project_version FROM items i \
         JOIN projects p ON p.id = i.project_id \
         WHERE i.id = $1 AND i.vault_id = $2 AND i.purged_at IS NULL",
    )
    .bind(item_id.to_string())
    .bind(vault_id.to_string())
    .fetch_optional(&mut *w.tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Current {
        version: row.try_get("version")?,
        trashed: row.try_get::<Option<i64>, _>("trashed_at")?.is_some(),
        project_id: parse_id(&row.try_get::<String, _>("project_id")?)?,
        project_version: row.try_get("project_version")?,
    })
}

/// A write carries the version of the project whose key wrapped its item
/// key. Checked inside the write's transaction, which holds the vault lock
/// a rotation also takes: an item key wrapped with the key a rotation just
/// replaced is refused (409), never stored where the new key cannot open
/// it. No `current_version` in the answer: that one is the item's.
fn check_project_version(current: i64, sent: u64) -> ApiResult<()> {
    if u64::try_from(current).ok() == Some(sent) {
        Ok(())
    } else {
        Err(ApiError::conflict(
            "the project key changed (project_version): sync and wrap the item key again",
        ))
    }
}

/// Writes a new version. `version` must be exactly `current + 1`; anything
/// else is a stale write (409 with the current version). The previous
/// version moves to the history.
async fn update_item(
    State(state): State<AppState>,
    auth: Auth,
    Path((vault_id, item_id)): Path<(String, String)>,
    ApiJson(req): ApiJson<UpdateItem>,
) -> ApiResult<Json<Item>> {
    let vault_id: VaultId = path_id(&vault_id)?;
    let item_id: ItemId = path_id(&item_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    let item = write_version(&state, vault_id, item_id, req, Writer::Person(&auth)).await?;
    Ok(Json(item))
}

/// Writes a new version of an item (people and agents; the caller checked
/// access). The previous version keeps its own author in the history (ADR
/// 0030 §7).
pub(crate) async fn write_version(
    state: &AppState,
    vault_id: VaultId,
    item_id: ItemId,
    req: UpdateItem,
    writer: Writer<'_>,
) -> ApiResult<Item> {
    let state = state.clone();
    check_blobs(&state, &req.wrapped_key, &req.overview, &req.details)?;
    let new_version = to_i64(req.version)?;
    let mut w = writer.begin(&state, vault_id).await?;
    let cur = current(&mut w, vault_id, item_id).await?;
    // A new item key (ADR 0036 §18) is also written to an item in the
    // trash, which stays there: revoking a holder must not leave an item it
    // could open after a restore. Any other write waits for the restore.
    if cur.trashed && req.attachment_keys.is_none() {
        return Err(ApiError::conflict("item is in the trash: restore it first"));
    }
    if new_version != cur.version + 1 {
        return Err(ApiError::stale(cur.version));
    }
    check_project_version(cur.project_version, req.project_version)?;
    let id = item_id.to_string();
    // The vault-data quota (ADR 0048 §3.2) is checked on what the write
    // really adds: the new version, minus the kept versions it drops. The
    // old current version moves to the history and keeps counting, so
    // same-size edits still grow the account until the history is full.
    // Measured before and after, under the owner's lock (see
    // `insert_item`).
    let limits = &state.config().limits;
    let quota_before = if crate::quota::measures_vault_bytes(limits) {
        let owner = crate::quota::owner_of(&mut w.tx, &vault_id.to_string()).await?;
        let before = crate::quota::vault_bytes(&mut w.tx, &owner).await?;
        Some((owner, before))
    } else {
        None
    };
    // A new item key (ADR 0036 §18) brings every attachment key wrapped
    // again with it, or the attachments would stay with the old one.
    if let Some(keys) = &req.attachment_keys {
        rewrap_attachments(&mut w, vault_id, item_id, keys).await?;
    }
    sqlx::query(
        "INSERT INTO item_versions (item_id, version, project_id, wrapped_key, overview, \
         details, created_at, author_agent_id) SELECT id, version, project_id, wrapped_key, \
         overview, details, updated_at, author_agent_id FROM items WHERE id = $1",
    )
    .bind(&id)
    .execute(&mut *w.tx)
    .await?;
    sqlx::query(
        "UPDATE items SET version = $1, wrapped_key = $2, overview = $3, details = $4, \
         revision = $5, updated_at = $6, author_agent_id = $7 WHERE id = $8",
    )
    .bind(new_version)
    .bind(req.wrapped_key.into_bytes())
    .bind(req.overview.into_bytes())
    .bind(req.details.into_bytes())
    .bind(w.revision)
    .bind(w.now)
    .bind(writer.author().map(|a| a.to_string()))
    .bind(&id)
    .execute(&mut *w.tx)
    .await?;
    // Keep at most `max_item_versions` previous versions, and the last one
    // the person wrote: its hosts are the confirmed ones (ADR 0030 §7).
    let keep = i64::from(state.config().limits.max_item_versions);
    sqlx::query(
        "DELETE FROM item_versions WHERE item_id = $1 AND version < $2 \
         AND version <> COALESCE((SELECT MAX(version) FROM item_versions \
         WHERE item_id = $1 AND author_agent_id IS NULL), 0)",
    )
    .bind(&id)
    .bind(new_version - keep)
    .execute(&mut *w.tx)
    .await?;
    if let Some((owner, before)) = quota_before {
        crate::quota::check_growth(&mut w.tx, limits, &owner, before).await?;
    }
    writer
        .log(&mut w, "item.updated", vault_id, cur.project_id, item_id)
        .await?;
    let revision = w.commit().await?;
    state.notify(vault_id, revision);
    fetch_item(&state, vault_id, item_id).await
}

/// Moves an item to the trash (purged after the retention period).
async fn trash_item(
    State(state): State<AppState>,
    auth: Auth,
    Path((vault_id, item_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let vault_id: VaultId = path_id(&vault_id)?;
    let item_id: ItemId = path_id(&item_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    move_to_trash(&state, vault_id, item_id, Writer::Person(&auth)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A new item key (ADR 0036 §18): stores every attachment key wrapped
/// again with it, in the write's transaction. The list must be exactly the
/// completed attachments of the item that are not deleted, so none stays
/// wrapped with the old key. An upload in progress also makes the write
/// fail with `409`: it carries a key wrapped with the old item key, and the
/// client tries again once it finishes (or the cleanup removes it).
async fn rewrap_attachments(
    w: &mut VaultWrite,
    vault_id: VaultId,
    item_id: ItemId,
    keys: &[klav_proto::vault::RewrappedAttachmentKey],
) -> ApiResult<()> {
    for key in keys {
        validate::exact(
            &key.wrapped_key,
            Kind::AttachmentKeyWrap,
            wrap::WRAPPED_KEY_LEN,
            "attachment_keys.wrapped_key",
        )?;
    }
    let uploading: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM attachments \
         WHERE vault_id = $1 AND item_id = $2 AND deleted_at IS NULL AND completed_at IS NULL",
    )
    .bind(vault_id.to_string())
    .bind(item_id.to_string())
    .fetch_one(&mut *w.tx)
    .await?;
    if uploading > 0 {
        return Err(ApiError::conflict(
            "an attachment of this item is still uploading: try again when it finishes",
        ));
    }
    let mut live: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM attachments \
         WHERE vault_id = $1 AND item_id = $2 AND deleted_at IS NULL AND completed_at IS NOT NULL",
    )
    .bind(vault_id.to_string())
    .bind(item_id.to_string())
    .fetch_all(&mut *w.tx)
    .await?;
    let mut sent: Vec<String> = keys.iter().map(|k| k.attachment_id.to_string()).collect();
    live.sort();
    sent.sort();
    if live != sent {
        return Err(ApiError::conflict(
            "attachment_keys must list every attachment of the item once: sync and try again",
        ));
    }
    for key in keys {
        sqlx::query("UPDATE attachments SET wrapped_key = $1, revision = $2 WHERE id = $3")
            .bind(key.wrapped_key.as_bytes().to_vec())
            .bind(w.revision)
            .bind(key.attachment_id.to_string())
            .execute(&mut *w.tx)
            .await?;
    }
    Ok(())
}

/// Moves an item to the trash (people and agents; the caller checked
/// access).
pub(crate) async fn move_to_trash(
    state: &AppState,
    vault_id: VaultId,
    item_id: ItemId,
    writer: Writer<'_>,
) -> ApiResult<()> {
    let mut w = writer.begin(state, vault_id).await?;
    let cur = current(&mut w, vault_id, item_id).await?;
    if cur.trashed {
        return Err(ApiError::conflict("item is already in the trash"));
    }
    sqlx::query("UPDATE items SET trashed_at = $1, revision = $2 WHERE id = $3")
        .bind(w.now)
        .bind(w.revision)
        .bind(item_id.to_string())
        .execute(&mut *w.tx)
        .await?;
    writer
        .log(&mut w, "item.trashed", vault_id, cur.project_id, item_id)
        .await?;
    let revision = w.commit().await?;
    state.notify(vault_id, revision);
    Ok(())
}

async fn restore_item(
    State(state): State<AppState>,
    auth: Auth,
    Path((vault_id, item_id)): Path<(String, String)>,
) -> ApiResult<Json<Item>> {
    let vault_id: VaultId = path_id(&vault_id)?;
    let item_id: ItemId = path_id(&item_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    let mut w = VaultWrite::begin_for(&state, vault_id, Some(auth.account_id)).await?;
    let cur = current(&mut w, vault_id, item_id).await?;
    if !cur.trashed {
        return Err(ApiError::conflict("item is not in the trash"));
    }
    sqlx::query("UPDATE items SET trashed_at = NULL, revision = $1 WHERE id = $2")
        .bind(w.revision)
        .bind(item_id.to_string())
        .execute(&mut *w.tx)
        .await?;
    log_item(
        &mut w,
        &auth,
        "item.restored",
        vault_id,
        cur.project_id,
        item_id,
    )
    .await?;
    let revision = w.commit().await?;
    state.notify(vault_id, revision);
    let item = fetch_item(&state, vault_id, item_id).await?;
    Ok(Json(item))
}

/// Permanently deletes an item that is in the trash.
async fn purge_item(
    State(state): State<AppState>,
    auth: Auth,
    Path((vault_id, item_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let vault_id: VaultId = path_id(&vault_id)?;
    let item_id: ItemId = path_id(&item_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    let mut w = VaultWrite::begin_for(&state, vault_id, Some(auth.account_id)).await?;
    let cur = current(&mut w, vault_id, item_id).await?;
    if !cur.trashed {
        return Err(ApiError::conflict("only items in the trash can be purged"));
    }
    let files = purge::purge_item(&mut w, item_id).await?;
    log_item(
        &mut w,
        &auth,
        "item.purged",
        vault_id,
        cur.project_id,
        item_id,
    )
    .await?;
    let revision = w.commit().await?;
    state.notify(vault_id, revision);
    purge::remove_files(&state, vault_id, &files).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Forgets every stored previous version of an item; the current one
/// stays. A person's client calls it after removing secrets it does not
/// want kept (the generator history, ADR 0022 §2): without it the stored
/// versions would still hold them.
async fn purge_versions(
    State(state): State<AppState>,
    auth: Auth,
    Path((vault_id, item_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let vault_id: VaultId = path_id(&vault_id)?;
    let item_id: ItemId = path_id(&item_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    let mut w = VaultWrite::begin_for(&state, vault_id, Some(auth.account_id)).await?;
    let cur = current(&mut w, vault_id, item_id).await?;
    sqlx::query("DELETE FROM item_versions WHERE item_id = $1")
        .bind(item_id.to_string())
        .execute(&mut *w.tx)
        .await?;
    log_item(
        &mut w,
        &auth,
        "item.versions_purged",
        vault_id,
        cur.project_id,
        item_id,
    )
    .await?;
    let revision = w.commit().await?;
    state.notify(vault_id, revision);
    Ok(StatusCode::NO_CONTENT)
}

async fn list_versions(
    State(state): State<AppState>,
    auth: Auth,
    Path((vault_id, item_id)): Path<(String, String)>,
) -> ApiResult<Json<ItemHistory>> {
    let vault_id: VaultId = path_id(&vault_id)?;
    let item_id: ItemId = path_id(&item_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    let item = fetch_item(&state, vault_id, item_id).await?;
    let rows = sqlx::query(
        "SELECT version, created_at, author_agent_id FROM item_versions WHERE item_id = $1 \
         ORDER BY version DESC",
    )
    .bind(item_id.to_string())
    .fetch_all(&state.db().pool)
    .await?;
    let mut versions = vec![ItemVersionInfo {
        version: item.version,
        created_at: item.updated_at,
        author_agent_id: item.author_agent_id,
    }];
    for row in &rows {
        versions.push(ItemVersionInfo {
            version: to_u64(row.try_get("version")?),
            created_at: row.try_get("created_at")?,
            author_agent_id: author(row)?,
        });
    }
    Ok(Json(ItemHistory { versions }))
}

async fn get_version(
    State(state): State<AppState>,
    auth: Auth,
    Path((vault_id, item_id, version)): Path<(String, String, String)>,
) -> ApiResult<Json<ItemVersion>> {
    let version: u64 = path_id(&version)?;
    let vault_id: VaultId = path_id(&vault_id)?;
    let item_id: ItemId = path_id(&item_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    let item = fetch_item(&state, vault_id, item_id).await?;
    if version == item.version {
        let missing = || ApiError::Internal("live item without blobs".into());
        return Ok(Json(ItemVersion {
            item_id,
            project_id: item.project_id,
            version,
            wrapped_key: item.wrapped_key.ok_or_else(missing)?,
            overview: item.overview.ok_or_else(missing)?,
            details: item.details.ok_or_else(missing)?,
            created_at: item.updated_at,
            author_agent_id: item.author_agent_id,
        }));
    }
    let row = sqlx::query(
        "SELECT project_id, wrapped_key, overview, details, created_at, author_agent_id \
         FROM item_versions WHERE item_id = $1 AND version = $2",
    )
    .bind(item_id.to_string())
    .bind(to_i64(version)?)
    .fetch_optional(&state.db().pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(ItemVersion {
        item_id,
        project_id: parse_id(&row.try_get::<String, _>("project_id")?)?,
        version,
        wrapped_key: Blob::new(row.try_get("wrapped_key")?),
        overview: Blob::new(row.try_get("overview")?),
        details: Blob::new(row.try_get("details")?),
        created_at: row.try_get("created_at")?,
        author_agent_id: author(&row)?,
    }))
}
