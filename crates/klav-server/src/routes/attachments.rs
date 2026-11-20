//! Encrypted attachments: resumable chunked upload, ranged download.
//!
//! 1. `POST …/items/{item_id}/attachments` declares the attachment (ID,
//!    exact ciphertext size, wrapped key).
//! 2. `PUT …/attachments/{id}/content?offset=N` appends one chunk; `offset`
//!    must equal the bytes received so far, so an interrupted upload resumes
//!    from `GET …/attachments/{id}` → `received`.
//! 3. `POST …/attachments/{id}/complete` publishes it (new vault revision).
//!
//! The server checks the STREAM header bytes (`0x01 0x30`) of the first
//! chunk and the declared size; it cannot decrypt anything.

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use klav_core::crypto::attachment::{HEADER_LEN, TAG_LEN};
use klav_core::crypto::encoding::Kind;
use klav_core::crypto::wrap;
use klav_core::ids::{AttachmentId, ItemId, VaultId};
use klav_proto::Blob;
use klav_proto::sync::{Attachment, CreateAttachment, UploadProgress, UploadQuery};
use sqlx::Row;
use sqlx::any::AnyRow;
use tower::ServiceExt;
use tower_http::services::ServeFile;

use crate::db::now_ms;
use crate::error::{ApiError, ApiJson, ApiQuery, ApiResult};
use crate::session::{Auth, parse_id};
use crate::state::AppState;
use crate::storage::UploadGuard;
use crate::validate;
use crate::vaultdb::{VaultWrite, path_id, require_member, to_i64, to_u64};

/// Smallest valid ciphertext: STREAM header plus one (empty) final block.
const MIN_SIZE: u64 = (HEADER_LEN + TAG_LEN) as u64;

pub(super) fn router(max_chunk: usize) -> Router<AppState> {
    Router::new()
        .route(
            "/v1/vaults/{vault_id}/items/{item_id}/attachments",
            post(create),
        )
        .route(
            "/v1/vaults/{vault_id}/attachments/{attachment_id}",
            get(get_meta).delete(delete),
        )
        .route(
            "/v1/vaults/{vault_id}/attachments/{attachment_id}/content",
            put(upload_chunk)
                .layer(DefaultBodyLimit::max(max_chunk))
                .get(download),
        )
        .route(
            "/v1/vaults/{vault_id}/attachments/{attachment_id}/complete",
            post(complete),
        )
}

pub(crate) const ATTACHMENT_COLUMNS: &str = "id, vault_id, item_id, size, received, wrapped_key, \
     revision, created_at, completed_at, deleted_at";

pub(crate) fn attachment_from_row(row: &AnyRow) -> ApiResult<Attachment> {
    Ok(Attachment {
        id: parse_id(&row.try_get::<String, _>("id")?)?,
        vault_id: parse_id(&row.try_get::<String, _>("vault_id")?)?,
        item_id: parse_id(&row.try_get::<String, _>("item_id")?)?,
        size: to_u64(row.try_get("size")?),
        received: to_u64(row.try_get("received")?),
        wrapped_key: row
            .try_get::<Option<Vec<u8>>, _>("wrapped_key")?
            .map(Blob::new),
        revision: to_u64(row.try_get("revision")?),
        created_at: row.try_get("created_at")?,
        completed_at: row.try_get("completed_at")?,
        deleted_at: row.try_get("deleted_at")?,
    })
}

async fn fetch(state: &AppState, vault_id: VaultId, id: AttachmentId) -> ApiResult<Attachment> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {ATTACHMENT_COLUMNS} FROM attachments \
         WHERE id = $1 AND vault_id = $2 AND deleted_at IS NULL"
    )))
    .bind(id.to_string())
    .bind(vault_id.to_string())
    .fetch_optional(&state.db().pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    attachment_from_row(&row)
}

/// [`fetch`], only while its vault is not deleted either.
async fn fetch_live(
    state: &AppState,
    vault_id: VaultId,
    id: AttachmentId,
) -> ApiResult<Attachment> {
    let live: Option<String> =
        sqlx::query_scalar("SELECT id FROM vaults WHERE id = $1 AND deleted_at IS NULL")
            .bind(vault_id.to_string())
            .fetch_optional(&state.db().pool)
            .await?;
    live.ok_or(ApiError::NotFound)?;
    fetch(state, vault_id, id).await
}

fn ids(vault_id: &str, attachment_id: &str) -> ApiResult<(VaultId, AttachmentId)> {
    Ok((path_id(vault_id)?, path_id(attachment_id)?))
}

async fn create(
    State(state): State<AppState>,
    auth: Auth,
    Path((vault_id, item_id)): Path<(String, String)>,
    ApiJson(req): ApiJson<CreateAttachment>,
) -> ApiResult<(StatusCode, Json<Attachment>)> {
    let vault_id: VaultId = path_id(&vault_id)?;
    let item_id: ItemId = path_id(&item_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    validate::exact(
        &req.wrapped_key,
        Kind::AttachmentKeyWrap,
        wrap::WRAPPED_KEY_LEN,
        "wrapped_key",
    )?;
    if req.size < MIN_SIZE || req.size > state.config().limits.max_attachment_bytes {
        return Err(ApiError::bad_request(format!(
            "size must be between {MIN_SIZE} and {} bytes",
            state.config().limits.max_attachment_bytes
        )));
    }
    let size = to_i64(req.size)?;
    // One transaction under the vault owner's lock (layer 07 of the 2026-11
    // round): the vault must be live, and the unfinished uploads of all the
    // owner's vaults stay under `max_pending_upload_bytes` even when many
    // are declared at once. The owner pays: there is no uploader column,
    // and today only the owner is a member.
    let mut tx = state.db().pool.begin().await?;
    // The lock first (a write, so the SQLite transaction never has to
    // upgrade from reading), on the owner of the live vault.
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
    let owner: String = sqlx::query_scalar("SELECT owner_account_id FROM vaults WHERE id = $1")
        .bind(vault_id.to_string())
        .fetch_one(&mut *tx)
        .await?;
    // The version the client saw (its key wrapped the attachment key): read
    // under the vault's lock, which every vault write (a new item key among
    // them) holds until it commits. Either this upload is declared first,
    // and the new key finds it in progress (`409`), or the new key commits
    // first, and this request sees a newer version (`409`). Taken after the
    // account's lock: every vault write that also locks the account (account
    // deletion, a person's item changes, an agent's) takes the account's
    // first. Without `item_version`, as before.
    if req.item_version.is_some() {
        sqlx::query("UPDATE vaults SET revision = revision WHERE id = $1")
            .bind(vault_id.to_string())
            .execute(&mut *tx)
            .await?;
    }
    let item: Option<(Option<i64>, i64)> = sqlx::query_as(
        "SELECT trashed_at, version FROM items WHERE id = $1 AND vault_id = $2 AND purged_at IS NULL",
    )
    .bind(item_id.to_string())
    .bind(vault_id.to_string())
    .fetch_optional(&mut *tx)
    .await?;
    match item {
        None => return Err(ApiError::NotFound),
        Some((Some(_), _)) => return Err(ApiError::conflict("item is in the trash")),
        Some((None, version)) => {
            if let Some(seen) = req.item_version
                && to_i64(seen)? != version
            {
                return Err(ApiError::Conflict {
                    message: "the item changed since this device read it (it may have a new key): sync and try again".into(),
                    current_version: Some(to_u64(version)),
                });
            }
        }
    }
    // Postgres sums BIGINT into NUMERIC, which `sqlx::Any` cannot decode.
    let pending: i64 = sqlx::query_scalar(
        "SELECT CAST(COALESCE(SUM(a.size), 0) AS BIGINT) \
         FROM attachments a JOIN vaults v ON v.id = a.vault_id \
         WHERE v.owner_account_id = $1 AND a.completed_at IS NULL AND a.deleted_at IS NULL",
    )
    .bind(&owner)
    .fetch_one(&mut *tx)
    .await?;
    let limit = state.config().limits.max_pending_upload_bytes;
    if to_u64(pending).saturating_add(req.size) > limit {
        return Err(ApiError::conflict(format!(
            "too many unfinished uploads ({limit} bytes at most): finish or wait for them"
        )));
    }
    let now = now_ms();
    let inserted = sqlx::query(
        "INSERT INTO attachments (id, vault_id, item_id, size, received, wrapped_key, revision, \
         created_at, updated_at) VALUES ($1, $2, $3, $4, 0, $5, 0, $6, $7) ON CONFLICT DO NOTHING",
    )
    .bind(req.id.to_string())
    .bind(vault_id.to_string())
    .bind(item_id.to_string())
    .bind(size)
    .bind(req.wrapped_key.into_bytes())
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict("attachment ID already exists"));
    }
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(fetch(&state, vault_id, req.id).await?),
    ))
}

async fn get_meta(
    State(state): State<AppState>,
    auth: Auth,
    Path((vault_id, attachment_id)): Path<(String, String)>,
) -> ApiResult<Json<Attachment>> {
    let (vault_id, id) = ids(&vault_id, &attachment_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    fetch(&state, vault_id, id).await.map(Json)
}

async fn upload_chunk(
    State(state): State<AppState>,
    auth: Auth,
    Path((vault_id, attachment_id)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<UploadQuery>,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> ApiResult<Json<UploadProgress>> {
    let (vault_id, id) = ids(&vault_id, &attachment_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    let chunk = body.map_err(|e| {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::PayloadTooLarge
        } else {
            ApiError::bad_request("invalid body")
        }
    })?;
    let store = state.attachments();
    let guard = store
        .lock(id)
        .ok_or_else(|| ApiError::conflict("another upload of this attachment is in progress"))?;
    // Read under the guard: a delete or a purge that committed before it
    // was taken is seen here, and one that commits later waits for it.
    let meta = fetch_live(&state, vault_id, id).await?;
    if meta.completed_at.is_some() {
        return Err(ApiError::conflict("upload already completed"));
    }
    let received = store.received(vault_id, id).await?;
    if query.offset != received {
        return Err(ApiError::Conflict {
            message: format!("offset must be {received}"),
            current_version: None,
        });
    }
    let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
    if chunk.is_empty() || received.saturating_add(chunk_len) > meta.size {
        return Err(ApiError::bad_request("chunk exceeds the declared size"));
    }
    if received == 0 && chunk.get(..2) != Some(&Kind::Attachment.header()[..]) {
        return Err(ApiError::bad_request(
            "content: not an encrypted attachment (expected header 0x01 0x30)",
        ));
    }
    store.append(&guard, vault_id, id, &chunk).await?;
    let received = received + chunk_len;
    sqlx::query(
        "UPDATE attachments SET received = $1, updated_at = $2 \
         WHERE id = $3 AND completed_at IS NULL AND deleted_at IS NULL",
    )
    .bind(to_i64(received)?)
    .bind(now_ms())
    .bind(id.to_string())
    .execute(&state.db().pool)
    .await?;
    Ok(Json(UploadProgress {
        received,
        size: meta.size,
    }))
}

async fn complete(
    State(state): State<AppState>,
    auth: Auth,
    Path((vault_id, attachment_id)): Path<(String, String)>,
) -> ApiResult<Json<Attachment>> {
    let (vault_id, id) = ids(&vault_id, &attachment_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    let store = state.attachments();
    let guard = store
        .lock(id)
        .ok_or_else(|| ApiError::conflict("an upload of this attachment is in progress"))?;
    let meta = fetch(&state, vault_id, id).await?;
    if meta.completed_at.is_some() {
        return Ok(Json(meta));
    }
    let received = store.received(vault_id, id).await?;
    if received != meta.size {
        return Err(ApiError::conflict(format!(
            "upload incomplete: {received} of {} bytes",
            meta.size
        )));
    }
    let mut w = VaultWrite::begin(&state, vault_id).await?;
    let updated = sqlx::query(
        "UPDATE attachments SET completed_at = $1, revision = $2 \
         WHERE id = $3 AND completed_at IS NULL AND deleted_at IS NULL",
    )
    .bind(w.now)
    .bind(w.revision)
    .bind(id.to_string())
    .execute(&mut *w.tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::conflict("attachment changed during completion"));
    }
    // From the move to the commit, in a task of its own that this handler
    // awaits: when the client goes away, hyper drops the handler mid-await,
    // and a move without its commit (or its undo) would leave the file
    // under its final name with the row still pending, which the orphan
    // sweep deletes. The task runs to its end either way and holds the
    // upload's guard until the file and the row agree, and while it reads
    // the answer.
    let completed = tokio::spawn(publish(state.clone(), guard, w, vault_id, id))
        .await
        .map_err(|e| ApiError::Internal(format!("completion task: {e}")))??;
    Ok(Json(completed))
}

/// How long [`committed`] waits before it reads a row a second time.
const REREAD_PAUSE: std::time::Duration = std::time::Duration::from_secs(1);

/// Moves a fully uploaded attachment into place, commits `w`, which marks
/// its row completed, and reads the completed attachment, all under the
/// upload's guard (a delete right after waits for the answer, as it did
/// when the handler held the guard). The file moves first: if that fails
/// the transaction rolls back and the upload can be completed again.
async fn publish(
    state: AppState,
    guard: UploadGuard,
    w: VaultWrite,
    vault_id: VaultId,
    id: AttachmentId,
) -> ApiResult<Attachment> {
    let store = state.attachments();
    store.finish(&guard, vault_id, id).await?;
    let revision = to_u64(w.revision);
    match w.commit().await {
        Ok(revision) => {
            state.notify(vault_id, revision);
            fetch(&state, vault_id, id).await
        }
        Err(e) => {
            // Logged here: if the client went away, nobody reads this
            // task's answer, and the failure would leave no trace.
            if let ApiError::Internal(why) = &e {
                tracing::error!(attachment = %id, error = %why, "a completion's commit failed");
            }
            // A commit can fail after the database applied it (the
            // connection broke before the answer), so the row says which.
            match committed(&state, vault_id, id).await {
                // The write landed: the file stays where its row needs it,
                // and the vault's other devices hear of the new revision.
                // The answer stays the commit's error, as before.
                Some(true) => state.notify(vault_id, revision),
                // It did not: the file goes back, so a retry finds the
                // upload as it was.
                Some(false) => {
                    if let Err(undo) = store.unfinish(&guard, vault_id, id).await {
                        tracing::error!(attachment = %id, error = %undo, "cannot undo a failed completion");
                    }
                }
                // Unknown: the file stays under its final name. If the
                // commit landed, that is right. If it did not, a retry says
                // "upload incomplete: 0 of N" and the person uploads again:
                // loud. Moving it back would, if the commit landed, leave a
                // completed row without its file, which the sweep then
                // takes for an orphan `.part`: the attachment would look
                // complete and be gone, silently. Nobody is notified here:
                // if the commit landed, the other devices learn of the
                // revision at their next sync or the vault's next write.
                None => {
                    tracing::error!(
                        attachment = %id,
                        "a completion's commit failed and its row cannot be read: the file stays under its final name"
                    );
                }
            }
            Err(e)
        }
    }
}

/// Whether the row of attachment `id` reads completed after a failed
/// commit: `Some(false)` when it is pending or gone, `None` when it cannot
/// be read, twice, [`REREAD_PAUSE`] apart.
async fn committed(state: &AppState, vault_id: VaultId, id: AttachmentId) -> Option<bool> {
    for attempt in 0..2 {
        if attempt > 0 {
            tokio::time::sleep(REREAD_PAUSE).await;
        }
        match fetch(state, vault_id, id).await {
            Ok(meta) => return Some(meta.completed_at.is_some()),
            Err(ApiError::NotFound) => return Some(false),
            Err(_) => {}
        }
    }
    None
}

/// Streams the ciphertext. Supports `Range` requests, so large attachments
/// can be downloaded in chunks and resumed.
async fn download(
    State(state): State<AppState>,
    auth: Auth,
    Path((vault_id, attachment_id)): Path<(String, String)>,
    req: Request,
) -> ApiResult<Response> {
    let (vault_id, id) = ids(&vault_id, &attachment_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    let meta = fetch(&state, vault_id, id).await?;
    if meta.completed_at.is_none() {
        return Err(ApiError::NotFound);
    }
    let path = state.attachments().path(vault_id, id);
    let mut response = match ServeFile::new(path).oneshot(req).await {
        Ok(response) => response.into_response(),
        Err(never) => match never {},
    };
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok(response)
}

async fn delete(
    State(state): State<AppState>,
    auth: Auth,
    Path((vault_id, attachment_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let (vault_id, id) = ids(&vault_id, &attachment_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    // The upload guard: a chunk being written finishes first (409 meanwhile)
    // and none starts until the files are gone.
    let guard = state
        .attachments()
        .lock(id)
        .ok_or_else(|| ApiError::conflict("an upload of this attachment is in progress"))?;
    let mut w = VaultWrite::begin(&state, vault_id).await?;
    let deleted = sqlx::query(
        "UPDATE attachments SET deleted_at = $1, wrapped_key = NULL, revision = $2 \
         WHERE id = $3 AND vault_id = $4 AND deleted_at IS NULL",
    )
    .bind(w.now)
    .bind(w.revision)
    .bind(id.to_string())
    .bind(vault_id.to_string())
    .execute(&mut *w.tx)
    .await?;
    if deleted.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    let revision = w.commit().await?;
    state.notify(vault_id, revision);
    state.attachments().remove(vault_id, id).await;
    drop(guard);
    Ok(StatusCode::NO_CONTENT)
}
