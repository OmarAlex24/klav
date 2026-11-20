//! Vaults, their members and their projects.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use klav_core::crypto::context::VaultContext;
use klav_core::crypto::encoding::Kind;
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::crypto::{share, wrap};
use klav_core::ids::{AccountId, ProjectId, VaultId};
use klav_proto::Blob;
use klav_proto::vault::{
    CreateProject, CreateVault, Member, MemberList, MemberType, Project, ProjectList, Role,
    SignVaultKey, UpdateProject, UpdateVault, Vault, VaultList,
};
use sqlx::Row;
use sqlx::any::AnyRow;

use crate::db::now_ms;
use crate::error::{ApiError, ApiJson, ApiResult};
use crate::routes::agents::account_identity;
use crate::session::{Auth, parse_id};
use crate::state::AppState;
use crate::validate;
use crate::vaultdb::{
    MEMBER_ACCOUNT, VaultWrite, path_id, require_member, require_owner, role_from_db, role_to_db,
    to_i64, to_u64,
};

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/vaults", get(list_vaults).post(create_vault))
        .route(
            "/v1/vaults/{vault_id}",
            get(get_vault).put(update_vault).delete(delete_vault),
        )
        .route("/v1/vaults/{vault_id}/restore", post(restore_vault))
        .route("/v1/vaults/{vault_id}/signature", put(sign_vault))
        .route("/v1/vaults/{vault_id}/members", get(list_members))
        .route(
            "/v1/vaults/{vault_id}/projects",
            get(list_projects).post(create_project),
        )
        .route(
            "/v1/vaults/{vault_id}/projects/{project_id}",
            put(update_project).delete(delete_project),
        )
}

const VAULT_COLUMNS: &str = "v.id, v.owner_account_id, v.revision, v.version, v.meta, \
     v.created_at, v.updated_at, v.deleted_at, m.role, m.shared_key, m.shared_key_signature";

fn vault_from_row(row: &AnyRow) -> ApiResult<Vault> {
    Ok(Vault {
        id: parse_id(&row.try_get::<String, _>("id")?)?,
        owner_account_id: parse_id(&row.try_get::<String, _>("owner_account_id")?)?,
        role: role_from_db(&row.try_get::<String, _>("role")?),
        revision: to_u64(row.try_get("revision")?),
        version: to_u64(row.try_get("version")?),
        meta: Blob::new(row.try_get("meta")?),
        shared_key: Blob::new(row.try_get("shared_key")?),
        shared_key_signature: row
            .try_get::<Option<Vec<u8>>, _>("shared_key_signature")?
            .map(Blob::new),
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        deleted_at: row.try_get("deleted_at")?,
    })
}

/// The vault as seen by `auth` (deleted vaults included).
pub(crate) async fn fetch_vault(
    state: &AppState,
    auth: &Auth,
    vault_id: VaultId,
) -> ApiResult<Vault> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {VAULT_COLUMNS} FROM vaults v JOIN vault_members m ON m.vault_id = v.id \
         WHERE v.id = $1 AND m.member_type = $2 AND m.member_id = $3 AND m.revoked_at IS NULL"
    )))
    .bind(vault_id.to_string())
    .bind(MEMBER_ACCOUNT)
    .bind(auth.account_id.to_string())
    .fetch_optional(&state.db().pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    vault_from_row(&row)
}

pub(super) fn check_meta(state: &AppState, meta: &Blob) -> ApiResult<()> {
    if meta.len() > state.config().limits.max_meta_bytes {
        return Err(ApiError::bad_request("meta: too large"));
    }
    Ok(())
}

async fn list_vaults(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<VaultList>> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {VAULT_COLUMNS} FROM vaults v JOIN vault_members m ON m.vault_id = v.id \
         WHERE m.member_type = $1 AND m.member_id = $2 AND m.revoked_at IS NULL \
         AND v.deleted_at IS NULL ORDER BY v.created_at, v.id"
    )))
    .bind(MEMBER_ACCOUNT)
    .bind(auth.account_id.to_string())
    .fetch_all(&state.db().pool)
    .await?;
    let vaults = rows.iter().map(vault_from_row).collect::<ApiResult<_>>()?;
    Ok(Json(VaultList { vaults }))
}

async fn create_vault(
    State(state): State<AppState>,
    auth: Auth,
    ApiJson(req): ApiJson<CreateVault>,
) -> ApiResult<(StatusCode, Json<Vault>)> {
    validate::exact(
        &req.shared_key,
        Kind::SharedVaultKey,
        share::SHARED_KEY_LEN,
        "shared_key",
    )?;
    check_meta(&state, &req.meta)?;
    check_vault_key_signature(
        &state,
        auth.account_id,
        req.id,
        &req.shared_key,
        &req.shared_key_signature,
    )
    .await?;
    let now = now_ms();
    let mut tx = state.db().pool.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO vaults (id, owner_account_id, revision, version, meta, meta_revision, \
         created_at, updated_at) VALUES ($1, $2, 1, 1, $3, 1, $4, $5) ON CONFLICT DO NOTHING",
    )
    .bind(req.id.to_string())
    .bind(auth.account_id.to_string())
    .bind(req.meta.into_bytes())
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict("vault ID already exists"));
    }
    sqlx::query(
        "INSERT INTO vault_members (vault_id, member_type, member_id, role, shared_key, \
         shared_key_signature, revision, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 1, $7, $8)",
    )
    .bind(req.id.to_string())
    .bind(MEMBER_ACCOUNT)
    .bind(auth.account_id.to_string())
    .bind(role_to_db(Role::Owner))
    .bind(req.shared_key.into_bytes())
    .bind(req.shared_key_signature.into_bytes())
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    state.notify(req.id, 1);
    Ok((
        StatusCode::CREATED,
        Json(fetch_vault(&state, &auth, req.id).await?),
    ))
}

/// Checks the account's signature over its shared vault key (spec §8.3).
/// Clients verify it themselves; this only catches a buggy client early.
async fn check_vault_key_signature(
    state: &AppState,
    account: AccountId,
    vault: VaultId,
    shared_key: &Blob,
    signature: &Blob,
) -> ApiResult<()> {
    let bytes: [u8; SIGNATURE_LEN] = signature
        .as_bytes()
        .try_into()
        .map_err(|_| ApiError::bad_request("shared_key_signature: expected 64 bytes"))?;
    let ctx = VaultContext { account, vault };
    share::verify_vault_key(
        &account_identity(state, account).await?,
        &ctx,
        shared_key.as_bytes(),
        &Signature::from_bytes(bytes),
    )
    .map_err(|_| ApiError::bad_request("shared_key_signature does not verify"))
}

/// `PUT /v1/vaults/{vault_id}/signature`: the owner signs the vault key of
/// a vault created before the signature existed (TOFU, ADR 0030 §1).
///
/// Sending the signature already stored is a no-op (Ed25519 is
/// deterministic, so a retry sends the same bytes); a different one is 409.
/// Deleted vaults can be signed too. Storing it bumps the vault revision
/// and re-sends the vault record, so other devices see it in their next
/// `changes`.
async fn sign_vault(
    State(state): State<AppState>,
    auth: Auth,
    Path(vault_id): Path<String>,
    ApiJson(req): ApiJson<SignVaultKey>,
) -> ApiResult<Json<Vault>> {
    let vault_id: VaultId = path_id(&vault_id)?;
    require_owner(&state, vault_id, auth.account_id).await?;
    let current = fetch_vault(&state, &auth, vault_id).await?;
    if current.owner_account_id != auth.account_id {
        return Err(ApiError::Forbidden);
    }
    check_vault_key_signature(
        &state,
        auth.account_id,
        vault_id,
        &current.shared_key,
        &req.shared_key_signature,
    )
    .await?;
    match &current.shared_key_signature {
        Some(stored) if stored.as_bytes() == req.shared_key_signature.as_bytes() => {
            return Ok(Json(current));
        }
        Some(_) => return Err(ApiError::conflict("the vault key is already signed")),
        None => {}
    }
    let signature = req.shared_key_signature.into_bytes();
    let mut tx = state.db().pool.begin().await?;
    let revision: i64 = sqlx::query_scalar(
        "UPDATE vaults SET revision = revision + 1, meta_revision = revision + 1 \
         WHERE id = $1 RETURNING revision",
    )
    .bind(vault_id.to_string())
    .fetch_one(&mut *tx)
    .await?;
    let updated = sqlx::query(
        "UPDATE vault_members SET shared_key_signature = $1, revision = $2, updated_at = $3 \
         WHERE vault_id = $4 AND member_type = $5 AND member_id = $6 \
         AND shared_key_signature IS NULL AND revoked_at IS NULL",
    )
    .bind(signature.clone())
    .bind(revision)
    .bind(now_ms())
    .bind(vault_id.to_string())
    .bind(MEMBER_ACCOUNT)
    .bind(auth.account_id.to_string())
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        // Another device signed it meanwhile. Ed25519 is deterministic, so
        // the same key gives the same bytes: that is not a conflict.
        drop(tx);
        let now = fetch_vault(&state, &auth, vault_id).await?;
        return match &now.shared_key_signature {
            Some(stored) if stored.as_bytes() == signature.as_slice() => Ok(Json(now)),
            _ => Err(ApiError::conflict("the vault key is already signed")),
        };
    }
    tx.commit().await?;
    state.notify(vault_id, to_u64(revision));
    fetch_vault(&state, &auth, vault_id).await.map(Json)
}

async fn get_vault(
    State(state): State<AppState>,
    auth: Auth,
    Path(vault_id): Path<String>,
) -> ApiResult<Json<Vault>> {
    fetch_vault(&state, &auth, path_id(&vault_id)?)
        .await
        .map(Json)
}

async fn update_vault(
    State(state): State<AppState>,
    auth: Auth,
    Path(vault_id): Path<String>,
    ApiJson(req): ApiJson<UpdateVault>,
) -> ApiResult<Json<Vault>> {
    let vault_id: VaultId = path_id(&vault_id)?;
    require_owner(&state, vault_id, auth.account_id).await?;
    check_meta(&state, &req.meta)?;
    let new_version = to_i64(req.version)?;
    let mut w = VaultWrite::begin(&state, vault_id).await?;
    let current: i64 = sqlx::query_scalar("SELECT version FROM vaults WHERE id = $1")
        .bind(vault_id.to_string())
        .fetch_one(&mut *w.tx)
        .await?;
    if new_version != current + 1 {
        return Err(ApiError::stale(current));
    }
    sqlx::query(
        "UPDATE vaults SET version = $1, meta = $2, meta_revision = $3, updated_at = $4 \
         WHERE id = $5",
    )
    .bind(new_version)
    .bind(req.meta.into_bytes())
    .bind(w.revision)
    .bind(w.now)
    .bind(vault_id.to_string())
    .execute(&mut *w.tx)
    .await?;
    let revision = w.commit().await?;
    state.notify(vault_id, revision);
    fetch_vault(&state, &auth, vault_id).await.map(Json)
}

/// Soft delete: the vault disappears from listings and rejects writes, and
/// is purged after the retention period unless restored.
async fn delete_vault(
    State(state): State<AppState>,
    auth: Auth,
    Path(vault_id): Path<String>,
) -> ApiResult<StatusCode> {
    let vault_id: VaultId = path_id(&vault_id)?;
    require_owner(&state, vault_id, auth.account_id).await?;
    let mut w = VaultWrite::begin(&state, vault_id).await?;
    sqlx::query("UPDATE vaults SET deleted_at = $1, meta_revision = $2 WHERE id = $3")
        .bind(w.now)
        .bind(w.revision)
        .bind(vault_id.to_string())
        .execute(&mut *w.tx)
        .await?;
    let revision = w.commit().await?;
    state.notify(vault_id, revision);
    Ok(StatusCode::NO_CONTENT)
}

async fn restore_vault(
    State(state): State<AppState>,
    auth: Auth,
    Path(vault_id): Path<String>,
) -> ApiResult<Json<Vault>> {
    let vault_id: VaultId = path_id(&vault_id)?;
    require_owner(&state, vault_id, auth.account_id).await?;
    let revision: Option<i64> = sqlx::query_scalar(
        "UPDATE vaults SET deleted_at = NULL, revision = revision + 1, \
         meta_revision = revision + 1 WHERE id = $1 AND deleted_at IS NOT NULL RETURNING revision",
    )
    .bind(vault_id.to_string())
    .fetch_optional(&state.db().pool)
    .await?;
    let Some(revision) = revision else {
        // Purged meanwhile (its membership went with it): 404, like any
        // vault that does not exist. Otherwise it is simply not deleted.
        require_owner(&state, vault_id, auth.account_id).await?;
        return Err(ApiError::conflict("vault is not deleted"));
    };
    state.notify(vault_id, to_u64(revision));
    fetch_vault(&state, &auth, vault_id).await.map(Json)
}

pub(crate) fn member_from_row(row: &AnyRow) -> ApiResult<Member> {
    let member_type = match row.try_get::<String, _>("member_type")?.as_str() {
        "agent" => MemberType::Agent,
        _ => MemberType::Account,
    };
    Ok(Member {
        member_type,
        member_id: row.try_get("member_id")?,
        role: role_from_db(&row.try_get::<String, _>("role")?),
        shared_key: Blob::new(row.try_get("shared_key")?),
        revision: to_u64(row.try_get("revision")?),
        revoked_at: row.try_get("revoked_at")?,
    })
}

pub(crate) const MEMBER_COLUMNS: &str =
    "member_type, member_id, role, shared_key, revision, revoked_at";

async fn list_members(
    State(state): State<AppState>,
    auth: Auth,
    Path(vault_id): Path<String>,
) -> ApiResult<Json<MemberList>> {
    let vault_id: VaultId = path_id(&vault_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {MEMBER_COLUMNS} FROM vault_members WHERE vault_id = $1 \
         ORDER BY created_at, member_type, member_id"
    )))
    .bind(vault_id.to_string())
    .fetch_all(&state.db().pool)
    .await?;
    let members = rows.iter().map(member_from_row).collect::<ApiResult<_>>()?;
    Ok(Json(MemberList { members }))
}

pub(crate) const PROJECT_COLUMNS: &str =
    "id, vault_id, version, revision, wrapped_key, meta, created_at, updated_at, deleted_at";

pub(crate) fn project_from_row(row: &AnyRow) -> ApiResult<Project> {
    Ok(Project {
        id: parse_id(&row.try_get::<String, _>("id")?)?,
        vault_id: parse_id(&row.try_get::<String, _>("vault_id")?)?,
        version: to_u64(row.try_get("version")?),
        revision: to_u64(row.try_get("revision")?),
        wrapped_key: row
            .try_get::<Option<Vec<u8>>, _>("wrapped_key")?
            .map(Blob::new),
        meta: row.try_get::<Option<Vec<u8>>, _>("meta")?.map(Blob::new),
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        deleted_at: row.try_get("deleted_at")?,
    })
}

/// A project of `vault_id` (deleted ones included, as tombstones). A
/// project that does not exist and one of another vault are the same 404:
/// a member cannot probe IDs outside its vaults.
pub(super) async fn fetch_project(
    state: &AppState,
    vault_id: VaultId,
    project_id: ProjectId,
) -> ApiResult<Project> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {PROJECT_COLUMNS} FROM projects WHERE id = $1 AND vault_id = $2"
    )))
    .bind(project_id.to_string())
    .bind(vault_id.to_string())
    .fetch_optional(&state.db().pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    project_from_row(&row)
}

async fn list_projects(
    State(state): State<AppState>,
    auth: Auth,
    Path(vault_id): Path<String>,
) -> ApiResult<Json<ProjectList>> {
    let vault_id: VaultId = path_id(&vault_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {PROJECT_COLUMNS} FROM projects WHERE vault_id = $1 AND deleted_at IS NULL \
         ORDER BY created_at, id"
    )))
    .bind(vault_id.to_string())
    .fetch_all(&state.db().pool)
    .await?;
    let projects = rows
        .iter()
        .map(project_from_row)
        .collect::<ApiResult<_>>()?;
    Ok(Json(ProjectList { projects }))
}

pub(super) fn check_project_key(blob: &Blob) -> ApiResult<()> {
    validate::exact(
        blob,
        Kind::ProjectKeyWrap,
        wrap::WRAPPED_KEY_LEN,
        "wrapped_key",
    )
}

async fn create_project(
    State(state): State<AppState>,
    auth: Auth,
    Path(vault_id): Path<String>,
    ApiJson(req): ApiJson<CreateProject>,
) -> ApiResult<(StatusCode, Json<Project>)> {
    let vault_id: VaultId = path_id(&vault_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    check_project_key(&req.wrapped_key)?;
    check_meta(&state, &req.meta)?;
    let mut w = VaultWrite::begin(&state, vault_id).await?;
    let inserted = sqlx::query(
        "INSERT INTO projects (id, vault_id, version, wrapped_key, meta, revision, created_at, \
         updated_at) VALUES ($1, $2, 1, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
    )
    .bind(req.id.to_string())
    .bind(vault_id.to_string())
    .bind(req.wrapped_key.into_bytes())
    .bind(req.meta.into_bytes())
    .bind(w.revision)
    .bind(w.now)
    .bind(w.now)
    .execute(&mut *w.tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict("project ID already exists"));
    }
    let revision = w.commit().await?;
    state.notify(vault_id, revision);
    Ok((
        StatusCode::CREATED,
        Json(fetch_project(&state, vault_id, req.id).await?),
    ))
}

/// Current version of a live project of the vault, inside a write.
pub(super) async fn live_project_version(
    w: &mut VaultWrite,
    vault_id: VaultId,
    project_id: ProjectId,
) -> ApiResult<i64> {
    sqlx::query_scalar(
        "SELECT version FROM projects WHERE id = $1 AND vault_id = $2 AND deleted_at IS NULL",
    )
    .bind(project_id.to_string())
    .bind(vault_id.to_string())
    .fetch_optional(&mut *w.tx)
    .await?
    .ok_or(ApiError::NotFound)
}

async fn update_project(
    State(state): State<AppState>,
    auth: Auth,
    Path((vault_id, project_id)): Path<(String, String)>,
    ApiJson(req): ApiJson<UpdateProject>,
) -> ApiResult<Json<Project>> {
    let vault_id: VaultId = path_id(&vault_id)?;
    let project_id: ProjectId = path_id(&project_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    check_project_key(&req.wrapped_key)?;
    check_meta(&state, &req.meta)?;
    let new_version = to_i64(req.version)?;
    let mut w = VaultWrite::begin(&state, vault_id).await?;
    let current = live_project_version(&mut w, vault_id, project_id).await?;
    if new_version != current + 1 {
        return Err(ApiError::stale(current));
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
    let revision = w.commit().await?;
    state.notify(vault_id, revision);
    fetch_project(&state, vault_id, project_id).await.map(Json)
}

/// Deletes an empty project (every item purged); leaves a tombstone.
async fn delete_project(
    State(state): State<AppState>,
    auth: Auth,
    Path((vault_id, project_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let vault_id: VaultId = path_id(&vault_id)?;
    let project_id: ProjectId = path_id(&project_id)?;
    require_member(&state, vault_id, auth.account_id).await?;
    let mut w = VaultWrite::begin(&state, vault_id).await?;
    live_project_version(&mut w, vault_id, project_id).await?;
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM items WHERE project_id = $1 AND purged_at IS NULL",
    )
    .bind(project_id.to_string())
    .fetch_one(&mut *w.tx)
    .await?;
    if remaining > 0 {
        return Err(ApiError::conflict(
            "project is not empty: purge its items (including the trash) first",
        ));
    }
    sqlx::query(
        "UPDATE projects SET deleted_at = $1, wrapped_key = NULL, meta = NULL, revision = $2, \
         updated_at = $3 WHERE id = $4",
    )
    .bind(w.now)
    .bind(w.revision)
    .bind(w.now)
    .bind(project_id.to_string())
    .execute(&mut *w.tx)
    .await?;
    let revision = w.commit().await?;
    state.notify(vault_id, revision);
    Ok(StatusCode::NO_CONTENT)
}
