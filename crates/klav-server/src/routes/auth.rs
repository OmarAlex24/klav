//! Sign-up and log-in with OPAQUE, sessions and the account keyset.
//!
//! The server never receives the master password, the Secret Key, the KEK or
//! the OPAQUE input: only OPAQUE protocol messages and blobs encrypted by the
//! client.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Extension, Json, Router};
use klav_core::crypto::encoding::Kind;
use klav_core::crypto::identity::{PUBLIC_IDENTITY_LEN, PublicIdentity};
use klav_core::crypto::invite::{self, InviteCode};
use klav_core::crypto::kdf::{self, KdfParams};
use klav_core::crypto::{aead, opaque};
use klav_core::ids::{AccountId, DeviceId};
use klav_proto::Blob;
use klav_proto::RegistrationMode;
use klav_proto::auth::{
    AccountKeyset, DeviceInfo, InviteCheckRequest, LoginFinishRequest, LoginFinishResponse,
    LoginStartRequest, LoginStartResponse, PreloginRequest, PreloginResponse, RefreshRequest,
    RegisterFinishRequest, RegisterFinishResponse, RegisterStartRequest, RegisterStartResponse,
    SessionTokens,
};
use sqlx::Row;

use crate::db::now_ms;
use crate::error::{ApiError, ApiJson, ApiResult};
use crate::logins::Purpose;
use crate::ratelimit::{ClientIp, Quota};
use crate::session::{self, Auth, parse_id};
use crate::state::AppState;
use crate::validate;

/// Length of the identity private keys sealed with the KEK (spec §6.3).
const SEALED_IDENTITY_LEN: usize = aead::OVERHEAD + 64;

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/auth/prelogin", post(prelogin))
        .route("/v1/auth/invite/check", post(invite_check))
        .route("/v1/auth/register/start", post(register_start))
        .route("/v1/auth/register/finish", post(register_finish))
        .route("/v1/auth/login/start", post(login_start))
        .route("/v1/auth/login/finish", post(login_finish))
        .route("/v1/auth/refresh", post(refresh))
        .route("/v1/auth/logout", post(logout))
}

/// Per-IP limit for every authentication endpoint.
pub(super) fn limit_ip(state: &AppState, ip: ClientIp) -> ApiResult<()> {
    let rl = &state.config().rate_limit;
    state.limiter().enforce(
        &format!("auth-ip:{}", ip.key()),
        Quota {
            per_minute: rl.auth_ip_per_minute,
            burst: rl.auth_ip_burst,
        },
    )
}

/// Per-account limit against online guessing, by e-mail **and** client IP
/// (layer 07 of the 2026-11 round). Keyed by e-mail alone, anyone who knows
/// the address could keep its owner from logging in from anywhere. Guessing
/// from many addresses gains nothing either: the OPAQUE input also needs the
/// 128-bit Secret Key (spec §4), so the password alone cannot be tried
/// online.
pub(super) fn limit_email(state: &AppState, email: &str, ip: ClientIp) -> ApiResult<()> {
    let rl = &state.config().rate_limit;
    state.limiter().enforce(
        &format!("auth-email:{}:{email}", ip.key()),
        Quota {
            per_minute: rl.auth_email_per_minute,
            burst: rl.auth_email_burst,
        },
    )
}

async fn find_account(state: &AppState, email: &str) -> ApiResult<Option<sqlx::any::AnyRow>> {
    Ok(sqlx::query(
        "SELECT id, email, opaque_record, kdf_params, public_identity, sealed_identity \
         FROM accounts WHERE email = $1",
    )
    .bind(email)
    .fetch_optional(&state.db().pool)
    .await?)
}

pub(super) fn keyset(row: &sqlx::any::AnyRow) -> ApiResult<AccountKeyset> {
    Ok(AccountKeyset {
        account_id: parse_id(&row.try_get::<String, _>("id")?)?,
        email: row.try_get("email")?,
        kdf_params: Blob::new(row.try_get("kdf_params")?),
        public_identity: Blob::new(row.try_get("public_identity")?),
        sealed_identity: Blob::new(row.try_get("sealed_identity")?),
    })
}

async fn prelogin(
    State(state): State<AppState>,
    Extension(ip): Extension<ClientIp>,
    ApiJson(req): ApiJson<PreloginRequest>,
) -> ApiResult<Json<PreloginResponse>> {
    limit_ip(&state, ip)?;
    let email = validate::email(&req.email)?;
    limit_email(&state, &email, ip)?;
    let kdf_params = match find_account(&state, &email).await? {
        Some(row) => Blob::new(row.try_get("kdf_params")?),
        None => Blob::new(KdfParams::decoy(&state.keys().decoy_secret, email.as_bytes()).encode()),
    };
    Ok(Json(PreloginResponse { kdf_params }))
}

/// The registration mode, or `403` when nobody can sign up.
fn registration_gate(state: &AppState) -> ApiResult<RegistrationMode> {
    match state.config().registration_mode() {
        mode @ (RegistrationMode::Open | RegistrationMode::Invite) => Ok(mode),
        RegistrationMode::Closed | RegistrationMode::Unknown => Err(ApiError::Forbidden),
    }
}

/// The per-IP bucket of invite attempts (ADR 0048 §1.3).
fn invite_bucket(state: &AppState, ip: ClientIp) -> (String, Quota) {
    let rl = &state.config().rate_limit;
    (
        format!("invite-ip:{}", ip.key()),
        Quota {
            per_minute: rl.invite_ip_per_minute,
            burst: rl.invite_ip_burst,
        },
    )
}

/// Takes a token from the invite bucket (`429` when empty).
fn charge_invite(state: &AppState, ip: ClientIp) -> ApiResult<()> {
    let (key, quota) = invite_bucket(state, ip);
    state.limiter().enforce(&key, quota)
}

/// `429` if the invite bucket is empty, without taking a token: sign-ups
/// pay only for their invite failures, but none is tried with the bucket
/// empty.
fn peek_invite(state: &AppState, ip: ClientIp) -> ApiResult<()> {
    let (key, quota) = invite_bucket(state, ip);
    state
        .limiter()
        .peek(&key, quota)
        .map_err(|retry_after_secs| ApiError::TooManyRequests { retry_after_secs })
}

/// One refused invite: a `warn` line with the client's IP key, never the
/// code or the email (an alert can be set on it), and `403 invite_invalid`.
fn refuse_invite(ip: ClientIp, route: &'static str) -> ApiError {
    tracing::warn!(client_ip = %ip.key(), route, "invite refused");
    ApiError::invite_invalid()
}

/// [`refuse_invite`] for a sign-up step: the failure also costs a token.
fn refuse_signup_invite(state: &AppState, ip: ClientIp, route: &'static str) -> ApiError {
    let (key, quota) = invite_bucket(state, ip);
    // The refusal stands even if the bucket just emptied.
    let _ = state.limiter().check(&key, quota);
    refuse_invite(ip, route)
}

/// Whether the invite with `digest` can be used by `email` now: it exists,
/// is not revoked or expired, has uses left and is not bound to another
/// email. Never reads `accounts` (ADR 0048 §1.3, T244).
async fn invite_usable(state: &AppState, digest: &[u8], email: &str) -> ApiResult<bool> {
    let found: Option<String> = sqlx::query_scalar(
        "SELECT id FROM registration_invites WHERE code_hash = $1 AND revoked_at IS NULL \
         AND (expires_at IS NULL OR expires_at > $2) AND used_count < max_uses \
         AND (bound_email IS NULL OR bound_email = $3)",
    )
    .bind(digest.to_vec())
    .bind(now_ms())
    .bind(email)
    .fetch_optional(&state.db().pool)
    .await?;
    Ok(found.is_some())
}

/// The digest of a sign-up's invite, if it has one that decodes.
fn invite_digest(invite: Option<&InviteCode>) -> Option<[u8; invite::DIGEST_LEN]> {
    invite.and_then(|code| code.digest().ok())
}

/// `POST /v1/auth/invite/check`: `204` if the invite can be used by the
/// email now, `403 invite_invalid` otherwise, and `404` on a server that is
/// not in `invite` mode. Every call costs a token of the invite bucket.
async fn invite_check(
    State(state): State<AppState>,
    Extension(ip): Extension<ClientIp>,
    ApiJson(req): ApiJson<InviteCheckRequest>,
) -> ApiResult<StatusCode> {
    if state.config().registration_mode() != RegistrationMode::Invite {
        return Err(ApiError::NotFound);
    }
    limit_ip(&state, ip)?;
    charge_invite(&state, ip)?;
    let email = validate::email(&req.email)?;
    let usable = match invite_digest(Some(&req.invite)) {
        Some(digest) => invite_usable(&state, &digest, &email).await?,
        None => false,
    };
    if usable {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(refuse_invite(ip, "invite/check"))
    }
}

async fn register_start(
    State(state): State<AppState>,
    Extension(ip): Extension<ClientIp>,
    ApiJson(req): ApiJson<RegisterStartRequest>,
) -> ApiResult<Json<RegisterStartResponse>> {
    limit_ip(&state, ip)?;
    let mode = registration_gate(&state)?;
    let email = validate::email(&req.email)?;
    limit_email(&state, &email, ip)?;
    // In `invite` mode, the same check as `invite/check`, before any OPAQUE
    // work. An invite sent to an `open` server is ignored.
    if mode == RegistrationMode::Invite {
        peek_invite(&state, ip)?;
        let usable = match invite_digest(req.invite.as_ref()) {
            Some(digest) => invite_usable(&state, &digest, &email).await?,
            None => false,
        };
        if !usable {
            return Err(refuse_signup_invite(&state, ip, "register/start"));
        }
    }
    let response = opaque::server_registration_response(
        &state.keys().opaque,
        req.registration_request.as_bytes(),
        email.as_bytes(),
    )
    .map_err(|_| ApiError::bad_request("invalid registration_request"))?;
    Ok(Json(RegisterStartResponse {
        registration_response: Blob::new(response),
    }))
}

async fn register_finish(
    State(state): State<AppState>,
    Extension(ip): Extension<ClientIp>,
    ApiJson(req): ApiJson<RegisterFinishRequest>,
) -> ApiResult<(StatusCode, Json<RegisterFinishResponse>)> {
    limit_ip(&state, ip)?;
    let mode = registration_gate(&state)?;
    let email = validate::email(&req.email)?;
    limit_email(&state, &email, ip)?;
    let invite = if mode == RegistrationMode::Invite {
        peek_invite(&state, ip)?;
        match invite_digest(req.invite.as_ref()) {
            Some(digest) => Some(digest),
            None => return Err(refuse_signup_invite(&state, ip, "register/finish")),
        }
    } else {
        None
    };

    validate::exact(
        &req.kdf_params,
        Kind::KdfParams,
        kdf::ENCODED_LEN,
        "kdf_params",
    )?;
    // Defence in depth for threat T3 (ADR 0010): clients already refuse weak
    // parameters, but the server does not store them either, so a buggy or
    // tampered client cannot create an account that is cheap to brute-force.
    //
    // Exactly the v1 defaults, not just within range (layer 07 of the
    // 2026-11 round): `prelogin` answers the defaults for unknown e-mails
    // (the decoy), so an account with other costs would stand out from a
    // missing one. The official clients always send the defaults.
    if !state.config().insecure_accept_weak_kdf {
        let params = KdfParams::decode(req.kdf_params.as_bytes()).map_err(|_| {
            ApiError::bad_request(
                "kdf_params: Argon2id parameters outside the accepted range (spec §4.4)",
            )
        })?;
        if (params.m_kib(), params.t(), params.p())
            != (
                KdfParams::DEFAULT_M_KIB,
                KdfParams::DEFAULT_T,
                KdfParams::DEFAULT_P,
            )
        {
            return Err(ApiError::bad_request(
                "kdf_params: new accounts use the v1 default Argon2id costs (spec §4.4)",
            ));
        }
    }
    validate::exact(
        &req.public_identity,
        Kind::PublicIdentity,
        PUBLIC_IDENTITY_LEN,
        "public_identity",
    )?;
    PublicIdentity::decode(req.public_identity.as_bytes())
        .map_err(|_| ApiError::bad_request("public_identity: invalid public keys"))?;
    validate::exact(
        &req.sealed_identity,
        Kind::IdentitySecrets,
        SEALED_IDENTITY_LEN,
        "sealed_identity",
    )?;
    let record = opaque::server_registration_record(req.registration_upload.as_bytes())
        .map_err(|_| ApiError::bad_request("invalid registration_upload"))?;

    let now = now_ms();
    let account = NewAccount {
        id: req.account_id,
        email,
        record,
        kdf_params: req.kdf_params.into_bytes(),
        public_identity: req.public_identity.into_bytes(),
        sealed_identity: req.sealed_identity.into_bytes(),
        now,
    };
    match invite {
        None => {
            if !insert_account(&state.db().pool, account).await? {
                return Err(ApiError::conflict("account already exists"));
            }
            tracing::info!(account = %req.account_id, "account registered");
        }
        Some(digest) => {
            // One transaction, the write first, so SQLite never upgrades a
            // read lock (ADR 0048 §1.3): spend a use of the invite, create
            // the account, record which account used it. A conflict rolls
            // the use back; two finishes for the last use cannot both
            // commit.
            let mut tx = state.db().pool.begin().await?;
            let invite_id: Option<String> = sqlx::query_scalar(
                "UPDATE registration_invites SET used_count = used_count + 1 \
                 WHERE code_hash = $1 AND revoked_at IS NULL \
                 AND (expires_at IS NULL OR expires_at > $2) AND used_count < max_uses \
                 AND (bound_email IS NULL OR bound_email = $3) RETURNING id",
            )
            .bind(digest.to_vec())
            .bind(now)
            .bind(&account.email)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(invite_id) = invite_id else {
                drop(tx);
                return Err(refuse_signup_invite(&state, ip, "register/finish"));
            };
            if !insert_account(&mut *tx, account).await? {
                drop(tx);
                return Err(ApiError::conflict("account already exists"));
            }
            sqlx::query(
                "INSERT INTO registration_invite_uses (invite_id, account_id, used_at) \
                 VALUES ($1, $2, $3)",
            )
            .bind(&invite_id)
            .bind(req.account_id.to_string())
            .bind(now)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            tracing::info!(account = %req.account_id, invite = %invite_id, "account registered");
        }
    }
    Ok((
        StatusCode::CREATED,
        Json(RegisterFinishResponse {
            account_id: req.account_id,
        }),
    ))
}

/// A new account's row, already validated.
struct NewAccount {
    id: AccountId,
    email: String,
    record: Vec<u8>,
    kdf_params: Vec<u8>,
    public_identity: Vec<u8>,
    sealed_identity: Vec<u8>,
    now: i64,
}

/// Inserts the account; `false` if its email or ID already exists.
async fn insert_account<'e, E>(exec: E, a: NewAccount) -> ApiResult<bool>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    let inserted = sqlx::query(
        "INSERT INTO accounts (id, email, opaque_record, kdf_params, public_identity, \
         sealed_identity, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT DO NOTHING",
    )
    .bind(a.id.to_string())
    .bind(a.email)
    .bind(a.record)
    .bind(a.kdf_params)
    .bind(a.public_identity)
    .bind(a.sealed_identity)
    .bind(a.now)
    .bind(a.now)
    .execute(exec)
    .await?;
    Ok(inserted.rows_affected() == 1)
}

async fn login_start(
    State(state): State<AppState>,
    Extension(ip): Extension<ClientIp>,
    ApiJson(req): ApiJson<LoginStartRequest>,
) -> ApiResult<Json<LoginStartResponse>> {
    limit_ip(&state, ip)?;
    let email = validate::email(&req.email)?;
    limit_email(&state, &email, ip)?;
    let account = find_account(&state, &email).await?;
    let (record, account_id) = match &account {
        Some(row) => (
            Some(row.try_get::<Vec<u8>, _>("opaque_record")?),
            Some(parse_id::<AccountId>(&row.try_get::<String, _>("id")?)?),
        ),
        None => (None, None),
    };
    let (login, response) = opaque::server_start_login(
        &state.keys().opaque,
        record.as_deref(),
        req.credential_request.as_bytes(),
        email.as_bytes(),
    )
    .map_err(|_| ApiError::bad_request("invalid credential_request"))?;
    let login_id = state
        .logins()
        .insert(login, account_id, Purpose::Login)
        .ok_or(ApiError::Unavailable)?;
    Ok(Json(LoginStartResponse {
        login_id,
        credential_response: Blob::new(response),
    }))
}

async fn login_finish(
    State(state): State<AppState>,
    Extension(ip): Extension<ClientIp>,
    ApiJson(req): ApiJson<LoginFinishRequest>,
) -> ApiResult<Json<LoginFinishResponse>> {
    limit_ip(&state, ip)?;
    let name = validate::display_name(&req.device.name)?;
    // Only a login's handle: one that confirms a deletion is spent here,
    // and refused (T166).
    let pending = state
        .logins()
        .take(&req.login_id, &Purpose::Login)
        .ok_or(ApiError::Unauthorized)?;
    let verified = pending
        .login
        .finish(req.credential_finalization.as_bytes())
        .is_ok();
    // Unknown accounts and wrong passwords fail identically.
    let account_id = match (verified, pending.account_id) {
        (true, Some(id)) => id,
        _ => return Err(ApiError::Unauthorized),
    };
    let device_id = upsert_device(&state, account_id, &req.device, &name).await?;
    let tokens = session::create(&state, account_id, device_id).await?;
    let row = sqlx::query(
        "SELECT id, email, kdf_params, public_identity, sealed_identity FROM accounts WHERE id = $1",
    )
    .bind(account_id.to_string())
    .fetch_one(&state.db().pool)
    .await?;
    tracing::info!(account = %account_id, device = %device_id, "login");
    Ok(Json(LoginFinishResponse {
        account: keyset(&row)?,
        device_id,
        session: tokens,
    }))
}

/// Reuses the device the client already has, or registers a new one if the
/// client has none, or if it is unknown, revoked or from another account.
async fn upsert_device(
    state: &AppState,
    account_id: AccountId,
    info: &DeviceInfo,
    name: &str,
) -> ApiResult<DeviceId> {
    let now = now_ms();
    let pool = &state.db().pool;
    if let Some(id) = info.id {
        let updated = sqlx::query(
            "UPDATE devices SET name = $1, kind = $2, last_seen_at = $3 \
             WHERE id = $4 AND account_id = $5 AND revoked_at IS NULL",
        )
        .bind(name)
        .bind(info.kind.as_str())
        .bind(now)
        .bind(id.to_string())
        .bind(account_id.to_string())
        .execute(pool)
        .await?;
        if updated.rows_affected() == 1 {
            return Ok(id);
        }
    }
    let id = DeviceId::generate();
    sqlx::query(
        "INSERT INTO devices (id, account_id, name, kind, created_at, last_seen_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id.to_string())
    .bind(account_id.to_string())
    .bind(name)
    .bind(info.kind.as_str())
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(id)
}

async fn refresh(
    State(state): State<AppState>,
    Extension(ip): Extension<ClientIp>,
    ApiJson(req): ApiJson<RefreshRequest>,
) -> ApiResult<Json<SessionTokens>> {
    limit_ip(&state, ip)?;
    session::refresh(&state, &req.refresh_token).await.map(Json)
}

async fn logout(State(state): State<AppState>, auth: Auth) -> ApiResult<StatusCode> {
    session::revoke(&state, &auth.session_id).await?;
    // The app signs out of this device: no more approval pushes to it.
    super::devices::forget_push(&state, &auth.device_id.to_string()).await?;
    Ok(StatusCode::NO_CONTENT)
}
