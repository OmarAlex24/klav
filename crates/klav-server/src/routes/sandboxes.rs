//! A sandbox's life, as the credential proxy reports it (ADR 0036 §4, §9,
//! E3.3). Three routes, each signed by the proxy (spec §13.3) and logged
//! with its body:
//!
//! * `POST /v1/agent/sandboxes` → `sandbox.issued`. The proxy calls it
//!   before it hands the issuer the package; a refusal here means no
//!   package.
//! * `POST /v1/agent/sandboxes/{id}/claimed` → `sandbox.claimed`, before
//!   the proxy counts the secret as spent (its caller arrives with layer 6).
//! * `POST /v1/agent/sandboxes/{id}/revoked` → `sandbox.revoked`, with the
//!   reason.
//!
//! What the server checks, all under the account's lock (the one every
//! log append takes), so a pause, a deletion, a grant or the proxy's own
//! revocation written before the lock is seen:
//!
//! * the proxy is still an active agent (the extractor's check, read again
//!   under the lock), on every write here, its ends included;
//! * the issuer is in the caller's own grant (`issuers`, signed by the
//!   account) with every profile asked for, and its `expires_at` is no
//!   later than its `max_ttl` from now (plus the clock window);
//! * the issuer is an active agent of the account, its grant names this
//!   proxy, and it is not paused (`403 agents_paused`);
//! * no more live sandboxes of that issuer than its `max_live`;
//! * a claim or an end only for a sandbox this proxy issued, each once; a
//!   claim only while the sandbox is live and its issuer still is one;
//!   `theft` and `released` only after a claim.
//!
//! The server never sees the sandbox's secret, its digest or the package.
//!
//! The server is also the second barrier (E3.3, layer 5a): a
//! `POST /v1/agent/access` that names a sandbox ([`barrier`]) passes only
//! while that sandbox is live, the person has not revoked it, and its
//! issuer still is one, and the proxy's `GET /v1/agent/me` lists the
//! issuers of its grant that no longer are ([`gone_issuers`]), so it ends
//! their sandboxes (`issuer_removed`).
//!
//! The person's revocation (E3.3, spec §13.11), two more routes:
//!
//! * `POST /v1/sandboxes/revoke` → `sandbox.revoke_requested`, signed by
//!   the account: one sandbox of a proxy, or all of them (those live when
//!   the server logs it, read under the account's lock). The server bars
//!   them from then on, whatever the proxy does.
//! * `GET /v1/agent/sandboxes/revocations?since=` → the proxy reads them
//!   by their position in the log, which is their cursor, and ends the
//!   sandboxes with `person`.
//!
//! The proxy's heartbeat (E3.3, spec §13.12), two more:
//!
//! * `POST /v1/agent/sandboxes/epochs` → `sandbox.store_reset`: a new
//!   store of the proxy, the first one too, under a fresh epoch that is
//!   never used twice.
//! * `PUT /v1/agent/sandboxes/state` → no event: the server keeps the last
//!   heartbeat of each proxy, signed, under its current epoch with a `seq`
//!   that grows, and hands it to every device in `GET /v1/sync`.
//!
//! Only an agent whose grant makes it a credential proxy (proxy profiles
//! or sandbox issuers) may call these two: the account's choice of proxy
//! is an encrypted preference the server cannot read (frozen by the owner
//! on 2026-11-13, ADR 0036).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use klav_core::crypto::sandbox::{RevokeScope, RevokeToSign, verify_revoke};
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::ids::{AccountId, AgentId, SandboxId};
use klav_proto::agent::{AgentStatus, GrantPayload, SandboxIssuer};
use klav_proto::audit::{ActorKind, AuditEvent};
use klav_proto::sandbox::{
    CHANNEL_KEY_DIGEST_LEN, MAX_REVOCATIONS_PAGE, PATH_PERSON_REVOKE, PATH_REVOCATIONS,
    PATH_SANDBOX_STATE, PATH_STORE_RESET, REVOKE_CLOCK_WINDOW_MS, RevokeTarget, SCOPE_ALL,
    SandboxClaimed, SandboxEnd, SandboxHeartbeat, SandboxIssue, SandboxRevocation,
    SandboxRevocations, SandboxRevoke, SandboxRevoked, SandboxState, SandboxStoreReset, all_covers,
    is_json_object, parse_scope,
};
use klav_proto::{Blob, ErrorCode};
use serde::Deserialize;
use sqlx::Row;

use crate::agentauth::{AgentAuth, CLOCK_SKEW_MS, effective_status};
use crate::audit;
use crate::db::now_ms;
use crate::error::{ApiError, ApiJson, ApiQuery, ApiResult};
use crate::session::Auth;
use crate::state::AppState;
use crate::vaultdb::{path_id, to_i64};

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/agent/sandboxes", post(issue))
        .route("/v1/agent/sandboxes/{sandbox_id}/claimed", post(claimed))
        .route("/v1/agent/sandboxes/{sandbox_id}/revoked", post(revoked))
        .route(PATH_PERSON_REVOKE, post(person_revoke))
        .route(PATH_REVOCATIONS, get(revocations))
        .route(PATH_STORE_RESET, post(store_reset))
        .route(PATH_SANDBOX_STATE, put(sandbox_state_put))
}

pub(crate) type Tx<'a> = sqlx::Transaction<'a, sqlx::Any>;

fn not_issuer(message: impl Into<String>) -> ApiError {
    ApiError::Coded(StatusCode::FORBIDDEN, ErrorCode::NotIssuer, message.into())
}

fn sandbox_revoked(message: impl Into<String>) -> ApiError {
    ApiError::Coded(
        StatusCode::FORBIDDEN,
        ErrorCode::SandboxRevoked,
        message.into(),
    )
}

/// Takes the account's lock: the same row every log append and every
/// pause locks, so the checks below see a pause written before it.
pub(crate) async fn lock_account(tx: &mut Tx<'_>, account: AccountId) -> ApiResult<()> {
    let locked = sqlx::query("UPDATE accounts SET updated_at = updated_at WHERE id = $1")
        .bind(account.to_string())
        .execute(&mut **tx)
        .await?;
    if locked.rows_affected() == 1 {
        Ok(())
    } else {
        Err(ApiError::Internal("sandbox of an unknown account".into()))
    }
}

/// The grant of `agent` as stored (signed by the account), if it has one.
async fn grant_payload(tx: &mut Tx<'_>, agent: AgentId) -> ApiResult<Option<GrantPayload>> {
    let payload: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT grant_payload FROM agents WHERE id = $1")
            .bind(agent.to_string())
            .fetch_optional(&mut **tx)
            .await?
            .flatten();
    payload
        .map(|p| {
            serde_json::from_slice(&p)
                .map_err(|_| ApiError::Internal("corrupt grant payload".into()))
        })
        .transpose()
}

/// Whether `issuer` is still an issuer of the proxy `proxy`, as far as the
/// issuer goes: an active agent of `account` whose own grant names the
/// proxy. Its listing in the proxy's grant and its pause are checked apart.
async fn still_issuer<'e, E>(
    db: E,
    account: AccountId,
    proxy: AgentId,
    issuer: AgentId,
    now: i64,
) -> ApiResult<bool>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    let Some(row) = sqlx::query(
        "SELECT account_id, status, expires_at, grant_payload FROM agents WHERE id = $1",
    )
    .bind(issuer.to_string())
    .fetch_optional(db)
    .await?
    else {
        return Ok(false);
    };
    if row.try_get::<String, _>("account_id")? != account.to_string() {
        return Ok(false);
    }
    let status = effective_status(
        &row.try_get::<String, _>("status")?,
        row.try_get("expires_at")?,
        now,
    )?;
    if status != AgentStatus::Active {
        return Ok(false);
    }
    let names_proxy = row
        .try_get::<Option<Vec<u8>>, _>("grant_payload")?
        .map(|p| {
            serde_json::from_slice::<GrantPayload>(&p)
                .map_err(|_| ApiError::Internal("corrupt grant payload".into()))
        })
        .transpose()?
        .and_then(|g| g.sandbox)
        .and_then(|s| s.proxy)
        .is_some_and(|p| p.agent_id == proxy);
    Ok(names_proxy)
}

/// The issuer `issuer` as the caller's grant lists it, checked to still be
/// an issuer of this proxy: an active agent of the same account whose own
/// grant names the proxy, and not paused. Run under the account's lock.
async fn current_issuer(
    tx: &mut Tx<'_>,
    auth: &AgentAuth,
    issuer: AgentId,
    now: i64,
) -> ApiResult<SandboxIssuer> {
    let gone = || not_issuer(format!("agent {issuer} is not an issuer of this proxy"));
    let mine = grant_payload(tx, auth.agent_id).await?.ok_or_else(gone)?;
    let listed = mine
        .issuers
        .into_iter()
        .find(|i| i.agent_id == issuer)
        .ok_or_else(gone)?;
    if !still_issuer(&mut **tx, auth.account_id, auth.agent_id, issuer, now).await? {
        return Err(gone());
    }
    crate::pause::refuse_if_paused(&mut **tx, auth.account_id, issuer, now).await?;
    Ok(listed)
}

/// The issuers in the grant of the proxy `proxy` that are no longer
/// issuers of it ([`still_issuer`]): revoked, denied, expired, or whose
/// grant now names no proxy or another one. A paused issuer is not gone:
/// its sandboxes work again when the pause ends. The proxy ends the live
/// sandboxes of these with `issuer_removed` (ADR 0036 E3.3, Q-C; threat
/// model T156). Empty for an agent with no issuers in its grant.
pub(crate) async fn gone_issuers(
    state: &AppState,
    account: AccountId,
    proxy: AgentId,
    grant: Option<&GrantPayload>,
) -> ApiResult<Vec<AgentId>> {
    let Some(grant) = grant else {
        return Ok(Vec::new());
    };
    let now = now_ms();
    let mut gone = Vec::new();
    for issuer in &grant.issuers {
        if !still_issuer(&state.db().pool, account, proxy, issuer.agent_id, now).await? {
            gone.push(issuer.agent_id);
        }
    }
    Ok(gone)
}

/// Whether the person revoked `sandbox` (`sandbox.revoke_requested`).
async fn person_revoked(tx: &mut Tx<'_>, sandbox: SandboxId) -> ApiResult<bool> {
    let found: Option<String> =
        sqlx::query_scalar("SELECT sandbox_id FROM sandbox_person_revoked WHERE sandbox_id = $1")
            .bind(sandbox.to_string())
            .fetch_optional(&mut **tx)
            .await?;
    Ok(found.is_some())
}

/// The second barrier (ADR 0036 E3.3): a `POST /v1/agent/access` of the
/// proxy `auth` that names `sandbox` passes only if that proxy issued it,
/// its end is not recorded, the person has not revoked it, it has not
/// expired, and its issuer is still in the proxy's grant and still an
/// issuer (`403 sandbox_revoked` otherwise), and not paused
/// (`403 agents_paused`). Run under the account's lock, so an end or a
/// revocation recorded before it is seen.
pub(crate) async fn barrier(
    tx: &mut Tx<'_>,
    auth: &AgentAuth,
    sandbox: SandboxId,
    now: i64,
) -> ApiResult<()> {
    let (issuer, expires_at, _, was_revoked) = match mine(tx, auth, sandbox).await {
        Ok(found) => found,
        Err(ApiError::Coded(_, ErrorCode::SandboxNotFound, _)) => {
            return Err(sandbox_revoked("this proxy never logged this sandbox"));
        }
        Err(e) => return Err(e),
    };
    if was_revoked {
        return Err(sandbox_revoked("this sandbox was revoked"));
    }
    if person_revoked(tx, sandbox).await? {
        return Err(sandbox_revoked("the person revoked this sandbox"));
    }
    if expires_at <= now {
        return Err(sandbox_revoked("this sandbox has expired"));
    }
    match current_issuer(tx, auth, issuer, now).await {
        Ok(_) => Ok(()),
        Err(ApiError::Coded(_, ErrorCode::NotIssuer, _)) => Err(sandbox_revoked(
            "this sandbox's issuer is no longer an issuer of this proxy",
        )),
        Err(e) => Err(e),
    }
}

/// The proxy itself, checked again under the lock, in the extractor's
/// order (its status, then a deletion, then a pause): the extractor checked
/// before the lock.
async fn proxy_may_act(tx: &mut Tx<'_>, auth: &AgentAuth, now: i64) -> ApiResult<()> {
    proxy_still_active(tx, auth, now).await?;
    crate::deletion::refuse_if_deleting(&mut **tx, auth.account_id).await?;
    crate::pause::refuse_if_paused(&mut **tx, auth.account_id, auth.agent_id, now).await
}

/// The proxy's status again, under the account's lock
/// ([`crate::agentauth::still_active`]). `audit::append_in` runs the same
/// check for the proxy's event, which rolls back the write before it;
/// checking first keeps the extractor's answer (`403 forbidden`) ahead of
/// a route's own refusals, and covers the heartbeat, which logs nothing.
async fn proxy_still_active(tx: &mut Tx<'_>, auth: &AgentAuth, now: i64) -> ApiResult<()> {
    crate::agentauth::still_active(&mut **tx, auth.agent_id, auth.account_id, now).await
}

/// The proxy's event, with its signed request (and body).
fn event(auth: &AgentAuth, action: &str, outcome: Option<&str>) -> AuditEvent {
    let mut event = AuditEvent::new(ActorKind::Agent, action);
    event.agent_id = Some(auth.agent_id);
    event.outcome = outcome.map(str::to_owned);
    event.agent_proof = Some(auth.proof.clone());
    event
}

/// `POST /v1/agent/sandboxes`: `sandbox.issued`.
async fn issue(State(state): State<AppState>, auth: AgentAuth) -> ApiResult<StatusCode> {
    let req: SandboxIssue = auth.logged_json()?;
    req.check_format(auth.agent_id)
        .map_err(ApiError::bad_request)?;
    let now = now_ms();
    if req.expires_at <= now {
        return Err(ApiError::bad_request("expires_at is in the past"));
    }
    let mut tx = state.db().pool.begin().await?;
    lock_account(&mut tx, auth.account_id).await?;
    proxy_may_act(&mut tx, &auth, now).await?;
    let issuer = current_issuer(&mut tx, &auth, req.issuer_id, now).await?;
    if let Some(p) = req.profiles.iter().find(|p| !issuer.profiles.contains(p)) {
        return Err(ApiError::Coded(
            StatusCode::FORBIDDEN,
            ErrorCode::ProfileNotAllowed,
            format!("this issuer may not use the profile {p}"),
        ));
    }
    let max_ttl_ms = i64::try_from(issuer.max_ttl_secs)
        .unwrap_or(i64::MAX / 2_000)
        .saturating_mul(1000);
    if req.expires_at > now.saturating_add(max_ttl_ms).saturating_add(CLOCK_SKEW_MS) {
        return Err(ApiError::bad_request(format!(
            "this issuer's sandboxes last at most {} s",
            issuer.max_ttl_secs
        )));
    }
    let live: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sandboxes WHERE proxy_id = $1 AND issuer_id = $2 \
         AND revoked_at IS NULL AND expires_at > $3 \
         AND NOT EXISTS (SELECT 1 FROM sandbox_person_revoked p \
         WHERE p.sandbox_id = sandboxes.id)",
    )
    .bind(auth.agent_id.to_string())
    .bind(req.issuer_id.to_string())
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    if live >= i64::from(issuer.max_live) {
        return Err(ApiError::Coded(
            StatusCode::CONFLICT,
            ErrorCode::TooManySandboxes,
            format!(
                "this issuer already has {live} live sandboxes, its limit is {}",
                issuer.max_live
            ),
        ));
    }
    let taken: Option<String> = sqlx::query_scalar("SELECT id FROM sandboxes WHERE id = $1")
        .bind(req.sandbox_id.to_string())
        .fetch_optional(&mut *tx)
        .await?;
    if taken.is_some() {
        return Err(ApiError::conflict("this sandbox ID is already used"));
    }
    sqlx::query(
        "INSERT INTO sandboxes (id, account_id, proxy_id, issuer_id, expires_at, issued_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(req.sandbox_id.to_string())
    .bind(auth.account_id.to_string())
    .bind(auth.agent_id.to_string())
    .bind(req.issuer_id.to_string())
    .bind(req.expires_at)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let mut event = event(&auth, "sandbox.issued", None);
    audit::append_in(&mut tx, auth.account_id, &mut event, now).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A sandbox this proxy issued: `(issuer, expires_at, claimed, revoked)`.
/// Another proxy's sandbox is not found, like one that does not exist:
/// `404 sandbox_not_found`, the one answer that lets the proxy drop the
/// sandbox's end.
async fn mine(
    tx: &mut Tx<'_>,
    auth: &AgentAuth,
    sandbox: SandboxId,
) -> ApiResult<(AgentId, i64, bool, bool)> {
    let row = sqlx::query(
        "SELECT issuer_id, expires_at, claimed_at, revoked_at FROM sandboxes \
         WHERE id = $1 AND proxy_id = $2 AND account_id = $3",
    )
    .bind(sandbox.to_string())
    .bind(auth.agent_id.to_string())
    .bind(auth.account_id.to_string())
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| {
        ApiError::Coded(
            StatusCode::NOT_FOUND,
            ErrorCode::SandboxNotFound,
            "this proxy logged no sandbox with this ID".into(),
        )
    })?;
    Ok((
        crate::session::parse_id(&row.try_get::<String, _>("issuer_id")?)?,
        row.try_get("expires_at")?,
        row.try_get::<Option<i64>, _>("claimed_at")?.is_some(),
        row.try_get::<Option<i64>, _>("revoked_at")?.is_some(),
    ))
}

/// `POST /v1/agent/sandboxes/{id}/claimed`: `sandbox.claimed`.
async fn claimed(
    State(state): State<AppState>,
    Path(sandbox): Path<String>,
    auth: AgentAuth,
) -> ApiResult<StatusCode> {
    let sandbox: SandboxId = path_id(&sandbox)?;
    let req: SandboxClaimed = auth.logged_json()?;
    if req.channel_key_sha256.as_bytes().len() != CHANNEL_KEY_DIGEST_LEN {
        return Err(ApiError::bad_request(format!(
            "channel_key_sha256 must be {CHANNEL_KEY_DIGEST_LEN} bytes"
        )));
    }
    let now = now_ms();
    let mut tx = state.db().pool.begin().await?;
    lock_account(&mut tx, auth.account_id).await?;
    proxy_may_act(&mut tx, &auth, now).await?;
    let (issuer, expires_at, was_claimed, was_revoked) = mine(&mut tx, &auth, sandbox).await?;
    if was_revoked || person_revoked(&mut tx, sandbox).await? {
        return Err(sandbox_revoked("this sandbox was revoked"));
    }
    if was_claimed {
        return Err(ApiError::Coded(
            StatusCode::CONFLICT,
            ErrorCode::SandboxClaimed,
            "this sandbox was already claimed".into(),
        ));
    }
    if expires_at <= now {
        return Err(sandbox_revoked("this sandbox has expired"));
    }
    match current_issuer(&mut tx, &auth, issuer, now).await {
        Ok(_) => {}
        Err(ApiError::Coded(_, ErrorCode::NotIssuer, _)) => {
            return Err(sandbox_revoked(
                "this sandbox's issuer is no longer an issuer of this proxy",
            ));
        }
        Err(e) => return Err(e),
    }
    sqlx::query("UPDATE sandboxes SET claimed_at = $1 WHERE id = $2")
        .bind(now)
        .bind(sandbox.to_string())
        .execute(&mut *tx)
        .await?;
    let mut event = event(&auth, "sandbox.claimed", None);
    audit::append_in(&mut tx, auth.account_id, &mut event, now).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/agent/sandboxes/{id}/revoked`: `sandbox.revoked`. Ending a
/// sandbox only takes access away, so it needs neither a live issuer nor a
/// live sandbox (the end of an expired one is the usual `ttl`). `person`
/// answers a revocation by the person that covers this sandbox, named by
/// its `at` ([`answers_person`]).
///
/// `person_local` (the proxy's own socket, E3.5) is still refused with the
/// `400` of `main`, in any shape of body, though `klav log verify` checks
/// it from this layer on: it needs only the proxy's key, so released
/// verifiers, which reject it, could be handed one with no act of the
/// person. The layer that sends it (the Mac proxy's local socket) lifts the
/// refusal, once every device has this verifier.
async fn revoked(
    State(state): State<AppState>,
    Path(sandbox): Path<String>,
    auth: AgentAuth,
) -> ApiResult<StatusCode> {
    let sandbox: SandboxId = path_id(&sandbox)?;
    // `person_local`, before the body is read as an end: the plain shapes
    // get one message; every shape, the typed one below included, is a 400
    // with nothing logged.
    let raw: serde_json::Value = auth.logged_json()?;
    let reason = match &raw {
        serde_json::Value::Object(fields) => fields.get("reason"),
        serde_json::Value::Array(items) => items.first(),
        _ => None,
    };
    if reason.and_then(serde_json::Value::as_str) == Some(SandboxEnd::PersonLocal.as_str()) {
        return Err(ApiError::bad_request("unknown reason person_local"));
    }
    let req: SandboxRevoked = auth.logged_json()?;
    // The typed value too: serde also reads a unit variant from a one-key
    // map (`{"reason":{"person_local":null}}`), which the check on the raw
    // string above does not see.
    if req.reason == SandboxEnd::PersonLocal {
        return Err(ApiError::bad_request("unknown reason person_local"));
    }
    if !is_json_object(&auth.body) {
        return Err(ApiError::bad_request("an end is a JSON object"));
    }
    req.check_format().map_err(ApiError::bad_request)?;
    let now = now_ms();
    let mut tx = state.db().pool.begin().await?;
    lock_account(&mut tx, auth.account_id).await?;
    // Only the status: an end is not refused for a pause or a deletion
    // beyond what the extractor does, but a proxy revoked since the
    // extractor's read logs nothing after `agent.revoked`.
    proxy_still_active(&mut tx, &auth, now).await?;
    let (_, _, was_claimed, was_revoked) = mine(&mut tx, &auth, sandbox).await?;
    if was_revoked {
        return Err(sandbox_revoked("this sandbox's end is already recorded"));
    }
    if req.reason.needs_claim() && !was_claimed {
        return Err(ApiError::conflict(format!(
            "only a claimed sandbox can end with {}",
            req.reason.as_str()
        )));
    }
    if let (SandboxEnd::Person, Some(at)) = (req.reason, req.at)
        && !answers_person(&mut tx, &auth, sandbox, at).await?
    {
        return Err(ApiError::conflict(
            "no revocation by the person of this sandbox has this at",
        ));
    }
    sqlx::query("UPDATE sandboxes SET revoked_at = $1, revoke_reason = $2 WHERE id = $3")
        .bind(now)
        .bind(req.reason.as_str())
        .bind(sandbox.to_string())
        .execute(&mut *tx)
        .await?;
    let mut event = event(&auth, "sandbox.revoked", Some(req.reason.as_str()));
    audit::append_in(&mut tx, auth.account_id, &mut event, now).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Whether a revocation by the person of `sandbox`, signed with `at`, is
/// logged: of this proxy, for this sandbox or `all` covering it.
async fn answers_person(
    tx: &mut Tx<'_>,
    auth: &AgentAuth,
    sandbox: SandboxId,
    at: i64,
) -> ApiResult<bool> {
    let rows = sqlx::query(
        "SELECT scope, sandbox_ids FROM sandbox_revocations \
         WHERE account_id = $1 AND proxy_id = $2 AND at_ms = $3",
    )
    .bind(auth.account_id.to_string())
    .bind(auth.agent_id.to_string())
    .bind(at)
    .fetch_all(&mut **tx)
    .await?;
    for row in rows {
        if covered(&row)?.contains(&sandbox) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The sandboxes a stored revocation covers.
fn covered(row: &sqlx::any::AnyRow) -> ApiResult<Vec<SandboxId>> {
    serde_json::from_str(&row.try_get::<String, _>("sandbox_ids")?)
        .map_err(|_| ApiError::Internal("corrupt sandbox revocation".into()))
}

/// `POST /v1/sandboxes/revoke`: `sandbox.revoke_requested` (ADR 0036
/// E3.3, spec §13.11). Signed by the account, within the clock window of
/// the server, and later than the last revocation of the same proxy and
/// scope, so an old `all` is never replayed over sandboxes issued after it
/// (`409` with `last_at` otherwise). The proxy is any agent of the
/// account, whatever its state or pause, and the sandbox any it logged,
/// ended or not: a revocation only takes access away.
///
/// The checks, the event, the revocation and the barrier's rows are one
/// transaction under the account's lock, so the revocation's cursor (its
/// event's position) commits in log order, and every allowed call logged
/// after it is checked against it (`agent_access::record`).
async fn person_revoke(
    State(state): State<AppState>,
    auth: Auth,
    ApiJson(req): ApiJson<SandboxRevoke>,
) -> ApiResult<Json<SandboxRevocation>> {
    let now = now_ms();
    // `abs_diff`: a made-up `at` near `i64::MIN` or `MAX` must not overflow.
    if req.at.abs_diff(now) > CLOCK_SKEW_MS.unsigned_abs() {
        return Err(ApiError::bad_request(
            "at is too far from the server's clock",
        ));
    }
    let target = parse_scope(&req.scope).map_err(ApiError::bad_request)?;
    let signature: [u8; SIGNATURE_LEN] = req
        .signature
        .as_bytes()
        .try_into()
        .map_err(|_| ApiError::bad_request("signature: expected 64 bytes"))?;
    let account = crate::routes::agents::account_identity(&state, auth.account_id).await?;
    verify_revoke(
        &account,
        &RevokeToSign {
            account: auth.account_id,
            proxy: req.proxy_id,
            scope: match target {
                RevokeTarget::All => RevokeScope::All,
                RevokeTarget::One(id) => RevokeScope::Sandbox(id),
            },
            at_ms: u64::try_from(req.at).map_err(|_| ApiError::bad_request("at"))?,
        },
        &Signature::from_bytes(signature),
    )
    .map_err(|_| ApiError::bad_request("the revocation's signature does not verify"))?;

    let mut tx = state.db().pool.begin().await?;
    lock_account(&mut tx, auth.account_id).await?;
    let owner: Option<String> = sqlx::query_scalar("SELECT account_id FROM agents WHERE id = $1")
        .bind(req.proxy_id.to_string())
        .fetch_optional(&mut *tx)
        .await?;
    if owner != Some(auth.account_id.to_string()) {
        return Err(ApiError::NotFound);
    }
    let scope = match target {
        RevokeTarget::All => SCOPE_ALL.to_owned(),
        RevokeTarget::One(id) => id.to_string(),
    };
    let last: Option<i64> = sqlx::query_scalar(
        "SELECT MAX(at_ms) FROM sandbox_revocations \
         WHERE account_id = $1 AND proxy_id = $2 AND scope = $3",
    )
    .bind(auth.account_id.to_string())
    .bind(req.proxy_id.to_string())
    .bind(&scope)
    .fetch_one(&mut *tx)
    .await?;
    if let Some(last) = last
        && req.at <= last
    {
        return Err(ApiError::LaterRevocation(last));
    }
    let sandbox_ids = match target {
        RevokeTarget::One(id) => {
            let found: Option<String> = sqlx::query_scalar(
                "SELECT id FROM sandboxes WHERE id = $1 AND proxy_id = $2 AND account_id = $3",
            )
            .bind(id.to_string())
            .bind(req.proxy_id.to_string())
            .bind(auth.account_id.to_string())
            .fetch_optional(&mut *tx)
            .await?;
            if found.is_none() {
                return Err(ApiError::Coded(
                    StatusCode::NOT_FOUND,
                    ErrorCode::SandboxNotFound,
                    "this proxy logged no sandbox with this ID".into(),
                ));
            }
            vec![id]
        }
        // Those the log issued before it, under the lock (a sandbox issued
        // after this revocation is not covered), not ended, and not expired
        // by the signed time, over-inclusive by the clock window
        // ([`all_covers`]): the same rule `klav log verify` rebuilds, which
        // reads no time the server chose. The query already leaves out what
        // expired before the same cutoff, so a proxy that died without
        // sending its `ttl` ends does not load them on every `all`;
        // `all_covers` stays the rule.
        RevokeTarget::All => {
            let rows = sqlx::query(
                "SELECT id, expires_at FROM sandboxes WHERE proxy_id = $1 AND account_id = $2 \
                 AND revoked_at IS NULL AND expires_at > $3",
            )
            .bind(req.proxy_id.to_string())
            .bind(auth.account_id.to_string())
            .bind(req.at.saturating_sub(REVOKE_CLOCK_WINDOW_MS))
            .fetch_all(&mut *tx)
            .await?;
            let mut ids = Vec::new();
            for row in &rows {
                if all_covers(row.try_get("expires_at")?, req.at) {
                    ids.push(crate::session::parse_id::<SandboxId>(
                        &row.try_get::<String, _>("id")?,
                    )?);
                }
            }
            ids.sort();
            ids
        }
    };
    let mut event = AuditEvent::new(ActorKind::Person, "sandbox.revoke_requested");
    event.device_id = Some(auth.device_id);
    event.agent_id = Some(req.proxy_id);
    event.decided_at = Some(req.at);
    event.account_signature = Some(Blob::new(signature.to_vec()));
    match target {
        RevokeTarget::One(id) => event.sandbox_id = Some(id),
        RevokeTarget::All => event.sandbox_ids.clone_from(&sandbox_ids),
    }
    audit::append_in(&mut tx, auth.account_id, &mut event, now).await?;
    let seq = to_i64(event.seq)?;
    let ids_json = serde_json::to_string(&sandbox_ids)
        .map_err(|e| ApiError::Internal(format!("sandbox revocation: {e}")))?;
    sqlx::query(
        "INSERT INTO sandbox_revocations (account_id, seq, proxy_id, scope, at_ms, signature, \
         device_id, sandbox_ids, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(auth.account_id.to_string())
    .bind(seq)
    .bind(req.proxy_id.to_string())
    .bind(&scope)
    .bind(req.at)
    .bind(signature.to_vec())
    .bind(auth.device_id.to_string())
    .bind(ids_json)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    // The barrier's rows: the first revocation of each sandbox stays.
    for id in &sandbox_ids {
        sqlx::query(
            "INSERT INTO sandbox_person_revoked (sandbox_id, account_id, proxy_id, seq, at_ms, \
             created_at) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (sandbox_id) DO NOTHING",
        )
        .bind(id.to_string())
        .bind(auth.account_id.to_string())
        .bind(req.proxy_id.to_string())
        .bind(seq)
        .bind(req.at)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Json(SandboxRevocation {
        seq: event.seq,
        proxy_id: req.proxy_id,
        scope,
        at: req.at,
        signature: req.signature,
        sandbox_ids,
    }))
}

/// The query of [`revocations`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationsQuery {
    /// The last position the proxy read (0 for all).
    #[serde(default)]
    since: u64,
}

/// `GET /v1/agent/sandboxes/revocations?since=`: the proxy's revocations
/// after `since`, oldest first, at most [`MAX_REVOCATIONS_PAGE`]. Their
/// positions are those of their events in the account's log, and a
/// revocation commits after every event before it (both under the
/// account's lock), so one read never sees a later one without the
/// earlier ones: a cursor never skips a revocation.
async fn revocations(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<RevocationsQuery>,
    auth: AgentAuth,
) -> ApiResult<Json<SandboxRevocations>> {
    let page = i64::try_from(MAX_REVOCATIONS_PAGE).unwrap_or(100);
    let rows = sqlx::query(
        "SELECT seq, scope, at_ms, signature, sandbox_ids FROM sandbox_revocations \
         WHERE account_id = $1 AND proxy_id = $2 AND seq > $3 ORDER BY seq LIMIT $4",
    )
    .bind(auth.account_id.to_string())
    .bind(auth.agent_id.to_string())
    .bind(to_i64(query.since)?)
    .bind(page + 1)
    .fetch_all(&state.db().pool)
    .await?;
    let more = rows.len() > MAX_REVOCATIONS_PAGE;
    let revocations = rows
        .iter()
        .take(MAX_REVOCATIONS_PAGE)
        .map(|row| {
            Ok(SandboxRevocation {
                seq: u64::try_from(row.try_get::<i64, _>("seq")?)
                    .map_err(|_| ApiError::Internal("corrupt sandbox revocation".into()))?,
                proxy_id: auth.agent_id,
                scope: row.try_get("scope")?,
                at: row.try_get("at_ms")?,
                signature: Blob::new(row.try_get::<Vec<u8>, _>("signature")?),
                sandbox_ids: covered(row)?,
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(Json(SandboxRevocations { revocations, more }))
}

/// Whether the account signed a grant that makes `auth` a credential proxy:
/// proxy profiles or sandbox issuers in its grant (ADR 0036 §2, §4). The
/// account's choice of proxy is an encrypted preference the server cannot
/// read, so this is the most it can check (frozen by the owner on
/// 2026-11-13, ADR 0036). Refused with `403 forbidden` otherwise.
async fn require_proxy_grant(tx: &mut Tx<'_>, auth: &AgentAuth) -> ApiResult<()> {
    let grant = grant_payload(tx, auth.agent_id).await?;
    if grant.is_some_and(|g| !g.profiles.is_empty() || !g.issuers.is_empty()) {
        Ok(())
    } else {
        Err(ApiError::Coded(
            StatusCode::FORBIDDEN,
            ErrorCode::Forbidden,
            "only an agent whose grant makes it a credential proxy may do this".into(),
        ))
    }
}

/// The epoch of this proxy's last `sandbox.store_reset`, if any.
async fn current_epoch(tx: &mut Tx<'_>, auth: &AgentAuth) -> ApiResult<Option<Vec<u8>>> {
    Ok(sqlx::query_scalar(
        "SELECT epoch FROM sandbox_store_epochs WHERE proxy_id = $1 AND account_id = $2 \
         ORDER BY seq DESC LIMIT 1",
    )
    .bind(auth.agent_id.to_string())
    .bind(auth.account_id.to_string())
    .fetch_optional(&mut **tx)
    .await?)
}

/// Refuses a request signed for `path` with anything after it (a query,
/// even an empty `?`): the device checks the signed path of a reset and of
/// a heartbeat against the route exactly, and would read one with a query
/// as tampering (review of #357, 1).
fn signed_exactly(auth: &AgentAuth, path: &str) -> ApiResult<()> {
    if auth.proof.path == path {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!(
            "sign this request for {path} exactly, with no query"
        )))
    }
}

/// `POST /v1/agent/sandboxes/epochs`: `sandbox.store_reset`, a new store
/// of the proxy (ADR 0036 E3.3, spec §13.12). An epoch this proxy used
/// before is a `409`: the proxy then starts another.
async fn store_reset(State(state): State<AppState>, auth: AgentAuth) -> ApiResult<StatusCode> {
    // Before anything is read: serde also reads the struct from an array
    // (`["<epoch>"]`), which the person's log verifier refuses, so the
    // server must never log one.
    if !is_json_object(&auth.body) {
        return Err(ApiError::bad_request("a store reset is a JSON object"));
    }
    let req: SandboxStoreReset = auth.logged_json()?;
    signed_exactly(&auth, PATH_STORE_RESET)?;
    req.check_format().map_err(ApiError::bad_request)?;
    let mut tx = state.db().pool.begin().await?;
    lock_account(&mut tx, auth.account_id).await?;
    // The time the event is logged with. A body that arrived after the
    // clock window is a `401` before this handler runs (the extractor
    // checks the window again once the body is in, #358), and
    // `audit::append_in` checks the signed route and this time with the log
    // verifier's own rules (`klav_proto::audit`), with nothing written
    // (review of #357, 2).
    let now = now_ms();
    proxy_may_act(&mut tx, &auth, now).await?;
    require_proxy_grant(&mut tx, &auth).await?;
    let epoch = req.store_epoch.as_bytes().to_vec();
    let used: Option<i64> = sqlx::query_scalar(
        "SELECT seq FROM sandbox_store_epochs WHERE proxy_id = $1 AND epoch = $2",
    )
    .bind(auth.agent_id.to_string())
    .bind(epoch.clone())
    .fetch_optional(&mut *tx)
    .await?;
    if used.is_some() {
        return Err(ApiError::conflict(
            "this store epoch was used before: start a new one",
        ));
    }
    let mut event = event(&auth, "sandbox.store_reset", None);
    audit::append_in(&mut tx, auth.account_id, &mut event, now).await?;
    sqlx::query(
        "INSERT INTO sandbox_store_epochs (proxy_id, epoch, account_id, seq, created_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(auth.agent_id.to_string())
    .bind(epoch)
    .bind(auth.account_id.to_string())
    .bind(to_i64(event.seq)?)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /v1/agent/sandboxes/state`: the proxy's heartbeat, kept out of the
/// log (only the last one of each proxy) with its signed request, for
/// every device of the person to check (spec §13.12). `409` when it is not
/// under the proxy's current epoch or its `seq` does not grow: the proxy
/// then starts a new epoch rather than reuse a `seq`.
async fn sandbox_state_put(
    State(state): State<AppState>,
    auth: AgentAuth,
) -> ApiResult<StatusCode> {
    // The array form, which serde also reads, is never kept: a device
    // reading the heartbeat's `v` first could not read one.
    if !is_json_object(&auth.body) {
        return Err(ApiError::bad_request("a heartbeat is a JSON object"));
    }
    let req: SandboxHeartbeat = auth.logged_json()?;
    signed_exactly(&auth, PATH_SANDBOX_STATE)?;
    req.check_format().map_err(ApiError::bad_request)?;
    let seq = i64::try_from(req.seq)
        .map_err(|_| ApiError::bad_request(format!("seq must be at most {}", i64::MAX)))?;
    let now = now_ms();
    if req.sent_at_ms > now.saturating_add(CLOCK_SKEW_MS) {
        return Err(ApiError::bad_request(
            "sent_at_ms is ahead of the server's clock",
        ));
    }
    let mut tx = state.db().pool.begin().await?;
    lock_account(&mut tx, auth.account_id).await?;
    proxy_may_act(&mut tx, &auth, now).await?;
    require_proxy_grant(&mut tx, &auth).await?;
    let epoch = req.store_epoch.as_bytes().to_vec();
    if current_epoch(&mut tx, &auth).await?.as_deref() != Some(epoch.as_slice()) {
        return Err(ApiError::conflict(
            "not the epoch of this proxy's last store reset: start a new one",
        ));
    }
    let last = sqlx::query("SELECT store_epoch, seq FROM sandbox_heartbeats WHERE proxy_id = $1")
        .bind(auth.agent_id.to_string())
        .fetch_optional(&mut *tx)
        .await?;
    if let Some(row) = last
        && row.try_get::<Vec<u8>, _>("store_epoch")? == epoch
        && row.try_get::<i64, _>("seq")? >= seq
    {
        return Err(ApiError::conflict(
            "seq does not grow within this epoch: start a new one",
        ));
    }
    let proof = serde_json::to_vec(&auth.proof)
        .map_err(|e| ApiError::Internal(format!("heartbeat proof: {e}")))?;
    sqlx::query(
        "INSERT INTO sandbox_heartbeats \
         (proxy_id, account_id, store_epoch, seq, sent_at_ms, proof, received_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (proxy_id) DO UPDATE SET account_id = excluded.account_id, \
         store_epoch = excluded.store_epoch, seq = excluded.seq, \
         sent_at_ms = excluded.sent_at_ms, proof = excluded.proof, \
         received_at = excluded.received_at",
    )
    .bind(auth.agent_id.to_string())
    .bind(auth.account_id.to_string())
    .bind(epoch)
    .bind(seq)
    .bind(req.sent_at_ms)
    .bind(proof)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The last heartbeat of each proxy of `account` that is still an active
/// agent, for `GET /v1/sync`: a revoked or replaced proxy's last one is
/// not handed out again (its row stays until the account goes).
pub(crate) async fn heartbeats<'e, E>(db: E, account: AccountId) -> ApiResult<Vec<SandboxState>>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    // `a.account_id = $1` is redundant (an agent's heartbeat row carries
    // its own account) and no test can tell it apart; it stays as a guard.
    let rows = sqlx::query(
        "SELECT h.proxy_id, h.proof, h.received_at FROM sandbox_heartbeats h \
         JOIN agents a ON a.id = h.proxy_id \
         WHERE h.account_id = $1 AND a.account_id = $1 AND a.status = $2 \
         ORDER BY h.proxy_id",
    )
    .bind(account.to_string())
    .bind(AgentStatus::Active.as_str())
    .fetch_all(db)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(SandboxState {
                proxy_id: crate::session::parse_id(&row.try_get::<String, _>("proxy_id")?)?,
                proof: serde_json::from_slice(&row.try_get::<Vec<u8>, _>("proof")?)
                    .map_err(|_| ApiError::Internal("corrupt heartbeat".into()))?,
                received_at: row.try_get("received_at")?,
            })
        })
        .collect()
}
