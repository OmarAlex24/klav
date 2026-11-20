//! Authentication of agent requests (spec §13.3, threat T25).
//!
//! Agents carry no bearer token. Every request is signed with the agent's
//! Ed25519 key over `method ‖ path ‖ timestamp ‖ nonce ‖ SHA-256(body)`, sent
//! in the `Klav-Agent`, `Klav-Timestamp`, `Klav-Nonce` and
//! `Klav-Signature` headers. The extractor:
//!
//! 1. rejects timestamps outside ±[`CLOCK_SKEW_MS`] before anything else,
//!    and a write whose signed path has a query string or an escape (`400`:
//!    its event would carry a route the log verifier refuses);
//! 2. reads the whole body (bounded by the JSON body limit) to hash it,
//!    then checks the timestamp again: a slow body never carries a request
//!    out of the window its event is checked against;
//! 3. verifies the signature with the agent's registered public identity;
//! 4. stores the nonce, and rejects the request if it was already used
//!    (before the per-agent rate limit: a request refused with `429` has
//!    still spent its nonce, so it cannot be replayed later);
//! 5. applies the per-agent rate limit;
//! 6. refuses every route but `/v1/agent/me` to agents that are not active
//!    (pending, denied or revoked), to every agent of an account whose
//!    deletion the person asked for (`403 account_deleting`, ADR 0037 §3),
//!    and to active agents the person paused (`403 agents_paused`, ADR 0033
//!    §7.4).
//!
//! The path is the one the client sent (`OriginalUri`), so a reverse proxy
//! must not rewrite `/v1/agent…` paths.

use axum::body::Bytes;
use axum::extract::{FromRequest, OriginalUri, Request};
use axum::http::Method;
use klav_core::crypto::agent::{self, NONCE_LEN, SignedRequest};
use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::ids::{AccountId, AgentId};
use klav_proto::Blob;
use klav_proto::agent::{
    AgentStatus, HEADER_AGENT, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP,
};
use klav_proto::audit::{AgentProof, MAX_PROOF_BODY};
use serde::de::DeserializeOwned;
use sqlx::Row;

use crate::db::now_ms;
use crate::error::{ApiError, ApiResult};
use crate::ratelimit::Quota;
use crate::session::parse_id;
use crate::state::AppState;

/// Accepted difference between the agent's clock and the server's: the
/// log verifier's window, from the same constant.
pub(crate) const CLOCK_SKEW_MS: i64 = klav_proto::audit::CLOCK_SKEW_MS;
/// Nonces are remembered for twice the skew window plus a margin: a request
/// older than that is rejected by its timestamp anyway. The margin covers
/// the clock reads (the check and the expiry use different `now`s) and the
/// purge running in between.
const NONCE_TTL_MS: i64 = 2 * CLOCK_SKEW_MS + 1000;
/// The only agent route open to pending, denied or revoked agents.
pub(crate) const ME_PATH: &str = "/v1/agent/me";
/// `last_seen_at` is only written when older than this.
const LAST_SEEN_GRANULARITY_MS: i64 = 60_000;

/// A verified agent request.
pub(crate) struct AgentAuth {
    pub(crate) agent_id: AgentId,
    pub(crate) account_id: AccountId,
    pub(crate) name: String,
    pub(crate) status: AgentStatus,
    /// The request body (already covered by the signature).
    pub(crate) body: Bytes,
    /// The signed request, for the audit log.
    pub(crate) proof: AgentProof,
}

impl AgentAuth {
    /// Parses the (signed) body as JSON.
    pub(crate) fn json<T: DeserializeOwned>(&self) -> ApiResult<T> {
        serde_json::from_slice(&self.body)
            .map_err(|e| ApiError::bad_request(format!("invalid body: {e}")))
    }

    /// [`Self::json`] for a request whose event must keep its body, so the
    /// person can check what the agent signed (ADR 0030 §4.2): bodies over
    /// [`MAX_PROOF_BODY`] are refused.
    pub(crate) fn logged_json<T: DeserializeOwned>(&self) -> ApiResult<T> {
        if self.body.len() > MAX_PROOF_BODY {
            return Err(ApiError::bad_request(format!(
                "this request is logged with its body: at most {MAX_PROOF_BODY} bytes"
            )));
        }
        self.json()
    }
}

fn header<'a>(req: &'a Request, name: &str) -> ApiResult<&'a str> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized)
}

fn fixed<const N: usize>(text: &str) -> ApiResult<[u8; N]> {
    Blob::from_text(text)
        .and_then(|b| b.into_bytes().try_into().ok())
        .ok_or(ApiError::Unauthorized)
}

/// The extractor's status check again, for an agent request that is about
/// to write and log: the caller holds the account's lock. The extractor
/// reads the status before that lock, so an agent the person revoked in
/// between would still write and log after `agent.revoked`. The
/// revocation takes the account's lock before it writes the agent's row,
/// so with the lock held this read sees it, and the status cannot change
/// until the caller's transaction ends. Anything but `active` (pending,
/// denied, revoked, a lapsed pending request) gets the extractor's own
/// answer, `403 forbidden`; an agent this account does not have, its
/// `401`; a status this server does not know is a corrupt row, `500`, as
/// in the extractor. `audit::append_in` runs it for every agent event, so
/// nothing an agent asks for is logged after its revocation.
pub(crate) async fn still_active<'e, E>(
    exec: E,
    agent: AgentId,
    account: AccountId,
    now: i64,
) -> ApiResult<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    let row =
        sqlx::query("SELECT status, expires_at FROM agents WHERE id = $1 AND account_id = $2")
            .bind(agent.to_string())
            .bind(account.to_string())
            .fetch_optional(exec)
            .await?
            // The extractor's answer for an agent it does not find.
            .ok_or(ApiError::Unauthorized)?;
    let status = effective_status(
        &row.try_get::<String, _>("status")?,
        row.try_get("expires_at")?,
        now,
    )?;
    if status == AgentStatus::Active {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// Status of a stored agent, with a lapsed pending request read as denied.
pub(crate) fn effective_status(status: &str, expires_at: i64, now: i64) -> ApiResult<AgentStatus> {
    let status = AgentStatus::parse(status)
        .ok_or_else(|| ApiError::Internal("corrupt agent status".into()))?;
    Ok(match status {
        AgentStatus::Pending if expires_at <= now => AgentStatus::Denied,
        other => other,
    })
}

impl FromRequest<AppState> for AgentAuth {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, ApiError> {
        let agent_id: AgentId = header(&req, HEADER_AGENT)?
            .parse()
            .map_err(|_| ApiError::Unauthorized)?;
        let timestamp: i64 = header(&req, HEADER_TIMESTAMP)?
            .parse()
            .map_err(|_| ApiError::Unauthorized)?;
        let nonce: [u8; NONCE_LEN] = fixed(header(&req, HEADER_NONCE)?)?;
        let signature =
            Signature::from_bytes(fixed::<SIGNATURE_LEN>(header(&req, HEADER_SIGNATURE)?)?);
        let method: Method = req.method().clone();
        let path = req
            .extensions()
            .get::<OriginalUri>()
            .map_or_else(|| req.uri().clone(), |o| o.0.clone());
        let path = path
            .path_and_query()
            .map_or_else(|| path.path().to_owned(), |pq| pq.as_str().to_owned());
        // Cheap checks first: stale or future requests never cost a
        // database lookup or a signature verification.
        let now = now_ms();
        // `abs_diff`: a timestamp near `i64::MIN` must not overflow.
        if now.abs_diff(timestamp) > CLOCK_SKEW_MS.unsigned_abs() {
            return Err(ApiError::Unauthorized);
        }
        // Every agent route that is not a read is logged with its signed
        // request, and the log verifier takes the route exactly as signed
        // (`AgentRoute::matches`): a query string or an escaped ID would
        // break the person's log for good. Refused before the body or the
        // nonce, so nothing is done or logged. Reads keep their queries.
        if method != Method::GET && method != Method::HEAD && path.contains(['?', '%']) {
            return Err(ApiError::bad_request(
                "a signed agent write is logged with its route as signed: no query string or percent-escape in the path",
            ));
        }
        let limit = state.config().limits.max_json_body_bytes;
        let body = axum::body::to_bytes(req.into_body(), limit)
            .await
            .map_err(|_| ApiError::PayloadTooLarge)?;
        // Again once the body is in: one held back must not take the
        // request past the window its event is checked against.
        // `audit::append_in` checks the time the event is logged at.
        let now = now_ms();
        if now.abs_diff(timestamp) > CLOCK_SKEW_MS.unsigned_abs() {
            return Err(ApiError::Unauthorized);
        }

        let row = sqlx::query(
            "SELECT account_id, name, public_identity, status, expires_at, last_seen_at \
             FROM agents WHERE id = $1",
        )
        .bind(agent_id.to_string())
        .fetch_optional(&state.db().pool)
        .await?
        .ok_or(ApiError::Unauthorized)?;
        let public = PublicIdentity::decode(&row.try_get::<Vec<u8>, _>("public_identity")?)
            .map_err(|_| ApiError::Internal("corrupt agent identity".into()))?;
        let digest = agent::body_digest(&body);
        let signed = SignedRequest {
            agent: agent_id,
            method: method.as_str(),
            path: &path,
            timestamp_ms: u64::try_from(timestamp).map_err(|_| ApiError::Unauthorized)?,
            nonce: &nonce,
            body_digest: &digest,
        };
        agent::verify_request(&public, &signed, &signature).map_err(|_| ApiError::Unauthorized)?;

        // The nonce first: a signed request refused by the rate limit
        // below has used it up and cannot be replayed once tokens refill.
        remember_nonce(state, agent_id, &nonce, now).await?;
        let rl = &state.config().rate_limit;
        state.limiter().enforce(
            &format!("agent:{agent_id}"),
            Quota {
                per_minute: rl.account_per_minute,
                burst: rl.account_burst,
            },
        )?;

        let last_seen: Option<i64> = row.try_get("last_seen_at")?;
        if last_seen.is_none_or(|t| now - t > LAST_SEEN_GRANULARITY_MS) {
            sqlx::query("UPDATE agents SET last_seen_at = $1 WHERE id = $2")
                .bind(now)
                .bind(agent_id.to_string())
                .execute(&state.db().pool)
                .await?;
        }
        let status = effective_status(
            &row.try_get::<String, _>("status")?,
            row.try_get("expires_at")?,
            now,
        )?;
        // Revocation takes effect here, on the next request: only `me`
        // (which tells the agent its state) works for an agent that is not
        // active. A request already past this point is checked again when
        // its event is logged, under the account's lock ([`still_active`]
        // in `audit::append_in`).
        if status != AgentStatus::Active && path != ME_PATH {
            return Err(ApiError::Forbidden);
        }
        let account_id: AccountId = parse_id(&row.try_get::<String, _>("account_id")?)?;
        // So do a deletion the person asked for and a pause, with their
        // reasons (the deletion first: it is the one that does not end by
        // itself). An allowed action is checked again when it is logged,
        // under the account's lock (`audit::append_in`).
        if status == AgentStatus::Active && path != ME_PATH {
            crate::deletion::refuse_if_deleting(&state.db().pool, account_id).await?;
            crate::pause::refuse_if_paused(&state.db().pool, account_id, agent_id, now).await?;
        }
        let proof = AgentProof {
            method: method.as_str().to_owned(),
            path: path.clone(),
            timestamp,
            nonce: Blob::new(nonce.to_vec()),
            body_digest: Blob::new(digest.to_vec()),
            body: (body.len() <= MAX_PROOF_BODY).then(|| Blob::new(body.to_vec())),
            signature: Blob::new(signature.to_bytes().to_vec()),
        };
        Ok(Self {
            agent_id,
            account_id,
            name: row.try_get("name")?,
            status,
            body,
            proof,
        })
    }
}

/// Stores a nonce; a second use of the same nonce is a replay (401).
async fn remember_nonce(
    state: &AppState,
    agent_id: AgentId,
    nonce: &[u8; NONCE_LEN],
    now: i64,
) -> ApiResult<()> {
    let inserted =
        sqlx::query("INSERT INTO agent_nonces (agent_id, nonce, expires_at) VALUES ($1, $2, $3)")
            .bind(agent_id.to_string())
            .bind(Blob::new(nonce.to_vec()).to_text())
            .bind(now + NONCE_TTL_MS)
            .execute(&state.db().pool)
            .await;
    match inserted {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            tracing::warn!(agent = %agent_id, "replayed agent request rejected");
            Err(ApiError::Unauthorized)
        }
        Err(e) => Err(e.into()),
    }
}

/// Forgets nonces whose request could no longer pass the time check.
pub(crate) async fn purge_nonces(state: &AppState, now: i64) -> ApiResult<u64> {
    let done = sqlx::query("DELETE FROM agent_nonces WHERE expires_at <= $1")
        .bind(now)
        .execute(&state.db().pool)
        .await?;
    Ok(done.rows_affected())
}
