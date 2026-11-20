//! Appending to the audit log (design §6, spec §13.7).
//!
//! Events are appended after the action they record is decided: an agent
//! never receives an item's details unless its access was logged first.
//!
//! Appends to one account's chain are serialised by the account row's lock
//! (layer 07 of the 2026-11 round): each one waits its turn instead of
//! racing for the next `seq` and giving up after a few attempts, which left
//! a committed action without its event when many happened at once. The
//! `(account_id, seq)` primary key still guards the chain.
//!
//! The event of a write is appended in the write's own transaction: both
//! are stored, or neither. That covers every person's write, the agent's
//! writes that log in themselves (a task asked for or ended, a request
//! for approval) and a task's expiry, which the sweep ends and logs in one
//! transaction per account. Each such transaction takes the account lock
//! first; one that also writes to a vault takes the vault lock after it,
//! the order every path that holds both uses.

use klav_core::crypto::audit::{GENESIS, chain_hash};
use klav_core::ids::AccountId;
use klav_core::policy::Permission;
use klav_proto::audit::{AgentRoute, AuditEvent, signed_near};
use sqlx::Row;

use crate::db::now_ms;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Agent uses of secrets in one minute that raise a `burst` alert.
const BURST_PER_MINUTE: i64 = 20;

/// Permissions that touch a secret value.
pub(crate) fn uses_secret(permission: Permission) -> bool {
    matches!(
        permission,
        Permission::Fill | Permission::Inject | Permission::Totp | Permission::Reveal
    )
}

/// Alerts for an agent's access: first use of this item's secrets by this
/// agent, and bursts.
pub(crate) async fn alerts(
    state: &AppState,
    event: &AuditEvent,
    now: i64,
) -> ApiResult<Vec<String>> {
    let mut alerts = Vec::new();
    let (Some(agent), Some(permission)) = (event.agent_id, event.permission) else {
        return Ok(alerts);
    };
    if event.outcome.as_deref() == Some("deny") {
        alerts.push("denied".to_owned());
    }
    if event.action != "agent.access"
        || !uses_secret(permission)
        || event.outcome.as_deref() != Some("allow")
    {
        return Ok(alerts);
    }
    if let Some(item) = event.item_id
        && !used_before(state, agent, item).await?
    {
        alerts.push("first_use".to_owned());
    }
    let recent: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE agent_id = $1 AND action = 'agent.access' \
         AND at > $2",
    )
    .bind(agent.to_string())
    .bind(now - 60_000)
    .fetch_one(&state.db().pool)
    .await?;
    if recent >= BURST_PER_MINUTE {
        alerts.push("burst".to_owned());
    }
    Ok(alerts)
}

/// Whether an earlier allowed secret access of `agent` to `item` exists.
async fn used_before(
    state: &AppState,
    agent: klav_core::ids::AgentId,
    item: klav_core::ids::ItemId,
) -> ApiResult<bool> {
    let rows: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT event FROM audit_events WHERE agent_id = $1 AND item_id = $2 \
         AND action = 'agent.access'",
    )
    .bind(agent.to_string())
    .bind(item.to_string())
    .fetch_all(&state.db().pool)
    .await?;
    Ok(rows.iter().any(|bytes| {
        serde_json::from_slice::<AuditEvent>(bytes).is_ok_and(|e| {
            e.outcome.as_deref() == Some("allow") && e.permission.is_some_and(uses_secret)
        })
    }))
}

/// An agent's event against its signed request, as the log verifier checks
/// it: the action's route, and the signed time near the event's `at`.
fn check_agent_proof(event: &AuditEvent) -> ApiResult<()> {
    let Some(proof) = &event.agent_proof else {
        return Ok(());
    };
    let route = AgentRoute::of(event).ok_or_else(|| {
        ApiError::Internal(format!(
            "an agent's signed request on {}, which no agent signs",
            event.action
        ))
    })?;
    if !route.matches(event, proof) {
        return Err(ApiError::bad_request(
            "the signed request is not this action's route as the log checks it: sign the path without a query string or escapes",
        ));
    }
    if !signed_near(proof.timestamp, event.at) {
        return Err(ApiError::Unauthorized);
    }
    Ok(())
}

/// Appends `event` to the account's chain; fills in `seq`, `at` and the
/// alerts. Returns the stored event.
pub(crate) async fn append(
    state: &AppState,
    account: AccountId,
    mut event: AuditEvent,
) -> ApiResult<AuditEvent> {
    let now = now_ms();
    let mut extra = alerts(state, &event, now).await?;
    event.alerts.append(&mut extra);
    let mut tx = state.db().pool.begin().await?;
    append_in(&mut tx, account, &mut event, now).await?;
    tx.commit().await?;
    Ok(event)
}

/// Appends `event` inside `tx` (which the caller commits), at time `now`.
/// Takes the account's lock first, so a write in the same transaction
/// (a pause, ADR 0033 §7) lands in the chain in the same order as in the
/// database.
///
/// An agent's event, whatever its outcome, is refused here with
/// `403 forbidden` if the agent is no longer active (a revocation committed
/// while its request waited for the lock, [`crate::agentauth::still_active`]),
/// so the chain never shows an agent's request after its `agent.revoked`,
/// and a write in the same transaction is rolled back with it.
///
/// An allowed agent action is refused here with `403 agents_paused` if the
/// agent is paused, and with `403 account_deleting` if the person asked to
/// delete the account: the checks run under the lock a pause and a
/// deletion take to be written, so the chain never shows an allowed action
/// inside a pause (ADR 0033 §7.6), and no request in flight gets past a
/// deletion (ADR 0037 §3).
///
/// An agent's event is checked first against its signed request with the
/// log verifier's own rules (`klav_proto::audit`): its route (`400`) and
/// its signed time within the window of `now`, the time it is logged at
/// (`401`, as a stale request). Nothing is written then: the server never
/// logs a proof the person's devices would refuse.
pub(crate) async fn append_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    account: AccountId,
    event: &mut AuditEvent,
    now: i64,
) -> ApiResult<()> {
    event.at = now;
    check_agent_proof(event)?;
    // The account's lock: also makes the SQLite transaction a writer before
    // it reads the head, so two appends never read the same one.
    let locked = sqlx::query("UPDATE accounts SET updated_at = updated_at WHERE id = $1")
        .bind(account.to_string())
        .execute(&mut **tx)
        .await?;
    if locked.rows_affected() != 1 {
        return Err(ApiError::Internal(
            "audit event for an unknown account".into(),
        ));
    }
    if event.agent_proof.is_some()
        && let Some(agent) = event.agent_id
    {
        // Every agent event, any outcome: the agent's status under the
        // lock its revocation takes to be written.
        crate::agentauth::still_active(&mut **tx, agent, account, now).await?;
        if event.outcome.as_deref() == Some("allow") {
            crate::deletion::refuse_if_deleting(&mut **tx, account).await?;
            crate::pause::refuse_if_paused(&mut **tx, account, agent, now).await?;
        }
    }
    let last = sqlx::query(
        "SELECT seq, hash FROM audit_events WHERE account_id = $1 \
         ORDER BY seq DESC LIMIT 1",
    )
    .bind(account.to_string())
    .fetch_optional(&mut **tx)
    .await?;
    let (seq, previous) = match last {
        Some(row) => {
            let hash: Vec<u8> = row.try_get("hash")?;
            let previous: [u8; 32] = hash
                .try_into()
                .map_err(|_| ApiError::Internal("corrupt audit hash".into()))?;
            (row.try_get::<i64, _>("seq")? + 1, previous)
        }
        None => (1, GENESIS),
    };
    event.seq = u64::try_from(seq).unwrap_or(0);
    let bytes =
        serde_json::to_vec(&*event).map_err(|e| ApiError::Internal(format!("audit event: {e}")))?;
    let hash = chain_hash(event.seq, &previous, &bytes);
    sqlx::query(
        "INSERT INTO audit_events (account_id, seq, event, hash, at, agent_id, item_id, action) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(account.to_string())
    .bind(seq)
    .bind(bytes)
    .bind(hash.to_vec())
    .bind(now)
    .bind(event.agent_id.map(|a| a.to_string()))
    .bind(event.item_id.map(|i| i.to_string()))
    .bind(&event.action)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use klav_core::ids::{AgentId, ItemId};
    use klav_proto::Blob;
    use klav_proto::audit::{ActorKind, AgentProof, CLOCK_SKEW_MS};

    const AT: i64 = 1_800_000_000_000;

    fn signed(action: &str, method: &str, path: &str, timestamp: i64) -> AuditEvent {
        let mut e = AuditEvent::new(ActorKind::Agent, action);
        e.agent_id = Some(AgentId::generate());
        e.at = AT;
        e.agent_proof = Some(AgentProof {
            method: method.into(),
            path: path.into(),
            timestamp,
            nonce: Blob::new(vec![0; 16]),
            body_digest: Blob::new(vec![0; 32]),
            body: None,
            signature: Blob::new(vec![0; 64]),
        });
        e
    }

    /// The check `append_in` runs before it writes: what the extractor
    /// refuses earlier is refused here too, should a handler take long
    /// enough to carry a request out of the window, or a route get past it.
    #[test]
    fn an_agent_event_is_checked_as_the_log_verifier_checks_it() {
        let ok = signed("agent.access", "POST", "/v1/agent/access", AT);
        assert!(check_agent_proof(&ok).is_ok());
        for at in [AT - CLOCK_SKEW_MS, AT + CLOCK_SKEW_MS] {
            assert!(
                check_agent_proof(&signed("agent.access", "POST", "/v1/agent/access", at)).is_ok()
            );
        }
        // The person's own events carry no proof.
        assert!(check_agent_proof(&AuditEvent::new(ActorKind::Person, "item.created")).is_ok());

        for path in [
            "/v1/agent/access?x=1",
            "/v1/agent/access?",
            "/v1/agent/access/",
        ] {
            assert!(
                matches!(
                    check_agent_proof(&signed("agent.access", "POST", path, AT)),
                    Err(ApiError::BadRequest(_))
                ),
                "{path}"
            );
        }
        let item = ItemId::generate();
        let mut escaped = signed(
            "agent.update",
            "PUT",
            &format!("/v1/agent/items/%{item}"),
            AT,
        );
        escaped.item_id = Some(item);
        assert!(matches!(
            check_agent_proof(&escaped),
            Err(ApiError::BadRequest(_))
        ));

        for at in [AT - CLOCK_SKEW_MS - 1, AT + CLOCK_SKEW_MS + 1] {
            assert!(matches!(
                check_agent_proof(&signed("agent.access", "POST", "/v1/agent/access", at)),
                Err(ApiError::Unauthorized)
            ));
        }
        // A proof on an action no agent signs is the server's own mistake.
        assert!(matches!(
            check_agent_proof(&signed("item.created", "POST", "/v1/agent/items", AT)),
            Err(ApiError::Internal(_))
        ));
    }

    /// A proxy's new store (#353, spec §13.12) is in the shared table: no
    /// route logs it yet, and when one does, a well-formed reset must not
    /// be the `500` of an action no agent signs.
    #[test]
    fn a_store_reset_is_an_agent_route() {
        use klav_proto::sandbox::{PATH_SANDBOX_STATE, PATH_STORE_RESET};
        let ok = signed("sandbox.store_reset", "POST", PATH_STORE_RESET, AT);
        assert!(check_agent_proof(&ok).is_ok());
        // Another route, a heartbeat's included, is not a reset's.
        for (method, path) in [
            ("PUT", PATH_STORE_RESET),
            ("PUT", PATH_SANDBOX_STATE),
            ("POST", "/v1/agent/sandboxes"),
        ] {
            assert!(
                matches!(
                    check_agent_proof(&signed("sandbox.store_reset", method, path, AT)),
                    Err(ApiError::BadRequest(_))
                ),
                "{method} {path}"
            );
        }
    }
}
