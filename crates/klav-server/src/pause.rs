//! Pauses of agents (ADR 0033 §7, spec §13.9).
//!
//! A pause is account state, signed by the account: the last decision per
//! scope (`all` or one agent) is stored in `agent_pauses`. While one is in
//! effect, every signed request of the agents it covers is refused with
//! `403 agents_paused`, except `GET /v1/agent/me`, which says why. The
//! check runs twice: in the request extractor (cheap, before any work) and
//! when an allowed agent action is appended to the audit log, under the
//! account's lock, the same one a pause takes to be written. A request in
//! flight when the pause lands is therefore refused before it is logged as
//! allowed, and the chain never shows an allowed agent action inside a
//! pause.

use klav_core::ids::{AccountId, AgentId};
use klav_proto::Blob;
use klav_proto::agent::{AgentPause, AgentPaused, PauseScope};
use sqlx::Row;

use crate::error::{ApiError, ApiResult};
use crate::session::parse_id;

/// `scope` of the account-wide pause.
pub(crate) const SCOPE_ALL: &str = "all";
/// `state` of a pause.
pub(crate) const STATE_PAUSE: &str = "pause";
/// `state` of a resume.
pub(crate) const STATE_RESUME: &str = "resume";

/// Every pause of `account` in effect at `now`, the account-wide one
/// first.
pub(crate) async fn in_effect<'e, E>(
    exec: E,
    account: AccountId,
    now: i64,
) -> ApiResult<Vec<AgentPause>>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    let rows = sqlx::query(
        "SELECT scope, at_ms, until_ms, signature FROM agent_pauses \
         WHERE account_id = $1 AND state = $2 AND (until_ms = 0 OR until_ms > $3) \
         ORDER BY scope",
    )
    .bind(account.to_string())
    .bind(STATE_PAUSE)
    .bind(now)
    .fetch_all(exec)
    .await?;
    let mut pauses = rows
        .iter()
        .map(|row| {
            let scope: String = row.try_get("scope")?;
            Ok(AgentPause {
                agent_id: if scope == SCOPE_ALL {
                    None
                } else {
                    Some(parse_id(&scope)?)
                },
                at: row.try_get("at_ms")?,
                until: row.try_get("until_ms")?,
                signature: Blob::new(row.try_get("signature")?),
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    pauses.sort_by_key(|p| p.agent_id.is_some());
    Ok(pauses)
}

/// The pause in effect on `agent` among `pauses`: its own or the
/// account-wide one. With both, the one that lasts longer (no end beats
/// any end), so the agent is told when it can work again.
pub(crate) fn for_agent(pauses: &[AgentPause], agent: AgentId) -> Option<AgentPaused> {
    let end = |p: &AgentPause| if p.until == 0 { i64::MAX } else { p.until };
    pauses
        .iter()
        .filter(|p| p.agent_id.is_none_or(|a| a == agent))
        .max_by_key(|p| (end(p), p.agent_id.is_some()))
        .map(|p| AgentPaused {
            scope: if p.agent_id.is_some() {
                PauseScope::Agent
            } else {
                PauseScope::All
            },
            since: p.at,
            until: (p.until != 0).then_some(p.until),
        })
}

/// The pause in effect on `agent` at `now`, if any.
pub(crate) async fn on_agent<'e, E>(
    exec: E,
    account: AccountId,
    agent: AgentId,
    now: i64,
) -> ApiResult<Option<AgentPaused>>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    Ok(for_agent(&in_effect(exec, account, now).await?, agent))
}

/// Refuses with `403 agents_paused` if `agent` is paused at `now`.
pub(crate) async fn refuse_if_paused<'e, E>(
    exec: E,
    account: AccountId,
    agent: AgentId,
    now: i64,
) -> ApiResult<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    match on_agent(exec, account, agent, now).await? {
        Some(paused) => Err(ApiError::Paused(paused)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pause(agent: Option<AgentId>, at: i64, until: i64) -> AgentPause {
        AgentPause {
            agent_id: agent,
            at,
            until,
            signature: Blob::new(vec![0; 64]),
        }
    }

    #[test]
    fn the_longer_pause_is_the_one_an_agent_is_told() {
        let a = AgentId::generate();
        let b = AgentId::generate();
        assert!(for_agent(&[], a).is_none());
        assert!(for_agent(&[pause(Some(b), 1, 0)], a).is_none());
        let all = for_agent(&[pause(None, 1, 50)], a).unwrap();
        assert_eq!(all.scope, PauseScope::All);
        assert_eq!(all.until, Some(50));
        // Its own pause, with no end, outlasts the account-wide hour.
        let mine = for_agent(&[pause(None, 1, 50), pause(Some(a), 2, 0)], a).unwrap();
        assert_eq!(mine.scope, PauseScope::Agent);
        assert_eq!((mine.since, mine.until), (2, None));
        // The account-wide one with no end outlasts its own hour.
        let all = for_agent(&[pause(None, 1, 0), pause(Some(a), 2, 50)], a).unwrap();
        assert_eq!(all.scope, PauseScope::All);
        assert_eq!(all.until, None);
    }
}
