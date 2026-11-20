//! Pausing agents, from the person's side (ADR 0033 §7, spec §13.9).
//!
//! A pause is account state: the person's device signs it with the account
//! identity and the server enforces it on every signed agent request. The
//! server lists the pauses in effect on every sync (`GET /v1/sync`); this
//! device keeps the ones whose signature checks out, so `klavd` can refuse
//! what it mediates for a paused agent even without asking the server.
//!
//! Pausing needs no presence (a scare must cost one click, ADR 0033 P2);
//! resuming does, and the caller (`klavd`, the CLI) asks for it before
//! calling [`Unlocked::resume_agents`].

use klav_core::crypto::agent::{self, PauseScope, PauseToSign};
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::ids::AgentId;
use klav_proto::Blob;
use klav_proto::agent::{AgentPause, AgentPauses, PauseAgents, PauseState};
use reqwest::Method;

use crate::error::{ClientError, ClientResult};
use crate::session::{Unlocked, now_ms};

/// `$KLAV_HOME/signed-pauses.json`: where `klavd` keeps the signed pauses
/// the last sync left in effect, so it still reports them after a restart
/// (`docs/klavd.md` §3). No secret; removed with the account.
pub const SIGNED_PAUSES_FILE: &str = "signed-pauses.json";

/// Whether `pause` is still in effect at `now` (Unix ms).
#[must_use]
pub fn in_effect(pause: &AgentPause, now: i64) -> bool {
    pause.until == 0 || pause.until > now
}

/// The pause in effect on `agent` at `now`, its own or the account-wide
/// one; with both, the one that lasts longer.
#[must_use]
pub fn holding(pauses: &[AgentPause], agent: AgentId, now: i64) -> Option<&AgentPause> {
    pauses
        .iter()
        .filter(|p| in_effect(p, now) && p.agent_id.is_none_or(|a| a == agent))
        .max_by_key(|p| {
            (
                if p.until == 0 { i64::MAX } else { p.until },
                p.agent_id.is_some(),
            )
        })
}

/// The account-wide pause in effect at `now`.
#[must_use]
pub fn every_agent(pauses: &[AgentPause], now: i64) -> Option<&AgentPause> {
    pauses
        .iter()
        .find(|p| p.agent_id.is_none() && in_effect(p, now))
}

fn scope(agent: Option<AgentId>) -> PauseScope {
    agent.map_or(PauseScope::All, PauseScope::Agent)
}

fn path(agent: Option<AgentId>) -> String {
    match agent {
        Some(id) => format!("/v1/agents/{id}/pause"),
        None => "/v1/agents/pause".to_owned(),
    }
}

/// When to sign a pause again after the scope's latest decision, `last`,
/// at `now` (Unix ms): just after it, if the server still takes that (its
/// ±5 minutes) and the pause has not ended by then.
fn after(last: i64, now: i64, until: i64) -> Option<i64> {
    let at = now.max(last.saturating_add(1));
    (at - now <= crate::audit::CLOCK_SKEW_MS && (until == 0 || until > at)).then_some(at)
}

/// A server older than the pauses has no route for them. The path of
/// every agent answers 405 (it reads as `/v1/agents/{id}` with the ID
/// `pause`, which only has `GET`); the path of one, 404, as for an agent
/// the server does not know. Said so; `status` stays, so `klavd` drops it.
fn unsupported(e: ClientError, agent: Option<AgentId>) -> ClientError {
    match e {
        ClientError::Api {
            status: status @ (404 | 405),
            code,
            current_version,
            ..
        } if status == 405 || agent.is_none() => ClientError::Api {
            status,
            code,
            message: "this server does not support pausing agents: update it".into(),
            current_version,
        },
        ClientError::Api {
            status: 404,
            code,
            current_version,
            ..
        } => ClientError::Api {
            status: 404,
            code,
            message: "no such agent on the server, or the server does not support pausing agents (update it)".into(),
            current_version,
        },
        other => other,
    }
}

impl Unlocked {
    /// The pauses of the account's agents in effect now, as this device
    /// last learned them (sync, or its own decision), signatures checked.
    #[must_use]
    pub fn agent_pauses(&self) -> Vec<AgentPause> {
        let now = now_ms();
        self.agent_pauses
            .iter()
            .filter(|p| in_effect(p, now))
            .cloned()
            .collect()
    }

    /// Takes the pauses this device knew before this session synced (what
    /// `klavd` saved before a restart, or learned in an earlier session),
    /// keeping only the ones this account signed. Only before the first
    /// sync, which replaces them: an unlock without network still knows
    /// them. One that does not check out is dropped silently: it came from
    /// this device's own file, not from the server.
    pub fn remember_pauses(&mut self, known: &[AgentPause]) {
        if self.agent_pauses.is_empty() {
            let mut ignored = Vec::new();
            self.agent_pauses = self.checked_pauses(known, &mut ignored);
        }
    }

    /// Signs a pause (`pause`) or a resume of every agent (`None`) or one,
    /// decided at `at` (Unix ms), until `until` (`0`: no end; always `0`
    /// in a resume). Nothing is sent.
    #[must_use]
    pub fn sign_pause(
        &self,
        agent: Option<AgentId>,
        pause: bool,
        at: i64,
        until: i64,
    ) -> PauseAgents {
        let until = if pause { until.max(0) } else { 0 };
        let signature = agent::sign_pause(
            &self.identity,
            &PauseToSign {
                account: self.account.account_id,
                scope: scope(agent),
                pause,
                at_ms: u64::try_from(at).unwrap_or(0),
                until_ms: u64::try_from(until).unwrap_or(0),
            },
        );
        PauseAgents {
            state: if pause {
                PauseState::Pause
            } else {
                PauseState::Resume
            },
            at,
            until,
            signature: Blob::new(signature.to_bytes().to_vec()),
        }
    }

    /// Sends a signed decision ([`Self::sign_pause`]) and keeps the pauses
    /// the server says are in effect afterwards.
    pub async fn send_pause(
        &mut self,
        agent: Option<AgentId>,
        decision: &PauseAgents,
    ) -> ClientResult<Vec<AgentPause>> {
        let answer: AgentPauses = self
            .send_json(Method::POST, &path(agent), decision)
            .await
            .map_err(|e| unsupported(e, agent))?;
        let mut notices = Vec::new();
        self.agent_pauses = self.checked_pauses(&answer.pauses, &mut notices);
        self.warnings.extend(notices);
        Ok(self.agent_pauses())
    }

    /// Pauses every agent (`None`) or one, now, until `until` (Unix ms;
    /// `0`: until the person resumes). No presence needed (ADR 0033 P2).
    ///
    /// When the server already has a decision on the scope dated at or
    /// after now (another device's clock runs ahead), the pause is signed
    /// once more just after it, if that is still within the server's
    /// ±5 minutes ([`ClientError::LaterPause`] otherwise): a pause is the
    /// safe direction, and the person meant it now.
    pub async fn pause_agents(
        &mut self,
        agent: Option<AgentId>,
        until: i64,
    ) -> ClientResult<Vec<AgentPause>> {
        let decision = self.sign_pause(agent, true, now_ms(), until);
        let last = match self.send_pause(agent, &decision).await {
            Err(ClientError::LaterPause(last)) => last,
            other => return other,
        };
        let now = now_ms();
        let Some(at) = after(last, now, until) else {
            return Err(ClientError::LaterPause(last));
        };
        let again = self.sign_pause(agent, true, at, until);
        match self.send_pause(agent, &again).await {
            // The server's clock disagrees with ours on the ±5 minutes.
            Err(ClientError::Api { status: 400, .. }) => Err(ClientError::LaterPause(last)),
            other => other,
        }
    }

    /// Resumes every agent (`None`) or one. The caller asks for presence
    /// first (Touch ID, or the master password, ADR 0033 P2). Resuming
    /// every agent does not lift the pauses of single agents.
    ///
    /// Never signed again after a later decision (unlike
    /// [`Self::pause_agents`]): a resume dated after someone else's pause
    /// would lift it.
    pub async fn resume_agents(&mut self, agent: Option<AgentId>) -> ClientResult<Vec<AgentPause>> {
        let decision = self.sign_pause(agent, false, now_ms(), 0);
        self.send_pause(agent, &decision).await
    }

    /// The pauses in `listed` whose signature by this account checks out.
    /// A pause that does not is dropped with a notice: the server cannot
    /// make this device refuse an agent the person did not pause.
    pub(crate) fn checked_pauses(
        &self,
        listed: &[AgentPause],
        notices: &mut Vec<String>,
    ) -> Vec<AgentPause> {
        listed
            .iter()
            .filter(|p| {
                let ok = <[u8; SIGNATURE_LEN]>::try_from(p.signature.as_bytes())
                    .ok()
                    .is_some_and(|sig| {
                        agent::verify_pause(
                            self.identity.public(),
                            &PauseToSign {
                                account: self.account.account_id,
                                scope: scope(p.agent_id),
                                pause: true,
                                at_ms: u64::try_from(p.at).unwrap_or(0),
                                until_ms: u64::try_from(p.until).unwrap_or(0),
                            },
                            &Signature::from_bytes(sig),
                        )
                        .is_ok()
                    });
                if !ok {
                    notices.push(format!(
                        "the server lists a pause of {} that this account did not sign; ignoring it",
                        p.agent_id
                            .map_or_else(|| "every agent".to_owned(), |a| format!("agent {a}"))
                    ));
                }
                ok
            })
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pause(agent: Option<AgentId>, until: i64) -> AgentPause {
        AgentPause {
            agent_id: agent,
            at: 1,
            until,
            signature: Blob::new(vec![0; 64]),
        }
    }

    #[test]
    fn the_pause_holding_an_agent() {
        let a = AgentId::generate();
        let b = AgentId::generate();
        let pauses = [pause(Some(b), 0), pause(None, 100)];
        assert_eq!(holding(&pauses, a, 50).map(|p| p.agent_id), Some(None));
        // Ended: nothing holds `a`; `b` keeps its own.
        assert!(holding(&pauses, a, 100).is_none());
        assert_eq!(holding(&pauses, b, 100).map(|p| p.agent_id), Some(Some(b)));
        // `b`'s own pause (no end) outlasts the account-wide hour.
        assert_eq!(holding(&pauses, b, 50).map(|p| p.agent_id), Some(Some(b)));
        assert!(every_agent(&pauses, 50).is_some());
        assert!(every_agent(&pauses, 100).is_none());
    }

    #[test]
    fn a_late_pause_is_signed_again_only_within_the_servers_minutes() {
        let now = 1_000_000_000;
        // The last decision is in the past: now will do.
        assert_eq!(after(now - 10, now, 0), Some(now));
        // Ahead of our clock: just after it, up to 5 minutes ahead.
        assert_eq!(after(now + 60_000, now, 0), Some(now + 60_001));
        let edge = now + crate::audit::CLOCK_SKEW_MS;
        assert_eq!(after(edge - 1, now, 0), Some(edge));
        assert_eq!(after(edge, now, 0), None);
        // A pause that would be over by then is not sent again.
        assert_eq!(after(now + 60_000, now, now + 60_001), None);
        assert_eq!(after(now + 60_000, now, now + 60_002), Some(now + 60_001));
        assert_eq!(after(i64::MAX, now, 0), None);
    }

    #[test]
    fn an_older_server_is_told_apart_from_a_refusal() {
        let api = |status, code| ClientError::Api {
            status,
            code,
            message: "not found".into(),
            current_version: None,
        };
        let message = |e: ClientError| match e {
            ClientError::Api { message, .. } => message,
            other => panic!("{other:?}"),
        };
        let old = message(unsupported(api(405, None), None));
        assert!(old.contains("does not support pausing"), "{old}");
        let none = message(unsupported(
            api(404, Some(klav_proto::ErrorCode::NotFound)),
            Some(AgentId::generate()),
        ));
        assert!(none.contains("no such agent"), "{none}");
        // Anything else is left as it is.
        let refused = message(unsupported(
            api(400, Some(klav_proto::ErrorCode::BadRequest)),
            None,
        ));
        assert_eq!(refused, "not found");
    }
}
