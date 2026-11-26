//! The enclave's enrollments and each account's live sandbox state (ADR
//! 0051 §3.2, §4.3, §6.1): which accounts it serves, under which agent and
//! generation, pinned to which account identity, and, from version 2, each
//! account's sandbox store, its heartbeat's epoch and `seq`, and how far
//! it read the person's revocations. With the seed, this is all a hand-off
//! carries; grants, items and profiles the receiver reads again from the
//! server under the same derived keys.
//!
//! An enrollment holds no secret, but it names an account and its e-mail;
//! a store holds the SHA-256 of each sandbox's secret and channel key,
//! never a secret or a key. None of it is logged, and none has a `Debug`.

use klav_core::ids::{AccountId, AgentId};
use klav_proto::Blob;
use serde::{Deserialize, Serialize};

use crate::heartbeat::HeartbeatFile;
use crate::sandboxes::StoreSnapshot;

/// The format of [`SharedState`] a holder writes.
pub const STATE_VERSION: u32 = 2;
/// Layer 3's format: the enrollments only. A joiner still reads it, from a
/// holder of the previous image during a rolling upgrade; its accounts
/// start with empty stores.
pub const STATE_VERSION_ENROLLMENTS_ONLY: u32 = 1;

/// One account the enclave serves.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    /// The account.
    pub account_id: AccountId,
    /// Its hosted proxy agent.
    pub agent_id: AgentId,
    /// The generation of the agent's keys (§3.2).
    pub generation: u32,
    /// The account's e-mail, for the agent's registration.
    pub email: String,
    /// The account identity (kind `0x05`) that signed the enroll request:
    /// the agent refuses any other (ADR 0014, point 4).
    pub account_public_identity: Blob,
    /// When it enrolled (Unix ms).
    pub enrolled_at_ms: u64,
}

/// One account's live sandbox state (version 2).
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountState {
    /// The account; one of the enrollments.
    pub(crate) account_id: AccountId,
    /// Whether its agent ever opened a session (the person approved it):
    /// an enroll with another account identity is refused from then on.
    pub(crate) served: bool,
    /// Its sandbox store and channel keys.
    pub(crate) store: StoreSnapshot,
    /// Its heartbeat; absent for an account never served.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) heartbeat: Option<HeartbeatFile>,
    /// The position in the account's log of the last revocation by the
    /// person its proxy acted on.
    pub(crate) revocation_cursor: u64,
}

/// What a hand-off carries besides the seed.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedState {
    /// [`STATE_VERSION`].
    pub v: u32,
    /// Every enrollment.
    pub enrollments: Vec<Enrollment>,
    /// Each account's live sandbox state (version 2), at most one per
    /// enrollment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) accounts: Vec<AccountState>,
}

impl SharedState {
    /// The JSON a hand-off seals.
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("the state serializes")
    }

    /// Reads a hand-off's state: version 1 or 2, every account's state for
    /// an enrolled account, and none twice.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let state: Self =
            serde_json::from_slice(bytes).map_err(|_| "the hand-off state is malformed")?;
        match state.v {
            STATE_VERSION => {}
            STATE_VERSION_ENROLLMENTS_ONLY if state.accounts.is_empty() => {}
            v => return Err(format!("hand-off state version {v}")),
        }
        let mut seen = std::collections::HashSet::new();
        for account in &state.accounts {
            if !state
                .enrollments
                .iter()
                .any(|e| e.account_id == account.account_id)
                || !seen.insert(account.account_id)
            {
                return Err("the hand-off state is malformed".into());
            }
        }
        Ok(state)
    }

    /// Takes the state of `account` out, if the holder sent one.
    pub(crate) fn take_account(&mut self, account: AccountId) -> Option<AccountState> {
        let at = self.accounts.iter().position(|a| a.account_id == account)?;
        Some(self.accounts.swap_remove(at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enrollment(n: u8) -> String {
        format!(
            r#"{{"account_id":"{}","agent_id":"{}","generation":0,"email":"p{n}@example.com","account_public_identity":"AQ","enrolled_at_ms":1}}"#,
            AccountId::from_bytes([n; 16]),
            AgentId::from_bytes([n + 100; 16])
        )
    }

    /// A joiner reads a layer 3 holder's state (a rolling upgrade from it)
    /// and this layer's; it refuses another version, an account's state
    /// for an account not enrolled, and one account twice.
    #[test]
    fn a_joiner_reads_version_1_and_2_and_nothing_else() {
        let v1 = format!(r#"{{"v":1,"enrollments":[{}]}}"#, enrollment(1));
        let state = SharedState::decode(v1.as_bytes()).expect("v1");
        assert_eq!(state.enrollments.len(), 1);
        assert!(state.accounts.is_empty());

        let account = |n: u8| {
            format!(
                r#"{{"account_id":"{}","served":true,"store":{{"sandboxes":[],"outbox":[],"channels":[],"unconfirmed_thefts":[]}},"revocation_cursor":7}}"#,
                AccountId::from_bytes([n; 16])
            )
        };
        let v2 = format!(
            r#"{{"v":2,"enrollments":[{}],"accounts":[{}]}}"#,
            enrollment(1),
            account(1)
        );
        let mut state = SharedState::decode(v2.as_bytes()).expect("v2");
        let one = state
            .take_account(AccountId::from_bytes([1; 16]))
            .expect("account");
        assert!(one.served);
        assert_eq!(one.revocation_cursor, 7);

        for bad in [
            format!(r#"{{"v":3,"enrollments":[{}]}}"#, enrollment(1)),
            format!(
                r#"{{"v":1,"enrollments":[{}],"accounts":[{}]}}"#,
                enrollment(1),
                account(1)
            ),
            format!(
                r#"{{"v":2,"enrollments":[{}],"accounts":[{}]}}"#,
                enrollment(1),
                account(2)
            ),
            format!(
                r#"{{"v":2,"enrollments":[{}],"accounts":[{},{}]}}"#,
                enrollment(1),
                account(1),
                account(1)
            ),
            format!(r#"{{"v":2,"enrollments":[{}],"extra":1}}"#, enrollment(1)),
        ] {
            assert!(SharedState::decode(bad.as_bytes()).is_err(), "{bad}");
        }
    }
}
