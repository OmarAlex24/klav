//! The enclave's enrollments (ADR 0051 §3.2, §4.3, §6.1): which accounts it
//! serves, under which agent and generation, pinned to which account
//! identity. With the seed, this is all a hand-off carries; everything
//! else (grants, items, sandboxes) the enclave reads again from the
//! server.
//!
//! An enrollment holds no secret, but it names an account and its e-mail:
//! it is never logged, and it has no `Debug`.

use klav_core::ids::{AccountId, AgentId};
use klav_proto::Blob;
use serde::{Deserialize, Serialize};

/// The format of [`SharedState`].
pub const STATE_VERSION: u32 = 1;

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

/// What a hand-off carries besides the seed.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedState {
    /// [`STATE_VERSION`].
    pub v: u32,
    /// Every enrollment.
    pub enrollments: Vec<Enrollment>,
}

impl SharedState {
    /// The JSON a hand-off seals.
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("the state serializes")
    }

    /// Reads a hand-off's state; refuses another version.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let state: Self =
            serde_json::from_slice(bytes).map_err(|_| "the hand-off state is malformed")?;
        if state.v != STATE_VERSION {
            return Err(format!("hand-off state version {}", state.v));
        }
        Ok(state)
    }
}
