//! Klav Cloud's hosted proxy, from the person's device (ADR 0051 §6.1):
//! today only the account's signature on its enroll request. The rest of
//! the device's side (verifying the attestation before any wrap, `klav
//! proxy use klav`) is ADR 0051's layer 5.

use klav_core::crypto::sign::Signature;
use klav_core::ids::AccountId;
use klav_proto::Blob;

use crate::Unlocked;

/// What `POST /v1/enroll` carries from the account.
pub struct HostedEnroll {
    /// The account.
    pub account_id: AccountId,
    /// The account's public identity (kind `0x05`).
    pub account_public_identity: Blob,
    /// The generation it asks for.
    pub generation: u32,
    /// When it was signed (Unix ms); the request carries this same value.
    pub at_ms: u64,
    /// `tuple("klav/v1/sig/hosted-proxy-enroll", account_id, u32_be(generation), u64_be(at_ms))`.
    pub signature: Signature,
}

impl Unlocked {
    /// Signs the account's request to enroll in Klav Cloud's hosted proxy
    /// at `generation`, at `at_ms` (ADR 0051 §6.1 step 2). It wraps nothing
    /// and grants nothing: the enclave only registers a pending agent,
    /// which the person still approves after verifying its attestation.
    pub fn sign_hosted_proxy_enroll(&self, generation: u32, at_ms: u64) -> HostedEnroll {
        let account_id = self.account.account_id;
        HostedEnroll {
            account_id,
            account_public_identity: Blob::new(self.identity.public().encode().to_vec()),
            generation,
            at_ms,
            signature: klav_core::nitro::sign_enroll(&self.identity, account_id, generation, at_ms),
        }
    }
}
