//! The mark the hosted proxy puts on the agent registrations it sends to
//! the server, and how the server checks it (spec §15.8, ADR 0051 §8).
//!
//! When an account enrolls in Klav Cloud's hosted proxy, the enclave
//! registers that account's derived proxy agent through the ordinary
//! `POST /v1/agents/register`, and signs the registration with its service
//! key, an identity derived from its seed (`nitro`, layer 3: one for every
//! account):
//!
//! ```text
//! tuple("klav/v1/sig/hosted-proxy-registration", account_id(16), agent_id(16),
//!       agent_ed25519_pub(32), agent_x25519_pub(32), u32_be(generation))
//! ```
//!
//! The server, configured with the Ed25519 half of the service key's public
//! identity, marks the agent `hosted`. The mark is bookkeeping, not a
//! security boundary: what makes the hosted proxy trustworthy is the
//! attestation each device checks before it wraps anything for it (ADR
//! 0051 §2.2). This module has no feature gate, so the server checks the
//! mark without compiling the attestation crates.

use ed25519_dalek::VerifyingKey;

use super::CryptoError;
use super::identity::{IdentityKeyPair, PublicIdentity};
use super::sign::{self, Signature};
use crate::ids::{AccountId, AgentId};

/// Signature label of the enclave's mark on a hosted agent's registration.
pub const LABEL_HOSTED_PROXY_REGISTRATION: &str = "klav/v1/sig/hosted-proxy-registration";
/// Length of the service key's Ed25519 public key, as the server holds it.
pub const SERVICE_PUBLIC_KEY_LEN: usize = 32;

/// What the mark on a hosted registration covers.
#[derive(Debug, Clone, Copy)]
pub struct HostedRegistration<'a> {
    /// The account the enclave derived the agent's keys for.
    pub account: AccountId,
    /// The agent's ID, as in the registration.
    pub agent: AgentId,
    /// The agent's public identity, as in the registration.
    pub agent_keys: &'a PublicIdentity,
    /// The account's key generation (ADR 0051 §3.2).
    pub generation: u32,
}

impl HostedRegistration<'_> {
    /// `tuple(label, account_id, agent_id, agent_ed25519_pub,
    /// agent_x25519_pub, u32_be(generation))`.
    pub fn message(&self) -> Vec<u8> {
        sign::signed_message(
            LABEL_HOSTED_PROXY_REGISTRATION,
            &[
                self.account.as_bytes(),
                self.agent.as_bytes(),
                self.agent_keys.ed25519(),
                self.agent_keys.x25519(),
                &self.generation.to_be_bytes(),
            ],
        )
        .expect("the registration label starts with klav/v1/sig/")
    }
}

/// The enclave marks a registration with its service key (an identity, of
/// which only the Ed25519 half signs).
pub fn sign_registration(
    service: &IdentityKeyPair,
    registration: &HostedRegistration<'_>,
) -> Signature {
    let a = registration.account;
    let b = registration.agent;
    let generation = registration.generation.to_be_bytes();
    sign::sign(
        service,
        LABEL_HOSTED_PROXY_REGISTRATION,
        &[
            a.as_bytes(),
            b.as_bytes(),
            registration.agent_keys.ed25519(),
            registration.agent_keys.x25519(),
            &generation,
        ],
    )
    .expect("the registration label starts with klav/v1/sig/")
}

/// The Ed25519 public key of the service key, as the server holds it
/// (`KLAV_HOSTED_PROXY_SERVICE_KEY`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostedServicePublic(VerifyingKey);

impl HostedServicePublic {
    /// From the 32 bytes of an Ed25519 public key. Refuses a point that
    /// isn't on the curve and a small-order one.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let bytes: &[u8; SERVICE_PUBLIC_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        if key.is_weak() {
            return Err(CryptoError::InvalidPublicKey);
        }
        Ok(Self(key))
    }

    /// The Ed25519 half of a service key's public identity.
    pub fn of(service: &PublicIdentity) -> Result<Self, CryptoError> {
        Self::from_bytes(service.ed25519())
    }

    /// From 64 hex digits (either case), the form of
    /// `KLAV_HOSTED_PROXY_SERVICE_KEY`.
    pub fn from_hex(text: &str) -> Result<Self, CryptoError> {
        let bytes = data_encoding::HEXLOWER_PERMISSIVE
            .decode(text.trim().as_bytes())
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        Self::from_bytes(&bytes)
    }

    /// The 32 bytes.
    pub fn to_bytes(&self) -> [u8; SERVICE_PUBLIC_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Checks the mark on a registration (strict: no malleable signatures,
    /// as [`sign::verify`]).
    pub fn verify_registration(
        &self,
        registration: &HostedRegistration<'_>,
        signature: &Signature,
    ) -> Result<(), CryptoError> {
        self.0
            .verify_strict(
                &registration.message(),
                &ed25519_dalek::Signature::from_bytes(&signature.to_bytes()),
            )
            .map_err(|_| CryptoError::Signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mark_covers_every_field_and_matches_sign_verify() {
        let service = IdentityKeyPair::generate();
        let public = HostedServicePublic::of(service.public()).unwrap();
        let agent_keys = IdentityKeyPair::generate();
        let other_keys = IdentityKeyPair::generate();
        let base = HostedRegistration {
            account: AccountId::from_bytes([1; 16]),
            agent: AgentId::from_bytes([2; 16]),
            agent_keys: agent_keys.public(),
            generation: 0,
        };
        let sig = sign_registration(&service, &base);
        assert_eq!(public.verify_registration(&base, &sig), Ok(()));
        // The same message `sign::verify` checks with the whole identity.
        let fields = [
            base.account.as_bytes().as_slice(),
            base.agent.as_bytes(),
            agent_keys.public().ed25519(),
            agent_keys.public().x25519(),
            &0u32.to_be_bytes(),
        ];
        assert_eq!(
            sign::verify(
                service.public(),
                LABEL_HOSTED_PROXY_REGISTRATION,
                &fields,
                &sig
            ),
            Ok(())
        );
        let changed = [
            HostedRegistration {
                account: AccountId::from_bytes([3; 16]),
                ..base
            },
            HostedRegistration {
                agent: AgentId::from_bytes([3; 16]),
                ..base
            },
            HostedRegistration {
                agent_keys: other_keys.public(),
                ..base
            },
            HostedRegistration {
                generation: 1,
                ..base
            },
        ];
        for registration in changed {
            assert_eq!(
                public.verify_registration(&registration, &sig),
                Err(CryptoError::Signature)
            );
        }
        let other = HostedServicePublic::of(IdentityKeyPair::generate().public()).unwrap();
        assert_eq!(
            other.verify_registration(&base, &sig),
            Err(CryptoError::Signature)
        );
    }

    #[test]
    fn the_public_key_parses_strictly() {
        let public = HostedServicePublic::of(IdentityKeyPair::generate().public()).unwrap();
        let text = hex::encode(public.to_bytes());
        assert_eq!(HostedServicePublic::from_hex(&text), Ok(public));
        assert_eq!(
            HostedServicePublic::from_hex(&text.to_uppercase()),
            Ok(public)
        );
        assert_eq!(
            HostedServicePublic::from_hex(&format!(" {text}\n")),
            Ok(public)
        );
        for bad in [
            "",
            &text[..62],
            &format!("{text}00"),
            &format!("{}zz", &text[..62]),
            // The identity point: small order.
            "0100000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert_eq!(
                HostedServicePublic::from_hex(bad),
                Err(CryptoError::InvalidPublicKey),
                "{bad}"
            );
        }
    }
}
