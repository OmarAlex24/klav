//! Keys and labels of Klav Cloud's hosted proxy (spec §15.6, ADR 0051 §3.1,
//! §2.2 step 5, §4.2 step 4 and §6.1).
//!
//! One 32-byte master seed lives only in enclave memory. Each account's
//! proxy agent keys are derived from it:
//!
//! ```text
//! okm = HKDF-SHA-256(ikm = seed, salt = none,
//!                    info = tuple("klav/v1/proxy/hosted-account", account_id(16), u32_be(generation)),
//!                    L = 64)
//! x25519_sk = okm[0..32]        ed25519_seed = okm[32..64]
//! ```
//!
//! so a routing bug inside the enclave can't open another account's items:
//! account A's request path holds only A's keys.

use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::attestation::Pcr;
use crate::crypto::CryptoError;
use crate::crypto::encoding::Tuple;
use crate::crypto::identity::{IdentityKeyPair, PublicIdentity};
use crate::crypto::random;
use crate::crypto::sign::{self, Signature};
use crate::ids::{AccountId, AgentId};

/// HKDF `info` label of an account's derived proxy keys.
pub const LABEL_HOSTED_ACCOUNT: &str = "klav/v1/proxy/hosted-account";
/// Label of the binding an attestation's `user_data` carries.
pub const LABEL_ENCLAVE_BINDING: &str = "klav/v1/proxy/enclave-binding";
/// HPKE `info` label of the seed handed from one enclave to another.
pub const LABEL_ENCLAVE_HANDOFF: &str = "klav/v1/proxy/enclave-handoff";
/// Signature label of an account's request to enroll in the hosted proxy.
pub const LABEL_HOSTED_PROXY_ENROLL: &str = "klav/v1/sig/hosted-proxy-enroll";
/// Length of the master seed.
pub const SEED_LEN: usize = 32;

/// The hosted proxy's master seed. Not `Debug`, not `Display`, not `Clone`;
/// zeroized on drop. Only an enclave ever holds one.
pub struct HostedSeed(SecretBox<[u8; SEED_LEN]>);

impl HostedSeed {
    /// A fresh seed from the OS CSPRNG (the first enclave, or after a total
    /// loss, ADR 0051 §4.4).
    pub fn generate() -> Self {
        Self(SecretBox::init_with_mut(|s: &mut [u8; SEED_LEN]| {
            random::fill(s)
        }))
    }

    /// A seed received from a peer enclave through the attested hand-off.
    pub fn from_bytes(bytes: &[u8; SEED_LEN]) -> Self {
        Self(SecretBox::new(Box::new(*bytes)))
    }

    /// The seed's bytes. Crate-private: sealing them to a verified peer
    /// (ADR 0051 §4.2) is a `klav-core` function of layer 3.
    pub(crate) fn expose(&self) -> &[u8; SEED_LEN] {
        self.0.expose_secret()
    }
}

/// The HKDF `info` of an account's keys.
pub fn hosted_account_info(account: AccountId, generation: u32) -> Vec<u8> {
    let mut info = Tuple::new(LABEL_HOSTED_ACCOUNT);
    info.push(account.as_bytes())
        .push(&generation.to_be_bytes());
    info.into_bytes()
}

/// The proxy agent keys of `account` at `generation`.
pub fn derive_account_keys(
    seed: &HostedSeed,
    account: AccountId,
    generation: u32,
) -> IdentityKeyPair {
    let mut okm = Zeroizing::new([0u8; 64]);
    Hkdf::<Sha256>::new(None, seed.expose())
        .expand(&hosted_account_info(account, generation), okm.as_mut())
        .expect("64 bytes is a valid HKDF-SHA256 output length");
    let mut x25519 = Zeroizing::new([0u8; 32]);
    let mut ed25519 = Zeroizing::new([0u8; 32]);
    x25519.copy_from_slice(&okm[..32]);
    ed25519.copy_from_slice(&okm[32..]);
    IdentityKeyPair::from_secret_bytes(&x25519, &ed25519)
}

/// What an attestation's `user_data` must equal for `account`'s hosted
/// proxy agent (ADR 0051 §2.2 step 5):
///
/// `SHA-256(tuple("klav/v1/proxy/enclave-binding", account_id(16), agent_id(16),
/// agent_ed25519_pub(32), agent_x25519_pub(32), u32_be(generation)))`
pub fn enclave_binding(
    account: AccountId,
    agent: AgentId,
    keys: &PublicIdentity,
    generation: u32,
) -> [u8; 32] {
    let mut tuple = Tuple::new(LABEL_ENCLAVE_BINDING);
    tuple
        .push(account.as_bytes())
        .push(agent.as_bytes())
        .push(keys.ed25519())
        .push(keys.x25519())
        .push(&generation.to_be_bytes());
    Sha256::digest(tuple.as_bytes()).into()
}

/// The HPKE `info` of the seed sealed from the holder H to the joining
/// enclave J (ADR 0051 §4.2 step 4): both images' PCR0 and both nonces,
/// each document's `nonce` as it appears in that document (the one in J's
/// document came from H, and the other way round).
///
/// `tuple("klav/v1/proxy/enclave-handoff", holder_pcr0(48), joiner_pcr0(48),
/// holder_document_nonce, joiner_document_nonce)`
///
/// Only the `info` is fixed here; the sealed blob, with its version and kind
/// byte, comes with the enclave (ADR 0051, layer 3).
pub fn handoff_info(
    holder_pcr0: &Pcr,
    joiner_pcr0: &Pcr,
    holder_document_nonce: &[u8],
    joiner_document_nonce: &[u8],
) -> Vec<u8> {
    let mut tuple = Tuple::new(LABEL_ENCLAVE_HANDOFF);
    tuple
        .push(holder_pcr0)
        .push(joiner_pcr0)
        .push(holder_document_nonce)
        .push(joiner_document_nonce);
    tuple.into_bytes()
}

/// The fields of an enroll request's signature (ADR 0051 §6.1 step 2), in
/// order: `account_id(16)`, `u32_be(generation)`, `u64_be(at_ms)`.
fn enroll_fields(account: AccountId, generation: u32, at_ms: u64) -> [Vec<u8>; 3] {
    [
        account.as_bytes().to_vec(),
        generation.to_be_bytes().to_vec(),
        at_ms.to_be_bytes().to_vec(),
    ]
}

/// The account signs its request to enroll in the hosted proxy:
/// `tuple("klav/v1/sig/hosted-proxy-enroll", account_id(16), u32_be(generation), u64_be(at_ms))`.
pub fn sign_enroll(
    account_keys: &IdentityKeyPair,
    account: AccountId,
    generation: u32,
    at_ms: u64,
) -> Signature {
    let fields = enroll_fields(account, generation, at_ms);
    let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    sign::sign(account_keys, LABEL_HOSTED_PROXY_ENROLL, &refs)
        .expect("the enroll label starts with klav/v1/sig/")
}

/// The enclave checks an enroll request against the identity key it was
/// given. The ±5 minute window on `at_ms` is the enclave's own check.
pub fn verify_enroll(
    account_public: &PublicIdentity,
    account: AccountId,
    generation: u32,
    at_ms: u64,
    signature: &Signature,
) -> Result<(), CryptoError> {
    let fields = enroll_fields(account, generation, at_ms);
    let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    sign::verify(account_public, LABEL_HOSTED_PROXY_ENROLL, &refs, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    static_assertions::assert_not_impl_any!(HostedSeed: std::fmt::Debug, std::fmt::Display, Clone);

    fn seed(b: u8) -> HostedSeed {
        HostedSeed::from_bytes(&[b; SEED_LEN])
    }

    #[test]
    fn keys_depend_on_seed_account_and_generation() {
        let a = AccountId::from_bytes([1; 16]);
        let b = AccountId::from_bytes([2; 16]);
        let base = derive_account_keys(&seed(7), a, 0);
        assert_eq!(derive_account_keys(&seed(7), a, 0).public(), base.public());
        for other in [
            derive_account_keys(&seed(8), a, 0),
            derive_account_keys(&seed(7), b, 0),
            derive_account_keys(&seed(7), a, 1),
        ] {
            assert_ne!(other.public().x25519(), base.public().x25519());
            assert_ne!(other.public().ed25519(), base.public().ed25519());
        }
    }

    #[test]
    fn the_binding_covers_every_field() {
        let keys = derive_account_keys(&seed(7), AccountId::from_bytes([1; 16]), 0);
        let other = derive_account_keys(&seed(7), AccountId::from_bytes([1; 16]), 1);
        let account = AccountId::from_bytes([1; 16]);
        let agent = AgentId::from_bytes([2; 16]);
        let base = enclave_binding(account, agent, keys.public(), 0);
        assert_ne!(
            base,
            enclave_binding(AccountId::from_bytes([3; 16]), agent, keys.public(), 0)
        );
        assert_ne!(
            base,
            enclave_binding(account, AgentId::from_bytes([3; 16]), keys.public(), 0)
        );
        assert_ne!(base, enclave_binding(account, agent, other.public(), 0));
        assert_ne!(base, enclave_binding(account, agent, keys.public(), 1));
    }

    #[test]
    fn enroll_signature_is_bound_to_its_fields() {
        let identity = IdentityKeyPair::generate();
        let account = AccountId::from_bytes([1; 16]);
        let sig = sign_enroll(&identity, account, 3, 1_000);
        assert_eq!(
            verify_enroll(identity.public(), account, 3, 1_000, &sig),
            Ok(())
        );
        for (acc, generation, at) in [
            (AccountId::from_bytes([2; 16]), 3, 1_000),
            (account, 4, 1_000),
            (account, 3, 1_001),
        ] {
            assert_eq!(
                verify_enroll(identity.public(), acc, generation, at, &sig),
                Err(CryptoError::Signature)
            );
        }
    }
}
