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
use hpke::rand_core::CryptoRng;
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::attestation::Pcr;
use crate::crypto::CryptoError;
use crate::crypto::encoding::{Kind, Tuple, strip_header};
use crate::crypto::hosted::{HostedRegistration, HostedServicePublic};
use crate::crypto::identity::{IdentityKeyPair, PublicIdentity};
use crate::crypto::random;
use crate::crypto::share::{hpke_open, hpke_seal};
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
/// HKDF `info` label that mixes the NSM's entropy into a new seed.
pub const LABEL_HOSTED_SEED: &str = "klav/v1/proxy/hosted-seed";
/// HKDF `info` label of the hosted proxy's service key (ADR 0051 §8).
pub const LABEL_HOSTED_SERVICE: &str = "klav/v1/proxy/hosted-service";
/// Signature label of the enclave's mark on a hosted agent's registration
/// (ADR 0051 §8), with the service key; defined once, in
/// [`crate::crypto::hosted`], where the server checks it.
pub use crate::crypto::hosted::LABEL_HOSTED_PROXY_REGISTRATION;
/// Length of the master seed.
pub const SEED_LEN: usize = 32;
/// Largest state a hand-off carries with the seed (the enrollments and the
/// in-memory stores, ADR 0051 §4.3).
pub const MAX_HANDOFF_STATE: usize = 8 * 1024 * 1024;
/// A sealed hand-off's bytes besides its state:
/// `header(2) ‖ enc(32) ‖ seed(32) ‖ … ‖ tag(16)`.
pub const HANDOFF_OVERHEAD: usize = 2 + 32 + SEED_LEN + 16;

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

    /// A fresh seed from the OS CSPRNG mixed with `entropy` from the
    /// enclave's NSM (ADR 0051 §13): neither source alone decides it.
    ///
    /// `seed = HKDF-SHA-256(ikm = os_random(32) ‖ entropy, salt = none,
    /// info = tuple("klav/v1/proxy/hosted-seed"), L = 32)`
    pub fn generate_with_entropy(entropy: &[u8]) -> Self {
        let mut os = Zeroizing::new([0u8; SEED_LEN]);
        random::fill(os.as_mut());
        Self::mix(&os, entropy)
    }

    /// [`HostedSeed::generate_with_entropy`] with the OS bytes given (the
    /// vectors).
    pub(crate) fn mix(os: &[u8; SEED_LEN], entropy: &[u8]) -> Self {
        let mut ikm = Zeroizing::new(Vec::with_capacity(SEED_LEN + entropy.len()));
        ikm.extend_from_slice(os);
        ikm.extend_from_slice(entropy);
        Self(SecretBox::init_with_mut(|s: &mut [u8; SEED_LEN]| {
            Hkdf::<Sha256>::new(None, &ikm)
                .expand(Tuple::new(LABEL_HOSTED_SEED).as_bytes(), s)
                .expect("32 bytes is a valid HKDF-SHA256 output length");
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

/// 64 bytes of HKDF-SHA-256 from the seed, split into an identity key
/// pair: X25519 secret first, Ed25519 seed second (the order of `kag1_`).
fn expand_identity(seed: &HostedSeed, info: &[u8]) -> IdentityKeyPair {
    let mut okm = Zeroizing::new([0u8; 64]);
    Hkdf::<Sha256>::new(None, seed.expose())
        .expand(info, okm.as_mut())
        .expect("64 bytes is a valid HKDF-SHA256 output length");
    let mut x25519 = Zeroizing::new([0u8; 32]);
    let mut ed25519 = Zeroizing::new([0u8; 32]);
    x25519.copy_from_slice(&okm[..32]);
    ed25519.copy_from_slice(&okm[32..]);
    IdentityKeyPair::from_secret_bytes(&x25519, &ed25519)
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
    expand_identity(seed, &hosted_account_info(account, generation))
}

/// The hosted proxy's service key (ADR 0051 §8): the same for every
/// account, so `klav-server`, configured with its public half, can tell a
/// hosted agent's registration from any other. Not a security boundary.
///
/// `okm = HKDF-SHA-256(seed, info = tuple("klav/v1/proxy/hosted-service"), L = 64)`,
/// split like the account keys.
pub fn hosted_service_keys(seed: &HostedSeed) -> IdentityKeyPair {
    expand_identity(seed, Tuple::new(LABEL_HOSTED_SERVICE).as_bytes())
}

/// The enclave marks the registration of `account`'s hosted agent with its
/// service key (spec §15.8). The bytes are [`crate::crypto::hosted`]'s,
/// the module `klav-server` checks them with: one definition of the mark.
pub fn sign_hosted_registration(
    service: &IdentityKeyPair,
    account: AccountId,
    agent: AgentId,
    agent_keys: &PublicIdentity,
    generation: u32,
) -> Signature {
    crate::crypto::hosted::sign_registration(
        service,
        &HostedRegistration {
            account,
            agent,
            agent_keys,
            generation,
        },
    )
}

/// Checks a registration mark against the service key's public identity:
/// [`HostedServicePublic::verify_registration`], the check `klav-server`
/// runs (ADR 0051, layer 4), with its Ed25519 half.
pub fn verify_hosted_registration(
    service_public: &PublicIdentity,
    account: AccountId,
    agent: AgentId,
    agent_keys: &PublicIdentity,
    generation: u32,
    signature: &Signature,
) -> Result<(), CryptoError> {
    HostedServicePublic::of(service_public)?.verify_registration(
        &HostedRegistration {
            account,
            agent,
            agent_keys,
            generation,
        },
        signature,
    )
}

/// The joining enclave's one-time X25519 key for a hand-off (ADR 0051 §4.2
/// step 1): its public half goes in the attestation's `public_key`. Not
/// `Debug`, `Display` or `Clone`; zeroized on drop.
pub struct HandoffKey(IdentityKeyPair);

impl HandoffKey {
    /// A fresh key.
    pub fn generate() -> Self {
        Self(IdentityKeyPair::generate())
    }

    /// A key from fixed bytes (the vectors).
    #[cfg(test)]
    pub(crate) fn from_secret(x25519: &[u8; 32]) -> Self {
        Self(IdentityKeyPair::from_secret_bytes(x25519, &[0x5a; 32]))
    }

    /// The X25519 public key the joiner attests.
    pub fn public(&self) -> [u8; 32] {
        *self.0.public().x25519()
    }
}

/// The holder seals the seed and its state to the joiner's attested key
/// (ADR 0051 §4.2 step 4), kind `0x28`:
/// `header(2) ‖ enc(32) ‖ HPKE(seed(32) ‖ state) ‖ tag(16)`, with
/// `info` = [`handoff_info`] and `aad = header`. Only call it after
/// [`super::verify_handoff_peer`] accepted the joiner.
pub fn seal_handoff(
    seed: &HostedSeed,
    state: &[u8],
    joiner_x25519: &[u8; 32],
    info: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    seal_handoff_with_rng(
        seed,
        state,
        joiner_x25519,
        info,
        &mut hpke::rand_core::UnwrapErr(getrandom::SysRng),
    )
}

pub(crate) fn seal_handoff_with_rng(
    seed: &HostedSeed,
    state: &[u8],
    joiner_x25519: &[u8; 32],
    info: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<Vec<u8>, CryptoError> {
    if state.len() > MAX_HANDOFF_STATE {
        return Err(CryptoError::Malformed("hand-off state too large"));
    }
    let mut plaintext = Zeroizing::new(Vec::with_capacity(SEED_LEN + state.len()));
    plaintext.extend_from_slice(seed.expose());
    plaintext.extend_from_slice(state);
    let header = Kind::EnclaveHandoff.header();
    let (enc, ciphertext) = hpke_seal(joiner_x25519, info, &header, &plaintext, rng)?;
    let mut blob = Vec::with_capacity(2 + enc.len() + ciphertext.len());
    blob.extend_from_slice(&header);
    blob.extend_from_slice(&enc);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// The joiner opens what [`seal_handoff`] sealed to its key: the seed and
/// the state.
pub fn open_handoff(
    key: &HandoffKey,
    blob: &[u8],
    info: &[u8],
) -> Result<(HostedSeed, Zeroizing<Vec<u8>>), CryptoError> {
    if blob.len() < HANDOFF_OVERHEAD || blob.len() > HANDOFF_OVERHEAD + MAX_HANDOFF_STATE {
        return Err(CryptoError::Malformed("hand-off length"));
    }
    let body = strip_header(blob, Kind::EnclaveHandoff)?;
    let (enc, ciphertext) = body.split_at(32);
    let plaintext = hpke_open(
        &key.0.hpke_private_key(),
        enc,
        info,
        &Kind::EnclaveHandoff.header(),
        ciphertext,
    )?;
    let (seed, state) = plaintext
        .split_first_chunk::<SEED_LEN>()
        .ok_or(CryptoError::Malformed("hand-off without a seed"))?;
    Ok((HostedSeed::from_bytes(seed), Zeroizing::new(state.to_vec())))
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
    static_assertions::assert_not_impl_any!(HandoffKey: std::fmt::Debug, std::fmt::Display, Clone);

    #[test]
    fn a_new_seed_depends_on_both_sources() {
        let base = HostedSeed::mix(&[1; 32], &[2; 32]);
        assert_eq!(HostedSeed::mix(&[1; 32], &[2; 32]).expose(), base.expose());
        assert_ne!(HostedSeed::mix(&[3; 32], &[2; 32]).expose(), base.expose());
        assert_ne!(HostedSeed::mix(&[1; 32], &[4; 32]).expose(), base.expose());
        assert_ne!(
            HostedSeed::generate_with_entropy(&[2; 32]).expose(),
            HostedSeed::generate_with_entropy(&[2; 32]).expose()
        );
    }

    #[test]
    fn the_service_key_is_apart_from_every_account_key() {
        let service = hosted_service_keys(&seed(7));
        assert_eq!(hosted_service_keys(&seed(7)).public(), service.public());
        assert_ne!(hosted_service_keys(&seed(8)).public(), service.public());
        let account = AccountId::from_bytes([1; 16]);
        assert_ne!(
            derive_account_keys(&seed(7), account, 0).public(),
            service.public()
        );
    }

    #[test]
    fn the_registration_mark_covers_every_field() {
        let service = hosted_service_keys(&seed(7));
        let account = AccountId::from_bytes([1; 16]);
        let agent = AgentId::from_bytes([2; 16]);
        let keys = derive_account_keys(&seed(7), account, 0);
        let other = derive_account_keys(&seed(7), account, 1);
        let sig = sign_hosted_registration(&service, account, agent, keys.public(), 0);
        assert_eq!(
            verify_hosted_registration(service.public(), account, agent, keys.public(), 0, &sig),
            Ok(())
        );
        let wrong = [
            (AccountId::from_bytes([3; 16]), agent, keys.public(), 0),
            (account, AgentId::from_bytes([3; 16]), keys.public(), 0),
            (account, agent, other.public(), 0),
            (account, agent, keys.public(), 1),
        ];
        for (acc, ag, k, generation) in wrong {
            assert_eq!(
                verify_hosted_registration(service.public(), acc, ag, k, generation, &sig),
                Err(CryptoError::Signature)
            );
        }
        let impostor = hosted_service_keys(&seed(8));
        assert_eq!(
            verify_hosted_registration(impostor.public(), account, agent, keys.public(), 0, &sig),
            Err(CryptoError::Signature)
        );
    }

    #[test]
    fn a_handoff_opens_only_with_its_key_and_info() {
        let joiner = HandoffKey::generate();
        let info = handoff_info(&[1; 48], &[2; 48], b"nonce h", b"nonce j");
        let blob = seal_handoff(&seed(9), b"state", &joiner.public(), &info).expect("seal");
        assert_eq!(blob.len(), HANDOFF_OVERHEAD + 5);
        assert_eq!(&blob[..2], &[0x01, 0x28]);
        let (opened, state) = open_handoff(&joiner, &blob, &info).expect("open");
        assert_eq!(opened.expose(), seed(9).expose());
        assert_eq!(state.as_slice(), b"state");

        let other = HandoffKey::generate();
        assert_eq!(
            open_handoff(&other, &blob, &info).err(),
            Some(CryptoError::Decryption)
        );
        let other_info = handoff_info(&[1; 48], &[3; 48], b"nonce h", b"nonce j");
        assert_eq!(
            open_handoff(&joiner, &blob, &other_info).err(),
            Some(CryptoError::Decryption)
        );
        let mut flipped = blob.clone();
        flipped[1] = 0x23;
        assert!(open_handoff(&joiner, &flipped, &info).is_err());
        let mut tampered = blob.clone();
        *tampered.last_mut().expect("tag") ^= 1;
        assert_eq!(
            open_handoff(&joiner, &tampered, &info).err(),
            Some(CryptoError::Decryption)
        );
        assert!(open_handoff(&joiner, &blob[..HANDOFF_OVERHEAD - 1], &info).is_err());
        let empty = seal_handoff(&seed(9), b"", &joiner.public(), &info).expect("seal");
        assert_eq!(
            open_handoff(&joiner, &empty, &info).expect("open").1.len(),
            0
        );
        assert!(
            seal_handoff(
                &seed(9),
                &vec![0; MAX_HANDOFF_STATE + 1],
                &joiner.public(),
                &info
            )
            .is_err()
        );
    }

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
