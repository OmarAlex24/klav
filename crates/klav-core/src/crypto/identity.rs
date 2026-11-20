//! Identity key pairs (spec §6): X25519 for HPKE and Ed25519 for signatures.
//!
//! Accounts and agents both have an identity. An account seals its private
//! keys under the KEK; agents store theirs locally (Fase 4).

use ed25519_dalek::{SigningKey, VerifyingKey};
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, Serializable};
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::encoding::{Kind, Tuple, strip_header};
use super::keys::{KEY_LEN, Kek, sealed::Sealed};
use super::{CryptoError, aead, random};
use crate::ids::AccountId;

/// Encoded length of a [`PublicIdentity`]: header(2) ‖ x25519(32) ‖ ed25519(32).
pub const PUBLIC_IDENTITY_LEN: usize = 66;
/// Label of the sealed identity secrets.
pub const LABEL_SECRETS: &str = "klav/v1/identity/secrets";
/// Label of the public-key fingerprint.
pub const LABEL_FINGERPRINT: &str = "klav/v1/identity/fingerprint";

type HpkePrivateKey = <X25519HkdfSha256 as Kem>::PrivateKey;
type HpkePublicKey = <X25519HkdfSha256 as Kem>::PublicKey;

/// Public half of an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    x25519: [u8; 32],
    ed25519: [u8; 32],
}

impl PublicIdentity {
    /// `0x01 ‖ 0x05 ‖ x25519_pk(32) ‖ ed25519_pk(32)`.
    pub fn encode(&self) -> [u8; PUBLIC_IDENTITY_LEN] {
        let mut out = [0u8; PUBLIC_IDENTITY_LEN];
        out[..2].copy_from_slice(&Kind::PublicIdentity.header());
        out[2..34].copy_from_slice(&self.x25519);
        out[34..].copy_from_slice(&self.ed25519);
        out
    }

    /// Decodes and validates both public keys.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != PUBLIC_IDENTITY_LEN {
            return Err(CryptoError::Malformed("public identity length"));
        }
        let body = strip_header(bytes, Kind::PublicIdentity)?;
        let mut x25519 = [0u8; 32];
        let mut ed25519 = [0u8; 32];
        x25519.copy_from_slice(&body[..32]);
        ed25519.copy_from_slice(&body[32..]);
        let identity = Self { x25519, ed25519 };
        identity.verifying_key()?;
        identity.hpke_public_key()?;
        Ok(identity)
    }

    /// X25519 public key bytes.
    pub fn x25519(&self) -> &[u8; 32] {
        &self.x25519
    }

    /// Ed25519 public key bytes.
    pub fn ed25519(&self) -> &[u8; 32] {
        &self.ed25519
    }

    /// `SHA-256(tuple("klav/v1/identity/fingerprint", x25519_pk, ed25519_pk))`.
    ///
    /// Bound into HPKE `info`, and the source of the 6-word code shown during
    /// agent pairing (Fase 4).
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut tuple = Tuple::new(LABEL_FINGERPRINT);
        tuple.push(&self.x25519).push(&self.ed25519);
        Sha256::digest(tuple.as_bytes()).into()
    }

    pub(crate) fn verifying_key(&self) -> Result<VerifyingKey, CryptoError> {
        let key =
            VerifyingKey::from_bytes(&self.ed25519).map_err(|_| CryptoError::InvalidPublicKey)?;
        if key.is_weak() {
            return Err(CryptoError::InvalidPublicKey);
        }
        Ok(key)
    }

    pub(crate) fn hpke_public_key(&self) -> Result<HpkePublicKey, CryptoError> {
        // An all-zero (or other low-order) X25519 key makes every DH output
        // zero; HPKE would fail at encapsulation, reject it upfront.
        if bool::from(self.x25519.ct_eq(&[0u8; 32])) {
            return Err(CryptoError::InvalidPublicKey);
        }
        HpkePublicKey::from_bytes(&self.x25519).map_err(|_| CryptoError::InvalidPublicKey)
    }
}

/// An identity key pair. Not `Debug`, not `Display`, not `Clone`.
pub struct IdentityKeyPair {
    /// X25519 private key, clamped (RFC 9180 `SerializePrivateKey`).
    x25519: SecretBox<[u8; 32]>,
    /// Ed25519 seed (RFC 8032 private key).
    ed25519: SecretBox<[u8; 32]>,
    public: PublicIdentity,
}

impl IdentityKeyPair {
    /// Generates a fresh identity from the OS CSPRNG.
    pub fn generate() -> Self {
        let x = Zeroizing::new(random::array::<32>());
        let ed = Zeroizing::new(random::array::<32>());
        Self::from_secret_bytes(&x, &ed)
    }

    /// Builds an identity from its two private keys. The X25519 key is clamped.
    pub(crate) fn from_secret_bytes(x25519: &[u8; 32], ed25519: &[u8; 32]) -> Self {
        let sk =
            HpkePrivateKey::from_bytes(x25519).expect("32-byte X25519 keys always deserialize");
        let x_pk = X25519HkdfSha256::sk_to_pk(&sk);
        let mut clamped = Box::new([0u8; 32]);
        {
            use zeroize::Zeroize as _;
            let mut bytes = sk.to_bytes();
            clamped.copy_from_slice(&bytes);
            bytes.as_mut_slice().zeroize();
        }
        let signing = SigningKey::from_bytes(ed25519);
        let public = PublicIdentity {
            x25519: x_pk.to_bytes().into(),
            ed25519: signing.verifying_key().to_bytes(),
        };
        Self {
            x25519: SecretBox::new(clamped),
            ed25519: SecretBox::new(Box::new(*ed25519)),
            public,
        }
    }

    /// The public half.
    pub fn public(&self) -> &PublicIdentity {
        &self.public
    }

    pub(crate) fn hpke_private_key(&self) -> HpkePrivateKey {
        HpkePrivateKey::from_bytes(self.x25519.expose_secret())
            .expect("stored X25519 key is 32 bytes")
    }

    #[cfg(test)]
    pub(crate) fn hpke_private_key_bytes(&self) -> [u8; 32] {
        *self.x25519.expose_secret()
    }

    pub(crate) fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(self.ed25519.expose_secret())
    }

    /// `x25519_sk(32) ‖ ed25519_seed(32)`.
    pub(crate) fn secrets_plaintext(&self) -> Zeroizing<[u8; 64]> {
        secrets_plaintext(self)
    }
}

fn secrets_context(account: AccountId, public: &PublicIdentity) -> Tuple {
    let mut tuple = Tuple::new(LABEL_SECRETS);
    tuple.push(account.as_bytes()).push(&public.encode());
    tuple
}

/// Seals the identity private keys under the KEK (kind `0x01`).
///
/// Plaintext: `x25519_sk(32) ‖ ed25519_seed(32)`. The AAD binds the account ID
/// and the encoded public identity, so a server that swaps the stored public
/// keys makes the blob fail to open.
pub fn seal_identity(kek: &Kek, account: AccountId, keys: &IdentityKeyPair) -> Vec<u8> {
    seal_secrets(
        kek.secret_bytes(),
        Kind::IdentitySecrets,
        &secrets_context(account, keys.public()),
        keys,
    )
}

/// Seals `x25519_sk ‖ ed25519_seed` under `key` (shared by the KEK-sealed
/// identity and the device-local copy, spec §6.3 and §12.2).
pub(crate) fn seal_secrets(
    key: &[u8; KEY_LEN],
    kind: Kind,
    context: &Tuple,
    keys: &IdentityKeyPair,
) -> Vec<u8> {
    let plaintext = secrets_plaintext(keys);
    aead::seal(key, kind, context, plaintext.as_ref())
}

/// Opens identity secrets sealed by [`seal_secrets`] and checks that they
/// match `expected`.
pub(crate) fn open_secrets(
    key: &[u8; KEY_LEN],
    kind: Kind,
    context: &Tuple,
    expected: &PublicIdentity,
    blob: &[u8],
) -> Result<IdentityKeyPair, CryptoError> {
    let plaintext = aead::open(key, kind, context, blob)?;
    if plaintext.len() != 64 {
        return Err(CryptoError::Malformed("identity secrets length"));
    }
    let mut x = Zeroizing::new([0u8; 32]);
    let mut ed = Zeroizing::new([0u8; 32]);
    x.copy_from_slice(&plaintext[..32]);
    ed.copy_from_slice(&plaintext[32..]);
    let keys = IdentityKeyPair::from_secret_bytes(&x, &ed);
    if keys.public() != expected {
        return Err(CryptoError::KeyMismatch);
    }
    Ok(keys)
}

#[cfg(test)]
pub(crate) fn seal_identity_with_nonce(
    kek: &Kek,
    account: AccountId,
    keys: &IdentityKeyPair,
    nonce: &[u8; aead::NONCE_LEN],
) -> Vec<u8> {
    let plaintext = secrets_plaintext(keys);
    aead::seal_with_nonce(
        kek.secret_bytes(),
        Kind::IdentitySecrets,
        &secrets_context(account, keys.public()),
        nonce,
        plaintext.as_ref(),
    )
}

fn secrets_plaintext(keys: &IdentityKeyPair) -> Zeroizing<[u8; 64]> {
    let mut plaintext = Zeroizing::new([0u8; 64]);
    plaintext[..32].copy_from_slice(keys.x25519.expose_secret());
    plaintext[32..].copy_from_slice(keys.ed25519.expose_secret());
    plaintext
}

/// Opens identity secrets sealed by [`seal_identity`].
///
/// `expected` is the public identity the caller believes belongs to the
/// account. Besides the AAD binding, the public keys are recomputed from the
/// decrypted private keys and compared ([`CryptoError::KeyMismatch`]).
pub fn open_identity(
    kek: &Kek,
    account: AccountId,
    expected: &PublicIdentity,
    blob: &[u8],
) -> Result<IdentityKeyPair, CryptoError> {
    open_secrets(
        kek.secret_bytes(),
        Kind::IdentitySecrets,
        &secrets_context(account, expected),
        expected,
        blob,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    static_assertions::assert_not_impl_any!(IdentityKeyPair: std::fmt::Debug, std::fmt::Display, Clone);

    #[test]
    fn public_identity_roundtrip() {
        let keys = IdentityKeyPair::generate();
        let encoded = keys.public().encode();
        assert_eq!(PublicIdentity::decode(&encoded).as_ref(), Ok(keys.public()));
        assert_ne!(
            keys.public().fingerprint(),
            IdentityKeyPair::generate().public().fingerprint()
        );
    }

    #[test]
    fn rejects_bad_public_keys() {
        let mut bytes = IdentityKeyPair::generate().public().encode();
        bytes[2..34].fill(0);
        assert_eq!(
            PublicIdentity::decode(&bytes),
            Err(CryptoError::InvalidPublicKey)
        );
        assert!(PublicIdentity::decode(&bytes[..65]).is_err());
    }

    #[test]
    fn x25519_key_is_stored_clamped() {
        let keys = IdentityKeyPair::from_secret_bytes(&[0xFF; 32], &[1; 32]);
        let sk = keys.x25519.expose_secret();
        assert_eq!(sk[0] & 7, 0);
        assert_eq!(sk[31] & 0x80, 0);
        assert_eq!(sk[31] & 0x40, 0x40);
    }

    #[test]
    fn seal_open_roundtrip_and_binding() {
        let kek = Kek::generate();
        let account = AccountId::generate();
        let keys = IdentityKeyPair::generate();
        let blob = seal_identity(&kek, account, &keys);
        let opened = open_identity(&kek, account, keys.public(), &blob).unwrap();
        assert_eq!(opened.public(), keys.public());

        // Wrong KEK, wrong account, swapped public keys: all rejected.
        assert!(open_identity(&Kek::generate(), account, keys.public(), &blob).is_err());
        assert!(open_identity(&kek, AccountId::generate(), keys.public(), &blob).is_err());
        let attacker = IdentityKeyPair::generate();
        assert_eq!(
            open_identity(&kek, account, attacker.public(), &blob).err(),
            Some(CryptoError::Decryption)
        );
    }
}
