//! Ed25519 signatures with domain separation (spec §9).
//!
//! The signed message is always `tuple(label, field1, …, fieldN)` and `label`
//! must start with `klav/v1/sig/`. AEAD and HKDF labels never use that
//! prefix, so a signature can never be confused with any other construction.
//! Verification uses `verify_strict` (rejects malleable signatures and
//! small-order keys).

use ed25519_dalek::Signer;

use super::CryptoError;
use super::encoding::Tuple;
use super::identity::{IdentityKeyPair, PublicIdentity};

/// Required prefix of every signature label.
pub const LABEL_PREFIX: &str = "klav/v1/sig/";
/// Signature length in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// An Ed25519 signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Builds a signature from its 64 bytes.
    pub const fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    /// The 64 signature bytes (`R ‖ S`).
    pub const fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0
    }
}

/// Builds the signed message `tuple(label, fields…)`.
pub fn signed_message(label: &str, fields: &[&[u8]]) -> Result<Vec<u8>, CryptoError> {
    if !label.starts_with(LABEL_PREFIX) || label.len() == LABEL_PREFIX.len() {
        return Err(CryptoError::Malformed(
            "signature label must start with klav/v1/sig/",
        ));
    }
    let mut tuple = Tuple::new(label);
    for field in fields {
        tuple.push(field);
    }
    Ok(tuple.into_bytes())
}

/// Signs `tuple(label, fields…)` with the identity's Ed25519 key.
pub fn sign(
    keys: &IdentityKeyPair,
    label: &str,
    fields: &[&[u8]],
) -> Result<Signature, CryptoError> {
    let message = signed_message(label, fields)?;
    Ok(Signature(keys.signing_key().sign(&message).to_bytes()))
}

/// Verifies a signature made by [`sign`].
pub fn verify(
    public: &PublicIdentity,
    label: &str,
    fields: &[&[u8]],
    signature: &Signature,
) -> Result<(), CryptoError> {
    let message = signed_message(label, fields)?;
    let key = public.verifying_key()?;
    key.verify_strict(
        &message,
        &ed25519_dalek::Signature::from_bytes(&signature.0),
    )
    .map_err(|_| CryptoError::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LABEL: &str = "klav/v1/sig/test";

    #[test]
    fn sign_verify_roundtrip() {
        let keys = IdentityKeyPair::generate();
        let sig = sign(&keys, LABEL, &[b"a", b"bc"]).unwrap();
        assert_eq!(verify(keys.public(), LABEL, &[b"a", b"bc"], &sig), Ok(()));
    }

    #[test]
    fn detects_tampering() {
        let keys = IdentityKeyPair::generate();
        let sig = sign(&keys, LABEL, &[b"a", b"bc"]).unwrap();
        let other = IdentityKeyPair::generate();
        assert_eq!(
            verify(other.public(), LABEL, &[b"a", b"bc"], &sig),
            Err(CryptoError::Signature)
        );
        assert_eq!(
            verify(keys.public(), LABEL, &[b"ab", b"c"], &sig),
            Err(CryptoError::Signature)
        );
        assert_eq!(
            verify(keys.public(), "klav/v1/sig/other", &[b"a", b"bc"], &sig),
            Err(CryptoError::Signature)
        );
        let mut bytes = sig.to_bytes();
        bytes[10] ^= 1;
        assert_eq!(
            verify(
                keys.public(),
                LABEL,
                &[b"a", b"bc"],
                &Signature::from_bytes(bytes)
            ),
            Err(CryptoError::Signature)
        );
    }

    #[test]
    fn requires_signature_label_prefix() {
        let keys = IdentityKeyPair::generate();
        for bad in ["klav/v1/item/details", "klav/v1/sig/", ""] {
            assert!(matches!(
                sign(&keys, bad, &[]),
                Err(CryptoError::Malformed(_))
            ));
        }
    }
}
