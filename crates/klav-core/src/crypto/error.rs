//! Error type shared by all cryptographic operations.

use thiserror::Error;

/// Errors returned by `klav_core::crypto`.
///
/// Decryption failures are deliberately opaque ([`CryptoError::Decryption`]):
/// a wrong key, a tampered ciphertext, a swapped AAD field or a rolled-back
/// version all look the same to the caller.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// Authentication failed: wrong key, tampered data or wrong context.
    #[error("decryption failed")]
    Decryption,
    /// The blob declares a format version this build does not understand.
    #[error("unsupported format version {0:#04x}")]
    UnsupportedVersion(u8),
    /// The blob is of a different kind than the operation expects.
    #[error("unexpected blob kind {found:#04x} (expected {expected:#04x})")]
    UnexpectedKind {
        /// Kind byte required by the operation.
        expected: u8,
        /// Kind byte found in the blob.
        found: u8,
    },
    /// The blob is truncated or otherwise structurally invalid.
    #[error("malformed data: {0}")]
    Malformed(&'static str),
    /// KDF parameters are outside the accepted range (too weak or too costly).
    #[error("KDF parameters rejected: {0}")]
    KdfParams(&'static str),
    /// Argon2id failed to run with the given parameters.
    #[error("key derivation failed")]
    Kdf,
    /// The Secret Key text is invalid.
    #[error("invalid Secret Key: {0}")]
    SecretKey(&'static str),
    /// Decrypted private keys do not match the expected public keys.
    #[error("private keys do not match the expected public keys")]
    KeyMismatch,
    /// A public key is invalid.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// HPKE encapsulation failed.
    #[error("HPKE encapsulation failed")]
    Encapsulation,
    /// A signature did not verify.
    #[error("invalid signature")]
    Signature,
    /// An OPAQUE protocol step failed (wrong password, tampered message or
    /// malformed input). Deliberately opaque, like [`CryptoError::Decryption`].
    #[error("OPAQUE authentication failed")]
    Opaque,
    /// An I/O error while streaming an attachment.
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<std::io::Error> for CryptoError {
    fn from(err: std::io::Error) -> Self {
        CryptoError::Io(err.to_string())
    }
}
