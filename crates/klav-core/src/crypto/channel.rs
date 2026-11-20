//! The keys of a sandbox's pinned channel (ADR 0036 §6): TLS 1.3 between
//! the forwarder in the sandbox and the credential proxy, each end with a
//! raw Ed25519 public key (RFC 7250).
//!
//! TLS itself is `rustls`, outside this crate. This module only signs: a
//! [`TlsSigner`] signs a TLS 1.3 `CertificateVerify` message (RFC 8446
//! §4.4.3) with Ed25519 (RFC 8032), and nothing else. It refuses any other
//! input, so the proxy's long-term identity key, which also signs Klav's
//! requests, never leaves this crate and cannot be made to sign one of
//! them through TLS.
//!
//! - **The proxy's signer** comes from its identity ([`TlsSigner::server`]):
//!   it signs only the server's `CertificateVerify`. The pin in a sandbox's
//!   package is the SHA-256 of this key's SPKI
//!   ([`super::sandbox::proxy_pin`]).
//! - **The forwarder's signer** is the channel key
//!   ([`TlsSigner::channel_key`]): a fresh Ed25519 key that never leaves
//!   its process and signs only the client's `CertificateVerify`. The proxy
//!   binds a sandbox to the SHA-256 of its SPKI
//!   ([`super::sandbox::channel_key_digest`]).
//!
//! Why a TLS signature can never be taken for a Klav one: a Klav signed
//! message is a tuple whose first four bytes are the big-endian length of
//! its label (`00 00 00 …`), while a `CertificateVerify` message starts
//! with 64 bytes of `0x20`.

use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

use super::CryptoError;
use super::identity::IdentityKeyPair;
use super::random;
use super::sandbox::{ED25519_SPKI_LEN, channel_key_digest};

/// The context string of a server's `CertificateVerify` (RFC 8446 §4.4.3).
pub const SERVER_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";
/// The context string of a client's `CertificateVerify`.
pub const CLIENT_CONTEXT: &[u8] = b"TLS 1.3, client CertificateVerify";
/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Which side of the handshake a signer signs for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The proxy.
    Server,
    /// The forwarder.
    Client,
}

impl Side {
    fn context(self) -> &'static [u8] {
        match self {
            Self::Server => SERVER_CONTEXT,
            Self::Client => CLIENT_CONTEXT,
        }
    }
}

/// An Ed25519 key that signs one side's TLS 1.3 `CertificateVerify` and
/// nothing else. Not `Debug`, not `Clone`; the key is wiped on drop.
pub struct TlsSigner {
    key: SigningKey,
    side: Side,
}

impl TlsSigner {
    /// The proxy's signer, from its identity: a copy of its Ed25519 key that
    /// signs only the server's `CertificateVerify`.
    pub fn server(identity: &IdentityKeyPair) -> Self {
        Self {
            key: identity.signing_key(),
            side: Side::Server,
        }
    }

    /// A fresh channel key from the OS CSPRNG, for the forwarder: it signs
    /// only the client's `CertificateVerify`.
    pub fn channel_key() -> Self {
        let seed = Zeroizing::new(random::array::<32>());
        Self {
            key: SigningKey::from_bytes(&seed),
            side: Side::Client,
        }
    }

    /// The side it signs for.
    pub fn side(&self) -> Side {
        self.side
    }

    /// The Ed25519 public key.
    pub fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// The DER `SubjectPublicKeyInfo` of the public key, as TLS sends it.
    pub fn spki(&self) -> [u8; ED25519_SPKI_LEN] {
        super::sandbox::ed25519_spki_of(&self.public())
    }

    /// `SHA-256(SPKI)`: what a sandbox is bound to (the forwarder's key) or
    /// pinned to (the proxy's).
    pub fn spki_sha256(&self) -> [u8; 32] {
        channel_key_digest(&self.public())
    }

    /// Signs `message` if it is this side's TLS 1.3 `CertificateVerify`
    /// content: 64 bytes of `0x20`, the side's context string, a zero byte
    /// and a transcript hash of 32 or 48 bytes (SHA-256 or SHA-384).
    pub fn sign_certificate_verify(
        &self,
        message: &[u8],
    ) -> Result<[u8; SIGNATURE_LEN], CryptoError> {
        if !is_certificate_verify(message, self.side) {
            return Err(CryptoError::Malformed(
                "only a TLS 1.3 CertificateVerify message is signed",
            ));
        }
        Ok(self.key.sign(message).to_bytes())
    }
}

/// Whether `message` is a TLS 1.3 `CertificateVerify` content for `side`.
pub fn is_certificate_verify(message: &[u8], side: Side) -> bool {
    let context = side.context();
    let head = 64 + context.len() + 1;
    let hash_len = message.len().wrapping_sub(head);
    message.len() > head
        && (hash_len == 32 || hash_len == 48)
        && message[..64].iter().all(|b| *b == 0x20)
        && &message[64..64 + context.len()] == context
        && message[64 + context.len()] == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, VerifyingKey};

    fn message(context: &[u8], hash_len: usize) -> Vec<u8> {
        let mut m = vec![0x20; 64];
        m.extend_from_slice(context);
        m.push(0);
        m.extend(std::iter::repeat_n(0xab, hash_len));
        m
    }

    #[test]
    fn each_side_signs_only_its_own_certificate_verify() {
        let identity = IdentityKeyPair::generate();
        let server = TlsSigner::server(&identity);
        let client = TlsSigner::channel_key();
        assert_eq!(&server.public(), identity.public().ed25519());
        for (signer, own, other) in [
            (&server, SERVER_CONTEXT, CLIENT_CONTEXT),
            (&client, CLIENT_CONTEXT, SERVER_CONTEXT),
        ] {
            for hash_len in [32, 48] {
                let m = message(own, hash_len);
                let sig = signer.sign_certificate_verify(&m).expect("own");
                VerifyingKey::from_bytes(&signer.public())
                    .expect("key")
                    .verify_strict(&m, &Signature::from_bytes(&sig))
                    .expect("verifies");
                assert!(
                    signer
                        .sign_certificate_verify(&message(other, hash_len))
                        .is_err()
                );
            }
            for hash_len in [0, 20, 31, 33, 47, 49, 64] {
                assert!(
                    signer
                        .sign_certificate_verify(&message(own, hash_len))
                        .is_err()
                );
            }
            let mut m = message(own, 32);
            m[0] = 0x21;
            assert!(signer.sign_certificate_verify(&m).is_err());
            let mut m = message(own, 32);
            m[64 + own.len()] = 1;
            assert!(signer.sign_certificate_verify(&m).is_err());
            assert!(signer.sign_certificate_verify(&[]).is_err());
        }
    }

    #[test]
    fn a_klav_signed_message_is_never_signed() {
        let identity = IdentityKeyPair::generate();
        let server = TlsSigner::server(&identity);
        let klav = super::super::sign::signed_message("klav/v1/sig/test", &[&[0x20; 128]])
            .expect("message");
        assert!(server.sign_certificate_verify(&klav).is_err());
    }

    #[test]
    fn the_spki_digest_is_the_proxy_pin_and_the_channel_digest() {
        let identity = IdentityKeyPair::generate();
        let server = TlsSigner::server(&identity);
        assert_eq!(
            server.spki_sha256(),
            super::super::sandbox::proxy_pin(identity.public())
        );
        assert_eq!(
            server.spki(),
            super::super::sandbox::ed25519_spki(identity.public())
        );
        let client = TlsSigner::channel_key();
        assert_eq!(client.spki_sha256(), channel_key_digest(&client.public()));
        assert_ne!(client.public(), TlsSigner::channel_key().public());
    }
}
