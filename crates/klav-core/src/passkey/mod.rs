//! Klav as a WebAuthn authenticator (ADR 0020, spec §14).
//!
//! - [`webauthn`]: the bytes of a registration and an assertion
//!   (authenticator data, COSE key, `none` attestation, `clientDataJSON`).
//! - [`rp`] (feature `rp-id`): which rpId an origin may use, with the
//!   Public Suffix List.
//!
//! The private key and its sealing (kind `0x15`) are in
//! [`crate::crypto::passkey`].

mod cbor;
#[cfg(feature = "rp-id")]
pub mod rp;
pub mod webauthn;
