//! Klav core.
//!
//! All cryptography in Klav lives in this crate: key derivation, the key
//! hierarchy, item and attachment encryption, signatures. It also hosts the
//! item model, `klav://` references, TOTP, agent policy evaluation, task
//! requests ([`task`]), the WebAuthn authenticator of passkeys ([`passkey`]), the hashes of the vault health report
//! ([`health`]) and the rule for which pages a login may be filled
//! into ([`site`]). Behind the feature `nitro-attestation`, `nitro`
//! verifies Klav Cloud's hosted proxy before a device wraps anything for it
//! (ADR 0051).
//!
//! The byte-level formats implemented here are specified in
//! `docs/especificacion-cripto.md`; test vectors live in `docs/vectores/`.

pub mod crypto;
pub mod generator;
pub mod health;
pub mod ids;
pub mod model;
pub mod narrowing;
#[cfg(feature = "nitro-attestation")]
pub mod nitro;
pub mod passkey;
pub mod policy;
pub mod secret_request;
pub mod site;
pub mod task;
pub mod text;
pub mod totp;

/// Version of this crate, as reported by `CARGO_PKG_VERSION`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
