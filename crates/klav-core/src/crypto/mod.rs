//! Cryptography of Klav. Formats are specified in `docs/especificacion-cripto.md`.
//!
//! Only RustCrypto crates, `hpke` and `opaque-ke` are used; nothing here implements a
//! primitive by hand.

pub mod aead;
pub mod agent;
pub mod attachment;
pub mod audit;
pub mod channel;
pub mod context;
pub mod encoding;
mod error;
pub mod hosted;
pub mod identity;
pub mod invite;
pub mod item;
pub mod kdf;
pub mod keys;
pub mod keystore;
pub mod local;
pub mod mcp;
pub mod meta;
pub mod opaque;
pub mod passkey;
pub mod random;
pub mod record;
pub mod sandbox;
pub mod secret_key;
pub mod share;
pub mod sign;
pub mod token;
pub mod wrap;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod vectors;

pub use error::CryptoError;
