//! Klav's credential proxy (ADR 0036): an agent with a per-item grant that
//! puts a granted credential into HTTP requests it builds itself, without
//! handing it to the caller. It redacts the value when a provider echoes
//! it: a net for accidental echoes, not a barrier against a caller that can
//! make a provider echo what it sends (threat model, T149).
//!
//! This crate has no cryptography of its own: the grant, the item and the
//! request signatures go through `klav-sdk` and `klav-core`. The value it
//! decrypts for a call lives in zeroizing buffers and a header marked
//! sensitive, never in a log line, an error or a `Debug` output.
//!
//! Layer 3 of the ADR: pairing, per-call access, injection, the policy's
//! host, method and path lists, the SSRF defence, response redaction, rate
//! limits and mode (a), on a loopback-only listener.

pub mod app;
pub mod channel;
pub mod claims;
pub mod counts;
pub mod errors;
pub mod heartbeat;
pub mod listener;
pub mod memory;
pub mod net;
pub mod paths;
pub mod profiles;
pub mod proxy;
pub mod rate;
pub mod sandboxes;

#[cfg(test)]
mod channel_e2e_tests;
#[cfg(test)]
mod e2e_tests;
#[cfg(test)]
mod forward_e2e_tests;
#[cfg(test)]
mod local_calls_e2e_tests;
#[cfg(test)]
mod locked_e2e_tests;
#[cfg(test)]
mod sandbox_e2e_tests;

/// Version of this build.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
