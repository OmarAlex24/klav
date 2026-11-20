//! Klav wire protocol.
//!
//! JSON request and response bodies exchanged between `klav-server` and its
//! clients (CLI, daemon, extension, mobile apps, agent SDK). The server is
//! AGPL-3.0 while clients are Apache-2.0, so the types both sides share live
//! here, under Apache-2.0 (ADR 0007).
//!
//! The server never decrypts anything: every encrypted payload travels as an
//! opaque [`Blob`] (base64url without padding) whose binary format is defined
//! in `docs/especificacion-cripto.md` and implemented by `klav-core`.
//! The HTTP API itself is documented in `docs/api.md`.

pub mod agent;
pub mod audit;
pub mod auth;
mod blob;
mod common;
pub mod rotate;
pub mod sandbox;
pub mod sync;
pub mod task;
pub mod vault;

pub use blob::Blob;
pub use common::{ErrorBody, ErrorCode, HealthResponse};

/// Prefix of every versioned API route.
pub const API_PREFIX: &str = "/v1";
