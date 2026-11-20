//! `klavd`: the Klav local daemon. It keeps one account unlocked in
//! memory so that `klav` (and the browser extension, through
//! `klav-native-host`, see [`native`]) do not ask
//! for the master password on every command, and locks it again after a
//! period of inactivity or when the machine sleeps.
//!
//! It listens on a Unix socket in `$KLAV_HOME` (directory 0700, socket
//! 0600) and only talks to processes of the same user (peer credentials).
//! The protocol is newline-delimited JSON, versioned, and documented in
//! `docs/klavd.md`.

//!
//! Without the default `server` feature only the client side is built
//! ([`client`], [`protocol`] and [`native`]), for the Mac app (ADR 0027).

#[cfg(feature = "server")]
mod browser;
pub mod client;
#[cfg(feature = "server")]
mod imports;
pub mod native;
#[cfg(feature = "server")]
pub mod peer;
#[cfg(feature = "server")]
mod presence;
#[cfg(feature = "server")]
mod prompt;
pub mod protocol;
#[cfg(feature = "server")]
mod server;
#[cfg(feature = "server")]
mod touchid;
pub mod uv;

#[cfg(feature = "server")]
pub use server::{Build, Config, SYNC_AFTER, forbid_same_user_debuggers, serve};
