//! Klav client library.
//!
//! Everything a Klav client needs besides the user interface: sign-up and
//! log-in (OPAQUE), the session and its refresh, the encrypted local cache,
//! delta sync with rollback detection (threat T7) and item CRUD. All
//! cryptography is delegated to `klav-core`; this crate only moves blobs
//! between the server, the disk and memory.
//!
//! Used by the `klav` CLI (direct mode) and by the `klavd` daemon, which
//! keeps an [`Unlocked`] vault in memory.
//!
//! Local state lives in a [`Home`] directory (see `docs/cli.md`):
//!
//! | File | Contents | Protection |
//! |---|---|---|
//! | `account.json` | server, e-mail, IDs, account keyset, local identity | mode 0600; secrets inside are ciphertext |
//! | `secret-key` | the Secret Key (text form) | mode 0600 |
//! | `session.bin` | access and refresh tokens | sealed with the local key |
//! | `cache.bin` | synced vaults (ciphertext) and high-water marks | sealed with the local key |
//! | `deletion.bin` | the account's deletion as this device knows it, and whether the server already deleted it (ADR 0037 §3) | sealed with the local key (purpose `deletion`) |
//! | `revocations.bin` | revocations whose key rotation the person asked for here and that are not finished (ADR 0033, amendment of 2026-11-10, F4) | sealed with the local key (purpose `revocations`) |
//! | `sandbox-marks.bin` | the highest heartbeat `seq` this device accepted per credential proxy, under its current store epoch (ADR 0036 E3.3) | sealed with the local key (purpose `sandbox-marks`) |
//! | `generator-outbox.bin` | generated passwords not uploaded yet (ADR 0022 §2) | sealed with the local key (`0x43`) |
//! | `outbox.bin` | passkeys registered and used without network, on iOS (ADR 0020 §11) | sealed with the local key (`0x43`) |
//! | `health.json` | health settings: the breach check, off by default (ADR 0022 §4) | mode 0600; not secret |
//! | `server-moved` | the server URL the account moved off, until `klav status` reports it (ADR 0028 §4) | mode 0600; not secret |

pub mod activity;
pub mod agent_passkeys;
pub mod agents;
pub mod api;
mod attach;
pub mod audit;
mod auth;
pub mod deletion;
mod error;
pub mod fill;
pub mod grant_change;
#[cfg(feature = "health")]
pub mod health;
pub mod history;
pub mod home;
pub mod import;
pub mod issuers;
pub mod item_grants;
pub mod kit;
pub mod offer;
pub mod ops;
pub mod passkey_outbox;
pub mod passkeys;
pub mod pause;
pub mod preferences;
pub mod proxy_admin;
mod push;
pub mod revoke;
pub mod rotate;
pub mod sandbox_revoke;
pub mod sandbox_state;
pub mod sandboxes;
pub mod secret_requests;
pub mod server;
mod session;
mod state;
mod sync;
pub mod tasks;
mod url;
mod vault_key;

pub use attach::MAX_ATTACHMENT_BYTES;
pub use auth::{
    LoginRequest, PasswordCheck, SignupRequest, account, emergency_kit, forget_account, login,
    set_server, signup, signup_with, unlock_with_local_key, unlock_with_password,
};
pub use error::{ClientError, ClientResult};
pub use home::Home;
pub use server::DEFAULT_SERVER;
pub use session::{
    ItemFilter, ItemLocation, ItemSummary, ProjectSummary, Resolved, SyncFetch, SyncPlan, Unlocked,
    VaultSummary,
};
pub use state::AccountFile;
pub use sync::SyncReport;
pub use url::ServerUrl;

/// The import formats and merge rules (ADR 0024).
pub use klav_import;

/// Name of the vault created at sign-up.
pub const DEFAULT_VAULT: &str = "Personal";
/// Name of the project created in every new vault (design §12: items go to
/// "General" unless a project is given).
pub const DEFAULT_PROJECT: &str = "General";
