//! Klav SDK for agent runtimes (design §5.1 and §5.4).
//!
//! An agent is an identity of its own (X25519 + Ed25519): it never knows
//! the person's master password or Secret Key. It registers, the person
//! approves it after comparing the 6-word pairing code, and from then on it
//! signs every request ([`Agent::send`]) and decrypts only the projects its
//! grant shares with it.
//!
//! By default the SDK hands **actions** to the runtime, not values: the
//! values it decrypts stay in zeroizing buffers and go straight to their
//! destination (a process, a file, a browser field). Only an explicit
//! `reveal`, allowed by the policy, returns a value.
//!
//! All cryptography is delegated to `klav-core`.

pub mod actions;
pub mod agent;
pub mod browser;
pub mod cdp;
pub mod config;
pub mod grant;
pub mod keystore;
pub mod passkeys;
pub mod proxy;
pub mod revocations;
pub mod rotate;
pub mod sandbox;
pub mod secret_file;
pub mod secret_requests;
pub mod session;
pub mod tasks;
pub mod template;
pub mod text;
pub mod writes;

pub use actions::{
    InjectRequest, Redactor, RunOutput, RunRequest, StreamRedactor, inject_file, run,
};
pub use agent::{Agent, AgentState, Registered, Registration};
pub use browser::{
    BrowserTarget, FieldSelector, FillOptions, FillReport, Target, fill, fill_target,
};
pub use config::AgentConfig;
pub use grant::OpenGrant;
pub use keystore::{KeyStore, KeyStoreChoice};
pub use proxy::{ProxyAccess, ProxyCall};
pub use rotate::RotateReport;
pub use secret_requests::{SecretRequestOutcome, SecretRequestSpec};
pub use session::{Access, Claim, ItemInfo, Session};
pub use tasks::{TaskAccessView, TaskRemovedView, TaskView};
pub use writes::{GenerateSpec, GeneratedInfo};

/// Version of `klav-core` this crate is built against.
pub fn core_version() -> &'static str {
    klav_core::VERSION
}
