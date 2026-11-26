//! Klav Cloud's hosted proxy, from the person's device (ADR 0051 §2.2,
//! §6.1–§6.3).
//!
//! The proxy is an ordinary agent of the account (`proxy: {mode: "klav",
//! agent_id}` in the account's preferences, §6.2) whose keys an AWS Nitro
//! Enclave holds. This device never wraps an item key for it, approves it
//! or names it as the account's proxy without first checking, through
//! `klav-core`'s `nitro-attestation`:
//!
//! 1. the Klav Enclave Transparency Manifest (`GET /v1/manifest`), signed
//!    by a release-authority key compiled into `klav-core`, not older than
//!    the highest `seq` this device verified ([`HOSTED_PROXY_FILE`]), not
//!    expired, and naming this account's Klav server;
//! 2. a fresh attestation (`GET /v1/attest`, a nonce of 32 random bytes):
//!    AWS's chain, the signature, the nonce, the timestamp, the PCRs of an
//!    image the manifest lists as `current` or `draining`, and `user_data`
//!    equal to the binding of the agent the **server** shows for the
//!    account, at its generation.
//!
//! [`Unlocked::upload_grant`](crate::session::Unlocked), which every grant
//! this device signs goes through, runs that check whenever the agent is
//! the account's hosted proxy or one this device enrolled: the item keys
//! go only to the key the attestation bound. A build without the feature
//! `hosted-proxy` refuses such a grant outright (fail closed).
//!
//! Without the feature, only the types (the status the apps and `klavd`
//! pass along) and the refusal are compiled; `klav-wasm` never builds any
//! of it, and the extension never wraps for a proxy.

use klav_core::ids::AgentId;
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, ClientResult};
use crate::session::Unlocked;

/// The hosted proxy's public API, unless the device names another
/// (`KLAV_HOSTED_PROXY_URL`). The answers are self-authenticating, so
/// another URL can only deny service (ADR 0051 §6.4).
pub const DEFAULT_ENDPOINT: &str = "https://proxy.klav.dev";
/// The variable that names another endpoint (tests, a staging enclave).
pub const ENDPOINT_ENV: &str = "KLAV_HOSTED_PROXY_URL";
/// `$KLAV_HOME/hosted-proxy.bin`: the highest manifest `seq` and
/// `seed_epoch` this device verified, the highest generation it enrolled
/// at and every hosted agent it enrolled. Sealed with the local key
/// (purpose `hosted-proxy`), apart from `cache.bin`, and removed with the
/// account.
pub const HOSTED_PROXY_FILE: &str = "hosted-proxy.bin";
/// The purpose of [`HOSTED_PROXY_FILE`]'s sealing.
const PURPOSE_HOSTED_PROXY: &str = "hosted-proxy";
/// Format of [`HOSTED_PROXY_FILE`]'s contents.
const HOSTED_PROXY_VERSION: u32 = 1;

/// What every proxy command of a build without the feature says (ADR 0051
/// §9): it fails closed and says why.
pub const UNSUPPORTED: &str =
    "the account uses Klav's hosted proxy, which this version does not support yet";

/// Where the hosted proxy stands, as this device checked it just now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostedState {
    /// The manifest and a fresh attestation verified: credentials may be
    /// wrapped for it.
    Verified,
    /// It couldn't be verified: a manifest or attestation that doesn't
    /// verify, an image the manifest doesn't list or revoked, a rollback,
    /// an expired manifest, or no release key pinned in this build. No new
    /// credential goes to it; what it holds stays until the person acts
    /// (ADR 0051 §6.3). The red row, with «Stop using it».
    Unverified,
    /// The endpoint or the Klav server didn't answer: nothing verified, so
    /// nothing is wrapped, but nothing is wrong either.
    Unreachable,
    /// The Klav server says the account is not entitled to it: the enclave
    /// serves nothing for the account (ADR 0051 §3.5).
    NotEntitled,
    /// The enclave doesn't know the account and the manifest's
    /// `seed_epoch` moved past the one this device saw: Klav Cloud's proxy
    /// lost its keys, and the person sets it up again (ADR 0051 §4.4).
    LostKeys,
    /// The server says its agent is revoked, or no longer has it.
    Revoked,
    /// This build can't verify it (no `hosted-proxy` feature).
    Unsupported,
}

impl HostedState {
    /// Whether the person should see the red row with «Stop using it».
    #[must_use]
    pub fn needs_attention(self) -> bool {
        matches!(
            self,
            Self::Unverified | Self::NotEntitled | Self::LostKeys | Self::Revoked
        )
    }
}

/// The enclave image an attestation matched, as the manifest lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedImageView {
    /// Its version (`0.12.0`).
    pub version: String,
    /// Its commit, 40 hex characters.
    pub commit: String,
    /// `aarch64` or `x86_64`.
    pub arch: String,
    /// `current` or `draining`.
    pub status: String,
    /// PCR0, PCR1 and PCR2, 96 hex characters each.
    pub pcr0: String,
    /// PCR1.
    pub pcr1: String,
    /// PCR2.
    pub pcr2: String,
}

/// `klav proxy cloud status`, the apps' row: never a value or a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedProxyView {
    /// Where it stands.
    pub state: HostedState,
    /// A short code of why, when not verified (`image_revoked`,
    /// `manifest_rollback`, `not_enrolled`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The sentence to show.
    pub message: String,
    /// The account's hosted agent, from the preferences.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<AgentId>,
    /// Its generation, as the enclave said and the attestation bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u32>,
    /// Its channel, `a<agent_id hex>.<endpoint>` (ADR 0051 §3.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// The server's word on the account's entitlement (absent from a server
    /// older than it, or when it couldn't be read).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entitled: Option<bool>,
    /// The image it runs, when verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<HostedImageView>,
    /// The `seq` of the manifest it was checked against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_seq: Option<u64>,
    /// The manifest's `seed_epoch`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_epoch: Option<u32>,
    /// When this device checked (Unix ms).
    pub checked_at_ms: u64,
    /// The endpoint it asked.
    pub endpoint: String,
}

/// What the person does with Klav Cloud's proxy: `klav proxy use klav`,
/// `klav proxy cloud stop` and `klav proxy cloud reset`, and the apps'
/// buttons (ADR 0051 §6.1, §6.3, §4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudAction {
    /// Enroll, verify and name it the account's proxy.
    Use,
    /// «Stop using it»: revoke its agent (changing the keys of what it
    /// held) and use no proxy.
    Stop,
    /// «Reset Klav Cloud proxy»: a new agent at the next generation, the
    /// credentials moved to it, the old one revoked.
    Reset,
}

/// What a [`CloudAction`] did: the proxy's status after it, and what the
/// person should read (issuers to add again, provider tokens to rotate).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudOutcome {
    /// `klav proxy status` after the change.
    pub status: crate::proxy_admin::ProxyStatus,
    /// What it did and what is left to the person, one sentence each.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// How this device reaches Klav Cloud's proxy, and in a test build what it
/// trusts. Nothing in it is secret.
#[derive(Debug, Clone, Default)]
pub struct HostedConfig {
    endpoint: Option<String>,
    #[cfg(feature = "hosted-proxy-testkit")]
    anchors: Option<(Vec<u8>, Vec<[u8; 32]>)>,
}

/// [`HOSTED_PROXY_FILE`]'s contents.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostedFile {
    v: u32,
    /// The highest manifest `seq` this device verified (the watermark of
    /// ADR 0051 §2.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    highest_seq: Option<u64>,
    /// The highest `seed_epoch` of a manifest it verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seed_epoch: Option<u32>,
    /// The highest generation it enrolled at: a reset asks for the next.
    #[serde(default)]
    generation: u32,
    /// Every hosted agent it enrolled, so a grant to one is checked even
    /// after the preferences name another.
    #[serde(default)]
    agents: Vec<AgentId>,
}

/// [`HOSTED_PROXY_FILE`], as read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FileRead {
    /// What it holds (the default when there is no file yet).
    Read(HostedFile),
    /// It doesn't open or parse: read as empty; the next verification
    /// writes it again, with a warning that the watermark was lost.
    Damaged,
    /// Written by a later version: read as empty and never written.
    Newer(u32),
}

impl FileRead {
    fn file(&self) -> HostedFile {
        match self {
            Self::Read(f) => f.clone(),
            Self::Damaged | Self::Newer(_) => HostedFile::default(),
        }
    }
}

impl HostedConfig {
    /// The endpoint [`ENDPOINT_ENV`] names, when it parses (https, or
    /// http to a loopback address); else the default.
    #[must_use]
    pub fn from_env() -> Self {
        let endpoint = std::env::var(ENDPOINT_ENV)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .and_then(|v| crate::url::ServerUrl::parse(v.trim()).ok())
            .map(|u| u.as_str().to_owned());
        Self {
            endpoint,
            #[cfg(feature = "hosted-proxy-testkit")]
            anchors: None,
        }
    }
}

impl Unlocked {
    /// Names another endpoint for Klav Cloud's proxy (`None`: the default,
    /// [`DEFAULT_ENDPOINT`]). Its answers are self-authenticating, so this
    /// can only deny service; plain HTTP only to a loopback address.
    pub fn set_hosted_proxy_endpoint(&mut self, url: Option<&str>) -> ClientResult<()> {
        self.hosted.endpoint = match url {
            Some(url) => Some(crate::url::ServerUrl::parse(url)?.as_str().to_owned()),
            None => None,
        };
        Ok(())
    }

    /// The endpoint this device asks.
    #[must_use]
    pub fn hosted_proxy_endpoint(&self) -> String {
        self.hosted
            .endpoint
            .clone()
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_owned())
    }

    /// Whether `id` is the account's hosted proxy or a hosted agent this
    /// device enrolled: a grant to it waits on a fresh verification.
    pub(crate) fn is_hosted_agent(&self, id: AgentId) -> bool {
        let named = self.preferences().is_ok_and(|p| {
            let s = p.proxy();
            s.mode == klav_core::model::preferences::ProxyMode::Klav && s.agent_id == Some(id)
        });
        named || self.read_hosted_file().file().agents.contains(&id)
    }

    /// Run before a grant is uploaded for `id` (ADR 0051 §2.2 step 7): a
    /// hosted agent gets one only after its attestation, with a fresh
    /// nonce, binds exactly `public`. Any other agent passes.
    pub(crate) async fn check_hosted_wrap(
        &mut self,
        id: AgentId,
        public: &klav_core::crypto::identity::PublicIdentity,
    ) -> ClientResult<()> {
        if !self.is_hosted_agent(id) {
            return Ok(());
        }
        #[cfg(not(feature = "hosted-proxy"))]
        {
            let _ = public;
            Err(ClientError::Invalid(format!(
                "{UNSUPPORTED}: nothing is shared with it from this device"
            )))
        }
        #[cfg(feature = "hosted-proxy")]
        {
            let checked = self
                .verify_hosted_agent(id, public)
                .await
                .map_err(|f| f.into_error())?;
            checked.wrappable()
        }
    }

    fn read_hosted_file(&self) -> FileRead {
        #[derive(Deserialize)]
        struct Format {
            v: u32,
        }
        let blob = match std::fs::read(self.home.file(HOSTED_PROXY_FILE)) {
            Ok(blob) => blob,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return FileRead::Read(HostedFile {
                    v: HOSTED_PROXY_VERSION,
                    ..HostedFile::default()
                });
            }
            Err(_) => return FileRead::Damaged,
        };
        let Ok(json) = klav_core::crypto::local::open_local_data(
            &self.local_key,
            &self.ctx,
            PURPOSE_HOSTED_PROXY,
            &blob,
        ) else {
            return FileRead::Damaged;
        };
        match serde_json::from_slice::<Format>(&json) {
            Ok(f) if f.v > HOSTED_PROXY_VERSION => return FileRead::Newer(f.v),
            Ok(f) if f.v == HOSTED_PROXY_VERSION => {}
            _ => return FileRead::Damaged,
        }
        serde_json::from_slice::<HostedFile>(&json).map_or(FileRead::Damaged, FileRead::Read)
    }

    /// Changes [`HOSTED_PROXY_FILE`] under the home's lock, read again
    /// there; values only move up and agents are only added. A file of a
    /// newer version is never written.
    #[cfg(feature = "hosted-proxy")]
    fn update_hosted_file(&self, change: impl FnOnce(&mut HostedFile)) -> ClientResult<()> {
        let _lock = self.home.lock()?;
        let mut file = match self.read_hosted_file() {
            FileRead::Newer(v) => {
                return Err(ClientError::Invalid(format!(
                    "{HOSTED_PROXY_FILE} is of a newer version of Klav (format {v}): update Klav"
                )));
            }
            FileRead::Damaged => HostedFile::default(),
            FileRead::Read(f) => f,
        };
        let before = file.clone();
        change(&mut file);
        file.v = HOSTED_PROXY_VERSION;
        file.highest_seq = file.highest_seq.max(before.highest_seq);
        file.seed_epoch = file.seed_epoch.max(before.seed_epoch);
        file.generation = file.generation.max(before.generation);
        for agent in &before.agents {
            if !file.agents.contains(agent) {
                file.agents.push(*agent);
            }
        }
        if file == before && before.v == HOSTED_PROXY_VERSION {
            return Ok(());
        }
        let json = serde_json::to_vec(&file)
            .map_err(|e| ClientError::Invalid(format!("hosted proxy state: {e}")))?;
        let blob = klav_core::crypto::local::seal_local_data(
            &self.local_key,
            &self.ctx,
            PURPOSE_HOSTED_PROXY,
            &json,
        )?;
        crate::home::write_private(&self.home.file(HOSTED_PROXY_FILE), &blob)
    }
}

#[cfg(feature = "hosted-proxy")]
pub use verify::{
    HostedCheck, HostedEnroll, HostedFailure, HostedResetReport, HostedStopReport, PreparedCloud,
    PreparedHostedReset, PreparedHostedUse,
};

#[cfg(feature = "hosted-proxy")]
mod verify {
    use klav_core::crypto::identity::PublicIdentity;
    use klav_core::crypto::sign::Signature;
    use klav_core::ids::{AccountId, AgentId};
    use klav_core::model::preferences::{ProxyMode, ProxySetting};
    use klav_core::nitro::{
        HostedProxyExpectation, ImageStatus, ManifestImage, NitroError, VerifiedManifest,
    };
    use klav_proto::Blob;
    use klav_proto::agent::{AgentStatus, HostedProxyStatus};
    use klav_proto::hosted::{
        AttestAnswer, EnrollAnswer, EnrollRequest, ManifestWire, NOT_ENROLLED, NOT_ENTITLED,
    };
    use serde::{Deserialize, Serialize};

    use super::{FileRead, HostedImageView, HostedProxyView, HostedState};
    use crate::error::{ClientError, ClientResult};
    use crate::issuers::IssuerResign;
    use crate::proxy_admin::ProxyAgentView;
    use crate::revoke::RevokeReport;
    use crate::session::{Unlocked, now_ms};

    /// How long the device waits for the enclave.
    const ENCLAVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

    /// What `POST /v1/enroll` carries from the account.
    pub struct HostedEnroll {
        /// The account.
        pub account_id: AccountId,
        /// The account's public identity (kind `0x05`).
        pub account_public_identity: Blob,
        /// The generation it asks for.
        pub generation: u32,
        /// When it was signed (Unix ms); the request carries this same value.
        pub at_ms: u64,
        /// `tuple("klav/v1/sig/hosted-proxy-enroll", account_id, u32_be(generation), u64_be(at_ms))`.
        pub signature: Signature,
    }

    /// Why a check of the hosted proxy failed, and how the apps show it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct HostedFailure {
        /// The state it leaves.
        pub state: HostedState,
        /// A short code (`image_revoked`, `unreachable`, …).
        pub reason: String,
        /// The sentence.
        pub message: String,
        /// What of the check got through, for the view.
        pub entitled: Option<bool>,
        /// The manifest's `seq` and `seed_epoch`, if it verified.
        pub manifest: Option<(u64, u32)>,
    }

    impl HostedFailure {
        fn new(state: HostedState, reason: &str, message: impl Into<String>) -> Self {
            Self {
                state,
                reason: reason.to_owned(),
                message: message.into(),
                entitled: None,
                manifest: None,
            }
        }

        fn unverified(e: &NitroError) -> Self {
            let message = match e {
                NitroError::NoReleaseKey => "this build of Klav has no release-authority key pinned, so it can't verify Klav Cloud's proxy yet; Klav won't share new credentials with it".to_owned(),
                NitroError::ManifestRollback => "Klav Cloud's proxy served an older manifest than this device already verified (a rollback); Klav won't share new credentials with it".to_owned(),
                NitroError::ManifestExpired => "Klav Cloud's proxy served an expired manifest: most likely a stale release, not an attack; Klav won't share new credentials with it until it serves a current one".to_owned(),
                NitroError::ImageRevoked => "Klav Cloud's proxy runs an image the release authority revoked; Klav won't share new credentials with it. Stop using it and rotate the provider tokens it held".to_owned(),
                NitroError::ImageNotListed => "Klav Cloud's proxy runs an image the manifest doesn't list; Klav won't share new credentials with it".to_owned(),
                other => format!(
                    "Klav Cloud's proxy couldn't be verified ({other}); Klav won't share new credentials with it"
                ),
            };
            Self::new(HostedState::Unverified, e.code(), message)
        }

        fn unreachable(what: &str) -> Self {
            Self::new(
                HostedState::Unreachable,
                "unreachable",
                format!(
                    "Klav Cloud's proxy can't be checked now ({what}); nothing is shared with it until it can"
                ),
            )
        }

        /// The error a command that needed a verified proxy returns.
        pub fn into_error(self) -> ClientError {
            match self.state {
                HostedState::Unreachable => ClientError::Network(self.message),
                HostedState::Unverified | HostedState::LostKeys | HostedState::Revoked => {
                    ClientError::Security(self.message)
                }
                HostedState::NotEntitled | HostedState::Unsupported | HostedState::Verified => {
                    ClientError::Invalid(self.message)
                }
            }
        }
    }

    /// A hosted proxy this device just verified (ADR 0051 §2.2 steps 1–6).
    #[derive(Debug, Clone)]
    pub struct HostedCheck {
        /// The agent the attestation binds.
        pub agent_id: AgentId,
        /// Its generation.
        pub generation: u32,
        /// Its channel.
        pub channel: String,
        /// The image it runs.
        pub image: HostedImageView,
        /// The manifest's `seq`.
        pub manifest_seq: u64,
        /// Its `seed_epoch`.
        pub seed_epoch: u32,
        /// Its `egress` addresses (for ADR 0044's strict profile, §3.5).
        pub egress: Vec<String>,
        /// A `current` image newer than this one is listed: it runs a
        /// `draining` image, so no new grant goes to it (§2.4).
        pub superseded: bool,
        /// When it was checked (Unix ms).
        pub checked_at_ms: u64,
    }

    impl HostedCheck {
        /// Whether a grant may be wrapped for it now.
        pub(crate) fn wrappable(&self) -> ClientResult<()> {
            if self.superseded {
                return Err(ClientError::Network(
                    "Klav Cloud's proxy is moving to a newer image; nothing is shared with the older one. Try again in a few minutes".into(),
                ));
            }
            Ok(())
        }

        fn view(&self, entitled: Option<bool>, endpoint: String) -> HostedProxyView {
            HostedProxyView {
                state: HostedState::Verified,
                reason: None,
                message: format!(
                    "Klav Cloud's proxy is attested: version {}, commit {}, verified just now",
                    self.image.version,
                    &self.image.commit[..7.min(self.image.commit.len())]
                ),
                agent_id: Some(self.agent_id),
                generation: Some(self.generation),
                channel: Some(self.channel.clone()),
                entitled,
                image: Some(self.image.clone()),
                manifest_seq: Some(self.manifest_seq),
                seed_epoch: Some(self.seed_epoch),
                checked_at_ms: self.checked_at_ms,
                endpoint,
            }
        }
    }

    /// `klav proxy use klav`, checked: the enrolled agent and what the
    /// sheet shows before presence (ADR 0051 §6.1 step 4).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PreparedHostedUse {
        /// The hosted agent the enclave registered for the account.
        pub agent_id: AgentId,
        /// What it verified.
        pub view: HostedProxyView,
        /// The preferences items an agent wrote that the commit replaces.
        #[serde(skip)]
        replaces: Vec<crate::session::ItemLocation>,
        /// The agent that wrote the preferences this replaces, if one did.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub replaces_agent: Option<AgentId>,
        /// What the person should know before confirming.
        #[serde(default)]
        pub warnings: Vec<String>,
    }

    /// `klav proxy cloud stop`: the hosted agent revoked (with its item
    /// keys changed) and the setting cleared.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct HostedStopReport {
        /// The revocation, when the server still had the agent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revoked: Option<RevokeReport>,
        /// The issuers re-signed with no proxy.
        pub issuers: IssuerResign,
        /// The provider tokens it held: the person rotates them at each
        /// provider (ADR 0036 §18).
        pub rotate_at_provider: Vec<String>,
    }

    /// `klav proxy cloud reset`, checked: a new agent at the next
    /// generation (ADR 0051 §3.2, §4.4).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PreparedHostedReset {
        /// The agent it replaces, if the account had one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub old_agent_id: Option<AgentId>,
        /// The new agent and what it verified.
        pub new: PreparedHostedUse,
        /// The credentials it shares with the new agent.
        pub credentials: Vec<String>,
    }

    /// What a reset did.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct HostedResetReport {
        /// The new hosted agent, as the server reports it.
        pub agent: Option<ProxyAgentView>,
        /// The credentials shared with it.
        pub shared: Vec<String>,
        /// Sharing them failed: why (the setting is not changed then).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub share_failed: Option<String>,
        /// The old agent's revocation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revoked: Option<RevokeReport>,
        /// The issuers re-signed with no proxy: the person adds them again
        /// for the new one, whose address changed.
        pub issuers: IssuerResign,
    }

    #[derive(Deserialize)]
    struct Refusal {
        #[serde(default)]
        error: String,
    }

    impl Unlocked {
        /// Sets the trust anchors to a fake NSM's root and test release
        /// keys. Only in a test build (`hosted-proxy-testkit`, which
        /// `klav-core`'s `nitro-testkit` refuses in a release build).
        #[cfg(feature = "hosted-proxy-testkit")]
        pub fn set_hosted_proxy_test_anchors(&mut self, root: &[u8], keys: &[[u8; 32]]) {
            self.hosted.anchors = Some((root.to_vec(), keys.to_vec()));
        }

        /// Whether this build has the release-authority keys to verify
        /// anything: a release build without them refuses before any
        /// request (ADR 0051 §14).
        fn release_keys_pinned(&self) -> bool {
            #[cfg(feature = "hosted-proxy-testkit")]
            if let Some((_, keys)) = &self.hosted.anchors {
                return !keys.is_empty();
            }
            !klav_core::nitro::RELEASE_AUTHORITY_KEYS.is_empty()
        }

        fn verify_manifest_bytes(
            &self,
            bytes: &[u8],
            signature: &[u8; 64],
            highest: Option<u64>,
            now: u64,
        ) -> Result<VerifiedManifest, NitroError> {
            #[cfg(feature = "hosted-proxy-testkit")]
            if let Some((_, keys)) = &self.hosted.anchors {
                return klav_core::nitro::fake::verify_manifest_with(
                    bytes, signature, keys, highest, now,
                );
            }
            klav_core::nitro::verify_manifest(bytes, signature, highest, now)
        }

        fn verify_document_bytes<'m>(
            &self,
            document: &[u8],
            manifest: &'m VerifiedManifest,
            expected: &HostedProxyExpectation<'_>,
        ) -> Result<&'m ManifestImage, NitroError> {
            #[cfg(feature = "hosted-proxy-testkit")]
            if let Some((root, _)) = &self.hosted.anchors {
                return klav_core::nitro::fake::verify_hosted_proxy_with(
                    document, root, manifest, expected,
                );
            }
            klav_core::nitro::verify_hosted_proxy(document, manifest, expected)
        }

        fn enclave_http() -> ClientResult<reqwest::Client> {
            crate::api::plain_client(ENCLAVE_TIMEOUT)
        }

        /// Signs the account's request to enroll in Klav Cloud's hosted
        /// proxy at `generation`, at `at_ms` (ADR 0051 §6.1 step 2). It
        /// wraps nothing and grants nothing: the enclave only registers a
        /// pending agent, which the person still approves after verifying
        /// its attestation.
        pub fn sign_hosted_proxy_enroll(&self, generation: u32, at_ms: u64) -> HostedEnroll {
            let account_id = self.account.account_id;
            HostedEnroll {
                account_id,
                account_public_identity: Blob::new(self.identity.public().encode().to_vec()),
                generation,
                at_ms,
                signature: klav_core::nitro::sign_enroll(
                    &self.identity,
                    account_id,
                    generation,
                    at_ms,
                ),
            }
        }

        /// `GET /v1/account/hosted-proxy`: whether the account is entitled
        /// (ADR 0051 §15). `None` from a server older than it (`404`).
        pub async fn hosted_proxy_entitlement(&mut self) -> ClientResult<Option<bool>> {
            let res = self
                .authed(
                    reqwest::Method::GET,
                    "/v1/account/hosted-proxy",
                    &crate::api::Body::Empty,
                )
                .await;
            match res {
                Ok(res) => {
                    let status: HostedProxyStatus = crate::api::json(res).await?;
                    Ok(Some(status.entitled))
                }
                Err(ClientError::Api { status: 404, .. }) => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// The manifest, verified against the pinned keys, the watermark
        /// and this account's server; the watermark moves up.
        async fn fetch_manifest(
            &self,
            http: &reqwest::Client,
        ) -> Result<VerifiedManifest, HostedFailure> {
            if !self.release_keys_pinned() {
                return Err(HostedFailure::unverified(&NitroError::NoReleaseKey));
            }
            let endpoint = self.hosted_proxy_endpoint();
            let res = http
                .get(format!("{endpoint}/v1/manifest"))
                .send()
                .await
                .map_err(|_| HostedFailure::unreachable("its manifest did not come"))?;
            if !res.status().is_success() {
                return Err(HostedFailure::unreachable(&format!(
                    "its manifest answered {}",
                    res.status().as_u16()
                )));
            }
            let wire: ManifestWire = res
                .json()
                .await
                .map_err(|_| HostedFailure::unreachable("its manifest is not readable"))?;
            let signature: [u8; 64] = data_encoding::HEXLOWER_PERMISSIVE
                .decode(wire.signature.as_bytes())
                .ok()
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| HostedFailure::unverified(&NitroError::ManifestSignature))?;
            let read = self.read_hosted_file();
            let highest = read.file().highest_seq;
            let now = u64::try_from(now_ms()).unwrap_or_default();
            let manifest = self
                .verify_manifest_bytes(wire.manifest.as_bytes(), &signature, highest, now)
                .map_err(|e| HostedFailure::unverified(&e))?;
            // Q6 (a): the enclave serves accounts of one Klav server only.
            if !manifest
                .server()
                .eq_ignore_ascii_case(self.api.base().host())
            {
                return Err(HostedFailure::new(
                    HostedState::Unverified,
                    "other_server",
                    format!(
                        "Klav Cloud's proxy serves accounts on {} only, and this account is on {}",
                        manifest.server(),
                        self.api.base().host()
                    ),
                ));
            }
            if self.hosted.endpoint.is_none() {
                let host = reqwest::Url::parse(&endpoint)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_owned))
                    .unwrap_or_default();
                if !host.eq_ignore_ascii_case(manifest.endpoint()) {
                    return Err(HostedFailure::new(
                        HostedState::Unverified,
                        "other_endpoint",
                        "Klav Cloud's manifest names another endpoint than the one this device asked",
                    ));
                }
            }
            if !matches!(read, FileRead::Newer(_)) {
                let (seq, epoch) = (manifest.seq(), manifest.seed_epoch());
                let _ = self.update_hosted_file(|f| {
                    f.highest_seq = Some(seq);
                    f.seed_epoch = Some(epoch);
                });
            }
            Ok(manifest)
        }

        /// ADR 0051 §2.2 steps 1–6 for `agent`, whose keys the server
        /// shows as `public`: the manifest, then an attestation with a
        /// fresh nonce whose `user_data` binds exactly those keys.
        pub async fn verify_hosted_agent(
            &mut self,
            agent: AgentId,
            public: &PublicIdentity,
        ) -> Result<HostedCheck, HostedFailure> {
            let http =
                Self::enclave_http().map_err(|e| HostedFailure::unreachable(&e.to_string()))?;
            let seen_epoch = self.read_hosted_file().file().seed_epoch;
            let manifest = self.fetch_manifest(&http).await?;
            let with_manifest = |mut f: HostedFailure| {
                f.manifest = Some((manifest.seq(), manifest.seed_epoch()));
                f
            };
            let account = self.account.account_id;
            let nonce = klav_core::crypto::random::array::<32>();
            let endpoint = self.hosted_proxy_endpoint();
            let res = http
                .get(format!(
                    "{endpoint}/v1/attest?account={account}&nonce={}",
                    data_encoding::BASE64URL_NOPAD.encode(&nonce)
                ))
                .send()
                .await
                .map_err(|_| {
                    with_manifest(HostedFailure::unreachable("its attestation did not come"))
                })?;
            let status = res.status().as_u16();
            if !(200..300).contains(&status) {
                let refusal: Refusal = res.json().await.unwrap_or(Refusal {
                    error: String::new(),
                });
                if status == 404 && refusal.error == NOT_ENROLLED {
                    let lost = seen_epoch.is_some_and(|seen| manifest.seed_epoch() > seen);
                    return Err(with_manifest(if lost {
                        HostedFailure::new(
                            HostedState::LostKeys,
                            "lost_keys",
                            "Klav Cloud's proxy lost its keys. Set it up again to keep using your credentials from sandboxes",
                        )
                    } else {
                        HostedFailure::new(
                            HostedState::Unreachable,
                            "not_enrolled",
                            "Klav Cloud's proxy doesn't know this account's proxy right now; nothing is shared with it until it does",
                        )
                    }));
                }
                if refusal.error == NOT_ENTITLED {
                    return Err(with_manifest(not_entitled()));
                }
                return Err(with_manifest(HostedFailure::unreachable(&format!(
                    "it answered {status}"
                ))));
            }
            let answer: AttestAnswer = res.json().await.map_err(|_| {
                with_manifest(HostedFailure::unreachable(
                    "its attestation is not readable",
                ))
            })?;
            if answer.agent_id != agent {
                return Err(with_manifest(HostedFailure::new(
                    HostedState::Unverified,
                    "other_agent",
                    "Klav Cloud's proxy attests another agent than the one the account names; Klav won't share new credentials with it",
                )));
            }
            let binding =
                klav_core::nitro::enclave_binding(account, agent, public, answer.generation);
            let now = u64::try_from(now_ms()).unwrap_or_default();
            let image = self
                .verify_document_bytes(
                    answer.document.as_bytes(),
                    &manifest,
                    &HostedProxyExpectation {
                        nonce: &nonce,
                        binding: &binding,
                        now_ms: now,
                    },
                )
                .map_err(|e| with_manifest(HostedFailure::unverified(&e)))?;
            let superseded = image.status() == ImageStatus::Draining
                && manifest.images().iter().any(|other| {
                    other.status() == ImageStatus::Current && other.version() > image.version()
                });
            let hex = |p: &[u8]| data_encoding::HEXLOWER.encode(p);
            let measurement = image.measurement();
            Ok(HostedCheck {
                agent_id: agent,
                generation: answer.generation,
                channel: channel_name(agent, manifest.endpoint()),
                image: HostedImageView {
                    version: image.version_text().to_owned(),
                    commit: image.commit().to_owned(),
                    arch: image.arch().to_owned(),
                    status: match image.status() {
                        ImageStatus::Current => "current",
                        ImageStatus::Draining => "draining",
                        ImageStatus::Revoked => "revoked",
                    }
                    .to_owned(),
                    pcr0: hex(&measurement.pcr0),
                    pcr1: hex(&measurement.pcr1),
                    pcr2: hex(&measurement.pcr2),
                },
                manifest_seq: manifest.seq(),
                seed_epoch: manifest.seed_epoch(),
                egress: manifest.egress().to_vec(),
                superseded,
                checked_at_ms: now,
            })
        }

        /// The agent the server shows for `id`, and its keys: pending or
        /// active, never one this device revoked.
        async fn hosted_agent_keys(
            &mut self,
            id: AgentId,
        ) -> Result<(klav_proto::agent::AgentInfo, PublicIdentity), HostedFailure> {
            if self.cache.revocations.contains_key(&id) {
                return Err(revoked());
            }
            let info = match self.agent_info(id).await {
                Ok(info) => info,
                Err(ClientError::NotFound(_) | ClientError::Api { status: 404, .. }) => {
                    return Err(revoked());
                }
                Err(e) => return Err(HostedFailure::unreachable(&e.to_string())),
            };
            if !matches!(info.status, AgentStatus::Pending | AgentStatus::Active) {
                return Err(revoked());
            }
            let public = PublicIdentity::decode(info.public_identity.as_bytes()).map_err(|_| {
                HostedFailure::new(
                    HostedState::Unverified,
                    "agent_key",
                    "the server shows a malformed key for the account's hosted proxy",
                )
            })?;
            Ok((info, public))
        }

        /// The hosted proxy's status (ADR 0051 §6.3), checked now: the
        /// preferences' agent, the server's entitlement, the manifest and
        /// a fresh attestation. Never fails for what it finds; only for
        /// what keeps it from looking (no session, unreadable preferences).
        pub async fn hosted_proxy_status(&mut self) -> ClientResult<Option<HostedProxyView>> {
            let setting = self.preferences()?.proxy();
            if setting.mode != ProxyMode::Klav {
                return Ok(None);
            }
            Ok(Some(self.hosted_view(setting.agent_id).await))
        }

        pub(crate) async fn hosted_view(&mut self, agent: Option<AgentId>) -> HostedProxyView {
            let endpoint = self.hosted_proxy_endpoint();
            let checked_at_ms = u64::try_from(now_ms()).unwrap_or_default();
            let entitled = self.hosted_proxy_entitlement().await.ok().flatten();
            let fail = |f: HostedFailure| {
                let (manifest_seq, seed_epoch) = match f.manifest {
                    Some((seq, epoch)) => (Some(seq), Some(epoch)),
                    None => (None, None),
                };
                HostedProxyView {
                    state: f.state,
                    reason: Some(f.reason),
                    message: f.message,
                    agent_id: agent,
                    generation: None,
                    channel: None,
                    entitled: f.entitled.or(entitled),
                    image: None,
                    manifest_seq,
                    seed_epoch,
                    checked_at_ms,
                    endpoint: endpoint.clone(),
                }
            };
            let Some(agent) = agent else {
                return fail(HostedFailure::new(
                    HostedState::Unverified,
                    "no_agent",
                    "the account's setting names Klav Cloud's proxy without its agent; set it up again with `klav proxy use klav`",
                ));
            };
            if entitled == Some(false) {
                return fail(not_entitled());
            }
            let public = match self.hosted_agent_keys(agent).await {
                Ok((_, public)) => public,
                Err(f) => return fail(f),
            };
            match self.verify_hosted_agent(agent, &public).await {
                Ok(check) => check.view(entitled, endpoint),
                Err(f) => fail(f),
            }
        }

        /// Checks `klav proxy use klav` (ADR 0051 §6.1 steps 1–4): the
        /// account's entitlement, the manifest, the enroll request this
        /// device signs, and the attestation of the agent the enclave
        /// registered, against the keys the server shows for it. The agent
        /// stays pending: the commit writes the setting after presence, and
        /// the first grant approves it.
        pub async fn prepare_hosted_proxy_use(&mut self) -> ClientResult<PreparedHostedUse> {
            self.prepare_hosted_enroll(false, None).await
        }

        /// Enrolls the account (`reset`: at the next generation, replacing
        /// `old`) and verifies the agent the enclave registered.
        async fn prepare_hosted_enroll(
            &mut self,
            reset: bool,
            old: Option<AgentId>,
        ) -> ClientResult<PreparedHostedUse> {
            self.sync().await?;
            if !self.release_keys_pinned() {
                return Err(HostedFailure::unverified(&NitroError::NoReleaseKey).into_error());
            }
            let mut warnings = Vec::new();
            let (current, replaces) = match self.read_preferences()? {
                crate::preferences::PreferencesRead::Read(p) => (Some(p.proxy()), Vec::new()),
                crate::preferences::PreferencesRead::ByAgent(items) => (None, items),
            };
            let replaces_agent = replaces.first().map(|(_, agent)| *agent);
            if let Some(by) = replaces_agent {
                warnings.push(crate::proxy_admin::replace_warning(by));
            }
            if current.is_some_and(|c| c.mode == ProxyMode::None) {
                warnings.push(crate::proxy_admin::OLDER_CLIENTS_PREFERENCES.to_owned());
            }
            warnings.push(OLDER_CLIENTS_HOSTED.to_owned());
            match current {
                Some(c) if c.mode == ProxyMode::Klav && !reset => {
                    if let Some(id) = c.agent_id
                        && self.hosted_agent_keys(id).await.is_ok()
                    {
                        return Err(ClientError::Invalid(
                            "the account already uses Klav Cloud's proxy: `klav proxy status` shows it, and `klav proxy cloud reset` sets it up again".into(),
                        ));
                    }
                }
                Some(c) if c.mode == ProxyMode::Own => {
                    if let Some(old) = c.agent_id {
                        let holding = self.agents().await?.into_iter().find(|a| {
                            a.id == old
                                && a.status == AgentStatus::Active
                                && a.grant.as_ref().is_some_and(|g| !g.items.is_empty())
                        });
                        if let Some(old) = holding {
                            return Err(ClientError::Invalid(format!(
                                "the current proxy, {:?}, still holds credentials: revoke it first with `klav agent revoke {}` (that also changes the keys of what it held)",
                                old.name, old.id
                            )));
                        }
                    }
                }
                _ => {}
            }
            match self.hosted_proxy_entitlement().await? {
                Some(true) => {}
                Some(false) => return Err(not_entitled().into_error()),
                None => {
                    return Err(ClientError::Invalid(
                        "this Klav server is older than Klav Cloud's proxy (ADR 0051): it can't use it".into(),
                    ));
                }
            }
            let http = Self::enclave_http()?;
            // Before anything is signed: a manifest this device accepts.
            let manifest = self
                .fetch_manifest(&http)
                .await
                .map_err(HostedFailure::into_error)?;
            let floor = self.read_hosted_file().file().generation;
            let generation = if reset { floor + 1 } else { floor };
            let at_ms = u64::try_from(now_ms()).unwrap_or_default();
            let signed = self.sign_hosted_proxy_enroll(generation, at_ms);
            let endpoint = self.hosted_proxy_endpoint();
            let res = http
                .post(format!("{endpoint}/v1/enroll"))
                .json(&EnrollRequest {
                    account_id: signed.account_id,
                    email: self.account.email.clone(),
                    account_public_identity: signed.account_public_identity,
                    generation,
                    at_ms,
                    signature: Blob::new(signed.signature.to_bytes().to_vec()),
                })
                .send()
                .await
                .map_err(|_| {
                    HostedFailure::unreachable("the enroll did not go through").into_error()
                })?;
            let status = res.status().as_u16();
            if !res.status().is_success() {
                let refusal: Refusal = res.json().await.unwrap_or(Refusal {
                    error: String::new(),
                });
                if refusal.error == NOT_ENTITLED {
                    return Err(not_entitled().into_error());
                }
                return Err(ClientError::Network(format!(
                    "Klav Cloud's proxy refused to enroll this account ({status} {})",
                    refusal.error
                )));
            }
            let answer: EnrollAnswer = res.json().await.map_err(|_| {
                ClientError::Network("Klav Cloud's proxy sent an unreadable enroll answer".into())
            })?;
            if answer.generation != generation
                || answer.channel != channel_name(answer.agent_id, manifest.endpoint())
                || (old.is_some() && Some(answer.agent_id) == old)
            {
                return Err(ClientError::Security(
                    "Klav Cloud's proxy answered the enroll with another generation or channel than asked; nothing was set".into(),
                ));
            }
            self.update_hosted_file(|f| {
                f.generation = generation;
                f.agents.push(answer.agent_id);
            })?;
            // The keys the server shows for that pending agent must be the
            // ones an approved image holds (§6.1 step 4: no six words).
            let (_, public) = self
                .hosted_agent_keys(answer.agent_id)
                .await
                .map_err(HostedFailure::into_error)?;
            let check = self
                .verify_hosted_agent(answer.agent_id, &public)
                .await
                .map_err(HostedFailure::into_error)?;
            check.wrappable()?;
            if !check.egress.is_empty() {
                warnings.push(format!(
                    "Klav Cloud's proxy reaches the Klav server from {}; a strict network profile with those addresses is not signed by this version yet (ADR 0044, ADR 0051 §3.5)",
                    check.egress.join(", ")
                ));
            }
            Ok(PreparedHostedUse {
                agent_id: answer.agent_id,
                view: check.view(Some(true), endpoint),
                replaces: replaces.into_iter().map(|(loc, _)| loc).collect(),
                replaces_agent,
                warnings,
            })
        }

        /// Writes `proxy: {mode: "klav", agent_id}` after presence (ADR
        /// 0051 §6.1 step 5), once a fresh attestation of the same agent
        /// verified again (the dialog may outlast the 5 minutes of the
        /// first). Then issuers that name another proxy are re-signed with
        /// none, as for `klav proxy use`.
        pub async fn commit_hosted_proxy_use(
            &mut self,
            prepared: PreparedHostedUse,
        ) -> ClientResult<IssuerResign> {
            let id = prepared.agent_id;
            let (_, public) = self
                .hosted_agent_keys(id)
                .await
                .map_err(HostedFailure::into_error)?;
            self.verify_hosted_agent(id, &public)
                .await
                .map_err(HostedFailure::into_error)?
                .wrappable()?;
            self.set_proxy_setting_replacing(ProxySetting::klav(id), &prepared.replaces)
                .await?;
            self.resign_issuers(Some(id)).await
        }

        /// «Stop using it» (ADR 0051 §6.3, ADR 0036 §3): revokes the
        /// account's hosted agent, which changes the key of every item it
        /// held, and sets the proxy to none. Works whatever the
        /// verification says, and when the server no longer has the agent.
        pub async fn stop_hosted_proxy(&mut self) -> ClientResult<HostedStopReport> {
            self.sync().await?;
            let setting = self.preferences()?.proxy();
            if setting.mode != ProxyMode::Klav {
                return Err(ClientError::Invalid(
                    "the account doesn't use Klav Cloud's proxy".into(),
                ));
            }
            let mut rotate_at_provider = Vec::new();
            let revoked = match setting.agent_id {
                Some(id) => {
                    if let Ok(grant) = self.current_proxy().await
                        && let Some(payload) = &grant.payload
                    {
                        rotate_at_provider = payload
                            .items
                            .iter()
                            .map(|i| self.item_names_for(i.item_id))
                            .collect();
                    }
                    match self.revoke_agent(id, true).await {
                        Ok(report) => Some(report),
                        Err(ClientError::NotFound(_) | ClientError::Api { status: 404, .. }) => {
                            None
                        }
                        Err(e) => return Err(e),
                    }
                }
                None => None,
            };
            self.set_proxy_setting_replacing(ProxySetting::NONE, &[])
                .await?;
            let issuers = self.resign_issuers(None).await?;
            Ok(HostedStopReport {
                revoked,
                issuers,
                rotate_at_provider,
            })
        }

        /// Checks «Reset Klav Cloud proxy» (ADR 0051 §3.2, §4.4): enrolls
        /// the account again at the next generation, which gives a new agent
        /// with new keys, and verifies it. Also the way back after the
        /// enclave lost its keys.
        pub async fn prepare_hosted_proxy_reset(&mut self) -> ClientResult<PreparedHostedReset> {
            self.sync().await?;
            let setting = self.preferences()?.proxy();
            if setting.mode != ProxyMode::Klav {
                return Err(ClientError::Invalid(
                    "the account doesn't use Klav Cloud's proxy: `klav proxy use klav` sets it up"
                        .into(),
                ));
            }
            let old = setting.agent_id;
            let credentials = match self.current_proxy().await {
                Ok(grant) => grant
                    .payload
                    .iter()
                    .flat_map(|p| p.items.iter())
                    .map(|i| self.item_names_for(i.item_id))
                    .collect(),
                Err(_) => Vec::new(),
            };
            // A generation above the old agent's, whatever this device
            // remembers.
            if let Ok(answer) = self.hosted_generation().await {
                self.update_hosted_file(|f| f.generation = f.generation.max(answer))?;
            }
            let new = self.prepare_hosted_enroll(true, old).await?;
            Ok(PreparedHostedReset {
                old_agent_id: old,
                new,
                credentials,
            })
        }

        /// The generation the enclave says the account's agent has,
        /// without verifying anything: only to pick a higher one.
        async fn hosted_generation(&self) -> ClientResult<u32> {
            let http = Self::enclave_http()?;
            let endpoint = self.hosted_proxy_endpoint();
            let account = self.account.account_id;
            let nonce = klav_core::crypto::random::array::<32>();
            let answer: AttestAnswer = http
                .get(format!(
                    "{endpoint}/v1/attest?account={account}&nonce={}",
                    data_encoding::BASE64URL_NOPAD.encode(&nonce)
                ))
                .send()
                .await
                .map_err(|e| ClientError::Network(e.to_string()))?
                .error_for_status()
                .map_err(|e| ClientError::Network(e.to_string()))?
                .json()
                .await
                .map_err(|e| ClientError::Network(e.to_string()))?;
            Ok(answer.generation)
        }

        /// Does a reset checked by [`Self::prepare_hosted_proxy_reset`],
        /// after presence: shares the old agent's credentials (items,
        /// profiles and rules as signed) with the new one, verified again
        /// before the grant; names the new one in the preferences; revokes
        /// the old one, which changes the keys of what it held; and
        /// re-signs issuers with no proxy (the new one has another address,
        /// so the person adds them again).
        pub async fn commit_hosted_proxy_reset(
            &mut self,
            prepared: PreparedHostedReset,
        ) -> ClientResult<HostedResetReport> {
            let new_id = prepared.new.agent_id;
            let (_, public) = self
                .hosted_agent_keys(new_id)
                .await
                .map_err(HostedFailure::into_error)?;
            self.verify_hosted_agent(new_id, &public)
                .await
                .map_err(HostedFailure::into_error)?
                .wrappable()?;
            let mut report = HostedResetReport {
                agent: None,
                shared: Vec::new(),
                share_failed: None,
                revoked: None,
                issuers: IssuerResign::default(),
            };
            // The old grant, as this account signed it.
            let held = match self.current_proxy().await {
                Ok(grant) => Some(self.held_request(&grant)?.0),
                Err(_) => None,
            };
            if let Some(mut request) = held.filter(|r| !r.items.is_empty()) {
                // Issuers name the old proxy's address: they don't carry over.
                request.issuers.clear();
                let names: Vec<String> = request
                    .items
                    .iter()
                    .map(|l| self.item_names_for(l.item))
                    .collect();
                let pairing = klav_core::crypto::agent::pairing_code(&public);
                match self
                    .grant_items_at(new_id, request, &pairing, Some(0))
                    .await
                {
                    Ok(r) if r.granted => report.shared = names,
                    Ok(r) => {
                        report.share_failed =
                            Some(r.failed.unwrap_or_else(|| "the grant was not taken".into()));
                    }
                    Err(e) => report.share_failed = Some(e.to_string()),
                }
                if report.share_failed.is_some() {
                    return Ok(report);
                }
            }
            self.set_proxy_setting_replacing(ProxySetting::klav(new_id), &prepared.new.replaces)
                .await?;
            if let Some(old) = prepared.old_agent_id {
                report.revoked = match self.revoke_agent(old, true).await {
                    Ok(r) => Some(r),
                    Err(ClientError::NotFound(_) | ClientError::Api { status: 404, .. }) => None,
                    Err(e) => {
                        self.warnings.push(format!(
                            "the old hosted agent {old} could not be revoked yet: {e}; `klav agent revoke {old} --rotate` finishes it"
                        ));
                        None
                    }
                };
            }
            report.issuers = self.resign_issuers(Some(new_id)).await?;
            report.agent = self
                .agents()
                .await
                .ok()
                .and_then(|list| list.into_iter().find(|a| a.id == new_id))
                .map(|a| ProxyAgentView {
                    id: a.id,
                    name: a.name,
                    status: a.status,
                    pairing_code: a.pairing_code,
                    paused: a.paused.is_some(),
                    last_seen_at: a.last_seen_at,
                });
            Ok(report)
        }

        /// The title of `item`, or its ID when this device no longer sees it.
        fn item_names_for(&self, item: klav_core::ids::ItemId) -> String {
            self.locate_item(item)
                .and_then(|loc| self.item_summary(loc).ok())
                .map_or_else(|| item.to_string(), |s| s.title)
        }
    }

    /// A [`CloudAction`](super::CloudAction), checked and ready for
    /// presence.
    #[derive(Debug, Clone)]
    pub enum PreparedCloud {
        /// `use klav`, enrolled and verified.
        Use(PreparedHostedUse),
        /// «Stop using it»: nothing to check beyond the setting.
        Stop,
        /// A reset, the new agent enrolled and verified.
        Reset(PreparedHostedReset),
    }

    impl PreparedCloud {
        /// The image version the presence prompt names, when verified.
        #[must_use]
        pub fn version(&self) -> Option<&str> {
            let view = match self {
                Self::Use(p) => &p.view,
                Self::Reset(r) => &r.new.view,
                Self::Stop => return None,
            };
            view.image.as_ref().map(|i| i.version.as_str())
        }

        /// What the person should know before confirming.
        #[must_use]
        pub fn warnings(&self) -> &[String] {
            match self {
                Self::Use(p) => &p.warnings,
                Self::Reset(r) => &r.new.warnings,
                Self::Stop => &[],
            }
        }

        /// The action.
        #[must_use]
        pub fn action(&self) -> super::CloudAction {
            match self {
                Self::Use(_) => super::CloudAction::Use,
                Self::Stop => super::CloudAction::Stop,
                Self::Reset(_) => super::CloudAction::Reset,
            }
        }
    }

    fn issuer_notes(resigned: &IssuerResign, notes: &mut Vec<String>) {
        if !resigned.done.is_empty() {
            notes.push(format!(
                "these issuers now name no proxy; make them issuers of Klav Cloud's proxy with `klav proxy issuer add` (its address is the channel `klav proxy status` shows): {}",
                resigned.done.join(", ")
            ));
        }
        if !resigned.failed.is_empty() {
            notes.push(format!(
                "these issuers could not be re-signed yet; run it again to finish them: {}",
                resigned.failed.join(", ")
            ));
        }
    }

    impl Unlocked {
        /// Checks `action` before presence.
        pub async fn prepare_cloud(
            &mut self,
            action: super::CloudAction,
        ) -> ClientResult<PreparedCloud> {
            match action {
                super::CloudAction::Use => {
                    Ok(PreparedCloud::Use(self.prepare_hosted_proxy_use().await?))
                }
                super::CloudAction::Stop => {
                    self.sync().await?;
                    if self.preferences()?.proxy().mode != ProxyMode::Klav {
                        return Err(ClientError::Invalid(
                            "the account doesn't use Klav Cloud's proxy".into(),
                        ));
                    }
                    Ok(PreparedCloud::Stop)
                }
                super::CloudAction::Reset => Ok(PreparedCloud::Reset(
                    self.prepare_hosted_proxy_reset().await?,
                )),
            }
        }

        /// Does what [`Self::prepare_cloud`] checked, after presence.
        pub async fn commit_cloud(
            &mut self,
            prepared: PreparedCloud,
        ) -> ClientResult<super::CloudOutcome> {
            let mut notes = Vec::new();
            match prepared {
                PreparedCloud::Use(p) => {
                    let resigned = self.commit_hosted_proxy_use(p).await?;
                    issuer_notes(&resigned, &mut notes);
                }
                PreparedCloud::Stop => {
                    let report = self.stop_hosted_proxy().await?;
                    match &report.revoked {
                        Some(r) => {
                            notes.push(
                                "Klav Cloud's proxy agent is revoked, and the keys of what it held changed"
                                    .into(),
                            );
                            if let Some(failed) = &r.failed {
                                notes.push(format!("not finished: {failed}; `klav agent revoke {} --rotate` finishes it", r.agent.id));
                            }
                        }
                        None => notes.push(
                            "the Klav server no longer had Klav Cloud's proxy agent: nothing to revoke".into(),
                        ),
                    }
                    if !report.rotate_at_provider.is_empty() {
                        notes.push(format!(
                            "rotate these provider tokens at each provider: Klav can't do it for you (ADR 0036 §18): {}",
                            report.rotate_at_provider.join(", ")
                        ));
                    }
                    issuer_notes(&report.issuers, &mut notes);
                }
                PreparedCloud::Reset(r) => {
                    let report = self.commit_hosted_proxy_reset(r).await?;
                    if let Some(failed) = &report.share_failed {
                        return Err(ClientError::Invalid(format!(
                            "the new Klav Cloud proxy agent did not get the credentials ({failed}); the account still uses the old one. Run the reset again"
                        )));
                    }
                    if !report.shared.is_empty() {
                        notes.push(format!(
                            "shared with the new agent: {}",
                            report.shared.join(", ")
                        ));
                    }
                    if report.revoked.is_some() {
                        notes.push(
                            "the old agent is revoked, and the keys of what it held changed".into(),
                        );
                    }
                    issuer_notes(&report.issuers, &mut notes);
                }
            }
            Ok(super::CloudOutcome {
                status: self.proxy_status().await?,
                notes,
            })
        }
    }

    /// What devices older than this layer do with the setting (ADR 0051 §9).
    pub const OLDER_CLIENTS_HOSTED: &str = "Devices with a Klav older than Klav Cloud's proxy refuse every proxy command once the account uses it, and never share a credential with it. Update Klav on every device you manage the proxy from";

    /// `a<agent_id hex>.<endpoint>` (ADR 0051 §3.4).
    #[must_use]
    pub fn channel_name(agent: AgentId, endpoint: &str) -> String {
        format!(
            "a{}.{}",
            data_encoding::HEXLOWER.encode(agent.as_bytes()),
            endpoint.to_ascii_lowercase()
        )
    }

    fn not_entitled() -> HostedFailure {
        let mut f = HostedFailure::new(
            HostedState::NotEntitled,
            "not_entitled",
            "this account isn't entitled to Klav Cloud's proxy (invited beta accounts only); it serves nothing for it",
        );
        f.entitled = Some(false);
        f
    }

    fn revoked() -> HostedFailure {
        HostedFailure::new(
            HostedState::Revoked,
            "agent_revoked",
            "the account's hosted proxy agent is revoked or gone; stop using it, or set it up again",
        )
    }
}

#[cfg(feature = "hosted-proxy")]
pub use verify::{OLDER_CLIENTS_HOSTED, channel_name};
