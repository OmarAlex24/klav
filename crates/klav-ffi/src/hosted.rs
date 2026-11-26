//! Klav Cloud's proxy in the apps (ADR 0051, layer 5): the row in the Mac's
//! «Development › Sandboxes» and «MCP servers» and in the iPhone's
//! «Settings › Credential proxy», «Use Klav Cloud Proxy», the red row with
//! «Stop using it», and «Set it up again».
//!
//! Everything here comes from `klav-client`, which verifies the enclave's
//! attestation and the signed manifest in `klav-core` (`nitro-attestation`):
//! no check is written in Swift. Nothing crossing is a secret: the image's
//! version, commit and PCRs are public, as is the manifest.

use klav_client::hosted_proxy::{CloudAction, CloudOutcome, HostedProxyView, HostedState};
use klav_client::proxy_admin::ProxyStatus;
use klav_core::model::preferences::ProxyMode;

/// Where Klav Cloud's proxy stands for the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HostedProxyState {
    /// The account doesn't use it (its own proxy, or none).
    NotUsed,
    /// Attested and listed: credentials may be shared with it.
    Verified,
    /// It couldn't be verified: the red row with «Stop using it». No new
    /// credential goes to it; what it holds stays until the person acts.
    Unverified,
    /// It, or the Klav server, didn't answer: nothing is shared now, and
    /// nothing is wrong either.
    Unreachable,
    /// The account isn't entitled: it serves nothing for it (red row).
    NotEntitled,
    /// It lost its keys: «Set it up again» (red row).
    LostKeys,
    /// Its agent is revoked or gone (red row).
    Revoked,
    /// This build can't verify it.
    Unsupported,
}

/// What the person does with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HostedProxyAction {
    /// «Use Klav Cloud Proxy»: enroll, verify, then name it the proxy.
    Use,
    /// «Stop using it»: revoke its agent and change the keys of what it held.
    Stop,
    /// «Set it up again»: a new agent, the credentials moved, the old one revoked.
    Reset,
}

/// Klav Cloud's proxy as the apps show it. Never a value or a key.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HostedProxyInfo {
    /// Where it stands.
    pub state: HostedProxyState,
    /// The red row, with «Stop using it».
    pub needs_attention: bool,
    /// Whether the account is entitled (the server's word): `None` from a
    /// server or `klavd` older than it, or when it couldn't be read. The
    /// apps offer «Use Klav Cloud Proxy» only on `Some(true)`.
    pub entitled: Option<bool>,
    /// The account uses its own proxy (an agent of the account): the note
    /// under the button says sandboxes move to Klav Cloud's while the own
    /// proxy keeps its credentials for its machine's local agents (Q5 (a)).
    pub replaces_own: bool,
    /// A short code of why, when not verified (`image_revoked`, …).
    pub reason: Option<String>,
    /// `klav-client`'s sentence, in English, for the details.
    pub message: String,
    /// Its agent.
    pub agent_id: Option<String>,
    /// The image it runs, when verified: version, commit, architecture,
    /// `current` or `draining`, and its three PCRs (hex).
    pub version: Option<String>,
    pub commit: Option<String>,
    pub arch: Option<String>,
    pub image_status: Option<String>,
    pub pcr0: Option<String>,
    pub pcr1: Option<String>,
    pub pcr2: Option<String>,
    /// The manifest it was checked against (`deploy/nitro/manifests/<seq>.json`).
    pub manifest_seq: Option<u64>,
    /// Where sandboxes reach it: `tls://a<agent>.<endpoint>:443`.
    pub channel: Option<String>,
    /// When this device checked (Unix ms).
    pub checked_at_ms: u64,
    /// How many credentials it holds.
    pub credentials: u32,
}

/// What an action did.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HostedProxyOutcomeInfo {
    /// Where it stands after it.
    pub info: HostedProxyInfo,
    /// What it did and what is left to the person (issuers to add again,
    /// provider tokens to rotate), one sentence each, in English.
    pub notes: Vec<String>,
}

fn state(s: HostedState) -> HostedProxyState {
    match s {
        HostedState::Verified => HostedProxyState::Verified,
        HostedState::Unverified => HostedProxyState::Unverified,
        HostedState::Unreachable => HostedProxyState::Unreachable,
        HostedState::NotEntitled => HostedProxyState::NotEntitled,
        HostedState::LostKeys => HostedProxyState::LostKeys,
        HostedState::Revoked => HostedProxyState::Revoked,
        HostedState::Unsupported => HostedProxyState::Unsupported,
    }
}

pub(crate) fn action(a: HostedProxyAction) -> CloudAction {
    match a {
        HostedProxyAction::Use => CloudAction::Use,
        HostedProxyAction::Stop => CloudAction::Stop,
        HostedProxyAction::Reset => CloudAction::Reset,
    }
}

/// The row from `klav proxy status` and, when the account doesn't use
/// it, the entitlement.
pub(crate) fn hosted_info(status: &ProxyStatus, entitled: Option<bool>) -> HostedProxyInfo {
    let credentials = u32::try_from(status.credentials.len()).unwrap_or(u32::MAX);
    let not_used = |message: &str| HostedProxyInfo {
        state: HostedProxyState::NotUsed,
        needs_attention: false,
        entitled,
        replaces_own: status.mode == ProxyMode::Own,
        reason: None,
        message: message.to_owned(),
        agent_id: None,
        version: None,
        commit: None,
        arch: None,
        image_status: None,
        pcr0: None,
        pcr1: None,
        pcr2: None,
        manifest_seq: None,
        channel: None,
        checked_at_ms: 0,
        credentials: 0,
    };
    if status.mode != ProxyMode::Klav {
        return not_used("the account doesn't use Klav Cloud's proxy");
    }
    match &status.hosted {
        Some(view) => view_info(view, entitled, credentials),
        // A klavd older than layer 5 reads the mode but can't check it.
        None => HostedProxyInfo {
            state: HostedProxyState::Unsupported,
            needs_attention: true,
            message: status.problems.first().cloned().unwrap_or_else(|| {
                "this klavd can't check Klav Cloud's proxy: update it".to_owned()
            }),
            agent_id: status.agent_id.map(|a| a.to_string()),
            credentials,
            ..not_used("")
        },
    }
}

fn view_info(view: &HostedProxyView, entitled: Option<bool>, credentials: u32) -> HostedProxyInfo {
    let image = view.image.as_ref();
    HostedProxyInfo {
        state: state(view.state),
        needs_attention: view.state.needs_attention(),
        entitled: view.entitled.or(entitled),
        replaces_own: false,
        reason: view.reason.clone(),
        message: view.message.clone(),
        agent_id: view.agent_id.map(|a| a.to_string()),
        version: image.map(|i| i.version.clone()),
        commit: image.map(|i| i.commit.clone()),
        arch: image.map(|i| i.arch.clone()),
        image_status: image.map(|i| i.status.clone()),
        pcr0: image.map(|i| i.pcr0.clone()),
        pcr1: image.map(|i| i.pcr1.clone()),
        pcr2: image.map(|i| i.pcr2.clone()),
        manifest_seq: view.manifest_seq,
        channel: view.channel.as_ref().map(|c| format!("tls://{c}:443")),
        checked_at_ms: view.checked_at_ms,
        credentials,
    }
}

pub(crate) fn outcome_info(outcome: CloudOutcome) -> HostedProxyOutcomeInfo {
    HostedProxyOutcomeInfo {
        info: hosted_info(&outcome.status, None),
        notes: outcome.notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use klav_client::hosted_proxy::HostedImageView;
    use klav_core::ids::AgentId;

    fn status(mode: ProxyMode, hosted: Option<HostedProxyView>) -> ProxyStatus {
        ProxyStatus {
            mode,
            agent_id: None,
            agent: None,
            credentials: Vec::new(),
            problems: Vec::new(),
            lost: Vec::new(),
            issuers: None,
            local_clients: Vec::new(),
            hosted,
        }
    }

    fn view(state: HostedState) -> HostedProxyView {
        HostedProxyView {
            state,
            reason: (state != HostedState::Verified).then(|| "image_revoked".to_owned()),
            message: "m".into(),
            agent_id: Some(AgentId::generate()),
            generation: Some(0),
            channel: Some("a00.proxy.klav.dev".into()),
            entitled: Some(true),
            image: (state == HostedState::Verified).then(|| HostedImageView {
                version: "0.12.0".into(),
                commit: "a".repeat(40),
                arch: "aarch64".into(),
                status: "current".into(),
                pcr0: "0".repeat(96),
                pcr1: "1".repeat(96),
                pcr2: "2".repeat(96),
            }),
            manifest_seq: Some(7),
            seed_epoch: Some(0),
            checked_at_ms: 1,
            endpoint: "https://proxy.klav.dev".into(),
        }
    }

    #[test]
    fn the_row_follows_the_check() {
        let own = hosted_info(&status(ProxyMode::Own, None), Some(true));
        assert_eq!(own.state, HostedProxyState::NotUsed);
        assert!(own.replaces_own && !own.needs_attention);
        assert_eq!(own.entitled, Some(true));

        let ok = hosted_info(
            &status(ProxyMode::Klav, Some(view(HostedState::Verified))),
            None,
        );
        assert_eq!(ok.state, HostedProxyState::Verified);
        assert!(!ok.needs_attention);
        assert_eq!(ok.version.as_deref(), Some("0.12.0"));
        assert_eq!(ok.channel.as_deref(), Some("tls://a00.proxy.klav.dev:443"));

        for (s, red) in [
            (HostedState::Unverified, true),
            (HostedState::NotEntitled, true),
            (HostedState::LostKeys, true),
            (HostedState::Revoked, true),
            (HostedState::Unreachable, false),
        ] {
            let info = hosted_info(&status(ProxyMode::Klav, Some(view(s))), None);
            assert_eq!(info.needs_attention, red, "{s:?}");
            assert_eq!(info.version, None);
        }

        // An older klavd: the mode without the check is a red row.
        let older = hosted_info(&status(ProxyMode::Klav, None), None);
        assert_eq!(older.state, HostedProxyState::Unsupported);
        assert!(older.needs_attention);
    }
}
