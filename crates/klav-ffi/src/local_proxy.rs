//! The credential proxy on this Mac, through its local socket (ADR 0036
//! E3.5, layer 11): the live sandbox list with the real connection of each,
//! and revoking without `klavd` (it works while Klav is locked, E2.3). The
//! socket and its lines are `klav_client::local_proxy`; this is the Mac
//! app's side, Mac only (`DaemonEngine`).
//!
//! Nothing here is a secret: IDs, the issuer's label, profile names and
//! times. The label is the issuer's words, which the app shows as such
//! (T136, T157).

use klav_client::local_proxy::{self, LocalProxyError, LocalSandbox, LocalSandboxes, codes};
use klav_core::ids::SandboxId;

use crate::daemon::DaemonEngine;
use crate::error::{KlavError, KlavResult, MAX_ERROR_TEXT};

/// One live sandbox of the proxy on this Mac.
#[derive(Debug, Clone, uniffi::Record)]
pub struct LocalSandboxInfo {
    /// Its ID.
    pub sandbox_id: String,
    /// The agent that started it.
    pub issuer_id: String,
    /// The label its issuer wrote (the issuer's words).
    pub label: String,
    /// Its profiles.
    pub profiles: Vec<String>,
    /// When it started (Unix ms).
    pub issued_ms: i64,
    /// When it ends (Unix ms).
    pub expires_ms: i64,
    /// Whether its forwarder claimed it.
    pub claimed: bool,
    /// Whether its forwarder is connected now.
    pub connected: bool,
    /// Its last call or its claim (Unix ms, the proxy's clock).
    pub last_seen_ms: Option<i64>,
}

/// The proxy on this Mac, as it answers on its socket.
#[derive(Debug, Clone, uniffi::Record)]
pub struct LocalProxyInfo {
    /// Its agent ID: the account's proxy when it matches the account's
    /// setting («On this Mac»).
    pub proxy_id: String,
    /// The port of its loopback listener.
    pub port: u16,
    /// Whether it serves local calls (local MCP clients need it).
    pub local_calls: bool,
    /// Whether it also listens for sandboxes' forwarders.
    pub channel: bool,
    /// Whether the account's MCP gateway is on, as the proxy last heard.
    pub mcp_gateway: bool,
    /// Its MCP profiles by name.
    pub mcp_profiles: Vec<String>,
    /// Its live sandboxes, newest first.
    pub sandboxes: Vec<LocalSandboxInfo>,
    /// Ends waiting for the Klav server.
    pub unsent_ends: u32,
}

/// Whether a proxy runs on this Mac.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum LocalProxyState {
    /// Nothing answers on its socket.
    NotRunning {
        /// Whether a proxy is registered in this Mac's Klav directory
        /// (`klav proxy local init` ran): then it only needs starting.
        registered: bool,
    },
    /// It answers.
    Running {
        /// What it said.
        info: LocalProxyInfo,
    },
    /// Something is wrong with the socket (another user's, a broken
    /// answer): the app says so and asks nothing of it.
    Unavailable {
        /// Why, in English.
        message: String,
    },
}

/// What a revocation through the socket did.
#[derive(Debug, Clone, uniffi::Record)]
pub struct LocalRevokeInfo {
    /// The sandboxes it ended.
    pub revoked: Vec<String>,
    /// Whether the Klav server already has every end; otherwise the proxy
    /// sends them as soon as it can, and serves none of them meanwhile.
    pub logged: bool,
}

fn sandbox_info(s: LocalSandbox) -> LocalSandboxInfo {
    LocalSandboxInfo {
        sandbox_id: s.sandbox_id.to_string(),
        issuer_id: s.issuer_id.to_string(),
        label: s.label,
        profiles: s.profiles,
        issued_ms: s.issued_at,
        expires_ms: s.expires_at,
        claimed: s.claimed,
        connected: s.connected,
        last_seen_ms: s.last_seen_at,
    }
}

pub(crate) fn proxy_info(l: LocalSandboxes) -> LocalProxyInfo {
    LocalProxyInfo {
        proxy_id: l.proxy_id.to_string(),
        port: l.port,
        local_calls: l.local_calls,
        channel: l.channel,
        mcp_gateway: l.mcp_gateway,
        mcp_profiles: l.mcp_profiles,
        sandboxes: l.sandboxes.into_iter().map(sandbox_info).collect(),
        unsent_ends: l.unsent_ends,
    }
}

fn revoke_error(e: LocalProxyError) -> KlavError {
    match e {
        LocalProxyError::NotRunning(_) => KlavError::NotFound {
            message: "No credential proxy runs on this Mac.".into(),
        },
        LocalProxyError::Refused { code, message } if code == codes::NOT_FOUND => {
            KlavError::NotFound {
                message: klav_core::text::shown(&message, MAX_ERROR_TEXT),
            }
        }
        LocalProxyError::Untrusted(why) => KlavError::Security {
            message: klav_core::text::shown(&why, MAX_ERROR_TEXT),
        },
        other => KlavError::Invalid {
            message: klav_core::text::shown(&other.to_string(), MAX_ERROR_TEXT),
        },
    }
}

#[uniffi::export]
impl DaemonEngine {
    /// The credential proxy on this Mac (ADR 0036 E3.5): whether it runs,
    /// and its live sandboxes. Needs neither `klavd` nor the vault open.
    pub fn local_proxy(&self) -> LocalProxyState {
        let home = self.home_dir();
        let path = local_proxy::socket_path(home, local_proxy::DEFAULT_NAME);
        match local_proxy::sandboxes(&path) {
            Ok(listed) => LocalProxyState::Running {
                info: proxy_info(listed),
            },
            Err(LocalProxyError::NotRunning(_)) => LocalProxyState::NotRunning {
                registered: home
                    .dir()
                    .join("agents")
                    .join(format!("{}.json", local_proxy::DEFAULT_NAME))
                    .exists(),
            },
            Err(e) => LocalProxyState::Unavailable {
                message: klav_core::text::shown(&e.to_string(), MAX_ERROR_TEXT),
            },
        }
    }

    /// Revokes one live sandbox (`Some`) or all of them (`None`) of the
    /// proxy on this Mac, at once and with no signature: the proxy logs it
    /// as `person_local`. Works while Klav is locked (E2.3).
    pub fn local_proxy_revoke(&self, sandbox_id: Option<String>) -> KlavResult<LocalRevokeInfo> {
        let target = match sandbox_id {
            Some(id) => Some(id.parse::<SandboxId>().map_err(|_| KlavError::Invalid {
                message: "not a sandbox ID".into(),
            })?),
            None => None,
        };
        let path = local_proxy::socket_path(self.home_dir(), local_proxy::DEFAULT_NAME);
        let revoked = local_proxy::revoke(&path, target).map_err(revoke_error)?;
        Ok(LocalRevokeInfo {
            revoked: revoked.revoked.iter().map(ToString::to_string).collect(),
            logged: revoked.logged,
        })
    }
}
