//! Accounts, OPAQUE registration and login, sessions and devices.
//!
//! Flow (see `docs/api.md`):
//!
//! 1. `POST /v1/auth/prelogin` → KDF parameters (decoys for unknown e-mails).
//! 2. The client derives the KEK and the OPAQUE input (`klav-core`).
//! 3. `POST /v1/auth/register/start` + `…/register/finish` (sign-up), or
//!    `POST /v1/auth/login/start` + `…/login/finish` (log-in).
//! 4. The login returns short-lived access tokens plus a rotating refresh
//!    token bound to a device.
//! 5. Deleting the account repeats the OPAQUE exchange inside a session
//!    (`POST /v1/account/delete/start` + `…/finish`) and schedules the
//!    deletion 7 days later (ADR 0037).

use klav_core::ids::{AccountId, DeviceId};
use serde::{Deserialize, Serialize};

use crate::Blob;

/// `POST /v1/auth/prelogin`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreloginRequest {
    /// Account e-mail.
    pub email: String,
}

/// Response to [`PreloginRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreloginResponse {
    /// Encoded KDF parameters (kind `0x06`). For unknown e-mails, stable
    /// decoy parameters indistinguishable from real ones.
    pub kdf_params: Blob,
}

/// `POST /v1/auth/register/start`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterStartRequest {
    /// Account e-mail.
    pub email: String,
    /// OPAQUE `RegistrationRequest`.
    pub registration_request: Blob,
}

/// Response to [`RegisterStartRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterStartResponse {
    /// OPAQUE `RegistrationResponse`.
    pub registration_response: Blob,
}

/// `POST /v1/auth/register/finish`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterFinishRequest {
    /// Account e-mail (same as in the start request).
    pub email: String,
    /// Client-generated account ID (it is part of the AAD of every blob).
    pub account_id: AccountId,
    /// OPAQUE `RegistrationUpload`.
    pub registration_upload: Blob,
    /// Encoded KDF parameters (kind `0x06`).
    pub kdf_params: Blob,
    /// Public identity (kind `0x05`).
    pub public_identity: Blob,
    /// Identity private keys sealed with the KEK (kind `0x01`).
    pub sealed_identity: Blob,
}

/// Response to [`RegisterFinishRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterFinishResponse {
    /// The new account.
    pub account_id: AccountId,
}

/// `POST /v1/auth/login/start`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginStartRequest {
    /// Account e-mail.
    pub email: String,
    /// OPAQUE `CredentialRequest` (KE1).
    pub credential_request: Blob,
}

/// Response to [`LoginStartRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStartResponse {
    /// Opaque handle of the pending login (valid for a short time).
    pub login_id: String,
    /// OPAQUE `CredentialResponse` (KE2).
    pub credential_response: Blob,
}

/// Kind of client installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    /// `klav` command-line interface.
    Cli,
    /// `klavd` daemon.
    Daemon,
    /// Browser extension.
    Browser,
    /// iOS app.
    Ios,
    /// macOS app (ADR 0027): the Mac's device, shared with `klav` and
    /// `klavd`.
    Macos,
    /// Android app.
    Android,
    /// Anything else (tests, scripts).
    Other,
}

impl DeviceKind {
    /// Stable text form (as stored and serialized).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Daemon => "daemon",
            Self::Browser => "browser",
            Self::Ios => "ios",
            Self::Macos => "macos",
            Self::Android => "android",
            Self::Other => "other",
        }
    }

    /// Parses the text form.
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "cli" => Self::Cli,
            "daemon" => Self::Daemon,
            "browser" => Self::Browser,
            "ios" => Self::Ios,
            "macos" => Self::Macos,
            "android" => Self::Android,
            "other" => Self::Other,
            _ => return None,
        })
    }
}

/// The device a login is for.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceInfo {
    /// ID returned by a previous login on this installation, if any. If it is
    /// unknown or revoked, the server registers a new device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<DeviceId>,
    /// Display name (1–64 characters), e.g. `"MacBook de Omar"`.
    pub name: String,
    /// Kind of installation.
    pub kind: DeviceKind,
}

/// `POST /v1/auth/login/finish`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginFinishRequest {
    /// Handle from [`LoginStartResponse`].
    pub login_id: String,
    /// OPAQUE `CredentialFinalization` (KE3).
    pub credential_finalization: Blob,
    /// Device being logged in.
    pub device: DeviceInfo,
}

/// Session credentials. Access tokens go in `Authorization: Bearer …`.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionTokens {
    /// Short-lived bearer token.
    pub access_token: String,
    /// Expiry of the access token (Unix milliseconds).
    pub access_expires_at: i64,
    /// Single-use refresh token; every refresh returns a new one.
    pub refresh_token: String,
    /// Expiry of the refresh token (Unix milliseconds).
    pub refresh_expires_at: i64,
}

impl std::fmt::Debug for SessionTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionTokens")
            .field("access_expires_at", &self.access_expires_at)
            .field("refresh_expires_at", &self.refresh_expires_at)
            .finish_non_exhaustive()
    }
}

/// Everything a client needs to unlock the account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountKeyset {
    /// Account ID.
    pub account_id: AccountId,
    /// Normalised e-mail.
    pub email: String,
    /// Encoded KDF parameters (kind `0x06`).
    pub kdf_params: Blob,
    /// Public identity (kind `0x05`).
    pub public_identity: Blob,
    /// Identity private keys sealed with the KEK (kind `0x01`).
    pub sealed_identity: Blob,
}

/// `GET /v1/account`: the keyset, and the pending deletion, if the person
/// asked for one (ADR 0037 §3). The keyset's fields are at the top level,
/// so a client that reads an [`AccountKeyset`] still works.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    /// Everything a client needs to unlock the account.
    #[serde(flatten)]
    pub keyset: AccountKeyset,
    /// The deletion the person asked for. Absent when there is none, and
    /// on older servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion: Option<AccountDeletion>,
}

/// A deletion of the account the person asked for (ADR 0037 §2): the
/// account is deleted at `delete_at` unless a device cancels it first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDeletion {
    /// When the person asked (Unix ms).
    pub requested_at: i64,
    /// When the server deletes the account (Unix ms): 7 days later.
    pub delete_at: i64,
    /// The device that asked.
    pub device_id: DeviceId,
    /// Its name, as the device list shows it.
    pub device_name: String,
}

/// `POST /v1/account/delete/start`: the first OPAQUE message, computed with
/// the master password and this device's Secret Key (ADR 0037 §1, spec
/// §4.5). The e-mail is the session's account, never the client's.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDeleteStartRequest {
    /// OPAQUE KE1.
    pub credential_request: Blob,
}

/// Response to [`AccountDeleteStartRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountDeleteStartResponse {
    /// Handle of this reauthentication: one use, 2 minutes, this session
    /// only, and only to delete the account.
    pub handle: String,
    /// OPAQUE KE2.
    pub credential_response: Blob,
}

/// `POST /v1/account/delete/finish`: the last OPAQUE message. If it
/// verifies, the deletion is scheduled in the same request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDeleteFinishRequest {
    /// Handle from [`AccountDeleteStartResponse`].
    pub handle: String,
    /// OPAQUE KE3.
    pub credential_finalization: Blob,
}

/// Response to [`LoginFinishRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFinishResponse {
    /// Account keyset (to open the identity with the KEK).
    pub account: AccountKeyset,
    /// The device this session belongs to; store it for the next login.
    pub device_id: DeviceId,
    /// Session credentials.
    pub session: SessionTokens,
}

/// `POST /v1/auth/refresh`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshRequest {
    /// Current refresh token. Reusing an already rotated token revokes the
    /// whole session (theft detection).
    pub refresh_token: String,
}

impl std::fmt::Debug for RefreshRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RefreshRequest { .. }")
    }
}

/// A device of the account (`GET /v1/devices`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// Device ID.
    pub id: DeviceId,
    /// Display name.
    pub name: String,
    /// Kind of installation.
    pub kind: DeviceKind,
    /// Registration time (Unix milliseconds).
    pub created_at: i64,
    /// Last authenticated request (Unix milliseconds, minute precision).
    pub last_seen_at: i64,
    /// Revocation time, if revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
    /// `true` for the device making the request.
    pub current: bool,
}

/// `GET /v1/devices`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceList {
    /// All devices, newest first (revoked ones included).
    pub devices: Vec<Device>,
}

/// Where the server sends a device's push notifications (APNs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PushEnvironment {
    /// `api.sandbox.push.apple.com` (development builds).
    Sandbox,
    /// `api.push.apple.com` (TestFlight and the App Store).
    Production,
}

impl PushEnvironment {
    /// Stable text form (as stored).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sandbox => "sandbox",
            Self::Production => "production",
        }
    }

    /// Parses [`Self::as_str`].
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "sandbox" => Some(Self::Sandbox),
            "production" => Some(Self::Production),
            _ => None,
        }
    }
}

/// `PUT /v1/devices/current/push`: the APNs device token of this device
/// (hex). Pushes only carry an approval or agent ID (ADR 0018 §5).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushRegistration {
    /// Device token, hexadecimal.
    pub token: String,
    /// APNs environment of the app build.
    pub environment: PushEnvironment,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_tokens() {
        let tokens = SessionTokens {
            access_token: "kat_secret".into(),
            access_expires_at: 1,
            refresh_token: "krt_secret".into(),
            refresh_expires_at: 2,
        };
        assert!(!format!("{tokens:?}").contains("secret"));
        let refresh = RefreshRequest {
            refresh_token: "krt_secret".into(),
        };
        assert!(!format!("{refresh:?}").contains("secret"));
    }

    #[test]
    fn an_account_with_a_deletion_still_reads_as_a_keyset() {
        let keyset = AccountKeyset {
            account_id: AccountId::generate(),
            email: "ana@example.com".into(),
            kdf_params: Blob::new(vec![1]),
            public_identity: Blob::new(vec![2]),
            sealed_identity: Blob::new(vec![3]),
        };
        let info = AccountInfo {
            keyset: keyset.clone(),
            deletion: Some(AccountDeletion {
                requested_at: 1,
                delete_at: 2,
                device_id: DeviceId::generate(),
                device_name: "iPhone".into(),
            }),
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["email"], "ana@example.com");
        assert_eq!(json["deletion"]["delete_at"], 2);
        // An older client reads the same body as a keyset.
        let old: AccountKeyset = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(old.account_id, keyset.account_id);
        let back: AccountInfo = serde_json::from_value(json).unwrap();
        assert_eq!(back.deletion, info.deletion);
        // And an older server's body has no deletion.
        let plain: AccountInfo =
            serde_json::from_value(serde_json::to_value(&keyset).unwrap()).unwrap();
        assert!(plain.deletion.is_none());
    }

    #[test]
    fn device_kind_text_roundtrip() {
        for kind in [
            DeviceKind::Cli,
            DeviceKind::Daemon,
            DeviceKind::Browser,
            DeviceKind::Ios,
            DeviceKind::Macos,
            DeviceKind::Android,
            DeviceKind::Other,
        ] {
            assert_eq!(DeviceKind::parse(kind.as_str()), Some(kind));
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, format!("\"{}\"", kind.as_str()));
        }
    }
}
