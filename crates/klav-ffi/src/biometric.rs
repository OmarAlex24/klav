//! Face ID enrolment and unlock (design §4.3, spec §12.3, ADR 0018 §3).
//!
//! The same scheme as `klavd`'s Touch ID (ADR 0013): after every
//! master-password unlock the local key is (re)wrapped for a Secure
//! Enclave key, binding the time of that unlock and the boot time. The
//! enclave lives in Swift behind [`PlatformKeystore`]; HKDF and the sealing
//! (kind `0x42`) stay in `klav-core`. The enrolment file is
//! `faceid.json` in the shared home, in the format of `touchid.json`.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use klav_client::Home;
use klav_core::crypto::keys::LocalKey;
use klav_core::crypto::keystore::{self, KeystoreBinding, P256_POINT_LEN, SHARED_SECRET_LEN};
use klav_core::crypto::local::LocalContext;
use klav_proto::Blob;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::KlavError;
use crate::types::BiometricState;

/// The master password is required again after this long.
pub(crate) const PASSWORD_EVERY: Duration = Duration::from_secs(14 * 24 * 3600);

const FILE: &str = "faceid.json";

/// Errors of the platform keystore, as Swift reports them.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum KeystoreError {
    /// No Secure Enclave, or no biometrics enrolled.
    #[error("biometrics are not available")]
    Unavailable,
    /// The person cancelled the prompt.
    #[error("cancelled")]
    Cancelled,
    /// The face (or finger) did not match.
    #[error("authentication failed")]
    AuthFailed,
    /// Authenticated, yet the key no longer works (biometry changed).
    #[error("the key was invalidated")]
    Invalidated,
    /// Anything else.
    #[error("keystore error")]
    Other,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for KeystoreError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Other
    }
}

/// A new keystore key: its opaque handle and its public point.
#[derive(Debug, Clone, uniffi::Record)]
pub struct KeystoreKey {
    /// Opaque handle (on Apple, the enclave-encrypted `dataRepresentation`).
    pub handle: Vec<u8>,
    /// Uncompressed SEC1 P-256 public point (65 bytes).
    pub public_key: Vec<u8>,
}

/// The result of wrapping: an ephemeral public point and the ECDH secret.
#[derive(uniffi::Record)]
pub struct KeystoreWrap {
    /// Ephemeral public point (65 bytes).
    pub ephemeral_public: Vec<u8>,
    /// ECDH shared secret (32 bytes).
    pub secret: Vec<u8>,
}

impl std::fmt::Debug for KeystoreWrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeystoreWrap(…)")
    }
}

/// The device's key store, implemented in Swift (Secure Enclave on a
/// device; a software key behind the Face ID prompt only in DEBUG
/// simulator builds, ADR 0018 §3). Mirrors `klav-touchid`.
#[uniffi::export(with_foreign)]
pub trait PlatformKeystore: Send + Sync {
    /// The keystore exists and biometrics are enrolled.
    fn available(&self) -> bool;
    /// Creates a P-256 key usable only after biometrics, tied to the
    /// currently enrolled biometry.
    fn create_key(&self) -> Result<KeystoreKey, KeystoreError>;
    /// ECDH of a fresh ephemeral key with `public_key` (no prompt).
    fn wrap(&self, public_key: Vec<u8>) -> Result<KeystoreWrap, KeystoreError>;
    /// Asks for biometrics (showing `reason`), then has the key agree with
    /// `ephemeral_public`. Returns the 32-byte shared secret.
    fn unwrap(
        &self,
        handle: Vec<u8>,
        ephemeral_public: Vec<u8>,
        reason: String,
    ) -> Result<Vec<u8>, KeystoreError>;
    /// Boot time of the device (Unix seconds), `0` if unknown.
    fn boot_time(&self) -> u64;
    /// Asks for the device owner (showing `reason`): Face ID, or the
    /// device passcode when Face ID fails or is locked out
    /// (LocalAuthentication's `deviceOwnerAuthentication`). No key is
    /// opened. `Unavailable` only when the device has no passcode, so no
    /// owner can be asked for (ADR 0037 A4).
    fn confirm_owner(&self, reason: String) -> Result<(), KeystoreError>;
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrolment {
    v: u32,
    handle: Blob,
    enclave_public: Blob,
    ephemeral_public: Blob,
    wrapped: Blob,
    password_at_ms: u64,
    boot_time_s: u64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn point(bytes: &[u8]) -> Option<[u8; P256_POINT_LEN]> {
    bytes
        .try_into()
        .ok()
        .filter(|p: &[u8; P256_POINT_LEN]| p[0] == 0x04)
}

fn secret(bytes: Vec<u8>) -> Option<Zeroizing<[u8; SHARED_SECRET_LEN]>> {
    let bytes = Zeroizing::new(bytes);
    let array: [u8; SHARED_SECRET_LEN] = bytes.as_slice().try_into().ok()?;
    Some(Zeroizing::new(array))
}

fn load(home: &Home) -> Option<Enrolment> {
    let text = std::fs::read(home.file(FILE)).ok()?;
    serde_json::from_slice(&text).ok()
}

/// Removes the enrolment (no longer usable, or the account's copy is
/// deleted). Turning Face ID off goes through [`turn_off`].
pub(crate) fn forget(home: &Home) {
    let _ = std::fs::remove_file(home.file(FILE));
}

/// Turns Face ID off in Klav: only after the device owner confirms (Face
/// ID, or the device passcode), never with the master password alone
/// (ADR 0037 A4, T162). Otherwise anyone holding the unlocked iPhone could
/// turn it off and then delete the account with the password alone. The
/// passcode is the same bar as enrolling a new face, which already makes
/// Klav stop using Face ID (residual risk 57).
///
/// A device with no passcode has no owner to ask and no Face ID either,
/// so the Secure Enclave key no longer opens: the enrolment goes.
pub(crate) fn turn_off(
    home: &Home,
    keystore: &Arc<dyn PlatformKeystore>,
    reason: &str,
) -> Result<(), KlavError> {
    if !enrolled(home) {
        return Ok(());
    }
    match keystore.confirm_owner(reason.to_owned()) {
        Ok(()) => {}
        Err(KeystoreError::Unavailable) if !keystore.available() => {}
        Err(KeystoreError::Unavailable) => {
            return Err(KlavError::BiometryUnavailable {
                message: "the iPhone could not ask for its owner".into(),
            });
        }
        Err(e @ (KeystoreError::Cancelled | KeystoreError::AuthFailed)) => {
            return Err(keystore_error(e));
        }
        Err(e) => {
            return Err(KlavError::BiometryFailed {
                message: format!("the iPhone could not confirm its owner ({e})"),
            });
        }
    }
    forget(home);
    Ok(())
}

/// Asks for the device owner before a protected value, or before lowering
/// an environment's protection (ADR 0032 §3, §3.1: Face ID every time).
/// It fails closed: a device that cannot ask (no passcode) hands nothing
/// out, unlike [`turn_off`], which has nothing left to protect then.
pub(crate) fn confirm_protected(
    keystore: &dyn PlatformKeystore,
    reason: String,
) -> Result<(), KlavError> {
    match keystore.confirm_owner(reason) {
        Ok(()) => Ok(()),
        Err(KeystoreError::Unavailable) => Err(KlavError::BiometryUnavailable {
            message: "the iPhone could not ask for its owner: set a passcode to use \
                      protected values"
                .into(),
        }),
        Err(e @ (KeystoreError::Cancelled | KeystoreError::AuthFailed)) => Err(keystore_error(e)),
        Err(e) => Err(KlavError::BiometryFailed {
            message: format!("the iPhone could not confirm its owner ({e})"),
        }),
    }
}

fn password_required(e: &Enrolment, now_ms: u64, boot: u64) -> Option<String> {
    let every = u64::try_from(PASSWORD_EVERY.as_millis()).unwrap_or(u64::MAX);
    // A password time in the future (the clock went back, or the file was
    // edited) would never expire: ask for the password.
    if e.password_at_ms > now_ms || now_ms.saturating_sub(e.password_at_ms) >= every {
        return Some(format!(
            "The master password is required every {} days.",
            PASSWORD_EVERY.as_secs() / 86_400
        ));
    }
    if boot == 0 || boot != e.boot_time_s {
        return Some("The master password is required after a restart.".into());
    }
    None
}

/// Face ID state for the lock screen.
pub(crate) fn state(home: &Home, keystore: &Arc<dyn PlatformKeystore>) -> BiometricState {
    let available = keystore.available();
    let enrolment = load(home);
    BiometricState {
        available,
        enrolled: available && enrolment.is_some(),
        password_required: enrolment
            .as_ref()
            .filter(|_| available)
            .and_then(|e| password_required(e, now_ms(), keystore.boot_time())),
    }
}

/// After a password unlock: enrol (first time) or rewrap with the new
/// password time. Returns `false` when the keystore is unavailable.
pub(crate) fn enrol(
    home: &Home,
    ctx: LocalContext,
    local_key: &LocalKey,
    keystore: &Arc<dyn PlatformKeystore>,
) -> Result<bool, KlavError> {
    if !keystore.available() {
        return Ok(false);
    }
    let boot_time_s = keystore.boot_time();
    if boot_time_s == 0 {
        return Ok(false);
    }
    let existing =
        load(home).and_then(|e| Some((point(e.enclave_public.as_bytes())?, e.handle.into_bytes())));
    let (public, handle) = match existing {
        Some(found) => found,
        None => {
            let key = keystore.create_key().map_err(keystore_error)?;
            let public = point(&key.public_key)
                .ok_or_else(|| KlavError::invalid("the keystore returned a bad public key"))?;
            (public, key.handle)
        }
    };
    let wrap = keystore.wrap(public.to_vec()).map_err(keystore_error)?;
    let ephemeral = point(&wrap.ephemeral_public)
        .ok_or_else(|| KlavError::invalid("the keystore returned a bad ephemeral key"))?;
    let shared = secret(wrap.secret)
        .ok_or_else(|| KlavError::invalid("the keystore returned a bad secret"))?;
    let password_at_ms = now_ms();
    let binding = KeystoreBinding {
        ctx,
        keystore_public: &public,
        ephemeral_public: &ephemeral,
        password_at_ms,
        boot_time_s,
    };
    let wrapped = keystore::wrap_local_key(&shared, &binding, local_key)?;
    let enrolment = Enrolment {
        v: 1,
        handle: Blob::new(handle),
        enclave_public: Blob::new(public.to_vec()),
        ephemeral_public: Blob::new(ephemeral.to_vec()),
        wrapped: Blob::new(wrapped),
        password_at_ms,
        boot_time_s,
    };
    let json = serde_json::to_vec_pretty(&enrolment)
        .map_err(|e| KlavError::invalid(format!("Face ID enrolment: {e}")))?;
    klav_client::home::write_private(&home.file(FILE), &json)?;
    Ok(true)
}

fn keystore_error(e: KeystoreError) -> KlavError {
    match e {
        KeystoreError::Cancelled | KeystoreError::AuthFailed => KlavError::BiometryFailed {
            message: e.to_string(),
        },
        _ => KlavError::BiometryUnavailable {
            message: e.to_string(),
        },
    }
}

/// Recovers the local key with Face ID (blocks on the prompt).
pub(crate) fn unlock(
    home: &Home,
    ctx: LocalContext,
    keystore: &Arc<dyn PlatformKeystore>,
    reason: &str,
) -> Result<LocalKey, KlavError> {
    if !keystore.available() {
        return Err(KlavError::BiometryUnavailable {
            message: "Face ID is not available".into(),
        });
    }
    let Some(enrolment) = load(home) else {
        return Err(KlavError::BiometryUnavailable {
            message: "Face ID is not set up yet: unlock once with the master password".into(),
        });
    };
    if let Some(message) = password_required(&enrolment, now_ms(), keystore.boot_time()) {
        return Err(KlavError::PasswordRequired { message });
    }
    open(home, &enrolment, ctx, keystore, reason)
}

/// Whether Face ID is set up on this device: Klav uses it, and asks for it
/// before deleting the account (ADR 0037 §1).
pub(crate) fn enrolled(home: &Home) -> bool {
    load(home).is_some()
}

/// Face ID with the Secure Enclave key, to confirm the person is there
/// before deleting the account (ADR 0037 §1): the key takes only the
/// enrolled faces (`biometryCurrentSet`), never the iPhone's code. The
/// local key it opens is dropped at once. The policy of [`unlock`] (the
/// password every 14 days and after a restart) does not apply: the master
/// password is asked for right after anyway.
pub(crate) fn confirm(
    home: &Home,
    ctx: LocalContext,
    keystore: &Arc<dyn PlatformKeystore>,
    reason: &str,
) -> Result<(), KlavError> {
    if !keystore.available() {
        return Err(KlavError::BiometryUnavailable {
            message: "Face ID is not available".into(),
        });
    }
    let Some(enrolment) = load(home) else {
        return Err(KlavError::BiometryUnavailable {
            message: "Face ID is not set up".into(),
        });
    };
    open(home, &enrolment, ctx, keystore, reason).map(drop)
}

/// Opens the local key of `enrolment` with Face ID (shows the prompt).
fn open(
    home: &Home,
    enrolment: &Enrolment,
    ctx: LocalContext,
    keystore: &Arc<dyn PlatformKeystore>,
    reason: &str,
) -> Result<LocalKey, KlavError> {
    let (Some(public), Some(ephemeral)) = (
        point(enrolment.enclave_public.as_bytes()),
        point(enrolment.ephemeral_public.as_bytes()),
    ) else {
        forget(home);
        return Err(KlavError::BiometryUnavailable {
            message: "the Face ID enrolment is damaged; it was removed".into(),
        });
    };
    let shared = match keystore.unwrap(
        enrolment.handle.as_bytes().to_vec(),
        ephemeral.to_vec(),
        reason.to_owned(),
    ) {
        Ok(bytes) => secret(bytes),
        Err(e @ (KeystoreError::Cancelled | KeystoreError::AuthFailed)) => {
            return Err(keystore_error(e));
        }
        Err(KeystoreError::Unavailable) => {
            return Err(KlavError::BiometryUnavailable {
                message: "Face ID is not available".into(),
            });
        }
        Err(KeystoreError::Invalidated) => None,
        // A passing failure (the Secure Enclave busy, an interrupted
        // prompt) keeps the enrolment: only an invalidated key loses it.
        Err(e @ KeystoreError::Other) => {
            return Err(KlavError::BiometryFailed {
                message: format!("Face ID failed ({e}); try again or use the master password"),
            });
        }
    };
    let Some(shared) = shared else {
        // The enrolled faces changed (biometryCurrentSet) or the key is
        // gone: only the password can set it up again.
        forget(home);
        return Err(KlavError::BiometryUnavailable {
            message: "Face ID changed on this device; the master password sets it up again".into(),
        });
    };
    let binding = KeystoreBinding {
        ctx,
        keystore_public: &public,
        ephemeral_public: &ephemeral,
        password_at_ms: enrolment.password_at_ms,
        boot_time_s: enrolment.boot_time_s,
    };
    keystore::unwrap_local_key(&shared, &binding, enrolment.wrapped.as_bytes()).map_err(|_| {
        forget(home);
        KlavError::BiometryUnavailable {
            message: "the Face ID enrolment does not open; it was removed".into(),
        }
    })
}
