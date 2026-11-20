//! Touch ID enrolment and unlock (design §4.3, spec §12.3, ADR 0013).
//!
//! After every master-password unlock the daemon (re)wraps the device's
//! local key for the Secure Enclave key, binding the time of that unlock
//! and the boot time. A later `unlock` without a password checks the
//! policy (password every [`PASSWORD_EVERY`] and after a restart), asks for
//! Touch ID and opens the account with the recovered local key.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use klav_client::Home;
use klav_core::crypto::keys::LocalKey;
use klav_core::crypto::keystore::{self, KeystoreBinding};
use klav_core::crypto::local::LocalContext;
use klav_proto::Blob;
use klav_touchid::{EnclaveKey, POINT_LEN};
use serde::{Deserialize, Serialize};

use crate::protocol::{BiometricStatus, ErrorBody, ErrorCode};

/// The master password is required again after this long.
pub(crate) const PASSWORD_EVERY: Duration = Duration::from_secs(14 * 24 * 3600);

const FILE: &str = crate::client::TOUCH_ID_FILE;

/// `$KLAV_HOME/touchid.json` (0600). Nothing here opens the account
/// without the Secure Enclave of this Mac and a finger.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrolment {
    v: u32,
    /// Secure Enclave key handle (encrypted by the enclave).
    handle: Blob,
    /// Its public point.
    enclave_public: Blob,
    /// Ephemeral public point of the current wrap.
    ephemeral_public: Blob,
    /// Local key, kind `0x42`.
    wrapped: Blob,
    /// Last master-password unlock (Unix ms), bound into the AAD.
    password_at_ms: u64,
    /// Boot time of that unlock (Unix s), bound into the AAD.
    boot_time_s: u64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn point(blob: &Blob) -> Option<[u8; POINT_LEN]> {
    blob.as_bytes().try_into().ok()
}

fn load(home: &Home) -> Option<Enrolment> {
    let text = std::fs::read(home.file(FILE)).ok()?;
    serde_json::from_slice(&text).ok()
}

fn forget(home: &Home) {
    let _ = std::fs::remove_file(home.file(FILE));
}

/// Why the password is needed even though Touch ID is enrolled.
fn password_required(e: &Enrolment, now_ms: u64, boot: Option<u64>) -> Option<String> {
    let every = u64::try_from(PASSWORD_EVERY.as_millis()).unwrap_or(u64::MAX);
    // A password time in the future (the clock went back, or the file was
    // edited) would never expire: ask for the password.
    if e.password_at_ms > now_ms || now_ms.saturating_sub(e.password_at_ms) >= every {
        return Some(format!(
            "The master password is required every {} days.",
            PASSWORD_EVERY.as_secs() / 86_400
        ));
    }
    if boot != Some(e.boot_time_s) {
        return Some("The master password is required after a restart.".into());
    }
    None
}

/// Touch ID state for `status`.
pub(crate) fn status(home: &Home, enabled: bool) -> BiometricStatus {
    let available = enabled && klav_touchid::available();
    let enrolment = load(home);
    BiometricStatus {
        available,
        enrolled: available && enrolment.is_some(),
        password_required: enrolment
            .as_ref()
            .filter(|_| available)
            .and_then(|e| password_required(e, now_ms(), klav_touchid::boot_time())),
    }
}

/// After a password unlock: enrol (first time) or refresh the wrap with
/// the new password time. Silent no-op when Touch ID is unavailable.
pub(crate) fn enrol(home: &Home, ctx: LocalContext, local_key: &LocalKey) -> Result<(), String> {
    if !klav_touchid::available() {
        return Ok(());
    }
    let Some(boot_time_s) = klav_touchid::boot_time() else {
        return Ok(());
    };
    let key = match load(home).and_then(|e| Some((point(&e.enclave_public)?, e.handle))) {
        Some((public, handle)) => EnclaveKey {
            handle: handle.into_bytes(),
            public,
        },
        None => klav_touchid::create_key().map_err(|e| e.to_string())?,
    };
    let wrap = klav_touchid::wrap(&key.public).map_err(|e| e.to_string())?;
    let password_at_ms = now_ms();
    let binding = KeystoreBinding {
        ctx,
        keystore_public: &key.public,
        ephemeral_public: &wrap.ephemeral_public,
        password_at_ms,
        boot_time_s,
    };
    let wrapped =
        keystore::wrap_local_key(&wrap.secret, &binding, local_key).map_err(|e| e.to_string())?;
    let enrolment = Enrolment {
        v: 1,
        handle: Blob::new(key.handle),
        enclave_public: Blob::new(key.public.to_vec()),
        ephemeral_public: Blob::new(wrap.ephemeral_public.to_vec()),
        wrapped: Blob::new(wrapped),
        password_at_ms,
        boot_time_s,
    };
    let json = serde_json::to_vec_pretty(&enrolment).map_err(|e| e.to_string())?;
    klav_client::home::write_private(&home.file(FILE), &json).map_err(|e| e.to_string())
}

fn unavailable(message: &str) -> ErrorBody {
    ErrorBody {
        code: ErrorCode::BiometryUnavailable,
        message: message.to_owned(),
        paused: None,
        presence: None,
    }
}

/// Recovers the local key with Touch ID (blocks on the prompt).
pub(crate) fn unlock(home: &Home, ctx: LocalContext, reason: &str) -> Result<LocalKey, ErrorBody> {
    let enrolment = enrolled(home)?;
    if let Some(reason) = password_required(&enrolment, now_ms(), klav_touchid::boot_time()) {
        return Err(unavailable(&reason));
    }
    open_enrolled(home, &enrolment, ctx, reason)
}

/// The enrolment of this home, if Touch ID can use it.
fn enrolled(home: &Home) -> Result<Enrolment, ErrorBody> {
    if !klav_touchid::available() {
        return Err(unavailable("Touch ID is not available"));
    }
    load(home).ok_or_else(|| {
        unavailable("Touch ID is not set up yet: unlock once with the master password")
    })
}

/// Opens the Secure Enclave key of `enrolment` with Touch ID (blocks on the
/// prompt) and unwraps the local key with it.
fn open_enrolled(
    home: &Home,
    enrolment: &Enrolment,
    ctx: LocalContext,
    reason: &str,
) -> Result<LocalKey, ErrorBody> {
    let (Some(public), Some(ephemeral)) = (
        point(&enrolment.enclave_public),
        point(&enrolment.ephemeral_public),
    ) else {
        forget(home);
        return Err(unavailable(
            "the Touch ID enrolment is damaged; it was removed",
        ));
    };
    let key = EnclaveKey {
        handle: enrolment.handle.as_bytes().to_vec(),
        public,
    };
    let secret = match klav_touchid::unwrap(&key, &ephemeral, reason) {
        Ok(s) => s,
        Err(e @ (klav_touchid::Error::Cancelled | klav_touchid::Error::AuthFailed)) => {
            return Err(ErrorBody {
                code: ErrorCode::BiometryFailed,
                message: e.to_string(),
                paused: None,
                presence: None,
            });
        }
        Err(klav_touchid::Error::Unavailable) => {
            return Err(unavailable("Touch ID is not available"));
        }
        Err(
            klav_touchid::Error::Invalidated
            | klav_touchid::Error::Other
            | klav_touchid::Error::NotFound,
        ) => {
            // The enrolled fingers changed (or the key is gone): only the
            // password can set it up again.
            forget(home);
            return Err(unavailable(
                "the enrolled fingerprints changed; the master password sets Touch ID up again",
            ));
        }
    };
    let binding = KeystoreBinding {
        ctx,
        keystore_public: &public,
        ephemeral_public: &ephemeral,
        password_at_ms: enrolment.password_at_ms,
        boot_time_s: enrolment.boot_time_s,
    };
    keystore::unwrap_local_key(&secret, &binding, enrolment.wrapped.as_bytes()).map_err(|_| {
        // Edited or foreign file (e.g. a later password time): drop it.
        forget(home);
        unavailable("the Touch ID enrolment does not match this account; it was removed")
    })
}

/// Every Touch ID call `klavd` makes, behind one seam (ADR 0041, layer 2):
/// [`Shim`] in `klavd`, and in the tests a fake that never reaches the
/// Secure Enclave or a dialog. `klavd` checks its own `--no-touch-id`
/// before it calls any of these.
pub(crate) trait Biometric: Send + Sync {
    /// Touch ID state for `status`.
    fn status(&self, home: &Home, enabled: bool) -> BiometricStatus;
    /// [`enrol`].
    fn enrol(&self, home: &Home, ctx: LocalContext, local_key: &LocalKey) -> Result<(), String>;
    /// [`unlock`] (blocks on the prompt).
    fn unlock(&self, home: &Home, ctx: LocalContext, reason: &str) -> Result<LocalKey, ErrorBody>;
    /// Touch ID with the Secure Enclave key, to confirm the person is
    /// there (ADR 0037 §1; blocks on the prompt): the key takes only the
    /// enrolled fingers (`biometryCurrentSet`), never the Mac's password,
    /// unlike [`Self::authenticate`]. The local key it gives back is
    /// dropped at once. The password policy of [`unlock`] (every 14 days,
    /// after a restart) does not apply: the caller asks for the master
    /// password right after, and a Mac that restarted must not lose its
    /// Touch ID step.
    fn confirm_with_key(
        &self,
        home: &Home,
        ctx: LocalContext,
        reason: &str,
    ) -> Result<(), ErrorBody>;
    /// Whether Touch ID can be shown now.
    fn available(&self) -> bool;
    /// Touch ID with `reason` (blocks on the prompt).
    fn authenticate(&self, reason: &str) -> Result<(), klav_touchid::Error>;
}

/// The real Touch ID, through `klav-touchid`'s shim.
pub(crate) struct Shim;

impl Biometric for Shim {
    fn status(&self, home: &Home, enabled: bool) -> BiometricStatus {
        status(home, enabled)
    }

    fn enrol(&self, home: &Home, ctx: LocalContext, local_key: &LocalKey) -> Result<(), String> {
        enrol(home, ctx, local_key)
    }

    fn unlock(&self, home: &Home, ctx: LocalContext, reason: &str) -> Result<LocalKey, ErrorBody> {
        unlock(home, ctx, reason)
    }

    fn confirm_with_key(
        &self,
        home: &Home,
        ctx: LocalContext,
        reason: &str,
    ) -> Result<(), ErrorBody> {
        let enrolment = enrolled(home)?;
        open_enrolled(home, &enrolment, ctx, reason).map(drop)
    }

    fn available(&self) -> bool {
        klav_touchid::available()
    }

    fn authenticate(&self, reason: &str) -> Result<(), klav_touchid::Error> {
        klav_touchid::authenticate(reason)
    }
}

/// What a failed Touch ID check answers (ADR 0014).
pub(crate) fn refused(e: &klav_touchid::Error) -> ErrorBody {
    match e {
        klav_touchid::Error::Cancelled | klav_touchid::Error::AuthFailed => ErrorBody {
            code: ErrorCode::BiometryFailed,
            message: e.to_string(),
            paused: None,
            presence: None,
        },
        _ => unavailable(&e.to_string()),
    }
}

/// Touch ID turned off for this `klavd` (`--no-touch-id`).
pub(crate) fn turned_off() -> ErrorBody {
    unavailable("Touch ID is turned off for this klavd")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enrolment(password_at_ms: u64, boot_time_s: u64) -> Enrolment {
        Enrolment {
            v: 1,
            handle: Blob::new(vec![1]),
            enclave_public: Blob::new(vec![4; 65]),
            ephemeral_public: Blob::new(vec![4; 65]),
            wrapped: Blob::new(vec![]),
            password_at_ms,
            boot_time_s,
        }
    }

    #[test]
    fn the_password_is_required_every_14_days_and_after_a_restart() {
        let day = 86_400_000u64;
        let now = 100 * day;
        let e = enrolment(now - 13 * day, 42);
        assert_eq!(password_required(&e, now, Some(42)), None);
        assert!(
            password_required(&e, now, Some(43))
                .unwrap()
                .contains("restart")
        );
        assert!(password_required(&e, now, None).is_some());
        // A password time in the future never expires: refused.
        let future = enrolment(now + day, 42);
        assert!(password_required(&future, now, Some(42)).is_some());
        let old = enrolment(now - 14 * day, 42);
        assert!(
            password_required(&old, now, Some(42))
                .unwrap()
                .contains("14 days")
        );
    }
}
