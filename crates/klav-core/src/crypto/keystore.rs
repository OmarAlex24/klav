//! Local key wrapped by a platform keystore (spec §12.3): the Secure
//! Enclave on Apple devices today, Android Keystore later.
//!
//! The keystore holds a non-exportable P-256 key that only works after a
//! biometric check. Wrapping needs no prompt: the platform makes an
//! ephemeral P-256 key and computes ECDH with the keystore's public key.
//! Unwrapping asks the keystore (and so the user's finger) for the same
//! ECDH with the ephemeral public key. `klav-core` never sees the
//! keystore's private key; it turns the shared secret into a wrapping key
//! and seals the local key:
//!
//! ```text
//! wrap_key = HKDF-SHA256(salt = ∅, ikm = ECDH(eph, keystore),
//!                        info = tuple("klav/v1/kdf/keystore-wrap", account_id, device_id,
//!                                     keystore_public, ephemeral_public), L = 32)
//! blob     = seal(wrap_key, kind 0x42, local_key,
//!                 tuple("klav/v1/local/keystore-wrap", account_id, device_id,
//!                       keystore_public, ephemeral_public,
//!                       u64_be(password_at_ms), u64_be(boot_time_s)))
//! ```
//!
//! `password_at_ms` (last master-password unlock) and `boot_time_s` (boot
//! the wrap was made in) are in the AAD, so the policy "password every N
//! days and after a reboot" cannot be extended by editing the enrolment
//! file: a changed value no longer opens.

use hkdf::Hkdf;
use secrecy::SecretBox;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::CryptoError;
use super::aead;
use super::encoding::{Kind, Tuple};
use super::keys::{KEY_LEN, LocalKey, sealed::Sealed};
use super::local::LocalContext;

/// HKDF `info` label of the wrapping key.
pub const LABEL_KEYSTORE_KEY: &str = "klav/v1/kdf/keystore-wrap";
/// AAD label of the wrapped local key.
pub const LABEL_KEYSTORE_WRAP: &str = "klav/v1/local/keystore-wrap";
/// Uncompressed SEC1 P-256 point (`0x04 ‖ x ‖ y`).
pub const P256_POINT_LEN: usize = 65;
/// Length of an ECDH shared secret (the x coordinate).
pub const SHARED_SECRET_LEN: usize = 32;
/// Length of the sealed local key.
pub const WRAPPED_LEN: usize = aead::OVERHEAD + KEY_LEN;

/// What a keystore wrap is bound to.
#[derive(Debug, Clone, Copy)]
pub struct KeystoreBinding<'a> {
    /// Account and device.
    pub ctx: LocalContext,
    /// The keystore key's public point.
    pub keystore_public: &'a [u8],
    /// The ephemeral public point of this wrap.
    pub ephemeral_public: &'a [u8],
    /// Last master-password unlock (Unix milliseconds).
    pub password_at_ms: u64,
    /// Boot time of the machine when wrapped (Unix seconds).
    pub boot_time_s: u64,
}

/// An all-zero shared secret is what ECDH gives for a point of small order
/// or a keystore that failed without saying so: never a key to wrap under.
fn check_shared(shared: &[u8; SHARED_SECRET_LEN]) -> Result<(), CryptoError> {
    use subtle::ConstantTimeEq as _;
    if bool::from(shared.ct_eq(&[0u8; SHARED_SECRET_LEN])) {
        return Err(CryptoError::Malformed("null keystore shared secret"));
    }
    Ok(())
}

fn check_point(point: &[u8]) -> Result<(), CryptoError> {
    if point.len() != P256_POINT_LEN || point[0] != 0x04 {
        return Err(CryptoError::Malformed("P-256 public point"));
    }
    Ok(())
}

pub(crate) fn key_info(b: &KeystoreBinding<'_>) -> Tuple {
    let mut tuple = Tuple::new(LABEL_KEYSTORE_KEY);
    tuple
        .push(b.ctx.account.as_bytes())
        .push(b.ctx.device.as_bytes())
        .push(b.keystore_public)
        .push(b.ephemeral_public);
    tuple
}

pub(crate) fn wrap_tuple(b: &KeystoreBinding<'_>) -> Tuple {
    let mut tuple = Tuple::new(LABEL_KEYSTORE_WRAP);
    tuple
        .push(b.ctx.account.as_bytes())
        .push(b.ctx.device.as_bytes())
        .push(b.keystore_public)
        .push(b.ephemeral_public)
        .push(&b.password_at_ms.to_be_bytes())
        .push(&b.boot_time_s.to_be_bytes());
    tuple
}

pub(crate) fn wrapping_key(
    shared: &[u8; SHARED_SECRET_LEN],
    b: &KeystoreBinding<'_>,
) -> Zeroizing<[u8; KEY_LEN]> {
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, shared)
        .expand(key_info(b).as_bytes(), out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// Seals `key` under the keystore shared secret (kind `0x42`).
pub fn wrap_local_key(
    shared: &[u8; SHARED_SECRET_LEN],
    binding: &KeystoreBinding<'_>,
    key: &LocalKey,
) -> Result<Vec<u8>, CryptoError> {
    check_point(binding.keystore_public)?;
    check_point(binding.ephemeral_public)?;
    check_shared(shared)?;
    Ok(aead::seal(
        &wrapping_key(shared, binding),
        Kind::KeystoreWrap,
        &wrap_tuple(binding),
        key.secret_bytes(),
    ))
}

/// Opens a local key sealed by [`wrap_local_key`]. Fails (opaquely) if
/// any bound value differs, policy fields included.
pub fn unwrap_local_key(
    shared: &[u8; SHARED_SECRET_LEN],
    binding: &KeystoreBinding<'_>,
    blob: &[u8],
) -> Result<LocalKey, CryptoError> {
    check_point(binding.keystore_public)?;
    check_point(binding.ephemeral_public)?;
    check_shared(shared)?;
    if blob.len() != WRAPPED_LEN {
        return Err(CryptoError::Malformed("wrapped local key length"));
    }
    let plain = aead::open(
        &wrapping_key(shared, binding),
        Kind::KeystoreWrap,
        &wrap_tuple(binding),
        blob,
    )?;
    let bytes: [u8; KEY_LEN] = plain
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Malformed("wrapped local key length"))?;
    Ok(LocalKey::from_secret(SecretBox::new(Box::new(bytes))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{AccountId, DeviceId};

    fn point(byte: u8) -> [u8; P256_POINT_LEN] {
        let mut p = [byte; P256_POINT_LEN];
        p[0] = 0x04;
        p
    }

    #[test]
    fn wrap_roundtrip_and_every_binding_matters() {
        let ctx = LocalContext {
            account: AccountId::generate(),
            device: DeviceId::generate(),
        };
        let (ks, eph) = (point(1), point(2));
        let binding = KeystoreBinding {
            ctx,
            keystore_public: &ks,
            ephemeral_public: &eph,
            password_at_ms: 1_700_000_000_000,
            boot_time_s: 1_699_000_000,
        };
        let shared = [7u8; 32];
        let key = LocalKey::generate();
        let blob = wrap_local_key(&shared, &binding, &key).unwrap();
        assert_eq!(blob.len(), WRAPPED_LEN);
        assert_eq!(&blob[..2], &[0x01, 0x42]);
        let opened = unwrap_local_key(&shared, &binding, &blob).unwrap();
        assert_eq!(opened.secret_bytes(), key.secret_bytes());
        // An all-zero shared secret is refused both ways.
        let null = [0u8; 32];
        assert!(wrap_local_key(&null, &binding, &key).is_err());
        let under_null = aead::seal(
            &wrapping_key(&null, &binding),
            Kind::KeystoreWrap,
            &wrap_tuple(&binding),
            key.secret_bytes(),
        );
        assert!(unwrap_local_key(&null, &binding, &under_null).is_err());

        let other = point(3);
        let variants = [
            KeystoreBinding {
                password_at_ms: binding.password_at_ms + 86_400_000,
                ..binding
            },
            KeystoreBinding {
                boot_time_s: binding.boot_time_s + 1,
                ..binding
            },
            KeystoreBinding {
                ephemeral_public: &other,
                ..binding
            },
            KeystoreBinding {
                keystore_public: &other,
                ..binding
            },
            KeystoreBinding {
                ctx: LocalContext {
                    device: DeviceId::generate(),
                    ..ctx
                },
                ..binding
            },
        ];
        for variant in &variants {
            assert!(unwrap_local_key(&shared, variant, &blob).is_err());
        }
        assert!(unwrap_local_key(&[8u8; 32], &binding, &blob).is_err());
        let bad_point = [0u8; P256_POINT_LEN];
        assert!(
            wrap_local_key(
                &shared,
                &KeystoreBinding {
                    ephemeral_public: &bad_point,
                    ..binding
                },
                &key
            )
            .is_err()
        );
    }
}
