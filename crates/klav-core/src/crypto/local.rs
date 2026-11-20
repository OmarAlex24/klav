//! Device-local key hierarchy (spec §12.2).
//!
//! ```text
//! KEK ──HKDF──▶ local key ──▶ local identity (kind 0x40): identity private keys
//!                          └─▶ local data     (kind 0x41): cache, session tokens
//! ```
//!
//! The local key is derived from the KEK and bound to one account and one
//! device:
//!
//! ```text
//! local_key = HKDF-SHA256(salt = ∅, ikm = KEK,
//!                         info = tuple("klav/v1/kdf/local-key", account_id, device_id), L = 32)
//! ```
//!
//! A password unlock derives it again from the KEK. A biometric unlock gets
//! it from the platform keystore instead (Secure Enclave, spec §12.3), and
//! then opens the local identity without needing the KEK. Nothing sealed
//! with the local key ever leaves the device.

use hkdf::Hkdf;
use secrecy::SecretBox;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::CryptoError;
use super::encoding::{Kind, Tuple};
use super::identity::{self, IdentityKeyPair, PublicIdentity};
use super::keys::{KEY_LEN, Kek, LocalKey, sealed::Sealed};
use crate::ids::{AccountId, DeviceId};

/// HKDF `info` label of the local key (inside a `tuple`).
pub const LABEL_LOCAL_KEY: &str = "klav/v1/kdf/local-key";
/// AAD label of the local identity.
pub const LABEL_LOCAL_IDENTITY: &str = "klav/v1/local/identity";
/// AAD label of local data.
pub const LABEL_LOCAL_DATA: &str = "klav/v1/local/data";
/// AAD label of the local outbox.
pub const LABEL_LOCAL_OUTBOX: &str = "klav/v1/local/outbox";
/// Maximum length of a local data purpose label.
pub const MAX_PURPOSE_LEN: usize = 64;

/// The account and device a local key belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalContext {
    /// Account.
    pub account: AccountId,
    /// This device (as registered with the server).
    pub device: DeviceId,
}

pub(crate) fn key_info(ctx: &LocalContext) -> Tuple {
    let mut tuple = Tuple::new(LABEL_LOCAL_KEY);
    tuple
        .push(ctx.account.as_bytes())
        .push(ctx.device.as_bytes());
    tuple
}

pub(crate) fn identity_tuple(ctx: &LocalContext, public: &PublicIdentity) -> Tuple {
    let mut tuple = Tuple::new(LABEL_LOCAL_IDENTITY);
    tuple
        .push(ctx.account.as_bytes())
        .push(ctx.device.as_bytes())
        .push(&public.encode());
    tuple
}

pub(crate) fn data_tuple(ctx: &LocalContext, purpose: &str) -> Tuple {
    let mut tuple = Tuple::new(LABEL_LOCAL_DATA);
    tuple
        .push(ctx.account.as_bytes())
        .push(ctx.device.as_bytes())
        .push(purpose.as_bytes());
    tuple
}

pub(crate) fn derive_bytes(kek: &[u8; KEY_LEN], ctx: &LocalContext) -> Zeroizing<[u8; KEY_LEN]> {
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, kek)
        .expand(key_info(ctx).as_bytes(), out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// Derives the local key of `ctx` from the KEK.
pub fn derive_local_key(kek: &Kek, ctx: &LocalContext) -> LocalKey {
    LocalKey::from_secret(SecretBox::new(Box::new(*derive_bytes(
        kek.secret_bytes(),
        ctx,
    ))))
}

/// Whether `password`, with `secret_key` under `params`, derives `expected`
/// as the local key of `ctx` (ADR 0041 §2.3): whether it is the master
/// password of the session that holds `expected` in memory.
///
/// The answer depends on `expected`, which only that session has: inputs
/// read from files a program replaced (another account's Secret Key and
/// parameters, made under a password it chose) derive another local key
/// and answer `false`. The keys are compared in constant time. Argon2id
/// runs once, with `params`' cost.
pub fn password_derives_local_key(
    password: &super::kdf::MasterPassword,
    secret_key: &super::secret_key::SecretKey,
    params: &super::kdf::KdfParams,
    ctx: &LocalContext,
    expected: &LocalKey,
) -> Result<bool, CryptoError> {
    use subtle::ConstantTimeEq;
    let kek = super::kdf::derive_kek(password, secret_key, params)?;
    let derived = derive_bytes(kek.secret_bytes(), ctx);
    Ok(bool::from(
        derived.as_slice().ct_eq(expected.secret_bytes().as_slice()),
    ))
}

/// Seals the identity private keys with the local key (kind `0x40`).
pub fn seal_local_identity(key: &LocalKey, ctx: &LocalContext, keys: &IdentityKeyPair) -> Vec<u8> {
    identity::seal_secrets(
        key.secret_bytes(),
        Kind::LocalIdentity,
        &identity_tuple(ctx, keys.public()),
        keys,
    )
}

/// Opens a local identity and checks it matches `expected`.
pub fn open_local_identity(
    key: &LocalKey,
    ctx: &LocalContext,
    expected: &PublicIdentity,
    blob: &[u8],
) -> Result<IdentityKeyPair, CryptoError> {
    identity::open_secrets(
        key.secret_bytes(),
        Kind::LocalIdentity,
        &identity_tuple(ctx, expected),
        expected,
        blob,
    )
}

pub(crate) fn outbox_tuple(ctx: &LocalContext) -> Tuple {
    let mut tuple = Tuple::new(LABEL_LOCAL_OUTBOX);
    tuple
        .push(ctx.account.as_bytes())
        .push(ctx.device.as_bytes());
    tuple
}

/// Seals the local outbox (kind `0x43`, spec §14.7): JSON with what this
/// device has yet to upload. Like every `0x4·` blob it never leaves the
/// device; its contents go to the server as ordinary API calls.
pub fn seal_local_outbox(key: &LocalKey, ctx: &LocalContext, plaintext: &[u8]) -> Vec<u8> {
    super::aead::seal(
        key.secret_bytes(),
        Kind::LocalOutbox,
        &outbox_tuple(ctx),
        plaintext,
    )
}

/// Opens the local outbox.
pub fn open_local_outbox(
    key: &LocalKey,
    ctx: &LocalContext,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    super::aead::open(
        key.secret_bytes(),
        Kind::LocalOutbox,
        &outbox_tuple(ctx),
        blob,
    )
}

fn check_purpose(purpose: &str) -> Result<(), CryptoError> {
    if purpose.is_empty()
        || purpose.len() > MAX_PURPOSE_LEN
        || !purpose
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(CryptoError::Malformed("local data purpose"));
    }
    Ok(())
}

/// Seals device-local data (kind `0x41`). `purpose` (`[a-z0-9-]{1,64}`)
/// separates the uses, e.g. `"cache"` and `"session"`, so one blob cannot be
/// substituted for another.
pub fn seal_local_data(
    key: &LocalKey,
    ctx: &LocalContext,
    purpose: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    check_purpose(purpose)?;
    Ok(super::aead::seal(
        key.secret_bytes(),
        Kind::LocalData,
        &data_tuple(ctx, purpose),
        plaintext,
    ))
}

/// Opens device-local data sealed for `purpose`.
pub fn open_local_data(
    key: &LocalKey,
    ctx: &LocalContext,
    purpose: &str,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    check_purpose(purpose)?;
    super::aead::open(
        key.secret_bytes(),
        Kind::LocalData,
        &data_tuple(ctx, purpose),
        blob,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> LocalContext {
        LocalContext {
            account: AccountId::generate(),
            device: DeviceId::generate(),
        }
    }

    #[test]
    fn local_key_is_bound_to_kek_account_and_device() {
        let kek = Kek::generate();
        let c = ctx();
        let a = derive_local_key(&kek, &c);
        assert_eq!(a.secret_bytes(), derive_local_key(&kek, &c).secret_bytes());
        let other_device = LocalContext {
            device: DeviceId::generate(),
            ..c
        };
        assert_ne!(
            a.secret_bytes(),
            derive_local_key(&kek, &other_device).secret_bytes()
        );
        assert_ne!(
            a.secret_bytes(),
            derive_local_key(&Kek::generate(), &c).secret_bytes()
        );
        // Independent from the KEK itself.
        assert_ne!(a.secret_bytes(), kek.secret_bytes());
    }

    #[test]
    fn only_the_sessions_own_password_derives_its_local_key() {
        use crate::crypto::kdf::{KdfParams, MasterPassword, derive_kek};
        use crate::crypto::secret_key::SecretKey;
        let key_of = |password: &str, sk: &SecretKey, params: &KdfParams, c: &LocalContext| {
            let kek = derive_kek(&MasterPassword::new(password), sk, params).unwrap();
            derive_local_key(&kek, c)
        };
        let params = KdfParams::insecure_for_tests(64, 1, 1, [1; 16]);
        let secret_key = SecretKey::generate();
        let c = ctx();
        let session = key_of("the person's", &secret_key, &params, &c);
        let check = |password: &str, sk: &SecretKey, p: &KdfParams, cx: &LocalContext| {
            password_derives_local_key(&MasterPassword::new(password), sk, p, cx, &session).unwrap()
        };
        assert!(check("the person's", &secret_key, &params, &c));
        assert!(!check("another", &secret_key, &params, &c));
        // Another device or account context derives another key.
        assert!(!check("the person's", &secret_key, &params, &ctx()));
        // Another Secret Key, or other parameters (another salt), too.
        assert!(!check("the person's", &SecretKey::generate(), &params, &c));
        let other_params = KdfParams::insecure_for_tests(64, 1, 1, [2; 16]);
        assert!(!check("the person's", &secret_key, &other_params, &c));
        // A consistent set a program made under a password it chose (its
        // own Secret Key and parameters) opens its own files, and still
        // doesn't derive the session's key.
        let theirs_sk = SecretKey::generate();
        let theirs_params = KdfParams::insecure_for_tests(64, 1, 1, [3; 16]);
        let theirs = key_of("theirs", &theirs_sk, &theirs_params, &c);
        assert!(
            password_derives_local_key(
                &MasterPassword::new("theirs"),
                &theirs_sk,
                &theirs_params,
                &c,
                &theirs,
            )
            .unwrap()
        );
        assert!(!check("theirs", &theirs_sk, &theirs_params, &c));
    }

    #[test]
    fn local_identity_roundtrip_and_binding() {
        let key = LocalKey::generate();
        let c = ctx();
        let keys = IdentityKeyPair::generate();
        let blob = seal_local_identity(&key, &c, &keys);
        let opened = open_local_identity(&key, &c, keys.public(), &blob).unwrap();
        assert_eq!(opened.public(), keys.public());
        assert!(open_local_identity(&LocalKey::generate(), &c, keys.public(), &blob).is_err());
        assert!(open_local_identity(&key, &ctx(), keys.public(), &blob).is_err());
        let other = IdentityKeyPair::generate();
        assert!(open_local_identity(&key, &c, other.public(), &blob).is_err());
        // The server-side sealed identity format is not interchangeable.
        let mut as_kek_blob = blob.clone();
        as_kek_blob[1] = Kind::IdentitySecrets as u8;
        assert!(open_local_identity(&key, &c, keys.public(), &as_kek_blob).is_err());
    }

    #[test]
    fn local_data_is_bound_to_its_purpose() {
        let key = LocalKey::generate();
        let c = ctx();
        let blob = seal_local_data(&key, &c, "cache", b"hello").unwrap();
        assert_eq!(
            &*open_local_data(&key, &c, "cache", &blob).unwrap(),
            b"hello"
        );
        assert!(open_local_data(&key, &c, "session", &blob).is_err());
        assert!(open_local_data(&LocalKey::generate(), &c, "cache", &blob).is_err());
        assert!(seal_local_data(&key, &c, "", b"").is_err());
        assert!(seal_local_data(&key, &c, "Cache", b"").is_err());
        assert!(seal_local_data(&key, &c, &"a".repeat(65), b"").is_err());
    }
}
