//! Master password + Secret Key → KEK (spec §4).
//!
//! ```text
//! P   = UTF-8(NFKD(password))
//! A   = Argon2id(v=0x13, P, salt, m, t, p, len=32)
//! B   = HKDF-SHA256(salt=salt, ikm=secret_key, info="klav/v1/kdf/secret-key", len=32)
//! KEK = HKDF-SHA256(salt=∅, ikm=A ⊕ B, info="klav/v1/kdf/kek", len=32)
//! O   = HKDF-SHA256(salt=∅, ikm=A ⊕ B, info="klav/v1/kdf/opaque", len=32)
//! ```
//!
//! `O` is the password fed to OPAQUE (see [`super::opaque`]). It is
//! independent from the KEK: knowing one reveals nothing about the other.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use super::encoding::{FORMAT_V1, Kind, Tuple, strip_header};
use super::keys::{KEY_LEN, Kek, sealed::Sealed};
use super::opaque::OpaqueInput;
use super::secret_key::SecretKey;
use super::{CryptoError, random};

/// HKDF info for the Secret Key branch.
pub const INFO_SECRET_KEY: &[u8] = b"klav/v1/kdf/secret-key";
/// HKDF info for the final KEK.
pub const INFO_KEK: &[u8] = b"klav/v1/kdf/kek";
/// HKDF info for the OPAQUE input (spec §4.5).
pub const INFO_OPAQUE: &[u8] = b"klav/v1/kdf/opaque";
/// Label of the decoy salt the server returns for unknown accounts (spec §4.5).
pub const LABEL_DECOY_SALT: &str = "klav/v1/server/decoy-kdf-salt";
/// Salt length in bytes.
pub const SALT_LEN: usize = 16;
/// Encoded length of [`KdfParams`]: header(2) ‖ m(4) ‖ t(4) ‖ p(4) ‖ salt(16).
pub const ENCODED_LEN: usize = 2 + 4 + 4 + 4 + SALT_LEN;

/// A master password. Not `Debug`, not `Display`, zeroized on drop.
pub struct MasterPassword(SecretString);

impl MasterPassword {
    /// Wraps a password typed by the user.
    pub fn new(password: impl Into<String>) -> Self {
        Self(SecretString::from(password.into()))
    }

    /// `UTF-8(NFKD(password))`: the exact bytes fed to Argon2id.
    fn normalized(&self) -> Zeroizing<Vec<u8>> {
        let nfkd: Zeroizing<String> = Zeroizing::new(self.0.expose_secret().nfkd().collect());
        Zeroizing::new(nfkd.as_bytes().to_vec())
    }
}

/// Versioned Argon2id parameters (format v1, kind `0x06`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParams {
    m_kib: u32,
    t: u32,
    p: u32,
    salt: [u8; SALT_LEN],
}

impl KdfParams {
    /// Production memory cost: 256 MiB.
    pub const DEFAULT_M_KIB: u32 = 256 * 1024;
    /// Production time cost.
    pub const DEFAULT_T: u32 = 3;
    /// Production parallelism.
    pub const DEFAULT_P: u32 = 4;
    /// Floor accepted when decoding: protects against a server downgrading parameters.
    pub const MIN_M_KIB: u32 = Self::DEFAULT_M_KIB;
    /// Floor for the time cost.
    pub const MIN_T: u32 = Self::DEFAULT_T;
    /// Floor for parallelism.
    pub const MIN_P: u32 = 1;
    /// Ceiling for the memory cost (4 GiB): protects against denial of service.
    pub const MAX_M_KIB: u32 = 4 * 1024 * 1024;
    /// Ceiling for the time cost.
    pub const MAX_T: u32 = 64;
    /// Ceiling for parallelism.
    pub const MAX_P: u32 = 64;

    /// Production defaults (m = 256 MiB, t = 3, p = 4) with a fresh random salt.
    pub fn generate() -> Self {
        Self {
            m_kib: Self::DEFAULT_M_KIB,
            t: Self::DEFAULT_T,
            p: Self::DEFAULT_P,
            salt: random::array(),
        }
    }

    /// Production defaults with a salt derived from `server_secret` and the
    /// account identifier (spec §4.5).
    ///
    /// The server answers the pre-login request for an unknown e-mail with
    /// these parameters, so the response looks the same whether the account
    /// exists or not, and is stable across requests.
    pub fn decoy(server_secret: &[u8; KEY_LEN], identifier: &[u8]) -> Self {
        let mut info = Tuple::new(LABEL_DECOY_SALT);
        info.push(identifier);
        let mut salt = [0u8; SALT_LEN];
        Hkdf::<Sha256>::new(None, server_secret)
            .expand(info.as_bytes(), &mut salt)
            .expect("16 bytes is a valid HKDF-SHA256 output length");
        Self {
            m_kib: Self::DEFAULT_M_KIB,
            t: Self::DEFAULT_T,
            p: Self::DEFAULT_P,
            salt,
        }
    }

    /// Builds parameters with arbitrary (possibly weak) costs.
    ///
    /// **Never use outside tests.** Available only in this crate's tests and
    /// behind the `insecure-test-kdf` feature.
    #[cfg(any(test, feature = "insecure-test-kdf"))]
    pub fn insecure_for_tests(m_kib: u32, t: u32, p: u32, salt: [u8; SALT_LEN]) -> Self {
        Self { m_kib, t, p, salt }
    }

    /// Memory cost in KiB.
    pub fn m_kib(&self) -> u32 {
        self.m_kib
    }

    /// Time cost (iterations).
    pub fn t(&self) -> u32 {
        self.t
    }

    /// Parallelism (lanes).
    pub fn p(&self) -> u32 {
        self.p
    }

    /// Salt (also the HKDF salt of the Secret Key branch).
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    /// `0x01 ‖ 0x06 ‖ u32(m) ‖ u32(t) ‖ u32(p) ‖ salt(16)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENCODED_LEN);
        out.extend_from_slice(&Kind::KdfParams.header());
        out.extend_from_slice(&self.m_kib.to_be_bytes());
        out.extend_from_slice(&self.t.to_be_bytes());
        out.extend_from_slice(&self.p.to_be_bytes());
        out.extend_from_slice(&self.salt);
        out
    }

    /// Decodes and validates parameters, rejecting anything below the
    /// production floor or above the denial-of-service ceiling.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let params = Self::decode_unchecked(bytes)?;
        params.check_bounds()?;
        Ok(params)
    }

    /// Decodes without enforcing the floor (ceiling still applies).
    #[cfg(any(test, feature = "insecure-test-kdf"))]
    pub fn decode_insecure_for_tests(bytes: &[u8]) -> Result<Self, CryptoError> {
        let params = Self::decode_unchecked(bytes)?;
        params.check_ceiling()?;
        Ok(params)
    }

    fn decode_unchecked(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ENCODED_LEN {
            return Err(CryptoError::Malformed("KDF parameters length"));
        }
        let body = strip_header(bytes, Kind::KdfParams)?;
        debug_assert_eq!(bytes[0], FORMAT_V1);
        let word = |i: usize| u32::from_be_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]);
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&body[12..]);
        Ok(Self {
            m_kib: word(0),
            t: word(4),
            p: word(8),
            salt,
        })
    }

    fn check_bounds(&self) -> Result<(), CryptoError> {
        if self.m_kib < Self::MIN_M_KIB {
            return Err(CryptoError::KdfParams("memory cost below the minimum"));
        }
        if self.t < Self::MIN_T {
            return Err(CryptoError::KdfParams("time cost below the minimum"));
        }
        if self.p < Self::MIN_P {
            return Err(CryptoError::KdfParams("parallelism below the minimum"));
        }
        self.check_ceiling()
    }

    fn check_ceiling(&self) -> Result<(), CryptoError> {
        if self.m_kib > Self::MAX_M_KIB || self.t > Self::MAX_T || self.p > Self::MAX_P {
            return Err(CryptoError::KdfParams("parameters above the maximum"));
        }
        Ok(())
    }
}

/// Intermediate values of the derivation, exposed to the test vectors.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct KdfParts {
    pub(crate) argon2: Zeroizing<[u8; KEY_LEN]>,
    pub(crate) secret_key: Zeroizing<[u8; KEY_LEN]>,
    pub(crate) kek: Zeroizing<[u8; KEY_LEN]>,
    pub(crate) opaque: Zeroizing<[u8; KEY_LEN]>,
}

pub(crate) fn derive_parts(
    password: &MasterPassword,
    secret_key: &SecretKey,
    params: &KdfParams,
) -> Result<KdfParts, CryptoError> {
    // The floor applies here too, not only when decoding: parameters built
    // any other way never derive below it. Test builds keep the fast
    // parameters of their vectors and servers.
    if cfg!(any(test, feature = "insecure-test-kdf")) {
        params.check_ceiling()?;
    } else {
        params.check_bounds()?;
    }
    let argon_params = Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN))
        .map_err(|_| CryptoError::KdfParams("rejected by Argon2"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut a = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(&password.normalized(), &params.salt, a.as_mut())
        .map_err(|_| CryptoError::Kdf)?;

    let mut b = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(Some(&params.salt), secret_key.bytes())
        .expand(INFO_SECRET_KEY, b.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");

    let mut mixed = Zeroizing::new([0u8; KEY_LEN]);
    for (out, (x, y)) in mixed.iter_mut().zip(a.iter().zip(b.iter())) {
        *out = x ^ y;
    }

    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, mixed.as_ref())
        .expand(INFO_KEK, kek.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");

    let mut opaque = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, mixed.as_ref())
        .expand(INFO_OPAQUE, opaque.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");

    Ok(KdfParts {
        argon2: a,
        secret_key: b,
        kek,
        opaque,
    })
}

/// Everything derived from the master password and the Secret Key in one
/// Argon2id run: the KEK and the OPAQUE input.
pub struct AccountKeys {
    kek: Kek,
    opaque: OpaqueInput,
}

impl AccountKeys {
    /// The KEK (opens the sealed identity, spec §6.3).
    pub fn kek(&self) -> &Kek {
        &self.kek
    }

    /// The OPAQUE input (authenticates to the server, spec §4.5).
    pub fn opaque_input(&self) -> &OpaqueInput {
        &self.opaque
    }

    /// Splits into the KEK and the OPAQUE input.
    pub fn into_parts(self) -> (Kek, OpaqueInput) {
        (self.kek, self.opaque)
    }
}

/// Derives the KEK and the OPAQUE input with a single Argon2id run.
///
/// Callers must obtain `params` through [`KdfParams::decode`] (or
/// [`KdfParams::generate`] at sign-up) so that the production floor applies.
pub fn derive_account_keys(
    password: &MasterPassword,
    secret_key: &SecretKey,
    params: &KdfParams,
) -> Result<AccountKeys, CryptoError> {
    let parts = derive_parts(password, secret_key, params)?;
    Ok(AccountKeys {
        kek: Kek::from_secret(SecretBox::new(Box::new(*parts.kek))),
        opaque: OpaqueInput::from_secret(SecretBox::new(Box::new(*parts.opaque))),
    })
}

/// Derives the KEK from the master password and the Secret Key.
///
/// Callers must obtain `params` through [`KdfParams::decode`] (or
/// [`KdfParams::generate`] at sign-up) so that the production floor applies.
pub fn derive_kek(
    password: &MasterPassword,
    secret_key: &SecretKey,
    params: &KdfParams,
) -> Result<Kek, CryptoError> {
    let parts = derive_parts(password, secret_key, params)?;
    Ok(Kek::from_secret(SecretBox::new(Box::new(*parts.kek))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast(salt: u8) -> KdfParams {
        KdfParams::insecure_for_tests(64, 1, 1, [salt; SALT_LEN])
    }

    static_assertions::assert_not_impl_any!(MasterPassword: std::fmt::Debug, std::fmt::Display, Clone);

    #[test]
    fn params_roundtrip_and_floor() {
        let params = KdfParams::generate();
        let bytes = params.encode();
        assert_eq!(bytes.len(), ENCODED_LEN);
        assert_eq!(KdfParams::decode(&bytes), Ok(params));

        let weak = fast(1).encode();
        assert!(matches!(
            KdfParams::decode(&weak),
            Err(CryptoError::KdfParams(_))
        ));
        assert_eq!(KdfParams::decode_insecure_for_tests(&weak), Ok(fast(1)));
    }

    #[test]
    fn params_ceiling_and_shape() {
        let huge = KdfParams::insecure_for_tests(KdfParams::MAX_M_KIB + 1, 3, 4, [0; 16]).encode();
        assert!(matches!(
            KdfParams::decode(&huge),
            Err(CryptoError::KdfParams(_))
        ));
        assert!(matches!(
            KdfParams::decode_insecure_for_tests(&huge),
            Err(CryptoError::KdfParams(_))
        ));
        assert!(KdfParams::decode(&[0x01, 0x06]).is_err());
        let mut wrong_kind = KdfParams::generate().encode();
        wrong_kind[1] = 0x07;
        assert!(matches!(
            KdfParams::decode(&wrong_kind),
            Err(CryptoError::UnexpectedKind { .. })
        ));
    }

    #[test]
    fn kek_depends_on_every_input() {
        let sk = SecretKey::from_bytes([7; 16]);
        let pw = MasterPassword::new("correct horse");
        let base = derive_parts(&pw, &sk, &fast(1)).unwrap();
        let other_pw = derive_parts(&MasterPassword::new("correct horsf"), &sk, &fast(1)).unwrap();
        let other_sk = derive_parts(&pw, &SecretKey::from_bytes([8; 16]), &fast(1)).unwrap();
        let other_salt = derive_parts(&pw, &sk, &fast(2)).unwrap();
        assert_ne!(*base.kek, *other_pw.kek);
        assert_ne!(*base.kek, *other_sk.kek);
        assert_ne!(*base.kek, *other_salt.kek);
        assert_ne!(*base.opaque, *other_pw.opaque);
        assert_ne!(*base.opaque, *other_sk.opaque);
        // The OPAQUE input and the KEK are independent outputs.
        assert_ne!(*base.opaque, *base.kek);
        // The Secret Key branch does not depend on the password.
        assert_eq!(*base.secret_key, *other_pw.secret_key);
    }

    #[test]
    fn decoy_params_are_stable_and_per_identifier() {
        let secret = [9u8; KEY_LEN];
        let a = KdfParams::decoy(&secret, b"ana@example.com");
        assert_eq!(a, KdfParams::decoy(&secret, b"ana@example.com"));
        assert_ne!(
            a.salt(),
            KdfParams::decoy(&secret, b"bob@example.com").salt()
        );
        assert_ne!(
            a.salt(),
            KdfParams::decoy(&[8u8; KEY_LEN], b"ana@example.com").salt()
        );
        // Indistinguishable in shape from real production parameters.
        assert_eq!(KdfParams::decode(&a.encode()), Ok(a));
    }

    #[test]
    fn password_is_nfkd_normalized() {
        let sk = SecretKey::from_bytes([1; 16]);
        // "é" precomposed (U+00E9) vs "e" + combining acute (U+0065 U+0301).
        let a = derive_parts(&MasterPassword::new("caf\u{e9}"), &sk, &fast(3)).unwrap();
        let b = derive_parts(&MasterPassword::new("cafe\u{301}"), &sk, &fast(3)).unwrap();
        assert_eq!(*a.kek, *b.kek);
    }
}
