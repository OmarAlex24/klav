//! Private key of a passkey (spec §14.1 and §14.3, ADR 0020 §4).
//!
//! A passkey signs with ES256: ECDSA over P-256 with SHA-256, deterministic
//! nonces (RFC 6979) and DER signatures, from RustCrypto's `p256`/`ecdsa`.
//! Its 32-byte scalar is sealed with the **vault key**, which no agent ever
//! receives, so an agent that reads the item's details (with `fill`,
//! `reveal` or `update`) only sees an opaque blob:
//!
//! ```text
//! kind 0x15, key = vault key,
//! AAD = header ‖ tuple("klav/v1/passkey/private-key", account, vault, item,
//!                      credential_id, rp_id, user_handle)
//! blob = 0x01 ‖ 0x15 ‖ nonce(24) ‖ ct(32 + 16)            (74 bytes)
//! ```
//!
//! The project is not in the AAD, so moving the item to another project of
//! the same vault keeps the key usable. The credential, the relying party
//! and the user are: the key cannot be moved to another site, credential or
//! account.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey, signature::Verifier};
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
use zeroize::Zeroizing;

use super::context::VaultContext;
use super::encoding::{Kind, Tuple};
use super::keys::{VaultKey, sealed::Sealed};
use super::{CryptoError, aead, random};
use crate::ids::ItemId;

/// AAD label of a sealed passkey private key.
pub const LABEL_PASSKEY_KEY: &str = "klav/v1/passkey/private-key";
/// Length of a sealed passkey private key (kind `0x15`).
pub const PASSKEY_KEY_BLOB_LEN: usize = aead::OVERHEAD + SCALAR_LEN;
/// Length of the P-256 scalar.
pub const SCALAR_LEN: usize = 32;
/// Length of an uncompressed SEC1 P-256 public key (`0x04 ‖ x ‖ y`).
pub const PUBLIC_KEY_LEN: usize = 65;
/// Length of the credential IDs Klav creates (ADR 0020 §5).
pub const CREDENTIAL_ID_LEN: usize = 16;
/// Longest credential ID WebAuthn allows (imported passkeys keep theirs).
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;
/// Longest user handle WebAuthn allows.
pub const MAX_USER_HANDLE_LEN: usize = 64;
/// Longest DNS name, the bound of an rpId.
pub const MAX_RP_ID_LEN: usize = 253;

/// AAGUID of Klav as an authenticator (spec §14.8, ADR 0020 §5): a fixed
/// UUID v4, `a36a6cd0-200d-411f-a41d-b964cce16689`, the same on every
/// platform.
pub const AAGUID: [u8; 16] = [
    0xa3, 0x6a, 0x6c, 0xd0, 0x20, 0x0d, 0x41, 0x1f, 0xa4, 0x1d, 0xb9, 0x64, 0xcc, 0xe1, 0x66, 0x89,
];

/// What a sealed passkey key is bound to, besides the vault and the item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasskeyBinding<'a> {
    /// Credential ID (16 random bytes when Klav creates it).
    pub credential_id: &'a [u8],
    /// Relying party ID: a lowercase ASCII (punycode) domain, no port.
    pub rp_id: &'a str,
    /// User handle given by the relying party (1 to 64 bytes).
    pub user_handle: &'a [u8],
}

impl PasskeyBinding<'_> {
    /// Checks the shapes the AAD relies on. The rpId rules of WebAuthn
    /// (origin, public suffixes) live in `passkey::rp`; this only rejects
    /// what can never be an rpId.
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.credential_id.is_empty() || self.credential_id.len() > MAX_CREDENTIAL_ID_LEN {
            return Err(CryptoError::Malformed("passkey credential ID length"));
        }
        if self.user_handle.is_empty() || self.user_handle.len() > MAX_USER_HANDLE_LEN {
            return Err(CryptoError::Malformed("passkey user handle length"));
        }
        let rp = self.rp_id;
        let shape_ok = !rp.is_empty()
            && rp.len() <= MAX_RP_ID_LEN
            && rp
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
            && !rp.starts_with('.')
            && !rp.ends_with('.')
            && !rp.contains("..");
        if !shape_ok {
            return Err(CryptoError::Malformed("passkey rp_id"));
        }
        Ok(())
    }

    fn tuple(&self, ctx: &VaultContext, item: ItemId) -> Tuple {
        let mut tuple = Tuple::new(LABEL_PASSKEY_KEY);
        tuple
            .push(ctx.account.as_bytes())
            .push(ctx.vault.as_bytes())
            .push(item.as_bytes())
            .push(self.credential_id)
            .push(self.rp_id.as_bytes())
            .push(self.user_handle);
        tuple
    }
}

/// The P-256 private key of one passkey. It never leaves `klav-core` in the
/// clear: the only ways out are sealing it (kind `0x15`) and signing with it.
/// It does not implement `Debug`, `Display` or `Clone`, and the scalar is
/// zeroized on drop (by `SigningKey`).
pub struct PasskeyPrivateKey(SigningKey);

impl PasskeyPrivateKey {
    /// A fresh key from the OS CSPRNG.
    pub fn generate() -> Self {
        loop {
            let scalar = Zeroizing::new(random::array::<SCALAR_LEN>());
            // Rejects 0 and values >= n (probability about 2^-32).
            if let Ok(key) = Self::from_scalar(&scalar) {
                return key;
            }
        }
    }

    /// Reads a private key from PKCS#8 DER, the form other password
    /// managers export (Bitwarden's `keyValue`). Only P-256 keys are
    /// accepted.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        SigningKey::from_pkcs8_der(der)
            .map(Self)
            .map_err(|_| CryptoError::Malformed("passkey PKCS#8 key"))
    }

    pub(crate) fn from_scalar(scalar: &[u8; SCALAR_LEN]) -> Result<Self, CryptoError> {
        SigningKey::from_slice(scalar)
            .map(Self)
            .map_err(|_| CryptoError::Malformed("passkey scalar out of range"))
    }

    /// Uncompressed SEC1 public key, `0x04 ‖ x(32) ‖ y(32)`.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        let point = self.0.verifying_key().to_sec1_point(false);
        point
            .as_bytes()
            .try_into()
            .expect("an uncompressed P-256 point is 65 bytes")
    }

    /// Public key as SubjectPublicKeyInfo DER, for `getPublicKey()`.
    pub fn public_key_spki_der(&self) -> Vec<u8> {
        self.0
            .verifying_key()
            .to_public_key_der()
            .expect("a P-256 public key always encodes as SPKI")
            .into_vec()
    }

    /// ES256 signature of `message` (SHA-256 inside), DER-encoded, with the
    /// deterministic RFC 6979 nonce. Only WebAuthn messages are signed with
    /// passkey keys (spec §14.1); callers outside the crate go through
    /// `passkey::webauthn`.
    pub(crate) fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature: DerSignature = self.0.sign(message);
        signature.as_bytes().to_vec()
    }

    pub(crate) fn scalar(&self) -> Zeroizing<[u8; SCALAR_LEN]> {
        Zeroizing::new(self.0.to_bytes().into())
    }
}

/// Verifies an ES256 DER signature of `message` with an uncompressed SEC1
/// public key. Klav never needs it to authenticate anyone: it lets tests,
/// importers and the extension check that a key and a signature belong
/// together.
pub fn verify_es256(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let key =
        VerifyingKey::from_sec1_bytes(public_key).map_err(|_| CryptoError::InvalidPublicKey)?;
    let signature = DerSignature::try_from(signature).map_err(|_| CryptoError::Signature)?;
    key.verify(message, &signature)
        .map_err(|_| CryptoError::Signature)
}

/// Seals the private key of a passkey of `item` with the vault key
/// (kind `0x15`, 74 bytes).
pub fn seal_passkey_key(
    vault_key: &VaultKey,
    ctx: &VaultContext,
    item: ItemId,
    binding: &PasskeyBinding<'_>,
    key: &PasskeyPrivateKey,
) -> Result<Vec<u8>, CryptoError> {
    binding.validate()?;
    Ok(aead::seal(
        vault_key.secret_bytes(),
        Kind::PasskeyKey,
        &binding.tuple(ctx, item),
        &*key.scalar(),
    ))
}

/// Opens a sealed passkey private key. Any authentication failure (another
/// key, vault, item, credential, rpId or user) is the opaque
/// [`CryptoError::Decryption`]; a scalar outside `[1, n−1]` is rejected.
pub fn open_passkey_key(
    vault_key: &VaultKey,
    ctx: &VaultContext,
    item: ItemId,
    binding: &PasskeyBinding<'_>,
    blob: &[u8],
) -> Result<PasskeyPrivateKey, CryptoError> {
    binding.validate()?;
    if blob.len() != PASSKEY_KEY_BLOB_LEN {
        return Err(CryptoError::Malformed("sealed passkey key length"));
    }
    let plain = aead::open(
        vault_key.secret_bytes(),
        Kind::PasskeyKey,
        &binding.tuple(ctx, item),
        blob,
    )?;
    let scalar: Zeroizing<[u8; SCALAR_LEN]> = Zeroizing::new(
        plain
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Malformed("passkey scalar length"))?,
    );
    PasskeyPrivateKey::from_scalar(&scalar)
}

/// Checks the shape of a sealed key without opening it: header and length.
/// Clients that only carry the blob (agents, the overview) use it to reject
/// garbage early.
pub fn check_sealed_passkey_key(blob: &[u8]) -> Result<(), CryptoError> {
    super::encoding::strip_header(blob, Kind::PasskeyKey)?;
    if blob.len() != PASSKEY_KEY_BLOB_LEN {
        return Err(CryptoError::Malformed("sealed passkey key length"));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn seal_passkey_key_with_nonce(
    vault_key: &VaultKey,
    ctx: &VaultContext,
    item: ItemId,
    binding: &PasskeyBinding<'_>,
    key: &PasskeyPrivateKey,
    nonce: &[u8; aead::NONCE_LEN],
) -> (Vec<u8>, Tuple) {
    let tuple = binding.tuple(ctx, item);
    let blob = aead::seal_with_nonce(
        vault_key.secret_bytes(),
        Kind::PasskeyKey,
        &tuple,
        nonce,
        &*key.scalar(),
    );
    (blob, tuple)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{ItemKey, ProjectKey};
    use crate::ids::{AccountId, VaultId};

    static_assertions::assert_not_impl_any!(
        PasskeyPrivateKey: std::fmt::Debug,
        std::fmt::Display,
        Clone
    );

    fn ctx() -> VaultContext {
        VaultContext {
            account: AccountId::generate(),
            vault: VaultId::generate(),
        }
    }

    const CRED: [u8; 16] = [7; 16];
    const BINDING: PasskeyBinding<'static> = PasskeyBinding {
        credential_id: &CRED,
        rp_id: "example.com",
        user_handle: b"user-1",
    };

    #[test]
    fn seals_to_74_bytes_and_opens_to_the_same_key() {
        let (ctx, vault, item) = (ctx(), VaultKey::generate(), ItemId::generate());
        let key = PasskeyPrivateKey::generate();
        let blob = seal_passkey_key(&vault, &ctx, item, &BINDING, &key).unwrap();
        assert_eq!(blob.len(), 74);
        assert_eq!(&blob[..2], &[0x01, 0x15]);
        check_sealed_passkey_key(&blob).unwrap();
        let opened = open_passkey_key(&vault, &ctx, item, &BINDING, &blob).unwrap();
        assert_eq!(opened.public_key(), key.public_key());
        assert_eq!(opened.public_key()[0], 0x04);
    }

    #[test]
    fn bound_to_vault_item_credential_rp_and_user() {
        let (ctx, vault, item) = (ctx(), VaultKey::generate(), ItemId::generate());
        let key = PasskeyPrivateKey::generate();
        let blob = seal_passkey_key(&vault, &ctx, item, &BINDING, &key).unwrap();
        let open = |vk: &VaultKey, c: &VaultContext, i: ItemId, b: &PasskeyBinding<'_>| {
            open_passkey_key(vk, c, i, b, &blob).err()
        };
        let dec = Some(CryptoError::Decryption);
        assert_eq!(open(&VaultKey::generate(), &ctx, item, &BINDING), dec);
        assert_eq!(open(&vault, &self::ctx(), item, &BINDING), dec);
        assert_eq!(open(&vault, &ctx, ItemId::generate(), &BINDING), dec);
        let other_cred = [8u8; 16];
        let cases = [
            PasskeyBinding {
                credential_id: &other_cred,
                ..BINDING
            },
            PasskeyBinding {
                rp_id: "evil.example",
                ..BINDING
            },
            PasskeyBinding {
                rp_id: "sub.example.com",
                ..BINDING
            },
            PasskeyBinding {
                user_handle: b"user-2",
                ..BINDING
            },
        ];
        for b in &cases {
            assert_eq!(open(&vault, &ctx, item, b), dec);
        }
        // What an agent holds (a project or item key) does not open it.
        for k in [
            ProjectKey::generate().secret_bytes(),
            ItemKey::generate().secret_bytes(),
        ] {
            assert!(aead::open(k, Kind::PasskeyKey, &BINDING.tuple(&ctx, item), &blob).is_err());
        }
        // Another kind byte is rejected before decryption.
        let mut swapped = blob.clone();
        swapped[1] = Kind::PasswordRecord as u8;
        assert!(open_passkey_key(&vault, &ctx, item, &BINDING, &swapped).is_err());
        assert!(check_sealed_passkey_key(&swapped).is_err());
        // Truncated: rejected.
        assert!(open_passkey_key(&vault, &ctx, item, &BINDING, &blob[..73]).is_err());
    }

    #[test]
    fn aaguid_is_a_v4_uuid() {
        let id = uuid::Uuid::from_bytes(AAGUID);
        assert_eq!(id.get_version_num(), 4);
        assert_eq!(id.to_string(), "a36a6cd0-200d-411f-a41d-b964cce16689");
    }

    #[test]
    fn out_of_range_scalars_are_rejected() {
        assert!(PasskeyPrivateKey::from_scalar(&[0; 32]).is_err());
        assert!(PasskeyPrivateKey::from_scalar(&[0xff; 32]).is_err());
        // A sealed zero scalar authenticates but does not open as a key.
        let (ctx, vault, item) = (ctx(), VaultKey::generate(), ItemId::generate());
        let blob = aead::seal(
            vault.secret_bytes(),
            Kind::PasskeyKey,
            &BINDING.tuple(&ctx, item),
            &[0; 32],
        );
        assert!(matches!(
            open_passkey_key(&vault, &ctx, item, &BINDING, &blob),
            Err(CryptoError::Malformed(_))
        ));
    }

    #[test]
    fn binding_shapes() {
        assert!(BINDING.validate().is_ok());
        let long = [0u8; 1024];
        let bad = [
            PasskeyBinding {
                credential_id: &[],
                ..BINDING
            },
            PasskeyBinding {
                credential_id: &long,
                ..BINDING
            },
            PasskeyBinding {
                user_handle: &[],
                ..BINDING
            },
            PasskeyBinding {
                user_handle: &[1; 65],
                ..BINDING
            },
            PasskeyBinding {
                rp_id: "Example.com",
                ..BINDING
            },
            PasskeyBinding {
                rp_id: "example.com:443",
                ..BINDING
            },
            PasskeyBinding {
                rp_id: ".example.com",
                ..BINDING
            },
            PasskeyBinding {
                rp_id: "",
                ..BINDING
            },
            PasskeyBinding {
                rp_id: "exämple.com",
                ..BINDING
            },
        ];
        for b in &bad {
            assert!(b.validate().is_err(), "{b:?}");
        }
    }

    #[test]
    fn signatures_are_deterministic_der_and_verify() {
        let key = PasskeyPrivateKey::generate();
        let sig = key.sign(b"message");
        assert_eq!(sig, key.sign(b"message"), "RFC 6979 nonce");
        assert_eq!(sig[0], 0x30, "DER SEQUENCE");
        let public = key.public_key();
        verify_es256(&public, b"message", &sig).unwrap();
        assert_eq!(
            verify_es256(&public, b"other", &sig),
            Err(CryptoError::Signature)
        );
        assert!(
            verify_es256(
                &PasskeyPrivateKey::generate().public_key(),
                b"message",
                &sig
            )
            .is_err()
        );
        // SPKI DER carries the same point at its end.
        let spki = key.public_key_spki_der();
        assert!(spki.ends_with(&public));
        assert_eq!(spki.len(), 91);
    }
}
