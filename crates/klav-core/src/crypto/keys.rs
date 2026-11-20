//! Symmetric keys of the hierarchy (spec §5).
//!
//! Each level has its own type so a key can never be used at the wrong level:
//! the compiler rejects wrapping an item key with a vault key. None of these
//! types implement `Debug`, `Display` or `Clone`; their bytes live in a
//! [`SecretBox`] and are zeroized on drop.

use secrecy::{ExposeSecret, SecretBox};

use super::random;

/// Length in bytes of every symmetric key.
pub const KEY_LEN: usize = 32;

pub(crate) mod sealed {
    use super::{KEY_LEN, SecretBox};

    /// Crate-private access to key bytes. The module is private, so code
    /// outside `klav-core` cannot name this trait or call its methods.
    pub trait Sealed: Sized {
        fn from_secret(bytes: SecretBox<[u8; KEY_LEN]>) -> Self;
        fn secret_bytes(&self) -> &[u8; KEY_LEN];
    }
}

/// Common interface of the 256-bit symmetric keys of the hierarchy.
pub trait SymmetricKey: sealed::Sealed {
    /// Generates a fresh random key from the OS CSPRNG.
    fn generate() -> Self;
}

macro_rules! define_key {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        pub struct $name(SecretBox<[u8; KEY_LEN]>);

        impl sealed::Sealed for $name {
            fn from_secret(bytes: SecretBox<[u8; KEY_LEN]>) -> Self {
                Self(bytes)
            }

            fn secret_bytes(&self) -> &[u8; KEY_LEN] {
                self.0.expose_secret()
            }
        }

        impl SymmetricKey for $name {
            fn generate() -> Self {
                Self(SecretBox::init_with_mut(|k: &mut [u8; KEY_LEN]| random::fill(k)))
            }
        }

        impl $name {
            /// Generates a fresh random key from the OS CSPRNG.
            pub fn generate() -> Self {
                <Self as SymmetricKey>::generate()
            }

            /// Builds a key from raw bytes. Used by tests and test vectors; real
            /// keys come from [`Self::generate`] or from unwrapping.
            #[cfg(test)]
            pub(crate) fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
                Self(SecretBox::new(Box::new(bytes)))
            }
        }
    };
}

define_key!(
    /// Key-encryption key derived from the master password and Secret Key
    /// (spec §4). Seals the identity private keys of an account.
    Kek
);
define_key!(
    /// Vault key: random, shared with members through HPKE.
    VaultKey
);
define_key!(
    /// Project key: wrapped under its vault key and, for grants, with HPKE.
    ProjectKey
);
define_key!(
    /// Item key: wrapped under its project key; encrypts the item sections.
    ItemKey
);
define_key!(
    /// Attachment key: wrapped under its item key; encrypts one attachment.
    AttachmentKey
);
define_key!(
    /// Local unlock key of one device (spec §12.2): derived from the KEK,
    /// it seals the device-local copy of the identity and the local cache.
    /// Never leaves the device.
    LocalKey
);

#[cfg(test)]
mod tests {
    use super::sealed::Sealed;
    use super::*;

    static_assertions::assert_not_impl_any!(Kek: std::fmt::Debug, std::fmt::Display, Clone);
    static_assertions::assert_not_impl_any!(VaultKey: std::fmt::Debug, std::fmt::Display, Clone);
    static_assertions::assert_not_impl_any!(ProjectKey: std::fmt::Debug, std::fmt::Display, Clone);
    static_assertions::assert_not_impl_any!(ItemKey: std::fmt::Debug, std::fmt::Display, Clone);
    static_assertions::assert_not_impl_any!(AttachmentKey: std::fmt::Debug, std::fmt::Display, Clone);
    static_assertions::assert_not_impl_any!(LocalKey: std::fmt::Debug, std::fmt::Display, Clone);

    #[test]
    fn generated_keys_differ() {
        assert_ne!(
            VaultKey::generate().secret_bytes(),
            VaultKey::generate().secret_bytes()
        );
    }
}
