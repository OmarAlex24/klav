//! Secret Key (spec §4.2): 128 random bits generated at sign-up, printed in
//! the emergency kit and mixed into the KEK derivation.
//!
//! Text form: `K1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`, where `K1` is the
//! version prefix and the 32 characters are
//! `BASE32(key(16) ‖ checksum(4))` (RFC 4648 alphabet, no padding) and
//! `checksum = SHA-256(tuple("klav/v1/secret-key/checksum", key))[0..4]`.

use data_encoding::BASE32_NOPAD;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::encoding::Tuple;
use super::{CryptoError, random};
use crate::ids::AccountId;

/// Raw Secret Key length.
pub const SECRET_KEY_LEN: usize = 16;
/// Checksum length.
pub const CHECKSUM_LEN: usize = 4;
/// Version prefix of the text form.
pub const PREFIX: &str = "K1";
/// Label of the checksum tuple.
pub const CHECKSUM_LABEL: &str = "klav/v1/secret-key/checksum";

/// The account Secret Key. Not `Debug`, not `Display`, zeroized on drop.
pub struct SecretKey(SecretBox<[u8; SECRET_KEY_LEN]>);

impl SecretKey {
    /// Generates a new Secret Key from the OS CSPRNG.
    pub fn generate() -> Self {
        Self(SecretBox::init_with_mut(|k: &mut [u8; SECRET_KEY_LEN]| {
            random::fill(k)
        }))
    }

    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; SECRET_KEY_LEN]) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    pub(crate) fn bytes(&self) -> &[u8; SECRET_KEY_LEN] {
        self.0.expose_secret()
    }

    fn checksum(key: &[u8; SECRET_KEY_LEN]) -> [u8; CHECKSUM_LEN] {
        let mut tuple = Tuple::new(CHECKSUM_LABEL);
        tuple.push(key);
        let bytes = Zeroizing::new(tuple.into_bytes());
        let digest = Sha256::digest(bytes.as_slice());
        let mut out = [0u8; CHECKSUM_LEN];
        out.copy_from_slice(&digest[..CHECKSUM_LEN]);
        out
    }

    /// The text form, e.g. `K1-ABCD-EFGH-…`. Returned as a secret: never log it.
    pub fn to_text(&self) -> SecretString {
        let mut raw = Zeroizing::new([0u8; SECRET_KEY_LEN + CHECKSUM_LEN]);
        raw[..SECRET_KEY_LEN].copy_from_slice(self.bytes());
        raw[SECRET_KEY_LEN..].copy_from_slice(&Self::checksum(self.bytes()));
        let encoded = Zeroizing::new(BASE32_NOPAD.encode(raw.as_ref()));
        let mut text = String::with_capacity(PREFIX.len() + 40);
        text.push_str(PREFIX);
        for group in encoded.as_bytes().chunks(4) {
            text.push('-');
            text.push_str(std::str::from_utf8(group).expect("base32 output is ASCII"));
        }
        SecretString::from(text)
    }

    /// Parses the text form.
    ///
    /// Case-insensitive; ignores `-` and whitespace; reads the digits `0`, `1`
    /// and `8` (not in the base32 alphabet) as `O`, `I` and `B`.
    pub fn parse(text: &str) -> Result<Self, CryptoError> {
        // Sized up front: a growing buffer would leave copies behind.
        let mut cleaned = Zeroizing::new(String::with_capacity(text.len()));
        cleaned.extend(
            text.chars()
                .filter(|c| *c != '-' && !c.is_whitespace())
                .map(|c| c.to_ascii_uppercase()),
        );
        if !cleaned.is_ascii() {
            return Err(CryptoError::SecretKey("unexpected character"));
        }
        if cleaned.len() < PREFIX.len() || !cleaned.starts_with('K') {
            return Err(CryptoError::SecretKey("missing K1 prefix"));
        }
        if !cleaned.starts_with(PREFIX) {
            return Err(CryptoError::SecretKey("unsupported Secret Key version"));
        }
        let mut body = Zeroizing::new(String::with_capacity(cleaned.len()));
        body.extend(cleaned[PREFIX.len()..].chars().map(|c| match c {
            '0' => 'O',
            '1' => 'I',
            '8' => 'B',
            other => other,
        }));
        drop(cleaned);
        let raw = Zeroizing::new(
            BASE32_NOPAD
                .decode(body.as_bytes())
                .map_err(|_| CryptoError::SecretKey("invalid characters or length"))?,
        );
        if raw.len() != SECRET_KEY_LEN + CHECKSUM_LEN {
            return Err(CryptoError::SecretKey("invalid length"));
        }
        // Straight into the heap: no copy of the key left on the stack.
        let mut key = Box::new([0u8; SECRET_KEY_LEN]);
        key.copy_from_slice(&raw[..SECRET_KEY_LEN]);
        let key = Self(SecretBox::new(key));
        let expected = Self::checksum(key.bytes());
        if !bool::from(expected.ct_eq(&raw[SECRET_KEY_LEN..])) {
            return Err(CryptoError::SecretKey("checksum mismatch (typo?)"));
        }
        Ok(key)
    }
}

/// Data printed in the emergency kit (the PDF itself is rendered by clients).
pub struct EmergencyKit {
    /// Account e-mail.
    pub email: String,
    /// Account ID.
    pub account_id: AccountId,
    /// Server URL where the account lives.
    pub server_url: String,
    secret_key: SecretKey,
}

impl EmergencyKit {
    /// Assembles the kit for a freshly created account.
    pub fn new(
        email: String,
        account_id: AccountId,
        server_url: String,
        secret_key: SecretKey,
    ) -> Self {
        Self {
            email,
            account_id,
            server_url,
            secret_key,
        }
    }

    /// The Secret Key printed in the kit.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static_assertions::assert_not_impl_any!(SecretKey: std::fmt::Debug, std::fmt::Display, Clone);
    static_assertions::assert_not_impl_any!(EmergencyKit: std::fmt::Debug, std::fmt::Display);

    #[test]
    fn text_shape() {
        let text = SecretKey::generate().to_text();
        let text = text.expose_secret();
        assert_eq!(text.len(), 2 + 8 * 5);
        assert!(text.starts_with("K1-"));
        assert_eq!(text.split('-').count(), 9);
    }

    #[test]
    fn roundtrip_and_lenient_parsing() {
        let key = SecretKey::from_bytes([0xA5; 16]);
        let text = key.to_text();
        let text = text.expose_secret();
        let parsed = SecretKey::parse(text).unwrap();
        assert_eq!(parsed.bytes(), key.bytes());
        let messy = format!(" {} ", text.to_lowercase().replace('-', " "));
        assert_eq!(SecretKey::parse(&messy).unwrap().bytes(), key.bytes());
    }

    #[test]
    fn confusable_digits_are_mapped() {
        // Find a key whose text contains an O, I or B and type the digit instead.
        for i in 0u8..=255 {
            let key = SecretKey::from_bytes([i; 16]);
            let text = key.to_text().expose_secret().to_string();
            let body = &text[2..];
            if body.contains('O') || body.contains('I') || body.contains('B') {
                let typed = format!(
                    "K1{}",
                    body.replace('O', "0").replace('I', "1").replace('B', "8")
                );
                assert_eq!(SecretKey::parse(&typed).unwrap().bytes(), key.bytes());
                return;
            }
        }
        panic!("no key with confusable characters found");
    }

    #[test]
    fn rejects_typos_and_wrong_versions() {
        let text = SecretKey::from_bytes([3; 16])
            .to_text()
            .expose_secret()
            .to_string();
        // Change one character of the body.
        let mut chars: Vec<char> = text.chars().collect();
        chars[5] = if chars[5] == 'A' { 'C' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert_eq!(
            SecretKey::parse(&typo).err(),
            Some(CryptoError::SecretKey("checksum mismatch (typo?)"))
        );
        assert!(SecretKey::parse(&text.replacen("K1", "K2", 1)).is_err());
        assert!(SecretKey::parse(&text.replacen("K1", "L1", 1)).is_err());
        assert!(SecretKey::parse(&text[3..]).is_err());
        assert!(SecretKey::parse(&text[..text.len() - 1]).is_err());
        assert!(SecretKey::parse("").is_err());
        assert!(SecretKey::parse("K1-ÄÄÄÄ").is_err());
    }
}
