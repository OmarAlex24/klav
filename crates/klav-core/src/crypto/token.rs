//! Bearer tokens issued by the server after an OPAQUE login (spec §4.6).
//!
//! A token is 32 random bytes, encoded as base64url without padding after a
//! short readable prefix (so secret scanners can recognise it). The server
//! only stores `SHA-256(tuple("klav/v1/server/token", token))`, so a copy of
//! the database does not contain usable tokens.

use data_encoding::BASE64URL_NOPAD;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

use super::encoding::Tuple;
use super::random;

/// Label of the token digest.
pub const LABEL_TOKEN: &str = "klav/v1/server/token";
/// Random bytes per token.
pub const TOKEN_BYTES: usize = 32;
/// Length of a digest.
pub const DIGEST_LEN: usize = 32;

/// Generates a fresh token `prefix ‖ base64url(32 random bytes)`.
pub fn generate_token(prefix: &str) -> SecretString {
    let bytes = zeroize::Zeroizing::new(random::array::<TOKEN_BYTES>());
    // Written once into a buffer of the right size: no intermediate copy
    // of the token is left behind.
    let mut token = String::with_capacity(prefix.len() + BASE64URL_NOPAD.encode_len(TOKEN_BYTES));
    token.push_str(prefix);
    BASE64URL_NOPAD.encode_append(bytes.as_ref(), &mut token);
    SecretString::from(token)
}

/// The value the server stores and looks tokens up by.
pub fn token_digest(token: &SecretString) -> [u8; DIGEST_LEN] {
    digest_str(token.expose_secret())
}

/// [`token_digest`] for a token received as plain text (e.g. from a header).
pub fn digest_str(token: &str) -> [u8; DIGEST_LEN] {
    let mut t = Tuple::new(LABEL_TOKEN);
    t.push(token.as_bytes());
    let bytes = zeroize::Zeroizing::new(t.into_bytes());
    Sha256::digest(bytes.as_slice()).into()
}

/// Whether `given` (from a header) is `expected`, in constant time: both
/// are first reduced to their [`digest_str`], so neither the length nor the
/// first differing byte of `expected` shows in the timing. For a shared
/// bearer secret held in the configuration (the auto-invite token, ADR
/// 0050 §2.2), which the server never stores as a digest.
pub fn same_token(given: &str, expected: &SecretString) -> bool {
    use subtle::ConstantTimeEq as _;
    let a = digest_str(given);
    let b = token_digest(expected);
    bool::from(a.ct_eq(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_token_matches_only_the_exact_token() {
        let expected = SecretString::from("an-internal-token-of-at-least-32-bytes");
        assert!(same_token(
            "an-internal-token-of-at-least-32-bytes",
            &expected
        ));
        assert!(!same_token(
            "an-internal-token-of-at-least-32-byteS",
            &expected
        ));
        assert!(!same_token(
            "an-internal-token-of-at-least-32-bytes ",
            &expected
        ));
        assert!(!same_token("", &expected));
    }

    #[test]
    fn tokens_are_prefixed_unique_and_digest_stably() {
        let a = generate_token("kat_");
        let b = generate_token("kat_");
        assert!(a.expose_secret().starts_with("kat_"));
        assert_eq!(a.expose_secret().len(), 4 + 43);
        assert_ne!(a.expose_secret(), b.expose_secret());
        assert_eq!(token_digest(&a), digest_str(a.expose_secret()));
        assert_ne!(token_digest(&a), token_digest(&b));
    }
}
