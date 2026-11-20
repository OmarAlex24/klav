//! Hashes for the vault health report (ADR 0022 §4), computed on the
//! person's client: the server sees nothing, so it cannot do this.
//!
//! * [`ReuseHasher`]: finds a password used in two or more items by
//!   comparing `SHA-256(salt ‖ value)` in memory. The salt is random and
//!   lives only for one run; neither it nor the hashes are ever stored.
//! * [`breach`] (feature `breach-check`): the SHA-1 prefix and suffix that
//!   Have I Been Pwned's k-anonymity range API needs. SHA-1 serves only
//!   this lookup, never a security purpose of Klav.

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::crypto::random;

/// Salt length of a [`ReuseHasher`] (bytes).
pub const REUSE_SALT_LEN: usize = 32;

/// Compares passwords without keeping them: a fingerprint is
/// `SHA-256(salt ‖ value)` with a salt drawn for this run. Two
/// fingerprints from the same hasher are equal iff the values are.
///
/// No `Debug`: the salt and the fingerprints are as sensitive as a fast
/// hash of the passwords for as long as they live.
pub struct ReuseHasher {
    salt: [u8; REUSE_SALT_LEN],
}

impl Drop for ReuseHasher {
    fn drop(&mut self) {
        self.salt.zeroize();
    }
}

/// A [`ReuseHasher`] fingerprint. Compare with `==` and use as a map key;
/// wiped on drop.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint([u8; 32]);

impl Drop for Fingerprint {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ReuseHasher {
    /// A hasher with a fresh random salt.
    pub fn new() -> Self {
        Self {
            salt: random::array(),
        }
    }

    /// The fingerprint of `value`.
    pub fn fingerprint(&self, value: &[u8]) -> Fingerprint {
        let mut hash = Sha256::new();
        hash.update(self.salt);
        hash.update(value);
        Fingerprint(hash.finalize().into())
    }
}

impl Default for ReuseHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Have I Been Pwned's range API with k-anonymity (ADR 0022 §4, T101):
/// only the first [`PREFIX_LEN`] hexadecimal characters of the password's
/// SHA-1 leave the device; the suffix is compared locally with the list
/// the service returns for that prefix.
#[cfg(feature = "breach-check")]
pub mod breach {
    use sha1::{Digest, Sha1};
    use zeroize::Zeroizing;

    /// Hexadecimal characters of the SHA-1 that are sent.
    pub const PREFIX_LEN: usize = 5;

    /// One password's range query: the prefix to send and the suffix to
    /// look for. No `Debug`: the suffix stays on the device.
    pub struct RangeQuery {
        prefix: String,
        suffix: Zeroizing<String>,
    }

    impl RangeQuery {
        /// The query for `password` (its UTF-8 bytes).
        pub fn new(password: &[u8]) -> Self {
            let digest = Zeroizing::new(<[u8; 20]>::from(Sha1::digest(password)));
            let hex = Zeroizing::new(data_encoding::HEXUPPER.encode(digest.as_slice()));
            Self {
                prefix: hex[..PREFIX_LEN].to_owned(),
                suffix: Zeroizing::new(hex[PREFIX_LEN..].to_owned()),
            }
        }

        /// The 5 uppercase hexadecimal characters that go to the service
        /// (`/range/{prefix}`).
        pub fn prefix(&self) -> &str {
            &self.prefix
        }

        /// How many times the service saw this password, from its answer
        /// for [`Self::prefix`] (`SUFFIX:COUNT` lines). `None` if it is not
        /// listed. Lines with a count of 0 are the padding that
        /// `Add-Padding: true` adds, and never match.
        pub fn count_in(&self, body: &str) -> Option<u64> {
            body.lines().find_map(|line| {
                let (suffix, count) = line.trim().split_once(':')?;
                if !suffix.trim().eq_ignore_ascii_case(&self.suffix) {
                    return None;
                }
                count.trim().parse::<u64>().ok().filter(|n| *n > 0)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_match_only_equal_values() {
        let h = ReuseHasher::new();
        assert!(h.fingerprint(b"hunter2") == h.fingerprint(b"hunter2"));
        assert!(h.fingerprint(b"hunter2") != h.fingerprint(b"hunter3"));
    }

    #[test]
    fn each_run_has_its_own_salt() {
        let a = ReuseHasher::new();
        let b = ReuseHasher::new();
        assert!(a.fingerprint(b"hunter2") != b.fingerprint(b"hunter2"));
    }

    #[cfg(feature = "breach-check")]
    #[test]
    fn range_query_sends_five_characters_and_finds_the_suffix() {
        use super::breach::RangeQuery;
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
        let q = RangeQuery::new(b"password");
        assert_eq!(q.prefix(), "5BAA6");
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                    1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n\
                    FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n";
        assert_eq!(q.count_in(body), Some(3_861_493));
        assert_eq!(q.count_in(&body.to_lowercase()), Some(3_861_493));
        assert_eq!(RangeQuery::new(b"not listed").count_in(body), None);
    }

    #[cfg(feature = "breach-check")]
    #[test]
    fn padding_lines_never_match() {
        use super::breach::RangeQuery;
        let q = RangeQuery::new(b"password");
        assert_eq!(
            q.count_in("1E4C9B93F3F0682250B6CF8331B7EE68FD8:0\r\n"),
            None
        );
        assert_eq!(q.count_in("garbage\r\n:\r\n"), None);
    }
}
