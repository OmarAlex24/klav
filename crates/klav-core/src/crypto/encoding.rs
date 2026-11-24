//! Canonical encodings shared by every format (spec §2).
//!
//! * Integers are big-endian.
//! * `lp(x) = u32_be(len(x)) ‖ x`.
//! * `tuple(label, f1, …, fn) = lp(label) ‖ lp(f1) ‖ … ‖ lp(fn)`.
//! * Every blob starts with a two-byte header `version ‖ kind`.

use super::CryptoError;

/// Format version implemented by this build.
pub const FORMAT_V1: u8 = 0x01;

/// Kind byte (second header byte) of every binary format (spec §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum Kind {
    /// Identity private keys sealed under the KEK.
    IdentitySecrets = 0x01,
    /// Project key wrapped under its vault key.
    ProjectKeyWrap = 0x02,
    /// Item key wrapped under its project key.
    ItemKeyWrap = 0x03,
    /// Attachment key wrapped under its item key.
    AttachmentKeyWrap = 0x04,
    /// Public identity bundle (X25519 + Ed25519 public keys).
    PublicIdentity = 0x05,
    /// Argon2id parameters.
    KdfParams = 0x06,
    /// Agent private keys, unencrypted (stored by the agent in the
    /// keychain, a 0600 file or an environment variable). Never sent to the
    /// server.
    AgentSecret = 0x07,
    /// Item overview (metadata visible with the `list` permission).
    ItemOverview = 0x10,
    /// Item details (fields and notes).
    ItemDetails = 0x11,
    /// Vault metadata (name), sealed with the vault key.
    VaultMeta = 0x12,
    /// Project metadata (name), sealed with the project key.
    ProjectMeta = 0x13,
    /// Vault and project names for an agent, sealed with the project key
    /// (spec §13.4).
    GrantLabels = 0x14,
    /// Private key of a passkey, sealed with the vault key so no agent can
    /// open it (spec §14.3, ADR 0020 §4).
    PasskeyKey = 0x15,
    /// Previous passwords of an item (and a pending one), sealed with the
    /// vault key so no agent can read them (spec §7.3).
    PasswordRecord = 0x16,
    /// Vault key wrapped with HPKE for a member (person or agent).
    SharedVaultKey = 0x20,
    /// Project key wrapped with HPKE for a member (agent grant).
    SharedProjectKey = 0x21,
    // `0x22` belongs to the link payload of ADR 0029 (not implemented yet).
    /// Item key wrapped with HPKE for an agent: a per-item grant, such as
    /// the credential proxy's (spec §8.2, ADR 0036 §2 and E10).
    SharedItemKey = 0x23,
    // `0x24` belongs to the inject command blob of ADR 0041 (not implemented yet).
    /// Proposal body of an agent secret request, sealed with HPKE to the
    /// account identity so the server never sees titles, fields, URLs or
    /// proxy upstreams (spec §13.14, ADR 0046 §1).
    SecretRequestProposal = 0x25,
    /// Attachment encrypted with STREAM.
    Attachment = 0x30,
    /// Device-local copy of the identity private keys, sealed with the
    /// local key. Never sent to the server.
    LocalIdentity = 0x40,
    /// Device-local data (cache, session tokens), sealed with the local key.
    /// Never sent to the server.
    LocalData = 0x41,
    /// Local key sealed under a platform keystore secret (Secure Enclave),
    /// spec §12.3. Never sent to the server.
    KeystoreWrap = 0x42,
    /// Local outbox: what this device still has to upload (the generator
    /// history in `klavd`, ADR 0022 §2), sealed with the local key. Never
    /// sent to the server.
    LocalOutbox = 0x43,
}

impl Kind {
    /// The two-byte header for this kind in format v1.
    pub const fn header(self) -> [u8; 2] {
        [FORMAT_V1, self as u8]
    }
}

/// Checks the two-byte header at the start of `blob` and returns the rest.
pub(crate) fn strip_header(blob: &[u8], kind: Kind) -> Result<&[u8], CryptoError> {
    let (header, rest) = blob
        .split_first_chunk::<2>()
        .ok_or(CryptoError::Malformed("missing header"))?;
    if header[0] != FORMAT_V1 {
        return Err(CryptoError::UnsupportedVersion(header[0]));
    }
    if header[1] != kind as u8 {
        return Err(CryptoError::UnexpectedKind {
            expected: kind as u8,
            found: header[1],
        });
    }
    Ok(rest)
}

/// Builder for `tuple(label, fields…)`.
#[derive(Debug, Clone, Default)]
pub struct Tuple(Vec<u8>);

impl Tuple {
    /// Starts a tuple with its domain-separation `label`.
    pub fn new(label: &str) -> Self {
        let mut t = Tuple(Vec::with_capacity(128));
        t.push(label.as_bytes());
        t
    }

    /// Appends `lp(field)`.
    ///
    /// # Panics
    ///
    /// Panics if `field` is longer than `u32::MAX` bytes.
    pub fn push(&mut self, field: &[u8]) -> &mut Self {
        let len = u32::try_from(field.len()).expect("tuple field longer than u32::MAX");
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(field);
        self
    }

    /// Appends `lp(u64_be(value))`.
    pub fn push_u64(&mut self, value: u64) -> &mut Self {
        self.push(&value.to_be_bytes())
    }

    /// The encoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the builder and returns the encoded bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// `header ‖ tuple`: the associated data of every AEAD blob (spec §2.4).
pub(crate) fn aad(header: &[u8], tuple: &Tuple) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len() + tuple.as_bytes().len());
    out.extend_from_slice(header);
    out.extend_from_slice(tuple.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tuple_is_length_prefixed() {
        let mut t = Tuple::new("ab");
        t.push(b"").push(b"xyz").push_u64(1);
        assert_eq!(
            t.as_bytes(),
            [
                &[0, 0, 0, 2][..],
                b"ab",
                &[0, 0, 0, 0],
                &[0, 0, 0, 3],
                b"xyz",
                &[0, 0, 0, 8],
                &[0, 0, 0, 0, 0, 0, 0, 1],
            ]
            .concat()
        );
    }

    #[test]
    fn tuple_is_injective_where_concat_is_not() {
        let mut a = Tuple::new("l");
        a.push(b"ab").push(b"c");
        let mut b = Tuple::new("l");
        b.push(b"a").push(b"bc");
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn strip_header_checks_version_and_kind() {
        let blob = [FORMAT_V1, Kind::ItemDetails as u8, 9];
        assert_eq!(strip_header(&blob, Kind::ItemDetails), Ok(&[9u8][..]));
        assert_eq!(
            strip_header(&blob, Kind::ItemOverview),
            Err(CryptoError::UnexpectedKind {
                expected: 0x10,
                found: 0x11
            })
        );
        assert_eq!(
            strip_header(&[0x02, 0x11], Kind::ItemDetails),
            Err(CryptoError::UnsupportedVersion(2))
        );
        assert!(matches!(
            strip_header(&[0x01], Kind::ItemDetails),
            Err(CryptoError::Malformed(_))
        ));
    }
}
