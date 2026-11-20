//! Opaque binary payloads, encoded as base64url without padding in JSON.

use std::fmt;

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// An opaque binary payload (usually ciphertext produced by `klav-core`).
///
/// In JSON it is a base64url string without padding (RFC 4648 §5). `Debug`
/// prints only the length, so a blob never ends up in logs by accident.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Blob(Vec<u8>);

impl Blob {
    /// Wraps raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the blob and returns the raw bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `true` if the blob holds no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The base64url text form (no padding), as in JSON and in headers.
    pub fn to_text(&self) -> String {
        BASE64URL_NOPAD.encode(&self.0)
    }

    /// Parses [`Blob::to_text`].
    pub fn from_text(text: &str) -> Option<Self> {
        BASE64URL_NOPAD.decode(text.as_bytes()).ok().map(Self)
    }
}

impl From<Vec<u8>> for Blob {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<&[u8]> for Blob {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl AsRef<[u8]> for Blob {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Blob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blob({} bytes)", self.0.len())
    }
}

impl Serialize for Blob {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64URL_NOPAD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Blob {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        BASE64URL_NOPAD
            .decode(text.as_bytes())
            .map(Self)
            .map_err(|_| serde::de::Error::custom("invalid base64url (no padding) blob"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip_uses_base64url_without_padding() {
        let blob = Blob::new(vec![0xfb, 0xff, 0x00, 0x01]);
        let json = serde_json::to_string(&blob).unwrap();
        assert_eq!(json, "\"-_8AAQ\"");
        assert_eq!(serde_json::from_str::<Blob>(&json).unwrap(), blob);
    }

    #[test]
    fn rejects_padding_and_standard_alphabet() {
        assert!(serde_json::from_str::<Blob>("\"-_8AAQ==\"").is_err());
        assert!(serde_json::from_str::<Blob>("\"+/8AAQ\"").is_err());
    }

    #[test]
    fn debug_hides_the_content() {
        let blob = Blob::new(b"secret-looking bytes".to_vec());
        assert_eq!(format!("{blob:?}"), "Blob(20 bytes)");
    }
}
