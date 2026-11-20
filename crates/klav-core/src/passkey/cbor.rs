//! Minimal CBOR encoder (RFC 8949) for the few structures an authenticator
//! emits: the COSE public key and the attestation object (spec §14.5).
//!
//! It only writes unsigned and negative integers, byte strings, text
//! strings and maps of definite length, always with the shortest length
//! form. Map entries are sorted when the map is built, by the bytes of
//! their encoded keys, shorter first and then lexicographically: the CTAP2
//! canonical order (and RFC 7049 §3.9). The order comes from construction,
//! so a caller cannot get it wrong. This is an encoding, not cryptography.

/// One encoded CBOR data item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Value(Vec<u8>);

impl Value {
    pub(crate) fn int(value: i64) -> Self {
        if value >= 0 {
            Self(head(0, value.unsigned_abs()))
        } else {
            // -1 - n is encoded as major type 1 with argument n.
            Self(head(1, (-1 - value).unsigned_abs()))
        }
    }

    pub(crate) fn bytes(value: &[u8]) -> Self {
        let mut out = head(2, value.len() as u64);
        out.extend_from_slice(value);
        Self(out)
    }

    pub(crate) fn text(value: &str) -> Self {
        let mut out = head(3, value.len() as u64);
        out.extend_from_slice(value.as_bytes());
        Self(out)
    }

    /// A map of definite length, in canonical order whatever the order of
    /// `entries`.
    ///
    /// # Panics
    ///
    /// Panics if two entries have the same key: CBOR maps used by WebAuthn
    /// never repeat keys, so that is a programming error.
    pub(crate) fn map(mut entries: Vec<(Value, Value)>) -> Self {
        entries.sort_by(|(a, _), (b, _)| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
        assert!(
            entries.windows(2).all(|w| w[0].0 != w[1].0),
            "duplicate CBOR map key"
        );
        let mut out = head(5, entries.len() as u64);
        for (key, value) in entries {
            out.extend_from_slice(&key.0);
            out.extend_from_slice(&value.0);
        }
        Self(out)
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Initial byte and argument, in the shortest form.
fn head(major: u8, argument: u64) -> Vec<u8> {
    let major = major << 5;
    match argument {
        0..=23 => vec![major | argument as u8],
        24..=0xff => vec![major | 24, argument as u8],
        0x100..=0xffff => {
            let mut out = vec![major | 25];
            out.extend_from_slice(&(argument as u16).to_be_bytes());
            out
        }
        0x1_0000..=0xffff_ffff => {
            let mut out = vec![major | 26];
            out.extend_from_slice(&(argument as u32).to_be_bytes());
            out
        }
        _ => {
            let mut out = vec![major | 27];
            out.extend_from_slice(&argument.to_be_bytes());
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(v: Value) -> String {
        hex::encode(v.into_bytes())
    }

    #[test]
    fn rfc8949_appendix_a_examples() {
        // Integers.
        for (value, expected) in [
            (0, "00"),
            (1, "01"),
            (10, "0a"),
            (23, "17"),
            (24, "1818"),
            (25, "1819"),
            (100, "1864"),
            (1000, "1903e8"),
            (1_000_000, "1a000f4240"),
            (1_000_000_000_000, "1b000000e8d4a51000"),
            (-1, "20"),
            (-10, "29"),
            (-100, "3863"),
            (-1000, "3903e7"),
        ] {
            assert_eq!(hex(Value::int(value)), expected, "{value}");
        }
        assert_eq!(hex(Value::int(i64::MIN)), "3b7fffffffffffffff");
        // Strings.
        assert_eq!(hex(Value::bytes(&[])), "40");
        assert_eq!(hex(Value::bytes(&[1, 2, 3, 4])), "4401020304");
        assert_eq!(hex(Value::text("")), "60");
        assert_eq!(hex(Value::text("a")), "6161");
        assert_eq!(hex(Value::text("IETF")), "6449455446");
        assert_eq!(hex(Value::text("\u{00fc}")), "62c3bc");
        assert_eq!(hex(Value::bytes(&[0; 24]))[..4], *"5818");
        assert_eq!(hex(Value::bytes(&[0; 256]))[..6], *"590100");
        // Maps.
        assert_eq!(hex(Value::map(vec![])), "a0");
        assert_eq!(
            hex(Value::map(vec![
                (Value::int(3), Value::int(4)),
                (Value::int(1), Value::int(2)),
            ])),
            "a201020304"
        );
    }

    #[test]
    fn maps_sort_by_encoded_key_length_then_bytes() {
        // CTAP2: integers before longer keys, negative after positive.
        let map = Value::map(vec![
            (Value::int(-3), Value::int(0)),
            (Value::int(3), Value::int(0)),
            (Value::int(-1), Value::int(0)),
            (Value::int(1), Value::int(0)),
            (Value::int(-2), Value::int(0)),
        ]);
        assert_eq!(hex(map), "a5010003002000210022 00".replace(' ', ""));
        // Text keys: shorter first, then by bytes.
        let map = Value::map(vec![
            (Value::text("authData"), Value::int(0)),
            (Value::text("fmt"), Value::int(0)),
            (Value::text("attStmt"), Value::int(0)),
        ]);
        let bytes = map.into_bytes();
        let fmt = bytes.windows(3).position(|w| w == b"fmt").unwrap();
        let att = bytes.windows(7).position(|w| w == b"attStmt").unwrap();
        let auth = bytes.windows(8).position(|w| w == b"authData").unwrap();
        assert!(fmt < att && att < auth);
    }

    #[test]
    #[should_panic(expected = "duplicate CBOR map key")]
    fn duplicate_keys_panic() {
        Value::map(vec![
            (Value::int(1), Value::int(0)),
            (Value::int(1), Value::int(1)),
        ]);
    }
}
