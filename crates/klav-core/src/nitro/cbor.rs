//! A strict CBOR reader (RFC 8949) for the AWS Nitro attestation document
//! (spec §15.2, ADR 0051 §2.2 step 2).
//!
//! It accepts only what a Nitro Secure Module emits and refuses everything
//! that would let two readers disagree about the same bytes:
//!
//! * indefinite lengths (and the `break` byte);
//! * a length or an integer not in its shortest form;
//! * duplicate map keys, and map keys that are not integers or text;
//! * floats, `undefined` and simple values other than `false`, `true` and
//!   `null`;
//! * text that is not UTF-8;
//! * nesting deeper than [`MAX_DEPTH`];
//! * bytes left over after the top-level item.
//!
//! Map order is not checked: the NSM writes its map in a fixed order that is
//! not the canonical one. `ciborium` is not used because its `Value` accepts
//! indefinite lengths and long-form lengths silently and keeps no trace of
//! them, so it could not refuse them (the test
//! `ciborium_accepts_what_this_reader_refuses` shows it). This is an
//! encoding, not cryptography.

use super::error::CborError;

/// Deepest nesting accepted. The attestation document needs 4 (the COSE
/// array, the payload map, `pcrs` or `cabundle`, and one value).
pub(crate) const MAX_DEPTH: usize = 8;

/// One decoded CBOR data item, borrowing from the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value<'a> {
    /// Major type 0.
    Uint(u64),
    /// Major type 1: the value is `-1 - n`; this holds `n`.
    Nint(u64),
    /// Major type 2.
    Bytes(&'a [u8]),
    /// Major type 3.
    Text(&'a str),
    /// Major type 4.
    Array(Vec<Value<'a>>),
    /// Major type 5, in the order of the input.
    Map(Vec<(Value<'a>, Value<'a>)>),
    /// Major type 6.
    Tag(u64, Box<Value<'a>>),
    /// `false` or `true`.
    Bool(bool),
    /// `null`.
    Null,
}

/// Decodes exactly one item that fills `input`.
pub(crate) fn decode(input: &[u8]) -> Result<Value<'_>, CborError> {
    let mut reader = Reader { input, pos: 0 };
    let value = reader.item(0)?;
    if reader.pos != input.len() {
        return Err(CborError::TrailingBytes);
    }
    Ok(value)
}

struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, CborError> {
        let b = *self.input.get(self.pos).ok_or(CborError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, len: u64) -> Result<&'a [u8], CborError> {
        let len = usize::try_from(len).map_err(|_| CborError::Truncated)?;
        let end = self.pos.checked_add(len).ok_or(CborError::Truncated)?;
        let slice = self.input.get(self.pos..end).ok_or(CborError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn remaining(&self) -> u64 {
        (self.input.len() - self.pos) as u64
    }

    /// Reads the argument of a head whose additional information is `info`,
    /// refusing indefinite lengths and any form longer than the shortest.
    fn argument(&mut self, info: u8) -> Result<u64, CborError> {
        let (value, min) = match info {
            0..=23 => return Ok(u64::from(info)),
            24 => (u64::from(self.byte()?), 24),
            25 => (u64::from(u16::from_be_bytes(self.array()?)), 0x100),
            26 => (u64::from(u32::from_be_bytes(self.array()?)), 0x1_0000),
            27 => (u64::from_be_bytes(self.array()?), 0x1_0000_0000),
            31 => return Err(CborError::IndefiniteLength),
            _ => return Err(CborError::Reserved),
        };
        if value < min {
            return Err(CborError::NonCanonical);
        }
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CborError> {
        let bytes = self.take(N as u64)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn item(&mut self, depth: usize) -> Result<Value<'a>, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError::TooDeep);
        }
        let head = self.byte()?;
        let major = head >> 5;
        let info = head & 0x1f;
        if major == 7 {
            return match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                31 => Err(CborError::IndefiniteLength),
                _ => Err(CborError::Unsupported),
            };
        }
        let arg = self.argument(info)?;
        match major {
            0 => Ok(Value::Uint(arg)),
            1 => Ok(Value::Nint(arg)),
            2 => Ok(Value::Bytes(self.take(arg)?)),
            3 => {
                let bytes = self.take(arg)?;
                std::str::from_utf8(bytes)
                    .map(Value::Text)
                    .map_err(|_| CborError::InvalidUtf8)
            }
            4 => {
                // Every item takes at least one byte: a longer count is a lie.
                if arg > self.remaining() {
                    return Err(CborError::Truncated);
                }
                let mut items = Vec::new();
                for _ in 0..arg {
                    items.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                if arg.saturating_mul(2) > self.remaining() {
                    return Err(CborError::Truncated);
                }
                let mut entries: Vec<(Value<'a>, Value<'a>)> = Vec::new();
                let mut keys: Vec<&'a [u8]> = Vec::new();
                for _ in 0..arg {
                    let start = self.pos;
                    let key = self.item(depth + 1)?;
                    if !matches!(key, Value::Uint(_) | Value::Nint(_) | Value::Text(_)) {
                        return Err(CborError::MapKeyType);
                    }
                    // Every length is in its shortest form, so two equal keys
                    // have the same bytes.
                    let raw = &self.input[start..self.pos];
                    if keys.contains(&raw) {
                        return Err(CborError::DuplicateKey);
                    }
                    keys.push(raw);
                    let value = self.item(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(Value::Map(entries))
            }
            6 => Ok(Value::Tag(arg, Box::new(self.item(depth + 1)?))),
            _ => Err(CborError::Reserved),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_shapes_the_nsm_writes() {
        // {"a": h'01', 1: [-35, null, true]}
        let bytes = [
            0xa2, 0x61, b'a', 0x41, 0x01, 0x01, 0x83, 0x38, 0x22, 0xf6, 0xf5,
        ];
        assert_eq!(
            decode(&bytes),
            Ok(Value::Map(vec![
                (Value::Text("a"), Value::Bytes(&[1])),
                (
                    Value::Uint(1),
                    Value::Array(vec![Value::Nint(34), Value::Null, Value::Bool(true)])
                ),
            ]))
        );
    }

    #[test]
    fn refuses_what_two_readers_could_read_differently() {
        let cases: &[(&[u8], CborError)] = &[
            // Indefinite map, array, byte string and a lone break.
            (&[0xbf, 0x61, b'a', 0x01, 0xff], CborError::IndefiniteLength),
            (&[0x9f, 0x01, 0xff], CborError::IndefiniteLength),
            (&[0x5f, 0x41, 0x00, 0xff], CborError::IndefiniteLength),
            (&[0xff], CborError::IndefiniteLength),
            // 1 written in two bytes; a 1-byte string with a 2-byte length.
            (&[0x18, 0x01], CborError::NonCanonical),
            (&[0x59, 0x00, 0x01, 0x00], CborError::NonCanonical),
            (
                &[0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
                CborError::NonCanonical,
            ),
            // {"a": 1, "a": 2}
            (
                &[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02],
                CborError::DuplicateKey,
            ),
            // {h'00': 1}
            (&[0xa1, 0x41, 0x00, 0x01], CborError::MapKeyType),
            // A half float, undefined, a simple value.
            (&[0xf9, 0x3c, 0x00], CborError::Unsupported),
            (&[0xf7], CborError::Unsupported),
            (&[0xf0], CborError::Unsupported),
            (&[0x1c], CborError::Reserved),
            (&[0x62, 0xff, 0xfe], CborError::InvalidUtf8),
            (&[0x01, 0x00], CborError::TrailingBytes),
            (&[0x42, 0x00], CborError::Truncated),
            (
                &[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                CborError::Truncated,
            ),
            (&[0xbb, 0, 0, 0, 1, 0, 0, 0, 0], CborError::Truncated),
            (&[], CborError::Truncated),
        ];
        for (bytes, expected) in cases {
            assert_eq!(decode(bytes), Err(*expected), "{bytes:02x?}");
        }
    }

    #[test]
    fn refuses_deep_nesting() {
        let mut bytes = vec![0x81; MAX_DEPTH + 1];
        bytes.push(0x00);
        assert_eq!(decode(&bytes), Err(CborError::TooDeep));
        assert!(decode(&bytes[1..]).is_ok());
    }

    /// The reason for this reader (ADR 0051 §13): `ciborium` decodes an
    /// indefinite-length map and a long-form integer without complaint, and
    /// its `Value` keeps nothing that would let a caller refuse them.
    #[test]
    fn ciborium_accepts_what_this_reader_refuses() {
        let indefinite = [0xbf, 0x61, b'a', 0x01, 0xff];
        let long_form = [0x18, 0x01];
        let lax = |b: &[u8]| ciborium::de::from_reader::<ciborium::Value, _>(b).is_ok();
        assert!(lax(&indefinite));
        assert!(lax(&long_form));
        assert_eq!(decode(&indefinite), Err(CborError::IndefiniteLength));
        assert_eq!(decode(&long_form), Err(CborError::NonCanonical));
    }
}
