//! A minimal protobuf reader: walks the fields of one message (ADR 0024).
//! Enough for Google Authenticator's `MigrationPayload`; no schema, no
//! code generation, no `prost`.

/// A field's value. Not `Debug`: `Bytes` is the TOTP secret of an account.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Value<'a> {
    /// Wire type 0.
    Varint(u64),
    /// Wire type 2: bytes, a string or an embedded message.
    Bytes(&'a [u8]),
    /// Wire types 1 and 5, unused by the payload.
    Fixed,
}

/// The message is not well formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Malformed;

/// Reads a varint at `at`, moving it past.
fn varint(buf: &[u8], at: &mut usize) -> Option<u64> {
    let mut out = 0u64;
    for shift in (0..64).step_by(7) {
        let b = *buf.get(*at)?;
        *at += 1;
        out |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some(out);
        }
    }
    None
}

/// The `(field number, value)` pairs of a message, in order, read as they
/// are asked for: nothing is collected, so a payload of millions of tiny
/// fields costs no memory. Yields one `Err` and stops at the first damaged
/// field.
pub(crate) fn fields(buf: &[u8]) -> Fields<'_> {
    Fields {
        buf,
        at: 0,
        done: false,
    }
}

/// The iterator of [`fields`].
pub(crate) struct Fields<'a> {
    buf: &'a [u8],
    at: usize,
    done: bool,
}

impl<'a> Fields<'a> {
    fn next_field(&mut self) -> Option<(u32, Value<'a>)> {
        let buf = self.buf;
        let key = varint(buf, &mut self.at)?;
        let number = u32::try_from(key >> 3).ok().filter(|n| *n > 0)?;
        let value = match key & 7 {
            0 => Value::Varint(varint(buf, &mut self.at)?),
            1 => {
                self.at = self.at.checked_add(8).filter(|e| *e <= buf.len())?;
                Value::Fixed
            }
            2 => {
                let len = usize::try_from(varint(buf, &mut self.at)?).ok()?;
                let end = self.at.checked_add(len).filter(|e| *e <= buf.len())?;
                let bytes = &buf[self.at..end];
                self.at = end;
                Value::Bytes(bytes)
            }
            5 => {
                self.at = self.at.checked_add(4).filter(|e| *e <= buf.len())?;
                Value::Fixed
            }
            _ => return None,
        };
        Some((number, value))
    }
}

impl<'a> Iterator for Fields<'a> {
    type Item = Result<(u32, Value<'a>), Malformed>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.at >= self.buf.len() {
            return None;
        }
        let field = self.next_field();
        if field.is_none() {
            self.done = true;
        }
        Some(field.ok_or(Malformed))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Encodes a varint.
    pub(crate) fn put_varint(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    /// Encodes a length-delimited field.
    pub(crate) fn put_bytes(out: &mut Vec<u8>, number: u32, bytes: &[u8]) {
        put_varint(out, u64::from(number) << 3 | 2);
        put_varint(out, bytes.len() as u64);
        out.extend_from_slice(bytes);
    }

    /// Encodes a varint field.
    pub(crate) fn put_int(out: &mut Vec<u8>, number: u32, v: u64) {
        put_varint(out, u64::from(number) << 3);
        put_varint(out, v);
    }

    #[test]
    fn round_trip_and_garbage() {
        let mut msg = Vec::new();
        put_bytes(&mut msg, 1, b"abc");
        put_int(&mut msg, 2, 300);
        put_int(&mut msg, 5, u64::MAX);
        msg.extend_from_slice(&[0x0d, 1, 2, 3, 4]); // field 1, fixed32
        let f: Vec<_> = fields(&msg).collect::<Result<_, _>>().unwrap();
        assert!(f[0] == (1, Value::Bytes(b"abc")));
        assert!(f[1] == (2, Value::Varint(300)));
        assert!(f[2] == (5, Value::Varint(u64::MAX)));
        assert!(f[3] == (1, Value::Fixed));
        let damaged = |b: &[u8]| fields(b).any(|f| f.is_err());
        assert!(damaged(&[0x0a, 5, 1])); // truncated bytes
        assert!(damaged(&[0x08])); // missing varint
        assert!(damaged(&[0x0b])); // wire type 3
        assert!(damaged(&[0x00, 0x00])); // field 0
        assert_eq!(fields(&[]).count(), 0);
    }

    #[test]
    fn stops_after_the_first_damaged_field() {
        let mut msg = Vec::new();
        put_int(&mut msg, 1, 7);
        msg.push(0x0b); // wire type 3
        put_int(&mut msg, 2, 8);
        let f: Vec<_> = fields(&msg).collect();
        assert_eq!(f.len(), 2);
        assert!(f[0] == Ok((1, Value::Varint(7))));
        assert!(f[1].is_err());
    }
}
