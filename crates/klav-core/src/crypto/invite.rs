//! Registration invite codes (ADR 0048 §1.3, spec §4.7).
//!
//! A code is 16 random bytes (128 bits), written in Crockford base32 (26
//! characters) after a `KLAV-` prefix, in groups that can be read aloud:
//! `KLAV-XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX`.
//!
//! **Canonical form.** Dashes and spaces are removed and the rest is
//! uppercased. A 30-character result must start with `KLAV` (the prefix is
//! removed by length, not by pattern: `K`, `A` and `V` are Crockford
//! symbols too, and `L` reads as `1`), and a 26-character result is taken
//! as the bare code. Then `I` and `L` read as `1` and `O` as `0`, and the 26
//! symbols decode to the 16 bytes. 26 symbols carry 130 bits, so the last
//! 2 bits must be zero: otherwise two spellings would decode to the same
//! bytes. Anything else is invalid, before any database is touched.
//!
//! **Digest.** The server stores and looks codes up only by
//! `SHA-256(tuple("klav/v1/server/invite", canonical bytes))`, like session
//! tokens (§4.6), so a copy of the database holds no usable code.
//!
//! The code is a secret until used: [`InviteCode`] wraps a
//! [`SecretString`], its `Debug` is redacted and it has no `Display`.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::encoding::Tuple;
use super::random;

/// Label of the invite digest.
pub const LABEL_INVITE: &str = "klav/v1/server/invite";
/// Random bytes per code.
pub const INVITE_BYTES: usize = 16;
/// Length of a digest.
pub const DIGEST_LEN: usize = 32;
/// What every written code starts with.
pub const PREFIX: &str = "KLAV-";
/// Crockford base32 symbols per code.
pub const SYMBOLS: usize = 26;
/// Longest text accepted before canonicalization (a pasted code with
/// generous spacing); anything longer is invalid without being read.
pub const MAX_INPUT_LEN: usize = 128;

/// Crockford's base32 alphabet (no `I`, `L`, `O`, `U`).
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Symbols per group when written: 5, 5, 5, 5 and 6.
const GROUPS: [usize; 5] = [5, 5, 5, 5, 6];

/// An invite code that is not a valid code. Carries no detail: the caller
/// answers the same for every reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid invite code")]
pub struct InvalidInvite;

/// A registration invite code, as typed or pasted (not yet canonical).
///
/// Serializes as a JSON string. `Debug` never prints it.
#[derive(Clone)]
pub struct InviteCode(SecretString);

impl InviteCode {
    /// A fresh code from the CSPRNG, written in its canonical spelling.
    pub fn generate() -> Self {
        let bytes = Zeroizing::new(random::array::<INVITE_BYTES>());
        Self::from_bytes(&bytes)
    }

    /// The canonical spelling of `bytes`: `KLAV-` and 26 symbols in groups.
    pub fn from_bytes(bytes: &[u8; INVITE_BYTES]) -> Self {
        let symbols = Zeroizing::new(encode(bytes));
        let mut text = String::with_capacity(PREFIX.len() + SYMBOLS + GROUPS.len() - 1);
        text.push_str(PREFIX);
        let mut at = 0;
        for (i, len) in GROUPS.iter().enumerate() {
            if i > 0 {
                text.push('-');
            }
            for &s in &symbols[at..at + len] {
                text.push(char::from(s));
            }
            at += len;
        }
        Self(SecretString::from(text))
    }

    /// A code as received (from a request, a prompt or an argument).
    pub fn new(text: impl Into<String>) -> Self {
        Self(SecretString::from(text.into()))
    }

    /// The text as received.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    /// The 16 bytes the code stands for (see the module's doc).
    pub fn canonical(&self) -> Result<Zeroizing<[u8; INVITE_BYTES]>, InvalidInvite> {
        canonical(self.expose())
    }

    /// The value the server stores and looks invites up by.
    pub fn digest(&self) -> Result<[u8; DIGEST_LEN], InvalidInvite> {
        Ok(digest_bytes(&*self.canonical()?))
    }
}

impl fmt::Debug for InviteCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InviteCode([redacted])")
    }
}

impl From<String> for InviteCode {
    fn from(text: String) -> Self {
        Self::new(text)
    }
}

impl Serialize for InviteCode {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.expose())
    }
}

impl<'de> Deserialize<'de> for InviteCode {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Self::new)
    }
}

/// `SHA-256(tuple(LABEL_INVITE, bytes))`.
pub fn digest_bytes(bytes: &[u8; INVITE_BYTES]) -> [u8; DIGEST_LEN] {
    let mut t = Tuple::new(LABEL_INVITE);
    t.push(bytes);
    let tuple = Zeroizing::new(t.into_bytes());
    Sha256::digest(tuple.as_slice()).into()
}

fn canonical(text: &str) -> Result<Zeroizing<[u8; INVITE_BYTES]>, InvalidInvite> {
    if text.len() > MAX_INPUT_LEN {
        return Err(InvalidInvite);
    }
    let mut clean = Zeroizing::new(Vec::with_capacity(SYMBOLS + 4));
    for b in text.bytes() {
        match b {
            b'-' | b' ' => {}
            b if b.is_ascii_alphanumeric() => clean.push(b.to_ascii_uppercase()),
            _ => return Err(InvalidInvite),
        }
    }
    let symbols: &[u8] = match clean.len() {
        SYMBOLS => &clean,
        30 if clean.starts_with(b"KLAV") => &clean[4..],
        _ => return Err(InvalidInvite),
    };
    let mut digits = Zeroizing::new([0u8; SYMBOLS]);
    for (d, &s) in digits.iter_mut().zip(symbols) {
        *d = value(s).ok_or(InvalidInvite)?;
    }
    decode(&digits).ok_or(InvalidInvite)
}

/// The value of one uppercase symbol, with Crockford's aliases.
fn value(symbol: u8) -> Option<u8> {
    let symbol = match symbol {
        b'I' | b'L' => b'1',
        b'O' => b'0',
        s => s,
    };
    ALPHABET
        .iter()
        .position(|&a| a == symbol)
        .and_then(|p| u8::try_from(p).ok())
}

/// 16 bytes to 26 symbols: the 128 bits, then two zero bits.
fn encode(bytes: &[u8; INVITE_BYTES]) -> [u8; SYMBOLS] {
    let value = Zeroizing::new(u128::from_be_bytes(*bytes));
    let mut out = [0u8; SYMBOLS];
    for (i, o) in out.iter_mut().enumerate().take(SYMBOLS - 1) {
        let shift = 128 - 5 * (i + 1);
        *o = ALPHABET[usize::try_from((*value >> shift) & 31).unwrap_or(0)];
    }
    out[SYMBOLS - 1] = ALPHABET[usize::try_from((*value & 0b111) << 2).unwrap_or(0)];
    out
}

/// 26 symbol values to 16 bytes, or `None` if the last 2 bits are not zero.
fn decode(digits: &[u8; SYMBOLS]) -> Option<Zeroizing<[u8; INVITE_BYTES]>> {
    let last = digits[SYMBOLS - 1];
    if last & 0b11 != 0 {
        return None;
    }
    let mut value = Zeroizing::new(0u128);
    for &d in &digits[..SYMBOLS - 1] {
        *value = (*value << 5) | u128::from(d);
    }
    *value = (*value << 3) | u128::from(last >> 2);
    Some(Zeroizing::new(value.to_be_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_codes_independently_computed() {
        // All zero bits: every symbol is `0`.
        let zeros = InviteCode::from_bytes(&[0; 16]);
        assert_eq!(zeros.expose(), "KLAV-00000-00000-00000-00000-000000");
        // All one bits: 25 × 11111 (`Z`), then 111 and the two zero bits,
        // 11100 = 28 = `W`.
        let ones = InviteCode::from_bytes(&[0xFF; 16]);
        assert_eq!(ones.expose(), "KLAV-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZW");
        assert_eq!(*ones.canonical().unwrap(), [0xFF; 16]);
        // The digest by hand: lp(label) ‖ lp(bytes), lengths as u32 BE.
        let mut manual = Vec::new();
        manual.extend_from_slice(&u32::try_from(LABEL_INVITE.len()).unwrap().to_be_bytes());
        manual.extend_from_slice(LABEL_INVITE.as_bytes());
        manual.extend_from_slice(&16u32.to_be_bytes());
        manual.extend_from_slice(&[0xFF; 16]);
        let expected: [u8; 32] = Sha256::digest(&manual).into();
        assert_eq!(ones.digest().unwrap(), expected);
    }

    #[test]
    fn generated_codes_round_trip_and_differ() {
        let a = InviteCode::generate();
        let b = InviteCode::generate();
        assert_eq!(a.expose().len(), PREFIX.len() + SYMBOLS + 4);
        assert!(a.expose().starts_with(PREFIX));
        assert_ne!(a.expose(), b.expose());
        let bytes = a.canonical().unwrap();
        assert_eq!(InviteCode::from_bytes(&bytes).expose(), a.expose());
        assert_ne!(a.digest().unwrap(), b.digest().unwrap());
    }

    #[test]
    fn spellings_canonicalize_to_the_same_bytes() {
        let code = InviteCode::from_bytes(&[0x5A; 16]);
        let bare: String = code.expose()[PREFIX.len()..].replace('-', "");
        let digest = code.digest().unwrap();
        for spelling in [
            code.expose().to_lowercase(),
            bare.clone(),
            bare.to_lowercase(),
            format!("klav {bare}"),
            format!("  {}  ", code.expose()),
            code.expose().replace('-', " "),
        ] {
            assert_eq!(
                InviteCode::new(spelling.clone()).digest(),
                Ok(digest),
                "{spelling}"
            );
        }
        // I and L read as 1, O as 0.
        let one = InviteCode::from_bytes(&[0; 16]).expose().replace('0', "O");
        assert_eq!(
            InviteCode::new(one).digest(),
            InviteCode::from_bytes(&[0; 16]).digest()
        );
    }

    #[test]
    fn rejects_what_is_not_a_code() {
        let ones = "KLAV-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZW";
        for bad in [
            "",
            "KLAV-",
            // Non-zero trailing bits: X = 29 = 11101.
            "KLAV-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZX",
            "KLAV-00000-00000-00000-00000-000001",
            // One symbol short, one too many.
            "KLAV-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZW",
            "KLAV-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZWW",
            // U is not a symbol; neither is punctuation or non-ASCII.
            "KLAV-UZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZW",
            "KLAV-ZZZZZ_ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZW",
            "KLAV-ÑZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZW",
            // 30 symbols without the prefix.
            "XLAVZZZZZZZZZZZZZZZZZZZZZZZZZW",
        ] {
            assert_eq!(InviteCode::new(bad).digest(), Err(InvalidInvite), "{bad}");
        }
        assert!(InviteCode::new(ones).digest().is_ok());
        assert!(InviteCode::new("x".repeat(MAX_INPUT_LEN + 1)).digest().is_err());
    }

    #[test]
    fn debug_never_shows_the_code() {
        let code = InviteCode::from_bytes(&[0x5A; 16]);
        assert_eq!(format!("{code:?}"), "InviteCode([redacted])");
        assert!(!format!("{:?}", Some(&code)).contains("KLAV"));
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, format!("\"{}\"", code.expose()));
        let back: InviteCode = serde_json::from_str(&json).unwrap();
        assert_eq!(back.digest(), code.digest());
    }
}
