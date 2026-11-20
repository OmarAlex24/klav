//! One-time passwords: TOTP (RFC 6238) on top of HOTP (RFC 4226), and
//! `otpauth://totp/…` URIs (Google Authenticator key URI format).
//!
//! SHA-1 is supported because RFC 6238 and nearly every service use it by
//! default (ADR 0005); it is used for nothing else.

use std::fmt::Write as _;

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use thiserror::Error;
use zeroize::Zeroizing;

/// Default period in seconds.
pub const DEFAULT_PERIOD: u64 = 30;
/// Default number of digits.
pub const DEFAULT_DIGITS: u32 = 6;
/// Accepted digits.
pub const DIGITS_RANGE: std::ops::RangeInclusive<u32> = 6..=8;
/// Accepted periods, in seconds.
pub const PERIOD_RANGE: std::ops::RangeInclusive<u64> = 1..=300;
/// Maximum secret length in bytes.
pub const MAX_SECRET_LEN: usize = 128;

/// TOTP errors. Messages never include the secret.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TotpError {
    /// Not a valid `otpauth://` URI.
    #[error("invalid otpauth URI: {0}")]
    InvalidUri(&'static str),
    /// Valid but unsupported (e.g. `hotp`).
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    /// The secret is not valid base32, is empty or is too long.
    #[error("invalid TOTP secret")]
    InvalidSecret,
    /// A parameter is out of range.
    #[error("invalid parameter: {0}")]
    InvalidParameter(&'static str),
}

/// HMAC hash function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    /// HMAC-SHA-1 (default).
    #[default]
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl Algorithm {
    fn name(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }

    fn parse(text: &str) -> Result<Self, TotpError> {
        match text.to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Ok(Algorithm::Sha1),
            "SHA256" => Ok(Algorithm::Sha256),
            "SHA512" => Ok(Algorithm::Sha512),
            _ => Err(TotpError::InvalidParameter("algorithm")),
        }
    }

    fn mac(self, key: &[u8], message: &[u8]) -> Zeroizing<Vec<u8>> {
        fn run<M: Mac + KeyInit>(key: &[u8], message: &[u8]) -> Zeroizing<Vec<u8>> {
            let mut mac =
                <M as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
            mac.update(message);
            let mut out = mac.finalize().into_bytes();
            let bytes = Zeroizing::new(out.to_vec());
            zeroize::Zeroize::zeroize(out.as_mut_slice());
            bytes
        }
        match self {
            Algorithm::Sha1 => run::<Hmac<sha1::Sha1>>(key, message),
            Algorithm::Sha256 => run::<Hmac<sha2::Sha256>>(key, message),
            Algorithm::Sha512 => run::<Hmac<sha2::Sha512>>(key, message),
        }
    }
}

/// Decodes a base32 secret leniently: case-insensitive, ignores spaces,
/// hyphens and `=` padding.
pub fn decode_base32_secret(text: &str) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    // Sized up front: a growing buffer would leave copies behind.
    let mut cleaned = Zeroizing::new(String::with_capacity(text.len()));
    cleaned.extend(
        text.chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
            .map(|c| c.to_ascii_uppercase()),
    );
    let bytes = Zeroizing::new(
        BASE32_NOPAD
            .decode(cleaned.as_bytes())
            .map_err(|_| TotpError::InvalidSecret)?,
    );
    if bytes.is_empty() || bytes.len() > MAX_SECRET_LEN {
        return Err(TotpError::InvalidSecret);
    }
    Ok(bytes)
}

/// A TOTP configuration. Not `Debug`, not `Display`, not `Clone`.
pub struct Totp {
    secret: SecretBox<Vec<u8>>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
    issuer: Option<String>,
    account: Option<String>,
}

impl Totp {
    /// Builds a TOTP from raw secret bytes.
    pub fn new(
        secret: &[u8],
        algorithm: Algorithm,
        digits: u32,
        period: u64,
    ) -> Result<Self, TotpError> {
        if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
            return Err(TotpError::InvalidSecret);
        }
        if !DIGITS_RANGE.contains(&digits) {
            return Err(TotpError::InvalidParameter("digits"));
        }
        if !PERIOD_RANGE.contains(&period) {
            return Err(TotpError::InvalidParameter("period"));
        }
        Ok(Self {
            secret: SecretBox::new(Box::new(secret.to_vec())),
            algorithm,
            digits,
            period,
            issuer: None,
            account: None,
        })
    }

    /// Builds a TOTP from a base32 secret with default parameters.
    pub fn from_base32(secret: &str) -> Result<Self, TotpError> {
        Self::new(
            &decode_base32_secret(secret)?,
            Algorithm::Sha1,
            DEFAULT_DIGITS,
            DEFAULT_PERIOD,
        )
    }

    /// Interprets a `totp` field value: an `otpauth://` URI or a bare base32 secret.
    pub fn from_field_value(value: &str) -> Result<Self, TotpError> {
        let trimmed = value.trim();
        if trimmed
            .get(..10)
            .is_some_and(|p| p.eq_ignore_ascii_case("otpauth://"))
        {
            Self::parse_otpauth(trimmed)
        } else {
            Self::from_base32(trimmed)
        }
    }

    /// Parses `otpauth://totp/[issuer:]account?secret=…&issuer=…&algorithm=…&digits=…&period=…`.
    ///
    /// Unknown parameters are ignored; repeated known parameters are rejected.
    pub fn parse_otpauth(uri: &str) -> Result<Self, TotpError> {
        let rest = uri
            .get(..10)
            .filter(|p| p.eq_ignore_ascii_case("otpauth://"))
            .map(|_| &uri[10..])
            .ok_or(TotpError::InvalidUri("missing otpauth:// scheme"))?;
        let rest = rest.split('#').next().unwrap_or_default();
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (kind, label) = path.split_once('/').unwrap_or((path, ""));
        if kind.eq_ignore_ascii_case("hotp") {
            return Err(TotpError::Unsupported("HOTP (counter-based) codes"));
        }
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(TotpError::InvalidUri("type must be totp"));
        }
        let label = percent_decode_str(label)
            .decode_utf8()
            .map_err(|_| TotpError::InvalidUri("label is not UTF-8"))?;

        let mut secret: Option<Zeroizing<Vec<u8>>> = None;
        let mut issuer: Option<String> = None;
        let mut algorithm: Option<Algorithm> = None;
        let mut digits: Option<u32> = None;
        let mut period: Option<u64> = None;
        let duplicate = |name| TotpError::InvalidUri(name);
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let plus = Zeroizing::new(value.replace('+', " "));
            let value = Zeroizing::new(
                percent_decode_str(&plus)
                    .decode_utf8()
                    .map_err(|_| TotpError::InvalidUri("parameter is not UTF-8"))?
                    .into_owned(),
            );
            match key.to_ascii_lowercase().as_str() {
                "secret" if secret.is_some() => return Err(duplicate("repeated secret")),
                "secret" => secret = Some(decode_base32_secret(&value)?),
                "issuer" if issuer.is_some() => return Err(duplicate("repeated issuer")),
                "issuer" => issuer = Some(value.to_string()),
                "algorithm" if algorithm.is_some() => return Err(duplicate("repeated algorithm")),
                "algorithm" => algorithm = Some(Algorithm::parse(&value)?),
                "digits" if digits.is_some() => return Err(duplicate("repeated digits")),
                "digits" => {
                    digits = Some(
                        value
                            .parse()
                            .map_err(|_| TotpError::InvalidParameter("digits"))?,
                    )
                }
                "period" if period.is_some() => return Err(duplicate("repeated period")),
                "period" => {
                    period = Some(
                        value
                            .parse()
                            .map_err(|_| TotpError::InvalidParameter("period"))?,
                    )
                }
                _ => {}
            }
        }
        let secret = secret.ok_or(TotpError::InvalidUri("missing secret"))?;
        let mut totp = Self::new(
            &secret,
            algorithm.unwrap_or_default(),
            digits.unwrap_or(DEFAULT_DIGITS),
            period.unwrap_or(DEFAULT_PERIOD),
        )?;
        let (label_issuer, account) = match label.split_once(':') {
            Some((i, a)) => (Some(i.trim().to_string()), a.trim().to_string()),
            None => (None, label.trim().to_string()),
        };
        // An empty `issuer=` leaves the label's issuer in place.
        let named = |s: Option<String>| s.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
        totp.issuer = named(issuer).or(named(label_issuer));
        totp.account = Some(account).filter(|s| !s.is_empty());
        Ok(totp)
    }

    /// Serializes back to an `otpauth://totp/…` URI. Contains the secret.
    pub fn to_otpauth(&self) -> SecretString {
        let enc = |s: &str| utf8_percent_encode(s, NON_ALPHANUMERIC).to_string();
        // Sized up front (percent-encoding at most triples a label): a
        // growing buffer would leave copies of the secret behind.
        let labels = self.issuer.as_deref().map_or(0, str::len) * 2
            + self.account.as_deref().map_or(0, str::len);
        let mut uri = Zeroizing::new(String::with_capacity(
            128 + 3 * labels + BASE32_NOPAD.encode_len(self.secret.expose_secret().len()),
        ));
        uri.push_str("otpauth://totp/");
        match (&self.issuer, &self.account) {
            (Some(i), Some(a)) => {
                let _ = write!(uri, "{}:{}", enc(i), enc(a));
            }
            (None, Some(a)) => uri.push_str(&enc(a)),
            (Some(i), None) => uri.push_str(&enc(i)),
            (None, None) => {}
        }
        let secret = Zeroizing::new(BASE32_NOPAD.encode(self.secret.expose_secret()));
        let _ = write!(uri, "?secret={}", secret.as_str());
        if let Some(i) = &self.issuer {
            let _ = write!(uri, "&issuer={}", enc(i));
        }
        let _ = write!(
            uri,
            "&algorithm={}&digits={}&period={}",
            self.algorithm.name(),
            self.digits,
            self.period
        );
        SecretString::from(uri.as_str().to_owned())
    }

    /// Hash function.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Number of digits.
    pub fn digits(&self) -> u32 {
        self.digits
    }

    /// Period in seconds.
    pub fn period(&self) -> u64 {
        self.period
    }

    /// Issuer, if known.
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// Account name, if known.
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    /// The same TOTP with this issuer and account name (empty means none),
    /// for [`Self::to_otpauth`].
    pub fn with_label(mut self, issuer: Option<&str>, account: Option<&str>) -> Self {
        self.issuer = issuer
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        self.account = account
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        self
    }

    /// Whether both have the same secret (in constant time). Parameters
    /// and labels are not compared.
    pub fn same_secret(&self, other: &Totp) -> bool {
        use subtle::ConstantTimeEq;
        let (a, b) = (self.secret.expose_secret(), other.secret.expose_secret());
        a.len() == b.len() && bool::from(a.as_slice().ct_eq(b.as_slice()))
    }

    /// HOTP value for `counter` (RFC 4226 §5.3), zero-padded to `digits`.
    pub fn hotp(&self, counter: u64) -> SecretString {
        let mac = self
            .algorithm
            .mac(self.secret.expose_secret(), &counter.to_be_bytes());
        let offset = usize::from(mac[mac.len() - 1] & 0x0f);
        let binary = u32::from_be_bytes([
            mac[offset] & 0x7f,
            mac[offset + 1],
            mac[offset + 2],
            mac[offset + 3],
        ]);
        let code = Zeroizing::new(binary % 10u32.pow(self.digits));
        let mut text = String::with_capacity(self.digits as usize);
        let _ = write!(text, "{:0width$}", *code, width = self.digits as usize);
        SecretString::from(text)
    }

    /// TOTP value at `unix_time` (seconds since the epoch, T0 = 0).
    pub fn generate(&self, unix_time: u64) -> SecretString {
        self.hotp(unix_time / self.period)
    }

    /// Seconds until the code for `unix_time` changes.
    pub fn seconds_remaining(&self, unix_time: u64) -> u64 {
        self.period - unix_time % self.period
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static_assertions::assert_not_impl_any!(Totp: std::fmt::Debug, std::fmt::Display, Clone);

    fn vectors() -> serde_json::Value {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/vectores/totp.json");
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn rfc6238_vectors() {
        let doc = vectors();
        let cases = doc["totp"].as_array().unwrap();
        assert_eq!(cases.len(), 18);
        for case in cases {
            let seed = hex::decode(case["seed"].as_str().unwrap()).unwrap();
            let algorithm = Algorithm::parse(case["algorithm"].as_str().unwrap()).unwrap();
            let totp = Totp::new(&seed, algorithm, 8, 30).unwrap();
            let time = case["time"].as_u64().unwrap();
            assert_eq!(
                format!("{:016x}", time / 30),
                case["counter_hex"].as_str().unwrap()
            );
            assert_eq!(
                totp.generate(time).expose_secret(),
                case["code"].as_str().unwrap(),
                "{case}"
            );
        }
    }

    #[test]
    fn rfc4226_vectors() {
        let doc = vectors();
        for case in doc["hotp"].as_array().unwrap() {
            let seed = hex::decode(case["seed"].as_str().unwrap()).unwrap();
            let hotp = Totp::new(&seed, Algorithm::Sha1, 6, 30).unwrap();
            let counter = case["counter"].as_u64().unwrap();
            assert_eq!(
                hotp.hotp(counter).expose_secret(),
                case["code"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn parses_otpauth() {
        let totp = Totp::parse_otpauth(
            "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60&image=x",
        )
        .unwrap();
        assert_eq!(totp.issuer(), Some("ACME Co"));
        assert_eq!(totp.account(), Some("john.doe@email.com"));
        assert_eq!(totp.algorithm(), Algorithm::Sha256);
        assert_eq!((totp.digits(), totp.period()), (8, 60));

        let minimal =
            Totp::parse_otpauth("OTPAUTH://TOTP/alice?secret=jbsw y3dp ehpk 3pxp").unwrap();
        assert_eq!(minimal.account(), Some("alice"));
        assert_eq!(minimal.issuer(), None);
        assert_eq!(
            (minimal.algorithm(), minimal.digits(), minimal.period()),
            (Algorithm::Sha1, 6, 30)
        );

        let no_label = Totp::parse_otpauth("otpauth://totp?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(no_label.account(), None);
    }

    #[test]
    fn otpauth_labels_padding_and_case() {
        // Padding, as is and percent-encoded, is the same secret.
        let bare = Totp::from_base32("MZXW6YTBOI").unwrap();
        for secret in ["MZXW6YTBOI======", "MZXW6YTBOI%3D%3D%3D%3D%3D%3D"] {
            let totp = Totp::parse_otpauth(&format!("otpauth://totp/x?secret={secret}")).unwrap();
            assert!(totp.same_secret(&bare), "{secret}");
        }

        // The `issuer` parameter wins over the label's.
        let both =
            Totp::parse_otpauth("otpauth://totp/Evil:ana?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
                .unwrap();
        assert_eq!(both.issuer(), Some("GitHub"));
        assert_eq!(both.account(), Some("ana"));

        // `+` is a space in a parameter (form encoding), `%2B` a plus; in
        // the label it is a plus.
        let issuer = |uri: &str| {
            Totp::parse_otpauth(uri)
                .unwrap()
                .issuer()
                .map(str::to_owned)
        };
        assert_eq!(
            issuer("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=Git+Hub").as_deref(),
            Some("Git Hub")
        );
        assert_eq!(
            issuer("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=A%2BB").as_deref(),
            Some("A+B")
        );
        assert_eq!(
            issuer("otpauth://totp/A+B:ana?secret=JBSWY3DPEHPK3PXP").as_deref(),
            Some("A+B")
        );

        // An empty (or blank) `issuer=` leaves the label's issuer.
        for empty in ["", "%20", "+"] {
            assert_eq!(
                issuer(&format!(
                    "otpauth://totp/GitHub:ana?secret=JBSWY3DPEHPK3PXP&issuer={empty}"
                ))
                .as_deref(),
                Some("GitHub"),
                "issuer={empty}"
            );
        }
        assert_eq!(
            issuer("otpauth://totp/ana?secret=JBSWY3DPEHPK3PXP&issuer="),
            None
        );

        // The type in capitals, with the scheme in lower case.
        let upper =
            Totp::parse_otpauth("otpauth://TOTP/GitHub:ana?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(upper.issuer(), Some("GitHub"));
        assert_eq!(upper.account(), Some("ana"));
    }

    #[test]
    fn otpauth_roundtrip() {
        let original = Totp::parse_otpauth(
            "otpauth://totp/Git%20Hub:omar%2Bx@ejemplo.mx?secret=JBSWY3DPEHPK3PXP&issuer=Git%20Hub&algorithm=SHA512&digits=7&period=45",
        )
        .unwrap();
        let again = Totp::parse_otpauth(original.to_otpauth().expose_secret()).unwrap();
        assert_eq!(again.issuer(), Some("Git Hub"));
        assert_eq!(again.account(), Some("omar+x@ejemplo.mx"));
        assert_eq!(
            (again.algorithm(), again.digits(), again.period()),
            (Algorithm::Sha512, 7, 45)
        );
        assert_eq!(
            again.generate(1_700_000_000).expose_secret(),
            original.generate(1_700_000_000).expose_secret()
        );
    }

    #[test]
    fn rejects_bad_uris() {
        use TotpError as E;
        let cases: &[(&str, TotpError)] = &[
            (
                "https://totp/x?secret=JBSWY3DP",
                E::InvalidUri("missing otpauth:// scheme"),
            ),
            (
                "otpauth://hotp/x?secret=JBSWY3DP&counter=1",
                E::Unsupported("HOTP (counter-based) codes"),
            ),
            (
                "otpauth://sms/x?secret=JBSWY3DP",
                E::InvalidUri("type must be totp"),
            ),
            ("otpauth://totp/x", E::InvalidUri("missing secret")),
            ("otpauth://totp/x?secret=", E::InvalidSecret),
            ("otpauth://totp/x?secret=0189", E::InvalidSecret),
            (
                "otpauth://totp/x?secret=JBSWY3DP&digits=5",
                E::InvalidParameter("digits"),
            ),
            (
                "otpauth://totp/x?secret=JBSWY3DP&digits=9",
                E::InvalidParameter("digits"),
            ),
            (
                "otpauth://totp/x?secret=JBSWY3DP&period=0",
                E::InvalidParameter("period"),
            ),
            (
                "otpauth://totp/x?secret=JBSWY3DP&algorithm=MD5",
                E::InvalidParameter("algorithm"),
            ),
            (
                "otpauth://totp/x?secret=JBSWY3DP&secret=JBSWY3DP",
                E::InvalidUri("repeated secret"),
            ),
        ];
        for (uri, expected) in cases {
            assert_eq!(
                Totp::parse_otpauth(uri).err().as_ref(),
                Some(expected),
                "{uri}"
            );
        }
    }

    #[test]
    fn field_values_and_timing() {
        let totp = Totp::from_field_value(" JBSWY3DPEHPK3PXP ").unwrap();
        assert_eq!(totp.generate(59).expose_secret().len(), 6);
        assert_eq!(totp.seconds_remaining(59), 1);
        assert_eq!(totp.seconds_remaining(60), 30);
        assert_eq!(
            totp.generate(60).expose_secret(),
            totp.generate(89).expose_secret()
        );
        assert!(Totp::from_field_value("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").is_ok());
        assert!(Totp::from_field_value("not base32!").is_err());
    }

    #[test]
    fn labels_and_secret_comparison() {
        let a = Totp::from_base32("JBSWY3DPEHPK3PXP")
            .unwrap()
            .with_label(Some("Example"), Some("ana@example.com"));
        let uri = a.to_otpauth();
        let b = Totp::parse_otpauth(uri.expose_secret()).unwrap();
        assert_eq!(b.issuer(), Some("Example"));
        assert_eq!(b.account(), Some("ana@example.com"));
        assert!(a.same_secret(&b));
        assert!(!a.same_secret(&Totp::from_base32("GEZDGNBVGY3TQOJQ").unwrap()));
        assert_eq!(a.with_label(Some(" "), None).issuer(), None);
    }
}
