//! Google Authenticator's export: one or more QR codes holding
//! `otpauth-migration://offline?data=<base64 MigrationPayload>`. Also plain
//! `otpauth://totp/…` links, one per line.
//!
//! ```text
//! MigrationPayload { 1: repeated OtpParameters, 2: version, 3: batch_size,
//!                    4: batch_index, 5: batch_id }
//! OtpParameters    { 1: secret, 2: name, 3: issuer, 4: algorithm,
//!                    5: digits, 6: type, 7: counter }
//! ```

use klav_core::model::item::ItemKind;
use klav_core::totp::{Algorithm, Totp};
use percent_encoding::percent_decode_str;
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::fields::{clean, new_item, set};
use crate::protobuf::{Value, fields};
use crate::{Batch, Entry, Format, ImportError, MAX_BATCH_SIZE, MAX_CODES, Parsed};

const MIGRATION: &str = "otpauth-migration://";

/// Whether `text` holds Google Authenticator links.
pub(crate) fn looks_like(text: &str) -> bool {
    let lower = text.get(..20).unwrap_or(text).to_ascii_lowercase();
    lower.starts_with(MIGRATION) || lower.starts_with("otpauth://")
}

fn invalid(what: &str) -> ImportError {
    ImportError::Invalid(format!("not a Google Authenticator export code ({what})"))
}

/// The base64 `data` of a migration link.
fn payload(link: &str) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let query = link
        .split_once('?')
        .map(|(_, q)| q)
        .ok_or_else(|| invalid("no data"))?;
    let data = query
        .split('&')
        .find_map(|p| p.strip_prefix("data="))
        .ok_or_else(|| invalid("no data"))?;
    let decoded = Zeroizing::new(
        percent_decode_str(data)
            .decode_utf8()
            .map_err(|_| invalid("bad encoding"))?
            .replace(' ', "+"),
    );
    let trimmed = decoded.trim_end_matches('=');
    for encoding in [
        &data_encoding::BASE64_NOPAD,
        &data_encoding::BASE64URL_NOPAD,
    ] {
        if let Ok(bytes) = encoding.decode(trimmed.as_bytes()) {
            return Ok(Zeroizing::new(bytes));
        }
    }
    Err(invalid("bad base64"))
}

/// One account of a payload.
enum Account {
    /// Imported.
    Entry(Box<Entry>),
    /// Not imported, and why.
    Skip(&'static str),
}

fn account(params: &[u8]) -> Result<Account, ImportError> {
    let mut secret: &[u8] = &[];
    let (mut name, mut issuer) = (String::new(), String::new());
    let (mut algorithm, mut digits, mut kind) = (0u64, 0u64, 0u64);
    for field in fields(params) {
        match field.map_err(|_| invalid("damaged account"))? {
            (1, Value::Bytes(b)) => secret = b,
            (2, Value::Bytes(b)) => name = String::from_utf8_lossy(b).into_owned(),
            (3, Value::Bytes(b)) => issuer = String::from_utf8_lossy(b).into_owned(),
            (4, Value::Varint(v)) => algorithm = v,
            (5, Value::Varint(v)) => digits = v,
            (6, Value::Varint(v)) => kind = v,
            _ => {}
        }
    }
    if kind == 1 {
        return Ok(Account::Skip(
            "counter-based (HOTP) codes are not supported",
        ));
    }
    let algorithm = match algorithm {
        0 | 1 => Algorithm::Sha1,
        2 => Algorithm::Sha256,
        3 => Algorithm::Sha512,
        _ => return Ok(Account::Skip("unsupported algorithm (MD5)")),
    };
    let digits = if digits == 2 { 8 } else { 6 };
    // The name is often «Issuer:account».
    let (name, mut issuer) = (clean(&name, 256), clean(&issuer, 256));
    let account = match name.split_once(':') {
        Some((prefix, rest))
            if issuer.is_empty() || prefix.trim().eq_ignore_ascii_case(&issuer) =>
        {
            if issuer.is_empty() {
                issuer = prefix.trim().to_owned();
            }
            rest.trim().to_owned()
        }
        _ => name,
    };
    Ok(build(secret, algorithm, digits, &issuer, &account))
}

fn build(secret: &[u8], algorithm: Algorithm, digits: u32, issuer: &str, account: &str) -> Account {
    let Ok(totp) = Totp::new(secret, algorithm, digits, 30) else {
        return Account::Skip("the secret is not valid");
    };
    let totp = totp.with_label(Some(issuer), Some(account));
    let title = if issuer.is_empty() { account } else { issuer };
    let mut item = new_item(ItemKind::Totp, title, &[], "", "One-time code");
    if !set(&mut item, "totp", totp.to_otpauth().expose_secret()) {
        return Account::Skip("the secret is not valid");
    }
    Account::Entry(Box::new(Entry::new(item, "")))
}

/// Parses QR contents or pasted text: migration links and `otpauth://`
/// links, any number, separated by white space.
pub(crate) fn parse_texts(texts: &[&str]) -> Result<Parsed, ImportError> {
    let mut parsed = Parsed::new(Format::GoogleAuthenticator);
    let mut accounts = 0;
    let mut codes = 0;
    let mut plain = Vec::new();
    let mut found = false;
    for link in texts.iter().flat_map(|t| t.split_whitespace()) {
        let lower = link.get(..20).unwrap_or(link).to_ascii_lowercase();
        if lower.starts_with(MIGRATION) {
            found = true;
            codes += 1;
            if codes > MAX_CODES {
                return Err(ImportError::Invalid(format!(
                    "more than {MAX_CODES} Google Authenticator export codes at once"
                )));
            }
            let bytes = payload(link)?;
            // Positions as the payload gives them: from 0, absent means 0.
            let (mut size, mut index) = (1u64, 0u64);
            let mut id = 0i64;
            let mut entries = Vec::new();
            for field in fields(&bytes) {
                match field.map_err(|_| invalid("damaged payload"))? {
                    (1, Value::Bytes(b)) => {
                        accounts += 1;
                        let at = format!("account {accounts}");
                        match account(b)? {
                            Account::Entry(mut entry) => {
                                parsed.admit()?;
                                entry.at = at;
                                entries.push(*entry);
                            }
                            Account::Skip(reason) => parsed.skip(at, reason),
                        }
                    }
                    (3, Value::Varint(v)) => size = v.max(1),
                    (4, Value::Varint(v)) => index = v,
                    (5, Value::Varint(v)) => id = v as i64,
                    _ => {}
                }
            }
            // Google Authenticator splits an export in a handful of codes;
            // a size beyond that (or a position past it) is not one of
            // its codes, and would make the list of missing ones huge.
            if size > u64::from(MAX_BATCH_SIZE) || index >= size {
                return Err(invalid("impossible position"));
            }
            let batch = Batch {
                id,
                // Both fit: index < size <= MAX_BATCH_SIZE.
                index: u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1),
                size: u32::try_from(size).unwrap_or(MAX_BATCH_SIZE),
            };
            parsed.batches.push((Some(batch), entries));
        } else if lower.starts_with("otpauth://") {
            found = true;
            accounts += 1;
            let at = format!("account {accounts}");
            match Totp::parse_otpauth(link) {
                Ok(totp) => {
                    let title = totp
                        .issuer()
                        .or(totp.account())
                        .unwrap_or_default()
                        .to_owned();
                    let mut item = new_item(ItemKind::Totp, &title, &[], "", "One-time code");
                    if set(&mut item, "totp", totp.to_otpauth().expose_secret()) {
                        parsed.admit()?;
                        plain.push(Entry::new(item, at));
                    } else {
                        parsed.skip(at, "the secret is not valid");
                    }
                }
                Err(_) => parsed.skip(at, "not a supported one-time code link"),
            }
        }
    }
    if !found {
        return Err(ImportError::NotRecognised(
            "no otpauth-migration:// or otpauth:// link found".into(),
        ));
    }
    if !plain.is_empty() {
        parsed.batches.push((None, plain));
    }
    Ok(parsed)
}

#[cfg(test)]
pub(crate) mod tests {
    use klav_core::model::item::FieldValue;

    use super::*;
    use crate::protobuf::tests::{put_bytes, put_int};

    /// `(secret, name, issuer, algorithm, digits, type)`.
    pub(crate) type Account<'a> = (&'a [u8], &'a str, &'a str, u64, u64, u64);

    /// A migration link with these accounts, as code `index` (from 0) of
    /// `size`.
    pub(crate) fn link(accounts: &[Account<'_>], index: u64, size: u64, id: u64) -> String {
        let mut payload = Vec::new();
        for (secret, name, issuer, algorithm, digits, kind) in accounts {
            let mut p = Vec::new();
            put_bytes(&mut p, 1, secret);
            put_bytes(&mut p, 2, name.as_bytes());
            put_bytes(&mut p, 3, issuer.as_bytes());
            put_int(&mut p, 4, *algorithm);
            put_int(&mut p, 5, *digits);
            put_int(&mut p, 6, *kind);
            put_bytes(&mut payload, 1, &p);
        }
        put_int(&mut payload, 2, 1);
        put_int(&mut payload, 3, size);
        put_int(&mut payload, 4, index);
        put_int(&mut payload, 5, id);
        let b64 = data_encoding::BASE64.encode(&payload);
        let enc = percent_encoding::utf8_percent_encode(&b64, percent_encoding::NON_ALPHANUMERIC);
        format!("otpauth-migration://offline?data={enc}")
    }

    fn uri(entry: &Entry) -> String {
        match entry.item.field("totp").unwrap().value() {
            FieldValue::Secret(s) => s.expose().to_owned(),
            _ => String::new(),
        }
    }

    #[test]
    fn reads_a_migration_link() {
        let l = link(
            &[
                (
                    b"Hello!\xde\xad\xbe\xef",
                    "Example:ana@example.com",
                    "Example",
                    1,
                    1,
                    2,
                ),
                (b"0123456789", "bob", "", 2, 2, 2),
                (b"counter", "hotp", "X", 1, 1, 1),
                (b"md5", "md5", "Y", 4, 1, 2),
            ],
            0,
            2,
            77,
        );
        let p = parse_texts(&[&l]).unwrap();
        let (batch, entries) = &p.batches[0];
        assert_eq!(
            *batch,
            Some(Batch {
                id: 77,
                index: 1,
                size: 2
            })
        );
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].item.title(), "Example");
        let t = Totp::from_field_value(&uri(&entries[0])).unwrap();
        assert_eq!(t.issuer(), Some("Example"));
        assert_eq!(t.account(), Some("ana@example.com"));
        assert_eq!(entries[1].item.title(), "bob");
        let t = Totp::from_field_value(&uri(&entries[1])).unwrap();
        assert_eq!((t.algorithm(), t.digits()), (Algorithm::Sha256, 8));
        assert_eq!(p.skipped.len(), 2);
        assert_eq!(p.skipped[0].at, "account 3");
    }

    #[test]
    fn plain_links_and_garbage() {
        let p = parse_texts(&["otpauth://totp/Site:ana?secret=JBSWY3DPEHPK3PXP&issuer=Site\n otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP"]).unwrap();
        assert_eq!(p.batches[0].1.len(), 1);
        assert_eq!(p.skipped.len(), 1);
        assert!(parse_texts(&["hello"]).is_err());
        assert!(parse_texts(&["otpauth-migration://offline?data=%%%"]).is_err());
        assert!(parse_texts(&["otpauth-migration://offline?data=AAAA"]).is_err());
    }

    const SECRET: &[u8] = b"0123456789";

    #[test]
    fn refuses_impossible_positions() {
        let one = |index, size| link(&[(SECRET, "a", "X", 1, 1, 2)], index, size, 9);
        // A size of 2^32 - 1 codes would list four thousand million
        // missing ones.
        for (index, size) in [
            (0, u64::from(u32::MAX)),
            (0, u64::MAX),
            (0, u64::from(MAX_BATCH_SIZE) + 1),
            // index is from 0: the third code of two, and u64::MAX + 1.
            (2, 2),
            (u64::MAX, u64::MAX),
            (u64::from(u32::MAX), 2),
        ] {
            assert!(
                matches!(
                    parse_texts(&[&one(index, size)]),
                    Err(ImportError::Invalid(_))
                ),
                "{index} of {size}"
            );
        }
        let last = parse_texts(&[&one(
            u64::from(MAX_BATCH_SIZE) - 1,
            u64::from(MAX_BATCH_SIZE),
        )])
        .unwrap();
        assert_eq!(
            last.batches[0].0,
            Some(Batch {
                id: 9,
                index: MAX_BATCH_SIZE,
                size: MAX_BATCH_SIZE
            })
        );
    }

    #[test]
    fn caps_the_codes_of_one_paste() {
        let code = link(&[(SECRET, "a", "X", 1, 1, 2)], 0, 1, 1);
        let many = vec![code.as_str(); MAX_CODES + 1];
        assert!(matches!(parse_texts(&many), Err(ImportError::Invalid(_))));
        assert!(parse_texts(&many[1..]).is_ok());
    }

    #[test]
    fn caps_the_accounts_of_one_paste() {
        // Each account a few bytes: the cap must hold while reading, not
        // after every account is in memory.
        let accounts = vec![(SECRET, "a", "X", 1, 1, 2); crate::MAX_ENTRIES + 1];
        let big = link(&accounts, 0, 1, 1);
        assert!(matches!(parse_texts(&[&big]), Err(ImportError::Invalid(_))));
    }
}
