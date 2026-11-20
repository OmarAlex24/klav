//! CSV exports: browsers (Chrome, Edge, Brave, Firefox, Safari), Bitwarden,
//! 1Password and a generic layout, recognised by their columns.

use std::collections::HashMap;

use klav_core::model::item::ItemKind;
use zeroize::Zeroizing;

use crate::fields::{LINK_LEFT_OUT, Links, add_tags, add_urls, clean, new_item, set};
use crate::{Entry, Format, ImportError, Parsed, Source};

/// Canonical columns and the header names that map to them.
const ALIASES: &[(&str, &[&str])] = &[
    ("title", &["title", "name"]),
    (
        "url",
        &[
            "url",
            "login_uri",
            "uri",
            "website",
            "web site",
            "login url",
        ],
    ),
    (
        "username",
        &["username", "login_username", "user name", "user", "login"],
    ),
    ("password", &["password", "login_password"]),
    (
        "totp",
        &["otpauth", "totp", "login_totp", "one-time password", "otp"],
    ),
    ("notes", &["notes", "note", "extra", "comments"]),
    ("tags", &["tags", "folder", "grouping", "labels"]),
    ("type", &["type"]),
    ("changed", &["timepasswordchanged"]),
];

fn detect(headers: &[String]) -> Format {
    let has = |h: &str| headers.iter().any(|x| x == h);
    if has("login_uri") || has("login_password") {
        Format::BitwardenCsv
    } else if has("httprealm") || has("formactionorigin") {
        Format::Firefox
    } else if has("archived") || has("favorite") {
        Format::OnePasswordCsv
    } else if has("otpauth") && has("title") {
        Format::Safari
    } else if headers.starts_with(&[
        "name".into(),
        "url".into(),
        "username".into(),
        "password".into(),
    ]) {
        Format::Chrome
    } else {
        Format::Csv
    }
}

/// Parses a CSV export. `source` only chooses the dialect's name when the
/// columns do not say (a generic layout from a browser).
pub(crate) fn parse(bytes: &[u8], source: Option<Source>) -> Result<Parsed, ImportError> {
    let mut csv = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::Headers)
        .from_reader(bytes);
    let headers: Vec<String> = csv
        .headers()
        .map_err(|_| ImportError::NotRecognised("cannot read the CSV header".into()))?
        .iter()
        .map(|h| h.trim().trim_start_matches('\u{feff}').to_lowercase())
        .collect();
    let mut columns: HashMap<&str, usize> = HashMap::new();
    for (canonical, aliases) in ALIASES {
        if let Some(i) = aliases
            .iter()
            .find_map(|a| headers.iter().position(|h| h == a))
        {
            columns.insert(canonical, i);
        }
    }
    if !columns.contains_key("password") && !columns.contains_key("notes") {
        return Err(ImportError::NotRecognised(
            "the CSV has no password or notes column (expected e.g. title,url,username,password,totp,notes,tags)".into(),
        ));
    }
    let mut format = detect(&headers);
    if format == Format::Csv {
        format = match source {
            Some(Source::Chrome) => Format::Chrome,
            Some(Source::Firefox) => Format::Firefox,
            Some(Source::Safari) => Format::Safari,
            _ => Format::Csv,
        };
    }
    let mut parsed = Parsed::new(format);
    // One record for every row, big enough for any of them (the pages of
    // a zeroed allocation cost nothing until used), so it never grows and
    // leaves copies of earlier rows behind; wiped at the end.
    let mut record = WipedRecord::new(bytes.len());
    for index in 0.. {
        let at = format!("row {}", index + 2); // 1-based, after the header
        match csv.read_record(&mut record.0) {
            Ok(true) => record.used(),
            Ok(false) => break,
            Err(_) => {
                // A row that is not UTF-8 was read into the buffer too.
                record.used();
                parsed.skip(&at, "unreadable row");
                continue;
            }
        }
        let record = &record.0;
        let get = |name: &str| -> Zeroizing<String> {
            Zeroizing::new(
                columns
                    .get(name)
                    .and_then(|&i| record.get(i))
                    .map(str::trim)
                    .unwrap_or_default()
                    .to_owned(),
            )
        };
        let kind = match get("type").to_lowercase().as_str() {
            "" | "login" | "1" => ItemKind::Login,
            "note" | "securenote" | "2" => ItemKind::Note,
            _ => {
                parsed.skip(&at, "unsupported item type");
                continue;
            }
        };
        let (title, url, username, password, totp, notes, tags) = (
            get("title"),
            get("url"),
            get("username"),
            get("password"),
            get("totp"),
            get("notes"),
            get("tags"),
        );
        if [&url, &username, &password, &notes, &totp]
            .iter()
            .all(|v| v.is_empty())
        {
            parsed.skip(&at, "empty row");
            continue;
        }
        // Firefox keeps the Firefox account's sync key as a login.
        if url.to_ascii_lowercase().starts_with("chrome://") {
            parsed.skip(&at, "Firefox's own sync entry");
            continue;
        }
        let links = Links::sort([url.as_str()]);
        let mut item = new_item(
            kind,
            &title,
            &links.for_title(),
            &username,
            &format!("Imported {at}"),
        );
        if kind == ItemKind::Login {
            if !set(&mut item, "username", &username) {
                parsed.note(&at, "user name not imported");
            }
            if !set(&mut item, "password", &password) {
                parsed.note(&at, "password not imported");
            }
            if !set(&mut item, "totp", &totp) {
                parsed.note(&at, "one-time password secret not recognised");
            }
            if !add_urls(&mut item, &links.web) {
                parsed.note(&at, "URL not valid, left out");
            }
            if links.dropped() {
                parsed.note(&at, LINK_LEFT_OUT);
            }
        } else if !title.is_empty() && clean(&title, 256) != item.title() {
            parsed.note(&at, "title shortened");
        }
        if !notes.is_empty() {
            item.set_notes(Some(&notes));
        }
        if !add_tags(&mut item, tags.split([',', ';'])) {
            parsed.note(&at, "a tag was not valid");
        }
        let mut entry = Entry::new(item, at);
        // Firefox says when the password changed, in ms since the epoch.
        entry.modified_ms = get("changed").parse::<i64>().ok().filter(|ms| *ms > 0);
        parsed.push(entry)?;
    }
    Ok(parsed)
}

/// The record rows are read into, overwritten with zeros when dropped.
/// Best effort: `csv` gives no access to the record's buffer, so this
/// writes a field of zeros as long as the longest row over it, and its
/// 8 KiB read buffer is not reached at all (zeroizing that would need
/// `csv-core` directly).
struct WipedRecord(csv::StringRecord, usize);

impl WipedRecord {
    fn new(capacity: usize) -> Self {
        Self(csv::StringRecord::with_capacity(capacity, 16), 0)
    }

    /// Notes how much of the buffer the row just read used.
    fn used(&mut self) {
        self.1 = self.1.max(self.0.as_byte_record().as_slice().len());
    }
}

impl Drop for WipedRecord {
    fn drop(&mut self) {
        self.0.clear();
        self.0.push_field(&"\0".repeat(self.1));
    }
}

#[cfg(test)]
mod tests {
    use klav_core::model::Item;
    use klav_core::model::item::FieldValue;

    use super::*;

    fn secret(item: &Item, field: &str) -> String {
        match item.field(field).unwrap().value() {
            FieldValue::Secret(s) => s.expose().to_owned(),
            FieldValue::Plain(s) => s.clone(),
            FieldValue::File(_) => String::new(),
        }
    }

    #[test]
    fn chrome_edge_brave_export() {
        let csv = "name,url,username,password,note\n\
                   GitHub,https://github.com/login,ana,pw1,\n\
                   ,https://www.example.com/x,bob,pw2,hello\n\
                   ,android://AbC==@com.example.app/,carla,pw3,\n\
                   ,,,,\n";
        let p = parse(csv.as_bytes(), None).unwrap();
        assert_eq!(p.format, Format::Chrome);
        assert_eq!(p.entries.len(), 3);
        assert_eq!(p.skipped[0].at, "row 5");
        assert_eq!(p.entries[0].item.title(), "GitHub");
        assert_eq!(secret(&p.entries[0].item, "password"), "pw1");
        assert_eq!(p.entries[1].item.title(), "example.com");
        assert_eq!(p.entries[1].item.notes().unwrap().expose(), "hello");
        assert_eq!(p.entries[2].item.title(), "com.example.app");
        // Edge drops the note column.
        let edge = "name,url,username,password\nA,https://a.example,u,p\n";
        assert_eq!(parse(edge.as_bytes(), None).unwrap().format, Format::Chrome);
    }

    #[test]
    fn firefox_export() {
        let csv = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\
                   \"https://accounts.example.org\",\"ana\",\"pw\",,\"https://accounts.example.org\",\"{x}\",\"1\",\"1\",\"1714558830123\"\n\
                   \"chrome://FirefoxAccounts\",\"uid\",\"{}\",\"Firefox Accounts credentials\",,\"{y}\",\"1\",\"1\",\"1\"\n";
        let p = parse(csv.as_bytes(), None).unwrap();
        assert_eq!(p.format, Format::Firefox);
        assert_eq!(p.entries.len(), 1);
        assert_eq!(p.entries[0].item.title(), "accounts.example.org");
        assert_eq!(p.entries[0].item.urls(), ["https://accounts.example.org"]);
        assert_eq!(p.entries[0].modified_ms, Some(1_714_558_830_123));
        assert_eq!(p.skipped[0].reason, "Firefox's own sync entry");
    }

    #[test]
    fn safari_export() {
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\n\
                   Example (ana),https://example.net/,ana,pw,,otpauth://totp/Example:ana?secret=JBSWY3DPEHPK3PXP&issuer=Example\n";
        let p = parse(csv.as_bytes(), None).unwrap();
        assert_eq!(p.format, Format::Safari);
        assert!(secret(&p.entries[0].item, "totp").starts_with("otpauth://"));
    }

    #[test]
    fn bitwarden_export_with_totp_and_notes() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   Work,,login,AWS,,,0,https://aws.amazon.com,root,pw,JBSWY3DPEHPK3PXP\n\
                   ,,note,Wifi,the password is X,,0,,,,\n\
                   ,,card,Visa,,,0,,,,\n\
                   ,,login,Bad TOTP,,,0,,u,p,not-base32!\n";
        let p = parse(csv.as_bytes(), None).unwrap();
        assert_eq!(p.format, Format::BitwardenCsv);
        assert_eq!(p.entries.len(), 3);
        assert!(p.entries[0].item.has_tag("Work"));
        assert_eq!(secret(&p.entries[0].item, "totp"), "JBSWY3DPEHPK3PXP");
        assert_eq!(p.entries[1].item.kind(), ItemKind::Note);
        assert_eq!(p.skipped[0].at, "row 4");
        assert_eq!(p.notes[0].at, "row 5");
        assert_eq!(p.notes[0].reason, "one-time password secret not recognised");
    }

    #[test]
    fn onepassword_and_generic_exports() {
        let csv = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n\
                   Stripe,https://dashboard.stripe.com,ana,pw,otpauth://totp/Stripe:ana?secret=JBSWY3DPEHPK3PXP,false,false,work;billing,\n";
        let p = parse(csv.as_bytes(), None).unwrap();
        assert_eq!(p.format, Format::OnePasswordCsv);
        assert!(p.entries[0].item.has_tag("work") && p.entries[0].item.has_tag("billing"));

        let generic = "title,username,password\nRouter,admin,pw\n";
        let p = parse(generic.as_bytes(), None).unwrap();
        assert_eq!(p.format, Format::Csv);
        assert_eq!(p.entries[0].item.title(), "Router");
        assert_eq!(
            parse(generic.as_bytes(), Some(Source::Safari))
                .unwrap()
                .format,
            Format::Safari
        );

        assert!(parse("a,b\n1,2\n".as_bytes(), None).is_err());
    }

    #[test]
    fn javascript_links_are_left_out() {
        let csv = "name,url,username,password\n\
                   ,javascript://github.com/%0aalert(document.cookie),ana,pw\n\
                   GitHub,JAVASCRIPT:alert(1),bob,pw\n\
                   ,github.com/login,carla,pw\n";
        let p = parse(csv.as_bytes(), None).unwrap();
        let [js, js2, bare] = &p.entries[..] else {
            panic!("three rows");
        };
        // Not «github.com»: the host of a javascript: link names nothing.
        assert_eq!(js.item.title(), "ana");
        assert!(js.item.urls().is_empty() && js2.item.urls().is_empty());
        assert_eq!(bare.item.urls(), ["https://github.com/login"]);
        let noted: Vec<&str> = p
            .notes
            .iter()
            .filter(|n| n.reason == LINK_LEFT_OUT)
            .map(|n| n.at.as_str())
            .collect();
        assert_eq!(noted, ["row 2", "row 3"]);
    }

    #[test]
    fn rows_are_capped_while_reading() {
        let mut csv = String::from("title,password\n");
        for _ in 0..=crate::MAX_ENTRIES {
            csv.push_str("a,b\n");
        }
        assert!(matches!(
            parse(csv.as_bytes(), None),
            Err(ImportError::Invalid(_))
        ));
    }

    #[test]
    fn a_long_row_in_the_middle_still_reads() {
        let long = "x".repeat(1000);
        let csv = format!("title,password\nA,p\nB,{long}\nC,q\n");
        let p = parse(csv.as_bytes(), None).unwrap();
        assert_eq!(p.entries.len(), 3);
        assert_eq!(secret(&p.entries[1].item, "password"), long);
        assert_eq!(secret(&p.entries[2].item, "password"), "q");
    }
}
