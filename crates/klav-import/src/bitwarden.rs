//! Bitwarden's unencrypted `.json` export. The password-protected one
//! (`"encrypted": true`) is refused: it would need Bitwarden's KDF and
//! AES-CBC (roadmap, fase 8).

use std::collections::HashMap;

use klav_core::model::item::{FieldKind, ItemKind, SecretValue};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::date::rfc3339_ms;
use crate::fields::{LINK_LEFT_OUT, Links, add, add_tags, add_urls, new_item, set};
use crate::limits::{JSON_BUDGET, capped, capped_opt, with_budget};
use crate::passkey::{self, BwFido2, ImportedPasskey};
use crate::{Entry, Format, ImportError, OldPassword, Parsed};

type Secret = Option<Zeroizing<String>>;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Export {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    password_protected: bool,
    #[serde(default, deserialize_with = "capped")]
    folders: Vec<Folder>,
    #[serde(default, deserialize_with = "capped_opt")]
    items: Option<Vec<BwItem>>,
}

#[derive(Deserialize)]
struct Folder {
    id: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwItem {
    #[serde(rename = "type")]
    kind: u8,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    notes: Secret,
    #[serde(default)]
    folder_id: Option<String>,
    #[serde(default)]
    login: Option<Login>,
    #[serde(default)]
    card: Option<Card>,
    #[serde(default)]
    identity: Option<Identity>,
    #[serde(default)]
    ssh_key: Option<SshKey>,
    #[serde(default, deserialize_with = "capped_opt")]
    fields: Option<Vec<BwField>>,
    #[serde(default, deserialize_with = "capped_opt")]
    password_history: Option<Vec<PasswordHistory>>,
    #[serde(default)]
    revision_date: Option<String>,
    #[serde(default)]
    deleted_date: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Login {
    #[serde(default, deserialize_with = "capped_opt")]
    uris: Option<Vec<Uri>>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Secret,
    #[serde(default)]
    totp: Secret,
    #[serde(default, deserialize_with = "capped_opt")]
    fido2_credentials: Option<Vec<BwFido2>>,
}

#[derive(Deserialize)]
struct Uri {
    #[serde(default)]
    uri: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Card {
    cardholder_name: Option<String>,
    brand: Option<String>,
    number: Secret,
    exp_month: Option<String>,
    exp_year: Option<String>,
    code: Secret,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Identity {
    title: Option<String>,
    first_name: Option<String>,
    middle_name: Option<String>,
    last_name: Option<String>,
    address1: Option<String>,
    address2: Option<String>,
    address3: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    company: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    ssn: Secret,
    username: Option<String>,
    passport_number: Secret,
    license_number: Secret,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshKey {
    private_key: Secret,
    public_key: Option<String>,
    key_fingerprint: Option<String>,
}

#[derive(Deserialize)]
struct BwField {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Secret,
    #[serde(rename = "type", default)]
    kind: u8,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordHistory {
    #[serde(default)]
    last_used_date: Option<String>,
    password: Secret,
}

fn text(v: &Option<String>) -> &str {
    v.as_deref().unwrap_or_default()
}

fn secret(v: &Secret) -> &str {
    v.as_deref().map_or("", String::as_str)
}

/// The login's passkey: the first of `fido2Credentials` that Klav can
/// use. The others are counted as not imported, each with a note.
fn passkey_of(
    parsed: &mut Parsed,
    at: &str,
    credentials: &[BwFido2],
    username: &str,
    modified_ms: Option<i64>,
) -> Option<ImportedPasskey> {
    let mut kept: Option<ImportedPasskey> = None;
    for c in credentials {
        if kept.is_some() {
            parsed.passkeys += 1;
            parsed.note(at, passkey::ONE_PER_LOGIN);
            continue;
        }
        match passkey::read(c, username, modified_ms) {
            Ok((p, counted)) => {
                if counted {
                    parsed.note(at, passkey::COUNTED);
                }
                kept = Some(p);
            }
            Err(reason) => {
                parsed.passkeys += 1;
                parsed.note(at, reason);
            }
        }
    }
    kept
}

pub(crate) fn parse(text_in: &str) -> Result<Parsed, ImportError> {
    let (export, spent) = with_budget(JSON_BUDGET, || serde_json::from_str::<Export>(text_in));
    let export = export.map_err(|e| {
        if spent {
            return crate::limits::too_many_parts();
        }
        ImportError::Invalid(format!(
            "not a Bitwarden JSON export (line {}, column {})",
            e.line(),
            e.column()
        ))
    })?;
    if export.encrypted || export.password_protected {
        return Err(ImportError::Encrypted(
            "this Bitwarden export is encrypted: export again as «.json» (not «.json (Encrypted)»)",
        ));
    }
    let items = export
        .items
        .ok_or_else(|| ImportError::NotRecognised("a JSON file without Bitwarden items".into()))?;
    // Looked up once per item: a scan of the list each time would be
    // quadratic in a file of many items and folders.
    let folders: HashMap<&str, &str> = export
        .folders
        .iter()
        .map(|f| (f.id.as_str(), f.name.as_str()))
        .collect();
    let mut parsed = Parsed::new(Format::Bitwarden);
    for (index, bw) in items.into_iter().enumerate() {
        let at = format!("item {}", index + 1);
        if bw.deleted_date.is_some() {
            parsed.skip(&at, "in Bitwarden's trash");
            continue;
        }
        let kind = match bw.kind {
            1 => ItemKind::Login,
            2 => ItemKind::Note,
            3 => ItemKind::Card,
            4 => ItemKind::Identity,
            5 => ItemKind::SshKey,
            _ => {
                parsed.skip(&at, "unsupported item type");
                continue;
            }
        };
        let login = bw.login.as_ref();
        let links = Links::sort(
            login
                .and_then(|l| l.uris.as_ref())
                .into_iter()
                .flatten()
                .filter_map(|u| u.uri.as_deref()),
        );
        let username = login.map(|l| text(&l.username)).unwrap_or_default();
        let fallback = format!("Imported {at}");
        let mut item = new_item(
            kind,
            text(&bw.name),
            &links.for_title(),
            username,
            &fallback,
        );
        let mut lost = false;
        let mut found_passkey = None;
        match kind {
            ItemKind::Login => {
                if let Some(l) = login {
                    lost |= !set(&mut item, "username", username);
                    lost |= !set(&mut item, "password", secret(&l.password));
                    if !set(&mut item, "totp", secret(&l.totp)) {
                        parsed.note(&at, "one-time password secret not recognised");
                    }
                    if !add_urls(&mut item, &links.web) {
                        parsed.note(&at, "a URL was not valid, left out");
                    }
                    if links.dropped() {
                        parsed.note(&at, LINK_LEFT_OUT);
                    }
                    found_passkey = passkey_of(
                        &mut parsed,
                        &at,
                        l.fido2_credentials.as_deref().unwrap_or_default(),
                        username,
                        bw.revision_date.as_deref().and_then(rfc3339_ms),
                    );
                }
            }
            ItemKind::Card => {
                if let Some(c) = &bw.card {
                    lost |= !set(&mut item, "cardholder", text(&c.cardholder_name));
                    lost |= !set(&mut item, "number", secret(&c.number));
                    lost |= !set(&mut item, "cvv", secret(&c.code));
                    if let (Some(m), Some(y)) = (&c.exp_month, &c.exp_year) {
                        let (m, y) = (m.trim(), y.trim());
                        let y = if y.len() == 2 {
                            format!("20{y}")
                        } else {
                            y.to_owned()
                        };
                        if let Ok(m) = m.parse::<u8>() {
                            lost |= !set(&mut item, "expiry", &format!("{y}-{m:02}"));
                        }
                    }
                    lost |= !add(&mut item, "Brand", FieldKind::Text, text(&c.brand));
                }
            }
            ItemKind::Identity => {
                if let Some(i) = &bw.identity {
                    let address: Vec<&str> = [&i.address1, &i.address2, &i.address3]
                        .into_iter()
                        .map(text)
                        .filter(|s| !s.trim().is_empty())
                        .collect();
                    for (field, value) in [
                        ("first_name", text(&i.first_name)),
                        ("last_name", text(&i.last_name)),
                        ("email", text(&i.email)),
                        ("phone", text(&i.phone)),
                        ("address", &address.join(", ")),
                        ("city", text(&i.city)),
                        ("region", text(&i.state)),
                        ("postal_code", text(&i.postal_code)),
                        ("country", text(&i.country)),
                    ] {
                        lost |= !set(&mut item, field, value);
                    }
                    for (label, kind, value) in [
                        ("Title", FieldKind::Text, text(&i.title)),
                        ("Middle name", FieldKind::Text, text(&i.middle_name)),
                        ("Company", FieldKind::Text, text(&i.company)),
                        ("Username", FieldKind::Text, text(&i.username)),
                        (
                            "Social security number",
                            FieldKind::Concealed,
                            secret(&i.ssn),
                        ),
                        (
                            "Passport number",
                            FieldKind::Concealed,
                            secret(&i.passport_number),
                        ),
                        (
                            "License number",
                            FieldKind::Concealed,
                            secret(&i.license_number),
                        ),
                    ] {
                        lost |= !add(&mut item, label, kind, value);
                    }
                }
            }
            ItemKind::SshKey => {
                if let Some(k) = &bw.ssh_key {
                    lost |= !set(&mut item, "private_key", secret(&k.private_key));
                    lost |= !set(&mut item, "public_key", text(&k.public_key));
                    lost |= !set(&mut item, "fingerprint", text(&k.key_fingerprint));
                }
            }
            _ => {}
        }
        for f in bw.fields.iter().flatten() {
            let kind = match f.kind {
                0 | 2 => FieldKind::Text,
                1 => FieldKind::Concealed,
                // Linked fields point at another field of the item.
                _ => continue,
            };
            let label = text(&f.name);
            let label = if label.trim().is_empty() {
                "Field"
            } else {
                label
            };
            lost |= !add(&mut item, label, kind, secret(&f.value));
        }
        if lost {
            parsed.note(&at, "a field was not valid, left out");
        }
        if !secret(&bw.notes).is_empty() {
            item.set_notes(Some(secret(&bw.notes)));
        }
        if let Some(folder) = bw.folder_id.as_deref().and_then(|id| folders.get(id))
            && !add_tags(&mut item, [*folder])
        {
            parsed.note(&at, "the folder name was not a valid tag");
        }
        let mut entry = Entry::new(item, at);
        entry.modified_ms = bw.revision_date.as_deref().and_then(rfc3339_ms);
        entry.passkey = found_passkey;
        entry.history = bw
            .password_history
            .iter()
            .flatten()
            .filter(|h| !secret(&h.password).is_empty())
            .map(|h| OldPassword {
                value: SecretValue::new(secret(&h.password)),
                until_ms: h.last_used_date.as_deref().and_then(rfc3339_ms),
            })
            .collect();
        parsed.push(entry)?;
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use klav_core::model::item::FieldValue;

    use super::*;

    const EXPORT: &str = r#"{
      "encrypted": false,
      "folders": [{"id": "f1", "name": "Work"}],
      "items": [
        {"id": "a", "type": 1, "name": "Example", "folderId": "f1", "notes": "hello",
         "revisionDate": "2024-05-01T10:20:30.123Z", "deletedDate": null,
         "passwordHistory": [{"lastUsedDate": "2024-01-01T00:00:00.000Z", "password": "old-1"}],
         "fields": [{"name": "PIN", "value": "1234", "type": 1}, {"name": "L", "value": null, "type": 3, "linkedId": 100}],
         "login": {"uris": [{"match": null, "uri": "https://example.com/login"}],
                   "username": "ana@example.com", "password": "new-pw", "totp": "JBSWY3DPEHPK3PXP",
                   "fido2Credentials": [{"credentialId": "x", "keyValue": "y"}]}},
        {"id": "b", "type": 2, "name": "Wifi", "notes": "the key", "secureNote": {"type": 0}},
        {"id": "c", "type": 3, "name": "Visa", "card": {"cardholderName": "Ana", "brand": "Visa",
          "number": "4111111111111111", "expMonth": "7", "expYear": "2031", "code": "123"}},
        {"id": "d", "type": 4, "name": "Me", "identity": {"firstName": "Ana", "lastName": "Pérez",
          "address1": "Calle 1", "address2": "Depto 2", "city": "CDMX", "ssn": "000"}},
        {"id": "e", "type": 5, "name": "Server", "sshKey": {"privateKey": "-----BEGIN-----\nk\n-----END-----",
          "publicKey": "ssh-ed25519 AAA", "keyFingerprint": "SHA256:x"}},
        {"id": "f", "type": 1, "name": "Gone", "deletedDate": "2024-02-02T00:00:00Z", "login": {}}
      ]
    }"#;

    fn value(entry: &Entry, field: &str) -> String {
        match entry.item.field(field).unwrap().value() {
            FieldValue::Secret(s) => s.expose().to_owned(),
            FieldValue::Plain(s) => s.clone(),
            FieldValue::File(_) => String::new(),
        }
    }

    #[test]
    fn reads_every_kind() {
        let p = parse(EXPORT).unwrap();
        assert_eq!(p.entries.len(), 5);
        assert_eq!(p.passkeys, 1);
        assert_eq!(p.skipped.len(), 1);
        assert_eq!(p.skipped[0].reason, "in Bitwarden's trash");
        let login = &p.entries[0];
        assert_eq!(login.item.title(), "Example");
        assert!(login.item.has_tag("Work"));
        assert_eq!(value(login, "password"), "new-pw");
        assert_eq!(value(login, "totp"), "JBSWY3DPEHPK3PXP");
        assert_eq!(value(login, "pin"), "1234");
        assert_eq!(login.item.urls(), ["https://example.com/login"]);
        assert_eq!(login.modified_ms, Some(1_714_558_830_123));
        assert_eq!(login.history.len(), 1);
        assert_eq!(login.history[0].value.expose(), "old-1");
        assert_eq!(p.entries[1].item.kind(), ItemKind::Note);
        assert_eq!(value(&p.entries[2], "expiry"), "2031-07");
        assert_eq!(value(&p.entries[3], "address"), "Calle 1, Depto 2");
        assert_eq!(value(&p.entries[3], "social_security_number"), "000");
        assert!(value(&p.entries[4], "private_key").contains('\n'));
    }

    #[test]
    fn a_counted_passkey_is_imported_with_a_warning_that_says_what_to_do() {
        let key = crate::samples::SAMPLE_PASSKEY_KEY;
        let json = format!(
            r#"{{"items": [{{"type": 1, "name": "Shop", "login": {{"username": "ana",
                "uris": [{{"uri": "https://shop.example.com"}}],
                "fido2Credentials": [
                  {{"credentialId": "b64.YQ", "keyValue": "{key}", "rpId": "shop.example.com",
                    "userHandle": "dQ", "counter": "7"}},
                  {{"credentialId": "b64.Yg", "keyValue": "{key}", "rpId": "shop.example.com",
                    "userHandle": "dQ", "counter": "0"}}]}}}}]}}"#
        );
        let p = parse(&json).unwrap();
        // The first one goes in; the second is counted as not imported.
        assert_eq!(p.passkeys, 1);
        let imported = p.entries[0].passkey.as_ref().expect("imported");
        assert_eq!(imported.credential_id(), b"a");
        let reasons: Vec<&str> = p.notes.iter().map(|n| n.reason.as_str()).collect();
        assert_eq!(reasons, [passkey::COUNTED, passkey::ONE_PER_LOGIN]);
        assert!(passkey::COUNTED.contains("register a new passkey for that site in Klav"));
    }

    #[test]
    fn refuses_encrypted_exports() {
        let err = parse(r#"{"encrypted": true, "encKeyValidation_DO_NOT_EDIT": "x", "data": "y"}"#)
            .err()
            .unwrap();
        assert!(matches!(err, ImportError::Encrypted(_)));
        assert!(parse(r#"{"passwordProtected": true, "salt": "x"}"#).is_err());
        assert!(parse(r#"{"other": 1}"#).is_err());
    }

    #[test]
    fn a_flood_of_items_stops_while_reading() {
        // `{"type":0}` is ten bytes; 20 million of them are 200 MB of text
        // and, as items, many times that. Two million spend the budget.
        let items = vec![r#"{"type":0}"#; 2_000_000].join(",");
        let json = format!(r#"{{"items": [{items}]}}"#);
        assert_eq!(parse(&json).err(), Some(crate::limits::too_many_parts()));
        // Under the budget, the count of entries still holds while reading.
        let items = vec![r#"{"type":2,"notes":"n"}"#; crate::MAX_ENTRIES + 1].join(",");
        let json = format!(r#"{{"items": [{items}]}}"#);
        assert_eq!(parse(&json).err(), Some(crate::limits::too_many_entries()));
    }

    #[test]
    fn only_web_links_are_imported() {
        let p = parse(
            r#"{"items": [{"type": 1, "name": "", "login": {"username": "ana", "uris": [
                {"uri": "javascript://github.com/%0aalert(1)"},
                {"uri": "androidapp://com.example.app"},
                {"uri": "https://example.com"}]}}]}"#,
        )
        .unwrap();
        let e = &p.entries[0];
        assert_eq!(e.item.urls(), ["https://example.com"]);
        assert_eq!(e.item.title(), "example.com");
        assert_eq!(p.notes[0].reason, LINK_LEFT_OUT);
    }
}
