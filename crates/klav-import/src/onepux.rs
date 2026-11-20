//! 1Password's `.1pux` export: a ZIP whose `export.data` is JSON with the
//! accounts, their vaults and the items. Attachments (`files/`) are not
//! imported; each one is counted in the notes.

use klav_core::model::Item;
use klav_core::model::item::{FieldKind, ItemKind, SecretValue};
use serde::Deserialize;
use serde::de::{Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use zeroize::Zeroizing;

use crate::date::ymd;
use crate::fields::{LINK_LEFT_OUT, Links, add, add_tags, add_urls, new_item, set, web_url};
use crate::limits::{JSON_BUDGET, capped, spend_one, with_budget};
use crate::{Entry, Format, ImportError, MAX_EXPORT_DATA, OldPassword, Parsed, zip};

#[derive(Deserialize)]
struct Export {
    #[serde(default, deserialize_with = "capped")]
    accounts: Vec<Account>,
}

#[derive(Deserialize)]
struct Account {
    #[serde(default, deserialize_with = "capped")]
    vaults: Vec<Vault>,
}

#[derive(Deserialize)]
struct Vault {
    #[serde(default)]
    attrs: VaultAttrs,
    #[serde(default, deserialize_with = "capped")]
    items: Vec<OpItem>,
}

#[derive(Deserialize, Default)]
struct VaultAttrs {
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpItem {
    #[serde(default)]
    category_uuid: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    updated_at: Option<i64>,
    #[serde(default)]
    details: Details,
    #[serde(default)]
    overview: Overview,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Details {
    #[serde(default, deserialize_with = "capped")]
    login_fields: Vec<LoginField>,
    #[serde(default)]
    notes_plain: Option<Zeroizing<String>>,
    #[serde(default, deserialize_with = "capped")]
    sections: Vec<Section>,
    #[serde(default, deserialize_with = "capped")]
    password_history: Vec<PasswordHistory>,
    #[serde(default)]
    password: Option<Zeroizing<String>>,
    #[serde(default)]
    passkey: Option<IgnoredAny>,
    #[serde(default)]
    document_attributes: Option<IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginField {
    #[serde(default)]
    value: Zeroizing<String>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    field_type: String,
    #[serde(default)]
    designation: String,
}

#[derive(Deserialize)]
struct Section {
    #[serde(default)]
    title: String,
    #[serde(default, deserialize_with = "capped")]
    fields: Vec<SectionField>,
}

#[derive(Deserialize)]
struct SectionField {
    #[serde(default)]
    title: String,
    #[serde(default)]
    id: String,
    /// One key naming the type (`concealed`, `string`, `totp`…).
    #[serde(default)]
    value: Value,
}

/// A JSON value of a section field. Read by hand rather than into
/// `serde_json::Value`, so its text (a password, a card number, an SSH
/// key) is wiped on drop and its maps count against the parse budget. Not
/// `Debug`.
#[derive(Default)]
enum Value {
    Text(Zeroizing<String>),
    Int(i64),
    /// Other numbers, as written by `to_string`.
    Number(Zeroizing<String>),
    Bool(bool),
    /// Keys in the order of the file.
    Object(Vec<(String, Value)>),
    /// `null` and lists, which no field kind uses.
    #[default]
    Other,
}

impl Value {
    fn as_str(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    /// The value of `key`; the last one if it repeats, as `serde_json`.
    fn get(&self, key: &str) -> Option<&Value> {
        self.as_object()?
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Value;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a field value")
            }

            fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
                Ok(Value::Bool(v))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
                Ok(Value::Int(v))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
                Ok(i64::try_from(v)
                    .map_or_else(|_| Value::Number(Zeroizing::new(v.to_string())), Value::Int))
            }

            fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
                Ok(Value::Number(Zeroizing::new(v.to_string())))
            }

            fn visit_str<E>(self, v: &str) -> Result<Value, E> {
                Ok(Value::Text(Zeroizing::new(v.to_owned())))
            }

            fn visit_string<E>(self, v: String) -> Result<Value, E> {
                Ok(Value::Text(Zeroizing::new(v)))
            }

            fn visit_unit<E>(self) -> Result<Value, E> {
                Ok(Value::Other)
            }

            fn visit_none<E>(self) -> Result<Value, E> {
                Ok(Value::Other)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Value::Other)
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut out = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !spend_one(size_of::<(String, Value)>()) {
                        return Err(serde::de::Error::custom("too many elements"));
                    }
                    let value = map.next_value::<Value>()?;
                    out.push((key, value));
                }
                Ok(Value::Object(out))
            }
        }
        d.deserialize_any(V)
    }
}

#[derive(Deserialize)]
struct PasswordHistory {
    #[serde(default)]
    value: Zeroizing<String>,
    #[serde(default)]
    time: Option<i64>,
}

#[derive(Deserialize, Default)]
struct Overview {
    #[serde(default)]
    title: String,
    #[serde(default)]
    url: String,
    #[serde(default, deserialize_with = "capped")]
    urls: Vec<OverviewUrl>,
    #[serde(default, deserialize_with = "capped")]
    tags: Vec<String>,
}

#[derive(Deserialize)]
struct OverviewUrl {
    #[serde(default)]
    url: String,
}

/// A section field's value as `(kind, text)`; `None` for kinds Klav does
/// not keep (references, files).
fn field_value(value: &Value) -> Option<(&'static str, Zeroizing<String>)> {
    let (key, inner) = value.as_object()?.first()?;
    let s = |v: &Value| Zeroizing::new(v.as_str().unwrap_or_default().to_owned());
    Some(match key.as_str() {
        "concealed" | "creditCardNumber" => ("concealed", s(inner)),
        "totp" => ("totp", s(inner)),
        "url" => ("url", s(inner)),
        "phone" => ("phone", s(inner)),
        "email" => (
            "email",
            match inner {
                Value::Object(_) => s(inner.get("email_address").unwrap_or(&Value::Other)),
                v => s(v),
            },
        ),
        "date" => (
            "date",
            Zeroizing::new(inner.as_i64().map(ymd).unwrap_or_default()),
        ),
        "monthYear" => (
            "month_year",
            Zeroizing::new(
                inner
                    .as_i64()
                    .filter(|v| *v > 100_000)
                    .map(|v| format!("{:04}-{:02}", v / 100, v % 100))
                    .unwrap_or_default(),
            ),
        ),
        "address" => {
            inner.as_object()?;
            let part = |k: &str| inner.get(k).and_then(Value::as_str).unwrap_or_default();
            let joined: Vec<&str> = ["street", "city", "state", "zip", "country"]
                .into_iter()
                .map(part)
                .filter(|p| !p.trim().is_empty())
                .collect();
            ("address", Zeroizing::new(joined.join(", ")))
        }
        "sshKey" => (
            "ssh_key",
            Zeroizing::new(
                inner
                    .get("privateKey")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            ),
        ),
        "reference" | "file" => return None,
        _ => match inner {
            Value::Text(t) => ("string", t.clone()),
            Value::Int(i) => ("string", Zeroizing::new(i.to_string())),
            Value::Number(n) => ("string", n.clone()),
            Value::Bool(b) => ("string", Zeroizing::new(b.to_string())),
            Value::Object(_) | Value::Other => return None,
        },
    })
}

fn kind_of(field: &str) -> FieldKind {
    match field {
        "concealed" | "ssh_key" => FieldKind::Concealed,
        "totp" => FieldKind::Totp,
        "url" => FieldKind::Url,
        "phone" => FieldKind::Phone,
        "email" => FieldKind::Email,
        "date" => FieldKind::Date,
        "month_year" => FieldKind::MonthYear,
        _ => FieldKind::Text,
    }
}

/// Where a section field goes in Klav's template for `kind`, by 1Password's
/// field ID.
fn template_field(kind: ItemKind, id: &str, value_kind: &str) -> Option<&'static str> {
    Some(match (kind, id) {
        (ItemKind::Login, _) if value_kind == "totp" => "totp",
        (ItemKind::Card, "cardholder") => "cardholder",
        (ItemKind::Card, "ccnum") => "number",
        (ItemKind::Card, "cvv") => "cvv",
        (ItemKind::Card, "expiry") => "expiry",
        (ItemKind::Card, "pin") => "pin",
        (ItemKind::Identity, "firstname") => "first_name",
        (ItemKind::Identity, "lastname") => "last_name",
        (ItemKind::Identity, "email") => "email",
        (ItemKind::Identity, "defphone" | "cellphone") => "phone",
        (ItemKind::Identity, "birthdate") => "birth_date",
        (ItemKind::ApiKey, "credential") => "api_key",
        (ItemKind::ApiKey, "username") => "key_id",
        (ItemKind::ApiKey, "hostname") => "base_url",
        (ItemKind::ApiKey, "expires") => "expires",
        (ItemKind::SshKey, _) if value_kind == "ssh_key" => "private_key",
        _ => return None,
    })
}

fn set_or_add(item: &mut Item, kind: ItemKind, f: &SectionField, section: &str) -> bool {
    let Some((value_kind, value)) = field_value(&f.value) else {
        return true;
    };
    if value.trim().is_empty() {
        return true;
    }
    if kind == ItemKind::Identity && value_kind == "address" {
        // Identity addresses split into Klav's own fields.
        let Some(o) = f.value.get("address").filter(|o| o.as_object().is_some()) else {
            return false;
        };
        let part = |k: &str| o.get(k).and_then(Value::as_str).unwrap_or_default();
        return [
            ("address", part("street")),
            ("city", part("city")),
            ("region", part("state")),
            ("postal_code", part("zip")),
            ("country", part("country")),
        ]
        .into_iter()
        .all(|(field, v)| set(item, field, v));
    }
    // Links follow the item's rule: only http and https.
    let value = if value_kind == "url" {
        match web_url(&value) {
            Some(url) => Zeroizing::new(url),
            None => return false,
        }
    } else {
        value
    };
    if let Some(field) = template_field(kind, &f.id, value_kind)
        && item.field(field).is_some_and(|x| x.is_empty())
    {
        return set(item, field, &value);
    }
    let label = match (f.title.trim(), section.trim()) {
        ("", "") => f.id.as_str(),
        ("", s) => s,
        (t, _) => t,
    };
    add(item, label, kind_of(value_kind), &value)
}

pub(crate) fn parse(archive: &[u8]) -> Result<Parsed, ImportError> {
    let data = zip::read_entry(archive, "export.data", MAX_EXPORT_DATA)?.ok_or_else(|| {
        ImportError::NotRecognised("a ZIP file without 1Password's export.data".into())
    })?;
    let (export, spent) = with_budget(JSON_BUDGET, || serde_json::from_slice::<Export>(&data));
    let export = export.map_err(|e| {
        if spent {
            return crate::limits::too_many_parts();
        }
        ImportError::Invalid(format!(
            "damaged .1pux file (export.data, line {}, column {})",
            e.line(),
            e.column()
        ))
    })?;
    let mut parsed = Parsed::new(Format::OnePassword);
    let vaults: Vec<&Vault> = export.accounts.iter().flat_map(|a| &a.vaults).collect();
    let tag_vaults = vaults.len() > 1;
    let mut n = 0;
    for vault in vaults {
        for op in &vault.items {
            n += 1;
            let at = format!("item {n}");
            if op.state == "deleted" {
                parsed.skip(&at, "in 1Password's trash");
                continue;
            }
            let kind = match op.category_uuid.as_str() {
                "001" | "005" => ItemKind::Login,
                "002" => ItemKind::Card,
                "004" => ItemKind::Identity,
                "112" => ItemKind::ApiKey,
                "114" => ItemKind::SshKey,
                _ => ItemKind::Note,
            };
            let d = &op.details;
            let mut urls: Vec<&str> = op
                .overview
                .urls
                .iter()
                .map(|u| u.url.as_str())
                .filter(|u| !u.trim().is_empty())
                .collect();
            if urls.is_empty() && !op.overview.url.trim().is_empty() {
                urls.push(&op.overview.url);
            }
            let links = Links::sort(urls);
            let username = d
                .login_fields
                .iter()
                .find(|f| f.designation == "username")
                .map(|f| f.value.as_str())
                .unwrap_or_default();
            let mut item = new_item(
                kind,
                &op.overview.title,
                &links.for_title(),
                username,
                &format!("Imported {at}"),
            );
            let mut lost = false;
            if kind == ItemKind::Login {
                lost |= !set(&mut item, "username", username);
                let password = d
                    .login_fields
                    .iter()
                    .find(|f| f.designation == "password")
                    .map(|f| f.value.as_str())
                    .or(d.password.as_deref().map(String::as_str))
                    .unwrap_or_default();
                lost |= !set(&mut item, "password", password);
                for f in d.login_fields.iter().filter(|f| f.designation.is_empty()) {
                    // Other form fields 1Password saved with the login;
                    // checkboxes and buttons carry nothing worth keeping.
                    let kind = match f.field_type.as_str() {
                        "P" => FieldKind::Concealed,
                        "T" | "E" | "U" => FieldKind::Text,
                        _ => continue,
                    };
                    let label = if f.name.trim().is_empty() {
                        "Form field"
                    } else {
                        &f.name
                    };
                    lost |= !add(&mut item, label, kind, &f.value);
                }
                if !add_urls(&mut item, &links.web) {
                    parsed.note(&at, "a URL was not valid, left out");
                }
            } else if let Some(url) = links.web.first() {
                lost |= !add(&mut item, "Website", FieldKind::Url, url);
            }
            if links.dropped() {
                parsed.note(&at, LINK_LEFT_OUT);
            }
            for section in &d.sections {
                for f in &section.fields {
                    lost |= !set_or_add(&mut item, kind, f, &section.title);
                }
            }
            if lost {
                parsed.note(&at, "a field was not valid, left out");
            }
            if d.document_attributes.is_some() {
                parsed.note(&at, "the attached document was not imported");
            }
            if d.passkey.is_some() {
                parsed.passkeys += 1;
            }
            if let Some(notes) = d.notes_plain.as_ref().filter(|n| !n.trim().is_empty()) {
                item.set_notes(Some(notes));
            }
            let mut tags: Vec<&str> = op.overview.tags.iter().map(String::as_str).collect();
            if tag_vaults {
                tags.push(&vault.attrs.name);
            }
            if op.state == "archived" {
                tags.push("archived");
            }
            if !add_tags(&mut item, tags) {
                parsed.note(&at, "a tag was not valid");
            }
            let mut entry = Entry::new(item, at);
            // Seconds in the file; a time beyond what ms can hold is
            // dropped rather than wrapped.
            entry.modified_ms = op
                .updated_at
                .filter(|t| *t > 0)
                .and_then(|t| t.checked_mul(1000));
            entry.history = d
                .password_history
                .iter()
                .filter(|h| !h.value.is_empty())
                .map(|h| OldPassword {
                    value: SecretValue::new(h.value.as_str()),
                    until_ms: h.time.and_then(|t| t.checked_mul(1000)),
                })
                .collect();
            parsed.push(entry)?;
        }
    }
    Ok(parsed)
}

#[cfg(test)]
pub(crate) mod tests {
    use klav_core::model::item::FieldValue;

    use super::*;

    // Section field values hold passwords, card numbers and SSH keys.
    static_assertions::assert_not_impl_any!(Value: std::fmt::Debug);
    static_assertions::assert_not_impl_any!(SectionField: std::fmt::Debug);

    pub(crate) const EXPORT_DATA: &str = r#"{"accounts": [{"attrs": {"name": "Ana"}, "vaults": [
      {"attrs": {"uuid": "v1", "name": "Private"}, "items": [
        {"uuid": "i1", "categoryUuid": "001", "state": "active", "updatedAt": 1714558830,
         "details": {"loginFields": [
             {"value": "ana@example.com", "name": "email", "fieldType": "E", "designation": "username"},
             {"value": "pw-1p", "name": "password", "fieldType": "P", "designation": "password"},
             {"value": "", "name": "remember", "fieldType": "C"}],
           "notesPlain": "note",
           "sections": [{"title": "", "fields": [
             {"title": "one-time password", "id": "TOTP_x", "value": {"totp": "otpauth://totp/Example:ana?secret=JBSWY3DPEHPK3PXP"}},
             {"title": "recovery code", "id": "r", "value": {"concealed": "abc-def"}}]}],
           "passwordHistory": [{"value": "older-1p", "time": 1700000000}],
           "passkey": {"credentialId": "x", "rpId": "example.com"}},
         "overview": {"title": "Example", "url": "https://example.com", "urls": [{"label": "", "url": "https://example.com/login"}], "tags": ["web"]}},
        {"uuid": "i2", "categoryUuid": "002", "state": "archived",
         "details": {"sections": [{"title": "", "fields": [
             {"title": "cardholder name", "id": "cardholder", "value": {"string": "Ana"}},
             {"title": "number", "id": "ccnum", "value": {"creditCardNumber": "4111111111111111"}},
             {"title": "expiry date", "id": "expiry", "value": {"monthYear": 203107}}]}]},
         "overview": {"title": "Visa"}},
        {"uuid": "i3", "categoryUuid": "006", "state": "active",
         "details": {"documentAttributes": {"fileName": "a.pdf"}}, "overview": {"title": "Scan"}}
      ]},
      {"attrs": {"uuid": "v2", "name": "Shared"}, "items": [
        {"uuid": "i4", "categoryUuid": "004", "state": "active",
         "details": {"sections": [{"title": "Identification", "fields": [
             {"title": "first name", "id": "firstname", "value": {"string": "Ana"}},
             {"title": "birth date", "id": "birthdate", "value": {"date": 631152000}},
             {"title": "address", "id": "address", "value": {"address": {"street": "Calle 1", "city": "CDMX", "country": "mx", "zip": "01000", "state": ""}}}]}]},
         "overview": {"title": "Me"}},
        {"uuid": "i5", "categoryUuid": "005", "state": "active",
         "details": {"password": "only-password"}, "overview": {"title": "Router", "url": "http://192.168.1.1"}}
      ]}
    ]}]}"#;

    fn value(entry: &Entry, field: &str) -> String {
        match entry.item.field(field).unwrap().value() {
            FieldValue::Secret(s) => s.expose().to_owned(),
            FieldValue::Plain(s) => s.clone(),
            FieldValue::File(_) => String::new(),
        }
    }

    pub(crate) fn sample() -> Vec<u8> {
        zip::tests::build(&[
            ("export.attributes", b"{\"version\":3}", false),
            ("export.data", EXPORT_DATA.as_bytes(), true),
        ])
    }

    #[test]
    fn reads_a_1pux() {
        let p = parse(&sample()).unwrap();
        assert_eq!(p.entries.len(), 5);
        assert_eq!(p.passkeys, 1);
        let login = &p.entries[0];
        assert_eq!(value(login, "username"), "ana@example.com");
        assert_eq!(value(login, "password"), "pw-1p");
        assert!(value(login, "totp").starts_with("otpauth://"));
        assert_eq!(value(login, "recovery_code"), "abc-def");
        assert_eq!(login.item.urls(), ["https://example.com/login"]);
        assert!(login.item.has_tag("web") && login.item.has_tag("Private"));
        assert_eq!(login.modified_ms, Some(1_714_558_830_000));
        assert_eq!(login.history[0].value.expose(), "older-1p");
        let card = &p.entries[1];
        assert_eq!(card.item.kind(), ItemKind::Card);
        assert_eq!(value(card, "number"), "4111111111111111");
        assert_eq!(value(card, "expiry"), "2031-07");
        assert!(card.item.has_tag("archived"));
        assert_eq!(p.entries[2].item.kind(), ItemKind::Note);
        assert!(p.notes.iter().any(|n| n.at == "item 3"));
        let me = &p.entries[3];
        assert_eq!(value(me, "birth_date"), "1990-01-01");
        assert_eq!(value(me, "city"), "CDMX");
        assert!(me.item.has_tag("Shared"));
        assert_eq!(value(&p.entries[4], "password"), "only-password");
    }

    fn one_item(item: &str) -> Vec<u8> {
        let data = format!(r#"{{"accounts": [{{"vaults": [{{"items": [{item}]}}]}}]}}"#);
        zip::tests::build(&[("export.data", data.as_bytes(), true)])
    }

    #[test]
    fn extreme_times_do_not_wrap() {
        // `t * 1000` wraps in release (and panics in debug) past
        // i64::MAX / 1000.
        let p = parse(&one_item(&format!(
            r#"{{"categoryUuid": "001", "updatedAt": {}, "overview": {{"title": "T"}},
                "details": {{"passwordHistory": [{{"value": "old", "time": {}}}, {{"value": "older", "time": {}}}]}}}}"#,
            i64::MAX,
            i64::MIN,
            i64::MAX / 1000 + 1,
        )))
        .unwrap();
        let e = &p.entries[0];
        assert_eq!(e.modified_ms, None);
        assert_eq!(e.history.len(), 2);
        assert!(e.history.iter().all(|h| h.until_ms.is_none()));
    }

    #[test]
    fn only_web_links_are_imported() {
        let p = parse(&one_item(
            r#"{"categoryUuid": "001", "overview": {"urls": [
                {"url": "javascript://github.com/%0aalert(document.cookie)"},
                {"url": "https://example.com"}]},
              "details": {"sections": [{"fields": [
                {"title": "site", "id": "s", "value": {"url": "data:text/html,x"}},
                {"title": "home", "id": "h", "value": {"url": "example.org"}}]}]}}"#,
        ))
        .unwrap();
        let e = &p.entries[0];
        assert_eq!(e.item.urls(), ["https://example.com"]);
        assert_eq!(e.item.title(), "example.com");
        assert_eq!(value(e, "home"), "https://example.org");
        assert!(e.item.field("site").is_none());
        let reasons: Vec<&str> = p.notes.iter().map(|n| n.reason.as_str()).collect();
        assert!(
            reasons.contains(&crate::fields::LINK_LEFT_OUT),
            "{reasons:?}"
        );
        // A javascript: link alone no longer names the item after its host.
        let p = parse(&one_item(
            r#"{"categoryUuid": "001", "overview": {"url": "javascript://github.com/x"}}"#,
        ))
        .unwrap();
        assert_eq!(p.entries[0].item.title(), "Imported item 1");
        assert!(p.entries[0].item.urls().is_empty());
    }

    #[test]
    fn a_flood_of_empty_items_stops_while_reading() {
        // 12 MiB of `{}`: four million items, gigabytes once parsed.
        let items = vec!["{}"; 4_000_000].join(",");
        let err = parse(&one_item(&items)).err().unwrap();
        assert_eq!(err, crate::limits::too_many_parts());
        // A field value's keys count too.
        let keys: Vec<String> = (0..1000).map(|i| format!("\"k{i}\": 1")).collect();
        let field = format!(r#"{{"value": {{"x": {{{}}}}}}}"#, keys.join(","));
        let size = size_of::<(String, Value)>();
        let (ok, spent) = with_budget(1001 * size, || serde_json::from_str::<SectionField>(&field));
        assert!(ok.is_ok() && !spent);
        let (err, spent) =
            with_budget(1000 * size, || serde_json::from_str::<SectionField>(&field));
        assert!(err.is_err() && spent);
    }

    #[test]
    fn field_values_keep_their_kinds() {
        let p = parse(&one_item(
            r#"{"categoryUuid": "006", "overview": {"title": "N"}, "details": {"sections": [{"fields": [
                {"title": "big", "id": "b", "value": {"string": 18446744073709551615}},
                {"title": "pi", "id": "p", "value": {"string": 3.5}},
                {"title": "yes", "id": "y", "value": {"string": true}},
                {"title": "mail", "id": "m", "value": {"email": {"email_address": "a@example.com", "provider": null}}},
                {"title": "list", "id": "l", "value": {"string": [1, 2]}},
                {"title": "escaped", "id": "e", "value": {"concealed": "a\"b\u00e9"}}]}]}}"#,
        ))
        .unwrap();
        let e = &p.entries[0];
        assert_eq!(value(e, "big"), "18446744073709551615");
        assert_eq!(value(e, "pi"), "3.5");
        assert_eq!(value(e, "yes"), "true");
        assert_eq!(value(e, "mail"), "a@example.com");
        assert!(e.item.field("list").is_none());
        assert_eq!(value(e, "escaped"), "a\"bé");
    }

    #[test]
    fn refuses_other_zips() {
        let other = zip::tests::build(&[("readme.txt", b"hi", false)]);
        assert!(matches!(parse(&other), Err(ImportError::NotRecognised(_))));
    }
}
