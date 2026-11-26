//! Stable references `klav://<vault>/<project>/<item>/<field>` (design §3).
//!
//! Each segment is either a **name** (matched case-insensitively) or an
//! **ID** (canonical UUID), so references survive renames when written with
//! IDs: `klav://trabajo/acme-api/stripe/api_key`.
//!
//! Rules:
//! * the scheme is `klav://` (case-insensitive);
//! * exactly four non-empty segments; no query string or fragment;
//! * segments are percent-decoded as UTF-8 and may not contain control
//!   characters; a decoded segment shaped like a UUID is an ID;
//! * the field segment, when a name, must be a valid field name
//!   ([`validate_field_name`]) or a valid variable name
//!   ([`validate_variable_name`]): in an `environment` item the fourth
//!   segment names a variable, case-sensitively (ADR 0032 §1), and
//!   [`resolve_variable`] finds it; in any other item it names a field
//!   ([`resolve_field`]).
//!
//! Names are displayed as people wrote them (`klav://Mi bóveda/…`): only
//! `%`, `/`, `?`, `#`, control characters and whitespace at either end of a
//! name are percent-encoded. Both that form and the fully encoded one
//! (`Mi%20b%C3%B3veda`) parse to the same reference.

use std::fmt;
use std::str::FromStr;

use percent_encoding::percent_decode_str;
use thiserror::Error;

use super::environment::{Variable, validate_variable_name};
use super::item::{Field, Item, ItemKind, validate_field_name};
use crate::ids::{FieldId, ItemId, ProjectId, VaultId, looks_like_id};

/// Scheme prefix.
pub const SCHEME: &str = "klav://";
/// Maximum length of a reference, in bytes.
pub const MAX_REFERENCE_LEN: usize = 2048;

/// Level of the hierarchy a segment refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Level {
    /// Vault.
    Vault,
    /// Project.
    Project,
    /// Item.
    Item,
    /// Field.
    Field,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Level::Vault => "vault",
            Level::Project => "project",
            Level::Item => "item",
            Level::Field => "field",
        })
    }
}

/// Errors parsing or resolving a reference.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReferenceError {
    /// Missing `klav://`.
    #[error("a reference must start with klav://")]
    Scheme,
    /// Not exactly four segments.
    #[error("a reference must have 4 segments (vault/project/item/field), found {0}")]
    SegmentCount(usize),
    /// A segment is empty.
    #[error("empty {0} segment")]
    EmptySegment(Level),
    /// Bad percent-encoding, non-UTF-8 or control characters.
    #[error("invalid {0} segment")]
    InvalidSegment(Level),
    /// `?` or `#` present.
    #[error("query strings and fragments are not allowed in references")]
    QueryOrFragment,
    /// Longer than [`MAX_REFERENCE_LEN`].
    #[error("reference too long")]
    TooLong,
    /// Nothing matches the segment.
    #[error("{0} not found")]
    NotFound(Level),
    /// Several entries share the name.
    #[error("{level} name {name:?} matches {count} entries; use its ID")]
    Ambiguous {
        /// Level of the ambiguous segment.
        level: Level,
        /// The ambiguous name.
        name: String,
        /// Number of matches.
        count: usize,
    },
}

/// A segment: by ID or by name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Selector<I> {
    /// Stable ID.
    Id(I),
    /// Name, matched case-insensitively.
    Name(String),
}

impl<I: fmt::Display> serde::Serialize for Selector<I> {
    /// IDs as canonical UUIDs, names as plain text.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Selector::Id(id) => serializer.collect_str(id),
            Selector::Name(name) => serializer.serialize_str(name),
        }
    }
}

impl<'de, I: FromStr> serde::Deserialize<'de> for Selector<I> {
    /// Text shaped like a UUID is an ID; anything else non-blank is a name.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if looks_like_id(&text) {
            return text
                .parse()
                .map(Selector::Id)
                .map_err(|_| serde::de::Error::custom("invalid ID"));
        }
        if text.trim().is_empty() || text.chars().any(char::is_control) {
            return Err(serde::de::Error::custom("empty or invalid name"));
        }
        Ok(Selector::Name(text))
    }
}

/// A parsed `klav://` reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Reference {
    /// Vault segment.
    pub vault: Selector<VaultId>,
    /// Project segment.
    pub project: Selector<ProjectId>,
    /// Item segment.
    pub item: Selector<ItemId>,
    /// Field segment.
    pub field: Selector<FieldId>,
}

fn decode_segment(raw: &str, level: Level) -> Result<String, ReferenceError> {
    if raw.is_empty() {
        return Err(ReferenceError::EmptySegment(level));
    }
    let decoded = percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| ReferenceError::InvalidSegment(level))?;
    if decoded.chars().any(char::is_control) || has_bad_escape(raw) {
        return Err(ReferenceError::InvalidSegment(level));
    }
    if decoded.trim().is_empty() {
        return Err(ReferenceError::EmptySegment(level));
    }
    Ok(decoded.into_owned())
}

/// `%` not followed by two hex digits (`percent_decode_str` passes it through).
fn has_bad_escape(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.iter().enumerate().any(|(i, &b)| {
        b == b'%'
            && !(bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
    })
}

fn selector<I: FromStr>(raw: &str, level: Level) -> Result<Selector<I>, ReferenceError> {
    let decoded = decode_segment(raw, level)?;
    if looks_like_id(&decoded) {
        return decoded
            .parse()
            .map(Selector::Id)
            .map_err(|_| ReferenceError::InvalidSegment(level));
    }
    if level == Level::Field
        && validate_field_name(&decoded).is_err()
        && validate_variable_name(&decoded).is_err()
    {
        return Err(ReferenceError::InvalidSegment(level));
    }
    Ok(Selector::Name(decoded))
}

impl Reference {
    /// Parses a reference.
    pub fn parse(text: &str) -> Result<Self, ReferenceError> {
        if text.len() > MAX_REFERENCE_LEN {
            return Err(ReferenceError::TooLong);
        }
        let rest = text
            .get(..SCHEME.len())
            .filter(|scheme| scheme.eq_ignore_ascii_case(SCHEME))
            .map(|_| &text[SCHEME.len()..])
            .ok_or(ReferenceError::Scheme)?;
        if rest.contains(['?', '#']) {
            return Err(ReferenceError::QueryOrFragment);
        }
        let segments: Vec<&str> = rest.split('/').collect();
        let [vault, project, item, field] = segments.as_slice() else {
            return Err(ReferenceError::SegmentCount(segments.len()));
        };
        Ok(Self {
            vault: selector(vault, Level::Vault)?,
            project: selector(project, Level::Project)?,
            item: selector(item, Level::Item)?,
            field: selector(field, Level::Field)?,
        })
    }

    /// Resolves the vault, project and item against a catalog.
    pub fn resolve(&self, catalog: &impl Catalog) -> Result<ResolvedReference, ReferenceError> {
        let vault = pick(&self.vault, &catalog.vaults(), Level::Vault)?;
        let project = pick(&self.project, &catalog.projects(vault), Level::Project)?;
        let item = pick(&self.item, &catalog.items(vault, project), Level::Item)?;
        Ok(ResolvedReference {
            vault,
            project,
            item,
            field: self.field.clone(),
        })
    }
}

impl FromStr for Reference {
    type Err = ReferenceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

fn write_selector<I: fmt::Display>(
    f: &mut fmt::Formatter<'_>,
    selector: &Selector<I>,
) -> fmt::Result {
    match selector {
        Selector::Id(id) => write!(f, "{id}"),
        Selector::Name(name) => write_name(f, name),
    }
}

/// Writes a name segment as people wrote it: spaces, accents and any other
/// Unicode stay as they are. Only what would break parsing is
/// percent-encoded (`%XX` over its UTF-8 bytes):
/// * `%`, `/`, `?` and `#`;
/// * control and other invisible characters (`text::is_hidden`: zero-width
///   spaces, bidi overrides…), so two references never look the same;
/// * any whitespace other than a plain space, which reads like one;
/// * whitespace at either end of the name, because tools trim whole
///   references (`klav run`, `klav.toml`, templates) and would eat it.
fn write_name(out: &mut impl fmt::Write, name: &str) -> fmt::Result {
    let start = name.len() - name.trim_start().len();
    let end = name.trim_end().len();
    for (i, c) in name.char_indices() {
        let edge = i < start || i >= end;
        let unclear = crate::text::is_hidden(c) || (c.is_whitespace() && c != ' ');
        if edge || unclear || matches!(c, '%' | '/' | '?' | '#') {
            let mut buf = [0u8; 4];
            for byte in c.encode_utf8(&mut buf).bytes() {
                write!(out, "%{byte:02X}")?;
            }
        } else {
            out.write_char(c)?;
        }
    }
    Ok(())
}

/// Whether `a` and `b` are the same `klav://` path (any number of
/// segments) once each segment is percent-decoded, ignoring case like name
/// resolution does. `klav://Personal/General/Mi%20banco` and
/// `klav://personal/general/Mi banco` match; text that is not a
/// well-formed path never does.
pub fn same_path(a: &str, b: &str) -> bool {
    fn decoded(text: &str) -> Option<Vec<String>> {
        let text = text.trim();
        let rest = text
            .get(..SCHEME.len())
            .filter(|scheme| scheme.eq_ignore_ascii_case(SCHEME))
            .map(|_| &text[SCHEME.len()..])?;
        rest.split('/').map(decode_name).collect()
    }
    match (decoded(a), decoded(b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// Whether two segments name the same thing once percent-decoded,
/// ignoring case like name resolution does (`Mi%20banco` and `mi banco`).
pub fn same_name(a: &str, b: &str) -> bool {
    match (decode_name(a), decode_name(b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// A segment percent-decoded and lowercased, if it is well formed.
fn decode_name(raw: &str) -> Option<String> {
    decode_segment(raw, Level::Item)
        .ok()
        .map(|name| name.to_lowercase())
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(SCHEME)?;
        write_selector(f, &self.vault)?;
        f.write_str("/")?;
        write_selector(f, &self.project)?;
        f.write_str("/")?;
        write_selector(f, &self.item)?;
        f.write_str("/")?;
        write_selector(f, &self.field)
    }
}

/// An ID with its current name, as listed by a [`Catalog`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Named<I> {
    /// ID.
    pub id: I,
    /// Current name.
    pub name: String,
}

/// What a client knows about the names in its vaults (decrypted metadata).
pub trait Catalog {
    /// Vaults visible to the caller.
    fn vaults(&self) -> Vec<Named<VaultId>>;
    /// Projects of a vault.
    fn projects(&self, vault: VaultId) -> Vec<Named<ProjectId>>;
    /// Items of a project (name = item title).
    fn items(&self, vault: VaultId, project: ProjectId) -> Vec<Named<ItemId>>;
}

/// A reference whose vault, project and item are resolved to IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedReference {
    /// Vault.
    pub vault: VaultId,
    /// Project.
    pub project: ProjectId,
    /// Item.
    pub item: ItemId,
    /// Field, resolved once the item is decrypted ([`resolve_field`]).
    pub field: Selector<FieldId>,
}

fn pick<I: Copy + PartialEq>(
    selector: &Selector<I>,
    entries: &[Named<I>],
    level: Level,
) -> Result<I, ReferenceError> {
    match selector {
        Selector::Id(id) => entries
            .iter()
            .find(|e| e.id == *id)
            .map(|e| e.id)
            .ok_or(ReferenceError::NotFound(level)),
        Selector::Name(name) => {
            let wanted = name.to_lowercase();
            let matches: Vec<I> = entries
                .iter()
                .filter(|e| e.name.to_lowercase() == wanted)
                .map(|e| e.id)
                .collect();
            match matches.as_slice() {
                [id] => Ok(*id),
                [] => Err(ReferenceError::NotFound(level)),
                _ => Err(ReferenceError::Ambiguous {
                    level,
                    name: name.clone(),
                    count: matches.len(),
                }),
            }
        }
    }
}

/// Finds the referenced field in a decrypted item.
pub fn resolve_field<'a>(
    item: &'a Item,
    field: &Selector<FieldId>,
) -> Result<&'a Field, ReferenceError> {
    match field {
        Selector::Id(id) => item.field_by_id(*id),
        Selector::Name(name) => item.field(name),
    }
    .ok_or(ReferenceError::NotFound(Level::Field))
}

/// Finds the referenced variable in a decrypted `environment` item: by
/// exact, case-sensitive name (a variable has no ID). Any other kind has
/// no variables.
pub fn resolve_variable<'a>(
    item: &'a Item,
    variable: &Selector<FieldId>,
) -> Result<&'a Variable, ReferenceError> {
    match (item.kind(), item.environment(), variable) {
        (ItemKind::Environment, Some(environment), Selector::Name(name)) => {
            environment.variable(name)
        }
        _ => None,
    }
    .ok_or(ReferenceError::NotFound(Level::Field))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::model::item::{FieldKind, ItemKind};

    struct Fixture {
        trabajo: VaultId,
        personal: VaultId,
        acme: ProjectId,
        stripe: ItemId,
        dup_a: ItemId,
        dup_b: ItemId,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                trabajo: VaultId::generate(),
                personal: VaultId::generate(),
                acme: ProjectId::generate(),
                stripe: ItemId::generate(),
                dup_a: ItemId::generate(),
                dup_b: ItemId::generate(),
            }
        }
    }

    impl Catalog for Fixture {
        fn vaults(&self) -> Vec<Named<VaultId>> {
            vec![
                Named {
                    id: self.trabajo,
                    name: "Trabajo".into(),
                },
                Named {
                    id: self.personal,
                    name: "Personal".into(),
                },
            ]
        }

        fn projects(&self, vault: VaultId) -> Vec<Named<ProjectId>> {
            if vault == self.trabajo {
                vec![Named {
                    id: self.acme,
                    name: "acme-api".into(),
                }]
            } else {
                vec![]
            }
        }

        fn items(&self, _vault: VaultId, project: ProjectId) -> Vec<Named<ItemId>> {
            if project != self.acme {
                return vec![];
            }
            vec![
                Named {
                    id: self.stripe,
                    name: "Stripe".into(),
                },
                Named {
                    id: self.dup_a,
                    name: "Postgres".into(),
                },
                Named {
                    id: self.dup_b,
                    name: "postgres".into(),
                },
            ]
        }
    }

    #[test]
    fn parses_names_and_ids() {
        let r: Reference = "klav://trabajo/acme-api/stripe/api_key".parse().unwrap();
        assert_eq!(r.vault, Selector::Name("trabajo".into()));
        assert_eq!(r.field, Selector::Name("api_key".into()));
        assert_eq!(r.to_string(), "klav://trabajo/acme-api/stripe/api_key");

        let id = ItemId::generate();
        let r = Reference::parse(&format!("KLAV://trabajo/acme-api/{id}/password")).unwrap();
        assert_eq!(r.item, Selector::Id(id));

        let r =
            Reference::parse("klav://Mi%20b%C3%B3veda/a%2Fb/T%C3%ADtulo%20%231/password").unwrap();
        assert_eq!(r.vault, Selector::Name("Mi bóveda".into()));
        assert_eq!(r.project, Selector::Name("a/b".into()));
        assert_eq!(r.item, Selector::Name("Título #1".into()));
        assert_eq!(Reference::parse(&r.to_string()).unwrap(), r);
    }

    #[test]
    fn rejects_malformed_references() {
        use ReferenceError as E;
        let cases: &[(&str, ReferenceError)] = &[
            ("op://a/b/c/d", E::Scheme),
            ("klav:/a/b/c/d", E::Scheme),
            ("", E::Scheme),
            ("klav://a/b/c", E::SegmentCount(3)),
            ("klav://a/b/c/d/", E::SegmentCount(5)),
            ("klav://a/b/c/d/e", E::SegmentCount(5)),
            ("klav://a//c/d", E::EmptySegment(Level::Project)),
            ("klav://%20/b/c/d", E::EmptySegment(Level::Vault)),
            ("klav://a/b/c/d?x=1", E::QueryOrFragment),
            ("klav://a/b/c/d#x", E::QueryOrFragment),
            ("klav://a/b/%FF/d", E::InvalidSegment(Level::Item)),
            ("klav://a/b/%0A/d", E::InvalidSegment(Level::Item)),
            ("klav://a/b/50%/d", E::InvalidSegment(Level::Item)),
            ("klav://a/b/c/9KEY", E::InvalidSegment(Level::Field)),
            ("klav://a/b/c/api-KEY", E::InvalidSegment(Level::Field)),
            ("klav://a/b/c/api key", E::InvalidSegment(Level::Field)),
        ];
        for (text, expected) in cases {
            assert_eq!(
                Reference::parse(text).as_ref().err(),
                Some(expected),
                "{text}"
            );
        }
        assert_eq!(
            Reference::parse(&format!("klav://{}/b/c/d", "a".repeat(MAX_REFERENCE_LEN))).err(),
            Some(E::TooLong)
        );
    }

    #[test]
    fn resolves_by_name_and_id() {
        let fx = Fixture::new();
        let resolved = Reference::parse("klav://trabajo/ACME-API/stripe/api_key")
            .unwrap()
            .resolve(&fx)
            .unwrap();
        assert_eq!(
            (resolved.vault, resolved.project, resolved.item),
            (fx.trabajo, fx.acme, fx.stripe)
        );

        let by_id = Reference::parse(&format!(
            "klav://{}/{}/{}/api_key",
            fx.trabajo, fx.acme, fx.dup_b
        ))
        .unwrap()
        .resolve(&fx)
        .unwrap();
        assert_eq!(by_id.item, fx.dup_b);

        let err = |s: &str| Reference::parse(s).unwrap().resolve(&fx).unwrap_err();
        assert_eq!(
            err("klav://nope/acme-api/stripe/x"),
            ReferenceError::NotFound(Level::Vault)
        );
        assert_eq!(
            err("klav://personal/acme-api/stripe/x"),
            ReferenceError::NotFound(Level::Project)
        );
        assert_eq!(
            err("klav://trabajo/acme-api/github/x"),
            ReferenceError::NotFound(Level::Item)
        );
        assert_eq!(
            err("klav://trabajo/acme-api/POSTGRES/url"),
            ReferenceError::Ambiguous {
                level: Level::Item,
                name: "POSTGRES".into(),
                count: 2
            }
        );
        let unknown_id = format!("klav://{}/acme-api/stripe/x", VaultId::generate());
        assert_eq!(err(&unknown_id), ReferenceError::NotFound(Level::Vault));
    }

    #[test]
    fn resolves_fields() {
        let mut item = Item::new(ItemKind::ApiKey, "Stripe").unwrap();
        item.add_field(Field::new("api_key", "API key", FieldKind::Concealed, "sk_test").unwrap())
            .unwrap();
        let id = item.fields()[0].id();
        assert_eq!(
            resolve_field(&item, &Selector::Name("api_key".into()))
                .unwrap()
                .id(),
            id
        );
        assert_eq!(
            resolve_field(&item, &Selector::Id(id)).unwrap().name(),
            "api_key"
        );
        assert_eq!(
            resolve_field(&item, &Selector::Name("password".into())).err(),
            Some(ReferenceError::NotFound(Level::Field))
        );
    }

    fn named(vault: &str, project: &str, item: &str) -> Reference {
        Reference {
            vault: Selector::Name(vault.into()),
            project: Selector::Name(project.into()),
            item: Selector::Name(item.into()),
            field: Selector::Name("password".into()),
        }
    }

    /// The form every reference had before names were shown as written:
    /// spaces, `% / ? #`, controls and all non-ASCII percent-encoded.
    fn old_display(r: &Reference) -> String {
        use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
        const OLD: &AsciiSet = &CONTROLS.add(b' ').add(b'/').add(b'?').add(b'#').add(b'%');
        fn segment<I: fmt::Display>(s: &Selector<I>) -> String {
            match s {
                Selector::Id(id) => id.to_string(),
                Selector::Name(n) => utf8_percent_encode(n, OLD).to_string(),
            }
        }
        format!(
            "klav://{}/{}/{}/{}",
            segment(&r.vault),
            segment(&r.project),
            segment(&r.item),
            segment(&r.field)
        )
    }

    #[test]
    fn displays_names_as_written() {
        let cases: &[(&str, &str, &str, &str)] = &[
            (
                "Mi bóveda",
                "Contraseña",
                "Café",
                "klav://Mi bóveda/Contraseña/Café/password",
            ),
            (
                "Personal",
                "General",
                "Banco Azul 🏦",
                "klav://Personal/General/Banco Azul 🏦/password",
            ),
            ("工作", "项目", "密码", "klav://工作/项目/密码/password"),
            (
                "a/b",
                "50%",
                "#1 ¿qué?",
                "klav://a%2Fb/50%25/%231 ¿qué%3F/password",
            ),
            // A literal `%20` in a name stays distinguishable from a space.
            (
                "x%20y",
                "x y",
                "General",
                "klav://x%2520y/x y/General/password",
            ),
            // Tools trim whole references, so edge whitespace is encoded.
            (
                " GitHub ",
                "\u{a0}nbsp",
                "Mi banco\u{3000}",
                "klav://%20GitHub%20/%C2%A0nbsp/Mi banco%E3%80%80/password",
            ),
            // Invisible characters and look-alike spaces stay encoded, so
            // `GitHub` and `GitHub` + U+200B never print the same.
            (
                "Git\u{200b}Hub",
                "a\u{202e}b",
                "Mi\u{a0}banco",
                "klav://Git%E2%80%8BHub/a%E2%80%AEb/Mi%C2%A0banco/password",
            ),
        ];
        for (vault, project, item, shown) in cases {
            let r = named(vault, project, item);
            assert_eq!(r.to_string(), *shown);
            assert_eq!(Reference::parse(shown).unwrap(), r, "{shown}");
            // What older versions showed (copied into klav.toml, grants,
            // logs) still parses to the same reference.
            let old = old_display(&r);
            assert_eq!(Reference::parse(&old).unwrap(), r, "{old}");
            assert!(shown.len() <= old.len(), "{shown} longer than {old}");
        }
    }

    #[test]
    fn compares_paths_and_names_decoded() {
        assert!(same_path(
            "klav://Personal/General/Mi%20banco",
            "KLAV://personal/general/Mi banco"
        ));
        assert!(same_path(
            "klav://B%C3%B3veda/a%2Fb/T",
            " klav://BÓVEDA/A%2FB/t "
        ));
        assert!(!same_path("klav://a/b/c", "klav://a/b/c/d"));
        assert!(!same_path("klav://a/b/x%2520y", "klav://a/b/x y"));
        assert!(!same_path("klav://a/b/50%", "klav://a/b/50%"));
        assert!(!same_path("a/b/c", "a/b/c"));
        assert!(same_name("Mi%20banco", "MI BANCO"));
        assert!(same_name("Caf%C3%A9", "CAFÉ"));
        assert!(!same_name("x%2520y", "x y"));
        assert!(!same_name("", ""));
    }

    fn name() -> impl Strategy<Value = String> {
        "[^\\p{Cc}]{1,24}".prop_filter("not blank, not an ID", |s| {
            !s.trim().is_empty() && !looks_like_id(s)
        })
    }

    proptest! {
        #[test]
        fn prop_display_parse_roundtrip(vault in name(), project in name(), item in name(), field in "[a-z0-9][a-z0-9_-]{0,20}") {
            let reference = Reference {
                vault: Selector::Name(vault),
                project: Selector::Name(project),
                item: Selector::Name(item),
                field: Selector::Name(field),
            };
            let shown = reference.to_string();
            prop_assert_eq!(&Reference::parse(&shown).unwrap(), &reference);
            // Old copies keep working and are never shorter.
            let old = old_display(&reference);
            prop_assert_eq!(&Reference::parse(&old).unwrap(), &reference);
            prop_assert!(shown.len() <= old.len());
            prop_assert!(same_path(&shown, &old));
        }

        /// Names in any script, with spaces, `% / ? #` and literal escapes.
        #[test]
        fn prop_tricky_names_roundtrip(
            parts in proptest::collection::vec(
                prop_oneof![
                    Just(" ".to_owned()), Just("%".to_owned()), Just("%20".to_owned()),
                    Just("/".to_owned()), Just("?".to_owned()), Just("#".to_owned()),
                    Just("ñ".to_owned()), Just("é".to_owned()), Just("🔑".to_owned()),
                    Just("密".to_owned()), Just("\u{a0}".to_owned()), Just("\u{3000}".to_owned()),
                    "[a-zA-Z0-9]{1,4}",
                ],
                1..8,
            )
        ) {
            let name: String = parts.concat();
            prop_assume!(!name.trim().is_empty() && !looks_like_id(&name));
            let reference = named(&name, &name, &name);
            let shown = reference.to_string();
            prop_assert_eq!(&Reference::parse(&shown).unwrap(), &reference);
            // The shown form survives the trim every consumer applies.
            prop_assert_eq!(shown.trim(), shown.as_str());
            prop_assert_eq!(&Reference::parse(&old_display(&reference)).unwrap(), &reference);
        }

        #[test]
        fn prop_parse_never_panics(text in "\\PC{0,80}") {
            let _ = Reference::parse(&text);
            let _ = Reference::parse(&format!("klav://{text}"));
        }
    }
}
