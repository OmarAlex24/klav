//! Reads what other password managers export and plans how it merges into a
//! Klav project (ADR 0024). No network, no encryption: the client
//! (`klav-client::import`) opens the project, asks [`plan`] what to do and
//! uploads the result.
//!
//! Formats:
//! - Bitwarden JSON (unencrypted) and CSV;
//! - 1Password `.1pux` and CSV;
//! - Google Authenticator export QR codes (`otpauth-migration://`), as the
//!   link or, with the `qr-image` feature, a PNG of the code; plain
//!   `otpauth://totp/` links too;
//! - browser CSV exports (Chrome, Edge, Brave, Firefox, Safari) and a
//!   generic CSV.
//!
//! Messages, reports and errors name rows and items by position, never by
//! a value from the file.

use std::collections::{HashMap, HashSet};

use klav_core::model::Item;
use klav_core::model::item::SecretValue;
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod bitwarden;
mod csv;
mod date;
mod fields;
mod google;
mod limits;
mod onepux;
mod passkey;
mod plan;
mod protobuf;
#[cfg(feature = "qr-image")]
mod qr;
#[cfg(any(test, feature = "samples"))]
pub mod samples;
mod zip;

pub use plan::{
    Action, Change, Existing, HistoryPush, Plan, PlannedCreate, PlannedUpdate, Row, Totals, plan,
};

/// Largest file accepted (a `.1pux` with attachments can be big; only
/// `export.data` is read from it).
pub const MAX_FILE: usize = 256 * 1024 * 1024;
/// Largest uncompressed `export.data` of a `.1pux`.
pub const MAX_EXPORT_DATA: usize = 64 * 1024 * 1024;
/// Most entries one file (and one [`ImportSet`]) may hold. Checked as each
/// one is read, so a file of a million empty items stops early.
pub const MAX_ENTRIES: usize = 100_000;
/// Most codes one Google Authenticator export is split in. The app puts
/// about ten accounts in each, so this is thousands of accounts.
pub const MAX_BATCH_SIZE: u32 = 256;
/// Most Google Authenticator export codes in one file or paste, and in one
/// [`ImportSet`].
pub const MAX_CODES: usize = 1024;
/// Most Google Authenticator exports (batch IDs) in one [`ImportSet`]: with
/// [`MAX_BATCH_SIZE`], what bounds [`ImportSet::missing_batches`].
pub const MAX_EXPORTS: usize = 16;

pub use limits::{append_wiping, read_wiping};
pub use passkey::ImportedPasskey;

/// Where an export came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// Bitwarden `.json`, unencrypted.
    Bitwarden,
    /// Bitwarden `.csv`.
    BitwardenCsv,
    /// 1Password `.1pux`.
    #[serde(rename = "1password")]
    OnePassword,
    /// 1Password `.csv`.
    #[serde(rename = "1password_csv")]
    OnePasswordCsv,
    /// Google Authenticator export QR codes, or `otpauth://totp/` links.
    GoogleAuthenticator,
    /// Chrome, Edge, Brave and other Chromium browsers.
    Chrome,
    /// Firefox.
    Firefox,
    /// Safari (macOS and iOS).
    Safari,
    /// Any CSV with recognisable column names.
    Csv,
}

impl Format {
    /// The name used in messages.
    pub fn name(self) -> &'static str {
        match self {
            Format::Bitwarden => "Bitwarden",
            Format::BitwardenCsv => "Bitwarden (CSV)",
            Format::OnePassword => "1Password",
            Format::OnePasswordCsv => "1Password (CSV)",
            Format::GoogleAuthenticator => "Google Authenticator",
            Format::Chrome => "Chrome, Edge or Brave",
            Format::Firefox => "Firefox",
            Format::Safari => "Safari",
            Format::Csv => "CSV",
        }
    }
}

/// What the person says the file is (`--from`, the wizard's choice). The
/// file's content still decides between, say, Bitwarden JSON and CSV.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Bitwarden.
    Bitwarden,
    /// 1Password.
    #[serde(rename = "1password")]
    OnePassword,
    /// Google Authenticator.
    Google,
    /// Chrome, Edge, Brave and other Chromium browsers.
    Chrome,
    /// Firefox.
    Firefox,
    /// Safari.
    Safari,
    /// A generic CSV.
    Csv,
}

impl Source {
    /// Parses a `--from` value (`edge` and `brave` mean `chrome`).
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text.trim().to_ascii_lowercase().as_str() {
            "bitwarden" => Source::Bitwarden,
            "1password" | "onepassword" => Source::OnePassword,
            "google" | "google-authenticator" | "authenticator" => Source::Google,
            "chrome" | "edge" | "brave" | "chromium" | "arc" | "dia" => Source::Chrome,
            "firefox" => Source::Firefox,
            "safari" => Source::Safari,
            "csv" | "generic" => Source::Csv,
            _ => return None,
        })
    }

    fn label(self) -> &'static str {
        match self {
            Source::Bitwarden => "Bitwarden",
            Source::OnePassword => "1Password",
            Source::Google => "Google Authenticator",
            Source::Chrome => "a browser",
            Source::Firefox => "Firefox",
            Source::Safari => "Safari",
            Source::Csv => "CSV",
        }
    }
}

/// Import errors. Messages never contain values from the file.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImportError {
    /// Not a format Klav knows.
    #[error("not a recognised export: {0}")]
    NotRecognised(String),
    /// A password-protected export.
    #[error("{0}")]
    Encrypted(&'static str),
    /// The file is damaged or not what it claims to be.
    #[error("{0}")]
    Invalid(String),
    /// Too big.
    #[error("the file is too large to import")]
    TooLarge,
    /// The file says it is from another source than the one chosen.
    #[error("this looks like a {found} export, not {wanted}")]
    WrongSource {
        /// What it looks like.
        found: &'static str,
        /// What was chosen.
        wanted: &'static str,
    },
    /// A PNG was given where QR images cannot be read.
    #[error(
        "reading QR codes from images is not available here: paste the otpauth-migration:// link instead"
    )]
    NoQrImages,
}

/// A remark about part of a file, by position (`row 4`, `item 12`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Remark {
    /// Where (`row 4`, `item 12`, `account 3`).
    pub at: String,
    /// What happened.
    pub reason: String,
}

/// One Google Authenticator QR code of an export in several.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch {
    /// Same for all the codes of one export.
    pub id: i64,
    /// Position, from 1.
    pub index: u32,
    /// How many codes the export has.
    pub size: u32,
}

/// What one file (or QR code) contributed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceReport {
    /// The file name, as given.
    pub name: String,
    /// Its format.
    pub format: Format,
    /// Entries read.
    pub items: usize,
    /// Parts not imported, and why.
    pub skipped: Vec<Remark>,
    /// Parts imported with something left out.
    pub notes: Vec<Remark>,
    /// Remarks beyond the first [`MAX_REMARKS`] of `skipped` and `notes`,
    /// counted but not listed (a damaged file can have thousands).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub more_remarks: usize,
    /// Passkeys found and not imported: the file does not carry their key
    /// (1Password), one is not valid, or a login already has one (ADR
    /// 0020 §2). Each has a note, except where the format never has keys.
    pub passkeys: usize,
    /// Google Authenticator codes read, when the export has several.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub batches: Vec<Batch>,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// Remarks listed per file; the rest are only counted.
pub const MAX_REMARKS: usize = 100;

/// Google Authenticator codes still missing from an export in several.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingBatch {
    /// The export.
    pub id: i64,
    /// How many codes it has.
    pub size: u32,
    /// Positions not read yet, from 1.
    pub missing: Vec<u32>,
}

/// A previous value of an entry's password, from the source's own history.
#[derive(Clone)]
pub struct OldPassword {
    /// The value.
    pub value: SecretValue,
    /// Until when it was used (Unix ms), if known.
    pub until_ms: Option<i64>,
}

/// One thing to import. Not `Debug`: it holds secrets.
#[derive(Clone)]
pub struct Entry {
    /// The item, as Klav would store it.
    pub item: Item,
    /// Where it was in the file (`row 4`).
    pub at: String,
    /// When the source last changed it (Unix ms), if it says.
    pub modified_ms: Option<i64>,
    /// Earlier passwords the source kept for it.
    pub history: Vec<OldPassword>,
    /// Its passkey, checked and with the key parsed, for the client to seal
    /// (logins only; Bitwarden is the only source that carries one).
    pub passkey: Option<ImportedPasskey>,
}

impl Entry {
    pub(crate) fn new(item: Item, at: impl Into<String>) -> Self {
        Self {
            item,
            at: at.into(),
            modified_ms: None,
            history: Vec::new(),
            passkey: None,
        }
    }
}

/// The entries of one or more files, before planning. Not `Debug`.
#[derive(Default, Clone)]
pub struct ImportSet {
    entries: Vec<Entry>,
    sources: Vec<SourceReport>,
    /// Google Authenticator codes already read: `(batch id, index)`.
    seen_batches: HashSet<(i64, u32)>,
    /// The largest size each Google Authenticator export said it had.
    batch_sizes: HashMap<i64, u32>,
}

impl ImportSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads one file (or pasted text) and adds what it holds. `source` is
    /// what the person said it is; `None` detects it. A Google
    /// Authenticator code that was already added is skipped.
    pub fn add(
        &mut self,
        name: &str,
        bytes: &[u8],
        source: Option<Source>,
    ) -> Result<SourceReport, ImportError> {
        if bytes.len() > MAX_FILE {
            return Err(ImportError::TooLarge);
        }
        let parsed = parse(bytes, source)?;
        let incoming = parsed.entries.len()
            + parsed
                .batches
                .iter()
                .map(|(_, entries)| entries.len())
                .sum::<usize>();
        if self.entries.len().saturating_add(incoming) > MAX_ENTRIES {
            return Err(limits::too_many_entries());
        }
        let codes = parsed.batches.iter().filter(|(b, _)| b.is_some()).count();
        let exports: HashSet<i64> = parsed
            .batches
            .iter()
            .filter_map(|(b, _)| b.map(|b| b.id))
            .filter(|id| !self.batch_sizes.contains_key(id))
            .collect();
        if self.seen_batches.len().saturating_add(codes) > MAX_CODES
            || self.batch_sizes.len().saturating_add(exports.len()) > MAX_EXPORTS
        {
            return Err(ImportError::Invalid(
                "too many Google Authenticator export codes in one import".into(),
            ));
        }
        let mut report = SourceReport {
            name: name.chars().filter(|c| !c.is_control()).take(200).collect(),
            format: parsed.format,
            items: 0,
            skipped: parsed.skipped,
            notes: parsed.notes,
            passkeys: parsed.passkeys,
            batches: Vec::new(),
            more_remarks: parsed.more_remarks,
        };
        for (batch, entries) in parsed.batches {
            if let Some(b) = batch {
                if !self.seen_batches.insert((b.id, b.index)) {
                    report.notes.push(Remark {
                        at: format!("QR code {} of {}", b.index, b.size),
                        reason: "already added".into(),
                    });
                    continue;
                }
                let size = self.batch_sizes.entry(b.id).or_insert(b.size);
                *size = (*size).max(b.size);
                report.batches.push(b);
            }
            report.items += entries.len();
            self.entries.extend(entries);
        }
        report.items += parsed.entries.len();
        self.entries.extend(parsed.entries);
        let listed = report.skipped.len() + report.notes.len();
        if listed > MAX_REMARKS {
            report.skipped.truncate(MAX_REMARKS);
            report
                .notes
                .truncate(MAX_REMARKS.saturating_sub(report.skipped.len()));
            report.more_remarks += listed - report.skipped.len() - report.notes.len();
        }
        self.sources.push(report.clone());
        Ok(report)
    }

    /// Everything read so far, in order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// What each file contributed.
    pub fn sources(&self) -> &[SourceReport] {
        &self.sources
    }

    /// Passkeys found in all the files (not imported).
    pub fn passkeys(&self) -> usize {
        self.sources.iter().map(|s| s.passkeys).sum()
    }

    /// Google Authenticator exports with codes not read yet. At most
    /// [`MAX_EXPORTS`] of them, each listing at most [`MAX_BATCH_SIZE`]
    /// positions: `add` refuses codes beyond those.
    pub fn missing_batches(&self) -> Vec<MissingBatch> {
        let mut ids: Vec<(i64, u32)> = self
            .batch_sizes
            .iter()
            .map(|(&id, &size)| (id, size.min(MAX_BATCH_SIZE)))
            .collect();
        ids.sort_unstable();
        ids.into_iter()
            .filter_map(|(id, size)| {
                let missing: Vec<u32> = (1..=size)
                    .filter(|i| !self.seen_batches.contains(&(id, *i)))
                    .collect();
                (!missing.is_empty()).then_some(MissingBatch { id, size, missing })
            })
            .collect()
    }

    /// Whether nothing was read.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// What a parser produced.
pub(crate) struct Parsed {
    pub(crate) format: Format,
    pub(crate) entries: Vec<Entry>,
    /// Google Authenticator entries, grouped by QR code.
    pub(crate) batches: Vec<(Option<Batch>, Vec<Entry>)>,
    /// At most [`MAX_REMARKS`]; the rest are counted in `more_remarks`.
    pub(crate) skipped: Vec<Remark>,
    /// At most [`MAX_REMARKS`]; the rest are counted in `more_remarks`.
    pub(crate) notes: Vec<Remark>,
    pub(crate) more_remarks: usize,
    pub(crate) passkeys: usize,
    /// Entries admitted so far (see [`Parsed::admit`]).
    admitted: usize,
}

impl Parsed {
    pub(crate) fn new(format: Format) -> Self {
        Self {
            format,
            entries: Vec::new(),
            batches: Vec::new(),
            skipped: Vec::new(),
            notes: Vec::new(),
            more_remarks: 0,
            passkeys: 0,
            admitted: 0,
        }
    }

    /// Counts one more entry; an error past [`MAX_ENTRIES`]. Every parser
    /// calls it before keeping an entry, so the cap holds while reading.
    pub(crate) fn admit(&mut self) -> Result<(), ImportError> {
        self.admitted += 1;
        if self.admitted > MAX_ENTRIES {
            return Err(limits::too_many_entries());
        }
        Ok(())
    }

    /// Adds an entry, counting it against [`MAX_ENTRIES`].
    pub(crate) fn push(&mut self, entry: Entry) -> Result<(), ImportError> {
        self.admit()?;
        self.entries.push(entry);
        Ok(())
    }

    pub(crate) fn skip(&mut self, at: impl Into<String>, reason: impl Into<String>) {
        if self.skipped.len() < MAX_REMARKS {
            self.skipped.push(Remark {
                at: at.into(),
                reason: reason.into(),
            });
        } else {
            self.more_remarks += 1;
        }
    }

    pub(crate) fn note(&mut self, at: impl Into<String>, reason: impl Into<String>) {
        if self.notes.len() < MAX_REMARKS {
            self.notes.push(Remark {
                at: at.into(),
                reason: reason.into(),
            });
        } else {
            self.more_remarks += 1;
        }
    }
}

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

fn fits(found: Format, wanted: Source) -> bool {
    match wanted {
        Source::Bitwarden => matches!(found, Format::Bitwarden | Format::BitwardenCsv),
        Source::OnePassword => matches!(found, Format::OnePassword | Format::OnePasswordCsv),
        Source::Google => found == Format::GoogleAuthenticator,
        // Browsers and the generic CSV: the columns decide the details.
        Source::Chrome | Source::Firefox | Source::Safari | Source::Csv => {
            matches!(
                found,
                Format::Chrome | Format::Firefox | Format::Safari | Format::Csv
            )
        }
    }
}

/// Detects the format from the content and parses it.
fn parse(bytes: &[u8], source: Option<Source>) -> Result<Parsed, ImportError> {
    let check = |found: Format| match source {
        Some(wanted) if !fits(found, wanted) => Err(ImportError::WrongSource {
            found: found.name(),
            wanted: wanted.label(),
        }),
        _ => Ok(()),
    };
    if bytes.starts_with(b"PK\x03\x04") {
        check(Format::OnePassword)?;
        return onepux::parse(bytes);
    }
    if bytes.starts_with(PNG_MAGIC) {
        check(Format::GoogleAuthenticator)?;
        #[cfg(feature = "qr-image")]
        {
            let texts = qr::decode_png(bytes)?;
            let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
            return google::parse_texts(&texts);
        }
        #[cfg(not(feature = "qr-image"))]
        return Err(ImportError::NoQrImages);
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ImportError::NotRecognised("the file is not text, a .1pux or a PNG".into()))?;
    let text = text.trim_start_matches('\u{feff}');
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        check(Format::Bitwarden)?;
        return bitwarden::parse(trimmed);
    }
    if google::looks_like(trimmed) {
        check(Format::GoogleAuthenticator)?;
        return google::parse_texts(&[trimmed]);
    }
    let parsed = csv::parse(text.as_bytes(), source)?;
    check(parsed.format)?;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Types that hold secrets from the file never print them (T34).
    static_assertions::assert_not_impl_any!(Entry: std::fmt::Debug, std::fmt::Display);
    static_assertions::assert_not_impl_any!(OldPassword: std::fmt::Debug, std::fmt::Display);
    static_assertions::assert_not_impl_any!(ImportedPasskey: std::fmt::Debug, std::fmt::Display);
    static_assertions::assert_not_impl_any!(ImportSet: std::fmt::Debug, std::fmt::Display);
    static_assertions::assert_not_impl_any!(Parsed: std::fmt::Debug, std::fmt::Display);
    static_assertions::assert_not_impl_any!(
        crate::protobuf::Value<'static>: std::fmt::Debug,
        std::fmt::Display
    );
    static_assertions::assert_not_impl_any!(
        crate::protobuf::Fields<'static>: std::fmt::Debug,
        std::fmt::Display
    );

    #[test]
    fn a_huge_batch_size_is_refused_before_listing_what_is_missing() {
        // size = u32::MAX used to make `missing_batches` build a list of
        // four thousand million positions (16 GiB).
        let code = crate::google::tests::link(
            &[(b"0123456789", "a", "X", 1, 1, 2)],
            0,
            u64::from(u32::MAX),
            5,
        );
        let mut set = ImportSet::new();
        assert!(set.add("qr", code.as_bytes(), None).is_err());
        assert!(set.missing_batches().is_empty());
    }

    #[test]
    fn the_codes_and_exports_of_a_set_are_capped() {
        let code = |id: u64, index: u64| {
            crate::google::tests::link(&[(b"0123456789", "a", "X", 1, 1, 2)], index, 3, id)
        };
        let mut set = ImportSet::new();
        for id in 0..MAX_EXPORTS as u64 {
            set.add("qr", code(id, 0).as_bytes(), None).unwrap();
        }
        // One more export would grow the list of missing codes past
        // MAX_EXPORTS × MAX_BATCH_SIZE.
        assert!(set.add("qr", code(99, 0).as_bytes(), None).is_err());
        // Another code of an export already there is fine.
        set.add("qr", code(0, 1).as_bytes(), None).unwrap();
        let missing = set.missing_batches();
        assert_eq!(missing.len(), MAX_EXPORTS);
        assert_eq!(missing[0].missing, vec![3]);
        assert_eq!(missing[1].missing, vec![2, 3]);
    }

    #[test]
    fn remarks_are_capped_while_reading() {
        let mut p = Parsed::new(Format::Csv);
        for i in 0..10_000 {
            p.skip(format!("row {i}"), "bad");
            p.note(format!("row {i}"), "odd");
        }
        assert_eq!(
            (p.skipped.len(), p.notes.len(), p.more_remarks),
            (MAX_REMARKS, MAX_REMARKS, 2 * (10_000 - MAX_REMARKS))
        );
    }

    #[test]
    fn source_names() {
        assert_eq!(Source::parse("Edge"), Some(Source::Chrome));
        assert_eq!(Source::parse("1password"), Some(Source::OnePassword));
        assert_eq!(Source::parse("authy"), None);
    }

    #[test]
    fn thousands_of_bad_rows_are_counted_not_listed() {
        let mut bad = String::from("name,url,username,password\n");
        for _ in 0..1000 {
            bad.push_str(",,,\n");
        }
        bad.push_str("A,https://a.example,u,p\n");
        let r = ImportSet::new()
            .add("bad.csv", bad.as_bytes(), None)
            .unwrap();
        assert_eq!((r.items, r.skipped.len(), r.more_remarks), (1, 100, 900));
    }

    #[test]
    fn the_samples_tell_one_story() {
        use crate::samples;
        let mut set = ImportSet::new();
        let bw = set
            .add("bitwarden.json", samples::bitwarden_json().as_bytes(), None)
            .unwrap();
        assert_eq!(
            (bw.format, bw.items, bw.passkeys, bw.skipped.len()),
            (Format::Bitwarden, 5, 0, 1)
        );
        // The passkey of the shop is read, with its key, for the client to seal.
        let shop = set
            .entries()
            .iter()
            .find(|e| e.item.title() == "Passkey Shop")
            .unwrap();
        assert_eq!(
            shop.passkey.as_ref().map(ImportedPasskey::rp_id),
            Some("shop.example.com")
        );
        let op = set
            .add("export.1pux", &samples::onepux(), Some(Source::OnePassword))
            .unwrap();
        assert_eq!((op.format, op.items), (Format::OnePassword, 2));
        let [first, second] = samples::google_links();
        let ga = set.add("pasted", first.as_bytes(), None).unwrap();
        assert_eq!(
            ga.batches,
            vec![Batch {
                id: 424_242,
                index: 1,
                size: 2
            }]
        );
        assert_eq!(set.missing_batches()[0].missing, vec![2]);
        let again = set.add("pasted", first.as_bytes(), None).unwrap();
        assert_eq!(again.items, 0);
        let ga2 = set.add("pasted", second.as_bytes(), None).unwrap();
        assert_eq!((ga2.items, ga2.skipped.len()), (0, 1));
        assert!(set.missing_batches().is_empty());
        set.add("chrome.csv", samples::chrome_csv().as_bytes(), None)
            .unwrap();
        set.add("firefox.csv", samples::firefox_csv().as_bytes(), None)
            .unwrap();
        set.add("safari.csv", samples::safari_csv().as_bytes(), None)
            .unwrap();
        assert_eq!(set.passkeys(), 0);
        let plan = crate::plan(set.entries(), &[], 1_800_000_000_000);
        // Bank (1Password) and GitHub (code, Chrome), shop (Safari) merge.
        assert_eq!(
            plan.totals,
            Totals {
                new: 9,
                merged: 2,
                duplicates: 2
            }
        );
        let bank = plan
            .rows
            .iter()
            .find(|r| r.at == "item 1" && r.title == "Example Bank")
            .unwrap();
        assert_eq!(bank.action, Action::Merge);
        assert!(bank.changes.contains(&Change::PasswordReplaced));
        let github_code = plan
            .rows
            .iter()
            .find(|r| r.kind == klav_core::model::item::ItemKind::Totp && r.title == "GitHub")
            .unwrap();
        assert_eq!(
            (github_code.action, github_code.target.as_str()),
            (Action::Merge, "GitHub")
        );
    }

    #[cfg(feature = "qr-image")]
    #[test]
    fn reads_qr_codes_from_png() {
        let [first, _] = crate::samples::google_links();
        let png = crate::samples::qr_png(&first);
        let mut set = ImportSet::new();
        let report = set.add("qr.png", &png, Some(Source::Google)).unwrap();
        assert_eq!(report.items, 2);
        assert!(
            set.add("blank.png", &crate::samples::qr_png("hello"), None)
                .is_err()
        );
    }

    #[test]
    fn wrong_source_is_refused() {
        let csv = "name,url,username,password\nA,https://a.example,u,p\n";
        let err = parse(csv.as_bytes(), Some(Source::Bitwarden))
            .err()
            .unwrap();
        assert!(matches!(err, ImportError::WrongSource { .. }));
        assert!(parse(csv.as_bytes(), Some(Source::Chrome)).is_ok());
        assert!(parse(b"\x00\x01binary", None).is_err());
    }
}
