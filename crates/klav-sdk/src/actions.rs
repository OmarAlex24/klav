//! Actions that use secrets without handing them to the caller: run a
//! command with them in its environment, write them into a file. Both use
//! the `inject` permission (design §5.2).
//!
//! What the command prints comes back with every injected value replaced by
//! `[redacted by klav]`, so an agent runtime can pass it to the LLM, and so
//! are the common accidental encodings of it (base64, hex, percent, JSON)
//! and long pieces of it ([`Redactor`]). That is a safety net, not a
//! guarantee: a command that encrypts a value or transforms it its own way
//! defeats it (threat T20).

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use klav_client::{ClientError, ClientResult};
use klav_core::ids::ItemId;
use klav_core::model::Item;
use klav_core::model::item::FieldKind;
use klav_core::policy::Permission;
use tokio::io::AsyncReadExt;
use zeroize::{Zeroize, Zeroizing};

use crate::secret_file::write_secret_file;
use crate::session::{Files, Session, field_bytes};
use crate::template::{self, Piece};

/// What replaces a secret in captured output.
pub const REDACTED: &str = "[redacted by klav]";
/// Captured output kept per stream.
pub const MAX_OUTPUT: usize = 64 * 1024;

/// A resolved reference.
pub struct Resolved {
    /// The reference as given.
    pub reference: String,
    /// Field type ([`FieldKind::File`] for an attachment).
    pub kind: FieldKind,
    /// The value: UTF-8 text, or the bytes of an attachment.
    pub value: Zeroizing<Vec<u8>>,
}

impl Resolved {
    /// The value as text, for an environment variable or a template: an
    /// attachment that is not UTF-8, or holds a NUL byte, cannot be one.
    pub fn text(&self) -> ClientResult<&str> {
        match std::str::from_utf8(&self.value) {
            Ok(text) if !text.contains('\0') => Ok(text),
            _ => Err(ClientError::Invalid(format!(
                "{} is a binary attachment: it can only go to a file ([files] in klav.toml, or inject_file with ref)",
                self.reference
            ))),
        }
    }
}

impl Session {
    /// Resolves references for `inject` (one access per item, logged with
    /// `reason`). `scope` is `klav.toml`'s `project`: short references are
    /// resolved there and nothing outside it is used. Waits up to `wait`
    /// when the policy says `ask`.
    pub async fn resolve(
        &mut self,
        references: &[String],
        scope: Option<(&str, &str)>,
        reason: &str,
        wait: Duration,
    ) -> ClientResult<Vec<Resolved>> {
        self.resolve_with(references, scope, reason, wait, true)
            .await
    }

    /// [`Session::resolve`]; with `with_files: false` (templates), attachments
    /// are not asked for and a reference to one fails.
    async fn resolve_with(
        &mut self,
        references: &[String],
        scope: Option<(&str, &str)>,
        reason: &str,
        wait: Duration,
        with_files: bool,
    ) -> ClientResult<Vec<Resolved>> {
        let mut located = Vec::with_capacity(references.len());
        for reference in references {
            let (item, field) = self.locate(reference, scope)?;
            let field = field.ok_or_else(|| {
                ClientError::Invalid(format!(
                    "{reference} names an item, not a field (add /password, /credential…)"
                ))
            })?;
            located.push((reference.clone(), item, field));
        }
        let ids: Vec<ItemId> = located.iter().map(|(_, item, _)| *item).collect();
        self.check_claim(Permission::Inject, &ids, None)?;
        let mut items: HashMap<ItemId, (Item, Files)> = HashMap::new();
        for (_, item, _) in &located {
            if !items.contains_key(item) {
                let opened = if with_files {
                    self.access_for_inject(*item, reason, wait).await?
                } else {
                    let opened = self
                        .access_waiting(*item, Permission::Inject, reason, None, wait)
                        .await?;
                    (opened, Files::new())
                };
                items.insert(*item, opened);
            }
        }
        located
            .into_iter()
            .map(|(reference, item, field)| {
                let (opened, files) = items
                    .get(&item)
                    .ok_or_else(|| ClientError::NotFound(format!("item {item}")))?;
                if !with_files && field_is_file(opened, &field) {
                    return Err(ClientError::Invalid(format!(
                        "{reference} is an attachment: write it with `ref`, not inside a template"
                    )));
                }
                let (kind, value) = field_bytes(opened, &field, files)?;
                Ok(Resolved {
                    reference,
                    kind,
                    value,
                })
            })
            .collect()
    }
}

fn field_is_file(item: &Item, field: &str) -> bool {
    let selector = match field.parse() {
        Ok(id) => klav_core::model::Selector::Id(id),
        Err(_) => klav_core::model::Selector::Name(field.to_owned()),
    };
    klav_core::model::resolve_field(item, &selector).is_ok_and(|f| f.kind() == FieldKind::File)
}

/// Shortest run of a secret's characters that is redacted on its own, when
/// the output holds part of the secret but not all of it (a value cut in
/// half, wrapped, or printed with `cut -c`).
///
/// It trades leaks for false positives: lower, and more ordinary text
/// (a PEM header, a common prefix such as `sk_live_`, a word inside a
/// passphrase) would be blanked out of the output; higher, and a bigger
/// piece of a secret could get through. Secrets shorter than this are only
/// redacted whole, never in pieces.
const MIN_FRAGMENT_CHARS: usize = 12;

/// Shortest encoding (base64, hex, percent or JSON) of a secret that is
/// redacted. A 4-character PIN encodes to 6 base64 characters, and those
/// would match pieces of any hash or token in the output; the secret itself
/// is still redacted whole, whatever its length.
const MIN_ENCODED_CHARS: usize = 8;

/// One string to find in the output: a secret, or an encoding of one.
struct Pattern {
    text: Zeroizing<String>,
    /// Length of the fragments of `text` that are also redacted (in chars);
    /// `None` when only the whole of it is. Scaled for each encoding so a
    /// fragment always stands for about [`MIN_FRAGMENT_CHARS`] secret
    /// bytes: 16 base64 characters, 24 hex digits.
    window: Option<usize>,
}

/// Replaces known secret values in text: verbatim, in the encodings a
/// command commonly prints by accident (base64 at any offset, hex,
/// percent-encoding, JSON escaping) and in pieces of at least
/// [`MIN_FRAGMENT_CHARS`] characters.
///
/// It is a safety net for mistakes, not a barrier against a command that
/// wants to leak a value: encryption, a custom transform, or pieces shorter
/// than [`MIN_FRAGMENT_CHARS`] still get through (threat T20).
///
/// No `Debug`: the patterns are secrets. They are zeroized on drop.
pub struct Redactor {
    patterns: Vec<Pattern>,
    /// Whether long fragments are replaced too ([`Self::new`]) or only
    /// counted ([`Self::whole_values`]).
    pieces: bool,
}

impl Redactor {
    /// A redactor for these values (empty ones are ignored).
    pub fn new<'a>(values: impl IntoIterator<Item = &'a str>) -> Self {
        let mut patterns: Vec<Pattern> = Vec::new();
        for value in values.into_iter().filter(|v| !v.is_empty()) {
            let long = value.chars().count() >= MIN_FRAGMENT_CHARS;
            let window = |w: usize| long.then_some(w);
            push_pattern(
                &mut patterns,
                Zeroizing::new(value.to_owned()),
                window(MIN_FRAGMENT_CHARS),
            );
            let mut derived: Vec<(Zeroizing<String>, usize)> = Vec::new();
            for encoded in base64_forms(value.as_bytes()) {
                derived.push((encoded, MIN_FRAGMENT_CHARS * 4 / 3));
            }
            for upper in [false, true] {
                derived.push((hex(value.as_bytes(), upper), MIN_FRAGMENT_CHARS * 2));
            }
            for encoded in percent_forms(value) {
                derived.push((encoded, MIN_FRAGMENT_CHARS));
            }
            for encoded in json_forms(value) {
                derived.push((encoded, MIN_FRAGMENT_CHARS));
            }
            for (text, w) in derived {
                if text.chars().count() >= MIN_ENCODED_CHARS {
                    push_pattern(&mut patterns, text, window(w));
                }
            }
        }
        Self {
            patterns,
            pieces: true,
        }
    }

    /// A redactor that replaces only whole values, verbatim and in the
    /// same encodings as [`Self::new`], never a piece of one (the
    /// credential proxy, ADR 0036 §8, T149). A piece of at least
    /// [`MIN_FRAGMENT_CHARS`] characters is left as it is and only counted
    /// ([`Self::scan_bytes`]): replacing pieces would tell a caller that can
    /// make a service echo its guesses which guesses are part of the value.
    /// The same work is done whether or not anything matches.
    pub fn whole_values<'a>(values: impl IntoIterator<Item = &'a str>) -> Self {
        Self {
            pieces: false,
            ..Self::new(values)
        }
    }

    /// `text` with every secret, encoding and long fragment replaced by
    /// [`REDACTED`], and how many places were replaced. Matches that
    /// overlap or touch are merged into one replacement (and count once),
    /// so the output never shows part of a secret next to a marker.
    ///
    /// Cost: `O(n · m)` for whole matches of short secrets (whose encodings
    /// are a few dozen characters), `O(n)` per pattern otherwise, and
    /// `O(n · w)` per fragment length `w` (at most 24): every `w`-character
    /// window of the output is hashed once and looked up in a set of the
    /// patterns' windows. Never quadratic in the output or in a secret.
    pub fn apply(&self, text: &str) -> (String, usize) {
        let ranges = self.merged_ranges(text);
        if ranges.is_empty() {
            return (text.to_owned(), 0);
        }
        let mut out = String::with_capacity(text.len());
        let mut copied = 0;
        for &(start, end) in &ranges {
            out.push_str(&text[copied..start]);
            out.push_str(REDACTED);
            copied = end;
        }
        out.push_str(&text[copied..]);
        (out, ranges.len())
    }

    /// [`Self::apply`] on bytes that may not be UTF-8 (an HTTP body): each
    /// valid UTF-8 run is redacted as text and the other bytes are copied
    /// as they are. A secret is UTF-8, so every occurrence of it, or of an
    /// encoding of it, lies inside one valid run.
    pub fn apply_bytes(&self, bytes: &[u8]) -> (Vec<u8>, usize) {
        let ranges = self.byte_ranges(bytes);
        (replace_ranges(bytes, &ranges), ranges.len())
    }

    /// [`Self::apply_bytes`], and how many pieces of a value it left as
    /// they are (always 0 for [`Self::new`], which replaces them).
    pub fn scan_bytes(&self, bytes: &[u8]) -> (Vec<u8>, usize, usize) {
        let (ranges, partial) = self.byte_scan(bytes);
        (replace_ranges(bytes, &ranges), ranges.len(), partial.len())
    }

    /// The byte ranges [`Self::apply_bytes`] replaces, sorted, merged when
    /// they overlap or touch.
    pub(crate) fn byte_ranges(&self, bytes: &[u8]) -> Vec<(usize, usize)> {
        self.byte_scan(bytes).0
    }

    /// The byte ranges to replace and the runs of pieces left as they are,
    /// each sorted and merged.
    fn byte_scan(&self, bytes: &[u8]) -> (Ranges, Ranges) {
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        let mut partial: Vec<(usize, usize)> = Vec::new();
        let mut offset = 0;
        for chunk in bytes.utf8_chunks() {
            let valid = chunk.valid();
            let (r, p) = self.scan(valid);
            ranges.extend(r.into_iter().map(|(s, e)| (offset + s, offset + e)));
            partial.extend(p.into_iter().map(|(s, e)| (offset + s, offset + e)));
            offset += valid.len() + chunk.invalid().len();
        }
        (ranges, partial)
    }

    /// Whether a pattern holds a CR or LF byte, so a match can cross a line
    /// end. Only a value that holds one does: the encodings escape them
    /// (`\n`, `%0A`) or never produce them (base64, hex), and fragments are
    /// pieces of the patterns.
    fn spans_lines(&self) -> bool {
        self.patterns
            .iter()
            .any(|p| p.text.bytes().any(is_line_end))
    }

    /// Longest pattern, in bytes: a match never spans more.
    pub(crate) fn longest(&self) -> usize {
        self.patterns
            .iter()
            .map(|p| p.text.len())
            .max()
            .unwrap_or(0)
    }

    /// Ranges of `text` to replace, sorted, merged when they overlap or
    /// touch (so the output never shows part of a secret next to a marker).
    fn merged_ranges(&self, text: &str) -> Vec<(usize, usize)> {
        self.scan(text).0
    }

    /// The ranges of `text` to replace and, for [`Self::whole_values`], the
    /// maximal runs of pieces that no replaced range covers; both sorted
    /// and merged. The fragments are looked up in both modes, so the cost
    /// does not depend on what matched.
    fn scan(&self, text: &str) -> (Ranges, Ranges) {
        let mut ranges = self.whole_ranges(text);
        let fragments = self.fragments(text);
        if self.pieces {
            ranges.extend(fragments);
            return (merge(ranges), Vec::new());
        }
        let ranges = merge(ranges);
        let partial = merge(fragments)
            .into_iter()
            .filter(|&(s, e)| !ranges.iter().any(|&(rs, re)| rs <= s && e <= re))
            .collect();
        (ranges, partial)
    }

    /// Every occurrence of a whole pattern, unsorted.
    fn whole_ranges(&self, text: &str) -> Vec<(usize, usize)> {
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        for pattern in &self.patterns {
            let p = pattern.text.as_str();
            // With pieces replaced too, the overlapping occurrences of a
            // long pattern are covered by its fragments; without them each
            // occurrence is found (only a periodic value overlaps itself).
            if self.pieces && pattern.window.is_some() {
                // Overlapping occurrences of a long pattern are covered by
                // its fragments below (when it is at least a window long).
                ranges.extend(text.match_indices(p).map(|(i, m)| (i, i + m.len())));
            } else {
                // A short secret's patterns are short: scanning from every
                // match stays cheap and catches overlapping occurrences.
                let step = p.chars().next().map_or(1, char::len_utf8);
                let mut from = 0;
                while let Some(i) = text[from..].find(p) {
                    ranges.push((from + i, from + i + p.len()));
                    from += i + step;
                }
            }
        }
        ranges
    }

    /// Ranges of `text` covered by a fragment (a `window`-character
    /// substring) of a pattern. Their union is every maximal run that a
    /// pattern shares with `text` and that is at least `window` long.
    fn fragments(&self, text: &str) -> Vec<(usize, usize)> {
        let mut sizes: Vec<usize> = self.patterns.iter().filter_map(|p| p.window).collect();
        sizes.sort_unstable();
        sizes.dedup();
        if sizes.is_empty() {
            return Vec::new();
        }
        let bounds = char_bounds(text);
        let mut ranges = Vec::new();
        for size in sizes {
            // Borrowed from the patterns: no extra copies of the secrets.
            let mut windows: HashSet<&str> = HashSet::new();
            for pattern in self.patterns.iter().filter(|p| p.window == Some(size)) {
                let b = char_bounds(&pattern.text);
                for w in b.windows(size + 1) {
                    windows.insert(&pattern.text[w[0]..w[size]]);
                }
            }
            if windows.is_empty() {
                continue;
            }
            for w in bounds.windows(size + 1) {
                if windows.contains(&text[w[0]..w[size]]) {
                    ranges.push((w[0], w[size]));
                }
            }
        }
        ranges
    }
}

/// Byte ranges `[start, end)` of a text.
type Ranges = Vec<(usize, usize)>;

/// `ranges` sorted, merged when they overlap or touch.
fn merge(mut ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// `bytes` with each of the sorted, disjoint `ranges` replaced by
/// [`REDACTED`].
pub(crate) fn replace_ranges(bytes: &[u8], ranges: &[(usize, usize)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut copied = 0;
    for &(start, end) in ranges {
        out.extend_from_slice(&bytes[copied..start]);
        out.extend_from_slice(REDACTED.as_bytes());
        copied = end;
    }
    out.extend_from_slice(&bytes[copied..]);
    out
}

/// Most bytes a [`StreamRedactor`] holds back: a body whose redacted
/// stretch grows past this is cut instead of buffered (fail closed).
pub const MAX_STREAM_HOLD: usize = 1 << 20;

/// Whether `b` ends a line: CR or LF.
fn is_line_end(b: u8) -> bool {
    b == b'\n' || b == b'\r'
}

/// A [`Redactor`] over a body that arrives in chunks (ADR 0036 §8): a
/// value split across two chunks is still replaced. It holds back the
/// last bytes of each chunk that could start a match (fewer than the
/// longest pattern) and any merged match that reaches them, so nothing is
/// emitted that a later chunk could turn into part of a secret.
///
/// [`Self::by_lines`] holds back, instead, what follows the last line end
/// (ADR 0036 §7, note of 2026-11-19): a server-sent event then goes out
/// with the chunk that ends it.
///
/// No `Debug`: the held bytes may be part of a secret. They are zeroized
/// on drop.
pub struct StreamRedactor {
    redactor: Redactor,
    held: Zeroizing<Vec<u8>>,
    replaced: usize,
    /// Pieces left as they are ([`Redactor::whole_values`]).
    partial: usize,
    /// Whether the last run of pieces counted went on past what was
    /// emitted: its rest, at the start of the held bytes, is not another.
    partial_open: bool,
    /// Whether each push emits through the last line end ([`Self::by_lines`]).
    by_lines: bool,
}

/// A body whose redacted stretch grew past [`MAX_STREAM_HOLD`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoldOverflow;

impl StreamRedactor {
    /// Wraps `redactor`.
    pub fn new(redactor: Redactor) -> Self {
        Self {
            redactor,
            held: Zeroizing::new(Vec::new()),
            replaced: 0,
            partial: 0,
            partial_open: false,
            by_lines: false,
        }
    }

    /// Wraps `redactor`, and each [`Self::push`] emits everything up to and
    /// including the last CR or LF seen so far, holding back only what
    /// follows it.
    ///
    /// When no pattern holds a CR or LF, a match never crosses a line end,
    /// so what comes before the last one can be scanned and emitted at
    /// once: the output and the counts are those of redacting the whole
    /// body in one go. When it emits depends only on where the line ends
    /// are, never on the values or on whether anything matched. A body
    /// with no line end for more than [`MAX_STREAM_HOLD`] bytes fails
    /// with [`HoldOverflow`].
    ///
    /// A value that holds a CR or LF could match across a line end: then
    /// this is [`Self::new`] ([`Self::emits_by_line`] says which).
    pub fn by_lines(redactor: Redactor) -> Self {
        let by_lines = !redactor.spans_lines();
        Self {
            by_lines,
            ..Self::new(redactor)
        }
    }

    /// Whether each push emits through the last line end
    /// ([`Self::by_lines`], with no value that holds a line end).
    pub fn emits_by_line(&self) -> bool {
        self.by_lines
    }

    /// How many places were replaced so far.
    pub fn replaced(&self) -> usize {
        self.replaced
    }

    /// How many pieces of a value were left as they are so far (only with
    /// [`Redactor::whole_values`]). A piece split across two chunks counts
    /// once; one cut into stretches shorter than a fragment by the chunks
    /// may not count. What is emitted, and when, never depends on it.
    pub fn partial(&self) -> usize {
        self.partial
    }

    /// Counts the runs of pieces that start before `cut` (the rest are
    /// still held and seen again).
    fn count_partial(&mut self, runs: &[(usize, usize)], cut: usize) {
        let mut open = false;
        for &(start, end) in runs.iter().filter(|&&(s, _)| s < cut) {
            if !(start == 0 && self.partial_open) {
                self.partial += 1;
            }
            open |= end > cut;
        }
        self.partial_open = open;
    }

    /// Takes the next chunk and returns what can be emitted now.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, HoldOverflow> {
        let longest = self.redactor.longest();
        if longest == 0 {
            return Ok(chunk.to_vec());
        }
        if self.by_lines {
            return self.push_by_lines(chunk);
        }
        self.held.extend_from_slice(chunk);
        // A match is at most `longest` bytes: one that starts before `cut`
        // is wholly in the buffer already.
        let mut cut = self.held.len().saturating_sub(longest - 1);
        let (ranges, partial) = self.redactor.byte_scan(&self.held);
        // A merged stretch that crosses `cut` may still grow: hold it all.
        if let Some(&(start, _)) = ranges.iter().find(|&&(s, e)| s < cut && e > cut) {
            cut = start;
        }
        if self.held.len() - cut > MAX_STREAM_HOLD {
            return Err(HoldOverflow);
        }
        let done: Vec<(usize, usize)> = ranges.into_iter().filter(|&(_, e)| e <= cut).collect();
        self.replaced += done.len();
        self.count_partial(&partial, cut);
        let out = replace_ranges(&self.held[..cut], &done);
        self.held.drain(..cut);
        Ok(out)
    }

    /// [`Self::push`] for [`Self::by_lines`]. The held bytes never hold a
    /// line end, so the last one is in `chunk`; only what goes out is
    /// scanned, once.
    fn push_by_lines(&mut self, chunk: &[u8]) -> Result<Vec<u8>, HoldOverflow> {
        let before = self.held.len();
        self.held.extend_from_slice(chunk);
        let cut = chunk
            .iter()
            .rposition(|&b| is_line_end(b))
            .map_or(0, |i| before + i + 1);
        if self.held.len() - cut > MAX_STREAM_HOLD {
            return Err(HoldOverflow);
        }
        if cut == 0 {
            return Ok(Vec::new());
        }
        let (ranges, partial) = self.redactor.byte_scan(&self.held[..cut]);
        self.replaced += ranges.len();
        self.count_partial(&partial, cut);
        let out = replace_ranges(&self.held[..cut], &ranges);
        self.held.drain(..cut);
        Ok(out)
    }

    /// The end of the body: what is still held, redacted.
    pub fn finish(self) -> Vec<u8> {
        self.finish_counted().0
    }

    /// [`Self::finish`], and how many matches were replaced in the whole
    /// body.
    pub fn finish_counted(self) -> (Vec<u8>, usize) {
        let (last, replaced, _) = self.finish_all();
        (last, replaced)
    }

    /// [`Self::finish_counted`], and how many pieces were left as they are
    /// in the whole body ([`Self::partial`]).
    pub fn finish_all(mut self) -> (Vec<u8>, usize, usize) {
        let (ranges, partial) = self.redactor.byte_scan(&self.held);
        self.replaced += ranges.len();
        let all = self.held.len();
        self.count_partial(&partial, all);
        (
            replace_ranges(&self.held, &ranges),
            self.replaced,
            self.partial,
        )
    }
}

/// Byte offset of every char of `s`, and its length.
fn char_bounds(s: &str) -> Vec<usize> {
    s.char_indices()
        .map(|(i, _)| i)
        .chain(std::iter::once(s.len()))
        .collect()
}

/// Adds `text` unless an equal pattern is there (an encoding of a plain
/// secret is often the secret itself); then it keeps its fragments, if
/// either had them.
fn push_pattern(patterns: &mut Vec<Pattern>, text: Zeroizing<String>, window: Option<usize>) {
    if let Some(same) = patterns.iter_mut().find(|p| *p.text == *text) {
        same.window = same.window.or(window);
        return;
    }
    patterns.push(Pattern { text, window });
}

/// `bytes` with `encoding`, into a buffer zeroized on drop.
fn encode(encoding: &data_encoding::Encoding, bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(vec![0u8; encoding.encode_len(bytes.len())]);
    encoding.encode_mut(bytes, &mut out);
    // Base64 is ASCII; the copy below has the exact length (no realloc).
    Zeroizing::new(String::from_utf8_lossy(&out).into_owned())
}

/// The base64 a secret can show up as: standard and URL-safe alphabets,
/// padded or not, alone or inside a larger blob.
///
/// Inside a blob (`Authorization: Basic base64(user:pass)`) the secret
/// starts at an unknown byte offset, and only its offset modulo 3 changes
/// the characters. For `k` = 0, 1, 2 bytes before it, base64 character `i`
/// holds bits `[6i, 6i + 6)` of the input, so the ones that hold only the
/// secret's bits run from `ceil(8k / 6)` to `floor(8(k + n) / 6)`. That
/// stable run is matched whatever comes before or after; the characters
/// from its start to the end (with padding or not) are matched too, for a
/// secret at the end of the blob.
fn base64_forms(secret: &[u8]) -> Vec<Zeroizing<String>> {
    use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD};
    let mut out = Vec::new();
    for (nopad, padded) in [(&BASE64_NOPAD, &BASE64), (&BASE64URL_NOPAD, &BASE64URL)] {
        for k in 0..3usize {
            let mut input = Zeroizing::new(Vec::with_capacity(k + secret.len()));
            input.resize(k, 0);
            input.extend_from_slice(secret);
            let start = (8 * k).div_ceil(6);
            let end = 8 * (k + secret.len()) / 6;
            let bare = encode(nopad, &input);
            let full = encode(padded, &input);
            if start < end {
                out.push(Zeroizing::new(bare[start..end].to_owned()));
            }
            out.push(Zeroizing::new(bare[start..].to_owned()));
            out.push(Zeroizing::new(full[start..].to_owned()));
        }
    }
    out
}

fn hex_digit(n: u8, upper: bool) -> char {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    char::from(digits[usize::from(n & 0xf)])
}

fn hex(bytes: &[u8], upper: bool) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for &b in bytes {
        out.push(hex_digit(b >> 4, upper));
        out.push(hex_digit(b, upper));
    }
    out
}

/// Percent-encodings of `secret`, as the usual encoders write them: they
/// differ in which punctuation they leave alone (RFC 3986, HTML forms,
/// JavaScript's `encodeURIComponent`, Python's `quote`), in the case of the
/// hex digits, and in writing a space as `+`.
fn percent_forms(secret: &str) -> Vec<Zeroizing<String>> {
    const KEEP: [&[u8]; 4] = [b"-._~", b"*-._", b"-_.!~*'()", b"-._~/"];
    let mut out = Vec::new();
    for keep in KEEP {
        for upper in [true, false] {
            for plus in [false, true] {
                if plus && !secret.contains(' ') {
                    continue;
                }
                out.push(percent(secret.as_bytes(), keep, upper, plus));
            }
        }
    }
    out
}

fn percent(bytes: &[u8], keep: &[u8], upper: bool, plus: bool) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len() * 3));
    for &b in bytes {
        if b.is_ascii_alphanumeric() || keep.contains(&b) {
            out.push(char::from(b));
        } else if plus && b == b' ' {
            out.push('+');
        } else {
            out.push('%');
            out.push(hex_digit(b >> 4, upper));
            out.push(hex_digit(b, upper));
        }
    }
    out
}

/// `secret` inside a JSON string, as serializers escape it: with or without
/// `\/` (PHP), and with non-ASCII as `\uXXXX` or not (Python's default).
fn json_forms(secret: &str) -> Vec<Zeroizing<String>> {
    let mut out = Vec::new();
    for slash in [false, true] {
        for ascii in [false, true] {
            out.push(json(secret, slash, ascii));
        }
    }
    out
}

fn json(secret: &str, slash: bool, ascii: bool) -> Zeroizing<String> {
    // The longest escape, `\uXXXX`, is 6 bytes for a 1-byte control char
    // (a 4-byte char becomes two of them: 12 bytes). Reserved up front so
    // the buffer never reallocates and leaves a copy behind.
    let mut out = Zeroizing::new(String::with_capacity(secret.len() * 6));
    let mut units = [0u16; 2];
    for c in secret.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '/' if slash => out.push_str("\\/"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if c < ' ' || (ascii && !c.is_ascii()) => {
                for unit in c.encode_utf16(&mut units).iter() {
                    out.push_str("\\u");
                    out.push_str(&hex(&unit.to_be_bytes(), false));
                }
            }
            c => out.push(c),
        }
    }
    units.zeroize();
    out
}

/// A command to run with secrets in its environment.
pub struct RunRequest {
    /// `NAME` → reference.
    pub env: Vec<(String, String)>,
    /// Files to write (0600) before running and remove after: path →
    /// reference.
    pub files: Vec<(PathBuf, String)>,
    /// Program and arguments (no secrets here: they would show in `ps`).
    pub command: Vec<OsString>,
    /// Working directory.
    pub cwd: Option<PathBuf>,
    /// Why (logged).
    pub reason: String,
    /// How long to wait for the person when the policy says `ask`.
    pub wait: Duration,
    /// Kill the command after this long.
    pub timeout: Duration,
}

/// What a command did; its output already redacted.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RunOutput {
    /// Exit code (`None` if killed by a signal or the timeout).
    pub code: Option<i32>,
    /// Standard output, redacted and truncated to [`MAX_OUTPUT`].
    pub stdout: String,
    /// Standard error, redacted and truncated.
    pub stderr: String,
    /// Places in the output where a secret value, an encoding of one or a
    /// long piece of one was replaced (adjacent matches count once).
    pub redactions: usize,
    /// Whether it was killed after the timeout.
    pub timed_out: bool,
}

/// Fails, before any secret is asked for, if `path` cannot be created:
/// it exists (without `force`) or its directory does not.
fn check_writable(path: &Path, force: bool) -> ClientResult<()> {
    if !force && std::fs::symlink_metadata(path).is_ok() {
        return Err(ClientError::Invalid(format!(
            "{} already exists",
            path.display()
        )));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(ClientError::Invalid(format!(
            "the directory of {} does not exist",
            path.display()
        )));
    }
    Ok(())
}

/// A new 0600 file that never shows partly written under its name
/// ([`write_secret_file`]); `force` replaces an existing one in one step.
fn write_new_private(path: &Path, content: &[u8], force: bool) -> ClientResult<()> {
    Ok(write_secret_file(path, content, force)?)
}

/// Removes the files it holds when dropped.
struct Written(Vec<PathBuf>);

impl Drop for Written {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

async fn read_capped(mut reader: impl tokio::io::AsyncRead + Unpin) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                // Keep reading so the child never blocks on a full pipe.
                let room = (MAX_OUTPUT * 2).saturating_sub(out.len());
                out.extend_from_slice(&buf[..n.min(room)]);
            }
        }
    }
    out
}

fn finish(bytes: &[u8], redactor: &Redactor) -> (String, usize) {
    let (mut text, n) = redactor.apply(&String::from_utf8_lossy(bytes));
    if text.len() > MAX_OUTPUT {
        let mut cut = MAX_OUTPUT;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        text.push_str("\n[output truncated by klav]");
    }
    (text, n)
}

/// Runs a command with the values of `req.env` in its environment and
/// `req.files` on disk, and returns its output redacted.
pub async fn run(
    session: &mut Session,
    scope: Option<(&str, &str)>,
    req: RunRequest,
) -> ClientResult<RunOutput> {
    let (program, args) = req
        .command
        .split_first()
        .ok_or_else(|| ClientError::Invalid("missing command".into()))?;
    let references: Vec<String> = req
        .env
        .iter()
        .map(|(_, r)| r.clone())
        .chain(req.files.iter().map(|(_, r)| r.clone()))
        .collect();
    // Checked before asking for anything, so a failure here never shows
    // in the audit log as a secret obtained.
    for (path, _) in &req.files {
        check_writable(path, false)?;
    }
    let values = session
        .resolve(&references, scope, &req.reason, req.wait)
        .await?;
    let (env_values, file_values) = values.split_at(req.env.len());
    let env_texts: Vec<&str> = env_values
        .iter()
        .map(Resolved::text)
        .collect::<ClientResult<_>>()?;
    // Attachments printed by the command are redacted when they are text,
    // and so are the values this session already wrote to files
    // (`inject_file`): the command may read those files (ADR 0030 §2).
    let redactor = Redactor::new(
        env_texts
            .iter()
            .copied()
            .chain(
                file_values
                    .iter()
                    .filter_map(|v| std::str::from_utf8(&v.value).ok()),
            )
            .chain(session.injected()),
    );
    let mut written = Written(Vec::new());
    for ((path, _), value) in req.files.iter().zip(file_values) {
        write_new_private(path, &value.value, false)?;
        written.0.push(path.clone());
    }
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(cwd) = &req.cwd {
        command.current_dir(cwd);
    }
    for ((name, _), value) in req.env.iter().zip(&env_texts) {
        command.env(name, value);
    }
    let spawned = command.spawn();
    // `Command` keeps copies of the environment that cannot be zeroized;
    // drop it and the values right away (threat T33).
    drop(command);
    drop(env_texts);
    drop(values);
    let mut child = spawned.map_err(|e| {
        ClientError::Invalid(format!("cannot run {}: {e}", program.to_string_lossy()))
    })?;
    let stdout = child.stdout.take().map(|s| tokio::spawn(read_capped(s)));
    let stderr = child.stderr.take().map(|s| tokio::spawn(read_capped(s)));
    let (status, timed_out) = match tokio::time::timeout(req.timeout, child.wait()).await {
        Ok(status) => (Some(status?), false),
        Err(_) => {
            let _ = child.kill().await;
            (None, true)
        }
    };
    let collect = |task: Option<tokio::task::JoinHandle<Vec<u8>>>| async move {
        match task {
            Some(t) => t.await.unwrap_or_default(),
            None => Vec::new(),
        }
    };
    let (out, n_out) = finish(&collect(stdout).await, &redactor);
    let (err, n_err) = finish(&collect(stderr).await, &redactor);
    drop(written);
    Ok(RunOutput {
        code: status.and_then(|s| s.code()),
        stdout: out,
        stderr: err,
        redactions: n_out + n_err,
        timed_out,
    })
}

/// What to write with [`inject_file`].
pub struct InjectRequest {
    /// A template with `{{ klav://… }}` references…
    pub template: Option<String>,
    /// …or one reference whose value is written as is.
    pub reference: Option<String>,
    /// The file to create (mode 0600).
    pub path: PathBuf,
    /// Replace an existing file.
    pub force: bool,
    /// Why (logged).
    pub reason: String,
    /// How long to wait for the person when the policy says `ask`.
    pub wait: Duration,
}

/// Writes secrets into a new 0600 file. Returns the bytes written. The
/// caller removes the file when done.
pub async fn inject_file(
    session: &mut Session,
    scope: Option<(&str, &str)>,
    req: InjectRequest,
) -> ClientResult<usize> {
    check_writable(&req.path, req.force)?;
    let mut remembered: Vec<Zeroizing<String>> = Vec::new();
    let content: Zeroizing<Vec<u8>> = match (&req.template, &req.reference) {
        (None, Some(reference)) => {
            let mut values = session
                .resolve(
                    std::slice::from_ref(reference),
                    scope,
                    &req.reason,
                    req.wait,
                )
                .await?;
            let value = values
                .pop()
                .ok_or_else(|| ClientError::Invalid("nothing resolved".into()))?;
            if let Ok(text) = std::str::from_utf8(&value.value) {
                remembered.push(Zeroizing::new(text.to_owned()));
            }
            value.value
        }
        (Some(text), None) => {
            let pieces = template::parse(text).map_err(ClientError::Invalid)?;
            let references = template::references(&pieces);
            // A template without references would write a file without any
            // policy check or audit event: it is not an injection.
            if references.is_empty() {
                return Err(ClientError::Invalid(
                    "the template has no {{ klav://… }} reference: write files without secrets yourself"
                        .into(),
                ));
            }
            let values = session
                .resolve_with(&references, scope, &req.reason, req.wait, false)
                .await?;
            for v in &values {
                remembered.push(Zeroizing::new(v.text()?.to_owned()));
            }
            let mut values = values.iter();
            let mut out = Zeroizing::new(Vec::with_capacity(text.len()));
            for piece in &pieces {
                match piece {
                    Piece::Text(t) => out.extend_from_slice(t.as_bytes()),
                    Piece::Reference(_) => {
                        let v = values
                            .next()
                            .ok_or_else(|| ClientError::Invalid("nothing resolved".into()))?;
                        out.extend_from_slice(v.text()?.as_bytes());
                    }
                }
            }
            out
        }
        _ => {
            return Err(ClientError::Invalid(
                "give either a template or one reference".into(),
            ));
        }
    };
    write_new_private(&req.path, &content, req.force)?;
    session.remember_injected(remembered.iter().map(|v| v.as_str()));
    Ok(content.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_replaces_every_value() {
        let r = Redactor::new(["hunter2", "", "hunter2-long"]);
        let (text, n) = r.apply("a hunter2-long b hunter2 c");
        assert_eq!(text, format!("a {REDACTED} b {REDACTED} c"));
        assert_eq!(n, 2);
        assert_eq!(r.apply("nothing").1, 0);
        let big = "x".repeat(MAX_OUTPUT + 10);
        let (cut, _) = finish(big.as_bytes(), &r);
        assert!(cut.ends_with("[output truncated by klav]"));
    }

    use data_encoding::{BASE64, BASE64URL_NOPAD};

    /// A synthetic secret with characters that every encoding treats
    /// differently (`/`, `+`-producing bytes, a space, a quote, non-ASCII).
    const LONG: &str = "MARKER-long/secret \"value\" ñ 9f?+";

    fn redacted_whole(r: &Redactor, shown: &str) {
        let (text, n) = r.apply(&format!("<{shown}>"));
        assert_eq!(text, format!("<{REDACTED}>"), "encoding not redacted");
        assert_eq!(n, 1);
    }

    #[test]
    fn redaction_catches_base64() {
        let r = Redactor::new([LONG]);
        let bytes = LONG.as_bytes();
        redacted_whole(&r, &BASE64.encode(bytes));
        redacted_whole(&r, &data_encoding::BASE64_NOPAD.encode(bytes));
        redacted_whole(&r, &data_encoding::BASE64URL.encode(bytes));
        redacted_whole(&r, &BASE64URL_NOPAD.encode(bytes));
    }

    #[test]
    fn redaction_catches_base64_at_any_offset() {
        let password = "MARKER-basic-pass-99";
        let r = Redactor::new([password]);
        // "ana:", "anna:" and "annie:" put the password at all three
        // offsets modulo 3 inside the blob.
        for user in ["ana", "anna", "annie"] {
            let prefix = format!("{user}:");
            let blob = BASE64.encode(format!("{prefix}{password}").as_bytes());
            let (text, n) = r.apply(&format!("Authorization: Basic {blob}\n"));
            // Only the characters that hold the user's bits are left.
            let keep = (8 * prefix.len()).div_ceil(6);
            assert_eq!(
                text,
                format!("Authorization: Basic {}{REDACTED}\n", &blob[..keep]),
                "offset {}",
                prefix.len() % 3
            );
            assert_eq!(n, 1);
            // In the middle of a blob, the characters after it stay.
            for tail in ["x", "xy", "xyz"] {
                let blob = BASE64URL_NOPAD.encode(format!("{prefix}{password}{tail}").as_bytes());
                let end = 8 * (prefix.len() + password.len()) / 6;
                let (text, _) = r.apply(&blob);
                assert_eq!(text, format!("{}{REDACTED}{}", &blob[..keep], &blob[end..]));
            }
        }
    }

    #[test]
    fn redaction_catches_hex() {
        let r = Redactor::new([LONG]);
        redacted_whole(&r, &data_encoding::HEXLOWER.encode(LONG.as_bytes()));
        redacted_whole(&r, &data_encoding::HEXUPPER.encode(LONG.as_bytes()));
    }

    #[test]
    fn redaction_catches_percent_encoding() {
        let r = Redactor::new([LONG]);
        let rfc = "MARKER-long%2Fsecret%20%22value%22%20%C3%B1%209f%3F%2B";
        redacted_whole(&r, rfc);
        redacted_whole(&r, &rfc.to_lowercase().replace("marker", "MARKER"));
        // Forms: `+` for a space; Python's `quote` keeps `/`.
        redacted_whole(&r, &rfc.replace("%20", "+"));
        redacted_whole(&r, &rfc.replace("%2F", "/"));
    }

    #[test]
    fn redaction_catches_json_escaping() {
        let secret = "MARKER-json\"quote\\back/slash\nline\u{1}ñ";
        let r = Redactor::new([secret]);
        let serde = serde_json::to_string(secret).unwrap();
        redacted_whole(&r, serde.trim_matches('"'));
        redacted_whole(&r, &serde.trim_matches('"').replace('/', "\\/"));
        redacted_whole(&r, &serde.trim_matches('"').replace('ñ', "\\u00f1"));
    }

    #[test]
    fn redaction_catches_long_fragments() {
        let secret = "MARKER-0123456789-abcdefghij-split";
        let r = Redactor::new([secret]);
        // Cut across two lines: each half is a fragment.
        let (head, tail) = secret.split_at(17);
        let (text, n) = r.apply(&format!("token: {head}\n{tail}\n"));
        assert_eq!(text, format!("token: {REDACTED}\n{REDACTED}\n"));
        assert_eq!(n, 2);
        // The whole run is redacted, not just the windows: no characters of
        // the secret are left next to the marker.
        let (text, _) = r.apply(&format!("[{}]", &secret[3..30]));
        assert_eq!(text, format!("[{REDACTED}]"));
        // Below the threshold, a piece stays.
        let piece = &secret[..MIN_FRAGMENT_CHARS - 1];
        assert_eq!(r.apply(piece), (piece.to_owned(), 0));
        // A fragment of an encoding counts too (base64 wrapped by `base64`).
        let b64 = BASE64.encode(secret.as_bytes());
        let (text, n) = r.apply(&format!("{}\n{}", &b64[..24], &b64[24..]));
        assert_eq!(text, format!("{REDACTED}\n{REDACTED}"));
        assert_eq!(n, 2);
    }

    #[test]
    fn short_secrets_only_match_whole() {
        let r = Redactor::new(["pin-4821", "42"]);
        let (text, n) = r.apply("pin-4821 pin-48 4821 x42y");
        assert_eq!(text, format!("{REDACTED} pin-48 4821 x{REDACTED}y"));
        assert_eq!(n, 2);
        // Encodings shorter than MIN_ENCODED_CHARS are not looked for: "42"
        // in hex is "3432", which would hit any number.
        assert_eq!(r.apply("3432 NDI=").1, 0);
        // A long enough encoding of a short secret is still caught whole…
        let hex = data_encoding::HEXLOWER.encode(b"pin-4821");
        assert_eq!(r.apply(&hex).0, REDACTED);
        // …but not in pieces.
        assert_eq!(r.apply(&hex[..12]).1, 0);
    }

    #[test]
    fn overlapping_matches_merge() {
        let r = Redactor::new(["MARKER-overlap-one-1", "overlap-one-1-and-two"]);
        let (text, n) = r.apply("a MARKER-overlap-one-1-and-two b");
        assert_eq!(text, format!("a {REDACTED} b"));
        assert_eq!(n, 1);
        // Self-overlapping occurrences of a short secret.
        let r = Redactor::new(["abab"]);
        assert_eq!(r.apply("xababab"), (format!("x{REDACTED}"), 1));
        // Adjacent secrets become one marker.
        let r = Redactor::new(["MARKER-adjacent-a", "MARKER-adjacent-b"]);
        let (text, n) = r.apply("MARKER-adjacent-aMARKER-adjacent-b!");
        assert_eq!(text, format!("{REDACTED}!"));
        assert_eq!(n, 1);
    }

    #[test]
    fn ordinary_output_is_unchanged() {
        let r = Redactor::new([LONG, "MARKER-other-value-77", "pin-4821"]);
        let output = "commit 3f786850e387550fdab836ed7e6dc881de23001b\n\
            Author: Ana <ana@example.com>\n\
            token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\n\
            https://example.com/a%20b?q=1+2&x=%2F\n\
            {\"ok\": true, \"path\": \"C:\\\\tmp\\/x\\u00f1\"}\n\
            ñandú 日本語 — 100% done in 4.2s\n";
        assert_eq!(r.apply(output), (output.to_owned(), 0));
    }

    #[test]
    fn repetitive_input_stays_linear() {
        // A periodic secret against periodic output at the read cap: the
        // worst case for a match-and-extend search, linear here.
        let secret = "a".repeat(4096);
        let r = Redactor::new([secret.as_str(), "aa"]);
        let (text, n) = r.apply(&"a".repeat(MAX_OUTPUT * 2));
        assert_eq!((text.as_str(), n), (REDACTED, 1));
    }

    #[test]
    fn private_files_are_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        write_new_private(&path, b"a", false).unwrap();
        assert!(write_new_private(&path, b"b", false).is_err());
        write_new_private(&path, b"b", true).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// Feeds `body` to a stream redactor in pieces cut at `cuts`.
    fn streamed(r: Redactor, body: &[u8], cuts: &[usize]) -> Vec<u8> {
        let mut stream = StreamRedactor::new(r);
        let mut out = Vec::new();
        let mut from = 0;
        let mut cuts: Vec<usize> = cuts.iter().map(|c| c % (body.len() + 1)).collect();
        cuts.sort_unstable();
        for cut in cuts.into_iter().chain(std::iter::once(body.len())) {
            if cut < from {
                continue;
            }
            out.extend(stream.push(&body[from..cut]).unwrap());
            from = cut;
        }
        out.extend(stream.finish());
        out
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn a_value_split_across_chunks_is_still_replaced() {
        let secret = "sk_live_0123456789abcdefXYZ";
        let b64 = base64_forms(secret.as_bytes());
        let body = format!("{{\"echo\":\"{secret}\",\"b64\":\"{}\"}}", b64[0].as_str());
        for cut in 0..=body.len() {
            let out = streamed(Redactor::new([secret]), body.as_bytes(), &[cut]);
            assert!(!contains(&out, secret.as_bytes()), "cut at {cut}");
            assert!(
                !contains(&out, &secret.as_bytes()[..MIN_FRAGMENT_CHARS]),
                "cut at {cut}"
            );
            assert!(contains(&out, REDACTED.as_bytes()));
        }
    }

    #[test]
    fn a_clean_body_streams_unchanged_and_invalid_utf8_passes() {
        let body = b"HTTP body \xff\xfe with bytes that are not UTF-8 \xe6\x97\xa5";
        for cut in 0..=body.len() {
            let out = streamed(
                Redactor::new(["a-secret-of-some-length"]),
                body,
                &[cut, cut / 2],
            );
            assert_eq!(out, body.to_vec());
        }
        // Without values, chunks pass straight through.
        let mut stream = StreamRedactor::new(Redactor::new([]));
        assert_eq!(stream.push(b"abc").unwrap(), b"abc");
        assert!(stream.finish().is_empty());
    }

    /// T149, Omar's answer (ADR 0036 E9): the proxy's redactor replaces
    /// only the whole value. A guessed piece comes back as it was, and is
    /// counted.
    #[test]
    fn whole_values_leave_a_guessed_piece_and_count_it() {
        let secret = "github_pat_0123456789abcdefghij";
        let r = Redactor::whole_values([secret]);
        for guess in [&secret[..12], &secret[..20], &secret[5..29], &secret[1..]] {
            let echoed = format!("404: no route /{guess}/x");
            let (out, replaced, partial) = r.scan_bytes(echoed.as_bytes());
            assert_eq!(out, echoed.as_bytes(), "a piece is left: {guess}");
            assert_eq!((replaced, partial), (0, 1), "{guess}");
        }
        // Shorter than a fragment: neither replaced nor counted.
        let (_, replaced, partial) = r.scan_bytes(&secret.as_bytes()[..11]);
        assert_eq!((replaced, partial), (0, 0));
        // The whole value, also next to a piece of itself: only the whole
        // one is replaced, and the piece beside it counts.
        let (out, replaced, partial) =
            r.scan_bytes(format!("a {secret} b {} c", &secret[..15]).as_bytes());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("a {REDACTED} b {} c", &secret[..15])
        );
        assert_eq!((replaced, partial), (1, 1));
        // Nothing of it: nothing counted.
        let (_, replaced, partial) = r.scan_bytes(b"a clean answer");
        assert_eq!((replaced, partial), (0, 0));
        // `new` (the CLI's output) still replaces pieces, and counts none.
        let (out, replaced, partial) = Redactor::new([secret]).scan_bytes(&secret.as_bytes()[..14]);
        assert_eq!(out, REDACTED.as_bytes());
        assert_eq!((replaced, partial), (1, 0));
    }

    /// The whole value is still replaced in every encoding `new` covers.
    #[test]
    fn whole_values_still_replace_every_encoding() {
        let r = Redactor::whole_values([LONG]);
        let bytes = LONG.as_bytes();
        let rfc = "MARKER-long%2Fsecret%20%22value%22%20%C3%B1%209f%3F%2B";
        let serde = serde_json::to_string(LONG).unwrap();
        for shown in [
            LONG.to_owned(),
            BASE64.encode(bytes),
            data_encoding::BASE64_NOPAD.encode(bytes),
            data_encoding::BASE64URL.encode(bytes),
            BASE64URL_NOPAD.encode(bytes),
            data_encoding::HEXLOWER.encode(bytes),
            data_encoding::HEXUPPER.encode(bytes),
            rfc.to_owned(),
            rfc.replace("%20", "+"),
            rfc.replace("%2F", "/"),
            serde.trim_matches('"').to_owned(),
        ] {
            redacted_whole(&r, &shown);
            let (_, replaced, partial) = r.scan_bytes(format!("<{shown}>").as_bytes());
            assert_eq!((replaced, partial), (1, 0), "{shown}");
        }
        // Inside a base64 blob, at every offset.
        let password = "MARKER-basic-pass-99";
        let r = Redactor::whole_values([password]);
        for user in ["ana", "anna", "annie"] {
            let blob = BASE64.encode(format!("{user}:{password}").as_bytes());
            let (text, n) = r.apply(&blob);
            assert!(text.ends_with(REDACTED), "{user}");
            assert_eq!(n, 1);
        }
        // A value that overlaps itself is replaced at every occurrence.
        let periodic = "abcabcabcabc";
        let (text, _) = Redactor::whole_values([periodic]).apply("abcabcabcabcabc");
        assert_eq!(text, REDACTED);
    }

    /// In a stream: the whole value is replaced across every cut, and a
    /// piece counts once wherever the chunks split it.
    #[test]
    fn whole_values_in_a_stream_count_a_piece_once() {
        let secret = "sk_live_0123456789abcdefXYZ";
        // Padding after the guess, so the cuts split it in what is emitted,
        // not only in what is held back.
        let body = format!(
            "{{\"echo\":\"{secret}\",\"guess\":\"{}\",\"pad\":\"{}\"}}",
            &secret[..16],
            "p".repeat(64)
        );
        for cut in 0..=body.len() {
            let mut stream = StreamRedactor::new(Redactor::whole_values([secret]));
            let mut out = stream.push(&body.as_bytes()[..cut]).unwrap();
            out.extend(stream.push(&body.as_bytes()[cut..]).unwrap());
            let (last, replaced, partial) = stream.finish_all();
            out.extend(last);
            assert!(!contains(&out, secret.as_bytes()), "cut at {cut}");
            assert!(contains(&out, &secret.as_bytes()[..16]), "cut at {cut}");
            assert_eq!((replaced, partial), (1, 1), "cut at {cut}");
        }
    }

    #[test]
    fn a_runaway_redacted_stretch_is_cut() {
        let secret = "b".repeat(64);
        let mut stream = StreamRedactor::new(Redactor::new([secret.as_str()]));
        let chunk = "b".repeat(64 * 1024);
        let mut overflow = false;
        for _ in 0..(MAX_STREAM_HOLD / chunk.len() + 2) {
            match stream.push(chunk.as_bytes()) {
                Ok(out) => assert!(!contains(&out, &secret.as_bytes()[..MIN_FRAGMENT_CHARS])),
                Err(HoldOverflow) => {
                    overflow = true;
                    break;
                }
            }
        }
        assert!(overflow);
    }

    /// Feeds `body` to `stream` in pieces cut at `cuts`: the output, the
    /// places replaced and the pieces left, and after each push how many
    /// bytes of the body had gone out (the emission points).
    fn fed(
        mut stream: StreamRedactor,
        body: &[u8],
        cuts: &[usize],
    ) -> ((Vec<u8>, usize, usize), Vec<usize>) {
        let mut out = Vec::new();
        let mut points = Vec::new();
        let mut from = 0;
        let mut cuts: Vec<usize> = cuts.iter().map(|c| c % (body.len() + 1)).collect();
        cuts.sort_unstable();
        for cut in cuts.into_iter().chain(std::iter::once(body.len())) {
            if cut < from {
                continue;
            }
            out.extend(stream.push(&body[from..cut]).unwrap());
            points.push(cut - stream.held.len());
            from = cut;
        }
        let (last, replaced, partial) = stream.finish_all();
        out.extend(last);
        ((out, replaced, partial), points)
    }

    /// Both kinds of redactor for `value`: pieces replaced (the CLI) and
    /// only whole values (the proxy).
    fn both() -> [fn(&str) -> Redactor; 2] {
        [|v| Redactor::new([v]), |v| Redactor::whole_values([v])]
    }

    /// Every form of `value` the redactor covers, as a program would print
    /// it: verbatim, base64 (both alphabets, padded or not, alone and at
    /// each offset inside a blob), hex, percent-encoding and JSON escaping.
    fn printed_forms(value: &str) -> Vec<String> {
        let bytes = value.as_bytes();
        let mut forms = vec![
            value.to_owned(),
            BASE64.encode(bytes),
            data_encoding::BASE64_NOPAD.encode(bytes),
            data_encoding::BASE64URL.encode(bytes),
            BASE64URL_NOPAD.encode(bytes),
            data_encoding::HEXLOWER.encode(bytes),
            data_encoding::HEXUPPER.encode(bytes),
            serde_json::to_string(value)
                .unwrap()
                .trim_matches('"')
                .to_owned(),
        ];
        for user in ["ana", "anna", "annie"] {
            forms.push(BASE64.encode(format!("{user}:{value}").as_bytes()));
        }
        forms.extend(percent_forms(value).iter().map(|f| f.as_str().to_owned()));
        forms.extend(json_forms(value).iter().map(|f| f.as_str().to_owned()));
        forms
    }

    /// A body with every form of `value` on lines of their own, ended by
    /// LF, CRLF or CR, two forms on one line, a 14-character piece and a
    /// clean line.
    fn body_of_forms(value: &str) -> Vec<u8> {
        let mut body = String::from("event: message\n");
        for (i, form) in printed_forms(value).iter().enumerate() {
            let end = ["\n", "\r\n", "\r"][i % 3];
            body.push_str(&format!("data: {{\"k\":\"{form}\"}}{end}"));
        }
        body.push_str(&format!("data: {value} and {value}\n"));
        body.push_str(&format!("data: {} piece\n\n", &value[..14]));
        body.push_str("data: a clean line with no end");
        body.into_bytes()
    }

    /// Nothing caught today is lost: at every split, in every form, line by
    /// line gives the default rule's output, and the output and counts of
    /// redacting the whole body at once.
    #[test]
    fn by_lines_redacts_what_the_default_does_at_every_split() {
        let body = body_of_forms(LONG);
        for make in both() {
            let whole = make(LONG).scan_bytes(&body);
            assert!(whole.1 > 20, "every form is found");
            for cut in 0..=body.len() {
                let (lines, _) = fed(StreamRedactor::by_lines(make(LONG)), &body, &[cut]);
                let (default, _) = fed(StreamRedactor::new(make(LONG)), &body, &[cut]);
                assert!(lines == whole, "line by line, cut at {cut}");
                assert!(lines.0 == default.0, "against the default, cut at {cut}");
            }
            // Three cuts, everywhere around the two forms on one line.
            let at = body.len() - 120;
            for a in at..body.len() {
                let (lines, _) = fed(
                    StreamRedactor::by_lines(make(LONG)),
                    &body,
                    &[a - 50, a, a + 7],
                );
                assert!(lines == whole, "cuts around {a}");
            }
        }
    }

    /// A line goes out with the chunk that ends it, redacted, with nothing
    /// held; the default rule holds its end until the next chunk.
    #[test]
    fn by_lines_emits_a_whole_line_before_the_next_chunk() {
        let secret = "sk_live_0123456789abcdefXYZ";
        let event = format!("event: message\ndata: {{\"result\":{{\"echo\":\"{secret}\"}}}}\n\n");
        let redacted =
            format!("event: message\ndata: {{\"result\":{{\"echo\":\"{REDACTED}\"}}}}\n\n");
        for make in both() {
            let mut stream = StreamRedactor::by_lines(make(secret));
            assert!(stream.emits_by_line());
            let out = stream.push(event.as_bytes()).unwrap();
            assert!(out == redacted.as_bytes(), "the event, redacted");
            assert!(stream.held.is_empty());
            assert_eq!(stream.replaced(), 1);
            let clean = b"event: ping\ndata: {}\n\n";
            assert_eq!(stream.push(clean).unwrap(), clean.to_vec());
            // A line in two chunks goes out whole with the second.
            assert!(stream.push(b"data: {\"a\":").unwrap().is_empty());
            assert_eq!(stream.push(b"1}\n\n").unwrap(), b"data: {\"a\":1}\n\n");
            assert!(stream.finish().is_empty());

            let mut default = StreamRedactor::new(make(secret));
            assert!(!default.emits_by_line());
            let out = default.push(clean).unwrap();
            assert!(out.len() < clean.len(), "the default holds the end back");
        }
    }

    /// Nothing goes out that a later chunk completes into a match: what
    /// follows the last line end waits, whatever it is.
    #[test]
    fn by_lines_holds_what_a_later_chunk_could_complete() {
        let secret = "sk_live_0123456789abcdefXYZ";
        let b64 = BASE64.encode(secret.as_bytes());
        for form in [secret, b64.as_str(), &secret[..16]] {
            for make in both() {
                for k in 1..form.len() {
                    let mut stream = StreamRedactor::by_lines(make(secret));
                    let first = stream
                        .push(format!("ok\ndata: {}", &form[..k]).as_bytes())
                        .unwrap();
                    assert!(first == b"ok\n", "only the ended line, cut at {k}");
                    let mut out = first;
                    out.extend(stream.push(format!("{}\n", &form[k..]).as_bytes()).unwrap());
                    out.extend(stream.finish());
                    let whole = make(secret).scan_bytes(format!("ok\ndata: {form}\n").as_bytes());
                    assert!(out == whole.0, "cut at {k}");
                }
            }
        }
    }

    /// CR, LF and CRLF all end a line, also with CRLF split between two
    /// chunks.
    #[test]
    fn by_lines_ends_lines_at_cr_lf_and_crlf() {
        let secret = "sk_live_0123456789abcdefXYZ";
        for end in ["\n", "\r", "\r\n"] {
            let mut stream = StreamRedactor::by_lines(Redactor::whole_values([secret]));
            assert_eq!(
                stream.push(format!("a{end}").as_bytes()).unwrap(),
                format!("a{end}").into_bytes()
            );
            let out = stream.push(format!("b {secret}{end}c").as_bytes()).unwrap();
            assert!(out == format!("b {REDACTED}{end}").into_bytes(), "{end:?}");
            assert_eq!(stream.finish(), b"c");
        }
        let mut stream = StreamRedactor::by_lines(Redactor::whole_values([secret]));
        assert_eq!(stream.push(b"x\r").unwrap(), b"x\r");
        assert_eq!(stream.push(b"\ny").unwrap(), b"\n");
        assert_eq!(stream.finish(), b"y");
    }

    /// A value with a line end in it could match across one: the stream
    /// falls back to the default rule, and still replaces it at every
    /// split.
    #[test]
    fn a_value_with_a_line_end_falls_back_to_the_default_rule() {
        for end in ["\n", "\r"] {
            let secret = format!("first-line-part{end}second-line-part");
            let body = format!("x {secret} y\nz");
            let inner = body.find(end).unwrap() + 1;
            for make in both() {
                let mut stream = StreamRedactor::by_lines(make(&secret));
                assert!(!stream.emits_by_line());
                let first = stream.push(&body.as_bytes()[..inner]).unwrap();
                assert!(!contains(&first, b"first-line-part"), "{end:?}");
                let whole = make(&secret).scan_bytes(body.as_bytes());
                assert_eq!(whole.1, 1);
                for cut in 0..=body.len() {
                    let (out, _) = fed(
                        StreamRedactor::by_lines(make(&secret)),
                        body.as_bytes(),
                        &[cut],
                    );
                    assert!(out.0 == whole.0, "{end:?}, cut at {cut}");
                }
            }
        }
        // Any value with a line end is enough; without one, by line.
        assert!(
            !StreamRedactor::by_lines(Redactor::new(["sk-0123456789", "a\nb"])).emits_by_line()
        );
        assert!(StreamRedactor::by_lines(Redactor::new(["sk-0123456789", "a b"])).emits_by_line());
    }

    #[test]
    fn by_lines_takes_empty_chunks_and_passes_without_values() {
        let mut stream = StreamRedactor::by_lines(Redactor::new(["sk_live_0123456789abc"]));
        assert!(stream.push(b"").unwrap().is_empty());
        assert!(stream.push(b"data: x").unwrap().is_empty());
        assert!(stream.push(b"").unwrap().is_empty());
        assert_eq!(stream.held.len(), 7);
        assert_eq!(stream.push(b"\n").unwrap(), b"data: x\n");
        assert!(stream.push(b"").unwrap().is_empty());
        assert!(stream.finish().is_empty());
        // Without values, chunks pass straight through, line end or not.
        let mut stream = StreamRedactor::by_lines(Redactor::new([]));
        assert_eq!(stream.push(b"abc").unwrap(), b"abc");
        assert!(stream.finish().is_empty());
    }

    /// The hold cap stays: a line longer than it is cut as an error, and
    /// lines under it stream however long the body.
    #[test]
    fn by_lines_cuts_a_line_longer_than_the_cap() {
        let r = || Redactor::whole_values(["sk_live_0123456789abcdefXYZ"]);
        let mut stream = StreamRedactor::by_lines(r());
        let mut line = vec![b'a'; 64 * 1024 - 1];
        line.push(b'\n');
        for _ in 0..(2 * MAX_STREAM_HOLD / line.len()) {
            assert_eq!(stream.push(&line).unwrap().len(), line.len());
        }
        let mut stream = StreamRedactor::by_lines(r());
        let chunk = vec![b'a'; 64 * 1024];
        let mut overflow = false;
        for _ in 0..(MAX_STREAM_HOLD / chunk.len() + 2) {
            match stream.push(&chunk) {
                Ok(out) => assert!(out.is_empty()),
                Err(HoldOverflow) => {
                    overflow = true;
                    break;
                }
            }
        }
        assert!(overflow);
        // A line end after the cap is too late: the tail is what counts.
        let mut stream = StreamRedactor::by_lines(r());
        let mut long = vec![b'a'; MAX_STREAM_HOLD + 1];
        long.push(b'\n');
        long.extend(vec![b'b'; MAX_STREAM_HOLD + 1]);
        assert_eq!(stream.push(&long), Err(HoldOverflow));
    }

    proptest::proptest! {
        /// When bytes go out depends only on where the line ends are: a
        /// right whole-value guess and a wrong one of the same length, in
        /// any form, give the same emission points.
        #[test]
        fn prop_by_lines_emits_at_the_same_points_for_a_right_and_a_wrong_guess(
            secret in "[A-Za-z0-9_\\-]{12,40}",
            wrong_seed in "[A-Za-z0-9_\\-]{40}",
            form in 0usize..4,
            before in "[a-z \r\n]{0,48}",
            after in "[a-z \r\n]{0,48}",
            cuts in proptest::collection::vec(0usize..200, 0..8),
            pieces in proptest::prelude::any::<bool>(),
        ) {
            let wrong = &wrong_seed[..secret.len()];
            proptest::prop_assume!(wrong != secret);
            let print = |v: &str| match form {
                0 => v.to_owned(),
                1 => BASE64.encode(v.as_bytes()),
                2 => data_encoding::HEXLOWER.encode(v.as_bytes()),
                _ => format!("\"{v}\""),
            };
            let make = || if pieces {
                Redactor::new([secret.as_str()])
            } else {
                Redactor::whole_values([secret.as_str()])
            };
            let right_body = format!("{before}{}{after}", print(&secret)).into_bytes();
            let wrong_body = format!("{before}{}{after}", print(wrong)).into_bytes();
            let (right, right_points) = fed(StreamRedactor::by_lines(make()), &right_body, &cuts);
            let (_, wrong_points) = fed(StreamRedactor::by_lines(make()), &wrong_body, &cuts);
            proptest::prop_assert!(right_points == wrong_points, "the emission points differ");
            proptest::prop_assert!(right.1 >= 1, "the right guess is replaced");
            proptest::prop_assert!(!contains(&right.0, secret.as_bytes()));
        }

        /// However a body is cut, line by line gives the output and the
        /// counts of redacting it at once.
        #[test]
        fn prop_by_lines_redacts_as_the_whole_body_does(
            secret in "[A-Za-z0-9_\\-]{12,40}",
            filler in proptest::collection::vec(
                proptest::prop_oneof![
                    proptest::prelude::any::<u8>(),
                    proptest::strategy::Just(b'\n'),
                    proptest::strategy::Just(b'\r'),
                ],
                0..48,
            ),
            forms in proptest::collection::vec(0usize..11, 0..4),
            cuts in proptest::collection::vec(0usize..600, 0..8),
            pieces in proptest::prelude::any::<bool>(),
        ) {
            let printed = printed_forms(&secret);
            let mut body = filler.clone();
            for f in forms {
                body.extend_from_slice(printed[f].as_bytes());
                body.extend_from_slice(&filler);
            }
            body.extend_from_slice(&secret.as_bytes()[..MIN_FRAGMENT_CHARS]);
            let make = || if pieces {
                Redactor::new([secret.as_str()])
            } else {
                Redactor::whole_values([secret.as_str()])
            };
            let whole = make().scan_bytes(&body);
            let (lines, _) = fed(StreamRedactor::by_lines(make()), &body, &cuts);
            proptest::prop_assert!(lines == whole, "line by line differs from the whole body");
        }

        /// However a body is cut into chunks, no copy of the value (or a
        /// 12-character piece of it) gets through, and a body without it
        /// comes out as it went in.
        #[test]
        fn prop_chunking_never_lets_a_value_through(
            secret in "[A-Za-z0-9_\\-]{12,40}",
            before in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64),
            after in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64),
            copies in 0usize..3,
            cuts in proptest::collection::vec(0usize..400, 0..6),
        ) {
            let mut body = before.clone();
            for _ in 0..copies {
                body.extend_from_slice(secret.as_bytes());
                body.extend_from_slice(&after);
            }
            let out = streamed(Redactor::new([secret.as_str()]), &body, &cuts);
            proptest::prop_assert!(!contains(&out, &secret.as_bytes()[..MIN_FRAGMENT_CHARS]));
            let (whole, _) = Redactor::new([secret.as_str()]).apply_bytes(&body);
            if !contains(&whole, REDACTED.as_bytes()) {
                proptest::prop_assert_eq!(out, body);
            }
        }
    }
}
