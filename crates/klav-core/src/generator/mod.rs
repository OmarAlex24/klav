//! Password, passphrase and PIN generators (ADR 0022 §1).
//!
//! Randomness comes from the OS CSPRNG with rejection sampling (no modulo
//! bias). Passphrases use the EFF Large Wordlist (7776 words, ~12.9 bits per
//! word), licensed CC BY 3.0 US: see `WORDLIST-NOTICE.md` next to this file.
//!
//! [`generate`] is the one entry point every client calls (Rust, WASM and
//! `klav-ffi`): the four types of [`GeneratorKind`], with the site's rules
//! for `smart` ([`rules`]), and the strength of the result.
//! [`change_password`] gives a site's change-password page for the
//! assisted change (ADR 0022 §5).

pub mod change_password;
pub mod rules;

use std::sync::OnceLock;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::random::uniform_u32;

/// Shortest password accepted.
pub const MIN_PASSWORD_LEN: usize = 4;
/// Longest password accepted.
pub const MAX_PASSWORD_LEN: usize = 256;
/// Fewest words in a passphrase.
pub const MIN_WORDS: usize = 3;
/// Most words in a passphrase.
pub const MAX_WORDS: usize = 32;
/// Longest separator accepted.
pub const MAX_SEPARATOR_LEN: usize = 8;
/// Shortest PIN accepted.
pub const MIN_PIN_LEN: usize = 4;
/// Longest PIN accepted.
pub const MAX_PIN_LEN: usize = 12;
/// Length of a `random` password, and of a `smart` one when the site
/// allows it (G1).
pub const DEFAULT_LENGTH: usize = 20;

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
/// Symbols that are safe to paste into shells and config files (no quotes,
/// backslash, backtick or space).
const SYMBOLS: &str = "!#$%&*+-.:;=?@^_~";
/// Characters easily confused when read aloud or on paper.
const AMBIGUOUS: &str = "Il1O0o";

const WORDLIST_SOURCE: &str = include_str!("eff_large_wordlist.txt");

/// Generator errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GeneratorError {
    /// Length outside [`MIN_PASSWORD_LEN`]..=[`MAX_PASSWORD_LEN`].
    #[error("password length must be between {MIN_PASSWORD_LEN} and {MAX_PASSWORD_LEN}")]
    Length,
    /// No character class selected, or fewer characters than required classes.
    #[error("select at least one character class, and no more classes than characters")]
    Classes,
    /// Word count outside [`MIN_WORDS`]..=[`MAX_WORDS`].
    #[error("passphrases need between {MIN_WORDS} and {MAX_WORDS} words")]
    Words,
    /// Separator empty, longer than [`MAX_SEPARATOR_LEN`] bytes, or with
    /// an ASCII letter or digit, or a hidden character
    /// ([`crate::text::is_hidden`]): see [`check_separator`].
    #[error(
        "a separator needs 1 to {MAX_SEPARATOR_LEN} bytes, no ASCII letter or digit, and no control or invisible character"
    )]
    Separator,
    /// PIN length outside [`MIN_PIN_LEN`]..=[`MAX_PIN_LEN`].
    #[error("PINs need between {MIN_PIN_LEN} and {MAX_PIN_LEN} digits")]
    PinLength,
    /// No password satisfies the site's rules.
    #[error("no password satisfies the site's rules")]
    SiteRules,
}

/// Which characters a password may contain. Every selected class appears at
/// least once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicy {
    /// Number of characters.
    pub length: usize,
    /// `a–z`.
    pub lowercase: bool,
    /// `A–Z`.
    pub uppercase: bool,
    /// `0–9`.
    pub digits: bool,
    /// `!#$%&*+-.:;=?@^_~`.
    pub symbols: bool,
    /// Exclude `I l 1 O 0 o`.
    pub avoid_ambiguous: bool,
}

impl Default for PasswordPolicy {
    /// 20 characters from all four classes (~127 bits).
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

impl PasswordPolicy {
    fn classes(&self) -> Vec<Vec<char>> {
        [
            (self.lowercase, LOWERCASE),
            (self.uppercase, UPPERCASE),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, set)| {
            set.chars()
                .filter(|c| !(self.avoid_ambiguous && AMBIGUOUS.contains(*c)))
                .collect()
        })
        .collect()
    }

    fn validate(&self) -> Result<Vec<Vec<char>>, GeneratorError> {
        if !(MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&self.length) {
            return Err(GeneratorError::Length);
        }
        let classes = self.classes();
        if classes.is_empty() || classes.len() > self.length {
            return Err(GeneratorError::Classes);
        }
        Ok(classes)
    }

    /// Upper bound of the entropy: `length × log2(alphabet size)`.
    pub fn entropy_bits(&self) -> f64 {
        let alphabet: usize = self.classes().iter().map(Vec::len).sum();
        self.length as f64 * (alphabet as f64).log2()
    }
}

/// Generates a password. Uniform over all passwords of the policy's alphabet
/// that contain every selected class.
pub fn generate_password(policy: &PasswordPolicy) -> Result<SecretString, GeneratorError> {
    let classes = policy.validate()?;
    let alphabet: Vec<char> = classes.iter().flatten().copied().collect();
    let alphabet_len = u32::try_from(alphabet.len()).expect("alphabet is small");
    loop {
        let mut candidate = Zeroizing::new(String::with_capacity(policy.length));
        for _ in 0..policy.length {
            candidate.push(alphabet[uniform_u32(alphabet_len) as usize]);
        }
        if classes
            .iter()
            .all(|class| candidate.chars().any(|c| class.contains(&c)))
        {
            return Ok(SecretString::from(candidate.to_string()));
        }
    }
}

/// How a passphrase is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphrasePolicy {
    /// Number of words.
    pub words: usize,
    /// Text between words.
    pub separator: String,
    /// Capitalize the first letter of each word.
    pub capitalize: bool,
    /// Append one random digit to one random word.
    pub include_number: bool,
}

impl Default for PassphrasePolicy {
    /// The `memorable` type of ADR 0022: five capitalised words joined by
    /// `-`, one of them with a digit (~70 bits).
    fn default() -> Self {
        Self {
            words: 5,
            separator: "-".into(),
            capitalize: true,
            include_number: true,
        }
    }
}

impl PassphrasePolicy {
    /// The word count within [`MIN_WORDS`]..=[`MAX_WORDS`], and a separator
    /// [`check_separator`] accepts.
    fn validate(&self) -> Result<(), GeneratorError> {
        if !(MIN_WORDS..=MAX_WORDS).contains(&self.words) {
            return Err(GeneratorError::Words);
        }
        check_separator(&self.separator)
    }

    /// Entropy in bits: `words × log2(7776)` (+ `log2(10 × words)` with a number).
    pub fn entropy_bits(&self) -> f64 {
        let words = self.words as f64;
        let mut bits = words * (wordlist().len() as f64).log2();
        if self.include_number {
            bits += (10.0 * words).log2();
        }
        bits
    }
}

/// Whether `separator` may join a passphrase's words: 1 to
/// [`MAX_SEPARATOR_LEN`] bytes, with no ASCII letter or digit, so that
/// [`known_entropy_bits`] tells it from the words and reads the passphrase
/// back as its policy's bits, and no control, format (zero-width, bidi),
/// line or paragraph separator character ([`crate::text::is_hidden`]),
/// which a person can neither see nor type back. Spaces and other visible
/// characters (`·`, `é`) are fine.
pub fn check_separator(separator: &str) -> Result<(), GeneratorError> {
    if separator.is_empty()
        || separator.len() > MAX_SEPARATOR_LEN
        || separator
            .chars()
            .any(|c| c.is_ascii_alphanumeric() || crate::text::is_hidden(c))
    {
        return Err(GeneratorError::Separator);
    }
    Ok(())
}

/// The EFF Large Wordlist (7776 words).
pub fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        WORDLIST_SOURCE
            .lines()
            .filter_map(|line| line.split('\t').nth(1))
            .map(str::trim)
            .collect()
    })
}

/// Generates a passphrase.
pub fn generate_passphrase(policy: &PassphrasePolicy) -> Result<SecretString, GeneratorError> {
    policy.validate()?;
    let list = wordlist();
    let list_len = u32::try_from(list.len()).expect("wordlist fits in u32");
    let words_len = u32::try_from(policy.words).expect("word count is small");
    let number_at = policy
        .include_number
        .then(|| uniform_u32(words_len) as usize);
    // Sized up front: a growing buffer would leave copies behind.
    let longest = list.iter().map(|w| w.len()).max().unwrap_or(0);
    let mut out = Zeroizing::new(String::with_capacity(
        // Upper-casing an ASCII letter keeps its length; 4 covers any char.
        policy.words * (longest + 4 + policy.separator.len()) + 1,
    ));
    for i in 0..policy.words {
        if i > 0 {
            out.push_str(&policy.separator);
        }
        let word = list[uniform_u32(list_len) as usize];
        if policy.capitalize {
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                out.extend(first.to_uppercase());
                out.push_str(chars.as_str());
            }
        } else {
            out.push_str(word);
        }
        if number_at == Some(i) {
            out.push(char::from(
                b'0' + u8::try_from(uniform_u32(10)).expect("digit"),
            ));
        }
    }
    Ok(SecretString::from(out.to_string()))
}

/// Generates a PIN: `len` digits, uniform.
pub fn generate_pin(len: usize) -> Result<SecretString, GeneratorError> {
    if !(MIN_PIN_LEN..=MAX_PIN_LEN).contains(&len) {
        return Err(GeneratorError::PinLength);
    }
    let mut out = Zeroizing::new(String::with_capacity(len));
    for _ in 0..len {
        out.push(char::from(
            b'0' + u8::try_from(uniform_u32(10)).expect("digit"),
        ));
    }
    Ok(SecretString::from(out.to_string()))
}

/// The four kinds of generated secret (ADR 0022 §1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratorKind {
    /// Random, within the site's rules (or `random` when there are none).
    #[default]
    Smart,
    /// Random characters ([`PasswordPolicy`]).
    Random,
    /// Words ([`PassphrasePolicy`]).
    Memorable,
    /// Digits only.
    Pin,
}

impl GeneratorKind {
    /// Every kind, in menu order.
    pub const ALL: [GeneratorKind; 4] = [Self::Smart, Self::Random, Self::Memorable, Self::Pin];
}

/// Options for [`generate`]. Each kind reads its own: `length` and the
/// classes for `random` (and `smart` without site rules, where `length`
/// is also the preferred length), the word settings for `memorable`, and
/// `pin_length` for `pin`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeneratorOptions {
    /// Which kind.
    pub kind: GeneratorKind,
    /// Password length.
    pub length: usize,
    /// `a–z`.
    pub lowercase: bool,
    /// `A–Z`.
    pub uppercase: bool,
    /// `0–9`.
    pub digits: bool,
    /// Symbols.
    pub symbols: bool,
    /// Exclude look-alike characters.
    pub avoid_ambiguous: bool,
    /// Passphrase words.
    pub words: usize,
    /// Passphrase separator.
    pub separator: String,
    /// Capitalise each word.
    pub capitalize: bool,
    /// Add a digit to one word.
    pub include_number: bool,
    /// PIN digits.
    pub pin_length: usize,
}

impl Default for GeneratorOptions {
    /// The defaults of ADR 0022 §1.1: `smart`, 20 characters with the four
    /// classes, five words and a six-digit PIN.
    fn default() -> Self {
        let password = PasswordPolicy::default();
        let phrase = PassphrasePolicy::default();
        Self {
            kind: GeneratorKind::Smart,
            length: password.length,
            lowercase: password.lowercase,
            uppercase: password.uppercase,
            digits: password.digits,
            symbols: password.symbols,
            avoid_ambiguous: password.avoid_ambiguous,
            words: phrase.words,
            separator: phrase.separator,
            capitalize: phrase.capitalize,
            include_number: phrase.include_number,
            pin_length: 6,
        }
    }
}

impl GeneratorOptions {
    fn password_policy(&self) -> PasswordPolicy {
        PasswordPolicy {
            length: self.length,
            lowercase: self.lowercase,
            uppercase: self.uppercase,
            digits: self.digits,
            symbols: self.symbols,
            avoid_ambiguous: self.avoid_ambiguous,
        }
    }

    fn passphrase_policy(&self) -> PassphrasePolicy {
        PassphrasePolicy {
            words: self.words,
            separator: self.separator.clone(),
            capitalize: self.capitalize,
            include_number: self.include_number,
        }
    }
}

/// What the page (or the item's URL) says about the password it wants.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SiteHints {
    /// The site's host, for the bundled rules.
    pub host: Option<String>,
    /// The field's `passwordrules` attribute.
    pub password_rules: Option<String>,
    /// The field's `minlength`.
    pub min_length: Option<usize>,
    /// The field's `maxlength`.
    pub max_length: Option<usize>,
}

/// Where the rules of a `smart` password came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "source")]
pub enum RulesSource {
    /// The field's `passwordrules` attribute.
    Field,
    /// Klav's bundled rules for `domain`.
    Bundled {
        /// The domain the rules are listed under.
        domain: String,
    },
    /// Only the field's `minlength`/`maxlength`.
    Lengths,
}

/// Why a `smart` password ignored the site's rules and is `random`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RulesFallback {
    /// The rules could not be read.
    Unreadable,
    /// No password satisfies them.
    Impossible,
}

/// Strength label of a generated secret, from its exact entropy (ADR 0022 §1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strength {
    /// Under 40 bits.
    Weak,
    /// 40–63 bits.
    Fair,
    /// 64–99 bits.
    Strong,
    /// 100 bits or more.
    VeryStrong,
}

impl Strength {
    /// The label for `bits` of entropy.
    pub fn of(bits: f64) -> Self {
        if bits < 40.0 {
            Self::Weak
        } else if bits < 64.0 {
            Self::Fair
        } else if bits < 100.0 {
            Self::Strong
        } else {
            Self::VeryStrong
        }
    }
}

/// A generated secret and what is known about it. Not `Debug`.
pub struct Generated {
    /// The secret.
    pub value: SecretString,
    /// The kind asked for.
    pub kind: GeneratorKind,
    /// Entropy in bits: exact for `pin` and `memorable`, and the upper
    /// bound `length × log2(alphabet)` for passwords (the share of
    /// candidates rejected for missing a class is tiny).
    pub bits: f64,
    /// Strength label of `bits`.
    pub strength: Strength,
    /// The site rules a `smart` password follows.
    pub rules: Option<RulesSource>,
    /// The site's rules make it shorter than asked, or drop it to a lower
    /// strength label than a site that leaves the choice open would get:
    /// «the site does not allow more».
    pub limited: bool,
    /// A `smart` password that could not follow the site's rules.
    pub fallback: Option<RulesFallback>,
}

/// Generates a secret of `options.kind`. `site` only matters for `smart`:
/// its `passwordrules` first, then the bundled rules for its host, and
/// then `random`. The field's `minlength`/`maxlength` always narrow the
/// length.
pub fn generate(options: &GeneratorOptions, site: &SiteHints) -> Result<Generated, GeneratorError> {
    let done = |value, bits: f64, rules, limited, fallback| Generated {
        value,
        kind: options.kind,
        bits,
        strength: Strength::of(bits),
        rules,
        limited,
        fallback,
    };
    match options.kind {
        GeneratorKind::Random => {
            let policy = options.password_policy();
            Ok(done(
                generate_password(&policy)?,
                policy.entropy_bits(),
                None,
                false,
                None,
            ))
        }
        GeneratorKind::Memorable => {
            let policy = options.passphrase_policy();
            Ok(done(
                generate_passphrase(&policy)?,
                policy.entropy_bits(),
                None,
                false,
                None,
            ))
        }
        GeneratorKind::Pin => {
            let bits = options.pin_length as f64 * 10f64.log2();
            Ok(done(
                generate_pin(options.pin_length)?,
                bits,
                None,
                false,
                None,
            ))
        }
        GeneratorKind::Smart => smart(options, site, done),
    }
}

fn smart(
    options: &GeneratorOptions,
    site: &SiteHints,
    done: impl Fn(SecretString, f64, Option<RulesSource>, bool, Option<RulesFallback>) -> Generated,
) -> Result<Generated, GeneratorError> {
    let field = site
        .password_rules
        .as_deref()
        .filter(|t| !t.trim().is_empty())
        .map(|t| (RulesSource::Field, t));
    let bundled = || {
        site.host
            .as_deref()
            .and_then(rules::bundled_for_host)
            .map(|(domain, t)| {
                (
                    RulesSource::Bundled {
                        domain: domain.to_owned(),
                    },
                    t,
                )
            })
    };
    let lengths = site.min_length.is_some() || site.max_length.is_some();
    let mut fallback = None;
    let found = match field.or_else(bundled) {
        Some((source, text)) => match rules::parse(text) {
            Ok(r) => Some((source, r.with_lengths(site.min_length, site.max_length))),
            Err(_) => {
                fallback = Some(RulesFallback::Unreadable);
                None
            }
        },
        None if lengths => Some((
            RulesSource::Lengths,
            rules::PasswordRules::lengths(site.min_length, site.max_length),
        )),
        None => None,
    };
    if let Some((source, site_rules)) = found {
        let preferred = options.length.clamp(MIN_PASSWORD_LEN, MAX_PASSWORD_LEN);
        match rules::plan(&site_rules, preferred) {
            Some(plan) => match rules::generate(&plan) {
                Ok(value) => {
                    let bits = plan.entropy_bits();
                    let limited = plan.length < preferred
                        || Strength::of(bits) < Strength::of(open_choice_bits(preferred));
                    return Ok(done(value, bits, Some(source), limited, None));
                }
                Err(_) => fallback = Some(RulesFallback::Impossible),
            },
            None => fallback = Some(RulesFallback::Impossible),
        }
    }
    let policy = options.password_policy();
    Ok(done(
        generate_password(&policy)?,
        policy.entropy_bits(),
        None,
        false,
        fallback,
    ))
}

/// Bits of a `preferred`-character password over Klav's preferred alphabet
/// (letters, digits and [`SYMBOLS`]): what a site that leaves the choice
/// open gets.
fn open_choice_bits(preferred: usize) -> f64 {
    let alphabet = (LOWERCASE.len() + UPPERCASE.len() + DIGITS.len() + SYMBOLS.len()) as f64;
    preferred as f64 * alphabet.log2()
}

/// The entropy of a password Klav generated, inferred from the value
/// alone (the generator history keeps the value, not the options): the
/// vault health report calls a generated password weak below 40 bits
/// (ADR 0022 §4). Only meaningful for generated values, which are uniform
/// over their alphabet:
///
/// * only digits: a PIN, `len × log2(10)`;
/// * three or more EFF words joined by one separator made of characters
///   that are neither ASCII letters nor digits, one of them with a
///   trailing digit or none: a `memorable` passphrase, as
///   [`PassphrasePolicy::entropy_bits`]. Every separator the generator
///   accepts ([`check_separator`]) is of that kind, so every passphrase it
///   generates reads back as its policy's bits. One generated before it
///   refused an empty separator or one with a letter or a digit stays in
///   the history as it was, and may read above its policy's bits;
/// * otherwise `len × log2(alphabet)`, where the alphabet is the union of
///   the classes present (lowercase, uppercase, digits and symbols; any
///   other character counts as a symbol). An upper bound, like
///   [`PasswordPolicy::entropy_bits`].
pub fn known_entropy_bits(value: &str) -> f64 {
    let len = value.chars().count();
    if len == 0 {
        return 0.0;
    }
    if value.chars().all(|c| c.is_ascii_digit()) {
        return len as f64 * 10f64.log2();
    }
    if let Some(bits) = passphrase_bits(value) {
        return bits;
    }
    let has = |set: &str| value.chars().any(|c| set.contains(c));
    let mut alphabet = 0usize;
    for (present, size) in [
        (has(LOWERCASE), LOWERCASE.len()),
        (has(UPPERCASE), UPPERCASE.len()),
        (has(DIGITS), DIGITS.len()),
    ] {
        if present {
            alphabet += size;
        }
    }
    if value.chars().any(|c| !c.is_ascii_alphanumeric()) {
        alphabet += SYMBOLS.len();
    }
    len as f64 * (alphabet as f64).log2()
}

/// [`known_entropy_bits`] of a passphrase from [`generate_passphrase`], or
/// `None` if `value` does not look like one.
///
/// An EFF word starts and ends with a letter, so the separator is one of
/// the runs of characters in `value` that are neither ASCII letters nor
/// digits, and each distinct run is tried. Inside a word the only such
/// character is the `-` of the four hyphenated words (`drop-down`,
/// `felt-tip`, `t-shirt`, `yo-yo`): with another separator such a word is
/// one piece, and with `-` it is two pieces whose first is never a word
/// itself, so they join back in one way only. At most one run parses: any
/// other run left inside a piece is not part of a word.
fn passphrase_bits(value: &str) -> Option<f64> {
    let mut runs: Vec<&str> = Vec::new();
    let mut start = None;
    for (i, c) in value.char_indices().chain([(value.len(), 'a')]) {
        match (c.is_ascii_alphanumeric(), start) {
            (false, None) => start = Some(i),
            (true, Some(from)) => {
                let run = &value[from..i];
                if !runs.contains(&run) {
                    runs.push(run);
                }
                start = None;
            }
            _ => {}
        }
    }
    runs.into_iter()
        .find_map(|separator| passphrase_with(value, separator))
}

/// [`passphrase_bits`] with `separator` between the words.
fn passphrase_with(value: &str, separator: &str) -> Option<f64> {
    let list = wordlist();
    let is_word = |piece: &str| {
        // A copy of part of the password: wiped when dropped.
        let lower = Zeroizing::new(piece.to_ascii_lowercase());
        list.binary_search(&lower.as_str()).is_ok()
    };
    // `word` with its trailing digit, if any: the bare word and how many
    // digits it had.
    let bare = |word: &str| {
        let bare = word.trim_end_matches(|c: char| c.is_ascii_digit());
        (bare.len(), word.len() - bare.len())
    };
    let mut pieces = value.split(separator);
    let (mut words, mut numbers) = (0, 0);
    while let Some(piece) = pieces.next() {
        let (len, digits) = bare(piece);
        let digits = if is_word(&piece[..len]) {
            digits
        } else if separator == "-" {
            // A hyphenated word, split by the separator: the digit, if
            // any, comes after its second half.
            let rest = pieces.next()?;
            // Sized up front: a growing buffer would leave copies behind.
            let mut joined = Zeroizing::new(String::with_capacity(piece.len() + 1 + rest.len()));
            joined.push_str(piece);
            joined.push('-');
            joined.push_str(rest);
            let (len, digits) = bare(&joined);
            if !is_word(&joined[..len]) {
                return None;
            }
            digits
        } else {
            return None;
        };
        match digits {
            0 => {}
            1 => numbers += 1,
            _ => return None,
        }
        words += 1;
    }
    if words < MIN_WORDS || numbers > 1 {
        return None;
    }
    Some(
        PassphrasePolicy {
            words,
            separator: separator.to_owned(),
            capitalize: false,
            include_number: numbers == 1,
        }
        .entropy_bits(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use proptest::prelude::*;
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn wordlist_is_the_eff_large_list() {
        let words = wordlist();
        assert_eq!(words.len(), 7776);
        assert_eq!(words.first(), Some(&"abacus"));
        assert_eq!(words.last(), Some(&"zoom"));
        assert_eq!(words.iter().collect::<HashSet<_>>().len(), 7776);
        assert!(
            words
                .iter()
                .all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
        );
    }

    #[test]
    fn default_password() {
        let policy = PasswordPolicy::default();
        let password = generate_password(&policy).unwrap();
        let p = password.expose_secret();
        assert_eq!(p.chars().count(), 20);
        assert!(p.chars().any(|c| c.is_ascii_lowercase()));
        assert!(p.chars().any(|c| c.is_ascii_uppercase()));
        assert!(p.chars().any(|c| c.is_ascii_digit()));
        assert!(p.chars().any(|c| SYMBOLS.contains(c)));
        assert!(policy.entropy_bits() > 120.0);
        assert_ne!(p, generate_password(&policy).unwrap().expose_secret());
    }

    #[test]
    fn password_policy_errors() {
        let none = PasswordPolicy {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert_eq!(
            generate_password(&none).err(),
            Some(GeneratorError::Classes)
        );
        assert_eq!(
            generate_password(&PasswordPolicy {
                length: 3,
                ..Default::default()
            })
            .err(),
            Some(GeneratorError::Length)
        );
        assert_eq!(
            generate_password(&PasswordPolicy {
                length: 257,
                ..Default::default()
            })
            .err(),
            Some(GeneratorError::Length)
        );
    }

    #[test]
    fn pin_and_ambiguity() {
        let pin = PasswordPolicy {
            length: 6,
            lowercase: false,
            uppercase: false,
            symbols: false,
            ..Default::default()
        };
        assert!(
            generate_password(&pin)
                .unwrap()
                .expose_secret()
                .chars()
                .all(|c| c.is_ascii_digit())
        );
        let clear = PasswordPolicy {
            length: 200,
            avoid_ambiguous: true,
            ..Default::default()
        };
        assert!(
            !generate_password(&clear)
                .unwrap()
                .expose_secret()
                .chars()
                .any(|c| AMBIGUOUS.contains(c))
        );
    }

    #[test]
    fn passphrases() {
        // Default (memorable): five capitalised words, one with a digit.
        let policy = PassphrasePolicy::default();
        let phrase = generate_passphrase(&policy).unwrap();
        let p = phrase.expose_secret();
        // Some EFF words contain '-': count capitals instead of splitting.
        assert_eq!(p.chars().filter(char::is_ascii_uppercase).count(), 5);
        assert_eq!(p.chars().filter(char::is_ascii_digit).count(), 1);
        assert!((policy.entropy_bits() - (5.0 * 7776f64.log2() + 50f64.log2())).abs() < 1e-9);
        let plain = PassphrasePolicy {
            words: 4,
            separator: " ".into(),
            capitalize: false,
            include_number: false,
        };
        let phrase = generate_passphrase(&plain).unwrap();
        let parts: Vec<&str> = phrase.expose_secret().split(' ').collect();
        assert_eq!(parts.len(), 4);
        assert!(parts.iter().all(|w| wordlist().contains(w)));
        assert!((plain.entropy_bits() - 51.7).abs() < 0.1);
        assert_eq!(
            generate_passphrase(&PassphrasePolicy {
                words: 2,
                ..Default::default()
            })
            .err(),
            Some(GeneratorError::Words)
        );
        assert_eq!(
            generate_passphrase(&PassphrasePolicy {
                separator: "\n".into(),
                ..Default::default()
            })
            .err(),
            Some(GeneratorError::Separator)
        );
    }

    /// A separator the estimator cannot tell from the words (empty, or with
    /// an ASCII letter or digit), one nobody can see or type back, or one
    /// over 8 bytes is refused; spaces and other visible characters pass.
    #[test]
    fn separators_the_estimator_cannot_read_are_refused() {
        for separator in [
            "",
            "x",
            "X",
            "1",
            "a-",
            "-0",
            " and ",
            "\n",
            "\t",
            "\0",
            "\u{200B}",
            "\u{2028}",
            "\u{202E}",
            "\u{FEFF}",
            "---------",
        ] {
            assert_eq!(
                check_separator(separator),
                Err(GeneratorError::Separator),
                "{separator:?}"
            );
            assert_eq!(
                generate_passphrase(&PassphrasePolicy {
                    separator: separator.into(),
                    ..Default::default()
                })
                .err(),
                Some(GeneratorError::Separator),
                "{separator:?}"
            );
        }
        for separator in [
            "-", ".", " ", "  ", "\u{A0}", "·", " · ", "é", "→", "--", "_", "~~~~~~~~",
        ] {
            assert_eq!(check_separator(separator), Ok(()), "{separator:?}");
            assert!(
                generate_passphrase(&PassphrasePolicy {
                    separator: separator.into(),
                    ..Default::default()
                })
                .is_ok(),
                "{separator:?}"
            );
        }
        // The message says what is allowed.
        assert_eq!(
            GeneratorError::Separator.to_string(),
            "a separator needs 1 to 8 bytes, no ASCII letter or digit, and no control or invisible character"
        );
    }

    #[test]
    fn pins() {
        for len in [MIN_PIN_LEN, 6, MAX_PIN_LEN] {
            let pin = generate_pin(len).unwrap();
            assert_eq!(pin.expose_secret().len(), len);
            assert!(pin.expose_secret().chars().all(|c| c.is_ascii_digit()));
        }
        assert_eq!(generate_pin(3).err(), Some(GeneratorError::PinLength));
        assert_eq!(generate_pin(13).err(), Some(GeneratorError::PinLength));
    }

    #[test]
    fn strength_labels() {
        assert_eq!(Strength::of(19.9), Strength::Weak);
        assert_eq!(Strength::of(40.0), Strength::Fair);
        assert_eq!(Strength::of(63.9), Strength::Fair);
        assert_eq!(Strength::of(64.0), Strength::Strong);
        assert_eq!(Strength::of(99.9), Strength::Strong);
        assert_eq!(Strength::of(100.0), Strength::VeryStrong);
    }

    fn kind(kind: GeneratorKind) -> GeneratorOptions {
        GeneratorOptions {
            kind,
            ..GeneratorOptions::default()
        }
    }

    #[test]
    fn generate_each_kind() {
        let none = SiteHints::default();
        let random = generate(&kind(GeneratorKind::Random), &none).unwrap();
        assert_eq!(random.value.expose_secret().chars().count(), DEFAULT_LENGTH);
        assert_eq!(random.strength, Strength::VeryStrong);
        let memorable = generate(&kind(GeneratorKind::Memorable), &none).unwrap();
        assert_eq!(memorable.strength, Strength::Strong);
        let pin = generate(&kind(GeneratorKind::Pin), &none).unwrap();
        assert_eq!(pin.value.expose_secret().len(), 6);
        // A six-digit PIN is honestly weak (ADR 0022 §1.2).
        assert_eq!(pin.strength, Strength::Weak);
        // Smart without any rule: random, 20 characters.
        let smart = generate(&GeneratorOptions::default(), &none).unwrap();
        assert_eq!(smart.kind, GeneratorKind::Smart);
        assert!(smart.rules.is_none() && smart.fallback.is_none() && !smart.limited);
        assert_eq!(smart.value.expose_secret().chars().count(), DEFAULT_LENGTH);
    }

    #[test]
    fn smart_follows_the_field_then_the_bundled_rules() {
        let options = GeneratorOptions::default();
        // The field's own rules win over the bundled ones.
        let field = SiteHints {
            host: Some("accor.com".into()),
            password_rules: Some("minlength: 6; maxlength: 6; allowed: digit".into()),
            ..SiteHints::default()
        };
        let g = generate(&options, &field).unwrap();
        assert_eq!(g.rules, Some(RulesSource::Field));
        assert!(g.limited);
        assert_eq!(g.strength, Strength::Weak);
        assert!(
            g.value.expose_secret().len() == 6
                && g.value.expose_secret().chars().all(|c| c.is_ascii_digit())
        );
        // Bundled: accor.com allows 10–20 with one of its listed symbols.
        let bundled = SiteHints {
            host: Some("all.accor.com".into()),
            ..SiteHints::default()
        };
        let g = generate(&options, &bundled).unwrap();
        assert_eq!(
            g.rules,
            Some(RulesSource::Bundled {
                domain: "accor.com".into()
            })
        );
        let p = g.value.expose_secret();
        assert_eq!(p.chars().count(), 20);
        assert!(p.chars().any(|c| "!#$%&()*,.:<>?@^{|}".contains(c)));
        // Fewer symbols than Klav's, still very strong: not «limited».
        assert!(!g.limited);
        // The field's maxlength narrows bundled rules.
        let narrow = SiteHints {
            max_length: Some(12),
            ..bundled.clone()
        };
        let g = generate(&options, &narrow).unwrap();
        assert_eq!(g.value.expose_secret().chars().count(), 12);
        assert!(g.limited);
        // Only lengths: random characters within them.
        let lengths = SiteHints {
            min_length: Some(8),
            max_length: Some(16),
            ..SiteHints::default()
        };
        let g = generate(&options, &lengths).unwrap();
        assert_eq!(g.rules, Some(RulesSource::Lengths));
        assert_eq!(g.value.expose_secret().chars().count(), 16);
        // A site that leaves the choice open is not «limited».
        let open = SiteHints {
            password_rules: Some("minlength: 8".into()),
            ..SiteHints::default()
        };
        assert!(!generate(&options, &open).unwrap().limited);
    }

    #[test]
    fn smart_falls_back_to_random_with_a_reason() {
        let options = GeneratorOptions::default();
        let unreadable = SiteHints {
            password_rules: Some("minimum: eight".into()),
            ..SiteHints::default()
        };
        let g = generate(&options, &unreadable).unwrap();
        assert_eq!(
            (g.rules, g.fallback),
            (None, Some(RulesFallback::Unreadable))
        );
        assert_eq!(g.value.expose_secret().chars().count(), DEFAULT_LENGTH);
        let impossible = SiteHints {
            password_rules: Some("minlength: 30; maxlength: 10".into()),
            ..SiteHints::default()
        };
        let g = generate(&options, &impossible).unwrap();
        assert_eq!(g.fallback, Some(RulesFallback::Impossible));
    }

    #[test]
    fn options_json_is_stable() {
        // The extension and the CLI send these as JSON.
        let o: GeneratorOptions = serde_json::from_str(r#"{"kind":"pin","pin_length":8}"#).unwrap();
        assert_eq!(
            (o.kind, o.pin_length, o.length),
            (GeneratorKind::Pin, 8, 20)
        );
        assert!(serde_json::from_str::<GeneratorOptions>(r#"{"kind":"pin","nope":1}"#).is_err());
        let s: SiteHints = serde_json::from_str(r#"{"host":"a.example","min_length":8}"#).unwrap();
        assert_eq!(s.min_length, Some(8));
        assert_eq!(
            serde_json::to_string(&RulesSource::Bundled {
                domain: "accor.com".into()
            })
            .unwrap(),
            r#"{"source":"bundled","domain":"accor.com"}"#
        );
        assert_eq!(
            serde_json::to_string(&Strength::VeryStrong).unwrap(),
            r#""very_strong""#
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

        #[test]
        fn prop_passwords_follow_policy(
            length in MIN_PASSWORD_LEN..64usize,
            lowercase in any::<bool>(),
            uppercase in any::<bool>(),
            digits in any::<bool>(),
            symbols in any::<bool>(),
            avoid_ambiguous in any::<bool>(),
        ) {
            let policy = PasswordPolicy { length, lowercase, uppercase, digits, symbols, avoid_ambiguous };
            match generate_password(&policy) {
                Err(GeneratorError::Classes) => prop_assert!(!(lowercase || uppercase || digits || symbols)),
                Err(other) => prop_assert!(false, "unexpected error {other}"),
                Ok(password) => {
                    let p = password.expose_secret();
                    prop_assert_eq!(p.chars().count(), length);
                    let alphabet: Vec<char> = policy.classes().into_iter().flatten().collect();
                    prop_assert!(p.chars().all(|c| alphabet.contains(&c)));
                    for class in policy.classes() {
                        prop_assert!(p.chars().any(|c| class.contains(&c)));
                    }
                }
            }
        }
    }

    /// `words` as [`generate_passphrase`] joins them for `policy`, with the
    /// digit after word `number_at`.
    fn as_generated(words: &[&str], policy: &PassphrasePolicy, number_at: Option<usize>) -> String {
        let mut out = String::new();
        for (i, word) in words.iter().enumerate() {
            if i > 0 {
                out.push_str(&policy.separator);
            }
            let mut chars = word.chars();
            if policy.capitalize
                && let Some(first) = chars.next()
            {
                out.extend(first.to_uppercase());
            }
            out.push_str(chars.as_str());
            if number_at == Some(i) {
                out.push('7');
            }
        }
        out
    }

    /// The EFF words with a `-` in them. Their first halves are not words,
    /// which is what lets [`known_entropy_bits`] read them back in one way
    /// only when `-` is also the separator.
    const HYPHENATED: [&str; 4] = ["drop-down", "felt-tip", "t-shirt", "yo-yo"];

    /// Policies the generator accepts, with separators of every kind it
    /// accepts ([`check_separator`]): the default `-`, `.`, a space, ` · `
    /// (several characters, one of them not ASCII), `--` (the hyphenated
    /// words' own character, twice) and `→é` (a non-ASCII letter).
    fn read_policies() -> Vec<(PassphrasePolicy, &'static str)> {
        vec![
            (PassphrasePolicy::default(), "default"),
            (
                PassphrasePolicy {
                    words: 3,
                    separator: ".".into(),
                    capitalize: false,
                    include_number: false,
                },
                "three words",
            ),
            (
                PassphrasePolicy {
                    words: 4,
                    separator: " ".into(),
                    capitalize: false,
                    include_number: true,
                },
                "space",
            ),
            (
                PassphrasePolicy {
                    words: 3,
                    separator: " · ".into(),
                    capitalize: true,
                    include_number: false,
                },
                "several characters",
            ),
            (
                PassphrasePolicy {
                    words: 3,
                    separator: "--".into(),
                    capitalize: true,
                    include_number: true,
                },
                "double hyphen",
            ),
            (
                PassphrasePolicy {
                    words: 3,
                    separator: "→é".into(),
                    capitalize: false,
                    include_number: false,
                },
                "non-ASCII letter",
            ),
        ]
    }

    /// The known entropy of a generated passphrase is its policy's, by
    /// construction: every one of the 7,776 words in every position, for
    /// each policy of [`read_policies`], with the digit on that word or on
    /// the next. The generator refuses every separator the estimator could
    /// not read, so this holds for every passphrase it generates
    /// (`generated_passphrases_read_back_their_policy` tries random
    /// separators). A single random value missed it about once in 324
    /// runs: the estimator misread a passphrase with one of [`HYPHENATED`].
    #[test]
    fn known_entropy_of_generated_values() {
        // A 6-digit PIN: ~19.9 bits, weak.
        assert!((known_entropy_bits("123456") - 6.0 * 10f64.log2()).abs() < 1e-9);

        let list = wordlist();
        assert_eq!(
            list.iter()
                .filter(|w| w.contains('-'))
                .copied()
                .collect::<Vec<_>>(),
            HYPHENATED
        );
        let default = PassphrasePolicy::default();
        assert!((default.entropy_bits() - (5.0 * 7776f64.log2() + 50f64.log2())).abs() < 1e-9);
        let filler = ["able", "acid", "zoom", "acorn", "zone"];
        for (policy, name) in read_policies() {
            let expected = policy.entropy_bits();
            let n = policy.words;
            for word in list {
                for at in 0..n {
                    let mut words = filler[..n].to_vec();
                    words[at] = word;
                    let numbers: Vec<Option<usize>> = if policy.include_number {
                        vec![Some(at), Some((at + 1) % n)]
                    } else {
                        vec![None]
                    };
                    for number_at in numbers {
                        let value = as_generated(&words, &policy, number_at);
                        let bits = known_entropy_bits(&value);
                        assert!((bits - expected).abs() < 1e-9, "{name}: {value}: {bits}");
                    }
                }
            }
            // `as_generated` is the generator's format: real passphrases of
            // the policy read back the same (never printed).
            for _ in 0..50 {
                let phrase = generate_passphrase(&policy).unwrap();
                let bits = known_entropy_bits(phrase.expose_secret());
                assert!((bits - expected).abs() < 1e-9, "{name}");
            }
        }
        // Three words without a number: ~38.8 bits, under 40 (weak).
        assert!(read_policies()[1].0.entropy_bits() < 40.0);

        // A random password of the default policy: 20 characters with
        // every class, `20 × log2(79)` over the union of classes present
        // (an upper bound of the policy's own bits).
        let all = (LOWERCASE.len() + UPPERCASE.len() + DIGITS.len() + SYMBOLS.len()) as f64;
        let random = "aB3$cD4%eF5&gH6*iJ7!";
        assert_eq!(random.chars().count(), DEFAULT_LENGTH);
        let bits = known_entropy_bits(random);
        assert!((bits - 20.0 * all.log2()).abs() < 1e-9);
        assert!(bits >= PasswordPolicy::default().entropy_bits() && bits > 100.0);
        // Short and lowercase only.
        assert!(known_entropy_bits("abcdefg") < 40.0);
        assert_eq!(known_entropy_bits(""), 0.0);
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

        /// Real passphrases with any separator the generator accepts, of 1
        /// to 4 characters drawn from symbols, spaces and non-ASCII
        /// characters, read back as their policy's bits (never printed).
        #[test]
        fn generated_passphrases_read_back_their_policy(
            chars in proptest::collection::vec(
                proptest::sample::select(
                    "!#$%&*+-.:;=?@^_~ \u{A0}·éñ→".chars().collect::<Vec<_>>()
                ),
                1..=4,
            ),
            words in MIN_WORDS..=8usize,
            capitalize in any::<bool>(),
            include_number in any::<bool>(),
        ) {
            let separator: String = chars.into_iter().collect();
            prop_assume!(check_separator(&separator).is_ok());
            let policy = PassphrasePolicy { words, separator, capitalize, include_number };
            let phrase = generate_passphrase(&policy).unwrap();
            let bits = known_entropy_bits(phrase.expose_secret());
            prop_assert!((bits - policy.entropy_bits()).abs() < 1e-9, "{:?}", policy.separator);
        }
    }

    /// A generated passphrase with one of [`HYPHENATED`] where its `-` is
    /// also a separator's character (anywhere with the default `-`, first
    /// with another separator) used to read as a random string, far above
    /// its entropy: `Drop-down-Able7-Acid-Zoom-Acorn` as 195 bits instead of
    /// 70, and a three-word passphrase without a number (38.8 bits) as
    /// 103, so it was not reported weak.
    #[test]
    fn known_entropy_reads_hyphenated_words() {
        let list = wordlist();
        // The parse is unique: no first half of a hyphenated word is a word.
        for word in HYPHENATED {
            let (first, _) = word.split_once('-').unwrap();
            assert!(list.binary_search(&first).is_err(), "{first}");
        }
        let default = PassphrasePolicy::default();
        let three = &read_policies()[1].0;
        for word in HYPHENATED {
            let value = as_generated(&[word, "able", "acid", "zoom", "acorn"], &default, Some(1));
            assert!(
                (known_entropy_bits(&value) - default.entropy_bits()).abs() < 1e-9,
                "{value}"
            );
            let value = as_generated(&[word, "able", "acid"], three, None);
            assert!(
                (known_entropy_bits(&value) - three.entropy_bits()).abs() < 1e-9,
                "{value}"
            );
            assert!(known_entropy_bits(&value) < 40.0, "{value}");
        }
        // Every word hyphenated, with `-` between them too.
        let value = as_generated(&HYPHENATED, &read_policies()[0].0, Some(3));
        assert!((known_entropy_bits(&value) - 4.0 * 7776f64.log2() - 40f64.log2()).abs() < 1e-9);
    }

    /// What is not a passphrase reads as before, as a random string over
    /// the classes it has: a hyphenated word alone, words not in the list,
    /// single letters, random passwords with `-`, and a separator the
    /// estimator does not read (empty).
    #[test]
    fn known_entropy_of_other_values_is_unchanged() {
        let random =
            |value: &str, alphabet: usize| value.chars().count() as f64 * (alphabet as f64).log2();
        let lower_symbols = LOWERCASE.len() + SYMBOLS.len();
        let all = LOWERCASE.len() + UPPERCASE.len() + DIGITS.len() + SYMBOLS.len();
        for (value, alphabet) in [
            ("well-known-word", lower_symbols),
            ("drop-down", lower_symbols),
            ("drop-down-able", lower_symbols),
            ("a-b-c-d-e", lower_symbols),
            ("aB3-cD4%eF5&gH6*iJ7!", all),
            ("x9-Qp-7Lm-Rt2-Vw", all),
            ("ableacidzoom", LOWERCASE.len()),
        ] {
            let bits = known_entropy_bits(value);
            assert!(
                (bits - random(value, alphabet)).abs() < 1e-9,
                "{value}: {bits}"
            );
        }
    }
}
