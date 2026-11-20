//! Site password rules (ADR 0022 §1.3): the `passwordrules` grammar of
//! <https://github.com/apple/password-manager-resources>, and the rules of
//! that repository bundled with Klav (`password-rules.json`, MIT: see
//! `PASSWORD-RULES-NOTICE.md`). Nothing here touches the network.
//!
//! The parser follows Apple's reference parser
//! (`tools/PasswordRulesParser/PasswordRulesParser.js`): the same lexical
//! rules for character classes (`-` only first, `]` only last, written
//! `]]`), the same canonicalisation (`required` classes are also
//! `allowed`; with nothing allowed, every printable ASCII character is), and
//! the same merging of repeated properties (largest `minlength`, smallest
//! `maxlength` and `max-consecutive`). Where the reference parser logs and
//! carries on, this one fails: an unreadable rule is ignored as a whole and
//! the caller falls back to a random password.

use std::collections::HashMap;
use std::sync::OnceLock;

use secrecy::SecretString;
use zeroize::Zeroizing;

use super::{GeneratorError, MAX_PASSWORD_LEN, MIN_PASSWORD_LEN, SYMBOLS};
use crate::crypto::random::uniform_u32;

const BUNDLED_SOURCE: &str = include_str!("password-rules.json");

/// Characters the rejection sampler may draw in all, across its attempts,
/// before a rule set is declared impossible. A budget of characters, not
/// of attempts: the page chooses the rules (and so the length), and each
/// draw asks the system for randomness (in WASM, `crypto.getRandomValues`),
/// so a page must not be able to keep the generator busy for seconds.
const MAX_DRAWS: usize = 250_000;

/// A set of printable ASCII characters (`' '..='~'`, 95 of them).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CharSet(u128);

impl CharSet {
    const FIRST: u8 = b' ';
    const LAST: u8 = b'~';

    /// No characters.
    pub const EMPTY: CharSet = CharSet(0);

    /// Every printable ASCII character, space included.
    pub fn ascii_printable() -> Self {
        Self::range(Self::FIRST, Self::LAST)
    }

    fn range(from: u8, to: u8) -> Self {
        (from..=to).fold(Self::EMPTY, |set, b| set.with(b as char))
    }

    /// `A–Z`.
    pub fn upper() -> Self {
        Self::range(b'A', b'Z')
    }

    /// `a–z`.
    pub fn lower() -> Self {
        Self::range(b'a', b'z')
    }

    /// `0–9`.
    pub fn digit() -> Self {
        Self::range(b'0', b'9')
    }

    /// The `special` class: every printable ASCII character that is not a
    /// letter or a digit, space included.
    pub fn special() -> Self {
        Self::range(b' ', b'/')
            .union(Self::range(b':', b'@'))
            .union(Self::range(b'[', b'`'))
            .union(Self::range(b'{', b'~'))
    }

    /// The characters of `text` that are printable ASCII.
    pub fn of(text: &str) -> Self {
        text.chars().fold(Self::EMPTY, Self::with)
    }

    /// Adds `c` if it is printable ASCII.
    #[must_use]
    pub fn with(self, c: char) -> Self {
        match Self::index(c) {
            Some(i) => Self(self.0 | (1 << i)),
            None => self,
        }
    }

    fn index(c: char) -> Option<u32> {
        let b = u8::try_from(c).ok()?;
        (Self::FIRST..=Self::LAST)
            .contains(&b)
            .then(|| u32::from(b - Self::FIRST))
    }

    /// Whether `c` is in the set.
    pub fn contains(self, c: char) -> bool {
        Self::index(c).is_some_and(|i| self.0 & (1 << i) != 0)
    }

    /// Characters in either set.
    #[must_use]
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Characters in both sets.
    #[must_use]
    pub fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Characters of `self` that are not in `other`.
    #[must_use]
    pub fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Number of characters.
    pub fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// Whether the set has no characters.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The characters, in code point order.
    pub fn chars(self) -> Vec<char> {
        (Self::FIRST..=Self::LAST)
            .map(char::from)
            .filter(|c| self.contains(*c))
            .collect()
    }
}

/// The rules a site sets for its passwords, canonicalised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordRules {
    /// Fewest characters.
    pub min_length: Option<usize>,
    /// Most characters.
    pub max_length: Option<usize>,
    /// Each set must contribute at least one character.
    pub required: Vec<CharSet>,
    /// The characters a password may contain (includes every required set).
    pub allowed: CharSet,
    /// Longest run of one repeated character.
    pub max_consecutive: Option<usize>,
}

impl PasswordRules {
    /// Rules with only length limits (the `minlength` and `maxlength`
    /// attributes of a field without `passwordrules`).
    pub fn lengths(min_length: Option<usize>, max_length: Option<usize>) -> Self {
        Self {
            min_length,
            max_length,
            required: Vec::new(),
            allowed: CharSet::ascii_printable(),
            max_consecutive: None,
        }
    }

    /// Narrows the length limits (a field's own `minlength`/`maxlength`).
    #[must_use]
    pub fn with_lengths(mut self, min_length: Option<usize>, max_length: Option<usize>) -> Self {
        if let Some(min) = min_length {
            self.min_length = Some(self.min_length.map_or(min, |m| m.max(min)));
        }
        if let Some(max) = max_length {
            self.max_length = Some(self.max_length.map_or(max, |m| m.min(max)));
        }
        self
    }
}

/// Why a rule text could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesSyntaxError {
    /// Character offset where reading stopped.
    pub position: usize,
}

enum Value {
    Classes(CharSet),
    Number(usize),
    Ignored,
}

struct Parser<'a> {
    input: &'a [char],
    pos: usize,
}

fn is_identifier_char(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '-'
}

fn is_whitespace(c: char) -> bool {
    matches!(c, ' ' | '\u{c}' | '\n' | '\r' | '\t')
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.input.get(self.pos).copied()
    }

    fn skip_whitespace(&mut self) {
        while self.peek().is_some_and(is_whitespace) {
            self.pos += 1;
        }
    }

    fn error<T>(&self) -> Result<T, RulesSyntaxError> {
        Err(RulesSyntaxError { position: self.pos })
    }

    fn identifier(&mut self) -> String {
        let start = self.pos;
        while self.peek().is_some_and(is_identifier_char) {
            self.pos += 1;
        }
        self.input[start..self.pos].iter().collect()
    }

    /// `[…]`: `-` counts only as the first character, `]` only as the last
    /// (written `]]`); characters that are not printable ASCII are skipped.
    fn custom_class(&mut self) -> Result<CharSet, RulesSyntaxError> {
        self.pos += 1; // '['
        if self.pos >= self.input.len() {
            return self.error();
        }
        let initial = self.pos;
        let mut set = CharSet::EMPTY;
        let mut last = None;
        loop {
            let c = self.input[self.pos];
            self.pos += 1;
            if CharSet::index(c).is_some() && !(c == '-' && self.pos - 1 > initial) {
                set = set.with(c);
                last = Some(c);
                if c == ']' {
                    break;
                }
            }
            if self.pos >= self.input.len() {
                break;
            }
        }
        let len = self.input.len();
        if last == Some(']')
            && ((self.pos < len && self.input[self.pos] != ']')
                || (self.pos == len && self.input[self.pos - 1] == ']'))
        {
            // The ']' that ended the class is not one of its characters,
            // unless the class also lists it earlier (it cannot: only last).
            return Ok(set.without(CharSet::of("]")));
        }
        if self.pos < len && self.input[self.pos] == ']' {
            self.pos += 1;
            return Ok(set);
        }
        self.error()
    }

    fn classes(&mut self) -> Result<CharSet, RulesSyntaxError> {
        let mut set = CharSet::EMPTY;
        loop {
            match self.peek() {
                Some(c) if is_identifier_char(c) => {
                    let start = self.pos;
                    set = set.union(match self.identifier().to_ascii_lowercase().as_str() {
                        "upper" => CharSet::upper(),
                        "lower" => CharSet::lower(),
                        "digit" => CharSet::digit(),
                        "special" => CharSet::special(),
                        // Klav generates ASCII: every ASCII character is
                        // also in `unicode`.
                        "ascii-printable" | "unicode" => CharSet::ascii_printable(),
                        _ => {
                            self.pos = start;
                            return self.error();
                        }
                    });
                }
                Some('[') => set = set.union(self.custom_class()?),
                _ => return self.error(),
            }
            self.skip_whitespace();
            match self.peek() {
                None | Some(';') => return Ok(set),
                Some(',') => {
                    self.pos += 1;
                    self.skip_whitespace();
                    if self.peek().is_none() {
                        return self.error();
                    }
                }
                Some(_) => return self.error(),
            }
        }
    }

    fn number(&mut self) -> Result<usize, RulesSyntaxError> {
        let start = self.pos;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.pos += 1;
        }
        if start == self.pos {
            return self.error();
        }
        let text: String = self.input[start..self.pos].iter().collect();
        self.skip_whitespace();
        if !matches!(self.peek(), None | Some(';')) {
            return self.error();
        }
        // Absurd numbers mean "no limit we can honour": capped below.
        Ok(text.parse().unwrap_or(usize::MAX))
    }

    fn property(&mut self) -> Result<(String, Value), RulesSyntaxError> {
        let start = self.pos;
        let name = self.identifier();
        let kind = match name.as_str() {
            "required" | "allowed" => 0,
            "minlength" | "maxlength" | "max-consecutive" => 1,
            // Newer properties of the grammar that Klav does not apply yet.
            "max-repeating" | "max-sequential" => 2,
            _ => {
                self.pos = start;
                return self.error();
            }
        };
        if self.peek() != Some(':') {
            return self.error();
        }
        self.pos += 1;
        self.skip_whitespace();
        if matches!(self.peek(), None | Some(';')) {
            return Ok((name, Value::Ignored));
        }
        let value = match kind {
            0 => Value::Classes(self.classes()?),
            1 => Value::Number(self.number()?),
            _ => {
                self.number()?;
                Value::Ignored
            }
        };
        Ok((name, value))
    }
}

/// Parses a `passwordrules` text.
pub fn parse(text: &str) -> Result<PasswordRules, RulesSyntaxError> {
    let chars: Vec<char> = text.chars().collect();
    let mut p = Parser {
        input: &chars,
        pos: 0,
    };
    let mut rules = PasswordRules {
        min_length: None,
        max_length: None,
        required: Vec::new(),
        allowed: CharSet::EMPTY,
        max_consecutive: None,
    };
    p.skip_whitespace();
    while p.peek().is_some() {
        if !p.peek().is_some_and(is_identifier_char) {
            return p.error();
        }
        match p.property()? {
            (name, Value::Classes(set)) if name == "required" => {
                if !set.is_empty() {
                    rules.required.push(set);
                    rules.allowed = rules.allowed.union(set);
                }
            }
            (_, Value::Classes(set)) => rules.allowed = rules.allowed.union(set),
            // A zero carries no rule, as in the reference parser.
            (_, Value::Number(0)) | (_, Value::Ignored) => {}
            (name, Value::Number(n)) => match name.as_str() {
                "minlength" => rules.min_length = Some(rules.min_length.map_or(n, |m| m.max(n))),
                "maxlength" => rules.max_length = Some(rules.max_length.map_or(n, |m| m.min(n))),
                _ => rules.max_consecutive = Some(rules.max_consecutive.map_or(n, |m| m.min(n))),
            },
        }
        p.skip_whitespace();
        match p.peek() {
            None => break,
            Some(';') => {
                p.pos += 1;
                p.skip_whitespace();
            }
            Some(_) => return p.error(),
        }
    }
    if rules.allowed.is_empty() {
        rules.allowed = CharSet::ascii_printable();
    }
    Ok(rules)
}

fn bundled() -> &'static HashMap<String, String> {
    static RULES: OnceLock<HashMap<String, String>> = OnceLock::new();
    RULES.get_or_init(|| {
        #[derive(serde::Deserialize)]
        struct Entry {
            #[serde(rename = "password-rules")]
            rules: String,
        }
        let raw: HashMap<String, Entry> =
            serde_json::from_str(BUNDLED_SOURCE).expect("bundled password rules are valid JSON");
        raw.into_iter().map(|(k, v)| (k, v.rules)).collect()
    })
}

/// The bundled rules for `host`: the exact host first, then dropping labels
/// from the left (`login.accor.com` → `accor.com`), never down to a single
/// label. Returns the domain the rules belong to and their text.
pub fn bundled_for_host(host: &str) -> Option<(&'static str, &'static str)> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let mut rest = host.as_str();
    loop {
        if !rest.contains('.') {
            return None;
        }
        if let Some((domain, rules)) = bundled().get_key_value(rest) {
            return Some((domain.as_str(), rules.as_str()));
        }
        rest = rest.split_once('.')?.1;
    }
}

/// Characters Klav prefers when a site leaves the choice open: letters,
/// digits and the shell-safe symbols of [`SYMBOLS`].
fn preferred() -> CharSet {
    CharSet::lower()
        .union(CharSet::upper())
        .union(CharSet::digit())
        .union(CharSet::of(SYMBOLS))
}

/// What the generator will draw from for `rules`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) length: usize,
    pub(crate) alphabet: CharSet,
    pub(crate) required: Vec<CharSet>,
    pub(crate) max_consecutive: Option<usize>,
}

impl Plan {
    pub(crate) fn entropy_bits(&self) -> f64 {
        self.length as f64 * (self.alphabet.len() as f64).log2()
    }
}

/// Chooses length and alphabet: the longest length allowed up to
/// `preferred_length` (or the minimum, if it is longer), and the site's
/// characters narrowed to Klav's preferred ones where the site allows it.
/// Each required class keeps at least one character, so the result always
/// satisfies the rules. `None` when no password can.
pub(crate) fn plan(rules: &PasswordRules, preferred_length: usize) -> Option<Plan> {
    let min = rules.min_length.unwrap_or(0).max(MIN_PASSWORD_LEN);
    let max = rules
        .max_length
        .unwrap_or(MAX_PASSWORD_LEN)
        .min(MAX_PASSWORD_LEN);
    if min > max {
        return None;
    }
    let length = preferred_length.clamp(min, max);
    let space = CharSet::of(" ");
    let narrow = |set: CharSet| {
        [set.intersection(preferred()), set.without(space), set]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or(set)
    };
    let required: Vec<CharSet> = rules
        .required
        .iter()
        .map(|r| narrow(r.intersection(rules.allowed)))
        .collect();
    if required.iter().any(|r| r.is_empty()) || required.len() > length {
        return None;
    }
    let alphabet = required
        .iter()
        .fold(narrow(rules.allowed), |a, r| a.union(*r));
    // One character (or none) is no password: `aaaa…` has no entropy. A
    // site that allows only that gets Klav's own password instead.
    if alphabet.len() < 2 {
        return None;
    }
    Some(Plan {
        length,
        alphabet,
        required: required.clone(),
        max_consecutive: rules.max_consecutive,
    })
}

/// Draws uniformly from `plan.alphabet`, rejecting candidates that miss a
/// required class or repeat a character more than `max_consecutive` times.
/// The result is uniform over every password that satisfies the plan.
pub(crate) fn generate(plan: &Plan) -> Result<SecretString, GeneratorError> {
    let alphabet = plan.alphabet.chars();
    let alphabet_len = u32::try_from(alphabet.len()).expect("at most 95 characters");
    for _ in 0..attempts(plan) {
        let mut candidate = Zeroizing::new(String::with_capacity(plan.length));
        for _ in 0..plan.length {
            candidate.push(alphabet[uniform_u32(alphabet_len) as usize]);
        }
        let classes_ok = plan
            .required
            .iter()
            .all(|set| candidate.chars().any(|c| set.contains(c)));
        if classes_ok
            && plan
                .max_consecutive
                .is_none_or(|n| longest_run(&candidate) <= n)
        {
            return Ok(SecretString::from(candidate.to_string()));
        }
    }
    Err(GeneratorError::SiteRules)
}

/// How many candidates the sampler draws for `plan` at most: MAX_DRAWS
/// characters in all.
fn attempts(plan: &Plan) -> usize {
    MAX_DRAWS / plan.length.max(1)
}

fn longest_run(text: &str) -> usize {
    let mut best = 0;
    let mut run = 0;
    let mut previous = None;
    for c in text.chars() {
        run = if previous == Some(c) { run + 1 } else { 1 };
        previous = Some(c);
        best = best.max(run);
    }
    best
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn named_classes() {
        assert_eq!(CharSet::ascii_printable().len(), 95);
        assert_eq!(CharSet::special().len(), 33);
        assert!(CharSet::special().contains(' '));
        assert_eq!(
            CharSet::upper()
                .union(CharSet::lower())
                .union(CharSet::digit())
                .union(CharSet::special()),
            CharSet::ascii_printable()
        );
        assert!(!CharSet::ascii_printable().contains('é'));
    }

    #[test]
    fn parses_like_the_reference_parser() {
        let r = parse("minlength: 8; maxlength: 20; max-consecutive: 2; required: lower, upper; required: digit;").unwrap();
        assert_eq!(r.min_length, Some(8));
        assert_eq!(r.max_length, Some(20));
        assert_eq!(r.max_consecutive, Some(2));
        assert_eq!(
            r.required,
            vec![CharSet::lower().union(CharSet::upper()), CharSet::digit()]
        );
        // Required classes are also allowed.
        assert_eq!(
            r.allowed,
            CharSet::lower()
                .union(CharSet::upper())
                .union(CharSet::digit())
        );

        // Nothing allowed: every printable ASCII character is.
        assert_eq!(
            parse("minlength: 6; maxlength: 16;").unwrap().allowed,
            CharSet::ascii_printable()
        );

        // `-` only first, `]` only last (as `]]`); other characters as is.
        let r = parse(r##"required: [-!"#$]; allowed: [a-c]"##).unwrap();
        assert_eq!(r.required, vec![CharSet::of("-!\"#$")]);
        assert_eq!(r.allowed, CharSet::of("-!\"#$ac"));
        let r = parse("required: [!]]; ").unwrap();
        assert_eq!(r.required, vec![CharSet::of("!]")]);
        let r = parse("required: [- !\"#$&'()*+,.:;<=>?@[^_`{|}~]]; allowed: lower").unwrap();
        assert!(
            r.required[0].contains(']')
                && r.required[0].contains('[')
                && r.required[0].contains(';')
        );
        // Non-ASCII characters inside a class are skipped.
        assert_eq!(
            parse("required: [’£$]").unwrap().required,
            vec![CharSet::of("$")]
        );

        // Repeated properties: largest minimum, smallest maximum.
        let r = parse("minlength: 8; minlength: 10; maxlength: 30; maxlength: 20; max-consecutive: 3; max-consecutive: 2").unwrap();
        assert_eq!(
            (r.min_length, r.max_length, r.max_consecutive),
            (Some(10), Some(20), Some(2))
        );

        // Case of class names does not matter; empty values are ignored.
        assert_eq!(
            parse("required: UPPER; minlength: ;").unwrap().required,
            vec![CharSet::upper()]
        );
        assert_eq!(
            parse("allowed: unicode").unwrap().allowed,
            CharSet::ascii_printable()
        );
        assert!(parse("max-sequential: 3; max-repeating: 2").is_ok());
    }

    #[test]
    fn rejects_what_it_cannot_read() {
        for bad in [
            "minimum: 8",
            "minlength 8",
            "minlength: eight",
            "minlength: 8 9",
            "required: lowercase",
            "required: lower upper",
            "required: lower,",
            "required: [abc",
            "; minlength: 8",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn every_bundled_rule_parses_and_can_be_satisfied() {
        let all = bundled();
        assert!(all.len() > 400);
        for (domain, text) in all {
            let rules =
                parse(text).unwrap_or_else(|e| panic!("{domain}: {text:?} at {}", e.position));
            let plan =
                plan(&rules, 20).unwrap_or_else(|| panic!("{domain}: no password fits {text:?}"));
            let password = generate(&plan).unwrap_or_else(|_| panic!("{domain}: gave up"));
            check(&rules, password.expose_secret(), domain);
        }
    }

    fn check(rules: &PasswordRules, password: &str, domain: &str) {
        let len = password.chars().count();
        assert!(
            rules.min_length.is_none_or(|m| len >= m),
            "{domain}: too short"
        );
        assert!(
            rules.max_length.is_none_or(|m| len <= m),
            "{domain}: too long"
        );
        assert!(
            password.chars().all(|c| rules.allowed.contains(c)),
            "{domain}: not allowed"
        );
        for set in &rules.required {
            assert!(
                password.chars().any(|c| set.contains(c)),
                "{domain}: misses a class"
            );
        }
        assert!(
            rules
                .max_consecutive
                .is_none_or(|n| longest_run(password) <= n),
            "{domain}: run"
        );
    }

    #[test]
    fn lookup_by_host_drops_labels_from_the_left() {
        assert_eq!(
            bundled_for_host("accor.com").map(|(d, _)| d),
            Some("accor.com")
        );
        assert_eq!(
            bundled_for_host("login.accor.com").map(|(d, _)| d),
            Some("accor.com")
        );
        assert_eq!(
            bundled_for_host("WWW.Accor.COM.").map(|(d, _)| d),
            Some("accor.com")
        );
        assert_eq!(
            bundled_for_host("account.xiaomi.com").map(|(d, _)| d),
            Some("account.xiaomi.com")
        );
        // Never a single label, never a suffix match inside a label.
        assert!(bundled_for_host("com").is_none());
        assert!(bundled_for_host("evilaccor.com").is_none());
        assert!(bundled_for_host("accor.com.evil.example").is_none());
    }

    #[test]
    fn plan_prefers_klav_characters_and_keeps_the_rules() {
        // Open choice: Klav's alphabet, 20 characters, no space.
        let p = plan(&parse("minlength: 6").unwrap(), 20).unwrap();
        assert_eq!(p.length, 20);
        assert_eq!(p.alphabet, preferred());
        // A short maximum wins; a long minimum wins.
        assert_eq!(
            plan(&parse("maxlength: 12").unwrap(), 20).unwrap().length,
            12
        );
        assert_eq!(
            plan(&parse("minlength: 32").unwrap(), 20).unwrap().length,
            32
        );
        // A required class Klav would not pick keeps its characters.
        let p = plan(&parse("required: [\"]; required: lower").unwrap(), 20).unwrap();
        assert!(p.alphabet.contains('"') && p.alphabet.contains('a') && !p.alphabet.contains('A'));
        // Digits only (a PIN-like site).
        let p = plan(
            &parse("minlength: 6; maxlength: 6; allowed: digit").unwrap(),
            20,
        )
        .unwrap();
        assert_eq!((p.length, p.alphabet), (6, CharSet::digit()));
        assert!((p.entropy_bits() - 6.0 * 10f64.log2()).abs() < 1e-9);
    }

    #[test]
    fn impossible_rules() {
        assert!(plan(&parse("minlength: 20; maxlength: 10").unwrap(), 20).is_none());
        assert!(plan(&parse("maxlength: 3").unwrap(), 20).is_none());
        assert!(plan(&parse("maxlength: 4; required: lower; required: upper; required: digit; required: special; required: [x]").unwrap(), 20).is_none());
        assert!(plan(&parse("allowed: [a]; max-consecutive: 2").unwrap(), 20).is_none());
        // One allowed character is never a password, whatever the rest says.
        assert!(plan(&parse("allowed: [a]").unwrap(), 20).is_none());
        assert!(plan(&parse("allowed: [a]; required: [a]").unwrap(), 20).is_none());
        assert!(plan(&parse("allowed: [ab]").unwrap(), 20).is_some());
        // A plan no candidate can meet: the sampler gives up instead of
        // looping forever.
        let tight = Plan {
            length: 4,
            alphabet: CharSet::ascii_printable(),
            required: "vwxyz"
                .chars()
                .map(|c| CharSet::of(&c.to_string()))
                .collect(),
            max_consecutive: None,
        };
        assert_eq!(generate(&tight).err(), Some(GeneratorError::SiteRules));
    }

    #[test]
    fn impossible_rules_stop_within_the_draw_budget() {
        // The longest password, with two characters that may never repeat:
        // no candidate can pass. The sampler stops after MAX_DRAWS
        // characters, not 100 000 attempts of 256.
        let hopeless = Plan {
            length: MAX_PASSWORD_LEN,
            alphabet: CharSet::of("ab"),
            required: vec![],
            max_consecutive: Some(1),
        };
        assert_eq!(generate(&hopeless).err(), Some(GeneratorError::SiteRules));
        assert!(attempts(&hopeless) * hopeless.length <= MAX_DRAWS);
        // Still a fair number of tries for long passwords, and many for short ones.
        assert!(attempts(&hopeless) >= 900);
        assert!(
            attempts(&Plan {
                length: 16,
                ..hopeless
            }) >= 15_000
        );
    }

    #[test]
    fn max_consecutive_is_enforced() {
        // No character twice in a row (uniform sampling still finds one
        // in a few tries with a real alphabet).
        let rules =
            parse("minlength: 30; maxlength: 30; allowed: lower; max-consecutive: 1").unwrap();
        let p = plan(&rules, 20).unwrap();
        for _ in 0..10 {
            let pw = generate(&p).unwrap();
            assert!(longest_run(pw.expose_secret()) <= 1);
        }
        assert_eq!(longest_run("aabbbc"), 3);
    }
}
