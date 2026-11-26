//! `.env` files (ADR 0032 §6): read for `klav env import`, written by
//! `klav inject --env … --dotenv`.
//!
//! What is read: `KEY=VALUE`, `export KEY=VALUE`, values in single quotes
//! (literal) or double quotes (with `\n`, `\r`, `\t`, `\\`, `\"` and `\$`),
//! both of which may span lines, unquoted values with a ` #` comment, blank
//! lines and `#` comments. **No error carries a value or the text of the
//! line**: only its number and what is wrong (`line 12: missing =`). Values
//! live in buffers sized up front and wiped on drop.

use zeroize::Zeroizing;

/// One variable read from a `.env`: its name, its value and the line it
/// starts on. Not `Debug`: the value is a secret.
pub(crate) struct DotenvVariable {
    pub(crate) name: String,
    pub(crate) value: Zeroizing<String>,
}

/// Why a `.env` does not read: a line number and a reason, never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DotenvError {
    pub(crate) line: usize,
    pub(crate) reason: &'static str,
}

impl std::fmt::Display for DotenvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.reason)
    }
}

fn is_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && name.len() <= klav_core::model::environment::MAX_VARIABLE_NAME_LEN
}

/// Reads a `.env`. A name that repeats keeps its later value, as every
/// loader does; `repeated` gets those names.
pub(crate) fn parse(
    text: &str,
    repeated: &mut Vec<String>,
) -> Result<Vec<DotenvVariable>, DotenvError> {
    let bytes = text.as_bytes();
    let mut out: Vec<DotenvVariable> = Vec::new();
    let mut i = 0;
    let mut line = 1;
    while i < bytes.len() {
        let start_line = line;
        // One logical line: skip blanks and comments.
        let line_end = bytes[i..]
            .iter()
            .position(|b| *b == b'\n')
            .map_or(bytes.len(), |p| i + p);
        let raw = &text[i..line_end];
        let trimmed = raw.trim_start();
        if trimmed.trim_end().is_empty() || trimmed.starts_with('#') {
            i = line_end + 1;
            line += 1;
            continue;
        }
        let offset = i + (raw.len() - trimmed.len());
        let rest = trimmed
            .strip_prefix("export")
            .filter(|r| r.starts_with([' ', '\t']))
            .map_or(trimmed, str::trim_start);
        let rest_offset = offset + (trimmed.len() - rest.len());
        let Some(eq) = rest[..rest.len().min(line_end - rest_offset)].find('=') else {
            return Err(DotenvError {
                line: start_line,
                reason: "missing =",
            });
        };
        let name = rest[..eq].trim_end();
        if !is_name(name) {
            return Err(DotenvError {
                line: start_line,
                reason: "invalid variable name",
            });
        }
        let mut j = rest_offset + eq + 1;
        while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
            j += 1;
        }
        // Sized up front: the value never moves to a bigger buffer, which
        // would leave an unwiped copy behind.
        let mut value = Zeroizing::new(String::with_capacity(bytes.len() - j));
        let after = match bytes.get(j) {
            Some(q @ (b'\'' | b'"')) => {
                let quote = *q;
                j += 1;
                let mut closed = false;
                while j < bytes.len() {
                    let b = bytes[j];
                    if b == quote {
                        closed = true;
                        j += 1;
                        break;
                    }
                    if b == b'\n' {
                        line += 1;
                    }
                    if quote == b'"' && b == b'\\' && j + 1 < bytes.len() {
                        let escaped = match bytes[j + 1] {
                            b'n' => Some('\n'),
                            b'r' => Some('\r'),
                            b't' => Some('\t'),
                            b'\\' => Some('\\'),
                            b'"' => Some('"'),
                            b'$' => Some('$'),
                            _ => None,
                        };
                        if let Some(c) = escaped {
                            value.push(c);
                            j += 2;
                            continue;
                        }
                    }
                    // Copy one whole character.
                    let width = utf8_width(b);
                    value.push_str(&text[j..j + width]);
                    j += width;
                }
                if !closed {
                    return Err(DotenvError {
                        line: start_line,
                        reason: "the quoted value never closes",
                    });
                }
                // Only blanks and a comment may follow.
                let end = bytes[j..]
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(bytes.len(), |p| j + p);
                let tail = text[j..end].trim();
                if !(tail.is_empty() || tail.starts_with('#')) {
                    return Err(DotenvError {
                        line,
                        reason: "unexpected text after the closing quote",
                    });
                }
                end
            }
            _ => {
                let end = bytes[j..]
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(bytes.len(), |p| j + p);
                let mut slice = &text[j..end];
                if let Some(hash) = slice.find(" #").or_else(|| slice.find("\t#")) {
                    slice = &slice[..hash];
                }
                value.push_str(slice.trim_end_matches(['\r', ' ', '\t']));
                end
            }
        };
        if let Some(existing) = out.iter().position(|v| v.name == name) {
            repeated.push(name.to_owned());
            out.remove(existing);
        }
        out.push(DotenvVariable {
            name: name.to_owned(),
            value,
        });
        i = after + 1;
        line += 1;
    }
    Ok(out)
}

fn utf8_width(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

/// Writes `NAME=value` lines a `.env` loader reads back as they are: single
/// quotes when the value has no `'` and no line break (literal in every
/// loader), else double quotes with `\\`, `\"`, `\n` and `\r` escaped.
pub(crate) fn render(variables: &[(String, Zeroizing<String>)]) -> Zeroizing<Vec<u8>> {
    let size: usize = variables
        .iter()
        .map(|(n, v)| n.len() + 2 * v.len() + 6)
        .sum();
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    for (name, value) in variables {
        out.extend_from_slice(name.as_bytes());
        out.push(b'=');
        if !value.contains(['\'', '\n', '\r']) {
            out.push(b'\'');
            out.extend_from_slice(value.as_bytes());
            out.push(b'\'');
        } else {
            out.push(b'"');
            for c in value.bytes() {
                match c {
                    b'\\' => out.extend_from_slice(b"\\\\"),
                    b'"' => out.extend_from_slice(b"\\\""),
                    b'\n' => out.extend_from_slice(b"\\n"),
                    b'\r' => out.extend_from_slice(b"\\r"),
                    b'$' => out.extend_from_slice(b"\\$"),
                    _ => out.push(c),
                }
            }
            out.push(b'"');
        }
        out.push(b'\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str) -> Vec<(String, String)> {
        parse(text, &mut Vec::new())
            .unwrap()
            .into_iter()
            .map(|v| (v.name, v.value.to_string()))
            .collect()
    }

    #[test]
    fn reads_the_usual_forms() {
        let text = "# comment\n\nA=1\nexport B = two words # note\nC='single # kept'\nD=\"x\\ny \\\"q\\\" \\$HOME\"\nE=\"multi\nline\"\nF=\n  G=indented\nH='it''s'x\n";
        let Err(err) = parse(text, &mut Vec::new()) else {
            panic!("parsed")
        };
        assert_eq!(
            err,
            DotenvError {
                line: 11,
                reason: "unexpected text after the closing quote"
            }
        );
        let text = &text[..text.find("H=").unwrap()];
        assert_eq!(
            read(text),
            vec![
                ("A".into(), "1".into()),
                ("B".into(), "two words".into()),
                ("C".into(), "single # kept".into()),
                ("D".into(), "x\ny \"q\" $HOME".into()),
                ("E".into(), "multi\nline".into()),
                ("F".into(), String::new()),
                ("G".into(), "indented".into()),
            ]
        );
    }

    #[test]
    fn errors_name_the_line_never_the_value() {
        let secret = "sk_live_NEVER_PRINTED";
        for (text, line, reason) in [
            (format!("A=1\n{secret}\n"), 2, "missing ="),
            (
                format!("A=1\n\n1BAD={secret}\n"),
                3,
                "invalid variable name",
            ),
            (
                format!("A=\"{secret}\n"),
                1,
                "the quoted value never closes",
            ),
            (
                format!("A='{secret}' tail\n"),
                1,
                "unexpected text after the closing quote",
            ),
        ] {
            let Err(e) = parse(&text, &mut Vec::new()) else {
                panic!("parsed")
            };
            assert_eq!((e.line, e.reason), (line, reason));
            assert!(!e.to_string().contains(secret));
            assert!(!format!("{e:?}").contains(secret));
        }
    }

    #[test]
    fn a_repeated_name_keeps_the_later_value() {
        let mut repeated = Vec::new();
        let vars = parse("A=1\nB=2\nA=3\n", &mut repeated).unwrap();
        assert_eq!(repeated, vec!["A".to_owned()]);
        let got: Vec<(&str, &str)> = vars
            .iter()
            .map(|v| (v.name.as_str(), v.value.as_str()))
            .collect();
        assert_eq!(got, vec![("B", "2"), ("A", "3")]);
    }

    #[test]
    fn what_it_renders_reads_back_the_same() {
        let values = [
            "plain",
            "with space and # hash",
            "it's",
            "line\nbreak",
            "back\\slash \"quoted\" $VAR ${X}",
            "crlf\r\nend",
            "ünicode ✓",
            "",
        ];
        let vars: Vec<(String, Zeroizing<String>)> = values
            .iter()
            .enumerate()
            .map(|(i, v)| (format!("V{i}"), Zeroizing::new((*v).to_owned())))
            .collect();
        let rendered = render(&vars);
        let text = std::str::from_utf8(&rendered).unwrap();
        let back = read(text);
        assert_eq!(back.len(), values.len());
        for (i, (name, value)) in back.iter().enumerate() {
            assert_eq!(name, &format!("V{i}"));
            assert_eq!(value, values[i]);
        }
    }
}
