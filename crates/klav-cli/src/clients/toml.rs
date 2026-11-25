//! Codex's `config.toml`, when there is no `codex` CLI to write it (the
//! desktop app alone): only `[mcp_servers.klav]` is inserted, replaced or
//! removed, with `toml_edit`, which keeps comments, order and spacing (ADR
//! 0033 §3.6).

use std::borrow::Cow;

use serde_json::Value;
use toml_edit::{Array, DocumentMut, InlineTable, Item, Table};

use super::{Entry, Malformed};

const SERVERS: &str = "mcp_servers";
const KEY: &str = "klav";
const BOM: char = '\u{feff}';

/// How a file ends its lines, and whether it starts with a byte order mark.
/// `toml_edit` writes every line with `\n` and drops the mark, so Klav takes
/// them off before editing and puts them back after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Layout {
    bom: bool,
    crlf: bool,
}

/// The layout of `text` and its body with `\n` line ends and no mark. A file
/// that mixes `\r\n` and `\n` is not touched: Klav could not tell which
/// one its new lines should use.
fn split(text: &str) -> Result<(Layout, Cow<'_, str>), Malformed> {
    let (bom, body) = match text.strip_prefix(BOM) {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let crlf = body.matches("\r\n").count();
    if crlf == 0 {
        return Ok((Layout { bom, crlf: false }, Cow::Borrowed(body)));
    }
    if let Some(lone) = body
        .match_indices('\n')
        .map(|(i, _)| i)
        .find(|&i| i == 0 || body.as_bytes()[i - 1] != b'\r')
    {
        let (line, column) = super::line_column(body, lone);
        return Err(Malformed {
            line,
            column,
            problem: "written with both CRLF and LF line ends".into(),
        });
    }
    Ok((
        Layout { bom, crlf: true },
        Cow::Owned(body.replace("\r\n", "\n")),
    ))
}

/// `text` (with `\n` line ends) back in `layout`.
fn join(layout: Layout, text: &str) -> String {
    let text = if layout.crlf {
        text.replace('\n', "\r\n")
    } else {
        text.to_owned()
    };
    if layout.bom {
        format!("{BOM}{text}")
    } else {
        text
    }
}

fn parse(text: &str) -> Result<DocumentMut, Malformed> {
    text.parse::<DocumentMut>().map_err(|e| {
        // The message quotes the line: only the position is kept.
        let (line, column) = e
            .span()
            .map_or((1, 1), |span| super::line_column(text, span.start));
        Malformed {
            line,
            column,
            problem: "not valid TOML".into(),
        }
    })
}

fn not_a_table() -> Malformed {
    Malformed {
        line: 1,
        column: 1,
        problem: format!("`{SERVERS}` is not a table"),
    }
}

/// `[mcp_servers.klav]`, as JSON.
pub(crate) fn entry(text: &str) -> Result<Option<Value>, Malformed> {
    member(text, KEY)
}

/// `[mcp_servers.<key>]`, as JSON.
pub(crate) fn member(text: &str, key: &str) -> Result<Option<Value>, Malformed> {
    let (_, body) = split(text)?;
    let doc = parse(&body)?;
    let Some(servers) = doc.get(SERVERS) else {
        return Ok(None);
    };
    let servers = servers.as_table_like().ok_or_else(not_a_table)?;
    Ok(servers.get(key).map(item_value))
}

/// `text` with `[mcp_servers.<key>]` set to a Streamable HTTP server at
/// `url` with fixed `headers` (Codex's `url` and `http_headers`, ADR 0049
/// §3.1; checked with `codex mcp list --json`, Codex 0.166.0).
pub(crate) fn set_http_member(
    text: &str,
    key: &str,
    url: &str,
    headers: &[(String, String)],
) -> Result<String, Malformed> {
    let (layout, body) = split(text)?;
    let mut doc = parse(&body)?;
    if !doc.contains_key(SERVERS) {
        let mut servers = Table::new();
        servers.set_implicit(true);
        doc.insert(SERVERS, Item::Table(servers));
    }
    let servers = doc
        .get_mut(SERVERS)
        .and_then(Item::as_table_like_mut)
        .ok_or_else(not_a_table)?;
    let mut table = Table::new();
    table.insert("url", toml_edit::value(url));
    let mut fixed = InlineTable::new();
    for (k, v) in headers {
        fixed.insert(k, v.as_str().into());
    }
    table.insert("http_headers", toml_edit::value(fixed));
    match servers.get_mut(key) {
        Some(existing) if existing.is_table() => {
            let position = existing.as_table().and_then(Table::position);
            if let Some(p) = position {
                table.set_position(Some(p));
            }
            *existing = Item::Table(table);
        }
        Some(existing) => *existing = Item::Table(table),
        None => {
            servers.insert(key, Item::Table(table));
        }
    }
    Ok(join(layout, &doc.to_string()))
}

/// `text` without `[mcp_servers.<key>]`.
pub(crate) fn remove_member(text: &str, key: &str) -> Result<String, Malformed> {
    let (layout, body) = split(text)?;
    let mut doc = parse(&body)?;
    if let Some(servers) = doc.get_mut(SERVERS).and_then(Item::as_table_like_mut) {
        servers.remove(key);
    }
    Ok(join(layout, &doc.to_string()))
}

/// `text` with `[mcp_servers.klav]` set to `entry`.
pub(crate) fn set_entry(text: &str, entry: &Entry) -> Result<String, Malformed> {
    let (layout, body) = split(text)?;
    let mut doc = parse(&body)?;
    if !doc.contains_key(SERVERS) {
        let mut servers = Table::new();
        servers.set_implicit(true);
        doc.insert(SERVERS, Item::Table(servers));
    }
    let servers = doc
        .get_mut(SERVERS)
        .and_then(Item::as_table_like_mut)
        .ok_or_else(not_a_table)?;
    let mut table = Table::new();
    table.insert("command", toml_edit::value(entry.command.as_str()));
    let mut args = Array::new();
    for a in &entry.args {
        args.push(a.as_str());
    }
    table.insert("args", toml_edit::value(args));
    if !entry.env.is_empty() {
        let mut env = InlineTable::new();
        for (k, v) in &entry.env {
            env.insert(k, v.as_str().into());
        }
        table.insert("env", toml_edit::value(env));
    }
    match servers.get_mut(KEY) {
        Some(existing) if existing.is_table() => {
            // Keep where the table was.
            let position = existing.as_table().and_then(Table::position);
            if let Some(p) = position {
                table.set_position(Some(p));
            }
            *existing = Item::Table(table);
        }
        Some(existing) => *existing = Item::Table(table),
        None => {
            servers.insert(KEY, Item::Table(table));
        }
    }
    Ok(join(layout, &doc.to_string()))
}

/// `text` without `[mcp_servers.klav]`.
pub(crate) fn remove_entry(text: &str) -> Result<String, Malformed> {
    let (layout, body) = split(text)?;
    let mut doc = parse(&body)?;
    if let Some(servers) = doc.get_mut(SERVERS).and_then(Item::as_table_like_mut) {
        servers.remove(KEY);
    }
    Ok(join(layout, &doc.to_string()))
}

/// Checks that `after` is valid and differs from `before` only in
/// `[mcp_servers.klav]`: without it, both read the same, byte for byte,
/// with the same line ends and byte order mark.
pub(crate) fn only_klav_changed(before: &str, after: &str) -> Result<(), String> {
    let (was, _) = split(before).map_err(|e| format!("before: {e}"))?;
    let (layout, body) =
        split(after).map_err(|e| format!("the file Klav wrote is not valid: {e}"))?;
    parse(&body).map_err(|e| format!("the file Klav wrote is not valid: {e}"))?;
    if layout != was {
        return Err("the line ends or the byte order mark of the file changed".into());
    }
    let strip = |text: &str| remove_entry(text).map_err(|e| e.to_string());
    if strip(before)?.trim_end() == strip(after)?.trim_end() {
        Ok(())
    } else {
        Err("another setting of the file changed".into())
    }
}

/// A TOML item as JSON (for comparing and showing an entry).
fn item_value(item: &Item) -> Value {
    match item {
        Item::None => Value::Null,
        Item::Value(v) => value(v),
        Item::Table(t) => Value::Object(
            t.iter()
                .map(|(k, v)| (k.to_owned(), item_value(v)))
                .collect(),
        ),
        Item::ArrayOfTables(a) => Value::Array(
            a.iter()
                .map(|t| {
                    Value::Object(
                        t.iter()
                            .map(|(k, v)| (k.to_owned(), item_value(v)))
                            .collect(),
                    )
                })
                .collect(),
        ),
    }
}

fn value(v: &toml_edit::Value) -> Value {
    use toml_edit::Value as V;
    match v {
        V::String(s) => Value::String(s.value().clone()),
        V::Integer(i) => Value::from(*i.value()),
        V::Float(f) => serde_json::Number::from_f64(*f.value()).map_or(Value::Null, Value::Number),
        V::Boolean(b) => Value::Bool(*b.value()),
        V::Datetime(d) => Value::String(d.value().to_string()),
        V::Array(a) => Value::Array(a.iter().map(value).collect()),
        V::InlineTable(t) => {
            Value::Object(t.iter().map(|(k, v)| (k.to_owned(), value(v))).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry {
            stdio_type: false,
            command: "/usr/local/bin/klav".into(),
            args: vec!["mcp".into(), "--agent".into(), "codex".into()],
            env: vec![("KLAV_HOME".into(), "/tmp/k h".into())],
        }
    }

    const CONFIG: &str = r#"# my codex settings
model = "gpt-5"   # the model

[mcp_servers.github]
command = "npx"
env = { GITHUB_TOKEN = "ghp_secret" }

[profiles.fast]
model = "mini"
"#;

    #[test]
    fn inserting_keeps_comments_and_other_tables() {
        let out = set_entry(CONFIG, &entry()).expect("set");
        assert!(
            out.starts_with("# my codex settings\nmodel = \"gpt-5\"   # the model\n"),
            "{out}"
        );
        assert!(
            out.contains(
                "[mcp_servers.github]\ncommand = \"npx\"\nenv = { GITHUB_TOKEN = \"ghp_secret\" }\n"
            ),
            "{out}"
        );
        assert!(out.contains("[mcp_servers.klav]"), "{out}");
        assert!(!out.contains("[mcp_servers]\n"), "{out}");
        only_klav_changed(CONFIG, &out).expect("only klav");
        let read = super::entry(&out).expect("parse").expect("klav");
        assert!(entry().matches(&read), "{read}");
        let removed = remove_entry(&out).expect("remove");
        only_klav_changed(&out, &removed).expect("only klav");
        assert_eq!(removed.trim_end(), CONFIG.trim_end());
    }

    #[test]
    fn replacing_keeps_the_table_where_it_was() {
        let text = "[mcp_servers.klav]\ncommand = \"klav\"\nargs = [\"mcp\"]\n\n[other]\nx = 1\n";
        let out = set_entry(text, &entry()).expect("set");
        let klav = out.find("[mcp_servers.klav]").expect("klav");
        let other = out.find("[other]").expect("other");
        assert!(klav < other, "{out}");
        only_klav_changed(text, &out).expect("only klav");
        assert_eq!(out.matches("[mcp_servers.klav]").count(), 1);
    }

    #[test]
    fn crlf_line_ends_and_a_bom_are_kept() {
        let crlf = format!("\u{feff}{}", CONFIG.replace('\n', "\r\n"));
        let out = set_entry(&crlf, &entry()).expect("set");
        assert!(out.starts_with('\u{feff}'), "{out:?}");
        assert!(!out.replace("\r\n", "").contains('\n'), "{out:?}");
        assert!(out.contains("[mcp_servers.klav]\r\n"), "{out:?}");
        only_klav_changed(&crlf, &out).expect("only klav");
        let read = super::entry(&out).expect("parse").expect("klav");
        assert!(entry().matches(&read), "{read}");
        let removed = remove_entry(&out).expect("remove");
        assert_eq!(removed.trim_end(), crlf.trim_end());
        // A writer that loses them is caught.
        assert!(only_klav_changed(&crlf, &out.replace("\r\n", "\n")).is_err());
        assert!(only_klav_changed(&crlf, &out.replacen('\u{feff}', "", 1)).is_err());
        // Both kinds of line end: not touched.
        let mixed = "a = 1\r\nb = 2\n";
        let err = set_entry(mixed, &entry()).expect_err("mixed");
        assert_eq!((err.line, err.column), (2, 6), "{err:?}");
        assert!(err.problem.contains("CRLF and LF"), "{err}");
    }

    #[test]
    fn repeated_keys_are_malformed() {
        // toml_edit refuses them itself, as the TOML spec says.
        let twice = "[mcp_servers.klav]\ncommand = \"/a\"\n[mcp_servers.klav]\ncommand = \"/b\"\n";
        assert!(super::entry(twice).is_err());
        let mixed =
            "mcp_servers = { klav = { command = \"/a\" } }\n[mcp_servers.klav]\ncommand = \"/b\"\n";
        assert!(super::entry(mixed).is_err());
        assert!(set_entry(twice, &entry()).is_err());
    }

    #[test]
    fn new_files_and_malformed_ones() {
        let out = set_entry("", &entry()).expect("set");
        assert!(super::entry(&out).expect("parse").is_some(), "{out}");
        let err = set_entry("a = 1\nb = = \"sk-secret\"\n", &entry()).expect_err("bad");
        assert_eq!(err.line, 2);
        assert!(!err.to_string().contains("secret"));
        let err = super::entry("mcp_servers = 3\n").expect_err("not a table");
        assert!(err.problem.contains("not a table"));
        assert!(only_klav_changed(CONFIG, &CONFIG.replace("mini", "max")).is_err());
    }
}
