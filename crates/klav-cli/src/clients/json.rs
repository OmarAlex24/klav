//! JSON settings (Claude Desktop, Cursor, VS Code; and reading Claude
//! Code's): only the `klav` member of the servers object is inserted,
//! replaced or removed, with `jsonc-parser`'s CST, so comments, spacing,
//! order and every other key stay as they were (ADR 0033 §3.6). The file is
//! never read into a structure and written back.

use jsonc_parser::ParseOptions;
use jsonc_parser::cst::{CstInputValue, CstNode, CstObject, CstRootNode};
use serde_json::Value;

use super::{Entry, Malformed};

/// The member Klav owns.
const KEY: &str = "klav";

/// JSON with comments and trailing commas (JSONC), and nothing looser: a
/// file with a missing comma or a single-quoted string is malformed, and
/// Klav does not touch it.
fn options() -> ParseOptions {
    ParseOptions {
        allow_comments: true,
        allow_trailing_commas: true,
        allow_loose_object_property_names: false,
        allow_missing_commas: false,
        allow_single_quoted_strings: false,
        allow_hexadecimal_numbers: false,
        allow_unary_plus_numbers: false,
        allow_bare_decimal_point_numbers: false,
        allow_non_finite_numbers: false,
        allow_extended_string_escapes: false,
    }
}

fn parse(text: &str) -> Result<CstRootNode, Malformed> {
    if text.starts_with('\u{feff}') {
        return Err(Malformed {
            line: 1,
            column: 1,
            problem: "not valid JSON: it starts with a byte order mark (BOM)".into(),
        });
    }
    CstRootNode::parse(text, &options()).map_err(|e| Malformed {
        line: e.line_display(),
        column: e.column_display(),
        // The kind only: some kinds quote what they found in the file.
        problem: "not valid JSON".into(),
    })
}

/// A client's settings text: valid, and without a repeated key in the root
/// object or in `container`. Clients read a repeated key as its last
/// occurrence, so a second `klav` (or `mcpServers`) would hide the entry
/// the client really runs: Klav treats the file as malformed instead.
fn parse_settings(text: &str, container: &str) -> Result<CstRootNode, Malformed> {
    let root = parse(text)?;
    no_repeated_keys(text, container)?;
    Ok(root)
}

/// Where the second occurrence of a repeated key is, in the root object or
/// in `container` (never what the other keys are).
fn no_repeated_keys(text: &str, container: &str) -> Result<(), Malformed> {
    use jsonc_parser::ast::Value as Ast;
    // `parse` already accepted the text with the same options.
    let Ok(ast) = jsonc_parser::parse_to_ast(text, &Default::default(), &options()) else {
        return Ok(());
    };
    let Some(Ast::Object(root)) = ast.value else {
        return Ok(());
    };
    let mut objects = vec![(&root, "the file")];
    for prop in &root.properties {
        if prop.name.as_str() == container
            && let Ast::Object(servers) = &prop.value
        {
            objects.push((servers, container));
        }
    }
    for (object, place) in objects {
        let mut seen = std::collections::HashSet::new();
        for prop in &object.properties {
            let name = prop.name.as_str();
            if !seen.insert(name) {
                let (line, column) = super::line_column(text, prop.range.start);
                let what = if name == KEY || name == container {
                    format!("`{name}`")
                } else {
                    "a key".to_owned()
                };
                return Err(Malformed {
                    line,
                    column,
                    problem: format!(
                        "{what} repeated in {}: the client would read only the last one",
                        if place == "the file" {
                            place.to_owned()
                        } else {
                            format!("`{place}`")
                        }
                    ),
                });
            }
        }
    }
    Ok(())
}

fn not_an_object(what: &str) -> Malformed {
    Malformed {
        line: 1,
        column: 1,
        problem: format!("{what} is not a JSON object"),
    }
}

/// The root object (an empty text counts as `{}`).
fn root_object(root: &CstRootNode) -> Result<Option<CstObject>, Malformed> {
    match root.value() {
        None => Ok(None),
        Some(value) => value
            .as_object()
            .map(Some)
            .ok_or_else(|| not_an_object("the file")),
    }
}

/// The servers object, if the file has one.
fn servers(root: &CstRootNode, container: &str) -> Result<Option<CstObject>, Malformed> {
    let Some(object) = root_object(root)? else {
        return Ok(None);
    };
    match object.get(container) {
        None => Ok(None),
        Some(prop) => prop
            .value()
            .and_then(|v| v.as_object())
            .map(Some)
            .ok_or_else(|| not_an_object(&format!("`{container}`"))),
    }
}

/// The `klav` member of `container`, as JSON.
pub(crate) fn entry(text: &str, container: &str) -> Result<Option<Value>, Malformed> {
    member(text, container, KEY)
}

/// The member `key` of `container`, as JSON (ADR 0049 §3.1: the MCP
/// gateway's entries are named after their profiles).
pub(crate) fn member(text: &str, container: &str, key: &str) -> Result<Option<Value>, Malformed> {
    let root = parse_settings(text, container)?;
    Ok(servers(&root, container)?
        .and_then(|s| s.get(key))
        .and_then(|p| p.value())
        .map(|v| to_value(&v)))
}

/// `text` with the member `key` of `container` set to `value`, as
/// [`set_entry`] does for `klav`.
pub(crate) fn set_member(
    text: &str,
    container: &str,
    key: &str,
    value: &Value,
) -> Result<String, Malformed> {
    set_input(text, container, key, value_input(value))
}

/// `text` without the member `key` of `container`.
pub(crate) fn remove_member(text: &str, container: &str, key: &str) -> Result<String, Malformed> {
    let root = parse_settings(text, container)?;
    if let Some(prop) = servers(&root, container)?.and_then(|s| s.get(key)) {
        prop.remove();
    }
    Ok(root.to_string())
}

/// A JSON value as CST input.
fn value_input(value: &Value) -> CstInputValue {
    match value {
        Value::Null => CstInputValue::Null,
        Value::Bool(b) => CstInputValue::Bool(*b),
        Value::Number(n) => CstInputValue::Number(n.to_string()),
        Value::String(s) => CstInputValue::String(s.clone()),
        Value::Array(a) => CstInputValue::Array(a.iter().map(value_input).collect()),
        Value::Object(o) => {
            CstInputValue::Object(o.iter().map(|(k, v)| (k.clone(), value_input(v))).collect())
        }
    }
}

/// A whole JSON settings text as a value (for read-only checks of managed
/// settings).
pub(crate) fn value(text: &str) -> Result<Value, Malformed> {
    let root = parse(text)?;
    Ok(root.value().map_or(Value::Null, |v| to_value(&v)))
}

/// `text` with the `klav` member set to `entry`: replaced in place if it is
/// there, else appended to `container` (created at the end of the root
/// object if missing).
pub(crate) fn set_entry(text: &str, container: &str, entry: &Entry) -> Result<String, Malformed> {
    set_input(text, container, KEY, to_input(entry))
}

fn set_input(
    text: &str,
    container: &str,
    key: &str,
    input: CstInputValue,
) -> Result<String, Malformed> {
    let root = parse_settings(text, container)?;
    let new_file = root.value().is_none();
    let object = match root_object(&root)? {
        Some(o) => o,
        None => root.object_value_or_set(),
    };
    match object.get(container) {
        None => {
            object.append(container, CstInputValue::Object(vec![(key.into(), input)]));
        }
        Some(prop) => {
            let servers = prop
                .value()
                .and_then(|v| v.as_object())
                .ok_or_else(|| not_an_object(&format!("`{container}`")))?;
            match servers.get(key) {
                Some(existing) => existing.set_value(input),
                None => {
                    servers.append(key, input);
                }
            }
        }
    }
    let mut out = root.to_string();
    if new_file && !out.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

/// `text` without the `klav` member (unchanged if it has none).
pub(crate) fn remove_entry(text: &str, container: &str) -> Result<String, Malformed> {
    let root = parse_settings(text, container)?;
    if let Some(prop) = servers(&root, container)?.and_then(|s| s.get(KEY)) {
        prop.remove();
    }
    Ok(root.to_string())
}

/// Checks that `after` is valid and differs from `before` only in the
/// `klav` member: every other key of the root and of `container` is the
/// same, byte for byte.
pub(crate) fn only_klav_changed(before: &str, after: &str, container: &str) -> Result<(), String> {
    only_member_changed(before, after, container, KEY)
}

/// [`only_klav_changed`] for the member `key`.
pub(crate) fn only_member_changed(
    before: &str,
    after: &str,
    container: &str,
    key: &str,
) -> Result<(), String> {
    let before = parse_settings(before, container).map_err(|e| format!("before: {e}"))?;
    let after = parse_settings(after, container)
        .map_err(|e| format!("the file Klav wrote is not valid: {e}"))?;
    let members = |root: &CstRootNode, inner: bool| -> Result<Vec<(String, String)>, String> {
        let object = if inner {
            servers(root, container).map_err(|e| e.to_string())?
        } else {
            root_object(root).map_err(|e| e.to_string())?
        };
        Ok(object
            .map(|o| o.properties())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|p| {
                let name = p.decoded_name()?;
                let skip = if inner {
                    name == key
                } else {
                    name == container
                };
                (!skip).then(|| (name, p.value().map(|v| v.to_string()).unwrap_or_default()))
            })
            .collect())
    };
    for inner in [false, true] {
        if members(&before, inner)? != members(&after, inner)? {
            return Err(if inner {
                format!("another server in `{container}` changed")
            } else {
                "another setting of the file changed".into()
            });
        }
    }
    Ok(())
}

fn to_input(entry: &Entry) -> CstInputValue {
    let strings =
        |v: &[String]| CstInputValue::Array(v.iter().cloned().map(CstInputValue::String).collect());
    let mut members = Vec::new();
    if entry.stdio_type {
        members.push(("type".to_owned(), CstInputValue::String("stdio".into())));
    }
    members.push((
        "command".to_owned(),
        CstInputValue::String(entry.command.clone()),
    ));
    members.push(("args".to_owned(), strings(&entry.args)));
    if !entry.env.is_empty() {
        members.push((
            "env".to_owned(),
            CstInputValue::Object(
                entry
                    .env
                    .iter()
                    .map(|(k, v)| (k.clone(), CstInputValue::String(v.clone())))
                    .collect(),
            ),
        ));
    }
    CstInputValue::Object(members)
}

/// A CST value as JSON (numbers as written; words as strings).
fn to_value(node: &CstNode) -> Value {
    if let Some(object) = node.as_object() {
        return Value::Object(
            object
                .properties()
                .into_iter()
                .filter_map(|p| {
                    Some((
                        p.decoded_name()?,
                        p.value().map_or(Value::Null, |v| to_value(&v)),
                    ))
                })
                .collect(),
        );
    }
    if let Some(array) = node.as_array() {
        return Value::Array(array.elements().iter().map(to_value).collect());
    }
    if let Some(s) = node.as_string_lit() {
        return Value::String(s.decoded_value().unwrap_or_default());
    }
    if let Some(b) = node.as_boolean_lit() {
        return Value::Bool(b.value());
    }
    if node.as_null_keyword().is_some() {
        return Value::Null;
    }
    if let Some(n) = node.as_number_lit() {
        let raw = n.to_string();
        return serde_json::from_str(&raw).unwrap_or(Value::String(raw));
    }
    Value::String(node.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry {
            stdio_type: true,
            command: "/usr/local/bin/klav".into(),
            args: vec!["mcp".into(), "--agent".into(), "cursor".into()],
            env: Vec::new(),
        }
    }

    const WITH_OTHERS: &str = r#"{
    // my servers
    "mcpServers": {
        "github": {
            "command": "npx",
            "env": { "GITHUB_TOKEN": "ghp_secret" }, // keep me
        },
    },
    "theme": "dark",
}
"#;

    #[test]
    fn inserting_keeps_comments_indentation_and_other_servers() {
        let out = set_entry(WITH_OTHERS, "mcpServers", &entry()).expect("set");
        assert!(out.contains("// my servers"), "{out}");
        assert!(out.contains("// keep me"), "{out}");
        assert!(
            out.contains(r#""env": { "GITHUB_TOKEN": "ghp_secret" }"#),
            "{out}"
        );
        assert!(
            out.contains("\n        \"klav\": {\n            \"type\": \"stdio\","),
            "{out}"
        );
        only_klav_changed(WITH_OTHERS, &out, "mcpServers").expect("only klav");
        let read = super::entry(&out, "mcpServers")
            .expect("parse")
            .expect("klav");
        assert!(entry().matches(&read), "{read}");
        // Removing it gives the other servers back as they were.
        let removed = remove_entry(&out, "mcpServers").expect("remove");
        only_klav_changed(&out, &removed, "mcpServers").expect("only klav");
        assert!(
            super::entry(&removed, "mcpServers")
                .expect("parse")
                .is_none()
        );
        assert!(
            removed.contains(r#""env": { "GITHUB_TOKEN": "ghp_secret" }, // keep me"#),
            "{removed}"
        );
    }

    #[test]
    fn replacing_changes_only_klav() {
        let first = set_entry(WITH_OTHERS, "mcpServers", &entry()).expect("set");
        let mut other = entry();
        other.command = "/Applications/Klav.app/Contents/Helpers/klav".into();
        let second = set_entry(&first, "mcpServers", &other).expect("set");
        only_klav_changed(&first, &second, "mcpServers").expect("only klav");
        assert_eq!(second.matches("\"klav\"").count(), 1, "{second}");
        let read = super::entry(&second, "mcpServers")
            .expect("parse")
            .expect("klav");
        assert!(other.matches(&read));
    }

    #[test]
    fn new_and_empty_files_get_only_klav() {
        for text in ["", "{}", "{}\n"] {
            let out = set_entry(text, "mcpServers", &entry()).expect("set");
            let value: Value = serde_json::from_str(&out).expect("strict JSON");
            assert_eq!(value.as_object().expect("object").len(), 1, "{out}");
            assert!(entry().matches(&value["mcpServers"]["klav"]), "{out}");
            // A new file ends with a line break; an existing one keeps its end.
            assert_eq!(out.ends_with('\n'), text != "{}", "{out:?}");
        }
    }

    #[test]
    fn a_container_is_added_at_the_end_of_a_compact_file() {
        let text = r#"{"theme":"dark","n":[1,2]}"#;
        let out = set_entry(text, "mcpServers", &entry()).expect("set");
        only_klav_changed(text, &out, "mcpServers").expect("only klav");
        let value: Value = serde_json::from_str(&out).expect("json");
        assert_eq!(value["theme"], "dark");
        assert_eq!(value["n"], serde_json::json!([1, 2]));
    }

    #[test]
    fn malformed_files_say_where_and_never_what() {
        let text = "{\n  \"mcpServers\": {\n    \"x\": \"sk-live-secret\"\n    \"y\": 1\n";
        let err = set_entry(text, "mcpServers", &entry()).expect_err("malformed");
        assert_eq!((err.line, err.column), (3, 26), "{err:?}");
        assert!(!err.to_string().contains("secret"), "{err}");
        let err = entry_of("[1, 2]").expect_err("not an object");
        assert!(err.problem.contains("not a JSON object"));
        let err = entry_of(r#"{"mcpServers": []}"#).expect_err("not an object");
        assert!(err.problem.contains("mcpServers"));
    }

    fn entry_of(text: &str) -> Result<Option<Value>, Malformed> {
        super::entry(text, "mcpServers")
    }

    #[test]
    fn repeated_keys_make_the_file_malformed() {
        // Clients read the last `klav`: Klav must not see the first one.
        let text = "{\n  \"mcpServers\": {\n    \"klav\": {\"command\": \"/a\"},\n    \"klav\": {\"command\": \"/b\"}\n  }\n}\n";
        let err = entry_of(text).expect_err("repeated klav");
        assert_eq!((err.line, err.column), (4, 5), "{err:?}");
        assert!(err.problem.contains("`klav` repeated"), "{err}");
        assert!(set_entry(text, "mcpServers", &entry()).is_err());
        assert!(remove_entry(text, "mcpServers").is_err());
        // A repeated `mcpServers`, or another repeated server, too; the
        // name of another server is never said.
        let text = r#"{"mcpServers": {"klav": {"command": "/a"}}, "mcpServers": {}}"#;
        let err = entry_of(text).expect_err("repeated container");
        assert!(err.problem.contains("`mcpServers` repeated"), "{err}");
        let text = r#"{"mcpServers": {"sk-ish": {}, "sk-ish": {}}}"#;
        let err = entry_of(text).expect_err("repeated server");
        assert!(!err.to_string().contains("sk-ish"), "{err}");
        // The check after writing catches one too.
        let good = r#"{"mcpServers": {"klav": {"command": "/a"}}}"#;
        let bad = r#"{"mcpServers": {"klav": {"command": "/a"}, "klav": {}}}"#;
        assert!(only_klav_changed(good, bad, "mcpServers").is_err());
        // The same name in different objects is fine.
        let text = r#"{"klav": 1, "mcpServers": {"klav": {"command": "/a"}}}"#;
        assert!(entry_of(text).expect("ok").is_some());
    }

    #[test]
    fn line_endings_and_a_bom() {
        let crlf = "{\r\n  \"mcpServers\": {\r\n    \"a\": {}\r\n  }\r\n}\r\n";
        let out = set_entry(crlf, "mcpServers", &entry()).expect("set");
        assert!(!out.replace("\r\n", "").contains('\n'), "{out:?}");
        only_klav_changed(crlf, &out, "mcpServers").expect("only klav");
        let err = entry_of("\u{feff}{}").expect_err("bom");
        assert!(err.problem.contains("byte order mark"), "{err}");
    }

    #[test]
    fn a_change_to_another_key_is_caught() {
        let after = WITH_OTHERS.replace("dark", "light");
        assert!(only_klav_changed(WITH_OTHERS, &after, "mcpServers").is_err());
        let after = WITH_OTHERS.replace("npx", "bunx");
        assert!(only_klav_changed(WITH_OTHERS, &after, "mcpServers").is_err());
        assert!(only_klav_changed(WITH_OTHERS, "{ nope", "mcpServers").is_err());
    }
}
