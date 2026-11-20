//! Why a path is not in its one canonical spelling (spec §13.4,
//! `klav_core::policy::is_canonical_path`), in words a caller can act on.
//!
//! Some HTTP clients escape reserved characters by default (Go's
//! `PathEscape`, JavaScript's `encodeURIComponent`): `%2C`, `%3A`, `%40`.
//! The proxy refuses them by design, since they are another spelling of the
//! same path, and says which character it refused and how to send it. The
//! explanation goes back to the caller only: it names at most one escape
//! or character, never the rest of the path (which could hold a
//! credential), and it is never logged.
//!
//! The rule itself lives in `klav-core`. The Klav server also refuses a
//! `"` in a proxied path (its approvals index the path as JSON, where a
//! `"` takes two bytes), so this module refuses it too, before the server
//! is asked. A proptest checks it refuses exactly what those two refuse.

use klav_core::policy::MAX_HTTP_PATH;

fn upper_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn any_hex(b: u8) -> Option<u8> {
    upper_hex(b.to_ascii_uppercase())
}

/// What is wrong with `path`, or `None` when it is canonical.
pub fn path_problem(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    if bytes.first() != Some(&b'/') {
        return Some("the path must start with `/`".into());
    }
    if bytes.len() > MAX_HTTP_PATH {
        return Some(format!("the path is longer than {MAX_HTTP_PATH} bytes"));
    }
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            let pair = bytes.get(i + 1..i + 3);
            let Some([hi, lo]) = pair else {
                return Some("a `%` that is not followed by two hex digits".into());
            };
            let (Some(h), Some(l)) = (any_hex(*hi), any_hex(*lo)) else {
                return Some("a `%` that is not followed by two hex digits".into());
            };
            let escape = format!("%{}{}", *hi as char, *lo as char);
            let decoded = h << 4 | l;
            if upper_hex(*hi).is_none() || upper_hex(*lo).is_none() {
                return Some(format!(
                    "`{escape}` uses lower-case hex: escapes are upper case, and only for a space, `?` or `#` (`%20`, `%3F`, `%23`)"
                ));
            }
            match decoded {
                b' ' | b'?' | b'#' => {}
                b'/' => {
                    return Some(format!(
                        "`{escape}` is an escaped `/`, which is never accepted: the provider could split the path differently"
                    ));
                }
                b'%' | b'\\' | b';' | b'"' => {
                    return Some(format!(
                        "`{escape}` escapes `{}`, which a path never carries",
                        decoded as char
                    ));
                }
                0x21..=0x7e => {
                    return Some(format!(
                        "`{escape}` escapes `{}`, which a path carries as itself: send `{}` unescaped (the proxy accepts one spelling per character, so a rule cannot be dodged by escaping)",
                        decoded as char, decoded as char
                    ));
                }
                _ => {
                    return Some(format!(
                        "`{escape}` escapes a control character or a byte outside ASCII, which a path never carries"
                    ));
                }
            }
            i += 3;
        } else if (0x21..=0x7e).contains(&b) && !matches!(b, b'?' | b'#' | b'\\' | b';' | b'"') {
            i += 1;
        } else {
            return Some(match b {
                b'\\' => "`\\` is never accepted in a path".into(),
                b'"' => "`\"` is never accepted in a path".into(),
                b';' => "`;` (path parameters) is never accepted".into(),
                b' ' => "a space must be escaped as `%20`".into(),
                b'?' | b'#' => format!("`{}` must be escaped", b as char),
                0x80.. => "a byte outside ASCII, which a path never carries".into(),
                _ => "a control character, which a path never carries".into(),
            });
        }
    }
    let segments: Vec<&str> = path[1..].split('/').collect();
    let last = segments.len() - 1;
    for (n, seg) in segments.iter().enumerate() {
        if matches!(*seg, "." | "..") {
            return Some("a `.` or `..` segment".into());
        }
        if seg.is_empty() && n != last {
            return Some("an empty segment (`//`)".into());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use klav_core::policy::is_canonical_path;
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn it_names_the_escape_and_how_to_send_it() {
        let p = path_problem("/v1/items/a%2Cb").unwrap();
        assert!(
            p.contains("`%2C`") && p.contains("send `,` unescaped"),
            "{p}"
        );
        assert!(path_problem("/v1/a%2Fb").unwrap().contains("escaped `/`"));
        assert!(path_problem("/v1/a%2cb").unwrap().contains("lower-case"));
        assert!(path_problem("/v1/%zz").unwrap().contains("two hex digits"));
        assert!(path_problem("/v1//a").unwrap().contains("empty segment"));
        assert!(path_problem("/v1/../a").unwrap().contains("`..`"));
        assert!(path_problem("/v1;a=b").unwrap().contains("`;`"));
        assert!(path_problem("/v1/a\"b").unwrap().contains("`\"` is never"));
        let p = path_problem("/v1/a%22b").unwrap();
        assert!(p.contains("`%22`") && p.contains("never carries"), "{p}");
        assert_eq!(path_problem("/v1/a%20b,c:d@e/"), None);
        // Only the refused escape, never the rest of the path.
        let p = path_problem("/v1/tok_live_secret/%3A").unwrap();
        assert!(!p.contains("tok_live_secret"));
    }

    /// What the server accepts in a proxied call: the policy's rule, and no
    /// `"` (`check_claims` in `klav-server`'s `routes/agent_access.rs`).
    fn accepted(path: &str) -> bool {
        is_canonical_path(path) && !path.contains('"')
    }

    proptest! {
        /// It refuses exactly what the server refuses.
        #[test]
        fn prop_agrees_with_the_policy(
            path in "/[a-zA-Z0-9/.%;:@,\\\\ ?#é_~\"-]{0,24}",
        ) {
            prop_assert_eq!(path_problem(&path).is_none(), accepted(&path));
        }

        #[test]
        fn prop_agrees_on_escapes(
            head in "/[a-z/]{0,6}",
            hi in "[0-9a-fA-FgG]",
            lo in "[0-9a-fA-FgG]",
            tail in "[a-z/.]{0,4}",
        ) {
            let path = format!("{head}%{hi}{lo}{tail}");
            prop_assert_eq!(path_problem(&path).is_none(), accepted(&path));
        }
    }
}
