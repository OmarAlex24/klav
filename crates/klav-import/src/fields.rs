//! Helpers the parsers share to build items.

use std::collections::HashSet;

use klav_core::model::Item;
use klav_core::model::item::{Field, FieldKind, ItemKind, slugify};

/// Text without control characters, at most `max` characters.
pub(crate) fn clean(text: &str, max: usize) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// The host of a URL, without `www.` (also `android://…@com.app/`).
pub(crate) fn host(url: &str) -> Option<String> {
    exact_host(url)
        .map(|h| h.trim_start_matches("www.").to_owned())
        .filter(|h| !h.is_empty())
}

/// The host of `url`, lowercase, as is (`www.` included): what a saved
/// passkey's rpId is compared with.
pub(crate) fn exact_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let host = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?;
    let host = host.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Most fields one imported item gets; the rest are left out with a note.
/// Klav's model has no cap of its own, and every field is checked against
/// the others for a free name.
pub(crate) const MAX_ITEM_FIELDS: usize = 256;

/// The scheme of `url` (RFC 3986: a letter, then letters, digits, `+`, `-`
/// or `.`, before a `:`), unless it is a host and a port
/// (`example.org:8443`).
fn scheme(url: &str) -> Option<&str> {
    let (head, rest) = url.split_once(':')?;
    let mut chars = head.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    let port = !rest.starts_with("//") && rest.starts_with(|c: char| c.is_ascii_digit());
    (valid && !port).then_some(head)
}

/// The links of an entry, sorted by what Klav keeps of them.
#[derive(Default)]
pub(crate) struct Links {
    /// `http` and `https` URLs, kept; one without a scheme gets `https://`.
    pub(crate) web: Vec<String>,
    /// App links (`android://…@com.example.app/`): they only name the item.
    apps: Vec<String>,
    /// Anything else (`javascript:`, `data:`, `file:`…): left out. Its
    /// host does not name the item either: `javascript://github.com/%0a…`
    /// is not GitHub.
    other: usize,
}

impl Links {
    pub(crate) fn sort<'a>(urls: impl IntoIterator<Item = &'a str>) -> Self {
        let mut links = Links::default();
        for url in urls.into_iter().map(str::trim).filter(|u| !u.is_empty()) {
            match scheme(url) {
                Some(s) if s.eq_ignore_ascii_case("http") || s.eq_ignore_ascii_case("https") => {
                    links.web.push(url.to_owned());
                }
                Some(s)
                    if ["android", "androidapp", "iosapp"]
                        .iter()
                        .any(|a| s.eq_ignore_ascii_case(a)) =>
                {
                    links.apps.push(url.to_owned());
                }
                Some(_) => links.other += 1,
                None => links.web.push(match url.strip_prefix("//") {
                    Some(rest) => format!("https://{rest}"),
                    None => format!("https://{url}"),
                }),
            }
        }
        links
    }

    /// What a title may come from: the web links, then the app links.
    pub(crate) fn for_title(&self) -> Vec<&str> {
        self.web
            .iter()
            .chain(&self.apps)
            .map(String::as_str)
            .collect()
    }

    /// Whether a link was left out.
    pub(crate) fn dropped(&self) -> bool {
        !self.apps.is_empty() || self.other > 0
    }
}

/// The remark for [`Links::dropped`].
pub(crate) const LINK_LEFT_OUT: &str = "a link that is not http or https was left out";

/// `url` as Klav keeps it ([`Links`]); `None` if it is left out.
pub(crate) fn web_url(url: &str) -> Option<String> {
    Links::sort([url]).web.pop()
}

/// A new item titled `title`, or after the first site, the user name or
/// `fallback` when it is empty or invalid.
pub(crate) fn new_item(
    kind: ItemKind,
    title: &str,
    sites: &[&str],
    username: &str,
    fallback: &str,
) -> Item {
    let title = clean(title, 256);
    let candidates = [
        title,
        sites.iter().find_map(|u| host(u)).unwrap_or_default(),
        clean(username, 256),
        fallback.to_owned(),
    ];
    for t in candidates.iter().filter(|t| !t.is_empty()) {
        if let Ok(item) = Item::from_template(kind, t) {
            return item;
        }
    }
    #[allow(clippy::expect_used)]
    Item::from_template(kind, "Imported item").expect("a plain title is valid")
}

/// Sets a template field; `false` if the value was refused.
pub(crate) fn set(item: &mut Item, field: &str, value: &str) -> bool {
    if value.trim().is_empty() {
        return true;
    }
    match item.field_mut(field) {
        Some(f) => f.set_value(value).is_ok(),
        None => false,
    }
}

/// Adds a field the template does not have, named after `label`, made
/// unique; `false` if the value was refused or the item is full
/// ([`MAX_ITEM_FIELDS`]).
pub(crate) fn add(item: &mut Item, label: &str, kind: FieldKind, value: &str) -> bool {
    if value.trim().is_empty() {
        return true;
    }
    if item.fields().len() >= MAX_ITEM_FIELDS {
        return false;
    }
    let label = clean(label, 64);
    let base = slugify(&label).unwrap_or_else(|| "field".to_owned());
    let base: String = base.chars().take(56).collect();
    // The names taken, once: asking the item for each candidate would walk
    // its fields again for every one.
    let taken: HashSet<&str> = item.fields().iter().map(|f| f.name()).collect();
    let name = std::iter::once(base.clone())
        .chain((2..).map(|n| format!("{base}-{n}")))
        .find(|n| !taken.contains(n.as_str()))
        .unwrap_or(base);
    let label = if label.is_empty() {
        name.clone()
    } else {
        label
    };
    match Field::new(&name, &label, kind, value) {
        Ok(field) => item.add_field(field).is_ok(),
        Err(_) => false,
    }
}

/// Adds `http`/`https` URLs ([`Links::web`]), skipping repeats; `false` if
/// one was refused.
pub(crate) fn add_urls(item: &mut Item, urls: &[String]) -> bool {
    let mut ok = true;
    for url in urls.iter().map(|u| u.trim()).filter(|u| !u.is_empty()) {
        if !item.urls().iter().any(|u| u == url) && item.add_url(url).is_err() {
            ok = false;
        }
    }
    ok
}

/// Adds tags (skipping repeats and invalid ones); `false` if one was refused.
pub(crate) fn add_tags<'a>(item: &mut Item, tags: impl IntoIterator<Item = &'a str>) -> bool {
    let mut ok = true;
    for tag in tags.into_iter().map(str::trim).filter(|t| !t.is_empty()) {
        let tag = clean(tag, 256);
        if !item.has_tag(&tag) && item.add_tag(&tag).is_err() {
            ok = false;
        }
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(
            host("https://www.Example.com/login").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            host("android://abc==@com.example.app/").as_deref(),
            Some("com.example.app")
        );
        assert_eq!(host("example.org:8443").as_deref(), Some("example.org"));
        assert_eq!(host(""), None);
    }

    #[test]
    fn custom_fields_get_unique_names() {
        let mut item = Item::from_template(ItemKind::Login, "x").unwrap();
        assert!(add(&mut item, "Security answer", FieldKind::Concealed, "a"));
        assert!(add(&mut item, "Security answer", FieldKind::Concealed, "b"));
        assert!(add(&mut item, "Password", FieldKind::Concealed, "c"));
        assert!(add(&mut item, "", FieldKind::Text, "d"));
        let names: Vec<&str> = item.fields().iter().map(|f| f.name()).collect();
        assert!(names.contains(&"security_answer") && names.contains(&"security_answer-2"));
        assert!(names.contains(&"password-2") && names.contains(&"field"));
        assert_eq!(
            new_item(ItemKind::Login, "", &[], "", "Item 3").title(),
            "Item 3"
        );
    }

    #[test]
    fn many_fields_with_one_label() {
        // Each name used to be found by asking the item for every
        // candidate (cubic in the fields); the item also stops at a cap.
        let mut item = Item::from_template(ItemKind::Login, "x").unwrap();
        let template = item.fields().len();
        for _ in 0..MAX_ITEM_FIELDS - template {
            assert!(add(&mut item, "Field", FieldKind::Text, "v"));
        }
        assert!(!add(&mut item, "Field", FieldKind::Text, "v"));
        assert_eq!(item.fields().len(), MAX_ITEM_FIELDS);
        let names: HashSet<&str> = item.fields().iter().map(|f| f.name()).collect();
        assert_eq!(names.len(), MAX_ITEM_FIELDS);
    }

    #[test]
    fn only_web_links_are_kept() {
        let l = Links::sort([
            "https://example.com/login",
            "HTTP://old.example",
            "example.org/path",
            "localhost:8443",
            "//cdn.example",
            "javascript://github.com/%0aalert(1)",
            "JavaScript:alert(1)",
            "data:text/html,<script>",
            "file:///etc/passwd",
            "mailto:ana@example.com",
            "android://AbC==@com.example.app/",
            "  ",
        ]);
        assert_eq!(
            l.web,
            [
                "https://example.com/login",
                "HTTP://old.example",
                "https://example.org/path",
                "https://localhost:8443",
                "https://cdn.example",
            ]
        );
        assert_eq!(l.apps, ["android://AbC==@com.example.app/"]);
        assert_eq!(l.other, 5);
        assert!(l.dropped());
        // The title never comes from a link that is left out.
        let js = Links::sort(["javascript://github.com/%0aalert(1)"]);
        let item = new_item(ItemKind::Login, "", &js.for_title(), "", "Imported row 2");
        assert_eq!(item.title(), "Imported row 2");
        let app = Links::sort(["android://x@com.example.app/"]);
        let item = new_item(ItemKind::Login, "", &app.for_title(), "", "Imported row 2");
        assert_eq!(item.title(), "com.example.app");
        assert!(!Links::sort(["https://a.example"]).dropped());
        assert_eq!(web_url("ftp://a.example"), None);
    }
}
