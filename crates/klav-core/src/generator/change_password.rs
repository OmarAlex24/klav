//! Where a site lets you change your password (ADR 0022 §1.3 and §5): the
//! page listed in `change-password-urls.json`, which is
//! `quirks/change-password-URLs.json` of
//! <https://github.com/apple/password-manager-resources> bundled with Klav
//! (MIT: see `CHANGE-PASSWORD-URLS-NOTICE.md`), or else the site's own
//! `https://<host>/.well-known/change-password`. Nothing here touches the
//! network.
//!
//! The lookup is the one of the bundled password rules: the exact host,
//! then dropping labels from the left, never down to a single label, and no
//! public suffix list (ADR 0006 §6).

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::site;

const BUNDLED_SOURCE: &str = include_str!("change-password-urls.json");

/// The well-known path of the change-password page
/// (<https://w3c.github.io/webappsec-change-password-url/>).
pub const WELL_KNOWN_PATH: &str = "/.well-known/change-password";

/// Where a change-password page came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "source")]
pub enum ChangePasswordSource {
    /// Klav's bundled list, under `domain`.
    Bundled {
        /// The domain the page is listed under.
        domain: String,
    },
    /// The site's own `/.well-known/change-password`.
    WellKnown,
}

/// A site's change-password page. Metadata only: no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangePasswordUrl {
    /// The page.
    pub url: String,
    /// The host it was looked up for.
    pub host: String,
    /// Where it came from.
    #[serde(flatten)]
    pub source: ChangePasswordSource,
}

fn bundled() -> &'static HashMap<String, String> {
    static PAGES: OnceLock<HashMap<String, String>> = OnceLock::new();
    PAGES.get_or_init(|| {
        serde_json::from_str(BUNDLED_SOURCE).expect("bundled change-password pages are valid JSON")
    })
}

/// The bundled page for `host`: the exact host first, then dropping labels
/// from the left (`login.example.com` → `example.com`), never down to a
/// single label. Returns the domain it is listed under and the page.
pub fn bundled_for_host(host: &str) -> Option<(&'static str, &'static str)> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let mut rest = host.as_str();
    loop {
        if !rest.contains('.') {
            return None;
        }
        if let Some((domain, url)) = bundled().get_key_value(rest) {
            return Some((domain.as_str(), url.as_str()));
        }
        rest = rest.split_once('.')?.1;
    }
}

/// The change-password page of the site at `host`: the bundled one, or
/// `https://<host>/.well-known/change-password`. `None` if `host` is not
/// a host name.
pub fn for_host(host: &str) -> Option<ChangePasswordUrl> {
    let host = site::item_host(host)?;
    if host.contains(['/', '?', '#', '@']) {
        return None;
    }
    Some(match bundled_for_host(&host) {
        Some((domain, url)) => ChangePasswordUrl {
            url: url.to_owned(),
            host,
            source: ChangePasswordSource::Bundled {
                domain: domain.to_owned(),
            },
        },
        None => ChangePasswordUrl {
            url: format!("https://{host}{WELL_KNOWN_PATH}"),
            host,
            source: ChangePasswordSource::WellKnown,
        },
    })
}

/// The change-password page of an item with these URLs: that of the first
/// one with a host. `None` if none has.
///
/// The well-known page keeps the item's port: a site on another port
/// (`https://nas.local:5001`) has its change page there, not on
/// `https://<host>`. The scheme is always `https` (ADR 0022 §1.3).
pub fn for_item(item_urls: &[String]) -> Option<ChangePasswordUrl> {
    item_urls.iter().find_map(|u| {
        let mut found = for_host(&site::item_host(u)?)?;
        if found.source == ChangePasswordSource::WellKnown
            && let Some(port) = port_of(u)
        {
            found.url = format!("https://{}:{port}{WELL_KNOWN_PATH}", found.host);
        }
        Some(found)
    })
}

/// The port an item URL names, if it is not its scheme's default.
fn port_of(item_url: &str) -> Option<u16> {
    let item_url = item_url.trim();
    let parsed = if item_url.contains("://") {
        url::Url::parse(item_url).ok()?
    } else {
        url::Url::parse(&format!("https://{item_url}")).ok()?
    };
    parsed.port()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bundled_page_is_an_https_url_with_a_host() {
        assert!(bundled().len() > 100);
        for (domain, page) in bundled() {
            assert!(domain.contains('.'), "{domain}");
            assert_eq!(domain, &domain.to_ascii_lowercase(), "{domain}");
            let url = url::Url::parse(page).unwrap_or_else(|e| panic!("{domain}: {e}"));
            assert_eq!(url.scheme(), "https", "{domain}");
            assert!(url.host_str().is_some_and(|h| !h.is_empty()), "{domain}");
        }
    }

    #[test]
    fn a_listed_site_gets_its_page_and_subdomains_find_it() {
        let found = for_host("23andme.com").unwrap();
        assert_eq!(found.url, "https://you.23andme.com/user/edit/password/");
        assert_eq!(
            found.source,
            ChangePasswordSource::Bundled {
                domain: "23andme.com".into()
            }
        );
        let sub = for_host("login.23andme.com").unwrap();
        assert_eq!(sub.url, found.url);
        assert_eq!(sub.host, "login.23andme.com");
        // Through an item's URLs, `www.` and paths included.
        let item = for_item(&["https://www.23andme.com/login?next=/".into()]).unwrap();
        assert_eq!(item.url, found.url);
    }

    #[test]
    fn any_other_site_gets_its_well_known_page() {
        let found = for_host("bank.example.com").unwrap();
        assert_eq!(
            found.url,
            "https://bank.example.com/.well-known/change-password"
        );
        assert_eq!(found.source, ChangePasswordSource::WellKnown);
        // Never down to a single label: `com` is not looked up.
        assert_eq!(bundled_for_host("com"), None);
        assert_eq!(bundled_for_host("evil-23andme.com"), None);
        let item = for_item(&[String::new(), "https://bank.example.com/login".into()]).unwrap();
        assert_eq!(item.host, "bank.example.com");
        assert_eq!(for_item(&[]), None);
    }

    #[test]
    fn the_well_known_page_keeps_the_item_s_port() {
        let page = |u: &str| for_item(&[u.into()]).unwrap().url;
        assert_eq!(
            page("https://nas.local:5001/login"),
            "https://nas.local:5001/.well-known/change-password"
        );
        assert_eq!(
            page("nas.local:5001"),
            "https://nas.local:5001/.well-known/change-password"
        );
        // Always https, also for an http item (ADR 0022 §1.3).
        assert_eq!(
            page("http://localhost:8443/"),
            "https://localhost:8443/.well-known/change-password"
        );
        assert_eq!(
            page("http://192.168.1.1/"),
            "https://192.168.1.1/.well-known/change-password"
        );
        // The default port and a bare host stay as they were.
        assert_eq!(
            page("https://bank.example.com:443/login"),
            "https://bank.example.com/.well-known/change-password"
        );
        assert_eq!(
            page("bank.example.com"),
            "https://bank.example.com/.well-known/change-password"
        );
        // A bundled page is the list's, whatever the item's port.
        assert_eq!(
            page("https://www.23andme.com:8443/"),
            "https://you.23andme.com/user/edit/password/"
        );
    }

    #[test]
    fn the_answer_serialises_flat() {
        let value = serde_json::to_value(for_host("23andme.com").unwrap()).unwrap();
        assert_eq!(value["source"], "bundled");
        assert_eq!(value["domain"], "23andme.com");
        let value = serde_json::to_value(for_host("bank.example.com").unwrap()).unwrap();
        assert_eq!(value["source"], "well_known");
        assert!(value.get("domain").is_none());
    }
}
