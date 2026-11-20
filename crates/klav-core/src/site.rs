//! Which pages a login may be filled into (threat T21, ADR 0017 §5).
//!
//! One rule for every client: the SDK and `klav mcp` (CDP), `klavd`
//! (browser extension, `autofill`) and the extension itself (through
//! `klav-wasm`). A page qualifies when:
//!
//! - it is `https`, or `http` on this machine (`localhost`, a name under
//!   `.localhost` (RFC 6761) or a loopback IP);
//! - its host is the host of one of the item's URLs, or a subdomain of it.
//!   A leading `www.` of the item's host is ignored, so `www.example.com`
//!   also covers `example.com`;
//! - when that item URL names a port (`http://localhost:3000`), the page
//!   is on that port: on one machine, another port is another program.
//!   An item URL without a port covers every port of its host.
//!
//! No Public Suffix List is consulted (as in ADR 0006): an item for
//! `example.com` never matches `example.com.evil.io` or `example.co`, and
//! an item for `accounts.example.com` does not match `mail.example.com`.
//!
//! The person may also be offered a login saved for a subdomain on the page
//! of its parent domain (ADR 0025): [`host_relation`] tells the three cases
//! apart and orders them. A parent is never a match for [`host_matches`]
//! or [`page_matches`], which agents and every fill without a person use.

use std::net::IpAddr;

use url::{Host, Url};

/// Why a page cannot be filled. It names the page by its [`origin`] only:
/// the path, query and fragment of a page may carry tokens.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SiteError {
    /// Not an absolute URL.
    #[error("cannot fill into {0}: not a web page")]
    NotAPage(String),
    /// No host (`file:`, `data:`, `about:`…).
    #[error("cannot fill into {0}: no host")]
    NoHost(String),
    /// `http` on another machine, or another scheme.
    #[error("cannot fill into {0}: only https pages (or http on this machine)")]
    Insecure(String),
}

/// What a report or an error may say about the page at `url`: its scheme,
/// host and port (`https://github.com`), never its path, query, fragment or
/// user info, where sign-in pages put tokens and codes. A URL without a
/// host gives just its scheme (`about:`).
pub fn origin(url: &str) -> String {
    match Url::parse(url) {
        Ok(parsed) => match parsed.host_str().filter(|h| !h.is_empty()) {
            Some(host) => match parsed.port() {
                Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
                None => format!("{}://{host}", parsed.scheme()),
            },
            None => format!("{}:", parsed.scheme()),
        },
        Err(_) => "a page that is not a web address".to_owned(),
    }
}

/// Whether `url` points to this machine (`localhost` or a loopback IP).
/// Also guards connections the SDK makes itself (CDP), so it does not
/// trust names it would have to resolve through DNS.
pub fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

/// Whether a page the browser loaded is on this machine: what
/// [`is_loopback`] accepts, or a name under `.localhost`. RFC 6761
/// reserves `.localhost` for loopback and Chromium and Firefox resolve it
/// themselves, without DNS, so `http://idmsa.localhost` is as local as
/// `http://localhost` (a test site can then have subdomains, like a
/// sign-in frame on another subdomain).
fn is_local_page(url: &Url) -> bool {
    if is_loopback(url) {
        return true;
    }
    let Some(Host::Domain(d)) = url.host() else {
        return false;
    };
    let d = d.to_ascii_lowercase();
    d.strip_suffix(".localhost")
        .is_some_and(|name| !name.is_empty())
}

/// The page's host (lowercase) if `url` is a page Klav may fill into:
/// `https`, or `http` on this machine.
pub fn fillable_host(url: &str) -> Result<String, SiteError> {
    let parsed = Url::parse(url).map_err(|_| SiteError::NotAPage(origin(url)))?;
    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| SiteError::NoHost(origin(url)))?
        .to_ascii_lowercase();
    match parsed.scheme() {
        "https" => Ok(host),
        "http" if is_local_page(&parsed) => Ok(host),
        _ => Err(SiteError::Insecure(origin(url))),
    }
}

/// An item URL parsed: a bare `github.com` is `https`. Only web
/// addresses name a site: an item saved with `ftp://` or `javascript://`
/// fills nothing.
fn item_url_parsed(item_url: &str) -> Option<Url> {
    let item_url = item_url.trim();
    let parsed = if item_url.contains("://") {
        Url::parse(item_url).ok()?
    } else {
        Url::parse(&format!("https://{item_url}")).ok()?
    };
    matches!(parsed.scheme(), "http" | "https").then_some(parsed)
}

/// The host of an item URL (`https://github.com/login`, or a bare
/// `github.com`), lowercase, without a leading `www.` or a trailing dot.
pub fn item_host(item_url: &str) -> Option<String> {
    let parsed = item_url_parsed(item_url)?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    let host = host.trim_end_matches('.');
    let host = host.strip_prefix("www.").unwrap_or(host).to_owned();
    (!host.is_empty()).then_some(host)
}

/// The Unicode form of [`item_host`] when the host is an internationalized
/// name (a label in punycode, `xn--…`): what the person would read, to
/// show next to the ASCII form so a look-alike stands out. `None` for an
/// ASCII name. Same parse as [`item_host`] and [`url_matches`].
pub fn item_host_unicode(item_url: &str) -> Option<String> {
    let ascii = item_host(item_url)?;
    if !ascii.split('.').any(|label| label.starts_with("xn--")) {
        return None;
    }
    let parsed = item_url_parsed(item_url)?;
    let mut unicode = parsed.clone();
    // The origin's Unicode form carries the host decoded (no port, scheme
    // dropped below).
    unicode.set_port(None).ok()?;
    let origin = unicode.origin().unicode_serialization();
    let host = origin.split_once("://")?.1.trim_end_matches('.');
    let host = host.strip_prefix("www.").unwrap_or(host).to_owned();
    (host != ascii).then_some(host)
}

/// How the page's host relates to a login's URLs (ADR 0025 §3). The order
/// of the variants is the order logins are offered in: `Exact` first, then
/// `Subdomain`, then `Parent`. It wins over any other order (recent use,
/// title), and only the best of it is ever filled without the person.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum HostRelation {
    /// The page's host is one of the item's hosts.
    Exact,
    /// The page is a subdomain of one of the item's hosts (`my.example.com`
    /// for an item of `example.com`).
    Subdomain,
    /// The page is the parent domain of one of the item's hosts
    /// (`example.com` for an item of `my.example.com`). Offered apart and
    /// only filled when the person picks it; never to agents (ADR 0025 §2).
    Parent,
}

impl HostRelation {
    /// Whether a fill without the person, or by an agent, may use it: only
    /// [`Self::Exact`] and [`Self::Subdomain`].
    pub fn matches(self) -> bool {
        self != Self::Parent
    }
}

/// The port an item URL names, if it names one other than its scheme's
/// default (`https://example.com:443` names none).
fn item_port(item_url: &str) -> Option<u16> {
    item_url_parsed(item_url)?.port()
}

fn is_ip(host: &str) -> bool {
    host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok()
}

/// How the page `host` relates to the item host `item` (both lowercase).
///
/// - An IP address has no subdomains and no parent: only the same address.
/// - A name of one label (`com`, `router`) has no subdomains: an item for
///   `com` would cover every `.com` site. `localhost` keeps them (RFC 6761).
/// - The page is a parent only if it is a page: at least two labels
///   (`example.com`, never `com` or `localhost`). Siblings never match, and
///   no Public Suffix List is consulted (ADR 0025 §1).
fn relation(host: &str, item: &str) -> Option<HostRelation> {
    let host = host.trim_end_matches('.');
    if host == item {
        return Some(HostRelation::Exact);
    }
    if is_ip(host) || is_ip(item) {
        return None;
    }
    let item_has_subdomains = item.contains('.') || item == "localhost";
    if item_has_subdomains && host.ends_with(&format!(".{item}")) {
        return Some(HostRelation::Subdomain);
    }
    let labels = host.split('.').filter(|l| !l.is_empty()).count();
    if labels >= 2 && item.ends_with(&format!(".{host}")) {
        return Some(HostRelation::Parent);
    }
    None
}

/// The best relation (in the order of [`HostRelation`]) between the page
/// `host` (from [`fillable_host`]) and any of the item's URLs; `None` when
/// the login is not for this page at all. An item with both
/// `example.com` and `my.example.com` is `Exact` on either page. It knows
/// no port: a decision to fill takes the page URL, through
/// [`url_relation`].
pub fn host_relation(host: &str, item_urls: &[String]) -> Option<HostRelation> {
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    item_urls
        .iter()
        .filter_map(|u| item_host(u))
        .filter_map(|h| relation(&host, &h))
        .min()
}

/// The page's host (lowercase) and port (or its scheme's default).
fn page_host_port(url: &str) -> Option<(String, Option<u16>)> {
    let page = Url::parse(url).ok()?;
    let host = page
        .host_str()
        .filter(|h| !h.is_empty())?
        .to_ascii_lowercase();
    Some((host, page.port_or_known_default()))
}

/// Each of the item's hosts with its relation to the page at `url`, when
/// that item URL's port (if it names one) is the page's: on one machine,
/// another port is another program, also for a parent (ADR 0030 capa 10).
fn url_relations<'a>(
    url: &str,
    item_urls: &'a [String],
) -> impl Iterator<Item = (HostRelation, String)> + 'a {
    let page = page_host_port(url);
    item_urls.iter().filter_map(move |u| {
        let (host, port) = page.as_ref()?;
        let item = item_host(u)?;
        let relation = relation(host, &item)?;
        item_port(u)
            .is_none_or(|p| Some(p) == *port)
            .then_some((relation, item))
    })
}

/// The best relation between the page at `url` and any of the item's
/// URLs, like [`host_relation`], but an item URL that names a port only
/// counts on that port. It does not check that the page is fillable: see
/// [`fillable_host`].
pub fn url_relation(url: &str, item_urls: &[String]) -> Option<HostRelation> {
    url_relations(url, item_urls).map(|(r, _)| r).min()
}

/// The item host the page `host` is a parent of (`my.example.com` on
/// `example.com`), to show next to a [`HostRelation::Parent`] login. The
/// closest one when there are several.
pub fn saved_subdomain(host: &str, item_urls: &[String]) -> Option<String> {
    let host = host.trim().to_ascii_lowercase();
    item_urls
        .iter()
        .filter_map(|u| item_host(u))
        .filter(|h| relation(&host, h) == Some(HostRelation::Parent))
        .min_by_key(String::len)
}

/// [`saved_subdomain`] for the page at `url`, with the ports of
/// [`url_relation`].
pub fn url_saved_subdomain(url: &str, item_urls: &[String]) -> Option<String> {
    url_relations(url, item_urls)
        .filter(|(r, _)| *r == HostRelation::Parent)
        .map(|(_, h)| h)
        .min_by_key(String::len)
}

/// Whether the page `host` (from [`fillable_host`]) belongs to one of the
/// item's URLs: the same host or a subdomain of it. Never a parent
/// ([`HostRelation::Parent`]): this is the rule for agents and for every
/// fill without the person. It knows no port: a decision to fill takes
/// the page URL, through [`url_matches`].
pub fn host_matches(host: &str, item_urls: &[String]) -> bool {
    host_relation(host, item_urls).is_some_and(HostRelation::matches)
}

/// Whether the page at `url` belongs to one of the item's URLs: its host
/// matches ([`host_matches`]) and, when that item URL names a port, the
/// page is on it. Never a parent. It does not check that the page is
/// fillable: see [`page_matches`].
pub fn url_matches(url: &str, item_urls: &[String]) -> bool {
    url_relation(url, item_urls).is_some_and(HostRelation::matches)
}

/// Whether a login with `item_urls` may be filled into the page at `url`.
pub fn page_matches(url: &str, item_urls: &[String]) -> Result<bool, SiteError> {
    fillable_host(url)?;
    Ok(url_matches(url, item_urls))
}

/// Letters and digits only, lowercase: `"Git Hub, Inc."` → `"githubinc"`.
fn issuer_key(text: &str) -> String {
    text.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Whether a one-time code's issuer names a login (ADR 0024 §3.4, ADR
/// 0035 §3): its title, one of its `hosts` or one label of them, compared
/// on letters and digits. `Google` names `accounts.google.com`; `Microsoft`
/// does not name `live.com`. Only a hint for the person (the issuer is
/// text of a link or an export): it never picks a site by itself.
pub fn issuer_names_site(issuer: &str, title: &str, hosts: &[String]) -> bool {
    let wanted = issuer_key(issuer);
    if wanted.is_empty() {
        return false;
    }
    issuer_key(title) == wanted
        || hosts.iter().any(|h| {
            issuer_key(h) == wanted || h.split('.').any(|label| issuer_key(label) == wanted)
        })
}

/// The last two labels of a host name, lowercase (`my.anydesk.com` →
/// `anydesk.com`), or `None` for an IP address, a single label or
/// something that is not a host name. Without the Public Suffix List
/// (ADR 0020 §6 keeps it to the rpId of passkeys), a suffix of several
/// labels gives the suffix: `amazon.co.uk` → `co.uk`. For
/// [`issuer_names_page`] that fails toward no match, which is safe.
fn last_two_labels(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let looks_like_a_host = labels.len() >= 2
        && labels
            .iter()
            .all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    looks_like_a_host.then(|| labels[labels.len() - 2..].join("."))
}

/// Whether a one-time code's issuer or title names the page `host` (from
/// [`fillable_host`]), for the popup's «On <host>» (ADR 0035 §3 applied to
/// a page). Unlike [`issuer_names_site`], whose hosts are the person's own
/// saved URLs, the page chooses its host: only its last two labels count,
/// never another label (`paypal.attacker.example` names no «PayPal»).
/// - text that is a host name names the page when its last two labels are
///   the page's: `anydesk.com` and `my.anydesk.com` on `my.anydesk.com`,
///   `accounts.google.com` on `google.com`;
/// - any other text names it when its letters and digits are the label
///   before the last one: «AnyDesk» on `my.anydesk.com`, «Google» on
///   `accounts.google.com`.
///
/// A host name is compared with its dots, so `anydeskcom.example` doesn't
/// pass for `anydesk.com`. Only a hint for the person: it never fills.
pub fn issuer_names_page(issuer: &str, host: &str) -> bool {
    let Some(page) = last_two_labels(host) else {
        return false;
    };
    if let Some(named) = last_two_labels(issuer) {
        return named == page;
    }
    let wanted = issuer_key(issuer);
    let name = page.split('.').next().unwrap_or_default();
    !wanted.is_empty() && issuer_key(name) == wanted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_is_named_only_by_its_last_two_labels() {
        // The page chooses every label before its domain: none of them count.
        assert!(!issuer_names_page("PayPal", "paypal.attacker.example"));
        assert!(!issuer_names_page("Google", "google.evil.com"));
        assert!(!issuer_names_page(
            "paypal.com",
            "paypal.com.attacker.example"
        ));
        // The site's own name, or its domain, on any of its hosts.
        assert!(issuer_names_page("AnyDesk", "my.anydesk.com"));
        assert!(issuer_names_page("anydesk.com", "my.anydesk.com"));
        assert!(issuer_names_page("my.anydesk.com", "anydesk.com"));
        assert!(issuer_names_page("Google", "accounts.google.com"));
        assert!(issuer_names_page("accounts.google.com", "mail.google.com"));
        assert!(issuer_names_page("Git Hub", "github.com"));
        assert!(issuer_names_page("Acme", "acme.localhost"));
        assert!(issuer_names_page("GitHub", "GitHub.com."));
        // A domain is compared with its dots; a name as letters and digits.
        assert!(!issuer_names_page("anydesk.com", "anydeskcom.example"));
        assert!(!issuer_names_page("anydesk com", "anydesk.com"));
        assert!(!issuer_names_page("Amazo", "www.amazon.com"));
        assert!(!issuer_names_page("Amazon", "amazonaws.com"));
        // Without the Public Suffix List, a suffix of two labels hides the
        // name: no match, never a wrong one.
        assert!(!issuer_names_page("Amazon", "www.amazon.co.uk"));
        // Nothing to name: an IP address, a single label, no text.
        assert!(!issuer_names_page("Router", "192.168.1.1"));
        assert!(!issuer_names_page("1.1", "192.168.1.1"));
        assert!(!issuer_names_page("localhost", "localhost"));
        assert!(!issuer_names_page("", "github.com"));
        assert!(!issuer_names_page("—", "github.com"));
    }

    #[test]
    fn an_issuer_names_a_title_a_host_or_one_of_its_labels() {
        let hosts = urls(&["accounts.google.com"]);
        assert!(issuer_names_site("Google", "Mail", &hosts));
        assert!(issuer_names_site("google", "", &hosts));
        assert!(issuer_names_site("accounts.google.com", "", &hosts));
        assert!(issuer_names_site("Git Hub", "GitHub", &[]));
        assert!(!issuer_names_site(
            "Microsoft",
            "Outlook",
            &urls(&["live.com"])
        ));
        assert!(!issuer_names_site("", "", &hosts));
        assert!(!issuer_names_site("—", "—", &hosts));
        assert!(!issuer_names_site("Googl", "Mail", &hosts));
    }

    fn urls(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn only_the_item_hosts_and_their_subdomains_match() {
        let urls = urls(&["https://github.com/login", "example.org"]);
        assert!(host_matches("github.com", &urls));
        assert!(host_matches("gist.github.com", &urls));
        assert!(host_matches("GitHub.com", &urls));
        assert!(host_matches("example.org", &urls));
        assert!(!host_matches("github.com.evil.io", &urls));
        assert!(!host_matches("evilgithub.com", &urls));
        assert!(!host_matches("github.co", &urls));
        assert!(!host_matches("", &urls));
        assert!(!host_matches("github.com", &[]));
        // www. on the item covers the bare domain and its subdomains.
        let www = self::urls(&["https://www.example.com"]);
        assert!(host_matches("example.com", &www));
        assert!(host_matches("www.example.com", &www));
        assert!(host_matches("login.example.com", &www));
        // A subdomain item does not cover its siblings or its parent.
        let accounts = self::urls(&["https://accounts.example.com"]);
        assert!(!host_matches("mail.example.com", &accounts));
        assert!(!host_matches("example.com", &accounts));
    }

    #[test]
    fn a_parent_page_is_its_own_relation_never_a_match() {
        let my = urls(&["https://my.1password.com/signin"]);
        assert_eq!(
            host_relation("1password.com", &my),
            Some(HostRelation::Parent)
        );
        // The agents' rule (and every fill without the person) is strict.
        assert!(!host_matches("1password.com", &my));
        assert!(!page_matches("https://1password.com/", &my).unwrap());
        assert_eq!(
            host_relation("my.1password.com", &my),
            Some(HostRelation::Exact)
        );
        assert_eq!(
            host_relation("a.my.1password.com", &my),
            Some(HostRelation::Subdomain)
        );
        assert_eq!(
            saved_subdomain("1password.com", &my).as_deref(),
            Some("my.1password.com")
        );
        assert_eq!(saved_subdomain("my.1password.com", &my), None);
        // Several levels up is still a parent.
        let deep = urls(&["https://a.b.example.com"]);
        assert_eq!(
            host_relation("example.com", &deep),
            Some(HostRelation::Parent)
        );
        assert_eq!(
            host_relation("b.example.com", &deep),
            Some(HostRelation::Parent)
        );
        // A top-level domain is never a page.
        assert_eq!(host_relation("com", &my), None);
        assert_eq!(host_relation("io", &urls(&["ana.github.io"])), None);
        // Siblings never match, in any direction.
        let accounts = urls(&["https://accounts.example.com"]);
        assert_eq!(host_relation("mail.example.com", &accounts), None);
        assert_eq!(host_relation("x.mail.example.com", &accounts), None);
        // Look-alikes are not parents.
        assert_eq!(host_relation("password.com", &my), None);
        assert_eq!(host_relation("1password.co", &my), None);
        // Nor are IP addresses.
        assert_eq!(host_relation("0.1", &urls(&["http://127.0.0.1"])), None);
        // `localhost` has one label: never a parent; a name under it may be.
        let local = urls(&["http://x.idmsa.localhost:3000"]);
        assert_eq!(host_relation("localhost", &local), None);
        assert_eq!(
            host_relation("idmsa.localhost", &local),
            Some(HostRelation::Parent)
        );
        // The page's `www.` is a sibling of the saved subdomain, as the ADR
        // reads: `www.1password.com` is not a parent of `my.1password.com`.
        assert_eq!(host_relation("www.1password.com", &my), None);
    }

    #[test]
    fn relations_order_exact_then_subdomain_then_parent() {
        assert!(HostRelation::Exact < HostRelation::Subdomain);
        assert!(HostRelation::Subdomain < HostRelation::Parent);
        // On `my.1password.com`, the login saved for it comes before the
        // one for `1password.com`, never the other way round.
        let exact = urls(&["https://my.1password.com"]);
        let domain = urls(&["https://1password.com"]);
        let mut offered = [
            ("domain", host_relation("my.1password.com", &domain)),
            ("exact", host_relation("my.1password.com", &exact)),
        ];
        offered.sort_by_key(|(_, r)| *r);
        assert_eq!(offered.map(|(n, _)| n), ["exact", "domain"]);
        // On `1password.com` the order flips: the domain is exact there,
        // the subdomain's login is only a parent.
        let mut offered = [
            ("sub", host_relation("1password.com", &exact)),
            ("domain", host_relation("1password.com", &domain)),
        ];
        offered.sort_by_key(|(_, r)| *r);
        assert_eq!(offered.map(|(n, _)| n), ["domain", "sub"]);
        // The best relation over all of an item's URLs counts.
        let both = urls(&["https://my.1password.com", "https://1password.com"]);
        assert_eq!(
            host_relation("1password.com", &both),
            Some(HostRelation::Exact)
        );
        assert_eq!(
            host_relation("my.1password.com", &both),
            Some(HostRelation::Exact)
        );
    }

    #[test]
    fn only_web_item_urls_name_a_site() {
        for url in [
            "ftp://github.com",
            "javascript://github.com/%0a",
            "file://github.com/x",
        ] {
            assert_eq!(item_host(url), None, "{url}");
            assert!(!host_matches("github.com", &urls(&[url])), "{url}");
        }
        // One label: only itself, never every site under it.
        let tld = urls(&["com", "https://router"]);
        assert!(!host_matches("github.com", &tld));
        assert!(host_matches("router", &tld));
        assert!(!host_matches("admin.router", &tld));
        let dot = urls(&["com."]);
        assert!(!host_matches("github.com", &dot));
        // localhost keeps its subdomains (RFC 6761).
        assert!(host_matches("app.localhost", &urls(&["http://localhost"])));
    }

    #[test]
    fn an_item_port_must_be_the_page_port() {
        let dev = urls(&["http://localhost:3000/login"]);
        assert!(url_matches("http://localhost:3000/login", &dev));
        assert!(!url_matches("http://localhost:4000/login", &dev));
        assert!(!url_matches("http://localhost/login", &dev));
        assert_eq!(page_matches("http://localhost:4000/", &dev), Ok(false));
        // A bare item URL with a port names it too.
        let bare = urls(&["127.0.0.1:8080"]);
        assert!(url_matches("http://127.0.0.1:8080/", &bare));
        assert!(!url_matches("http://127.0.0.1:9090/", &bare));
        // The scheme's default port is no port: the item covers them all.
        let site = urls(&["https://example.com:443", "github.com"]);
        assert!(url_matches("https://example.com/", &site));
        assert!(url_matches("https://example.com:8443/", &site));
        assert!(url_matches("https://gist.github.com:8443/", &site));
        // An item with a port on https wants it.
        let alt = urls(&["https://example.com:8443"]);
        assert!(url_matches("https://login.example.com:8443/", &alt));
        assert!(!url_matches("https://example.com/", &alt));
        assert!(!url_matches("not a url", &alt));
    }

    #[test]
    fn a_parent_keeps_the_port_scheme_and_one_label_rules() {
        // An item URL with a port: its parent page only on that port.
        let alt = urls(&["https://my.example.com:8443"]);
        assert_eq!(url_relation("https://example.com/", &alt), None);
        assert_eq!(
            url_relation("https://example.com:8443/", &alt),
            Some(HostRelation::Parent)
        );
        assert_eq!(url_saved_subdomain("https://example.com/", &alt), None);
        assert_eq!(
            url_saved_subdomain("https://example.com:8443/", &alt).as_deref(),
            Some("my.example.com")
        );
        // The host shown is one whose port the page is on.
        let two = urls(&["https://a.example.com:8443", "https://bbb.example.com"]);
        assert_eq!(
            url_saved_subdomain("https://example.com/", &two).as_deref(),
            Some("bbb.example.com")
        );
        // And a parent is never a match, on any port.
        assert!(!url_matches("https://example.com:8443/", &alt));
        assert_eq!(page_matches("https://example.com:8443/", &alt), Ok(false));
        // Only web addresses name a site, for a parent too.
        for url in ["ftp://my.example.com", "javascript://my.example.com/%0a"] {
            assert_eq!(
                url_relation("https://example.com/", &urls(&[url])),
                None,
                "{url}"
            );
        }
        // One label has no subdomains: `com` is no relation of `github.com`
        // (it would be a subdomain, filled without the person), and a page
        // of one label is never a parent.
        assert_eq!(host_relation("github.com", &urls(&["com"])), None);
        assert_eq!(host_relation("github.com", &urls(&["com."])), None);
        assert_eq!(
            host_relation("admin.router", &urls(&["https://router"])),
            None
        );
        assert_eq!(
            host_relation("router", &urls(&["https://admin.router"])),
            None
        );
        assert_eq!(
            host_relation("app.localhost", &urls(&["http://localhost"])),
            Some(HostRelation::Subdomain)
        );
        // A trailing dot on the page is the same page.
        let my = urls(&["https://my.example.com"]);
        assert_eq!(
            host_relation("example.com.", &my),
            Some(HostRelation::Parent)
        );
        assert_eq!(
            url_relation("https://my.example.com./", &my),
            Some(HostRelation::Exact)
        );
        assert_eq!(host_relation("com.", &my), None);
    }

    #[test]
    fn ip_addresses_match_only_themselves() {
        let local = urls(&["http://127.0.0.1:8080/login"]);
        assert!(host_matches("127.0.0.1", &local));
        assert!(!host_matches("localhost", &local));
        assert!(!host_matches("1.127.0.0.1", &local));
        let localhost = urls(&["http://localhost:3000"]);
        assert!(host_matches("localhost", &localhost));
        assert!(!host_matches("127.0.0.1", &localhost));
    }

    #[test]
    fn only_https_or_local_http_pages_are_fillable() {
        assert_eq!(fillable_host("https://GitHub.com/x").unwrap(), "github.com");
        assert_eq!(
            fillable_host("http://127.0.0.1:8080/").unwrap(),
            "127.0.0.1"
        );
        assert_eq!(
            fillable_host("http://localhost:3000/").unwrap(),
            "localhost"
        );
        assert_eq!(fillable_host("http://[::1]:3000/").unwrap(), "[::1]");
        // Names under `.localhost` are this machine too (RFC 6761).
        assert_eq!(
            fillable_host("http://idmsa.localhost:3000/").unwrap(),
            "idmsa.localhost"
        );
        assert!(matches!(
            fillable_host("http://localhost.evil.io/"),
            Err(SiteError::Insecure(_))
        ));
        assert!(matches!(
            fillable_host("http://evillocalhost/"),
            Err(SiteError::Insecure(_))
        ));
        assert!(matches!(
            fillable_host("http://github.com/"),
            Err(SiteError::Insecure(_))
        ));
        assert!(fillable_host("file:///etc/passwd").is_err());
        assert!(fillable_host("about:blank").is_err());
        assert!(fillable_host("data:text/html,x").is_err());
        assert!(fillable_host("chrome-extension://abc/x").is_err());
        assert!(fillable_host("not a url").is_err());
        // The user info of a URL is not its host.
        assert_eq!(
            fillable_host("https://github.com@evil.io/").unwrap(),
            "evil.io"
        );
    }

    #[test]
    fn reports_and_errors_name_only_the_origin() {
        assert_eq!(
            origin("https://user:pw@GitHub.com/login?token=s3cret#code=1"),
            "https://github.com"
        );
        assert_eq!(
            origin("http://127.0.0.1:8080/cb?code=s3cret"),
            "http://127.0.0.1:8080"
        );
        assert_eq!(origin("about:blank"), "about:");
        assert_eq!(origin("not a url"), "a page that is not a web address");
        for url in [
            "http://github.com/reset?token=s3cret",
            "data:text/html,s3cret",
            "file:///tmp/s3cret",
            "s3cret",
        ] {
            let message = fillable_host(url).unwrap_err().to_string();
            assert!(!message.contains("s3cret"), "{message}");
        }
    }

    #[test]
    fn pages_match_items() {
        let urls = urls(&["https://github.com"]);
        assert!(page_matches("https://github.com/login", &urls).unwrap());
        assert!(!page_matches("https://github.com.evil.io/login", &urls).unwrap());
        assert!(page_matches("http://github.com/login", &urls).is_err());
        // Internationalised look-alikes are compared in their punycode form.
        assert!(!page_matches("https://gіthub.com/", &urls).unwrap());
        // A sign-in frame on another subdomain of a local test site.
        let local = vec!["http://localhost:3000/".to_owned()];
        assert!(page_matches("http://idmsa.localhost:3000/", &local).unwrap());
    }
}
