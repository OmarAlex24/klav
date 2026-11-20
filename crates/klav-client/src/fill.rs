//! Browser autofill (ADR 0017 §5): which items to offer on a page, and the
//! values to type once the person picked one.
//!
//! A login is offered and filled only where `klav_core::site` says its
//! URLs match the page; the check runs here, in the process that holds the
//! vault, and again in the extension. Logins are offered exact host first,
//! then subdomain (ADR 0025 §3). A login saved for a subdomain of the page
//! (`my.example.com` on `example.com`) is offered apart, in
//! [`Suggestions::parent`], and only filled when the person picks it
//! ([`Unlocked::autofill`] with `chosen`). Cards and identities have no
//! URL: they are offered on any fillable page and only filled when the
//! person picks them. One-time codes saved on their own (kind `totp`) are
//! listed in [`Suggestions::codes`] when they name the page, for the
//! person to copy: they never fill.

use klav_core::model::item::{FieldKind, FieldValue, ItemKind};
use klav_core::model::{Item, SecretValue};
use klav_core::site::{self, HostRelation};
use klav_core::totp::Totp;
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, ClientResult};
use crate::ops::SecretText;
use crate::session::{ItemFilter, ItemLocation, ItemSummary, Unlocked};

/// An item to offer on a page (metadata only, never secrets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suggestion {
    /// Item ID (what `autofill` takes).
    pub id: klav_core::ids::ItemId,
    /// Type.
    pub kind: ItemKind,
    /// Title.
    pub title: String,
    /// Username of a login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// A non-secret hint: a card's last four digits, an identity's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// `vault/project`.
    pub location: String,
    /// The login has a TOTP secret (its code is filled after the password).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub totp: bool,
    /// An assisted change left a new password pending (ADR 0022 §5): the
    /// menu offers it next to the current one ([`FillPart::Pending`]) until
    /// the person or the agent decides.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pending: bool,
    /// How a login's URLs relate to the page (ADR 0025 §3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation: Option<HostRelation>,
    /// The host the login was saved for, when the page is its parent
    /// (`my.example.com` on `example.com`): shown next to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
}

/// What `suggest` offers for a page.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Suggestions {
    /// The page's host, when it is fillable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Logins whose URLs match the page (exact host or a subdomain), in
    /// that order: what may be filled without the person picking it.
    pub logins: Vec<Suggestion>,
    /// Logins saved for a subdomain of the page (ADR 0025): offered in their
    /// own group, «Saved for a subdomain», and filled only when the person
    /// picks one. Never to agents.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent: Vec<Suggestion>,
    /// One-time codes saved on their own (kind `totp`, often imported
    /// from Google Authenticator) that name the page: their issuer or
    /// title names its site ([`code_names_page`]), or one of their
    /// confirmed URLs matches it. The popup shows them, with the codes of
    /// `logins`, at the top of «Codes». Metadata only; never filled.
    /// Absent from an older klavd: none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub codes: Vec<Suggestion>,
    /// Payment cards.
    pub cards: Vec<Suggestion>,
    /// Identities and addresses.
    pub identities: Vec<Suggestion>,
}

/// One value to type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FillValue {
    /// Field name in the item (`username`, `password`, `totp`, `number`…).
    pub name: String,
    /// Field type.
    pub kind: FieldKind,
    /// Text to type: TOTP codes are computed, expiry dates formatted.
    pub value: SecretText,
}

/// The values of one item for one page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutofillValues {
    /// Item ID.
    pub id: klav_core::ids::ItemId,
    /// Type.
    pub kind: ItemKind,
    /// Title.
    pub title: String,
    /// Values, in the order to type them.
    pub fields: Vec<FillValue>,
}

/// Which values `autofill` returns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FillPart {
    /// Every value of the item that a form can take.
    #[default]
    All,
    /// Only the current TOTP code (the second step of a login).
    Totp,
    /// Like `All`, with the pending password of an assisted change in
    /// place of the current one (ADR 0022 §5), so the person is not locked
    /// out if the site took the new one and nobody confirmed it.
    Pending,
}

fn plain(item: &Item, name: &str) -> Option<String> {
    item.field(name).and_then(|f| match f.value() {
        FieldValue::Plain(v) if !v.trim().is_empty() => Some(v.trim().to_owned()),
        _ => None,
    })
}

fn has_totp(item: &Item) -> bool {
    item.fields()
        .iter()
        .any(|f| f.kind() == FieldKind::Totp && !f.is_empty())
}

/// `2027-09` → `09/27`.
fn expiry(value: &str) -> String {
    let (y, m) = value.split_once('-').unwrap_or((value, ""));
    format!("{m}/{}", y.get(2..).unwrap_or(y))
}

/// Whether a one-time code saved on its own is for the page at `url`
/// (whose fillable host is `host`): its title or its issuer names the
/// page's domain (`site::issuer_names_page`: only the host's last two
/// labels, since the page chooses the rest), or one of the URLs the person
/// confirmed matches the page, by the rule of logins (a site an agent
/// added waits for the person, ADR 0030 §7). The issuer is read only when
/// the title and URLs say no, since it takes opening the item. A hint for
/// the person, who copies the code: it never fills anything.
fn code_names_page(
    url: &str,
    host: &str,
    title: &str,
    confirmed_urls: &[String],
    issuer: impl FnOnce() -> Option<String>,
) -> bool {
    site::issuer_names_page(title, host)
        || site::url_matches(url, confirmed_urls)
        || issuer().is_some_and(|issuer| site::issuer_names_page(&issuer, host))
}

/// The issuer of the first filled code field: an `otpauth://` link names
/// it, a bare secret does not. Only the label is kept.
fn code_issuer(item: &Item) -> Option<String> {
    item.fields()
        .iter()
        .filter(|f| f.kind() == FieldKind::Totp && !f.is_empty())
        .find_map(|f| {
            let value = match f.value() {
                FieldValue::Secret(s) => s.expose(),
                FieldValue::Plain(s) => s.as_str(),
                FieldValue::File(_) => return None,
            };
            Totp::from_field_value(value)
                .ok()?
                .issuer()
                .map(str::to_owned)
        })
}

impl Unlocked {
    fn suggestion(&self, summary: &ItemSummary) -> Suggestion {
        let loc = ItemLocation {
            vault: summary.vault_id,
            project: summary.project_id,
            item: summary.id,
        };
        let item = self.open_item(loc).ok();
        let hint = item.as_ref().and_then(|item| match item.kind() {
            ItemKind::Card => item.field("number").and_then(|f| match f.value() {
                FieldValue::Secret(s) => {
                    let digits: String = s.expose().chars().filter(char::is_ascii_digit).collect();
                    (digits.len() >= 4).then(|| format!("•••• {}", &digits[digits.len() - 4..]))
                }
                _ => None,
            }),
            ItemKind::Identity => {
                let name = [plain(item, "first_name"), plain(item, "last_name")]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" ");
                (!name.is_empty()).then_some(name)
            }
            _ => None,
        });
        Suggestion {
            id: summary.id,
            kind: summary.kind,
            title: summary.title.clone(),
            username: summary.username.clone(),
            hint,
            location: format!("{}/{}", summary.vault, summary.project),
            totp: item.as_ref().is_some_and(has_totp),
            pending: summary.kind == ItemKind::Login
                && item
                    .as_ref()
                    .is_some_and(|item| self.pending_of(loc, item).is_some()),
            relation: None,
            site: None,
        }
    }

    /// The items to offer on the page at `url`: logins whose confirmed URLs
    /// match it (a site an agent added waits for the person, ADR 0030 §7),
    /// the one-time codes saved on their own that name it, and every card
    /// and identity. Nothing for a page Klav never fills (`http` on another
    /// machine, `file:`…).
    pub fn suggest(&self, url: &str) -> ClientResult<Suggestions> {
        let Ok(host) = site::fillable_host(url) else {
            return Ok(Suggestions::default());
        };
        let mut out = Suggestions {
            host: Some(host.clone()),
            ..Suggestions::default()
        };
        for summary in self.list_items(&ItemFilter::default())? {
            match summary.kind {
                ItemKind::Login => {
                    // Only the sites the person confirmed: one an agent
                    // added waits for them, in every group (ADR 0030 §7).
                    // With the page's URL, so an item's port counts.
                    let Some(relation) = site::url_relation(url, &summary.confirmed_urls) else {
                        continue;
                    };
                    let mut s = self.suggestion(&summary);
                    s.relation = Some(relation);
                    if relation == HostRelation::Parent {
                        s.site = site::url_saved_subdomain(url, &summary.confirmed_urls);
                        out.parent.push(s);
                    } else {
                        out.logins.push(s);
                    }
                }
                ItemKind::Card => out.cards.push(self.suggestion(&summary)),
                ItemKind::Identity => out.identities.push(self.suggestion(&summary)),
                _ => {}
            }
        }
        // Codes on their own with a filled code field (`codes` is cached
        // per item version): those whose title, URLs or issuer name the page.
        let codes = ItemFilter {
            kind: Some(ItemKind::Totp),
            codes: true,
            ..ItemFilter::default()
        };
        for summary in self.list_items(&codes)? {
            let loc = ItemLocation {
                vault: summary.vault_id,
                project: summary.project_id,
                item: summary.id,
            };
            let issuer = || self.open_item(loc).ok().as_ref().and_then(code_issuer);
            if code_names_page(url, &host, &summary.title, &summary.confirmed_urls, issuer) {
                out.codes.push(self.suggestion(&summary));
            }
        }
        // Exact host first, then subdomain (ADR 0025 §3), then by title.
        out.logins
            .sort_by_cached_key(|s| (s.relation, s.title.to_lowercase()));
        out.parent.sort_by_cached_key(|s| s.title.to_lowercase());
        out.codes.sort_by_cached_key(|s| s.title.to_lowercase());
        out.cards.sort_by_key(|s| s.title.to_lowercase());
        out.identities.sort_by_key(|s| s.title.to_lowercase());
        Ok(out)
    }

    /// The values of the item `id` to type into the page at `url`. A login
    /// whose URLs do not match the page is refused (phishing protection);
    /// cards and identities only need a fillable page. A login saved for a
    /// subdomain of the page ([`HostRelation::Parent`]) is filled only when
    /// `chosen`: the person picked it in the menu or the popup, in its own
    /// group (ADR 0025 §2). Nothing filled without the person sets it.
    pub fn autofill(
        &self,
        id: &str,
        url: &str,
        part: FillPart,
        chosen: bool,
    ) -> ClientResult<AutofillValues> {
        let host = site::fillable_host(url).map_err(|e| ClientError::Denied(e.to_string()))?;
        let loc = self.find_item(id)?;
        let summary = self.item_summary(loc)?;
        if summary.id.to_string() != id {
            return Err(ClientError::Invalid(
                "autofill takes an item ID, not a title".into(),
            ));
        }
        match summary.kind {
            ItemKind::Login => {
                // Only the sites the person confirmed (ADR 0030 §7), on the
                // port an item URL names, and a parent only when they picked
                // it (ADR 0025 §2).
                let allowed = match site::url_relation(url, &summary.confirmed_urls) {
                    Some(HostRelation::Parent) => chosen,
                    Some(_) => true,
                    None => false,
                };
                if !allowed {
                    if site::url_matches(url, &summary.pending_urls) {
                        return Err(ClientError::Denied(format!(
                            "{host} was added to {} by an agent and you have not confirmed it: confirm it on the item first",
                            summary.title
                        )));
                    }
                    return Err(ClientError::Denied(format!(
                        "{} is not one of the addresses of {}: Klav does not fill it (phishing protection)",
                        host, summary.title
                    )));
                }
            }
            ItemKind::Card | ItemKind::Identity => {}
            other => {
                return Err(ClientError::Invalid(format!(
                    "a {other:?} item cannot be filled into a page"
                )));
            }
        }
        let item = self.open_item(loc)?;
        let pending = match part {
            FillPart::Pending => Some(self.pending_of(loc, &item).ok_or_else(|| {
                ClientError::NotFound(format!("a pending password in {}", summary.title))
            })?),
            _ => None,
        };
        let mut fields = Vec::new();
        for f in item.fields() {
            if f.is_empty() {
                continue;
            }
            let wanted = match part {
                FillPart::All | FillPart::Pending => match summary.kind {
                    ItemKind::Login => {
                        matches!(
                            f.kind(),
                            FieldKind::Username | FieldKind::Password | FieldKind::Totp
                        )
                    }
                    ItemKind::Card => ["cardholder", "number", "expiry", "cvv"].contains(&f.name()),
                    _ => !matches!(f.kind(), FieldKind::File) && !f.kind().is_secret(),
                },
                FillPart::Totp => f.kind() == FieldKind::Totp,
            };
            if !wanted {
                continue;
            }
            let value: SecretValue = match (f.kind(), f.value()) {
                (_, FieldValue::Secret(_))
                    if pending.as_ref().is_some_and(|p| p.field == f.name()) =>
                {
                    pending.as_ref().expect("checked").value.clone()
                }
                (FieldKind::Totp, _) => self.totp(loc, Some(f.name()))?.0,
                (FieldKind::MonthYear, FieldValue::Plain(v)) => SecretValue::new(expiry(v)),
                (_, FieldValue::Plain(v)) => SecretValue::new(v.clone()),
                (_, FieldValue::Secret(s)) => SecretValue::new(s.expose()),
                (_, FieldValue::File(_)) => continue,
            };
            fields.push(FillValue {
                name: f.name().to_owned(),
                kind: f.kind(),
                value: SecretText::from(&value),
            });
        }
        if part == FillPart::Totp && fields.is_empty() {
            return Err(ClientError::NotFound(format!(
                "a one-time password in {}",
                summary.title
            )));
        }
        Ok(AutofillValues {
            id: summary.id,
            kind: summary.kind,
            title: summary.title,
            fields,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_dates_are_typed_as_month_and_year() {
        assert_eq!(expiry("2027-09"), "09/27");
    }

    /// `code_names_page` for a code with this title, issuer and URLs, on `url`.
    fn names(url: &str, title: &str, issuer: Option<&str>, urls: &[&str]) -> bool {
        let host = site::fillable_host(url).expect("a fillable page");
        let urls: Vec<String> = urls.iter().map(|u| (*u).to_owned()).collect();
        code_names_page(url, &host, title, &urls, || issuer.map(str::to_owned))
    }

    #[test]
    fn a_page_cannot_steer_the_match_with_the_labels_it_chooses() {
        // A phishing page puts the brand before its own domain: no title,
        // issuer or saved URL of that brand's code names it.
        for (url, brand) in [
            ("https://paypal.attacker.example/signin", "PayPal"),
            ("https://google.evil.com/", "Google"),
            (
                "https://accounts.google.com.evil.com/",
                "accounts.google.com",
            ),
        ] {
            assert!(!names(url, brand, None, &[]), "{url} {brand}");
            assert!(!names(url, "Work", Some(brand), &[]), "{url} {brand}");
        }
        assert!(!names(
            "https://paypal.attacker.example/",
            "PayPal",
            Some("PayPal"),
            &["https://paypal.com"]
        ));
    }

    #[test]
    fn a_code_whose_title_names_the_site_is_for_the_page() {
        // A Google Authenticator import keeps the issuer as the title.
        assert!(names(
            "https://www.amazon.com/ap/signin",
            "Amazon",
            None,
            &[]
        ));
        assert!(names("https://anydesk.com/", "anydesk.com", None, &[]));
        // On any host of the site the title names.
        assert!(names("https://my.anydesk.com/", "anydesk.com", None, &[]));
        assert!(names("https://my.anydesk.com/", "AnyDesk", None, &[]));
        assert!(names("https://anydesk.com/", "my.anydesk.com", None, &[]));
        assert!(names("https://github.com/login", "Git Hub", None, &[]));
    }

    #[test]
    fn a_code_whose_issuer_names_the_site_is_for_the_page() {
        assert!(names(
            "https://github.com/sessions/two-factor",
            "Work",
            Some("GitHub"),
            &[]
        ));
        assert!(names(
            "https://accounts.google.com/",
            "ana@example.com",
            Some("Google"),
            &[]
        ));
        assert!(names(
            "https://mail.google.com/",
            "ana@example.com",
            Some("accounts.google.com"),
            &[]
        ));
        assert!(names(
            "http://acme.localhost:8123/login",
            "Second factor",
            Some("Acme"),
            &[]
        ));
    }

    #[test]
    fn a_code_with_a_url_of_the_page_is_for_it() {
        assert!(names(
            "https://vpn.example.com/",
            "Office VPN",
            None,
            &["https://vpn.example.com"]
        ));
        // A subdomain matches as for logins; a parent does not (ADR 0025).
        assert!(names(
            "https://a.vpn.example.com/",
            "Office VPN",
            None,
            &["vpn.example.com"]
        ));
        assert!(!names(
            "https://example.com/",
            "Office VPN",
            None,
            &["vpn.example.com"]
        ));
    }

    #[test]
    fn a_code_that_names_another_site_is_not_for_the_page() {
        assert!(!names(
            "https://github.com/login",
            "GitLab",
            Some("GitLab"),
            &[]
        ));
        // The rule compares whole labels, not pieces of them.
        assert!(!names("https://www.amazon.com/", "Amazo", None, &[]));
        assert!(!names("https://amazonaws.com/", "Amazon", None, &[]));
        // Microsoft does not name live.com: the issuer is only a hint.
        assert!(!names(
            "https://login.live.com/",
            "Outlook",
            Some("Microsoft"),
            &[]
        ));
        // Without the Public Suffix List, a suffix of two labels hides
        // the name: no match rather than a wrong one.
        assert!(!names("https://www.amazon.co.uk/", "Amazon", None, &[]));
        // No title and no issuer names nothing.
        assert!(!names("https://github.com/", "", None, &[]));
        assert!(!names("https://github.com/", "—", Some(""), &[]));
    }

    #[test]
    fn the_issuer_is_read_only_when_the_title_and_urls_say_no() {
        let host = "github.com".to_owned();
        let read = std::cell::Cell::new(false);
        let issuer = || {
            read.set(true);
            Some("GitHub".to_owned())
        };
        assert!(code_names_page(
            "https://github.com/",
            &host,
            "GitHub",
            &[],
            issuer
        ));
        assert!(!read.get());
        assert!(code_names_page(
            "https://github.com/",
            &host,
            "Work",
            &[],
            || {
                read.set(true);
                Some("GitHub".to_owned())
            }
        ));
        assert!(read.get());
    }

    #[test]
    fn the_issuer_comes_from_an_otpauth_link_and_never_from_a_bare_secret() {
        let code = |value: &str| {
            let mut item = Item::from_template(ItemKind::Totp, "x").expect("template");
            item.field_mut("totp")
                .expect("totp")
                .set_value(value)
                .expect("set");
            code_issuer(&item)
        };
        assert_eq!(
            code("otpauth://totp/ana%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme").as_deref(),
            Some("Acme")
        );
        assert_eq!(
            code("otpauth://totp/Globex:ana?secret=JBSWY3DPEHPK3PXP").as_deref(),
            Some("Globex")
        );
        assert_eq!(code("JBSWY3DPEHPK3PXP"), None);
        assert_eq!(
            code_issuer(&Item::from_template(ItemKind::Totp, "Empty").expect("template")),
            None
        );
    }
}
