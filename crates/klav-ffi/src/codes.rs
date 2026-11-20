//! «Set up codes in Klav» (ADR 0035): the app opens `otpauth://` links
//! as iOS's verification code app, and the person saves the code into a
//! login they choose. The link is read here, by `klav-core`, as soon as it
//! arrives: Swift only ever holds a [`CodeLink`], never the secret.
//!
//! Nothing is replaced without the person's «Replace»: [`decide`] tells a
//! login without a code, one with this very code and one with another
//! apart, and [`KlavCore::save_code`] writes only what it allows, in the
//! same call that read the login.

use std::sync::Arc;

use klav_client::ops::{FieldInput, ItemPatch, NewItem, SecretText};
use klav_core::model::Item;
use klav_core::model::item::{FieldKind, FieldValue, ItemKind};
use klav_core::site;
use klav_core::totp::Totp;
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::{ItemInfo, KlavCore, KlavError, KlavResult, item_id, location};

/// Longest issuer or account shown: they are text of the link (T144).
const MAX_LINK_TEXT: usize = 96;

/// The field of a login that holds its one-time code (klav-core's template).
const CODE_FIELD: &str = "totp";

/// A one-time code link (`otpauth://totp/…`) the app was opened with, read
/// by `klav-core`. Holds the secret: not `Debug`, never handed out; it is
/// zeroed when the app lets go of it (T145).
#[derive(uniffi::Object)]
pub struct CodeLink {
    totp: Totp,
}

/// What a [`CodeLink`] says about itself, without the secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CodeLinkInfo {
    /// Who issued it, as the link says (cleaned and short).
    pub issuer: Option<String>,
    /// The account, as the link says (cleaned and short).
    pub account: Option<String>,
    /// Digits of a code.
    pub digits: u32,
    /// Seconds a code lasts.
    pub period: u64,
    /// `SHA1`, `SHA256` or `SHA512`.
    pub algorithm: String,
}

#[uniffi::export]
impl CodeLink {
    /// Reads `link`. Only time-based codes (`otpauth://totp/…`); the error
    /// never repeats the link. Nothing in it is fetched (`image=` and the
    /// other unknown parameters are dropped).
    #[uniffi::constructor]
    pub fn new(link: String) -> KlavResult<Arc<Self>> {
        let link = Zeroizing::new(link);
        let totp = Totp::parse_otpauth(link.trim()).map_err(|e| {
            KlavError::invalid(format!("not a one-time code link Klav can save: {e}"))
        })?;
        Ok(Arc::new(Self { totp }))
    }

    /// Issuer, account and kind of code, for the sheet.
    pub fn info(&self) -> CodeLinkInfo {
        let shown = |s: Option<&str>| {
            s.map(|s| klav_core::text::shown(s, MAX_LINK_TEXT))
                .filter(|s| !s.is_empty())
        };
        CodeLinkInfo {
            issuer: shown(self.totp.issuer()),
            account: shown(self.totp.account()),
            digits: self.totp.digits(),
            period: self.totp.period(),
            algorithm: algorithm_name(&self.totp).to_owned(),
        }
    }
}

fn algorithm_name(totp: &Totp) -> &'static str {
    use klav_core::totp::Algorithm;
    match totp.algorithm() {
        Algorithm::Sha1 => "SHA1",
        Algorithm::Sha256 => "SHA256",
        Algorithm::Sha512 => "SHA512",
    }
}

/// The code a login has, next to the link's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CodeState {
    /// No one-time code.
    None,
    /// Another code: saving this one replaces it, only with «Replace».
    Other,
    /// This very code (same secret): nothing to save.
    Same,
}

/// A login the code could go into.
#[derive(Debug, Clone, uniffi::Record)]
pub struct CodeTarget {
    /// The login.
    pub item: ItemInfo,
    /// The link's issuer names its title or one of its confirmed sites.
    pub issuer_match: bool,
    /// The link's account is its user name.
    pub account_match: bool,
    /// The code it has now.
    pub code: CodeState,
}

/// What [`KlavCore::save_code`] did.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum CodeSaveOutcome {
    /// Saved into the login.
    Saved {
        /// The login, as saved.
        item: ItemInfo,
    },
    /// The login already has this code: nothing written.
    AlreadyThere {
        /// The login.
        item: ItemInfo,
    },
    /// The login has another code and `replace` was not set: nothing
    /// written. Ask the person, then call again with `replace`.
    NeedsReplace {
        /// The login.
        item: ItemInfo,
    },
}

/// A new login for the code («New login» in the sheet).
#[derive(Debug, Clone, uniffi::Record)]
pub struct NewCodeLogin {
    /// Title.
    pub title: String,
    /// User name (the link's account, or what the person typed).
    #[uniffi(default = None)]
    pub username: Option<String>,
    /// The site the person typed; never taken from the link.
    #[uniffi(default = None)]
    pub site: Option<String>,
    /// Vault ID (default: Personal).
    #[uniffi(default = None)]
    pub vault_id: Option<String>,
    /// Project ID (default: General).
    #[uniffi(default = None)]
    pub project_id: Option<String>,
}

/// What saving `link` into `item` would do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decision {
    /// The code field AutoFill uses (the first one with a value) gives
    /// this very code: same secret, algorithm, digits and period.
    Already,
    /// No code yet: set this (empty or missing) field.
    Set(String),
    /// Another code in this field, the one AutoFill uses. Other code
    /// fields are never touched, even one that holds this code: AutoFill
    /// would still fill the first.
    Replace(String),
}

impl Decision {
    fn state(&self) -> CodeState {
        match self {
            Decision::Already => CodeState::Same,
            Decision::Set(_) => CodeState::None,
            Decision::Replace(_) => CodeState::Other,
        }
    }
}

/// Decides where `link` goes in `item`, without writing (ADR 0035 §3).
/// Only the code field AutoFill uses counts, the one `totp_of`, the
/// extension and «Done» read: the first code field with a value.
pub(crate) fn decide(item: &Item, link: &Totp) -> Decision {
    let first = item
        .fields()
        .iter()
        .find(|f| f.kind() == FieldKind::Totp && !f.is_empty());
    let Some(field) = first else {
        return Decision::Set(CODE_FIELD.to_owned());
    };
    let same = match field.value() {
        FieldValue::Secret(s) => Totp::from_field_value(s.expose()).is_ok_and(|t| {
            t.same_secret(link)
                && t.algorithm() == link.algorithm()
                && t.digits() == link.digits()
                && t.period() == link.period()
        }),
        _ => false,
    };
    if same {
        Decision::Already
    } else {
        // A value that no longer reads as a code still counts as one: it is
        // never overwritten without «Replace».
        Decision::Replace(field.name().to_owned())
    }
}

/// The patch that puts `link` in `field`.
fn code_patch(field: String, link: &Totp) -> ItemPatch {
    ItemPatch {
        set: vec![FieldInput {
            name: field,
            value: SecretText::new(link.to_otpauth().expose_secret()),
            kind: Some(FieldKind::Totp),
            secret: true,
        }],
        ..ItemPatch::default()
    }
}

fn not_a_login() -> KlavError {
    KlavError::invalid("a one-time code from a link goes into a login")
}

#[uniffi::export]
impl KlavCore {
    /// The live logins `link` could go into, with how each matches it and
    /// the code each has: first the ones of its issuer and account, then
    /// of its issuer, then the rest, each by title. The issuer is compared
    /// with the title and the sites the person confirmed (ADR 0030 §7).
    pub fn code_targets(&self, link: Arc<CodeLink>) -> KlavResult<Vec<CodeTarget>> {
        let issuer = link.totp.issuer().unwrap_or_default().to_owned();
        let account = link
            .totp
            .account()
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        self.with(|u| {
            let filter = klav_client::ItemFilter {
                kind: Some(ItemKind::Login),
                ..klav_client::ItemFilter::default()
            };
            let mut out = Vec::new();
            for summary in u.list_items(&filter)? {
                let loc = klav_client::ItemLocation {
                    vault: summary.vault_id,
                    project: summary.project_id,
                    item: summary.id,
                };
                let Ok(item) = u.open_item(loc) else {
                    continue;
                };
                let hosts: Vec<String> = summary
                    .confirmed_urls
                    .iter()
                    .filter_map(|url| site::item_host(url))
                    .collect();
                let user = summary
                    .username
                    .as_deref()
                    .unwrap_or_default()
                    .trim()
                    .to_lowercase();
                out.push(CodeTarget {
                    issuer_match: site::issuer_names_site(&issuer, &summary.title, &hosts),
                    account_match: !account.is_empty() && user == account,
                    code: decide(&item, &link.totp).state(),
                    item: summary.into(),
                });
            }
            out.sort_by_cached_key(|t| {
                (
                    !(t.issuer_match && t.account_match),
                    !t.issuer_match,
                    t.item.title.to_lowercase(),
                    t.item.id.clone(),
                )
            });
            Ok(out)
        })
    }

    /// Saves `link` into the login `id`. Reads the login and writes in the
    /// same call: the same code writes nothing, and another code is only
    /// replaced with `replace` (the person pressed «Replace»). A login
    /// changed meanwhile on another device fails with `Conflict`, and the
    /// sheet asks again.
    pub fn save_code(
        &self,
        link: Arc<CodeLink>,
        id: String,
        replace: bool,
    ) -> KlavResult<CodeSaveOutcome> {
        self.writing(|u| {
            let loc = location(u, &id)?;
            let summary = u.item_summary(loc)?;
            if summary.kind != ItemKind::Login || summary.trashed {
                return Err(not_a_login());
            }
            let item = u.open_item(loc)?;
            let field = match decide(&item, &link.totp) {
                Decision::Already => {
                    return Ok(CodeSaveOutcome::AlreadyThere {
                        item: summary.into(),
                    });
                }
                Decision::Replace(_) if !replace => {
                    return Ok(CodeSaveOutcome::NeedsReplace {
                        item: summary.into(),
                    });
                }
                Decision::Set(field) | Decision::Replace(field) => field,
            };
            drop(item);
            let patch = code_patch(field, &link.totp);
            let id = item_id(&id)?.to_string();
            let saved = self.runtime.block_on(u.edit(&id, &patch))?;
            Ok(CodeSaveOutcome::Saved { item: saved.into() })
        })
    }

    /// Saves `link` in a new login: its title, the user name and the site
    /// the person gave (never one taken from the link), no password. A
    /// title another live item of the project has is refused, as in
    /// `create_item`.
    pub fn save_code_new(&self, link: Arc<CodeLink>, login: NewCodeLogin) -> KlavResult<ItemInfo> {
        self.writing(|u| {
            let mut fields = Vec::new();
            if let Some(user) = login
                .username
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                fields.push(FieldInput {
                    name: "username".into(),
                    value: SecretText::new(user),
                    kind: None,
                    secret: false,
                });
            }
            fields.push(FieldInput {
                name: CODE_FIELD.into(),
                value: SecretText::new(link.totp.to_otpauth().expose_secret()),
                kind: Some(FieldKind::Totp),
                secret: true,
            });
            let new = NewItem {
                kind: ItemKind::Login,
                title: login.title.trim().to_owned(),
                vault: login.vault_id,
                project: login.project_id,
                fields,
                urls: login
                    .site
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .into_iter()
                    .collect(),
                tags: Vec::new(),
                notes: None,
                allow_duplicate: false,
            };
            Ok(self.runtime.block_on(u.create(&new))?.into())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use klav_core::model::item::Field;

    static_assertions::assert_not_impl_any!(CodeLink: std::fmt::Debug, std::fmt::Display, Clone);

    const LINK: &str = "otpauth://totp/Example:ana@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&image=https%3A%2F%2Fexample.com%2Flogo.png";
    const OTHER: &str = "otpauth://totp/Example:ana?secret=KRSXG5CTMVRXEZLU";

    fn link(text: &str) -> Arc<CodeLink> {
        CodeLink::new(text.to_owned()).unwrap_or_else(|_| panic!("a test link"))
    }

    fn login(codes: &[(&str, &str)]) -> Item {
        let mut item = Item::from_template(ItemKind::Login, "Example").unwrap();
        for (name, value) in codes {
            match item.field_mut(name) {
                Some(f) => f.set_value(value).unwrap(),
                None => item
                    .add_field(Field::new(name, "", FieldKind::Totp, value).unwrap())
                    .unwrap(),
            }
        }
        item
    }

    #[test]
    fn a_link_tells_its_issuer_and_account_but_never_its_secret() {
        let info = link(LINK).info();
        assert_eq!(info.issuer.as_deref(), Some("Example"));
        assert_eq!(info.account.as_deref(), Some("ana@example.com"));
        assert_eq!(
            (info.digits, info.period, info.algorithm.as_str()),
            (6, 30, "SHA1")
        );
        assert!(!format!("{info:?}").contains("JBSW"));
        // Stored without the logo's address: Klav fetches nothing of it.
        let stored = link(LINK).totp.to_otpauth();
        assert!(!stored.expose_secret().contains("image"));
    }

    #[test]
    fn a_links_text_is_shown_plain_and_short() {
        let info = link(&format!(
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=Git%E2%80%AEbuH%0Aevil{}",
            "x".repeat(200)
        ))
        .info();
        let issuer = info.issuer.unwrap_or_default();
        assert!(!issuer.chars().any(klav_core::text::is_hidden));
        assert!(issuer.starts_with("Git buH evil"));
        assert_eq!(issuer.chars().count(), MAX_LINK_TEXT);
    }

    #[test]
    fn only_time_based_codes_are_read_and_errors_never_repeat_the_link() {
        for bad in [
            "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1",
            "otpauth://totp/x",
            "otpauth://totp/x?secret=JBSWY3DP!!",
            "otpauth-migration://offline?data=CgA",
            "https://example.com",
        ] {
            let err = CodeLink::new(bad.to_owned())
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default();
            assert!(err.starts_with("not a one-time code link"), "{bad}: {err}");
            assert!(
                !err.contains("JBSW") && !err.contains("example.com"),
                "{err}"
            );
        }
    }

    #[test]
    fn nothing_is_replaced_without_asking() {
        let code = link(LINK);
        assert_eq!(
            decide(&login(&[]), &code.totp),
            Decision::Set("totp".into())
        );
        assert_eq!(
            decide(&login(&[("totp", OTHER)]), &code.totp),
            Decision::Replace("totp".into())
        );
        // The same secret and kind of code, with other labels, is this code.
        assert_eq!(
            decide(&login(&[("totp", "jbsw y3dp ehpk 3pxp")]), &code.totp),
            Decision::Already
        );
        // This code only in a second field: AutoFill fills the first, so
        // the first is the one replaced; the second stays.
        assert_eq!(
            decide(
                &login(&[("totp", OTHER), ("totp-imported", LINK)]),
                &code.totp
            ),
            Decision::Replace("totp".into())
        );
        // Another code in a second field, the first empty: the one with a
        // value is what AutoFill fills.
        assert_eq!(
            decide(
                &login(&[("totp", ""), ("totp-imported", OTHER)]),
                &code.totp
            ),
            Decision::Replace("totp-imported".into())
        );
        assert_eq!(
            decide(&login(&[("totp", ""), ("totp-imported", LINK)]), &code.totp),
            Decision::Already
        );
    }

    #[test]
    fn the_same_secret_with_another_kind_of_code_is_another_code() {
        // Other digits, period or algorithm give other codes: AutoFill
        // would fill one the site doesn't take.
        let stored = |extra: &str| format!("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP{extra}");
        for (extra, other) in [
            ("", false),
            ("&digits=6&period=30&algorithm=SHA1", false),
            ("&digits=8", true),
            ("&period=60", true),
            ("&algorithm=SHA256", true),
        ] {
            let decision = decide(&login(&[("totp", &stored(extra))]), &link(LINK).totp);
            let expected = if other {
                Decision::Replace("totp".into())
            } else {
                Decision::Already
            };
            assert_eq!(decision, expected, "{extra}");
        }
        // And the other way round: the link's kind differs from the login's.
        let eight = link("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8");
        assert_eq!(
            decide(&login(&[("totp", "JBSWY3DPEHPK3PXP")]), &eight.totp),
            Decision::Replace("totp".into())
        );
    }

    #[test]
    fn the_patch_sets_the_normalised_link_as_a_secret_code() {
        let patch = code_patch("totp".into(), &link(LINK).totp);
        let [field] = patch.set.as_slice() else {
            panic!("one field")
        };
        assert!(field.secret && field.kind == Some(FieldKind::Totp));
        assert!(
            field
                .value
                .expose()
                .starts_with("otpauth://totp/Example:ana%40example%2Ecom?secret=JBSWY3DPEHPK3PXP")
        );
        assert!(patch.add_urls.is_empty() && patch.remove.is_empty() && patch.title.is_none());
    }
}
