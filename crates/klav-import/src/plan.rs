//! How imported entries merge into a project (ADR 0024 §3).
//!
//! - **Same site and user name** (or, without URLs, the same title and user
//!   name): one login. What the import adds (URLs, a one-time code, notes,
//!   fields) goes into it; nothing is duplicated.
//! - **Different password:** the newer one is current. Klav's stays only
//!   when the source dates its own and Klav knows its password is newer
//!   (from the password history: since when the current one is in use);
//!   otherwise the imported one wins. The other one goes to the password history
//!   (`0x16`), so no password is lost. The source's own history goes there
//!   too.
//! - **One-time codes** never replace each other: a login that already has a
//!   different one keeps it and gains a second code field.
//! - **Google Authenticator codes** join the login whose site (title or
//!   host) matches the issuer and whose user name is the account, when there
//!   is exactly one; otherwise they become their own one-time code item.
//! - **Other kinds** merge only with an item of the same kind and title
//!   whose values do not contradict them.
//! - **A taken title** for a new item gets the user name, or a number.
//! - **Passkeys** (Bitwarden) go into the login they came with. A login
//!   that already has another passkey keeps it (ADR 0020 §2: replacing
//!   one is confirmed by the person); the same passkey adds nothing.
//!
//! The [`Row`]s of the plan carry no secret values.

use std::collections::HashSet;

use klav_core::ids::ItemId;
use klav_core::model::Item;
use klav_core::model::item::{FieldKind, FieldValue, ItemKind, SecretValue, template};
use klav_core::totp::Totp;
use serde::{Deserialize, Serialize};

use crate::fields::{add, exact_host, host};
use crate::{Entry, ImportedPasskey};

/// A live item of the destination project, opened by the client.
pub struct Existing {
    /// Its ID.
    pub id: ItemId,
    /// The item.
    pub item: Item,
    /// Since when its password is in use (Unix ms), if Klav knows: the end
    /// of the latest previous password in its history.
    pub password_since: Option<i64>,
    /// The passwords its history already holds (so a repeated import adds
    /// nothing).
    pub previous: Vec<SecretValue>,
}

/// What happens to one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// A new item.
    New,
    /// Merged into an item (of the project or of the same import).
    Merge,
    /// Nothing new: skipped.
    Duplicate,
}

/// What a merge or creation changed, for the preview.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    /// The item had no password: the imported one was added.
    PasswordAdded,
    /// The imported password is now the current one; the previous one goes
    /// to the password history.
    PasswordReplaced,
    /// Klav's password is newer and stays; the imported one goes to the
    /// password history.
    PasswordKept,
    /// Earlier passwords from the source go to the password history.
    HistoryAdded,
    /// A one-time code is added.
    TotpAdded,
    /// The item already has another one-time code: the imported one is
    /// added as a second code field.
    TotpSecond,
    /// URLs are added.
    UrlsAdded,
    /// Notes are added.
    NotesAdded,
    /// Fields are added or filled.
    FieldsAdded,
    /// Tags are added.
    TagsAdded,
    /// The title was taken: it gets the user name or a number.
    Renamed,
    /// A Google Authenticator code with no clear login: its own item.
    TotpItem,
    /// The imported passkey goes into the login.
    PasskeyAdded,
    /// The login already has another passkey, which stays: the imported
    /// one is not kept.
    PasskeyKept,
    /// The imported passkey is for a site the login is not saved for (by
    /// its URLs): it is not imported, and the login gets no new site
    /// (T119).
    PasskeyOtherSite,
}

/// One line of the preview. No secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    /// Where it was in the file (`row 4`).
    pub at: String,
    /// Its title in the file.
    pub title: String,
    /// Its kind.
    pub kind: ItemKind,
    /// User name (or a one-time code's account), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// The site, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// What happens.
    pub action: Action,
    /// The title of the item it ends up in.
    pub target: String,
    /// What changes.
    pub changes: Vec<Change>,
    /// The sites a merge adds to the item (with [`Change::UrlsAdded`]), by
    /// host: shown in the preview, so a file cannot add a site to a login
    /// of the vault without naming it (T119).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sites_added: Vec<String>,
}

/// Counts for the preview.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    /// Entries that become new items.
    pub new: usize,
    /// Entries merged into an item.
    pub merged: usize,
    /// Entries with nothing new.
    pub duplicates: usize,
}

/// A value for the password history (`0x16`) of an item.
#[derive(Clone)]
pub struct HistoryPush {
    /// The field (`password`).
    pub field: String,
    /// The value.
    pub value: SecretValue,
    /// Until when it was used (Unix ms).
    pub until_ms: i64,
}

/// An item to create. Not `Debug`.
pub struct PlannedCreate {
    /// The item.
    pub item: Item,
    /// What its password history starts with.
    pub history: Vec<HistoryPush>,
    /// A passkey for the client to seal and put in it.
    pub passkey: Option<ImportedPasskey>,
}

/// An item of the project to update. Not `Debug`.
pub struct PlannedUpdate {
    /// Which.
    pub id: ItemId,
    /// The item after the merge. The client moves the passwords it
    /// replaces to the history.
    pub item: Item,
    /// Other values for its password history.
    pub history: Vec<HistoryPush>,
    /// A passkey for the client to seal and put in it (it had none).
    pub passkey: Option<ImportedPasskey>,
}

/// The whole plan. Not `Debug`.
pub struct Plan {
    /// One row per entry, in order.
    pub rows: Vec<Row>,
    /// Counts.
    pub totals: Totals,
    /// Items to create.
    pub creates: Vec<PlannedCreate>,
    /// Items to update.
    pub updates: Vec<PlannedUpdate>,
}

struct Target {
    item: Item,
    /// `(id, password_since)` for an item of the project; `None` for one
    /// this import creates.
    existing: Option<(ItemId, Option<i64>)>,
    /// When the source last changed it (new items).
    modified_ms: Option<i64>,
    history: Vec<HistoryPush>,
    /// Passwords the item's history already holds.
    known: Vec<SecretValue>,
    /// A passkey the import adds (the item had none).
    passkey: Option<ImportedPasskey>,
    /// The URLs an item of the project had before this import: the only
    /// sites a passkey from the file may go into it for (T119).
    vault_urls: Vec<String>,
    changed: bool,
}

impl Target {
    /// Adds a value to the history unless it is there already; whether it
    /// was new.
    fn remember(&mut self, value: &str, until_ms: i64) -> bool {
        if self.known.iter().any(|k| k.expose() == value) {
            return false;
        }
        let before = self.history.len();
        push(&mut self.history, value, until_ms);
        self.history.len() > before
    }

    fn when(&self) -> Option<i64> {
        match self.existing {
            Some((_, since)) => since,
            None => self.modified_ms,
        }
    }
}

/// A field's value as text (`None` for attachments).
fn text(item: &Item, field: &str) -> Option<String> {
    item.field(field)
        .and_then(|f| value_text(f.value()).map(str::to_owned))
}

fn value_text(value: &FieldValue) -> Option<&str> {
    match value {
        FieldValue::Secret(s) => Some(s.expose()),
        FieldValue::Plain(s) => Some(s),
        FieldValue::File(_) => None,
    }
}

fn user(item: &Item) -> String {
    text(item, "username")
        .unwrap_or_default()
        .trim()
        .to_lowercase()
}

fn hosts(item: &Item) -> Vec<String> {
    item.urls().iter().filter_map(|u| host(u)).collect()
}

fn totp_of(value: &str) -> Option<Totp> {
    Totp::from_field_value(value).ok()
}

/// Whether a one-time code's issuer names this login's site (the rule the
/// iOS «Save code» sheet warns with too, ADR 0035 §3).
fn issuer_matches(issuer: &str, item: &Item) -> bool {
    klav_core::site::issuer_names_site(issuer, item.title(), &hosts(item))
}

/// Whether the item holds this one-time code secret in any code field.
fn has_totp(item: &Item, totp: &Totp) -> bool {
    item.fields()
        .iter()
        .filter(|f| f.kind() == FieldKind::Totp)
        .filter_map(|f| value_text(f.value()).and_then(totp_of))
        .any(|t| t.same_secret(totp))
}

/// A title that is free: `title`, `title (user)`, `title (2)`…
fn unique(title: &str, user: &str, taken: &HashSet<String>) -> String {
    if !taken.contains(&title.trim().to_lowercase()) {
        return title.to_owned();
    }
    let user = user.trim();
    if !user.is_empty() && user.chars().count() <= 64 {
        let candidate = format!("{title} ({user})");
        if !taken.contains(&candidate.to_lowercase()) {
            return candidate;
        }
    }
    (2..)
        .map(|n| format!("{title} ({n})"))
        .find(|c| !taken.contains(&c.to_lowercase()))
        .unwrap_or_else(|| title.to_owned())
}

/// Whether the template of `kind` has a field called `name`.
fn in_template(kind: ItemKind, name: &str) -> bool {
    template(kind).iter().any(|(n, _, _)| *n == name)
}

fn set_value(item: &mut Item, field: &str, value: &str) {
    if let Some(f) = item.field_mut(field) {
        let _ = f.set_value(value);
    }
}

fn push(history: &mut Vec<HistoryPush>, value: &str, until_ms: i64) {
    if value.is_empty()
        || history
            .iter()
            .any(|h| h.field == "password" && h.value.expose() == value)
    {
        return;
    }
    history.push(HistoryPush {
        field: "password".into(),
        value: SecretValue::new(value),
        until_ms,
    });
}

/// Adds the source's own earlier passwords; whether any was new.
fn push_source_history(target: &mut Target, entry: &Entry, current: &str, now_ms: i64) -> bool {
    let mut added = false;
    for old in &entry.history {
        if old.value.expose() != current {
            added |= target.remember(
                old.value.expose(),
                old.until_ms.or(entry.modified_ms).unwrap_or(now_ms),
            );
        }
    }
    added
}

/// Merges `entry` into `target`; the changes it made.
fn merge(target: &mut Target, entry: &Entry, now_ms: i64) -> Vec<Change> {
    let mut changes = Vec::new();
    let e = &entry.item;
    let when = target.when();
    let is_new = target.existing.is_none();
    // Password.
    if let (Some(new), Some(old)) = (text(e, "password"), text(&target.item, "password"))
        && !new.is_empty()
        && new != old
    {
        if old.is_empty() {
            set_value(&mut target.item, "password", &new);
            changes.push(Change::PasswordAdded);
        } else {
            let imported_newer = match (entry.modified_ms, when) {
                (Some(imported), Some(klav)) => imported > klav,
                _ => true,
            };
            if imported_newer {
                set_value(&mut target.item, "password", &new);
                // For an item of the project the client moves `old` to the
                // history itself when it saves the new version.
                if is_new {
                    target.remember(&old, entry.modified_ms.unwrap_or(now_ms));
                }
                changes.push(Change::PasswordReplaced);
            } else if target.remember(&new, entry.modified_ms.unwrap_or(now_ms)) {
                changes.push(Change::PasswordKept);
            }
        }
    }
    let current = text(&target.item, "password").unwrap_or_default();
    if push_source_history(target, entry, &current, now_ms) {
        changes.push(Change::HistoryAdded);
    }
    let t = &mut target.item;
    // One-time codes.
    for field in e.fields().iter().filter(|f| f.kind() == FieldKind::Totp) {
        let Some(code) = value_text(field.value()).filter(|v| !v.is_empty()) else {
            continue;
        };
        let Some(totp) = totp_of(code) else { continue };
        if has_totp(t, &totp) {
            continue;
        }
        if t.field("totp").is_some_and(|f| f.is_empty()) {
            set_value(t, "totp", code);
            changes.push(Change::TotpAdded);
        } else if add(t, "One-time password (imported)", FieldKind::Totp, code) {
            changes.push(Change::TotpSecond);
        }
    }
    // URLs, one per site: `https://github.com/` adds nothing to an item
    // with `https://github.com/login`.
    let mut urls = false;
    for url in e.urls() {
        let site = host(url);
        let known = t
            .urls()
            .iter()
            .any(|u| u == url || (site.is_some() && host(u) == site));
        if !known && t.add_url(url).is_ok() {
            urls = true;
        }
    }
    if urls {
        changes.push(Change::UrlsAdded);
    }
    // Other fields: fill empty template fields, add the rest once.
    let mut fields = false;
    for field in e.fields().iter().filter(|f| f.kind() != FieldKind::Totp) {
        let Some(value) = value_text(field.value()).filter(|v| !v.is_empty()) else {
            continue;
        };
        if field.name() == "password" {
            continue;
        }
        if in_template(t.kind(), field.name()) {
            if t.field(field.name()).is_some_and(|f| f.is_empty()) {
                set_value(t, field.name(), value);
                fields = true;
            }
            continue;
        }
        let known = t
            .fields()
            .iter()
            .any(|f| value_text(f.value()) == Some(value));
        if !known && add(t, field.label(), field.kind(), value) {
            fields = true;
        }
    }
    if fields {
        changes.push(Change::FieldsAdded);
    }
    // Notes.
    if let Some(notes) = e
        .notes()
        .map(|n| n.expose().to_owned())
        .filter(|n| !n.trim().is_empty())
    {
        let existing = t.notes().map(|n| n.expose().to_owned()).unwrap_or_default();
        if existing.trim().is_empty() {
            t.set_notes(Some(&notes));
            changes.push(Change::NotesAdded);
        } else if !existing.contains(notes.trim()) {
            t.set_notes(Some(&format!("{existing}\n\n{notes}")));
            changes.push(Change::NotesAdded);
        }
    }
    // Tags.
    let mut tags = false;
    for tag in e.tags() {
        if !t.has_tag(tag) && t.add_tag(tag).is_ok() {
            tags = true;
        }
    }
    if tags {
        changes.push(Change::TagsAdded);
    }
    if !changes.is_empty() {
        target.changed = true;
    }
    // Passkey. Keeping Klav's changes nothing in the item.
    if let Some(imported) = &entry.passkey {
        let has = target
            .item
            .passkey()
            .map(|p| p.credential_id())
            .or_else(|| target.passkey.as_ref().map(ImportedPasskey::credential_id));
        match has {
            // A login of the vault takes a passkey only for a site it is
            // already saved for: a file cannot add a site to it through
            // the passkey (T119). A login this import creates shows its
            // site in the preview.
            None if target.item.kind() == ItemKind::Login
                && !is_new
                && !for_its_site(&target.vault_urls, imported) =>
            {
                changes.push(Change::PasskeyOtherSite);
            }
            None if target.item.kind() == ItemKind::Login => {
                if passkey_site(&mut target.item, imported) && !changes.contains(&Change::UrlsAdded)
                {
                    changes.push(Change::UrlsAdded);
                }
                target.passkey = Some(imported.clone());
                target.changed = true;
                changes.push(Change::PasskeyAdded);
            }
            Some(id) if id == imported.credential_id() => {}
            _ => changes.push(Change::PasskeyKept),
        }
    }
    changes
}

/// The sites of the URLs in `after` that are not in `before`, each once
/// ([`site_label`]; the URL itself if it has no host).
fn sites_added(before: &[String], after: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for url in after.iter().filter(|u| !before.contains(u)) {
        let site = site_label(url).unwrap_or_else(|| url.clone());
        if !out.contains(&site) {
            out.push(site);
        }
    }
    out
}

/// How the preview names the site of `url`: the host the saved login is
/// matched on (the same parse as `url_matches`, punycode for an
/// internationalized name), and next to it, for such a name, the Unicode
/// form, so a look-alike stands out: `xn--bnk-… (bаnk.com)` (T119).
fn site_label(url: &str) -> Option<String> {
    let ascii = klav_core::site::item_host(url)?;
    Some(match klav_core::site::item_host_unicode(url) {
        Some(unicode) => format!("{ascii} ({unicode})"),
        None => ascii,
    })
}

/// Whether a login with these URLs is saved for the passkey's site (the
/// rpId's origin matches one of them, as when a passkey is saved into a
/// chosen login). URLs this same import adds do not count.
fn for_its_site(urls: &[String], passkey: &ImportedPasskey) -> bool {
    klav_core::site::url_matches(&format!("https://{}", passkey.rp_id()), urls)
}

/// Adds `https://<rpId>` to `item` if no URL has the rpId as its host,
/// as saving the passkey would (`Item::set_passkey`, which parses each URL:
/// a bare host does not count), so the preview shows it. `true` if added.
fn passkey_site(item: &mut Item, passkey: &ImportedPasskey) -> bool {
    let rp_id = passkey.rp_id();
    if item
        .urls()
        .iter()
        .any(|u| u.contains("://") && exact_host(u).is_some_and(|h| h == rp_id))
    {
        return false;
    }
    item.add_url(&format!("https://{rp_id}")).is_ok()
}

/// Whether `e` can merge into `t` without contradicting it (kinds other
/// than logins and one-time codes).
fn compatible(t: &Item, e: &Item) -> bool {
    t.kind() == e.kind()
        && t.title().trim().eq_ignore_ascii_case(e.title().trim())
        && e.fields().iter().all(|f| {
            let Some(v) = value_text(f.value()).filter(|v| !v.is_empty()) else {
                return true;
            };
            match t.field(f.name()).and_then(|x| value_text(x.value())) {
                Some(existing) => existing.is_empty() || existing == v,
                None => true,
            }
        })
}

/// The target an entry merges into, if any.
fn find(targets: &[Target], e: &Item, code: Option<&Totp>) -> Option<usize> {
    if let Some(code) = code {
        // A one-time code: the login of its issuer and account, if there
        // is exactly one; else a code item with the same secret.
        let issuer = code.issuer().unwrap_or_default();
        let account = code.account().unwrap_or_default().trim().to_lowercase();
        let logins: Vec<usize> = targets
            .iter()
            .enumerate()
            .filter(|(_, t)| {
                t.item.kind() == ItemKind::Login
                    && issuer_matches(issuer, &t.item)
                    && (account.is_empty() || user(&t.item) == account)
            })
            .map(|(i, _)| i)
            .collect();
        return match logins.as_slice() {
            [one] => Some(*one),
            _ => targets
                .iter()
                .position(|t| t.item.kind() == ItemKind::Totp && has_totp(&t.item, code)),
        };
    }
    if e.kind() == ItemKind::Login {
        let (u, h) = (user(e), hosts(e));
        return targets.iter().position(|t| {
            t.item.kind() == ItemKind::Login
                && user(&t.item) == u
                && if h.is_empty() {
                    hosts(&t.item).is_empty()
                        && t.item.title().trim().eq_ignore_ascii_case(e.title().trim())
                } else {
                    hosts(&t.item).iter().any(|x| h.contains(x))
                }
        });
    }
    targets.iter().position(|t| compatible(&t.item, e))
}

/// Plans how `entries` merge into the project that holds `existing`.
pub fn plan(entries: &[Entry], existing: &[Existing], now_ms: i64) -> Plan {
    let mut targets: Vec<Target> = existing
        .iter()
        .filter(|x| !x.item.kind().is_system())
        .map(|x| Target {
            item: x.item.clone(),
            existing: Some((x.id, x.password_since)),
            modified_ms: None,
            history: Vec::new(),
            known: x.previous.clone(),
            passkey: None,
            vault_urls: x.item.urls().to_vec(),
            changed: false,
        })
        .collect();
    let mut taken: HashSet<String> = targets
        .iter()
        .map(|t| t.item.title().trim().to_lowercase())
        .collect();
    let mut rows = Vec::with_capacity(entries.len());
    let mut totals = Totals::default();
    for entry in entries {
        let e = &entry.item;
        let code = (e.kind() == ItemKind::Totp)
            .then(|| text(e, "totp").and_then(|v| totp_of(&v)))
            .flatten();
        let shown_user = match &code {
            Some(c) => c.account().unwrap_or_default().to_owned(),
            None => text(e, "username").unwrap_or_default(),
        };
        let mut row = Row {
            at: entry.at.clone(),
            title: e.title().to_owned(),
            kind: e.kind(),
            username: Some(shown_user.clone()).filter(|u| !u.is_empty()),
            host: e.urls().iter().find_map(|u| site_label(u)),
            action: Action::New,
            target: String::new(),
            changes: Vec::new(),
            sites_added: Vec::new(),
        };
        match find(&targets, e, code.as_ref()) {
            Some(i) => {
                let target = &mut targets[i];
                let before = target.item.urls().to_vec();
                row.changes = merge(target, entry, now_ms);
                row.sites_added = sites_added(&before, target.item.urls());
                row.target = target.item.title().to_owned();
                if row
                    .changes
                    .iter()
                    .all(|c| matches!(c, Change::PasskeyKept | Change::PasskeyOtherSite))
                {
                    row.action = Action::Duplicate;
                    totals.duplicates += 1;
                } else {
                    row.action = Action::Merge;
                    totals.merged += 1;
                }
            }
            None => {
                let mut item = e.clone();
                let title = unique(e.title(), &shown_user, &taken);
                if title != e.title() && item.set_title(&title).is_ok() {
                    row.changes.push(Change::Renamed);
                }
                if code.is_some() {
                    row.changes.push(Change::TotpItem);
                }
                if let Some(passkey) = &entry.passkey {
                    if passkey_site(&mut item, passkey) {
                        row.changes.push(Change::UrlsAdded);
                    }
                    row.changes.push(Change::PasskeyAdded);
                }
                taken.insert(item.title().trim().to_lowercase());
                let current = text(&item, "password").unwrap_or_default();
                row.target = item.title().to_owned();
                let mut target = Target {
                    item,
                    existing: None,
                    modified_ms: entry.modified_ms,
                    history: Vec::new(),
                    known: Vec::new(),
                    passkey: entry.passkey.clone(),
                    vault_urls: Vec::new(),
                    changed: true,
                };
                if push_source_history(&mut target, entry, &current, now_ms) {
                    row.changes.push(Change::HistoryAdded);
                }
                totals.new += 1;
                targets.push(target);
            }
        }
        rows.push(row);
    }
    let mut creates = Vec::new();
    let mut updates = Vec::new();
    for t in targets {
        match t.existing {
            None => creates.push(PlannedCreate {
                item: t.item,
                history: t.history,
                passkey: t.passkey,
            }),
            Some((id, _)) if t.changed => updates.push(PlannedUpdate {
                id,
                item: t.item,
                history: t.history,
                passkey: t.passkey,
            }),
            Some(_) => {}
        }
    }
    Plan {
        rows,
        totals,
        creates,
        updates,
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;
    use crate::OldPassword;
    use crate::fields::{new_item, set};

    fn login(title: &str, url: &str, user: &str, pw: &str) -> Item {
        let urls: Vec<&str> = (!url.is_empty()).then_some(url).into_iter().collect();
        let mut item = new_item(ItemKind::Login, title, &urls, user, "x");
        set(&mut item, "username", user);
        set(&mut item, "password", pw);
        for u in &urls {
            item.add_url(u).unwrap();
        }
        item
    }

    fn code(issuer: &str, account: &str, secret: &str) -> Item {
        let t = Totp::from_base32(secret)
            .unwrap()
            .with_label(Some(issuer), Some(account));
        let mut item = new_item(ItemKind::Totp, issuer, &[], "", "x");
        set(&mut item, "totp", t.to_otpauth().expose_secret());
        item
    }

    fn entry(item: Item) -> Entry {
        Entry::new(item, "row 2")
    }

    fn existing(item: Item, password_since: i64) -> Existing {
        Existing {
            id: item.id(),
            item,
            password_since: Some(password_since),
            previous: Vec::new(),
        }
    }

    /// `item` with a passkey sealed as the client would (ADR 0020).
    fn with_passkey(mut item: Item, credential: &str) -> Item {
        use klav_core::crypto::context::VaultContext;
        use klav_core::crypto::keys::VaultKey;
        use klav_core::ids::{AccountId, VaultId};
        use klav_core::model::passkey::Passkey;
        let imported = crate::passkey::tests::imported(credential);
        let ctx = VaultContext {
            account: AccountId::generate(),
            vault: VaultId::generate(),
        };
        let sealed = Passkey::import(
            &VaultKey::generate(),
            &ctx,
            item.id(),
            imported.credential_id(),
            &imported.account(),
            imported.key(),
        )
        .unwrap();
        item.set_passkey(sealed).unwrap();
        item
    }

    fn passkey_entry(item: Item, credential: &str) -> Entry {
        let mut e = entry(item);
        e.passkey = Some(crate::passkey::tests::imported(credential));
        e
    }

    #[test]
    fn a_passkey_goes_into_its_login_unless_it_has_another() {
        let shop = "https://shop.example.com";
        let project = vec![
            existing(login("Shop", shop, "ana", "pw"), 1000),
            existing(with_passkey(login("Shop", shop, "bob", "pw"), "Ym9i"), 1000),
            existing(with_passkey(login("Shop", shop, "eva", "pw"), "ZXZh"), 1000),
        ];
        let entries = vec![
            // Same password: only the passkey is new, and it makes a merge.
            passkey_entry(login("Shop", shop, "ana", "pw"), "YW5h"),
            // Bob's login keeps its own passkey: nothing changes.
            passkey_entry(login("Shop", shop, "bob", "pw"), "b3RoZXI"),
            // Eva's is the same passkey: a duplicate.
            passkey_entry(login("Shop", shop, "eva", "pw"), "ZXZh"),
            // A new login with its passkey, then a second entry for it.
            passkey_entry(login("Shop", shop, "leo", "pw"), "bGVv"),
            passkey_entry(login("Shop", shop, "leo", "pw"), "bGVvMg"),
        ];
        let p = plan(&entries, &project, 5000);
        let actions: Vec<(Action, Vec<Change>)> = p
            .rows
            .iter()
            .map(|r| (r.action, r.changes.clone()))
            .collect();
        assert_eq!(
            actions,
            [
                (Action::Merge, vec![Change::PasskeyAdded]),
                (Action::Duplicate, vec![Change::PasskeyKept]),
                (Action::Duplicate, vec![]),
                (Action::New, vec![Change::Renamed, Change::PasskeyAdded]),
                (Action::Duplicate, vec![Change::PasskeyKept]),
            ]
        );
        // Only Ana's login is updated, with the passkey for the client to seal.
        assert_eq!(p.updates.len(), 1);
        assert_eq!(p.updates[0].id, project[0].id);
        let added = p.updates[0].passkey.as_ref().unwrap();
        assert_eq!(added.credential_id(), b"ana");
        assert!(p.updates[0].item.passkey().is_none());
        assert_eq!(p.creates.len(), 1);
        assert_eq!(
            p.creates[0].passkey.as_ref().unwrap().credential_id(),
            b"leo"
        );
    }

    /// T119: a file cannot add a site to a login of the vault through a
    /// passkey for another site, with or without a password in the entry.
    #[test]
    fn a_passkey_for_another_site_stays_out_of_a_login() {
        let shop = "https://shop.example.com";
        let project = vec![
            existing(login("Shop", shop, "ana", "pw"), 1000),
            existing(login("Shop", shop, "bob", "pw"), 1000),
        ];
        let hostile = |user: &str, pw: &str, credential: &str| {
            let mut e = entry(login("Shop", shop, user, pw));
            e.passkey = Some(crate::passkey::tests::imported_for(
                credential,
                "evil.example.net",
            ));
            e
        };
        let entries = vec![
            // The same password: the passkey is all the entry brings.
            hostile("ana", "pw", "YW5h"),
            // No password at all.
            hostile("bob", "", "Ym9i"),
        ];
        let p = plan(&entries, &project, 5000);
        for row in &p.rows {
            assert_eq!(row.action, Action::Duplicate, "{row:?}");
            assert_eq!(row.changes, vec![Change::PasskeyOtherSite]);
        }
        assert!(p.updates.is_empty(), "no login changes");

        // A newer password: the login is saved, without the passkey and
        // without its site.
        let mut newer = hostile("ana", "pw2", "YW5h");
        newer.modified_ms = Some(9000);
        let p = plan(&[newer], &project, 9500);
        assert_eq!(p.rows[0].action, Action::Merge);
        assert_eq!(
            p.rows[0].changes,
            vec![Change::PasswordReplaced, Change::PasskeyOtherSite]
        );
        assert!(p.updates[0].passkey.is_none());
        assert_eq!(p.updates[0].item.urls(), [shop]);

        // A URL the same entry adds does not count as a site of the login:
        // the preview names it, and the passkey still stays out.
        let mut e = hostile("ana", "pw", "YW5h");
        e.item.add_url("https://evil.example.net").unwrap();
        let p = plan(&[e], &project, 5000);
        assert_eq!(
            p.rows[0].changes,
            vec![Change::UrlsAdded, Change::PasskeyOtherSite]
        );
        assert_eq!(p.rows[0].sites_added, ["evil.example.net"]);
        assert!(p.updates[0].passkey.is_none());

        // A bare host is a site of the login, but saving the passkey adds
        // its address: the preview says so.
        let bare = vec![existing(
            login("Shop", "shop.example.com", "ana", "pw"),
            1000,
        )];
        let p = plan(
            &[passkey_entry(
                login("Shop", "shop.example.com", "ana", "pw"),
                "YW5h",
            )],
            &bare,
            5000,
        );
        assert_eq!(
            p.rows[0].changes,
            vec![Change::UrlsAdded, Change::PasskeyAdded]
        );
        assert_eq!(
            p.updates[0].item.urls(),
            ["shop.example.com", "https://shop.example.com"]
        );

        // A login of a parent site takes it (the rule of a chosen login), and
        // a new login shows the passkey's site it gets.
        let parent = vec![existing(
            login("Example", "https://example.net", "ana", "pw"),
            1000,
        )];
        let mut on_parent =
            passkey_entry(login("Example", "https://example.net", "ana", "pw"), "YW5h");
        on_parent.passkey = Some(crate::passkey::tests::imported_for(
            "YW5h",
            "id.example.net",
        ));
        let fresh = hostile("leo", "pw", "bGVv");
        let p = plan(&[on_parent, fresh], &parent, 5000);
        assert_eq!(p.rows[0].action, Action::Merge);
        assert_eq!(
            p.rows[0].changes,
            vec![Change::UrlsAdded, Change::PasskeyAdded]
        );
        assert!(
            p.updates[0]
                .item
                .urls()
                .iter()
                .any(|u| u == "https://id.example.net")
        );
        assert_eq!(p.rows[1].action, Action::New);
        assert!(p.rows[1].changes.contains(&Change::UrlsAdded));
        assert!(
            p.creates[0]
                .item
                .urls()
                .iter()
                .any(|u| u == "https://evil.example.net")
        );
    }

    /// T119: each site is named as the login will be matched on, not as the
    /// file spells it.
    #[test]
    fn the_preview_names_a_site_as_the_login_matches_it() {
        let project = vec![existing(
            login("Bank", "https://bank.com", "ana", "pw"),
            1000,
        )];
        let named = |extra: &str| {
            let mut e = login("Bank", "https://bank.com", "ana", "pw");
            e.add_url(extra).unwrap();
            let p = plan(&[entry(e)], &project, 5000);
            assert_eq!(p.rows[0].action, Action::Merge, "{extra}");
            p.rows[0].sites_added.clone()
        };
        // A Cyrillic «а»: punycode, with the Unicode form next to it.
        let lookalike = named("https://b\u{0430}nk.com/");
        assert_eq!(lookalike, ["xn--bnk-6cd.com (b\u{0430}nk.com)"]);
        assert!(klav_core::site::url_matches(
            "https://xn--bnk-6cd.com/",
            &["https://b\u{0430}nk.com/".to_owned()]
        ));
        // An escaped dot: the host is decoded.
        assert_eq!(
            named("https://login.bank.com%2eevil.net/"),
            ["login.bank.com.evil.net"]
        );
        // A backslash ends the host.
        assert_eq!(named("https://evil.net\\.bank.com/"), ["evil.net"]);
        // The row's own site uses the same parse.
        let mut e = login("Shop", "https://sh\u{043e}p.example/", "ana", "pw");
        e.add_url("https://shop.example/").unwrap();
        let p = plan(&[entry(e)], &[], 5000);
        assert_eq!(
            p.rows[0].host.as_deref(),
            Some("xn--shp-ted.example (sh\u{043e}p.example)")
        );
    }

    /// T119: an entry of the same user with one more site merges into the
    /// vault's login, and the preview names the site it adds (the row's
    /// own host column shows the entry's first site, the login's).
    #[test]
    fn a_merge_names_the_sites_it_adds() {
        let project = vec![existing(
            login("Bank", "https://bank.com", "ana", "pw"),
            1000,
        )];
        let mut e = login("Bank", "https://bank.com", "ana", "pw");
        e.add_url("https://evil.example.net").unwrap();
        e.add_url("https://www.evil.example.net/login").unwrap();
        let p = plan(&[entry(e)], &project, 5000);
        let row = &p.rows[0];
        assert_eq!(row.action, Action::Merge);
        assert_eq!(row.host.as_deref(), Some("bank.com"));
        assert_eq!(row.changes, vec![Change::UrlsAdded]);
        assert_eq!(row.sites_added, ["evil.example.net"]);
        // Nothing new: nothing named.
        let p = plan(
            &[entry(login("Bank", "https://bank.com", "ana", "pw2"))],
            &project,
            5000,
        );
        assert!(p.rows[0].sites_added.is_empty());
    }

    const A: &str = "JBSWY3DPEHPK3PXP";
    const B: &str = "GEZDGNBVGY3TQOJQ";

    #[test]
    fn same_site_and_user_is_one_login() {
        let project = vec![existing(
            login("GitHub", "https://github.com/login", "ana", "pw"),
            1000,
        )];
        let entries = vec![
            entry(login("GitHub", "https://www.github.com/", "Ana", "pw")),
            entry(login("GitHub", "https://github.com", "bob", "pw2")),
        ];
        let p = plan(&entries, &project, 5000);
        assert_eq!(p.rows[0].action, Action::Duplicate);
        assert_eq!(p.rows[1].action, Action::New);
        assert_eq!(p.rows[1].target, "GitHub (bob)");
        assert_eq!(p.rows[1].changes, vec![Change::Renamed]);
        assert_eq!(
            p.totals,
            Totals {
                new: 1,
                merged: 0,
                duplicates: 1
            }
        );
        assert!(p.updates.is_empty());
        assert_eq!(p.creates.len(), 1);
        // Another site of the same login is added.
        let other = vec![entry(login(
            "GitHub",
            "https://gist.github.com",
            "ana",
            "pw",
        ))];
        assert_eq!(plan(&other, &project, 5000).rows[0].action, Action::New);
        // The same file again adds nothing.
        let again = vec![entry(login(
            "GitHub",
            "https://github.com/login",
            "ana",
            "pw",
        ))];
        let p = plan(&again, &project, 5000);
        assert_eq!(p.rows[0].action, Action::Duplicate);
        assert!(p.updates.is_empty() && p.creates.is_empty());
    }

    #[test]
    fn no_password_is_lost() {
        let project = vec![existing(
            login("Bank", "https://bank.example", "ana", "klav-pw"),
            2000,
        )];
        // Newer in the source: the imported one wins.
        let mut newer = entry(login("Bank", "https://bank.example", "ana", "new-pw"));
        newer.modified_ms = Some(3000);
        newer.history = vec![OldPassword {
            value: SecretValue::new("ancient"),
            until_ms: Some(10),
        }];
        let p = plan(&[newer], &project, 9000);
        assert_eq!(
            p.rows[0].changes,
            vec![Change::PasswordReplaced, Change::HistoryAdded]
        );
        let u = &p.updates[0];
        assert_eq!(text(&u.item, "password").unwrap(), "new-pw");
        // klav-pw goes to the history when the client saves; ancient now.
        assert_eq!(u.history.len(), 1);
        assert_eq!(u.history[0].value.expose(), "ancient");
        // Older in the source: Klav's stays, the imported one is kept.
        let mut older = entry(login("Bank", "https://bank.example", "ana", "old-pw"));
        older.modified_ms = Some(1000);
        let p = plan(&[older], &project, 9000);
        assert_eq!(p.rows[0].changes, vec![Change::PasswordKept]);
        assert_eq!(text(&p.updates[0].item, "password").unwrap(), "klav-pw");
        assert_eq!(p.updates[0].history[0].value.expose(), "old-pw");
        assert_eq!(p.updates[0].history[0].until_ms, 1000);
        // Once in the history, the same older password adds nothing.
        let mut known = existing(
            login("Bank", "https://bank.example", "ana", "klav-pw"),
            2000,
        );
        known.previous = vec![SecretValue::new("old-pw")];
        let mut older = entry(login("Bank", "https://bank.example", "ana", "old-pw"));
        older.modified_ms = Some(1000);
        assert_eq!(
            plan(&[older], &[known], 9000).rows[0].action,
            Action::Duplicate
        );
        // No date: the imported one wins.
        let p = plan(
            &[entry(login("Bank", "https://bank.example", "ana", "x"))],
            &project,
            9000,
        );
        assert_eq!(p.rows[0].changes, vec![Change::PasswordReplaced]);
    }

    #[test]
    fn repeated_entries_in_one_import_keep_both_passwords() {
        let entries = vec![
            entry(login("", "https://shop.example", "ana", "first")),
            entry(login("", "https://shop.example/account", "ana", "second")),
        ];
        let p = plan(&entries, &[], 9000);
        assert_eq!(
            p.totals,
            Totals {
                new: 1,
                merged: 1,
                duplicates: 0
            }
        );
        let c = &p.creates[0];
        assert_eq!(text(&c.item, "password").unwrap(), "second");
        assert_eq!(c.history[0].value.expose(), "first");
        assert_eq!(c.item.urls().len(), 1);
    }

    #[test]
    fn google_codes_join_their_login() {
        let project = vec![
            existing(
                login("GitHub", "https://github.com", "ana@example.com", "pw"),
                1,
            ),
            existing(login("Example", "https://example.com", "ana", "pw"), 1),
            existing(
                login("Example", "https://login.example.com", "ana2", "pw"),
                1,
            ),
        ];
        let entries = vec![
            entry(code("GitHub", "Ana@example.com", A)),
            entry(code("GitHub", "ana@example.com", A)),
            entry(code("Example", "", B)),
            entry(code("Unknown Co", "x", B)),
        ];
        let p = plan(&entries, &project, 1);
        assert_eq!(p.rows[0].action, Action::Merge);
        assert_eq!(p.rows[0].target, "GitHub");
        assert_eq!(p.rows[0].changes, vec![Change::TotpAdded]);
        assert_eq!(p.rows[1].action, Action::Duplicate);
        // Two Example logins: not a clear match.
        assert_eq!(p.rows[2].action, Action::New);
        assert!(p.rows[2].changes.contains(&Change::TotpItem));
        assert!(p.rows[2].changes.contains(&Change::Renamed));
        // Same secret as the Example code: one item.
        assert_eq!(p.rows[3].action, Action::Duplicate);
        assert_eq!(p.creates.len(), 1);
        // A different code on the login is kept; the new one is a second field.
        let mut with_code = login("GitHub", "https://github.com", "ana", "pw");
        set(&mut with_code, "totp", B);
        let p = plan(
            &[entry(code("GitHub", "ana", A))],
            &[existing(with_code, 1)],
            1,
        );
        assert_eq!(p.rows[0].changes, vec![Change::TotpSecond]);
        let codes = p.updates[0]
            .item
            .fields()
            .iter()
            .filter(|f| f.kind() == FieldKind::Totp)
            .count();
        assert_eq!(codes, 2);
    }

    #[test]
    fn other_kinds_merge_only_without_contradictions() {
        let mut card = new_item(ItemKind::Card, "Visa", &[], "", "x");
        set(&mut card, "number", "4111");
        let project = vec![existing(card.clone(), 1)];
        let mut same = card.clone();
        set(&mut same, "cvv", "123");
        let mut other = new_item(ItemKind::Card, "Visa", &[], "", "x");
        set(&mut other, "number", "5555");
        let p = plan(&[entry(same), entry(other)], &project, 1);
        assert_eq!(p.rows[0].action, Action::Merge);
        assert_eq!(p.rows[0].changes, vec![Change::FieldsAdded]);
        assert_eq!(p.rows[1].action, Action::New);
        assert_eq!(p.rows[1].target, "Visa (2)");
    }
}
