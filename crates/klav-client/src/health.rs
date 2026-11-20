//! Vault health (ADR 0022 §4): reused, weak and old passwords, and,
//! only if the person turns it on, passwords seen in breaches.
//!
//! It runs on the person's client, because the server sees nothing. It
//! looks at the non-empty `password` fields of every live item (the
//! generator history and other system items are not items here). Card PINs
//! and other `concealed` fields are left out: they are short by design.
//!
//! * **Reused:** the same value in two or more items. Values are compared
//!   in memory by `SHA-256(salt ‖ value)`, with a salt drawn for this run
//!   ([`klav_core::health::ReuseHasher`]); nothing of it is stored.
//! * **Weak:** a `zxcvbn` score of 2 or less, or, for a value that came out
//!   of the generator (it is in the generator history or the local
//!   outbox), fewer than 40 bits of known entropy
//!   ([`klav_core::generator::known_entropy_bits`]).
//! * **Old:** unchanged for more than a year, according to the item's
//!   password record (`0x16`), or else to when the item was created.
//! * **Breached** (off by default): Have I Been Pwned's range API with
//!   k-anonymity. Only the first 5 hexadecimal characters of each SHA-1
//!   are sent, with `Add-Padding: true`; the service also sees the IP
//!   address and the time. The setting is local ([`HealthSettings`]).
//!
//! The report never carries a value, a hash or a `zxcvbn` hint (they
//! describe the value): only items, hosts and the reason.

use std::collections::{BTreeMap, HashMap, HashSet};

use klav_core::generator::known_entropy_bits;
use klav_core::health::ReuseHasher;
use klav_core::health::breach::RangeQuery;
use klav_core::ids::{ItemId, ProjectId, VaultId};
use klav_core::model::item::{FieldKind, FieldValue, ItemKind};
use klav_core::site;
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, ClientResult};
use crate::home::{Home, write_private};
use crate::session::{ItemSummary, Unlocked};

/// A password unchanged for longer than this is old (365 days).
pub const OLD_AFTER_MS: i64 = 365 * 24 * 60 * 60 * 1000;
/// A `zxcvbn` score at or below this is weak.
pub const WEAK_SCORE: u8 = 2;
/// A generated password under this many bits is weak (ADR 0022 §1.2).
pub const WEAK_GENERATED_BITS: f64 = 40.0;
/// Have I Been Pwned's password range API.
pub const BREACH_API: &str = "https://api.pwnedpasswords.com";
/// Largest answer read from the breach API for one prefix.
const MAX_RANGE_RESPONSE: usize = 4 * 1024 * 1024;
/// The local settings file, in the home directory.
pub const SETTINGS_FILE: &str = "health.json";
/// What turning the breach check on means, for every interface that offers
/// it (ADR 0022 §4: the setting says what is sent).
pub const BREACH_CHECK_NOTICE: &str = "The breach check asks Have I Been Pwned \
(api.pwnedpasswords.com) about each password. Only the first 5 characters of \
the password's SHA-1 hash are sent, never the password or the full hash, and \
the answer is padded so its size gives nothing away. Have I Been Pwned sees \
your IP address and the time of the check. The setting applies to this device only.";

/// Local health settings (`health.json`, not synced, not secret).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthSettings {
    /// Check passwords against Have I Been Pwned. Off by default.
    #[serde(default)]
    pub breach_check: bool,
}

impl HealthSettings {
    /// The settings of `home` (defaults if there are none).
    pub fn load(home: &Home) -> ClientResult<Self> {
        match std::fs::read(home.file(SETTINGS_FILE)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| ClientError::Corrupt(format!("{SETTINGS_FILE}: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(ClientError::Io(e)),
        }
    }

    /// Saves the settings in `home`.
    pub fn save(&self, home: &Home) -> ClientResult<()> {
        home.ensure()?;
        let json = serde_json::to_vec_pretty(self).expect("settings serialize");
        write_private(&home.file(SETTINGS_FILE), &json)
    }
}

/// An item with a problem, as the report shows it: never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthItem {
    /// Item ID.
    pub id: ItemId,
    /// Vault ID.
    pub vault_id: VaultId,
    /// Project ID.
    pub project_id: ProjectId,
    /// `klav://vault/project/item` (by name).
    pub reference: String,
    /// Type.
    pub kind: ItemKind,
    /// Title.
    pub title: String,
    /// Username, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Hosts of its URLs.
    pub hosts: Vec<String>,
    /// The field's name.
    pub field: String,
    /// The field's label (its name if it has none).
    pub field_label: String,
}

/// Items that share one password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReusedGroup {
    /// Two or more items, by title.
    pub items: Vec<HealthItem>,
}

/// A weak password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeakPassword {
    /// Where.
    pub item: HealthItem,
    /// `zxcvbn` score, 0 (worst) to 4.
    pub score: u8,
    /// Known entropy in bits, when the value came out of the generator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_bits: Option<u32>,
}

/// Where the age of a password comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgeSource {
    /// The item's password record: when the current value replaced the
    /// previous one.
    Record,
    /// When the item was created (no change recorded).
    Created,
}

/// An old password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OldPassword {
    /// Where.
    pub item: HealthItem,
    /// Unchanged since (Unix ms).
    pub since_ms: i64,
    /// Whole days since then.
    pub days: u64,
    /// Where `since_ms` comes from.
    pub source: AgeSource,
}

/// A password seen in breaches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreachedPassword {
    /// Where.
    pub item: HealthItem,
    /// How many times Have I Been Pwned saw it.
    pub count: u64,
}

/// The breach check's outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BreachReport {
    /// Not checked: the setting is off (the default).
    Off,
    /// Checked.
    Checked {
        /// The passwords seen in breaches.
        found: Vec<BreachedPassword>,
        /// Prefixes sent (one per distinct password prefix).
        queries: usize,
    },
    /// The check did not finish (network or service error); nothing else
    /// of the report depends on it.
    Failed {
        /// Why.
        message: String,
    },
}

/// The vault health report: items, hosts and reasons, never values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultHealth {
    /// When it was computed (Unix ms).
    pub checked_at: i64,
    /// Items looked at.
    pub items: usize,
    /// Password fields looked at.
    pub passwords: usize,
    /// Items that could not be opened (left out).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub skipped: usize,
    /// Groups of items that share a password, largest first.
    pub reused: Vec<ReusedGroup>,
    /// Weak passwords.
    pub weak: Vec<WeakPassword>,
    /// Passwords unchanged for more than a year, oldest first.
    pub old: Vec<OldPassword>,
    /// The breach check.
    pub breaches: BreachReport,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

impl VaultHealth {
    /// Whether nothing needs attention.
    pub fn is_clean(&self) -> bool {
        self.reused.is_empty()
            && self.weak.is_empty()
            && self.old.is_empty()
            && !matches!(&self.breaches, BreachReport::Checked { found, .. } if !found.is_empty())
    }
}

/// One distinct password waiting for the breach check: the SHA-1 prefix to
/// send and the suffix to look for (no value). No `Debug`.
struct PendingQuery {
    query: RangeQuery,
    items: Vec<HealthItem>,
}

/// The local part of the report, computed under the vault's lock, and the
/// breach queries still to send (the network part, which needs no lock).
/// Holds SHA-1 suffixes, not values; no `Debug`.
pub struct HealthScan {
    report: VaultHealth,
    pending: Vec<PendingQuery>,
}

impl HealthScan {
    /// The report. With `breach_api` (the base URL, [`BREACH_API`] in
    /// production), checks each distinct password prefix against Have I
    /// Been Pwned first; without it the breach check stays off.
    pub async fn finish(self, breach_api: Option<&str>) -> VaultHealth {
        let Self {
            mut report,
            pending,
        } = self;
        if let Some(base) = breach_api {
            report.breaches = match check_breaches(base, &pending).await {
                Ok(found) => found,
                Err(e) => BreachReport::Failed {
                    message: e.to_string(),
                },
            };
        }
        report
    }
}

async fn check_breaches(base: &str, pending: &[PendingQuery]) -> ClientResult<BreachReport> {
    let http = crate::api::http_client()?;
    let base = base.trim_end_matches('/');
    let mut by_prefix: BTreeMap<&str, Vec<&PendingQuery>> = BTreeMap::new();
    for p in pending {
        by_prefix.entry(p.query.prefix()).or_default().push(p);
    }
    let mut found = Vec::new();
    for (prefix, queries) in &by_prefix {
        let response = http
            .get(format!("{base}/range/{prefix}"))
            .header("Add-Padding", "true")
            .send()
            .await
            // The URL names a hash prefix: keep it out of the message.
            .map_err(|e| {
                ClientError::Network(format!(
                    "Have I Been Pwned: {}",
                    crate::api::without_url(&e)
                ))
            })?;
        if !response.status().is_success() {
            return Err(ClientError::Network(format!(
                "Have I Been Pwned answered {}",
                response.status()
            )));
        }
        // A padded range is about 40 KB: an endless body is refused
        // instead of filling memory (ADR 0030, layer 10).
        let body = crate::api::read_limited(response, MAX_RANGE_RESPONSE).await?;
        let body = String::from_utf8(body).map_err(|_| {
            ClientError::Network("Have I Been Pwned: the answer is not text".into())
        })?;
        for q in queries {
            if let Some(count) = q.query.count_in(&body) {
                found.extend(q.items.iter().map(|item| BreachedPassword {
                    item: item.clone(),
                    count,
                }));
            }
        }
    }
    found.sort_by(|a, b| b.count.cmp(&a.count).then(a.item.title.cmp(&b.item.title)));
    Ok(BreachReport::Checked {
        found,
        queries: by_prefix.len(),
    })
}

fn health_item(summary: &ItemSummary, field: &str, label: &str) -> HealthItem {
    let mut hosts: Vec<String> = Vec::new();
    for url in &summary.confirmed_urls {
        if let Some(host) = site::item_host(url)
            && !hosts.contains(&host)
        {
            hosts.push(host);
        }
    }
    HealthItem {
        id: summary.id,
        vault_id: summary.vault_id,
        project_id: summary.project_id,
        reference: summary.reference.clone(),
        kind: summary.kind,
        title: summary.title.clone(),
        username: summary.username.clone(),
        hosts,
        field: field.to_owned(),
        field_label: if label.is_empty() {
            field.to_owned()
        } else {
            label.to_owned()
        },
    }
}

/// The `zxcvbn` score of `value` (0–4), with the item's title, username
/// and hosts as known inputs. Only the score leaves this function: the
/// estimate's feedback and match sequence describe the value.
fn score(value: &str, item: &HealthItem) -> u8 {
    let mut inputs: Vec<&str> = vec![item.title.as_str()];
    if let Some(user) = &item.username {
        inputs.push(user);
    }
    inputs.extend(item.hosts.iter().map(String::as_str));
    // zxcvbn copies the value into buffers it does not wipe; they are
    // freed as soon as it returns.
    u8::from(zxcvbn::zxcvbn(value, &inputs).score())
}

impl Unlocked {
    /// Computes the local part of the vault health report at `now_ms`
    /// (reused, weak and old passwords) and prepares the breach queries.
    /// Nothing leaves the device here; see [`HealthScan::finish`].
    pub fn health_scan(&self, now_ms: i64) -> HealthScan {
        let hasher = ReuseHasher::new();
        let generated: HashSet<_> = self
            .all_generated()
            .iter()
            .map(|e| hasher.fingerprint(e.value.expose().as_bytes()))
            .collect();
        let mut report = VaultHealth {
            checked_at: now_ms,
            items: 0,
            passwords: 0,
            skipped: 0,
            reused: Vec::new(),
            weak: Vec::new(),
            old: Vec::new(),
            breaches: BreachReport::Off,
        };
        // Distinct values, in the order first seen: their items, and the
        // breach query of each.
        let mut seen = HashMap::new();
        let mut distinct: Vec<PendingQuery> = Vec::new();
        for (loc, summary, created_at) in self.live_items() {
            let item = match self.open_item(loc) {
                Ok(item) => item,
                Err(_) => {
                    report.skipped += 1;
                    continue;
                }
            };
            report.items += 1;
            let mut record = None;
            for field in item.fields() {
                if field.kind() != FieldKind::Password || field.is_empty() {
                    continue;
                }
                let FieldValue::Secret(value) = field.value() else {
                    continue;
                };
                let value = value.expose();
                report.passwords += 1;
                let entry = health_item(&summary, field.name(), field.label());

                let fingerprint = hasher.fingerprint(value.as_bytes());
                let generated_bits = generated
                    .contains(&fingerprint)
                    .then(|| known_entropy_bits(value));
                let score = score(value, &entry);
                if score <= WEAK_SCORE || generated_bits.is_some_and(|b| b < WEAK_GENERATED_BITS) {
                    report.weak.push(WeakPassword {
                        item: entry.clone(),
                        score,
                        // Truncation is intended: whole bits are enough.
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        generated_bits: generated_bits.map(|b| b.max(0.0) as u32),
                    });
                }

                let record = record.get_or_insert_with(|| self.record_of(loc, &item).ok());
                let changed = record
                    .as_ref()
                    .and_then(|r| r.field_history(field.name()).iter().map(|p| p.to_ms).max());
                let (since_ms, source) = match changed {
                    Some(to_ms) => (to_ms, AgeSource::Record),
                    None => (created_at, AgeSource::Created),
                };
                if now_ms - since_ms > OLD_AFTER_MS {
                    report.old.push(OldPassword {
                        item: entry.clone(),
                        since_ms,
                        days: u64::try_from((now_ms - since_ms) / 86_400_000).unwrap_or(0),
                        source,
                    });
                }

                match seen.get(&fingerprint) {
                    Some(&index) => {
                        let pending: &mut PendingQuery = &mut distinct[index];
                        pending.items.push(entry);
                    }
                    None => {
                        seen.insert(fingerprint, distinct.len());
                        distinct.push(PendingQuery {
                            query: RangeQuery::new(value.as_bytes()),
                            items: vec![entry],
                        });
                    }
                }
            }
        }
        for pending in &distinct {
            let mut items: Vec<HealthItem> = Vec::new();
            for item in &pending.items {
                if !items.iter().any(|i| i.id == item.id) {
                    items.push(item.clone());
                }
            }
            if items.len() >= 2 {
                report.reused.push(ReusedGroup { items });
            }
        }
        report.reused.sort_by(|a, b| {
            b.items
                .len()
                .cmp(&a.items.len())
                .then_with(|| a.items[0].title.cmp(&b.items[0].title))
        });
        report.old.sort_by_key(|o| o.since_ms);
        HealthScan {
            report,
            pending: distinct,
        }
    }

    /// The whole report: [`Self::health_scan`] and then, with
    /// `breach_api`, the breach check. For a caller that holds no lock.
    pub async fn vault_health(&self, now_ms: i64, breach_api: Option<&str>) -> VaultHealth {
        self.health_scan(now_ms).finish(breach_api).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_out_forgets_the_breach_check_setting() {
        assert!(crate::auth::ACCOUNT_FILES.contains(&SETTINGS_FILE));
    }

    #[test]
    fn settings_default_to_off_and_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path());
        assert!(!HealthSettings::load(&home).unwrap().breach_check);
        HealthSettings { breach_check: true }.save(&home).unwrap();
        assert!(HealthSettings::load(&home).unwrap().breach_check);
        std::fs::write(home.file(SETTINGS_FILE), b"{\"nope\":1}").unwrap();
        assert!(HealthSettings::load(&home).is_err());
    }

    #[test]
    fn the_notice_says_what_is_sent() {
        for words in [
            "5 characters",
            "SHA-1",
            "IP address",
            "padded",
            "this device",
        ] {
            assert!(BREACH_CHECK_NOTICE.contains(words), "{words}");
        }
    }
}
