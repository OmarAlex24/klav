//! The password record of an item (spec §7.3, ADR 0022 §3): the previous
//! values of its `password` and `concealed` fields, and a pending one, kept
//! apart from the item's versions and sealed with the vault key.
//!
//! ```json
//! {"v":1,"history":[{"field":"password","value":"…","from_ms":…,"to_ms":…}],
//!  "pending":{"field":"password","value":"…","created_at_ms":…,"task_id":"…"}}
//! ```
//!
//! Version 2 adds two optional keys for the assisted change (ADR 0022 §5):
//! `unconfirmed: true` on a history entry that was generated and never
//! confirmed (a cancelled change), and `rotation_id` on the pending value
//! (the `pending_id` the agent holds). A record that uses neither is still
//! written as version 1, byte for byte as before, so older readers keep
//! opening it.
//!
//! `from_ms` (when the value became current) is left out when nobody knows
//! it: a value older than the record whose versions the server already
//! dropped. Clients never edit the record themselves: they call
//! [`PasswordRecord::note_changes`] with the item before and after an edit,
//! and [`PasswordRecord::backfill`] the first time.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::item::{FieldKind, FieldValue, Item, ModelError, SecretValue};
use crate::crypto::context::VaultContext;
use crate::crypto::keys::VaultKey;
use crate::crypto::record::{decrypt_password_record, encrypt_password_record};

/// Schema version of a record that uses no version 2 key.
pub const RECORD_VERSION: u32 = 1;
/// Schema version of a record with an unconfirmed entry or a pending
/// `rotation_id` (ADR 0022 §5).
pub const RECORD_VERSION_ROTATION: u32 = 2;
/// Previous values kept per field; the oldest go first.
pub const MAX_HISTORY_PER_FIELD: usize = 100;

/// Whether a field of this type has its values recorded.
pub fn is_recorded(kind: FieldKind) -> bool {
    matches!(kind, FieldKind::Password | FieldKind::Concealed)
}

/// A previous value of a field. Not `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct PreviousValue {
    /// Field name.
    pub field: String,
    /// The value.
    pub value: SecretValue,
    /// When it became current (Unix ms), if known.
    pub from_ms: Option<i64>,
    /// When it stopped being current (Unix ms).
    pub to_ms: i64,
    /// Generated for an assisted change and never confirmed: the site may
    /// or may not have taken it (ADR 0022 §5, «generada, no confirmada»).
    pub unconfirmed: bool,
}

/// A new value not yet confirmed (assisted change, ADR 0022 §5). Not `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingValue {
    /// Field name.
    pub field: String,
    /// The value.
    pub value: SecretValue,
    /// When it was generated (Unix ms).
    pub created_at_ms: i64,
    /// The task that generated it.
    pub task_id: Option<String>,
    /// The assisted change it belongs to (the agent's `pending_id`).
    pub rotation_id: Option<String>,
}

/// The record. Entries are kept oldest first.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct PasswordRecord {
    history: Vec<PreviousValue>,
    pending: Option<PendingValue>,
    /// Since when the current values became current, as a backfill saw
    /// them in the versions (field, ms). Not stored: it only dates the
    /// value the same edit is about to replace.
    current_from: Vec<(String, i64)>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPrevious {
    field: String,
    value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from_ms: Option<i64>,
    to_ms: i64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    unconfirmed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPending {
    field: String,
    value: String,
    created_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rotation_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecord {
    v: u32,
    #[serde(default)]
    history: Vec<RawPrevious>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<RawPending>,
}

impl Drop for RawPrevious {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.value);
    }
}

impl Drop for RawPending {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.value);
    }
}

fn json_error(err: serde_json::Error) -> ModelError {
    ModelError::Json(format!(
        "{:?} error at line {} column {}",
        err.classify(),
        err.line(),
        err.column()
    ))
}

impl PasswordRecord {
    /// An empty record.
    pub fn new() -> Self {
        Self::default()
    }

    /// Previous values, oldest first.
    pub fn history(&self) -> &[PreviousValue] {
        &self.history
    }

    /// Previous values of one field, newest first.
    pub fn field_history(&self, field: &str) -> Vec<&PreviousValue> {
        self.history
            .iter()
            .rev()
            .filter(|p| p.field == field)
            .collect()
    }

    /// The pending value.
    pub fn pending(&self) -> Option<&PendingValue> {
        self.pending.as_ref()
    }

    /// Whether the record holds nothing.
    pub fn is_empty(&self) -> bool {
        self.history.is_empty() && self.pending.is_none()
    }

    /// Records that `field` held `value` until `to_ms`. Empty values and a
    /// repeat of the field's latest entry are skipped; past
    /// [`MAX_HISTORY_PER_FIELD`], the field's oldest entry goes. Returns
    /// whether anything changed.
    pub fn push(
        &mut self,
        field: &str,
        value: &SecretValue,
        from_ms: Option<i64>,
        to_ms: i64,
    ) -> bool {
        if value.expose().is_empty() {
            return false;
        }
        if self
            .history
            .iter()
            .rev()
            .find(|p| p.field == field)
            .is_some_and(|p| &p.value == value)
        {
            return false;
        }
        // Kept in `to_ms` order: an import can bring values older than
        // the ones already recorded.
        let at = self.history.partition_point(|p| p.to_ms <= to_ms);
        self.history.insert(
            at,
            PreviousValue {
                field: field.to_owned(),
                value: value.clone(),
                from_ms,
                to_ms,
                unconfirmed: false,
            },
        );
        self.trim(field);
        true
    }

    /// When the current value of `field` became current, if the record
    /// knows: the end of its latest previous value, or the version where a
    /// backfill first saw it.
    fn current_since(&self, field: &str) -> Option<i64> {
        self.history
            .iter()
            .rev()
            .find(|p| p.field == field)
            .map(|p| p.to_ms)
            .or_else(|| {
                self.current_from
                    .iter()
                    .find(|(f, _)| f == field)
                    .map(|(_, at)| *at)
            })
    }

    /// Moves to the history every recorded field of `before` whose value
    /// changed, or that `after` no longer has (or left empty), at `now_ms`.
    /// Returns whether anything changed.
    pub fn note_changes(&mut self, before: &Item, after: &Item, now_ms: i64) -> bool {
        let mut changed = false;
        for old in before.fields().iter().filter(|f| is_recorded(f.kind())) {
            let FieldValue::Secret(value) = old.value() else {
                continue;
            };
            let same = after
                .field_by_id(old.id())
                .or_else(|| after.field(old.name()))
                .is_some_and(|f| matches!(f.value(), FieldValue::Secret(v) if v == value));
            if !same {
                let since = self.current_since(old.name());
                changed |= self.push(old.name(), value, since, now_ms);
            }
        }
        changed
    }

    /// Fills the record from an item's stored versions (G6): `versions` are
    /// `(created_at_ms, item)`, in any order, and `current` is the item as
    /// it is now. Each value a field had that differs from the next one is
    /// recorded, with the dates of the versions where it started and
    /// ended. Returns whether anything was added.
    pub fn backfill(&mut self, versions: &mut [(i64, Item)], current: &Item) -> bool {
        versions.sort_by_key(|(at, _)| *at);
        let mut changed = false;
        // field name → (value, first seen)
        let mut open: Vec<(String, SecretValue, i64)> = Vec::new();
        let names = |item: &Item| -> Vec<(String, SecretValue)> {
            item.fields()
                .iter()
                .filter(|f| is_recorded(f.kind()))
                .filter_map(|f| match f.value() {
                    FieldValue::Secret(v) if !v.expose().is_empty() => {
                        Some((f.name().to_owned(), v.clone()))
                    }
                    _ => None,
                })
                .collect()
        };
        let steps: Vec<(i64, Vec<(String, SecretValue)>)> = versions
            .iter()
            .map(|(at, item)| (*at, names(item)))
            .collect();
        for (at, values) in &steps {
            // Values that ended at this version.
            let mut still = Vec::new();
            for (field, value, since) in open.drain(..) {
                if values.iter().any(|(f, v)| *f == field && *v == value) {
                    still.push((field, value, since));
                } else {
                    changed |= self.push_once(&field, &value, since, *at);
                }
            }
            open = still;
            for (field, value) in values {
                if !open.iter().any(|(f, _, _)| f == field) {
                    open.push((field.clone(), value.clone(), *at));
                }
            }
        }
        // What the oldest stored versions held and the current item no
        // longer does ended with the current version; its date is not
        // known here, so the newest stored version's date stands in.
        let last = steps.last().map_or(0, |(at, _)| *at);
        let now = names(current);
        for (field, value, since) in open {
            if now.iter().any(|(f, v)| *f == field && *v == value) {
                self.current_from.retain(|(f, _)| *f != field);
                self.current_from.push((field, since));
            } else {
                changed |= self.push_once(&field, &value, since, last);
            }
        }
        // Keep oldest first across fields.
        self.history.sort_by_key(|p| p.to_ms);
        changed
    }

    /// [`Self::push`], unless the record already has that value with that
    /// end date (a backfill that runs twice adds nothing).
    fn push_once(&mut self, field: &str, value: &SecretValue, from_ms: i64, to_ms: i64) -> bool {
        if self
            .history
            .iter()
            .any(|p| p.field == field && p.to_ms == to_ms && &p.value == value)
        {
            return false;
        }
        self.push(field, value, Some(from_ms), to_ms)
    }

    /// Removes one entry of the history.
    pub fn remove(&mut self, index: usize) -> Option<PreviousValue> {
        (index < self.history.len()).then(|| self.history.remove(index))
    }

    /// Sets the pending value.
    pub fn set_pending(&mut self, pending: Option<PendingValue>) {
        self.pending = pending;
    }

    /// Starts an assisted change (ADR 0022 §5, step 4): `pending` becomes
    /// the pending value. A pending value already there (a change nobody
    /// confirmed or cancelled) goes to the history as unconfirmed first, so
    /// no password is lost. Returns whether that happened.
    pub fn begin_pending(&mut self, pending: PendingValue, now_ms: i64) -> bool {
        let stale = self.cancel_pending(now_ms);
        self.pending = Some(pending);
        stale
    }

    /// Takes the pending value out to make it current (step 7): the caller
    /// writes it into the field, and [`Self::note_changes`] then moves the
    /// value it replaces to the history.
    pub fn take_pending(&mut self) -> Option<PendingValue> {
        self.pending.take()
    }

    /// Cancels the pending value (`rotate_cancel`, or «Keep the current
    /// one»): it goes to the history marked unconfirmed, from its creation
    /// to `now_ms`, and the current value stays. Returns whether there was
    /// one.
    pub fn cancel_pending(&mut self, now_ms: i64) -> bool {
        let Some(pending) = self.pending.take() else {
            return false;
        };
        if pending.value.expose().is_empty() {
            return true;
        }
        let at = self.history.partition_point(|p| p.to_ms <= now_ms);
        self.history.insert(
            at,
            PreviousValue {
                field: pending.field.clone(),
                value: pending.value.clone(),
                from_ms: Some(pending.created_at_ms),
                to_ms: now_ms,
                unconfirmed: true,
            },
        );
        self.trim(&pending.field);
        true
    }

    /// Drops the oldest entries of `field` past [`MAX_HISTORY_PER_FIELD`].
    fn trim(&mut self, field: &str) {
        while self.history.iter().filter(|p| p.field == field).count() > MAX_HISTORY_PER_FIELD {
            let oldest = self
                .history
                .iter()
                .position(|p| p.field == field)
                .expect("the field has entries");
            self.history.remove(oldest);
        }
    }

    /// The schema version this record is written with: 2 only if it uses a
    /// version 2 key.
    fn version(&self) -> u32 {
        let rotation = self.history.iter().any(|p| p.unconfirmed)
            || self
                .pending
                .as_ref()
                .is_some_and(|p| p.rotation_id.is_some());
        if rotation {
            RECORD_VERSION_ROTATION
        } else {
            RECORD_VERSION
        }
    }

    /// The record as JSON (secrets included).
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let raw = RawRecord {
            v: self.version(),
            history: self
                .history
                .iter()
                .map(|p| RawPrevious {
                    field: p.field.clone(),
                    value: p.value.expose().to_owned(),
                    from_ms: p.from_ms,
                    to_ms: p.to_ms,
                    unconfirmed: p.unconfirmed,
                })
                .collect(),
            pending: self.pending.as_ref().map(|p| RawPending {
                field: p.field.clone(),
                value: p.value.expose().to_owned(),
                created_at_ms: p.created_at_ms,
                task_id: p.task_id.clone(),
                rotation_id: p.rotation_id.clone(),
            }),
        };
        Zeroizing::new(serde_json::to_vec(&raw).expect("record serializes"))
    }

    /// Parses a record.
    pub fn decode(bytes: &[u8]) -> Result<Self, ModelError> {
        let raw: RawRecord = serde_json::from_slice(bytes).map_err(json_error)?;
        if raw.v != RECORD_VERSION && raw.v != RECORD_VERSION_ROTATION {
            return Err(ModelError::UnsupportedSchema(raw.v));
        }
        // Version 1 has no version 2 keys.
        if raw.v == RECORD_VERSION
            && (raw.history.iter().any(|p| p.unconfirmed)
                || raw
                    .pending
                    .as_ref()
                    .is_some_and(|p| p.rotation_id.is_some()))
        {
            return Err(ModelError::Json(
                "a version 1 password record with version 2 keys".into(),
            ));
        }
        let mut record = Self {
            history: raw
                .history
                .iter()
                .map(|p| PreviousValue {
                    field: p.field.clone(),
                    value: SecretValue::new(p.value.as_str()),
                    from_ms: p.from_ms,
                    to_ms: p.to_ms,
                    unconfirmed: p.unconfirmed,
                })
                .collect(),
            pending: raw.pending.as_ref().map(|p| PendingValue {
                field: p.field.clone(),
                value: SecretValue::new(p.value.as_str()),
                created_at_ms: p.created_at_ms,
                task_id: p.task_id.clone(),
                rotation_id: p.rotation_id.clone(),
            }),
            current_from: Vec::new(),
        };
        // A record written elsewhere over the limit is trimmed on read.
        let fields: Vec<String> = record.history.iter().map(|p| p.field.clone()).collect();
        for field in fields {
            record.trim(&field);
        }
        Ok(record)
    }

    /// Seals the record of `item` with the vault key (blob `0x16`).
    pub fn seal(&self, key: &VaultKey, ctx: &VaultContext, item: crate::ids::ItemId) -> Vec<u8> {
        encrypt_password_record(key, ctx, item, &self.encode())
    }

    /// Opens the record of `item`.
    pub fn open(
        key: &VaultKey,
        ctx: &VaultContext,
        item: crate::ids::ItemId,
        blob: &[u8],
    ) -> Result<Self, ModelError> {
        let plain = decrypt_password_record(key, ctx, item, blob)?;
        Self::decode(&plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{AccountId, ItemId, VaultId};

    // T34: what holds a previous or pending password never prints it.
    static_assertions::assert_not_impl_any!(PreviousValue: std::fmt::Debug, std::fmt::Display);
    static_assertions::assert_not_impl_any!(PendingValue: std::fmt::Debug, std::fmt::Display);
    static_assertions::assert_not_impl_any!(PasswordRecord: std::fmt::Debug, std::fmt::Display);
    use crate::model::item::{Field, ItemKind};

    fn login(password: &str) -> Item {
        let mut item = Item::from_template(ItemKind::Login, "GitHub").unwrap();
        item.field_mut("password")
            .unwrap()
            .set_value(password)
            .unwrap();
        item
    }

    fn values(record: &PasswordRecord, field: &str) -> Vec<String> {
        record
            .field_history(field)
            .iter()
            .map(|p| p.value.expose().to_owned())
            .collect()
    }

    #[test]
    fn note_changes_moves_old_values() {
        let mut record = PasswordRecord::new();
        let a = login("one");
        let mut b = a.clone();
        b.field_mut("password").unwrap().set_value("two").unwrap();
        assert!(record.note_changes(&a, &b, 1_000));
        assert_eq!(values(&record, "password"), ["one"]);
        assert_eq!(record.history()[0].from_ms, None);
        // A change that does not touch the password records nothing.
        let mut c = b.clone();
        c.set_title("GitHub (work)").unwrap();
        assert!(!record.note_changes(&b, &c, 2_000));
        // The next change knows since when the value was current.
        let mut d = c.clone();
        d.field_mut("password").unwrap().set_value("three").unwrap();
        assert!(record.note_changes(&c, &d, 3_000));
        assert_eq!(values(&record, "password"), ["two", "one"]);
        assert_eq!(record.field_history("password")[0].from_ms, Some(1_000));
        // Emptying or removing a concealed field records its value too.
        let mut e = d.clone();
        e.add_field(Field::new("pin", "PIN", FieldKind::Concealed, "1234").unwrap())
            .unwrap();
        let mut f = e.clone();
        f.remove_field("pin");
        assert!(record.note_changes(&e, &f, 4_000));
        assert_eq!(values(&record, "pin"), ["1234"]);
        // Plain fields and TOTP secrets are not recorded.
        let mut g = f.clone();
        g.field_mut("username").unwrap().set_value("ana").unwrap();
        g.field_mut("totp")
            .unwrap()
            .set_value("JBSWY3DPEHPK3PXP")
            .unwrap();
        let mut h = g.clone();
        h.field_mut("username").unwrap().set_value("bea").unwrap();
        h.field_mut("totp").unwrap().set_value("").unwrap();
        assert!(!record.note_changes(&g, &h, 5_000));
        // An empty old value is never recorded.
        let blank = login("");
        assert!(!record.note_changes(&blank, &login("x"), 6_000));
    }

    #[test]
    fn at_most_one_hundred_per_field() {
        let mut record = PasswordRecord::new();
        for i in 0..150 {
            record.push("password", &SecretValue::new(format!("p{i}")), None, i);
        }
        record.push("pin", &SecretValue::new("0000"), None, 999);
        let history = record.field_history("password");
        assert_eq!(history.len(), MAX_HISTORY_PER_FIELD);
        assert_eq!(history[0].value.expose(), "p149");
        assert_eq!(history[99].value.expose(), "p50");
        assert_eq!(values(&record, "pin"), ["0000"]);
        // A repeat of the latest value is skipped.
        assert!(!record.push("password", &SecretValue::new("p149"), None, 1_000));
    }

    #[test]
    fn backfill_takes_the_distinct_values_of_the_versions() {
        let v1 = login("first");
        let mut v2 = v1.clone();
        v2.set_title("GitHub 2").unwrap();
        let mut v3 = v2.clone();
        v3.field_mut("password")
            .unwrap()
            .set_value("second")
            .unwrap();
        let mut v4 = v3.clone();
        v4.field_mut("password")
            .unwrap()
            .set_value("third")
            .unwrap();
        let current = v4.clone();
        let mut versions = vec![(40, v4), (10, v1), (30, v3), (20, v2)];
        let mut record = PasswordRecord::new();
        assert!(record.backfill(&mut versions, &current));
        let h = record.field_history("password");
        assert_eq!(values(&record, "password"), ["second", "first"]);
        assert_eq!((h[1].from_ms, h[1].to_ms), (Some(10), 30));
        assert_eq!((h[0].from_ms, h[0].to_ms), (Some(30), 40));
        // Running it again adds nothing.
        assert!(!record.backfill(&mut versions, &current));
        // The value the next edit replaces is dated from its first version.
        let mut next = current.clone();
        next.field_mut("password")
            .unwrap()
            .set_value("fourth")
            .unwrap();
        assert!(record.note_changes(&current, &next, 50));
        let h = record.field_history("password");
        assert_eq!((h[0].from_ms, h[0].to_ms), (Some(40), 50));

        // An item with one version: its only value is dated from it.
        let only = login("only");
        let mut record = PasswordRecord::new();
        assert!(!record.backfill(&mut [(7, only.clone())], &only));
        let mut next = only.clone();
        next.field_mut("password")
            .unwrap()
            .set_value("new")
            .unwrap();
        assert!(record.note_changes(&only, &next, 9));
        assert_eq!(record.history()[0].from_ms, Some(7));
    }

    #[test]
    fn json_and_sealing() {
        let mut record = PasswordRecord::new();
        record.push("password", &SecretValue::new("old"), Some(1), 2);
        record.set_pending(Some(PendingValue {
            field: "password".into(),
            value: SecretValue::new("new"),
            created_at_ms: 3,
            task_id: None,
            rotation_id: None,
        }));
        let json = record.encode();
        assert_eq!(
            std::str::from_utf8(&json).unwrap(),
            r#"{"v":1,"history":[{"field":"password","value":"old","from_ms":1,"to_ms":2}],"pending":{"field":"password","value":"new","created_at_ms":3}}"#
        );
        assert!(PasswordRecord::decode(&json).unwrap() == record);
        assert!(PasswordRecord::decode(br#"{"v":9}"#).is_err());
        assert!(PasswordRecord::decode(br#"{"v":1,"extra":1}"#).is_err());

        let ctx = VaultContext {
            account: AccountId::generate(),
            vault: VaultId::generate(),
        };
        let key = VaultKey::generate();
        let item = ItemId::generate();
        let blob = record.seal(&key, &ctx, item);
        assert!(PasswordRecord::open(&key, &ctx, item, &blob).unwrap() == record);
        assert!(PasswordRecord::open(&key, &ctx, ItemId::generate(), &blob).is_err());
    }

    #[test]
    fn older_values_go_in_date_order() {
        let mut r = PasswordRecord::new();
        r.push("password", &SecretValue::new("newer"), None, 2000);
        r.push("password", &SecretValue::new("older"), None, 1000);
        let newest_first: Vec<&str> = r
            .field_history("password")
            .iter()
            .map(|p| p.value.expose())
            .collect();
        assert_eq!(newest_first, ["newer", "older"]);
    }

    fn pending(value: &str, at: i64, rotation: Option<&str>) -> PendingValue {
        PendingValue {
            field: "password".into(),
            value: SecretValue::new(value),
            created_at_ms: at,
            task_id: Some("task".into()),
            rotation_id: rotation.map(str::to_owned),
        }
    }

    #[test]
    fn an_assisted_change_never_loses_a_password() {
        // Confirm: the pending becomes current and the old one goes to the
        // history with its end date.
        let before = login("old");
        let mut record = PasswordRecord::new();
        assert!(!record.begin_pending(pending("new", 10, Some("r1")), 10));
        assert_eq!(record.pending().unwrap().rotation_id.as_deref(), Some("r1"));
        let taken = record.take_pending().unwrap();
        let mut after = before.clone();
        after
            .field_mut(&taken.field)
            .unwrap()
            .set_value(taken.value.expose())
            .unwrap();
        assert!(record.note_changes(&before, &after, 20));
        assert!(record.pending().is_none());
        let h = record.field_history("password");
        assert_eq!(values(&record, "password"), ["old"]);
        assert_eq!(h[0].to_ms, 20);
        assert!(!h[0].unconfirmed);

        // Cancel: the current value stays and the pending goes to the
        // history, marked unconfirmed, from its creation to now.
        let mut record = PasswordRecord::new();
        record.begin_pending(pending("rejected", 30, Some("r2")), 30);
        assert!(record.cancel_pending(40));
        assert!(!record.cancel_pending(41));
        let h = record.field_history("password");
        assert_eq!(h[0].value.expose(), "rejected");
        assert_eq!((h[0].from_ms, h[0].to_ms), (Some(30), 40));
        assert!(h[0].unconfirmed);

        // A new change over a pending nobody resolved keeps that one too.
        let mut record = PasswordRecord::new();
        record.begin_pending(pending("first", 50, Some("r3")), 50);
        assert!(record.begin_pending(pending("second", 60, Some("r4")), 60));
        assert_eq!(record.pending().unwrap().value.expose(), "second");
        assert_eq!(values(&record, "password"), ["first"]);
        assert!(record.history()[0].unconfirmed);
    }

    #[test]
    fn version_two_only_when_needed() {
        // Without version 2 keys the bytes are those of version 1.
        let mut plain = PasswordRecord::new();
        plain.push("password", &SecretValue::new("old"), Some(1), 2);
        plain.set_pending(Some(PendingValue {
            rotation_id: None,
            ..pending("new", 3, None)
        }));
        let json = plain.encode();
        assert!(
            std::str::from_utf8(&json)
                .unwrap()
                .starts_with(r#"{"v":1,"#)
        );

        let mut record = PasswordRecord::new();
        record.push("password", &SecretValue::new("old"), Some(1), 2);
        record.begin_pending(pending("rejected", 3, Some("r1")), 3);
        record.cancel_pending(4);
        record.begin_pending(pending("new", 5, Some("r2")), 5);
        let json = record.encode();
        assert_eq!(
            std::str::from_utf8(&json).unwrap(),
            r#"{"v":2,"history":[{"field":"password","value":"old","from_ms":1,"to_ms":2},{"field":"password","value":"rejected","from_ms":3,"to_ms":4,"unconfirmed":true}],"pending":{"field":"password","value":"new","created_at_ms":5,"task_id":"task","rotation_id":"r2"}}"#
        );
        assert!(PasswordRecord::decode(&json).unwrap() == record);
        // Version 1 never carries version 2 keys; version 3 is unknown.
        assert!(
            PasswordRecord::decode(
                br#"{"v":1,"history":[{"field":"p","value":"x","to_ms":1,"unconfirmed":true}]}"#
            )
            .is_err()
        );
        assert!(
            PasswordRecord::decode(
                br#"{"v":1,"pending":{"field":"p","value":"x","created_at_ms":1,"rotation_id":"r"}}"#
            )
            .is_err()
        );
        assert!(PasswordRecord::decode(br#"{"v":3}"#).is_err());
        // Version 2 without its keys reads too.
        assert!(PasswordRecord::decode(br#"{"v":2,"history":[]}"#).is_ok());
    }
}
