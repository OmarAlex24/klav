//! Caps that hold while a file is read, not after, and buffers that are
//! wiped when they grow.

use std::cell::Cell;
use std::io::{self, Read};
use std::marker::PhantomData;

use serde::de::{Deserialize, Deserializer, SeqAccess, Visitor};
use zeroize::Zeroizing;

use crate::{ImportError, MAX_ENTRIES};

pub(crate) fn too_many_entries() -> ImportError {
    ImportError::Invalid(format!(
        "the file has more than {MAX_ENTRIES} entries: split it and import each part"
    ))
}

/// The error when a JSON export spends [`JSON_BUDGET`].
pub(crate) fn too_many_parts() -> ImportError {
    ImportError::Invalid(
        "the file has too many items or fields to import at once: split it and import each part"
            .into(),
    )
}

/// Bytes the lists of one JSON export may take once parsed, counted as the
/// size of each element (its text lives apart, and is bounded by the file).
/// A 64 MiB file of `{}` would otherwise become gigabytes of empty items.
pub(crate) const JSON_BUDGET: usize = 128 * 1024 * 1024;

thread_local! {
    /// What is left of the budget of the parse running on this thread;
    /// `None` outside [`with_budget`] (no cap).
    static BUDGET: Cell<Option<usize>> = const { Cell::new(None) };
    /// Whether the running parse ran out of budget.
    static SPENT: Cell<bool> = const { Cell::new(false) };
}

/// Runs a parse with `budget` bytes for its lists ([`capped`]). The second
/// value says whether the budget ran out (and so why the parse failed).
pub(crate) fn with_budget<T>(budget: usize, parse: impl FnOnce() -> T) -> (T, bool) {
    struct Reset(Option<usize>, bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            BUDGET.with(|b| b.set(self.0));
            SPENT.with(|s| s.set(self.1));
        }
    }
    let _reset = Reset(
        BUDGET.with(|b| b.replace(Some(budget))),
        SPENT.with(|s| s.replace(false)),
    );
    let out = parse();
    (out, SPENT.with(Cell::get))
}

/// Takes `bytes` from the running budget; `false` when it is spent.
fn spend(bytes: usize) -> bool {
    BUDGET.with(|b| match b.get() {
        None => true,
        Some(left) if left >= bytes => {
            b.set(Some(left - bytes));
            true
        }
        Some(_) => {
            SPENT.with(|s| s.set(true));
            false
        }
    })
}

/// `#[serde(deserialize_with = "capped")]` for a list: reads it element by
/// element and fails as soon as the running budget is spent.
pub(crate) fn capped<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Capped<T>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for Capped<T> {
        type Value = Vec<T>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a list")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            let mut out = Vec::new();
            while let Some(v) = seq.next_element()? {
                if !spend(size_of::<T>().max(1)) {
                    return Err(serde::de::Error::custom("too many elements"));
                }
                out.push(v);
            }
            Ok(out)
        }
    }
    d.deserialize_seq(Capped(PhantomData))
}

/// [`capped`] for an optional list (`null` or absent is `None`).
pub(crate) fn capped_opt<'de, D, T>(d: D) -> Result<Option<Vec<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Wrap<T>(Vec<T>);
    impl<'de, T: Deserialize<'de>> Deserialize<'de> for Wrap<T> {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            capped(d).map(Wrap)
        }
    }
    Ok(Option::<Wrap<T>>::deserialize(d)?.map(|w| w.0))
}

/// Charges one element of `size` bytes to the running budget (for maps
/// read by hand); `false` when it is spent.
pub(crate) fn spend_one(size: usize) -> bool {
    spend(size.max(1))
}

/// Appends `data`, moving to a bigger buffer by hand when it does not fit
/// so the old one is wiped (a plain `extend` would free it as it was).
pub fn append_wiping(buf: &mut Zeroizing<Vec<u8>>, data: &[u8]) {
    let needed = buf.len().saturating_add(data.len());
    if needed > buf.capacity() {
        let mut bigger = Zeroizing::new(Vec::with_capacity(
            needed.max(buf.capacity().saturating_mul(2)),
        ));
        bigger.extend_from_slice(buf);
        // The old buffer is zeroized as it drops.
        *buf = bigger;
    }
    buf.extend_from_slice(data);
}

/// Reads at most `limit` bytes of `reader` into a buffer that is wiped on
/// drop, and so are the smaller ones it outgrew. `hint` is the expected
/// size (a file's length), reserved up front so a file read whole is
/// copied once.
pub fn read_wiping(
    mut reader: impl Read,
    hint: usize,
    limit: usize,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(Vec::with_capacity(hint.min(limit)));
    let mut chunk = Zeroizing::new([0u8; 8192]);
    while buf.len() < limit {
        let want = chunk.len().min(limit - buf.len());
        let n = match reader.read(&mut chunk[..want]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        append_wiping(&mut buf, &chunk[..n]);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct List {
        #[serde(deserialize_with = "capped")]
        items: Vec<[u64; 4]>,
    }

    #[test]
    fn the_budget_stops_a_list_while_reading() {
        let json = format!("{{\"items\": [{}]}}", vec!["[1,2,3,4]"; 100].join(","));
        let (ok, spent) = with_budget(100 * 32, || serde_json::from_str::<List>(&json));
        assert_eq!((ok.unwrap().items.len(), spent), (100, false));
        let (err, spent) = with_budget(99 * 32, || serde_json::from_str::<List>(&json));
        assert!(err.is_err() && spent);
        // Outside a budget nothing is capped, and the flag is reset.
        assert_eq!(
            serde_json::from_str::<List>(&json).unwrap().items.len(),
            100
        );
        assert!(!SPENT.with(Cell::get));
    }

    #[test]
    fn growing_keeps_every_byte() {
        let mut buf = Zeroizing::new(Vec::with_capacity(1));
        for i in 0..1000u32 {
            append_wiping(&mut buf, &i.to_le_bytes());
        }
        assert_eq!(buf.len(), 4000);
        assert_eq!(&buf[3996..], &999u32.to_le_bytes());
        let data: Vec<u8> = (0..20_000u32).map(|i| i as u8).collect();
        let read = read_wiping(&data[..], 0, 30_000).unwrap();
        assert_eq!(&read[..], &data[..]);
        let capped = read_wiping(&data[..], 100_000, 10_001).unwrap();
        assert_eq!(capped.len(), 10_001);
    }

    #[test]
    fn a_hinted_read_does_not_grow() {
        let data = vec![7u8; 50_000];
        let read = read_wiping(&data[..], data.len(), data.len() + 1).unwrap();
        assert_eq!(read.len(), data.len());
        assert_eq!(read.capacity(), data.len());
    }
}
