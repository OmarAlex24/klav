//! Imports in progress (ADR 0024): the files added so far, held in the
//! unlocked session and dropped with it on `lock`. A file can arrive in
//! pieces, because a native message carries at most 1 MiB.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use klav_client::klav_import::{ImportError, ImportSet, MAX_FILE, Source, append_wiping};
use zeroize::Zeroizing;

use crate::protocol::{ErrorBody, ErrorCode, ImportAdded};

/// Imports kept at once; a new one drops the least recently used.
const MAX_IMPORTS: usize = 4;
/// An import untouched this long is forgotten.
const IDLE: Duration = Duration::from_secs(30 * 60);
/// Bytes of files received by all the imports of a session together: the
/// imports live until `lock`, so without it four imports of 256 MiB each
/// would stay in memory.
const BUDGET: usize = MAX_FILE;

struct Pending {
    set: ImportSet,
    /// A file arriving in pieces: its name and the bytes so far.
    piece: Option<(String, Zeroizing<Vec<u8>>)>,
    touched: Instant,
    /// Bytes received for this import (counted against [`BUDGET`]).
    received: usize,
}

/// The imports of one unlocked session.
#[derive(Default)]
pub(crate) struct Imports {
    pending: HashMap<String, Pending>,
    next: u64,
}

fn invalid(message: impl Into<String>) -> ErrorBody {
    ErrorBody {
        code: ErrorCode::Invalid,
        message: message.into(),
        paused: None,
        presence: None,
    }
}

fn import_error(e: &ImportError) -> ErrorBody {
    invalid(e.to_string())
}

fn unknown() -> ErrorBody {
    ErrorBody {
        code: ErrorCode::NotFound,
        message: "no such import (it ends when klavd locks): start again".into(),
        paused: None,
        presence: None,
    }
}

impl Imports {
    fn expire(&mut self) {
        self.pending.retain(|_, p| p.touched.elapsed() < IDLE);
    }

    /// Adds a file, or a piece of one. Without `session`, starts an import.
    pub(crate) fn add(
        &mut self,
        session: Option<&str>,
        name: &str,
        from: Option<&str>,
        data: &[u8],
        more: bool,
    ) -> Result<ImportAdded, ErrorBody> {
        self.expire();
        let source = from
            .map(|f| Source::parse(f).ok_or_else(|| invalid(format!("unknown source `{f}`"))))
            .transpose()?;
        let (id, mut pending) = match session {
            Some(id) => (id.to_owned(), self.pending.remove(id).ok_or_else(unknown)?),
            None => {
                if self.pending.len() >= MAX_IMPORTS
                    && let Some(oldest) = self
                        .pending
                        .iter()
                        .min_by_key(|(_, p)| p.touched)
                        .map(|(id, _)| id.clone())
                {
                    self.pending.remove(&oldest);
                }
                self.next += 1;
                (
                    format!("import-{}", self.next),
                    Pending {
                        set: ImportSet::new(),
                        piece: None,
                        touched: Instant::now(),
                        received: 0,
                    },
                )
            }
        };
        pending.touched = Instant::now();
        let others: usize = self.pending.values().map(|p| p.received).sum();
        if others
            .saturating_add(pending.received)
            .saturating_add(data.len())
            > BUDGET
        {
            if session.is_some() {
                self.pending.insert(id, pending);
            }
            return Err(invalid(format!(
                "the imports in progress already hold {} MiB: finish or cancel one first",
                BUDGET / (1024 * 1024)
            )));
        }
        pending.received += data.len();
        let result = Self::take_piece(&mut pending, name, source, data, more);
        let added = ImportAdded {
            session: id.clone(),
            partial: pending.piece.is_some(),
            sources: pending.set.sources().to_vec(),
            entries: pending.set.entries().len(),
            passkeys: pending.set.passkeys(),
            missing: pending.set.missing_batches(),
        };
        // A failed first file leaves nothing to come back to.
        if session.is_some() || result.is_ok() {
            self.pending.insert(id, pending);
        }
        result.map(|()| added)
    }

    fn take_piece(
        pending: &mut Pending,
        name: &str,
        source: Option<Source>,
        data: &[u8],
        more: bool,
    ) -> Result<(), ErrorBody> {
        let mut bytes = match pending.piece.take() {
            Some((previous, bytes)) if previous == name => bytes,
            Some(_) => {
                return Err(invalid(
                    "the previous file did not arrive whole: add it again",
                ));
            }
            None => Zeroizing::new(Vec::new()),
        };
        if bytes.len().saturating_add(data.len()) > MAX_FILE {
            return Err(import_error(&ImportError::TooLarge));
        }
        // Grown by hand so each smaller copy of the file is wiped.
        append_wiping(&mut bytes, data);
        if more {
            pending.piece = Some((name.to_owned(), bytes));
            return Ok(());
        }
        pending
            .set
            .add(name, &bytes, source)
            .map(|_| ())
            .map_err(|e| import_error(&e))
    }

    /// The files of an import, whole.
    pub(crate) fn get(&mut self, session: &str) -> Result<&ImportSet, ErrorBody> {
        self.expire();
        let pending = self.pending.get_mut(session).ok_or_else(unknown)?;
        if pending.piece.is_some() {
            return Err(invalid("a file is still arriving: send its last piece"));
        }
        pending.touched = Instant::now();
        Ok(&pending.set)
    }

    /// Forgets an import. `false` if there was none.
    pub(crate) fn remove(&mut self, session: &str) -> bool {
        self.pending.remove(session).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use klav_client::klav_import::samples;

    #[test]
    fn files_arrive_whole_or_in_pieces() {
        let mut imports = Imports::default();
        let json = samples::bitwarden_json();
        let (a, b) = json.as_bytes().split_at(100);
        let first = imports.add(None, "bitwarden.json", None, a, true).unwrap();
        assert!(first.partial);
        assert_eq!(first.entries, 0);
        let id = first.session;
        assert!(imports.get(&id).is_err(), "half a file");
        let done = imports
            .add(Some(&id), "bitwarden.json", None, b, false)
            .unwrap();
        assert!(!done.partial);
        assert_eq!((done.entries, done.passkeys), (5, 0));
        let [link, _] = samples::google_links();
        let more = imports
            .add(Some(&id), "qr", Some("google"), link.as_bytes(), false)
            .unwrap();
        assert_eq!(more.entries, 7);
        assert_eq!(more.missing.len(), 1, "the second QR code");
        assert_eq!(imports.get(&id).unwrap().sources().len(), 2);
        assert!(imports.remove(&id));
        assert!(imports.get(&id).is_err());
    }

    #[test]
    fn bad_files_and_unknown_imports() {
        let mut imports = Imports::default();
        // A bad first file starts nothing.
        assert!(imports.add(None, "x", None, b"{not json", false).is_err());
        assert!(imports.pending.is_empty());
        assert!(
            imports
                .add(None, "x", Some("nonsense"), b"a,b\n", false)
                .is_err()
        );
        let id = imports
            .add(
                None,
                "chrome.csv",
                None,
                samples::chrome_csv().as_bytes(),
                false,
            )
            .unwrap()
            .session;
        // A bad later file keeps what was there.
        assert!(
            imports
                .add(Some(&id), "y", Some("bitwarden"), b"{}", false)
                .is_err()
        );
        assert_eq!(imports.get(&id).unwrap().entries().len(), 2);
        assert!(
            imports
                .add(Some("import-99"), "z", None, b"", false)
                .is_err()
        );
        for _ in 0..MAX_IMPORTS {
            imports
                .add(None, "c", None, samples::chrome_csv().as_bytes(), false)
                .unwrap();
        }
        assert_eq!(imports.pending.len(), MAX_IMPORTS);
        assert!(imports.get(&id).is_err(), "the oldest was dropped");
    }

    #[test]
    fn imports_share_one_memory_budget() {
        let mut imports = Imports::default();
        let piece = vec![b'a'; BUDGET / 2];
        let first = imports.add(None, "a.csv", None, &piece, true).unwrap();
        // A second import may not hold another half and more.
        let second = imports.add(None, "b.csv", None, &piece, true).unwrap();
        assert!(
            imports
                .add(Some(&second.session), "b.csv", None, b"x", true)
                .is_err()
        );
        assert!(imports.add(None, "c.csv", None, b"x", true).is_err());
        // The import that hit the limit is still there; cancelling frees.
        assert!(imports.remove(&first.session));
        imports
            .add(Some(&second.session), "b.csv", None, b"x", true)
            .unwrap();
    }
}
