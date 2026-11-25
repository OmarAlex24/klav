//! The calls in flight, so that an answer still on its way can be cut
//! when its sandbox ends or the person pauses the agents (ADR 0036 §7,
//! note of 2026-11-19, step M3). A stream (`text/event-stream`) may stay
//! open for minutes; without this it would go on until the channel's next
//! check of its connection.
//!
//! Every call registers before it asks the server for the item, so an end
//! or a pause that comes after that is never missed: one that came before
//! is the server's refusal, or the proxy's check of the sandbox after the
//! access.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use klav_core::ids::SandboxId;
use tokio::sync::watch;

/// Why a call in flight was cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CutReason {
    /// Its sandbox ended, for whatever reason.
    SandboxEnded,
    /// The person paused the agents.
    Paused,
}

/// One registered call: its sandbox (`None`: this machine) and where its
/// cut is said.
type Entry = (Option<SandboxId>, watch::Sender<Option<CutReason>>);

/// The calls in flight, by registration.
#[derive(Default)]
pub(crate) struct Cuts {
    next: AtomicU64,
    open: Mutex<HashMap<u64, Entry>>,
}

impl Cuts {
    /// Registers a call from `sandbox` (`None`: a program on this
    /// machine). It stays registered until the handle drops.
    pub(crate) fn register(self: &Arc<Self>, sandbox: Option<SandboxId>) -> CutHandle {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = watch::channel(None);
        self.lock().insert(id, (sandbox, tx));
        CutHandle {
            id,
            cuts: Arc::clone(self),
            rx,
        }
    }

    /// Cuts every call of these sandboxes: they ended.
    pub(crate) fn cut_sandboxes(&self, ended: &[SandboxId]) {
        self.cut_of(ended, CutReason::SandboxEnded);
    }

    /// Cuts every call of these sandboxes: the person paused their issuer.
    /// They have not ended, and their calls answer as paused.
    pub(crate) fn pause_sandboxes(&self, paused: &[SandboxId]) {
        self.cut_of(paused, CutReason::Paused);
    }

    /// Cuts the calls of `sandboxes` for `reason`, keeping the reason of a
    /// call cut before.
    fn cut_of(&self, sandboxes: &[SandboxId], reason: CutReason) {
        if sandboxes.is_empty() {
            return;
        }
        for (sandbox, tx) in self.lock().values() {
            if sandbox.is_some_and(|s| sandboxes.contains(&s)) {
                tx.send_if_modified(|was| {
                    if was.is_some() {
                        return false;
                    }
                    *was = Some(reason);
                    true
                });
            }
        }
    }

    /// Cuts every call, a sandbox's or this machine's: the person paused
    /// the agents.
    pub(crate) fn cut_all_paused(&self) {
        for (_, tx) in self.lock().values() {
            tx.send_if_modified(|reason| {
                if reason.is_some() {
                    return false;
                }
                *reason = Some(CutReason::Paused);
                true
            });
        }
    }

    /// Calls registered now (tests).
    #[cfg(test)]
    pub(crate) fn open(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Entry>> {
        self.open.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// One call's registration: says when the call is cut, and takes it out
/// of [`Cuts`] when dropped.
pub(crate) struct CutHandle {
    id: u64,
    cuts: Arc<Cuts>,
    rx: watch::Receiver<Option<CutReason>>,
}

impl CutHandle {
    /// Why the call was cut, if it was.
    pub(crate) fn reason(&self) -> Option<CutReason> {
        *self.rx.borrow()
    }

    /// Waits until the call is cut, and says why. Cancel safe.
    pub(crate) async fn cut(&mut self) -> CutReason {
        loop {
            if let Some(reason) = *self.rx.borrow_and_update() {
                return reason;
            }
            if self.rx.changed().await.is_err() {
                // The sender lives in the registry while this handle does:
                // never closed first. Wait forever rather than spin.
                std::future::pending::<()>().await;
            }
        }
    }
}

impl Drop for CutHandle {
    fn drop(&mut self) {
        self.cuts.lock().remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_call_is_cut_only_for_its_own_sandbox_or_a_pause() {
        let cuts = Arc::new(Cuts::default());
        let (a, b) = (SandboxId::generate(), SandboxId::generate());
        let mut of_a = cuts.register(Some(a));
        let of_b = cuts.register(Some(b));
        let local = cuts.register(None);
        assert_eq!(cuts.open(), 3);
        cuts.cut_sandboxes(&[a]);
        assert_eq!(of_a.cut().await, CutReason::SandboxEnded);
        assert_eq!(of_b.reason(), None);
        assert_eq!(local.reason(), None);
        cuts.cut_all_paused();
        assert_eq!(of_b.reason(), Some(CutReason::Paused));
        assert_eq!(local.reason(), Some(CutReason::Paused));
        // A pause never rewrites an end that came first.
        assert_eq!(of_a.reason(), Some(CutReason::SandboxEnded));
        // An issuer's pause answers as a pause, not an end.
        let paused = SandboxId::generate();
        let of_paused = cuts.register(Some(paused));
        cuts.pause_sandboxes(&[paused]);
        assert_eq!(of_paused.reason(), Some(CutReason::Paused));
        drop((of_a, of_b, local, of_paused));
        assert_eq!(cuts.open(), 0);
    }

    /// A handle registered after a cut is not cut by it.
    #[tokio::test]
    async fn a_later_call_starts_uncut() {
        let cuts = Arc::new(Cuts::default());
        let a = SandboxId::generate();
        cuts.cut_sandboxes(&[a]);
        cuts.cut_all_paused();
        let mut later = cuts.register(Some(a));
        assert_eq!(later.reason(), None);
        let waited = tokio::time::timeout(std::time::Duration::from_millis(50), later.cut()).await;
        assert!(waited.is_err());
    }
}
