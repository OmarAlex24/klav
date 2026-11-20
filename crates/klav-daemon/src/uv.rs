//! The user-verification window for passkeys (ADR 0020 §8).
//!
//! By default every passkey use (signing in or saving) needs a real
//! verification: Touch ID, or the master password in Klav's frame. The
//! person can pick a longer window, a local setting of this `klavd`
//! (`passkeys.json`, not synced). `klavd` keeps when the last real
//! verification happened in memory, with a monotonic clock; locking drops
//! it with the session, and sleeping locks.

#[cfg(feature = "server")]
use std::path::Path;
#[cfg(feature = "server")]
use std::time::{Duration, Instant};

#[cfg(feature = "server")]
use klav_client::home::{Home, write_private};
use serde::{Deserialize, Serialize};

// Only `Window` is part of the protocol; the rest is `klavd`'s.
#[cfg(feature = "server")]
const FILE: &str = "passkeys.json";

#[cfg(feature = "server")]
/// How long the unlock in Klav's passkey frame covers the use it was for.
pub(crate) const FLOW: Duration = Duration::from_secs(60);
#[cfg(feature = "server")]
/// «Every 5 min».
pub(crate) const FIVE_MINUTES: Duration = Duration::from_secs(5 * 60);

/// When a passkey use needs a new verification.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Window {
    /// «Always» (default): a real verification on every use.
    #[default]
    #[serde(rename = "always")]
    Always,
    /// «Every 5 min»: again if the last one was more than 5 minutes ago.
    #[serde(rename = "5m")]
    FiveMinutes,
    /// «While Klav is unlocked»: the unlock counts until the next lock.
    #[serde(rename = "unlocked")]
    Unlocked,
}

#[cfg(feature = "server")]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    v: u32,
    window: Window,
}

#[cfg(feature = "server")]
/// The window of `home`. Missing, unreadable, of another version, or
/// writable by other users: «Always» (it never loosens by accident).
pub(crate) fn load(home: &Home) -> Window {
    let path = home.file(FILE);
    if !private(&path) {
        return Window::Always;
    }
    std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Stored>(&bytes).ok())
        .filter(|s| s.v == 1)
        .map_or(Window::Always, |s| s.window)
}

#[cfg(all(feature = "server", unix))]
fn private(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).is_ok_and(|m| m.mode() & 0o022 == 0)
}

#[cfg(all(feature = "server", not(unix)))]
fn private(path: &Path) -> bool {
    path.exists()
}

#[cfg(feature = "server")]
/// Saves the window of `home`.
pub(crate) fn save(home: &Home, window: Window) -> klav_client::ClientResult<()> {
    home.ensure()?;
    let json = serde_json::to_vec_pretty(&Stored { v: 1, window }).expect("window serializes");
    write_private(&home.file(FILE), &json)
}

#[cfg(feature = "server")]
/// The last real verification of this session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Verified {
    pub(crate) at: Instant,
    /// An unlock in Klav's passkey frame (it covers the use it was for).
    pub(crate) flow: bool,
    /// A passkey use already relied on it.
    pub(crate) spent: bool,
}

#[cfg(feature = "server")]
impl Verified {
    /// An unlock: `flow` when it was Klav's passkey frame that asked.
    pub(crate) fn unlock(at: Instant, flow: bool) -> Self {
        Self {
            at,
            flow,
            spent: false,
        }
    }

    /// Touch ID or the password for a passkey use (or to loosen the
    /// window): the use it was for consumes it.
    pub(crate) fn checked(at: Instant) -> Self {
        Self {
            at,
            flow: false,
            spent: true,
        }
    }
}

#[cfg(feature = "server")]
/// Whether a passkey use at `now` needs a real verification first.
///
/// - «Always»: yes, unless Klav's passkey frame unlocked less than
///   [`FLOW`] ago and no use has relied on that unlock yet.
/// - «Every 5 min»: if there is none from the last 5 minutes.
/// - «While unlocked»: only without one (an unlock always records one).
pub(crate) fn needs_verification(window: Window, last: Option<Verified>, now: Instant) -> bool {
    let Some(last) = last else { return true };
    let age = now.saturating_duration_since(last.at);
    match window {
        Window::Always => !(last.flow && !last.spent && age <= FLOW),
        Window::FiveMinutes => age > FIVE_MINUTES,
        Window::Unlocked => false,
    }
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;

    fn at(start: Instant, secs: u64) -> Instant {
        start + Duration::from_secs(secs)
    }

    #[test]
    fn always_asks_on_every_use_but_the_one_its_frame_unlocked_for() {
        let t = Instant::now();
        let w = Window::Always;
        assert!(needs_verification(w, None, t));
        // An unlock in the passkey frame covers the next use, for a minute.
        let flow = Verified::unlock(t, true);
        assert!(!needs_verification(w, Some(flow), at(t, 59)));
        assert!(needs_verification(w, Some(flow), at(t, 61)));
        assert!(needs_verification(
            w,
            Some(Verified {
                spent: true,
                ..flow
            }),
            at(t, 1)
        ));
        // Any other unlock (the CLI, the popup) covers nothing.
        assert!(needs_verification(
            w,
            Some(Verified::unlock(t, false)),
            at(t, 1)
        ));
        // Touch ID for one use is spent by it.
        assert!(needs_verification(w, Some(Verified::checked(t)), at(t, 1)));
    }

    #[test]
    fn five_minutes_counts_from_the_last_real_verification() {
        let t = Instant::now();
        let w = Window::FiveMinutes;
        assert!(needs_verification(w, None, t));
        for last in [Verified::unlock(t, false), Verified::checked(t)] {
            assert!(!needs_verification(w, Some(last), at(t, 300)));
            assert!(needs_verification(w, Some(last), at(t, 301)));
        }
    }

    #[test]
    fn while_unlocked_the_unlock_counts_until_the_lock() {
        let t = Instant::now();
        let w = Window::Unlocked;
        assert!(needs_verification(w, None, t));
        let unlock = Verified {
            spent: true,
            ..Verified::unlock(t, false)
        };
        assert!(!needs_verification(w, Some(unlock), at(t, 86_400)));
    }

    #[test]
    fn the_windows_go_from_strict_to_loose() {
        assert!(Window::Always < Window::FiveMinutes);
        assert!(Window::FiveMinutes < Window::Unlocked);
        assert_eq!(
            serde_json::to_string(&Window::FiveMinutes).unwrap(),
            "\"5m\""
        );
    }

    #[test]
    fn a_missing_odd_or_shared_file_means_always() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path().join("home"));
        assert_eq!(load(&home), Window::Always);
        save(&home, Window::Unlocked).unwrap();
        assert_eq!(load(&home), Window::Unlocked);
        let path = home.file(FILE);
        std::fs::write(&path, br#"{"v":2,"window":"unlocked"}"#).unwrap();
        assert_eq!(load(&home), Window::Always);
        std::fs::write(&path, br#"{"v":1,"window":"forever"}"#).unwrap();
        assert_eq!(load(&home), Window::Always);
        save(&home, Window::Unlocked).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
            assert_eq!(load(&home), Window::Always);
        }
    }
}
