//! Who is at the other end of `klavd`'s socket (ADR 0041 §1.1 and §2.1,
//! layer 1).
//!
//! What the kernel says about a peer is a key with a named residual, or a
//! hint; never proof of which code asks (§1.1, finding B1). This module
//! only describes the peer; nothing gates on it yet (layer 2 keys the
//! presence windows on [`Identity::window_key`]).
//!
//! - **macOS:** the audit token names the socket's last user (`last_pid`).
//!   `klavd` reads that process's unique ID first; checks that the process
//!   holds, right now, a descriptor for the other end of this connection;
//!   reads its parent, session, start time and controlling terminal; and
//!   reads the unique ID again last. Any failed read, or a unique ID that
//!   changed, makes the peer unknown. The reads are in the Touch ID shim
//!   (`klav-touchid`), where `unsafe` is allowed.
//! - **Linux:** `SO_PEERPIDFD` names the process that connected. `klavd`
//!   reads `/proc/<pid>/stat` and checks, last, that the pidfd still names
//!   that pid (the pid wasn't reused while `/proc` was read). On a kernel
//!   without `SO_PEERPIDFD` (before 6.5) there is no identity at all.

use std::os::fd::{AsFd, BorrowedFd};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
mod procfs;
#[cfg(test)]
mod tests;

/// When a process started, as this machine's kernel reports it: on macOS
/// microseconds since the Unix epoch, on Linux clock ticks since boot.
/// Only compared with start times read the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StartTime(pub u64);

/// A process: its pid together with its start time, so that a pid the
/// system reuses later doesn't name the same process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Process {
    /// Process ID.
    pub pid: i32,
    /// When it started.
    pub start: StartTime,
}

/// A session: its ID together with its leader's start time, so that a
/// session ID the system reuses later doesn't name the same session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Session {
    /// Session ID (the leader's pid).
    pub id: i32,
    /// When the leader started.
    pub leader_start: StartTime,
}

/// A peer whose process the kernel names and every read succeeded for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// The process: on macOS the socket's last user, which holds the
    /// connection; on Linux the process that connected.
    pub process: Process,
    /// Its parent, when that is still the process that created it. `None`
    /// for pid 1 (`launchd`, `init`), for an orphan on macOS (its creator
    /// is gone), and when the parent can't be read.
    pub parent: Option<Process>,
    /// Its session, when the process at the session ID is that session's
    /// leader. `None` when the leader has exited or can't be read.
    pub session: Option<Session>,
    /// The controlling terminal's device number, if it has one. A hint for
    /// the person (§1.3), and what makes the session the key.
    pub terminal: Option<u64>,
}

/// What `klavd` knows about the other end of a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// Every read succeeded and named the same process.
    Known(Peer),
    /// The process left, a read failed, a re-check didn't match, or (macOS)
    /// the process doesn't hold the connection: a window of this
    /// connection only.
    Unknown,
    /// Linux without `SO_PEERPIDFD` (before 6.5): no window at all; each
    /// value asks (ADR 0041, the owner's decision).
    NoPeerPidfd,
}

/// What a presence window is keyed on (§2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WindowKey {
    /// A peer in a terminal: its session.
    Session(Session),
    /// A peer with no terminal, on macOS: its parent.
    Parent(Process),
    /// An unknown peer: a window of its own connection only.
    Connection,
    /// No window at all (Linux without `SO_PEERPIDFD`).
    NoWindow,
}

/// Whether a peer with no terminal is keyed by its parent. On Linux every
/// such peer is keyed by its connection: an orphan's parent is the nearest
/// subreaper, any process may become one (`PR_SET_CHILD_SUBREAPER`), and
/// another process can't read the flag, so a parent can't be told from a
/// subreaper (§2.1's fallback; Omar confirmed it, ADR 0041 Q-L1.2).
const PARENT_KEYS: bool = cfg!(target_os = "macos");

impl Identity {
    /// The key of the presence window this peer would share (§2.1).
    pub fn window_key(&self) -> WindowKey {
        match self {
            Identity::NoPeerPidfd => WindowKey::NoWindow,
            Identity::Unknown => WindowKey::Connection,
            Identity::Known(peer) if peer.terminal.is_some() => peer
                .session
                .map_or(WindowKey::Connection, WindowKey::Session),
            Identity::Known(peer) => match peer.parent {
                Some(parent) if PARENT_KEYS && parent.pid > 1 => WindowKey::Parent(parent),
                _ => WindowKey::Connection,
            },
        }
    }
}

/// Where [`identify_with`] can be paused, for tests that change the peer
/// between two reads (as a program that stops `klavd` could).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// After the first read of the process's identity (macOS: the unique
    /// ID; Linux: the pid behind the pidfd).
    First,
    /// After the check that it holds the connection (macOS) or the first
    /// read of `/proc` (Linux), before the parent and session are read.
    Middle,
    /// Before the last re-check.
    Last,
}

/// Who is at the other end of `socket`, a connection accepted on
/// `klavd`'s listening socket.
pub fn identify(socket: impl AsFd) -> Identity {
    identify_with(socket.as_fd(), &mut |_| {})
}

pub(crate) fn identify_with(socket: BorrowedFd<'_>, pause: &mut dyn FnMut(Step)) -> Identity {
    #[cfg(target_os = "macos")]
    return macos::identify(socket, pause);
    #[cfg(target_os = "linux")]
    return linux::identify(socket, pause);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (socket, pause);
        Identity::Unknown
    }
}

/// The name of a controlling terminal from its device number, as
/// [`Peer::terminal`] holds it, for the presence prompt (ADR 0041 §2.4):
/// `ttys003` on macOS (`devname_r(3)`, in the Touch ID shim), `pts/3` on
/// Linux (the major and minor numbers). `None` when it can't be named, or
/// when the name has anything but ASCII letters, digits, `/`, `.`, `_` and
/// `-`: the prompt then says "a terminal" (the ADR's own choice 2).
pub fn terminal_name(device: u64) -> Option<String> {
    #[cfg(target_os = "macos")]
    let name = u32::try_from(device)
        .ok()
        .and_then(klav_touchid::device_name);
    #[cfg(not(target_os = "macos"))]
    let name = linux_terminal_name(device);
    name.filter(|n| plain_name(n))
}

/// The device number of this process's own controlling terminal, read the
/// way `klavd` reads a peer's ([`Peer::terminal`]): the shim's
/// `process_info` on macOS, `/proc/self/stat` on Linux. `None` with no
/// controlling terminal, or when it can't be read. `klavd` never calls it:
/// `klav` names its terminal with [`terminal_name`] before it asks for the
/// master password, so the person can compare it with the name `klavd`
/// gives (ADR 0041 §2.4, layer 3). Not `ttyname`, which names the terminal
/// on one descriptor, and that differs when it is redirected.
pub fn own_terminal() -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        let pid = i32::try_from(std::process::id()).ok()?;
        klav_touchid::process_info(pid)?.terminal.map(u64::from)
    }
    #[cfg(target_os = "linux")]
    {
        let stat = procfs::parse_stat(&std::fs::read_to_string("/proc/self/stat").ok()?)?;
        (stat.tty_nr != 0).then_some(u64::from(stat.tty_nr))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    None
}

/// Whether `name` may go into a system dialog as a terminal's name.
fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
}

/// The name under `/dev` of a Linux terminal whose `tty_nr` (field 7 of
/// `/proc/<pid>/stat`, the kernel's `new_encode_dev`) is `device`: the
/// pseudo-terminals (`pts/N`, major 136), the virtual consoles (`ttyN`)
/// and the serial ports (`ttySN`, major 4). Anything else has no name here.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(crate) fn linux_terminal_name(device: u64) -> Option<String> {
    let device = u32::try_from(device).ok()?;
    let major = (device >> 8) & 0xfff;
    let minor = (device & 0xff) | ((device >> 12) & 0xfff00);
    match (major, minor) {
        (136, n) => Some(format!("pts/{n}")),
        (4, n @ 0..=63) => Some(format!("tty{n}")),
        (4, n @ 64..=255) => Some(format!("ttyS{}", n - 64)),
        _ => None,
    }
}

/// The identity when `SO_PEERPIDFD` fails with `errno`: a kernel that
/// doesn't know the option (`ENOPROTOOPT`) gives no window at all; any
/// other failure (the process left) gives an unknown peer.
#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
pub(crate) fn without_pidfd(errno: nix::errno::Errno) -> Identity {
    if errno == nix::errno::Errno::ENOPROTOOPT {
        Identity::NoPeerPidfd
    } else {
        Identity::Unknown
    }
}
