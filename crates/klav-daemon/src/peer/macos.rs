//! The peer on macOS (ADR 0041 §1.1): the socket's last user, checked to
//! hold the connection, and the same process from the first read to the
//! last.

use std::os::fd::BorrowedFd;

use klav_touchid::{self as shim, ProcessInfo, UniqueId};

use super::{Identity, Peer, Process, Session, StartTime, Step};

/// The kernel reads [`identify_reading`] makes. `klavd` makes them through
/// the Touch ID shim ([`Shim`]); tests wrap it to make one read differ.
pub(super) trait Kernel {
    /// The socket's audit token: `last_pid` and its pid version.
    fn peer_token(&mut self, socket: BorrowedFd<'_>) -> Option<(i32, i32)>;
    /// The unique IDs of `pid`.
    fn unique_id(&mut self, pid: i32) -> Option<UniqueId>;
    /// Whether `pid` holds the other end of `socket`.
    fn holds_peer_end(&mut self, pid: i32, socket: BorrowedFd<'_>) -> Option<bool>;
    /// The kernel's description of `pid`.
    fn process_info(&mut self, pid: i32) -> Option<ProcessInfo>;
}

/// The reads through the Touch ID shim (`klav-touchid`).
pub(super) struct Shim;

impl Kernel for Shim {
    fn peer_token(&mut self, socket: BorrowedFd<'_>) -> Option<(i32, i32)> {
        shim::peer_token(socket)
    }

    fn unique_id(&mut self, pid: i32) -> Option<UniqueId> {
        shim::unique_id(pid)
    }

    fn holds_peer_end(&mut self, pid: i32, socket: BorrowedFd<'_>) -> Option<bool> {
        shim::holds_peer_end(pid, socket)
    }

    fn process_info(&mut self, pid: i32) -> Option<ProcessInfo> {
        shim::process_info(pid)
    }
}

pub(super) fn identify(socket: BorrowedFd<'_>, pause: &mut dyn FnMut(Step)) -> Identity {
    identify_reading(&mut Shim, socket, pause)
}

/// The peer of `socket` as `kernel`'s reads describe it.
pub(super) fn identify_reading(
    kernel: &mut impl Kernel,
    socket: BorrowedFd<'_>,
    pause: &mut dyn FnMut(Step),
) -> Identity {
    read(kernel, socket, pause).map_or(Identity::Unknown, Identity::Known)
}

fn read(
    kernel: &mut impl Kernel,
    socket: BorrowedFd<'_>,
    pause: &mut dyn FnMut(Step),
) -> Option<Peer> {
    // The token names `last_pid`; its pid version must be the one the
    // unique-ID read sees, or the pid changed hands (or exec'd) in between.
    let (pid, version) = kernel.peer_token(socket)?;
    let first = kernel.unique_id(pid)?;
    if first.version != version {
        return None;
    }
    pause(Step::First);
    // The fd-ownership check: `last_pid` may have exited and its pid been
    // reused by a process that never held this connection.
    if !kernel.holds_peer_end(pid, socket)? {
        return None;
    }
    pause(Step::Middle);
    let info = kernel.process_info(pid)?;
    let uid = nix::unistd::getuid().as_raw();
    if info.ruid != uid || info.euid != uid {
        return None;
    }
    let start = StartTime(info.start_micros);
    let parent = parent(kernel, &info, first);
    let session = session(kernel, info.sid, start);
    pause(Step::Last);
    // The same process from the first read to the last (R3): the reads in
    // between could have hit another process at the same pid.
    let again = kernel.process_info(pid)?;
    let last = kernel.unique_id(pid)?;
    if again != info || last.unique != first.unique {
        return None;
    }
    Some(Peer {
        process: Process { pid, start },
        parent,
        session,
        terminal: info.terminal.map(u64::from),
    })
}

/// The peer's parent: the process at `ppid` has the unique ID the peer
/// records for its parent (`p_puniqueid`), before and after its start time
/// is read. That match shows the process at `ppid` is the parent the
/// kernel records now, not a process that took its pid. It doesn't prove
/// creation: the kernel rewrites `p_puniqueid` when it reparents. An orphan
/// is reparented to `launchd` (1), so it has no parent; whether macOS
/// reparents to anything else (a debugger's attach) isn't verified (ADR
/// 0041, "Plan in layers", item 1). The start times aren't compared: they
/// are wall-clock times, and a clock stepped back between the two starts
/// would reject a good parent.
fn parent(kernel: &mut impl Kernel, info: &ProcessInfo, peer: UniqueId) -> Option<Process> {
    let ppid = info.ppid;
    if ppid <= 1 {
        return None;
    }
    let before = kernel.unique_id(ppid)?;
    if before.unique != peer.parent {
        return None;
    }
    let parent = kernel.process_info(ppid)?;
    let after = kernel.unique_id(ppid)?;
    (after.unique == before.unique).then_some(Process {
        pid: ppid,
        start: StartTime(parent.start_micros),
    })
}

/// The session `sid`, when the process at that pid leads it and is the
/// same process before and after its start time is read.
fn session(kernel: &mut impl Kernel, sid: i32, start: StartTime) -> Option<Session> {
    if sid <= 0 {
        return None;
    }
    let before = kernel.unique_id(sid)?;
    let leader = kernel.process_info(sid)?;
    let after = kernel.unique_id(sid)?;
    let leads = leader.session_leader && leader.sid == sid;
    (leads && after.unique == before.unique && leader.start_micros <= start.0).then_some(Session {
        id: sid,
        leader_start: StartTime(leader.start_micros),
    })
}
