//! The peer on Linux (ADR 0041 §1.1): the process that connected, named
//! by `SO_PEERPIDFD`, read from `/proc`, and the pidfd checked again last.
//! The order of the reads and the re-checks is [`read_peer`].

use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};

use nix::sys::socket::{getsockopt, sockopt::PeerPidfd};

use super::procfs::{ProcReads, Stat, parse_fdinfo_pid, parse_stat, parse_status_uids, read_peer};
use super::{Identity, Step, without_pidfd};

pub(super) fn identify(socket: BorrowedFd<'_>, pause: &mut dyn FnMut(Step)) -> Identity {
    identify_from(socket, |socket| getsockopt(&socket, PeerPidfd), pause)
}

/// [`identify`] with the `SO_PEERPIDFD` read given, so that a test can be a
/// kernel without it.
pub(super) fn identify_from(
    socket: BorrowedFd<'_>,
    peer_pidfd: impl FnOnce(BorrowedFd<'_>) -> nix::Result<OwnedFd>,
    pause: &mut dyn FnMut(Step),
) -> Identity {
    match peer_pidfd(socket) {
        Ok(pidfd) => identify_reading(&mut Live { pidfd: &pidfd }, pause),
        Err(errno) => without_pidfd(errno),
    }
}

/// The peer that `proc`'s reads describe, for a `klavd` of this user.
pub(super) fn identify_reading(proc: &mut impl ProcReads, pause: &mut dyn FnMut(Step)) -> Identity {
    let uid = nix::unistd::getuid().as_raw();
    read_peer(proc, uid, pause).map_or(Identity::Unknown, Identity::Known)
}

/// The reads of `/proc` for the process a pidfd names.
pub(super) struct Live<'a> {
    pub(super) pidfd: &'a OwnedFd,
}

impl ProcReads for Live<'_> {
    /// The pid a pidfd names, while its process hasn't been reaped (the pid
    /// can't be reused until then).
    fn pidfd_pid(&mut self) -> Option<i32> {
        let path = format!("/proc/self/fdinfo/{}", self.pidfd.as_raw_fd());
        parse_fdinfo_pid(&std::fs::read_to_string(path).ok()?)
    }

    fn stat(&mut self, pid: i32) -> Option<Stat> {
        parse_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
    }

    fn uids(&mut self, pid: i32) -> Option<(u32, u32)> {
        parse_status_uids(&std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?)
    }
}
