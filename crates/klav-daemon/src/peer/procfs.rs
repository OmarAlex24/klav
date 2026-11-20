//! What Linux's `/proc` says about a peer (ADR 0041 §1.1): the parsing,
//! and the order of the reads with their re-checks ([`read_peer`]). Both
//! are pure over [`ProcReads`], so they are tested on every platform, not
//! only on Linux CI, and a test can make one read differ.
#![cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]

use super::{Peer, Process, Session, StartTime, Step};

/// The reads [`read_peer`] makes. `klavd` reads `/proc` (`linux::Live`);
/// tests give a reader where one read differs.
pub(crate) trait ProcReads {
    /// The pid the peer's pidfd names (`/proc/self/fdinfo/<pidfd>`): -1
    /// once the process was reaped.
    fn pidfd_pid(&mut self) -> Option<i32>;
    /// `/proc/<pid>/stat`.
    fn stat(&mut self, pid: i32) -> Option<Stat>;
    /// The real and effective user IDs in `/proc/<pid>/status`.
    fn uids(&mut self, pid: i32) -> Option<(u32, u32)>;
}

/// The peer a pidfd names, when it runs as `uid` and every read named the
/// same process: the pidfd still names the pid after every other read, so
/// the process wasn't reaped and its pid not reused in between (finding
/// S3), and its `stat` didn't change (a parent that left would change
/// `ppid`).
pub(crate) fn read_peer(
    proc: &mut impl ProcReads,
    uid: u32,
    pause: &mut dyn FnMut(Step),
) -> Option<Peer> {
    let pid = proc.pidfd_pid().filter(|pid| *pid > 0)?;
    pause(Step::First);
    let first = stat_of(proc, pid)?;
    let (ruid, euid) = proc.uids(pid)?;
    if ruid != uid || euid != uid {
        return None;
    }
    pause(Step::Middle);
    let start = StartTime(first.start);
    let parent = parent(proc, &first);
    let session = session(proc, first.sid, start);
    pause(Step::Last);
    if stat_of(proc, pid)? != first || proc.pidfd_pid()? != pid {
        return None;
    }
    Some(Peer {
        process: Process { pid, start },
        parent,
        session,
        terminal: (first.tty_nr != 0).then_some(u64::from(first.tty_nr)),
    })
}

/// `/proc/<pid>/stat`, when it is that pid's.
fn stat_of(proc: &mut impl ProcReads, pid: i32) -> Option<Stat> {
    proc.stat(pid).filter(|stat| stat.pid == pid)
}

/// The parent as `/proc` names it. Only a description on Linux: a peer
/// with no terminal is keyed by its connection (`PARENT_KEYS`). Read before
/// the last re-check, which fails if the peer was reparented meanwhile.
fn parent(proc: &mut impl ProcReads, peer: &Stat) -> Option<Process> {
    if peer.ppid <= 1 {
        return None;
    }
    let parent = stat_of(proc, peer.ppid)?;
    (parent.start <= peer.start).then_some(Process {
        pid: peer.ppid,
        start: StartTime(parent.start),
    })
}

/// The session `sid`, when the process at that pid leads it. A session
/// keeps its ID's pid from being reused while it has members, so the
/// process at that pid, if it leads a session with that ID, leads this one.
fn session(proc: &mut impl ProcReads, sid: i32, start: StartTime) -> Option<Session> {
    if sid <= 0 {
        return None;
    }
    let leader = stat_of(proc, sid)?;
    (leader.sid == sid && leader.start <= start.0).then_some(Session {
        id: sid,
        leader_start: StartTime(leader.start),
    })
}

/// The fields of `/proc/<pid>/stat` that the peer's identity uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stat {
    pub(crate) pid: i32,
    pub(crate) ppid: i32,
    pub(crate) sid: i32,
    /// The controlling terminal's device number, 0 for none.
    pub(crate) tty_nr: u32,
    /// Clock ticks after boot.
    pub(crate) start: u64,
}

/// Parses `/proc/<pid>/stat` (`proc_pid_stat(5)`). The command name, field
/// 2, is in parentheses and may itself hold spaces and parentheses, so the
/// fields after it are counted from the last `)`.
pub(crate) fn parse_stat(text: &str) -> Option<Stat> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    if close < open {
        return None;
    }
    let pid = text.get(..open)?.trim().parse().ok()?;
    // Field 3 (state) is the first after the name.
    let rest: Vec<&str> = text.get(close + 1..)?.split_ascii_whitespace().collect();
    let field = |n: usize| rest.get(n.checked_sub(3)?).copied();
    let tty: i64 = field(7)?.parse().ok()?;
    Some(Stat {
        pid,
        ppid: field(4)?.parse().ok()?,
        sid: field(6)?.parse().ok()?,
        // The kernel prints the dev_t as a signed int.
        tty_nr: u32::try_from(tty)
            .or_else(|_| i32::try_from(tty).map(i32::cast_unsigned))
            .ok()?,
        start: field(22)?.parse().ok()?,
    })
}

/// The `Pid:` of a pidfd's `/proc/self/fdinfo/<fd>`: the process's pid,
/// or -1 once it has exited and been reaped.
pub(crate) fn parse_fdinfo_pid(text: &str) -> Option<i32> {
    text.lines()
        .find_map(|line| line.strip_prefix("Pid:"))?
        .trim()
        .parse()
        .ok()
}

/// The real and effective user IDs on the `Uid:` line of
/// `/proc/<pid>/status`.
pub(crate) fn parse_status_uids(text: &str) -> Option<(u32, u32)> {
    let mut ids = text
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_ascii_whitespace();
    Some((ids.next()?.parse().ok()?, ids.next()?.parse().ok()?))
}
