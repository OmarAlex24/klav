//! The proxy's memory (ADR 0044 §3): no core dumps, not dumpable on Linux,
//! and its pages locked out of swap as it touches them, when the host
//! allows it.
//!
//! [`harden_process`] runs first in `main`, before the tokio runtime and
//! its threads exist and before anything reads the proxy's key: called any
//! later, the key would already be in memory. A test in `cli.rs` fails if
//! the call moves below the runtime; the binary itself never refuses for
//! the threads that run (ADR 0044 §11, L13 withdrawn): the core limit, the
//! dumpable flag and `mlockall` apply to the whole process. Only the binary
//! calls it; tests that run the proxy in their own process (`app::bind`)
//! are never hardened, and this module's own tests harden only a child
//! process.
//!
//! - **Core dumps off on every Unix:** `RLIMIT_CORE` goes to `(0, 0)`. An
//!   unprivileged process can't raise it back. A failure is fatal.
//! - **Not dumpable on Linux:** `PR_SET_DUMPABLE` 0. A process of the same
//!   user then can't `ptrace` it or read `/proc/<pid>/mem`, and the kernel
//!   writes no core even to a piped `core_pattern` (systemd-coredump,
//!   apport), which ignores `RLIMIT_CORE`. A failure is fatal.
//! - **Memory locked on fault** with
//!   `mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)` (Omar's decision of
//!   2026-11-19, amending ADR 0044 §3.2): every page the proxy has touched,
//!   and every page it touches later, stays out of swap, but nothing is
//!   made resident only to lock it (thread stacks above all). Only when the
//!   `memlock` limit is unlimited or this process may raise it to
//!   unlimited: the kernel counts the whole size of every mapping marked to
//!   lock against a finite limit, so a later allocation would fail and end
//!   the proxy mid-request. Otherwise the proxy starts unlocked and says why
//!   ([`MemoryReport::why`]), unless the operator required the lock
//!   ([`LockChoice`]). A kernel that doesn't know `MCL_ONFAULT` (before
//!   Linux 4.4) is a lock that could not be taken: never a fall back to
//!   locking every page at once. The lock is then read back from `VmLck` in
//!   `/proc/self/status`; one that doesn't read back is undone, and one
//!   that can be neither read back nor undone is said as that
//!   ([`MemoryReport::lock_not_undone`], Omar's decision 19 of 2026-11-19
//!   in ADR 0044): the proxy starts. The operator may turn the lock
//!   off (`--no-memory-lock`, [`LOCK_ENV`]`=off`); core dumps stay off.
//!   macOS has no `mlockall` (its kernel answers `ENOSYS`) and encrypts
//!   swap.
//!
//! What this reports holds only limits, sizes and error codes, never a
//! value.
//!
//! The module uses only `std`, `nix` and `serde`, so its Linux paths can be
//! type-checked on their own on a Mac (the workspace doesn't cross-compile
//! there).

use nix::errno::Errno;
use nix::sys::resource::{RLIM_INFINITY, Resource, getrlimit, rlim_t, setrlimit};
use serde::{Deserialize, Serialize};

/// The variable that makes an unlocked start of `init` and `serve` fatal,
/// like `--require-memory-lock`.
pub const REQUIRE_ENV: &str = "KLAV_PROXY_REQUIRE_MEMORY_LOCK";

/// The variable that turns the memory lock off, like `--no-memory-lock`:
/// `on` (the default) or `off`.
pub const LOCK_ENV: &str = "KLAV_PROXY_MEMORY_LOCK";

/// What took effect in the proxy's memory: `memory` in `klav-proxy status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryReport {
    /// Always `off` in a proxy that started: turning them off is never
    /// skipped.
    pub core_dumps: CoreDumps,
    /// `false` on Linux once the flag is off. `null` where the system has no
    /// such flag (macOS).
    pub dumpable: Option<bool>,
    /// Whether the memory is locked on fault: every mapping present at
    /// start and every later one is marked so that its pages are locked
    /// out of swap once touched, and the pages touched so far are locked.
    /// `true` only when `mlockall` succeeded and `VmLck` read back is more
    /// than 0.
    pub locked: bool,
    /// The operator turned the lock off (`--no-memory-lock` or
    /// `KLAV_PROXY_MEMORY_LOCK=off`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub lock_turned_off: bool,
    /// `VmLck` in `/proc/self/status` right after the lock, in KiB: the size
    /// of the mappings marked to lock, not what is resident.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_lck_kib: Option<u64>,
    /// Why the memory is not locked, with the limit and how to raise it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// `mlockall` succeeded, `VmLck` did not confirm it, and `munlockall`
    /// failed: the memory stays marked to lock, unconfirmed, and a limit
    /// the proxy raised stays raised (ADR 0044, decision 19).
    /// `locked` is `false` then, and `why` says all of it; this is neither
    /// locked nor unlocked, and nothing words it as either.
    #[serde(default, skip_serializing_if = "is_false")]
    pub lock_not_undone: bool,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !*b
}

impl MemoryReport {
    /// The dumpable flag in words, for the log and `status`.
    pub fn dumpable_words(&self) -> &'static str {
        match self.dumpable {
            Some(false) => "not dumpable",
            Some(true) => "dumpable",
            None => "no dumpable flag on this system",
        }
    }
}

/// Whether the process can leave a core dump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreDumps {
    /// `RLIMIT_CORE` is `(0, 0)`.
    Off,
}

impl CoreDumps {
    /// As `status` prints it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
        }
    }
}

/// What `serve` writes next to its registration once it listens, and
/// `status` shows as `memory`: the report and when that `serve` wrote it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRecord {
    /// What took effect.
    #[serde(flatten)]
    pub report: MemoryReport,
    /// When that `serve` wrote the record, once it was listening (Unix ms).
    pub since: i64,
}

/// The record's file format: `v` first.
const RECORD_VERSION: u32 = 1;

/// The largest record file `status` reads.
pub const MAX_RECORD_BYTES: u64 = 4096;

#[derive(Serialize, Deserialize)]
struct RecordFile {
    v: u32,
    #[serde(flatten)]
    record: MemoryRecord,
}

impl MemoryRecord {
    /// The file's bytes.
    pub fn to_file(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&RecordFile {
            v: RECORD_VERSION,
            record: self.clone(),
        })
        .map_err(|e| e.to_string())
    }

    /// Reads the file's bytes; another version is refused. A record that
    /// says both `locked: true` and `lock_not_undone: true` is read as the
    /// lock that could be neither confirmed nor undone, with `locked`
    /// `false` (ADR 0044, Omar's decision 28 of 2026-11-19): `status`'s line
    /// and its `--json` then agree, and a reader that knows only `locked`
    /// never reads `true` for it. No `serve` writes such a record.
    pub fn from_file(bytes: &[u8]) -> Result<Self, String> {
        let file: RecordFile = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if file.v != RECORD_VERSION {
            return Err(format!("unknown version {}", file.v));
        }
        let mut record = file.record;
        if record.report.lock_not_undone {
            record.report.locked = false;
        }
        Ok(record)
    }
}

/// What the operator asked of the lock, read before the process hardens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockChoice {
    /// Try to lock (unless turned off).
    pub lock: bool,
    /// An unlocked start is fatal.
    pub required: bool,
}

impl LockChoice {
    /// For `init` and `serve`: `--no-memory-lock` or [`LOCK_ENV`]`=off`
    /// turns the lock off, `--require-memory-lock` or [`REQUIRE_ENV`] makes
    /// it required, and both at once is refused. Both variables are always
    /// read, so a value neither accepts stops the start even with a flag.
    pub fn for_start(
        no_lock_flag: bool,
        require_flag: bool,
        lookup: impl Fn(&str) -> Option<std::ffi::OsString>,
    ) -> Result<Self, String> {
        let off_env = lock_off_from_env(&lookup)?;
        let require_env = require_from_env(&lookup)?;
        let off = no_lock_flag || off_env;
        let required = require_flag || require_env;
        if off && required {
            let off_by = if no_lock_flag {
                "--no-memory-lock".to_owned()
            } else {
                format!("{LOCK_ENV}=off")
            };
            let required_by = if require_flag {
                "--require-memory-lock".to_owned()
            } else {
                format!("{REQUIRE_ENV}=1")
            };
            return Err(format!(
                "the memory lock is turned off ({off_by}) and required ({required_by}) at once: keep only one of them"
            ));
        }
        Ok(Self {
            lock: !off,
            required,
        })
    }

    /// For `status`: [`LOCK_ENV`] turns its own lock off too; the
    /// requirement is never read, as `status` never fails for the lock
    /// (ADR 0044 §11, L4).
    pub fn for_status(lookup: impl Fn(&str) -> Option<std::ffi::OsString>) -> Result<Self, String> {
        Ok(Self {
            lock: !lock_off_from_env(&lookup)?,
            required: false,
        })
    }
}

/// Turns core dumps off, makes the process not dumpable on Linux and, when
/// `lock` and the host allows it, locks its memory on fault. An error means
/// one of the first two could not be done, and the proxy must not go on;
/// the lock never stops it (unless required: [`enforce`]).
pub fn harden_process(lock: bool) -> Result<MemoryReport, String> {
    core_dumps_off()?;
    let dumpable = not_dumpable()?;
    let locked = if lock {
        lock_memory()
    } else {
        Locked::not(TURNED_OFF)
    };
    Ok(report_of(dumpable, !lock, locked))
}

/// The report of a process whose core dumps are off.
fn report_of(dumpable: Option<bool>, lock_turned_off: bool, locked: Locked) -> MemoryReport {
    MemoryReport {
        core_dumps: CoreDumps::Off,
        dumpable,
        locked: locked.locked,
        lock_turned_off,
        vm_lck_kib: locked.vm_lck_kib,
        why: locked.why,
        lock_not_undone: locked.not_undone,
    }
}

/// Why the memory is not locked when the operator turned the lock off.
pub const TURNED_OFF: &str = "the memory lock is turned off (--no-memory-lock or KLAV_PROXY_MEMORY_LOCK=off); core dumps stay off";

/// Fails when the memory is not locked and the operator required it. A lock
/// that could be neither confirmed nor undone counts as not locked
/// (ADR 0044, decision 19).
pub fn enforce(report: &MemoryReport, required: bool) -> Result<(), String> {
    if required && report.lock_not_undone {
        return Err(format!(
            "the memory lock could not be confirmed, nor undone, and the lock is required (--require-memory-lock or {REQUIRE_ENV}=1): {}",
            report.why.as_deref().unwrap_or("no reason given")
        ));
    }
    if required && !report.locked {
        return Err(format!(
            "the memory could not be locked and the lock is required (--require-memory-lock or {REQUIRE_ENV}=1): {}",
            report.why.as_deref().unwrap_or("no reason given")
        ));
    }
    Ok(())
}

/// The warning for a proxy that runs unlocked on a host that could lock it:
/// only the reason, which holds limits and error codes. None where the
/// system has no way to lock (macOS, whose swap is encrypted: `status` says
/// so, and a warning on every start would only teach operators to ignore
/// it), and none when the operator turned the lock off. A lock that could
/// be neither confirmed nor undone has its own words, never "unlocked".
pub fn unlocked_warning(report: &MemoryReport) -> Option<String> {
    if report.lock_not_undone {
        return Some(format!(
            "klav-proxy could not confirm its memory lock and could not undo it, so it can't say whether the values it handles stay out of swap: {}",
            report.why.as_deref().unwrap_or("no reason given")
        ));
    }
    if report.locked || report.lock_turned_off || report.why.as_deref() == Some(NOT_LOCKED_HERE) {
        return None;
    }
    Some(format!(
        "klav-proxy runs with its memory unlocked, so the values it handles may reach swap: {}",
        report.why.as_deref().unwrap_or("no reason given")
    ))
}

/// The lock in words, for `status`: `turned_off` names how the switch was
/// set. The half state comes first: a report that says both `locked` and
/// `lock_not_undone` is said as the half state (decision 28), never as
/// locked; decision 19's words say neither "locked" nor "not locked".
pub fn lock_words(report: &MemoryReport, turned_off: &str) -> String {
    if report.lock_not_undone {
        format!(
            "lock could not be confirmed and could not be undone: {}",
            report.why.as_deref().unwrap_or("no reason given")
        )
    } else if report.locked {
        match report.vm_lck_kib {
            Some(kib) => format!("locked on fault (VmLck {kib} kB at start)"),
            None => "locked on fault".into(),
        }
    } else if report.lock_turned_off {
        format!("not locked: the lock is turned off ({turned_off})")
    } else {
        format!(
            "not locked: {}",
            report.why.as_deref().unwrap_or("no reason given")
        )
    }
}

/// Whether this system can lock a process's memory at all: only Linux.
pub const CAN_LOCK_HERE: bool = cfg!(target_os = "linux");

/// The stderr line `status` prints about its own process's memory (ADR 0044,
/// Omar's decision 26 of 2026-11-19, which overturned L23), from the report
/// `harden_process` gave it: no second lock attempt. Labeled as that
/// process's, never as a `serve`'s. `None` where the system can't lock
/// (`can_lock` false: macOS, own choice L25), with the switch on or off.
/// Only `KLAV_PROXY_MEMORY_LOCK` reaches `status` (L10), so it alone is
/// named.
pub fn status_own_line(report: &MemoryReport, can_lock: bool) -> Option<String> {
    if !can_lock {
        return None;
    }
    Some(format!(
        "klav-proxy: memory of this status process, not of any serve: core dumps {}, {}, {}.",
        report.core_dumps.as_str(),
        report.dumpable_words(),
        lock_words(report, &format!("{LOCK_ENV}=off"))
    ))
}

/// Whether [`REQUIRE_ENV`] asks for the lock, from `lookup` (the process's
/// environment in the binary). Unset, `0` or `false` is no; `1` or `true`
/// is yes; anything else is refused rather than guessed.
pub fn require_from_env(
    lookup: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<bool, String> {
    let Some(value) = lookup(REQUIRE_ENV) else {
        return Ok(false);
    };
    match value.to_str() {
        Some("1" | "true") => Ok(true),
        Some("0" | "false") => Ok(false),
        _ => Err(format!(
            "{REQUIRE_ENV} must be 1 or true (require the memory lock), or 0 or false; unset it for the default"
        )),
    }
}

/// Whether [`LOCK_ENV`] turns the lock off. Unset or `on` is no; `off` is
/// yes; anything else is refused rather than guessed.
pub fn lock_off_from_env(
    lookup: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<bool, String> {
    let Some(value) = lookup(LOCK_ENV) else {
        return Ok(false);
    };
    match value.to_str() {
        Some("on") => Ok(false),
        Some("off") => Ok(true),
        _ => Err(format!(
            "{LOCK_ENV} must be off (start without locking the memory) or on; unset it for the default"
        )),
    }
}

/// The number after `field` in `/proc/<pid>/status` (`VmLck:  2832 kB`).
pub fn status_number(status: &str, field: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix(field))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
}

/// What to check when a hardening step fails.
const CHECK: &str = "check that no seccomp profile, container runtime or service manager setting blocks it (docs/self-hosting.md §9.2). klav-proxy does not start without it (ADR 0044 §3.1)";

/// `RLIMIT_CORE` to `(0, 0)`, then read back.
fn core_dumps_off() -> Result<(), String> {
    setrlimit(Resource::RLIMIT_CORE, 0, 0).map_err(|e| {
        format!("cannot turn core dumps off: setrlimit(RLIMIT_CORE, 0, 0) failed with {e}; {CHECK}")
    })?;
    match getrlimit(Resource::RLIMIT_CORE) {
        Ok((0, 0)) => Ok(()),
        Ok((soft, hard)) => Err(format!(
            "core dumps are still allowed after setrlimit(RLIMIT_CORE, 0, 0): getrlimit reads soft {soft}, hard {hard}; {CHECK}"
        )),
        Err(e) => Err(format!(
            "cannot read RLIMIT_CORE back after turning core dumps off: getrlimit failed with {e}; {CHECK}"
        )),
    }
}

/// `PR_SET_DUMPABLE` 0, then read back (Linux).
#[cfg(target_os = "linux")]
fn not_dumpable() -> Result<Option<bool>, String> {
    use nix::sys::prctl;
    prctl::set_dumpable(false).map_err(|e| {
        format!(
            "cannot make the process not dumpable: prctl(PR_SET_DUMPABLE, 0) failed with {e}; {CHECK}"
        )
    })?;
    match prctl::get_dumpable() {
        Ok(false) => Ok(Some(false)),
        Ok(true) => Err(format!(
            "the process is still dumpable after prctl(PR_SET_DUMPABLE, 0): PR_GET_DUMPABLE reads 1; {CHECK}"
        )),
        Err(e) => Err(format!(
            "cannot read the dumpable flag back: prctl(PR_GET_DUMPABLE) failed with {e}; {CHECK}"
        )),
    }
}

/// No such flag outside Linux.
#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)]
fn not_dumpable() -> Result<Option<bool>, String> {
    Ok(None)
}

/// The lock's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locked {
    /// Locked, and read back.
    pub locked: bool,
    /// `VmLck` read back, in KiB.
    pub vm_lck_kib: Option<u64>,
    /// Why not.
    pub why: Option<String>,
    /// Taken, not confirmed, and not undone ([`MemoryReport::lock_not_undone`]).
    pub not_undone: bool,
}

impl Locked {
    fn not(why: impl Into<String>) -> Self {
        Self {
            locked: false,
            vm_lck_kib: None,
            why: Some(why.into()),
            not_undone: false,
        }
    }
}

/// The flags of the lock: present and future mappings, each page locked
/// once touched (`MCL_ONFAULT`, Linux 4.4). `nix` 0.31 names only the first
/// two; the third is `libc`'s own constant for the target (it is `0x8000`
/// on PowerPC), passed through unchanged.
#[cfg(target_os = "linux")]
pub fn lock_flags() -> nix::sys::mman::MlockAllFlags {
    use nix::sys::mman::MlockAllFlags;
    MlockAllFlags::MCL_CURRENT
        | MlockAllFlags::MCL_FUTURE
        | MlockAllFlags::from_bits_retain(nix::libc::MCL_ONFAULT)
}

/// The calls the lock makes, injected so that every branch and its order
/// are tested without touching the process ([`SystemLock`] on Linux).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
trait LockCalls {
    /// `getrlimit(RLIMIT_MEMLOCK)`.
    fn memlock_limit(&mut self) -> nix::Result<(rlim_t, rlim_t)>;
    /// `setrlimit(RLIMIT_MEMLOCK, soft, hard)`.
    fn set_memlock_limit(&mut self, soft: rlim_t, hard: rlim_t) -> nix::Result<()>;
    /// `mlockall` with [`lock_flags`].
    fn mlockall(&mut self) -> nix::Result<()>;
    /// `VmLck` of this process, in KiB.
    fn vm_lck_kib(&mut self) -> Option<u64>;
    /// `munlockall`.
    fn munlockall(&mut self) -> nix::Result<()>;
}

/// The real calls (Linux).
#[cfg(target_os = "linux")]
struct SystemLock;

#[cfg(target_os = "linux")]
impl LockCalls for SystemLock {
    fn memlock_limit(&mut self) -> nix::Result<(rlim_t, rlim_t)> {
        getrlimit(Resource::RLIMIT_MEMLOCK)
    }

    fn set_memlock_limit(&mut self, soft: rlim_t, hard: rlim_t) -> nix::Result<()> {
        setrlimit(Resource::RLIMIT_MEMLOCK, soft, hard)
    }

    fn mlockall(&mut self) -> nix::Result<()> {
        nix::sys::mman::mlockall(lock_flags())
    }

    fn vm_lck_kib(&mut self) -> Option<u64> {
        read_vm_lck_kib()
    }

    fn munlockall(&mut self) -> nix::Result<()> {
        nix::sys::mman::munlockall()
    }
}

/// Locks on fault when [`decide_lock`] allows it (Linux).
#[cfg(target_os = "linux")]
fn lock_memory() -> Locked {
    lock_with(&mut SystemLock)
}

/// `VmLck` of this process, in KiB.
#[cfg(target_os = "linux")]
fn read_vm_lck_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status_number(&status, "VmLck:")
}

/// The lock, start to end: the limit is read and, when [`decide_lock`]
/// allows it, raised; `mlockall` runs and the lock is read back from
/// `VmLck`. A lock that took but does not read back is undone with
/// `munlockall` **before** a raised limit is put back, so the process never
/// runs marked to lock under a finite limit (§3.2: a later allocation would
/// fail and end the proxy mid-request), nor locked while it reports
/// otherwise. A limit put back is read again, and the reason says what it
/// reads.
///
/// When the unlock itself fails, the lock could be neither confirmed nor
/// undone (ADR 0044, Omar's decision 19, which overturned L18): the proxy
/// goes on, the memory stays marked to lock, and a raised limit **stays
/// raised**, since putting a finite limit back under the lock is what
/// would end the proxy mid-request. The outcome says so
/// ([`Locked::not_undone`]); it is never an error. This branch has run
/// only against the scripted calls of the tests, never on a kernel.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn lock_with(calls: &mut impl LockCalls) -> Locked {
    let before = calls.memlock_limit();
    let raised = match decide_lock(
        || before,
        || calls.set_memlock_limit(RLIM_INFINITY, RLIM_INFINITY),
    ) {
        LockDecision::Refuse(why) => return Locked::not(why),
        LockDecision::Lock { raised } => raised,
    };
    let mut outcome = match calls.mlockall() {
        Err(Errno::EINVAL) => Locked::not(
            "this kernel refused mlockall with MCL_ONFAULT (EINVAL): locking only the pages the proxy touches needs Linux 4.4 or later, and klav-proxy never falls back to making every page resident to lock it",
        ),
        Err(e) => Locked::not(format!(
            "mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) failed ({e}) with the memlock limit unlimited"
        )),
        Ok(()) => {
            let read_back = calls.vm_lck_kib();
            if let Some(kib) = read_back.filter(|kib| *kib > 0) {
                return Locked {
                    locked: true,
                    vm_lck_kib: Some(kib),
                    why: None,
                    not_undone: false,
                };
            }
            let read = match read_back {
                Some(_) => "VmLck in /proc/self/status reads 0 kB",
                None => "VmLck could not be read back from /proc/self/status",
            };
            if let Err(e) = calls.munlockall() {
                return Locked {
                    locked: false,
                    vm_lck_kib: read_back,
                    why: Some(format!(
                        "mlockall returned success but {read}, and munlockall then failed ({e}): the lock could not be confirmed and could not be undone, so the memory stays marked to lock, unconfirmed{}. {CHECK_LOCK}",
                        if raised {
                            ", and the memlock limit it raised to unlimited stays raised, since a finite limit under the lock could make a later allocation fail"
                        } else {
                            ""
                        }
                    )),
                    not_undone: true,
                };
            }
            Locked {
                locked: false,
                vm_lck_kib: read_back,
                why: Some(format!(
                    "mlockall returned success but {read}, so the lock was undone with munlockall and is not reported"
                )),
                not_undone: false,
            }
        }
    };
    if raised && let Ok((soft, hard)) = before {
        let why = outcome.why.get_or_insert_with(String::new);
        match calls.set_memlock_limit(soft, hard) {
            Ok(()) => match calls.memlock_limit() {
                Ok((s, h)) => why.push_str(&format!(
                    "; the memlock limit it had raised to unlimited is back to {} (hard limit {})",
                    limit_words(s),
                    limit_words(h)
                )),
                Err(e) => why.push_str(&format!(
                    "; the memlock limit it had raised to unlimited was put back, but cannot be read again ({e})"
                )),
            },
            Err(e) => why.push_str(&format!(
                "; the memlock limit it raised to unlimited could not be put back ({e}), and nothing is locked"
            )),
        }
    }
    outcome
}

/// What to check when the lock can't be undone.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const CHECK_LOCK: &str = "Check that no seccomp profile or container runtime setting blocks munlockall, or turn the lock off with KLAV_PROXY_MEMORY_LOCK=off (docs/self-hosting.md §9.2)";

/// Not tried outside Linux (ADR 0044 §3.1): macOS's kernel has no
/// `mlockall` (it answers `ENOSYS`), `nix` has no `RLIMIT_MEMLOCK` there, and
/// its swap is encrypted.
#[cfg(not(target_os = "linux"))]
fn lock_memory() -> Locked {
    Locked::not(NOT_LOCKED_HERE)
}

/// Why the memory is never locked outside Linux.
pub const NOT_LOCKED_HERE: &str = "this system can't lock a process's memory (macOS has no mlockall); macOS encrypts swap, and only core dumps are turned off";

/// What to do about `mlockall` (ADR 0044 §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockDecision {
    /// The `memlock` limit was, or now is (`raised`), unlimited: lock.
    Lock {
        /// This process raised it.
        raised: bool,
    },
    /// Don't lock, and why (the limit and how to raise it).
    Refuse(String),
}

/// How to raise the limit, for the warning and `status`.
const RAISE_IT: &str = "raise it to unlimited for klav-proxy: `LimitMEMLOCK=infinity` in its systemd unit, `ulimits: memlock: -1` in Docker Compose, or `--ulimit memlock=-1:-1` with `docker run`; or turn the lock off with KLAV_PROXY_MEMORY_LOCK=off";

/// Locks only when the `memlock` limit is unlimited, or when `raise` (a
/// `setrlimit` to unlimited, soft and hard) succeeds: only the limit
/// decides, never `CAP_IPC_LOCK` (Omar's decision of 2026-11-19, L3).
/// `get` is `getrlimit`; both are injected so the rule is tested without
/// touching the process.
pub fn decide_lock(
    get: impl FnOnce() -> nix::Result<(rlim_t, rlim_t)>,
    raise: impl FnOnce() -> nix::Result<()>,
) -> LockDecision {
    let (soft, hard) = match get() {
        Ok(limits) => limits,
        Err(e) => {
            return LockDecision::Refuse(format!(
                "the memlock limit cannot be read ({e}), so the memory is not locked"
            ));
        }
    };
    if soft == RLIM_INFINITY && hard == RLIM_INFINITY {
        return LockDecision::Lock { raised: false };
    }
    match raise() {
        Ok(()) => LockDecision::Lock { raised: true },
        Err(e) => LockDecision::Refuse(format!(
            "the memlock limit is {} (hard limit {}) and this process may not raise it ({e}); locking under a finite limit could end the proxy mid-request. To lock, {RAISE_IT}",
            limit_words(soft),
            limit_words(hard)
        )),
    }
}

/// A limit in words: `unlimited`, or bytes in KiB, MiB or GiB.
fn limit_words(limit: rlim_t) -> String {
    if limit == RLIM_INFINITY {
        return "unlimited".into();
    }
    // `rlim_t` is `u64` on 64-bit Linux and macOS, `u32` on some 32-bit
    // targets.
    #[allow(clippy::useless_conversion)]
    let bytes = u64::from(limit);
    for (unit, size) in [("GiB", 1u64 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)] {
        if bytes >= size && bytes % size == 0 {
            return format!("{} {unit}", bytes / size);
        }
    }
    format!("{bytes} bytes")
}

#[cfg(test)]
// The child prints its report for the parent; it holds no value.
#[allow(clippy::print_stdout)]
pub(crate) mod tests {
    use super::*;

    /// The child this module's process tests re-run the test binary as:
    /// the variable names the mode, and only that child hardens itself.
    const CHILD: &str = "KLAV_PROXY_MEMORY_TEST_CHILD";

    /// Runs the test `name` again in a child process with [`CHILD`] set to
    /// `mode`, in `dir`.
    fn child(name: &str, mode: &str, dir: &std::path::Path) -> std::process::Output {
        std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                name,
                "--nocapture",
                "--test-threads=1",
                "--include-ignored",
            ])
            .env(CHILD, mode)
            .current_dir(dir)
            .output()
            .expect("run the child")
    }

    fn child_mode() -> Option<String> {
        std::env::var(CHILD).ok()
    }

    /// Whether a child of this process locks (Linux): the rule of
    /// [`decide_lock`] applied to the limit it inherits. Unlimited, or a
    /// soft limit under an unlimited hard one, or `CAP_SYS_RESOURCE` (bit
    /// 24 of `CapEff`), which raises any limit. `Err` says why not.
    #[cfg(target_os = "linux")]
    pub(crate) fn a_child_may_lock() -> Result<(), String> {
        let (soft, hard) = getrlimit(Resource::RLIMIT_MEMLOCK).expect("getrlimit");
        if hard == RLIM_INFINITY {
            return Ok(());
        }
        let status = std::fs::read_to_string("/proc/self/status").expect("status");
        let cap_eff = status
            .lines()
            .find_map(|l| l.strip_prefix("CapEff:"))
            .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
            .expect("CapEff");
        if cap_eff & (1 << 24) != 0 {
            return Ok(());
        }
        Err(format!(
            "this process's memlock limit is {} (hard limit {}) and it has no CAP_SYS_RESOURCE, so no child may raise it to unlimited",
            limit_words(soft),
            limit_words(hard)
        ))
    }

    /// For the tests that need a lock: they are `#[ignore]`d, and CI's
    /// `test` task runs them with a raised limit. Run without one, they
    /// fail here rather than pass having checked nothing.
    #[cfg(target_os = "linux")]
    pub(crate) fn require_a_child_that_locks() {
        if let Err(why) = a_child_may_lock() {
            panic!(
                "precondition not met: {why}. Run it with an unlimited memlock limit (`prlimit --memlock=unlimited:unlimited -- cargo test …`, as CI's test task does)"
            );
        }
    }

    /// The child's report, from its `KLAV-MEMORY-REPORT` line.
    fn child_report(out: &std::process::Output) -> MemoryReport {
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let line = stdout
            .lines()
            .find_map(|l| l.split_once("KLAV-MEMORY-REPORT ").map(|(_, r)| r))
            .unwrap_or_else(|| panic!("no report: {stdout}"));
        serde_json::from_str(line).expect("report")
    }

    /// On a line of its own: the harness prints the test's name before
    /// it, without a line break.
    fn print_report(report: &MemoryReport) {
        println!(
            "\nKLAV-MEMORY-REPORT {}",
            serde_json::to_string(report).expect("json")
        );
    }

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<std::ffi::OsString> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| pairs.iter().find(|(k, _)| k == name).map(|(_, v)| v.into())
    }

    #[test]
    fn an_unlimited_limit_locks_without_raising() {
        let decision = decide_lock(
            || Ok((RLIM_INFINITY, RLIM_INFINITY)),
            || panic!("an unlimited limit needs no raise"),
        );
        assert_eq!(decision, LockDecision::Lock { raised: false });
    }

    #[test]
    fn a_limit_that_can_be_raised_locks() {
        // A soft limit under an unlimited hard one, as any process may
        // raise, and a finite hard limit with the privilege to raise it.
        for limits in [(64 << 10, RLIM_INFINITY), (8 << 20, 8 << 20)] {
            let raised = std::cell::Cell::new(false);
            let decision = decide_lock(
                || Ok(limits),
                || {
                    raised.set(true);
                    Ok(())
                },
            );
            assert_eq!(decision, LockDecision::Lock { raised: true }, "{limits:?}");
            assert!(raised.get());
        }
    }

    #[test]
    fn a_finite_limit_that_cannot_be_raised_is_not_locked_and_says_how_to_raise_it() {
        // Also with CAP_IPC_LOCK, which the rule never asks about (L3): only
        // the limit decides.
        let decision = decide_lock(|| Ok((8 << 20, 8 << 20)), || Err(Errno::EPERM));
        let LockDecision::Refuse(why) = decision else {
            panic!("a finite limit must not be locked")
        };
        assert!(
            why.contains("memlock limit is 8 MiB (hard limit 8 MiB)"),
            "{why}"
        );
        assert!(why.contains("EPERM"), "{why}");
        assert!(why.contains("LimitMEMLOCK=infinity"), "{why}");
        assert!(why.contains("memlock: -1"), "{why}");
        assert!(why.contains("--ulimit memlock=-1:-1"), "{why}");
        assert!(why.contains("KLAV_PROXY_MEMORY_LOCK=off"), "{why}");
        // A limit that cannot be read is not locked either.
        let unread = decide_lock(|| Err(Errno::EINVAL), || panic!("never raised"));
        assert!(matches!(unread, LockDecision::Refuse(why) if why.contains("cannot be read")));
    }

    #[test]
    fn limits_read_in_words() {
        assert_eq!(limit_words(RLIM_INFINITY), "unlimited");
        assert_eq!(limit_words(64 << 10), "64 KiB");
        assert_eq!(limit_words(8 << 20), "8 MiB");
        assert_eq!(limit_words(2 << 30), "2 GiB");
        assert_eq!(limit_words(1000), "1000 bytes");
        assert_eq!(limit_words(0), "0 bytes");
    }

    /// The lock's calls, scripted: each answer is given up front, and every
    /// call is written down in order.
    struct Script {
        limits: Vec<nix::Result<(rlim_t, rlim_t)>>,
        set: Vec<nix::Result<()>>,
        mlockall: nix::Result<()>,
        vm_lck: Option<u64>,
        munlockall: nix::Result<()>,
        calls: Vec<String>,
    }

    impl Script {
        /// A limit of `limits`; raising it and every later call succeed,
        /// and `VmLck` reads `vm_lck`.
        fn new(limits: (rlim_t, rlim_t), vm_lck: Option<u64>) -> Self {
            Self {
                limits: vec![Ok(limits), Ok(limits)],
                set: vec![Ok(()), Ok(())],
                mlockall: Ok(()),
                vm_lck,
                munlockall: Ok(()),
                calls: Vec::new(),
            }
        }
    }

    impl LockCalls for Script {
        fn memlock_limit(&mut self) -> nix::Result<(rlim_t, rlim_t)> {
            self.calls.push("getrlimit".into());
            self.limits.remove(0)
        }

        fn set_memlock_limit(&mut self, soft: rlim_t, hard: rlim_t) -> nix::Result<()> {
            self.calls.push(format!(
                "setrlimit {} {}",
                limit_words(soft),
                limit_words(hard)
            ));
            self.set.remove(0)
        }

        fn mlockall(&mut self) -> nix::Result<()> {
            self.calls.push("mlockall".into());
            self.mlockall
        }

        fn vm_lck_kib(&mut self) -> Option<u64> {
            self.calls.push("VmLck".into());
            self.vm_lck
        }

        fn munlockall(&mut self) -> nix::Result<()> {
            self.calls.push("munlockall".into());
            self.munlockall
        }
    }

    const FINITE: (rlim_t, rlim_t) = (64 << 10, RLIM_INFINITY);

    /// Decision 11 and L11: a kernel that refuses `MCL_ONFAULT` is a lock
    /// that could not be taken; success counts only once `VmLck` reads more
    /// than 0.
    #[test]
    fn the_lock_is_reported_only_when_it_took_and_reads_back() {
        let mut locked = Script::new((RLIM_INFINITY, RLIM_INFINITY), Some(2832));
        assert_eq!(
            lock_with(&mut locked),
            Locked {
                locked: true,
                vm_lck_kib: Some(2832),
                why: None,
                not_undone: false,
            }
        );
        assert_eq!(locked.calls, ["getrlimit", "mlockall", "VmLck"]);
        // Raised, locked and read back: the limit stays unlimited.
        let mut raised = Script::new(FINITE, Some(2832));
        assert!(lock_with(&mut raised).locked);
        assert_eq!(
            raised.calls,
            [
                "getrlimit",
                "setrlimit unlimited unlimited",
                "mlockall",
                "VmLck"
            ]
        );
        for (errno, words) in [
            (Errno::EINVAL, "Linux 4.4"),
            (Errno::EPERM, "EPERM"),
            (Errno::ENOMEM, "ENOMEM"),
        ] {
            let mut failed = Script::new((RLIM_INFINITY, RLIM_INFINITY), Some(2832));
            failed.mlockall = Err(errno);
            let outcome = lock_with(&mut failed);
            assert!(!outcome.locked);
            let why = outcome.why.expect("why");
            assert!(why.contains(words), "{why}");
            // Nothing took, so nothing is read back or undone.
            assert_eq!(failed.calls, ["getrlimit", "mlockall"]);
        }
    }

    /// Finding 1 of the re-review of #466: a lock that took but does not
    /// read back is undone with `munlockall` before a raised limit is put
    /// back, and the limit is read again; the report says unlocked, why,
    /// and what the limit reads.
    #[test]
    fn a_lock_that_does_not_read_back_is_undone_before_the_limit_goes_back() {
        for (vm_lck, read) in [(None, "could not be read back"), (Some(0), "reads 0 kB")] {
            let mut script = Script::new(FINITE, vm_lck);
            let outcome = lock_with(&mut script);
            assert!(!outcome.not_undone);
            assert_eq!(
                script.calls,
                [
                    "getrlimit",
                    "setrlimit unlimited unlimited",
                    "mlockall",
                    "VmLck",
                    "munlockall",
                    "setrlimit 64 KiB unlimited",
                    "getrlimit"
                ],
                "{read}"
            );
            assert!(!outcome.locked);
            assert_eq!(outcome.vm_lck_kib, vm_lck);
            let why = outcome.why.expect("why");
            assert!(why.contains(read), "{why}");
            assert!(why.contains("undone with munlockall"), "{why}");
            assert!(
                why.contains("is back to 64 KiB (hard limit unlimited)"),
                "{why}"
            );
            // A required lock stops the start with that reason.
            let report = report_of(
                Some(false),
                false,
                Locked {
                    why: Some(why),
                    ..outcome
                },
            );
            assert!(
                enforce(&report, true)
                    .expect_err("required")
                    .contains("undone")
            );
        }
        // Not raised: undone, and no limit to put back.
        let mut unraised = Script::new((RLIM_INFINITY, RLIM_INFINITY), None);
        assert!(!lock_with(&mut unraised).locked);
        assert_eq!(
            unraised.calls,
            ["getrlimit", "mlockall", "VmLck", "munlockall"]
        );
        // The limit read again after it went back: what it reads, said.
        let mut unread = Script::new(FINITE, None);
        unread.limits = vec![Ok(FINITE), Err(Errno::EIO)];
        let why = lock_with(&mut unread).why.expect("why");
        assert!(why.contains("cannot be read again (EIO"), "{why}");
        // A limit that can't be put back is said, unlocked.
        let mut stuck = Script::new(FINITE, None);
        stuck.set = vec![Ok(()), Err(Errno::EPERM)];
        let outcome = lock_with(&mut stuck);
        assert!(!outcome.locked);
        assert!(
            outcome
                .why
                .expect("why")
                .contains("could not be put back (EPERM")
        );
    }

    /// Decision 19 (overturning L18): a lock that took, doesn't read back
    /// and can't be undone is no error. The proxy goes on, the limit it
    /// raised is never put back under the lock (nor read again), and the
    /// report, the warning, `enforce` and the log say "could not be
    /// confirmed and could not be undone", never "locked" and never plainly
    /// "unlocked". Run only against these scripted calls, never on a kernel.
    #[test]
    fn a_lock_that_can_be_neither_read_back_nor_undone_goes_on_and_says_so() {
        for (limits, vm_lck, calls) in [
            (
                FINITE,
                None,
                &[
                    "getrlimit",
                    "setrlimit unlimited unlimited",
                    "mlockall",
                    "VmLck",
                    "munlockall",
                ][..],
            ),
            (
                (RLIM_INFINITY, RLIM_INFINITY),
                Some(0),
                &["getrlimit", "mlockall", "VmLck", "munlockall"][..],
            ),
        ] {
            let raised = limits == FINITE;
            let mut script = Script::new(limits, vm_lck);
            script.munlockall = Err(Errno::EPERM);
            let outcome = lock_with(&mut script);
            // The order, exactly: nothing after the failed unlock, so the
            // raised limit stays unlimited.
            assert_eq!(script.calls, calls);
            assert!(outcome.not_undone && !outcome.locked, "{outcome:?}");
            assert_eq!(outcome.vm_lck_kib, vm_lck);
            let report = report_of(Some(false), false, outcome);
            let why = report.why.clone().expect("why");
            assert!(why.contains("munlockall then failed (EPERM"), "{why}");
            assert!(
                why.contains("could not be confirmed and could not be undone"),
                "{why}"
            );
            assert_eq!(
                why.contains("the memlock limit it raised to unlimited stays raised"),
                raised,
                "{why}"
            );
            for words in [&why, &unlocked_warning(&report).expect("warns")] {
                assert!(!words.contains("unlocked"), "{words}");
                assert!(!words.contains("not locked"), "{words}");
                assert!(!words.contains("put back"), "{words}");
            }
            assert!(
                unlocked_warning(&report).expect("warns").starts_with(
                    "klav-proxy could not confirm its memory lock and could not undo it"
                ),
            );
            // Not required: the start goes on. Required: fatal, as for any
            // lock that isn't confirmed.
            enforce(&report, false).expect("goes on");
            let err = enforce(&report, true).expect_err("required");
            assert!(
                err.starts_with(
                    "the memory lock could not be confirmed, nor undone, and the lock is required"
                ),
                "{err}"
            );
            // In the record, one more field, and the version stays 1 (L17).
            let json = serde_json::to_value(&report).expect("json");
            assert_eq!(json["locked"], false);
            assert_eq!(json["lock_not_undone"], true);
        }
    }

    /// The report of decision 19's state as [`lock_with`] really builds it
    /// (a raised limit, `VmLck` unreadable, `munlockall` refused): for the
    /// tests of the words `status` prints, never a hand-written reason.
    pub(crate) fn half_state_report() -> MemoryReport {
        let mut script = Script::new(FINITE, None);
        script.munlockall = Err(Errno::EPERM);
        let report = report_of(Some(false), false, lock_with(&mut script));
        assert!(report.lock_not_undone && !report.locked, "{report:?}");
        report
    }

    /// Decision 28: a record that says both `locked: true` and
    /// `lock_not_undone: true` reads as the half state, `locked` `false`; a
    /// record of the half state as written survives its file.
    #[test]
    fn a_record_of_the_half_state_survives_its_file_and_never_reads_locked() {
        let record = MemoryRecord {
            report: half_state_report(),
            since: 42,
        };
        let bytes = record.to_file().expect("bytes");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(json["v"], 1);
        assert_eq!(json["locked"], false);
        assert_eq!(json["lock_not_undone"], true);
        assert_eq!(MemoryRecord::from_file(&bytes), Ok(record.clone()));
        // Contradictory: both true. Read as the half state.
        let both = br#"{"v":1,"core_dumps":"off","dumpable":false,"locked":true,"vm_lck_kib":2832,"why":"w","lock_not_undone":true,"since":1}"#;
        let read = MemoryRecord::from_file(both).expect("reads");
        assert!(
            !read.report.locked && read.report.lock_not_undone,
            "{read:?}"
        );
        assert_eq!(read.report.vm_lck_kib, Some(2832));
        assert_eq!(
            serde_json::to_value(&read).expect("json")["locked"],
            false,
            "status --json must not say locked"
        );
        assert!(
            lock_words(&read.report, "x")
                .starts_with("lock could not be confirmed and could not be undone: w")
        );
        // `lock_not_undone: false` changes nothing.
        let plain = br#"{"v":1,"core_dumps":"off","dumpable":false,"locked":true,"lock_not_undone":false,"since":1}"#;
        assert!(MemoryRecord::from_file(plain).expect("reads").report.locked);
    }

    /// Decision 26: `status`'s line about its own process, in each state,
    /// from the outcome `lock_with` builds through the scripted calls (the
    /// half state's reason included), labeled as that process's; nothing
    /// where the system can't lock (L25), with the switch on or off.
    #[test]
    fn the_status_line_says_what_its_own_process_got() {
        const START: &str = "klav-proxy: memory of this status process, not of any serve: core dumps off, not dumpable, ";
        let mut locked = Script::new((RLIM_INFINITY, RLIM_INFINITY), Some(20196));
        let locked = report_of(Some(false), false, lock_with(&mut locked));
        let mut refused = Script::new((64 << 10, 64 << 10), None);
        refused.set = vec![Err(Errno::EPERM)];
        let refused = report_of(Some(false), false, lock_with(&mut refused));
        let off = report_of(Some(false), true, Locked::not(TURNED_OFF));
        let half = half_state_report();
        let half_why = half.why.clone().expect("why");
        for (report, want) in [
            (&locked, "locked on fault (VmLck 20196 kB at start).".to_owned()),
            (
                &refused,
                "not locked: the memlock limit is 64 KiB (hard limit 64 KiB) and this process may not raise it (EPERM: Operation not permitted); locking under a finite limit could end the proxy mid-request. To lock, raise it to unlimited for klav-proxy: `LimitMEMLOCK=infinity` in its systemd unit, `ulimits: memlock: -1` in Docker Compose, or `--ulimit memlock=-1:-1` with `docker run`; or turn the lock off with KLAV_PROXY_MEMORY_LOCK=off.".to_owned(),
            ),
            (
                &off,
                "not locked: the lock is turned off (KLAV_PROXY_MEMORY_LOCK=off).".to_owned(),
            ),
            (
                &half,
                format!("lock could not be confirmed and could not be undone: {half_why}."),
            ),
        ] {
            assert_eq!(
                status_own_line(report, true).as_deref(),
                Some(format!("{START}{want}").as_str())
            );
            // Never a serve's words, and never on macOS.
            assert!(!status_own_line(report, true).expect("line").contains("recorded"));
            assert_eq!(status_own_line(report, false), None);
        }
        assert!(
            half_why.contains("munlockall then failed (EPERM"),
            "{half_why}"
        );
        // What macOS's `harden_process` returns, with the switch on or off.
        let mac = MemoryReport {
            dumpable: None,
            why: Some(NOT_LOCKED_HERE.into()),
            ..refused
        };
        assert_eq!(
            status_own_line(&mac, CAN_LOCK_HERE).is_some(),
            cfg!(target_os = "linux")
        );
        let mac_off = MemoryReport {
            dumpable: None,
            ..off
        };
        assert_eq!(
            status_own_line(&mac_off, CAN_LOCK_HERE).is_some(),
            cfg!(target_os = "linux")
        );
    }

    /// A refused limit: nothing locked, nothing undone, nothing put back.
    #[test]
    fn a_refused_limit_never_reaches_mlockall() {
        let mut script = Script::new((8 << 20, 8 << 20), Some(2832));
        script.set = vec![Err(Errno::EPERM)];
        let outcome = lock_with(&mut script);
        assert!(!outcome.locked);
        assert!(outcome.why.expect("why").contains("8 MiB"));
        assert_eq!(script.calls, ["getrlimit", "setrlimit unlimited unlimited"]);
    }

    #[test]
    fn status_numbers_are_read_from_their_line() {
        let status = "Name:\tklav-proxy\nVmLck:\t    2832 kB\nThreads:\t17\n";
        assert_eq!(status_number(status, "VmLck:"), Some(2832));
        assert_eq!(status_number(status, "Threads:"), Some(17));
        assert_eq!(status_number(status, "VmRSS:"), None);
        assert_eq!(status_number("VmLck:\tlots kB\n", "VmLck:"), None);
    }

    #[test]
    fn the_require_variable_is_one_or_zero() {
        let none = |_: &str| None;
        assert_eq!(require_from_env(none), Ok(false));
        for (value, want) in [("1", true), ("true", true), ("0", false), ("false", false)] {
            assert_eq!(
                require_from_env(env_of(&[(REQUIRE_ENV, value)])),
                Ok(want),
                "{value}"
            );
        }
        for value in ["", "yes", "2", "TRUE", "on", "off"] {
            let err = require_from_env(env_of(&[(REQUIRE_ENV, value)])).expect_err(value);
            assert!(err.contains(REQUIRE_ENV), "{err}");
        }
    }

    /// L9, accepted by Omar on 2026-11-19 (decision 21): the switch is `on`
    /// or `off`, nothing else.
    #[test]
    fn the_lock_variable_is_on_or_off() {
        assert_eq!(lock_off_from_env(|_: &str| None), Ok(false));
        assert_eq!(lock_off_from_env(env_of(&[(LOCK_ENV, "on")])), Ok(false));
        assert_eq!(lock_off_from_env(env_of(&[(LOCK_ENV, "off")])), Ok(true));
        for value in ["", "0", "false", "OFF", "no", "1"] {
            let err = lock_off_from_env(env_of(&[(LOCK_ENV, value)])).expect_err(value);
            assert!(err.contains(LOCK_ENV), "{err}");
        }
    }

    /// Decision 12 and L10: off and required at once is refused, whichever
    /// way each was asked; `status` honours the switch and never the
    /// requirement.
    #[test]
    fn the_lock_turned_off_and_required_is_refused() {
        let start = |off: bool, req: bool, env: &[(&str, &str)]| {
            LockChoice::for_start(off, req, env_of(env))
        };
        assert_eq!(
            start(false, false, &[]),
            Ok(LockChoice {
                lock: true,
                required: false
            })
        );
        assert_eq!(
            start(true, false, &[]),
            Ok(LockChoice {
                lock: false,
                required: false
            })
        );
        assert_eq!(
            start(false, false, &[(LOCK_ENV, "off")]),
            Ok(LockChoice {
                lock: false,
                required: false
            })
        );
        assert_eq!(
            start(false, false, &[(REQUIRE_ENV, "1")]),
            Ok(LockChoice {
                lock: true,
                required: true
            })
        );
        for (off, req, env, names) in [
            (
                true,
                true,
                vec![],
                ["--no-memory-lock", "--require-memory-lock"],
            ),
            (
                false,
                false,
                vec![(LOCK_ENV, "off"), (REQUIRE_ENV, "true")],
                [LOCK_ENV, REQUIRE_ENV],
            ),
            (
                true,
                false,
                vec![(REQUIRE_ENV, "1")],
                ["--no-memory-lock", REQUIRE_ENV],
            ),
            (
                false,
                true,
                vec![(LOCK_ENV, "off")],
                [LOCK_ENV, "--require-memory-lock"],
            ),
        ] {
            let err = start(off, req, &env).expect_err("off and required");
            for name in names {
                assert!(err.contains(name), "{name}: {err}");
            }
        }
        // A value neither accepts is refused even when a flag decides.
        assert!(start(true, false, &[(LOCK_ENV, "no")]).is_err());
        assert!(start(false, true, &[(REQUIRE_ENV, "yes")]).is_err());
        // `status`: the switch, never the requirement.
        assert_eq!(
            LockChoice::for_status(env_of(&[(LOCK_ENV, "off"), (REQUIRE_ENV, "1")])),
            Ok(LockChoice {
                lock: false,
                required: false
            })
        );
        assert_eq!(
            LockChoice::for_status(env_of(&[(REQUIRE_ENV, "yes")])),
            Ok(LockChoice {
                lock: true,
                required: false
            })
        );
        assert!(LockChoice::for_status(env_of(&[(LOCK_ENV, "no")])).is_err());
    }

    #[test]
    fn an_unlocked_start_is_fatal_only_when_required() {
        let unlocked = MemoryReport {
            core_dumps: CoreDumps::Off,
            dumpable: Some(false),
            locked: false,
            lock_turned_off: false,
            vm_lck_kib: None,
            why: Some("the memlock limit is 8 MiB".into()),
            lock_not_undone: false,
        };
        enforce(&unlocked, false).expect("not required");
        let err = enforce(&unlocked, true).expect_err("required");
        assert!(err.contains("the memlock limit is 8 MiB"), "{err}");
        assert!(
            unlocked_warning(&unlocked)
                .expect("warns")
                .contains("8 MiB")
        );
        let locked = MemoryReport {
            locked: true,
            vm_lck_kib: Some(2832),
            why: None,
            ..unlocked.clone()
        };
        enforce(&locked, true).expect("locked");
        assert_eq!(unlocked_warning(&locked), None);
        // No warning where the system can't lock at all, but a required
        // lock still stops the start.
        let mac = MemoryReport {
            dumpable: None,
            locked: false,
            vm_lck_kib: None,
            why: Some(NOT_LOCKED_HERE.into()),
            ..locked
        };
        assert_eq!(unlocked_warning(&mac), None);
        assert!(enforce(&mac, true).is_err());
        // Nor when the operator turned the lock off.
        let off = MemoryReport {
            lock_turned_off: true,
            why: Some(TURNED_OFF.into()),
            ..unlocked
        };
        assert_eq!(unlocked_warning(&off), None);
    }

    #[test]
    fn the_report_has_the_shape_status_shows() {
        let report = MemoryReport {
            core_dumps: CoreDumps::Off,
            dumpable: Some(false),
            locked: false,
            lock_turned_off: false,
            vm_lck_kib: None,
            why: Some("the memlock limit is 8 MiB".into()),
            lock_not_undone: false,
        };
        assert_eq!(
            serde_json::to_value(&report).expect("json"),
            serde_json::json!({
                "core_dumps": "off",
                "dumpable": false,
                "locked": false,
                "why": "the memlock limit is 8 MiB",
            })
        );
        let locked = MemoryReport {
            dumpable: None,
            locked: true,
            vm_lck_kib: Some(2832),
            why: None,
            ..report.clone()
        };
        assert_eq!(
            serde_json::to_value(&locked).expect("json"),
            serde_json::json!({"core_dumps": "off", "dumpable": null, "locked": true, "vm_lck_kib": 2832})
        );
        let off = MemoryReport {
            lock_turned_off: true,
            why: Some(TURNED_OFF.into()),
            ..report
        };
        assert_eq!(
            serde_json::to_value(&off).expect("json")["lock_turned_off"],
            true
        );
    }

    #[test]
    fn the_record_survives_its_file_and_another_version_is_refused() {
        let record = MemoryRecord {
            report: MemoryReport {
                core_dumps: CoreDumps::Off,
                dumpable: Some(false),
                locked: true,
                lock_turned_off: false,
                vm_lck_kib: Some(2832),
                why: None,
                lock_not_undone: false,
            },
            since: 42,
        };
        let bytes = record.to_file().expect("bytes");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).expect("json"),
            serde_json::json!({
                "v": 1, "core_dumps": "off", "dumpable": false, "locked": true,
                "vm_lck_kib": 2832, "since": 42,
            })
        );
        assert_eq!(MemoryRecord::from_file(&bytes), Ok(record));
        // The first round's records, without the new fields, still read.
        let first = br#"{"v":1,"core_dumps":"off","dumpable":false,"locked":true,"since":1}"#;
        let read = MemoryRecord::from_file(first).expect("first round");
        assert!(read.report.locked && !read.report.lock_turned_off);
        let other = br#"{"v":2,"core_dumps":"off","dumpable":false,"locked":true,"since":1}"#;
        assert_eq!(
            MemoryRecord::from_file(other),
            Err("unknown version 2".into())
        );
    }

    /// The process test: a child hardens itself and reports what took
    /// effect. `getrlimit(RLIMIT_CORE)` is `(0, 0)`; on Linux the process is
    /// not dumpable and can still read what the proxy and the standard
    /// library read under `/proc/self` (ADR 0044 §3.1, "to confirm").
    #[test]
    fn a_hardened_child_has_no_core_limit_and_is_not_dumpable() {
        const NAME: &str = "memory::tests::a_hardened_child_has_no_core_limit_and_is_not_dumpable";
        if child_mode().as_deref() == Some("report") {
            let report = harden_process(true).expect("harden");
            assert_eq!(getrlimit(Resource::RLIMIT_CORE).expect("getrlimit"), (0, 0));
            // Lowered for good: the process can't raise it back, unless it
            // runs as root (CAP_SYS_RESOURCE), which can raise any limit.
            if !nix::unistd::geteuid().is_root() {
                assert!(setrlimit(Resource::RLIMIT_CORE, 0, 1 << 20).is_err());
            }
            #[cfg(target_os = "linux")]
            {
                assert!(!nix::sys::prctl::get_dumpable().expect("get_dumpable"));
                assert_eq!(report.dumpable, Some(false));
                // What the standard library and glibc read about the process
                // itself: the thread count and the main thread's stack.
                for path in ["/proc/self/maps", "/proc/self/status", "/proc/self/cgroup"] {
                    std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
                }
                std::fs::read_link("/proc/self/exe").expect("exe");
                std::fs::read_dir("/proc/self/fd").expect("fd").count();
                std::thread::available_parallelism().expect("parallelism");
                std::thread::spawn(|| ()).join().expect("a thread starts");
                // Locked means read back: `VmLck` is still more than 0.
                if report.locked {
                    assert!(report.vm_lck_kib.expect("vm_lck") > 0);
                    assert!(read_vm_lck_kib().expect("VmLck") > 0);
                }
            }
            #[cfg(not(target_os = "linux"))]
            assert_eq!(report.dumpable, None);
            #[cfg(target_os = "macos")]
            {
                // ADR 0044 §3.1, "to confirm": macOS's kernel has no
                // mlockall. Tried here, in the child only.
                use nix::sys::mman::{MlockAllFlags, mlockall};
                assert_eq!(
                    mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE),
                    Err(Errno::ENOSYS)
                );
                assert!(!report.locked);
                assert_eq!(report.why.as_deref(), Some(NOT_LOCKED_HERE));
            }
            print_report(&report);
            return;
        }
        if child_mode().is_some() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let report = child_report(&child(NAME, "report", dir.path()));
        assert_eq!(report.core_dumps, CoreDumps::Off);
        assert!(!report.lock_turned_off);
        assert_eq!(report.locked, report.why.is_none(), "{report:?}");
        // The branch the inherited limit decides, never a skip: locked
        // where a child may lock, and unlocked with the limit otherwise.
        #[cfg(target_os = "linux")]
        match a_child_may_lock() {
            Ok(()) => assert!(report.locked, "{report:?}"),
            Err(_) => assert!(
                report
                    .why
                    .as_deref()
                    .is_some_and(|w| w.contains("memlock limit is")),
                "{report:?}"
            ),
        }
        #[cfg(not(target_os = "linux"))]
        assert!(!report.locked);
        // This test process itself was never hardened.
        #[cfg(target_os = "linux")]
        assert!(nix::sys::prctl::get_dumpable().expect("get_dumpable"));
    }

    /// Decision 12: with the lock turned off, nothing is locked and the
    /// limit is never raised; core dumps are still off.
    #[test]
    fn a_child_with_the_lock_turned_off_locks_nothing_and_keeps_core_dumps_off() {
        const NAME: &str = "memory::tests::a_child_with_the_lock_turned_off_locks_nothing_and_keeps_core_dumps_off";
        if child_mode().as_deref() == Some("off") {
            #[cfg(target_os = "linux")]
            let before = getrlimit(Resource::RLIMIT_MEMLOCK).expect("memlock");
            let report = harden_process(false).expect("harden");
            assert_eq!(getrlimit(Resource::RLIMIT_CORE).expect("getrlimit"), (0, 0));
            #[cfg(target_os = "linux")]
            {
                assert_eq!(
                    getrlimit(Resource::RLIMIT_MEMLOCK).expect("memlock"),
                    before,
                    "the limit is never raised"
                );
                assert_eq!(read_vm_lck_kib(), Some(0));
            }
            print_report(&report);
            return;
        }
        if child_mode().is_some() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let report = child_report(&child(NAME, "off", dir.path()));
        assert_eq!(report.core_dumps, CoreDumps::Off);
        assert!(report.lock_turned_off && !report.locked, "{report:?}");
        assert_eq!(report.vm_lck_kib, None);
        assert_eq!(report.why.as_deref(), Some(TURNED_OFF));
        assert_eq!(unlocked_warning(&report), None);
    }

    /// Decision 11: locked on fault, 64 threads' stacks are not made
    /// resident. With every page locked as it is mapped, each thread's
    /// 2 MiB stack would be (at least 128 MiB for 64 threads).
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs a memlock limit a child may make unlimited; CI's test task runs it with one"]
    fn a_locked_child_does_not_make_untouched_stacks_resident() {
        const NAME: &str = "memory::tests::a_locked_child_does_not_make_untouched_stacks_resident";
        const THREADS: usize = 64;
        if child_mode().as_deref() == Some("stacks") {
            let report = harden_process(true).expect("harden");
            assert!(report.locked, "{report:?}");
            let rss = || {
                let status = std::fs::read_to_string("/proc/self/status").expect("status");
                status_number(&status, "VmRSS:").expect("VmRSS")
            };
            let before = rss();
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    let rx = std::sync::Arc::clone(&rx);
                    std::thread::Builder::new()
                        .stack_size(2 << 20)
                        .spawn(move || {
                            let _ = rx
                                .lock()
                                .map(|r| r.recv_timeout(std::time::Duration::from_secs(5)));
                        })
                        .expect("thread")
                })
                .collect();
            std::thread::sleep(std::time::Duration::from_millis(200));
            let with_threads = rss();
            drop(tx);
            for h in handles {
                h.join().expect("join");
            }
            println!("\nKLAV-STACKS {before} {with_threads}");
            return;
        }
        if child_mode().is_some() {
            return;
        }
        require_a_child_that_locks();
        let dir = tempfile::tempdir().expect("tempdir");
        let out = child(NAME, "stacks", dir.path());
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let (before, with_threads) = stdout
            .lines()
            .find_map(|l| l.strip_prefix("KLAV-STACKS "))
            .and_then(|l| l.split_once(' '))
            .map(|(a, b)| {
                (
                    a.parse::<u64>().expect("kib"),
                    b.parse::<u64>().expect("kib"),
                )
            })
            .unwrap_or_else(|| panic!("no measure: {stdout}"));
        // 32 MiB: a quarter of what 64 populated stacks would take.
        assert!(
            with_threads.saturating_sub(before) < 32 << 10,
            "{THREADS} threads made {} KiB resident under the lock ({before} → {with_threads} KiB)",
            with_threads - before
        );
    }

    /// No core file after `SIGABRT` with a `core_pattern` that writes a file
    /// (ADR 0044, layer 1): a hardened child aborts in an empty directory,
    /// which stays empty, while an unhardened control leaves a core. By
    /// hand, on a Linux host whose pattern is a plain relative file name
    /// (the kernel's default, `core`) and whose hard core limit lets the
    /// control dump: `cargo test -p klav-proxy --lib
    /// memory::tests::a_hardened_child_leaves_no_core_file_after_abort --
    /// --ignored`. Elsewhere it fails on its precondition. CI's runner
    /// pipes its cores to apport, so CI doesn't run it. The piped case
    /// (systemd-coredump) is the ignored test below.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs a core_pattern that writes a file and a hard core limit above 0; run by hand"]
    fn a_hardened_child_leaves_no_core_file_after_abort() {
        const NAME: &str = "memory::tests::a_hardened_child_leaves_no_core_file_after_abort";
        match child_mode().as_deref() {
            Some("abort") => {
                harden_process(true).expect("harden");
                std::process::abort();
            }
            Some("abort-unhardened") => {
                // The control: as many core bytes as the hard limit allows.
                let (_, hard) = getrlimit(Resource::RLIMIT_CORE).expect("getrlimit");
                setrlimit(Resource::RLIMIT_CORE, hard, hard).expect("setrlimit");
                std::process::abort();
            }
            Some(_) => return,
            None => {}
        }
        let pattern = std::fs::read_to_string("/proc/sys/kernel/core_pattern").unwrap_or_default();
        let pattern = pattern.trim();
        assert!(
            !(pattern.is_empty() || pattern.starts_with('|') || pattern.contains('/')),
            "precondition not met: core_pattern {pattern:?} does not write a file in the working directory (see the ignored systemd-coredump test)"
        );
        let (_, hard) = getrlimit(Resource::RLIMIT_CORE).expect("getrlimit");
        assert!(
            hard > 0,
            "precondition not met: the hard core limit is 0, so even the control can't dump"
        );
        let control = tempfile::tempdir().expect("tempdir");
        let out = child(NAME, "abort-unhardened", control.path());
        assert!(!out.status.success());
        assert!(
            std::fs::read_dir(control.path()).expect("dir").count() > 0,
            "the unhardened control left no core file with core_pattern {pattern:?} and a hard core limit of {hard}: the test can't tell a hardened process from one that could not dump"
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let out = child(NAME, "abort", dir.path());
        assert!(!out.status.success(), "the child aborts");
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .expect("dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert!(left.is_empty(), "a hardened process left {left:?}");
    }

    /// By hand, on a Linux host whose `core_pattern` pipes to
    /// systemd-coredump (`|/usr/lib/systemd/systemd-coredump …`): a hardened
    /// child that aborts leaves no entry in `coredumpctl`, while an
    /// unhardened control with an unlimited core limit does. Run it with
    /// `cargo test -p klav-proxy --lib memory::tests::systemd_coredump -- --ignored --nocapture`
    /// as a user who may read the journal (in the `systemd-journal` group, or
    /// with `sudo -E`), with `ulimit -c unlimited` first so the control can
    /// dump.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs a Linux host with systemd-coredump; run by hand"]
    fn systemd_coredump_collects_nothing_from_a_hardened_process() {
        const NAME: &str =
            "memory::tests::systemd_coredump_collects_nothing_from_a_hardened_process";
        match child_mode().as_deref() {
            Some("abort") => {
                harden_process(true).expect("harden");
                std::process::abort();
            }
            Some("abort-unhardened") => {
                let (_, hard) = getrlimit(Resource::RLIMIT_CORE).expect("getrlimit");
                setrlimit(Resource::RLIMIT_CORE, hard, hard).expect("setrlimit");
                std::process::abort();
            }
            Some(_) => return,
            None => {}
        }
        let pattern = std::fs::read_to_string("/proc/sys/kernel/core_pattern").expect("pattern");
        assert!(
            pattern.starts_with('|') && pattern.contains("systemd-coredump"),
            "this host's core_pattern is {pattern:?}, not systemd-coredump"
        );
        let entries = |pid: u32| -> bool {
            // systemd-coredump may take a moment to write its entry.
            std::thread::sleep(std::time::Duration::from_secs(3));
            std::process::Command::new("coredumpctl")
                .args(["--no-pager", "--quiet", "list", &pid.to_string()])
                .output()
                .expect("coredumpctl")
                .status
                .success()
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let spawn = |mode: &str| {
            std::process::Command::new(std::env::current_exe().expect("test binary"))
                .args(["--exact", NAME, "--nocapture", "--include-ignored"])
                .env(CHILD, mode)
                .current_dir(dir.path())
                .spawn()
                .expect("spawn")
        };
        let mut control = spawn("abort-unhardened");
        let control_pid = control.id();
        assert!(!control.wait().expect("wait").success());
        assert!(
            entries(control_pid),
            "the unhardened control left no coredumpctl entry: run `ulimit -c unlimited` first, or check that this user may read the journal"
        );
        let mut hardened = spawn("abort");
        let hardened_pid = hardened.id();
        assert!(!hardened.wait().expect("wait").success());
        assert!(
            !entries(hardened_pid),
            "systemd-coredump collected a core of the hardened process {hardened_pid}"
        );
    }
}
