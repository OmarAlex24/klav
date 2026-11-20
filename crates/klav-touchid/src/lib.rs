//! Touch ID for `klavd` (design §4.3, ADR 0013): a Secure Enclave P-256
//! key, created with the `biometryCurrentSet` access control, protects the
//! device's local key. This crate only moves bytes across the FFI to a
//! small Swift shim (CryptoKit + LocalAuthentication); turning the ECDH
//! secret into a wrapping key and sealing the local key is done by
//! `klav-core` (spec §12.3).
//!
//! Without the shim (any OS but macOS, or a Mac without the Swift
//! toolchain at build time) every call reports [`Error::Unavailable`] and
//! `klavd` keeps using the master password.

// The FFI calls are the only `unsafe` in the crate; each block carries a
// `// SAFETY:` comment (enforced by `clippy::undocumented_unsafe_blocks`).
// Builds without the shim contain no `unsafe` and keep the lint active.
#![cfg_attr(klav_se_shim, allow(unsafe_code))]

use zeroize::Zeroizing;

/// Length of an uncompressed P-256 point.
pub const POINT_LEN: usize = 65;
/// Length of an ECDH shared secret.
pub const SECRET_LEN: usize = 32;
/// Room for the Secure Enclave key handle (about 570 bytes in practice).
const HANDLE_CAP: usize = 4096;

/// Why a Touch ID operation did not succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// No Secure Enclave, no enrolled fingers, no GUI session, or no shim.
    Unavailable,
    /// The user cancelled the prompt.
    Cancelled,
    /// Biometric authentication failed (e.g. locked out after attempts).
    AuthFailed,
    /// Authentication worked but the key does not: the enrolled fingers
    /// changed since enrolment. A password unlock enrols again.
    Invalidated,
    /// Any other failure.
    Other,
    /// No keychain item with that service and account.
    NotFound,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::Unavailable => "Touch ID is not available",
            Error::Cancelled => "Touch ID was cancelled",
            Error::AuthFailed => "Touch ID failed",
            Error::Invalidated => "the enrolled fingerprints changed",
            Error::Other => "Touch ID error",
            Error::NotFound => "not found in the keychain",
        })
    }
}

impl std::error::Error for Error {}

/// A Secure Enclave key: an opaque handle (useless off this Mac) and its
/// public point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnclaveKey {
    /// Opaque handle, encrypted by the Secure Enclave.
    pub handle: Vec<u8>,
    /// Public point (SEC1 uncompressed).
    pub public: [u8; POINT_LEN],
}

/// A wrap: the ephemeral public point and the shared secret.
pub struct Wrap {
    /// Ephemeral public point, stored next to the wrapped key.
    pub ephemeral_public: [u8; POINT_LEN],
    /// ECDH shared secret (input to HKDF in `klav-core`).
    pub secret: Zeroizing<[u8; SECRET_LEN]>,
}

#[cfg(klav_se_shim)]
mod shim {
    unsafe extern "C" {
        pub(super) fn klav_se_available() -> i32;
        pub(super) fn klav_se_create(
            handle: *mut u8,
            handle_cap: usize,
            handle_len: *mut usize,
            public_out: *mut u8,
        ) -> i32;
        pub(super) fn klav_se_wrap(
            enclave_public: *const u8,
            ephemeral_out: *mut u8,
            secret_out: *mut u8,
        ) -> i32;
        pub(super) fn klav_se_unwrap(
            handle: *const u8,
            handle_len: usize,
            ephemeral_public: *const u8,
            reason: *const std::ffi::c_char,
            secret_out: *mut u8,
        ) -> i32;
        pub(super) fn klav_la_authenticate(reason: *const std::ffi::c_char) -> i32;
        pub(super) fn klav_kc_store(
            service: *const std::ffi::c_char,
            account: *const std::ffi::c_char,
            data: *const u8,
            len: usize,
        ) -> i32;
        pub(super) fn klav_kc_load(
            service: *const std::ffi::c_char,
            account: *const std::ffi::c_char,
            out: *mut u8,
            cap: usize,
            out_len: *mut usize,
        ) -> i32;
        pub(super) fn klav_kc_delete(
            service: *const std::ffi::c_char,
            account: *const std::ffi::c_char,
        ) -> i32;
        pub(super) fn klav_preferred_language(out: *mut u8, cap: usize, out_len: *mut usize)
        -> i32;
        pub(super) fn klav_pid_path(pid: i32, out: *mut u8, cap: usize, out_len: *mut usize)
        -> i32;
        pub(super) fn klav_peer_token(fd: i32, pid: *mut i32, version: *mut i32) -> i32;
        pub(super) fn klav_proc_unique_id(
            pid: i32,
            unique: *mut u64,
            parent: *mut u64,
            version: *mut i32,
        ) -> i32;
        pub(super) fn klav_proc_holds_peer(pid: i32, fd: i32, holds: *mut i32) -> i32;
        pub(super) fn klav_proc_info(pid: i32, out: *mut i64) -> i32;
        pub(super) fn klav_devname(
            device: u32,
            out: *mut u8,
            cap: usize,
            out_len: *mut usize,
        ) -> i32;
        pub(super) fn klav_boot_time() -> i64;
        pub(super) fn klav_screen_locked() -> i32;
        pub(super) fn klav_reset_exception_ports() -> i32;
    }
}

#[cfg(klav_se_shim)]
fn status(code: i32) -> Result<(), Error> {
    match code {
        0 => Ok(()),
        1 => Err(Error::Unavailable),
        2 => Err(Error::Cancelled),
        3 => Err(Error::AuthFailed),
        4 => Err(Error::Invalidated),
        6 => Err(Error::NotFound),
        _ => Err(Error::Other),
    }
}

/// Whether Touch ID can be used now (Secure Enclave and enrolled fingers).
pub fn available() -> bool {
    #[cfg(klav_se_shim)]
    {
        // SAFETY: no arguments; the shim only queries CryptoKit and
        // LocalAuthentication.
        unsafe { shim::klav_se_available() == 1 }
    }
    #[cfg(not(klav_se_shim))]
    false
}

/// Creates a new Secure Enclave key (no prompt).
pub fn create_key() -> Result<EnclaveKey, Error> {
    #[cfg(klav_se_shim)]
    {
        let mut handle = vec![0u8; HANDLE_CAP];
        let mut len = 0usize;
        let mut public = [0u8; POINT_LEN];
        // SAFETY: `handle` has `HANDLE_CAP` writable bytes and the shim
        // writes at most `handle_cap`; `len` is a valid `usize`; `public`
        // has the 65 bytes the shim writes. All outlive the call.
        let code = unsafe {
            shim::klav_se_create(
                handle.as_mut_ptr(),
                HANDLE_CAP,
                &mut len,
                public.as_mut_ptr(),
            )
        };
        status(code)?;
        if len == 0 || len > HANDLE_CAP {
            return Err(Error::Other);
        }
        handle.truncate(len);
        Ok(EnclaveKey { handle, public })
    }
    #[cfg(not(klav_se_shim))]
    {
        let _ = HANDLE_CAP;
        Err(Error::Unavailable)
    }
}

/// Makes a fresh wrap secret for `public` (no prompt).
pub fn wrap(public: &[u8; POINT_LEN]) -> Result<Wrap, Error> {
    #[cfg(klav_se_shim)]
    {
        let mut ephemeral_public = [0u8; POINT_LEN];
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        // SAFETY: `public` points to 65 readable bytes; the two outputs
        // have the 65 and 32 bytes the shim writes; all outlive the call.
        let code = unsafe {
            shim::klav_se_wrap(
                public.as_ptr(),
                ephemeral_public.as_mut_ptr(),
                secret.as_mut_ptr(),
            )
        };
        status(code)?;
        Ok(Wrap {
            ephemeral_public,
            secret,
        })
    }
    #[cfg(not(klav_se_shim))]
    {
        let _ = public;
        Err(Error::Unavailable)
    }
}

/// Recovers the wrap secret: shows the Touch ID prompt with `reason`.
/// Blocks until the user answers.
pub fn unwrap(
    key: &EnclaveKey,
    ephemeral_public: &[u8; POINT_LEN],
    reason: &str,
) -> Result<Zeroizing<[u8; SECRET_LEN]>, Error> {
    #[cfg(klav_se_shim)]
    {
        let reason = std::ffi::CString::new(reason.replace('\0', " ")).map_err(|_| Error::Other)?;
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        // SAFETY: `handle` is readable for its length, `ephemeral_public`
        // for 65 bytes, `reason` is NUL-terminated, and `secret` has the
        // 32 bytes the shim writes; all outlive the call.
        let code = unsafe {
            shim::klav_se_unwrap(
                key.handle.as_ptr(),
                key.handle.len(),
                ephemeral_public.as_ptr(),
                reason.as_ptr(),
                secret.as_mut_ptr(),
            )
        };
        status(code)?;
        Ok(secret)
    }
    #[cfg(not(klav_se_shim))]
    {
        let _ = (key, ephemeral_public, reason);
        Err(Error::Unavailable)
    }
}

/// Asks for Touch ID showing `reason` and blocks until the person answers.
/// A presence check for approvals (ADR 0014); no key is involved.
pub fn authenticate(reason: &str) -> Result<(), Error> {
    #[cfg(klav_se_shim)]
    {
        let reason = std::ffi::CString::new(reason.replace('\0', " ")).map_err(|_| Error::Other)?;
        // SAFETY: `reason` is NUL-terminated and outlives the call.
        status(unsafe { shim::klav_la_authenticate(reason.as_ptr()) })
    }
    #[cfg(not(klav_se_shim))]
    {
        let _ = reason;
        Err(Error::Unavailable)
    }
}

/// Longest secret stored in the keychain by [`keychain_store`].
pub const KEYCHAIN_CAP: usize = 4096;

#[cfg(klav_se_shim)]
fn c_strings(
    service: &str,
    account: &str,
) -> Result<(std::ffi::CString, std::ffi::CString), Error> {
    Ok((
        std::ffi::CString::new(service).map_err(|_| Error::Other)?,
        std::ffi::CString::new(account).map_err(|_| Error::Other)?,
    ))
}

/// Stores `secret` as a generic password in the login keychain (macOS),
/// replacing a previous item with the same `service` and `account`.
pub fn keychain_store(service: &str, account: &str, secret: &[u8]) -> Result<(), Error> {
    #[cfg(klav_se_shim)]
    {
        if secret.len() > KEYCHAIN_CAP {
            return Err(Error::Other);
        }
        let (service, account) = c_strings(service, account)?;
        // SAFETY: both strings are NUL-terminated, `secret` is readable for
        // its length; all outlive the call.
        status(unsafe {
            shim::klav_kc_store(
                service.as_ptr(),
                account.as_ptr(),
                secret.as_ptr(),
                secret.len(),
            )
        })
    }
    #[cfg(not(klav_se_shim))]
    {
        let _ = (service, account, secret);
        Err(Error::Unavailable)
    }
}

/// Reads a secret stored with [`keychain_store`].
pub fn keychain_load(service: &str, account: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    #[cfg(klav_se_shim)]
    {
        let (service, account) = c_strings(service, account)?;
        let mut out = Zeroizing::new(vec![0u8; KEYCHAIN_CAP]);
        let mut len = 0usize;
        // SAFETY: both strings are NUL-terminated; `out` has `KEYCHAIN_CAP`
        // writable bytes and the shim writes at most `cap`; `len` is a
        // valid `usize`. All outlive the call.
        let code = unsafe {
            shim::klav_kc_load(
                service.as_ptr(),
                account.as_ptr(),
                out.as_mut_ptr(),
                KEYCHAIN_CAP,
                &mut len,
            )
        };
        status(code)?;
        if len > KEYCHAIN_CAP {
            return Err(Error::Other);
        }
        out.truncate(len);
        Ok(out)
    }
    #[cfg(not(klav_se_shim))]
    {
        let _ = (service, account);
        Err(Error::Unavailable)
    }
}

/// Deletes a secret stored with [`keychain_store`] (fine if absent).
pub fn keychain_delete(service: &str, account: &str) -> Result<(), Error> {
    #[cfg(klav_se_shim)]
    {
        let (service, account) = c_strings(service, account)?;
        // SAFETY: both strings are NUL-terminated and outlive the call.
        status(unsafe { shim::klav_kc_delete(service.as_ptr(), account.as_ptr()) })
    }
    #[cfg(not(klav_se_shim))]
    {
        let _ = (service, account);
        Err(Error::Unavailable)
    }
}

/// Room for a language tag (BCP 47 tags are far shorter).
#[cfg(klav_se_shim)]
const LANGUAGE_CAP: usize = 64;

/// The first of the person's preferred languages on this Mac (a BCP 47
/// tag, e.g. `es-MX`), the one the Touch ID prompt is shown in. `None`
/// without the shim or when macOS gives none.
pub fn preferred_language() -> Option<String> {
    #[cfg(klav_se_shim)]
    {
        let mut out = [0u8; LANGUAGE_CAP];
        let mut len = 0usize;
        // SAFETY: `out` has `LANGUAGE_CAP` writable bytes and the shim
        // writes at most `cap`; `len` is a valid `usize`. Both outlive the
        // call.
        let code =
            unsafe { shim::klav_preferred_language(out.as_mut_ptr(), LANGUAGE_CAP, &mut len) };
        status(code).ok()?;
        let tag = out.get(..len)?;
        String::from_utf8(tag.to_vec()).ok()
    }
    #[cfg(not(klav_se_shim))]
    None
}

/// Room for an executable path (`PROC_PIDPATHINFO_MAXSIZE`).
#[cfg(klav_se_shim)]
const PATH_CAP: usize = 4096;

/// The executable of process `pid` as the kernel knows it (symbolic links
/// resolved). `None` without the shim, or when the process is gone.
pub fn process_path(pid: i32) -> Option<std::path::PathBuf> {
    #[cfg(klav_se_shim)]
    {
        use std::os::unix::ffi::OsStrExt;
        let mut out = vec![0u8; PATH_CAP];
        let mut len = 0usize;
        // SAFETY: `out` has `PATH_CAP` writable bytes and the shim writes at
        // most `cap`; `len` is a valid `usize`. Both outlive the call.
        let code = unsafe { shim::klav_pid_path(pid, out.as_mut_ptr(), PATH_CAP, &mut len) };
        status(code).ok()?;
        let path = out.get(..len).filter(|p| !p.is_empty())?;
        Some(std::ffi::OsStr::from_bytes(path).into())
    }
    #[cfg(not(klav_se_shim))]
    {
        let _ = pid;
        None
    }
}

/// The socket peer's audit token (`LOCAL_PEERTOKEN`): the pid and pid
/// version of the process that last connected, sent or received on the
/// socket (its `last_pid`), not necessarily the one that connected (ADR
/// 0041 §1.1). `None` without the shim or when that process is gone.
pub fn peer_token(fd: std::os::fd::BorrowedFd<'_>) -> Option<(i32, i32)> {
    #[cfg(klav_se_shim)]
    {
        use std::os::fd::AsRawFd;
        let (mut pid, mut version) = (0i32, 0i32);
        // SAFETY: `fd` is a descriptor this process holds open for the
        // call (it is borrowed); `pid` and `version` are valid `i32`s that
        // outlive the call.
        let code = unsafe { shim::klav_peer_token(fd.as_raw_fd(), &mut pid, &mut version) };
        status(code).ok()?;
        (pid > 0).then_some((pid, version))
    }
    #[cfg(not(klav_se_shim))]
    {
        let _ = fd;
        None
    }
}

/// A process's identity for the life of the boot (`p_uniqueid`, read with
/// `PROC_PIDUNIQIDENTIFIERINFO`): never reused within a boot, unlike the
/// pid, and kept across `exec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UniqueId {
    /// The process's own unique ID.
    pub unique: u64,
    /// The unique ID of its parent: the process that created it, until it
    /// is reparented, when the kernel rewrites it to the new parent's
    /// (`launchd`'s, 1, for an orphan).
    pub parent: u64,
    /// The pid version, which `exec` changes; the audit token carries the
    /// same number.
    pub version: i32,
}

/// The unique IDs of process `pid`. `None` without the shim or when no
/// process has that pid.
pub fn unique_id(pid: i32) -> Option<UniqueId> {
    #[cfg(klav_se_shim)]
    {
        let (mut unique, mut parent, mut version) = (0u64, 0u64, 0i32);
        // SAFETY: the three outputs are valid and outlive the call.
        let code =
            unsafe { shim::klav_proc_unique_id(pid, &mut unique, &mut parent, &mut version) };
        status(code).ok()?;
        Some(UniqueId {
            unique,
            parent,
            version,
        })
    }
    #[cfg(not(klav_se_shim))]
    {
        let _ = pid;
        None
    }
}

/// Whether process `pid` holds, right now, a descriptor for the other end
/// of the Unix-socket connection whose own end is `fd` (`PROC_PIDLISTFDS`
/// and `PROC_PIDFDSOCKETINFO`). `None` without the shim, when the process
/// is gone, or when a read fails.
pub fn holds_peer_end(pid: i32, fd: std::os::fd::BorrowedFd<'_>) -> Option<bool> {
    #[cfg(klav_se_shim)]
    {
        use std::os::fd::AsRawFd;
        let mut holds = 0i32;
        // SAFETY: `fd` is held open for the call (it is borrowed); `holds`
        // is a valid `i32` that outlives the call.
        let code = unsafe { shim::klav_proc_holds_peer(pid, fd.as_raw_fd(), &mut holds) };
        status(code).ok()?;
        Some(holds == 1)
    }
    #[cfg(not(klav_se_shim))]
    {
        let _ = (pid, fd);
        None
    }
}

/// What the kernel says about a process (`sysctl` `KERN_PROC_PID`, which
/// also answers for processes of other users, unlike `proc_pidinfo`'s
/// `PROC_PIDTBSDINFO`, and `getsid`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Start time, in microseconds since the Unix epoch.
    pub start_micros: u64,
    /// Parent pid (`launchd`, 1, for an orphan).
    pub ppid: i32,
    /// Session ID.
    pub sid: i32,
    /// Real user ID.
    pub ruid: u32,
    /// Effective user ID.
    pub euid: u32,
    /// The controlling terminal's device number, if it has one.
    pub terminal: Option<u32>,
    /// Whether it leads its session.
    pub session_leader: bool,
}

/// The kernel's description of process `pid`. `None` without the shim,
/// when no process has that pid, or when the kernel's controlling-terminal
/// flag and device number disagree (see [`decode_process_info`]).
pub fn process_info(pid: i32) -> Option<ProcessInfo> {
    #[cfg(klav_se_shim)]
    {
        let mut out = [0i64; 8];
        // SAFETY: `out` has the 8 `i64`s the shim writes and outlives the
        // call.
        let code = unsafe { shim::klav_proc_info(pid, out.as_mut_ptr()) };
        status(code).ok()?;
        decode_process_info(out)
    }
    #[cfg(not(klav_se_shim))]
    {
        let _ = pid;
        None
    }
}

/// Decodes what the shim's `klav_proc_info` writes: start seconds and
/// microseconds, ppid, session ID, real and effective user IDs, the
/// controlling terminal's device number (-1 for none) and flags (1: has a
/// controlling terminal, 2: leads its session).
///
/// A terminal flag with no device, or a device with no flag, gives `None`:
/// the process is described as neither in a terminal nor out of one, so
/// the caller treats it as unknown rather than keying it by its parent.
#[cfg_attr(not(any(test, klav_se_shim)), allow(dead_code))]
fn decode_process_info(out: [i64; 8]) -> Option<ProcessInfo> {
    let [secs, micros, ppid, sid, ruid, euid, tdev, flags] = out;
    let start_micros = u64::try_from(secs)
        .ok()?
        .checked_mul(1_000_000)?
        .checked_add(u64::try_from(micros).ok()?)?;
    let terminal = match (flags & 1 != 0, tdev) {
        (false, -1) => None,
        (true, -1) | (false, _) => return None,
        (true, device) => Some(u32::try_from(device).ok()?),
    };
    Some(ProcessInfo {
        start_micros,
        ppid: i32::try_from(ppid).ok()?,
        sid: i32::try_from(sid).ok()?,
        ruid: u32::try_from(ruid).ok()?,
        euid: u32::try_from(euid).ok()?,
        terminal,
        session_leader: flags & 2 != 0,
    })
}

/// Room for a device name (`ttys003`); a longer one is no terminal name.
#[cfg(klav_se_shim)]
const DEVNAME_CAP: usize = 64;

/// The name under `/dev` of the character device `device` (`devname_r(3)`,
/// with the call's own buffer, so concurrent calls never see each other's),
/// for a controlling terminal's device number as [`ProcessInfo::terminal`]
/// gives it: `ttys003`. `None` without the shim, or when no device has that
/// number (ADR 0041 §2.4: the prompt then says "a terminal").
pub fn device_name(device: u32) -> Option<String> {
    #[cfg(klav_se_shim)]
    {
        let mut out = vec![0u8; DEVNAME_CAP];
        let mut len = 0usize;
        // SAFETY: `out` has `DEVNAME_CAP` writable bytes and the shim
        // writes at most `cap`; `len` is a valid `usize`. Both outlive the
        // call.
        let code = unsafe { shim::klav_devname(device, out.as_mut_ptr(), DEVNAME_CAP, &mut len) };
        status(code).ok()?;
        let name = out.get(..len).filter(|n| !n.is_empty())?;
        String::from_utf8(name.to_vec()).ok()
    }
    #[cfg(not(klav_se_shim))]
    {
        let _ = device;
        None
    }
}

/// Boot time of the machine (Unix seconds), to require the password after
/// a reboot.
pub fn boot_time() -> Option<u64> {
    #[cfg(klav_se_shim)]
    {
        // SAFETY: no arguments; reads `kern.boottime` with sysctl.
        let t = unsafe { shim::klav_boot_time() };
        u64::try_from(t).ok().filter(|t| *t > 0)
    }
    #[cfg(not(klav_se_shim))]
    None
}

/// Whether the login session's screen is locked (false without a GUI
/// session or without the shim).
pub fn screen_locked() -> bool {
    #[cfg(klav_se_shim)]
    {
        // SAFETY: no arguments; reads the CoreGraphics session dictionary.
        unsafe { shim::klav_screen_locked() == 1 }
    }
    #[cfg(not(klav_se_shim))]
    false
}

/// Drops the Mach exception handlers inherited from the parent process, so
/// that a daemon started from a browser's native messaging host neither
/// keeps the browser's crash reporter alive nor reports its crashes to it.
/// Returns false if it could not (or without the shim).
pub fn detach_crash_handlers() -> bool {
    #[cfg(klav_se_shim)]
    {
        // SAFETY: no arguments; changes only this task's exception ports.
        unsafe { shim::klav_reset_exception_ports() == 0 }
    }
    #[cfg(not(klav_se_shim))]
    false
}

/// Whether this build includes the Swift shim.
pub const fn compiled_in() -> bool {
    cfg!(klav_se_shim)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_terminal_flag_and_device_that_disagree_describe_no_process() {
        let out = |tdev: i64, flags: i64| [1_700_000_000, 250, 41, 40, 501, 501, tdev, flags];
        let info = decode_process_info(out(0x1000_0003, 1 | 2)).expect("in a terminal");
        assert_eq!(info.terminal, Some(0x1000_0003));
        assert!(info.session_leader);
        assert_eq!(info.start_micros, 1_700_000_000_000_250);
        assert_eq!(
            (info.ppid, info.sid, info.ruid, info.euid),
            (41, 40, 501, 501)
        );
        let alone = decode_process_info(out(-1, 0)).expect("no terminal");
        assert_eq!(alone.terminal, None);
        assert!(!alone.session_leader);
        // A flag with no device, and a device with no flag.
        assert_eq!(decode_process_info(out(-1, 1)), None);
        assert_eq!(decode_process_info(out(0x1000_0003, 0)), None);
    }
}
