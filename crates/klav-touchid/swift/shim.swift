// Swift shim for klav-touchid (ADR 0013, ADR 0014). Only CryptoKit,
// Security, LocalAuthentication and CoreGraphics, plus libproc, sysctl and
// libbsm for the socket peer (ADR 0041 §1.1); no secrets are logged.
// Every function returns a status code:
//   0 ok · 1 unavailable · 2 cancelled · 3 authentication failed
//   4 key invalidated (biometry changed) · 5 other error · 6 not found
// Buffers are owned by the Rust caller; sizes are fixed (P-256 points are
// 65 bytes, shared secrets 32) except the key handle (capacity + length).

import CoreGraphics
import CryptoKit
import Foundation
import LocalAuthentication
import Security

private let OK: Int32 = 0
private let UNAVAILABLE: Int32 = 1
private let CANCELLED: Int32 = 2
private let AUTH_FAILED: Int32 = 3
private let INVALIDATED: Int32 = 4
private let OTHER: Int32 = 5
private let NOT_FOUND: Int32 = 6

/// Shows the Touch ID prompt with `text` and waits for the answer.
private func authenticate(_ context: LAContext, _ text: String) -> Int32 {
    var policyError: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &policyError) else {
        return UNAVAILABLE
    }
    let done = DispatchSemaphore(value: 0)
    var success = false
    var failure: Error?
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: text) { ok, error in
        success = ok
        failure = error
        done.signal()
    }
    done.wait()
    if success { return OK }
    if let la = failure as? LAError {
        switch la.code {
        case .userCancel, .systemCancel, .appCancel, .userFallback:
            return CANCELLED
        case .biometryNotAvailable, .biometryNotEnrolled, .notInteractive:
            return UNAVAILABLE
        default:
            return AUTH_FAILED
        }
    }
    return AUTH_FAILED
}

private func copySecret(_ secret: SharedSecret, _ out: UnsafeMutablePointer<UInt8>) -> Int32 {
    return secret.withUnsafeBytes { raw -> Int32 in
        guard raw.count == 32, let base = raw.baseAddress else { return OTHER }
        out.update(from: base.assumingMemoryBound(to: UInt8.self), count: 32)
        return OK
    }
}

/// 1 when the Secure Enclave exists and biometrics are enrolled.
@_cdecl("klav_se_available")
public func klav_se_available() -> Int32 {
    guard SecureEnclave.isAvailable else { return 0 }
    var error: NSError?
    return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) ? 1 : 0
}

/// Creates a Secure Enclave P-256 key usable only after biometrics, tied
/// to the currently enrolled fingers. Writes its opaque handle (only this
/// Mac's Secure Enclave can use it) and its public point (65 bytes).
@_cdecl("klav_se_create")
public func klav_se_create(
    _ handle: UnsafeMutablePointer<UInt8>, _ handleCap: Int, _ handleLen: UnsafeMutablePointer<Int>,
    _ publicOut: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard SecureEnclave.isAvailable else { return UNAVAILABLE }
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet], &error)
    else { return UNAVAILABLE }
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let data = key.dataRepresentation
        let point = key.publicKey.x963Representation
        guard data.count <= handleCap, point.count == 65 else { return OTHER }
        data.copyBytes(to: handle, count: data.count)
        handleLen.pointee = data.count
        point.copyBytes(to: publicOut, count: 65)
        return OK
    } catch {
        return OTHER
    }
}

/// Wraps without a prompt: an ephemeral P-256 key agrees with the Secure
/// Enclave public key. Writes the ephemeral public point and the secret.
@_cdecl("klav_se_wrap")
public func klav_se_wrap(
    _ enclavePublic: UnsafePointer<UInt8>,
    _ ephemeralOut: UnsafeMutablePointer<UInt8>, _ secretOut: UnsafeMutablePointer<UInt8>
) -> Int32 {
    do {
        let peer = try P256.KeyAgreement.PublicKey(
            x963Representation: Data(bytes: enclavePublic, count: 65))
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let secret = try ephemeral.sharedSecretFromKeyAgreement(with: peer)
        let point = ephemeral.publicKey.x963Representation
        guard point.count == 65 else { return OTHER }
        point.copyBytes(to: ephemeralOut, count: 65)
        return copySecret(secret, secretOut)
    } catch {
        return OTHER
    }
}

/// Unwraps: asks for Touch ID (showing `reason`), then has the Secure
/// Enclave key agree with the ephemeral public point.
@_cdecl("klav_se_unwrap")
public func klav_se_unwrap(
    _ handle: UnsafePointer<UInt8>, _ handleLen: Int,
    _ ephemeralPublic: UnsafePointer<UInt8>, _ reason: UnsafePointer<CChar>,
    _ secretOut: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let context = LAContext()
    // Authenticate first so that a cancelled prompt can be told apart
    // from a key that no longer works.
    let auth = authenticate(context, String(cString: reason))
    guard auth == OK else { return auth }
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: Data(bytes: handle, count: handleLen),
            authenticationContext: context)
        let peer = try P256.KeyAgreement.PublicKey(
            x963Representation: Data(bytes: ephemeralPublic, count: 65))
        let secret = try key.sharedSecretFromKeyAgreement(with: peer)
        return copySecret(secret, secretOut)
    } catch {
        // Authenticated, yet the key does not work: the enrolled fingers
        // changed (biometryCurrentSet) or the handle is not ours.
        return INVALIDATED
    }
}

/// Boot time (Unix seconds), or -1.
@_cdecl("klav_boot_time")
public func klav_boot_time() -> Int64 {
    var boot = timeval()
    var size = MemoryLayout<timeval>.size
    guard sysctlbyname("kern.boottime", &boot, &size, nil, 0) == 0 else { return -1 }
    return Int64(boot.tv_sec)
}

/// 1 when the login session's screen is locked (0 also without a GUI
/// session, e.g. over SSH).
@_cdecl("klav_screen_locked")
public func klav_screen_locked() -> Int32 {
    guard let info = CGSessionCopyCurrentDictionary() as? [String: Any] else { return 0 }
    return (info["CGSSessionScreenIsLocked"] as? Bool ?? false) ? 1 : 0
}

/// Writes the first of the person's preferred languages (a BCP 47 tag such
/// as `es-MX`) into `out`, UTF-8 without NUL. LocalAuthentication writes
/// its part of the Touch ID prompt in that language, so `klavd` writes the
/// reason in it too. `Locale.preferredLanguages` reads the user's settings,
/// also from a LaunchAgent without UI.
@_cdecl("klav_preferred_language")
public func klav_preferred_language(
    _ out: UnsafeMutablePointer<UInt8>, _ cap: Int, _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    guard let first = Locale.preferredLanguages.first else { return NOT_FOUND }
    let bytes = Array(first.utf8)
    guard !bytes.isEmpty, bytes.count <= cap else { return OTHER }
    out.update(from: bytes, count: bytes.count)
    outLen.pointee = bytes.count
    return OK
}

/// Writes the executable path of process `pid` into `out` (UTF-8 without
/// NUL), as the kernel knows it (`proc_pidpath`, symbolic links resolved).
/// `klavd` uses it to tell the person which program asked (a hint, not a
/// check).
@_cdecl("klav_pid_path")
public func klav_pid_path(
    _ pid: Int32, _ out: UnsafeMutablePointer<UInt8>, _ cap: Int, _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    var buffer = [CChar](repeating: 0, count: Int(4 * MAXPATHLEN))
    let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
    guard length > 0 else { return NOT_FOUND }
    let bytes = buffer.prefix(Int(length)).map { UInt8(bitPattern: $0) }
    guard bytes.count <= cap else { return OTHER }
    out.update(from: bytes, count: bytes.count)
    outLen.pointee = bytes.count
    return OK
}

/// Asks for Touch ID with `reason` (a person approving an agent or an
/// action, ADR 0014). No key is involved: the answer is the presence check.
@_cdecl("klav_la_authenticate")
public func klav_la_authenticate(_ reason: UnsafePointer<CChar>) -> Int32 {
    return authenticate(LAContext(), String(cString: reason))
}

private func keychainQuery(_ service: UnsafePointer<CChar>, _ account: UnsafePointer<CChar>) -> [String: Any] {
    return [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: String(cString: service),
        kSecAttrAccount as String: String(cString: account),
    ]
}

/// Stores `data` as a generic password of the login keychain (replacing
/// any previous one with the same service and account). Used for agent
/// keys on a Mac (design §5.1); the legacy keychain needs no entitlement.
@_cdecl("klav_kc_store")
public func klav_kc_store(
    _ service: UnsafePointer<CChar>, _ account: UnsafePointer<CChar>,
    _ data: UnsafePointer<UInt8>, _ len: Int
) -> Int32 {
    let query = keychainQuery(service, account)
    SecItemDelete(query as CFDictionary)
    var attributes = query
    attributes[kSecValueData as String] = Data(bytes: data, count: len)
    attributes[kSecAttrLabel as String] = "Klav agent key"
    return SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess ? OK : OTHER
}

/// Reads a generic password stored by `klav_kc_store`.
@_cdecl("klav_kc_load")
public func klav_kc_load(
    _ service: UnsafePointer<CChar>, _ account: UnsafePointer<CChar>,
    _ out: UnsafeMutablePointer<UInt8>, _ cap: Int, _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    var query = keychainQuery(service, account)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return NOT_FOUND }
    if status == errSecUserCanceled || status == errSecAuthFailed { return CANCELLED }
    guard status == errSecSuccess, let data = result as? Data else { return OTHER }
    guard data.count <= cap else { return OTHER }
    data.copyBytes(to: out, count: data.count)
    outLen.pointee = data.count
    return OK
}

/// Deletes a generic password stored by `klav_kc_store` (OK if absent).
@_cdecl("klav_kc_delete")
public func klav_kc_delete(_ service: UnsafePointer<CChar>, _ account: UnsafePointer<CChar>) -> Int32 {
    let status = SecItemDelete(keychainQuery(service, account) as CFDictionary)
    return (status == errSecSuccess || status == errSecItemNotFound) ? OK : OTHER
}

/// Drops the exception handlers this process inherited from its parent.
/// A browser starts the native host, and the host starts `klavd`: without
/// this, `klavd` would keep the browser's crash reporter alive and send it
/// its own crash reports. Afterwards crashes go to the system, as for any
/// process started by launchd.
@_cdecl("klav_reset_exception_ports")
public func klav_reset_exception_ports() -> Int32 {
    let mask = exception_mask_t(
        EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_ARITHMETIC
            | EXC_MASK_EMULATION | EXC_MASK_SOFTWARE | EXC_MASK_BREAKPOINT
            | EXC_MASK_SYSCALL | EXC_MASK_MACH_SYSCALL | EXC_MASK_RPC_ALERT
            | EXC_MASK_CRASH | EXC_MASK_RESOURCE | EXC_MASK_GUARD | EXC_MASK_MACHINE)
    let result = task_set_exception_ports(
        mach_task_self_, mask, mach_port_t(MACH_PORT_NULL), EXCEPTION_DEFAULT, THREAD_STATE_NONE)
    return result == KERN_SUCCESS ? OK : OTHER
}

// Who is at the other end of `klavd`'s socket (ADR 0041 §1.1, layer 1).
// The orchestration (which read comes first, the unique-ID re-check) is in
// `klav-daemon` (`peer.rs`); these are the kernel reads it needs.

/// Pid and pid version of the socket's last user (`LOCAL_PEERTOKEN`).
@_cdecl("klav_peer_token")
public func klav_peer_token(
    _ fd: Int32, _ pidOut: UnsafeMutablePointer<Int32>, _ versionOut: UnsafeMutablePointer<Int32>
) -> Int32 {
    var token = audit_token_t()
    var len = socklen_t(MemoryLayout<audit_token_t>.size)
    guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &len) == 0,
        Int(len) == MemoryLayout<audit_token_t>.size
    else { return NOT_FOUND }
    let pid = audit_token_to_pid(token)
    guard pid > 0 else { return NOT_FOUND }
    pidOut.pointee = pid
    versionOut.pointee = audit_token_to_pidversion(token)
    return OK
}

// `PROC_PIDUNIQIDENTIFIERINFO` and its layout (`sys/proc_info_private.h`):
// uuid[16], p_uniqueid u64, p_puniqueid u64, p_idversion i32,
// p_orig_ppidversion i32, two reserved u64.
private let PROC_PIDUNIQIDENTIFIERINFO: Int32 = 17
private let UNIQ_SIZE = 56

@_cdecl("klav_proc_unique_id")
public func klav_proc_unique_id(
    _ pid: Int32, _ uniqueOut: UnsafeMutablePointer<UInt64>,
    _ parentOut: UnsafeMutablePointer<UInt64>, _ versionOut: UnsafeMutablePointer<Int32>
) -> Int32 {
    var buffer = [UInt8](repeating: 0, count: UNIQ_SIZE)
    let n = buffer.withUnsafeMutableBytes {
        proc_pidinfo(pid, PROC_PIDUNIQIDENTIFIERINFO, 0, $0.baseAddress, Int32(UNIQ_SIZE))
    }
    guard n == Int32(UNIQ_SIZE) else { return NOT_FOUND }
    let (unique, parent, version) = buffer.withUnsafeBytes {
        ($0.loadUnaligned(fromByteOffset: 16, as: UInt64.self),
         $0.loadUnaligned(fromByteOffset: 24, as: UInt64.self),
         $0.loadUnaligned(fromByteOffset: 32, as: Int32.self))
    }
    guard unique != 0 else { return OTHER }
    uniqueOut.pointee = unique
    parentOut.pointee = parent
    versionOut.pointee = version
    return OK
}

private func socketInfo(_ pid: Int32, _ fd: Int32) -> socket_fdinfo? {
    var info = socket_fdinfo()
    let size = Int32(MemoryLayout<socket_fdinfo>.size)
    guard proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &info, size) == size else { return nil }
    return info
}

/// 1 when process `pid` holds, now, a descriptor for the other end of the
/// connection whose own end is `fd`; 0 when it holds none.
@_cdecl("klav_proc_holds_peer")
public func klav_proc_holds_peer(_ pid: Int32, _ fd: Int32, _ holdsOut: UnsafeMutablePointer<Int32>) -> Int32 {
    guard let mine = socketInfo(getpid(), fd), mine.psi.soi_kind == SOCKINFO_UN else { return OTHER }
    let ownPcb = mine.psi.soi_pcb
    let peerPcb = mine.psi.soi_proto.pri_un.unsi_conn_pcb
    guard ownPcb != 0, peerPcb != 0 else { return OTHER }
    let entry = MemoryLayout<proc_fdinfo>.stride
    let needed = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
    guard needed > 0 else { return NOT_FOUND }
    var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(needed) / entry + 32)
    let bytes = Int32(fds.count * entry)
    let got = fds.withUnsafeMutableBytes { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, $0.baseAddress, bytes) }
    guard got > 0, got < bytes else { return got <= 0 ? NOT_FOUND : OTHER }
    var holds: Int32 = 0
    for item in fds.prefix(Int(got) / entry) where item.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) {
        guard let other = socketInfo(pid, item.proc_fd), other.psi.soi_kind == SOCKINFO_UN else { continue }
        if other.psi.soi_pcb == peerPcb && other.psi.soi_proto.pri_un.unsi_conn_pcb == ownPcb {
            holds = 1
            break
        }
    }
    holdsOut.pointee = holds
    return OK
}

/// What `sysctl(KERN_PROC_PID)` says about `pid`, and its session.
/// `out`: [start seconds, start microseconds, ppid, session id, ruid, euid,
/// controlling terminal (dev_t, or -1), flags: 1 has a controlling
/// terminal, 2 session leader]. The terminal flag and the device number are
/// passed as the kernel gives them, even when they disagree: the Rust side
/// (`decode_process_info`) then describes no process at all.
@_cdecl("klav_proc_info")
public func klav_proc_info(_ pid: Int32, _ out: UnsafeMutablePointer<Int64>) -> Int32 {
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.stride
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
    guard sysctl(&mib, 4, &info, &size, nil, 0) == 0 else { return OTHER }
    guard size == MemoryLayout<kinfo_proc>.stride, info.kp_proc.p_pid == pid else { return NOT_FOUND }
    let sid = getsid(pid)
    guard sid > 0 else { return NOT_FOUND }
    let start = info.kp_proc.p_starttime
    let eflag = info.kp_eproc.e_flag
    var flags: Int64 = 0
    if eflag & Int32(EPROC_CTTY) != 0 { flags |= 1 }
    if eflag & Int32(EPROC_SLEADER) != 0 { flags |= 2 }
    out[0] = Int64(start.tv_sec)
    out[1] = Int64(start.tv_usec)
    out[2] = Int64(info.kp_eproc.e_ppid)
    out[3] = Int64(sid)
    out[4] = Int64(info.kp_eproc.e_pcred.p_ruid)
    out[5] = Int64(info.kp_eproc.e_ucred.cr_uid)
    out[6] = info.kp_eproc.e_tdev == -1 ? -1 : Int64(UInt32(bitPattern: info.kp_eproc.e_tdev))
    out[7] = flags
    return OK
}

/// Writes the name of the character device `device` under `/dev` into
/// `out` (UTF-8 without NUL), as `devname_r(3)` gives it (`ttys003` for a
/// pseudo-terminal): the terminal's name in a presence prompt (ADR 0041
/// §2.4). `NOT_FOUND` when no device has that number. `devname_r` with this
/// call's own buffer, never `devname`, whose static buffer another call
/// running at the same time overwrites (finding 6 of the second layer-2
/// review): `klavd` names terminals from concurrent tasks.
@_cdecl("klav_devname")
public func klav_devname(
    _ device: UInt32, _ out: UnsafeMutablePointer<UInt8>, _ cap: Int, _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    var buffer = [CChar](repeating: 0, count: 256)
    let found: [UInt8]? = buffer.withUnsafeMutableBufferPointer { b in
        guard let base = b.baseAddress,
            let name = devname_r(dev_t(bitPattern: device), S_IFCHR, base, Int32(b.count))
        else { return nil }
        return Array(String(cString: name).utf8)
    }
    guard let bytes = found, !bytes.isEmpty else { return NOT_FOUND }
    guard bytes.count <= cap else { return OTHER }
    out.update(from: bytes, count: bytes.count)
    outLen.pointee = bytes.count
    return OK
}
