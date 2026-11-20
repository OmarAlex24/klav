import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// The device's key store for Face ID unlock (ADR 0018 §3, spec §12.3).
/// Swift only creates the Secure Enclave key and computes ECDH; HKDF and
/// sealing the local key happen in `klav-core`.
enum Keystores {
    /// The keystore for this build: the Secure Enclave on a device, and a
    /// software key behind the Face ID prompt only in DEBUG simulator builds.
    static func platform() -> PlatformKeystore {
        #if targetEnvironment(simulator) && DEBUG
        return SimulatorKeystore()
        #else
        return SecureEnclaveKeystore()
        #endif
    }

    /// The simulated keystore is in use (shown in Settings).
    static var isSimulated: Bool {
        #if targetEnvironment(simulator) && DEBUG
        return true
        #else
        return false
        #endif
    }
}

/// Boot time of the device (`kern.boottime`, Unix seconds), or 0.
func deviceBootTime() -> UInt64 {
    var boot = timeval()
    var size = MemoryLayout<timeval>.size
    guard sysctlbyname("kern.boottime", &boot, &size, nil, 0) == 0, boot.tv_sec > 0 else { return 0 }
    return UInt64(boot.tv_sec)
}

/// Shows the biometric prompt and waits (call off the main thread). Maps
/// the answer to the keystore errors `klav-ffi` understands.
func authenticateBiometrics(_ context: LAContext, reason: String) throws {
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
        throw KeystoreError.Unavailable
    }
    let done = DispatchSemaphore(value: 0)
    var failure: Error?
    var ok = false
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, err in
        ok = success
        failure = err
        done.signal()
    }
    done.wait()
    if ok { return }
    switch (failure as? LAError)?.code {
    case .userCancel?, .systemCancel?, .appCancel?, .userFallback?:
        throw KeystoreError.Cancelled
    case .biometryNotAvailable?, .biometryNotEnrolled?, .biometryLockout?, .notInteractive?:
        throw KeystoreError.Unavailable
    default:
        throw KeystoreError.AuthFailed
    }
}

/// The device owner, for turning Face ID off in Klav (ADR 0037 A4):
/// Face ID, or the device passcode when Face ID fails or is locked out
/// (`deviceOwnerAuthentication`). Never the master password alone.
enum DeviceOwner {
    /// Shows the prompt and waits (call off the main thread).
    static func confirm(_ reason: String) throws {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw failure((error as? LAError)?.code)
        }
        let done = DispatchSemaphore(value: 0)
        var failed: Error?
        var ok = false
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, err in
            ok = success
            failed = err
            done.signal()
        }
        done.wait()
        if ok { return }
        throw failure((failed as? LAError)?.code)
    }

    /// Only a device with no passcode is `Unavailable`: there is no owner
    /// to ask and no Face ID either, and `klav-ffi` then lets the
    /// enrolment go. Everything else, a lockout included, refuses: a
    /// lockout is what someone who failed Face ID on purpose gets.
    static func failure(_ code: LAError.Code?) -> KeystoreError {
        switch code {
        case .passcodeNotSet?:
            return .Unavailable
        case .userCancel?, .systemCancel?, .appCancel?, .userFallback?:
            return .Cancelled
        case .authenticationFailed?:
            return .AuthFailed
        default:
            return .Other
        }
    }
}

private func biometricsAvailable() -> Bool {
    var error: NSError?
    return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
}

private func secret(_ shared: SharedSecret) -> Data {
    shared.withUnsafeBytes { Data($0) }
}

/// The Secure Enclave: a P-256 key usable only after Face ID, tied to the
/// enrolled faces (`biometryCurrentSet`), kept as its enclave-encrypted
/// `dataRepresentation` (no keychain entitlement, as in ADR 0013).
final class SecureEnclaveKeystore: PlatformKeystore, @unchecked Sendable {
    func available() -> Bool {
        SecureEnclave.isAvailable && biometricsAvailable()
    }

    func createKey() throws -> KeystoreKey {
        guard SecureEnclave.isAvailable else { throw KeystoreError.Unavailable }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet], &error)
        else { throw KeystoreError.Unavailable }
        do {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
            return KeystoreKey(handle: key.dataRepresentation,
                               publicKey: key.publicKey.x963Representation)
        } catch {
            throw KeystoreError.Other
        }
    }

    func wrap(publicKey: Data) throws -> KeystoreWrap {
        do {
            let peer = try P256.KeyAgreement.PublicKey(x963Representation: publicKey)
            let ephemeral = P256.KeyAgreement.PrivateKey()
            let shared = try ephemeral.sharedSecretFromKeyAgreement(with: peer)
            return KeystoreWrap(ephemeralPublic: ephemeral.publicKey.x963Representation,
                                secret: secret(shared))
        } catch {
            throw KeystoreError.Other
        }
    }

    func unwrap(handle: Data, ephemeralPublic: Data, reason: String) throws -> Data {
        let context = LAContext()
        // Authenticate first so a cancelled prompt is told apart from a key
        // that no longer works.
        try authenticateBiometrics(context, reason: reason)
        // A bad ephemeral key is the enrolment file's problem, not a
        // changed face: `Other` keeps the enrolment. Only the Secure
        // Enclave refusing the key is `Invalidated`, which makes Klav stop
        // using Face ID (ADR 0037 A4).
        guard let peer = try? P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublic) else {
            throw KeystoreError.Other
        }
        do {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: handle, authenticationContext: context)
            return secret(try key.sharedSecretFromKeyAgreement(with: peer))
        } catch {
            // The enrolled faces changed (biometryCurrentSet) or the key
            // is gone.
            throw KeystoreError.Invalidated
        }
    }

    func bootTime() -> UInt64 { deviceBootTime() }

    func confirmOwner(reason: String) throws { try DeviceOwner.confirm(reason) }
}

#if targetEnvironment(simulator) && DEBUG
/// **Simulator only, DEBUG only** (ADR 0018 §3): the simulator has no
/// Secure Enclave, so a software P-256 key stands in for it, behind the
/// same (simulated) Face ID prompt. Its private key sits in the enrolment
/// file. This type does not exist in device or release builds.
final class SimulatorKeystore: PlatformKeystore, @unchecked Sendable {
    func available() -> Bool { biometricsAvailable() }

    func createKey() throws -> KeystoreKey {
        let key = P256.KeyAgreement.PrivateKey()
        return KeystoreKey(handle: key.rawRepresentation, publicKey: key.publicKey.x963Representation)
    }

    func wrap(publicKey: Data) throws -> KeystoreWrap {
        try SecureEnclaveKeystore().wrap(publicKey: publicKey)
    }

    func unwrap(handle: Data, ephemeralPublic: Data, reason: String) throws -> Data {
        try authenticateBiometrics(LAContext(), reason: reason)
        guard let peer = try? P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublic) else {
            throw KeystoreError.Other
        }
        do {
            let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: handle)
            return secret(try key.sharedSecretFromKeyAgreement(with: peer))
        } catch {
            throw KeystoreError.Invalidated
        }
    }

    func bootTime() -> UInt64 { deviceBootTime() }

    func confirmOwner(reason: String) throws { try DeviceOwner.confirm(reason) }
}
#endif

/// Presence check without a key (approving an agent or an action, ADR
/// 0014 §5.4): Face ID, or the device passcode when there is no Face ID.
enum Presence {
    static func confirm(_ reason: String) async -> Bool {
        await withCheckedContinuation { continuation in
            let context = LAContext()
            var error: NSError?
            let policy: LAPolicy = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
                ? .deviceOwnerAuthenticationWithBiometrics : .deviceOwnerAuthentication
            guard context.canEvaluatePolicy(policy, error: &error) else {
                continuation.resume(returning: false)
                return
            }
            context.evaluatePolicy(policy, localizedReason: reason) { ok, _ in
                continuation.resume(returning: ok)
            }
        }
    }
}
