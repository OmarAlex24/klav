# 0013 · Touch ID on macOS: Swift shim with CryptoKit, Secure Enclave key without *entitlements*, and `mlock` postponed

- Status: accepted
- Date: 2026-11-02

## Context
The design (§4.3) calls for unlocking `klavd` with Touch ID: a P-256 key in the Secure Enclave, with the `biometryCurrentSet` ACL, wraps the device's local key (spec §12.2). In addition:

- the password must be asked for again every N days (14 by default) and after a restart;
- the binary is signed and notarized;
- `unsafe` is only allowed in the native bridge, with `// SAFETY:` comments.

The spec (§12.1) and ADR 0011 left the `mlock` decision to this ADR.

## Decision
1. **Swift shim with CryptoKit**, in its own crate, `crates/klav-touchid` (Apache-2.0).
   - `build.rs` compiles `swift/shim.swift` with `swiftc -emit-library -static` and links it with CoreGraphics, CryptoKit, Foundation, LocalAuthentication and Security. The system Swift libraries (`/usr/lib/swift`, in the *shared cache*) are linked with absolute paths, without `rpath`.
   - Without macOS, without `swiftc` or with `KLAV_NO_SWIFT=1`, nothing is compiled and every function returns `Unavailable`. That way CI on Linux and a Mac without Xcode keep working, and `klavd` uses the password.
   - It is the only crate with `unsafe` today. It repeats the workspace *lints* with `unsafe_code = "warn"` (allowed only when the shim is compiled) and `clippy::undocumented_unsafe_blocks = "deny"`.
   - The C interface uses caller buffers with fixed sizes (65-byte points, 32-byte secrets) plus the *handle* with capacity and length. No memory is freed across languages.
2. **Secure Enclave key stored as `dataRepresentation`** (`SecureEnclave.P256.KeyAgreement.PrivateKey`), not in the Keychain.
   - That *handle* is encrypted by the Secure Enclave itself and only works on this Mac.
   - **It doesn't need `keychain-access-groups`, a provisioning profile or an app bundle.** This was checked on this machine: an unsigned binary, an *ad hoc* one and the one signed with Developer ID and *hardened runtime* all create the key, reload it and wrap without a dialog.
   - Rejected alternative: `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` and `kSecAttrIsPermanent`. It stores the key in the data protection Keychain, which requires the keychain group *entitlement* and, with it, a provisioning profile.
   - Rejected alternative: the `security-framework` and `objc2-*` crates, which add dependencies and don't avoid that problem.
3. **ECDH in the shim, everything else in `klav-core`.**
   - When wrapping, CryptoKit creates an ephemeral P-256 pair and computes the ECDH with the enclave's public key. There is no dialog.
   - When unwrapping, it first authenticates with `LAContext.evaluatePolicy` and then the enclave computes the ECDH with that context. Authenticating first makes it possible to tell "the user canceled" apart from "the key no longer works".
   - The shim only returns the shared secret. HKDF and the XChaCha20-Poly1305 sealing of the local key (type `0x42`) belong to `klav-core` (spec §12.3, vector `llavero.json`).
   - No new cryptographic dependency enters Rust: P-256 lives in CryptoKit, the system library.
4. **Policy, bound in the AAD:**
   - `password_at_ms` (last password unlock) and `boot_time_s` (boot, through `sysctl kern.boottime`) go in the AAD of type `0x42`;
   - `klavd` requires the password if 14 days have passed or if the boot changed;
   - editing `touchid.json` to extend the deadline makes the blob stop opening;
   - every password unlock rewraps with a new ephemeral pair.
5. **Automatic enrollment and opt-out:**
   - the first password unlock sets up Touch ID, without a dialog, if it is available (design §4.3);
   - `klavd --no-touch-id` or `KLAV_NO_TOUCH_ID=1` turn it off;
   - `klav unlock --password` and `--password-stdin` use the password, and scripts never wait for a fingerprint.
6. **Errors:**
   - canceling or failing the fingerprint gives `biometry_failed` and keeps the enrollment;
   - if authentication works but the key doesn't (the fingerprints changed, `biometryCurrentSet`), or the file doesn't open, the enrollment is deleted and the response is `biometry_unavailable`;
   - in any of those cases `klav` asks for the password, which sets up Touch ID again.
7. **Lock on screen lock:** `klavd` polls `CGSessionCopyCurrentDictionary()` (`CGSSessionScreenIsLocked`) every 2 s. With no graphical session (SSH) it is treated as unlocked.
8. **Signing and notarization** (`scripts/macos/`):
   - `build-sign.sh` builds in *release* and signs `klav` and `klavd` with the Developer ID identity (`SZ3F58F8LX`), *hardened runtime* and a timestamp. No *entitlements* are needed. It packages them in a zip.
   - `notarize.sh` submits it with `notarytool` using a Keychain profile (`KLAV_NOTARY_PROFILE`). There are never credentials in the repository or in argv.
   - Command-line binaries can't be *stapled*; Gatekeeper checks the ticket online.
9. **`mlock`: postponed.**
   - The attacker who can read swap or a memory dump is root or the same user, who can already read `klavd`'s live memory (out of scope, threat model §6).
   - macOS encrypts swap.
   - Doing it properly requires `unsafe` or `memsec`/`region` on every secret type in `klav-core` and turning off *core dumps*.
   - It will be revisited with the desktop app or if the model changes. Meanwhile, the defense is `zeroize`/`secrecy` and a short window: lock on idle, on sleep and on screen lock.

## Consequences
- **Not tested automatically:** the Touch ID dialog from a daemon without a bundle needs a finger.
  - The `touch_id_round_trip` test is marked `#[ignore]`; it runs with `cargo test -p klav-touchid -- --ignored`.
  - Enrollment, wrapping and policy are tested without a dialog, on macOS and with vectors.
- Building `klavd` with Touch ID requires the Xcode Command Line Tools. Without them, the binary works only with the password and `build.rs` warns about it.
- A `touchid.json` copied to another Mac is useless: the *handle* only works with its own Secure Enclave, and the AAD binds the account and the device.
