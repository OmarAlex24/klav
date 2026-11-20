# 0011 · `klav-client` library, client TLS and local keys

- Status: accepted
- Date: 2026-11-02

## Context
Phase 3 brings the first real clients: the `klav` CLI and the `klavd` daemon. Both do the same things with the server (registration, login, session, sync, CRUD) and with the disk (encrypted cache, *high-water marks*). In addition:

- The CLI must speak HTTPS to real servers, and `deny.toml` bans `ring` and `openssl`.
- The `meta` format for vaults and projects was left "for phase 3" ([`api.md`](../api.md) §4.1), and `klav://bóveda/proyecto/…` references need those names.
- Unlocking with Touch ID (design §4.3) needs a *local unlock key* that opens the account without the password, and the local cache needs a key to be encrypted with.

## Decision
1. **New crate `crates/klav-client`** (Apache-2.0) with everything that isn't interface: account, session and its renewal, encrypted local cache, sync with *rollback* detection and item CRUD. It is used by the CLI (direct mode) and the daemon, and will be used by the SDK and `klav mcp` (phase 4). Putting it inside `klav-cli` would force the daemon to depend on a binary. It contains no cryptography: everything goes through `klav-core`.
2. **TLS with `rustls` and the `aws-lc-rs` provider**, through `reqwest` (feature `rustls`), with the system certificate store (`rustls-platform-verifier`).
   - Rejected alternatives: `rustls-rustcrypto` (alpha, and it pulls in `rustls-webpki` 0.102 with open security advisories and `rsa` with the Marvin attack), `native-tls` (on Linux it is OpenSSL, which is banned) and `ring` (banned).
   - `aws-lc-rs` is the default `rustls` provider, maintained by AWS and FIPS-validated. Its licenses (ISC, Apache-2.0, MIT, BSD-3-Clause) are already allowed.
   - TLS is only transport: it protects the session tokens and the plaintext metadata. Klav's data is still end-to-end encrypted with `klav-core`, and the rule "Klav's cryptography lives in `klav-core`" doesn't change. `ring` and `openssl` are still banned.
   - `webpki-root-certs` (Mozilla roots as data, CDLA-Permissive-2.0) comes in as a license exception in `deny.toml`.
   - `http://` is only accepted for `localhost`/`127.0.0.1`/`::1` (development and tests). The client doesn't follow redirects.
   - **Open question for Omar:** if a 100 % RustCrypto provider is preferred once `rustls-rustcrypto` matures, the change is local to `klav-client`.
3. **Vault and project metadata** (spec §7.2): JSON `{ "v": 1, "name", "description"? }` sealed with the vault key (type `0x12`) or the project key (type `0x13`), with the version in the AAD like items. The project's metadata uses the project key so that an agent with a project *grant* can read its name.
4. **Local hierarchy** (spec §12.2): `llave local = HKDF(KEK, tuple("klav/v1/kdf/local-key", cuenta, dispositivo))`. It seals a local copy of the identity (type `0x40`) and the local data (type `0x41`: cache and tokens). A password unlock recomputes it from the KEK; a biometric one gets it from the Secure Enclave (phase 3, ADR 0013). It is derived rather than random so that no other wrapping is stored on disk and no key cycle is created (KEK ↔ local key).
5. **Local state** in a directory (`KLAV_HOME`, by default `~/Library/Application Support/klav` on macOS and `~/.config/klav` on Linux), mode 0700, files 0600 written atomically. The Secret Key is stored in that directory (as 1Password stores it on the device): on its own it is useless without the password.
6. ***Rollback* detection (T7):** inside the encrypted cache, the client stores the highest revision seen per vault and the highest version per vault, project and item, plus purged items and deleted projects. Any regression (in `/v1/sync`, in `changes` or in a version) aborts the whole sync with a security error and doesn't touch the cache. The marks survive a vault disappearing.
7. **Session renewal across processes:** *refresh tokens* are single-use and reusing one revokes the session, so the CLI and the daemon renew under a file lock (`session.lock`) and, before renewing, adopt the tokens another process may have saved.

## Consequences
- A single place for client logic; the CLI and the daemon only change the interface.
- The clients' dependency tree includes `aws-lc-sys` (C code compiled with `cc`): client builds need a C compiler. The server doesn't change.
- The cache, the tokens and the local identity never travel to the server; losing the directory only means signing in again.
- If the local cache is deleted, the *rollback* marks are lost with it (a local attacker with access to the directory is outside the model, §6 of the threat model).
