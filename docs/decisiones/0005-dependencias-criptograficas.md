# 0005 · Cryptographic dependencies of `klav-core`

- Status: accepted
- Date: 2026-11-02

## Context
`CLAUDE.md` allows only RustCrypto, `hpke` and `opaque-ke`, and requires an ADR for any new cryptographic dependency. Phase 1 implements key derivation, the key hierarchy, item and attachment encryption, signatures and TOTP, so we need to pin down which crates are used and for what. When this decision was written, the latest RustCrypto releases had already moved the STREAM construction out of `aead` into its own crate (`aead-stream`).

## Decision
`klav-core` uses exactly these cryptographic dependencies (versions pinned in `Cargo.lock`):

| Crate | Version | Use |
|---|---|---|
| `chacha20poly1305` | 0.11 | XChaCha20-Poly1305 for all symmetric envelopes |
| `aead-stream` | 0.6 | STREAM (`StreamBE32`) for attachments (RustCrypto) |
| `argon2` | 0.6 | Argon2id for the master password |
| `hkdf` | 0.13 | HKDF-SHA256 |
| `sha2` | 0.11 | SHA-256 (HKDF, fingerprints, Secret Key checksum); SHA-256/512 for TOTP |
| `hpke` | 0.15 | HPKE RFC 9180, only with the `x25519`, `chacha`, `hkdfsha2` features (no ML-KEM or NIST) |
| `ed25519-dalek` | 3 | Ed25519 signatures |
| `x25519-dalek` | 3 | Transitive through `hpke` (not used directly) |
| `hmac` | 0.13 | HMAC for TOTP (RFC 4226/6238) |
| `sha1` | 0.11 | SHA-1 **only** for TOTP, because RFC 6238 and almost every service use it by default; never for anything else |
| `getrandom` | 0.4 | Operating system CSPRNG |
| `subtle` | 2.6 | Constant-time comparisons |
| `secrecy`, `zeroize` | 0.10, 1.9 | Secrets in memory |

Supporting, non-cryptographic dependencies: `data-encoding` (base32), `unicode-normalization` (NFKD of the password), `uuid` (ID format), `thiserror`.

`opaque-ke` remains approved for phase 2 (OPAQUE), unchanged.

`cargo-deny` bans `openssl`, `openssl-sys` and `ring` across the whole workspace.

## Consequences
- Any cryptographic crate outside this list (for example, `memsec` for `mlock`, or AES) requires a new ADR.
- Major version updates of these crates are checked against the vectors in `docs/vectores/`, which must keep passing unchanged.
- SHA-1 in the dependency tree is intentional and limited to TOTP.
