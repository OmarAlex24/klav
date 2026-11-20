# 0009 · OPAQUE with `opaque-ke`: suite, KSF and the `crypto-bigint` advisory

- Status: accepted
- Date: 2026-11-02

## Context
Phase 2 implements login with OPAQUE (design §4.1). `CLAUDE.md` and ADR 0005 already approve `opaque-ke`; what's left is to pin the suite, how it relates to the account KDF and where the code lives. The spec (§4.3) reserved the `klav/v1/kdf/opaque` label for deriving the OPAQUE input from `A ⊕ B`.

## Decision
1. **`opaque-ke` 4.0** with the `ristretto255` feature only. Suite `klav-opaque-v1`: OPRF ristretto255-SHA512, 3DH over ristretto255 with SHA-512, context `klav/v1/opaque` (spec §4.5).
2. **OPAQUE input:** `O = HKDF(A ⊕ B, "klav/v1/kdf/opaque")`, independent of the KEK. A single Argon2id per unlock produces both.
3. **`opaque-ke` KSF = identity.** A *deliberate deviation* from using Argon2id inside OPAQUE. Argon2id (256 MiB, t=3, p=4) already runs on the client as part of `A`. Repeating it inside OPAQUE would double the cost of every unlock without improving security:
   - without the Secret Key, `O` has at least 128 bits of entropy and the stolen database does not allow dictionary attacks;
   - with the Secret Key (stolen emergency kit) and the database, each guess costs a full Argon2id, the same as attacking the `identity-secrets` blob (§6.3), which the attacker also has.
4. **OPAQUE export key and session key:** not used (the KEK comes from the KDF and the server issues its own tokens).
5. **All OPAQUE code lives in `klav-core`** (`crypto::opaque`), client and server. `klav-server` doesn't depend on any cryptographic crate.
6. **SHA-512 from `sha2` 0.10** as a direct dependency of the core (`sha2-v010`), because `opaque-ke` 4 uses the `digest` 0.10 traits. It is only used inside the OPAQUE suite.
7. **`RUSTSEC-2026-0387` (`crypto-bigint` 0.5.5) is ignored in `deny.toml`.** Every version of `opaque-ke` depends on `elliptic-curve` 0.13, which brings in `crypto-bigint` 0.5 (the fix only exists in 0.7.6). In the ristretto255 suite, `elliptic-curve` only provides `expand_message_xmd` (hashing). The arithmetic is done by `curve25519-dalek`, so the vulnerable `crypto-bigint` code doesn't process Klav secrets. This needs revisiting when `opaque-ke` moves to `elliptic-curve` 0.14 or if the suite changes.

## Consequences
- The server never sees the password, the Secret Key, the KEK or `O`, and its database is useless for attacking passwords without the emergency kit (threats T1 and T2).
- Changing the password or the KDF parameters requires a new OPAQUE registration (left for phase 3).
- OPAQUE messages don't carry Klav's `versión ‖ tipo` header; the suite version goes in the `/v1` route (spec §4.5).
- The dependency tree contains old RustCrypto versions (`curve25519-dalek` 4, `sha2` 0.10, `rand_core` 0.6) only because of `opaque-ke`.
