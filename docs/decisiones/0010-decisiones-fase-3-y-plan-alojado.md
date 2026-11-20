# 0010 · KDF minimum on the server and hosted plan to-dos

- Status: accepted
- Date: 2026-11-02

## Context
When phase 2 closed, four open questions remained, which Omar settled before phase 3 started:

1. The server only checked the *shape* of `kdf_params` when registering an account (only the client enforced the Argon2id minimum, threat T3).
2. `register/finish` returns `409` if the email already exists, so registration reveals which emails have an account (threat model §7.6).
3. Attachments are only stored on the server's local disk (S3 was left "without a phase" in the roadmap).
4. There is no TLS to Postgres (ADR [0008](0008-pila-del-servidor.md) §4).

## Decision
1. **Phase 3: the server also enforces the KDF minimum** (defense in depth). `register/finish` decodes `kdf_params` with `KdfParams::decode` from `klav-core` and returns `400` if the parameters fall outside the range in spec §4.4 (below the production minimum or above the maximum). That way a buggy or tampered client can't create an account that is cheap to brute-force.
   - The in-process server tests use reduced parameters. For them there is the `Config::insecure_accept_weak_kdf` field, hidden from the docs and marked `#[serde(skip)]`: it can't be turned on from the TOML or from environment variables, so a deployed server always enforces the minimum. A Cargo *feature* is not used because, with `cargo test --workspace`, it would be unified into the real binary that the end-to-end tests launch.
   - Today no endpoint changes an account's *keyset*. When password change arrives, it must apply the same check.
2. **Phase 8 (hosted plan): email verification** so that registration stops revealing which emails exist.
3. **Phase 8: attachment storage in S3.**
4. **Phase 8: TLS to Postgres.** It needs its own ADR because of the extra cryptographic dependencies (a `rustls` provider).

Points 2 to 4 are only noted in the roadmap; they are not implemented now.

## Consequences
- An account with weak parameters can no longer exist on a Klav server, even if the client gets it wrong.
- Raising the minimum in the future forces a decision about existing accounts (which would stay below it): that will be settled with password change.
- The phase 8 roadmap gains three deliverables and the threat model notes the phase for each one.
