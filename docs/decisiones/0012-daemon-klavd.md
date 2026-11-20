# 0012 · `klavd` daemon: local engine, socket with peer UID and line-delimited JSON protocol

- Status: accepted
- Date: 2026-11-02

## Context
Phase 3 calls for a daemon (`klavd`) that keeps the account unlocked in memory. It must serve the CLI and, later, the extension (phase 5, native messaging) and Touch ID unlock. The roadmap requires three things:

- a Unix socket with access control;
- an idle lock;
- that the CLI uses the daemon when it is running and, if not, unlocks on its own.

Three things need deciding: what the daemon does, how it talks to the CLI and how it is protected.

## Decision
1. **The daemon is the engine.** `klavd` holds the `Unlocked` from `klav-client` and runs the high-level operations: list, show, create, edit, resolve references, TOTP and attachments. The CLI sends it requests and shows the results.
   - The CLI never receives the vault keys, only the values it asks for.
   - Rejected alternative: having the daemon hand the local key to the CLI so the CLI decrypts. It would be simpler, but any process that talks to the daemon would walk away with the key that opens the whole account, not just one value.
2. **Its own protocol, minimal and versioned:** line-delimited JSON over the socket. Each message carries `v` (version) and `id`. Operations are an `enum` with `op` and `deny_unknown_fields`.
   - It is documented in [`klavd.md`](../klavd.md) and tested in `protocol.rs`: the wire format is fixed.
   - HTTP over the socket, gRPC and JSON-RPC were rejected: they add dependencies and surface with no gain for a single local client.
   - Native messaging (phase 5) also uses JSON, so the same `Request` will work there.
3. **Access control:**
   - the socket is inside `$KLAV_HOME` (0700) and has mode 0600;
   - on top of that, each connection is checked against the peer's UID: Tokio's `peer_cred()`, which uses `getpeereid` on macOS and `SO_PEERCRED` on Linux. If the UID isn't the daemon's, the connection is closed.

   There is no protection against another process of the same user: with that UID it can read the files in `$KLAV_HOME` and the process memory anyway (out of scope, threat model §6). That line will be crossed by the extension's signature (phase 5) and the approvals (phase 4).
4. **Locking:**
   - **on idle** (`--idle-lock`, 15 min by default);
   - **on sleep**, detected from the difference between the wall clock and the monotonic clock, with no dependencies and no OS-specific code;
   - **on screen lock** on macOS, with the Touch ID shim (ADR 0013). On Linux, screen lock through logind/D-Bus is still pending.

   A single daemon per `KLAV_HOME`, with a file lock. It stops if its directory disappears.
5. **On-demand start:** `klav unlock` starts `klavd` if it isn't running (in its own process group) and waits for the socket. The other commands use the daemon if it is there, and otherwise direct mode. `--no-daemon` or `KLAV_NO_DAEMON=1` force direct mode. To start it with the login session there are launchd and systemd examples in `klavd.md`.
6. **Sync in the daemon** (for reads, changed by [ADR 0026](0026-lecturas-sin-esperar-al-servidor.md): they answer from the local copy and sync in the background): before an operation it syncs if the last sync was more than 30 s ago. With no network it answers from the cache with a warning; a rollback is an error (`rollback`, the CLI exits with 3; since layer 10 of [ADR 0030](0030-ronda-de-seguridad-2026-11.md), only in `sync`: in every other operation it is a warning). It shares session renewal with the CLI in direct mode through the `session.lock` lock (ADR 0011).

## Consequences
- The CLI has two paths (direct and daemon) with the same interface (`Backend`). The tests cover both.
- **Secrets on the socket:** the password in `unlock`, and the revealed and resolved values in the responses. They travel in plaintext inside the machine, only for the same UID, in buffers that are zeroed. `serde_json`'s internal copies can't be guaranteed (T33). `mlock` is postponed (ADR 0013).
- **Old clients:** a client with another protocol version gets `bad_request` with a clear message. Bumping the version means updating `klav` and `klavd` together, which ship together.
