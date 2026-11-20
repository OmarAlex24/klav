# 0007 · `klav-proto` crate for the HTTP protocol

- Status: accepted
- Date: 2026-11-02

## Context
Phase 2 defines the server's HTTP API (JSON request and response bodies). Those types are used by two sides with different licenses: the server (`klav-server`, AGPL-3.0, ADR 0003) and the clients (CLI, daemon, SDK, WASM, FFI; Apache-2.0). If the types lived in the server, no client could depend on them without inheriting the AGPL. Putting them in `klav-core` would mix the transport format (JSON, base64, error codes) with the cryptography and the model, and would force a rebuild of the core for any API change.

## Decision
We create `crates/klav-proto` (Apache-2.0) with the protocol types:

- `Blob`: opaque bytes that go in JSON as unpadded base64url (RFC 4648 §5). Its `Debug` only shows the length.
- Request and response bodies for each endpoint, errors (`ErrorBody`, `ErrorCode`) and API constants.
- Identifiers reuse the types in `klav_core::ids` (in JSON, a UUID in canonical form).

`klav-proto` contains no cryptography and no logic: only `serde`. The binary format of each `Blob` is still defined in `docs/especificacion-cripto.md` and implemented in `klav-core`. The API reference is in `docs/api.md`.

## Consequences
- The CLI, the daemon and the SDK (phases 3 and 4) use exactly the same types as the server and don't depend on AGPL code.
- `cargo-deny` still prevents anything from depending on `klav-server`.
- An incompatible API change requires a new route (`/v2/…`) or an optional field; the `/v1` prefix goes on every route.
