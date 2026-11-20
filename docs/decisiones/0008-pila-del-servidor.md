# 0008 · Server stack: axum, sqlx `Any`, SQLite and Postgres

- Status: accepted
- Date: 2026-11-02

## Context
The design (§9) settles on axum + sqlx, Postgres for the hosted plan and SQLite for self-hosting. We need to decide how code is shared between both databases, which dependencies the server brings in and what happens with TLS.

## Decision
1. **A single set of queries with `sqlx::Any`.** Queries use `$1, $2…` placeholders (both engines accept them) and only portable types: IDs as `TEXT` (canonical UUID), timestamps as `BIGINT` in Unix milliseconds, blobs as `BLOB`/`BYTEA` and flags as nullable timestamps. Migrations are two parallel directories (`migrations/sqlite`, `migrations/postgres`) with the same schema; the server picks one based on the URL scheme. The compile-time checked query macros are not used (they require a database at build time).
2. **Concurrency.** Every transaction that modifies a vault starts by taking its row (`UPDATE vaults SET revision = revision + 1 … RETURNING revision`). In Postgres this serializes writers to the same vault; in SQLite it makes the transaction a writer from the first statement (no `SQLITE_BUSY` errors when promoting it). Revisions end up in the same order as the commits.
3. **SQLite** uses WAL, a 10 s `busy_timeout` and foreign keys turned on.
4. **No TLS to Postgres for now.** sqlx's TLS options use `rustls` with `ring` or `aws-lc-rs`, and `ring` is banned in `deny.toml` (ADR 0005). Meanwhile, Postgres must be on a private network or a Unix socket. Enabling TLS (for example, with a `rustls` provider built on RustCrypto) will require another ADR before the hosted plan (phase 8).
5. **New non-cryptographic dependencies:** `axum`, `tokio`, `tower`, `tower-http`, `sqlx` (features `any`, `sqlite-bundled`, `postgres`, `runtime-tokio`, `migrate`, `macros`), `tracing`, `tracing-subscriber`, `toml`, `serde_json`, `thiserror`. In tests: `reqwest` without TLS and `tempfile`.
6. **Transitive cryptographic dependencies** that `sqlx-postgres` brings in for Postgres SCRAM-SHA-256 and MD5 authentication: `md-5`, `sha2` 0.10, `hmac`, `hkdf`, `rand`. They are RustCrypto, they only authenticate the database connection and they do **not** touch Klav data. All of Klav's cryptography stays in `klav-core`.
7. **In-memory rate limiting** (token buckets per IP, account and email) with no dependencies. With several instances, each one limits on its own.

## Consequences
- A single implementation of the logic, always tested against SQLite and against Postgres in CI (service container).
- Some engine-specific optimizations (`UUID`, `JSONB` types) are left out; they aren't needed because the server only stores blobs.
- Rate limiting, SSE notifications and the temporary login state live in memory: the hosted plan with several instances will need sticky routing or a shared bus (phase 8).
