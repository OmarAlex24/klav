# 0003 · AGPL for the server, Apache-2.0 for the rest

- Status: accepted
- Date: 2026-11-02

## Context
Klav is open source from day one, and the business is a cheap hosted plan. We don't want anyone reselling the server as a closed service, but we do want the SDK and the clients to integrate without friction.

## Decision
`klav-server` is AGPL-3.0-only. Everything else (core, CLI, daemon, SDK, WASM, FFI, apps) is Apache-2.0.

## Consequences
- Integrating `klav-sdk` into proprietary agents is allowed.
- External contributions: we will decide whether a DCO/CLA is needed before accepting the first external PR.
