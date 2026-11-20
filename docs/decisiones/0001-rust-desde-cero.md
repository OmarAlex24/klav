# 0001 · From scratch and in Rust, with a shared core

- Status: accepted
- Date: 2026-11-02

## Context
We considered building the agent layer on top of Vaultwarden/Bitwarden to ship sooner. We want Klav to be its own product, with an agent model built into the cryptography, not bolted on top.

## Decision
We build from scratch. Core, server, CLI/MCP, daemon and SDK in Rust. The extension uses `klav-core` through WASM (with a TypeScript UI) and mobile through uniffi (with a native Swift/Kotlin UI). Cryptography exists **only** in `klav-core`.

## Consequences
- A single cryptographic implementation to audit, with shared test vectors.
- Mobile autofill and the extension take more time; that is why they come in milestone B, after the agents are working.
