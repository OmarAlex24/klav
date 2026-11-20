# Klav

**Open-source, end-to-end encrypted password manager built for humans and AI agents.**

Agents get **actions, not values**: connect Claude Code, Claude Desktop, Codex, Cursor, or VS Code so your agents can sign in to websites, run commands with API keys, and use passkeys — without ever seeing your passwords, with Touch ID / Face ID approvals and a verifiable audit log.

[Website (`klav.dev`)](https://klav.dev) · [Documentation (`docs.klav.dev`)](https://docs.klav.dev) · [What Klav does](docs/features.md) · [Security (`SECURITY.md`)](SECURITY.md) · [Contributing](CONTRIBUTING.md)

> **Public preview (`v0.9`):** Klav is self-hosted today and has not yet undergone an external security audit (planned before `1.0`). Use it with care while it matures, and report any security issue privately via [`SECURITY.md`](SECURITY.md).

---

## Why Klav?

Every coding agent you run today usually gets a raw copy of your `.env` files, long-lived API keys, or browser logins.

Klav treats each agent as its own cryptographic principal:

- **Zero-knowledge vault:** Your master password and 128-bit Secret Key never leave your devices. The server stores only ciphertext.
- **Scoped agent identities:** Pair an agent with 6 words and Touch ID / Face ID. Grant per-project permissions (`allow`, `ask`, `deny`) for `list`, `fill`, `inject`, `totp`, `create`, `update`, `delete`, `passkey`, `rotate`, and `reveal` (`reveal` is denied by default).
- **Actions instead of raw secrets:** `klav mcp`, the CLI, and the SDK fill browser logins (`fill_login`), use passkeys inside approved tasks (`passkey_sign_in`), and run commands with injected secrets (`run_with_secrets`, with output redaction) without returning secret values to the model.
- **Human-in-the-loop approvals & tasks:** Sensitive calls pause and prompt you on your Mac (Touch ID) or iPhone (Face ID). Approve once, for a time window, or bundle multi-site jobs into one revocable task.
- **Tamper-evident audit log & kill switch:** Every agent call is signed and hash-chained. Pause all agents in one click (even while locked) or revoke an agent to rotate project keys and see an exact "what did this agent see?" exposure report.

---

## What works today

### For AI agents
- **One-command client setup:** `klav client connect claude-code|claude-desktop|codex|cursor|vscode` configures MCP safely (with backups), installs the agent skill, and registers the agent.
- **MCP server (`klav mcp`), CLI (`klav agent …`), and SDK (`klav-sdk`, `@klav/sdk`):** Browser autofill via the extension or CDP, command execution with env/file injection (`klav run`, `klav inject`, `run_with_secrets`, `inject_file`), TOTP, task requests, and assisted password rotation.
- **Sandbox credential proxy (early preview):** `klav-proxy` and `klav-forward` keep real API tokens outside disposable sandboxes over a pinned TLS 1.3 channel (base-URL mode, `northflank` preset, `klav proxy` / `klav sandbox` CLI, and the Mac app's Active Sandboxes panel).

### For everyday passwords
- **Native Mac app:** Menu bar & window, Touch ID via `klavd`, vault editor, Vault Health, agent approvals & activity, automatic Sparkle updates (`Klav.dmg`, Apple silicon, macOS 15+).
- **Native iPhone app:** Face ID (Secure Enclave), AutoFill for passwords, TOTP codes, and passkeys, APNs push approvals (TestFlight beta, iOS 18+).
- **Browser extension:** Chromium (Chrome, Brave, Edge, Arc, Dia) and Firefox — multi-step login autofill, TOTP, passkeys, cards, addresses, generator, and agent `fill_login`.
- **CLI (`klav`) + local daemon (`klavd`):** macOS and Linux (`x86_64`, glibc 2.36+).
- **Importers:** Bitwarden JSON (including passkeys) & CSV, 1Password `.1pux` & CSV, Google Authenticator export QR codes, and Chrome/Edge/Brave/Firefox/Safari CSVs.
- **Vault health & assisted password change:** Detects reused, weak, old, and (opt-in) Have I Been Pwned breached passwords, and lets an approved agent rotate reused passwords without seeing them.

See [`docs/features.md`](docs/features.md) for the full feature-by-feature matrix across every surface.

---

## Quick start

1. **Host your server** (Docker Compose with SQLite, or Postgres / Railway — see [`docs/self-hosting.md`](docs/self-hosting.md) or [docs.klav.dev/self-hosting](https://docs.klav.dev/self-hosting/)):
   ```sh
   # Start once with registration open to create your accounts
   KLAV_ALLOW_REGISTRATION=true docker compose up -d --build
   # After creating your accounts, close registration
   docker compose up -d
   ```
   Put a reverse proxy with TLS (Caddy, nginx, Traefik) in front before connecting from other devices.

2. **Install Klav:**
   - **macOS:** Download `Klav.dmg` from [klav.dev/#download](https://klav.dev/#download) (or GitHub Releases), drag Klav to Applications, and run **Set up this Mac** to install `klavd`, `/usr/local/bin/klav`, browser native messaging, and the agent skill.
   - **Linux:** Download `klav-linux-x86_64.tar.gz` from [klav.dev/#download](https://klav.dev/#download) (contains `klav`, `klavd`, and `klav-native-host`).
   - **From source:** `cargo build --release -p klav-cli -p klav-daemon` (requires the Rust toolchain in `rust-toolchain.toml`).

3. **Connect an agent:**
   ```sh
   klav client connect claude-code   # or codex, cursor, vscode, claude-desktop
   ```

---

## Security & architecture

All cryptography lives in a single Rust crate ([`crates/klav-core`](crates/klav-core)) with versioned binary formats and test vectors in [`docs/vectores/`](docs/vectores/):

- **Key derivation:** Argon2id + 128-bit Secret Key → account KEK
- **Authentication:** OPAQUE (`opaque-ke`) — the server never sees your master password
- **Encryption:** XChaCha20-Poly1305 with bound AAD (`account‖vault‖project‖item‖version`), STREAM chunked attachments, and HPKE (RFC 9180) for wrapping project/item keys to agents
- **Signing & passkeys:** Ed25519 for signed agent requests, grants, revocations, and the hash-chained audit log; ES256 (`p256`) for synced WebAuthn passkeys
- **Safety:** Secrets wrapped in `secrecy::SecretBox` / `zeroize`; `unsafe` forbidden outside `klav-ffi` and the macOS Touch ID shim

Read the full architecture and security docs:
- [Public security overview](https://docs.klav.dev/security/)
- [Cryptography specification](docs/especificacion-cripto.md) · [Threat model](docs/modelo-de-amenazas.md) · [Design doc](docs/diseno.md)

---

## On the way

Designs accepted in [`docs/decisiones/`](docs/decisiones/) and planned for upcoming public releases (see [docs.klav.dev/on-the-way](https://docs.klav.dev/on-the-way/)):

- **Per-repository environments (`klav env`):** Named `development` / `production` variable sets, `.env` import, and Touch ID / `ask-once` protection on production secrets.
- **Transparent sandbox proxy (`HTTPS_PROXY` mode & MCP gate):** Zero-code-change credential injection for tools and MCP servers inside sandboxes, plus iOS active-sandbox management and egress pinning.
- **Deployed services:** Domain-challenged enrollment tokens, key ratcheting, clone detection, and keyless workload federation so leaked PaaS environment variables leave nothing long-lived to rotate.
- **Store listings & hosted server:** Chrome Web Store, Mozilla Add-ons, Apple App Store, and Klav's managed server (`api.klav.dev`, $20/year — [join the waitlist](https://klav.dev/#waitlist)).

---

## Repository docs

User-facing documentation is in English at [`apps/docs`](apps/docs) ([docs.klav.dev](https://docs.klav.dev)) and [`docs/self-hosting.md`](docs/self-hosting.md). Several internal reference documents and older ADRs under [`docs/`](docs/) are still migrating from Spanish to English ([ADR 0031](docs/decisiones/0031-repositorio-en-ingles-y-open-source.md)).

## License

- [`crates/klav-server`](crates/klav-server): [`AGPL-3.0-only`](crates/klav-server/LICENSE)
- Everything else (core, CLI, daemon, proxy, forwarder, SDK, browser extension, macOS & iOS apps): [`Apache-2.0`](LICENSE-APACHE)

See [ADR 0003](docs/decisiones/0003-licencias.md) for the licensing rationale.
