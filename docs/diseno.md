# Klav — design document (v0.1)

> An open source, end-to-end encrypted password manager, built so that people **and agents** can use secrets without exposing them.

Status: **approved** (2026-11-02). Changes to this document are recorded as decisions in [`decisiones/`](decisiones/). Progress is tracked in [`roadmap.md`](roadmap.md).

---

## 1. Principles

1. **Zero-knowledge.** The server only stores encrypted data and minimal metadata. If it is hacked, no secrets leave with the attacker.
2. **The language model is not the agent.** The agent's *runtime* (your code) can be trusted with a key. The *LLM* (its context, the provider's logs, prompt injection) cannot. By default, Klav hands out **actions and references**, not values.
3. **Least privilege, enforced with cryptography.** An agent can only decrypt what was shared with its public key. The server's permissions are a second barrier, not the only one.
4. **Everything goes in the audit log, and nothing can be rewritten.**
5. **No home-made cryptography.** Only standard primitives with audited implementations (RustCrypto, `opaque-ke`, `hpke`).

## 2. Components

```
klav/                       (monorepo, workspace de Cargo + pnpm)
├─ crates/
│  ├─ klav-core       Rust · criptografía, modelo de elementos, formato de sincronización, TOTP, evaluación de políticas
│  ├─ klav-server     Rust · axum + sqlx (Postgres en el plan alojado, SQLite para alojarlo uno mismo)
│  ├─ klav-proto      Rust · tipos del protocolo HTTP compartidos por servidor y clientes (ADR 0007)
│  ├─ klav-cli        Rust · binario `klav` (incluye `klav mcp`)
│  ├─ klav-daemon     Rust · `klavd`: estado desbloqueado, Touch ID, host de native messaging, socket local
│  ├─ klav-wasm       Rust → WASM · núcleo para la extensión
│  ├─ klav-ffi        Rust → uniffi · núcleo para Swift/Kotlin
│  └─ klav-sdk        Rust · SDK para runtimes de agentes (también publicado en npm vía WASM)
├─ apps/
│  ├─ extension/       TypeScript · MV3 (Chrome, Firefox, Safari más adelante)
│  ├─ ios/             Swift · app + Credential Provider Extension
│  └─ android/         Kotlin · app + Autofill Service
├─ skill/              SKILL.md para agentes
└─ docs/               modelo de amenazas, especificación criptográfica, vectores de prueba
```

Everything that can be Rust is Rust. The extension's UI is TypeScript because the browser requires it, and the mobile UI is native Swift/Kotlin because the system's autofill extensions need it. Cryptography lives **only** in `klav-core`.

**Licenses:** `klav-server` under AGPL-3.0. Core, SDK, CLI and clients under Apache-2.0.

## 3. Data model

```
Cuenta
└─ Bóveda            límite criptográfico y de perfil: "Personal", "Trabajo", "Familia"
   └─ Proyecto       límite criptográfico más fino: "acme-api", "app-ios", "redes"
      └─ Elemento    login · tarjeta · identidad/dirección · llave SSH · archivo · TOTP · nota segura · API key
```

- **Vault = profile.** Work and Personal are separate vaults, with separate keys. They can be shown or hidden per device (for example, "on the work phone, only Work").
- **A project** groups within a vault. It is the unit normally shared with an agent and the one linked to a repository (see §7).
- An item has **typed fields** (`username`, `password`, `totp`, `file`, `text`, `concealed`…), tags, URLs (for autofill) and attachments.
- **Stable references:** `klav://<bóveda>/<proyecto>/<elemento>/<campo>`, for example `klav://trabajo/acme-api/stripe/api_key`. They can also go by ID so they don't break on renaming. Names are shown as they were typed (`klav://Mi bóveda/…`); only `%`, `/`, `?`, `#`, control characters and spaces at the ends of a name are `%`-encoded, and the old fully encoded form is still valid ([cli.md](cli.md) §4).
- On deletion, the item goes to a trash for 30 days. Each item keeps its version history.

## 4. Cryptography

### 4.1 Account keys

- **Master password + Secret Key** (128 random bits, generated at sign-up and included in the PDF "emergency kit"). Both go into the derivation. That way, even if the server's database is stolen, a brute-force attack against the password alone isn't possible.
- `KEK = HKDF(Argon2id(contraseña, salt, m=256MiB, t=3, p=4) ⊕ HKDF(secret_key))`
- **Authentication with OPAQUE** (`opaque-ke`): the server never sees the password or a hash that can be attacked offline.
- Each account has a **key pair**: X25519 for encrypting (HPKE) and Ed25519 for signing. The private key is stored encrypted with the KEK.

### 4.2 Key hierarchy

```
Llave de bóveda (256 bits aleatoria)  ── envuelta con HPKE para cada miembro (persona o agente)
  └─ Llave de proyecto                ── envuelta con la de bóveda y, si hay un grant, con HPKE para el agente
       └─ Llave de elemento           ── envuelta con la de proyecto
            └─ campos y adjuntos      ── XChaCha20-Poly1305
```

- AAD = `account_id ‖ vault_id ‖ project_id ‖ item_id ‖ version`. That way the server can't move an encrypted item somewhere else or roll it back to an earlier version without it being detected.
- Attachments (`.p8`, PDFs) are encrypted in chunks (STREAM) with their own key.
- Everything sensitive in memory is kept in `zeroize`/`secrecy`, and `mlock` is used where possible.

### 4.3 Unlocking with Face ID / Touch ID

- On the first unlock with the password, the device creates a **key in the Secure Enclave** (P-256, non-exportable, with the `biometryCurrentSet` ACL).
- That key wraps the *local unlock key* (which in turn opens the account's private key). Using it requires Face ID or Touch ID. If the enrolled biometrics change (for example, another fingerprint is added), the key is invalidated and the password is asked for again.
- **Mac:** `klavd` includes a small Swift shim (LocalAuthentication + Security.framework) linked through FFI. The binary is signed and notarized. The extension and the CLI ask `klavd` to unlock, so Touch ID works from the browser and from the terminal without a desktop app.
- **iOS:** the same, natively. **Android:** BiometricPrompt with a Keystore key backed by StrongBox or a TEE.
- Configurable policy: ask for the master password every N days (14 by default) and after a restart; lock after inactivity.

## 5. Agents

### 5.1 How does an agent get access? With its own key, never with yours

An agent is an **identity** with its own key pair, as if it were a device or a person you share things with. It doesn't know your master password or your Secret Key.

**Registration (pairing):**

1. On the agent's machine: `klav agent register --name "mi-agente"`. It generates an X25519 + Ed25519 key pair locally and sends a *request* to the server with the public key, the name and the permissions it asks for.
2. The request reaches your phone or your Mac. You see the name, the key's fingerprint (a short 6-word code that the terminal also shows, to confirm it is the same one) and choose:
   - which vaults or projects you share with it,
   - which permissions it has (§5.2),
   - what requires approval (§5.3),
   - when it expires.
3. You approve it with Face ID. **Your client** wraps those projects' keys with the agent's public key and uploads the *grant*. The server never sees the keys in the clear.
4. The agent stores its private key like this:
   - if it runs on your Mac: in the Keychain,
   - if it runs on a server (your personal agent): in a file with 0600 permissions, in an environment variable or in the cloud's KMS.

**Connecting an agent client** (Claude Code, Codex, Cursor, Claude Desktop, VS Code; ADR [0033](decisiones/0033-agentes-desde-la-app-de-mac.md)):

- **One agent per client,** with the client's name (`claude-code`, `cursor`…). That way the audit log tells one from another, and revoking or pausing one doesn't touch the others.
- `klav client connect <cliente>`, or "Connect" in the Mac app, registers the agent, writes the `klav mcp` entry in the client's configuration (with its CLI when it has one, or with a minimal edit that keeps the formatting, with a backup first) and installs the skill. Writing the entry doesn't grant access to anything.
- **The agent itself can connect** when the person asks it for something that needs a secret: it runs `klav client connect`, passes the person the 6 words and waits. **Approval is always the person's,** with Touch ID and with no projects checked. The person compares the words by eye, except when the app started the registration (ADR 0033 §3.1).

**Requests:** each request is signed with the agent's Ed25519 key (timestamp + nonce + hash of the body). There is no *bearer* token that can be stolen and reused.

**Pause** ("Pause agents", all of them or one, ADR 0033 §7):

1. It is **reversible**: the grant, the keys, the pending requests and the tasks don't change, and resuming restores everything as it was, without comparing words again.
2. It is **account state, signed by the account**, and **the server** enforces it on each signed request, like revocation. That way it also holds for an agent on another machine or one that doesn't go through `klavd`. `klavd` also enforces it on what it mediates, as a second barrier.
3. Pausing is immediate and asks for nothing; resuming asks for Touch ID, or the master password where there is none.
4. **It doesn't undo what is already under way:** a process that already received its variables, a file injected until its TTL, or what has already entered the LLM's context. For a stolen key, revoking and rotating are what help.

**Revocation:**

1. The server blocks the grant instantly.
2. Klav offers to **rotate the project key**, re-wrapping the item keys.
3. The audit log shows **which secrets that agent got to reveal**, so you rotate exactly those. Revoking doesn't make the agent forget what it already saw, and Klav says so explicitly.

Disconnecting a client (removing its `klav mcp` entry) doesn't cut off the agent: it still has its key and other paths (`klav agent run`, the SDK). What cuts it off is pausing or revoking.

### 5.2 Permissions

| Permission | What it allows | Default |
|---|---|---|
| `list` | see metadata (title, URL, username, kind); never secrets | ✅ |
| `fill` | fill a login or a card without returning the value to the LLM | ✅ |
| `inject` | `run` / `inject`: put secrets into a process or file (no TOTP seeds, ADR [0030](decisiones/0030-ronda-de-seguridad-2026-11.md)) | ✅ |
| `totp` | generate 2FA codes | ⚠️ ask: for that agent, 2FA stops being a second factor |
| `reveal` | return the value in the clear | ⛔ off |
| `create` | create items (for example, save a new API key) | ✅ |
| `update` | edit items | ask |
| `delete` | send to the trash | ⛔ off |
| `passkey` | sign in with one of the person's passkeys, through the browser (ADR [0020](decisiones/0020-passkeys.md)) | ⛔ only inside an approved task (ADR [0021](decisiones/0021-solicitudes-de-tarea.md)); no grant gives it |
| `rotate` | assisted password change (ADR [0022](decisiones/0022-generador-historial-y-cambio-asistido.md)) | ⛔ only inside an approved task (ADR 0021); no grant gives it |
| `proxy` | use the value inside an HTTP request that the credential proxy builds, without ever returning it (ADR [0036](decisiones/0036-sandboxes-de-agentes.md) §2) | ⛔ off; only in a per-item grant, with each rule's items, hosts, methods and path prefixes, and with `reveal`, `inject` and `fill` in `deny` |

Each permission can be scoped by **vault, project, tag or domain** (for example, `fill` only on `*.github.com`), by **schedule** and with an **expiry**.

### 5.3 Approvals

For each permission, the policy is `allow`, `ask` or `deny`. With `ask`, the agent receives a `pending_approval_id` and you get a push notification:

> **mi-agente** wants to *reveal* `trabajo/acme-api/stripe/api_key`
> Reason: "set up the test webhook"
> [Deny] [Approve once] [Approve 15 min]

It is approved with Face ID or Touch ID, and the approval is signed by your device in the audit log.

### 5.4 Where is it decrypted? Runtime versus LLM

- **Local MCP (`klav mcp`, stdio):** it runs as a child process of the agent, with the agent's key. It decrypts there and **carries out** the action (fill, inject). To the LLM it only returns `{"ok": true, "filled": ["username", "password"]}`.
- **SDK for your personal agent (`klav-sdk`):** if your agent drives a browser (Playwright, CDP), it calls `klav.fill(page, "klav://personal/redes/x")`. The secret goes from the SDK to the DOM and never passes through the model.
- **Extension in *your* browser:** the agent asks for `fill_login(url)` and the extension fills the tab. You see it happen.
- **`reveal`:** it is the path by which the value enters the LLM's context **directly**. That is why it is off by default.
- **`inject` is not a sealed channel** (ADR [0030](decisiones/0030-ronda-de-seguridad-2026-11.md) §2): the process `run` launches receives the value and can print it encoded or send it out, and Klav only masks in the output the literal value, its usual encodings (base64, hex, URL, JSON) and its pieces of 12 characters or more: a value encrypted or transformed in a custom way gets through. That is why an agent with `inject` can get to the value. It stays on `allow` because it is the agents' core flow, but without TOTP fields (those go through `totp`), and whoever doesn't want it sets it to `ask` or scopes it by project or tag.

### 5.5 MCP tools

All of them require the `reason` parameter (mandatory text, saved in the audit log).

| Tool | Permission |
|---|---|
| `search_items(query, vault?, project?, type?)` | list |
| `get_item(ref)`: metadata and field names, without values | list |
| `fill_login(url \| ref, target, submit?)`: target = `extension` or `sdk:<session>`; `submit` submits the form afterwards | fill |
| `fill_card(ref, target)` | fill |
| `run_with_secrets(command, env_map \| project)` | inject |
| `inject_file(template \| ref, path, ttl?)` | inject |
| `get_totp(ref)` | totp |
| `reveal(ref, field)` | reveal |
| `create_item(type, vault, project, fields, generate?)`: with `generate`, the runtime generates and seals the password without returning it (ADR [0022](decisiones/0022-generador-historial-y-cambio-asistido.md) §7) | create |
| `update_item(ref, patch)` | update |
| `delete_item(ref)` | delete |
| `change_password_url(ref)`: the site's change page | list |
| `rotate_password(ref, target, task_id?)`: only `target: "extension"`; returns `{filled, pending_id}` | rotate (in a task) |
| `rotate_confirm(ref, pending_id)` and `rotate_cancel(ref, pending_id)` | rotate (in a task) |
| `passkey_sign_in(ref, target, task_id?)`: only `target: "extension"`; `klavd` signs on the page and returns `{used, rp_id, expires_in_s?}` (ADR [0020](decisiones/0020-passkeys.md) §9) | passkey (in a task) |
| `request_access(scope, reason)`: asks the human for a permission it doesn't have | — |

The **skill** teaches the agent to search first with `search_items`, to prefer `fill`/`inject` over `reveal`, to always explain the reason and to ask for access instead of failing (ADR [0033](decisiones/0033-agentes-desde-la-app-de-mac.md) §6 and E3):

- **It is thin:** it only keeps the rules that hardly change, and how to connect if the agent isn't connected yet. The details of each tool (arguments, steps, what it returns) travel live in the `tools/list` descriptions and in the results' `next` and `warning`, inside the same binary.
- **It ships inside the `klav` binary,** with its version in `metadata.klav-skill-version`. `klav skill install|update|status` put it in the clients' folders and keep it up to date, and never overwrite a copy the person edited.
- **It is not a security barrier:** what prevents revealing a secret is the grant, the policy and the approvals.

## 6. Audit log

Each event stores:

```
{ id, ts, actor: {type: user|agent|device, id, name}, action, target_ref,
  result: ok|denied|pending|error, reason, approval_id?, ip, client, prev_hash, hash, sig }
```

- **Hash-chained:** each event includes the hash of the previous one.
- Client actions (people, agents, devices) are **signed by whoever performs them**, and trusted devices sign the head of the chain from time to time. That way, not even the server can delete or alter events without it showing.
- **Views** (ADR [0033](decisiones/0033-agentes-desde-la-app-de-mac.md) §8), all over this same chain, with no other store:
  - **per item**, "who used it" on its page: the agent, the action in words, when, the reason "according to the agent" and how it happened (allowed by the policy, approved, inside a task or denied);
  - **per agent**, "what it saw" (the projects it had and the items it used) and its timeline, with the tasks grouped;
  - **the full audit log**, with filters by agent, item, vault, permission, result, alerts, period and text, and at the top how far the chain is verified.

  Titles and URLs are resolved on the device; the audit log gains no fields for these views. `klav-client` keeps the already verified chain in its encrypted cache and only asks for what is new. It can be exported as JSON/CSV.
- **Pauses:** `agents.paused` and `agents.resumed`, with the bytes the account signed. `klav log verify` warns about an access allowed to a paused agent.
- **Alerts:** an agent's first use of a secret, bursts of accesses, accesses outside the schedule.

## 7. Injection and projects

```bash
klav run -- npm run dev                       # carga los secretos del proyecto como variables de entorno
klav inject -i .env.tpl -o .env               # sustituye las referencias en una plantilla
klav inject -r klav://trabajo/app-ios/apns/archivo -o ./AuthKey.p8 --ttl 10m
```

- **A `klav.toml` file in the repo** (no secrets, can be committed):

  ```toml
  project = "trabajo/acme-api"

  [env]
  STRIPE_KEY   = "klav://trabajo/acme-api/stripe/api_key"
  DATABASE_URL = "klav://trabajo/acme-api/postgres/url"

  [files]
  "secrets/AuthKey.p8" = "klav://trabajo/app-ios/apns/archivo"
  ```

- Inside that directory, `klav run` and the agents **are scoped to that project by default**.
- **Injected files:**
  - they are created with mode 0600,
  - `--ttl` deletes them when it runs out and `klav run` deletes them when the process exits,
  - if the path isn't in `.gitignore`, Klav warns.
- On Unix, `--fifo` can be used: the secret is read from a named pipe and never touches the disk.
- **Honest warning:** an injected file is plain text on disk while it exists. `run` is safer; `inject` exists for tools that only accept files (such as Apple's `.p8`).

## 8. MVP clients

| Client | MVP features |
|---|---|
| **CLI + `klavd`** (macOS, Linux) | login, unlock (Touch ID on Mac), CRUD, `run`/`inject`, TOTP, `agent register/list/revoke`, `mcp`, audit log |
| **Extension** | autofill of login/card/address, TOTP, saving new logins, password generator, `fill` for agents and approvals in the browser. It talks to `klavd` over native messaging for Touch ID; if there is no daemon, it asks for the password |
| **iOS** | unlock with Face ID, view and edit, Credential Provider (passwords + one-time codes, iOS 18+), push approvals, agent registration |
| **Android** | the same, with BiometricPrompt and Autofill Service |

Outside the MVP: a desktop app on Windows and Linux, SSH agent (`klavd` can do it later), sharing with other people, Windows. Passkeys were here; since ADR [0020](decisiones/0020-passkeys.md) (accepted on 2026-11-04) they have their own section in the roadmap. The Mac app also left this list: ADR [0027](decisiones/0027-app-de-mac.md) (accepted on 2026-11-05) makes it a native SwiftUI app with a menu bar and a window, a `klavd` client, that installs the CLI, the LaunchAgent and the browsers' *hosts* from a DMG.

## 9. Server

- axum + sqlx. **Postgres** for the hosted plan and **SQLite** for self-hosting with `docker compose up`.
- **Sync:** a revision per vault and encrypted deltas. Changes are announced over SSE/WebSocket.
- **Push** (APNs/FCM) for approvals. Whoever self-hosts the server can use the hosted plan's **push relay**, because the published apps only accept pushes signed with our credentials. This relay is a natural part of the paid plan's value.
- Rate limiting per account, agent and IP. No content telemetry.

## 10. Threat model (summary)

| Threat | Mitigation |
|---|---|
| The server's database is stolen | Everything is end-to-end encrypted; Secret Key + Argon2id; OPAQUE |
| The server is malicious | AAD against moves and old versions; vault keys signed by the account (ADR 0030); audit log signed by the clients; key fingerprints when pairing |
| Prompt injection against the agent | `reveal` off; `fill`/`inject` don't return values (though the process `inject` launches can get it out: residual risk, ADR 0030); scoped by domain; approvals |
| The agent's private key is stolen | Scoped grant with an expiry; immediate revocation; alerts; audit log to know what to rotate |
| The phone or the Mac is stolen | Secure Enclave + biometrics; automatic lock; password every N days |
| Local malware with root privileges | Out of scope (as in any manager); reduced with mlock, zeroize and fast locking |
| Supply chain | `cargo-vet`/`cargo-deny`, reproducible builds, signed binaries, SBOM |

## 11. Plan by phases (PRs stacked with `gh stack`)

1. **Phase 0 · Foundation:** monorepo, licenses, CI, `docs/threat-model.md` and `docs/crypto-spec.md` with test vectors.
2. **Phase 1 · `klav-core`:** KDF, key hierarchy, encryption of items and attachments, TOTP, item model and references.
3. **Phase 2 · `klav-server`:** accounts with OPAQUE, vaults/projects/items, sync, SQLite/Postgres.
4. **Phase 3 · CLI + `klavd`:** login, unlock, CRUD, `run`/`inject`, Touch ID on Mac.
5. **Phase 4 · Agents:** registration, grants, policies, approvals, chained audit log, `klav mcp`, skill, `klav-sdk`.
6. **Phase 5 · Extension:** autofill, saving logins, TOTP, `fill` for agents.
7. **Phase 6 · iOS:** app, Face ID, Credential Provider, push approvals.
8. **Phase 7 · Android.**
9. **Phase 8 · Launch:** importers (1Password `.1pux`, Bitwarden JSON, CSV), hosted plan, external audit.

Phases 1–4 already give something useful for your personal agent: CLI + MCP + Touch ID.

## 12. Open decisions

They are resolved as ADRs in [`decisiones/`](decisiones/) and checked off in the roadmap.

- Project mandatory or optional? (Proposal: optional; if none is given, it goes to the vault's "General" project.)
- Can the agent *create* projects, or only items inside existing projects?
- How many days between master password prompts? (Proposal: 14.)
- GitHub organization (`klav` is taken) and domain.
- Language of the public README (proposal: English before launch; the internal docs in Spanish).
