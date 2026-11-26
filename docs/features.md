# What Klav does

This page lists everything Klav does, where you can do it, and what is still to come. It is the source for the README and the public docs.

It describes `main` as of 2026-11-19. Each line under "Works today" was checked against the code: the commands in `crates/klav-cli/src/cli.rs`, the tools in the `tools/list` of `crates/klav-cli/src/mcp.rs`, the `klavd` operations in `crates/klav-daemon/src/protocol.rs`, `klav-proxy`, `klav-forward`, and the app views. When a page and the code disagree, this page follows the code.

Most linked pages are still in Spanish. They move to English in waves ([ADR 0031](decisiones/0031-repositorio-en-ingles-y-open-source.md)).

## Statuses

- **Works today:** merged in `main` and tested.
- **Accepted, not built:** an accepted ADR describes it; the code is not there yet.
- **Idea, no ADR:** Omar asked for it, but nothing is designed yet.

## Surfaces

| Surface | What it is | Page |
|---|---|---|
| CLI | `klav`, the terminal client, on macOS and Linux | [cli.md](cli.md) |
| `klavd` | The local daemon. It keeps the vault unlocked in memory and asks for Touch ID on a Mac. Everything the extension and the Mac app do goes through it, and the CLI uses it when it runs | [klavd.md](klavd.md) |
| Extension | The browser extension for Chromium browsers (Chrome, Brave, Edge, Arc, Dia) and Firefox. It talks to `klavd`. Not in the stores yet | [extension.md](extension.md) |
| iOS app | The iPhone app, with Face ID and AutoFill. In TestFlight | [ios.md](ios.md) |
| Mac app | The menu bar app and window. It uses `klavd` | [macos.md](macos.md) |
| `klav mcp` | An MCP server over stdio that gives an agent Klav's tools, with the agent's own identity | [cli.md](cli.md#klav-mcp) |
| SDK | `klav-sdk` in Rust, and `@klav/sdk` for Node (`packages/sdk`), a wrapper around the `klav` binary | [cli.md](cli.md#sdk) |
| Skill | `skill/SKILL.md`, the rules an agent follows. It is built into `klav` and installed with `klav skill` | [cli.md](cli.md#la-skill-klav-skill) |
| Proxy & forwarder | `klav-proxy` and `klav-forward` (early preview). Keeps real API tokens outside disposable sandboxes over a pinned TLS 1.3 channel | [self-hosting.md §9](self-hosting.md#9-credential-proxy-klav-proxy), [try-sandboxes.md](try-sandboxes.md) |
| Server | `klav-server`. It stores only encrypted data. You host your own, or use Klav's own at `api.klav.dev`, free during its invite-only beta: you request an invite on klav.dev ([ADR 0048](decisiones/0048-invite-beta-and-distribution.md) §4) | [api.md](api.md), [self-hosting.md](self-hosting.md), [sitio-web.md](sitio-web.md) §3 |

## Works today: for people

### Your vault and its items

Item kinds: login, card, identity, SSH key, file, one-time code, secure note and API key. Items live in projects, and projects in vaults. Every item has a `klav://Vault/Project/Item` reference. Titles are unique in a project.

- **CLI:** `klav item add|attach|get|edit|sites|rm|ls|search|history`, `klav vault ls|create` and `klav project ls|create`. Values stay hidden unless you pass `--reveal`. `klav item ls --kind` filters by kind. [cli.md §4](cli.md#4-elementos)
- **Extension:** browse and search, with tabs by kind. Create a login, secure note, card or code by hand ("New item"). Update a login from the save bar. There is no form to edit any field of an existing item. [extension.md §7](extension.md#7-the-popup)
- **iOS app:** view, search, create, edit and move to the trash, with tabs by kind. [ios.md §1](ios.md#1-architecture)
- **Mac app:** view, search, create, edit and move to the trash ("New item", ⌘N), show and copy values, open sites and copy references. [macos.md §2](macos.md#2-barra-de-menús-y-ventana)
- **Files** are stored as encrypted attachments with `klav item attach`. Only the CLI and agents can write a file out (`klav inject -r`, `inject_file`). The apps list file items but do not show or save the file.
- **Trash:** the CLI (`klav item rm`), the iOS app and the Mac app move an item to the trash. The extension cannot. No client can restore it yet, although the server has the route.
- **Sites an agent added** to a login wait for you to confirm them, and only confirmed sites are filled. Confirm or remove them with `klav item sites`, in the popup, in the iOS app or in the Mac app.

### Sign in to sites

- **Extension:** fills logins on the page, with a menu in the field, a sign-in card and a central search. It handles multi-step sign-ins (email first, then password, then code). It saves or updates a login when you submit a form. It checks the site before it fills, and a login saved for a subdomain is offered on the parent site only if you choose it. [extension.md §5](extension.md#5-autofill)
- **iOS app:** AutoFill for passwords in Safari and other apps. [ios.md §3](ios.md#3-autofill)
- **Mac app:** copy the username or password from the menu bar search. The clipboard stays on this Mac and clears after 30 seconds.
- **CLI:** `klav item get <item> --reveal`, or `--field` for one value.

### One-time codes

- **CLI:** `klav totp <item>`, and `klav item ls --codes`.
- **Extension:** live codes in the popup and its "Codes" tab, copy with one click, and the code filled on the page after the password. [extension.md §6](extension.md#6-saving-generating-and-one-time-codes)
- **iOS app:** the "Codes" view, codes in AutoFill (iOS 18 or later), and Klav in "Set up codes in" so a site's `otpauth://` link saves its code in Klav. [ios.md, ADR 0035](ios.md#set-up-codes-in-klav-adr-0035)
- **Mac app:** the live code in the item, and "Code" to copy from the menu bar.

### Passkeys

- **Extension:** create and use passkeys stored in Klav, in Chromium browsers and Firefox, also from the field's menu. You can hand a request back to the browser. The popup sets how often Klav asks for Touch ID. [extension.md §13](extension.md#13-passkeys)
- **iOS app:** a passkey provider in AutoFill. A passkey created there syncs when you open the app. [ios.md §3](ios.md#passkeys-adr-0020-11)
- **Mac:** through the extension and `klavd`. The Mac app has no passkey view.
- **Import:** passkeys from a Bitwarden JSON export.
- The CLI has no passkey commands.

### Cards and addresses

- **Extension:** fills cards and addresses (identity items) on any page.
- **iOS app and Mac app:** copy from the item. iOS AutoFill does not fill cards.
- **CLI:** `klav item get`.

### Password generator and password history

- **Generator:** smart (follows the site's password rules), random, memorable and PIN. CLI `klav generate`, the extension (in the menu of new password fields), the iOS app (in the item editor and Settings › Passwords) and the Mac app (in the item editor). [cli.md](cli.md#generar-contraseñas)
- **Generator history:** every generated password is kept before it is used, so a failed sign-up does not lose it. CLI `klav generated ls|show|rm`, the extension and the iOS app. [ios.md](ios.md#generator-and-previous-passwords)
- **Password history** of each item: CLI `klav item history`, the extension, the iOS app and the Mac app ("Previous passwords").

### Vault health and assisted password change

- **Vault health:** reused, weak and old passwords, and breached ones if you turn on the check with Have I Been Pwned (off by default). CLI `klav health` and `klav health breach-check on|off`, the popup's "Health" view, iOS (Settings › Passwords) and the Mac app ("Vault health", ⌘4). [cli.md](cli.md#salud-de-la-bóveda)
- **Fix my reused passwords:** you offer an agent a task to change your reused passwords, one site after another. The agent gets the sites, never the list of passwords. CLI `klav health --fix-with <agent>`, the popup, the iOS app and the Mac app ("Vault health"). [cli.md](cli.md#arreglar-las-repetidas-con-un-agente)
- **Assisted password change:** an agent changes a password in your browser without seeing it (the `rotate_password` tool, [below](#the-tools-an-agent-uses)). The new password is kept as pending until the site accepts it. The "Pending change" card asks you to keep the new one or the current one, in the popup and the iOS app. [extension.md §8](extension.md#assisted-password-change)

### Import from another password manager

Bitwarden (JSON without a password, with passkeys; CSV), 1Password (`.1pux`; CSV), Google Authenticator (photos of its export QR codes, or the `otpauth-migration://` links), and the CSV of Chrome, Edge, Brave, Firefox and Safari. A repeated login is merged, not duplicated, and a replaced password goes to the item's history. Authy has no export; the docs explain how to move each code by hand.

- **CLI:** `klav import <file>…`, with `--dry-run` and `--json`. [cli.md](cli.md#importar)
- **Extension:** "Where are you coming from?" [extension.md §12](extension.md#12-import)
- **iOS app:** the same, with the camera or Photos for the QR codes. [ios.md §8](ios.md#8-import)
- Not in the Mac app.

### Your account, devices and servers

- **Create an account** on a device: CLI `klav signup` and the Mac app's "Set up this Mac". **Sign in:** CLI `klav login`, the Mac app and the iOS app. The server is `api.klav.dev` by default; "Use my own server" points to yours. On a server in invite mode, both ask for an invite code (`--invite`, `KLAV_INVITE` or a prompt in the CLI; "Invite code" in the Mac app) and check it before the password. When a server's per-account quota would be exceeded, they show its message. [cli.md §3](cli.md#3-cuenta-y-dispositivos)
- **Emergency kit** with the Secret Key: shown when you create the account, and again with `klav account kit`, or "Print the emergency kit" on iOS.
- **Unlock:** Touch ID on a Mac through `klavd`, Face ID on the iPhone, or the master password. `klavd` locks after a time without use (15 minutes by default) and when the computer sleeps. Unlocking in the Mac app also unlocks the extension and the CLI. [klavd.md §6](klavd.md#6-touch-id-macos)
- **Move to another server URL:** `klav account set-server`, and "Use another server" in iOS Settings.
- **Sync and offline:** reads use the local copy and sync in the background. A server that serves older data than this device saw is refused as a rollback (exit code 3). `klav sync --reset-cache` starts again after a restore you trust.
- **Sign out and delete this device's copy:** `klav logout`, and "Delete this iPhone’s copy" or "Delete this Mac’s copy" after an account deletion.
- **List or remove your devices:** the server has the routes, but no client offers them yet.

### Delete your account

You ask, Klav waits 7 days, then deletes everything the account has on the server. You can cancel during the wait from any device. While it waits, every agent stops.

- **CLI:** `klav account delete` and `klav account delete --cancel`.
- **iOS app:** Settings › Account › "Delete my account". [ios.md §11](ios.md#11-deleting-the-account)
- **Mac app:** Settings (⌘,) › Account. [macos.md §8](macos.md#8-borrar-la-cuenta)
- Not in the extension.

### Host the server yourself

- `docker compose up` with SQLite, or Postgres. TLS through a reverse proxy (Caddy or nginx). Registration is closed by default in `docker-compose`. [self-hosting.md §1](self-hosting.md#1-quick-start-with-docker-compose)
- A Railway image and its steps. The Railway template is not published yet. [self-hosting.md §8](self-hosting.md#8-railway)
- Push notifications for approvals need your own APNs key.
- Limits: one instance only, attachments on local disk only (no S3), and no way to change the master password or recover the account. [self-hosting.md §6](self-hosting.md#6-known-limitations)

## Works today: for agents

An agent has its own identity and a grant you approve: a set of projects and a policy that says `allow`, `ask` or `deny` for each permission (`list`, `fill`, `inject`, `totp`, `reveal`, `create`, `update`, `delete`, `passkey`, `rotate`). Every action needs a reason and goes to the audit log. By default agents get actions, not values: Klav puts the secret where it is used, and the agent never sees it.

### Connect an agent

- **Agent clients:** Claude Code, Claude Desktop, Codex, Cursor and VS Code. `klav client connect <client>` adds Klav's MCP entry to the client's settings (with a backup), installs the skill and registers the agent. `klav client list|disconnect|restore` manage it. [cli.md](cli.md#conectar-un-cliente-de-agentes-klav-client)
- **Any other runtime:** `klav agent register --name <name>`.
- **Six words:** the agent prints six pairing words, and you compare them when you approve. Approve with `klav agent approve`, in the Mac app (Requests) or on the iPhone.
- **The skill:** `klav skill status|install|update|uninstall|show`. An edited copy is never overwritten. The Mac app installs it from "Set up this Mac" and keeps it up to date.
- **Mac app:** Development › Clients connects or disconnects a client, with a summary of the change before it writes.

### The tools an agent uses

`klav mcp` gives an agent these tools. The CLI has `klav agent run|inject|fill|totp|task|browser` for the same actions without MCP, and the SDK has them for code.

| Tool | What it does | CLI without MCP | SDK |
|---|---|---|---|
| `search_items`, `get_item` | Find items and read their metadata, never values | — | Rust `Session::items`, `Session::item_info` |
| `fill_login` | Type a login into a browser page, optionally submit | `klav agent fill` | Rust `fill`; Node `fill` |
| `fill_card` | Type a card into a browser page | `klav agent fill` | Rust `fill` |
| `run_with_secrets` | Run a command with secrets in its environment; the output comes back redacted | `klav agent run` | Rust `run`; Node `run` |
| `inject_file` | Write secrets or an attachment into a new 0600 file | `klav agent inject` | Rust `inject_file`; Node `inject` |
| `get_totp` | A one-time code, typed into the page or returned | `klav agent totp` | Rust `Session::totp`; Node `totp` |
| `reveal` | A value into the agent's context. Denied by default | — | Rust `Session::access` |
| `create_item`, `update_item`, `delete_item` | Change items. `create_item` can generate a password the agent never sees | — | Rust `Session::create_item`, `update_item`, `trash_item`, `create_item_generated` |
| `request_access` | Ask you for a permission instead of failing | — | Rust `Session::access` |
| `request_task`, `get_task`, `list_tasks`, `end_task` | Tasks (see below) | `klav agent task request\|wait\|show\|end` | Rust and Node |
| `change_password_url`, `rotate_password`, `rotate_confirm`, `rotate_cancel` | Assisted password change | — | Rust `klav_sdk::rotate` |
| `passkey_sign_in` | Sign in with your passkey, inside a task | — | Rust `klav_sdk::passkeys` |

The Rust SDK has every action. With only `klav agent …`, an agent cannot search, read metadata, change items, use `reveal` or `request_access`, change a password or use a passkey. The Node SDK has fill, run, inject, codes, approvals and tasks, and nothing else yet. Pages: [cli.md §9](cli.md#9-agentes), [cli.md, `klav mcp`](cli.md#klav-mcp).

### Use a login without seeing it

- The agent fills the page through Chrome's DevTools protocol (a `--cdp` address, or a browser it named with `klav agent browser register`) or through your extension (`target: "extension"`, your active tab). [extension.md §8](extension.md#8-agents)
- Klav checks the page's address against the item, types the password only into a password field that has the focus, and submits only a form on the page's own origin.
- The answer has field names and, after submit, the address it reached. Never the values.

### API keys and files in commands

- **For you:** `klav run -- <command>` with `klav.toml` or `-e NAME=klav://…`, and `klav inject` to write a template or one value into a 0600 file, with `--ttl` and `--fifo`. [cli.md §6](cli.md#6-klav-run), [cli.md §7](cli.md#7-klav-inject)
- **For agents:** `run_with_secrets` and `inject_file`, or `klav agent run|inject`. The output comes back with the values replaced by `[redacted by klav]`. That is a safety net for a command that prints a value by mistake, not a sealed channel: the command has the value, and an agent that writes the command can get it out. A TOTP seed is never injected.

### Grants and policies

- `klav agent approve` sets the projects or vaults, `allow`/`ask`/`deny` per permission, the sites where `fill` works (`--fill-domain`), weekly hours, an expiry and a policy file. Running it again changes the grant.
- **Change a grant:** the CLI (`klav agent approve` on an active agent) and the Mac app (Development › Agents › "Change permissions…"). Both show only what changes before anything is signed. Widening asks for Touch ID or the master password; narrowing asks for nothing. The iOS app shows agents but cannot change their permissions yet.

### Approvals and tasks

- **Approvals:** when the policy says `ask`, the agent's request waits for you. Approve once, for a while ("approve for 15 min", up to 24 h), or deny. The agent waits in the background (`klav approval wait`) and retries with the approval. [cli.md](cli.md#aprobaciones-ask)
- **Tasks:** before a job over several items or sites, the agent asks once with `request_task`. You see one card, uncheck what you don't want and approve. "End task" stops it. `reveal` and `delete` never go in a task; `passkey` and `rotate` only work inside one. A request outside the task can be approved once or added to the task. [cli.md](cli.md#tareas)
- **Where you decide:** CLI `klav approval` and `klav task`, the popup, the iOS app (with push notifications and Face ID), and the Mac app's Requests (with Touch ID or the master password).

### Audit log

- Every agent action is in a hash chain with signed events: who, what, which item, why, and how it was decided.
- **CLI:** `klav log`, filtered by item, agent, vault, time, alerts, permission, outcome, text or task, as text, JSON or CSV. `klav log verify` checks the chain and exits with 3 if it was altered. `klav agent show` lists what an agent used. [cli.md](cli.md#bitácora)
- **Mac app:** Development › Activity (⌘5) and "Who used it" on each item.
- **iOS app:** "Activity" in the Agents sheet. [ios.md §10](ios.md#10-agents-the-pause-and-the-activity-adr-0033-9)
- Not in the extension.

### Pause and revoke

- **Pause agents:** every agent or one, now, for a time or until you resume. Pausing asks for nothing; resuming asks for Touch ID, Face ID or the master password. A paused agent gets `paused` from every tool and exit code 7 from `klav agent …`.
  - CLI `klav agent pause|resume`, the Mac app (menu bar and Development › Agents, also while locked) and the iOS app (Agents sheet).
- **Revoke an agent:** `klav agent revoke`, which prints what the agent used; `--rotate` also changes the keys of its projects. The Mac app (Development › Agents › "Revoke…") and the iOS app (the Agents sheet, "Revoke…") revoke too, show what the agent used, and offer to change its projects' keys.

### Agent sandboxes with a credential proxy (preview)

An agent running in a disposable sandbox holds only a one-time sandbox credential claimed over a pinned TLS 1.3 channel (`klav-forward`). Your self-hosted `klav-proxy` injects the real API token into allowed upstream requests and revokes access immediately when the sandbox stops or expires ([ADR 0036](decisiones/0036-sandboxes-de-agentes.md), [ADR 0042](decisiones/0042-sandboxes-for-daily-use.md)).

- **CLI:** `klav proxy use|status|grant|revoke`, `klav proxy issuer add|remove`, `klav proxy sandboxes [revoke]`, `klav proxy local status|revoke|init` (the proxy on this machine, through its local socket, with the vault locked), `klav proxy grant --preset northflank`, and `klav sandbox start|stop|ls`.
- **Proxy & forwarder:** `klav-proxy` (mode (a) base-URL forwarding, per-item grants, SSRF defense, response redaction, `--no-local-calls`, memory locking and no-core-dump hardening, Docker image & systemd unit) and `klav-forward up|status|env|down`, plus daily Boat sandbox helpers (`deploy/sandbox/`, `deploy/sandbox-template/`). [self-hosting.md §9](self-hosting.md#9-credential-proxy-klav-proxy), [try-sandboxes.md](try-sandboxes.md)
- **Mac app:** Development › Sandboxes (⌘7) shows the account's proxy, signed heartbeats, theft signals, and active sandboxes with one-click Revoke / Revoke all (without Touch ID). The proxy can run on the Mac as a LaunchAgent (Start and Stop in Development › Sandboxes and › MCP servers): the panel then says "On this Mac", shows each sandbox's live connection, and the menu bar revokes them while Klav is locked ("Revoked on this Mac"). A sandbox reaching the Mac's proxy still needs `klav-proxy serve --channel` by hand.

## Accepted, not built

- **Add a device with a QR code** ([ADR 0029](decisiones/0029-anadir-dispositivo-con-qr.md)): sign in on a new device from one that is already signed in, without typing the Secret Key. [Roadmap](roadmap.md#añadir-un-dispositivo-con-un-qr-aceptado-adr-0029)
- **Environments per repository** ([ADR 0032](decisiones/0032-entornos-por-repositorio.md)): `development` and `production` sets of variables for a repository, with `production` protected by Touch ID and by agent policy. The format, the server's rules, the CLI (`klav env`, `klav run --env`, `klav inject --env --dotenv`, `klav env scan`), the protection in `klavd` and the agents' side (`klav agent approve --env`, `klav agent run --env`, `environment` in `run_with_secrets` and `@klav/sdk`, one approval for a protected environment and the items it points to, and the runtime's own check of the protected flag) are built; the popup and the iOS and Mac apps are not, so the public docs keep it under On the way. [Roadmap](roadmap.md#entornos-por-repositorio-aceptado-adr-0032)
- **More for agent sandboxes** ([ADR 0036](decisiones/0036-sandboxes-de-agentes.md), [ADR 0044](decisiones/0044-proxy-key-at-rest.md)): transparent `HTTPS_PROXY` interception (mode (b)), the MCP gate (mode (c)), additional presets (`railway`, `maple`), the iOS Active Sandboxes panel and per-call approval push cards, Tailscale with per-sandbox ephemeral keys for the proxy on a Mac, and proxy egress-network alerts and pinning. [Roadmap](roadmap.md#sandboxes-de-agentes-con-un-proxy-de-credenciales-aceptado-adr-0036)
- **The MCP gateway** ([ADR 0049](decisiones/0049-mcp-gateway.md)): your own `klav-proxy` takes your agents, in sandboxes and on your Mac, to remote MCP servers (Maple, GitHub, Cloudflare…) without the provider's key in any agent's config, with allow, ask and deny per tool signed in the grant, unlisted tools denied and hidden, and every tool call in the audit log. The format, the server switch, the audit checks, the proxy, the CLI and the Mac and iOS apps are built; the hand tests against real MCP servers are not, and every gateway preset is refused until its hand test, so it isn't ready to use yet. [Roadmap](roadmap.md#la-pasarela-mcp-servidores-mcp-remotos-por-klav-proxy-con-reglas-por-herramienta-aceptado-adr-0049)
- **Klav Cloud's hosted proxy** ([ADR 0051](decisiones/0051-hosted-nitro-enclave-proxy.md)): a credential proxy Klav runs inside an AWS Nitro Enclave, so sandboxes keep working while every device of yours is off, without a proxy of your own. Your devices check, in `klav-core`, that the enclave runs an image Klav published and that it holds the keys they wrap for, before they share anything with it. A later, higher tier, first for invited beta accounts. Built: the verification in `klav-core`, the server's per-account switch, the enclave's engine (with a fake NSM in tests), and the clients (`klav proxy use klav`, `klav proxy cloud`, the Mac and iPhone rows), which check the enclave before every grant. The AWS infrastructure and the reproducible enclave image are written but not deployed. Not built: the release-authority keys (until they are pinned, every client fails closed), so nothing is deployed. The public docs mention it only on the Sandboxes page under On the way. [Roadmap](roadmap.md#el-proxy-alojado-de-klav-cloud-en-un-aws-nitro-enclave-aceptado-adr-0051)
- **Deployed services** ([ADR 0038](decisiones/0038-deployed-services.md)): an app on a PaaS keeps only a service ID and a low-value enrollment token. Each instance proves it runs behind the service's domain, its key ratchets, clones are detected, usage is recorded, and incident mode freezes everything. Where the provider accepts a signed workload identity (Anthropic first), your proxy holds no provider key for the service, only a signing key from your vault and tokens that expire in 10 minutes; elsewhere the key gets the provider's limits ([ADR 0045](decisiones/0045-keyless-services.md)). Copy detection for sandboxes is designed and built with the services. [Roadmap](roadmap.md#siguiente-fase--servicios-desplegados-que-un-paas-filtrado-no-deje-nada-que-rotar-adr-0038-aceptado-la-fuente-única-y-los-canaries-aún-sin-adr)
- **Presence before `klavd` hands out a value, and the `inject` card with the command** ([ADR 0041](decisiones/0041-presence-for-values-and-the-inject-card.md)): the terminal, the browser extension and any other program ask for Touch ID (on Linux, the master password) once per window and per terminal session or browser, 5 minutes by default, before reading a value; the Mac app's own unlock counts as its presence until Klav locks, and with the setting on Always every value asks, the app included. An agent's `inject` approval shows the command or file, according to the agent, encrypted to your devices, and "for a while" covers only that command in that folder. Today neither exists: an unlocked `klavd` gives values to any program of your user, and the card shows the agent, the item and the reason. The public docs don't list it until Omar says so ([ADR 0039](decisiones/0039-public-docs-site.md), amendment of 2026-11-13). [Roadmap](roadmap.md#presencia-para-los-valores-y-la-tarjeta-de-inject-aceptado-adr-0041)
- **Change an agent's permissions from the iPhone** ([ADR 0033](decisiones/0033-agentes-desde-la-app-de-mac.md), amendment of 2026-11-10): the Mac app and the CLI already do it, and the iPhone already revokes. [Roadmap](roadmap.md#agentes-desde-la-app-de-mac-aceptado-adr-0033)
- **In the stores** (Omar's decision of 2026-11-13; [roadmap](roadmap.md)): the extension in the Chrome Web Store and on addons.mozilla.org, and the iPhone app in the App Store. Until then the Chromium build is a zip loaded by hand, the Firefox build an `.xpi` Mozilla signs without listing it ([releasing.md](releasing.md) §3), and the iPhone app a TestFlight beta. The public docs list them under On the way, and the landing page under "Also on the way" ([ADR 0039](decisiones/0039-public-docs-site.md) §3 and its amendment of 2026-11-13; [sitio-web.md](sitio-web.md) §6).
- **Also decided, not built:** opening `api.klav.dev` to everyone after its invite-only beta, with sign-up without an invite and the hosted plan of 20 USD a year, announced to beta accounts at least 60 days ahead ([ADR 0048](decisiones/0048-invite-beta-and-distribution.md) Q1 and Q5; the waitlist is now the queue of beta invites), attachments in S3 and email verification at sign-up ([ADR 0010](decisiones/0010-decisiones-fase-3-y-plan-alojado.md)), and a push relay for self-hosted servers ([ADR 0018](decisiones/0018-app-ios.md), phase 8). Unlocking the extension without `klavd` is postponed ([ADR 0017](decisiones/0017-extension-de-navegador.md) §2).

## Idea, no ADR

- **Personal agents in the cloud,** such as Muse, Grok Bot and Dots, using your passwords without seeing them. [Roadmap](roadmap.md#agentes-personales-en-la-nube-idea-de-omar-sin-adr)
- **Spend caps** for deployed services. ADR 0038 leaves them for a later version (its Q-A).
- **A single source of truth with `klav rotate`:** Klav pushes values to the PaaS and rotates a key in every place with one command.
- **Canaries** in PaaS variables, to detect a leak.
- **Android** (phase 7). [Roadmap](roadmap.md#fase-7--android)
- More, without a date: a desktop app for Windows and Linux, an SSH agent in `klavd`, sharing with other people, and Safari. [Roadmap](roadmap.md#después-sin-fecha)

## Gaps by surface

What works on some surfaces and not others, in one place:

| Surface | Missing today |
|---|---|
| Mac app | Import, generator history, the "Pending change" card |
| iOS app | Card AutoFill, changing an agent's permissions |
| Extension | Editing an existing item by hand, moving an item to the trash, the audit log, agent management, deleting the account |
| CLI | Passkeys |
| Every client | Restoring from the trash, listing or removing devices |
| `klav agent …` (no MCP, no SDK) | Search, item metadata, changing items, `reveal`, `request_access`, assisted change, passkeys |
| Node SDK | Search, item metadata, changing items, `reveal`, `request_access`, assisted change, passkeys |

The consolidation round brings the Mac app closer to the others ([roadmap](roadmap.md#ronda-de-consolidación-2026-11-10)).

## Keeping this page true

When a PR adds, removes or moves a capability, it updates this page in the same PR. When this page and the code disagree, the code wins and this page is fixed.
