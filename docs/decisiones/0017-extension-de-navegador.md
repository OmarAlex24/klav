# 0017 · Browser extension: thin client of `klavd` over native messaging, `klav-wasm` for the pure parts and the no-daemon mode postponed

- Status: accepted
- Date: 2026-11-02

## Context
Phase 5 brings the browser extension (design §8, roadmap): autofill for logins, cards and addresses, TOTP, saving logins, password generator, `fill_login` with the `extension` target for agents and approvals from the browser. The roadmap says "native messaging with `klavd` (Touch ID); password if there is no daemon", and ADR [0001](0001-rust-desde-cero.md) says the extension uses `klav-core` through WASM.

We need to decide:

1. where the unlocked account lives and who decrypts;
2. what the WASM does;
3. how the extension talks to `klavd` and how to check who is on the other end;
4. how an agent's request reaches the tab;
5. what the *content script* (the code that runs inside the page) receives;
6. what to do with the "no daemon" mode.

## Decision

### 1. The extension is a thin client of `klavd`
The unlocked account, Touch ID, sync, the encrypted cache, *rollback* detection and approval signatures stay in `klavd` (ADR [0012](0012-daemon-klavd.md)). The extension stores no key and no value: it asks `klavd`, over native messaging, only for what it needs at each moment.

- **Unlock:** the *popup* sends `unlock` without a password (Touch ID, ADR [0013](0013-touch-id-secure-enclave.md)). If Touch ID isn't available, fails or isn't set up, the *popup* asks for the master password and sends it in `unlock` (**password unlock through the daemon**). The end-to-end tests use this path.
- **Lock:** `klavd` decides it (idle, sleep, screen locked). The extension has no timer of its own: it asks for the state and shows "locked" when `klavd` answers `locked`. The *popup*'s lock button sends `lock`.
- The extension **stores nothing in `chrome.storage`** except preferences with no secrets (shortcut, showing the icon in fields). Neither values nor vault metadata.

### 2. The no-daemon mode is postponed
A standalone mode with the password inside the extension is not an "alternative": it is a second `klav-client` in WASM. It would need:

- enrolling the extension as a device (OPAQUE login with the emergency kit);
- delta sync with the anti-*rollback* marks (T7) and its own encrypted cache in browser storage;
- unwrapping the vault keys with HPKE, renewing the session with single-use *refresh tokens* shared with nobody;
- signing approvals with the account identity;
- a 256 MiB Argon2id inside a *service worker* that the browser can kill after 30 s.

It is a new surface to audit (the account key would live in the browser process, next to every page) for a case that doesn't exist today: `klav` and `klavd` are installed together, and the extension is useless without the CLI to create the account. That is why **phase 5 ships only the daemon mode**. The roadmap checkbox is split: "native messaging with `klavd` (Touch ID or password)" is done; "password without a daemon" stays open, for when there is a reason (for example, the extension on a machine without the CLI). If it is done, it will be its own ADR and will use `klav-client` compiled to WASM, not a new TypeScript client.

### 3. `klav-wasm` carries the pure parts that have to match Rust
The WASM is loaded in the *background* and in the extension pages (never in the *content script*). It exports, with `wasm-bindgen`, `klav-core` functions with no state and no vault secrets:

- **site matching:** `fillable_host(url)` and `host_matches(host, urls)`, the anti-*phishing* rule (§5) that used to live in `klav-sdk`. It moves to `klav-core::site` and is used by the SDK, `klavd` and the extension. That way the rule is a single implementation in three places;
- the password and passphrase **generator** (`klav-core::generator`), for new-password fields even when `klavd` is locked.

There is no vault cryptography in the WASM or in TypeScript. The generator uses `getrandom` with `crypto.getRandomValues` (feature `wasm_js`, only on `wasm32`). The extension's CSP allows `'wasm-unsafe-eval'` to instantiate that bundled WASM; there is no remote code.

`klav-core` gains the `url` dependency (WHATWG, MIT/Apache-2.0), which is not cryptographic and was already in the tree through `reqwest`.

### 4. Native messaging: its own binary, `klav-native-host`
The browser launches the native messaging *host* as one process per connection, with the fixed path from the manifest, with no arguments of its own, and kills it when the port closes. `klavd` has to outlive the browser and must not mix that lifecycle with its own. That is why the *host* is a small binary, `klav-native-host`, in the `klav-daemon` crate, which only acts as a bridge:

```
extensión ──(stdin/stdout, 4 bytes de longitud + JSON)── klav-native-host ──(socket Unix, JSON por líneas)── klavd
```

- **Starting `klavd`:** if it isn't running, the *host* starts it the same way `klav unlock` does (the code moves to `klav-daemon::client`, shared).
- **`KLAV_HOME`:** the browser doesn't pass environment variables. `klav extension install-host` writes, inside `$KLAV_HOME`, an executable *wrapper* that sets `KLAV_HOME` and the allowed extensions, and calls the binary. The *host* manifest points to that *wrapper*.
- **Origin check on both sides:**
  - the browser only lets the extensions listed in the manifest connect (`allowed_origins` in Chromium, `allowed_extensions` in Firefox);
  - the *host* checks again the origin the browser passes it (`chrome-extension://<id>/` in `argv[1]` in Chromium; the ID in `argv[2]` in Firefox) against its list, and exits without answering if it isn't there;
  - `klavd` still checks the peer's UID (T32);
  - the extension only accepts internal messages from its own ID (`sender.id`) and, from a *content script*, uses the origin the browser gives (`sender.origin`/`sender.url`), never one the page claims.
- **Allowlist of operations:** the *host* only forwards to `klavd` the operations the extension needs (`status`, `unlock`, `lock`, `sync`, `vaults`, `projects`, `list`, `view`, `suggest`, `autofill`, `totp`, `create`, `edit`, `approvals`, `decide_approval`, `extension_reply`). Never `resolve`, `attach`, `create_many`, agents, revocation, audit log or `shutdown`. `create` and `edit` from the extension never carry `allow_duplicate`. (ADR [0024](0024-importadores.md) §5 adds `import_add`, `import_preview`, `import_apply` and `import_cancel` for the import assistant: they return no values and never duplicate titles. `create_many` was removed. ADR [0032](0032-entornos-por-repositorio.md) §6 adds `environments`, `environment`, `environment_save` and `environment_trash`, and `resolve` only with `variables_only` and one reference, for «Show» and «Copy» of an environment's variable, which `klavd` checks and protects like a value.)
- **Size:** from the extension to the *host*, at most 1 MiB per message; from the *host* to the extension, 1 MiB (Chromium's limit). List responses only carry metadata.
- **Versioned protocol** (`v: 1`), documented in [`extension.md`](../extension.md), with Rust tests for the wire format, the 4-byte frame, the operation list and the origin check.
- **Browsers:** `klav extension install-host` writes the manifest for Chrome, Chromium, Brave, Arc, Edge, Dia and Firefox in their user directories on macOS and Linux (Dia: `~/Library/Application Support/Dia/User Data/NativeMessagingHosts`, the same layout as Arc). It accepts `--user-data-dir` for a specific profile (the tests use throwaway profiles).
- **Extension IDs:** the development manifest carries a public key (`key`) that pins the Chromium ID; Firefox uses `browser_specific_settings.gecko.id`. The store IDs are added with `--extension-id` until they exist and are pinned in the code.

### 5. Autofill: the *content script* only receives what it is going to type
- **Matching (anti-*phishing*, T21):** a login is only offered and filled if the frame's host matches the host of one of the item's URLs or is a subdomain of it (`www.` is ignored), with `https` (or `http` on the same machine). It is the SDK's rule, now in `klav-core::site`. The *Public Suffix List* is not used (as in ADR [0006](0006-semantica-de-politicas.md)): a `https://ejemplo.com` URL doesn't fill on `otro.ejemplo.com.evil.io` or on `ejemplo.co`. Cards and identities have no URL: they are filled wherever the person picks them, only on `https` (or local `http`).
- **`klavd` checks the match**, not just the extension: `autofill { item, url }` refuses a login whose site doesn't match. The URL is set by the *background* from what the browser says about the frame, not by the page.
- **It never fills on its own when the page loads.** Filling requires a gesture from the person: the icon in the field, the suggestions menu or the keyboard shortcut.
- **The suggestions menu doesn't run in the page:** it is an extension page inside an `iframe` (in a closed *shadow root*). The page can't read its content; the *content script* doesn't see the list of items. Only when one is picked does the *background* ask `klavd` for the values and send them **to the specific frame** that asked for the menu (`frameId` and, in Chromium, `documentId`), and the *content script* checks its origin again before typing.
- **TOTP:** if the login has TOTP, after the password it fills the one-time code field if it is on the page, or the one on the next page of the same site for 2 minutes. The code is computed in `klavd` right before it is typed.
- **Save on submit:** the *content script* detects the submission of a form with a password and sends the username and password to the *background*, which offers to save them or update the matching login, with the unique-titles rule.

### 6. Agents: `fill_login` with the `extension` target goes through `klavd`
The agent runtime is still the one that decrypts, with its grant, and the server still records the access with the domain, as with the SDK (ADR [0014](0014-agentes-fase-4.md) §9). What changes is the transport to the tab:

1. `klav mcp` (or `klav agent fill --target extension`) connects to `klavd` (the one for its `KLAV_HOME`, or `KLAV_BROWSER_HOME`) and asks for `browser_tab`: the origin of the active tab in the focused window, without the path.
2. It checks `fillable_host` and `host_matches` against the item's URLs. If they don't match, it fails without revealing the host.
3. It asks the server for access (`fill`, with that host as `domain`): the policy, the `ask` approvals and the audit log are the usual ones.
4. It sends the values in `browser_fill` to `klavd`, which hands them to that browser's extension over the *host* connection. The extension checks that it is the same tab, that its origin didn't change and that it matches the item's URLs; it fills, shows on the page "Klav filled for agent *name*: *reason*" and answers only with the field names (and, with `submit`, whether another page loaded and its origin).
5. The values never go back to the agent or the LLM.

**Event channel:** the `klavd` protocol was request-response only. A connection that sends `extension_attach` (only the *host* sends it) is registered as a browser, and `klavd` can write event lines to it (`{"v":1,"event":{…}}`), which the extension answers with `extension_reply`. It is additive: clients that don't register see no events, so the version stays at 1. `browser_tab` and `browser_fill` don't need the account unlocked: the agent brings the values.

**Approvals in the browser:** the *popup* lists the pending approvals (`approvals`) and decides them (`decide_approval`) with Touch ID through `klavd`, or with the password if Touch ID isn't available, the same as the CLI.

### 7. Extension permissions, minimal
- `nativeMessaging` to talk to `klav-native-host`;
- `storage` only for preferences with no secrets;
- `clipboardWrite` and `alarms` to copy and clear the clipboard after 30 s (in Chromium, plus `offscreen`, because a *service worker* has no clipboard);
- a *content script* declared for `http://*/*` and `https://*/*`: detecting forms and offering to save requires seeing the page without a prior click, like any password manager. It runs in an isolated world and receives nothing from the vault until the person picks what to fill.

No `webRequest`, no `history`, no `cookies`, no remote code. The justification for each permission is in [`extension.md`](../extension.md).

### 8. Stack
Strict TypeScript, `esbuild` for bundling (no *plugins* and no runtime code), `vitest` + `jsdom` for the form detection tests, `eslint` and Playwright for the end-to-end test with Chromium. A single codebase produces the Chromium package (MV3 with a *service worker*) and the Firefox one (MV3 with `background.scripts`).

## Consequences
- Without `klavd`, the extension only shows how to install it. The no-daemon mode stays as an open roadmap checkbox and a question for Omar.
- `klavd` gains the event channel and new operations (`suggest`, `autofill`, `extension_attach`, `extension_reply`, `browser_tab`, `browser_fill`); `docs/klavd.md` and `extension.md` document them.
- Any process of the same user can ask for `browser_fill` with its own values and a made-up agent label: it would type its own text into the active tab, as long as the origin matches the URLs it sends. It isn't new power (that process can already talk to the socket and the browser); it stays in the threat model.
- `klav-core` gains `site` and the `url` dependency; `klav-sdk` uses those functions instead of its own.
- Building the extension needs the `wasm32-unknown-unknown` target and `wasm-bindgen-cli` with the exact version of the `wasm-bindgen` crate.

## Implementation notes (phase 5)
- **No `storage`:** there was no need to store preferences. What the extension remembers (open menus, a login waiting to be saved, the last login with a code) lives in the *background*'s memory. *Changed with the redesign, below.*
- **No `activeTab`:** the *popup* asks the *background* for the active tab's address, and the *background* gets it from the browser with `sender.url` (the same `where`/`here` exchange as the agents).
- **Firefox 140 or newer** (the current ESR): it is the version that supports `data_collection_permissions`, which `addons.mozilla.org` requires; the extension declares that it collects no data. Firefox for Android has no *native messaging*: it isn't offered there.
- **Clipboard:** without `clipboardRead`, it is cleared after 30 s even if something else was copied outside Klav (threat model, residual risk 15).

## Redesign notes (2026-11-03)

With the new interface ([`diseno-visual/README.md`](../diseno-visual/README.md)):

- **`storage`, for a single setting:** "Only fill, don't press" (`storage.local`, key `onlyFill`, a boolean). Nothing from the vault, no hosts, no history. Everything else stays in the *background*'s memory.
- **`*.localhost` is the same machine** for the §5 rule (RFC 6761): `fillable_host` accepts `http://idmsa.localhost`, and an item for `http://localhost` matches its subdomains, like any host. This makes it possible to test sign-ins with a frame from another subdomain without a real domain. `is_loopback`, which guards the SDK's CDP connections, doesn't change: only `localhost` and the *loopback* IPs.
- **New surfaces in the page:** the "Sign in as …" card, the central search and the agent notice are extension pages in an `iframe`, like the menu (§5). Filling still requires a real click in a visible frame. A login from another site is only filled from the search, after a question with both hosts in view (threat model T69).
- **Multi-step sign-ins:** after a login is picked, Klav follows its steps (email, password, code) and presses the buttons, with the state in the *background* per tab and a 60 s deadline. Each step goes through `suggest` and `autofill` again (§5). There are no new `klavd` operations (threat model T68).
