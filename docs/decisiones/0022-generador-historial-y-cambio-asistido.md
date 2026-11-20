# 0022 · Generator with per-site rules, generator and password history sealed with the vault key, vault health on the client, and agent-assisted password change

- Status: accepted
- Date: 2026-11-04

> **Accepted on 2026-11-04.**
>
> **Implemented on `main` (phase 1, PRs #88–#92):**
> - generator (§1): smart, random, memorable and PIN kinds; a `passwordrules` interpreter and bundled Apple rules; strength bar and per-character colors; in the extension, on iOS and in `klav generate --type`;
> - generator history (§2): `generator_history` in the system project, local-first writing (`0x43`) from `klavd`, retention, and deletion with a purge of versions;
> - password history (§3): the `0x16` record sealed with the vault key, backfill from the versions, "Previous passwords" in the extension and on iOS, and `klav item history`.
>
> **Implemented on `main` (fourth step of Omar's work order, PRs #118, #119, #121 and #123–#126):**
> - vault health (§4): `klav-client` (feature `health`, with `zxcvbn` and the optional HIBP lookup, off), `vault_health` in `klavd`, `klav health`, the "Health" view in the *popup* and on iOS;
> - assisted change (§5): the `rotate` permission only in tasks, the `/v1/agent/rotations` routes and the person's, `agent_rotate_*` in `klavd`, the pending password in the `0x16` record written before filling, the fill in the extension, and the "Pending change" card in the *popup* and on iOS;
> - "Fix my reused passwords" (§6): tasks offered from the *popup*, iOS and `klav health --fix-with`;
> - MCP and SDK tools (§7), `create_item` with `generate`, and the skill (§8).
>
> The end-to-end test (`apps/extension/e2e/cambio-asistido.spec.ts`) also covers the sign-up that fails and two sites where the second rejects the new one. The ADR is fully implemented.

## Context
Omar asked for three things:

1. a generator like 1Password's;
2. a history, so that no password is ever lost;
3. that an agent go to each site where passwords are reused, change it to a strong one, and that Klav be updated.

**What already exists:**
- `klav-core::generator`: password (`PasswordPolicy`, 4–256 characters, four classes, no ambiguous ones) and passphrase (`PassphrasePolicy`, EFF Large Wordlist), with rejection sampling and `entropy_bits()`;
- `klav generate` in the CLI;
- in the extension, a basic version (`generator()` in `apps/extension/src/ui/menu.ts`): a fixed 20 characters, "Another" and "Use this password", which types into new-password fields;
- the server keeps the previous versions of each item (`item_versions`), up to `max_item_versions` (50 by default). It deletes them on passing the cap with **any** edit, whether it is a change of tag or of title.

**The reference** is 1Password's generator: Copy, regenerate and Autofill buttons; the password with colors by character type; a strength bar; the "Smart Password" (respects the site's requirements), "Random", "Memorable" and "PIN Code" kinds; "Use as default for suggestions"; and "Password Generator History". The **function** is copied; the look is Klav's ([`diseno-visual`](../diseno-visual/README.md)).

**Rule that stays:** Klav doesn't query third parties unless the person turns it on, as with site icons (they are fetched from the site itself only if the person turns it on). It affects per-site rules (§1.3) and the breached-password lookup (§4.3).

## Decision

### 1. Generator

#### 1.1 Kinds

| Kind | Key | What it generates | Default |
|---|---|---|---|
| Smart | `smart` | random within the site's rules (§1.3) | **yes** |
| Random | `random` | current `PasswordPolicy` | 20 characters, all four classes |
| Memorable | `memorable` | current `PassphrasePolicy` | 5 words, `-`, initial capital and a number |
| PIN | `pin` | digits only, uniform | 6 digits (4–12) |

- `pin` is a new function, `generate_pin(len)`, with rejection sampling like the others.
- Options: length, classes, no ambiguous characters, number of words, separator and capitals, as in `klav generate` today.
- **Default kind:** the person chooses it with "Use as default for suggestions". It is a **local** setting on each device (it isn't secret and doesn't need syncing in v1).

#### 1.2 Strength
- For a **generated** password, `entropy_bits()` comes from the alphabet and the length, not from an estimate over the text. It is an **upper bound**, not the exact entropy: rejection sampling discards passwords that don't meet the rules (one of each class, the page's rules such as "no consecutive repeats"), and that narrows the space a little. With Klav's policies the difference is small, but the number isn't "the truth". Since the security round (ADR 0030, layer 09), the generator always rejects an alphabet of fewer than 2 characters (the entropy would be 0) and has a total budget of draws, so that impossible rules on the page don't hang it. The bar uses that number:

  | Bits | Label |
  |---|---|
  | < 40 | weak |
  | 40–63 | fair |
  | 64–99 | strong |
  | ≥ 100 | very strong |

  A 6-digit PIN (≈ 20 bits) comes out "weak", and that is honest: it is for where the site limits attempts. A strict site rule (for example, 6–16 digits) also lowers the bar, and the item page explains it: "the site doesn't allow more".
- For passwords the person typed, the strength comes from `zxcvbn` (§4).

#### 1.3 Smart: per-site rules, without the network
In this order:

1. **The field's `passwordrules` attribute** (Apple's proposal, which some sites use), which the extension reads from the page. Also the `<input>`'s `minlength` and `maxlength`.
2. **Bundled rules** from [`apple/password-manager-resources`](https://github.com/apple/password-manager-resources), file `quirks/password-rules.json`:
   - **MIT license** (verified on 2026-11-04 in `LICENSE.md`, "Copyright 2020 - 2026 Apple Inc."); the repository is still active (last *push* 2026-11-03);
   - about 67 KB of JSON, one entry per domain with the same grammar as `passwordrules`;
   - it sits next to the code with a `PASSWORD-RULES-NOTICE.md` (like `WORDLIST-NOTICE.md`) and is updated with a repository script, **never at run time**: no network;
   - the lookup goes by the exact host, and then by stripping labels from the left (`login.accor.com` → `accor.com`), without reaching a single label. The PSL is **not** used: it is an exact key lookup in a list, as ADR 0006 §6 requires.
3. If there are no rules, `random` with 20 characters.

- **The interpreter** lives in `klav-core::generator::rules`, pure, and also in WASM. It understands `minlength`, `maxlength`, `required`, `allowed`, `max-consecutive` and the classes `upper`, `lower`, `digit`, `special`, `ascii-printable` and `[…]`.
- **Generation** stays uniform: it picks the longest allowed length up to 20 (or the minimum if that is larger), requires one of each `required` class and rejects those that break `max-consecutive`.
- **Impossible or unintelligible rules:** they are ignored with a warning, and `random` is used.
- **From the same repository**, `quirks/change-password-URLs.json` (MIT) gives each site's change-password page for the assisted change (§5). If it isn't there, `https://<host>/.well-known/change-password` is used, which belongs to the site itself, not to a third party.

#### 1.4 Where it is
- **Extension:** the menu of the new-password field gains the kind selector, "Copy", "Another", "Use this password" and the bar. The password is set in Geist Mono, colored by character type and without using blue, which in Klav means agents:
  - letters in Tinta;
  - digits in Gris;
  - symbols in Tinta on Niebla.

  It is noted in `diseno-visual` when implemented.
- **iOS:** on the item page when creating or editing a login, with the rules of its URL's host.
- **CLI:** `klav generate [--type smart|random|memorable|pin] [--site HOST] [--length N] [--words N] …`.
- All three call the same `klav-core` API (WASM, `klav-ffi` and Rust), so they give the same result.

### 2. Generator history
**Problem:** a generated password typed into a sign-up or change form is lost if the form fails, if the page reloads or if the person doesn't press "Save".

**Decision: every generated password is saved encrypted before it goes out to the page.** It is saved in **an item of its own, synced**, and is written **locally first**.

- **The item:** a new `ItemKind::GeneratorHistory`, one per account, in a **system project** `Klav` in the personal vault.
  - The client never includes that project in a grant: `--vault V` skips it and a grant that names it isn't signed. An agent never receives its key.
  - It doesn't appear in the item list; it is opened from the generator ("Generator history").
  - It syncs like any item, so the password generated on the Mac is on the iPhone.
- **Local-first writing:**
  - On the desktop, the extension sends the password to `klavd` (new operation `generator_record`, with the host). `klavd` adds it to a sealed local queue and **only then** does the extension type it into the page. The queue is the `0x43` type of ADR 0020 §11, which stops being iOS-only.
  - The queue is flushed to the item in the background. Without the network, the password stays in the queue and isn't lost.
  - On iOS, the app generates and saves in the same flow. The AutoFill extension uses the outbox of ADR 0020 §11.
  - Without `klavd` (for example, if the extension isn't hooked up), the menu says "Without Klav on this computer, this password isn't kept in the history" and lets you copy it.
- **Each entry:** the value (secret), the date, the host and, if it was saved afterwards, the `item_id` of the login where it ended up.
- **How many and for how long:**
  - the last **200** entries, or **365 days**, whichever comes first;
  - an entry already saved in a login is deleted after **30 days**, because that login already has it in its own history (§3).
- **How it is deleted:**
  - one entry or "Delete all", from the generator history;
  - deleting writes a new version of the item without those entries, and then **purges its previous versions** on the server (new person route, `DELETE /v1/vaults/{v}/items/{i}/versions`). Otherwise, the 50 stored versions would keep what was deleted.
- **Rejected alternatives:**
  - only the local queue: it doesn't sync and is lost with the computer;
  - keeping it in the vault without an item (a new vault blob): it would force a sync route of its own.

### 3. Per-item password history
**Problem:** the version history doesn't work as a password history.

- It deletes after 50 edits of **any** kind: changing the tags 50 times takes old passwords with it.
- Versions go in *details* with the item key, so an agent with `fill` could also ask for them.

**Decision: the password history goes separately, inside the item, sealed with the vault key.**

- **The password record:** new blob **`0x16` password-record**, the same envelope as `0x15`:
  - sealed with the `VaultKey`, which no agent receives (ADR 0014 §2.2);
  - AAD = `header ‖ tuple("klav/v1/item/password-record", account_id, vault_id, item_id)`;
  - it goes in *details* as `password_record` (base64url), like the passkey blob;
  - the content is JSON: `{v, history: [{field, value, from_ms, to_ms}], pending: {field, value, created_at_ms, task_id?}?}`; `pending` is the assisted change's (§5);
  - fields it covers: those of type `password` and `concealed`, by name.
- **Why with the vault key:** old passwords are often still alive on other sites (exactly the reused case), so they are worth as much as the current ones. A runtime with `fill` receives the current one because it needs it; it never needs the old ones.
  - **Cost:** the same as ADR 0020 P4: a person with whom only a project is shared doesn't see the history.
  - An agent with `update` can't read it or move it to another item (AAD), but it could remove it from *details* when rewriting the item. The server's 50 versions and the audit log mitigate this (residual risk 27).
- **Cap:** 100 previous passwords per field; past that, the oldest is discarded. It is a few bytes and doesn't depend on how many times the item is edited.
- **When it is written:** each time one of the person's clients (or `klavd` in the assisted change) changes a `password` or `concealed` field, it moves the previous value to `history` with its dates. `klav-core` does it (`Item::set_secret_field`), not each interface.
- **What already exists isn't lost:** the first time one of the person's clients writes an item's record, it **backfills it from the server's versions**: it decrypts them and takes the distinct values, with each version's date.
- **Where it is shown:** "Previous passwords" on the item page in the extension and on iOS, with the date and copy or show; and `klav item history <ref> [--reveal N] [--copy N]`, which by default only shows dates and masks.
- **The server's version history stays**, to restore the whole item (`api.md` §4.4). `max_item_versions` doesn't change.
- **Rejected alternative:** raising `max_item_versions` or not counting edits without a password. It doesn't solve the old ones reaching an agent with `fill`, and the server doesn't know what changed (it doesn't see the content).

### 4. Vault health
**It is computed on the client**: the server sees nothing, so it can't.

- **What it measures:**
  - **reused:** the same value in two or more items. They are compared in memory, by the SHA-256 of a random salt for that run and the value, and none of that is saved;
  - **weak:** `zxcvbn` with a score ≤ 2, or known entropy < 40 bits if it came from the generator;
  - **old:** unchanged for more than a year (according to the record of §3, or the creation date).
- **Where:** `klavd` (operation `vault_health`, which the *popup* shows), `klav health` in the CLI and the iOS app through `klav-ffi`. The extension computes nothing: it asks `klavd` for the result, like everything else.
- **`zxcvbn` 3.1.1** (MIT, verified on crates.io on 2026-11-04) goes in `klav-client` behind the `health` feature. It isn't cryptography. `klav-wasm` doesn't build it (its dictionaries weigh about 1 MB).
- **Breached passwords (optional, off by default):** a Have I Been Pwned lookup with k-anonymity.
  - Only the 5-hex-character prefix of the SHA-1 is sent, to `api.pwnedpasswords.com/range/`, with `Add-Padding: true` so that the response size gives nothing away.
  - It is a query to a third party, so the rule applies: it is turned on only if the person turns it on, with a text that says what is sent (the prefix, and the IP and the time the third party sees). The setting is local.
  - **SHA-1 is a new cryptographic dependency for `klav-core`**, and this ADR lists it: `sha1` 0.11 (MIT OR Apache-2.0, from RustCrypto, already in `Cargo.lock` via `tungstenite`), behind the `breach-check` feature. It is only used to compute HIBP's prefix and suffix, never for a Klav security purpose. `klav-client` does the networking. On accepting, it goes into the `CLAUDE.md` list.
- **What it offers:** each problem links to the item, and the reused ones offer "Fix with an agent" (§6).

### 5. Agent-assisted password change
- **It is a task** (ADR 0021) with the new **`rotate`** permission.
  - Like `passkey`, it only exists inside a task: no grant can have `rotate` rules (ADR 0021 §5).
  - `rotate` implies filling the current password in the change form, so there is no need to ask for `fill` separately for that item.
- **The agent never sees the old password or the new one.** `klavd` generates and types them.
  - There is only the `extension` target, with the person's `klavd`, unlocked and on their machine. With `sdk:` the new value would go through the agent's runtime.
  - It is the same restriction as with passkeys (ADR 0020 §9): an agent in the cloud can't.
- **The flow, for each site:**
  1. The agent opens the change page. `change_password_url(ref)` gives the site's (§1.3).
  2. `rotate_password(ref, target: "extension", reason)`: the server checks the task and records the event. `klavd` verifies the task's signed decision, as in ADR 0020 §9, step 3.
  3. `klavd` generates the new one with the site's rules (the form's `passwordrules`, or the bundled ones).
  4. **Before touching the page**, `klavd` writes a new version of the item: the current one stays the same, the new one goes as `pending` in the `0x16` record, and the old one is already in `history`. If that write fails, it fills nothing.
  5. The extension fills "current password" with the old one, and "new" and "confirm" with the new one (the `current-password` and `new-password` fields `fill.ts` already recognizes). Only in a tab whose host matches the item (T61). To the agent it only answers `{filled: [...], pending_id}`.
  6. The agent submits the form (`submit: true` or a click) and looks at the result: a success message, or an error that says why the site rejected it.
  7. `rotate_confirm(ref, pending_id, reason)`: `klavd` writes another version, in which the new one becomes the current one and the old one stays in `history` with its end date.
     - `rotate_cancel(ref, pending_id, reason)` keeps the current one and moves the pending one to `history`, marked "generated, not confirmed".
- **No password is lost.** On any failure (the site rejects it, the network drops, the agent stops) the old one and the pending one stay saved.
  - While there is a pending one, the item page says "Pending change: did the new password work?", with [Use the new one] and [Keep the current one].
  - The page's menu offers both to the person, so they aren't locked out if the site accepted the new one and nobody confirmed it.
- **Audit log:** each step is an event under the task (`rotate.started`, `rotate.confirmed`, `rotate.cancelled`), with the `item_id` and the host, never values.

### 6. "Fix my reused passwords"
- Vault health proposes the list: the logins that share a password, with their change page.
- **The person offers the task to an agent**, without the agent seeing the list of reused ones:
  - in the *popup*, the app or `klav health --fix-with <agente>`, the person chooses the agent, reviews the list (unchecks what they don't want) and approves **once** with Face ID or Touch ID;
  - their client signs a task decision (ADR 0021 §4) without a prior request from the agent, with `rotate` (and `totp` where needed) for those logins. It is an "offered task": `request` is empty and the person writes `task` and `reason`.
- **The agent sees it** with `list_tasks()` and goes through the sites one by one with the flow of §5. `klav log --task <id>` shows each site as changed, pending or failed.
- **Why this way:** if the agent could ask "which passwords are reused", the LLM would learn which accounts share a secret. The person already knows; the agent only needs the list of sites.

### 7. MCP tools
| Tool | Permission | Returns |
|---|---|---|
| `change_password_url(ref)` | `list` | the site's change URL, or `/.well-known/change-password` |
| `rotate_password(ref, target, reason, task_id?)` | `rotate` (in a task) | `{filled, pending_id}` |
| `rotate_confirm(ref, pending_id, reason)` | `rotate` | `{ok: true}` |
| `rotate_cancel(ref, pending_id, reason)` | `rotate` | `{ok: true}` |
| `list_tasks()` | — | the agent's tasks, also the offered ones (ADR 0021 §7) |

- There is no tool to generate a password and return it: the value would enter the LLM's context. Instead, `create_item` gains `generate: true` (with optional `type` and `site`). The runtime generates the password with the site's rules and seals it; to the LLM it only returns the metadata. It is the way for an agent to create an account with a strong password without seeing it. It is governed by `create`, as today.

### 8. Skill (when it is implemented, not now)
`skill/SKILL.md` gains a few lines:

- to change passwords, ask for a task with `rotate`, or use the one the person offered you (`list_tasks`);
- for each site: `change_password_url`, open the page, `rotate_password` with `target: "extension"`, submit the form, check, and call `rotate_confirm` (or `rotate_cancel` if the site rejected it);
- never try to see, copy or type the password yourself;
- for a new account, `create_item` with `generate: true`.

## Consequences
- **Specification:**
  - §2.3, the label `klav/v1/item/password-record`;
  - §3, the type `0x16`;
  - §7.1, the `password_record` key in *details* and the `generator_history` kind;
  - a new §7.3 for the password record.

  `v` stays at 1. An old client skips items with these keys ("does not decrypt"), as with passkeys; nothing is published.
- **`klav-core`:**
  - `generator::rules` (the `passwordrules` interpreter) and Apple's data with its license notice;
  - `generate_pin`;
  - the `0x16` record and `Item::set_secret_field`;
  - `ItemKind::GeneratorHistory`;
  - `Permission::Rotate`;
  - the `breach-check` feature with `sha1`.
- **`klav-client`:** the `health` feature with `zxcvbn`, the record backfill from versions, and the optional HIBP lookup.
- **`klavd`:** `generator_record`, `vault_health` and the assisted-change operations (`agent_rotate_begin`, `agent_rotate_confirm`, `agent_rotate_cancel`). The `0x43` queue is also used on the desktop.
- **Server:** `DELETE /v1/vaults/{v}/items/{i}/versions` (person) and the `rotate.*` events. Blobs stay opaque.
- **Interfaces:** the new generator in the extension, iOS and the CLI; "Previous passwords"; vault health; `klav item history` and `klav health`.
- **Threat model:** §5.10 (T96–T101) and residual risk 27.
- **`docs/diseno-visual`:** the colors of the generated password (§1.4), when implemented.

## Questions for Omar
Each one had a default value, which is what this ADR describes. Omar accepted the ADR on 2026-11-04 without changing any, so all of them keep their default value. Omar also set the work order (1) generator and history (ADR 0022 §1–3, done), 2) importers, 3) task requests (ADR 0021), 4) assisted change (ADR 0022 §5–7), 5) passkeys (ADR 0020) and 6) Android (phase 7)), which puts the assisted change after task requests.

| # | Question | Default |
|---|---|---|
| G1 | The generator's default kind? | Smart, with 20 characters if the site sets no rules |
| G2 | Bundle Apple's rules (MIT)? | Yes, updated by a repository script, never at run time |
| G3 | Where does the generator history live? | An item of its own in a system project that no grant includes, with local-first writing (`0x43`) |
| G4 | How many entries and for how long? | 200 entries or 365 days; 30 days if it was already saved in a login |
| G5 | Password history separate from versions? | Yes: the `0x16` record sealed with the vault key, 100 per field |
| G6 | Backfill the history from the versions that already exist? | Yes, the first time a client writes the record |
| G7 | Breached-password lookup (HIBP)? | Optional and off by default, with k-anonymity and padding |
| G8 | `sha1` in `klav-core` for HIBP? | Yes, behind `breach-check`; only for the HIBP prefix |
| G9 | Who starts "fix the reused ones"? | The person, who offers the task to an agent; the agent doesn't query the health |
| G10 | Password colors | Letters in Tinta, digits in Gris, symbols in Tinta on Niebla; no blue |
