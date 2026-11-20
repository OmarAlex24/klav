# 0020 · Passkeys: Klav as a WebAuthn authenticator (ES256, synced discoverable credentials), the private key sealed with the vault key, RustCrypto's `p256`/`ecdsa`, and the PSL only for the rpId

- Status: accepted
- Date: 2026-11-04

> **Accepted on 2026-11-04.** Omar answered P1 with the work order: 1) generator and history (ADR 0022 §1–3, done), 2) importers, 3) task requests (ADR 0021), 4) assisted change (ADR 0022 §5–7), 5) passkeys (ADR 0020) and 6) Android (phase 7). Passkeys come fifth and there is no code yet; the additions to the [specification](../especificacion-cripto.md) (§2.3, §3, §7.1 and §14) and to the [threat model](../modelo-de-amenazas.md) (§5.8 and residual risks 21–24) stand as "accepted, pending implementation". The `0x43` queue (§11) already exists on the desktop because of ADR [0022](0022-generador-historial-y-cambio-asistido.md).

## Context
Klav stores passwords and TOTP. Sites are moving to passkeys, which today end up in iCloud or Google, outside the vault. Passkeys are under "Después (sin fecha)" in the [roadmap](../roadmap.md) and outside the MVP in [`diseno.md`](../diseno.md), so an ADR is needed before touching code. What has to be decided:

- the schema: where a passkey lives within the item model;
- the cryptography and its dependencies: `CLAUDE.md` and ADR [0005](0005-dependencias-criptograficas.md) require an ADR for any new cryptographic crate;
- how to validate the rpId, given the "no *Public Suffix List*" rule of ADRs [0006](0006-semantica-de-politicas.md) §6 and [0017](0017-extension-de-navegador.md) §5;
- how to guarantee that an agent never gets a passkey's private key out (ADR [0014](0014-agentes-fase-4.md)), and under what conditions it can **use** the person's;
- how the iOS extension writes, which today is read-only and has no network (ADR [0018](0018-app-ios.md) §4).

## Decision

### 1. Scope of v1
- Klav is an **authenticator** (passkey provider) in two places:
  - the browser extension (Chromium and Firefox), through `klavd`;
  - the iOS Credential Provider Extension.
- ES256 (`-7`) only, discoverable credentials and `none` attestation.
- Outside v1:
  - Ed25519 (`-8`), possible later with `ed25519-dalek`, which is already in the tree (P11);
  - the `prf`, `largeBlob` and `hmac-secret` extensions (P8);
  - *conditional create* (creating a passkey automatically when signing in with a password);
  - cross-origin frames and Related Origin Requests (P10);
  - Safari and Android;
  - importing and exporting with FIDO's CXF/CXP.

> **Implementation note, 2026-11-05; Omar decided the counter the same day.** Passkeys from Bitwarden's unencrypted JSON are imported (`login.fido2Credentials`), because that file carries the private key (PKCS#8). They go into the login they come with, sealed with the vault key (`0x15`), and are never stored in the clear. The details are in [ADR 0024](0024-importadores.md). **Counter** (decided by Omar on 2026-11-05): Klav always signs with 0 (§5), and an exported passkey with a counter greater than 0 is imported anyway, with a warning on that row, because an RP that watches the counter may reject it. The warning says what to do in that case: sign in another way and register a new passkey in Klav for that site. CXF/CXP stays outside v1.

### 2. Where the passkey lives: inside a `login` item, at most one per item (P3, accepted)
- **Why:**
  - an account is a single entry (password + TOTP + passkey), as in Apple Passwords and Bitwarden; every platform does it this way;
  - the passkeys of several accounts on the same site are several logins, each with its own;
  - the menu, the card and QuickType don't duplicate rows;
  - `urls`, `username`, the unique-title rule and projects are reused.
- **An account without a password:** it is a login without a password.
- **Another user on the same site:** goes in another login.
- **Same `rp_id` + `user_handle`:** it is **replaced** after confirming in the UI, as CTAP2 requires.
- **Alternative:** its own `ItemKind::Passkey`. It separates passkeys from logins and duplicates rows on every surface.

### 3. Schema (additions to the specification's v1 JSON, §7.1)
In *details*, a new optional `passkey` key, only with `kind = login`:

| Key | Type | Notes |
|---|---|---|
| `credential_id` | base64url | 16 random bytes; immutable |
| `rp_id` | text | lowercase ASCII (punycode) domain; immutable |
| `rp_name` | optional text | display only |
| `user_handle` | base64url | 1 to 64 bytes, given by the RP; immutable |
| `user_name` | text | `user.name` |
| `user_display_name` | optional text | `user.displayName` |
| `alg` | integer | `-7` |
| `created_at` | integer | Unix ms |
| `key` | base64url | 74-byte `0x15` blob (§4) |

In *overview*, a new optional key `passkey: { rp_id, credential_id, user_name }`. It carries no secrets and whoever has `list` sees it, like `username`.

- **Consistency:** when the item is rebuilt, the *overview* summary must match what comes out of *details*. If not, `SectionMismatch`, as already happens with `username`.
- **Compatibility:** `Overview` and `RawDetails` reject unknown keys (`deny_unknown_fields`), and `ItemKind` has no catch-all case.
  - An old client skips the item with the "does not decrypt" warning (`crates/klav-client/src/session.rs`) and nothing else breaks.
  - Nothing is published, so this is accepted. `v` stays at 1 and it is noted in the specification's changelog.
- **Editing:**
  - `credential_id`, `rp_id`, `user_handle` and `key` are immutable: `klav item edit` and `ItemEdit` don't touch them;
  - an edit of the login keeps the passkey intact;
  - only `Item::set_passkey` and `Item::remove_passkey` change it.
- **URL:** when the passkey is created, if no URL of the login is on the `rp_id` host, `https://<rp_id>` is added.

### 4. The private key is sealed with the vault key: new blob `0x15` (P4, accepted)
- **Problem:**
  - agents receive project keys (ADR 0014 §2.2) and an item's *details* through `POST /v1/agent/access`, after the policy is evaluated;
  - the server doesn't see the item's kind;
  - if the P-256 scalar were only inside *details* (encrypted with the item key), an agent runtime with `fill` or `reveal` on that login could get it out.
- **Decision:**
  - the scalar (32 bytes) is sealed with the **vault key** (`VaultKey`), which no agent ever receives (ADR 0014 §2.2);
  - format: `0x01 ‖ 0x15 ‖ nonce(24) ‖ ct(32 + 16)`, 74 bytes, the same envelope as `0x02`–`0x04` (specification §3.1);
  - AAD: `header ‖ tuple("klav/v1/passkey/private-key", account_id, vault_id, item_id, credential_id, rp_id, user_handle)`;
  - the blob travels inside *details*, so it is encrypted twice;
  - `project_id` is left out of the AAD, so that moving the item to another project in the same vault doesn't force a reseal.
- **What is gained:**
  - the barrier against agents is **cryptographic**: with `reveal`, an agent sees the metadata and an opaque blob. When an agent **uses** a passkey inside a task (§9), `klavd` signs, and it does have the vault key; the agent's runtime never opens `0x15`;
  - an agent with `update` can't move the key to another `rp_id` or another item, because the AAD fails;
  - an agent with `create` can't forge a valid passkey.
- **Cost:**
  - one blob type, one label and new vectors;
  - if in the future a **project** is shared with another person (without the vault key), that person won't be able to use its passkeys. Sharing by vault, which is what is planned, does carry them. Omar accepted this.
- **Rejected alternative:** enforcing the rule only in the clients, with no cryptographic barrier. It leaves the key within reach of a compromised agent runtime.

### 5. Authenticator parameters

| Parameter | Value | Reason |
|---|---|---|
| Algorithm | ES256 (`-7`): ECDSA P-256/SHA-256, DER signature, RFC 6979 nonce | doesn't depend on the random generator when signing; reproducible vectors |
| `signCount` | **always 0** | like Apple's and Google's synced passkeys; the RP treats it as "no counter"; no conflicts on sync; signing writes nothing, so the iOS extension stays read-only when signing in |
| Flags on create | UP·UV·BE·BS·AT = `0x5D` | synced passkey (BE = BS = 1) |
| Flags on sign | UP·UV·BE·BS = `0x1D` | UV only if there was a real verification inside the chosen window, or an agent's task approval (§8) |
| AAGUID | a fixed Klav UUID v4, a constant in `klav-core`, the same on every platform (P2) | the RP can show "Klav"; it is registered in the community list `passkey-authenticator-aaguids`. See "Pending checks" |
| Attestation | always `fmt: "none"` and `attStmt: {}`, even if the RP asks for `direct` | there is no CA; WebAuthn allows it |
| `credential_id` | 16 bytes from `getrandom` | independent of the item's ID |
| Resident credential | always (`rk = true`) | |
| Extensions | only `credProps` → `{ rk: true }`; the rest are ignored | `prf` in v2 (P8) |
| `authenticatorAttachment` / transports | `"platform"` / `["internal", "hybrid"]` | like desktop providers |
| COSE key | `{1: 2, 3: -7, -1: 1, -2: x, -3: y}` in CTAP2 canonical order | |
| `attestationObject` | `{"fmt", "attStmt", "authData"}` in canonical order (by length, then alphabetical) | |

### 6. Dependencies
This ADR lists its dependencies; ADR 0005 isn't edited. The list of approved crates in `CLAUDE.md` is updated **on accepting** this ADR, not before.

- **`p256` 0.14 and `ecdsa` 0.17**, from RustCrypto (Apache-2.0 OR MIT).
  - Features: in `p256`, `ecdsa`, `sha256` and `pkcs8` (SPKI DER for `getPublicKey()` and the future export); in `ecdsa`, `rfc6979` and `der`.
  - ADR 0018 §5 rejected `p256` **0.13** because it uses `crypto-bigint` 0.5.5 (RUSTSEC-2026-0387, timing leaks). The advisory considers versions `>= 0.7.6` fixed.
  - **Verified nuance (2026-11-03):** `p256` alone doesn't give that guarantee. `p256` 0.14.0 requires `elliptic-curve ^0.14.1`, and `elliptic-curve` 0.14.1 still accepts `crypto-bigint ^0.7.5`, which is vulnerable. Only `elliptic-curve` 0.14.3 requires `^0.7.8`. Today it resolves to `crypto-bigint` 0.7.9 or 0.7.10 because 0.7.0–0.7.8 are yanked (0.7.6–0.7.8 for an incompatible change, [#1373](https://github.com/RustCrypto/crypto-bigint/pull/1373), not for security).
  - **Also, the current `ignore` of RUSTSEC-2026-0387 in `deny.toml` goes by ID**, so it covers any version of `crypto-bigint`: `cargo-deny` wouldn't warn if a 0.7.5 came in.
  - **That is why the layer that adds `p256`:**
    - pins the minimum explicitly in the workspace (`elliptic-curve >= 0.14.3` or `crypto-bigint >= 0.7.9`);
    - adds a guard to `deny.toml` that rejects `crypto-bigint` 0.7 earlier than 0.7.6;
    - with that, arithmetic with the secret scalar goes through the fixed version.
  - **Consequence:** two major versions of `crypto-bigint` remain in the tree. 0.5.5 still comes in via `opaque-ke` → `elliptic-curve` 0.13.8, with the `ignore` that already exists (ADR 0009). `multiple-versions = "warn"` in `deny.toml` tolerates it: it warns, it doesn't fail.
- **Why not others:**
  - `aws-lc-rs`: it isn't RustCrypto, it doesn't build well for `wasm32-unknown-unknown` (and `klav-wasm` depends on `klav-core`), and ADR 0018 keeps it for transport only;
  - `ring`: it is banned in `deny.toml`.
- **`psl` 2.1** (MIT/Apache-2.0, like its dependency `psl-types`; it publishes new versions several times a month, with the list up to date):
  - it is used **only** to validate the rpId;
  - it sits behind `klav-core`'s **non-default** `rp-id` feature, which `klav-client` turns on (and `klav-import`, which is already in its graph, for the rpId of imported passkeys);
  - `klav-wasm` doesn't build it, so the extension package doesn't grow;
  - site matching (`klav-core::site`, ADR 0017 §5) stays **without** the PSL;
  - compared with `publicsuffix` (no releases since 2024-11), `psl` carries the list up to date.
- **CBOR:**
  - a minimal in-house encoder in `klav-core`, which only encodes integers, `bstr`, `tstr` and definite-length maps;
  - the canonical order comes from how it is built;
  - it is encoding, not cryptography;
  - `ciborium` 0.2 (Apache-2.0) comes in only as a *dev-dependency*, to decode in the tests with a verifier independent of the encoder;
  - rejected: `minicbor` (BlueOak-1.0.0, outside the `allow` list in `deny.toml`) and `coset` (Apache-2.0, but for full COSE; too much for a single key).
- **Verifiers:**
  - in Rust: `ciborium` + `p256` (verification) + the vectors from WebAuthn L3's "Test Vectors" section ("ES256 Credential with No Attestation");
  - in the extension's e2e tests: `@simplewebauthn/server` 14 as a real RP and `@simplewebauthn/browser` 14 in the page (both MIT), as *devDependencies* of `apps/extension`.
- **`webauthn-rs-core` rejected:** 0.6.2 no longer uses openssl, but:
  - it is MPL-2.0, like its cryptographic base `crypto-glue` 0.2, and both would need new exceptions in `deny.toml`;
  - `crypto-glue` pulls in `rsa` 0.10.0-rc, with the Marvin advisory (RUSTSEC-2023-0071, no fixed version), plus `p384`, `p521`, AES, MD5 and `argon2` 0.5 (Klav uses 0.6).

### 7. rpId validation (`klav_core::passkey::rp`; `klavd` calls it with the origin the browser gives)
- The origin must be `https:`, or `http:` on `localhost` or `*.localhost` (RFC 6761, like `klav-core::site`).
- The `null` origin and hosts that are an IP are rejected.
- `rp_id` (by default, the origin's host) is lowercase, ASCII/punycode and without a port.
- `rp_id` must be the host or a suffix of whole labels: `host == rp_id || host.ends_with("." + rp_id)`.
- `rp_id` can't be a **known** public suffix in the PSL (ICANN or private).
- `rp_id` can't have a single label, except `localhost`. The PSL doesn't have `localhost`, and its wildcard rule would treat it as a public suffix.
- If validation fails, Klav **doesn't return an error**: it passes the call to the browser's authenticator, which applies its own rules (including Related Origin Requests).
- Credentials are looked up by exact `passkey.rp_id == rp_id`, as WebAuthn requires, not with `host_matches`.

### 8. User verification (UV) (P6, changed by Omar's answer)
- **By default, Touch ID on every use.** Every creation and every signature with a passkey go through `klavd`'s presence confirmation (`touchid::confirm_presence`).
- **The person can choose another window**, in a local device setting (in `klavd`'s on the desktop), which doesn't sync:

  | Option | Value | What it asks for |
  |---|---|---|
  | "Every time" (default) | `always` | a real verification on every use |
  | "Every 5 minutes" | `5m` | a real verification if the last one was more than 5 minutes ago |
  | "While Klav is unlocked" | `unlocked` | the unlock counts as verification until the next lock |

- **What a real verification is:**
  - Touch ID in `klavd`;
  - without Touch ID, the master password typed into a Klav frame, never into the page. With "Every time" that costs an Argon2id (about a second) on every sign-in; whoever doesn't want that picks another window;
  - with Klav locked, unlocking within the same flow (with Touch ID or with the password in Klav's frame).
- **The window:**
  - `klavd` keeps in memory the time of the last real verification, with a monotonic clock;
  - it forgets it on locking, so locking always closes the window;
  - loosening the setting (going from "Every time" to another option) asks for a real verification.
- **The UV flag is only 1 if there was a real verification inside the chosen window.** If there wasn't, Klav asks for one before signing; if the person cancels it, the page receives `NotAllowedError`. Klav never signs with UV = 0 to save itself the question.
- **UP** (presence) is the person's click on Klav's surface.
- **Agents:** inside an approved task, the Touch ID or Face ID with which the person approved the task counts as the UV (and UP) of those uses, for the task's duration (§9). Omar accepted this.
- **iOS:** the Face ID that opens the extension is the UV. The extension asks for Face ID every time it opens (T72), so on iOS v1 it is always equivalent to "Every time" and the setting doesn't apply.

**Note of 2026-11-17 ([ADR 0041](0041-presence-for-values-and-the-inject-card.md) §2.5, Omar's decision, not built).**

- **One window per key.** The window above is one for the whole `klavd` today: `passkey_presence` loads the setting and reads one `slot.verified()` (`crates/klav-daemon/src/server.rs:2013–2027`). It becomes one window per key, the same key as ADR 0041's presence window: a terminal session, the browser, a parent process, or the connection when none of those can be read. A verification for one key no longer counts for another.
- **What stays.** The browser's passkey uses come through its hosts, so they share the browser's key. The setting, its three values and its default ("Every time") don't change, and neither does `passkey_flow`'s one-use unlock.
- **Where the setting lives (ADR 0041 §2.4, P4).** Today `passkeys.json` is re-read on every use (`uv::load`, `crates/klav-daemon/src/server.rs:2019`). A program of the same user can then write a looser value, so the setting moves into `klavd`'s sealed local data (spec §12.2), read at unlock. Missing means "Every time"; a blob that doesn't open means "Every time".
- **The upgrade (ADR 0041 §2.4, Omar's decision of 2026-11-18).** The existing `passkeys.json` is ignored: its value isn't read, so a person who had loosened the setting is back on "Every time", and Klav tells them once so they choose again. Loosening the setting isn't retroactive: a verification lasts what its prompt said. The loosening's own verification no longer counts as the window's first one (confirmed by Omar on 2026-11-18): it only authorizes the change, and the next use asks once more.

### 9. Agents (P12, changed by Omar's answer): they use the person's passkeys only inside an approved task
- **What doesn't change:** the key stays sealed with the vault key (§4) and only `klavd` opens it. No agent runtime, with any permission, receives the scalar or a blob it could open. The agent asks for the **use**; `klavd` signs.
- **New `passkey` permission** in `Permission`:
  - `deny` by default;
  - **it is only granted inside an approved task request** (ADR [0021](0021-solicitudes-de-tarea.md), "Task requests", also accepted), with its expiry (24 h at most);
  - **it can't go in a permanent grant:** the client refuses to sign, and the server rejects (`400`), a grant whose policy has a `passkey` rule. Outside a current task there is nothing to approve: `request_access(…, "passkey")` answers that a task has to be requested.
- **Only through the person's `klavd`, unlocked, on their machine:**
  - the only target is `extension`: the agent drives a browser with Klav's extension, hooked up to the person's `klavd` (ADR [0017](0017-extension-de-navegador.md) §6). The origin is given by the browser (T80), never by the runtime;
  - `sdk:<sesión>` and CDP are left out: there the origin and the `clientDataJSON` would come from the agent's runtime;
  - `klavd` talks over a Unix socket with a UID check (ADR [0012](0012-daemon-klavd.md)), so an agent running in the cloud **can't** use passkeys, by construction, not by policy;
  - with Klav locked, the use fails with `locked` and the agent tells the person. Klav doesn't unlock for an agent.
- **How it is used (signing in only; creating a passkey for the person is left out):**
  1. The agent calls `passkey_sign_in(ref, target: "extension", reason)`; the runtime sends the server `POST /v1/agent/access` with `passkey`, the tab's host as `domain` and the `task_id`. The server checks the task's lease and records the event **before** answering, without *details*.
  2. The runtime asks `klavd` for the new operation `agent_passkey_arm`, with its signed request and the `task_id`.
  3. **`klavd` verifies on its own, without trusting the runtime or the server** (double barrier, like T22). It fetches the task with the person's session and checks the account's signature on the task's decision, that it is still current and not ended, that the agent is the task's (and its request's signature), that the item is in the task with `passkey`, and that the tab's host matches the `rp_id` and the approved domain.
  4. `klavd` arms a use: the next `get` request from that tab for that `rp_id`, within the following 60 s, is answered by Klav with that passkey and without the person's surface. The page shows in blue "Klav used the passkey of *title* for the agent *name*: *reason*".
  5. The response to the agent carries only `{used: true, rp_id}`; the assertion goes to the page, like any other.
- **UV:** the Touch ID or Face ID of the task approval counts as verification (§8). The flags are UP·UV·BE·BS.
- **Audit log:** each use is recorded under the task, with the server's event (permission `passkey`, `task_id`) and `klavd`'s `passkey.used` with the agent and the `task_id` (§10).
- **The agent's own passkeys** (created for its account at the RP and sealed with a key of its own) remain for **later**, with their own ADR.

> **Implementation note, 2026-11-05, confirmed by Omar on 2026-11-05.** Step 5 said the agent always receives `{used: true, rp_id}`. That would force `passkey_sign_in` to wait for the page to ask for the passkey, and the page only asks for it when someone presses its button: the agent can't press it while its tool is waiting, because its calls go one after another. The implementation doesn't wait:
> - if the tab already has a `get` request from that site waiting (in the field's menu or with Klav's frame open), `klavd` signs at that moment and the agent receives `{used: true, rp_id}`;
> - if not, the use stays armed for 60 s for the site's next request in that tab, and the agent receives `{used: false, armed: true, rp_id, expires_in_s: 60, next}`; `next` tells it to press the site's passkey button.
>
> `used` is only `true` if `klavd` really signed. The armed window is a new threat, T139 in the threat model: it is bounded by the tab, the host, the rpId and the login, a single use, the 60 s and locking. The protocol is in [`klavd.md`](../klavd.md) §3.
>
> **Security review note, 2026-11-05.** A check is added to step 3: before arming, `klavd` looks in the server's audit log (`GET /v1/audit`, the last 1000 events) for the allowed `agent.access` of that same signed request (agent, item, task, `nonce` and signature). That way step 1 no longer depends on the agent complying: an agent that signs the request and gives it only to `klavd`, without sending it to the server, arms nothing. The check trusts the server: it keeps the audit log complete against an agent that skips it, not against a malicious server. Each request arms only once, also after locking and unlocking, because `klavd` keeps the used `nonce`s outside the session. A `klavd` restart forgets them. Since `klavd` starts locked, repeating the request requires the person to unlock within its 5 minutes, and then one server event can cover two uses (T139).

### 10. Audit log (P7)
- Creating or replacing a passkey is already recorded as `item.created` or `item.updated`, which the server attests.
- **Use** is local (counter 0, no write). v1 adds the person event `passkey.used`:
  - it carries only the `item_id`, without `rp_id` or domain;
  - if the use was by an agent inside a task, it also carries the `agent_id` and the `task_id` (the domain is already in the server event from step 1 of §9);
  - `klavd` sends it best-effort through a new, limited route, `POST /v1/audit/person`;
  - on iOS it goes to the outbox (§11) and the app sends it later.

### 11. iOS: the extension registers without the network, with an outbox (P5, accepted)
- ADR 0018 §4 is respected: the extension stays without the network and doesn't compete with the app for the *refresh token*.
- **On registering,** the extension builds the complete creation:
  - a new item key, wrapped with the project key;
  - the two sealed sections;
  - the `0x15` blob.
- **Where it stores it:** in `outbox.bin`, with a new local type, **`0x43` local-outbox**:
  - it goes in the `0x40`–`0x4F` range, that of the blobs that never leave the device;
  - it is sealed with the local key;
  - it has its own label, `klav/v1/local/outbox`, because `0x41` already uses `klav/v1/local/data`;
  - AAD (the plan didn't fix it): `header ‖ tuple("klav/v1/local/outbox", account_id, device_id)`, by symmetry with `0x41`;
  - a simpler alternative, with no new type: a `0x41` with the `outbox` purpose (specification §12.2 already separates uses by purpose). A type of its own is proposed so that the queue, which carries complete creations, can't be confused with the cache or the session even if the purpose is wrong; if Omar prefers fewer types, the change only touches layer 9.
- **Immediate use:**
  - the extension **merges** the queue with the cache when reading, so the passkey works right away on that phone;
  - it also registers it in `ASCredentialIdentityStore`.
- **Sync:** the app empties the queue when it comes to the foreground, with a `create` that uses the ID the client chose. If a title clashes, it renames it.
- **Risk:** uninstalling the app before opening it loses the passkey. The UI says so: "Open Klav to sync this passkey".
- **Alternative:** letting the extension make a network call. `session.lock` already orders the refresh between processes, but it adds memory to the extension.

## Checks done (2026-11-03)
Against crates.io, npm, RustSec's `advisory-db`, and `main`'s `deny.toml` and `Cargo.lock`:

| Claim | Result |
|---|---|
| `p256` 0.14 and `ecdsa` 0.17 exist | Yes: `p256` 0.14.0 (2026-07-03) and `ecdsa` 0.17.0 (2026-07-02), stable, Apache-2.0 OR MIT |
| `elliptic-curve` 0.14 requires `crypto-bigint` ≥ 0.7.8, after the fix | Only 0.14.3 (`^0.7.8`); 0.14.1 accepts `^0.7.5`. RUSTSEC-2026-0387 considers `>= 0.7.6` fixed. Today it resolves to 0.7.9/0.7.10 because the earlier ones are yanked. See §6 |
| Licenses of `psl`, `ciborium`, `coset` and `minicbor` | `psl` 2.1.246: MIT/Apache-2.0 ✓; `ciborium` 0.2.2: Apache-2.0 ✓; `coset` 0.4.2: Apache-2.0 ✓; `minicbor` 2.3.1: BlueOak-1.0.0 ✗ (outside `allow`) |
| `multiple-versions` at `warn` | Yes (`[bans]` in `deny.toml`) |
| `webauthn-rs-core` 0.6: license and dependencies | 0.6.2 (2026-10-31): MPL-2.0, without openssl; `crypto-glue` 0.2 (MPL-2.0) → `rsa` 0.10.0-rc (RUSTSEC-2023-0071, unpatched) |
| Licenses of `@simplewebauthn/server` and `@simplewebauthn/browser` | MIT, both (14.0.3 and 14.0.0) |
| Today in `Cargo.lock` | `crypto-bigint` 0.5.5 and `elliptic-curve` 0.13.8, via `opaque-ke` and `voprf`; no `p256`, `ecdsa`, `psl` or CBOR |

## Pending checks
They aren't decisions; they are checked in the layer named and, if they fail, whatever depends on them is adjusted:

1. **AAGUID in Chromium:** whether Chromium zeroes the AAGUID with `attestation: "none"`. If so, the RP won't see "Klav" even though the extension sends it, and P2 loses its reason in Chromium. It is checked in the registration e2e (layer 7), by reading the AAGUID `@simplewebauthn/server` sees.
2. **`match_origin_as_fallback` in Firefox 140:** whether Firefox 140 (the extension's current minimum) supports that `content_scripts` key. If not, it is removed from the Firefox manifest; `about:blank` frames fall back to the browser anyway (layer 7).
3. **iOS 18 in the simulator:** whether Safari in the iOS 18 simulator accepts a third-party passkey provider against `http://localhost`. If not, that test is left for Omar's iPhone (layer 10).
4. **`crypto-bigint` minimum:** that layer 2 leaves `crypto-bigint` 0.7 at ≥ 0.7.9 in `Cargo.lock` and that the `deny.toml` guard (§6) fails with a 0.7 earlier than 0.7.6.

## Questions for Omar
Each one had a default value. Those marked **⚑** changed the following layers (schema, binary format, iOS or the UV flow). The **Status** column records the answers of 2026-11-04 (next section); the **Value** column is what this ADR describes today.

| # | Question | Value | Status |
|---|---|---|---|
| P1 | Where do they go in the roadmap? | Fifth in the work order: after importers, task requests and assisted change, and **before phase 7** (Android). The rest of the ADR doesn't change | **resolved** |
| P2 | Klav's own AAGUID or zeros? | A fixed Klav AAGUID, registered in the community list | no objection; the default stands |
| P3 **⚑** | Passkey inside the login or as its own kind? | Inside the login, one per item (§2) | accepted |
| P4 **⚑** | Seal the key with the vault key (`0x15`)? | Yes: it is the cryptographic barrier against agents. In exchange, sharing a project with another person won't carry its passkeys (§4) | accepted |
| P5 **⚑** | Registration on iOS: outbox or network in the extension? | Outbox (`0x43`), with the "Open Klav" warning (§11) | accepted |
| P6 **⚑** | UV on the desktop | Touch ID on every use by default; setting "Every time" / "Every 5 minutes" / "While Klav is unlocked"; UV = 1 only with a real verification inside the chosen window (§8) | **changed** |
| P7 | Record *use* in the audit log? | Yes: `passkey.used` with the `item_id` (and the agent and the task if any), best-effort (§10) | no objection; the default stands |
| P8 | The `prf` extension (other end-to-end encrypted apps use it)? | In v2, with HMAC-SHA256 and a seed sealed next to the key | no objection; the default stands |
| P9 | Conditional mediation when Klav and the browser both have passkeys | Klav only, without passing it to the browser; "Use another device" in the menu | no objection; the default stands |
| P10 | Cross-origin frames? | In v1 they fall back to the browser | no objection; the default stands |
| P11 | Ed25519 (`-8`) as well as ES256? | Not in v1 | no objection; the default stands |
| P12 | Agents with passkeys? | Yes, the person's, only inside an approved task, with the `passkey` permission and through their `klavd`; the agent's own, later (§9) | **changed** |
| P13 | A modal request (`get`/`create`) with Klav locked: show the unlock or silently fall back to the browser, since it isn't known whether Klav has a matching passkey? | Show the surface with "Unlock" and "Use another device". Without `klavd` installed, fall back silently | no objection; the default stands |

## Omar's answers (2026-11-04)
These answers fix the content. With the answer to P1, Omar accepted the ADR the same day.

- **P3, P4 and P5: accepted as they were.**
  - P3: the passkey goes inside the login, because every platform does it that way and it allows passkeys for several accounts (one login per account).
  - P4: it is accepted that sharing a project with another person doesn't carry the passkeys.
  - P5: an outbox on iOS.
- **P6 changes** (§8):
  - by default, Touch ID on **every use** of a passkey;
  - the person can choose "Every time" (default), "Every 5 minutes" or "While Klav is unlocked";
  - the UV flag is only 1 if there was a real verification inside the chosen window.
  - What was decided here to close it: without Touch ID, the real verification is the master password in a Klav frame, with its Argon2id; the setting is local and loosening it asks for verification; locking closes the window; on iOS it doesn't apply.
- **P12 changes** (§9): agents **can** use the person's passkeys, under these conditions:
  - only inside an approved task request (ADR [0021](0021-solicitudes-de-tarea.md)), with the new `passkey` permission, which can't be given in a permanent grant;
  - only through the person's `klavd`, unlocked, on their machine, and with the `extension` target. The private key never leaves `klavd`: the agent drives a browser with Klav's extension and `klavd` signs. An agent in the cloud can't;
  - the Touch ID or Face ID with which Omar approves the task counts as the verification (UV) of those uses; Omar accepted this;
  - each use is recorded in the audit log under the task;
  - the agent's own passkeys remain as "later".
  - What was decided here to close it: signing in only (not creating); `klavd` verifies the task's signed decision on its own before signing; UP also comes from the task approval (residual risk 24).
- **P1: resolved.** Omar set the work order: 1) generator and history (ADR 0022 §1–3, done), 2) importers, 3) task requests (ADR 0021), 4) assisted change (ADR 0022 §5–7), 5) passkeys (ADR 0020) and 6) Android (phase 7). Passkeys come before Android.
- **P2, P7–P11 and P13:** Omar didn't comment on them; they keep their default value.

## Consequences
- `klav-core` gains `p256`, `ecdsa` and `psl` (the latter behind the `rp-id` feature), and `ciborium` as a *dev-dependency*. On accepting, the list of approved crates in `CLAUDE.md` is updated.
- **The specification gains** (accepted; pending implementation, except `0x43`, which the desktop already uses):
  - in §2.3, the labels `klav/v1/passkey/private-key` and `klav/v1/local/outbox`;
  - in §3, the types `0x15` and `0x43`;
  - in §7.1, the `passkey` key;
  - a new section, **§14 "Passkeys"** (authData, COSE, `clientDataJSON` and AAGUID); the changelog moves to §15 and is still the last one. ADR [0019](0019-nombre-klav.md) §2 cites "specification §14" for the changelog; it is accepted and isn't edited, so that reference is to be read as §15.
- New vectors in `docs/vectores/passkey.json` (layer 2).
- **Components** (following layers):
  - `klavd` and `klav-native-host` gain three operations (`passkey_candidates`, `passkey_get` and `passkey_create`); `klavd` also gains `agent_passkey_arm` (§9), only over the socket and outside the native *host*'s list, and the UV window setting (§8);
  - `klav-core` gains the `Permission::Passkey` permission, which grant validation rejects outside a task (ADR 0021); `klav mcp` gains `passkey_sign_in`;
  - the extension gains a script in the `MAIN` world and a `passkey` surface;
  - `klav-ffi` gains five methods;
  - the server gains `POST /v1/audit/person`; blobs stay opaque.
- **Threat model:** threats T80–T90 (§5.8) and residual risks 21–24.
- **Signatures:** the specification's §9 rule ("every signature carries `klav/v1/sig/`") applies to the Ed25519 identity keys. Passkey P-256 keys are of another kind, are generated per credential and only sign WebAuthn messages (`authData ‖ clientDataHash`), so there is no cross-protocol confusion. The specification's §14 says so.
- `docs/diseno.md` still says passkeys are outside the MVP; it is updated on accepting, along with the roadmap's "Después (sin fecha)" row.
