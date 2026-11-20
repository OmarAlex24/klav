# 0014 · Agents (phase 4): registration, grants, signed requests, approvals, audit log, MCP and SDK

- Status: accepted
- Date: 2026-11-02

## Context
Phase 4 closes milestone A: an AI agent uses a person's vault without knowing their password or their Secret Key (ADR [0002](0002-agentes-con-identidad-propia.md), design §5). We need to pin down:

- the format of what gets signed and stored;
- what the server can check, given that it never sees names, tags or URLs;
- how the agent's key is stored;
- which dependencies come in for MCP and for filling forms in a browser.

Three topics that earlier phases left for this one: the policy schedule (threat model §7.5), the fingerprint word table (spec §6.2) and the per-project scope of `klav.toml` (`cli.md` §5).

## Decision

### 1. Identity and registration
1. **The agent generates its identity** (X25519 + Ed25519, spec §6) and its `AgentId` on the client. Registration is `POST /v1/agents/register` with the account email, a name, an optional note and the public identity.
2. **Registration doesn't reveal accounts.** The server always answers `202` with the same shape. If the email doesn't exist, it stores nothing. A repeated ID is `409` regardless of the email. In addition:
   - there are at most 20 pending requests per account (any further ones are silently dropped);
   - a request expires after an hour;
   - the endpoint uses the per-IP authentication *rate limit*.
3. **6-word pairing code** (spec §13.1):
   - `palabra_i = EFF[u32_be(huella[4i..4i+4]) mod 7776]`, with i = 0…5, over the *EFF Large Wordlist* that the generator already uses. Its license (CC BY 3.0 US) is in `crates/klav-core/src/generator/WORDLIST-NOTICE.md`.
   - That is about 77.5 bits; the modulo bias is less than 2⁻¹⁹ per word.
   - The person compares the words the agent shows with the ones their device shows before approving (T10).
   - When approving, the client recomputes the code from the identity the server gives it and compares it with the one the person confirmed. That way the server can't swap the key between showing it and approving it.
4. **The agent pins the account identity the first time** it sees it (TOFU), in `agents/<nombre>.json`. If it changes later, it refuses to continue.
   - To close the gap of that first time, `klav status` (person) and `klav agent status` (agent) show the account's 6 words, so they can be compared.
   - The agent also stores the highest *grant* version it accepted and rejects a lower one (*rollback*).
5. **Agent private key** (type `0x07`, spec §13.2): `"kag1_" ‖ base64url(0x01 ‖ 0x07 ‖ x25519_sk ‖ ed25519_seed)`, unencrypted, because whoever reads it *is* the agent. It is stored in one of these places:
   - the macOS Keychain (generic password in the login keychain, service `dev.klav.agent`, through the Swift shim from ADR 0013 and without *entitlements*);
   - a 0600 file (the SDK rejects files readable by others);
   - the `KLAV_AGENT_KEY` variable, which takes priority over what is stored.

   An unsigned, rebuilt binary makes macOS ask again for permission to read the Keychain. That is why the tests and the manual testing guide use a file.

### 2. Grants
1. **The grant is signed JSON and is stored byte for byte.** The person's client builds a `GrantPayload` with:
   - `v`, account, agent and `version` (the current one + 1);
   - date;
   - the policy;
   - the list of projects, each with its key wrapped with HPKE for the agent (type `0x21`, spec §8).

   The client serializes the payload and signs those exact bytes over `tuple("klav/v1/sig/agent-grant", account_id, agent_id, identidad_pública_del_agente(66), payload)` (spec §13.4).
   - The server stores the payload as a blob and returns it as is, so no canonical serialization is needed.
   - The server verifies the signature and that the version is the next one; if it isn't, it answers `409`.
   - The agent verifies the signature again with the pinned account identity.
2. **Projects are shared, not vaults.** `--vault V` expands to V's current projects. A project created later isn't included until a new grant. That way the agent never receives a vault key.
3. **Grant policies name vaults and projects by ID.** The client translates the names before signing, and the server rejects a grant with name selectors, because it can't see names.

### 3. Signed agent requests
1. **There is no bearer token.** Each request is signed with Ed25519 over `tuple("klav/v1/sig/agent-request", agent_id, método, ruta_con_query, u64_be(ts_ms), nonce(16), SHA-256(cuerpo))`. The signature travels in the `Klav-Agent`, `Klav-Timestamp`, `Klav-Nonce` and `Klav-Signature` headers (spec §13.3).
2. **±5-minute window.** Nonces are stored in the database for 10 minutes with primary key `(agent_id, nonce)`. The nonce is inserted before the request is served, and a uniqueness violation is a *replay* (`401`, T25).
3. **The signed path is the one the client sent** (`OriginalUri`), so a reverse proxy must not rewrite `/v1/agent…` (`self-hosting.md` §3).
4. **Revocation is checked on every request**, in the same extractor that verifies the signature: a revoked agent stops working on the next request.

### 4. Policy enforcement on the server
1. **Double barrier** (T22). The agent can only decrypt the projects in its grant. On top of that, the server evaluates the policy (`klav_core::policy`) on every agent endpoint, and the agent runtime evaluates it again with the decrypted data.
2. **The server doesn't see tags, domains or names.**
   - In actions on an item, the agent declares the domain and the tags in the signed request, and the server evaluates with them. If the agent lies, it can only use what its own runtime would have denied it: the key is still the barrier.
   - For listing, the server uses `evaluate_upper_bound`, the most permissive effect possible for some tags and domain (`max(forzado, min(posible))`), and only lists the projects where it comes out `allow`. There are *proptests* that check it is never stricter than `evaluate` nor different when the rule doesn't depend on tags or domain.
   - The list never carries `details`: secrets arrive one at a time through `POST /v1/agent/access`, after the policy is evaluated.
3. **Schedule** (design §5.2): `Scope.hours` is a list of `TimeWindow { days, start, end, utc_offset }` with a fixed UTC offset (`mon-fri 09:00-18:00 -06:00`). There is no time zone database, which would be a large dependency for the server and for WASM. The consequence: **with daylight saving time the offset has to be updated**. Windows can cross midnight, and `start == end` covers the whole day. With `--hours`, the CLI gives each permission a rule (the default one if it had none) and puts the window on them, so outside the schedule everything is `deny`.

### 5. `ask` approvals
1. An action in `ask` creates a pending approval and the agent receives `pending_approval_id`. The person decides from the CLI or `klavd`; phase 6 will add mobile *push* on the same endpoint.
2. **The decision is signed by the account.** When creating the request, the server builds an `ApprovalRequest` in JSON with:
   - the agent;
   - the permission;
   - the vault, the project and the item;
   - the reason and the `claims`;
   - the grant version.

   It stores those bytes only once. The person signs exactly those bytes in `tuple("klav/v1/sig/approval", approval_id, agent_id, request, "approve"|"deny", u64_be(lease_until_ms), u64_be(decided_at_ms))` (spec §13.5). The server stores the signature and the agent can verify it.
3. **Leases** ("approve for 15 min"): `lease_until_ms > decided_at_ms` allows the same action (agent, permission and item) to repeat until that time without asking again, for at most 24 hours.
   - An approval without a lease is spent on first use.
   - An approval is only valid with the grant version it was requested under; a new grant expires the pending requests.
4. **Presence:** approving a registration, a grant or a request requires Touch ID (`LAContext`, no key) through `klavd`, or the master password if there is no Touch ID. In direct mode, the CLI already asked for the password to unlock.

### 6. Audit log
1. **One chain per account:** `hash_n = SHA-256(tuple("klav/v1/audit/event", u64_be(n), hash_{n-1}, evento_n))`, where `evento_n` is the exact JSON bytes the server stored (spec §13.7). No canonical form is needed: nobody re-serializes the event.
   - Agent events (`reason` required) carry the **request signed by the agent** (§13.3), with the body if it is up to 16 KiB. The verifier checks the signature and that the event's reason, item and permission match what was signed. Larger item writes only store the body's digest.
   - The person's decisions (grants, approvals, revocations) carry the signed bytes and the account's signature.
   - **Deviation from design §6:** item creations, edits and deletions made by the person are **attested by the server** (chained, without a client signature). Signing them would require changing the phase 2 write protocol.
   - The server records the policy decision **before** answering: an agent never receives a secret without an event.
2. **The head is signed by trusted devices.** Each successful `klav log verify` signs the current head with the account identity, uploads it (`POST /v1/audit/heads`) and saves it in `audit-head.json`. A server that rewrites, deletes or reorders the history before a signed head is exposed; so is one that shortens the chain.
3. **`reason` is stored in plaintext** on the server, because it needs it for alerts and to show it in approvals. This is documented in the threat model (T20): the agent must not put secrets in `reason`.
4. **Basic alerts:** `first_use` (first use of an item's secrets by an agent), `burst` (20 or more accesses in 1 minute) and `denied`. They are computed when the event is appended and are stored inside it.
5. **Export:** `klav log --json` or `--csv`. The CSV neutralizes cells that start with `=`, `+`, `-` or `@`, because the agent writes the reason.

### 7. Revocation and rotation
1. **Revoking** is `POST /v1/agents/{id}/revoke`, with an account signature over `tuple("klav/v1/sig/agent-revocation", account_id, agent_id, u64_be(revoked_at_ms))` (spec §13.6). It blocks the agent on the next request and denies its pending approvals. It doesn't ask for Touch ID: removing access should cost nothing.
2. **Project key rotation** (`klav agent revoke --rotate`, `GET …/keys` and `POST …/rotate` in `api.md` §4.2):
   - The client generates a new project key and wraps it with the vault key.
   - It uses it to rewrap the keys of **all** the project's items (current and history) and seals the metadata again.
   - The server applies it in a single transaction and answers `409` if the key set changed in the meantime.
   - The client reissues, with the new key, the grant of the other active agents that had that project (same policy, version + 1). The person already approved their keys and the previous grant is signed by the account, so the words are not compared again.

   **Cost:**
   - the work grows with the number of stored versions (up to 50 per item, plus the current one); the `rotate` body accepts up to 64 MiB;
   - item keys **don't change**, so an agent that already decrypted an item keeps what it saw and, if the server colludes, can open its future edits (T24). Rotation protects items created afterwards. Changing item keys is left for later (residual risk 11);
   - the other agents with that project need a new grant (it is issued automatically).

   The "what it saw" report lists the projects whose keys it had and, according to the audit log, the items it used, with which permissions and whether it obtained a secret.

### 8. MCP
1. **`klav mcp` is JSON-RPC 2.0 over stdio written by hand**, without the `rmcp` crate:
   - only `initialize`, `ping`, `tools/list` and `tools/call` are needed, plus empty lists of resources and *prompts*;
   - `rmcp` pulls in macros and a large dependency tree for a protocol of a few lines;
   - writing it by hand makes clear what goes out on stdout, which carries only JSON-RPC (one message per line).
2. **Values don't go back to the LLM except with `reveal`.**
   - `run_with_secrets` removes the injected values from the process output.
   - `inject_file` only writes inside the working directory (symbolic links in the parent directory are resolved).
   - `get_item` returns metadata and the field names for its kind, without values.
   - `fill_login` and `fill_card` accept the `sdk:<sesión>` target: a browser session the runtime registered beforehand, so the LLM can't pick an arbitrary CDP *endpoint*. The `extension` target answers "not available yet" (phase 5).
   - **Documented exception:** `get_totp` without a target returns the code. It is single-use and expires in 30 s, and `totp` is `ask` by default (T26). With `target` it types it into the page and doesn't return it; the skill asks to prefer that form.
3. **`ask` from MCP:** each tool waits for the person for up to `wait_seconds` (by default the `--wait` of `klav mcp`, 2 min; at most 10). If the decision doesn't arrive, the result is an error with the request ID and how to approve it.
4. **`request_access(ref, permission)`** doesn't widen grants. If the policy says `ask`, it creates the request and returns its ID. If it says `deny`, it returns the command the person would have to run (`klav agent approve … --allow …`) so the agent can ask them for it with its reason. Notifying the phone comes in phase 6.
5. **Agent writes:** `create_item` seals the item with the key of the granted project. `update_item` reads the item (`access` with `update`), applies the patch and writes the next version with the same item key. With `ask` there are two requests; approving the first one "for a few minutes" (`--for`) covers both. `delete_item` sends it to the trash.
6. **Denials also go in the audit log:** the runtime evaluates the policy with the real tags, but sends the request to the server even if it gets `deny`, so the event is recorded (with the `denied` alert).

### 9. SDK and browser
1. **`fill` uses a minimal CDP client** on top of `tokio-tungstenite` (without TLS: CDP is local) and types into the field with `DOM.focus` + `Input.insertText`. The value never goes back to the caller.
   - The WebSocket *handshake* uses SHA-1 (RFC 6455) through `tungstenite`, which also brings in `rand` for frame masks. These aren't cryptographic uses by Klav and they don't enter `klav-core`.
   - It only accepts browsers on the same machine (`127.0.0.1`, `::1`, `localhost`): the value travels in plaintext over the WebSocket.
   - Before typing, the SDK reads the tab's real address and requires `https` (or `http` on the same machine) and that its host is the host of one of the item's URLs or a subdomain of it (T21). That host goes to the server as `domain`, so the policy is enforced on both sides. The address is read again before each field. Cards have no URL: for them only the policy counts.
   - Without selectors, it fills the username and password of a login or the fields of a card with common selectors (`autocomplete`, `type=password`…); `--selector campo=css` changes them.
2. **Named sessions:** the runtime registers a browser (CDP endpoint and tab) as `sdk:<nombre>` in `$KLAV_HOME/browser-sessions/`. That way `klav mcp` can fill there without the LLM picking an *endpoint*.
3. **The agent's `run` and `inject`** use the `inject` permission. `run` returns the process output with the injected values replaced by `[redacted by klav]` (a safety net: a process that encodes the value gets around it). `inject` only writes new 0600 files, never to stdout. Attachments aren't available to agents yet (ADR [0016](0016-adjuntos-para-agentes.md) enabled them later).
4. **npm package:** `@klav/sdk` (`packages/sdk`), a minimal Node wrapper that calls `klav agent …`, instead of `klav-wasm`. WASM can't speak CDP or read the Keychain, and there is no JavaScript that signs or decrypts. The wrapper passes the reference, the reason and the selectors, never values. Playwright example in `examples/playwright`.

### 10. `klav.toml` and agents
`klav mcp` and the SDK honor `[project]` in `klav.toml`. If it exists, short references are resolved there and the tools only see that project, even if the grant has more.

## Consequences
- New versioned formats with vectors in `docs/vectores/agentes.json`: the pairing code, type `0x07` and the four signatures.
- New labels, with the `klav/v1/sig/` prefix (§9 of the spec): `agent-request`, `agent-grant`, `approval` and `agent-revocation`.
- New dependency outside `klav-core`: `tokio-tungstenite` (WebSocket client for CDP), without `rustls`, because CDP is local.
- Accepted risks, documented in the threat model:
  - the first time the agent sees the account (TOFU), mitigated by comparing words;
  - `reason` in plaintext;
  - the person's CRUD events attested by the server;
  - daylight saving time with a fixed offset.
