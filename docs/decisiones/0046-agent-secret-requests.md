# 0046 · Agent secret requests: an agent proposes a secret item, the person enters it in a hidden input on their device, and the value never touches the LLM

- Status: Accepted and implemented across layers 1–6 (2026-11-23; pending CI verification of full HTTP E2E and Xcode/extension builds). Omar accepted Q1–Q5 with the recommended option in each on 2026-11-23 («si esta bien, vamos con los recomendados»).
- Date: 2026-11-23
- Builds on: [ADR 0014](0014-agentes-fase-4.md) (signed agent requests and approvals), [ADR 0015](0015-aprobaciones-reutilizables-y-espera.md) (long-poll wait), [ADR 0021](0021-solicitudes-de-tarea.md) (cards built from the person's own vault), [ADR 0036](0036-sandboxes-de-agentes.md) (per-item proxy grants) and [ADR 0041](0041-presence-for-values-and-the-inject-card.md) (HPKE-encrypted request payloads to the account's identity)

## Context

### The gap today
Klav's core rule is that **secret values must not enter an LLM's context**. That already holds when using secrets that exist in the vault (`fill_login`, `run_with_secrets`, `inject_file`, `klav-proxy`) and when creating a brand-new password (`create_item` with `generate: true`, ADR [0022](0022-generador-historial-y-cambio-asistido.md) §7).

It breaks down in one everyday workflow: **adding or rotating an external secret that already exists outside Klav** — for example, an API key from Vercel AI Gateway, Stripe, OpenAI or Cloudflare, a database URL, or a webhook secret.

Today the agent has only three options, all awkward or unsafe:
1. **Ask the person to paste the key in chat** and pass it to `create_item` / `update_item` — breaks the zero-LLM-exposure rule.
2. **Print a manual CLI command** (`klav item add api-key --title "…" -s api_key`) and wait for the person to switch terminals, create the item, optionally run `klav proxy grant …`, and come back to confirm.
3. **Rely on a client-specific secret prompt** (such as T3 Code's `request_secret`), which only exists in one host, doesn't work across Claude Code, Codex, Cursor, VS Code or iOS push approvals, doesn't natively store the item in Klav, and cannot pair saving the item with a `klav-proxy` grant for sandboxes.

### What Omar wants (2026-11-23)
A native Klav flow where an agent proposes a secret it needs (creating a new item or updating a secret field of an existing one, and optionally proposing a `klav-proxy` profile for sandboxes), and the person only types or pastes the value into a hidden input card on their own device — Mac, iPhone, extension or terminal — without the value ever reaching the agent or the Klav server in clear text.

## Decision

### 1. The request: metadata only, HPKE-encrypted to the account
An active agent sends a signed **secret request** (`POST /v1/agent/secret-requests`, signed with `klav/v1/sig/agent-request` like every other agent call):

**In the clear (stored by the server and logged):**

| Field | Type | Notes |
|---|---|---|
| `request_id` | UUID | Server-assigned (or idempotency key per request) |
| `mode` | `"create"` \| `"update"` | Whether the agent asks for a new item or a field update on an existing one |
| `target_item_id` | optional UUID | Required when `mode = "update"`; omitted for `"create"` |
| `reason` | text | Mandatory, max 500 chars; plain text, no secrets (same rule as `ApprovalRequest` and `TaskRequest`) |
| `proposal_digest` | 32 bytes (hex) | `SHA-256(proposal_bytes)` |
| `proposal_blob` | bytes | HPKE-encrypted `proposal_bytes` (kind `0x25`, spec §13.14) to the account's X25519 identity (`info = tuple("klav/v1/agent/secret-request", account_id, agent_id, request_id, account_fingerprint)`, `aad = 0x01 ‖ 0x25`) |

**Inside `proposal_bytes` (JSON, encrypted end-to-end; the server never reads it):**

```json
{
  "v": 1,
  "mode": "create",
  "kind": "api_key",
  "title": "Vercel AI Gateway",
  "vault_id": "<optional UUID of a granted vault>",
  "project_id": "<optional UUID of a granted project>",
  "field": "api_key",
  "placeholder": "vck_…",
  "setup_url": "https://vercel.com/dashboard/ai-gateway",
  "base_url": "https://ai-gateway.vercel.sh",
  "notes": "Used by voz.mjs to generate narration",
  "proxy_proposal": {
    "preset": null,
    "profile": "vercel-ai",
    "upstream": "https://ai-gateway.vercel.sh",
    "header": "authorization",
    "prefix": "Bearer ",
    "methods": ["POST"],
    "ask_methods": [],
    "path_prefixes": ["/v1"],
    "rate_per_minute": 60
  }
}
```

- **No value field exists** in the schema (`deny_unknown_fields`). An agent can never attach a secret value to a secret request.
- **Zero-knowledge metadata:** following [ADR 0041](0041-presence-for-values-and-the-inject-card.md) §5.2–§5.3, the server never sees the item title, field name, provider URLs or proxy upstream. It holds `proposal_blob` only until the request is decided or expires (1 hour TTL), and an hourly sweep deletes expired blobs; the audit log keeps only `proposal_digest` and `reason`.
- **Kinds allowed:** `api_key` (default), `login`, `note`, `ssh_key` and `totp` (Q4). System kinds (`generator_history`, `preferences`) are rejected.
- **Limits:** at most **5 pending secret requests per agent** (same cap as ADR 0021 tasks), 1-hour expiry, max 8 KiB for `proposal_blob`. Paused agents (`403 agents_paused`) and accounts pending deletion (`403 account_deleting`) are refused at once. `klav-proxy` itself may not create secret requests.
- **Who can request:** any active non-proxy agent with a valid grant — even if its grant denies `create` or `update` (or if it is a sandbox issuer with no projects at all) — because **the person**, not the agent, writes the item to the vault (Q2).

### 2. The person's card: built from the person's vault, never trusting agent text
The request arrives in **Requests** across the Mac app, iOS (APNs push type `secret_request` with a random ID and no text, T75), the browser extension popup, and the CLI (`klav secret-request`).

The person's client decrypts `proposal_blob` with the account's X25519 key, verifies `SHA-256(proposal_bytes) == proposal_digest`, and renders a single card:

- **Header:** agent name (quoted, *"name set by the agent"*), ID prefix, and `reason` (*"according to the agent"*).
- **In `create` mode:**
  - Editable **kind**, **vault / project picker**, **title**, and **field name** (pre-filled from the proposal, editable by the person).
  - If `project_id` is in the agent's grant, it is preselected and explicitly badged **"Shared with `<agent>`"**. Otherwise the picker defaults to `Personal / General` (or the person's choice) and shows **"Not shared with `<agent>`"**.
  - **Unique title check:** if the chosen project already has an item with that title, the card warns before saving and refuses silent overwrite; the person renames it, picks another project, or explicitly switches to updating that item.
  - Any agent-suggested non-secret fields (`urls`, `base_url`, `notes`) are shown in full, editable, and marked **"Suggested by `<agent>`"**. For `login` items, agent-suggested `urls` are clearly highlighted so a prompt-injected agent cannot sneak a phishing site into confirmed autofill URLs (T234).
- **In `update` mode:**
  - The card looks up `target_item_id` in the **person's own decrypted vault** (never trusting any title or URL from the agent, same rule as ADR 0021 §3). If the item does not exist or is in the trash, the card refuses to fulfill and explains why.
  - Shows the item's real vault, project, title and hosts, and states clearly: **"Replace `<field>` of `<real title>` (previous value stays in password history)"**.
  - If the item is protected (ADR 0032 §3.1), the card says so and requires presence (Touch ID / Face ID / master password).
- **Hidden input:**
  - A masked single-line (or multi-line for `ssh_key` / `note`) secret input, with optional `placeholder` from the proposal (sanitized, plain text, max 64 chars).
  - The typed/pasted value lives only in the card's memory and is cleared on save, cancel, deny, or lock (same rule as `ItemDraft` in [`docs/macos.md`](../macos.md) §2).
- **Optional `setup_url` ("Open provider page"):**
  - Only `https://` URLs with no userinfo, no IP literals and no private/loopback hosts are accepted; anything else is dropped with a notice.
  - Never auto-opened. Displayed with its full host and path (and punycode/IDN warning if applicable), explicitly labeled **"Link suggested by `<agent>` — check the domain before opening"** (T235).
- **Optional `proxy_proposal` ("Also grant to credential proxy"):**
  - Shown only when the account has a configured credential proxy (`mode == own`, ADR 0036 §3) and the proposal carries `proxy_proposal`. If no proxy is configured, the card notes it and lets the person save the vault item alone.
  - Validates the spec with the exact same rules as `klav proxy grant` (`ProxyCredentialSpec`, `MAX_GRANT_METHODS = 4`, preset notes if `preset` is set, SSRF/host checks, and the host-reach warning of T151).
  - Shows the full profile preview (`profile`, `upstream`, `header`, `prefix`, `allow` methods/paths, `ask` methods/paths, `rate`) behind an **explicit toggle, unchecked by default** (Q3); `klav proxy issuer add` remains separate.
  - Enabling it **always requires presence** (Touch ID, Face ID or master password), just like `klav proxy grant`.
  - Saving an item to a project outside the agent's grant **never widens that agent's grant**: granting `proxy_proposal` wraps the item key (`0x23`) only for `klav-proxy`.

### 3. Saving and signing the decision
When the person clicks **Save** (or runs `klav secret-request fulfill <id>`):

1. **Vault write (E2E):** the person's device creates or updates the item using the normal encrypted item flow (`POST /v1/vaults/{v}/projects/{p}/items` or `PUT …/items/{id}`). The new version is authored by the person; previous secret values move to the password record (`0x16`).
2. **Optional proxy grant:** if the person enabled the proxy toggle and confirmed with presence, the device signs and uploads `klav-proxy`'s updated per-item grant (`v: 2`, blob `0x23`) — the exact same flow as `klav proxy grant`. If the item was saved but the proxy grant fails, the UI reports both outcomes clearly (nothing is rolled back silently, and the decision does not claim `proxy_profile` was granted).
3. **Signed decision:** the person's device signs the result with the account's Ed25519 key (new label `klav/v1/sig/secret-request-decision`) and posts it to `POST /v1/secret-requests/{id}/decide`:

   ```
   decision = JSON {
     v: 1,
     request_id,
     agent_id,
     status: "fulfilled" | "denied",
     item_id?,          // present only if fulfilled AND item is inside the agent's grant
     vault_id?,         // present only if fulfilled AND item is inside the agent's grant
     project_id?,       // present only if fulfilled AND item is inside the agent's grant
     field?,            // present only if fulfilled
     proxy_profile?,    // present only if proxy grant succeeded
     in_grant: bool     // whether the asking agent can access the saved item directly
   }
   sig = Ed25519(account, tuple(
     "klav/v1/sig/secret-request-decision",
     request_id,
     agent_id,
     proposal_digest,
     decision_bytes,
     u64_be(decided_at_ms)
   ))
   ```

- **No cross-project metadata leak:** if the person saved the item into a vault/project the asking agent does **not** have in its grant (for example, a sandbox-only secret granted only to `klav-proxy`), `in_grant` is `false` and `vault_id`/`project_id`/`item_id` are omitted from `decision` — the agent learns only `{ status: "fulfilled", in_grant: false, proxy_profile: "vercel-ai" }` (or `proxy_profile: null`), never the names or IDs of ungranted projects (T236).
- **Signature verification by the agent:** before acting on the response, `klav-sdk` / `klav mcp` verifies `sig` against the account's pinned public identity (TOFU, ADR 0014 §1.4) and checks `request_id`, `agent_id` and `proposal_digest` match what it sent (T237). A malicious server cannot forge a fulfillment or swap the returned `item_id` or `proxy_profile`.
- **Denying** is signed the same way (`status: "denied"`).

### 4. Agent interface (MCP, CLI, SDK)
- **MCP tool `request_secret`:**
  - Arguments: `{ reason, mode?, type?, title?, ref?, field?, project?, placeholder?, setup_url?, base_url?, notes?, proxy_profile?, wait_seconds? }`.
  - Long-poll up to `wait_seconds` (default 60 s, max 600 s, same as `request_task`, ADR 0021 §7).
  - While pending, returns:
    ```json
    {
      "status": "pending",
      "request_id": "…",
      "expires_at": "…",
      "fulfill_command": "klav secret-request fulfill <id>",
      "wait_command": "/path/to/klav agent secret-request wait <id> --agent <name> --timeout 10m --json",
      "next": "Tell the person what secret you need and why, wait in the background with wait_command, and continue once it exits 0."
    }
    ```
  - When fulfilled (after verifying the account's signature):
    - If `in_grant: true`: resolves the local reference and returns `{ status: "fulfilled", ref: "klav://<Vault>/<Project>/<Title>/<field>", item_id, field, in_grant: true, proxy_profile? }`.
    - If `in_grant: false`: returns `{ status: "fulfilled", in_grant: false, field, proxy_profile? }` with a `next` note (e.g., use the proxy profile in a sandbox, or ask the person if local access is needed).
  - **Never returns the secret value.**
- **CLI (agent side):**
  - `klav agent secret-request create --reason "…" [--mode create|update] [--type api-key] [--title "…"] [--ref REF] [--field api_key] [--setup-url URL] [--wait 2m] [--json]`
  - `klav agent secret-request wait <id> [--timeout 10m] [--json]` (exit codes matching ADR 0015 / ADR 0033: `0` fulfilled, `4` pending, `5` denied, `6` expired, `7` paused, `8` account deleting).
- **CLI (person side):**
  - `klav secret-request ls [--json]`
  - `klav secret-request show <id> [--json]`
  - `klav secret-request fulfill <id> [--vault V] [--project P] [--title T] [--grant-proxy] [--secret-stdin]` (prompts without echo on `/dev/tty` by default)
  - `klav secret-request deny <id>`
- **SDK:** `Session::request_secret` in `klav-sdk` and `requestSecret` in `@klav/sdk`.

### 5. Server routes and audit log
- **Agent routes (signed):**
  - `POST /v1/agent/secret-requests`
  - `GET /v1/agent/secret-requests/{id}?wait=N` (long-poll)
- **Person routes (authenticated session):**
  - `GET /v1/secret-requests`
  - `GET /v1/secret-requests/{id}`
  - `POST /v1/secret-requests/{id}/decide`
- **SSE & Push:**
  - `GET /v1/events` emits a `secret_request` event so the Mac app and extension refresh immediately.
  - APNs sends a push of type `secret_request` with only a random ID (T75).
- **Audit log:**
  - `secret_request.created` (agent_id, request_id, mode, target_item_id?, proposal_digest, reason)
  - `secret_request.decided` (agent_id, request_id, status, item_id?, proxy_profile?, signed by account)
  - `klav log verify` verifies `secret_request.decided` against the account identity and the matching `secret_request.created`'s `proposal_digest`.

### 6. Threat model (proposed additions: T234–T239)

| ID | Threat | Mitigation |
|---|---|---|
| **T234** | Prompt-injected agent proposes a `login` item with a phishing URL in `urls`, hoping the person's Save turns it into a confirmed autofill site (bypassing ADR 0030 §7) | Card highlights agent-suggested `urls` explicitly as *"Suggested by `<agent>`"* and leaves them unchecked/unconfirmed by default on `login` items until the person explicitly confirms or edits them (Q4) |
| **T235** | Prompt-injected agent sets `setup_url` to a lookalike phishing page so the person signs in and leaks their provider credentials | Only `https://` with no userinfo/IP literals/private hosts; never auto-opened; full domain shown with *"Link suggested by `<agent>` — check the domain before opening"* |
| **T236** | Agent probes whether items or projects exist outside its grant by sending `update` with guessed UUIDs or inspecting the fulfillment response | In `update` mode, the server/client refuses `target_item_id` outside the agent's granted projects unless the person explicitly confirms; when the person saves to an ungranted project, `decision` omits `vault_id`, `project_id` and `item_id` (`in_grant: false`) |
| **T237** | Malicious server forges `fulfilled` or swaps `item_id` / `proxy_profile` in the response | Person signs `decision_bytes` with `klav/v1/sig/secret-request-decision` bound to `proposal_digest`; `klav-sdk` verifies the signature against the account's pinned identity |
| **T238** | Compromised or noisy agent floods the person with secret-request cards (approval fatigue, T27) | Cap of 5 pending requests per agent, 1-hour expiry, server rate limits, and pausing/revoking the agent blocks new requests immediately |
| **T239** | Agent proposes an overly broad `proxy_proposal` (e.g. `DELETE` allowed, or pointing to a provider hosting the proxy itself, T151) hoping the person clicks Save without noticing | Proxy grant toggle is unchecked by default, displays the full `klav proxy grant` preview and warnings, enforces `MAX_GRANT_METHODS = 4`, and requires separate presence (Touch ID / Face ID / master password) |

**Residual risks:**
- A person who blindly clicks an agent-suggested `setup_url` without reading the domain can still be phished (mitigated by explicit domain display and warning, not eliminated).
- `reason` stays in plain text on the server and in the audit log (same as ADR 0014 / ADR 0021); an agent could mistakenly put sensitive context in `reason` (mitigated by skill rules and length cap).

## The owner's decisions (2026-11-23)

Omar accepted the ADR on 2026-11-23 taking the recommended option for every open question:

- **Q1 · Metadata encryption:** `proposal_blob` is HPKE-encrypted to the account's X25519 identity (`klav/v1/agent/secret-request`); the server keeps only `reason`, `mode`, `target_item_id?`, `proposal_digest` and expiry, and sweeps expired/decided blobs.
- **Q2 · Who may request:** any active non-proxy agent (capped at 5 pending requests per agent) may send `request_secret` without needing `create` or `update` in its grant, because the person performs the vault write.
- **Q3 · `proxy_proposal` in the same card:** option (a) — the card can save the item and (via an explicit unchecked toggle + Touch ID / Face ID / master password presence) sign `klav-proxy`'s per-item grant (`0x23`), leaving `klav proxy issuer add` separate.
- **Q4 · Allowed kinds and `login` URLs:** option (a) — allow `api_key`, `note`, `ssh_key`, `totp` and `login`; any `urls` suggested by an agent on a `login` stay unchecked/unconfirmed by default so a prompt-injected agent cannot plant a phishing autofill URL (T234).
- **Q5 · Updating an existing item:** include `mode: "update"` in v1 (replacing one secret field of an existing item, with the old value preserved in password history `0x16` and the card reading the real item metadata from the person's vault).

No open questions remain.

## Plan in layers (once accepted)

1. **`klav-core` + spec + vectors:** `SecretRequestProposal`, `SecretRequestDecision`, blob kind `0x25` (`klav/v1/agent/secret-request`), signature label `klav/v1/sig/secret-request-decision`, URL validator for `setup_url`, spec §13.14 and test vectors in `docs/vectores/secret-request.json`.
2. **`klav-proto` + `klav-server` + migration:** `secret_requests` table, hourly blob sweep, `/v1/agent/secret-requests` (with long-poll) and `/v1/secret-requests` routes, `secret_request.created`/`decided` audit events, SSE event and APNs `secret_request` push.
3. **`klav-client` + `klavd` + `klav-sdk`:** HPKE seal/open, decision signing and verification, `klav log verify` checks, `klavd` operations, `Session::request_secret`.
4. **`klav-cli` + `klav mcp` + skill:** `request_secret` MCP tool, `klav agent secret-request create|wait`, `klav secret-request ls|show|fulfill|deny`, and a short update to `skill/SKILL.md` (and `skill/klav-migrate/SKILL.md`) so agents use `request_secret` when a key is missing.
5. **Apps (`klav-ffi`, Mac, iOS, extension):** the Requests card with hidden input, project picker, `setup_url` warning, and optional `proxy_proposal` toggle with Touch ID / Face ID.
6. **End-to-end test:** agent calls `request_secret` for an API key with `proxy_proposal`; person fulfills it via hidden input (verifying the value never appears in server logs, DB blobs, stdout/stderr, or the MCP response); agent verifies the signed decision and runs a command / proxy call with the new reference; forged decision and phishing `setup_url` are rejected.

## Rejected alternatives
- **Having the agent create an empty placeholder item with `create_item` and asking the person to edit it later:** requires giving the agent `create` permission, leaves broken empty items in the vault if the person declines, has no push notification or wait loop, and cannot carry a `proxy_proposal`.
- **Extending `create_item` to accept a value from a host-side secret prompt:** still couples Klav to one specific host (T3 Code), bypasses iOS/Mac Requests and audit-signed decisions, and cannot run from remote agents or sandboxes.
