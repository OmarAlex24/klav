# 0049 · MCP gateway: remote MCP servers through `klav-proxy`, with per-tool rules signed in the grant, filtered `tools/list`, tool-level approvals and audit, for sandboxes and for the agents on the person's Mac

- Status: accepted (2026-11-25)
- Date: 2026-11-25
- Amends:
  - [ADR 0036](0036-sandboxes-de-agentes.md) §7, Omar's decision 3 of the note of 2026-11-19 ("per-tool approval is not designed now; it would need a new field in the signed rule, its own ADR and a round of device updates"). This is that ADR.
  - Threat T226 (the MCP gate cannot tell one tool from another).
  - [ADR 0006](0006-semantica-de-politicas.md), narrowly (Q3 was answered (a)): a new policy dimension, `mcp_tools`, that a rule without it cannot use to allow a tool call (§5.3).
- Builds on and does not replace: mode (c) of ADR 0036 §7 and its steps M2–M5 (stream limits, the `maple` preset), the memory layer of [ADR 0044](0044-proxy-key-at-rest.md), and the approval card machinery of [ADR 0041](0041-presence-for-values-and-the-inject-card.md) §5.3.

## Context

### What was asked
Klav as **"Composio without handing your keys to a third party"**: one place where the person's agents reach remote MCP servers (Maple, GitHub, Cloudflare, Linear, Stripe, Northflank and any other), with the provider key never in the agent's config, the sandbox or a vendor's cloud, and with a say on **which tools** an agent may call, not only which host. This applies to sandboxes (Boat) and to local agents on the Mac (Claude Code, Codex, Cursor, VS Code).

It is also Omar's most frequent credential chore: he generates Cloudflare and Northflank API keys again and again for his agents.

### What the code does today (`main` at `caf23e5b`, read on 2026-11-25)

- **The MCP gate (mode (c)) is a mode (a) profile.** A call to `http://127.0.0.1:<port>/<profile>/<path>` is sent to the profile's upstream with the credential in the profile's header (`crates/klav-proxy/src/proxy.rs:1-13`, `forward` at `:1015`). The proxy never reads the body. Every MCP call is the same `POST /mcp`, so the policy cannot tell `query_logs` from `delete_dashboard` (T226). The only limit is the key's own scope: for Maple, a restricted read-only key (ADR 0036 §7, decision 2 of 2026-11-19).
- **M2 is on `main`; M3–M5 are not.** The `StreamRedactor` already has its line-by-line emission (`by_lines`, `crates/klav-sdk/src/actions.rs:449-489`). `klav-proxy` has no `text/event-stream` handling yet (`grep` finds none), the whole call still has the 120 s `DEFAULT_REQUEST_TIMEOUT` and the 60 s `BODY_IDLE` (`proxy.rs:39`, `:50`), and the roadmap boxes for mode (c) and the presets are open (`docs/roadmap.md:352-355`). This ADR comes after M3–M5; it doesn't redo them.
- **The proxy on the Mac is not built.** The roadmap item "the proxy on the Mac: LaunchAgent and Tailscale" is open (`docs/roadmap.md:357`). `klav-proxy` can already keep its key in the macOS keychain (`crates/klav-proxy/src/main.rs:120`).
- **The grant.** `GrantPayload` is `v: 1` (projects), `v: 2` (items, profiles, `proxy` rules) or `v: 3` (sandbox issuers) (`crates/klav-proto/src/agent.rs:110-160`). A `ProxyProfile` is `{name, item_id, field?, header, prefix, upstream, rate_per_minute?}` (`agent.rs:295`). The hosts, methods and paths are `proxy` rules of the policy, with `Scope.domains`, `Scope.methods`, `Scope.path_prefixes` and `Scope.items` (`crates/klav-core/src/policy.rs:745-800`). `Scope`, `Rule`, `Policy`, `ProxyProfile`, `GrantPayload` and `Claims` all reject unknown fields, so an older runtime or server fails closed on anything new.
- **Rule semantics (ADR 0006).** Every live rule whose scope matches counts, and the most restrictive effect wins (`evaluate`, `policy.rs:1048`). An empty dimension doesn't constrain. There is already one exception in that spirit: a `proxy` request whose method or path the policy cannot judge is matched only by `deny` rules (`unjudgeable`, `policy.rs:1063-1066`).
- **Two barriers per call.** For every injected request, the proxy makes a signed `POST /v1/agent/access` with `permission: proxy` and `Claims {domain, method, path}` (`crates/klav-sdk/src/proxy.rs:1-12`; `crates/klav-proto/src/agent.rs` `Claims`). The server evaluates the policy, logs the access with the signed body in the audit log (up to `MAX_PROOF_BODY` = 16 KiB, `crates/klav-proto/src/audit.rs:25`) and applies `ask`, revocation and the pause. The proxy evaluates the same policy again.
- **Approvals.** An `ask` creates an approval keyed by `target_key` = grant version, permission, vault, project, item, domain and, for the proxy, method, path and sandbox (`crates/klav-server/src/routes/agent_access.rs:308-334`). The same key serves "once", leases ("for a while") and tasks (`agent_access.rs:422-447`). The person signs the exact `ApprovalRequest` bytes (spec §13.5), and `ApprovalRequest` carries `claims`.
- **Older devices and a new claim.** `approval_view` parses every `ApprovalRequest` (`crates/klav-client/src/agents.rs:796`), and the list collects into one `Result` (`agents.rs:864`). **One approval with an unknown claim makes an older device fail its whole approvals list,** and its `klav log verify` reports tampering. ADR 0041 §5.6 hit the same wall with `claims.command` and solved it with an account switch; this ADR reuses that pattern (§9).
- **The loopback listener has no caller identity** (ADR [0042](0042-sandboxes-for-daily-use.md) §3): any process on the proxy's host uses every profile, and the audit log only names the proxy. `--no-local-calls` refuses them all. The listener rejects web pages (`Origin`, `Sec-Fetch-Site`, a loopback `Host`: `not_local`, `proxy.rs:827`).
- **The signing sheet's display caps.** `MAX_GRANT_METHODS` = 4, `MAX_GRANT_PATHS` = 3, `MAX_GRANT_PATH_LEN` = 32 (`crates/klav-client/src/proxy_admin.rs:67-71`), and `MAX_ISSUER_PROFILES` = 6 (`agent.rs`): the person's confirmation shows everything it signs. Tool patterns need the same kind of caps.
- **`klav mcp`** is Klav's own stdio MCP server (vault tools), not a gateway. It speaks protocol versions `2024-11-05`, `2025-03-26` and `2025-06-18` (`crates/klav-cli/src/mcp.rs:34-36`). Nothing in this ADR changes it.

### MCP facts this design rests on (read on 2026-11-25 at modelcontextprotocol.io, revision `2025-11-25`)

- **One message per POST.** "The body of the POST request MUST be a single JSON-RPC request, notification, or response." JSON-RPC batching was added in `2025-03-26` and removed in `2025-06-18` (changelog of `2025-06-18`, item 1).
- **Answers.** For a request, the server answers `application/json` (one object) or `text/event-stream`. On that stream it "MAY send JSON-RPC requests and notifications before sending the JSON-RPC response". A client `GET` opens a stream for server-initiated messages, which "MUST NOT" carry responses "unless resuming" (`Last-Event-ID`). `DELETE` with `MCP-Session-Id` ends a session.
- **Priming and polling (SEP-1699, new in `2025-11-25`).** A server "SHOULD immediately send an SSE event consisting of an event ID and an empty `data` field". It "MAY close the connection (without terminating the SSE stream) at any time", sending a `retry` field first, and the client resumes with a `GET` carrying `Last-Event-ID`. So the response to a `POST` can arrive on a later `GET`.
- **Ping goes both ways.** "Either the client or server can initiate a ping." The receiver "MUST respond promptly", and a sender that gets no answer "MAY" terminate the connection.
- **`MCP-Protocol-Version`** is mandatory on every request after `initialize`. Without it, a server "SHOULD assume protocol version 2025-03-26", the revision that still had batches. An unsupported version gets `400`.
- **`MCP-Session-Id`**: visible ASCII; "MCP Servers MUST NOT use sessions for authentication".
- **Tool names** "SHOULD" be 1–128 characters from `A-Z a-z 0-9 _ - .`, "SHOULD" be case-sensitive and "SHOULD" be unique within a server (SEP-986, new in `2025-11-25`). These are SHOULDs, so the proxy has to enforce them itself.
- **`tools/list` is paginated** (`cursor`, `nextCursor`). Servers with `listChanged` send `notifications/tools/list_changed`.
- **Annotations are untrusted:** "clients MUST consider tool annotations to be untrusted unless they come from trusted servers". `readOnlyHint` and `destructiveHint` therefore can't drive policy.
- **Experimental tasks** (`2025-11-25`): a tool call can be made task-augmented and its result fetched later.
- **Server-to-client features:** sampling (now with tool calling), elicitation (including URL-mode elicitation) and roots.
- **Security best practices:** token passthrough is forbidden *for MCP servers that accept client tokens*. The confused-deputy section is about MCP proxies that run their own OAuth. Neither applies to v1 of this design: the gateway accepts no client token for the provider, strips whatever the client sends (§2.4), and runs no OAuth (§4).

## Decision

### 1. What the gateway is, and what "zero-knowledge" means here
> Note of 2026-11-26: "no hosted gateway in this ADR" stands here; [ADR 0051](0051-hosted-nitro-enclave-proxy.md) (accepted that day) runs the gateway's MCP profiles for sandboxes in Klav Cloud's hosted proxy, inside an AWS Nitro Enclave the person's devices verify.

- **It is not a new program.** The MCP gateway is `klav-proxy` with **MCP profiles**: a profile that also knows its upstream's MCP endpoint and lets the proxy read, check and filter the JSON-RPC in it (§5). The same binary serves:
  - sandboxes, through `klav-forward` and the pinned channel (ADR 0036 §5–§6);
  - the person's Mac, on its loopback listener, once the Mac proxy exists (§3).
- **No vendor logic in `klav-proxy`.** The proxy knows one generic thing, "an MCP profile". Presets (`maple`, `github`, `cloudflare`…) are data in `klav-client` that fill the same fields a person could type (§2.3), as the `northflank` preset does today.
- **What stays zero-knowledge, said exactly:**
  - Klav's sync server never sees the provider key or any MCP body. It sees what it already sees for the proxy (item, host, method, path), plus **the tool name and a digest of the arguments** (§5.4). That is new metadata, and residual risk 105 says so.
  - The proxy sees everything in the clear, because it builds the request. It is the person's own (ADR 0036 §1), and ADR 0044 is what protects its memory and key.
  - Klav runs nothing that sees plaintext (Omar's answer 10 in ADR 0036): no hosted gateway in this ADR.

### 2. MCP profiles: any remote server, plus presets
#### 2.1 What a profile gains
`ProxyProfile` gains one optional field, `mcp`, which takes the grant to **`v: 4`** (a superset of `v: 3`; older proxies and servers reject it, fail closed):

```json
{ "name": "maple", "item_id": "…", "header": "authorization", "prefix": "Bearer ",
  "upstream": "https://api.maple.dev",
  "mcp": { "endpoint": "/mcp", "headers": [] } }
```

- **`endpoint`:** the upstream's MCP endpoint path, canonical (`is_canonical_path`), at most 64 bytes. An MCP profile forwards **only** that exact path: `POST` (messages), `GET` (the server's stream) and `DELETE` (end of session). Any other path, including OAuth discovery under `/.well-known/`, gets `403 klav_not_allowed` before the server is asked. The `proxy` rule's `path_prefixes` must contain the endpoint; the client signs it that way.
- **`headers`:** at most 4 fixed, **non-secret** headers the person signs, each name at most 64 bytes and each value at most 128 printable ASCII bytes, never a reserved header or one the profile injects. Some servers choose toolsets or a read-only mode by header. A preset uses this only after a hand test shows the header does what the vendor says.
- **The local URL stays `/<profile><endpoint>`**, as built for Maple (`/maple/mcp`, ADR 0036 §7, decision 4).
- **Custom auth needs nothing new:** `header` and `prefix` already cover `Authorization: Bearer …`, `Authorization: Token …`, `x-api-key: …` and similar.

#### 2.2 The CLI
```
klav proxy grant ITEM --profile NAME --mcp-url https://HOST[:PORT]/PATH \
    [--header NAME] [--prefix TEXT] [--mcp-header NAME:VALUE]… \
    [--tools-allow PATTERN,…] [--tools-ask PATTERN,…] [--tools-deny PATTERN,…]
klav proxy grant ITEM --preset maple [any option above]
```
`--mcp-url` splits into `upstream` and `endpoint`. The three `--tools-*` options build the tool rules of §5.3. The sheet shows every pattern in full before Touch ID or Face ID (caps in §5.3).

#### 2.3 Presets: starting points, each shipped only after a hand test
A preset fills the profile and a first set of tool rules, and the person sees and edits all of it before signing. **This ADR doesn't assert any vendor's endpoint, auth scheme or tool names.** Each row ships in the CLI only after a hand test against the real server confirms those three things, and until then `--preset X` is refused, as `railway` is today.

| Preset | What the hand test must confirm | Starting tool rules (edited at the test) |
|---|---|---|
| `maple` | `api.maple.dev/mcp` (EU: `--upstream`), `Authorization: Bearer maple_ak_…` with a restricted key, and the tool names (M5 of ADR 0036) | allow `get_*`, `list_*`, `search_*`, `find_*`, `inspect_*`, `query_*`, `describe_*`, `explain_*`, `compare_*`; ask `create_*`, `update_*`, `delete_*`, `manage_*`, `transition_*`, `merge_*`; deny none (the key is read-only) |
| `github` | Whether the remote server accepts a fine-grained PAT as a bearer, and its read-only header if any | allow reads; ask writes; deny admin and secret tools |
| `cloudflare` | Which of Cloudflare's MCP servers accept an API token rather than OAuth only | per server |
| `linear` | Whether a personal API key works, or the server is OAuth-only (then not in v1, §4) | — |
| `stripe` | Whether a restricted key works as a bearer | allow reads; ask writes; deny refunds/payouts if listed |
| `northflank` | Whether an MCP server exists at all, or the REST profile of ADR 0036 §7 stays the way | — |

#### 2.4 What the proxy still does on every call (unchanged from ADR 0036 §7)
It strips any `Authorization`, `Cookie` or provider header the caller sends (the placeholder) and puts the real one; doesn't follow redirects; resolves DNS itself and refuses private, loopback and metadata addresses; verifies TLS with the `webpki` roots; asks for `identity` and blocks other encodings; and redacts the whole injected value from the answer. For MCP profiles it also strips `WWW-Authenticate` from **every** answer, local or sandbox (M3 decided this for sandboxes only), so no client starts its own OAuth with the vendor (T265).

### 3. Local agents on the Mac
#### 3.1 Where they connect
> Note of 2026-11-26: with Klav Cloud's hosted proxy ([ADR 0051](0051-hosted-nitro-enclave-proxy.md), Q5 (a)), the Mac keeps its own local proxy for its local agents, known only to that Mac, and the hosted proxy serves sandboxes. Nothing in this section changes.

- **To the Mac's own proxy, on loopback.** The client's MCP entry is plain Streamable HTTP:
  ```json
  { "type": "http", "url": "http://127.0.0.1:8790/maple/mcp",
    "headers": { "Authorization": "Bearer klc1_…" } }
  ```
  `klc1_…` is a **local client token** (§3.2), **never the provider's key**. Nothing in `~/.claude.json`, `.cursor/mcp.json`, `~/.codex/config.toml` or VS Code's `mcp.json` can call the provider without the proxy. **Said plainly:** under Q2 (a) a Klav token does sit in each client's config file. It only works on this Mac's loopback, for the profiles the person signed for that client (§3.2). The exact entry syntax per client isn't verified yet (§14).
- **This needs the Mac proxy as a LaunchAgent** (ADR 0036 §1, roadmap item still open), next to `klavd` and not inside it. It works with the Mac locked, because the proxy is an agent with its own grant and approvals go to the phone (ADR 0036 §1).
- **`klav client connect <client> --mcp <profile>…`** writes or removes these entries with the minimal, reversible editors ADR 0033 §3.6 already uses (`toml_edit`, `jsonc-parser`), and `klav client disconnect` removes them. The Mac app's Development section lists them.
- **A person whose proxy runs on a VPS** can't use it from local agents in v1. A local `klav-forward` with a long-lived package is possible later; it is not designed here.

#### 3.2 Who is calling: local client tokens (Q2)
- **Today the loopback listener can't tell callers apart** (ADR 0042 §3), so the audit log could never say "claude-code called `maple:query_logs`".
- **The proposal:** the person's device generates one random 32-byte token per client. Its text form is versioned from the first byte, like `kag1_` (spec §13.2): `klc1_` + base64url without padding of `0x01 ‖ token(32)`. A token with another version byte or length is refused. It goes in the spec as a new §13.16, with vectors in `docs/vectores/mcp-gateway.json` (§10). The proxy's grant gains `local_clients: [{name, token_digest, profiles}]`, part of `v: 4` and signed by the account:
  - `name` is the person's label (`claude-code`, `cursor`), 1–32 of `a-z 0-9 -`;
  - `token_digest` = `SHA-256(tuple("klav/v1/proxy/local-client", agent_id(16), token))`;
  - `profiles` names the MCP profiles that client may use.
- **On loopback**, a call to an MCP profile must carry `Authorization: Bearer klc1_…`. The proxy compares the digest in constant time, checks the profile is in that client's list, and then strips the header like any other. A call with no token or a wrong one gets `401 klav_local_client_unknown`, with a `next` that says to run `klav client connect`. Mode (a) profiles that aren't MCP keep today's behavior.
- **The client's name goes to the server** in a new `AccessRequest.local_client` field, next to `sandbox` and outside `claims`. The server accepts it only if the proxy's grant has that name. Like `sandbox`, it is appended to `target_key`, so one client's approval, pending or given, never serves another client or the proxy's other callers (§5.4). The approval card and the Activity views show it "according to the proxy's configuration".
- **What it is and isn't:**
  - It is a capability to use named profiles through `127.0.0.1` of this Mac. It decrypts nothing, signs nothing, and Klav's server never sees it.
  - Any process of the same user can read it from the client's config file. That process could already reach the open loopback port today, so the token adds attribution and per-client profiles, not a wall (T263, residual risk 104).
  - Revoking a client means re-signing the grant without it (Touch ID), and it takes effect at the proxy's next grant refresh (30 s, `GRANT_REFRESH`, `proxy.rs:71`).

### 4. OAuth-only servers versus API keys, honestly
- **v1 works only with servers that accept a static credential in a header:** an API key, a personal access token or a restricted key. That is what a profile can carry today.
- **OAuth-only servers fail in v1, by design.** The endpoint-only path refuses discovery, and `WWW-Authenticate` is stripped, so the client never runs an OAuth flow with the vendor. That flow would hand the client a credential that works without the proxy (T265). The proxy turns an upstream `401` on an MCP profile into a JSON-RPC error that says: "this server needs OAuth sign-in, which Klav doesn't support yet; use an API key if the vendor offers one".
- **What a later design has to solve** (its own ADR, Q5):
  1. **Who signs in.** The browser consent runs on the person's device, never on a proxy host with no screen.
  2. **Where the refresh token lives.** As a vault item, granted to the proxy like any credential.
  3. **Rotation.** Most servers rotate refresh tokens on every use. The proxy has no permission to write an item back (its grant denies the permissions that hand values out, and it has no `update`), and ADR 0044 wants nothing stored in the clear on its disk. So either the proxy gains a narrow write-back permission (new permission, new review), or the person's device refreshes and wraps short-lived access tokens for the proxy, which needs a device online every hour, like ADR 0036 §17's child tokens.
  4. **Client registration.** Dynamic client registration per proxy, or a Client ID Metadata Document hosted at `klav.dev` (recommended by the `2025-11-25` revision). The second makes Klav a named OAuth client of each vendor and brings in the spec's confused-deputy rules.
  5. **Two proxies or two sandboxes refreshing at once** race on a rotated token.

### 5. JSON-RPC governance inside `klav-proxy`
#### 5.1 The request path of an MCP profile, in order, before the server is asked
1. **Caller and profile,** as today (sandbox profiles; local client token, §3.2).
2. **Method and path:** `POST`, `GET` or `DELETE`, on the exact `endpoint`.
3. **Headers.**
   - `POST` needs `Content-Type: application/json` and no `Content-Encoding`.
   - Every request except `initialize` needs `MCP-Protocol-Version` with one of the versions the proxy speaks: **`2025-06-18` and `2025-11-25`**. Older ones are refused, because `2025-03-26` has batches and `2024-11-05` is the old transport.
   - A `GET` with `Last-Event-ID` (a resumed stream) passes through. What comes back on it is filtered as in §5.2, so it can't replay an unfiltered answer (T264).
4. **The body of a `POST`:** at most 1 MiB, UTF-8 without a BOM, exactly one JSON value with nothing after it, nesting depth at most 64. A strict parser in `klav-proxy` (a `serde` visitor, no new crate) rejects:
   - **duplicate keys at any depth**, which close the "the proxy reads the first `name`, the upstream reads the last" gap (T255);
   - invalid escapes and lone surrogates.

   Strings are compared after JSON unescaping, so `"tools/call"` *is* `tools/call` and gets governed as one.
5. **The shape.**
   - An array (a batch) is refused (T254).
   - The object must have `jsonrpc` exactly `"2.0"`, a string `method`, and `params` that is an object or absent.
   - `id`, when present, is a string or an integer that fits in an `i64`. `null` and fractions are refused.
   - Top-level members other than `jsonrpc`, `id`, `method` and `params` are refused.
   - A JSON-RPC **response** from the client passes only when it answers a server `ping` the proxy let through to this caller (same `id`, `result` exactly `{}`). Every other client response is refused in v1 (§5.2, §5.5).
6. **The method,** compared byte for byte after unescaping:

   | Method | v1 |
   |---|---|
   | `initialize`, `notifications/initialized`, `notifications/cancelled` | forwarded; policy without a tool (§5.3) |
   | `ping` from the client | **answered by the proxy itself** (`{}`), with no credential, no server call and no audit entry, so a client's keep-alive doesn't fill the log |
   | `tools/list` | forwarded; the answer is filtered (§5.2) |
   | `tools/call` | must have an `id` (a `tools/call` notification is refused: an upstream might still run it); `params.name` must match the tool-name grammar `[A-Za-z0-9_.-]{1,128}`; `params.arguments` an object or absent; other members of `params` only `_meta` (so a task-augmented call is refused in v1); then the tool policy (§5.3) |
   | everything else (`resources/*`, `prompts/*`, `completion/complete`, `logging/setLevel`, `tasks/*`, unknown) | refused in v1 with a JSON-RPC error `-32601` made by the proxy, never sent upstream (Q4) |

   A refusal made by the proxy is an HTTP `200` carrying a JSON-RPC error with the request's `id` and a `Klav-Error` header. That way MCP clients show the message to the model instead of tearing the session down. Malformed bodies get HTTP `400` with a JSON-RPC error whose `id` is `null`.
7. **The server is asked**, once per forwarded message, as today: `POST /v1/agent/access` with `permission: proxy` and claims `{domain, method, path}`. For `tools/call` the claims add `mcp_tool` (the name) and `mcp_args` (§5.4).
8. **The bytes forwarded are the bytes received.** The proxy never re-serializes a request, so number precision, key order and escapes reach the upstream exactly as the client wrote them, and what the proxy judged is what the upstream parses (modulo the duplicate keys it already refused).

#### 5.2 Filtering `tools/list`, in JSON and in SSE
- **Where it sits.** Upstream bytes go through the `Redactor` first (whole values, as today), then the SSE framing (M2's line emission), then the JSON-RPC inspection. The filter only removes, so it can't undo a redaction.
- **How.** For the answer to a `tools/list` the proxy sent on this connection (same `id`):
  - it reads `result.tools` as a list of raw elements (`serde_json`'s `raw_value` feature, which adds no crate);
  - it reads each element's `name` with the strict parser;
  - it evaluates the policy locally with `mcp_tool = name` (§5.3);
  - it re-emits **the kept elements byte for byte**, with the rest of `result` (`nextCursor` included) untouched.
- **What is removed:**
  - tools the policy denies;
  - tools whose name fails the grammar.

  A list with a duplicate name is refused whole, with a JSON-RPC error: an upstream that breaks the uniqueness rule isn't guessed at. Tools that are `ask` stay visible; their description isn't modified.
- **Pages** are filtered one by one. An answer whose `id` doesn't match a pending `tools/list` of this connection is never treated as a list.
- **Size:** a `tools/list` answer, or one SSE event, larger than 4 MiB cuts the response with an error. That is the same "cut, never a clean end" rule as M3.
- **Pending requests.** For each caller's session, the proxy keeps in memory a table of the requests it forwarded and that haven't been answered: `id → method`. Every response, wherever it arrives (the `POST`'s own answer, its SSE stream or a resumed `GET` stream), must match an entry of the same caller's session. It is filtered by that entry's method (a `tools/list` answer always goes through the filter) and removes the entry. A response with no entry, or a second one for the same `id`, is dropped. Entries end with the session or after 15 minutes, the longest a stream lives (M3).
- **On SSE streams** (the `POST` answer and the `GET` stream):
  - events with no `data` or an empty `data` (the priming event), comments and events that only carry `id` or `retry` pass unchanged, so polling and resumption work (SEP-1699);
  - any other event's `data` must be one JSON-RPC message, and an event that isn't cuts the stream;
  - a response passes only through the pending-requests table above;
  - `notifications/tools/list_changed`, `notifications/progress`, `notifications/message` and `notifications/cancelled` pass. The client re-lists through the filter;
  - a server `ping` passes to the client, and the proxy remembers its `id` so the client's `{}` answer can go back (§5.1, step 5). That answer is a forwarded message like any other: one `agent.access` with no tool, folded in the views;
  - **other server-to-client requests** (`sampling/createMessage`, `elicitation/create`, `roots/list`, anything else) are **dropped** in v1, and since the client never saw them, a client response to them is refused. An upstream that waits for an answer times out on its side (T262);
  - other notifications are dropped.
- **Sessions.** The proxy remembers each `MCP-Session-Id` it saw in an `initialize` answer together with its caller (sandbox or local client), in memory only. A request carrying a session ID bound to another caller is refused (T266).
- **Rug-pull detection (v1, local).** The proxy keeps in memory a SHA-256 of each kept tool's raw element. When a later list changes the definition behind the same name, it writes one log line with the profile and tool name (never the definition). Showing it to the person (in the heartbeat, spec §13.12, or the audit log) and signed pinning of definitions are later work (§12).

#### 5.3 Signed per-tool rules
- **`Scope` gains `mcp_tools: Vec<ToolPattern>`,** valid only in `proxy` rules whose items include an MCP profile's item (`check_proxy` refuses it elsewhere). A `ToolPattern` is:
  - an exact name in the tool grammar (`query_logs`);
  - a prefix with one trailing `*` (`get_*`);
  - `*` alone, any tool, which the sheet marks in red when it allows.

  Matching is case-sensitive, as the spec recommends.
- **`policy::Request` gains `mcp_tool: Option<String>`.** It is set for `tools/call`, and for each tool the proxy checks while filtering `tools/list`.
- **The one semantic addition (Q3, recommended (a)):** a request with `mcp_tool` is matched by a rule without `mcp_tools` **only if that rule denies**. This is the same mechanism as `unjudgeable` (`policy.rs:1063-1066`). So:
  - the rule that lets `initialize`, `notifications/*` and `tools/list` through (hosts, methods, endpoint, no tools) **never allows a tool call by itself**;
  - **a tool no rule names is denied**, and the `tools/list` filter hides it;
  - otherwise ADR 0006 is unchanged: every matching rule counts and the most restrictive wins. `allow get_*` plus `deny get_api_key` gives `deny` for `get_api_key`.
- **An example grant for Maple** (four `proxy` rules on the same item, host `api.maple.dev` and endpoint `/mcp`):
  - allow, methods `POST`, `GET`, `DELETE`, no tools: the session itself;
  - allow, tools `get_*`, `list_*`, `query_*`, `search_*`, `find_*`, `inspect_*`;
  - ask, tools `create_*`, `update_*`, `delete_*`, `manage_*`;
  - deny, tools `create_api_key`, `update_role` (exact names: patterns only end in `*`, so a suffix like "any `…_api_key`" can't be written).
- **Display caps** (in `klav-client`, like `MAX_GRANT_METHODS`): at most 24 patterns per rule, 48 per profile, 64 bytes per pattern, and 4 tool rules per profile. The sheet shows every pattern, grouped by allow, ask and deny.
- **What names can't express (an honest limit):** a tool whose action is an argument can't be split by its name. Maple's `manage_*` tools take the action (create, update, delete) inside `arguments`. Such a tool is either all `ask` or all `allow`. Rules on arguments are out of v1 (§12). The key's own scope stays the hard limit, and the person should still use a restricted key.

#### 5.4 Approvals for `ask`
- **The claim.** `Claims` gains `mcp_tool` (the name) and `mcp_args` (a 32-byte digest, base64url without padding):

  ```
  mcp_args = SHA-256(tuple("klav/v1/proxy/mcp-args", agent_id(16), item_id(16), lp(tool), raw_arguments))
  ```

  `raw_arguments` are the exact bytes of `params.arguments` as received (empty when absent). Both claims sit in the body the proxy signs, so they reach the audit log with `agent.access`. The server never sees the arguments, only their digest.
- **Keys.** `target_key` appends `mcp_tool` and `mcp_args` when present, after method, path and sandbox, so keys without them stay what they were (`agent_access.rs:308`).
  - **"Once"** matches the full key: the same tool with **the same arguments**. A retry with other arguments needs a new approval (T261).
  - **"For a while"** (a lease) matches a second key without `mcp_args`: the same tool with **any arguments**. The card says so before the person picks it.
  - The approval stores both keys. `reuse_approved` uses the lease key only for leases.
  - Both keys keep the sandbox and gain `local_client`, after the tool claims, so an approval never crosses callers (§3.2).
  - **A limit of binding raw bytes:** a client or model that retries with the same arguments written differently (another key order, other spacing) produces another digest. The retry needs a new approval rather than spending the first one. That fails closed, but it can annoy; the hand tests measure how often it happens.
- **The caller under the person's signature.** Today `ApprovalRequest` (`crates/klav-proto/src/agent.rs:1141`) carries neither the sandbox nor anything about the caller: the sandbox is only in `target_key`. With the `mcp_gateway` switch on (§9), `ApprovalRequest` gains an optional `caller` (`{sandbox_id}` or `{local_client}`), so the person signs which caller they approved. It is omitted for every other approval, whose bytes stay what they are.
- **The card** (Mac, iPhone, `klav approval`) shows:
  - the caller: the sandbox label, or the local client, "according to the proxy";
  - the profile, which the person signed;
  - the **tool name**, which the grammar limits to `[A-Za-z0-9_.-]`, so it can't carry line breaks, *bidi* characters, quotes or spaces (T140), "according to the MCP server";
  - "arguments: not shown (digest …)" until the sealed arguments layer.
- **The Touch ID / Face ID prompt** (T140) only ever says: fixed text + profile name + tool name. Never arguments, never a description.
- **Who enforces the grammar, three times over.** The proxy checks it before asking. The server refuses an access whose `mcp_tool` or `local_client` breaks its grammar (`400`), so no such approval is ever stored. The person's device checks both again in `approval_view`, before it builds any prompt. On a violation it shows a `security` card with nothing to approve and signs nothing, as ADR 0041 §5.4 does for a mismatched command.
- **Sealed arguments (later layer, Q6).** The arguments travel to the person's devices sealed with HPKE to the account's identity, exactly the way the `inject` card travels (ADR 0041 §5.2–§5.4):
  - **the blob:** new kind **`0x27` `mcp-call`** (`0x26` is claimed by ADR 0047's origin report; both are free in code today, so re-check at that layer), with plaintext `lp(profile) ‖ lp(tool) ‖ raw_arguments`, at most 8 KiB;
  - **the binding:** `info` binds the account, agent and item, and the device recomputes `mcp_args` and shows a `security` card on mismatch;
  - **the path:** uploaded with the signed `PUT /v1/agent/approvals/{id}/…` route of ADR 0041 §5.3, and hidden until the blob arrives.
  - **Rendering:** the card shows the arguments as escaped, monospaced JSON, with control and *bidi* characters made visible, "according to the agent".
  - **Larger than 8 KiB:** the card says "arguments: N KiB, too large to show" and offers only "once".

  This layer depends on ADR 0041 §5.3's machinery, which is accepted and not built.
- **While waiting**, the proxy holds the request for up to 2 minutes, as today (ADR 0036 §9), so the approved call is the held one. After that, the client gets a JSON-RPC error with `approval_id`, and a retry with the same arguments spends the decision (ADR 0015 §2).
- **How the agent waits.** In a sandbox, as today: `klav-forward approval wait ID` (ADR 0036 §10). A local MCP client has no Klav identity and no `klav-forward`, so the error's text is the whole instruction: "The person has to approve `maple · deploy_worker` on their Mac or iPhone. Tell them, wait for them to say it's done, then call the same tool again with the same arguments. Don't call it in a loop." The skill says the same.

#### 5.5 What is refused or dropped, in one place
Batches, duplicate keys, trailing data, non-object messages, client responses other than the answer to a server `ping`, `tools/call` notifications, task-augmented calls, methods outside §5.1's table, unknown protocol versions, any path but the endpoint, server-to-client requests other than `ping`, responses with no pending request, `tools/list` answers with duplicate names, and `WWW-Authenticate`.

### 6. Audit: who called which tool
- **Every forwarded message is an `agent.access` by the proxy** (as today), and for `tools/call` its signed body carries `mcp_tool` and `mcp_args`. No new audit action, so `klav log verify`'s closed table only learns the two claims (§9).
- **What people see:**
  - `klav log`: `claude-code → maple:query_logs (via proxy, according to the proxy)`;
  - Mac and iOS Activity: "claude-code called **maple · query_logs**" in place of "POST /mcp", with the T136 treatment (plain text, one line, marked).
  - A sandbox shows its label where a local client shows its name. `initialize` and `tools/list` show as "connected to maple" and "listed maple's tools", folded in the views.
- **Never logged:** bodies, arguments, descriptions, results and headers. Only the arguments' digest.

### 7. One endpoint per server, not an aggregator (Q1)

| | (a) One URL per upstream (`/maple/mcp`, `/cloudflare/mcp`) | (b) One `/mcp` that merges every granted upstream (`maple__query_logs`) |
|---|---|---|
| Context the model loads | The same tools, minus the denied ones | The same; the prefix makes every name longer |
| Schema caching | The client caches per server, as it already does | The proxy must merge pages from N upstreams under one cursor of its own |
| `list_changed` | Passes through per server | The proxy must multiplex N `GET` streams into one |
| Sessions and `initialize` | Pass-through: one upstream session per client session | The proxy becomes a real MCP server: it terminates sessions, merges capabilities, instructions and protocol versions, and rewrites IDs |
| Names | The vendor's, unchanged; skills and docs still match | Renamed; collisions with `__` inside names; the 128-character limit |
| Failure | One upstream down affects one entry | One upstream down breaks or degrades `initialize` for all |
| Client setup | N entries, which `klav client connect` writes in one command | One entry |
| Code in the proxy | A filtering pass-through | A stateful MCP server and client, many times larger |

**Recommendation: (a), with no aggregator planned.** The only thing (b) wins is one config entry, and `klav client connect` already makes N entries one command. Revisit only if a client caps how many servers it accepts. Filtering denied tools gives the context savings, not merging, and some clients already defer tool loading.

### 8. Local stdio MCP servers stay separate
- **`klav agent run --exec -- server`** (ADR 0036 §15) stays the way to start a **local stdio** server that needs a token. The value goes into that process (residual risk 31), its output isn't redacted, and Klav sees no tools: there is no governance per tool.
- **The gateway is for remote Streamable HTTP servers.** Where a vendor offers both, the remote one through the gateway is the safer choice: the key never enters a process on the Mac.
- **The proxy never spawns stdio servers.** That would turn it into a code-running service, the "stdio transport in proxy scenarios" risk of the spec's best practices. Per-tool rules for stdio servers would need a stdio shim; that's out of scope here.

### 9. Safe with older clients, proxies and servers
The server deploys when merged (`main` deploys production), so every layer that touches `klav-server` gets a "safe with older clients" review before merge.

- **A `v: 4` grant** (`mcp`, `mcp_tools`, `local_clients`) is refused by older proxies and servers (`deny_unknown_fields`). A person's client signs `v: 4` only for MCP profiles, and the sheet asks for `--every-device-is-updated`, as ADR 0036 did for `v: 2` and `v: 3`.
- **The new claims and `ApprovalRequest.caller`** break an older device's approvals list and its `klav log verify` (Context). So the gateway's claims sit behind an **account switch, `mcp_gateway`**, exactly as ADR 0041 §5.6 does for `claims.command`:
  - **while it is off:**
    - the server refuses `claims.mcp_tool` and `claims.mcp_args` with `400 mcp_gateway_off`;
    - every existing answer stays byte-identical;
    - the proxy serves MCP profiles in "no tool claims" mode, where `tools/call` is refused with a JSON-RPC error saying the gateway isn't on for the account;
  - **turning it on** is one person-only request, after the sheet's "update every device first" confirmation;
  - **`/v1/agent/me`** advertises it with `mcp_gateway: true`, omitted while off.
- **`AccessRequest.local_client`** is a new optional field. An older server rejects the request (`deny_unknown_fields`), so the proxy sends it only when `/v1/agent/me` advertises `mcp_gateway`.

| Server | Proxy | Devices | What happens |
|---|---|---|---|
| older | new | any | No `mcp_gateway`; the proxy keeps mode (c) as built, tool-blind |
| new, switch off | new | any | As today; `tools/call` on an MCP profile refused with a clear error |
| new, switch on | older | new | The older proxy can't read a `v: 4` grant and fails closed; the person updates it |
| new, switch on | new | an older one left | That device fails its approvals list and reports tampering, which the sheet warned about |
| new, switch on | new | new | The gateway |

### 10. Dependencies
- **No new cryptographic dependency.** SHA-256 (`sha2`) for the local client digest and `mcp_args`, and HPKE (`hpke`, through `klav-core`'s `hpke_seal`) for the sealed arguments. Both already exist. The labels are new (`klav/v1/proxy/local-client`, `klav/v1/proxy/mcp-args`, plus `klav/v1/proxy/mcp-call-seal` for `0x27`). As always, only `klav-core` computes them.
- **Versioned formats and vectors.** `klc1_` (version byte `0x01`, spec §13.16), the local client digest, `mcp_args`, tool-pattern matching and, at its layer, blob `0x27` (spec §3 and §13.15), all with vectors in `docs/vectores/mcp-gateway.json`.
- **No new crate.** `serde_json` gains its `raw_value` feature in `klav-proxy` (no crate added). The strict parser and the SSE reader are code in `klav-proxy`, the latter on top of M2's line emission.

### 11. Threats (proposed IDs; re-check at layer 1, `main` moves)
ADR 0048 took T242–T253 and residual risks 98–100. This ADR proposes T254–T266 and 101–105, as a new §5.26 of the threat model.

| ID | Threat | Mitigation |
|---|---|---|
| T254 | JSON-RPC smuggling: a batch, a `tools/call` sent as a notification, an unknown or differently cased method, a client "response" to an unseen request | One object per `POST`; methods compared byte for byte after unescaping; `tools/call` needs an `id`; client responses and unknown methods refused by the proxy; `MCP-Protocol-Version` limited to revisions without batches (§5.1) |
| T255 | Parser differential between the proxy and the upstream: duplicate keys, escapes, BOM, trailing data, numbers | Strict parser (duplicates, BOM, trailing bytes and lone surrogates refused, depth 64); comparisons after unescaping; the exact received bytes forwarded, never re-serialized (§5.1, steps 4 and 8) |
| T256 | `tools/list` rug-pull or tool poisoning: the upstream adds tools or changes what a name does after the person signed | Unlisted tools denied and hidden (Q3); kept tools filtered on every page and after `list_changed`; definition changes logged (§5.2). A changed meaning behind an allowed name remains (risk 101) |
| T257 | Tool-name games: `get_and_delete_all` matched by `get_*`, `DeleteService` against `delete_*`, names outside the grammar | Patterns are case-sensitive and names outside the grammar are removed; with unlisted tools denied, a name no pattern foresaw fails closed; vendor-chosen names under an allowed prefix remain (risk 101); the key's scope is the hard limit |
| T258 | Prompt injection in tool descriptions or results | Not mitigated by the proxy, which doesn't rewrite content. Denied tools never reach the model; writes go through `ask`; read-only keys (risk 102) |
| T259 | Exfiltration through allowed tool arguments (a secret in a dashboard title, a comment, feedback) | Presets put outbound-text tools (`send_*`, `comment_*`, `create_*`) on `ask`; the audit log carries tool and argument digest; rate limits. What an allowed tool accepts remains (risk 103) |
| T260 | Untrusted strings in the approval UI (T140): tool names, client names, arguments, descriptions | The grammars (`[A-Za-z0-9_.-]` for tools, `a-z 0-9 -` for clients), checked by the proxy, refused by the server (`400`) and checked again by the device before any prompt, with a `security` card on failure; the system prompt carries only fixed text, profile and tool; arguments only in the sealed card, escaped, "according to the agent"; descriptions never shown |
| T261 | An approval spent on other arguments | "Once" binds the argument digest; a lease binds only the tool, and the card says so (§5.4) |
| T262 | Server-to-client requests (sampling, elicitation including URL mode, roots) used to reach the model or the person | Dropped in v1, except `ping`; client responses refused except the `{}` answer to a server `ping` the proxy passed (§5.2) |
| T263 | A same-user process reads `klc1_` from a client's config and calls as that client | Same reach as today's open loopback; the token only names the caller and limits profiles; web pages still refused (`not_local`); revocable by re-signing (risk 104) |
| T264 | A resumed SSE stream replays an unfiltered `tools/list` or another request's response | Every response must match a pending request of the same caller's session, is filtered by that request's method wherever it arrives, and is accepted once (§5.2) |
| T265 | The client starts its own OAuth with the vendor and gets a credential that bypasses the proxy | Endpoint-only path; `WWW-Authenticate` stripped on every MCP answer; OAuth out of v1 (§4) |
| T266 | One caller uses another caller's `MCP-Session-Id` on a shared profile | Session IDs bound in memory to their caller; a mismatch refused; sessions never authenticate, since the credential is the proxy's on every call |

**Residual risks (proposed 101–105, all "pending implementation"):**

101. **An allowed tool name can change meaning** (T256, T257). The vendor controls names and behavior. Klav limits by name, logs every call and asks for what the person marked; the key's scope is the hard limit.
102. **Prompt injection through tool descriptions and results** (T258). The gateway doesn't inspect or rewrite content, and no filter here makes a model safe against it.
103. **Exfiltration through what an allowed tool accepts** (T259). The list limits which tools, not what goes into them. Rules on arguments are later work.
104. **Local client tokens are readable by the person's own processes** (T263). They name callers and limit profiles; they don't isolate one process from another on the same account.
105. **The Klav server learns tool names and argument digests** for every MCP call (§1). It needs them to apply `ask` and `deny` and to keep the audit log. It never sees arguments, results or keys.

### 12. Left for later, not designed here
- OAuth-only servers (§4; Q5).
- Rules on arguments, and an "ask if the argument `action` is `delete`" form.
- Signed pinning of tool definitions, so a changed description needs a new signature.
- `resources/*` and `prompts/*` (Q4 (b)).
- A local forwarder for Mac agents to a remote proxy.
- Per-tool rules for local stdio servers.

### 13. What this ADR chose on its own (Omar can overturn each)
1. Grant `v: 4` as a superset, rather than a separate record.
2. Protocol versions `2025-06-18` and `2025-11-25` only.
3. A client `ping` answered by the proxy; a server `ping` passed to the client and its answer forwarded.
4. Proxy-made refusals as HTTP `200` with a JSON-RPC error, malformed bodies as `400`.
5. A list with duplicate tool names refused whole.
6. `ask` tools visible, unmodified, in `tools/list`.
7. Server-to-client requests dropped.
8. The size caps: 1 MiB per request, 4 MiB per list or event, 8 KiB of sealed arguments.
9. The display caps: 24/48 patterns, 4 tool rules.
10. Case-sensitive patterns, with only a trailing `*`.
11. "Once" bound to the argument digest, leases not.
12. Rug-pull detection logged locally only.
13. `WWW-Authenticate` stripped for local MCP callers too.
14. Presets refused until a hand test, as `railway` is.
15. Resumed streams passed and filtered through the pending-requests table, rather than stripping `Last-Event-ID`.
16. `ApprovalRequest.caller`, behind the same switch, so the person signs which caller they approved.

### 14. Not verified (checked at the hand tests, layer 7)
- **Each client's entry syntax and header support:** Claude Code, Codex, Cursor and VS Code. §3.1 shows one JSON shape; each client's exact form comes from its public docs at layer 5 and is tested at layer 7.
- **How each client reacts** to an HTTP `200` carrying a JSON-RPC error, to a `401` from the proxy, and to the approval error's text.
- **Which protocol version each upstream negotiates.** One that only speaks `2025-03-26` is refused under §5.1, so its preset can't ship until it upgrades or this rule changes.
- **Whether each upstream answers with JSON or SSE, primes its streams and closes connections early (SEP-1699),** and whether the pending-requests table handles what it does.
- **The display caps against real lists.** Maple's tool list, as this session's client saw it on 2026-11-25, has about 140 tools with about 45 distinct leading verbs. A full Maple classification fits in 24 patterns per rule and 48 per profile, but only just. The caps are measured at the Maple hand test and raised there if needed.
- **How often retries change the arguments' bytes** (§5.4), which decides whether "once" is usable as bound.
- **The vendor facts in §2.3's table.**

## Rejected alternatives
- **Approval and policy from MCP annotations** (`readOnlyHint`, `destructiveHint`). The spec says they are untrusted.
- **A hosted gateway run by Klav.** Klav runs nothing that sees plaintext (ADR 0036, answer 10).
- **The aggregator (§7).** A stateful MCP server in the proxy for one config entry.
- **Re-serializing requests after inspection.** It would change numbers and escapes, and open a differential between what was judged and what was sent.
- **Putting the provider key in the client config with a local `klav` stdio wrapper.** The key would be in a process again (risk 31).
- **A tool list signed as exact names only.** Vendors add tools every release, and prefixes with unlisted-denied give the same fail-closed result with fewer re-signs.

## Consequences
- **New:**
  - in `klav-core`: `ToolPattern`, `Scope.mcp_tools` and `Request.mcp_tool`;
  - in `klav-proto`: `ProxyProfile.mcp`, grant `v: 4` with `local_clients`, `Claims.mcp_tool`/`mcp_args`, `AccessRequest.local_client` and `ApprovalRequest.caller`;
  - in `klav-server`: the `mcp_gateway` switch and the lease key;
  - in `klav-proxy`: the JSON-RPC and SSE governance and local client tokens;
  - in the CLI: `--mcp-url`, `--tools-*` and `klav client connect --mcp`;
  - the approval card and Activity rows on Mac and iOS.
- **Spec:** §13.4 (grant `v: 4`, `local_clients`), §13.16 (`klc1_`), §2.3 (three labels), §3 (`0x27` at its layer), §13.15 (`mcp-call`), with vectors in `docs/vectores/mcp-gateway.json`.
- **Glossary terms to add at layer 1:** MCP gateway, MCP profile, MCP endpoint, tool rule / tool pattern, unlisted tool, local client / local client token, argument digest, sealed arguments.
- **Docs site:** a page on the MCP gateway under "On the way" until it ships (ADR 0039 §3).
- **What the person gives up:** OAuth-only servers in v1, `resources` and `prompts` in v1, and the convenience of a single aggregated endpoint.

## Plan in layers
Each layer is a PR of a stack, with its tests, its roadmap box and, where it applies, the spec and its vectors.

0. **Prerequisites, not part of this stack:** ADR 0044 layer 1 (the proxy's memory); ADR 0036 mode (c) M2–M5 (stream limits, the `maple` preset, the hand test); and, for local agents only, the Mac proxy as a LaunchAgent.
1. **Docs:** this ADR accepted, threat model §5.26 (T254–T266, risks 101–105, T226 amended), glossary terms, spec §13.4, §13.16 (`klc1_`) and §2.3, roadmap section.
2. **`klav-core` and `klav-proto`:** `ToolPattern`, `Scope.mcp_tools`, `Request.mcp_tool` with the deny-only rule (Q3), `check_proxy`, `ProxyProfile.mcp`, grant `v: 4`, `local_clients`, the two claims and `local_client`; `docs/vectores/mcp-gateway.json` (§10: `klc1_`, pattern matching, evaluation, `mcp_args`).
3. **`klav-server`:**
   - the `mcp_gateway` switch and `400 mcp_gateway_off`;
   - the claims in `target_key`, and the lease key;
   - checking `local_client` against the grant;
   - `klav log verify` and the audit views reading the claims.

   Reviewed as safe with older clients before merge.
4. **`klav-proxy`:**
   - the strict parser, §5.1's request path, `ping`;
   - the `tools/list` filter in JSON and SSE, server-to-client requests dropped;
   - session binding, the pending-requests table (resumed streams included), server `ping`, `WWW-Authenticate`;
   - local client tokens;
   - end-to-end tests against a fake MCP server: batches, duplicates, rug-pull, notifications, an `ask` held and approved.
5. **`klav-client` and `klav-cli`:** `klav proxy grant --mcp-url --tools-*`, the sheet with every pattern, `klav client connect --mcp`, `klav log` rendering, the presets as data (refused until tested), and the setup lines of `klav sandbox start` for any MCP profile, not only `maple` (M4 covers only `maple`).
6. **Mac and iOS:** the approval card with caller, profile and tool; Activity rows; the Development › MCP servers list; turning the switch on.
7. **Hand tests:** Maple from Claude Code on the Mac and from a Boat sandbox, then one preset per PR as each passes. Each test marks its preset's box.
8. **Sealed arguments** (`0x27`), after ADR 0041 §5.3's route, column and hiding exist.

## Omar's answers (2026-11-25)
Omar accepted this ADR on 2026-11-25 and chose the recommended option, **(a)**, in all six questions:

| Question | Answer |
|---|---|
| Q1. One URL per server or an aggregator | (a) One URL per server, written by `klav client connect`; no aggregator planned |
| Q2. Which local agent is calling | (a) One local client token per client (`klc1_`), its digest signed into the proxy's grant |
| Q3. A tool no rule names | (a) Denied and hidden; a rule without `mcp_tools` can only deny a tool call |
| Q4. Resources, prompts, completions | (a) Refused in v1 with a JSON-RPC error |
| Q5. OAuth-only servers | (a) Out of v1; their own ADR after the gateway ships |
| Q6. What an `ask` card shows | (a) Caller, profile and tool, "once" bound to the argument digest; sealed arguments in a later layer |

## Implementation notes (layers 1–3, 2026-11-25)
What layers 1–3 fixed that the text above leaves open. Each can be overturned before the layer that depends on it ships.

1. **`mcp_args` bytes (§5.4).** `lp(tool)` is read as the tuple's own field: `tuple(label, agent_id, item_id, tool, raw_arguments)`, every field length-prefixed once (spec §2.3), not a second prefix inside a field. Its text form has one spelling, and the server refuses any other. Spec §13.16 and `mcp-gateway.json` freeze it.
2. **The approval keys (§5.4).** The gateway's part of `target_key` is one fixed-slot nested array after method, path and sandbox, `["mcp", tool, args, local_client]`, with `""` for an absent slot. It can't be read as the sandbox's string slot, and keys without the gateway's fields stay byte for byte what they were. The lease key is the same with `args` empty. It's stored in a new nullable column, `approvals.lease_key` (migration 0022), used only by leases. A named approve-once decision for other arguments gets `409`.
3. **`caller` (§5.4).** While the switch is on, it is on every approval whose call names a sandbox or a local client, not only tool calls. While it is off, no approval carries it.
4. **The switch (§9).** It is `accounts.mcp_gateway_at`, set by `POST /v1/account/mcp-gateway` in the person's session; `GET` reads it, and an older server answers `404`. Turning it on writes no audit event (§6: no new audit action). The precondition, "update every device first", is the client's sheet (layer 5).
5. **What the server refuses before it evaluates or logs (`400`):**
   - the gateway's fields while the switch is off (`mcp_gateway_off`);
   - the fields on anything but `proxy`, and `mcp_tool` without `mcp_args` or the other way round;
   - a tool or client name outside its grammar, or `mcp_args` that isn't a digest;
   - a sandbox and a local client in one call;
   - a path over 64 bytes with any of the fields, which keeps the keys within the approvals' indexes;
   - a `local_client` the proxy's grant doesn't have for that item's MCP profile.

   None of these is ever logged. `klav log verify` and the approval card check every one but the last, which needs the grant, and treat a logged one as tampering.
6. **No default lets a tool through.** A tool call with no rule for its permission is `deny` (`Reason::OutOfScope`), even for permissions that allow by default. A tool named on any permission but `proxy`, or outside the grammar, is unjudgeable: only `deny` rules apply.
7. **Format details (§2.1, §3.2).**
   - `mcp.headers` are `{name, value}`. Besides the reserved headers of ADR 0036, an MCP header can't be `authorization`, `cookie`, `www-authenticate`, `mcp-session-id`, `mcp-protocol-version`, `last-event-id`, `content-type`, `content-encoding`, `accept`, `accept-encoding` or `origin`.
   - The endpoint must be reached by a non-deny `proxy` rule whose path prefix covers it.
   - At most 16 `local_clients` per grant.
   - Rules with `mcp_tools` name only MCP profiles' items, and at least one.
   - The display caps (§5.3) are constants in `klav-core` (`MAX_TOOL_PATTERNS_PER_RULE` and the rest) that only the signing sheet applies, so the hand tests can raise them without a server release.
8. **The proxy until layer 4.** A `klav-proxy` built from layers 1–3 reads a `v: 4` grant but serves none of its MCP profiles. Served as a plain mode (a) profile, the session rule would let every tool through.
9. **The device's check (§5.4).** `approval_view` keeps a request whose tool or caller breaks its grammar as a `security` card. Its fixed text never repeats the offending field. Nothing on it can be approved or denied, and no "add to the task" either. The approvals list still loads.
10. **Glossary.** The terms are in `docs/glossary.md`. They go into the public glossary when the gateway ships (ADR 0039 §3).

## Implementation notes (layer 4, 2026-11-25)
What layer 4 (`klav-proxy`) fixed that the text above leaves open, or does differently. Each can be overturned.

1. **Where it lives.** `crates/klav-proxy/src/mcp/`: `jsonrpc` (the strict parser and the shapes), `sse` (the event reader) and the request path, tables and filter. A profile with `mcp` goes only through it; one whose endpoint or headers don't parse is left out, never served as a plain profile. The non-MCP path is the same code as before, with the access-and-send half shared (`send_upstream`).
2. **The strict parser.** A `serde` visitor that decodes every key and string into a `String` (`serde_json`'s skipping paths don't check surrogates) and refuses duplicate keys at any depth and nesting past 64. A second pass reads the shape with `RawValue`, so the argument digest and the filter work on the bytes received. `serde_json`'s `raw_value` feature, no new crate.
3. **The shape is strict both ways.** A client message has only `jsonrpc`, `id`, `method` and `params` (a response only `jsonrpc`, `id` and `result`). An upstream message must have only the JSON-RPC members too, or the answer is cut. An `id` is a string or an integer written with digits only (`1.0`, `1e0` and anything past `i64` are refused).
4. **Refusals.** A refused request with an `id` is HTTP `200` with a JSON-RPC error: `-32601` for a method outside the table, `-32602` for `tools/call` params, `-32000` for every other Klav refusal, with `data.klav_error` (the same code as `Klav-Error`), `next`, and `approval_id`, `expires_at` or `retry_after` where they apply. A malformed body, a refused notification (`tools/call` without an `id` included) and a refused client response are `400` with `id` `null`, as the MCP spec asks for input the server can't accept. A refusal made inside an answer (a list with a duplicate name) carries `data.klav_error` only: the upstream's headers have already gone out. New codes: `klav_local_client_unknown` (`401`), `klav_mcp_session_unknown` (`404`), `klav_mcp_refused` (`400`), `klav_mcp_method_refused`, `klav_mcp_gateway_off` and `klav_mcp_tools_refused` (in a JSON-RPC error), all in `api.md` §8.13.
5. **The endpoint only.** A query on the endpoint is refused too, as any other path or method (`403 klav_not_allowed`).
6. **Sessions (T266), stricter than the text.** An `MCP-Session-Id` the proxy did not see this caller open is refused with `404 klav_mcp_session_unknown`, which an MCP client reads as "start a new session". That includes every session after a proxy restart (they live in memory only) and an ID the upstream hands to a second caller (that `initialize` answer is cut). At most 1024 sessions; the least recently used go first.
7. **Pending requests (T264).** Keyed by conversation: profile, caller and session (or none, for a server without sessions). A response on a `POST`'s own answer matches that `POST`'s request first; anywhere else, any request of the conversation with that `id`. Several instances of one client share a name and number alike, so a duplicate pending `id` is not refused: when entries with that `id` disagree on the method, the oldest is taken and the answer is read as a `tools/list` one, which only removes. At most 256 per conversation, each for 15 minutes.
8. **SSE framing.** Lines end at LF or CRLF; any other CR cuts the stream, because a client also ends a line at a lone CR and the two would read different events. Unknown fields are dropped (a client ignores them), events go out with LF line ends, and a dropped event keeps its `id` and `retry`, so `Last-Event-ID` stays exact. An event without its blank line at the end is discarded, as a client does. The 4 MiB cap is per event; each line is also held to M2's 1 MiB (`MAX_STREAM_HOLD`).
9. **Other answers.** A JSON body is held whole (4 MiB) and must be one JSON-RPC message, or the answer is cut; with an error status, a body that isn't one is emptied instead. A body that is neither JSON nor SSE is dropped, its status kept. An upstream `401` becomes the OAuth JSON-RPC error for a request, and `502 klav_upstream_blocked` with the same message for a `GET`, a `DELETE` or a notification. A `tools/list` result that isn't an object with a `tools` array is refused like a duplicate list.
10. **The switch.** The proxy reads `mcp_gateway` from `GET /v1/agent/me` once before serving and at every grant refresh (30 s); `me` is now also asked when the grant has MCP profiles and no issuers. Until the server says on (or with an older server), `tools/call` gets `klav_mcp_gateway_off` and nothing else changes.
11. **Local client tokens.** Exactly one `Authorization` header, scheme `Bearer` in any case. The digest is compared in constant time against every client of the grant (`LocalClientToken::matches`). A known client on a profile it may not use gets `403 klav_not_allowed`, not `401`. `local_client` goes on every forwarded message of a local client while the switch is on (`initialize`, `tools/list` and the answer to a server `ping` too), never with `sandbox`.
12. **Checking the server's "allowed" (`klav-sdk`).** When the proxy's own policy says `ask`, the approval the server names must carry the same `mcp_tool`, the same `mcp_args` unless the account signed a lease (`lease_until` is under its signature), and, when it names a `caller`, this call's caller; a local client's call needs one. The proxy's own memory of pending approvals is keyed by tool, digest and local client as well.
13. **Rug-pull detection.** The digest is `SHA-256(tuple("klav/v1/proxy/tool-definition", raw_element))`, computed in `klav-core` (`crypto::mcp::tool_definition_digest`). It never leaves the proxy, so it has no vectors. At most 8192 definitions; the count of changes since start is kept (only a number) for a later `status`.
14. **The 2-minute hold is not built.** §5.4 says the proxy holds an `ask` for up to 2 minutes "as today" (ADR 0036 §9), but no profile does that today: an `ask` answers `klav_approval_pending` at once and the retry spends the decision. Layer 4 does the same for tool calls. Holding is its own change, for every profile.
15. **The filter reads the rules of its request.** A `tools/list` answer is filtered with the grant the proxy held when the `POST` or `GET` that carries it was sent. On a `GET` stream that lives up to 15 minutes, a list that arrives late can follow rules up to that old, not the 30 s of a grant refresh. Only what the list shows lags: every `tools/call` is judged by both policies when it is made.
16. **Turning the switch on from `klav-client`.** `Unlocked::turn_mcp_gateway_on` is only the request; the sheet that asks the person to update every device first is layer 5's. The end-to-end tests use it.

## Implementation notes (layer 5, 2026-11-25)
What layer 5 (`klav-client`, `klav-cli`, `klavd`) fixed that the text above leaves open, or does differently. Each can be overturned.

1. **The switch is part of the grant, not its own command.** `klav proxy grant --mcp-url` reads `GET /v1/account/mcp-gateway`; while it is off, or while the proxy's grant is older than `v: 4`, the sheet shows the older-devices warning and nothing is signed without `--every-device-is-updated`. After presence, the client turns the switch on and then signs the grant, so a proxy never serves an MCP profile whose tool calls the server would refuse. A server without the route (`404`) is refused before presence. There is no `klav proxy mcp-gateway` command.
2. **The spec.** `ProxyCredentialSpec` gains one optional `mcp` (`endpoint`, `headers`, `tools_allow`, `tools_ask`, `tools_deny`), absent from every other spec, so the bytes `klavd` takes for a plain profile are unchanged. `--mcp-url` defaults to `authorization` and `Bearer `, methods `POST`, `GET`, `DELETE`, and the endpoint as the only path prefix; it refuses `--upstream`, `--path-prefix`, `--ask` and `--ask-method` (tools ask, methods don't). The endpoint is also kept to `A-Z a-z 0-9 / . _ - ~`, so it can go in a shell line and a URL unquoted.
3. **The rules it signs.** The session rule (no tools), then one rule per effect that has patterns, on the same item, host and endpoint, for `POST`. Repeats count once. The caps of §5.3 are checked when the rules are built, before any preview; at most 3 tool rules come out, under the cap of 4.
4. **Re-granting keeps local clients**, as it keeps issuers: a profile replaced under the same name stays on the clients that had it. A change that takes a profile away from a client says so in the sheet (`local_clients_losing`).
5. **Presets.** `GATEWAY_PRESETS` in the CLI lists `maple`, `github`, `cloudflare`, `linear` and `stripe` with what each hand test must confirm. All are refused with `--mcp-url`, and the last four on their own, with a message that gives the explicit flags. `--preset maple` alone is still ADR 0036's MCP gate, byte for byte; layer 7 turns it into a gateway preset.
6. **Local clients, on the wire.** `klav client connect <client> --mcp P,…` makes the `klc1_` token in the CLI process with `klav-core`, sends only its digest (`LocalClientChange::Set { profiles, token_digest }`) to `klavd` or signs directly, and writes the token only into the client's settings. `klavd` gains `LocalClientPreview` and `LocalClientChange` (presence, with the base version and the proxy's ID the preview showed) and a dialog that names the client, the proxy and the profiles. The client's name is the client's ID (`claude-code`, `codex`, `cursor`, `vscode`). Every connect signs a new token; `Set` without a digest keeps the current one, which `disconnect --mcp P` uses to drop one profile.
7. **The entries.** Named after the profile. Claude Code: `claude mcp add-json --scope user NAME -`, the entry on standard input, never on the command line (Claude Code refuses standard input from inside its own sessions, and the error says to run it in a terminal). Codex: `[mcp_servers.NAME]` with `url` and `http_headers`, written with `toml_edit` (checked with `codex mcp list --json`, Codex 0.166.0); its CLI takes a bearer only from an environment variable. Cursor: `url` and `headers`. VS Code: `type: http`, `url` and `headers`. Claude Desktop and Antigravity are refused. An entry counts as Klav's when it points at `http://127.0.0.1:<port>/<profile>/…` and its only header is a `Bearer klc1_…`; another one under the same name needs `--replace` (connect) or `--force` (disconnect). Files get a backup first and an atomic write; only the named members change.
8. **Order.** Connect signs first and writes after: a grant with a token nobody has is harmless, and running it again makes another. Disconnect signs first too, since the grant is what stops the token.
9. **Sandbox setup lines.** The issuer can't read the proxy's grant, so `GET /_klav/sandboxes` now also answers `mcp: [{profile, endpoint}]` for the issuer's profiles, which `klav sandbox start` reads after the start (best effort: a failed list still hands the package out). An older `klav` ignores the field, and an older proxy doesn't send it, in which case `maple` keeps M4's lines by name. The generic lines for `maple` at `/mcp` are M4's, byte for byte.
10. **The views.** `LogLine` gains `sandbox` (from the signed body, under the same grammar check as the tool). `ApprovalView` gains `item_id`, so the CLI can name the profile from the proxy's grant. `klav log` and `klav approval` read the profile from `klav proxy status`, best effort (`MCP` when unknown). The log cannot tell `initialize` from `tools/list` (neither has a claim), so both read as one "MCP session" row, folded per caller. `klav approval show` is new.
11. **The Touch ID dialog** of an MCP grant names the endpoint and up to 12 patterns of each effect, counting the rest; the CLI's sheet showed every one before presence.

## Implementation notes (layer 6, 2026-11-25)
What layer 6 (`klav-ffi`, `klavd`, the Mac and iPhone apps) fixed that the text above leaves open, or does differently. Each can be overturned.

1. **The profile on the card and in Activity.** It comes from `proxy_status`, the proxy's grant as this device verified it, only for rows whose agent is the account's proxy, and only when some approval names a tool or some line is a proxied call. It is best effort: when the status can't be read, the card and the row show the tool alone, never another field in its place.
2. **The security card crosses as a flag.** `ApprovalItem.security` is a `bool`; the apps say their own fixed text in the person's language, and none of the offending fields reaches them (`klav-client` already drops them). `klavd` now refuses a security card in `decide_approval` and `add_to_task` before any Touch ID prompt; before this layer it asked for Touch ID first and `klav-client` refused after.
3. **The prompt (T140).** For a tool call, `klavd`'s Touch ID prompt, the Mac's password sheet and the iPhone's Face ID reason say fixed text, the profile and the tool, and whether it is one call with these exact arguments or the tool with any arguments for a while. Never the agent's name, its reason or the caller.
4. **The caller is named by the sandbox's ID, not its label.** §5.4 says "the sandbox label", but the label only comes from the sandbox list, which verifies the whole audit log. The card and Activity say "sandbox" and the first 8 characters of its ID, as `klav log` does.
5. **Session rows.** A proxied message with no tool claim is a session row when a local client sent it or it went through an MCP profile; a sandbox's session message through a profile this device can't name reads as a plain proxied request. Consecutive session rows of one agent, item, profile, caller, outcome and verification fold into the newest, in `klav-ffi` for both apps, unless the older one raised an alert; `LogEntryInfo.folded` counts the rest. "Who used it" folds the same way when the uses also went through the same way.
6. **The switch has its own operation in `klavd`,** which departs from layer 5's note 1 for the apps only (the CLI still has no command for it): `mcp_gateway` reads it (`null` from an older server) and `mcp_gateway_on` turns it on. `klavd` refuses `mcp_gateway_on` without `every_device_updated` and on an older server before presence, asks for Touch ID (or the master password) otherwise, and answers at once when it is already on. The Mac's sheet asks for the person's word with a checkbox before it sends it.
7. **Development › MCP servers is Mac only** (`DaemonEngine::mcp_servers`); `KlavCore` doesn't expose it. The local URL it shows uses `klav-proxy`'s default port (8790), because the apps don't know the port the proxy was started with.
8. **Left over from layer 5, fixed here:** `docs/klavd.md` now lists `local_client_preview` and `local_client_change` (the idle-lock test failed without them), and `proxy_grant`'s prompt builder in `klavd` allows clippy's `too_many_arguments`.

## Implementation notes (ADR 0036 layer 11, 2026-11-25)
1. **The proxy can run on the Mac.** ADR 0036 layer 11 adds the `dev.klav.proxy` LaunchAgent, which runs the bundle's `klav` as `klav-proxy serve --if-registered`: the loopback listener (8790 by default) that local MCP clients call, and the proxy's local socket. Development › MCP servers shows the proxy on this Mac at the top, with Start or Stop, because local clients reach the servers only through it.
2. **The app learns the real port.** The local socket's `sandboxes` answer carries the listener's port and the proxy's MCP profiles ([api.md](../api.md) §8.14). When the account's proxy runs on this Mac on another port and serves the profile, the local URL and Copy use that port. This supersedes layer 6 note 7 for a running proxy; with no proxy running here, the URL still says 8790.

## Open questions for Omar (answered above)
**Q1. One URL per MCP server, or one aggregated endpoint?**
- **(a) One URL per server** (`/maple/mcp`, `/cloudflare/mcp`), written by `klav client connect` in one command; no aggregator planned (Recommended).
- (b) One `/mcp` that merges and namespaces every granted server.
- (c) Both: per server now, the aggregator as a later layer.

**Q2. How does the gateway know which local agent is calling?**
- **(a) One local client token per client** (`klc1_`), its digest signed into the proxy's grant with the profiles it may use, sent as the MCP entry's bearer. Attribution and per-client profiles, no wall between same-user processes (Recommended).
- (b) A `klav mcp bridge <profile>` stdio command in each client's config, with no token on disk. The caller's name is still self-reported, and it adds one process per server per client.
- (c) No identity: the open loopback as today, with Activity saying only "a program on this Mac".

**Q3. What happens to a tool no rule names?**
- **(a) Denied and hidden from `tools/list`.** A rule without `mcp_tools` can only deny a tool call (a narrow amendment to ADR 0006, like the existing `unjudgeable` case). New vendor tools stay invisible until the person adds them (Recommended).
- (b) `ask`: visible, and every call needs an approval.
- (c) Allowed, like any request the session rule matches. Fails open when a vendor adds a destructive tool.

**Q4. MCP beyond tools (`resources/read`, `prompts/get`, completions) in v1?**
- **(a) Refused in v1 with a clear JSON-RPC error.** Tools only; add later with their own rules (Recommended).
- (b) One signed per-profile switch, "allow resources and prompts", with no per-item rules.
- (c) Passed through ungoverned.

**Q5. OAuth-only MCP servers?**
- **(a) Out of v1. API key, PAT and restricted-key servers only; OAuth gets its own ADR after the gateway ships,** answering §4's five problems (Recommended).
- (b) In v1, with the person's device doing the OAuth and refresh and wrapping short-lived access tokens for the proxy. Needs a device online every hour.
- (c) In v1, with the proxy holding the refresh token and a new narrow write-back permission (conflicts with ADR 0044's "nothing stored in the clear").

**Q6. How much does an `ask` card show, and when?**
- **(a) First release: caller, profile and tool name, with "once" bound to a digest of the arguments. A later layer adds the HPKE-sealed arguments view (`0x27`)** once ADR 0041 §5.3's machinery exists (Recommended).
- (b) Hold `ask` for tools until the sealed arguments view exists, and ship allow/deny first.
- (c) Tool name only, with no argument digest, so "once" covers any arguments.
