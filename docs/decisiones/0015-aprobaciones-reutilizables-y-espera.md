# 0015 · Approvals that serve the retry, explicit `approval_id` and agent waiting

- Status: accepted
- Date: 2026-11-02

## Context
In the milestone A test with Claude Code ([probar-hito-a.md](../probar-hito-a.md) §10, test 5) the `ask` flow failed like this:

1. The agent called `get_totp` (policy `ask`). The tool waited, nobody approved in time and it returned the pending request `b397e30b…`.
2. Omar approved it with `klav approval approve b397e30b…`.
3. The agent called `get_totp` again, without the ID. The server created **another** request (`2e5a6fc0…`), the call waited again and failed.

With ADR [0014](0014-agentes-fase-4.md) §5 every request without `approval_id` creates a new request, and the MCP tools don't accept `approval_id`. An approval given after the original call returned is useless. On top of that, the agent has no way to find out that the person approved: Omar had to type "I approved it" to it.

This ADR completes §5 of 0014 (and its §8.3); the rest stays the same.

## Decision

### 1. Same target
Two requests have the **same target** if these match:

- the agent and its grant version;
- the permission;
- the vault, the project and the item (or no item, for `create`);
- the domain declared in `claims.domain` (for `fill`, the real host of the tab the SDK read; empty otherwise).

The server stores it as a `target_key` column (migration `0008`), computed by a single function used by creation, lookups and the check of an `approval_id`. The reason and the tags are not part of the target: the person approves "this agent, this action, this item (and this site)". Requests from before the migration have no `target_key` and are never reused.

Counting the domain is stricter than 0014, where a lease covered the item on any domain: now a `fill` lease for `github.com` doesn't work for another host.

### 2. What the server does with `ask`
If the request carries `approval_id`, that approval is used (§3). If not, in this order:

1. **Active lease** with the same target: it goes through.
2. **Unspent single-use approval** with the same target, decided less than 10 minutes ago: it is spent on this request and it goes through. Spending is `UPDATE … SET used_at = now WHERE id = $1 AND used_at IS NULL`; if two requests race, only one changes the row and the other moves on to the next step.
3. **Pending request** (not expired) with the same target: **that one** is returned (`202` with the same `pending_approval_id` and its `expires_at`). No new one is created. This comes before the limit of 10 pending requests per agent, so a retry never gets `429`.
4. If there is nothing, a new request is created.

**Races.** A partial unique index `(agent_id, target_key) WHERE status = 'pending'` prevents two pending requests with the same target. Since a pending request expires lazily (the row stays in `pending` after `expires_at`), the agent's expired pending requests are marked `expired` before inserting. If the insert hits the index, the server reads back the pending request that won and returns its ID.

**Use window.** A single-use approval can be spent during the 10 minutes after the decision, with or without `approval_id`. Before, it didn't expire; now a forgotten approval doesn't stay open forever.

**What doesn't change:**
- a single-use approval is spent exactly once;
- a lease ("approve for 15 min") lets the action repeat until it expires, for at most 24 hours;
- an approval is only valid with the grant version it was requested under;
- `update_item` is still two requests (`access` with `update` and the write): a single-use approval covers the first; to cover both, `--for`.

**Accepted risk.** Without `approval_id`, the request that spends the approval can carry a different reason from the one that asked for it (the LLM rephrases). It is the same agent, the same action and the same item, within 10 minutes; the audit log stores the reason of each request next to the ID of the approval it used.

### 3. Explicit `approval_id`
Every MCP tool that can end up pending accepts an optional `approval_id`, and so do the Rust SDK (`Session::claim_approval`), the `klav agent …` commands (`--approval ID`) and `@klav/sdk` (`approvalId`).

- The runtime reads the approval (`GET /v1/agent/approvals/{id}`) and checks **before acting** that the permission, the item and, if applicable, the domain are those of the action. If not, it fails without doing anything ("approval_id is for another action or item").
- `get_totp` with `target` uses `fill` (the code is typed into the page); a `totp` approval doesn't work for that.
- In `run_with_secrets` and `inject_file` with a template, the permission has to be `inject` and the item one of those the action uses.
- Only the matching request carries the `approval_id` to the server, which checks the target again (`400` if it doesn't match), the status (`409` pending, expired or already spent; `403` denied), the grant version and the use window.

### 4. Waiting without asking every so often
- **Server:** `GET /v1/agent/approvals/{id}?wait=N` is a *long-poll* of up to 30 s (the HTTP client cuts off at 60 s). It answers as soon as the request stops being pending, when it reaches its `expires_at` (it returns `expired`) or when `N` runs out. Within the same instance, `decide` notifies through a `broadcast` channel and the answer is immediate; on top of that the server checks the database again every 2 s. That way it works with several instances behind Postgres, and with revocation or a new grant, which expire pending requests without notifying through the channel.
- `ApprovalInfo` gains `used_at` (optional), so the agent knows whether its single-use approval has already been spent.
- **CLI:** `klav approval wait <id> [--timeout 10m] [--agent NOMBRE] [--json]` authenticates **as the agent** (like `klav mcp`: `--agent` or `KLAV_AGENT`, with its key from the Keychain, the file or `KLAV_AGENT_KEY`). It doesn't open the person's vault. It repeats the *long-poll* until there is a decision or until `--timeout` (trimmed to the request's expiry). It prints one line:

  ```json
  {"approval_id":"…","status":"approved","lease_until":0,"used":false}
  ```

  Exit codes: `0` approved, `4` still pending when `--timeout` runs out, `5` denied, `6` expired.
- The SDK uses the same *long-poll* instead of checking every second.

### 5. Pending responses that can be followed up
- `klav mcp` waits **60 s** by default (2 min before) before returning the request. Each call can ask for a different `wait_seconds` (at most 10 min).
- If there is no decision, the result (with `isError`) is JSON:

  ```json
  {
    "status": "pending",
    "pending_approval_id": "…",
    "expires_at": 1767312000000,
    "approve_command": "klav approval approve …",
    "wait_command": "KLAV_HOME=… /ruta/klav approval wait … --agent claude-code --timeout 10m --json",
    "next": "Tell the person … run wait_command in the background … call this tool again with approval_id"
  }
  ```

  `wait_command` uses the binary's absolute path, `KLAV_HOME` and the agent name from `klav mcp`, because the agent's terminal doesn't inherit the MCP server's environment. It never includes `KLAV_AGENT_KEY`: if the key is only in that variable, the agent's terminal needs it too.
- `klav agent …` without `--wait` exits with `4` and writes `klav approval approve <id>`, `klav approval wait <id>` and `--approval <id>` to stderr for the retry.
- The **skill** asks the agent to: tell the person what it is asking for, why, and the exact command to approve; launch `wait_command` **in the background** with whatever its environment offers (in Claude Code, Bash with `run_in_background` or Monitor), to wake up when the person decides without them having to say so; on waking up with `0`, repeat the same tool with `approval_id`; with `5` or `6`, say so and not look for another way.

### 6. Audit log
- Each request leaves its event, as before (`ask`, `allow` or `deny`), with its reason and its signed request.
- A request that reuses a pending request records `ask` with the same `approval_id`.
- A request that goes through thanks to an approval (explicit, spent implicitly or through a lease) records `allow` with the `approval_id` it used. Together with `approval.decided`, the audit log has the request, the decision and each use.

## Consequences
- Migration `0008` (SQLite and Postgres): nullable `target_key` column and partial unique index. Compatible with existing rows.
- A retry no longer needs the ID to use what the person approved; the explicit ID serves to tie the retry to a specific approval and to fail early if it doesn't match.
- The agent finds out about the decision through a background process, without polling more than once every 30 s (or every 2 s inside the server).
- Stricter than 0014: leases take the domain into account, and single-use approvals expire 10 minutes after the decision.
- **Accepted (phase 4 polish):** without `approval_id`, a retry with a different `reason` for the same agent, permission and target within the 10-minute window spends the approval given for the original reason; both reasons stay in the audit log (T27b and residual risk 12 of the threat model).
- **Accepted (phase 4 polish):** `wait_command` never carries the agent's key. If the key only lives in `KLAV_AGENT_KEY` (no Keychain or file), the terminal where the agent runs `klav approval wait` needs that variable; Klav doesn't copy it into any command.
