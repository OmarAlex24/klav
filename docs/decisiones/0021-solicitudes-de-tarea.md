# 0021 · Task requests: an agent asks at once for the items and permissions of a job, the person approves a single card, and Klav creates a lease over that set of targets

- Status: accepted
- Date: 2026-11-04

> **Accepted on 2026-11-04.** There is no code yet: it comes third in Omar's work order (1) generator and history (ADR 0022 §1–3, done), 2) importers, 3) task requests (ADR 0021), 4) assisted change (ADR 0022 §5–7), 5) passkeys (ADR 0020) and 6) Android (phase 7)). The additions to the [specification](../especificacion-cripto.md) (§2.3 and §13.8) and to the [threat model](../modelo-de-amenazas.md) (§5.9 and residual risks 25–26) stand as "accepted, pending implementation". It depends on ADR [0020](0020-passkeys.md) only for the `passkey` permission; the rest holds without passkeys.

## Context
With the `ask` policy, each item is a different target (ADR [0015](0015-aprobaciones-reutilizables-y-espera.md) §1). An agent that downloads the invoices from 8 sites generates 8 approvals, each with its Face ID, and many more if each site asks for TOTP. Today there are two alternatives, and both are bad:

- approving each one, so the person approves out of fatigue (T27);
- giving a permanent `allow` on a project, too broad for a two-hour job.

The leases of ADR [0014](0014-agentes-fase-4.md) §5.3 already allow repeating an action until the time the person set (24 h at most), but only for one target. What is missing is a way to approve **a set of targets** for **a specific job**, with an expiry.

Also, ADR 0020 (Omar's answer to P12) needs a place to grant the `passkey` permission, which can't go in a permanent grant, and ADR [0022](0022-generador-historial-y-cambio-asistido.md) needs the same for `rotate`.

## Decision

### 1. The request
The agent sends a **task request**, signed with its key like any agent request (ADR 0014 §3, `POST /v1/agent/tasks`):

| Field | Type | Notes |
|---|---|---|
| `task` | text | short title (120 characters at most); written by the agent |
| `reason` | text | reason (500 at most); mandatory, as in the other tools |
| `duration` | duration | `30m`, `2h`…; at least 5 min, **at most 24 h** (like leases); counts from approval |
| `access` | list | 1 to 50 accesses |
| `access[].ref` | `klav://` reference | or the short form of `klav.toml`; the runtime translates it to IDs before sending |
| `access[].permissions` | list | `fill`, `totp`, `inject`, `update`, `passkey` (ADR 0020), `rotate` (ADR 0022) |
| `access[].domain` | optional text | expected host; if missing, the item's URLs are used (§3) |

- **IDs reach the server, not names:** the runtime resolves each `ref` with its decrypted copy (as it already does with `access`). The server stores the request's bytes as they are, like the `ApprovalRequest` of ADR 0014 §5.2. `task` and `reason` stay **in the clear**, like `reason` today (T20): the agent must not put secrets there.
- **Format:**
  - MCP sends it as JSON (`request_task`, §7);
  - in the CLI, a **TOML** or JSON file, with the same keys.
  - **YAML isn't accepted**, even though it was the starting example. `serde_yaml` has been marked `0.9.34+deprecated` since 2024-03 and has no clear successor. `toml`, on the other hand, is already in `Cargo.lock` (1.1.8) and is the format of `klav.toml`. A task file is short and flat, and in TOML it is just as readable.
  - The keys are in English, like `klav.toml` and MCP's parameters (Q1).

The starting example (in YAML):

```yaml
tarea: Descargar las facturas de octubre
motivo: Conciliar los gastos del mes
duracion: 2h
accesos:
  - login: AWS
    permisos: [fill, totp]
  - login: Telmex
    permisos: [fill]
```

becomes this in `tarea.toml`:

```toml
task = "Descargar las facturas de octubre"
reason = "Conciliar los gastos del mes"
duration = "2h"

[[access]]
ref = "Facturas/AWS"
permissions = ["fill", "totp"]

[[access]]
ref = "Facturas/Telmex"
permissions = ["fill"]
```

### 2. What can't go in a task
- **`reveal` never goes in a task.** The agent can't ask for it and the card doesn't offer it.
  - It is irreversible: what is revealed enters the LLM's context and can't be "un-revealed" (threat model §6).
  - A task approves many things with a single Face ID, and mixing something irreversible in there is exactly what encourages approval out of fatigue (T27).
  - If it is really needed, the agent uses the usual path, one card per value (`reveal` is `deny` by default).
  - `fill` means Klav writes the value without the agent seeing it, and that one does go in tasks.
- **Nor `delete`**, for the same reason: it isn't undone within the job (the trash recovers it, but it isn't something approved in bulk).
- **`create` and `list`** aren't requested: `list` is already given by the grant, and `create` has no item to point at. If the grant leaves them on `ask`, they keep their normal approval.

### 3. Klav completes the proposal, in the person's client
The card doesn't show what the agent said: it shows what the **person's client** decrypts for those IDs.

- **Titles and sites:** each item's title, username and hosts come from the person's vault, never from the agent's text. An agent can't call the bank account "Facturas Telmex".
- **Domains:** if the access doesn't carry `domain`, the client puts in the hosts of the item's URLs. If it does and it doesn't match any URL (the `klav-core::site` rule), the access is marked "The site does not match the item" and left unchecked.
- **TOTP:** the *overview* an agent with `list` sees does **not** say whether a login has TOTP (`Overview` only carries `kind`, `title`, `username`, `urls` and `tags`), and `get_item` only lists the fields of the kind's template. No flag is added to the *overview*:
  - it would be a schema change (`deny_unknown_fields`);
  - and it would be new metadata for any agent with `list` (which accounts have 2FA).

  Instead, the person's client, which does decrypt *details*, adds `totp` to every access with `fill` on a login that has TOTP. It marks it "Added by Klav" and the person can remove it. That way the agent doesn't fall short halfway through the job. The agent learns about it from the response to the decision, which carries the final set (§4).
- **Passkey:** if the login has a passkey and no password, Klav changes `fill` to `passkey`. If it has both, it offers `passkey` unchecked.
- **What the policy denies:** the client evaluates the grant's policy (`klav_core::policy::evaluate`). A permission in `deny` by an explicit rule shows crossed out, "Your policy denies it", and can't be checked: a task doesn't widen a `deny` rule of the person's (ADR 0006, the most restrictive wins).

### 4. The approval: a single card
- **What is shown:**
  - the agent, the task and the reason, marked "according to the agent";
  - the duration and the time it expires;
  - one row per item, with its title, the username, the site and the permissions;
  - warnings next to `totp` ("2FA stops being a second factor for this agent", T26), `passkey` ("the agent will sign in with your passkey; your approval counts as verification", ADR 0020 §9) and `rotate` (ADR 0022).
- **The person can uncheck** items or permissions before approving, and shorten the duration (never lengthen it beyond what was requested or beyond 24 h).
- **They approve with Face ID or Touch ID**, like any approval (ADR 0014 §5.4).
- **The client signs the decision** (specification §13.8):

  ```
  decision = JSON { v, task_id, agent_id, revision, expires_at_ms,
                    access: [{ vault_id, project_id, item_id, permissions, domains, added_by_klav }] }
  firma    = Ed25519(cuenta, tuple("klav/v1/sig/task-decision", task_id, agent_id, request, decision,
                                   "approve"|"deny", u64_be(decided_at_ms)))
  ```

  - `request` is the exact bytes the server stored;
  - `decision` goes as bytes and is stored as is: no canonical form is needed;
  - the server verifies the signature and stores it, and the agent's runtime verifies it with the account's pinned identity (TOFU, ADR 0014 §1.4) before using the task.
- **Approving creates a lease over that set of targets.** For each approved `(elemento, permiso)`, the server stores a row with:
  - the `target_key` of ADR 0015 §1 **without the domain**;
  - the list of approved hosts.

  An agent request passes if its `claims.domain` is one of those hosts or a subdomain, with the same `klav-core::site` rule. That way a task covers the AWS login on `signin.aws.amazon.com` and on `console.aws.amazon.com` without another approval, but not on another site. Permissions without a domain (`inject`, `update`) don't check it.
- **Denying** is signed too, as today.

### 5. How a request inside a task is evaluated
On the server and, again, in the runtime (double barrier, T22):

1. **`passkey` and `rotate`:** they only pass if a current task covers them. Outside a task they are `deny`, with the hint "ask for a task" (`request_task`). No grant can have rules for these two permissions: the client doesn't sign it and the server rejects it with `400`.
2. **The rest:** the policy is evaluated as always.
   - `deny` → `deny`; the task doesn't change it.
   - `ask` → if a current task covers the target, `allow`; if not, the normal approval (or the "Outside the task" card, §6).
   - `allow` → `allow`.
3. **Current** means approved, before `expires_at`, not ended, and with the agent not revoked. It is checked **on each use**, not only on approval.
4. The task does **not** depend on the grant's version (unlike a single approval): each use evaluates the current grant again. If a new grant removes the project, the agent no longer has the key; if it adds a `deny` rule, the rule wins.
5. Requests carry an optional `task_id`. If the agent has a single current task that covers the action, the runtime fills it in on its own.

### 6. Something outside the task
An `ask` request from an agent with a current task, which the task doesn't cover (for example, a TOTP that was removed or a new site), goes back to ADR 0015's normal `ask`, with the same pending request and the same `approval_id`. The card changes:

> **Outside the task** "Descargar las facturas de octubre"
> **mi-agente** wants *totp* for `Facturas/Telmex`
> [Deny] [Approve once] [Add to the task]

- **"Approve once"** is ADR 0015's single-use approval.
- **"Add to the task"** signs a new revision of the decision (`revision + 1`) with that target added and the **same** `expires_at`: it doesn't extend the task. The server only accepts the next revision.
  - It also approves the pending request once, so the agent's wait exits with `0`. If the agent doesn't retry with that `approval_id` and uses the target through the task, that first use spends the single-use approval of the same target (lease approvals aren't touched): what was added doesn't outlive the task, and once it ends the next use asks for approval.
  - Since layer 06 of the 2026-11 security round, that approval is **bound to the task** (`task_id` in `POST /v1/approvals/{id}/decide`, outside what is signed). The server never reuses it without its ID (ADR 0015 §2), only accepts it by its ID while the task is still current, and the first use through the task spends only the approvals bound to that task. That way it doesn't outlive the task either if the agent didn't use it: before, it served its 10 minutes even if the task had ended.
- **`reveal` or `delete`** outside the task only offer "Deny" and "Approve once" (§2).

### 7. How it is requested (agent)
- **MCP:** `request_task({task, reason, duration, access, wait_seconds?})`.
  - It waits like ADR 0015 §4–5: up to `wait_seconds` (60 s by default, 10 min at most).
  - If there is no decision, it returns `{"status": "pending", "pending_task_id", "expires_at", "approve_command": "klav task approve …", "wait_command": "… klav agent task wait … --agent … --timeout 10m --json", "next"}`. `wait_command` follows the rules of ADR 0015 §5: absolute path, `KLAV_HOME` and never `KLAV_AGENT_KEY`.
  - Approved, it returns `{task_id, status, expires_at, access: [{ref, permissions, domains, added_by_klav}], removed: [...]}`: what the person approved, what Klav added and what it removed.
  - New tools: `get_task(task_id)` and `end_task(task_id, reason)` (the agent closes the task when it finishes), and `list_tasks()` (its own, also those the person offered it in ADR 0022 §6).
  - The other tools accept an optional `task_id`.
- **CLI:** `klav agent task request tarea.toml [--wait] [--json]`, `klav agent task wait <id>` (exit codes from ADR 0015: `0` approved, `4` pending, `5` denied, `6` expired), `klav agent task show|end <id>`.
- **SDK:** `Session::request_task` in `klav-sdk` and `requestTask` in `@klav/sdk`, with the same *long-poll*.
- **Server:** `POST /v1/agent/tasks`, `GET /v1/agent/tasks/{id}?wait=N` (*long-poll* like ADR 0015 §4) and `POST /v1/agent/tasks/{id}/end`. At most 5 pending and 10 current tasks per agent.

### 8. How it is managed (person)
- **CLI:** `klav task ls`, `klav task show <id>`, `klav task approve <id> [--without REF[:permiso]]… [--for 1h]`, `klav task deny <id>` and `klav task end <id>`. Approving asks for Touch ID through `klavd`, or the password.
- **iOS:** a push notification of type `task`, with a random ID and no text, like the approval ones (T75). The card and the Face ID are in the app.
- **Extension and Mac:** the card shows in the *popup* ("Agent requests") and in `klavd`'s approval surface. While a task is current, the *popup* and the iOS app show it with the time left and an **"End task"** button.
- **Server:** `GET /v1/tasks`, `GET /v1/tasks/{id}`, `POST /v1/tasks/{id}/decide` and `POST /v1/tasks/{id}/end` (the last one signed, like revocation).

### 9. Audit log
- **New events:**
  - `task.requested`, with the request signed by the agent;
  - `task.decided`, with the decision's bytes and the account's signature (also each "Add to the task" revision);
  - `task.ended`, with who ended it: the person, the agent, the expiry or the revocation. The server records the expiry the first time it notices it, in a query or in the periodic cleanup.
- **Each use carries the `task_id`** next to the permission, the item, the domain and that request's reason. A use outside the task carries its `approval_id`, as today.
- **`klav log --task <id>`** shows the summary: the task, the reason, who approved it and when, each use (item, permission, host, time and result), what was approved outside the task and how it ended.
- Alerts (`first_use`, `burst`, `denied`) stay the same inside a task.

### 10. Skill (when it is implemented, not now)
`skill/SKILL.md` gains a few lines:

- before a job that touches several sites or items, ask for **one** task with `request_task` (all the items and permissions you are going to need, a real reason and just the right duration), wait with `wait_command` and work with what came back approved;
- if something falls outside the task, ask for it with the normal tool: the person will see "Outside the task" and decide; don't ask for a new task to get around it;
- `reveal` doesn't go in tasks;
- the person's passkeys are only used through the browser with Klav (`target: "extension"`), never through `sdk:`;
- when finished, `end_task`.

## Consequences
- **New formats:** the `klav/v1/sig/task-decision` signature (specification §2.3 and §13.8) and its vectors in `docs/vectores/agentes.json`. No existing format changes.
- **Server:** a migration with the `tasks` tables (request, signed decision, revision, state, `expires_at`) and `task_targets` (`target_key` without domain, and hosts); the routes of §7 and §8; the evaluation of §5 in `agent_access`.
- **`klav-core`:** `Permission::Passkey` (ADR 0020) and `Permission::Rotate` (ADR 0022), and the grant validation rule (no rules for those two); `TaskRequest` and `TaskDecision` types.
- **Clients:** the card in the CLI, the *popup*, `klavd` and iOS; the `task` push notification.
- **Agents:** `request_task`, `get_task`, `list_tasks` and `end_task` in MCP; `klav agent task …`; `requestTask` in the SDK.
- **Threat model:** §5.9 (T91–T95) and residual risks 25–26.
- **What doesn't change:** ADR 0015's single approvals, leases and `approval_id` stay the same; a task is another way to reach `allow`, never broader than the grant.

## Questions for Omar
Each one had a default value, which is what this ADR describes. Omar accepted the ADR on 2026-11-04 without changing any, so all of them keep their default value.

| # | Question | Default |
|---|---|---|
| Q1 | Task file keys in English or in Spanish? | English (`task`, `reason`, `duration`, `access`, `ref`, `permissions`), like `klav.toml` and MCP |
| Q2 | `reveal` in tasks? | Never, not even checked by hand (§2) |
| Q3 | Does Klav add `totp` to logins with TOTP? | Yes, checked and with the "Added by Klav" label; the person removes it if they want (§3) |
| Q4 | Maximum duration | 24 h, like leases |
| Q5 | Does "Add to the task" extend the expiry? | No: same `expires_at` (§6) |
| Q6 | Limits | 50 accesses per task; 5 pending and 10 current tasks per agent |
| Q7 | Does the task die with a new grant? | No: each use evaluates the current grant again; revocation does end it (§5) |
| Q8 | YAML in the CLI? | No, only TOML or JSON (§1) |
