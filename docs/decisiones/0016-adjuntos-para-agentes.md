# 0016 · Attachments for agents with `inject`, in the same decision as the item

- Status: accepted
- Date: 2026-11-02

## Context
ADR [0014](0014-agentes-fase-4.md) §9.3 left attachments out of the agents' scope. In the real milestone A test this showed up twice:

1. The case that motivates `inject` in the design (§7) is Apple's `.p8`: a file that a tool only accepts on disk. An agent with `inject` couldn't write it, neither with `inject_file` nor with the `[files]` of `klav.toml`.
2. The "what it saw" report marked the `APNs` item with `SECRET: yes` even though `inject_file` had failed. The server recorded an allowed `inject` (it handed over the *details*), but those *details* had no value at all: the item's only secret is the attachment, and the server never handed it over.

Through its grant, the agent already has everything needed to decrypt an attachment: the project key opens the item key, and that one opens the attachment's (spec §10). What was missing is the server handing it over behind the same policy barrier as the *details*.

## Decision

### 1. A single request and a single decision
`POST /v1/agent/access` accepts `include_attachments: true`, only with `inject`. If the policy allows it, the response carries, besides the item, **all** its completed, non-deleted attachments: metadata with the wrapped key and the *ciphertext*.

- It is the same decision: with `ask`, one approval (or one lease) covers the item and its attachments. A second download route would have needed another check, and with "approve once" the approval would already be spent on the first request.
- The server doesn't know which field the agent asked for (the *details* are encrypted), so it hands over all the item's attachments. The runtime asks for `include_attachments` only if the item has any.
- Limit: 16 MiB of *ciphertext* in total per request (`MAX_AGENT_ATTACHMENTS_BYTES`). Above that, `400`, before evaluating the policy: it leaves no event in the audit log because nothing is handed over. Typical keys and `.p8` files weigh a few KiB.
- `search_items` and `get_item` show how many attachments an item has (`attachments`), so the agent knows it can ask for them. The field name goes in the encrypted *details*: the agent knows it from the person or from the reference it is given.
- So that the runtime knows whether an item has attachments, `GET /v1/agent/items` lists the attachment metadata of each project (without content). It isn't new information: the agent can already decrypt those items' keys.

### 2. No new cryptography
The runtime (`klav-sdk`) decrypts with the usual hierarchy and only with `klav-core`: the grant's project key opens the item key (`unwrap_item_key`), that opens the attachment's (`unwrap_attachment_key`, with the full `AttachmentContext` in the AAD) and STREAM opens the content (`decrypt_attachment_bytes`). It checks that each attachment belongs to the requested item and has the declared size. An attachment that doesn't open is an error, never a half-written file.

### 3. Where an attachment can go
Only to a file, never into the LLM's context:

- MCP `inject_file` with `ref` (and `klav agent inject -r`, `inject` in `@klav/sdk`): writes the bytes as they are into a new 0600 file.
- `[files]` of `klav.toml` in `run_with_secrets` (and `klav agent run`): they are written before the command and deleted when it ends.
- Into an environment variable, only if it is UTF-8 with no null bytes; otherwise, an error.
- Into a template, never (as in the person's `klav inject`). For templates the runtime doesn't even ask for the attachments.
- `reveal` and `fill` don't hand over attachments.

If a command prints the content of a text attachment, the output shows it as `[redacted by klav]`, the same as variables.

### 4. The audit log says what was handed over
The `agent.access` event carries `attachments`, the list of attachments handed over, only when the result is `allow`. The field is optional and omitted when empty, so earlier events have the same hash and `klav log verify` doesn't change. The server reads the content before recording the decision: if it can't read it, no event is left saying it was handed over.

### 5. A "what it saw" report that doesn't exaggerate
`SECRET` is computed on the person's device, which can read the item:

- `yes` if any attachment was handed over (`yes (file)` in the table, `attachments` in `--json`);
- `yes` if the *details* were handed over (`fill`, `inject`, `totp`, `reveal` allowed) and the item has any secret field with a value, or notes;
- `yes` if the device can't open the item (deleted or not synced): when in doubt, it is marked;
- `no` otherwise, such as an item whose only secret is an attachment that was never handed over.

The content that counts is the item's **current** content: if the person later deleted its secret fields, an earlier access shows `no` even though it handed over values at the time. This is accepted: the report is for deciding what to change now, and a value that is no longer in the item has to be changed at the source anyway.

In addition, the runtime checks **before** asking for anything what can fail in advance: that the target file doesn't exist (without `overwrite`) and that its directory exists, also for each `[files]` entry. That way a common failure doesn't leave in the audit log an access that served no purpose.

## Consequences
- Additive changes in `klav-proto`: `AccessRequest.include_attachments`, `AccessGranted.attachments` (`AgentAttachment`), `AgentProjectItems.attachments` and `AuditEvent.attachments`. No migration.
- Injecting a text field from an item with attachments also downloads its attachments, and the report counts them as handed over. It is conservative and capped at 16 MiB. Separating fields and attachments would require the server to know which field each attachment belongs to, which today is encrypted.
- Residual risk: the report is still based on what the server handed over. A compromised runtime that received the *details* has whatever they contain; what this ADR changes is that an item with no text values is no longer marked as if it had them.
- Replaces the last sentence of 0014 §9.3 ("Attachments aren't available to agents yet").
