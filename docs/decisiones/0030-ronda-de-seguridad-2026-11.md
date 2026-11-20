# 0030 · Security round 2026-11: vault key signed by the account, `inject` without TOTP and with its residual risk written down, approvals verified by the SDK, strict rules for `klav log verify`, decisions bound to what was shown, tasks without a site, and sites added by agents pending confirmation

- Status: proposed (accepted on merging the PR of layer `seguridad/01-adr`)
- Date: 2026-11-05

> On 2026-11-05 a read-only security audit was done on `main` at `d0d317b`. Twelve layers of fixes follow it, stacked with `gh stack` (roadmap, "Ronda de seguridad (2026-11-05)"). Most findings are implementation bugs and are fixed without changing the design. The seven in this ADR do change it or make it more precise. Omar set the seven decisions in the brief. In §1 (the vault version in the signed message) and in §7 (which of the two ways out Omar proposed) the choice was made by the subagent that wrote this ADR, and each section justifies it. Omar reviews them in the PR, and merging it accepts them.

## Context
The findings that touch the design are seven:

- **G1, the vault key has no author.** `Unlocked::rebuild` (`klav-client/src/session.rs`) opens the `shared_key` (type `0x20`, HPKE) the server lists for each vault and takes `owner_account_id` from the server's response. HPKE only proves that the blob was encrypted **for** the account's identity, and the server knows that public identity. So a malicious server can create a vault with a key it chose, encrypt it for the account and list it. The client accepts it, and whatever the person stores there is readable by the server. It is a hole in trust boundary F1: the server can make up a key the client uses as its own.
- **G3, `inject` reaches the value.** `inject` is in `allow` by default, and `diseno.md` §5.4 says `reveal` is "the only way" a value enters the LLM's context. That isn't so. An agent that launches `run_with_secrets` with `echo $X | base64` sees the encoded value. `field_bytes` (`klav-sdk/src/session.rs`) also hands a TOTP seed to `inject`, and with it the agent bypasses the `ask` of `totp` (T26). Finally, the `Redactor` of `run_with_secrets` only covers the values of **that** call, not those of an earlier `inject_file` in the same session.
- **G4, the SDK doesn't verify approvals.** `Session::claim_approval` checks the state, `lease_until` and `used_at` of what the server says, but not the account's signature (`ApprovalInfo.signature`). `access_inner` accepts a `200` even when its local policy says `ask`. The double barrier of T22 then depends on the server alone.
- **G5, `klav log verify` is more lenient than T12 says.** `check_agent_proof` (`klav-client/src/audit.rs`) requires the signed request only if `actor == Agent` (and the server writes `actor`). If `proof.body` is missing, it compares nothing. It doesn't compare `method`/`path` with the action. It takes agent keys from `GET /v1/agents`, which the server also provides. It doesn't reject repeated nonces. And when paging, `audit_entries` trusts `head_seq` without requiring consecutive `seq`.
- **G6, something other than what was shown gets signed.** `decide_task` and `decide_approval` make a second `GET` and sign the `request` of that response. The card the person saw came from an earlier `GET`, so a server can show one request and get another one signed.
- **Tasks without a site.** `TaskAccess::allows` (`klav-core/src/task.rs`) returns `true` if `domains` is empty, also for the permissions that verify the domain (`Permission::checks_domain`: `fill`, `passkey`, `rotate`). A login with no URLs approved with `fill` in a task is then filled **on any site**. `propose` leaves those permissions checked with `domains = []`.
- **G8, `update` can add sites.** With `update`, an agent (or a *prompt injection*) can add `https://banco-falso.example` to the URLs of the bank login. From then on, the site rule (T21, T61, T73) accepts it for the person's autofill and for the agent's fills. The `update` approval doesn't show the change: `ApprovalRequest` doesn't carry the body and the person can't decrypt it. Besides, `update` can be in `allow` or inside a task, and then there is no card.

## Decision

### 1. The account signs its vault key (G1)
- **New label** `klav/v1/sig/vault-key`, with the Ed25519 identity of the owning account:

  ```
  mensaje = tuple("klav/v1/sig/vault-key", account_id(16), vault_id(16), shared_key)
  firma   = Ed25519(cuenta dueña, mensaje)
  ```

  `shared_key` is the exact bytes of the `0x20` blob. Its HPKE `info` already carries the recipient's fingerprint (spec §8), so the signature also binds **who** the key is for. `account_id` is the owning account's, the same one that goes in the AAD of everything inside the vault.
- **Without the vault version in the message.** The plan left it as a choice, and it is ruled out for three reasons:
  - `Vault.version` is the version of the **metadata** (it goes up with every rename), not of the key. Signing it would force a new signature on every rename without protecting anything else.
  - A member's `shared_key` is written once to `vault_members` and never changes: the rotation of T24 is per project (ADR 0014), not per vault.
  - T7 already covers a rollback of the metadata: the version goes in the AAD of `0x12` and the client keeps its *high-water marks*.

  If the vault key ever rotates, that ADR will add a generation number to the message or a new label. It is written here so it isn't forgotten.
- **Where it goes:** a new column next to the `shared_key` in `vault_members` (both migration dialects) and a `shared_key_signature` field in `CreateVault` and in `Vault`. From layer 02 on, `POST /v1/vaults` without a signature answers `400`.
- **The client rejects** (a warning and no use, as today with a vault that doesn't decrypt):
  - every vault whose signature doesn't verify with the **account's own** identity, which the client keeps sealed with the KEK and checked by T9;
  - every vault with `owner_account_id != account_id` as long as sharing with people doesn't exist ("Después", roadmap). The `VaultContext` is built with the session's `account_id`, never with the one the server states.
- **`create_vault` keeps the key it generated** until the final `sync` and checks that the listed vault opens with that same key. If not, it fails with `Security`.
- **Existing vaults, without a signature (TOFU).** The first sync after updating signs every own vault that opens fine and uploads the signature (new route of layer 02), with a one-time warning that names the signed vaults.
  - If the device's encrypted cache already had that vault, the listed `shared_key` must be **byte for byte** the cache's. There the TOFU doesn't trust the server: the cache is sealed with the local key.
  - A device without that vault in its cache (a new one) signs it anyway, and the warning says so. That is the limit of this TOFU: residual risk 32.
  - Afterwards, the device stores in its cache that the vault is signed and rejects forever a version without a signature. The TOFU is **once per device**, not every time the server removes the signature.
- **Agents:** nothing changes. No agent receives a vault key (T97, ADR 0004), only project keys wrapped by HPKE inside a grant the account already signs (§13.4).
- **Spec and vectors:** the label, the message and a vector of the signed message go in the spec (§2.3, §8) and in `docs/vectores/` **with the code, in layer 02**, as was done with §13.8. This ADR doesn't touch the spec.

### 2. `inject` stays in `allow`, without TOTP and with its residual risk written down (G3)
- **`inject` stays in `allow` by default.** It is the agents' central flow (`klav run`, `.env`, the `.p8`), and moving it to `ask` would lead to approval fatigue (T27).
- **The concrete paths are closed:**
  - **TOTP fields aren't injected.** `inject`, `run_with_secrets` and templates reject a `FieldKind::Totp` field with an error that points to `get_totp` / `klav totp`, which go through the `totp` permission and its `ask` (T26).
  - **The `Redactor` of `run_with_secrets`** also covers the values of the files the same MCP session injected earlier with `inject_file`, not only those of that call.
  - **`inject_file` over MCP** warns, in the JSON, if `git check-ignore` doesn't ignore the destination (`secret_files::warn_if_not_ignored`), as the CLI already does (T35). `inject()` in `@klav/sdk` limits `out` to inside `cwd`, as MCP does.
- **Residual risk (T20, residual 31):** a process launched with a secret can encode it, print it some other way or send it over the network. The `Redactor` only recognizes the literal value (later it was widened to its usual encodings and its long pieces; see T20 and residual risk 31). With `inject` the agent **can** reach the value, and Klav says so instead of promising the opposite:
  - `diseno.md` §5.4 stops saying that `reveal` is the only way;
  - the skill says that `run` isn't a sealed channel.

  Whoever doesn't want it puts `inject` in `ask` or in `deny` in the grant, or scopes it by project or tag.

### 3. The agent runtime verifies approvals (G4)
- **`claim_approval` verifies the signature** of the account with the identity the agent pinned (TOFU, ADR 0014 §1.4) with `agent::verify_approval`, over `(approval_id, agent_id, request, decisión, lease_until_ms, decided_at_ms)` (spec §13.5).
  - An `Approved` approval without a signature, or with one that doesn't verify, is a `Security` error.
  - What it already checks stays the same: that `lease_until` hasn't expired and that a one-time approval isn't spent (`used_at`).
- **A `200` with the local decision `ask` is only accepted if it is backed:**
  - by an approval the runtime verified (the one it named with `approval_id`, or the one the server reused under ADR 0015 §2);
  - or by a current task whose signed decision the runtime already verified and that covers that target (ADR 0021 §5).
- **`AccessGranted` and the write responses** gain an optional `approval_id` for the reuse without `approval_id` of ADR 0015 §2. It is the approval the server used. The runtime fetches it and verifies it before decrypting. A `200` without backing is `Security` ("the server let through what your policy asks to approve").
- **`refresh()`** doesn't lower `Entry.version` or swap `wrapped_key` for that of a lower version (T7, now also in the agent).
- **Writes in `ask`: first the approval, then the body** (layer 06, residual risk 35). Before, a write in `ask` went with its sealed item on the first try, and a server that applied it without approval was only exposed afterwards. Now, if the local policy says `ask` and no verified task covers it, the runtime asks for the approval through `POST /v1/agent/approvals`, without the body (permission, vault, project, item, reason and tags). The server runs the write's checks without spending anything: it creates or returns the request (`202`) or names what already covers it (a lease or an unspent one-time approval, or a task). The runtime verifies the account's signature and that the approval is for that write, and only then sends the body with that `approval_id`. A `200` saying no approval is needed isn't believed: nothing is sent. The new action `agent.ask` goes into the table of §4, with a required body.

### 4. Rules of `klav log verify` (G5)
`klav log verify` stops trusting what the server writes about each event:

1. **The proof is required by `action`, not by `actor`.** A closed table says, for each action, whether it carries the agent's signed request, the account's signature or neither (the ones only the server attests, residual risk 10). An action that isn't in the table is an error, not an `Ok(false)`.
2. **Required body** in `agent.access` and `task.requested`. The signed `body_digest` must be the SHA-256 of the body the event carries.
3. **Action → (method, path) table.** The signed `method` and `path` must be the action's: a signature of `GET /v1/agent/me` isn't valid as proof of an `agent.access`.
4. **`item_id` and `permission` come from what was signed.** If the event carries them, they must be in the signed body, and be equal. Also in `approval.decided` and in `agent.granted`, against the bytes the account signed.
5. **Agent keys vouched for by the chain.** The `agent.granted` event doesn't carry the agent's identity, but the message the account signs does (spec §13.4). So the identity `GET /v1/agents` gives is only used to verify that agent's requests if some `agent.granted` in the chain verifies with it. If the server changed it, the grant's signature doesn't verify. An agent that no longer appears in `/v1/agents` (for example, revoked) gives a warning, not an abort.
6. **Unique nonce:** the pair `(agent_id, nonce)` doesn't repeat in the chain. The signed `timestamp` must fall within the ±5 min window (T25) around the event's `at`.
7. **Strict paging:** each page must start at `after + 1` and continue without gaps. If it doesn't advance, it is an error, not an infinite loop.
8. **Local pin:** the pinned head's file carries the `account_id`, and if it is missing while there are events, there is a warning.
9. **Assisted change (ADR 0022 §5):** `rotate.started` and the agent's confirmation or cancellation carry their signed request with a body. The confirmation and the cancellation don't sign the host, and the person's (from the item card) carries no signature: both must name the agent, the item, the host and the task of an earlier allowed `rotate.started` in the chain. The task the person offers goes in `task.decided` with an empty request, as it is signed.

### 5. The signature is bound to what the person saw (G6)
- When **showing** a task or an approval, the client computes `SHA-256(request)` over the exact bytes of that response's `request`, and the card keeps that digest.
- **When deciding**, `decide_task` and `decide_approval` receive the digest of what was shown and abort, without signing, if the bytes of the second `GET` give another one ("the request changed while you were looking at it; open it again").
- It holds for every surface that decides:
  - the CLI;
  - `klavd` and the *popup*, which send the digest with the decision;
  - `klav-ffi` / iOS;
  - the extension, which also shows `approval.domain` as "according to the agent", because the agent claims it.
- **Tasks the person offers** (ADR 0022 §6, "Fix my reused passwords"): there is no agent request the server could change, so they carry no digest. What is signed comes from the local vault at signing time (`prepare_offer` rebuilds each row in `klavd`, in `klav-ffi` and in the CLI): the agent the person chose by its ID, its logins, and as sites only the ones the person confirmed (§7), never one an agent added.
- **No signed format changes:** the message of §13.5 and that of §13.8 already carry the whole `request`. Only which bytes are accepted for signing changes. The SHA-256 is `klav-core`'s (`sha2`), with no new dependencies.

### 6. Tasks without a site
A permission that verifies the domain (`fill`, `passkey`, `rotate`) on an item without any valid host **is left unchecked and can't be checked**:

- `propose` leaves it unchecked, with the "no site" mark (CLI, *popup* and iOS show it, like "Your policy denies it");
- `ProposalRow::set` doesn't check it;
- `TaskDecision::check_first` rejects a decision with that permission and empty `domains`;
- `TaskAccess::allows` returns `false` for those permissions if `domains` is empty, instead of today's `true`.

The server applies the same rule when evaluating `task_targets` (double barrier, T22). A decision already signed with `domains = []` on one of those permissions stops working: it fails closed.

Payment cards (`ItemKind::Card`) and identities (`ItemKind::Identity`) have no URL. They are the only exception (Omar's decision, 2026-11-05, option B): if the agent asked for a `domain`, `propose` binds `fill` to that host and the row shows it "according to the agent" (CLI, *popup* and iOS). The person then approves "this card on this site", and the task only covers that host or its subdomains, as with a login. With no `domain` asked for, nothing comes checked, the same as a login with no URLs. Outside the task they are filled as today: with the grant's policy and, if it is in `ask`, with its approval (T21).

A row whose `domain` doesn't match the item's URLs (`domain_mismatch`, T92) can't be checked again either: not by `ProposalRow::set` in the core, nor by `chosen` in the client (a `with` on that row is ignored), nor by the *popup* or iOS, which show it locked.

### 7. Sites added by an agent, pending confirmation (G8)
The plan offered two ways out:

- **A.** The `update` approval shows the change of URLs, if the person's client can decrypt the patch.
- **B.** The runtime doesn't fill on hosts an agent added until the person confirms them.

**B is chosen**, because A doesn't close the problem:

- a card only exists with `ask`, and `update` can also be in `allow` or inside a task, with no card at all;
- `ApprovalRequest` doesn't carry the write's body;
- an approval serves the retry, whose body can be a different one (ADR 0015 §2): to show the patch, the approval would have to be bound to the body and the format of §13.5 changed, and even then the other two paths would remain;
- the real damage isn't even in the agent, but in the **person's autofill**: their extension would offer the bank login on the host the agent added.

B covers every path with one rule:

- **Authorship per version.** The server knows by which route each version arrived (the agents' or the people's). It stores the author in `item_versions` (`account` or the `agent_id`) and returns it in `Item` and in `ItemVersionInfo`. Versions from before the migration count as the person's (a limit noted in §Consequences).
- **Confirmed hosts** of an item = the hosts of its URLs in the **latest version written by the person**. If the current version is the person's, they are all of them. If it is an agent's, the client compares with the person's latest. If there is none (an agent created it), none is confirmed.
- **Who applies it:**
  - **The person's client** (`klav-client`, and through it `klavd`, the extension, the CLI and `klav-ffi`/iOS): `suggest`, `autofill` and the Credential Provider's matching only use the confirmed hosts. The others appear on the item page as "Sites added by *mi-agente*", with **Confirm** and **Remove**. If it doesn't have the person's version in its cache, it fetches it from `GET …/items/{id}/versions/{v}`; if it can't, the host stays pending (fails closed).
  - **The agent runtime:** along with the current version in `AccessGranted`, the server sends the `wrapped_key` and the *overview* of the person's latest version. The runtime decrypts them with its project key (the version goes in the AAD, T6), and the SDK (`browser.rs`) only writes on confirmed hosts. The error says "an agent added this site and the person hasn't confirmed it". An agent's fills through the extension (`target: "extension"`) apply the same check in the SDK before asking `klavd` for them, which only forwards them to the tab.
- **Exception for an agent's sign-up (ADR 0022 §7).** In an agent fill, and only there, if the item **has no version written by the person** and **all its versions were written by the same agent that fills**, that agent fills on the hosts of its URLs. It is the assisted sign-up flow: the agent creates the login with `create_item` and `generate: true` and fills it in the registration form. The threat of G8 is an agent adding a phishing site to an item that holds a secret of the person's; in an item the agent itself created and the person never touched, no secret of the person's is at stake, only what the agent already wrote. As soon as the person writes a version, theirs is in charge again as in any other item. If another agent writes a version, or one from the history is missing (trimmed or deleted with `DELETE …/versions`, so it could be anyone's), there is no exception. Another agent never has it. The person's autofill, the iOS Credential Provider, tasks ("The site does not match the item") and the assisted change (ADR 0022 §5–6, which comes from an offer or a task of the person's) don't change: for them those hosts stay pending.
- **Confirming** is a normal edit by the person (a new version written by the account), so no new signed format is needed.
- **Inside a task**, a requested `domain` that is only on unconfirmed hosts is marked as "The site does not match the item" (ADR 0021 §3).

**How it turned out in layer 06:**

- Migration `0013_autoria` (SQLite and Postgres): `author_agent_id` in `items` and in `item_versions`. The agents' routes fill it; the people's leave it `NULL`. No column with "the person's latest version" is needed: the server looks it up in `item_versions` (`author_agent_id IS NULL`, the newest), and when trimming the history (`max_item_versions`) it never deletes that version.
- The person's client keeps in its cache, encrypted like the rest, the person's latest version of every item whose current version is an agent's. It downloads it when syncing with `GET …/versions` and `GET …/versions/{n}`, once per current version and per project version: a rotation rewraps the stored versions with the new key, so after one it is downloaded again.
- The CLI shows pending sites in `klav item get` and manages them with `klav item sites REF [--confirm | --remove URL]`. Confirming is an edit without changes by the person. The extension and the iOS app no longer suggest or fill on those sites (the rule is in `klav-client` and in `klav-ffi`), but they don't show them on the item page yet.
- The agents' `item.updated` events in the audit log aren't used to give an author to versions from before the migration: the event doesn't say which version number it wrote, and matching them by time would be a guess. Those versions count as the person's (residual risk 33).

**The sign-up exception, in the code:** `AccessGranted` carries `sole_author` (false if missing). The server sets it if the requester is the author of the current version, there is no version by the person and the stored versions are `version − 1`, all by that agent. The runtime (`confirmed_of` in `klav-sdk`) accepts it only if, in addition, `author_agent_id` is its own ID and no `person_version` arrived. An agent's fills through the extension go through the same `check_confirmed` of the SDK before asking `klavd` for anything, which only forwards to the tab. An old server doesn't send it, and then there is no exception (fails closed).

A malicious server **alone** gains nothing by lying about authorship: it can't write URLs because it has no item keys. Lying only helps it if it colludes with an agent that has `update` (residual risk 33).

## Consequences
- **New formats** (layer 02): the `klav/v1/sig/vault-key` signature and its vector. No existing encrypted format changes. The messages of §13.5 and §13.8 stay the same (§5).
- **Protocol:**
  - `shared_key_signature` in `CreateVault` and in `Vault`, and the route to upload the TOFU signature (layer 02);
  - optional `approval_id` in `AccessGranted` and in the agents' write responses (layer 04);
  - author in `Item` and `ItemVersionInfo`, and the person's version and `sole_author` in `AccessGranted` (layer 06).

  They are added fields. An old client against a new server still doesn't verify the vault key, as today, until it is updated.
- **Migrations** (both dialects): the signature in `vault_members` (layer 02) and the author in `item_versions` (layer 06).
- **Breaks on purpose** (fails closed):
  - tasks already approved with `fill` on an item without URLs (§6);
  - audit log chains with events the new verifier doesn't accept (§4), which are reported as tampered;
  - versions written by an agent before the migration, which count as the person's (§7) because there is no record of their author. The audit log does have the agents' `item.updated` with their signed request, and layer 06 can use them to mark those versions if it turns out to be simple.
- **Threat model:** new T118 (vault key injected or substituted), T20 with the residual of `inject`, and F2, T11, T12, T21, T24, T27, T34 and T92 brought up to date. §6 covers "Otro proceso del mismo usuario frente a `klavd`". Residual risks 31–33.
- **Amendment to [ADR 0026](0026-lecturas-sin-esperar-al-servidor.md) §3** (layer 10, 2026-11-05): in `klavd`, a *rollback* or a security failure found by a passing sync (also the background one) is a warning on every response, not an error that brings down reads. The verified copy keeps serving, and it is retried with the first request that arrives after 30 s. Writes aren't blocked either: they go on, with the warning, and `klav sync --reset-cache` is the way out. That way, a server that poisons the marks doesn't lock the person out of their vault (T7). An expired session and tampered state are still an error, as 0026 says.
- **With [ADR 0028](0028-servidor-por-defecto-klav-dev.md)** (default server and moves, layer 10, 2026-11-05): the anti-*rollback* marks, the vaults seen with a signature (§1), the revoked agents (layer 03) and the audit log's pinned head (§4, by `account_id`) belong to the account, not to the host. The automatic move and `klav account set-server` (or "Use another server" on iOS) only change the URL after checking that the new host has the same account, and don't touch any of that. **They aren't deleted when changing servers:** if they were, a host with an old copy of the database (T109) could roll back the vault, serve without a signature a vault that was already seen signed, or give the key back to a revoked agent, without a warning. If the new host is an older trusted restore, the way out is `klav sync --reset-cache`, which keeps the revocations and the signatures. Signing in with "Use my own server" is another account on a device without an account: it starts without marks, and signing out (`forget_account`) deletes everything local, also 0028's `server-moved` note. On iOS, `set_server` queues with the other `klav-ffi` calls, so that a sync in flight doesn't bring the account back with the old URL.
- **Amendment to [ADR 0012](0012-daemon-klavd.md) §4** (lock on sleep, 2026-11-06): since layer 10, `klavd` detects suspension with a clock that keeps running while asleep (`CLOCK_MONOTONIC` on macOS, `CLOCK_BOOTTIME` on Linux) against the monotonic one, which stops. Where that clock exists, the wall clock no longer decides. NTP, the hypervisor or the person can adjust it without the machine sleeping, and locking because of that only gives false locks. The rule of the rollback of more than 1 s existed so that a backward adjustment wouldn't hide a suspension from the wall check; against the clock that runs while asleep, a suspension can't be hidden. The wall rules (a forward jump of more than the awake time + 20 s, a rollback of more than 1 s) stay as a fallback on a system without that clock. When it locks on its own, `klavd` writes the time and the reason to its stderr (`$KLAV_HOME/klavd.log`), with nothing about the account.
- **`diseno.md`:** §5.4 and §10 stop saying that `reveal` is the only way a value reaches the LLM.
- **Roadmap:** section "Ronda de seguridad (2026-11-05)", with one box per layer (01–12). The current phase doesn't change.

## Rejected alternatives
- **Also signing the vault version** (§1): it would force a new signature on every rename and protects nothing T7 doesn't already cover.
- **TOFU only with the vault in the cache, and asking for confirmation on a new device** (§1): it closes residual 32 better, but adds a new screen and command for a case that only happens once per device and per old vault. It can be added later without changing the format.
- **`inject` in `ask` by default** (§2): it breaks the agents' central flow and leads to approval fatigue. It is better to close the concrete paths and write down the residual.
- **Showing the patch in the `update` approval** (§7, option A): it doesn't cover `allow` or tasks, and requires binding the approval to the body, with a new signed format. B also protects the person's autofill, which is where the damage is.
- **Marking in the blob itself which URL an agent added** (§7): the agent writes the whole blob and could remove the mark. Authorship has to come from outside the blob.
