# `klavd`: local daemon and its protocol

`klavd` keeps an account unlocked in memory, so that `klav` and the
browser extension ([`extension.md`](extension.md)) don't ask for the
master password on every command. It locks again:

- after a time without use;
- when the machine goes to sleep.

On macOS it also unlocks with Touch ID (§6). The decision is in
[ADR 0012](decisiones/0012-daemon-klavd.md).

## 1. Usage

```sh
klav unlock                 # arranca klavd si no corre y lo desbloquea
klav unlock --idle-lock 5m  # tiempo de inactividad al arrancarlo (por defecto 15m)
klav status                 # "daemon: unlocked with password (pid …), locks in 14m"
klav lock                   # bloquea ya
klav lock --stop            # bloquea y detiene klavd
klav --no-daemon item ls    # ignora klavd (o KLAV_NO_DAEMON=1)
```

- If `klavd` is running, every `klav` command goes through it.
- If it is locked, `klav` asks for the password and unlocks it, for that
  command and the ones after it.
- If it isn't running, `klav` unlocks in its own process (direct mode) and
  forgets it when it ends.

`klav unlock` looks for `klavd`:

1. first, next to the `klav` binary (if `klav` is a symbolic link, next to
   its target: the Mac app's `/usr/local/bin/klav` starts the `klavd` in
   `Klav.app/Contents/Helpers`);
2. then, in the `PATH`.

It starts it in its own process group, so `Ctrl-C` in the terminal doesn't
stop it. It writes its errors, and the reason each time it locks on its own, to
`$KLAV_HOME/klavd.log`.

### Starting it at login

This is optional: `klav unlock` starts it when it's needed. The Mac app
registers it itself as a LaunchAgent with `SMAppService` ([macos.md](macos.md)
§3); what follows is for an install without the app.

`--if-not-running` exits successfully, without starting another one, if a
`klavd` already answers on the socket of this `KLAV_HOME`. That way a
LaunchAgent with `KeepAlive` doesn't retry forever when another `klavd` (one
from `cargo install`, or the one `klav unlock` started) got there first.

**macOS** (`~/Library/LaunchAgents/dev.klav.klavd.plist`, and then
`launchctl load -w` on that file):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.klav.klavd</string>
  <key>ProgramArguments</key>
  <array><string>/usr/local/bin/klavd</string><string>--idle-lock</string><string>15m</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
</dict>
</plist>
```

**Linux** (`~/.config/systemd/user/klavd.service`, and then
`systemctl --user enable --now klavd`):

```ini
[Unit]
Description=Klav daemon

[Service]
ExecStart=%h/.cargo/bin/klavd --idle-lock 15m
Restart=on-failure

[Install]
WantedBy=default.target
```

## 2. Security

| Measure | Detail |
|---|---|
| **Socket** | `$KLAV_HOME/klavd.sock`, mode 0600, inside a 0700 directory |
| **Access control (T32)** | A connection is accepted only if the peer's UID (`getpeereid` on macOS, `SO_PEERCRED` on Linux) is that of the user running `klavd`. Any other is closed without an answer |
| **One daemon per `KLAV_HOME`** | An exclusive lock on `klavd.lock`. An orphaned socket from a daemon that died is replaced when the new one renames its socket into place |
| **Idle lock (T31)** | After `--idle-lock` with no requests that use the account, the unlocked state is forgotten. Only a request that worked and hands out or changes something counts as use; listing and reading state doesn't, so a client that polls doesn't keep `klavd` unlocked (which requests count: end of this section) |
| **Lock on sleep** | Every 2 s it compares the monotonic clock, which doesn't advance during sleep, with one that does (`CLOCK_MONOTONIC` on macOS, `CLOCK_BOOTTIME` on Linux). If the second gets more than 20 s ahead of the first, it locks. The wall clock doesn't count: NTP, the hypervisor or the person adjust it without the machine sleeping, and a sleep can't hide from those two clocks. Only on a system without the clock that advances during sleep does the wall clock decide: a jump forward of more than 20 s over the monotonic clock, or a jump back of more than 1 s, which could hide a sleep. The check runs in its own task and waits for no request: one that has been waiting a minute for the network doesn't delay the lock |
| **Locking doesn't wait** | `status` and `lock` don't wait for requests in progress (ADR 0030 layer 10). A request that ends after a `lock` doesn't leave the account open: its result is thrown away and it answers `locked` |
| **Screen lock** | macOS only (§6): it locks when the screen locks |
| **Not dumpable (Linux)** | At start-up `klavd` calls `prctl(PR_SET_DUMPABLE, 0)`: another process of the same user can't `ptrace` it or read `/proc/<pid>/mem`, whatever Yama's setting is (ADR 0041 §8). On macOS a signed build's hardened runtime does the same; a `klavd` from `cargo install` doesn't |
| **Proves its socket before it takes the path** | `klavd` binds its socket as `klavd.new` in the same directory, a name no client uses, reads its device and inode, connects to it, and waits for a connection from its own pid. A connection from another process accepted before that one is closed without an answer, also when such connections filled the backlog and `klavd`'s own connect was refused: it drops what is queued and tries again, for up to 10 s. Only then does it rename the socket to `klavd.sock`. A connection queued at `klavd.new` after `klavd`'s own stays queued, and is served like any client's once the socket is `klavd.sock`. A client that connects while `klavd` starts finds nothing, or an orphaned socket nobody answers, and tries again; it never stops the start (ADR 0041 §8) |
| **Stops on its own** | If its directory (and with it the socket) disappears, or if the socket path names anything but its own socket file: every 2 s `klavd` reads the path, without following a symbolic link, and compares its device and inode with those it proved at start-up (ADR 0041 §8). A relay that renames the socket away and binds its own there, or leaves a symbolic link to it, stops `klavd`, which then leaves that path alone. A swap put back between two checks isn't seen, and the directory isn't watched |
| **Logs nothing about the account** | Neither requests nor responses. To stderr it writes only startup errors; when it locks on its own, the time and the reason: idle, sleep, a jump forward or back of the wall clock (without the clock that advances during sleep) or a locked screen; about pauses (§3), one decided while locked that has now been signed, one the server rejected for good or doesn't support, or a `local-pauses.json` or `signed-pauses.json` it can't read or write; and an `account-deletion.json` it can't read or write (§3, Deleting the account) |

Requests and responses can carry secrets: the password in `unlock`, revealed
values and the values resolved for `run`/`inject`. That is why only the same
user sees them. Both sides keep the lines in buffers that are zeroed
(`zeroize`). The intermediate copies `serde_json` makes can't be guaranteed
(T33).

Before ADR 0041's gate, any process of that user got values from an
unlocked `klavd` with no presence (`view` with `reveal`,
`previous_password`, `totp`, `generated_value`, `resolve`, `autofill`); it
may still `extension_attach`, and the peer's executable only words the
Touch ID dialog (§6.1). [ADR
0041](decisiones/0041-presence-for-values-and-the-inject-card.md),
accepted on 2026-11-17, asks for presence once per window
and per key (a terminal session, the browser, a parent process, or the
connection) before those operations. The Mac app reads until Klav locks
only on a connection where its `unlock`, or the gate's window
verification, followed `hold`, not because of its code signature: what
the kernel says about the peer doesn't prove which code it is (ADR 0041 §1.1, §1.2). With the setting on Always,
every value asks, the app included. The gate is on since layer 6; layers
2–5 built it off, behind a hidden `--presence-gate` flag that is gone.
Clients still tell from `status` (§5) whether the `klavd` they talk to has
it: an older one, or one of layers 2–5, does not. `hold` still answers
`not_supported` (below). The gate, below §3.

`mlock` is postponed (ADR 0013): an attacker who reads swap can already read live memory.

### What counts as use for the idle lock

A request counts only if it worked. Which ones count is decided in one
place in `klavd` (`counts_as_use`, which names every operation), and a
test holds these three lists equal to it:

- **Not use** (they only list or report state, hand out no secret value and change nothing): `status`, `vaults`, `projects`, `list`, `suggest`, `passkey_candidates`, `agents`, `agent_labels`, `approvals`, `tasks`, `task_log`, `task_progress`, `secret_requests`, `agent_exposure`, `agent_revocations`, `grant_editor`, `grant_change_prepare`, `proxy_status`, `proxy_grant_preview`, `proxy_issuer_preview`, `audit_log`, `audit_status`, `item_activity`, `sandbox_list`, `sandbox_list_flagged`, `sandbox_list_checked`, `generator_history`, `password_history`, `import_preview`, `extension_attach`, `extension_reply`, `extension_presence`, `browser_tab`, `hold`
- **Use only when it changes the setting** (asking for the setting is not use): `health_settings`, `passkey_uv`, `presence_window`
- **Use** (everything else: it returns a secret value or a decrypted field, signs, approves or denies, writes to the vault, to the server or to this device, unlocks or locks, or fills): `unlock`, `lock`, `shutdown`, `sync`, `reset_cache`, `create_vault`, `create_project`, `set_project_repos`, `view`, `create`, `edit`, `trash`, `totp`, `resolve`, `autofill`, `passkey_get`, `passkey_create`, `attach`, `approve_agent`, `deny_agent`, `set_agent_label`, `decide_approval`, `decide_task`, `add_to_task`, `end_task`, `fulfill_secret_request`, `deny_secret_request`, `revoke_agent`, `grant_change_apply`, `proxy_use`, `proxy_grant`, `proxy_revoke`, `proxy_issuer_add`, `proxy_issuer_remove`, `pause_agents`, `resume_agents`, `confirm_presence`, `cancel_account_deletion`, `verify_audit`, `sandbox_revoke`, `audit_reset`, `generator_record`, `generated_value`, `generator_delete`, `previous_password`, `vault_health`, `import_add`, `import_apply`, `import_cancel`, `browser_fill`, `agent_passkey_arm`, `agent_passkey_use`, `agent_rotate_begin`, `agent_rotate_confirm`, `agent_rotate_cancel`, `agent_rotate_pending`, `resolve_pending`, `reused_offer`, `offer_task`

`health_settings` counts with `breach_check`, and `passkey_uv` and `presence_window` with
`window`. `view` counts without `reveal` too: it opens one item's fields,
while `list` gives only what a row shows (title, username, sites, tags),
never a secret value. Some are use because they are hard to place: `sync`
writes this device's copy, `verify_audit` signs the log's head,
`vault_health` and `reused_offer` decrypt every password to compare them,
`confirm_presence` asks for Touch ID, the imports are kept in `klavd`'s
memory, and `agent_rotate_pending` uses up the agent's signed request.
`sandbox_list`, `sandbox_list_flagged` and `sandbox_list_checked` verify
the audit log as `verify_audit` does and can post this device's signed
head of it, as before; they still don't count. A key change the person
asked for with `revoke_agent` and `background` counts at each step, as
part of that request; resumed at unlock, it doesn't (§3). Nothing else
moves the clock: `locks_in_secs` in `status` (§5) is the time left.

A client that refreshes a one-time code (`totp`) or reopens an item
(`view`) on its own keeps `klavd` unlocked while it does: those requests
hand out a value. The Mac app's vault list does it for every login with a
one-time code it shows, and the extension's popup while it is open.

## 3. Protocol, version 1

Line-delimited JSON (`\n`) over the Unix socket, in both directions.

`klav`, `klav-native-host` and the Mac app speak it
([ADR 0027](decisiones/0027-app-de-mac.md) §3). The client side is in
`klav-daemon::client` and `klav-daemon::protocol`; without the `server`
feature (on by default), `klav-daemon` is only that client, without the
Touch ID *shim*, the QR reader or the command line. That is how `KlavFFI`
uses it for the Mac app's `DaemonEngine`, with one connection per request: a
long wait, such as a Touch ID unlock, doesn't hold up the menu bar's
state.

- The client sends a request and waits for its response before sending the
  next one.
- A connection can carry many requests.
- A line is at most 100 MiB.

```text
→ {"v":1,"id":7,"request":{"op":"view","query":"GitHub","reveal":false}}
← {"v":1,"id":7,"ok":{ … ItemView … },"warnings":["offline (…); using the local copy"]}
← {"v":1,"id":8,"error":{"code":"locked","message":"klavd is locked: run `klav unlock`"}}
```

- **`v`:** protocol version. `klavd` rejects any other with `bad_request`.
  An incompatible change bumps the version. A new optional field doesn't.
- **`id`:** a number the client picks and the response repeats. It is `0` if
  the line couldn't be read. The error message never repeats the input.
- **`request`:** an object with `op` and its arguments. Unknown fields are
  rejected.
- **Response:** carries `ok` (the result) or `error`, and optionally `warnings`
  (warnings the client shows on stderr).
- **The presence gate's three envelope fields** (ADR 0041, layer 3; all
  optional, and sent only to a `klavd` whose `status` has `presence`,
  because a `klavd` from before layer 3 answers an unknown envelope field
  with `bad_request`). A `klavd` of layers 3–5 read all three with its
  gate off too, and ignored them there; no client of this repository sends
  them to such a `klavd`:
  - **`notify: true`** asks for a notice before a Touch ID dialog this
    request causes. Just before the dialog, `klavd` writes
    `{"v":1,"id":7,"notice":"touch_id"}`, with the request's `id` and no
    `ok` or `error`, and the answer follows as usual. The client prints
    its own terminal's name (`klav: Touch ID for the terminal ttys003`), to
    compare with the dialog's. Only with `notify`: a client that didn't ask
    never gets a notice, so an older CLI, the Mac app and the extension
    read answers as before. The Rust client refuses a notice it didn't ask
    for, one with another `id`, or more than four.
  - **`shown`** (`always`, `5m` or `unlocked`), on an `unlock` with
    `password`: the window the client's own question said the password
    opens (`always`: none). `klavd` opens it only if it is what it would
    open now, and otherwise none (§3, the gate, `unlock`).
  - **`untyped: true`**, on an `unlock` with `password`: the client didn't
    read this password on its terminal (stdin, a pipe, a program that
    keeps it). The unlock then opens no window, whatever
    `shown` says, and isn't the passkey verification of ADR 0020 §8 for
    the caller's key (Omar's decisions 4 and B of 2026-11-19). Missing
    means typed, as every client sent before. It is the client's own
    word, which `klavd` doesn't check (Omar's decision I of 2026-11-19):
    the CLI sends it with `--password-stdin`; the Mac app and the
    extension send nothing, because the person types into their own
    window. Without the gate it is ignored.

### Operations

The types are those of `klav-client::ops`; bytes are base64url without
padding.

| `op` | Arguments | Result | Locked |
|---|---|---|---|
| `status` | — | `DaemonStatus` (§5) | yes |
| `unlock` | `password?`, `passkey_flow?` | `DaemonStatus` (without `password`: Touch ID, §6). Only the extension's *background* sets `passkey_flow`, for the passkey frame (verification window, below) | yes |
| `lock` | — | `DaemonStatus` | yes |
| `shutdown` | — | `{}` and the daemon exits | yes |
| `sync` | — | `SyncReport` | no |
| `reset_cache` | — | `SyncReport`. Forgets the local copy and the *rollback* marks and downloads everything again (`klav sync --reset-cache`). Keeps the revocations and the vault key signatures | no |
| `vaults` | — | `[VaultSummary]` | no |
| `projects` | `vault?` | `[ProjectSummary]` | no |
| `create_vault` | `name` | `{}` | no |
| `create_project` | `vault?`, `name` | `{}` | no |
| `set_project_repos` | `vault?`, `project`, `repos` | `ProjectSummary` (normalized `host/owner/repo` links in encrypted project metadata, ADR 0032 §2) | no |
| `list` | `filter` (`vault?`, `project?`, `kind?`, `kinds?`, `codes?`, `tag?`, `query?`, `trash`). `kinds` is several kinds added to `kind`; `codes` keeps only the items with a one-time code, of any kind (it opens their details once per version) | `[ItemSummary]` | no |
| `view` | `query`, `reveal`, `password?` | `ItemView` (secrets only with `reveal`). No presence, also with `reveal` | no |
| `create` | `item` (`NewItem`: `kind`, `title`, `vault?`, `project?`, `fields`, `urls`, `tags`, `notes?`, `allow_duplicate?`) | `ItemSummary` | no |
| `edit` | `query`, `patch` (`ItemPatch`; `allow_duplicate` to rename to a title that already exists) | `ItemSummary` | no |
| `trash` | `query` | `ItemSummary` | no |
| `totp` | `query`, `field?`, `password?` | `{code, remaining}`. No presence | no |
| `resolve` | `references`, `password?` | `[{reference, canonical, kind, value}]`; a file field comes downloaded. No presence, and no `klav.toml` trust question: that one is only in the CLI's `klav run` | no |
| `suggest` | `url` | `Suggestions`: `host` and the logins whose site matches the page; in `codes`, the codes on their own (kind `totp`) whose issuer or title names the page's domain (`site::issuer_names_page`: only its last two labels, T186) or whose confirmed URL matches; plus cards and identities (metadata only). An older `klavd` sends no `codes`: none | no |
| `autofill` | `item` (ID), `url`, `part` (`all` or `totp`), `password?` | `{id, kind, title, fields: [{name, kind, value}]}`. A login whose site doesn't match `url` answers `denied`. No presence | no |
| `attach` | `query`, `field`, `file_name`, `content` | `ItemSummary` | no |
| `passkey_candidates` | `origin`, `rp_id?`, `allow_credentials` | `{rp_id?, candidates: [{item, title, user_name, credential_id, vault}]}`: the passkeys for that rpId, filtered by `allowCredentials`. With no `rp_id` in the response, the origin or the rpId isn't valid (§14.9 of the spec) and the extension passes the call to the browser. Metadata only | no |
| `passkey_get` | `origin`, `rp_id?`, `challenge`, `item`, `password?` | `PasskeyAssertion` (`credential_id`, `client_data_json`, `authenticator_data`, `signature`, `user_handle`, `item`), in base64url. It checks the rpId and that `item` is a candidate **before** asking for presence; if not, `denied` or `not_found` | no |
| `passkey_create` | `request` (`PasskeyCreateRequest`: `origin`, `rp_id?`, `rp_name?`, `user_id`, `user_name`, `user_display_name?`, `challenge`, `exclude_credentials`, `item?`, `replace`, `vault?`, `project?`), `password?` | `{status}`: `created` with `PasskeyRegistration` (`credential_id`, `client_data_json`, `attestation_object`, `authenticator_data`, `public_key` SPKI, `public_key_algorithm`, `transports`, `item`, `title`); `browser` if the rpId isn't valid; `excluded` if Klav has one of `exclude_credentials`; `exists` (`item`, `title`) if there is already a passkey for that account and `replace` didn't come | no |
| `agents` | — | `[AgentView]` (with the six words and the verified grant) | no |
| `agent_labels` | — | `AgentLabels` (person-owned E2E-encrypted labels and machine/host notes, ADR 0047 §1) | no |
| `set_agent_label` | `agent`, `label?`, `host?` | `AgentLabels` (sets or clears the person-owned label/host for `agent`, ADR 0047 §1) | no |
| `approve_agent` | `agent`, `grant` (`projects`, `vaults`, `policy`), `pairing_code`, `password?` | `AgentView`. Only for a pending registration: with an active agent it answers `invalid` and points to `grant_change_prepare` (ADR 0033, amendment of 2026-11-10, F4; T187). It checks the projects, the agent's state and its words before asking for presence | no |
| `grant_editor` | `agent` | `GrantEditor`: the current grant of an active agent in the apps' editor model (`editable: true`, with `editor`: permissions, `fill` sites, schedule and expiry), or `editable: false` with the reason (`not_active`, `no_grant`, `unreadable`, `proxy`, `issuer`, `rules`) and the signed policy, to show it in words. No presence | no |
| `grant_change_prepare` | `agent`, `change` (`GrantChange`: `projects`, `vaults?`, `policy` as `{"editor": …}` or `{"rules": Policy}`, `rotate_removed`) | `GrantChangePreview`: only the differences, one per line (`lines`, each with `kind` and `widens`), `widens`, `digest`, `removed_projects`, `rotate_removed` and `warnings`. It syncs and reads and verifies the current grant itself; it doesn't sign. `invalid` if nothing changes, if the agent isn't active or if it is the proxy's grant | no |
| `grant_change_apply` | `agent`, `change` (the same one), `digest` (that of the sheet that was shown), `password?` | `GrantChangeReport` (`agent` with the new grant and, with `rotate_removed`, `rotated`, `regranted`, `not_regranted`, `failed`, `pending`). It syncs and verifies the current grant again, rebuilds the sheet and doesn't sign if the digest is no longer the one that came (`security`: "the grant changed while you were looking at it"). It asks for presence only if the change widens, as `klavd` computes it (P8) | no |
| `agent_revocations` | — | `[PendingRevocation]`: the key changes this device owes, from the sealed record (`revocations.bin`): `agent_id`, `name`, `projects`, `rotated`, `pending`, `regrants` (projects already rotated whose other agents are waiting for a grant), `unknown_projects`, `narrowed` (projects taken away from an active agent, not a revocation), `items` (items shared one by one without a new key), `log_unchecked` (the audit log hasn't been read yet), `without_key_change` (a revocation without a key change: only the keys of the items shared one by one change), `skipped` (`vault/project: reason` or `item <id>: reason` for what ended up out of reach: a deleted vault or one the server no longer lists, a deleted project, an item this device no longer sees) and `last_error`. A revocation without rotation shows only while it still has items left, out of reach ones included. An item out of reach changes key if it reappears; a purged one never comes back (sync rejects a purged item that reappears), so an entry with only purged items keeps showing, with `needs_work` false: `klavd` doesn't resume it. A record that doesn't open is an error (`internal`), never an empty list. No presence | no |
| `deny_agent` | `agent` | `{}` | no |
| `approvals` | `all` | `[ApprovalView]`; with `task` (`id`, `task`, `expires_at`, `can_add`) when there is a current task of the same agent and the request falls outside it (ADR 0021 §6), `request_digest`, the hex SHA-256 of the exact bytes of the request the card was built from, and `target_name?`, the target's short name for the Touch ID dialog (the item's title, or `vault/project` without an item; missing if this device doesn't have the item) | no |
| `decide_approval` | `approval` (ID or prefix), `approve`, `digest` (the `request_digest` of the card that was shown), `lease_secs?`, `password?` | `ApprovalView`. If the request the server returns on deciding doesn't give that digest, it signs nothing and answers `security` (ADR 0030 §5) | no |
| `tasks` | `all` | `[TaskCard]`: pending and current tasks (or all recent ones), with the card this client completes (ADR 0021 §3: titles and hosts from the vault, `totp` added by Klav, a site that doesn't match, permissions the policy denies) and its `request_digest` | no |
| `decide_task` | `task` (ID or prefix), `approve`, `digest` (the card's `request_digest`), `choice` (`without`, `with`: `[[item_id, permission?]]`; `for_secs?`), `password?` | `TaskCard` with the signed decision. Like `decide_approval`: if the request changed, it doesn't sign (when denying too) | no |
| `secret_requests` | `all` | `[SecretRequestCard]`: pending (or all recent) agent secret requests (ADR 0046), with HPKE-opened proposals, validated `setup_url`, real vault metadata in `update` mode and `proposal_digest` | no |
| `fulfill_secret_request` | `request` (ID or prefix), `input` (`FulfillSecretRequest` with `digest`, `secret`, destination overrides and optional `grant_proxy`), `password?` | `FulfillSecretResult`: creates or updates the item, optionally grants `klav-proxy` access (asking for presence when `grant_proxy` is true), and posts the account-signed decision | no |
| `deny_secret_request` | `request` (ID or prefix), `digest` (the card's `proposal_digest`) | `SecretRequestCard` with the signed denial. Refuses if the request changed since shown | no |
| `add_to_task` | `approval` (ID or prefix), `digest` (the card's `request_digest`), `password?` | `TaskCard` with the new revision. "Add to the task": it signs the decision `revision + 1` with that item, permission and host added and the same `expires_at`, and approves the request once, so the agent's `approval wait` exits with 0. Only for `fill`, `totp`, `inject` and `update` on an item; `fill` only if the site matches the item | no |
| `end_task` | `task` (ID or prefix) | `TaskCard`; signs `task-end` | no |
| `task_log` | `task` (ID or prefix) | `TaskLog`: the card, its events (oldest to newest) and what the agent asked for separately while it ran (`outside`). If the audit log doesn't match the copy (`security`), the card the server lists, without events, and `log_warning` | no |
| `agent_exposure` | `agent` | `Exposure`: the grant's projects and the items it used according to the audit log. If the audit log doesn't match the copy, the projects, no items and `log_warning` with the reason | no |
| `revoke_agent` | `agent`, `rotate`, `background?` | `RevokeReport` (agent, `exposure`, `rotated`, `already_rotated`, `regranted`, `not_regranted`, `failed`, `pending`, `warnings`). It revokes and saves the revocation before looking at the audit log, even if this device can't read the agent's grant (it shows in `warnings`). The projects it rotates come from the verified grant (or the signed one the server sends) and from every `agent.granted` in the verified chain for that agent, with the account's signature checked; if the audit log can't be read, it rotates the ones it knows but doesn't finish (`log_unchecked`, and `complete()` false) until it's asked again; a server that rewrites the chain can't prevent the key change. With `background` (and `rotate`), it answers as soon as it revokes and records that rotation was asked for, with `pending` filled, and rotates in the background; `status` follows it. An older `klavd` rejects `background` (`bad_request`) without doing anything. With `rotate`, it rotates one project at a time and lets go of the account between one and the next (below, Revoking with a key change). Called again with `rotate` on an agent already revoked, it finishes what's left without rotating twice. If the audit log can't be read, `exposure` comes out without items and with `log_warning`, and it isn't an error | no |
| `pause_agents` | `agent?` (ID; without it, all), `until?` (Unix milliseconds) | `[PauseInEffect]`, as in `status`. No presence. Pausing, below | only without `agent` |
| `resume_agents` | `agent?`, `password?` | `[PauseInEffect]` still in effect. Asks for Touch ID (or `password`). Pausing, below | no |
| `confirm_presence` | `purpose` (`delete_account`) | `{ok: true}`. It only asks for Touch ID: it opens the Secure Enclave key and lets it go, without unlocking anything. It is the Touch ID step of `klav account delete`; the password and the deletion go from the `klav` process, never through `klavd`. Without Touch ID set up, `biometry_unavailable`. Deleting the account, below | yes |
| `cancel_account_deletion` | `password?` | `{canceled}`: cancels the deletion of the account (`false` if there wasn't one). Asks for Touch ID (or `password`), like `resume_agents`: canceling gives the agents back. Deleting the account, below | no |
| `audit_log` | `filter` (`item?`, `agent?`, `vault?`, `since?`, `until?`, `alerts`, `task?`, `permissions?`, `outcomes?`, `text?`, `limit?`) | `[LogLine]`, newest to oldest; with `limit`, only the N newest that pass the other filters (an older `klavd` ignores it, and the caller cuts again). Each line carries `by_agent`: an agent wrote it, not the person; that is what tells them apart, not the `actor` (`you` or the name, and an agent can be called `you`). A line with an agent the server lists carries its name in `agent_name`: for the person's `agent.granted`, who the grant was for. `permissions` is a list of permissions (`fill`, `inject`, `totp`, `reveal`…); `outcomes`, of `allow`, `ask`, `deny` and `approve`; `text` searches, case-insensitively, in the item (its reference with the title, resolved on this device), the agent, the reason and the site. Each line carries `verified`: it is in the last event this device verified, or before it (ADR 0033 §8.1). It downloads only what's new (the cached chain, below) | no |
| `verify_audit` | — | `VerifyReport` (with `warnings` if something was left unchecked). It downloads the whole chain, verifies it, requires that it keep what this device had already downloaded, saves it as the local copy, signs the head unless this device already signed that same head, and saves it in `audit-head.json` with the `account_id`; `signed_head` is the head this device has signed, now or in an earlier verification | no |
| `audit_status` | — | `ChainStatus`: `events` (the last event this device downloaded; 0 with none) and `verified?` (the last one it verified). No network: it answers without syncing first | no |
| `audit_reset` | — | The files it forgot (`["audit-chain.bin", "audit-head.json"]`, or the ones there were). `klav log reset`: forgets the copy of the audit log, the one in memory too, and the verified head, for a server restored from a backup the person trusts. From then on this device accepts the chain the server has (below). No network and no presence; the extension can't ask for it | yes |
| `sandbox_list` | — | `SandboxList` (ADR 0036 E2.1): `sandboxes`, every sandbox in the verified chain issued by a proxy whose signature the chain vouches for (a proxy it does not vouch for leaves none), oldest first (`sandbox_id`, `proxy_id`, `issuer_id`, `issuer_name?`, `label`, `profiles`, `issued_at`, `expires_at`, `claimed_at?`, `status`: `waiting`, `active`, `revoking`, `expired`, `ended`, with `end_reason?` and `ended_at?`, or `proxy_revoked`, with `proxy_revoked_at?` (the account's signed `agent.revoked` of its proxy is in the verified chain after the sandbox's issue and that proxy logged no end, which it never can; not live, never ended); a reader takes a status, end reason or `no_signs` it does not know as `unknown`, and an unknown status as live, never ended, `revoked_by_person_at?`, and `connected?` and `last_seen_at?` from the heartbeat); `proxy?`, the account's own proxy with its last heartbeat that counts (`agent_id`, `name?`, `paused`, `heartbeat_sent_at?`, `heartbeat_age_ms?`, `quiet`, `no_signs?`: `no_heartbeat`, `no_epoch`, `other_epoch`, `ahead`, `version` or `rollback`); `verified_events`, `warnings` and `marks_unreadable`. It reads the heartbeat watermark of `sandbox-marks.bin`, then `GET /v1/sync`, then verifies the whole chain as `verify_audit` does, and stores the new watermark. `security` on tampering, on a heartbeat the proxy did not sign, when the server does not list the proxy the account's setting names, or when an agent wrote the preferences (as in every `klavd`: an app that cannot show `sandbox_list_flagged`'s flag never gets a list without it); preferences this device cannot read give the rows of every proxy, no `proxy` and a warning. The apps and the CLI show only the account's proxy's rows unless asked for all. The extension can't ask for it. An older `klavd` answers `bad_request` | no |
| `sandbox_list_flagged` | — | The same `SandboxList`, for a caller that shows a security flag: when an agent wrote the account's preferences, instead of a `security` error it gives the rows of every proxy, no `proxy`, and `security`: `{"kind": "preferences_by_agent", "agent_id"}` (never in `warnings`). A reader takes a `kind` it does not know as `unknown`, still a security problem. The caller shows it as one (the CLI exits 3) and offers `klav proxy use`, which replaces those preferences whole after presence, using nothing in them. Every other failure is `sandbox_list`'s. A `klavd` older than it answers `bad_request`: the caller then asks `sandbox_list`, which fails closed. The extension can't ask for it | no |
| `sandbox_list_checked` | — | `CheckedList`, for a caller that says in its own words which check refused the list: `{list}` with `sandbox_list_flagged`'s list, or `{refused: {check, message}}` instead of its `security` error. `check` is `{"kind": "unlisted_proxy", "agent_id"}` (the account's proxy setting names an agent the server does not list), `{"kind": "proxy_heartbeat", "agent_id"}` (a heartbeat of the account's proxy that the proxy did not sign, or that is not one) or `{"kind": "log"}` (the account's log did not verify); `message` is the same English text that error carries, for the CLI and as a last resort. A reader takes a `kind` it does not know, or a `refused` whose `check` does not decode (a known `kind` without its `agent_id`, or no object at all), as `unknown`, still a refusal, with `message` empty when it is missing; an answer with both takes the refusal, and one with neither `list` nor `refused` is a refusal too. Any other failure, a `security` one of no known check included, is `sandbox_list_flagged`'s error. A `klavd` older than this answers `bad_request`: ask `sandbox_list_flagged` then, which fails with `security`, so the list is never shown | no |
| `sandbox_revoke` | `proxy` (agent ID), `scope`: `"all"` (every sandbox of `proxy` issued so far) or one sandbox ID. Required: without it, or with anything else, `bad_request`, and nothing is revoked | `RevokeOutcome`: `{outcome: "revoked", revocation}` (the signed `SandboxRevocation` as the server stored it, with the sandboxes the server says it covers: for one sandbox `klav-client` requires exactly that one, or fails with `security`), or `{outcome: "not_applied", proxy_id, scope, later_at}` when the server has a revocation of the same proxy and scope signed later, too far ahead of this device's clock (ADR 0036 E2.3). Signed with the account's identity, without presence: it only takes access away. The answer is the signed revocation as the server says it stored it, and the server says it denies the sandboxes from then on; what proves each one stopped is its end, signed by the proxy in the verified log, later. The extension can't ask for it. An older `klavd` answers `bad_request` | no |
| `item_activity` | `item` (ID, reference or search) | `ItemActivity` ("Who used it", ADR 0033 §8.1): `item_id`, `reference?`, `trashed`, `deleted` (no longer on this device) and `uses`, the agents' events on the item, newest to oldest. Each use is a `LogLine` with `how` (`policy`, `approved_once`, `approved_for`, `task`, `asked`, `denied` or `other`), `lease_until?` and `approved_at?` (with an approval) and `task?` (the task's title, in the agent's words) | no |
| `generator_record` | `value`, `host?` | `{created_at}`. Saves a generated password in the local queue (`0x43`) and syncs it to disk before answering; it works without network | no |
| `generator_history` | — | `[GeneratedView]` (`created_at`, `host?`, `saved_in?`, `saved_in_title?`, `pending`), newest to oldest; no values | no |
| `generated_value` | `created_at`, `password?` | The value of that entry. No presence | no |
| `generator_delete` | `which` (`{"some": [created_at…]}` or `"all"`) | `{removed}`; it also purges the versions of the item that kept them | no |
| `password_history` | `query` | `PasswordHistoryView`: `entries` (`index`, `field`, `label`, `from_ms?`, `to_ms`, `unconfirmed`), newest to oldest, `pending` and `pending_since?`; no values. `unconfirmed` marks a password that an assisted change generated and nobody confirmed | no |
| `previous_password` | `query`, `index`, `password?` | The value of that previous password. No presence | no |
| `vault_health` | — | `VaultHealth` (ADR 0022 §4): `items`, `passwords`, `skipped?`, `reused` (groups of `items`), `weak` (`item`, `score`, `generated_bits?`), `old` (`item`, `since_ms`, `days`, `source`: `record` or `created`) and `breaches` (`status`: `off`, `checked` with `found` and `queries`, or `failed` with `message`). Each `item` carries ID, reference, title, username, `hosts` and field; never values. The Have I Been Pwned lookup runs only if `health.json` turns it on, and outside the session's lock | no |
| `extension_attach` | `browser` | `{}`. The connection is now an extension's: it receives events (below). No presence to attach: any process of the same user may. An agent's values ask for this connection's presence (below, the gate) | yes |
| `extension_reply` | `event`, `ok?` or `error?` | `{}`. Answers an event of this connection. A `presence` event takes only an `error` (the person declined): its `ok` is `extension_presence`, and an `ok` here is `bad_request` | yes |
| `extension_presence` | `event`, `password` | `{}`. The master password for this connection's `presence` event `event` (the gate, below), checked against the unlocked session. Wrong: `wrong_credentials`, and the event keeps waiting for another. Only on the connection the event went to; any other, or an event no longer waiting: `not_found` | yes |
| `browser_tab` | — | `BrowserTab`: `{tab, url, browser}` of the active tab of the browser with the focus | yes |
| `browser_fill` | `tab`, `host`, `agent`, `agent_id?`, `item?`, `reason`, `kind`, `fields`, `selectors?`, `submit?` | The extension's report: `{url, filled, submitted?, navigated?, url_after?}`, never values (the SDK adds `warnings?` for the person: below, Compatibility). `agents_paused` if a pause stops the agent (below). Needs the session unlocked, for the connection's presence (§3, the gate); a pause is checked first and works locked | no |
| `resolve_pending` | `query`, `accept` | The item's `PasswordHistoryView`. The person decides on the pending password of an assisted change: `accept` makes it current ("Use the new one"); if not, it goes to the history as unconfirmed ("Keep the current one"). With nothing pending, `not_found` | no |
| `agent_rotate_begin` | `tab`, `step` (`RotationStep`), `submit?` | `{filled, pending_id}` (plus `submitted?`, `navigated?`, `url_after?` with `submit`); never values. Assisted change, below | no |
| `agent_rotate_confirm` | `step` | `{ok: true}`: the pending one becomes current and the previous one goes to the history | no |
| `agent_rotate_cancel` | `step` | `{ok: true}`: the current one stays and the pending one goes to the history as unconfirmed | no |
| `agent_rotate_pending` | `step`, with a request signed for `POST /v1/agent/rotations/{id}/pending` | `{pending}`: whether the item's pending password is this change's. Read only; asked before the server gets the step. Hands out no value, and asks no presence: it needs a request the agent signed, checked as for a step (signature, age, once, the task). An older `klavd` answers `bad_request` | no |
| `agent_passkey_arm` | `tab`, `step` (`PasskeyArmStep`) | `PasskeyArmed`: `{used, rp_id, expires_in_s?}`; never the assertion. An agent signs in with one of the person's passkeys, below | no |
| `agent_passkey_use` | `tab_id`, `origin`, `rp_id?`, `challenge`, `token` | `PasskeyAssertion`, like `passkey_get`. Only the extension, with the *token* of the use armed in that tab | no |
| `passkey_uv` | `window?` (`always`, `5m` or `unlocked`), `password?` | `{window}`: the passkey verification window of this `KLAV_HOME`, sealed in `passkey-window.bin` (the gate, below), after changing it if `window` comes. Loosening it asks for Touch ID (or `password`) and opens nothing; tightening it, nothing | no |
| `presence_window` | `window?` (`always`, `5m` or `unlocked`), `password?` | `{window}`: the presence setting (the gate, below), after changing it if `window` comes. Loosening asks for Touch ID (or `password`) and opens no window; tightening asks nothing and shortens open windows at once. A `klavd` of layers 2–5 with its gate off answers `not_supported`. The extension can't ask for it | no |
| `hold` | — | `{declared, held}`: declares this connection held (the gate, below). Today it always answers `not_supported`: on macOS until Omar's by-hand check of layer 5 on a signed build passes, and always on Linux. The extension can't ask for it | yes |
| `health_settings` | `breach_check?` | `{breach_check, notice}`: the breach lookup setting of this `KLAV_HOME` (`health.json`), after changing it if `breach_check` comes, and what it sends | yes |
| `reused_offer` | `agent?` | `ReusedOffer` (ADR 0022 §6): `agents` (active ones with a grant, only `{id, name}`), `agent`, `rows` (the logins that share a password, sorted by host: `item_id`, reference, title, username, `hosts`, `change_url`, `group`, `permissions` and `blocked?`: `not_granted`, `no_site`, `not_login` or `other_field`) and the default title, reason and duration. Without `agent`, the only one there is. Never values | no |
| `offer_task` | `offer` (`agent`, `items`, `task?`, `reason?`, `duration_secs?`), `password?` | `TaskCard` of the offered task: `rotate` on each login, and `totp` ("Added by Klav") if it has a code and the policy doesn't deny it. It checks everything before asking for presence | no |
| `task_progress` | `task` (ID or prefix) | `TaskProgress`: the card and each site with `rotate` (`state`: `changed`, `pending` or `failed`; `started` if there is an open change; `at`). If the audit log doesn't match the copy, the card without sites and `log_warning`: where each site stands comes from the audit log | no |

The "Locked" column says whether the operation works with the daemon
locked. Those that don't answer `locked`.

The `password?` of `view`, `totp`, `resolve`, `autofill`,
`generated_value` and `previous_password` is the gate's (below): the
master password, sent after a `presence_required`. `klavd` checks it and
the operation never sees it.

**A master password as presence.** Wherever a `password` stands in for
Touch ID on an unlocked `klavd` (the gate, the operations that already ask
and take a `password`, the settings, an `unlock` while unlocked;
`confirm_presence` takes none), it
counts only if it is the password of the vault this `klavd` unlocked: with
the Secret Key, it must derive the session's local key. A password that only
opens the account files now in `KLAV_HOME` is `wrong_credentials`. If those
files were replaced, the person's own password fails too, until they are
put back. One password is checked
at a time: another that arrives meanwhile gets `presence_busy` at once.

**Agents and the extension** ([`extension.md`](extension.md) §8). The extension
attaches with `extension_attach` through `klav-native-host`; from then on,
between responses, it receives event lines, which it answers with
`extension_reply`:

```text
← {"v":1,"event":{"kind":"tab","id":4}}
→ {"v":1,"id":9,"request":{"op":"extension_reply","event":4,"ok":{"tab_id":12,"url":"https://github.com/login","focused":true}}}
← {"v":1,"event":{"kind":"fill","id":5,"tab_id":12,"host":"github.com","agent":"claude-code","reason":"…","item_kind":"login","fields":[…],"submit":false}}
```

An agent asks for `browser_tab`, checks the site and decrypts the values with
its own grant (the daemon can be locked), and sends them with
`browser_fill`. `klavd` passes them only to that tab's connection and
returns to the agent whatever the extension answers. If no browser is
attached, it answers `not_found`; if the tab is already on another site, the
extension answers `denied` and writes nothing.

`item?` (from this version on) is the item the values came from, a hint
for the presence prompt's title only (the gate, below): the agent doesn't
sign it, and nothing is checked or handed out by it. The SDK sends it and,
if `klavd` can't read the field (an older one), sends the fill again
without it.

**Pausing agents** ([ADR 0033](decisiones/0033-agentes-desde-la-app-de-mac.md) §7).
The server enforces the pause on every signed request from an agent
([`api.md`](api.md) §8.1); `klavd` is the second barrier for what it mediates.

- **`pause_agents`** doesn't ask for presence: pausing must cost nothing (P2).
  It applies the pause here first, right away; then it signs it with the
  account and sends it to the server.
  - **Locked**, pausing every agent works the same: it stays here with `local:
    true` and the warning "paused on this computer only". The next unlock
    signs it and sends it, with the time of that moment (the server only
    accepts recent decisions) and the same `until`; if it has already ended,
    it is thrown away. Pausing one agent needs the account unlocked
    (`locked`). With no account in this `KLAV_HOME` it answers `not_logged_in`.
  - **Without network, or with an error that time fixes**, it stays here
    (`local: true`) with a warning, and the watcher retries it every 30 s
    while `klavd` is unlocked. It keeps it on everything except a 4xx that
    the same pause would get again: a 5xx, an expired session, a 401,
    408 or 429, and a 409 that couldn't be resolved. With a final 4xx
    (an agent the server doesn't know) it is thrown away, with the error or,
    if nobody is waiting for the answer, a line in `klavd.log`.
  - **A server older than pauses** answers `405` to the pause of every
    agent. The pause stays here with `local: true` and `server_unsupported:
    true`, with the warning "this server does not support pausing agents
    (update it): every agent is paused on this computer only…" and a line
    in `klavd.log`. The watcher stops sending it; each unlock tries once
    more, in case the server has been updated. Meanwhile only what `klavd`
    mediates is cut off. To the pause of one agent that server answers
    `404`, as to an agent it doesn't know: they can't be told apart, and it
    is thrown away with the error.
  - **A 409 because of a later decision** on the server (another device
    with its clock ahead signed after): the body carries its `last_at`
    ([`api.md`](api.md) §8.1) and the pause is signed again at `last_at +
    1`, if that falls within the server's ±5 minutes and before its
    `until`. If not, it stays here and is retried. A resume is never signed
    again like that: dated after someone else's pause, it would lift it.
  - **It survives a `klavd` restart**: pauses waiting for the server are
    saved in `$KLAV_HOME/local-pauses.json` (0600, written atomically;
    version `v: 1`). It carries no secrets: the account, the agent, `at`,
    `until`, whether it was decided while locked and the program it came
    through. It is rewritten on every change and deleted when none is left.
    On startup, `klavd` reads it and keeps the ones for this `KLAV_HOME`'s
    account that haven't ended. If it can't read it, it starts without them
    and says so in `klavd.log`: the pauses the server already took stay in
    effect.
  - **On unlock**, a pause decided while locked that gets signed brings a
    warning for the person: "a pause of every agent was decided while Klav
    was locked (from the terminal), with no password or Touch ID; it is now
    signed and stops the agents everywhere". The origin is the peer's
    program according to the kernel (the terminal, the app, the browser or "a program
    Klav does not recognize"): a hint, not a check. The same warning always
    goes to `klavd.log`, only once: if the unlock's send fails and the
    watcher succeeds later, nobody is waiting for the answer, but it is
    written down.
  - A pause decided here is signed only by the account it was decided for.
  - An `until` that has already passed answers `invalid`.
- **`resume_agents`** asks for Touch ID (or `password`), like approving. With
  one agent, the dialog says its name. It lifts the local pause of that scope
  and signs and sends the resume. Resuming every agent doesn't lift the
  pauses of one agent: the response carries the ones still in effect. If the
  server doesn't take it, the local pause has already been lifted and the
  response says so with a warning, without an error, in two cases: without
  network, when the server has no signed pause of that scope ("offline (…):
  resumed on this computer"), and with a server older than pauses, which
  answers `405` to the pause of every agent and has none to lift ("this
  server does not support pausing agents (update it): resumed on this
  computer…"). To the pause of one agent that server answers `404`, as to an
  agent it doesn't know, and that is still an error.
- **What it rejects** with `agents_paused` while a pause stops the agent:
  `browser_fill`, `agent_rotate_begin`, `agent_rotate_confirm`,
  `agent_passkey_arm` and `agent_passkey_use` (a use armed before the pause
  isn't used after it). `browser_fill` carries `agent_id` from this version
  on; without it (an older SDK), only the pause of every agent stops it.
- **In `browser_fill`, the pause of one agent is advisory; the pause of every
  agent is firm.** The caller declares `agent_id`: `browser_fill` doesn't
  carry a request signed by the agent, so a program that talks to `klavd`
  can put in another agent's ID, or none, and get around the pause of a
  single agent. The pause of every agent doesn't depend on `agent_id` and
  stops any fill. `agent_rotate_begin`, `agent_rotate_confirm` and
  `agent_passkey_arm` carry the agent's signed request, and
  `agent_passkey_use` spends a use that was armed with one; there the agent
  is the one that signed, and both pauses are firm. That program is already
  another process of the same user facing `klavd` (threat model §6,
  T133).
- **`agent_rotate_cancel` does work** during a pause: it is the safe
  direction, because it keeps the current password and only moves the
  pending one to the history. Confirming, on the other hand, would make the
  new one current: with the pause, it stays pending and the person decides
  on the item's card (`resolve_pending`). The server rejects every signed
  request from a paused agent, so in practice only a cancellation that the
  server recorded before the pause applies. A confirmation the server
  recorded before the pause stays pending here, and the item and the log
  disagree until the pause ends and the agent retries, or the person
  decides.
- **What it knows**: the signed pauses the last sync brought or its own
  decision (only those that verify with the account's identity), plus the
  local ones. They are kept on lock, so `status` gives them and what it
  mediates stays cut off with `klavd` locked. A change bumps
  `revision`.
- **The signed ones survive a restart**: `klavd` saves the last list
  in `$KLAV_HOME/signed-pauses.json` (0600, written atomically,
  `v: 1`, with the account) and loads it on startup, only if it belongs to
  this `KLAV_HOME`'s account and the pause hasn't ended. It carries no
  secrets: the agent, `at`, `until` and the account's signature. On startup,
  `klavd` is locked and can't check the signatures, so it loads it without
  checking them: a fake file can only make it reject more, never less. On
  unlock it checks them with the account's identity and drops the ones that
  don't verify; the next sync replaces them with what the server says. Until
  then, a pause that another device lifted while `klavd` wasn't running
  still shows in `status`. It is deleted with the account (`klav logout`).
- The extension can ask for neither `pause_agents` nor `resume_agents`, like
  `revoke_agent`.
- **Compatibility:** requests reject unknown fields. Against an older
  `klavd` that is still running, an SDK or a CLI of this version sends a
  `browser_fill` that `klavd` can't read (because of `agent_id`), and it
  answers `bad_request` with `id` 0. The SDK recognizes it and repeats the fill without `agent_id`, with
  the warning "klavd is older than this klav…: restart it (`klav lock
  --stop`, then `klav unlock`)" in the report's `warnings` (in `klav mcp`,
  `warning`). That `klavd` doesn't know about pauses, so nothing is lost
  without `agent_id`. Layer 3 of ADR 0033 ships everything at once.

**Deleting the account** ([ADR 0037](decisiones/0037-borrar-la-cuenta.md)).
`klavd` doesn't delete the account and has no operation that does it (T164):
`klav account delete` asks for it, in a terminal, from its own process
([cli.md](cli.md) §3). `klavd` does three things:
- **The Touch ID step**, with `confirm_presence`, when Touch ID is set up. The
  dialog says "confirm it’s you to delete your account" (in Spanish, «confirmar que eres tú para borrar tu cuenta»). It uses the Secure
  Enclave key (`biometryCurrentSet`), so a fingerprint added after setting
  up Touch ID doesn't work. It doesn't look at the 14 days or the restart:
  those decide whether unlocking asks for the password, and here the
  password is asked for anyway, afterwards.
- **What it mediates for agents is cut off** while the deletion is pending:
  `browser_fill`, `agent_rotate_begin`, `agent_rotate_confirm`,
  `agent_passkey_arm` and `agent_passkey_use` answer `account_deleting`,
  before looking at the pauses. It is a second barrier: the server already
  rejects every signed request from an agent. `klavd` knows it from the sync
  (`deletion` in `GET /v1/sync`) or because it was canceled from here, and
  gives it in `status` (`account_deletion`), locked too.
- **It saves it for after a restart** in
  `$KLAV_HOME/account-deletion.json` (0600, written atomically;
  version `v: 1`), like the pauses: the account, the pending deletion (dates,
  the device that asked for it) and `deleted` if the server has already
  deleted it. It carries no secrets. On startup, `klavd` reads it if it
  belongs to this `KLAV_HOME`'s account, so `status` says so while locked
  even after a restart; if it can't read it, it starts without it, says so
  in `klavd.log` and learns it again on unlock. It is deleted when there is
  no longer a pending deletion. What counts is the account's sealed copy
  (`deletion.bin`, [cli.md](cli.md) §1) and the next sync: a fake file only
  makes `klavd` deny agents more and show a warning until unlock.
- **Canceling with presence** with `cancel_account_deletion`, unlocked:
  Touch ID or the master password, the same as `resume_agents` (amendment
  A2 of ADR 0037). Canceling gives the agents back, so an agent that
  reaches the person's session can't cancel to get back in.

Once the date has passed, the server no longer has the account. If `klavd`
knew the date, the sync that gets `401` stops syncing and warns in
`warnings` on every response: "Klav deleted your account on … UTC…". Reads
keep working with the local copy, read-only (also
`generator_history` and `generated_value`, to copy whatever is there), and
what it mediates for agents fails with `account_deleted`. `status` says so
with `account_deleted`.
- **Writing fails with `account_deleted`**, without network, before touching
  anything, like `writing()` in `klav-ffi`: `create_vault`, `create_project`,
  `create`, `edit`, `trash`, `attach`, `passkey_create`, `resolve_pending`,
  `generator_record` (the extension's too), `generator_delete`,
  `import_apply`, `reset_cache`, and the decisions about agents
  (`approve_agent`, `grant_change_apply`, `decide_approval`, `decide_task`,
  `add_to_task`, `end_task`, `revoke_agent`, `resume_agents`, `deny_agent`,
  `agent_rotate_confirm`, `agent_rotate_cancel`, `offer_task`). Several
  would go to the server and get its `401`, but others write on this device
  before or without network: the generator's queue, the cache that
  `reset_cache` empties before syncing (and could no longer fill again) or
  the pause that `resume_agents` lifts here first. Left out are the breach
  lookup setting (`health_settings`), the passkey window (`passkey_uv`), the
  local copy of the audit log (`audit_reset`) and pausing agents, which can
  no longer use anything.
- **Nothing is uploaded:** the generator's queue is no longer tried every 30 s,
  and signing in with a passkey doesn't send `passkey.used`. Whatever is in
  the queue stays there for the person to copy.
- **Nothing deletes the copy** (T165): the person deletes it with `klav logout`,
  which stops `klavd` first, or with "Delete this Mac’s copy"
  ([macos.md](macos.md)). Both refuse while there are generated passwords
  not yet uploaded, unless `--discard-unsent` or "Delete anyway": a site may
  hold the only other copy.

Without the date (`klavd` didn't sync in the 7 days), it is just another
expired session.

**The cached audit log** ([ADR 0033](decisiones/0033-agentes-desde-la-app-de-mac.md) §8.4).
`audit_log`, `item_activity`, `task_log` and `agent_exposure` no longer
download the whole chain on every call:
- **The copy:** `klav-client` saves the chain it downloaded in
  `$KLAV_HOME/audit-chain.bin` (0600, `v: 1`, with the account), sealed with
  the local key (spec §12.2, purpose `audit`). It also keeps it in memory
  while the account is unlocked. A file from another account is ignored; one
  that doesn't open or is of another version is ignored too, with a warning in
  `warnings`. In both cases the chain is downloaded again and the file is
  overwritten. It is deleted with the account (`klav logout`); `reset_cache`
  doesn't touch it, because it is what binds the server to what it already sent.
- **If the server was restored from a backup you trust:** `audit_reset`
  (`klav log reset`) forgets the copy, on disk and in memory, and the head
  pinned in `audit-head.json`. It doesn't use the network and works locked;
  with `klavd` unlocked it does it under the session's lock, so no view
  writes the old copy back. It means accepting the server's chain as good:
  what gave it away was exactly that.
- **What isn't the audit log doesn't wait for it:** `revoke_agent` revokes and
  rotates even if the chain doesn't match, and `agent_exposure`, `task_log` and
  `task_progress` answer with what doesn't come from it and `log_warning`.
  `audit_log`, `item_activity` and `verify_audit`, which are the audit log,
  still fail with `security`.
- **What's new:** each view asks for `GET /v1/audit?after=` from the
  second-to-last event of the copy, so the last one comes back again. That
  event must arrive identical (hash and bytes), and each new event must follow
  the chain (§13.7 of the spec). If the server says the chain is shorter than
  the copy, or returns an event it already sent differently, the view fails
  with `security` ("… it was truncated", "… the chain was rewritten").
  Rewriting an old event changes the hashes of all those that follow, so the
  next view notices without verifying anything.
- **Without a copy too:** the chain, whether from the copy or downloaded whole
  because the copy was missing or didn't open, must reach the head this
  device verified (`audit-head.json`) with the same hash. If not, the view
  fails with `security` instead of marking another chain's events as
  verified.
- **What a view doesn't do:** it checks neither signatures nor the rules of
  ADR 0030 §4 on the new events. Each line carries `verified`, and the events
  after the last one this device verified show as "Not verified yet" until
  the next `verify_audit`. Verifying on every view would sign a new head each
  time and ask for the list of agents and the other devices' heads on every
  opening.
- **`verify_audit`** still downloads the whole chain, so that each rule sees
  the bytes the server gives today. Then it requires that the chain keep the
  copy (neither shorter nor with a different event) and saves it as the new
  copy.

**Assisted password change** (ADR [0022](decisiones/0022-generador-historial-y-cambio-asistido.md) §5).
The agent never receives either the current password or the new one: `klavd`
generates, saves and types them.

1. The agent opens the change on the server (`POST /v1/agent/rotations`,
   signed with its key) and sends `klavd` `agent_rotate_begin` with a
   `RotationStep`: `agent_id`, `task_id`, `rotation_id`, `item_id` and
   `request`, the signed request as it sent it (`AgentRequestProof`:
   `method`, `path`, `timestamp_ms`, `nonce`, `body`, `signature`; SDK:
   `Agent::call_proved`).
2. `klavd` checks the signature with the agent's key that comes in its grant
   (signed by the account), that the agent is active, `POST` and the exact
   path, an age within ±5 min and that the `nonce` hasn't been used in this
   session. Then it verifies the task's signed decision: approved, current,
   of the same agent and with `rotate` for that item and the host the agent
   signed, like passkeys (ADR 0020 §9). Any failure answers
   `security` or `denied` and touches nothing.
3. A `rotate_probe` event to the tab: the extension picks the *frame* (the one
   with the focus on an `<input type=password>` and whose site matches the
   item; if not, the main one) and returns a `RotateTarget` with the address
   the browser gives for that *frame* and the field's rules
   (`passwordrules`, `minlength`, `maxlength`). `klavd` checks that
   address against the item's host and addresses (T61).
4. It generates the new password with those rules (or the bundled ones for the
   site) and writes a new version of the item with it as pending in
   record `0x16` (`rotation_id`). If that write fails, it fills
   nothing. If the current password changed since step 2, it answers `invalid`.
   Before that, still in step 2, it refuses (`invalid`) while the item holds
   the pending password of another change under the same task: the server
   may have that one recorded as confirmed already. The server has recorded
   the new start by then, so the agent's runtime cancels it at once: the log
   shows a `rotate.started` and `rotate.cancelled` pair for the refused
   change, which never touched the item. A pending password of another task
   is replaced, even one whose confirm the server recorded and `klavd` did
   not apply: the item then keeps the old password while the log says
   confirmed, and the new one is in the history, unconfirmed.
5. A `rotate_fill` event to that *frame*: the current one in "current
   password", the new one in the field with the focus (or in "new password")
   and in "confirm"; only in `<input type=password>`. The extension returns
   the roles it filled (`current_password`, `new_password`,
   `confirm_password`). If this step fails, the pending one stays and the
   error message asks the agent to cancel (`ROTATE_KEPT_PENDING`; the SDK
   cuts that hint once the server has the change closed, by the SDK's own
   cancel or already before it).
6. Depending on what the site answers, the agent closes the change in three
   calls:
   1. It asks `klavd` whether the item's pending password is this change's
      (`agent_rotate_pending`, read only), with a request of its own signed
      for `/v1/agent/rotations/{id}/pending`, a path the server has no route
      for. If it isn't (the person decided already, an older client applied
      the step, or it was never stored), nothing goes to the server. The
      exception is the `cancel` the agent's runtime sends when `klavd` did
      not fill: the server closes that one anyway. With `klavd` locked, the
      question fails and the server receives nothing.
   2. It signs the close and sends it to the server. A refusal (a pause, a
      revocation, a deletion request, a stale signature) changes nothing in
      the item, so the card and a retry still work. The server's `409` for
      the same outcome means an earlier call recorded it: the agent goes on
      to step 3. A `409` for the other outcome stops it, touching nothing.
   3. Only then does it send the same signed request to `klavd`
      (`agent_rotate_confirm` or `agent_rotate_cancel`). `klavd` keeps its
      own record of used requests, so it accepts one the server already
      took. If `klavd` refuses here, or its answer is lost, the item and the
      log may disagree until the step is applied, and the agent says so:
      retrying the same step finishes it (or answers «not pending» if
      `klavd` had applied it), and so does the person on the card.

   An older SDK sends the close to `klavd` first and then to the server;
   `klavd` takes both orders. While the agent doesn't close it, the person
   can decide with `resolve_pending`; after that, the agent's `confirm` or
   `cancel` fails and records nothing. If the person's choice is not the
   outcome the agent already recorded, `resolve_pending` answers with a
   warning that says what the log says and where the other password is (in
   the item's history).

These operations aren't on the extension's list: only a client of the
socket (the agent) can send them. `resolve_pending` is, because it is the
person's decision on the item's card.

**"Fix my reused passwords"** (ADR 0022 §6). `reused_offer`,
`offer_task` and `task_progress` belong to the person: the *popup* and
`klav health --fix-with`. No MCP tool, SDK method or `klav agent` command
asks for them, so the agent never receives the list of reused passwords,
only the task with its sites (`list_tasks`). The task is sorted by host,
not by group, and its default title and reason don't say "reused". The
socket doesn't tell the person apart from one of their processes, as with
`vault_health`: the boundary is that the agent has no path to these
operations, not the socket (threat model, T103).

- **Progress** comes from the task's `rotate.*` events, oldest to
  newest: the last one for each item wins. After a `rotate.confirmed`, a
  later `rotate.cancelled` or denied `rotate.started` leaves the site
  changed. `rotate.confirmed` is
  changed; `rotate.cancelled` or a denied `rotate.started`, failed;
  `rotate.started` without a close, pending in progress, and with no events, pending.
  A site already changed stays changed if a later attempt fails.
- **A `resolve_pending` by the person** also closes the agent's change on the
  server (`POST /v1/rotations/{id}/confirm` or `/cancel`,
  [`api.md`](api.md) §8.6), with a `rotate.confirmed` or
  `rotate.cancelled` event by the person: the site shows as changed or failed,
  the item is free for another change and the agent's later close gets
  `409` without leaving an event. If the server doesn't answer, the decision
  holds on the item anyway and a warning remains.

**Revoking with a key change** (ADR 0033, amendment of 2026-11-10, F2).
The Mac app calls `revoke_agent` with `rotate` and `background`: `klavd`
answers as soon as the server revokes and the sealed record says that rotation
was asked for, and rotates in the background. If the app closes halfway, nothing
is lost: a lock cuts the rotation off and the next unlock resumes it.
Against an older `klavd`, which doesn't know `background`, the app calls it
twice: first without `rotate`, which returns as soon as the server revokes,
and then with `rotate`. The CLI makes a single call with `rotate`, which
answers when it finishes.

- **One project at a time.** Each step takes the account, rotates one project,
  issues the grants of that project's other agents again, records it
  in `revocations.bin` and lets go of the account before the next one. The vault
  and the extension wait for one project at most.
- **Progress goes in `status`** (`revocations`, §5), which answers without the
  account, locked too.
- **Locking cuts it off** between steps or halfway through one, with what's done
  already recorded. `revoke_agent` then answers `locked`, like any
  operation cut off by a lock, with a message that says the agent is
  already revoked and the key change continues on unlock; `status`
  says what's left. If the lock comes with a project's rotation already
  on the server and not recorded, that project is rotated again when it resumes:
  it ends up with a newer key, with no other effect.
- **On unlock, `klavd` resumes it on its own** (P11), in the background and one
  project at a time: also the items shared one by one that were left
  without a new key, the reading of the audit log that was missing and the key
  change of the projects taken away from an active agent
  (`rotate_removed`). Before publishing the unlocked session, `klavd` reads
  the record, so no `status` of that session reports it as empty. A
  revocation whose projects this device doesn't
  know (`unknown_projects`) isn't resumed: it waits for the person (T189). A
  revocation without rotation never rotates a project.
- **Two steps in a row that move nothing stop it** until the next
  unlock: they neither changed a key, nor issued a grant, nor changed
  what's left. `klavd` records it in the record as `last_error` ("it
  made no progress in two steps in a row…", without names), so `status`,
  the apps and `klav agent show` say it stopped, never that it is still
  running. The next step that changes a key clears it. `klavd.log` only
  keeps the agent's ID.
- **What can't be reached doesn't block.** After a sync that
  worked, a deleted project, a project or an item whose vault
  is deleted or no longer listed by the server, or an item this
  device no longer sees (purged, or that the server stopped sending), is skipped
  and reported (`skipped`), on every step. A read that fails never counts
  as "can't be reached". What was skipped because of a vault and the items that are no longer
  seen stay recorded and are pending again if they come back; a
  deleted project never comes back. Neither does a purged item, so its
  revocation stays on the list, with no pending work, saying it was left
  out. Whatever fails stays in
  `last_error` and `klavd.log` says only which agent stopped: the reason
  can name a vault or a project, and the log would keep them after
  locking. Resuming it doesn't count as use: it doesn't delay the
  idle lock.

**Changing an active agent's grant** (ADR 0033, amendment of
2026-11-10, F3). `grant_change_prepare` builds the sheet and `grant_change_apply`
signs it if it is still the same one:

- **The digest binds the signature to the sheet.** `digest` is
  `SHA-256(tuple("klav/v1/grant-change", bytes firmados del grant vigente,
  JSON de lo que el cambio resuelve))` (spec §2.3): the project IDs and the
  already resolved policy, not the names the caller sent. When signing,
  `klavd` rebuilds it with the grant and the projects of that moment and
  aborts if it doesn't match (T188): a project created between the sheet
  and the signature forces it to be seen again.
- **What the editor can't express isn't changed with it:** a change in the
  editor's model on a grant with rules or an issuer's grant is rejected in
  `klavd`, not only in the app; the whole policy (`klav agent approve
  --policy-file`) can change it.
- **An agent revoked on this device doesn't get another grant**, even if the
  server reports it as active again (T24): `grant_change_prepare` rejects it
  with `security`, and signing any grant for it is refused too.
- **Widening asks for presence; narrowing doesn't** (P8). `klavd` decides it
  with the grant it verified itself, never the caller (T187). Whatever it
  can't show narrows counts as widening.
- **The words aren't asked for:** the agent's identity is inside the
  signature of its current grant.
- **What doesn't fit in the editor's model** (rules by tag or by
  vault, expiry per rule, the proxy's grant or an issuer's) comes out
  read-only in `grant_editor`. `grant_change_prepare` accepts a whole
  policy (`{"rules": …}`), which is what `klav agent approve` sends, but
  never the proxy's grant.

**Who can call them.** `klavd` doesn't tell programs apart (§6.1, T140): the
app, the CLI and any process of the same user call the four new
operations and `revoke_agent`. The barrier for widening is presence, with a
dialog that `klavd` builds. Narrowing and revoking don't ask for it
(risk 71). The extension gets none of them: `klav-native-host` rejects
them.

**Presence on approvals** (ADR [0014](decisiones/0014-agentes-fase-4.md)).
Before signing, `approve_agent`, `grant_change_apply` when it widens, `decide_approval` and `decide_task` with `approve: true`, `add_to_task`, `offer_task` and `resume_agents` ask for
Touch ID: presence only, no key. If they receive `password`, they check the
master password instead.

- Whatever can fail is checked before the dialog: in `approve_agent`, the
  projects, the agent's state and its words; in `offer_task`, the whole
  offer.
- The dialog says who asks for what and on which item (§6.1).
- If Touch ID isn't available or fails, it answers `biometry_unavailable` or
  `biometry_failed`.
- Then `klav` asks for the password and repeats the operation with `password`.
- While the Touch ID dialog is waiting, the other operations with the
  account wait; `status` and `lock` don't.

**Sync** ([ADR 0026](decisiones/0026-lecturas-sin-esperar-al-servidor.md),
which changes 0012 §6). The local copy is synced when it is more than 30 s old:

- **Reads** (`vaults`, `projects`, `list`, `view`, `suggest`, `autofill`,
  `totp`, `passkey_candidates`, `passkey_get`, `generator_history`, `generated_value`, `password_history`,
  `previous_password`, and also `approvals` and `tasks`, which read from the server
  and take only titles and sites from the copy): they answer without syncing first
  and, if the copy is stale, start a sync in the background, one at a
  time. The account is held only to plan it and to apply it; the round
  trips to the server go without it. Locking cancels it and throws away what
  it brings.
- **Everything else** (writes and operations that already talk to the server):
  syncs before answering, as always.
- **Without network:** the local copy, with the warning "offline (…); using the local
  copy" until a sync succeeds.
- **Rollback or a security failure** (impossible marks, oversized lists):
  the sync applies nothing and **every following response**, reads
  and writes, carries a warning that says so and names `klav sync
  --reset-cache`, until a sync succeeds. Reads keep answering with the local
  copy, the one already verified: a server that sends impossible marks
  doesn't lock the person out of their vault. `klavd` tries again with the
  first request that arrives after 30 s (in the background if it is a read);
  without requests it retries nothing. Only `sync` answers with the
  `rollback` or `security` error (ADR 0030, layer 10, which amends ADR 0026
  §3).
- **Any other error that isn't a network one** (expired session, tampered state): the
  sync applies nothing and every following read fails with
  that error until a sync succeeds. Each one tries again in the
  background.
- A read that starts the sync has already answered, so changes from
  another device, warnings and errors arrive with the next read.
  To find out without asking for more, `status` carries `revision` (it goes up when a
  sync brings changes or on unlock) and `syncing` (§5).

`unlock` and `sync` always sync before answering. `unlock` doesn't leave the
account open if that fails. With a session already open, an `unlock` that brings
`password` checks it: a wrong password answers
`wrong_credentials`.

**Passkeys** (ADR [0020](decisiones/0020-passkeys.md), spec §14).
`origin` is the one the browser reported for the sender, never one the
page wrote. The private key doesn't leave `klavd` through any
operation: it signs inside and returns the assertion.

- `passkey_get` and `passkey_create` ask for presence like approvals
  (Touch ID, or `password` instead), with the site in the dialog's
  text. With presence confirmed, the UV flag is set to 1.
- Before the dialog, the rpId is checked and, in `passkey_get`, that `item`
  is a candidate: a page that isn't the site's doesn't open the dialog.
  `excludeCredentials` and the repeated account are checked **after**
  presence, so that the page can't probe whether the person has an account (T86).
- With `item`, the chosen login has to belong to the site by the URLs the
  person confirmed (ADR 0030 §7): one an agent added doesn't count, and
  the answer is `denied`. One with no URL at all is also valid (the passkey gives it
  the site's), and so is one that already has the passkey for that same account. It is the
  same list the frame offers (`suggest`).
- Saving the passkey in an existing login writes a version by the
  person, and that would confirm all its URLs without them seeing it: before
  saving, the ones an agent added are removed and stay pending. The
  agent can propose them again.
- **Verification window** (ADR 0020 §8, `passkey_uv`). It is a local
  setting, not synced, sealed in `passkey-window.bin` in the `KLAV_HOME`
  (§3, the gate, «Settings»; the old `passkeys.json` is no longer read). If
  it is missing or doesn't open, it is `always`. What a verification covers
  is per key (§3, the gate): one key's verification never covers another's
  use.
  - `always` (default): Touch ID or `password` on every use, except the use
    for which the passkey frame unlocked Klav (`unlock` with
    `passkey_flow`). That unlock covers **one** use and only for 60 s.
    An unlock through the CLI or the *popup* covers none.
  - `5m`: another verification if the last real one was more than 5 minutes ago.
    An unlock the client typed counts (an `untyped` one doesn't), as does
    the presence of a use; loosening the setting opens nothing.
  - `unlocked`: the unlock holds until the next lock.
  - It applies the same to signing and to saving a passkey.
  - A use consumes the verification it relied on, in any window:
    going from `unlocked` to `always` leaves no free use.
  - `klavd` keeps the time in memory, with a monotonic clock, inside the
    session: locking clears it, and putting the Mac to sleep locks.
  - A `password` that arrives is always checked, even if the window covers
    the use. Inside the window, the UV flag stays at 1: there was a
    real verification. Presence (UP) is still the click in Klav's
    frame, on every use.
- `passkey_candidates` and `passkey_get` are reads (they don't sync first);
  `passkey_create` is a write: it saves the login and syncs.
- After answering the page, `passkey_get` sends `passkey.used` with the
  item to `POST /v1/audit/person` in the background and with a 10 s limit,
  without holding the session (except if the server rejects the token: then it
  retries with the session, which renews it). It is best effort: the signature doesn't wait for the network and,
  if it fails, only the event is lost.
- All three are on `klav-native-host`'s list.

**An agent signs in with one of the person's passkeys** (ADR 0020 §9). The
key never leaves `klavd`; the agent asks for the **use**, only inside a
task with `passkey`, and only in the person's browser.

1. The agent asks for `browser_tab`, sends the server `POST /v1/agent/access`
   with `passkey`, the tab's host in `claims.domain` and the task (the
   server logs it before answering, [`api.md`](api.md) §8.3) and
   sends `klavd` `agent_passkey_arm` with a `PasskeyArmStep`: `agent_id`,
   `task_id`, `item_id` and `request`, that signed request.
2. `klavd` checks it on its own, as in the assisted change: the signature,
   the active agent, `POST /v1/agent/access`, ±5 min and the `nonce` only
   once; that the body asks for `passkey` for that item and that task; that the
   login has a passkey and that the host can use its rpId
   (`klav_core::passkey::rp`); and the task's signed decision: approved,
   current, of the same agent and with `passkey` on that item and that host.
   Finally, that the server logged it: it looks among the last 1000
   events of the audit log (`GET /v1/audit`) for an allowed `agent.access` by
   that agent, item, task and permission whose `agent_proof` has the same
   `nonce` and the same signature, and whose actor is an agent. A signed request
   that the agent didn't send, or that the server denied, arms nothing (T139). This
   trusts the server: it stops an agent that skips it, not a dishonest
   server. Each signed request is good once in this `klavd`, also
   after locking and unlocking (used `nonce`s last 10 minutes outside
   the session; a restart forgets them, and `klavd` starts locked).
   With `klavd` locked it answers `locked` and asks the person for nothing.
3. It arms a use in the session: a random *token* (`kpa_…`; `klavd` keeps
   only its SHA-256), bound to the extension's connection, the tab, the
   host, the rpId, the login, the agent and the task, for 60 s. One per
   tab; locking clears them.
4. A `passkey_arm` event to the tab (`tab_id`, `host`, `rp_id`, `item`,
   `title`, `agent`, `reason`, `token`, `expires_in_ms`). The extension
   checks that the tab is still on `host`. If the page is already waiting for a
   passkey from that site, it uses it right then and answers `{used: true}`;
   if not, it keeps it and answers `{used: false}`.
5. The extension answers the next `get` request from that site in that
   tab with `agent_passkey_use`. `klavd` removes the use (once, even if it
   fails) if the *token*, the connection and the tab match and it hasn't expired;
   checks that the origin is on the armed host and that the request's rpId
   is the armed one; and signs with UV, without Touch ID and without spending the
   person's window (the task's approval is the verification,
   ADR 0020 §8). Then it sends `passkey.used` with the agent and the task.
6. The agent gets `PasskeyArmed`. `used` is `true` only if `klavd`
   really signed: what the extension says isn't enough. If unused, it carries
   `expires_in_s` and the agent presses the site's button.

`agent_passkey_arm` isn't on the extension's list. `agent_passkey_use`
is, because the extension sends it, and it only works with the *token* that `klavd`
gave that connection.

### The presence gate (ADR 0041)

[ADR 0041](decisiones/0041-presence-for-values-and-the-inject-card.md)
§2–§3. Built off in layers 2–5, behind a hidden `--presence-gate` flag, and
on for everyone since layer 6; the flag is gone.

**Which operations.** Every operation has one row of §3's table,
`presence::gate` in `crates/klav-daemon/src/presence.rs`, a `match` with no
catch-all: a new operation doesn't compile without its row.

| Row | Operations | What `klavd` does |
|---|---|---|
| Window | `view` with `reveal`, `previous_password`, `totp`, `generated_value`, `resolve`, `autofill` | The caller's key needs an open window, or a verification now |
| Extension's connection | `extension_attach`, and the value events it then gets (`browser_fill`'s `fill`, the fill step of `agent_rotate_begin`, `passkey_arm`) | One presence for the connection, until Klav locks or the connection closes; under `always`, one per event. Below, «The extension's connection» |
| Passkey window | `passkey_get`, `passkey_create` | The passkey window, now per key |
| Already asks | `approve_agent`, `decide_approval` and `decide_task` with `approve`, `add_to_task`, `offer_task`, `fulfill_secret_request` with `grant_proxy`, `grant_change_apply`, `proxy_use`, `proxy_grant`, `proxy_revoke`, `proxy_issuer_add`, `proxy_issuer_remove`, `resume_agents`, `cancel_account_deletion`, `confirm_presence` | As today: they ask for presence themselves, and never open or use a window |
| Setting | `presence_window` and `passkey_uv` with `window` | Loosening asks; tightening doesn't |
| Declares | `hold` | Below |
| Agent's proof | `agent_passkey_arm`, `agent_passkey_use`, `agent_rotate_*`, `browser_fill` | As today: the agent's own signed request or grant, no value of the person's |
| Browser channel | `browser_tab`, `extension_reply`, `extension_presence` | As today; `browser_tab` follows P25 (below) |
| No value | Everything else, also `view` without `reveal`, `sandbox_list_checked`, `agent_labels`, `set_agent_label`, `set_project_repos` and the settings without `window` | As today |

**Windows.** A window belongs to one key: the peer's terminal session, its
parent process (macOS, a peer with no terminal), or the connection
(`klav_daemon::peer`, §2.1). Two keys never share one. The setting says how
long one verification lasts:

- `5m` (the default when there is no setting): 5 minutes, on a monotonic
  clock;
- `unlocked`: until Klav locks;
- `always`: no window; each value asks, with the value's own text.

A window keeps what the prompt said: it lasts what the prompt, or the
client's question from `presence_required` or `status`, said it lasts, and
`klavd` checks a password only against the ask it answers (below). A move
from `5m` to `unlocked` leaves open windows at 5 minutes. Tightening shortens them at once; loosening
opens nothing, and `unlocked` → `always` → `unlocked` brings nothing back.
Locking drops every window. A verification that ends after a lock grants
nothing. The unlock is a verification for the key that unlocked: its window
opens. A key with no window (Linux before 6.5, no `SO_PEERPIDFD`) asks on
every value.

**Asking.** With Touch ID, `klavd` shows the dialog itself ("let the
terminal ttys003 use your vault for 5 minutes", §6.1). Without it, or with
Touch ID off, it answers `presence_required` with a `presence` object, and
the client asks the person for the master password and sends the same
request again with `password`:

```json
{"code": "presence_required", "message": "…",
 "presence": {"key": "session", "window": "5m", "terminal": "ttys003",
              "lasts": "5m"}}
```

- `key`: `session`, `parent`, `connection` or `none`.
- `window`: the setting the verification would open.
- `terminal?`: the peer's controlling terminal, named from its device
  number (macOS: `devname_r`; Linux: `pts/N`, `ttyN`, `ttySN`). Only names of
  letters, digits and `/._-`, up to 32 bytes; otherwise missing.
- `declared?`: `true` when this connection sent `hold`.
- `lasts?`: what the password grants: a window for the key, `5m` or
  `until_lock`. Missing when it grants only this one value: with `always`,
  with `key` `none`, and for a value that asks every time whatever the
  setting (ADR 0032's «every time»), even with `window` `5m`. The client
  words its question from `lasts`, never from `window` alone.
- `value?`: when `lasts` is missing (except for «every time», which has
  its own text), the one value it hands out, as data
  the client words in its own language: `kind` (`show`, `previous`,
  `code`, `fill`, `generated` or `resolve`), `title?` (the item's title
  from the vault, cleaned as §6.1's prompts clean it, never the query) and
  `count?` (for `resolve`, how many values). The CLI says "show the code of
  “GitHub”", and cleans the title again before printing it. `show`,
  `previous`, `code` and `fill` always carry a `title`: before asking,
  `klavd` resolves the query to exactly one item under the session's lock,
  and a query that names none, or more than one, gets `not_found` or
  `invalid` at once, with nothing asked (what `view` without `reveal`
  already tells any caller). So the vague "show a value from your vault"
  only appears from a `klavd` that sends no title; the real `klavd` no
  longer does. `generated` and `resolve` name no item.

The title is a **hint**, not proof (Omar's decision D of 2026-11-19).
Renaming an item is a write, and writes need no presence (ADR 0041 §3), so
a program can give its target the title of an item the person would
approve. What the person reads is the title the item has when `klavd`
asks; what binds the answer is the item itself (below).

**The password answers one ask.** `klavd` remembers, per connection, the
last `presence_required` it sent: the `presence` object, a SHA-256 of the
request without its `password`, and the item it named. A request with
`password` is checked only if `klavd` would ask exactly that again now:
same object, same request, same item. Otherwise the password isn't checked, and the answer is a new
`presence_required` with what `klavd` asks now (the setting changed in
between, the item was renamed, so its title in the object differs, or the
query now names another item). A password sent with no
`presence_required` before it, on that connection, isn't checked either,
and a request `klavd` can't serialize again is refused as `internal`. The
ask is kept per connection: a client resends on the connection that got
the ask. So a password never grants more than the question the person
read. For the four requests bound to an item (`view`, `previous_password`,
`totp`, `autofill`), what it hands out is the item, at the version, that
`klavd` asked about; for `resolve`, every item its references name, each at
its version; for `generated_value`, the history entry (below). The CLI then asks once more with the new words, and stops at a
third ask.

**The item binds the hand-out, also when the answer opens a window.** For
`view`, `previous_password`, `totp` and `autofill`, `klavd` remembers with
the ask the item it resolved and its version (the item's `version`, which
every write to its content raises and a sync never lowers). When the request
reaches the vault, under the session's lock and in the same hold that
hands the value out, `klavd` checks that the query still names that item,
at that version, whether the answer was a password or a Touch ID dialog,
and whether it grants one value or opens a window: if not, the answer is
`conflict` ("the item changed while you confirmed: nothing was handed
out"). For a password sent again, the version is the one `klavd` asked
about, not the one at the resend. That covers a rename or an edit during a
Touch ID dialog, an edit between `presence_required` and the resend, and a
new version a sync brought meanwhile (Omar's decision F of 2026-11-19). It
doesn't make the title proof: an item renamed or edited *before* the ask
is asked for as it is then (above). An ask for one value names the item;
an ask that opens a window names who and for how long, and no item.

`resolve` and `generated_value` are bound the same way since layer 6
(Omar's decision K, which overturned the ADR's own choice 51). Before
asking, `klavd` resolves each reference of a `resolve` to its item and
checks its field, and remembers every item with its version; a reference
that names nothing, or a field the item doesn't have, is refused at once
with the error `resolve` gave it before (now before the ask), and nothing
is asked. For `generated_value`, it remembers a digest of the
entry (its instant and its value); an instant with no entry is `not_found`
at once. At the hand-out, under the session's lock, it checks the same
again: an item edited, moved or deleted, a reference that now names another
item, or an entry deleted or replaced while it asked, is `conflict`, and
nothing is handed out.

**A `conflict` opens no window.** A verification that passes doesn't open
its window by itself: `klavd` opens it, under the session's lock, only
once the hand-out has found the item and the version it asked about. After
a `conflict`, or any refusal before that check, no window is open, and the
next value asks again (Omar's decisions G and L of 2026-11-19).

**One prompt at a time.** While one Touch ID dialog of `klavd` is open, any
other request that needs one gets `presence_busy` at once, whatever its key:
no queue forms behind a dialog. A request that will show a dialog doesn't
wait for a lock an open dialog's holder keeps either: the session's, which
an operation that already asks or a passkey use holds while its dialog is
open, or the one an `unlock` holds. It gets `presence_busy` at once, also
when the dialog opens while it waits. A request that needs no dialog, such
as a value whose window is open, waits for the session's lock like any
request, and is served once the dialog closes. One that finds out it needs
a dialog only after that wait (a widening `grant_change_apply`, a passkey
use whose window lapsed meanwhile) gets `presence_busy` if a dialog opened
while it waited. That covers every dialog `klavd` shows with
the gate: a value's, an unlock's, `confirm_presence`, a passkey use, an
operation that already asks, and a setting's loosening. A wrong password is
`wrong_credentials` and grants nothing; a canceled Touch ID is
`biometry_failed`. A change of either setting while another change is
running gets `presence_busy`.

**`unlock`.** A second `unlock` while an unlock's Touch ID dialog is open,
or while it waits for an unlock whose dialog then opens, gets
`presence_busy`. An `unlock` that finds `klavd` already unlocked by
another key answers `ok` with `already_unlocked: true` in `DaemonStatus`:
without `password` it granted the caller nothing; with it, the caller's own
window opens, as for any password unlock (next). The unlock dialog says which window it opens ("unlock your
vault for the terminal ttys003, and let it use the vault for 5 minutes");
`klavd` can't read the sealed setting while locked, so it uses the one it
read at its last unlock. At the first unlock since `klavd` started it says
only "unlock your vault" and opens no window.

A **password `unlock`** opens what the client's question said, sent as
`shown`, if that is what `klavd` would open now for the caller's key, and
otherwise none; without `shown` (an older client) none. The client learns
what to say from `status`'s `presence` (§5). The first unlock since
`klavd` started opens no window, with a password as with Touch ID: the
setting is sealed until then, `status` sends no `lasts`, and the first
value asks (Omar's decision A of 2026-11-19). A password the client didn't
read on its terminal (`untyped`, §3's envelope; the CLI's
`--password-stdin`) unlocks, opens no window and grants no passkey
verification for the caller's key, also when `klavd` was already unlocked
(Omar's decisions 4 and B of 2026-11-19). A Touch ID unlock is unaffected
by `untyped`.

**Settings.** The presence setting (`presence.bin`) and the passkey window
(`passkey-window.bin`) are sealed local data (spec §12.2, kind `0x41`,
purposes `presence` and `passkey-window`), opened with the local key at
unlock. Missing: `5m` for presence, `always` for passkeys. One that doesn't
open, of another version or another layout (a file a program wrote, one
setting's blob in the other's place): `always`. Both answer `locked` while
locked, and `status` leaves `passkey_uv` out while locked. The old
`passkeys.json` is never read: at the first unlock that finds it, `klavd`
deletes it and warns once, "Klav no longer reads your old passkey setting:
passkeys now ask every time. Choose again in the extension's settings".

**The passkey window per key.** As above, with the passkey setting: an
unlock covers the unlocking key's passkey uses, and another key's use asks.
An `untyped` password unlock covers none (above).

**`hold`** (§1.2). A connection that sends `hold` is declared; the next
verification on it (its `unlock`, or the gate's window verification) holds
it until Klav locks, under `5m` or `unlocked`. A declaration survives a lock,
a held connection doesn't. Only that connection, never another of the same
key. Not held by: an `always` value, a passkey use, `confirm_presence` or
another "already asks" operation. `always` drops every declaration and held
connection, and a move back brings none. Built, and off: `hold` answers
`not_supported` until Omar has run layer 5's by-hand checks on a signed
Developer ID build (the debugger and the hostile `HOME`,
`CFFIXED_USER_HOME` and `KLAV_HOME`), and always on Linux. Turning it on
is one constant, `HOLD_SUPPORTED` in `crates/klav-daemon/src/server.rs`.

**The extension's connection** (ADR 0041 §3.1, layer 4). Before an agent's
values go to a browser connection (a `browser_fill`, the fill step of an
`agent_rotate_begin`, an `agent_passkey_arm`), `klavd` asks the person,
needing the session unlocked (`locked` otherwise, also for `browser_fill`,
which worked locked before the gate). Under `5m` and `unlocked`, one
answer covers that connection until Klav locks or it closes; under
`always`, every event asks, and moving to `always` drops what was covered.

- **With Touch ID**, `klavd` shows the dialog (§6.1). Canceled: `denied`.
- **Without it** (Linux, Touch ID off, `biometry_unavailable`), `klavd`
  sends the connection a `presence` event and waits up to 120 s:

  ```text
  ← {"v":1,"event":{"kind":"presence","id":6,"tab_id":12,"presence":{"key":"connection","window":"5m","lasts":"until_lock","browser":{"event":"fill","agent":"claude-code","title":"GitHub","attached":2,"connection":true}}}}
  → {"v":1,"id":10,"request":{"op":"extension_presence","event":6,"password":"…"}}
  ```

  `presence` is `presence_required`'s object (§3, the gate) with `browser`:
  `event` (`fill`, `password_change` or `passkey_sign_in`), `agent` (the
  name the agent gave, cleaned), `title?` (the item's title from the vault,
  cleaned: for a fill, from `browser_fill`'s `item?` hint; missing without
  it), `site?` (for a passkey, the rpId of the login's passkey in the
  vault, never the one the agent claims, T140), `attached?` (how many
  extension connections are attached, when more than one) and
  `connection` (`true` when the connection's key is the connection itself,
  so the text says "this browser connection" and not "a browser"). The
  extension shows it in Klav's own frame (§6.1's words) and sends the
  password with `extension_presence` on the same connection (own choice
  32). An `extension_reply` with an `error`, or no answer in time, is
  declined.
- **Declined** (Touch ID canceled, the frame closed, no answer): the agent
  gets `denied` with "the person declined in the browser to let agents
  fill there: nothing reached the page. Do not retry on your own; tell the
  person, and try again only if they ask". Nothing was sent to the page,
  and for a password change nothing was stored as pending: the question
  comes after the probe and before the new password is saved.
- **One at a time** per connection: a second event that needs a presence
  while one is open gets `presence_busy`.

**One browser in front** (P25, Omar's decision on Q-N5). With more than
one extension connection attached, `browser_tab` asks every
connection and needs exactly one to report focus; otherwise
`browser_ambiguous`. Right before each value event (`fill`, `rotate_fill`,
`passkey_arm`) `klavd` asks again, and only the connection that gets the
values may report focus. The check runs before the presence question too,
so the person is never asked for a browser that then gets nothing. With
one connection, that one.

## 4. Errors

| `code` | Meaning | `klav` exits with |
|---|---|---|
| `locked` | It has to be unlocked | 1 |
| `not_logged_in` | There is no account in this `KLAV_HOME` | 1 |
| `wrong_credentials` | Wrong password | 1 |
| `rollback` | **Possible server rollback (T7)**: nothing was applied | 3 |
| `security` | A security check failed (tampered grant, different pairing words, tampered audit log) | 3 |
| `not_found`, `invalid`, `conflict` | As in direct mode. `conflict` also means the item, or what a `resolve` or `generated_value` named, changed while `klavd` asked (§3, the gate) | 1 |
| `network`, `session_expired` | Server unreachable; session expired or revoked | 1 |
| `biometry_unavailable` | Touch ID isn't available or isn't turned on | 1 (`klav` asks for the password) |
| `biometry_failed` | Touch ID canceled or failed | 1 (`klav` asks for the password) |
| `bad_request` | Malformed line, another version or unknown fields | 1 |
| `denied` | Refused on purpose: a login on a page that isn't its site, or an operation the extension can't use | 1 |
| `agents_paused` | The person paused that agent or every agent (ADR 0033 §7) | 7 |
| `account_deleting` | The person asked to delete the account (ADR 0037 §3): `klavd` mediates nothing for agents | 8 |
| `account_deleted` | Klav has already deleted the account: it can neither write nor mediate for agents | 8 in agent commands; 1 in the others |
| `presence_required` | No window for the caller's key and no Touch ID to ask. It carries `presence` (§3, the gate); the client asks for the master password and sends `password` | `klav` asks on its controlling terminal and sends it again; 9 with no terminal ([cli.md](cli.md) §8) |
| `presence_busy` | Another Touch ID dialog is open, another master password is being checked, or another setting change is running; try again after it. Also a second presence on one extension connection | 1 (`klav` says which, from what it sent) |
| `browser_ambiguous` | More than one browser is attached and not exactly one reports focus, or the one that does isn't the one that would get the values (§3, the gate) | 1 |
| `not_supported` | This `klavd` doesn't do it: `hold` (on macOS until the signed-build check, and on Linux); `presence_window` on a `klavd` of layers 2–5 with its gate off | 1 |
| `extension_not_allowed` | Only `klav-native-host` sends it, never `klavd`: the extension that started it isn't on its list. The message says which command adds it ([extension.md](extension.md) §3) | — |
| `internal` | Any other error | 1 |

## 5. `DaemonStatus`

```json
{
  "version": "0.9.0", "commit": "ce4fa50990924bf17d349b752ad8020ff6b3a9ff",
  "commit_time": 1794593822, "protocol": 1, "pid": 4242,
  "logged_in": true, "unlocked": true, "email": "ana@example.com",
  "unlocked_with": "password", "idle_lock_secs": 900, "locks_in_secs": 712,
  "touch_id": { "available": true, "enrolled": true, "password_required": null },
  "revision": 7, "syncing": false,
  "passkey_uv": "always", "passkey_verified": false,
  "browsers": [{ "browser": "Google Chrome", "connected": true, "at_ms": 1762300000000 }],
  "agents_paused": [{ "since": 1762300000000, "until": 1762303600000, "local": true }],
  "account_deletion": { "requested_at": 1762300000000, "delete_at": 1762904800000,
                        "device_id": "…", "device_name": "MacBook de Ana" },
  "revocations": [{ "agent_id": "…", "name": "claude-code", "projects": 5,
                    "rotated": 2, "regrants": 0, "to_change": 3, "needs_work": true,
                    "running": true }]
}
```

- **`version`:** the workspace's version number, the same for every build
  of one release (those from before 0.9.0 said `0.0.0`).
- **`commit`**, **`commit_time`:** the commit this `klavd` was built from,
  its full 40-digit lowercase hash, and that commit's committer time in
  Unix seconds: the same build `klavd --version` names
  (`klavd 0.9.0 (ce4fa5099092 2026-11-13T18:17:02Z)`). They tell two builds
  of one `version` apart; the Mac app restarts a `klavd` that isn't its own
  build. Both or neither: missing from a build whose source had no Git
  history (`--version` says `(commit unknown)`) and from older `klavd`.
- **`revision`:** goes up when a sync brings changes or on
  unlock. A client that keeps what it read reads again only when it changes.
- **`syncing`:** a background sync is in progress (§3).
- **`passkey_uv`**, **`passkey_verified`:** the passkey verification
  window (§4) and whether the next use falls inside it.
  `passkey_uv` is missing while locked (the setting is sealed), and
  `passkey_verified` is about the caller's key. With `passkey_verified`,
  the frame doesn't ask for the password.
- **`browsers`:** the extensions that have connected since `klavd` started,
  most recent first (16 at most): the name the browser gives
  (`navigator.userAgentData`, "Firefox" in Firefox), whether it is still connected and
  when that changed. Missing if none has connected. The Mac app uses it to say
  "Connected in Chrome".
- **`agents_paused`:** the pauses of agents in effect (§3, Pausing agents),
  with `klavd` locked too: `agent_id?` (without it, every agent), `since`,
  `until?` and `local` when the server doesn't have it yet ("Paused on this
  Mac; unlock to pause everywhere"). With `local`,
  `server_unsupported` when the server doesn't support pauses ("Paused on this
  Mac only: … Update the server"). Missing if there are none.
- **`account_deletion`:** the account deletion the person asked for and
  nobody canceled (§3, Deleting the account), as the last
  sync left it, also after restarting `klavd` (`account-deletion.json`): `requested_at`, `delete_at`, `device_id` and
  `device_name`, in Unix milliseconds. Missing if there is none.
  **`account_deleted`:** `true` when a sync found the
  account already deleted; missing otherwise.
- **`revocations`:** the key changes this device owes (§3,
  Revoking with a key change): `agent_id`, `name` (the name the agent gave
  itself), `projects` and `rotated` ("Changing keys: 2 of 5
  projects"), `regrants`, `to_change?` (projects still changing, not counting the
  skipped ones), `needs_work?` (something is left that `klavd` or "Finish" can
  do; without it, all that's left is what can't be reached, or the projects aren't
  known), `unknown_projects?`, `narrowed?`, `items?`, `log_unchecked?`,
  `without_key_change?` (a revocation without a key change: only the keys of
  the items shared one by one change, so what was skipped
  are items and no app talks about "every key"; an older `klavd`
  doesn't send it and older apps ignore it), `skipped?`
  (how many, projects and items), `running?` while `klavd` is working on
  it and `last_error?`. A key change that `klavd` finished by skipping
  something it can't reach (a deleted project leaves no entry in the record)
  stays on the list with `needs_work` false and `skipped`, and `rotated`
  counting only projects, until `klavd` restarts, the agent owes a change
  again or is revoked again: no app reads it as
  "every key changed". **`revocations_unreadable`:** `true` when the record
  didn't open on the last read: then `revocations` may be stale and
  nothing is taken as finished; missing otherwise. **`revocations_newer`:** in addition,
  a newer version of Klav wrote it: Klav has to be updated, not the
  file set aside (spec §12.2); missing otherwise. With `klavd` locked, only the
  agent and the counts the last unlocked moment left: without the
  name or the error, which can name a vault or a project, and never
  `running`, because locking stops the change and throws away the half-done step. After
  restarting `klavd`, nothing until unlock, because the record is sealed.
  The extension never receives it, as it doesn't receive `agents` either. Missing if there
  are none.

- **`already_unlocked`:** only in the answer to an `unlock`, `true` when another key had already unlocked `klavd` (§3, the gate).
  Missing otherwise.
- **`presence`:** how a client tells the gate is on: since layer 6
  always there (an older `klavd`, and one of layers 2–5 with its gate off,
  leave it out). What an `unlock` from the caller's key would mean now:
  `elsewhere` (`true` when `klavd` is unlocked and another key unlocked
  it), `key`, `terminal?` and `declared?` as in `presence_required`, and
  `lasts?`: the window a typed password unlock opens (`5m` or
  `until_lock`), missing when it opens none, which includes the first
  unlock since `klavd` started, when the setting isn't read yet. `klav
  unlock` words its question from it and sends `shown` to match.

`status` doesn't start syncs and doesn't count as use. `klav status --json`
includes it under `klavd`.

## 6. Touch ID (macOS)

Details in [ADR 0013](decisiones/0013-touch-id-secure-enclave.md) and spec §12.3.

- **Automatic setup:** the first `klav unlock` with a password creates a P-256 key in the Secure Enclave (ACL `biometryCurrentSet`) and wraps the device's local key with it. It shows no dialog. The result is saved in `$KLAV_HOME/touchid.json` (0600), which is useless on another Mac.
- **Unlocking:** once it is set up, `klav unlock`, or any command with `klavd` locked, asks for Touch ID.
- **Falling back to the password:** if you cancel or the fingerprint fails, `klav` asks for the password. `klav unlock --password` and `--password-stdin` always use the password.
- **Password required:**
  - every 14 days;
  - after a restart;
  - when the enrolled fingerprints change, because the Secure Enclave invalidates the key. In that case the setup is deleted and the password creates it again.

  The first two values are cryptographically bound to the blob: editing the file doesn't extend the deadline. A password time in the future (the clock went back or someone changed it) also asks for the password.
- **Screen lock:** when the screen locks, `klavd` locks.
- **Turning it off:** `klavd --no-touch-id` or `KLAV_NO_TOUCH_ID=1`. To remove the setup, delete `touchid.json`.
- **Build:** without Xcode's Command Line Tools, or with `KLAV_NO_SWIFT=1`, `klavd` is built without Touch ID.
- **Signing:** `scripts/macos/build-sign.sh` signs the binaries with Developer ID and *hardened runtime*; `scripts/macos/notarize.sh` notarizes them.

### 6.1 The dialog's text

macOS writes the dialog as "`<process>` is trying to `<reason>`." (in Spanish, «`<proceso>` está intentando `<motivo>`.»). `klavd` only supplies the reason, and builds it in a single place, `crates/klav-daemon/src/prompt.rs`:

- **Who asks for what and on which item,** without IDs. The reason is a lowercase predicate without a final period, because macOS adds the rest.
- **In the Mac's language:** Spanish if macOS's first preferred language is Spanish (`es`, `es-MX`, `es-419`…), English otherwise. The Touch ID shim reads it with `Locale.preferredLanguages`, which also works in a LaunchAgent without a UI. It is the language macOS writes its own part in («está intentando»), so the two halves match. The Spanish uses the app's words (`Localizable.xcstrings`): bóveda, elemento, tarea, rellenar.
- **Where it comes from,** when `klavd` knows it by itself: the *pid* of the other end of the socket that the kernel gives (`LOCAL_PEEREPID`) and the path of its executable (`proc_pidpath`). `klav-native-host` next to `klavd` or in `Klav.app/Contents/Helpers` is the browser; `klav`, the terminal; `Klav.app/Contents/MacOS/Klav`, the Mac app. Any other program adds nothing. It never comes from a field the client sends. It is a hint for the person, not an access control: any program of the same user can launch `klav-native-host` (T140).
- **Outside names,** the agent's (it picks it when it registers) and the items' titles (they can come from an import), are cleaned first: control characters and line breaks become a space, Unicode format characters (*bidi*, zero-width, tags) are removed, runs of spaces become one, quotes inside become `'`, and they are cut to 40 characters with "…". They always go in quotes: «» in Spanish, “” in English.
- **What the agent writes freely never goes in:** its reason (`reason`), a task's title or the site it claims (T140).
- **Passkeys:** "sign in to “example.com” with your passkey" and "save a passkey for “example.com” in Klav" (in Spanish, «iniciar sesión en «example.com» con tu passkey» and «guardar una passkey de «example.com» en Klav»). The site is the rpId that `klavd` checked against the origin the browser gives (ADR 0020 §7), not the one the page writes, and it is cleaned and quoted like outside names.
- **Passkey verification window:** loosening it (ADR 0020 §8) asks to "let your passkeys sign in without asking every time" («dejar que tus passkeys inicien sesión sin preguntar cada vez»), with where it comes from.
- **macOS supplies the `<process>`:** the display name and the icon of the *bundle* that holds the executable.
  - The app's `klavd` lives in `Klav.app/Contents/Helpers/klavd.app`, so the dialog says "Klav", with the app's icon ([macos.md](macos.md) §3).
  - A `klavd` from `cargo install` is a standalone binary and shows as "klavd". An `Info.plist` embedded in the binary changes nothing (it was tried: ADR 0027, note of 2026-11-05), so there is no `build.rs` for that.

| Operation | Before | Now (English) | Now (Spanish) |
|---|---|---|---|
| `unlock` | unlock Klav for ana@example.com | unlock your vault for your browser (ana@example.com) | desbloquear tu bóveda para tu navegador (ana@example.com) |
| `decide_approval`, `inject` | approve a Klav agent request (b4d905d6-…) | let “release-mac” use “Sparkle EdDSA” in a command | dejar que «release-mac» use «Sparkle EdDSA» en un comando |
| `decide_approval`, `fill` | approve a Klav agent request (…) | let “claude-code” fill “GitHub” | dejar que «claude-code» rellene «GitHub» |
| `decide_approval`, `totp` | approve a Klav agent request (…) | let “claude-code” get a code for “GitHub” | dejar que «claude-code» obtenga un código de «GitHub» |
| `approve_agent` | approve the Klav agent release-mac | give the agent “release-mac” access to Personal/Release | dar al agente «release-mac» acceso a Personal/Release |
| `decide_task` | approve a Klav agent task (…) | approve the task of “claude-code”: 3 items | aprobar la tarea de «claude-code»: 3 elementos |
| `add_to_task` | add a Klav agent request to its task (…) | add “GitHub” to the task of “claude-code” | añadir «GitHub» a la tarea de «claude-code» |
| `offer_task` | offer claude-code a Klav task on 4 logins | offer “claude-code” a task to change 4 passwords | ofrecer a «claude-code» una tarea para cambiar 4 contraseñas |
| `resume_agents` | — | let “claude-code” use Klav again · let your agents use Klav again | dejar que «claude-code» vuelva a usar Klav · dejar que tus agentes vuelvan a usar Klav |
| `confirm_presence` (`delete_account`) | — | confirm it’s you to delete your account | confirmar que eres tú para borrar tu cuenta |
| `view`, `totp`… (a window) | — | let the terminal ttys003 use your vault for 5 minutes · let this connection use your vault until Klav locks | dejar que la terminal ttys003 use tu bóveda durante 5 minutos · dejar que esta conexión use tu bóveda hasta que Klav se bloquee |
| `totp`, `autofill`, `resolve`… (Always) | — | show the code of “GitHub” (for the terminal ttys003) · fill “GitHub” in a browser · use 3 values from your vault in a command (for a program with no terminal) | mostrar el código de «GitHub» (para la terminal ttys003) · rellenar «GitHub» en un navegador · usar 3 valores de tu bóveda en un comando (para un programa sin terminal) |
| `unlock` | — | unlock your vault for the terminal ttys003, and let it use the vault for 5 minutes (ana@example.com) | desbloquear tu bóveda para la terminal ttys003 y dejar que la use durante 5 minutos (ana@example.com) |
| An extension's connection (`5m` or `unlocked`) | — | let agents fill in a browser until Klav locks, starting with “claude-code”'s fill of “GitHub” · … through this browser connection … (Linux) · starting with “claude-code”'s password change for “GitHub” · starting with “claude-code”'s passkey sign-in to “github.com”; and "; 2 browser connections are attached" when there are more | dejar que los agentes rellenen en un navegador hasta que Klav se bloquee, empezando por el relleno de «GitHub» que pidió «claude-code» · … por esta conexión del navegador … · el cambio de contraseña de «GitHub» que pidió «claude-code» · el inicio de sesión con passkey en «github.com» que pidió «claude-code»; y «; hay 2 conexiones del navegador activas» |
| An extension's connection (`always`) | — | let a browser connection receive “claude-code”'s values for “GitHub” | dejar que una conexión del navegador reciba los valores de «claude-code» para «GitHub» |
| `presence_window` (loosens) | — | ask for your presence every 5 minutes instead of for every value | pedir tu presencia cada 5 minutos en vez de en cada valor |
| `grant_change_apply` (widens) | — | let “claude-code” do more: Personal/Release, reveal (ask) | dejar que «claude-code» haga más: Personal/Release, revelar (preguntar) |

In `grant_change_apply` only the lines that widen show, in the order of
the sheet: added projects, permissions with their new effect (in the app's
words: fill, inject, code, reveal, create, edit, delete),
"more sites", "more hours", "no expiry" or "expires later", and "other
rules" for a change from the CLI outside the editor's model. Up to three, and
then "and 2 more changes" («y 2 cambios más»): the sheet already showed them all.

- **The other permissions** of `decide_approval`: `list` ("see the list of", «vea la lista de»), `reveal` ("see the value of", «vea el valor de»), `create` ("create an item in", «cree un elemento en»), `update` ("change", «cambie»), `delete` ("delete", «borre»), `passkey` ("sign in to … with your passkey", «inicie sesión en … con tu passkey») and `rotate` ("change the password of", «cambie la contraseña de»). A new permission doesn't compile without its words.
- **With the source:** the unlock says "for your browser", "for the terminal" or "for the Klav app" («para tu navegador», «para la terminal», «para la app de Klav»). Approvals end with "(from your browser)" or «(desde tu navegador)», and the same with the terminal and the app.
- **With several projects,** an agent's permission names the first two and counts the rest: "Work/P1, Work/P2 and 3 more", «Work/P1, Work/P2 y 3 más».
- **A task's number** counts the items that stay checked after what the person changed on the card.
- **Without the item on this device,** it says "an item" or «un elemento».
- **A value with the setting on Always** ends with who asks, as
  the dialogs that open a window name it: "(for the terminal ttys003)",
  "(for a terminal)", "(for a program with no terminal)", "(for a
  browser)", "(for this connection)", "(for this browser connection)",
  «(para la terminal ttys003)», «(para una terminal)», «(para un programa
  sin terminal)», «(para un navegador)», «(para esta conexión)», «(para
  esta conexión del navegador)» (Omar's decision C of 2026-11-19). A fill
  for the browser's own window already says "in a browser" and keeps its
  text. Before this, the Always texts named no one.
  **Approved by Omar as built** on 2026-11-19 (his decision H).
