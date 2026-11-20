# 0026 · `klavd` reads without waiting for the server (*stale-while-revalidate*)

- Status: accepted
- Date: 2026-11-05
- Changes: [ADR 0012](0012-daemon-klavd.md) §6

## Context
Omar uses the extension every day against a server on Railway (us-west2) from Mexico, with about 350 entries. The *popup* is slow to show the vault. Measured with `apps/extension/e2e/perf.spec.ts`, which puts a proxy with a 270 ms round trip between `klavd` and `klav-server`; these are medians of 5 openings, in ms until the first row:

| Situation | copy less than 30 s old | copy more than 30 s old |
|---|---|---|
| As is (tab without a web page: new tab, `chrome://`) | 3583 | 3579 |
| Without waiting for the active tab | 592 | 965 |
| The same, without asking for approvals or tasks | 42 | 410 |

Four things add up, in this order of weight:

1. **The active tab.** `popup_here` asks the *content script* for its address and, if there isn't one (a new tab, a browser page), waits the 3 s of `WHERE_WAIT_MS` before giving up on the answer. The *popup* waited for that before asking for the list.
2. **Approvals and tasks.** `watchApprovals` asks for `approvals` and `tasks` on opening. Both go to the server (2 round trips) while holding `klavd`'s account, and `klavd` serves each connection in order: `list` waited behind them.
3. **Inline sync** (ADR 0012 §6): a read with a copy more than 30 s old synced before answering, at least one round trip.
4. **Starting the native *host*** costs about 8 ms: it doesn't matter.

## Decision
1. **Reads that only look at the local copy answer from it right away**: `vaults`, `projects`, `list`, `view`, `suggest`, `autofill`, `totp`, `generator_history`, `generated_value`, `password_history` and `previous_password`. If the copy is more than 30 s old, they start a background sync and don't wait for it. `approvals` and `tasks` join the list even though they talk to the server: they read the requests and tasks from it, and only take titles and sites from the copy. Syncing first added up to two round trips with the account held, right when the *popup* has just drawn and the person starts typing.
2. **One background sync at a time**, in three steps (`klav-client`):
   - **Plan**, with the account: copies the access token and each vault's revision.
   - **Fetch**, without the account: `GET /v1/sync` and whatever `changes` are needed. Meanwhile, `klavd` keeps answering.
   - **Apply**, with the account, with the same rollback checks (T7) as any sync, in a single shared function. If another sync changed the cache in the meantime (`generation`), the response is discarded and nothing changes.
   - If the token is about to expire, it is renewed while planning, with the account (one round trip). If the server rejects the token (it was rotated in the meantime), it syncs with the account, as before. The background thread never touches the refresh token or the keys.
   - If `klavd` locks during the sync, or locks and is unlocked again, the result is discarded: each session carries a number (`serial`).
3. **A sync error that isn't a network error sticks.** A rollback, an expired session or a tampered state make every following read fail with that error, the same as when they synced before answering. Each of those reads tries again in the background, and the first sync that succeeds clears it. With no network, the following reads carry the warning "offline (…); using the local copy" until a sync succeeds.

   > **Amended on 2026-11-05 by [ADR 0030](0030-ronda-de-seguridad-2026-11.md), layer 10.** A rollback or a security failure (impossible *high-water marks*, oversized lists) no longer makes reads fail: it stays as a **warning** on every response, reads and writes, that names `klav sync --reset-cache`. Reads keep answering from the local copy, which is already verified. `klavd` tries again with the first request that arrives after 30 s (in the background if it is a read), and the first sync that succeeds clears the warning. Only `sync` returns the error (`klav sync` exits with 3). The reason: a hostile server that sent an impossible revision once poisoned the *high-water marks* and locked the person out of their vault for good. With this ADR as written, every read failed as well. The expired session and the tampered state stay as above. The shared sync from layer 02 only goes to the network while applying if a vault key is still waiting to be signed or a person's version is still waiting to be fetched (ADR 0030 §1 and §7). The background sync checks the shape of the vault list (how many, possible counters, no repeats) before asking for their changes.
4. **The *popup* learns about changes** through two new optional fields in `DaemonStatus`:
   - `revision`: goes up when a sync brings changes, by any path, or on unlock.
   - `syncing`: a background sync is in progress.

   The protocol stays at version 1, as `klavd.md` §3 requires for a new optional field, and the *host*'s list of operations doesn't change.
5. **Everything else stays as it was:**
   - Writes and the other operations that talk to the server (`resolve`, `agents`, `decide_approval`, `decide_task`, `add_to_task`, `end_task`, `task_log`, audit log, revocation, import, `generator_record`, `create`, `edit`, `trash`…) sync first, if needed.
   - `unlock` and `sync` always sync, and `sync` returns its error.
   - `klavd` still serves each connection in order.
6. **The *popup*:**
   - After `status`, it asks for `list` without waiting for anything else; the active tab with `suggest` goes at the same time.
   - Approvals and tasks are requested after the vault is drawn, and not while the person is typing in the search (until 1.5 s after the last keystroke): those requests hold the account during their round trips, and a search would have to wait for them.
   - While `syncing` is still set it polls `status`, and asks for `list` again only if `revision` changed. After that it checks every 3 s.
   - It draws the rows that fit on screen first, and the rest when the browser is idle.
   - Each icon is looked up when its row comes on screen.
   - `whereIs` stops waiting the 3 s if the tab has no *content script*: the browser already said there is nobody to answer.

**Rejected:**
- **Renewing the token ahead of time from `klavd`'s timer.** It would change the traffic pattern (one renewal every ~15 min even if nobody uses Klav) and would hold the account on every attempt without network. The token lasts as long as the default idle lock (15 min), so it almost never expires with `klavd` unlocked and in use; when it does, it only costs one round trip, and with the list already answered.
- **A limit on `list`.** 350 summaries over the native port aren't what costs time. The *popup* still draws at most 100 rows.
- **Serving a connection's requests in parallel.** It would change the protocol's semantics, and it isn't needed if reads don't wait for the network and approvals come later.

**Pending:** having `approvals` and `tasks` fetch from the server without holding the account, with the same plan, fetch and apply pattern. Until then, a search that lands right during one of those queries waits up to two round trips, the same as before this change.

## Consequences
- **Rollback (T7).** Answering from the local copy before syncing doesn't weaken the protection. That copy is the state this device already verified, the same one that holds the *high-water marks*. Detection protects what gets applied, and what gets applied goes through the same checks. The only thing that changes is when the person finds out: the read that starts the sync answers from the good copy, and the next one fails with `rollback`, the same as today. *(Amended by ADR 0030, layer 10: the next one carries a `rollback` warning and doesn't fail; see §3.)* No data from a server that goes backwards reaches the cache.
- **One read of delay.** Changes from another device, the no-network warning and the rollback error arrive one read later than before. `klav item ls` right after editing on another device shows the previous copy once; `klav sync` is still the way to ask for the latest.
- **Autofill.** `autofill` can fill with the password from a few seconds ago if it was changed on another device, as already happened without network. The site match is checked the same way, against the verified copy.
- **Traffic.** The syncs are the same and at the same time. Sometimes there is one extra: if an operation with network syncs inline while the background one is in progress, the background one is discarded.
- **CLI.** The CLI with `klavd` inherits the same behavior; in direct mode nothing changes.
