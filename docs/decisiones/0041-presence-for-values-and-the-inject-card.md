# 0041 · Presence before `klavd` hands out a value, and an `inject` card that shows the command

- Status: Accepted (2026-11-17). The presence part (layers 1–6) is built and on since 2026-11-24, with `hold` still answering `not_supported` until Omar runs layer 5's by-hand checks on a signed build; the `inject` card (layers 7–13) is not built. Omar made the decisions marked "Owner's decision (2026-11-17)". After the first independent review, the same day, Omar answered P2, P3, P6, P7, P12, P15 and P17 and revised decision 1; after the report on that review, Omar answered Q1, Q2, Q3 and Q5; after the second independent review, Omar answered four more points (the third-round answers below). P4, P5, P9, P18 and P20 are confirmed by Omar on condition that the second independent review passes. The designs the first review reshaped (P1, P6, P8, P10, P11, P13, P14, P16, P19) were rewritten at Omar's direction, and the second review checks them. P21–P26 are new, and P4 and P22 were revised in the third round. After the third independent review (2026-11-18), Omar accepted P4, P21, P24 and P25 with changes, and chose not to build P26 (the fourth-round answers below). The same day he answered the fourth round's questions Q-N1–Q-N5, confirmed that a loosening's own verification opens nothing, and chose what an extension connection's prompt says. Nothing of P4, P21, P24 or P25 waits for him. On 2026-11-19 he answered the questions of layer 2's second and third reviews and of §3.1's prompt (the fifth-round answers below). He confirmed every amendment and every one of the ADR's own choices he was asked about, except one: §3.1's prompt names the event that caused it. P22 and P23 still wait for a review. The lists are at the end
- Date: 2026-11-17
- Changes:
  - [ADR 0036](0036-sandboxes-de-agentes.md) Q-D (dated note there; its E6.2, and T171 in its E7, said the card shows the command);
  - [ADR 0020](0020-passkeys.md) §8: the passkey window becomes one per session (dated note there);
  - residual risks 49 and 63 of the [threat model](../modelo-de-amenazas.md), and §6 "Otro proceso del mismo usuario frente a `klavd`", which this ADR narrows.
- Meets [ADR 0032](0032-entornos-por-repositorio.md) §3 (protected environments and items) and [ADR 0033](0033-agentes-desde-la-app-de-mac.md)'s amendment of 2026-11-10 (grant changes through the sheet of differences)

## Context

### Problem 1: any program of the person's user reads values from an unlocked `klavd`
`klavd` accepts a connection from any process of the same user and checks nothing else:

- `same_user` compares the peer's UID with its own (`crates/klav-daemon/src/server.rs:1211`).
- The program at the other end is only classified for the Touch ID prompt, by its executable's path (`peer_source`, `server.rs:1221`; `Source::of_executable`, `crates/klav-daemon/src/prompt.rs:82`). The code says so itself: "A hint for the person, not a check: any program of the same user can start `klav-native-host` or `klav`" (`prompt.rs:65`).
- On Linux there is not even the hint: `klav_touchid::process_path` returns `None` without the macOS shim (`crates/klav-touchid/src/lib.rs:381`).

With `klavd` unlocked, these operations hand out a value with no presence (`server.rs:2896–3003`, `handle_browser` at `server.rs:1720`):

| Operation | What it gives | CLI that uses it |
|---|---|---|
| `view` with `reveal: true` | every value of an item | `klav item get --reveal` |
| `previous_password` | one previous password | `klav item history --reveal` |
| `totp` | the current code | `klav totp` |
| `generated_value` | one generated password | `klav generated show` |
| `resolve` | the values behind `klav://` references, files downloaded | `klav run`, `klav inject` |
| `autofill` | the values to type into a page | the extension |
| `extension_attach` | the agents' fill events (values the agent decrypted), and the old and new password of an assisted change | the extension |

The threat model records this as residual risk 49 and leaves it "for another ADR". This is that ADR.

The browser bridge doesn't narrow it:

- `klav-native-host` takes the extension's origin from the arguments of whoever starts it (`crates/klav-daemon/src/native.rs:95–120`).
- It lets `view`, `totp`, `autofill`, `previous_password`, `generated_value` and `extension_attach` through (`check_request`, `native.rs:184`).
- Any program can start the real host with a store extension's origin, so "exempt the extension" would mean "exempt any program that starts the host".

The only presence window today is the passkey one (`crates/klav-daemon/src/uv.rs`, ADR 0020 §8):

- `always`, `5m` or `unlocked`, kept in memory with a monotonic clock and lost on lock;
- one for the whole `klavd`: `passkey_presence` loads the setting once and reads one `slot.verified()` (`server.rs:2013–2027`).

ADR 0032 §3 (accepted, not built) asks for Touch ID once per `klav run`/`inject` of a protected environment, and for every Show or Copy of a protected item.

### Problem 2: the `inject` card does not show the command
An agent's `inject` (`klav agent run`, `klav agent inject`, the MCP tools `run_with_secrets` and `inject_file`) goes to the server:

- It is `POST /v1/agent/access` with `Permission::Inject`, one request per item (`crates/klav-sdk/src/actions.rs:96–109`).
- `Inject`'s default effect is `Allow` (`crates/klav-core/src/policy.rs:111–114`).
- When the policy says `ask`, the server builds an `ApprovalRequest` (`crates/klav-proto/src/agent.rs:1141`). It carries the agent, the permission, the vault, the project, the item, the reason, the claims and the grant version. **It carries no command, no working directory and no destination file.**
- An approval's target is grant version, permission, vault, project, item and claimed domain (`target_key`, `crates/klav-server/src/routes/agent_access.rs:308`). For `proxy` it also carries the method, the path and the sandbox.

Yet ADR 0036 (E6.2 and the answer to Q-D), T171 and residual risk 63 say that with `inject: ask` "the card shows the command before each `inject`". That is false today, and `klav proxy issuer add --inject-ask` asks the person to rely on it (`crates/klav-cli/src/cli.rs:999`). Its warnings (`crates/klav-client/src/issuers.rs:348–366`) only say that each `inject` asks first, which is true.

## The owner's decisions (2026-11-17 to 2026-11-19)

Omar decided these on 2026-11-17, the fourth-round answers on 2026-11-18, and the fifth-round answers on 2026-11-19. The ADR records them as given.

**Presence.**

1. **Owner's decision (2026-11-17), revised the same day.** The terminal, the browser extension, the Mac app and any other program need the person's presence (Touch ID) before `klavd` hands out a value. That includes autofill when the window has lapsed. Each case:
   - **The Mac app:** its own unlock with a real verification counts as its presence, and lasts until Klav locks. If `klavd` was unlocked from somewhere else, the app asks once. The person sees nothing new when unlocking from the app.

     *What "nothing new" means (third round):* no new prompt. The words of the unlock dialog do change, to say what the unlock grants (§1.2). With the setting on Always, the app too asks for each value (the third-round answer below).
   - **Everything else:** once per window.

   *Withdrawn wording:* the first version said "The Mac app, verified by its code signature, asks nothing more than it does today". The review showed that `klavd` can't tell which code is at the other end of the socket (§1.1, finding B1), so the exemption by signature was withdrawn. §1.2 designs what replaces it.
2. **Owner's decision (2026-11-17).** The window is configurable with the passkey setting's three values (Always, 5 minutes, While unlocked). The default is 5 minutes. It is kept in memory and lost on lock.
3. **Owner's decision (2026-11-17).** The person's own `klav run` and `klav inject` (`resolve`) use the same window. The protected environments and items of ADR 0032 ask every time.
4. **Owner's decision (2026-11-17).** On Linux, presence is the master password, with the same window.

**The `inject` card.** `inject` asks by default only together with this card.

5. **Owner's decision (2026-11-17).** The command, or the destination file's path, travels end-to-end encrypted to the person's devices; the server keeps only a digest. The card says the text is "according to the agent": Klav does not see the command run.

   **What "keeps only a digest" means exactly (third round).** It is inherent in delivering the command to devices that aren't online:
   - **In the clear,** the server keeps only the digest, in the agent's signed request and in the audit log, for as long as the log lasts.
   - **Encrypted,** it holds the command blob (HPKE to the account's identity, §5.2) until the approval is decided or expires. An hourly sweep deletes the blobs of expired approvals (§5.3). Its backups may keep a copy until they rotate.
   - **Who could ever open it:** only a holder of the account identity's private key, which means the person's unlocked devices. Never the server, its operator, or anyone holding its backups. The agent wrote the description, so it already knows it.
6. **Owner's decision (2026-11-17).** An approval is bound to the exact command (and working directory), or the exact file. "For a while" covers only that same one.
7. **Owner's decision (2026-11-17).** When `inject` asks by default, every already approved agent asks too. Before the update, the person gets the list of agents that change, and signs with presence an explicit exception for each one that should keep going without asking.

**Answers to the first round of proposals** (2026-11-17):

- **P3. Owner's decision (2026-11-17).** One window per terminal session. The browser has its own. A peer with no terminal is keyed by its parent process. §2.1 adds what the review changed inside this (findings B1 and S2).
- **P7. Owner's decision (2026-11-17).** Agents' browser fills ask one presence per extension connection, until lock or close.
- **Revised the same day. Owner's decision (2026-11-17).** Always wins over "one presence per extension connection": with the setting on Always, every agent fill asks for presence. With 5 minutes or While unlocked, it is one presence per extension connection (§3.1).
- **P2. Superseded.** It verified the Mac app by its code signature. Revised decision 1 removes the exemption it served, so the answer has nothing left to apply to.
- **P6. Owner's decision (2026-11-17).** Writes do not ask for presence, as today (risk 76).
- **P12. Owner's decision (2026-11-17).** A plain SHA-256 digest (risk 73).
- **P15. Owner's decision (2026-11-17).** Tasks no longer cover `inject` once the card is on.
- **P17. Owner's decision (2026-11-17).** "Before the update" means when the owner turns the card on, from the sheet in the Mac app or `klav agent inject-card`.
- **The passkey window. Owner's decision (2026-11-17).** It becomes one per session too, keyed like the presence window (finding S5). The default, Always, is unchanged. This changes ADR 0020 §8, which carries a dated note.

**Answers to the questions of the second round** (2026-11-17):

- **Q1. Owner's decision (2026-11-17).** `memoffset`, which isn't cryptographic, is approved as a transitive dependency of `nix` 0.31 with the `socket` feature, only in `klav-daemon`, for `SO_PEERPIDFD` on Linux (§1.1, §9).
- **Q2. Owner's decision (2026-11-17): a stop rule, not an option.** If layer 1 can't confirm that `klavd` can check, on macOS, that the process the kernel reports really holds that socket (§1.1), layer 1 stops and reports what it found. Nothing else of presence is built until Omar chooses between a window per connection and the session key with the residual named.
- **Q3. Owner's decision (2026-11-17).** No holder secret for the extension, now. Agents' browser fills keep one presence per extension connection, and every fill on Always (§3.1). The third round replaced the app's holder secret with a held connection (§1.2); the extension uses neither. Below, "a holder" is a program on a held connection.
- **Q5. Owner's decision (2026-11-17).** `nix`'s `fs` feature is approved in `klav-sdk` (it adds no crate; `klav-cli` already uses it), so the file form of `inject` writes through the directory it opened (§5.1, §9).

**Answers after the second independent review** (2026-11-17):

- **The until-lock grant. Owner's decision (2026-11-17).** It is accepted, and Always wins:
  - any program may ask for `hold` (§1.2);
  - the prompt says plainly "until Klav locks" and never claims to know the asker is the app;
  - with the setting on 5 minutes or While unlocked, a holder reads without asking until lock (decision 1 for the app);
  - **with the setting on Always, nobody skips:** a holder too is asked for each value.

  Decision 2 and §1.2 read accordingly; §1.2 says what the app does and shows under Always.
- **The signed Mac app ignores `KLAV_HOME`. Owner's decision (2026-11-17).**
  - A Developer ID build always uses the default directory. Debug builds and the sample app keep honoring it, and the CLI and `klavd` don't change.
  - Today the guard is `#if os(iOS)`, not a Debug guard (`apps/ios/Shared/KlavHome.swift:3`, `:61`; `apps/ios/Mac/KlavMacApp.swift:80–81`).
  - Layer 5 builds it (§1.2).
- **Linux kernels before 6.5 ask on every command. Owner's decision (2026-11-17).**
  - Without `SO_PEERPIDFD` there is no window: `klavd` fails closed, and each command that hands out a value asks for the master password.
  - There is no fallback to the pid plus the start time (Rejected alternatives).
  - §2.3 says what "the same window" of decision 4 means on such a kernel.
- **Linux and the screen lock: said, nothing built now. Owner's decision (2026-11-17).**
  - `klavd` locks on screen lock only on macOS (`docs/klavd.md:94`). On Linux a window survives the screen lock, as an unlock does today (risk 79).
  - Locking `klavd` with the screen on Linux is separate later work, with no date. P5 is corrected.

Two points of the second review have only one answer, and the ADR states them plainly:

- **The migration keeps scopes exactly.** Nothing in it may widen a grant (§6, K2).
- **The server holds the encrypted command until the approval is decided or expires,** and its backups may hold it longer (decision 5, above).

**Answers after the third independent review** (2026-11-18):

The third review covered only P4, P21, P24, P25 and P26, as written at commit `327e752b`. It didn't cover P22, P23 or the card's layers (7–13). It read the code and the documentation and ran nothing: what it marked "likely" or as a question is written below as something to confirm in a named layer, never as a fact. Its findings are cited as N1–N11, in the review's order.

- **P21, the held connection, stays with three changes. Owner's decision (2026-11-18).**
  - (a) The signed build takes its home from the account record (`getpwuid(getuid())->pw_dir`) and ignores every environment variable, not only `KLAV_HOME` (N1).
  - (b) Only the `unlock` dialog, and the gate's window verification whose text says "until Klav locks", mark a declared connection as held. Every other verification on a declared connection leaves it as it was, and the declaration is dropped when the setting moves to Always (N6).
  - (c) The Developer ID build script checks the hardened runtime flag and the three entitlements on every build, and fails if any is wrong, instead of one check by hand (N10).

  §1.2 reads accordingly.
- **Unlock: say so, and don't queue. Owner's decision (2026-11-18)** (N2).
  - While an unlock prompt is open, a second `unlock` gets `presence_busy` instead of waiting in line.
  - An `unlock` that finds `klavd` already unlocked by another key tells its caller so, instead of succeeding as if the unlock were its own. What the caller sees is Omar's answer to Q-N1 (below).
- **P25, the browser: refuse unless one connection is clearly the one. Owner's decision (2026-11-18)** (N5).
  - With more than one extension connection attached, a fill goes out only if exactly one reports focus. Otherwise the agent gets `browser_ambiguous`, with a `next` that tells the person to bring the browser to the front or close the others.
  - Omar was told the cost. With one browser and one profile, nothing changes. With two browsers or two profiles, the browser has to be in front.
- **P26 is not built. Owner's decision (2026-11-18)** (N3).
  - `klavd` doesn't watch its directory. The 2-second poll stays, and §8 says plainly what the poll doesn't cover.
  - Not building it was the recommendation of the report that put the review to Omar. The reviewer's recommendation was different: it judged P26 ready for Linux only.
- **P4: the existing `passkeys.json` is ignored on upgrade. Owner's decision (2026-11-18)** (N8).
  - It isn't read. A person who had loosened the passkey setting is back on Always, and Klav tells them once, so they choose again (how: Omar's answer to Q-N3, below).
- **Loosening is not retroactive. Owner's decision (2026-11-18)** (N8).
  - A window, or a per-value verification, lasts what the prompt the person approved said.
  - A looser setting applies from the next presence.
- **A debugger's reparenting is accepted as a residual risk. Owner's decision (2026-11-18).**
  - Layer 1 left it unverified whether a debugger's attach makes the debugger the parent of a process on macOS (Plan in layers, item 1, "Not verified; for Omar").
  - Omar accepts it: whoever can debug a program already controls it, as in the B1 case he confirmed.
  - Layer 2 runs the check if it can, and records the result, without stopping for it.
- **Everything else the review named goes into the ADR. Owner's decision (2026-11-18).** These are the corrections that have no real alternative: N4 (`shutdown` and a second `klavd`), N7 (the prompt's duration comes from the window key), the rest of N8 (the password change), N9 (where `presence_busy` works, and the terminal's name) and N11 (the connection count is a hint).

Where writing these down needed a choice Omar's words didn't settle, the fourth round listed it as Q-N1–Q-N5, with options and a recommendation. Omar answered them the same day.

**Answers to the fourth round's questions** (2026-11-18). Omar chose from short descriptions of each option, and took the recommended one each time. The options as they were put to him are under Still open.

- **Q-N1. Owner's decision (2026-11-18): (a).** An `unlock` that finds `klavd` already unlocked by another key answers `ok` with `already_unlocked: true`.
  - Without the master password it grants the caller's key nothing, and the CLI and the app say so: "Klav was already unlocked elsewhere; this unlock gave this terminal nothing. If you didn't unlock it, lock Klav".
  - With the master password, the checked password opens the caller's window (§2.4).
  - He declined (b), a new error, and (c), an extra Touch ID for the caller's own window.
- **Q-N2. Owner's decision (2026-11-18): (a).** While `klavd` is locked, reading and changing the presence and passkey settings both answer `locked`. He was told the cost: `status` stops reporting the passkey setting while locked, and the clients have to accept that (§2.4).
- **Q-N3. Owner's decision (2026-11-18): (a).** At the first unlock after the upgrade, `klavd` checks only whether `passkeys.json` exists, never its contents. If it does, it warns and deletes the file (§2.4).
- **Q-N4. Owner's decision (2026-11-18): (a).** A peer keyed by its connection gets the 5-minute window on that connection, and the prompt says "this connection" (§2.4). He was told that on Linux the browser then asks once every 5 minutes, and declined (b), "this request", one value per verification.
- **Q-N5. Owner's decision (2026-11-18): (a).** P25's rule is applied at `browser_tab`, and again just before each value-carrying event (§3.1). He was told the cost: one more round to the extensions per fill when more than one connection is attached.
- **The loosening's own verification opens nothing. Confirmed by Omar (2026-11-18).** The fourth round had written it from his answer that loosening isn't retroactive, without asking, and it changes today's passkey behavior: today, loosening `passkey_uv` counts as the passkey window's first verification. Asked directly, he confirmed it. The verification of a loosening only authorizes the change, and the next value or passkey use asks once more, with the new window's text (§2.4).
- **An extension connection's prompt says what it grants. Owner's decision (2026-11-18).** §3.1's prompt named one agent and one item, but by his decision on Q3 one presence per extension connection covers every agent fill on that connection until Klav locks (every fill on Always). He chose that the text say so: agents may fill in that browser until Klav locks, and it mentions the fill that caused the prompt. How often it asks doesn't change. He declined one presence per fill, and a 5-minute window (§3.1). On 2026-11-19 he chose that it name the event that caused it, whichever it is (below).

The fourth round, and this record of the answers, also made choices of their own that Omar wasn't asked about: two in the design and three in the wording of §3.1's prompt. Still open lists them in one place, as the ADR's choices, which he can overturn. He answered the three on the wording on 2026-11-19 (below).

**Answers after layer 2's second and third reviews, and on §3.1's prompt** (2026-11-19). Omar was asked about the amendments those reviews made and about the ADR's own choices behind them, and, for layer 4, about the three wording choices of §3.1. He took the recommended option each time but one, the text per event. The options as they were put to him are in layer 2's PR; the ADR's own choices he was asked about are under Still open, each with its answer.

- **The §2.3 amendment. Owner's decision (2026-11-19).** A master password counts as presence only if it is the password of the session `klavd` has unlocked in memory, and that applies always: on an unlocked `klavd`, with the gate on or off. This also confirms T225. He declined the option to apply it only with the gate on, which would have left today's password checks of the operations that already ask open to the swap. A loosening of the passkey setting while `klavd` is locked, with the gate off, has no session to check against, and stays as built (below).
- **The busy rule covers every dialog. Owner's decision (2026-11-19)** (own choice 17). With the gate on, every Touch ID dialog `klavd` shows takes part in the one-prompt-at-a-time rule. He declined limiting it to the gate's own dialogs.
- **One password check at a time. Owner's decision (2026-11-19)** (own choice 18). Another check that arrives meanwhile is answered busy at once: `presence_busy` with the gate on, `conflict` with it off. He was told the residual and accepted it: a program of his own user can keep the limit taken by sending wrong passwords, which denies his own check for as long as it keeps sending. It denies availability only. He declined a queue, which the same program fills instead, and no limit, which costs an Argon2id run per wrong password (§2.3).
- **iOS's password checks move to the session, later. Owner's decision (2026-11-19).** The two `KlavCore` methods that still check a password against the files on disk, `cancel_account_deletion_with_password` and `resume_agents_with_password`, switch to the session's check in a separate PR, after the presence layers, with no urgency. It isn't part of layers 2–6 (Plan in layers, item 2, "Owed, outside layers 2–6"). He declined leaving them as they are.
- **The gate-off loosening of the passkey setting while locked. Owner's decision (2026-11-19)** (own choice 19). It stays as built until layer 6: with the gate off, a loosening while locked still checks the password against the files on disk. He declined answering `locked`, which an older client would see as a new error.
- **The first unlock since `klavd` started. Owner's decision (2026-11-19)** (own choice 13). Kept: the dialog states no window and opens none, and the first value asks once more.
- **The new prompt texts. Owner's decision (2026-11-19)** (own choice 14). Approved as written in `docs/klavd.md` §6.1, in English and Spanish.
- **The other own choices of layer 2. Owner's decision (2026-11-19).** Rows 6, 7, 8, 9, 10, 11, 12, 15, 16, 20, 21 and 22 of Still open's tables are accepted as a block. He saw a one-line summary of each, and accepted them together.
- **"A browser" and "this browser connection". Owner's decision (2026-11-19)** (own choice 3). §3.1's prompt keeps "a browser" on macOS and "this browser connection" on Linux.
- **"Until Klav locks". Owner's decision (2026-11-19)** (own choice 4). Kept short, without "or the browser closes".
- **A text per event. Owner's decision (2026-11-19)** (own choice 5, **overturned**). The prompt names truthfully what caused it: a fill, the fill step of an assisted password change, or an agent's passkey sign-in (`passkey_arm`). His reason, as he accepted it: the dialog is the person's only evidence of what is happening, and calling a passkey sign-in a fill is inaccurate. He saw these examples, in Spanish, with the final wording left to layer 4: «…empezando por el relleno de «GitHub» que pidió «claude-code»», «…empezando por el cambio de contraseña de «GitHub» que pidió «claude-code»», «…empezando por el inicio de sesión con passkey en «github.com» que pidió «claude-code»» (§3.1).
- **The Always text. Owner's decision (2026-11-19).** Unchanged: "let a browser connection receive “claude-code”'s values for “GitHub”", one text for every event (§3.1).
- **Which requests are busy at once while a dialog is open. Owner's decision (2026-11-19)** (own choice 23). Kept as built: a request that is known to ask is answered `presence_busy` at once, and a `grant_change_apply`, which is known to widen only under the session's lock, waits and is answered `presence_busy` when it reaches its prompt. He declined answering every `grant_change_apply` busy at once, which would refuse a narrowing for a dialog it never needed.
- **Connections queued at the staging name after `klavd`'s own. Owner's decision (2026-11-19)** (own choice 24). Served once the socket is in place, as built. He declined closing them: `klavd`'s own connection already proved the socket, and those clients pass the same user check as any other.

**Answers after layer 3's review** (2026-11-19). An independent review of layer 3's PR found eight problems; Omar decided these five points with it. The rest of the fix round's choices are the ADR's own, rows 32–42 of Still open.

- **Exit code 9 stays. Owner's decision (2026-11-19)** (own choice 25). With the gate on and no terminal to ask on, a value command exits with 9.
- **The terminal prints its name before a value's Touch ID dialog. Owner's decision (2026-11-19)** (own choice 28, overturned for values). `klavd` tells the CLI just before it shows a dialog, with the smallest protocol addition, opt-in per request: the envelope's `notify`, and a `notice` line before the answer (`docs/klavd.md` §3). An older CLI, the Mac app and the extension never ask for it, and read answers as before. Nothing about how existing clients read answers changed, so the stop he set for that case didn't apply.
- **A password on stdin never counts as presence for a value. Owner's decision (2026-11-19)** (own choice 26, its first half). Also when a terminal is there: the CLI asks on the terminal and never uses the stdin line for it.
- **An unlock with a password from stdin, with the gate on, unlocks but opens no window. Owner's decision (2026-11-19)** (own choice 26's second half, **overturned** for the gate-on case). The same holds everywhere the CLI sends a master password it didn't read from the terminal. With the gate off, nothing changes.
- **`klav unlock` on an already unlocked Klav asks for no password. Owner's decision (2026-11-19)** (own choice 31, kept and extended). It sends nothing, and when another key unlocked it, says the unlock gave this terminal nothing.

Not asked then, so still the ADR's own choices: rows 1 and 2 of Still open's tables, row 30, and rows 32–42, added by layer 3's fix round. Omar answered 32–42 after the second review (below).

**Answers after layer 3's second review** (2026-11-19). A second independent review of layer 3's PR, after its fix round, found new problems and questioned own choices 32–42. Omar decided these five points with it; the second fix round built them (Plan in layers, item 3).

- **A. The first password unlock since `klavd` started opens no window. Owner's decision (2026-11-19)** (own choice 35, **overturned**). As its Touch ID dialog already did (own choice 13): `klavd` can't read the sealed setting yet, so a question must not promise a window it can't name. `status`'s `presence` sends no `lasts` there, the CLI's question says the unlock opens no window, and the first value asks. The wire value `lasts: setting`, which existed only for this, is gone.
- **B. An unlock whose password the client didn't read on its terminal grants no passkey verification, with the gate on. Owner's decision (2026-11-19)** (own choice 42, **overturned**). A new envelope field, `untyped`, says so (`docs/klavd.md` §3). It already opened no window (his decision 4); now it also isn't ADR 0020 §8's verification for the caller's key. With the gate off nothing changes. As corrected by his decision I: `untyped` is the client's own word, not something `klavd` checks. The CLI sends it for a password from `--password-stdin`; the Mac app and the extension send nothing, because the person types into their own window; and a client that sends nothing counts as typed.
- **C. With the setting on Always, a value's Touch ID dialog names who asks. Owner's decision (2026-11-19).** As the dialogs that open a window do, so the CLI's "Touch ID for the terminal …" line has something to compare with. Built, with this wording, which **Omar approved as built on 2026-11-19** (his decision H, own choice 45):

  | | English | Spanish |
  |---|---|---|
  | Before | show the code of “GitHub” | mostrar el código de «GitHub» |
  | After | show the code of “GitHub” (for the terminal ttys003) | mostrar el código de «GitHub» (para la terminal ttys003) |

  Every value's text gains the same ending, with who asks as the other prompts say it: "a terminal", "a program with no terminal", "a browser", "this connection", "this browser connection" («una terminal», «un programa sin terminal», «un navegador», «esta conexión», «esta conexión del navegador»). A fill for the browser's own window ("fill “GitHub” in a browser") already says who, and keeps its text (own choice 45).
- **D. An item's title in a prompt is a hint, not proof. Owner's decision (2026-11-19).** Renaming an item is a write, and writes need no presence (§3), so a program can give its target the title of an item the person would approve. No code change: the item, not its title, binds the hand-out (own choices 36 and 43). §1.3 and §2.2 say so, and the threat model accepts it as risk 94.
- **E. Own choices 32, 33, 34, 36, 37, 38, 39, 40 and 41 are accepted as a block. Owner's decision (2026-11-19).** The ordering constraints of 32 (a client resends on the connection that got the ask) and 34 (the gate stays off until the Mac app and the extension send `shown`) are now in the plan items of layers 4, 5 and 6.

Rows 43–50, added by the second fix round, were not asked then; Omar answered them after the third review (below).

**Answers after layer 3's third review** (2026-11-19, a third batch). A third independent review of layer 3's PR, after its second fix round, found new problems. Omar decided these five points with it; the third fix round built them (Plan in layers, item 3).

- **F. An item edited between the ask and the hand-out is not handed out. Owner's decision (2026-11-19).** `klavd` remembers, with the ask, the version of the item it asked about (the item's `version`, which every write to its content raises and a sync never lowers; moving it to the trash and restoring it change neither its content nor its `version`), and answers `conflict` if the hand-out finds another, under the session's lock in the same hold that hands it out. This holds for every value request bound to an item (`view`, `totp`, `previous_password`, `autofill`), under Touch ID and under the password sent again: for a resend, the version is the one `klavd` asked about, not the one it reads at the resend. A sync that brings a new version during the dialog counts as an edit. An edit made **before** the ask stays possible (risk 76): a program that changes an item's password makes the old one the newest entry of its history, so "show a previous password of X" then hands out what was the current password a moment before. The prompt's words stay literally true. The layer's own note, not part of the decision: a program that edits in a loop can keep the person from getting a value this way, which adds nothing to what it can already do, since it can lock Klav at any time.
- **G. A `conflict` opens no window. Owner's decision (2026-11-19).** When the answer would have opened a window and the hand-out is refused with `conflict` (the query names another item now, or decision F), the window that answer was going to open is not opened, and the next attempt asks again, by Touch ID and by the password sent again alike. With this, own choices 43 and 44 are accepted: the request is bound to the item also when its answer opens a window.
- **H. The Always wording is approved as built. Owner's decision (2026-11-19)** (own choice 45): the trailing "(for the terminal ttys003)" / «(para la terminal ttys003)», with the variants "(for a terminal)", "(for a program with no terminal)", "(for a browser)", "(for this connection)", "(for this browser connection)" / «(para una terminal)», «(para un programa sin terminal)», «(para un navegador)», «(para esta conexión)», «(para esta conexión del navegador)».
- **I. `untyped` stays as built. Owner's decision (2026-11-19)** (own choice 46). The client declares that a password was not typed; a client that sends nothing counts as typed. It is the client's own word, not something `klavd` checks: the CLI sends it for `--password-stdin`, and the Mac app and the extension send nothing, because the person types into their own window (decision B, corrected; T230).
- **J. Accepted as a block. Owner's decision (2026-11-19):** own choice 47, the question's reader (a paste goes in whole, no cursor movement, escape sequences are dropped), with two fixes: a line past 1024 bytes is refused whole, by reading on to Enter and discarding what is queued then (in a paste of several lines, what the terminal delivers after that instant can still reach the shell: decision M), and `ESC O` with a parameter is dropped whole; 48, the remembered request is `klav-core`'s existing `body_digest`, and a request that can't be serialized is refused; 49, `lasts: setting` is gone from the wire; 50, `autofill` naming an item by its title is still asked about, and refused by the fill after presence, and its ask names the item; and own choice 30, open since an earlier round: the `already_unlocked` text says "this program" instead of "this terminal" when the CLI has no terminal.

**Answers after the third fix round** (2026-11-19, a fourth batch), on the three own choices that round added:

- **K. `resolve` and `generated_value` get bound too, before the gate is turned on. Owner's decision (2026-11-19)** (own choice 51). Not in layer 3's PR: a later round binds `klav run`, `klav inject` and `klav generated show` to what they were asked about, before layer 6.
- **L. A refusal before the item-and-version check opens no window. Owner's decision (2026-11-19)** (own choice 52), as built: the window opens only when the hand-out passes.
- **M. The over-long line is refused as built, and its gap is closed before the gate is turned on. Owner's decision (2026-11-19)** (own choice 53). The reader reads on to Enter and discards what is queued. In a paste of several lines, what the terminal delivers after that instant can still reach the shell; that gap gets its fix and its test before layer 6.

Everything below that isn't one of these sentences is design. Each piece keeps its first-round number (P1–P20); new ones continue from P21. The lists are at the end. Findings of the second review are cited as K1–K2 (blocking) and R1–R10 (should fix), and findings of the third as N1–N11.

## Decision

### 1. Who the peer is

#### 1.1 What the kernel says about the other end of the socket
**P1, rewritten at Omar's direction after finding B1.** `klavd` can't learn reliably which code, or even which process, sends a request. The review read xnu's source and didn't run it; layer 1 confirms each point:

- **macOS: the token follows the socket's last user, not its connector.** `LOCAL_PEERTOKEN`, `LOCAL_PEERPID` and `LOCAL_PEEREPID` resolve the socket's `last_pid` with `proc_find()` and return that process's current identity (`bsd/kern/uipc_usrreq.c`, `uipc_ctloutput`).
  - `last_pid` moves to whichever process last connected, sent or received on the socket (`so_update_last_owner_locked`, `bsd/kern/uipc_socket.c`).
  - `exec` keeps the pid and only bumps the pid version (`bsd/kern/kern_exec.c`).
  - `klavd` has no earlier token to compare a later one with. The first version's line about the token making a reused pid fail to match was wrong.
- **The trick.** A program of the person's user can:
  1. send `SIGSTOP` to `klavd` (same UID);
  2. connect;
  3. fork, and have the child exec any binary it likes with the socket still open;
  4. write everything but the final newline from the parent, and the newline from the child just before the exec;
  5. send `SIGCONT`, and keep using the socket from the parent.

  `klavd` then sees the exec'ed binary, whether it reads the token at accept time or per request. The program can also pass the descriptor to another process (`SCM_RIGHTS`), which then appears as the peer.
- **Linux: credentials are fixed at `connect()`.** `SO_PEERCRED` and `SO_PEERPIDFD` record the connecting process at `connect()` and don't follow later senders. `SO_PEERPIDFD` (Linux 6.5 and later) names that exact process, so a reused pid doesn't match. To be confirmed in layer 1 (layer 1 found: Plan in layers, item 1).
  - The fork and exec trick still works on Linux: the connector can exec any binary under the same pid, or fork and pass the descriptor on.
  - What it can't do is make the connector a process of another session.

**The rule that follows: nothing that protects a value rests on which code the peer is.** What the kernel gives `klavd` is used only as a key with a named residual, or as a hint. §1.3 lists every such point.

**What `klavd` reads**, per request:

- the UID, as today;
- on macOS, `last_pid`, through the audit token;
- on Linux, the pidfd from `SO_PEERPIDFD`, then `/proc/<pid>/stat` for the session, the parent, the start time and the controlling terminal. After reading `/proc` it checks the pidfd again (the process may have exited and the pid been reused while `/proc` was read). That closes finding S3's race.

**How Linux reads it (finding S3).** Through `nix` 0.31's `PeerPidfd`, behind its `socket` feature, which brings in `memoffset` (Omar's decision on Q1; §9). Raw `libc` would have needed `unsafe` in `klav-daemon`, which `CLAUDE.md` doesn't allow. `SO_PEERPIDFD` exists from Linux 6.5. On an older kernel there is no window at all (Omar's decision): `klavd` fails closed, and each command that hands out a value asks for the master password (§2.3). `PR_SET_DUMPABLE` (§8) needs only `nix`'s `process` feature, which adds no crate.

**macOS: the fd-ownership check against pid reuse.** On macOS the pid that `last_pid` names may have exited and been reused by an unrelated process, possibly one in the person's terminal session. A program can steer that: it stops `klavd`, leaves `last_pid` on a child that exits, uses up pids, and waits for the person's next command. So `klavd` checks that the process `last_pid` resolves to holds, right now, a descriptor for the other end of this connection:

- it lists the process's descriptors (`proc_pidinfo` with `PROC_PIDLISTFDS`);
- it compares each socket's connected peer (`proc_pidfdinfo` with `PROC_PIDFDSOCKETINFO`) with its own end.

If none matches, the peer is unknown and gets a window of its own connection. This runs in the Touch ID shim, where `unsafe` is allowed. To be confirmed in layer 1 that `PROC_PIDFDSOCKETINFO` gives what's needed to match the two ends (layer 1 found: Plan in layers, item 1).

**macOS: the same process from first read to last (R3).** The process can exit, and its pid be reused, between the descriptor check and the reads of its session, parent, start time and terminal. A program can stretch that gap by stopping `klavd`. So `klavd` reads the process's unique ID (`p_uniqueid`, through `proc_pidinfo` with `PROC_PIDUNIQIDENTIFIERINFO`) first, before the descriptor check, and again last, after every other read. If the two differ, or either read fails, the peer is unknown. That is the macOS counterpart of Linux's pidfd re-check. To be confirmed in layer 1 that `p_uniqueid` is never reused within a boot; the stop rule below covers this check too (layer 1 found: Plan in layers, item 1).

**Stop rule (Omar's decision on Q2).** If layer 1 can't confirm the descriptor check, or the unique-ID re-check, it stops and reports what it found, and nothing else of presence is built until Omar chooses how macOS keys a terminal peer: a window per connection, or the session key with pid reuse named as a residual. This ADR doesn't assume either outcome.

#### 1.2 The Mac app: a held connection, not a signature or a token
**P21, rewritten in the third round after K1 and R1; accepted by Omar on 2026-11-18 with the fourth round's changes (N1, N2, N6, N10).** What makes a request count as "the app, already verified" is the connection it arrives on:

- the `unlock`, or the gate's window verification, made on a connection that declared `hold` lasts until Klav locks, on that connection only;
- no secret is issued, and nothing that could be replayed travels on the socket;
- nothing depends on what code the peer appears to be.

Everything about it is in this section.

**Why the second version changed.** The second version gave the app a 32-byte holder secret, presented on each request. That failed in two ways:

- **It was a bearer token (R1).** A program that relayed one app request between two watchdog ticks kept the secret until lock, and could use it from any connection.
- **The app never got to ask for it on a Mac with Touch ID (K1).** With Touch ID, `klavd` shows the dialog itself and answers `presence_required` only when Touch ID is missing. The app opens one connection per request (`crates/klav-ffi/src/daemon.rs:150–155`), so it was asked on every request and never sent `hold`.

- **The held connection.** `DaemonEngine` (Rust, in `klav-ffi`; `docs/macos.md`, "El motor es `klavd`") keeps one long-lived connection to `klavd`. On it, one at a time, it sends the requests that can need presence: `unlock`, and the window's operations (§3).
  - Everything else keeps one connection per request, as today, so a long call doesn't hold up the menu bar's status.
  - `klavd` already serves a connection's requests in order until the client hangs up, with no idle timeout (`serve_connection`, `crates/klav-daemon/src/server.rs:1620`).
- **`hold` is a declaration.** It is the first request on that connection, with no argument. It asks for nothing and grants nothing by itself: it tells `klavd` that the connection's `unlock`, or its first window verification, should last until Klav locks, instead of for one window.
  - `klavd` answers with whether the connection is held.
  - Any program may send it. `klav-native-host` doesn't pass it: its allowlist (`check_request`, `crates/klav-daemon/src/native.rs:184`) stays without it.
- **What a verification on a declared connection grants (Omar's decision of 2026-11-18, N6).** The rule is by operation, so it holds whether `klavd` shows Touch ID or the app sends the master password after `presence_required`.
  - **What marks it held,** with the setting on 5 minutes or While unlocked: only two verifications (§2.3) on that connection.
    - An `unlock` that unlocks `klavd`, or one that brings the master password (a real verification of its own). An `unlock` without the password that finds `klavd` already unlocked by another key grants nothing (Omar's decisions of 2026-11-18, N2 and Q-N1).
    - The gate's verification for the `Window` purpose (§4) at the connection's first value, whose text says "until Klav locks" (the table below).
  - **What a held connection reads** with no prompt, until Klav locks or the connection closes: the operations of §3's "Window" row, and nothing else.
  - **What doesn't mark it held.** Every other verification on a declared connection leaves it as it was, and shows its own text:
    - the operations that already ask (§3's "Already asks" rows: `confirm_presence`, `approve_agent` and the others), `passkey_get` and `passkey_create`;
    - `presence_window` and `passkey_uv` loosening;
    - an `EveryTime` presence for ADR 0032's protected set.
  - **Passkeys.** A held connection doesn't skip a passkey prompt. Its passkey uses keep the passkey window (§2.5), keyed by its connection.
  - **With the setting on Always:** a declaration has no effect, and every value asks, on any connection (Omar's decision). When the setting moves to Always, every held connection stops being held at once, because tightening applies at once. Every declaration is dropped too (Omar's decision of 2026-11-18). A move back to 5 minutes or While unlocked doesn't bring either back: the app opens a new long connection and declares again, at its next unlock or when its own Settings moves the setting off Always (the ADR's own choice, not Omar's; Still open). Until then, its long connection is an ordinary one, keyed by its connection (§2.1).
- **The prompts.** `klavd` shows them itself, as for any peer (§3.2). On a declared connection, they say what is granted and for how long, and never who asks. Today the app's unlock says "unlock your vault for the Klav app (account)" / «desbloquear tu bóveda para la app de Klav (cuenta)» (`crates/klav-daemon/src/prompt.rs:102`, `:105`). The words change; the number of prompts doesn't:

  | When | English | Spanish |
  |---|---|---|
  | `unlock` on a declared connection | unlock your vault and let the program that asked use it until Klav locks (account) | desbloquear tu bóveda y dejar que el programa que lo pidió la use hasta que Klav se bloquee (cuenta) |
  | The first value on a declared connection, with `klavd` already unlocked | let the program that asked use your vault until Klav locks | dejar que el programa que lo pidió use tu bóveda hasta que Klav se bloquee |
  | Always: `unlock` | unlock your vault (account) | desbloquear tu bóveda (cuenta) |
  | Always: each value | the value's own text, as for any peer (§3.2) | el texto del valor, como para cualquier par (§3.2) |

  macOS names "Klav" as the process that asks, because `klavd` shows the dialog itself (`klavd.md` §6.1). A program that isn't the app and declares `hold` gets exactly what the words say (risk 77). A dialog the person didn't cause should be canceled.
- **The app's sequences (K1):**

  | Case | What the app does | What the person sees |
  |---|---|---|
  | Unlocked from the app; 5 minutes or While unlocked | Opens its long connection, sends `hold`, then `unlock` on it. Touch ID succeeds, and the connection is held | One Touch ID at unlock, as today, with the new words. No prompt for values until Klav locks |
  | Unlocked elsewhere, then the app used | Opens its long connection and sends `hold`. Its first value request meets the gate, and `klavd` shows the dialog. It succeeds, and the connection is held | One Touch ID at the first value, and none after until Klav locks |
  | A Mac without Touch ID, or Touch ID locked out | As above, but `klavd` answers `presence_required`. The app asks for the master password in its own window and sends the same request again with `password` | The master password once: at unlock, as today, or at the first value |
  | The setting on Always | Sends `hold` all the same, and `klavd` answers that it has no effect | The plain unlock text, then Touch ID for each value, with that value's text |
  | Klav locks (idle, sleep, screen lock, `lock`), or `klavd` restarts | Every held connection is dropped. The app opens a new one when the person unlocks | As in the first row |

  An app `unlock` without the password that finds `klavd` already unlocked by another key grants nothing and is told so (Omar's decision on Q-N1). The app is then in the second row.

- **What `klavd` keeps:** one flag per connection, in memory.
  - It drops them all on lock, sleep, screen lock (macOS), idle lock and exit (P5), and drops one when its connection closes.
  - Nothing is written, logged or derived.
- **What travels:** nothing secret.
  - `hold` carries no value, so nothing needs to hide from `RequestEnvelope`'s derived `Debug` (`crates/klav-daemon/src/protocol.rs:33`).
  - After the verification, the app's requests carry no proof: the proof is the connection.
- **What a relay obtains (R1, T203).** The watchdog polls every 2 s (`TICK`, `crates/klav-daemon/src/server.rs:32`). A program can rename the socket away, bind its own at the path, and rename the original back, all between two ticks. It catches only the connections opened in that gap:
  - **the app's one-request connections:** their requests and answers, which carry no values. Anything the program sends on them is a connection of its own, with an unknown key.
  - **the app's held connection,** only if the app opens it in that gap: at launch, after `klavd` restarts (which locks it), or after the connection drops. The program is then that connection's other end, and reads everything on it until Klav locks, as any relay reads what passes through it.

  There is no token to carry away to another connection. P26, which would have watched the directory, is not built (Omar's decision of 2026-11-18): the 2-second poll stays, and §8 says what it doesn't cover.
- **After a `shutdown` (N4), nothing watches the path.** `shutdown` asks for nothing (§3), and `klavd.lock` is a plain `try_lock` on a file of the user (`crates/klav-daemon/src/server.rs:1137–1145`). A program can:
  1. send `shutdown`;
  2. take `klavd.lock` itself;
  3. run the genuine `klavd` binary with `KLAV_HOME` set to a directory linked to the person's files;
  4. bind its own socket at the real path, and relay to that `klavd`.

  The real `klavd` is gone, so no watchdog looks at the path. The app's held connection, opened through it, is the program's to read, as above. Whether that second `klavd` can also do the Touch ID unlock is a question the review didn't run: layer 2 confirms it (Plan in layers, item 2). T203 states this route.
- **The signed app's home (Omar's decisions of 2026-11-17 and 2026-11-18; N1).** A program that starts the app with `KLAV_HOME` pointing at a directory it controls would have the app connect to its socket and unlock through it. `KLAV_HOME` isn't the only way:
  - **The fallback follows the environment too.** Without `KLAV_HOME`, `KlavHome.directory()` asks `FileManager` for `.applicationSupportDirectory` in the user domain (`apps/ios/Shared/KlavHome.swift:64–65`), which resolves through the process's home.
    - For a process that isn't sandboxed, CoreFoundation likely takes that home from `CFFIXED_USER_HOME`, and possibly from `HOME`. The hardened runtime strips only `DYLD_*`. The review judged this likely and didn't run it; layer 5's checklist does.
    - The program then relays to the real socket. It never touches the real path, so the watchdog doesn't fire, and it reads everything on the held connection until lock.
  - **So the Developer ID build takes its home from the account record** (`getpwuid(getuid())->pw_dir`), appends `Library/Application Support/klav`, and ignores every environment variable. Debug builds and the sample app keep honoring `KLAV_HOME`, and the CLI and `klavd` don't change.
  - **The build knows it is the signed one at compile time.** `scripts/macos/build-app.sh` builds the Developer ID app with `-configuration Release` (`:141`), and `scripts/macos/test.sh` builds Debug (`:68`). Layer 5 puts the environment path behind `#if DEBUG` in `KlavHome.directory()` (`apps/ios/Shared/KlavHome.swift:60–61`), and the Release path reads only the account record. Today every macOS build honors `KLAV_HOME`, and the only guard is `#if os(iOS)` (`:3`).
  - **To be confirmed in layer 5:**
    - nothing in `klav-ffi` reads the environment for the home: the app passes it in (`KlavCore(homeDir:)`, `apps/ios/Shared/CoreService.swift:10`);
    - nothing else builds a Release app for daily use;
    - the app's other lookups of the person's home: `homeDirectoryForCurrentUser` and `KLAV_BROWSER_HOME` in `apps/ios/Mac/Setup/MacSystem.swift:34–38`. They place the CLI link and the browsers' manifests, not the socket.
  - **`docs/macos.md`** documents `KLAV_HOME` for the app ("El directorio es el de la CLI y `klavd`") and says otherwise in layer 5.
- **What a program that reads the app's memory, or injects code into it, gets.** It can use the held connection as the app does.
  - **A Debug build** is signed with `get-task-allow`. Any debugger of the same user attaches, and through the app reads the window's values until Klav locks. `macos.md` says so in layer 5.
  - **A Developer ID build** runs with the hardened runtime (`ENABLE_HARDENED_RUNTIME: YES`, `apps/ios/project.yml:145`), without `get-task-allow`, `com.apple.security.cs.disable-library-validation` or `com.apple.security.cs.allow-dyld-environment-variables`. A program of the same user can't attach to it or load its own library into it, unless it is root or System Integrity Protection is off.
- **Layer 5's checks of the signed build, and a stop rule (R2, N10).** `hold` is turned on for good in layer 6, so what can regress on every build is checked on every build. The rest runs once, by hand.
  - **On every build** (Omar's decision of 2026-11-18). `scripts/macos/build-app.sh` checks the Developer ID app it has just signed (its `release` mode, after `:189–192`), and fails the build if any check is wrong:
    - the signature carries the hardened runtime flag (`codesign -dv` shows `runtime` in its flags);
    - its entitlements (`codesign -d --entitlements -`) include none of `get-task-allow`, `disable-library-validation` and `allow-dyld-environment-variables`.

    Today the script only verifies the signature (`codesign --verify --deep --strict`, `:192`).
  - **Once, by hand (Omar), on layer 5's Developer ID build:**
    - a debugger run as the same user, without root, can't attach (`lldb -p`);
    - the hostile variables. Omar starts the app with `HOME`, `CFFIXED_USER_HOME` and `KLAV_HOME` all pointing at a directory with a socket of its own, and checks which socket it connected to (`lsof -U -p <pid>`). It must be the default one.

    A later change that breaks either of these isn't caught by the script. The home rule is in code (`#if DEBUG`), and a debugger attach is refused only because of the flag and entitlements the script checks.

  `hold` itself sits behind that outcome. Layer 2 builds it answering `not_supported`. Layer 6 turns it on only if layer 5's by-hand checks passed and the script's check is in place. **If any check fails,** `klavd` keeps answering `not_supported`, so no program can get an until-lock grant, and Omar decides between fixing the build and dropping `hold`. Without it, the app's long connection is an unknown peer keyed by its connection (§2.1): it gets the window, 5 minutes by default, and asks again when the window lapses.
- **Linux (R9).** `hold` is macOS-only, and the Linux `klavd` answers it with `not_supported`. On Linux the program that asks collects the master password itself (§2.3), so an until-lock grant would only lengthen what a fake prompt yields. There is no Mac app there either.
- **ADR 0032's protected items aren't weakened.** They ask every time, from any peer, a held connection included (§3, "Every time").
- **A new app against an older `klavd`.** The older `klavd` rejects the unknown `hold` request with `bad_request` "malformed request" (`crates/klav-daemon/src/server.rs:1683`; `Request` rejects unknown variants). The app goes on without it and keeps its long connection.
  - It's safe because an older `klavd` has no presence gate: nothing asks, and nothing was granted.
  - A fake `klavd` that answers that way gains nothing it didn't already have (T203).
- **An older app against a gated `klavd`.** The older app opens one connection per request and never sends `hold`.
  - On a Mac with Touch ID, each value request shows a one-use dialog: the window of its own connection.
  - Without Touch ID, the app shows `presence_required` as an error.
  - The app carries its own `klavd` (`Klav.app/Contents/Helpers/klavd.app`), so this happens only with a `klavd` installed apart. The fix is to update the app.
- **Why the extension doesn't use it** (Omar's decision on Q3). Its agents' fills keep one presence per connection, and every fill on Always (§3.1). Its own values go through `klav-native-host`, which doesn't pass `hold`.
- **Why the CLI doesn't use it.** Each `klav` command is a new process with its own connection. A held connection would have to outlive the command, in a process that the terminal's other programs can reach. The terminal keeps the window (§2).

#### 1.3 Every point where the design trusts who the peer is (finding B1)
| Point | What it reads | What the trick, or passing the descriptor, lets a program do | Status |
|---|---|---|---|
| The source in the Touch ID prompt ("from the terminal", "from your browser", "from the Klav app") | the executable path of `last_pid` (macOS) | Make the prompt name any program, the app included, by exec'ing it | **Hint.** It decides nothing (T140). The prompts on a declared connection never name the app (§1.2) |
| An item's title in a value's prompt or question (§2.4) | the item's title in the vault when `klavd` asks | Rename its target to the title of an item the person would approve, before the ask: renaming is a write and needs no presence (§3) | **Hint** (Omar's decision D of 2026-11-19; risk 94). For `view`, `previous_password`, `totp` and `autofill`, the item `klavd` resolved before asking, at the version it asked about, binds the hand-out: a rename or an edit after the ask gets `conflict` (own choices 36 and 43; Omar's decision F). Since layer 6, `resolve` is bound the same way to every item its references name, and `generated_value` to its history entry (Omar's decision K) |
| The controlling terminal's name in the prompt (§2.4) | the peer's controlling terminal, a device number that layer 2 turns into a name | Name its own terminal. A terminal that is already another session's controlling terminal can't become its own (to be confirmed in layer 1 on both systems; layer 1 found: Plan in layers, item 1) | **Hint**, for the person to compare with the terminal they typed in |
| The window key for a peer in a terminal: session ID and leader start time | Linux: the connector, through the pidfd. macOS: `last_pid`, checked to hold the connection (§1.1) | Its own session only. On macOS, without the fd-ownership check, it could borrow the person's session through pid reuse | **Key with named residual.** The residual is a process that already runs in the person's session (S4, §2.2). If layer 1 can't confirm the macOS check, the stop rule of §1.1 applies |
| The window key for a peer with no terminal: the parent process | the same | Its own children only. An orphan's parent is `launchd`, `init` or a subreaper, which §2.1 treats as unknown | **Key with named residual** (S2: making the browser its parent, T204) |
| The browser's shared window | the parent is the browser | A program registered as a native-messaging host in a manifest the user can write becomes the browser's child (T204) | **Key with named residual** (risk 78) |
| The app's until-lock grant | the connection an `unlock` or the gate's window verification was made on, after `hold` | Nothing: it is bound to the connection, whatever the peer. A relay in place when the app opens that connection is its other end (T203) | **Per connection** (§1.2) |
| An extension connection's presence (§3.1) | the connection | Nothing: it is bound to the connection, whatever the peer | **Per connection**, with S6's residual |
| The passkey window's key (§2.5) | the same key as the presence window | The same as for the presence window | **Key with named residual**, the same as the presence window's |
| `presence_busy` (§2.4) | the key of the prompt that is open; for `unlock`, only that an unlock prompt is open | A program in its own key gets `presence_busy` while the person's prompt is open, and can retry right after; it can't join the person's prompt. A program that sends `unlock` just before the person makes the person's own `unlock` get `presence_busy`, which tells them | **Order only.** It decides nothing about values, and works only where `klavd` shows the prompt (Touch ID) |
| `passkey_flow` on `unlock` (ADR 0020 §8) | a request field | Unchanged: it was never about the peer | — |
| `browser_fill`'s target (`BrowserHub::tab`, `crates/klav-daemon/src/browser.rs:271`) | which attached connection says it has focus | A fake extension says it has focus while the real one doesn't (the person is typing to an agent in a terminal) | **Residual** (S6, N5, §3.1) |

### 2. The window

#### 2.1 One window per terminal session; the browser's own; the parent for the rest
P3 is Omar's decision. What follows is how it is keyed.

- **A peer in a terminal** (it has a controlling terminal): the key is its session ID together with the start time of that session's leader, so a session ID the system reuses later doesn't inherit a window.
- **A peer with no terminal:** the key is its parent process (pid and start time). On macOS every app started from the Dock or Finder, and every process those apps start without a pty, is in `launchd`'s session (checked on 2026-11-17 with `getsid` on this Mac: the browser and other GUI apps all report session 1). That is why the session can't be the key there.
  - **The browser's window.** The extension's hosts are children of the browser, so they share it.
  - **A program that starts `klav-native-host` or `klav` itself** is the parent of what it starts, so it gets a window of its own.
  - **Orphans (finding S2).** After a double fork, a process's parent is `launchd` (pid 1) on macOS, or `init` or a subreaper on Linux, so every orphan would share one key. A parent that is pid 1, or the user's service manager (`systemd --user`, the usual subreaper), is treated as **unknown**. Another process can't read whether a process is a subreaper (`PR_GET_CHILD_SUBREAPER` reads only the caller's own flag), so layer 1 recognizes the service manager by its executable. If that can't be done reliably, Linux keys every no-terminal peer by its connection.
- **The Mac app** has no window on its held connection (§1.2). Its other connections, and an app without `hold`, are a peer with no terminal whose parent is `launchd`, so unknown: a window of their own connection.
  - *A note from the third review:* a program that starts the app's binary as its own child is that process's parent. The app's other connections then share that program's window, which is the program's own key (Q-L1.1). Nothing on the held connection changes.
- **When none of this can be read** (the process left, or on macOS the fd-ownership check or the unique-ID re-check fails), the peer gets a window of its own connection only. For a peer that opens one connection per command, that amounts to Always: it fails closed. On a Linux kernel without `SO_PEERPIDFD` there is no window at all (§2.3).
- **Reading the start time and the controlling terminal** of another process: `proc_pidinfo` on macOS, `/proc/<pid>/stat` on Linux. To be confirmed in layer 1 (layer 1 found: Plan in layers, item 1).

#### 2.2 The honest limit
A window is shared by everything in its session, or everything under the same parent. These routes reach a window without the person's presence:

- **Same session.** An agent running in the person's terminal, or a command started from it, reads inside that terminal's window (T141, T142).
- **Code the person's next shell runs** (finding S4). Writing `~/.zshrc`, `~/.bashrc`, `PROMPT_COMMAND`, a `.envrc` that `direnv` loads, or a `klav` placed earlier in the `PATH` makes the next shell the person opens run the program's code in the person's session. No Accessibility permission and no access to an open terminal is needed.
- **Typing into an open terminal** (finding S4):
  - `tmux send-keys` and `screen -X stuff` into a multiplexer session;
  - AppleScript's `do script` into Terminal, which needs the Automation permission, not Accessibility;
  - `TIOCSTI` on a Linux kernel that still allows it.
- **A request timed to the person's own** (finding S4). A program in another session sends its request while the person is about to approve their own. The Touch ID dialog can't show which session asks, beyond the terminal's name (§2.4).
- **An `unlock` started by another peer** (finding S4). Unlocking counts as a verification for the peer that unlocked (§2.3). A program that starts `unlock` gets a window from the person's Touch ID. So the `unlock` prompt says the window and the terminal (§2.4), not only "unlock".
  - **The race (N2).** A program sends `unlock` (on a declared connection, after `hold`) just before the person's own. The person approves the one dialog they expected, and the program's connection gets the window, or is held until lock.
  - **Today the person's `unlock` then succeeds silently.** It waits on `state.unlocking` (`crates/klav-daemon/src/server.rs:2715`). With no password, a queued `unlock` that finds `klavd` unlocked returns `ok` with no verification (`:2718–2738`).
  - **Omar's decision of 2026-11-18.** While an unlock prompt is open, a second `unlock` gets `presence_busy`. An `unlock` that finds `klavd` already unlocked by another key tells its caller so (§2.4).
  - **Where it works.** Only where `klavd` shows the prompt, a Mac with Touch ID. Where the client collects the master password, no prompt is open in `klavd`. There an `unlock` without the password can't succeed, so a program needs the password itself to win this race.
- **The browser's children** (T204): a program the browser starts as a native-messaging host shares the browser's window.
- **An item that wears another's title** (Omar's decision D of 2026-11-19; risk 94). With Always, or outside a window, the prompt names the item by its title, and a program can rename items without presence. It can give its target the title of an item the person expects to approve, or ask for its target while the person expects a request for that title. The person approves a title, not an item. For the four requests bound to an item (`view`, `previous_password`, `totp`, `autofill`), a rename or an edit after the ask is caught (`conflict`, Omar's decision F); one before it isn't. An ask that opens a window names who and for how long, and no item at all. Since layer 6, `resolve` and `generated_value` are bound too (Omar's decision K): each reference is resolved to its item before the ask, and a swap of the item behind a reference, or of the history entry, between the ask and the hand-out is `conflict`. Before layer 6 they were bound to no item (own choice 51).
- **Linux with Yama's `ptrace_scope` at 0** (a note from layer 1's review, for Omar; not a decision). A program of the same user can `ptrace` a process inside the person's terminal session, or take one of its descriptors with `pidfd_getfd`, and act inside that session's window. Layer 1 can't close it: the kernel names the session's process, which is the one acting. `PR_SET_DUMPABLE` protects `klavd`, not the person's shell.

The skill tells agents to run in their own terminal, but it is not a barrier (T132). An agent the person runs in their own shell is as trusted as that shell for the length of the window. Whoever wants less picks Always.

#### 2.3 What a real verification is
A real verification is:

- Touch ID through `klav_touchid::authenticate`, which `klavd` already shows for the operations that already ask (`State::touch_id` in `crates/klav-daemon/src/server.rs`, through the `touchid::Biometric` seam);
- on a Mac without Touch ID, the master password;
- on Linux, the master password (decision 4).

**How a master password is checked** (amended after the second layer-2 review, finding 1; confirmed by Omar on 2026-11-19, gate on or off). A password counts only if it is the password of the session `klavd` has unlocked in memory: with the Secret Key, it must derive that session's local key, compared in constant time (`klav_core::crypto::local::password_derives_local_key`, through `klav_client::PasswordCheck`, which `klavd` keeps from the unlock). No file decides it: a program that replaces the account files in the home can make the person's own password fail, never make its own count. This read "checked with `unlock_with_password` as `confirm_presence` already does": a password that opened the files on disk counted, so a program that put a consistent account of its own there, under a password it chose, proved presence with that password (T225). The same check covers every place a password stands in for presence on an unlocked `klavd`, with the gate off too: the gate's window verification, the operations that already ask and take a `password` (§3's «Already asks» rows; `confirm_presence` takes none), the passkey and presence settings, and an `unlock` while unlocked. The one exception is a loosening of the passkey setting while `klavd` is locked, with the gate off: there is no session to check against, so it still checks the files on disk, until layer 6 (Omar's decision of 2026-11-19, own choice 19). One password is checked at a time, and another that arrives meanwhile is answered busy at once (Omar's decision of 2026-11-19, own choice 18). He accepted the residual: a program of the person's user that sends wrong passwords back to back keeps the person's own check refused while it sends. That denies availability only.

Unlocking `klavd` counts as the unlocking peer's verification, for its key, and on a declared connection as §1.2 describes.

**Decision 4's "same window" on a Linux kernel before 6.5** (Omar's decision): there is none. Without `SO_PEERPIDFD`, `klavd` can't key a peer safely (§1.1), so every command that hands out a value asks for the master password, as the direct mode does.

**What decision 4 protects, and what it doesn't (finding S1).**

- **It protects against** a program that doesn't know the master password: it can't read values until the person types the password for its key.
- **It doesn't protect against** a program that asks the person for the password itself. That can be:
  - a window of its own;
  - a replacement `klavd` that answers `presence_required` (T203);
  - on X11, any client that reads other clients' keystrokes.

On Linux, decision 4 makes typing the master password a routine every 5 minutes. So a fake prompt there is ordinary, not surprising. On macOS a password prompt appears only when Touch ID isn't available, which makes it rarer and more noticeable.

**P5, confirmed by Omar on condition that the second review passes; corrected in the third round.**

- **What drops every window and every held connection.** Locking and sleeping (they lock `klavd`), and on macOS the screen lock.
- **On Linux the screen lock doesn't.** `klavd` doesn't lock with the screen there (`docs/klavd.md:94`), so a window survives it, as an unlock does today (Omar's decision; risk 79). Locking `klavd` with the screen on Linux is later work, with no date.
- **A window also ends** when its session's leader, or its parent, exits.

#### 2.4 The setting, and the prompt
**P4, revised in the third round after R4; accepted by Omar on 2026-11-18 with the fourth round's changes (N8).**

- **Where it lives.** In `klavd`'s local data, not in a plain file. It is sealed with the device's local key (spec §12.2: kind `0x41`, AAD with `klav/v1/local/data` and the purpose `presence`), with the same three values and the same `Window` type. The local key is derived from the KEK, so a program of the same user can't write a valid setting: an edited blob fails to open.
- **When it is read.** At unlock, into memory. `klavd` uses that copy until it locks, and writes a change to memory and to the store together. Editing or swapping the stored blob while `klavd` is unlocked changes nothing until the next unlock. To be confirmed in layer 2 that `klavd` holds the local key at unlock: it opens the local identity (`0x40`) with it.
- **The defaults.** Missing means **5 minutes**, the decided default. A blob that doesn't open, or another version, means **Always**.
- **Changing it.** Loosening asks for a real verification; tightening asks for nothing (as in ADR 0020 §8).
- **Loosening is not retroactive** (Omar's decision of 2026-11-18).
  - A window, or a per-value verification, lasts what the prompt the person approved said. A verification made under Always covers its one value, and a 5-minute window stays 5 minutes after a move to While unlocked.
  - The looser setting applies from the next presence.
  - **The loosening's own verification opens nothing** (confirmed by Omar on 2026-11-18). It only authorizes the change, and its prompt names the change, not a window. The next value, or passkey use, asks once more, with the new window's text. Today `passkey_uv` loosening counts as the passkey window's verification (`slot.set_verified`, `crates/klav-daemon/src/server.rs:2071–2073`, and `docs/klavd.md`'s passkey window: "as do … the one that loosened the setting"). Layer 2 drops that, for both settings, and updates `klavd.md`.
  - Tightening still applies at once, to windows already open.
- **While `klavd` is locked** (Omar's decision on Q-N2, 2026-11-18). `klavd` has no local key to seal with, and no copy in memory. So `presence_window` and `passkey_uv`, reading or changing, answer `locked`, and Settings shows the value after the next unlock. Today `passkey_uv` works while locked: it writes `passkeys.json` (`server.rs:2058–2079`).
  - **`status` stops reporting the passkey setting while locked** (the cost Omar was told, and accepted). Today `klavd` always sends `passkey_uv` in `status` (`crates/klav-daemon/src/protocol.rs:1119`). The Rust clients read it with `#[serde(default)]`, and the extension with a fallback (`apps/extension/src/ui/popup.ts:1284`), both to Always.
  - So a client that reads `status` while locked must not show that default as the person's setting. Layer 2 leaves the field out of `status` while locked. Layers 3–5 make the CLI, the extension and the app show the setting only from an unlocked `klavd`.
- **A master password change** changes the KEK, so the local key with it, and the clients re-seal their local data (spec §12.2; not built, "fase futura"). The presence and passkey blobs go in the list of what it re-seals. Otherwise they stop opening, and both settings fall to Always.
- **The upgrade: the existing `passkeys.json` is ignored** (Omar's decision of 2026-11-18).
  - Its value isn't read. A person who had loosened the passkey setting is back on Always, the passkey setting's default for a missing blob.
  - Klav tells them once, so they choose again (Omar's decision on Q-N3, 2026-11-18):
    - at its first unlock after the upgrade, `klavd` checks only whether the file exists, never its contents;
    - if it does, the unlock's answer carries a warning ("Klav no longer reads your old passkey setting: passkeys now ask every time. Choose again in the extension's settings"), which the client that unlocked shows. To be confirmed in layers 3–5 that the CLI, the extension and the app each show an `unlock` answer's warnings;
    - `klavd` then deletes the file, so the warning comes once.
  - A person whose file already said Always is told too. That costs one sentence, and keeps the file unread.
- **The limits (risk 75).** A program of the same user can still:
  - delete the blob, which returns the setting to 5 minutes at the next unlock;
  - put back an older sealed copy, which returns it to a value the person once chose.

  It can't write "While unlocked" if the person never chose it. Settings shows the value `klavd` uses, so the person would see the change after the next unlock.
- **Why not a file.** A `presence.json` would be re-read on every use, as `passkeys.json` is (`uv::load`, `crates/klav-daemon/src/server.rs:2019`). A program could then write `{"v":1,"window":"unlocked"}` and loosen Always or 5 minutes to "until lock" (R4).
- **The passkey setting moves too,** in layer 2, with the same rules and its own default: missing means Always. The same edit loosens the passkey window today. ADR 0020 §8's note says so.

**P24, new in the third round; accepted by Omar on 2026-11-18 with the fourth round's changes (N2, N7, N9).** The prompt and the order of prompts (finding S4):

- **The prompt names the peer's controlling terminal** when it has one: "let the terminal ttys003 use your vault for 5 minutes" / «dejar que la terminal ttys003 use tu bóveda durante 5 minutos». A peer with no terminal is "a program with no terminal" / «un programa sin terminal».
  - Layer 1 gives `klavd` only the terminal's device number (`Peer.terminal: Option<u64>`, `crates/klav-daemon/src/peer.rs:72`). **Layer 2 turns it into a name:**
    - on macOS with `devname_r` and the caller's buffer, in the Touch ID shim, where `unsafe` is allowed (`devname`'s static buffer is shared between threads: second layer-2 review, finding 6);
    - on Linux by decoding the major and minor numbers (`/dev/pts/N` for the pseudo-terminals).

    To be confirmed in layer 2 on both systems. A number it can't name is shown as "a terminal" / «una terminal» (the ADR's own choice, not Omar's; Still open).
- **The prompt's duration comes from the window key** (N7, and Omar's decision that a verification lasts what its prompt said):
  - **A session or parent key:** "for 5 minutes", or "until Klav locks" with While unlocked.
  - **A connection key** (an unknown peer, an orphan, and on Linux every peer with no terminal, the browser's hosts included: Q-L1.2). It says "this connection", and the window stays on the connection (Omar's decision on Q-N4, 2026-11-18): "let this connection use your vault for 5 minutes" / «dejar que esta conexión use tu bóveda durante 5 minutos». On Linux the browser then asks once every 5 minutes per connection of its host, which Omar was told.
    - That is true of a connection that closes after one request, which then gets less than the words say.
    - It is also true of a long one: `klav-native-host` relays its browser port over one `klavd` connection (`crates/klav-daemon/src/native.rs`, `run`), and the app without `hold` keeps one too (§1.2).
  - **No window** (a Linux kernel without `SO_PEERPIDFD`, §2.3): the prompt names only what it hands out, and says nothing about a window.
  - **Always:** the value's own text (§3.2).
  - **Where the client asks** (Linux, a Mac without Touch ID, Touch ID locked out), the CLI, the extension's frame or the app words the password prompt, and doesn't know the key. So `presence_required` carries what the prompt must say: the key's kind (session, parent, connection or none), the window (Always, 5 minutes or While unlocked) and the terminal's name. Layers 3, 4 and 5 word their prompts from it, with the same rules as above.
    - Since layer 3's review it also carries what the password grants, `lasts` (5 minutes, until Klav locks, or missing for one value), and for one value its kind and title as data (`value`), so each client words it in its own language (findings 4 and 6). `klavd` checks a password only as the answer to the ask it last sent that connection, unchanged: same object, same request, same item. Otherwise it asks again and leaves the password unchecked (finding 2, own choice 32). `status` carries the same for an `unlock` (`presence`), and a password `unlock` opens only what the client's question said (`shown`, finding 1, own choice 34).
- **The CLI prints the same terminal name** on its own terminal before it asks (`klav: Touch ID for the terminal ttys003`), so the person can compare the two (N9).
  - Before an unlock's Touch ID it prints that line from `status`; before a value's, when `klavd`'s notice says the dialog opens now (Omar's decision 2 of 2026-11-19; `docs/klavd.md` §3). With no controlling terminal the line says "this program". Before a master-password question it writes `klav: master password for the terminal ttys003`, then what the password grants.
  - It must name its **controlling** terminal, the one `klavd` reads. `ttyname` names the terminal on a given descriptor, which can differ when standard input or output is redirected.
  - Layer 3 reads the CLI's own controlling terminal's device number the way layer 1 reads a peer's, and names it with layer 2's conversion. So both sides name the same device the same way.
  - `ttyname` on `/dev/tty` likely gives `/dev/tty` itself, not the terminal's name. Layer 3 confirms that before using it. `nix`'s `term` feature (§9) stays approved in case layer 3 needs it.
- **No queue behind an open prompt.** While a presence prompt is open for one key, a request from another key that needs presence gets `presence_busy` at once, instead of a second dialog right after the first. The CLI and the extension say "another program is asking for Touch ID; try again". That stops a program from lining up its dialog to appear the moment the person finishes their own.
  - **It works only where `klavd` shows the prompt** (N9): a Mac with Touch ID. On Linux, on a Mac without Touch ID, or with Touch ID locked out, the client collects the master password (§3.2), no prompt is open in `klavd`, and the rule does nothing.
- **`unlock` (Omar's decision of 2026-11-18, N2).**
  - **It isn't queued.** While an unlock prompt is open, a second `unlock`, from any key, gets `presence_busy` instead of waiting on `state.unlocking`.
  - **It says when the unlock wasn't its own.** An `unlock` that finds `klavd` already unlocked by another key tells its caller so (Omar's decision on Q-N1, 2026-11-18):
    - the answer is `ok` with `already_unlocked: true`;
    - without `password`, it grants the caller's key nothing: no window, and no held connection. The CLI and the app say "Klav was already unlocked elsewhere; this unlock gave this terminal (or app) nothing. If you didn't unlock it, lock Klav";
    - with `password`, the checked password is the caller's own real verification (§2.3): it opens the caller's window, or on a declared connection marks it held, and the answer still carries `already_unlocked`.

    `klavd` records the key that unlocked it, until it locks. An `unlock` from that same key answers as today.
- **The `unlock` prompt** says the window: "unlock your vault for the terminal ttys003, and let it use the vault for 5 minutes".

#### 2.5 The passkey window, per session
The passkey window becomes one per key as well (Omar's decision, above). `passkey_presence` (`server.rs:2013–2027`) keeps `uv::load` for the setting, but reads and writes `verified` by the requesting key instead of one `slot.verified()`.

- The browser's passkey uses come through the browser's hosts, so on macOS they share the browser's key. On Linux each host connection has its own (Q-L1.2).
- The default, Always, doesn't change, and neither does the passkey frame's one-use unlock (`passkey_flow`).
- With the gate on, a password `unlock` the client didn't read on its terminal (`untyped`) is no passkey verification for the caller's key (Omar's decision B of 2026-11-19). `untyped` is the client's own word, which `klavd` doesn't check; a client that sends nothing counts as typed (his decision I).
- ADR 0020 §8 carries a dated note.

### 3. What counts as handing out a value

**P6, the table, revised at Omar's direction after finding M1 (the decision on writes is Omar's).** A request needs the gate when its answer, or an event sent on its connection afterwards, carries a secret value. Each `Request` variant of `crates/klav-daemon/src/protocol.rs:47`, **taken with its argument** (`view` with or without `reveal`, `decide_*` approving or denying, `grant_change_apply` widening or narrowing, `passkey_uv` loosening or tightening), sits in exactly one row below. Layer 2 turns this table into one exhaustive `match` without `_`, so a new operation doesn't compile until someone places it.

| Gate | Operations | Why |
|---|---|---|
| **Window** (decisions 1–4) | `view` with `reveal: true`, `previous_password`, `totp`, `generated_value`, `resolve`, `autofill` | They return a value |
| **Per extension connection, or every fill on Always** (§3.1) | `extension_attach` | Its events carry agents' values |
| **Every time** (decision 3) | `view` with `reveal`, `previous_password`, `totp`, `generated_value` and `resolve` when the item is in ADR 0032's protected set, from any peer, a held connection included. Not `autofill`: ADR 0032 §3.1 keeps the browser's autofill of a protected login as it is (residual risk 45), so it uses the window like any other autofill | ADR 0032 §3.1 |
| **Already asks**, with its own window | `passkey_get`, `passkey_create` (the passkey window, now per key: §2.5) | ADR 0020 §8 |
| **Already asks** (unchanged) | `approve_agent`, `decide_approval` and `decide_task` approving, `add_to_task`, `offer_task`, `grant_change_apply` widening, `proxy_use`, `proxy_grant`, `proxy_revoke`, `proxy_issuer_add`, `proxy_issuer_remove`, `resume_agents`, `cancel_account_deletion`, `confirm_presence`, `passkey_uv` loosening (whose verification no longer opens the passkey window: §2.4) | Presence already |
| **Asks** (new) | `presence_window` loosening (§2.4), `inject_card_apply` (§6) | A real verification |
| **Declares** (new) | `hold` (§1.2) | No verification and no value of its own: it scopes the connection's `unlock`, or its first window verification. Answered `not_supported` on Linux, and on macOS until layer 6 turns it on after layer 5's checklist |
| **An agent's own proof** (unchanged) | `agent_passkey_arm`, `agent_passkey_use`, `agent_rotate_begin`, `agent_rotate_confirm`, `agent_rotate_cancel`, `agent_rotate_pending`, `browser_fill` | An agent's signed request and task, or values the agent brought. The values reach a page only through an attached extension (§3.1) |
| **The browser's channel** (unchanged) | `browser_tab`, `extension_reply` | The active tab's origin, and an attached extension's report. Neither carries a signed request or a value |
| **No value** | `status`, `unlock`, `lock`, `sync`, `reset_cache`, `vaults`, `projects`, `create_vault`, `create_project`, `list`, `view` without `reveal`, `create`, `edit`, `trash`, `suggest`, `passkey_candidates`, `attach`, `agents`, `deny_agent`, `approvals`, `decide_approval` and `decide_task` denying, `tasks`, `end_task`, `task_log`, `agent_exposure`, `revoke_agent`, `agent_revocations`, `grant_editor`, `grant_change_prepare`, `grant_change_apply` narrowing, `inject_card_prepare` (§6), `presence_window` reading or tightening, `passkey_uv` reading or tightening, `proxy_status`, `proxy_grant_preview`, `proxy_issuer_preview`, `pause_agents`, `audit_log`, `verify_audit`, `sandbox_list`, `sandbox_list_flagged`, `sandbox_list_checked` (added by layer 2: the code had it and this table didn't; it lists, with the proxy pin checked, and returns no value), `sandbox_revoke`, `item_activity`, `audit_status`, `audit_reset`, `generator_record`, `generator_history`, `generator_delete`, `password_history`, `vault_health`, `import_add`, `import_preview`, `import_apply`, `import_cancel`, `resolve_pending`, `reused_offer`, `task_progress`, `health_settings`, `shutdown` | Metadata, or a write the caller brings. `import_preview` returns titles, user names, hosts and counts, never a value (`crates/klav-import/src/plan.rs:105`). `approvals` returns the decrypted command of an `inject` card (§5.4) |

**Writes stay without presence** (Omar's decision on P6). A program of the same user can still `edit` a login to add its own site as the person, and the person's autofill would then fill there (risk 76). It can also change an item's password before an ask: the old one becomes the newest entry of the history, so "show a previous password of X" then hands out what was the current password (Omar's decision F; an edit after the ask is a `conflict`). `vault_health` stays without presence too: it names which logins share a password, which T103 keeps from agents, but not the password.

**`shutdown` stays without presence**, and a program can also simply kill `klavd`. What that allows is T203 (§8).

#### 3.1 `extension_attach` and the agents' browser fills
P7 is Omar's decision, and so is "Always wins". What follows is how it works and what it doesn't cover.

- **Attaching stays free.** The real extension attaches when the browser starts, and a Touch ID at every browser launch would teach the person to approve prompts blindly.
- **When the presence comes.**
  - With 5 minutes or While unlocked, the first event that would carry values on a connection (`fill`, the fill step of `agent_rotate_begin`, `passkey_arm`) asks for presence. The connection then stays verified until `klavd` locks or the connection closes.
  - With **Always**, every such event asks, with no exception.
  - A held connection (§1.2) doesn't skip this presence, and `klav-native-host` doesn't pass `hold` (Omar's decision on Q3).
- **The prompt says what it grants** (Omar's decision of 2026-11-18). With 5 minutes or While unlocked, one presence covers every agent fill on that connection until Klav locks, not only the event that caused it. So the text says that agents may fill until Klav locks, and names the event that caused it (Omar's decision of 2026-11-19, below). How often it asks doesn't change.

  | Case | English | Spanish |
  |---|---|---|
  | A fill, 5 minutes or While unlocked, macOS | let agents fill in a browser until Klav locks, starting with “claude-code”'s fill of “GitHub” | dejar que los agentes rellenen en un navegador hasta que Klav se bloquee, empezando por el relleno de «GitHub» que pidió «claude-code» |
  | A fill, 5 minutes or While unlocked, Linux | let agents fill through this browser connection until Klav locks, starting with “claude-code”'s fill of “GitHub” | dejar que los agentes rellenen por esta conexión del navegador hasta que Klav se bloquee, empezando por el relleno de «GitHub» que pidió «claude-code» |
  | The fill step of an assisted password change, macOS (example; layer 4 words it) | let agents fill in a browser until Klav locks, starting with “claude-code”'s password change for “GitHub” | dejar que los agentes rellenen en un navegador hasta que Klav se bloquee, empezando por el cambio de contraseña de «GitHub» que pidió «claude-code» |
  | The fill step of an assisted password change, Linux (example; layer 4 words it) | let agents fill through this browser connection until Klav locks, starting with “claude-code”'s password change for “GitHub” | dejar que los agentes rellenen por esta conexión del navegador hasta que Klav se bloquee, empezando por el cambio de contraseña de «GitHub» que pidió «claude-code» |
  | An agent's passkey sign-in, macOS (example; layer 4 words it) | let agents fill in a browser until Klav locks, starting with “claude-code”'s passkey sign-in to “github.com” | dejar que los agentes rellenen en un navegador hasta que Klav se bloquee, empezando por el inicio de sesión con passkey en «github.com» que pidió «claude-code» |
  | An agent's passkey sign-in, Linux (example; layer 4 words it) | let agents fill through this browser connection until Klav locks, starting with “claude-code”'s passkey sign-in to “github.com” | dejar que los agentes rellenen por esta conexión del navegador hasta que Klav se bloquee, empezando por el inicio de sesión con passkey en «github.com» que pidió «claude-code» |
  | Always (per event, unchanged) | let a browser connection receive “claude-code”'s values for “GitHub” | dejar que una conexión del navegador reciba los valores de «claude-code» para «GitHub» |

  - The two settings give the same text: for this presence, 5 minutes and While unlocked both last until Klav locks or the connection closes (Omar's decisions on P7 and Q3). The words are the most it can last: a connection that closes first, when the browser quits or restarts the extension, gets less, as with §2.4's "this connection". The text says "until Klav locks" and not "or the browser closes" (Omar's decision of 2026-11-19, own choice 4).
  - "A browser" is a hint, as in §3.2. On Linux the wording follows §3.2's: "this browser connection" (Omar's decision of 2026-11-19, own choice 3).
  - **A text per event** (Omar's decision of 2026-11-19, which overturned the ADR's own choice 5 of one text for all three). The prompt names truthfully the event that caused it: a fill (`browser_fill`), the fill step of an assisted password change (`agent_rotate_begin`), or an agent's passkey sign-in (`passkey_arm`). The dialog is the person's only evidence of what is happening, and calling a passkey sign-in a fill would be inaccurate.
    - So there are three texts per language, and per system (macOS and Linux). The fill's are the ones above. The assisted change's and the passkey sign-in's are examples: Omar saw the Spanish ones, and their final wording is layer 4's, written natively in each language, never as a literal translation of the other.
    - The passkey sign-in names the site of the passkey `klavd` armed: the rpId of the login's passkey in the vault, which `klavd` checked against the tab's host (`docs/klavd.md`, `agent_passkey_arm`). Never the site the agent claims (T140, below). How the dialog and the frame get it is layer 4's to settle.
    - The Always text stays one text for every event (Omar's decision of 2026-11-19).
  - Where the extension's frame asks for the master password instead (§3.2), it shows the same text. How the frame gets the agent's name, the item's title, the event and, for a passkey, its site from `klavd` is layer 4's to settle.
  - The agent's name and the item's title are cleaned and quoted like any outside name (T140). The item's title comes from `klavd`'s vault, looked up by the item the agent's signed fill names.
  - The site the agent claims never enters the dialog. The first version quoted `<site>`, which T140 forbids (finding S6).
  - When more than one extension connection is attached, the prompt says so: "…; 2 browser connections are attached". That count is a hint (N11): two browsers, or several profiles of one, each attach a connection, so two is ordinary.
- **If the presence fails or is canceled,** the fill answers `denied` to the agent, with `next` saying the person declined in the browser.
- **Which connection gets the fill** (findings S6 and N5).
  - **Today.** `BrowserHub::tab` asks every attached connection for its active tab, newest first, and takes the first that reports focus. If none does, it takes the newest (`crates/klav-daemon/src/browser.rs:246–271`). The third version said "the first attached", which was wrong.
  - **Why that isn't enough.** `attach` re-pushes a connection, so re-attaching makes it the newest (`browser.rs:124–132`). The real extension reports its window's `focused` (`apps/extension/src/background/agents.ts:72`), which is false while the person types to an agent in a terminal. So a fake that attaches last, and doesn't claim focus, gets the fill.
  - **P25, accepted by Omar on 2026-11-18 in this form (N5).** With one extension connection attached, a fill goes to it, as today. With more than one, a fill goes out only if exactly one reports focus. Otherwise `klavd` refuses with `browser_ambiguous`, and the agent's `next` tells the person to bring the browser to the front or close the others.
  - **Where it is checked** (Omar's decision on Q-N5, 2026-11-18). The choice of connection is made at `browser_tab`, and the value-carrying events (`browser_fill`, the fill step of `agent_rotate_begin`, `passkey_arm`) route by the tab string it returned (`BrowserHub::route`). So `klavd` applies the rule at `browser_tab`, and again just before each value-carrying event: with more than one connection attached, it asks each for focus again, and sends only if the tab's connection is still the only one that reports it.
  - **The cost** (told to Omar). With one browser and one profile, nothing changes. With two browsers or two profiles, the browser has to be in front, and each fill costs one more round to the extensions.
  - **What it buys.** A fake no longer wins by being the newest. It still wins when it is the only connection that claims focus, for instance while the real browser is behind the terminal, or when it is the only connection attached. The prompt comes exactly when the person asked an agent to fill, so the person is likely to approve it. The first version said the prompt would come "at a moment when they didn't start one", which was false.
  - What T198 does: one presence per connection (or per fill on Always), and no fill to an ambiguous target. What it doesn't: tell a fake extension from the real one (risk 78).

#### 3.2 How the extension and the CLI ask
**P8, revised at Omar's direction after finding S6.**

- **On a Mac with Touch ID,** `klavd` shows the dialog itself, with the request waiting, as for `passkey_get`, with §2.4's texts. Examples:

  | Case | English | Spanish |
  |---|---|---|
  | Always | fill “GitHub” in a browser | rellenar «GitHub» en un navegador |
  | 5 minutes | let a browser use your vault for 5 minutes | dejar que un navegador use tu bóveda durante 5 minutos |
  | While unlocked | let a browser use your vault until Klav locks | dejar que un navegador use tu bóveda hasta que Klav se bloquee |

  "A browser" replaces "your browser" because the source is a hint (§1.3). These are the texts for macOS, where the browser's hosts share the browser's parent key (§2.1). On Linux every peer with no terminal, the browser's hosts included, is keyed by its connection (Q-L1.2). There, the 5-minute and While-unlocked texts say "this browser connection" / «esta conexión del navegador» (§2.4; Omar's decision on Q-N4).
- **Without Touch ID** (Linux, a Mac without it, Touch ID locked out), `klavd` answers `presence_required` (a new `ErrorCode`), carrying the key's kind, the window and the terminal's name, so the client's prompt says what it grants (§2.4). The extension opens Klav's own frame for the master password, the one the passkey flow already uses, never a field in the page, and sends the request again with `password`.
- **The CLI** asks for the master password on its terminal and sends it the same way. Without a terminal (a script), it fails with `presence_required`, like ADR 0032's production run; layer 3 picks the exit code from `cli.md`'s table.
- **An older Mac app:** §1.2.
- **An older extension or CLI** shows `presence_required` as an error and doesn't retry. That is why the gate ships turned off, and is turned on only after the CLI, the extension and the Mac app answer it (§7, layer 6).

### 4. The person's `klav run` and `klav inject`, the direct mode, and ADR 0032
- **`resolve` goes through the window** (decision 3). One verification covers the whole command, because the CLI sends all references in one `resolve`.
- **One gate, two policies.** Layer 2 adds one function in `klavd`, `presence::require(peer, purpose)`, with `purpose` one of `Window` and `EveryTime { reason }`.
  - ADR 0032's layers call it with `EveryTime` for protected items and environments (Show, Copy, `klav run --env production`, a reference into the protected set). So the "Touch ID every time" of ADR 0032 §3.1 is this gate, not a second mechanism.
  - The prompt text comes from the same `prompt.rs` builder.
  - **P9, confirmed by Omar on condition that the second review passes.** ADR 0032 §3's "one confirmation per `klav run --env production`" becomes "one `EveryTime` presence per such command". The warning about values an agent changed (its answer 7) goes on the CLI before the dialog, as written there.
- **The direct mode** (`klav --no-daemon`, or no `klavd` running) needs no change. It asks for the master password on every command, a real verification every time. ADR 0037's rule that `--no-daemon` is refused while Touch ID is enrolled covers only account deletion and stays so.
- **iOS** has no `klavd`. Face ID opens the app and the AutoFill extension every time (T72), which is already Always.

### 5. The encrypted command

#### 5.1 What the agent sends
**P10, widened at Omar's direction after findings S7 and M7.** With `inject`, the agent's runtime describes what it will do with the value:

- **A command:** `klav agent run -- argv…` and MCP `run_with_secrets` describe:
  - the exact `argv`;
  - **the absolute path `argv[0]` resolves to** after the runtime's own `PATH` lookup (what it will `exec`);
  - the working directory, absolute;
  - **the names of the environment variables that receive values**;
  - **how the output comes back**: `0x01` returned redacted, as `klav agent run` and `run_with_secrets` do today. `0x02`, output passed through unredacted, is reserved for ADR 0036 §15's `--exec`, which has no flag in the code today.
- **A file:** `klav agent inject -o path` and MCP `inject_file` describe the destination path, absolute, with its parent directory canonicalized.
  - The runtime opens that parent directory when it describes the request, and writes the file through that descriptor (`openat`), so a directory swapped after the approval doesn't redirect the write (finding M7).
  - Today's writer (`crates/klav-sdk/src/secret_file.rs`) works by path. Layer 9 moves it to the directory descriptor, with `nix`'s `fs` feature in `klav-sdk`, which adds no crate (Omar's decision on Q5; §9).
- **SDK calls** that return values to the calling program under `inject` describe that program: its resolved executable path, its `argv` and its working directory, as form `0x03` (§5.2, R5), labeled "this program". There is no output mode: the values go to that program.

**What the description doesn't cover** (finding S7, T200):

- the rest of the environment the agent passes on (`PATH`, `NODE_OPTIONS`, `LD_PRELOAD`…);
- the files in the working directory, which the agent can edit. "For a while" on `npm run deploy` covers whatever the agent then writes into `package.json`.

The runtime is the one that `exec`s the command or writes the file, so on an honest runtime the description is what happens. A compromised runtime can describe one thing and do another: that is why the card says "according to the agent". §6 of the threat model already puts a compromised runtime out of scope.

#### 5.2 The format: blob `0x24` `inject-command`
**P11, revised at Omar's direction after findings S8 and M5.** No new primitive and no new dependency: HPKE with the suite of spec §8.1, through `klav-core`'s existing `hpke_seal`/`hpke_open` (`crates/klav-core/src/crypto/share.rs:69` and `:87`), and SHA-256.

```
form      = 0x01 (command) | 0x02 (file) | 0x03 (this program)
plaintext = form(1) ‖ lp(argv0_resolved) ‖ lp(cwd) ‖ output(1)
            ‖ u32_be(n) ‖ lp(arg_1) ‖ … ‖ lp(arg_n)
            ‖ u32_be(m) ‖ lp(var_1) ‖ … ‖ lp(var_m)                      (command)
plaintext = form(1) ‖ lp(path)                                           (file)
plaintext = form(1) ‖ lp(argv0_resolved) ‖ lp(cwd)
            ‖ u32_be(n) ‖ lp(arg_1) ‖ … ‖ lp(arg_n)                    (this program)
info      = tuple("klav/v1/inject/command-seal", account_id(16), agent_id(16), item_id(16), fingerprint_account)
(enc, ct) = SealBase(pkR = the account's x25519_pk, info, aad = header, pt = plaintext)
blob      = 0x01 ‖ 0x24 ‖ enc(32) ‖ ct(len(plaintext) + 16)
digest    = SHA-256(tuple("klav/v1/inject/command-digest", account_id(16), agent_id(16), plaintext))
```

- **The header.** The first byte is the version (`0x01`) and the second the kind, as in every blob (spec §2.4). `0x24` is free (spec §3).
- **The labels.** The two labels are new, under `klav/v1/inject/`: `klav/v1/share/…` is the key-sharing namespace (spec §2.3), and this blob isn't a key. Layer 7 adds both to spec §2.3's table (finding M5).
- **The recipient is the account's identity,** which every agent already pinned when it connected and every unlocked device of the person holds (spec §6.3). No new key, and every device of the person can open it.
- **`info` binds the agent, the item and the account, not the request (R10).**
  - The blob opens only as that agent's description for that item, so a server can't move it to another agent's or another item's approval.
  - A server can serve another real description of the same agent and item. Its digest differs from this request's `claims.command` unless it is the same description, so the device refuses it (§5.4): the server can't get a false command approved.
  - Binding `info` to the request isn't needed for that, and the request has no identifier of its own before the agent signs it (`AccessRequest`, `crates/klav-proto/src/agent.rs:868–895`).
- **The digest is deterministic,** so "for a while" can match the next request with the same description (decision 6). It hashes the exact plaintext.
- **The strings** are UTF-8, not normalized, and compared byte for byte. `arg_1` is `argv[0]` as the agent gave it; `argv0_resolved` is the path it resolves to. `var_i` are sorted bytewise and unique; `argv` keeps its order. Any other form byte is rejected.
- **Limits** (lowered after finding S8): at most 128 arguments and 4 KiB of `argv`; 1 KiB each for `argv0_resolved` and the working directory or the path; at most 64 variable names of up to 128 bytes each; and 8 KiB for the whole plaintext. Past them, the runtime refuses before asking, with `next`: "put the command in a script file and run that". No truncation: the card would hide what it binds.
- **Vectors** go in `docs/vectores/inject-command.json`:
  - a command, a file, "this program", an empty argument, an `argv` with spaces and quotes, and variables;
  - rejections: another kind, another form byte, a truncated blob, another agent's `info`, and unsorted variables.

#### 5.3 Where the digest and the blob go, and when each copy is deleted
**P13, rewritten at Omar's direction after finding S8.**

- **The digest goes in the signed body.** The agent's `AccessRequest` gets `claims.command`: the 32-byte digest, base64url without padding. It sits inside the body the agent signs (spec §13.3), so it goes to the audit log with `agent.access`, where it stays.
- **The blob never goes in the signed body.** `AccessRequest` (`crates/klav-proto/src/agent.rs:868–895`) is that body, and the audit log keeps it in `AgentProof.body` up to `MAX_PROOF_BODY` (16 KiB; `crates/klav-proto/src/audit.rs:25`, `:36–55`). A blob there would be kept forever, against decision 5. It would also push the body over the 16 KiB that access refuses.
- **How the blob travels.**
  1. The access answers that it needs approval, with the pending approval's ID (as today).
  2. The agent uploads the blob with a signed `PUT /v1/agent/approvals/{id}/command`, whose body is the blob.
  3. The server accepts it only for a pending approval of that agent whose request carries a digest, once, up to 9 KiB. It writes **no audit event** for it: it is delivery, not an action.
  4. A retry of the same access finds the same pending approval, and a second upload answers `409` without changing anything.
- **Hidden until the blob arrives.** An approval whose request carries a digest isn't listed (`GET /v1/approvals` leaves it out) and isn't notified until its blob has arrived. Today the server sends the push when it creates the approval (`crates/klav-server/src/routes/agent_access.rs:924`); for these approvals the push moves to the upload. So an honest request never shows the person the `security` card of §5.4 while its blob is on the way.
  - **If the blob never arrives,** the approval expires like any other, 10 minutes after it was created (`APPROVAL_TTL_MS`, `agent_access.rs:50`), without ever being shown. The agent's next access with it gets `409` "the approval expired: ask again" (`agent_access.rs:741`), and its runtime's `next` says the command's description didn't reach the server.
  - **The audit log** shows the `agent.access` with outcome `ask` and its digest, written when the request was made (`agent_access.rs:848`), and nothing for the expiry, as today.
  - **Devices still check.** A device that is shown the approval still opens the blob and checks it against the digest (§5.4). Hiding only spares an honest request a false alarm. A server that lists the approval early, or without a blob, gets the `security` card.
- **How it is bound.** By the digest, which the person's device checks after opening the blob (§5.4). The server can't open it, so it doesn't check, and a swapped or missing blob only makes the card refuse.
- **The approval.** `ApprovalRequest` keeps `v: 1` and gets `claims.command` through `Claims`. The person signs the request bytes (spec §13.5), so the signature binds the decision to the digest.
- **The target.** `target_key` appends the digest when there is one, after the domain, the way it appends method, path and sandbox today. Keys without one stay what they always were. So "once" and "for a while" both match only the same description (decision 6).
- **The copies, and when each goes:**
  - **The agent's runtime:** in memory, until the upload is answered.
  - **The server:** in a new nullable column of the approval, deleted when the approval is decided (approved or denied) or expires, whichever is first. An expiry may never be read, because pending requests expire lazily, so the server's periodic purge (`purge_loop`, `crates/klav-server/src/lib.rs:157`, hourly by default) also deletes the blobs of expired approvals. The server's backups hold it until they rotate; it is encrypted to the account (decision 5).
  - **The person's devices:** in memory while the card is open. `klavd`'s `approvals` answer carries the plaintext to the caller and doesn't cache it. A decided approval's card shows the digest and "the command is no longer stored".
- **The answer.** `GET /v1/approvals` and an approval's own `GET` carry `command_blob` only when the server still has it. The field is omitted when absent, so the answer to an older client is unchanged (§5.6).

#### 5.4 The card and the Touch ID prompt
**P14, revised at Omar's direction after findings S7 and M6.**

- **Before showing anything, the person's device** (`klav-client`'s `approval_view`, `crates/klav-client/src/agents.rs:796`; the same in `KlavFFI` for iOS):
  1. opens the blob with the account's identity, and `info` built from the request's own `agent_id` and `item_id`;
  2. recomputes the digest and compares it with `claims.command`;
  3. on a missing blob, a blob that doesn't open, or a digest that differs, shows a `security` card with nothing to approve, and signs nothing. The card says the description doesn't match the request, and that the agent or the server sent it: an agent can upload a mismatched blob for its own request (R10).
- **The card** shows, below the item:

  ```
  command:  npm run deploy -- --prod          (according to the agent)
  runs:     /opt/homebrew/bin/npm
  in:       /Users/…/dev/app
  gets:     STRIPE_KEY, DATABASE_URL
  output:   comes back to the agent redacted
  ```

  or `file: /Users/…/dev/app/.env (according to the agent)`.
  - **The text.**
    - The `argv` is shown shell-quoted, so spaces and quotes are visible.
    - Control characters, line breaks and Unicode format characters (*bidi*, zero-width) are shown escaped (`\n`, `\u{202E}`), not removed: exactness is the point, and a hidden character would change the command.
    - Long commands wrap; nothing is cut.
    - The value never appears: the description holds variable names, not values.
  - **"For a while"** reads "Approve this command in this folder for 15 min (files in the folder can change what it does)" (finding S7).
  - **Look-alike characters** (a Cyrillic «а» in `argv[0]`) are not escaped. `runs:` shows the resolved path, which is where they would matter, but a look-alike there still passes (T201, finding M6).
- **The Touch ID prompt** never contains the command (T140: what the agent writes freely never goes in). It says "let “claude-code” use “Stripe” in the command shown" / «dejar que «claude-code» use «Stripe» en el comando que se muestra», or "…write “Stripe” to the file shown" / «…escriba «Stripe» en el archivo que se muestra».
- **The surfaces:** `klav approval list|approve` (CLI), `klavd`'s `approvals` (the extension's popup and the Mac app), and iOS. The iPhone's push notification carries no command: it is encrypted to the account, and the notification goes through Apple.
- **A run over several items** asks once per item, as today (one `access` per item). Each card shows the same command. When ADR 0032's one-approval-per-run with `items` is built, it carries the same digest, and the card shows the command once.
- **The agent's runtime** checks that an approval it uses names its own digest (ADR 0030's approval check in the SDK).
- **`klav log verify`** gains a new check (finding M3). Today it checks each event against its own signed body: for `approval.decided`, the claims of the request the person signed against the event's fields (`crates/klav-client/src/audit.rs:1153–1158` for method and path). It doesn't cross-check an `agent.access` against the `approval.decided` it used. Layer 10 adds that `command` is equal on both, and that `agent.access` names one when its approval does.

#### 5.5 Tasks
P15 is Omar's decision. A task approves `inject` on items ahead of time, with no command (`crates/klav-core/src/task.rs:51`). Once the card is on:

- **New tasks.** The person's surfaces show `inject` unchecked on a task card, with "asks with the command each time", and `add_to_task` isn't offered for an `inject` approval.
- **Tasks already running** when the switch goes on (finding S10). The server stops covering `inject` by any task from that moment: its task lookup (`task_for`, `agent_access.rs`) skips `inject` when the account's switch is on.
  - The agent's runtime accepts a verified task that covers `inject` (T11), and it learns the switch only from the server.
  - So against a malicious server, a task signed before the switch that includes `inject` keeps covering it until the task ends (T200).

#### 5.6 Versions: server, clients and agents
The server deploys when merged, and older clients must keep working. Today:

- `ApprovalRequest`, `AccessRequest` and `Claims` reject unknown fields (`deny_unknown_fields`, `crates/klav-proto/src/agent.rs:846`, `:867`, `:1140`).
- So nothing with a digest may exist on an account until all its devices read it.

**P16, revised at Omar's direction after findings B2 and S9: an account switch, turned on only by §6's migration.**

- **While the switch is off:**
  - the server refuses `claims.command` with `400 inject_card_off`;
  - the agent's runtime sends no command, and asks as today, without a command;
  - nothing new is written to approvals or to the audit log;
  - the server's answers to every existing request are byte-identical to today's. The one new answer, `400 inject_card_off`, comes only to a request with `claims.command`, which only a new agent sends.
- **Turning it on** happens only through §6, in one person-only request with B2's precondition (§6, step 6).
- **Turning it off: no path in this ADR.** The grants and exceptions the migration signed stay as signed, and the audit log keeps the digests. A later ADR can add one if it's ever needed. A malicious server can report the switch off (below).
- **Advertising it.** Only `GET /v1/agent/me` says it, with `inject_card: true`, and only while the account's switch is on. While it's off, the field is left out, so the answer stays byte-identical. `/v1/health` doesn't carry it: the switch belongs to an account, and `/v1/health` speaks for the server.
  - **The agent's runtime** sends a command only when `inject_card` is `true`.
  - **The person's sheet** learns that the server can do this when it calls the switch's endpoint. An older server answers `404`, and the sheet says the server doesn't support the card yet.
  - **Why this way.** "Byte-identical with the switch off" then holds for every existing request, and layer 8 checks it with one test per answer. With the switch on, an older agent ignores the field: `AgentMe` doesn't reject unknown fields (`crates/klav-proto/src/agent.rs:760–761`).
- **What a malicious server can do with the switch.** It can report it off. The runtime then sends no command, and the card says "this agent's Klav didn't describe the command (an older Klav, or the server turned the card off)". It can make the card disappear, but not show a false command.

| Server | Agent's runtime | Person's devices | What happens |
|---|---|---|---|
| older (self-hosted) | new | any | `/v1/agent/me` has no `inject_card`; the agent asks as today, without a command |
| new, switch off | new | any | As today |
| new, switch on | older | new | An approval without a command, shown with "this agent's Klav doesn't describe the command"; only "once", never "for a while" (decision 6 has nothing to bind to). The server enforces it: with the switch on, it refuses a decision with a lease on an `inject` approval without a command (the lease check, `crates/klav-server/src/routes/approvals.rs:137`) |
| new, switch on | new | new | The card |
| new, switch on | any | an older one left (finding S9) | That device breaks, and blames the wrong cause. Its `klav log verify`, and every log view that verifies the chain, rejects each `agent.access` that carries `claims.command` with "the signed body is not the action's request" (`crates/klav-client/src/audit.rs:1252`, `:1370`), and each such `approval.decided` with "the approval request is not readable" (`audit.rs:1131`). It reports both as **tampering**, not as "update Klav". Its approval list fails on the first such request (`approval_view`, `crates/klav-client/src/agents.rs:796`), and so does "add to the task" (`crates/klav-client/src/tasks.rs:1083`) |

**What the sheet tells the person before the switch** (§6, step 3): "A Klav older than this one, on any of your devices, will show your audit log as tampered and fail to list requests once the card is on. That's not tampering: update it. Update every device first." The person confirms it, as with ADR 0036's `--every-device-is-updated`.

**Layer 8 is safe with older clients** on these conditions, which its review checks before merge:

- with the switch off, the server's answers to every existing request are byte-identical to today's;
- `command_blob` is omitted when absent;
- the new column is nullable, and migrations only add;
- `target_key` is unchanged without a digest;
- turning the switch on is one person-only request with B2's precondition, all or nothing.

### 6. The migration (decision 7)

P17 is Omar's decision on "before the update". **P17's sheet, and the new proposals P22 and P23 (both revised in the third round after K2, R6 and R7).** One sheet, in the Mac app (Development › Agents) and in the CLI (`klav agent inject-card`). Its steps:

0. **The server first (R6).** `inject_card_prepare` asks the server for the switch's state and for the grant version of every active agent, paused agents included. An older server answers `404`, and the sheet stops before anything is signed: "this server can't show the command yet".
1. **The list** (`inject_card_prepare`, no presence). It syncs, reads and verifies each agent's grant in force, and lists every active agent whose signed grant lets `inject` through without asking anywhere:
   - **What puts an agent on the list:**
     - the default (no `inject` rule; `crates/klav-core/src/policy.rs:111–114`), or
     - an explicit `allow` rule for `inject`, whatever its scope.
   - **Who isn't listed:**
     - agents whose grant has no projects and no items (an issuer approved with none): they can't `inject` anything yet, and the grant that gives them projects carries the rule;
     - a proxy, whose grant always denies `inject` explicitly (`ensure_value_denies`, `crates/klav-client/src/proxy_admin.rs:1240`);
     - agents explicitly set to `ask` or `deny`: nothing changes for them;
     - revoked agents. Paused agents are listed.
   - **Each row** shows the name, its projects, and how it allows `inject` today ("by default", or each `allow` rule with its scope).
2. **Exceptions.** Each row has "Keep without asking", off by default. In the CLI: `--keep <agent>`, repeatable.
3. **The devices.** The warning of §5.6, and "Every device runs a Klav that shows the card": a checkbox in the app, `--every-device-is-updated` in the CLI.
4. **The differences, then presence once** (`inject_card_apply`). The sheet shows ADR 0033's line-by-line differences (F3), agent by agent: only `inject` lines change. Then one presence: "make 4 agents ask before `inject`, and keep 1 as it is" / «hacer que 4 agentes pregunten antes de `inject` y dejar 1 como está».
5. **The new grants: scopes kept exactly** (**P23**, rewritten after K2). An active agent's grant changes only through the sheet of differences (`crates/klav-daemon/src/server.rs:3058–3060`), so `inject_card_apply` follows F3:
   - **It takes the sheet's digest:** the list, the exceptions, and every active agent's grant version, as `inject_card_prepare` returned them. It syncs again, and refuses if any grant in force changed.
   - **An agent not kept:**
     - each `allow` rule for `inject` becomes `ask`, with the same scope and the same expiry;
     - an agent with no `inject` rule (the default `allow`) gets one `inject: ask` rule with an empty scope. Empty dimensions don't constrain (`crates/klav-core/src/policy.rs:742`), so that rule matches every request the default did.
   - **A kept agent:**
     - its existing rules stay as they are, and if it has `allow` rules, nothing is signed for it;
     - only an agent with no `inject` rule gets an explicit `inject: allow` with an empty scope, so the switch's precondition can see the choice. No new field: that grant change, signed with this presence, is the record of the exception.
   - **Everything else is copied as it is,** under F3's copy-everything rule: every other rule, permission, project, item, profile and field. It goes through the whole-policy path (`ChangePolicy::Rules`, `crates/klav-client/src/grant_change.rs:315`). The editor's path refuses issuer grants and grants with rules it can't show (`grant_change.rs:747–760`). The whole-policy path signs them, so issuers and grants with tag, domain or hour rules are covered.
   - **Never wider.** Before signing, the client checks, agent by agent, that the new policy differs from the old only in `inject` rules, and that no request gets a less restrictive effect. Three properties of `evaluate` (`crates/klav-core/src/policy.rs:1048–1090`) make that hold for the changes above:
     - once a permission has rules, a request outside all their scopes is `deny` (`:15`, `:1088`);
     - effects are ordered `allow < ask < deny` (`:168–175`);
     - the most restrictive matching rule wins (`:1076`).

     Replacing `allow` with `ask` in place, or adding an empty-scope rule with the default's effect or with `ask`, can't widen any request. Anything else is refused, and the sheet names the agent.
   - **For example,** an agent with `inject allow {tags:[ci]}`, not kept, gets `inject ask {tags:[ci]}`, and everything without the tag stays `deny`. Kept, it is unchanged.
6. **One request, all or nothing** (**P22**, findings B2, R6 and R7). `inject_card_apply` sends every re-signed grant and the switch in one person-only request, with every active agent's grant version as step 0 returned it, paused agents included. Under the account's lock, the server:
   - compares every active agent's latest grant version with the one sent, and refuses with `409 inject_card_not_ready` if any differs: an agent approved, re-granted or registered in between, listed or not;
   - checks that, with the new grants, every active agent with projects or items has an explicit `inject` rule;
   - stores every grant, with the audit event its grant route writes today, and turns the switch on in the same transaction. Either all of it happens, or nothing does.

   Every grant write takes the same account lock; layer 8 adds the lock wherever a grant route doesn't take it today. So no grant can land between the check and the switch.

   **The partial states, and the way out:**
   - **An honest server has none:** the grants and the switch land together, or not at all.
   - **A `409`** leaves everything as it was; the sheet lists again.
   - **A failure in the network** leaves the person not knowing. The sheet asks the server again (step 0), which says whether the switch is on.
   - **An older server** answered `404` at step 0, before anything was signed.
   - **A malicious server** can store the grants and leave the switch off. The agents then ask without the card, which the card's text for a missing command already describes. Step 0 shows the switch off, and the person can run the sheet again.

**Grants signed before** stay valid until the migration re-signs them. Agents run as today until the switch is on: decision 7's "asks too" starts with the switch.

**After the switch:**

- **New grants.** Every grant a new client signs on that account carries an explicit `inject` rule, and a new agent's default policy writes `inject: ask`.
  - **ADR 0032 §3.1** has the client write a permission's default as an explicit project rule before it adds an inherited one (finding S10). For `inject` that default is `allow`, which would pass the `409`. With the switch on, the default it writes for `inject` is `ask`.
  - The grant editor shows `inject` with the card's note.
- **Re-approving.** `klav agent approve` builds a whole policy from its flags (`ChangePolicy::Rules`, `crates/klav-client/src/grant_change.rs:315`), so a grant without an `inject` rule would bring back the default `allow`. With the switch on, **the server answers `409 inject_rule_missing`** to a grant with projects or items and without an explicit `inject` rule (a proxy's `deny` counts), like ADR 0032 §3.1's `409` for a dropped protection.
  - A new client adds `ask` itself before signing.
  - An older device that slipped through gets the `409`, and a message to update. Its approve breaks instead of silently allowing `inject`.
  - The `409` helps only with an honest server. A malicious server can accept the older device's grant, and the agent's runtime then evaluates a grant the account did sign, with no `inject` rule: `allow`. That stays residual (T202). The person confirmed every device was updated, and `klav log verify` shows the grant change.
- **`klav proxy issuer add --inject-ask`** stays, and becomes redundant once the switch is on. Its warnings change in layer 12 to say the card shows the command.

**Rejected: changing `Permission::Inject`'s default effect to `Ask` in `klav-core`.**

- It would change the meaning of every grant already signed, but only where the new code runs: an older self-hosted server and an older runtime would keep evaluating `allow`.
- There would be no place for the exceptions decision 7 asks for.

### 7. Order: presence first
**P18, confirmed by Omar on condition that the second review passes.** Presence ships before the card, because:

- it narrows risk 49 with no server change, no format, no migration and no deploy risk;
- the card needs a format, a server change behind a switch, every surface and a migration;
- presence also changes what the person sees daily (Touch ID in the terminal and the browser), and that should settle before a second change to approvals.

Inside presence, the clients learn `presence_required` before `klavd` sends it:

1. layer 2 builds the gate turned off by default, on only with a `klavd` start flag that the tests use;
2. layers 3–5 teach the CLI, the extension and the Mac app;
3. layer 6 turns it on.

The test harness starts `klavd` with Touch ID off (`KLAV_NO_TOUCH_ID`, `crates/klav-cli/tests/common/mod.rs:121`), so from layer 6 the end-to-end tests give the master password where they read values.

### 8. Replacing `klavd`, and reading its memory
**What a window is worth (finding S1; P19 rewritten).** The first version said a window is worth only what reading `klavd`'s memory costs. That was wrong. A program of the same user has three ways in:

- **Replace `klavd` (T203).**
  1. It ends the real `klavd` (`shutdown`, which asks for nothing, or `SIGKILL`).
  2. It listens on the socket and answers `presence_required`.
  3. The CLI and the extension then send it the master password.

  This already applies to `unlock` today, and the threat model had no entry for it.
- **Stop it, and front a second `klavd` (N4).** The sequence is in §1.2: `shutdown`, take `klavd.lock`, run the genuine `klavd` on a home linked to the person's files, and relay to it from the real path. Once the real `klavd` has exited, nothing watches the path. Whether that second `klavd` can do the Touch ID unlock is to be confirmed in layer 2.
- **Relay.**
  1. It renames or hard-links the socket file elsewhere (the directory is the user's).
  2. It binds its own socket at the path.
  3. It forwards each request to the real `klavd` through the other name.

  It then reads everything in both directions: the master password, the values, and whatever passes on a held connection opened through it. Today `klavd` stops only when the socket path disappears (`server.rs:1354`, `exists()`), and the relay's socket keeps the path existing. **P19, revised at Omar's direction after finding S1:** the watchdog also compares the path's device and inode with its own listening socket's, and locks and stops when they differ. To be confirmed in layer 2 that the listening socket's inode can be read for the comparison.
  - **That detects a relay that stays in place across a tick (R1).** It doesn't detect one that renames the original back before the next tick, 2 s later (`TICK`, `crates/klav-daemon/src/server.rs:32`). §1.2 says what such a program catches. The second version's claim that the watchdog "turns a relay into the replacement" was overstated.
  - **P26, not built (Omar's decision of 2026-11-18).** The third version proposed watching `klavd`'s directory (kqueue `EVFILT_VNODE` on macOS, inotify on Linux) and stopping at the first change to the socket's name. The review found it couldn't deliver that (N3, from inotify(7) and Apple's kqueue(2); read, not run):
    - a rename of a directory above the socket produces no event in the watched directory;
    - on macOS the event doesn't name the entry, so `klavd` would have to stat the path again. A rename away, a bind and a rename back before that stat are missed, and every write to the directory wakes the watcher.

    The reviewer judged it ready for Linux only. Not building it was the recommendation of the report that put the review to Omar.
  - **What the 2-second poll doesn't cover**, said plainly:
    - **a swap between two ticks:** the socket file, or any directory above it, renamed away, a socket bound at the path, and the original renamed back before the next tick. The poll looks up the whole path, so a swap still in place at a tick is caught, wherever along the path it was made;
    - **the connections opened in that gap,** which the program reads in both directions (§1.2): at most the app's held connection, if the app opens it then;
    - **anything after `klavd` has exited:** a `shutdown` or a kill ends the poll with it (the route above).
- **Read its memory.**
  - **On Linux,** `klavd` calls `prctl(PR_SET_DUMPABLE, 0)` at start-up, through `nix`'s `process` feature (`set_dumpable`, which adds no crate). A process of the same user then can't `ptrace` it or read `/proc/<pid>/mem`, whatever Yama's setting is.
  - **On macOS,** a Developer ID `klavd` with the hardened runtime refuses a debugger of the same user. A `klavd` from `cargo install` doesn't, where developer tools are enabled.

**No client check of `klavd` closes this.** "The CLI checks `klavd`'s code signature" would rest on the same kind of peer identity that §1.1 shows doesn't hold. At most it is a hint, with that caveat, and this ADR doesn't propose it. Decision 4 and the held connection protect against a program that **asks** `klavd`, not against one that **is** `klavd` or sits in front of it (risk 49, T195, T203).

### 9. Dependencies, by layer
No new cryptographic dependency. `nix` 0.31 is already in `klav-daemon`, `klav-cli`, `klav-sdk` and `klav-proxy`. Every feature below is in `nix` 0.31.3, and only `socket` brings in a crate:

| Layer | Crate | `nix` feature today | Adds | For | Approval |
|---|---|---|---|---|---|
| 1 | `klav-daemon` | `time`, `user` | `socket` (brings in `memoffset`) | `SO_PEERPIDFD` on Linux | Owner's decision (2026-11-17) on Q1; `CLAUDE.md` |
| 1 | `klav-daemon` | — | `process` (no crate) | `PR_SET_DUMPABLE` (§8) | No new crate; listed here so the layer doesn't stop to ask |
| 3 | `klav-cli` | `fs`, `hostname`, `signal`, `user` | `term` (no crate), only if layer 3 needs it | The CLI's own controlling terminal's name (§2.4). Layer 3 first tries layer 2's conversion of the device number, which needs no feature | No new crate; listed here so the layer doesn't stop to ask |
| 9 | `klav-sdk` | none | `fs` (no crate) | `openat`, the write through the directory it opened (§5.1) | Owner's decision (2026-11-17) on Q5; `CLAUDE.md` |

The third version's row for `event` and `inotify` in `klav-daemon` (layer 2) is gone: P26 is not built (Omar's decision of 2026-11-18).

The macOS fd-ownership check and the unique-ID re-check (layer 1), and `devname_r` for the terminal's name (layer 2), go in the Touch ID shim's own FFI, where `unsafe` is allowed, like `klav_pid_path` (`crates/klav-touchid/src/lib.rs:389`). The held connection needs no cryptography and no dependency (§1.2).

`klav-daemon` declares `nix` behind its `server` feature (`crates/klav-daemon/Cargo.toml`). Cargo unifies features, so `memoffset` and the features above are compiled into every binary that links `klav-daemon` with `server`: `klavd` and `klav` (`klav-cli`), and whatever links `klav-sdk`. `klav-ffi` links it without default features, so not the Mac app.

## Rejected alternatives
- **Presence for every value, with no window.** That is the Always option. As the default, it would make the person press Touch ID for every `klav run` and every autofill, and decision 2 chose 5 minutes.
- **Exempting the extension by its origin.** Any program can start `klav-native-host` with a store origin (§Context).
- **Exempting the Mac app by its code signature.** The first version's design: the kernel tells `klavd` the socket's last user, which a program steers (§1.1, finding B1).
- **A holder secret presented on each request.** The second version's design. It was a bearer token that a relay could keep until lock (R1), and the app never got to ask for it on a Mac with Touch ID (K1). §1.2 replaces it with the held connection.
- **On a Linux kernel before 6.5, the pid plus its start time instead of a pidfd.** A pid reused before `klavd`'s first read isn't detected, and stopping `klavd` stretches that gap at will. Omar chose no window instead (§2.3).
- **The presence setting in a plain file.** A program could write a looser value (R4, §2.4).
- **Watching `klavd`'s directory (P26).** It can't deliver "the first change to the socket's name" (N3, §8). Omar chose not to build it (2026-11-18).
- **Queuing a second `unlock` behind an open one.** A program's `unlock` sent just before the person's would win the person's Touch ID, and the person's own would then succeed silently (N2). Omar chose `presence_busy` (2026-11-18).
- **Sending a fill to the newest connection when none reports focus.** A fake that re-attaches is the newest (N5). Omar chose `browser_ambiguous` with more than one connection (2026-11-18).
- **Showing the command in the Touch ID dialog.** T140: free text from the agent never enters it.
- **Sending the command in clear to the server, or the blob inside the signed body.** Decision 5, and §5.3.
- **A keyed digest.** Omar chose the plain one (P12).
- **Changing `inject`'s default in `klav-core`.** §6.

## Consequences
- The terminal and the browser ask for Touch ID (on Linux, the master password) about once every 5 minutes per terminal session, or per browser on macOS, while they read values.
  - On Linux every peer with no terminal, the browser's hosts included, is keyed by its connection (Q-L1.2). So the browser asks once every 5 minutes per connection of its host, and again for each new one.
  - The Mac app asks only when `klavd` was unlocked elsewhere, once until Klav locks.
  - With the setting on Always, everything asks for each value, the app included.
  - On a Linux kernel before 6.5, each command that hands out a value asks.
- With two browsers, or two profiles of one, an agent's fill needs the browser in front (P25).
- Loosening the setting doesn't lengthen a window already open, and its own verification opens none: the next value asks once more. Tightening shortens a window at once. An old `passkeys.json` is ignored, and the person is told once.
- While Klav is locked, the presence and passkey settings can't be read or changed, and `status` doesn't report the passkey setting.
- An `unlock` from a terminal or the app that finds Klav already unlocked elsewhere says so, and without the master password gives that terminal or app nothing.
- An agent's fill in the browser asks once per extension connection, and the prompt says that agents may then fill there until Klav locks, and names the event that caused it: a fill, an assisted password change, or a passkey sign-in.
- Residual risk 49 narrows. What remains:
  - programs in the same session, or under the same parent;
  - code that the person's next shell runs;
  - programs that drive the app or a terminal;
  - programs that replace `klavd` or sit in front of it.
- With the card on, an `inject` that asks shows what it is for, and "for a while" stops covering other commands. Agents that ran `inject` without asking start asking, except those kept explicitly.
- New: one blob kind (`0x24`), one signed-request field (`claims.command`), one upload route, one approval column, one account switch turned on in one request with its precondition, and a server `409` on accounts with the switch on.
- The migration never widens a grant: each `allow` for `inject` becomes `ask` in place, and a kept agent keeps its rules (§6, step 5).
- Older servers and agents keep working without the card. The person's older devices break, and report tampering, once the switch is on. The sheet says so before.

## Threats
New entries for the threat model (§5.20, "accepted, not built"):

| ID | Threat | Mitigation |
|---|---|---|
| T195 | A program of the same user reads values through `klavd` | Presence per window and per key (§2): a terminal session, the browser, or a parent process; unknown peers per connection; on a Linux kernel before 6.5, every command. The app reads until lock only on a connection where an `unlock`, or the gate's window verification, followed `hold` (§1.2), and with Always it asks for each value too. Protected items every time. Doesn't cover a program that replaces `klavd` or relays (T203) |
| T196 | A program shares the person's window: it runs in the same session, gets the person's next shell to run it (`~/.zshrc`, `~/.bashrc`, `PROMPT_COMMAND`, `.envrc`, a `klav` earlier in the `PATH`), types into an open terminal (`tmux send-keys`, `screen -X stuff`, AppleScript `do script` with Automation, `TIOCSTI`), times its request to the person's own, or starts an `unlock` | The window is per key, never for the whole `klavd`. The prompt names the terminal, the CLI prints the name of its own controlling terminal, and the prompt's duration comes from the window key. A second key's prompt isn't queued behind an open one, and a second `unlock` isn't queued behind an open unlock prompt (`presence_busy`). Both work only where `klavd` shows the prompt, a Mac with Touch ID: where the client collects the master password, no prompt is open in `klavd`. An `unlock` that finds `klavd` already unlocked by another key says so, and without the master password grants nothing. The `unlock` prompt says the window. The rest is residual 49 |
| T197 | A program drives the real Mac app (Accessibility, System Events) | Not closed: the app's held connection doesn't ask again until lock. Protected items still ask every time, and with Always every value asks. Residual risk 74 |
| T198 | A fake extension attaches to receive agents' fills | One presence per connection (every fill on Always), whose prompt says that agents may fill there until Klav locks and names the event that caused it, a fill, an assisted password change or a passkey sign-in (§3.1). With more than one connection attached, a fill goes out only if exactly one reports focus, checked at `browser_tab` and again just before each value-carrying event (Omar's decision on Q-N5); otherwise `browser_ambiguous`. So a fake no longer gets a fill by being the newest connection. It still gets one when it is the only connection, or the only one claiming focus while the real browser is behind another window. The prompt counts the connections, which is a hint: two browsers or two profiles make two. It can't tell a fake from the real one (residual risk 78) |
| T199 | The server swaps or replays an `inject` card's command | `info` binds account, agent and item, not the request: the server can serve another real description of the same agent and item, but the device recomputes the digest, compares it with the request's `claims.command` and refuses on a mismatch, and the decision signs the digest (§5.2, §5.4). A server that swaps both the blob and the digest gets the person to sign another description's digest; the agent's runtime then refuses the approval, because it doesn't name its own digest. The server can't get a false command approved. The `security` card blames the agent or the server: an agent can upload a mismatched blob for its own request |
| T200 | An agent gets "for a while" for one command and runs something else | The digest covers `argv`, the resolved `argv[0]`, the working directory, the receiving variables and the output mode, and enters `target_key`; the runtime and the log check it. Not covered: the inherited environment, files in the working directory (named on the button), a compromised runtime (out of scope, §6), and a task signed before the switch against a malicious server |
| T201 | The command's text deceives the person (*bidi*, line breaks, look-alike characters, length) | Shown escaped and complete, with the resolved path, never in the Touch ID dialog, marked "according to the agent". Look-alike characters, in `argv[0]` too, are not caught |
| T202 | An older device re-signs a grant without the `inject` rule after the migration, an agent is approved or re-granted while the list is shown, or the migration widens a grant | The grants and the switch go in one request, all or nothing, compared against every active agent's grant version under the account's lock, which every grant write takes (§6, step 6). Each `allow` becomes `ask` with the same scope, and the client refuses any change that widens (step 5). After the switch, `409 inject_rule_missing`, which only an honest server sends. The person confirmed every device was updated, and the grant changes are in the audit log |
| T203 | A program ends or replaces `klavd`, or relays between the clients and `klavd`, and collects the master password and values | Not closed. The watchdog stops `klavd` when its socket path no longer names its socket at a tick, every 2 s (§8). A program that renames the socket, or a directory above it, and renames it back between two ticks isn't detected. It catches the connections opened in that gap: with the app's held connection among them, everything on it until lock (§1.2). Nothing watches the path after `klavd` exits: a program can send `shutdown` (it asks for nothing), take `klavd.lock` (a plain lock on a file of the user), run the genuine `klavd` on a home linked to the person's files, and relay to it from the real path. Whether that second `klavd` can do the Touch ID unlock is to be confirmed in layer 2. The directory isn't watched (P26 not built, Omar's decision of 2026-11-18). The signed app takes its home from the account record and ignores every environment variable. A replacement can ask for the master password. Whether it can also show a Touch ID dialog that names Klav is to be confirmed in layer 2: a program can name its own bundle "Klav". If it can, a Touch ID dialog is no evidence of the real `klavd`. The design doesn't change, because nothing in it treats the dialog's name as proof; only what T203 says the person sees does. Residual risk 49 |
| T204 | A program registers itself as a native-messaging host in a manifest the user can write, becomes the browser's child, and shares the browser's window | Not closed: the manifest directories are the user's. T64 and T122 cover other extensions and the manifests' contents, not this. What the person sees: no prompt while the browser's window is open; on macOS, a Touch ID that names a browser. Residual risk 78 |
| T225 | A program puts a consistent set of account files of its own (another account, under a password it chose) in the home of an unlocked `klavd`, and proves presence with that password (second layer-2 review, finding 1) | Closed in layer 2 (an amendment made after review, confirmed by Omar on 2026-11-19): a password counts only if it derives the local key of the session `klavd` unlocked in memory (§2.3), with the gate on or off; no file decides it. While the files are swapped, the person's own password fails too, and works again once they are put back. The unlock itself, while locked, still opens whatever account the files hold: that is the direct mode's rule and outside this ADR |

| T231 | A program renames an item while the person confirms a value from it, or asks with a query that names no single item, so that what is handed out isn't the item the prompt named (layer 3's second review, finding 2) | Closed in layer 3: the query resolves to one item before the ask (`not_found` or `invalid` otherwise), the prompt names it, and the hand-out re-reads it under the session's lock (`conflict` if it changed). A rename before the ask is risk 94 |

Residual risks:

- **49 (rewritten)**: what stays is:
  - the same session or parent, and the routes of T196;
  - programs that replace `klavd`, relay, or read its memory (an unsigned `klavd` on macOS), including a swap between two watchdog ticks, and a second `klavd` fronted at the path after a `shutdown` (T203);
  - writes.
- **63 (rewritten)**: today the card doesn't show the command, so `--inject-ask` only makes each `inject` ask. With the card on, it shows the command "according to the agent".
- **73 (new)**: what the server learns from the card:
  - the plain digest lets it test guesses (P12);
  - equal digests show it that two requests describe the same command;
  - the blob's exact length shows the description's length.
- **74 (new)**: a program with Accessibility access drives the app (T197).
- **75 (new, revised in the third and fourth rounds)**: the setting lives sealed in `klavd`'s local data, so a program can't write a looser value. It can delete it, which returns 5 minutes at the next unlock, or put back an older sealed copy, which returns a value the person once chose. Settings shows the value in use (§2.4). An old `passkeys.json` is ignored on upgrade (Omar's decision of 2026-11-18). A master password change, when it is built, must re-seal both settings, or they fall to Always.
- **76 (new)**: writes stay without presence. A program can add its own site to a login as the person. It can also change an item's password before an ask, so the old password becomes the newest entry of the history, and "show a previous password of X" hands out what was the current password a moment before; the prompt's words stay literally true. An edit after the ask is a `conflict` (Omar's decision F of 2026-11-19).
- **77 (new, revised in the third and fourth rounds)**: any program that declares `hold` and gets the person's `unlock`, or the gate's window verification with "until Klav locks", reads until Klav locks, on that connection (§1.2); with Always, it doesn't. A relay in place when the app opens its held connection reads everything on it until lock (T203). A Debug build of the app lets any debugger of the same user use its held connection. The signed build ignores every environment variable for its home; the build script checks its hardened runtime and entitlements on every build, and the debugger and the hostile variables are checked once by hand in layer 5.
- **79 (new)**: on Linux, `klavd` doesn't lock with the screen (`docs/klavd.md:94`), so a presence window, like an unlock today, survives the screen lock (§2.3, Omar's decision). Locking with the screen on Linux is later work, with no date.
- **78 (new, revised in the fourth round)**: a fake extension, or a program the browser starts through a rewritten manifest, shares the browser's window or gets the agents' fills (T198, T204). With more than one connection attached, a fill needs exactly one to report focus; a fake still gets it when it is the only connection, or the only one that claims focus. Once the person approves a connection's presence, every agent fill on it goes out without asking until Klav locks (every fill asks on Always); the prompt says so (§3.1, Omar's decision of 2026-11-18).
- **94 (new, accepted by Omar on 2026-11-19, his decision D)**: an item's title in a value's prompt is a hint. Writes need no presence (risk 76), so a program can rename its target to the title of an item the person would approve, before the ask; the person approves a title, not an item (§2.2, T231).
- **95 (closed in layer 6, Omar's decision K)**: as first built, `resolve` and `generated_value` were bound to no item; since 2026-11-24 both are bound (Plan in layers, item 6). What follows describes the gap as it was. `resolve` reads each reference only at the hand-out, so a program can rename or edit the item behind a reference between the ask and the hand-out and get no `conflict`; the ask says "use N values from your vault in a command", which stays literally true (§2.2, T231).

## Plan in layers
One branch per layer, stacked with `gh stack`; Omar merges. Each layer updates the docs it changes (`klavd.md`, `cli.md`, `extension.md`, `macos.md`, the public docs site where `features.md` says it works today), and checks its roadmap box.

0. **`docs/adr-0041`.** This ADR, the threat model's entries, the notes in ADRs 0020 and 0036, the roadmap and the glossary. No code.
1. **`presence/peer` (`klav-touchid`, `klav-daemon`):**
   - macOS: the audit token of `last_pid`, the fd-ownership check, the session, the parent, the start time and the controlling terminal, in the shim;
   - Linux: `SO_PEERPIDFD` (`nix`'s `socket` feature, with `memoffset`, approved), `/proc` and the pidfd re-check, and `PR_SET_DUMPABLE` (`process` feature); §9.

   **Stop rule** (Omar's decision on Q2): if the macOS fd-ownership check or the unique-ID re-check can't be confirmed, the layer stops and reports, and no other presence layer starts until Omar chooses (§1.1).

   **What layer 1 found (2026-11-18).** Run on macOS 27.2 (Apple silicon); Linux only through the PR's CI. The tests named are in `crates/klav-daemon/src/peer/tests.rs`.
   - **§1.1, the token follows `last_pid`: confirmed by running it.** After the connector's child wrote, `LOCAL_PEERPID` and `LOCAL_PEERTOKEN` named the child; after the child exec'd, the same pid with the next pid version; once it exited, with the connector still holding the socket, `LOCAL_PEERTOKEN` failed (`EINVAL`). A connector blocked in `read()` on the socket becomes `last_pid` again: receiving counts too. Tests `b1_*`.
   - **§1.1, the fd-ownership check: confirmed (stop rule, first half).** `PROC_PIDFDSOCKETINFO` gives each Unix socket its own control-block handle (`soi_pcb`) and its connected peer's (`unsi_conn_pcb`). A process holds the other end when one of its sockets has the daemon end's `unsi_conn_pcb` as its `soi_pcb`, and the daemon end's `soi_pcb` as its `unsi_conn_pcb`. The connector matched. A process holding another connection to the same socket didn't, nor did one with no socket or the daemon itself, and an exited one couldn't be read. Test `macos_the_fd_ownership_check_tells_holders_from_others`.
   - **§1.1, the unique-ID re-check: confirmed (stop rule, second half).** `PROC_PIDUNIQIDENTIFIERINFO` (flavor 17, from the private `proc_info_private.h`; 56 bytes) answers for any process, of this user or not. `p_uniqueid` stays across `exec`, while the pid version changes. The token's pid version equals that read's `p_idversion`, so `klavd` binds the token to the first unique-ID read.
     - **Reuse.** A pid reused after 81 673 forks (a full wrap of the pid space, 64 s) had a different unique ID. Across those forks every new process's unique ID was larger than the one before. That is the evidence that it isn't reused within a boot: a run, not a proof.
     - **Test** `macos_a_pid_reused_between_the_first_read_and_the_last_is_unknown`, ignored by default and run by hand (68 s, passed; passed again, 98 s, after the reads moved behind the `Kernel` trait). Every read between the first and the last succeeded on the new process; only the last unique ID made the peer unknown.
   - **§1.1, Linux credentials fixed at `connect()`:** only by CI. Tests `b1_*` expect the connector on Linux after its child wrote last.
   - **§1.3, another session's controlling terminal:** confirmed on macOS by running it. `TIOCSCTTY`, from a new session's leader on a pty that another session controls, fails with `EPERM`. It isn't kept as a test, because it needs `ioctl`, so `unsafe` outside the crates that allow it. Not confirmed on Linux.
   - **§1.1, the two re-checks are guarded by tests that make only the last read differ.** On Linux, `procfs::read_peer` holds the order of the reads for `klavd` and for the tests: a reader where only the last pidfd read says the process was reaped, or names another pid, or where only the last `stat` changed, gives an unknown peer (test `a_pidfd_or_stat_that_changes_by_the_last_read_is_unknown`, on every platform; `linux_a_pidfd_reaped_by_the_last_read_is_unknown` on real `/proc`, CI). On macOS, the shim's reads with only the last unique ID, or the last `process_info`, changed give an unknown peer (`macos_a_unique_id_that_changes_by_the_last_read_is_unknown`). Removing either re-check made these tests fail on macOS, where the shared `read_peer` test runs too. On Linux these tests run only in CI, and the guard on real `/proc` wasn't checked by removing the re-check.
   - **§2.1, reading the start time and the controlling terminal:** `proc_pidinfo` with `PROC_PIDTBSDINFO` answers for processes of the same user and refuses others (`EPERM` for `launchd` and root's daemons). So layer 1 reads the start time, parent, session, terminal and user IDs with `sysctl` (`KERN_PROC_PID`) and `getsid`, and reads the peer, its parent and its session's leader the same way. Those reads, and the unique-ID read, answered for root's `launchd` and `logind` (session leaders with no terminal). **A terminal session whose leader is root's `login`,** which is how Terminal and iTerm2 start a shell, was run by hand: Omar ran the test `by_hand_from_a_terminal_window_a_peer_is_keyed_by_the_session_login_leads` (ignored by default) from such a window on 2026-11-18, and it passed. Both reads on the leader answered, and the peer was keyed by the session `login` leads. A terminal that starts the shell itself (Warp does) leads the session with the person's own shell, which the tests that open a terminal with `script` cover; from one of those the by-hand test fails and says so. Linux reads `/proc/<pid>/stat` (CI).
   - **§2.1, a terminal flag with no device:** when the kernel's controlling-terminal flag and its device number disagree, the shim describes no process (`klav_touchid::process_info` gives `None`), so the peer is unknown rather than keyed by its parent. When a session's leader exits, macOS clears both for the members, which keep the dead leader's session ID: run, test `a_session_whose_leader_left_gives_no_session_key`.
   - **§2.1, orphans on macOS:** run, and it differs from what this item first recorded. When the kernel reparents a process to `launchd`, it rewrites `p_puniqueid` to `launchd`'s unique ID (1): the creator's ID doesn't survive. Layer 1 accepts a parent only when the process at `ppid` has the unique ID the peer records, before and after its other reads, and never pid 1, so an orphan has no parent. Test `an_orphan_after_a_double_fork_is_keyed_by_its_connection`. That match shows the process at `ppid` is the parent the kernel records now, not that it created the peer. The parent's start time is no longer compared with the peer's, because both are wall-clock times and a clock stepped back rejected a good parent. That comparison was what rejected a parent that started after the peer, so it matters whether macOS reparents a process to anything but `launchd` (a debugger's attach is the candidate). **Not verified.** **Owner's decision (2026-11-18):** accepted as a residual risk, because whoever can debug a program already controls it, as in the B1 case. Layer 2 runs the check if it can and records the result, without stopping for it. The session leader's start time is still compared.
   - **Descriptor passing** was tested by inheritance, not `SCM_RIGHTS`. `nix` sends a descriptor only with its `uio` feature, which isn't approved, the standard library's API for it is unstable, and the tests in `klav-daemon` can't use `unsafe`. The kernel state is the same: two processes hold one connection. With the connector gone, the receiver (macOS) or nobody (Linux) is the peer, keyed by its connection. With the connector alive in its own session and the receiver in a terminal session, writing last, the peer is the receiver keyed by that terminal's session on macOS, and the connector keyed by its connection on Linux (test `a_descriptor_passed_into_a_terminal_session_is_keyed_by_who_kernel_names`). Either way a session key goes only to a process inside that session. The tests pause `klavd`'s side in-process between two reads, where a program would send `SIGSTOP`.
   - **Linux, non-dumpable:** the tests run `identify` inside a non-dumpable process, whose `/proc/self` files the kernel then owns as root (`linux_klavd_is_not_dumpable_and_still_identifies_its_peer`), and check that the real `klavd` is non-dumpable from start-up (`klavd_is_not_dumpable_from_start_up` in `tests/socket.rs`). Both only by CI.

   **Owner's decision (2026-11-18).** Layer 1 found two things that differ from this ADR's text. Omar chose option (a) for both.
   - **Q-L1.1, the B1 sequence ends in a known peer.** The literal sequence, a child that execs while holding the socket, doesn't end in an unknown peer. On macOS the peer is that child, keyed by its parent, the connector (`WindowKey::Parent`). On Linux it is the connector, keyed by its connection. Both are the program's own processes, never anyone else's, and the test `b1_a_child_that_execs_holding_the_socket_is_the_attackers_own` asserts that. On macOS the peer is unknown only when the child exited or no longer holds the socket (two more tests). In practice, on macOS one approval of that prompt opens a window keyed on the connector, which every child of the connector without a terminal can reuse for the window's length. An unknown peer would have had one connection. Options:
     - (a) accept it, and change this item's B1 test to "ending in the program's own key, never in another's" (recommended: it is the parent key §2.1 already gives a program's children, and the program gets nothing it couldn't get by connecting from each child);
     - (b) keep "unknown": macOS keys every peer with no terminal by its connection, as Linux does, and the browser's hosts share no window on macOS either.
   - **Q-L1.2, Linux keys every peer with no terminal by its connection** (§2.1's fallback). The user's service manager can't be recognized reliably. That was judged from how subreapers work, not run: any process may set `PR_SET_CHILD_SUBREAPER` (`systemd --user`, `containerd-shim`, `tini`), and another process can't read the flag. So the browser's hosts share no window on Linux, and each fill or value from a host asks. Options:
     - (a) accept the fallback (recommended: it fails closed, and a key a program can take over by becoming a subreaper isn't a key);
     - (b) recognize `systemd --user` by its executable, as §2.1 allowed, with the residual that any program of the user can become a subreaper.

   Tests, on both platforms:
   - **the stop, connect, fork, exec, continue sequence** (finding B1), ending in the program's own key, never in another's (Q-L1.1 above; before layer 1 this read "ending in a prompt for an unknown peer, never in a reused window");
   - descriptor passing to another process;
   - an orphan after a double fork, keyed as unknown;
   - children in the same session and in a new one (`setsid`);
   - on macOS, a peer that exits and whose pid is reused between the first read and the last, with `klavd` stopped in between: unknown;
   - on Linux, a kernel without `SO_PEERPIDFD`: no window, every value asks.
2. **`presence/gate` (`klav-daemon`), turned off by default:**
   - `presence::require`, the windows per key, the passkey window per key (§2.5), the presence setting and the passkey setting in the sealed local data (§2.4), and the `presence_window` operation;
   - the settings' rules of the fourth round (§2.4): loosening not retroactive, and its own verification opening nothing (confirmed by Omar); `locked` while locked, and `status` without the passkey setting while locked (Omar's decision on Q-N2); the old `passkeys.json` ignored, checked only for existence, with the one-time warning, then deleted (Omar's decision on Q-N3);
   - `hold` and the held connection, answering `not_supported` until layer 6, and always on Linux (§1.2), with what marks a connection held and what doesn't, and declarations dropped on Always (Omar's decision of 2026-11-18);
   - `presence_required`, `presence_busy`, the exhaustive classification of §3, and the socket-inode watchdog. There is no directory watch: P26 is not built;
   - the `unlock` rule (§2.4): `presence_busy` for a second `unlock` while an unlock prompt is open, and `ok` with `already_unlocked` when another key unlocked `klavd` (Omar's decision on Q-N1);
   - the prompts: the terminal's name, from the device number (`devname_r` in the shim on macOS, the major and minor numbers on Linux), and the duration from the window key, with "this connection" for a connection key (§2.4, Omar's decision on Q-N4).

   A note from layer 1's review: the CLI starts `klavd` with `process_group(0)`, not `setsid` (`crates/klav-daemon/src/client.rs`), so `klavd` stays in the caller's terminal session, a member of the session it may key windows on. Layer 2 decides whether that matters. The third review found no effect of it on P4, P21, P24, P25 or P26.

   To be confirmed in layer 2, by running it where it can; none of these stops the layer:
   - that `klavd` holds the local key at unlock (§2.4), and that the listening socket's inode can be read (§8);
   - whether a replacement can show a Touch ID dialog that names Klav (T203);
   - whether a second, genuine `klavd` on a home linked to the person's files can do the Touch ID unlock (N4, T203);
   - whether a debugger's attach reparents a process on macOS (item 1; Omar accepted the risk). The result is recorded here.

   **What layer 2 found (2026-11-19).** Run on macOS 27.2 (Apple silicon); Linux only through the PR's CI. The gate is behind `klavd --presence-gate`, a hidden flag, off by default. Unit tests in `crates/klav-daemon/src/presence/tests.rs`, through the socket in `crates/klav-daemon/tests/presence.rs`.
   - **The local key at unlock: yes.** `unlock` opens the presence and passkey settings with the session's local key (`Unlocked::local_key`, as `touchid::enrol` already did) and keeps them in memory. The socket test seals a setting, locks, unlocks and reads it again; an edited blob reads as Always, a deleted one as 5 minutes.
   - **The socket's inode: yes, from the path, not the descriptor.** `fstat` on the listening socket describes the socket, not the file (macOS: device `-1` and another inode). So `klavd` binds under a staging name, `klavd.new`, reads `lstat` of it, connects to it and accepts until a connection arrives from its own pid (any other accepted before it is closed unanswered; the third layer-2 review, C, below), checks the staging name still has that inode and is a socket, and only then renames it to `klavd.sock`, which must then have that inode (`bound_socket`). The path never names a socket that isn't proven. The watchdog compares the pair every 2 s, without following a symbolic link; a relay that renames the socket and binds its own, or leaves a link to it, stops `klavd`, which then doesn't remove the relay's socket (tested). Amended after the second layer-2 review (findings 2 and 4): the first version bound at `klavd.sock` itself, so a client that connected during start-up was taken for a relay and `klavd` exited, and a symbolic link to the socket passed the check.
   - **The terminal's name: yes, while the terminal is open.** `devname_r` (in the shim, with the caller's buffer) names a live pseudo-terminal (`ttys002`), and gives nothing for one that has closed or an unknown device; Linux decodes `tty_nr` (`pts/N`, `ttyN`, `ttySN`). A real `script` pseudo-terminal is named in a test on both systems.
   - **A debugger's attach reparents a process on macOS: not run.** Developer mode is off on this Mac (`DevToolsSecurity -status`), so an attach would ask for an administrator's authorization. The brief said to stop at any dialog. The command for Omar is in layer 2's PR. Nothing is recorded as a result.
   - **A replacement's Touch ID dialog, and a second genuine `klavd`'s Touch ID unlock: not run,** by the brief. By-hand steps for Omar are in layer 2's PR.
   - **`process_group(0)` (layer 1's note): no effect.** `klavd` is never its own client: the windows are keyed on the peer, and a peer is another process. That `klavd` sits in the caller's session changes no key.
   - **The protected set's `EveryTime`** is in `presence::require`, unused until ADR 0032's layers call it (§4).
   - **`klav-ffi`** maps `presence_required` and `presence_busy` to `Denied` and `not_supported` to `Invalid`, without changing the Swift bindings: the Mac app gets the gate's codes in layer 5.

   **What the second layer-2 review found (2026-11-19), and the amendments made after it.** An independent security review of layer 2's PR at its first head found eight things. Each is fixed in the same PR, with tests through the socket where it could be done. On 2026-11-19 Omar confirmed the amendments that had a choice in them: findings 1, 3 and 5, and the staging name and its rule for other connections in finding 2 (own choices 17–22). Findings 4, 6, 7 and 8 are corrections with one fix each and no choice in them, which he wasn't asked about as such:
   1. **A presence password was checked against the files on disk, not the unlocked session** (high, with the gate on or off). §2.3 is amended: the password must derive the session's local key in memory (T225). One password check runs at a time. Omar confirmed both on 2026-11-19, with the gate on or off (own choice 18 for the second).
   2. **A client connecting while `klavd` started was taken for a relay, and `klavd` exited.** The socket is proven under a staging name and only then renamed into place (above).
   3. **Two setting changes could race** (read, decide, save and apply weren't one step), for the presence setting and the passkey setting alike. A change now holds a lock from the read to the change in memory; a second change meanwhile gets `presence_busy` (own choice 20, accepted by Omar on 2026-11-19).
   4. **A symbolic link to the socket passed the socket checks.** They now require a socket file, read without following links.
   5. **Only the gate's prompts took part in the busy rule.** With the gate on, every Touch ID dialog `klavd` shows does now; with it off nothing changes (own choice 17, confirmed by Omar on 2026-11-19).
   6. **`devname` returned a static buffer**, so two threads naming terminals could read each other's name. The shim calls `devname_r` with its own buffer.
   7. **A panic during a prompt left the busy flag set**, so every later prompt got `presence_busy` until `klavd` restarted. The open prompt is now held by a guard that clears it on unwind.
   8. **The gate wasn't tied to §3's classification.** Every request now goes through one match over the classification, exhaustive in code, before any handler runs: an operation of the «window» row can't reach its handler without the gate.

   **What the third layer-2 review found (2026-11-19), and the amendments made after it.** A read-only review of the fixes above found one defect, one hardening, a test that could hang, and documents that overstated. Each is fixed in the same PR. On 2026-11-19 Omar was asked about the cost it found in choice 18 (below), and accepted it. Later that day he was asked about the two choices its fixes A and C made, 23 and 24, and kept both as built (Decisions; Still open):
   - **A. A prompt could wait behind an open dialog through a lock** (medium, with the gate on). The operations that already ask, and passkey uses, show their Touch ID with the session's lock held, and the gate read a value's title under that lock before it looked at the busy rule. So a value from another key waited for the dialog to close and then showed its own, the queue §2.4 forbids; another operation that already asks, and an `unlock` that came in just before the running unlock's dialog opened, did the same through their locks. Now a request that will show a prompt never waits for a lock an open dialog's holder keeps: it gets `presence_busy` at once, also when the dialog opens while it waits. The gate passes a covered value, or one with a password, without reading the title, and reads it only for a prompt that names the value, then without waiting behind a dialog. A request that needs no prompt, such as a value whose window is open, waits for the session's lock as before. A request known to ask only under that lock (a widening `grant_change_apply`, a passkey use whose window lapsed while it waited) gets `presence_busy` when it reaches its prompt if a dialog opened while it waited (the ADR's own choice 23). `setting_change` and `confirm_presence` wait on no lock a dialog's holder keeps, and needed no change. With the gate off nothing changes.
   - **B. A test that would hang instead of failing** if the busy rule for a second `unlock` were removed. Every request a test sends while it holds a prompt open now has a bounded wait.
   - **C. `klavd` could fail to start when the staging socket's backlog was full** (low, with the gate on or off; likely, not confirmed by the review). A program connecting to `klavd.new` in a loop could fill the backlog between `bind` and `klavd`'s own connect, which was then refused. The probe now accepts and drops what is queued and tries its own connect again, within the same 10 s (§8). A connection queued after `klavd`'s own stays queued, and the main loop serves it like any client's once the socket is `klavd.sock` (the ADR's own choice 24). The path still never names a socket that isn't proven.
   - **D. Documents.** `docs/klavd.md` said a connection at the staging name was always closed unanswered, and that no queue formed behind a dialog; §2.3 cited a Touch ID function the second review's fixes removed; §2.3 and `docs/klavd.md` listed `confirm_presence`, which takes no password, among the places a password stands in for presence; and the roadmap's line for this layer left out the start-up change. Corrected.

   **Known, and not fixed in this layer:**
   - **The Mac app's text for `conflict`.** With the gate off, a password check that finds another one running answers `conflict` (own choice 18, confirmed by Omar on 2026-11-19). `klav-ffi` maps it to the app's "The item changed on another device. Sync and try again.", which is wrong for it. Layer 5, which teaches the app the busy answer anyway, fixes the wording (item 5).
   - **The one-at-a-time password limit can be kept busy.** A program of the person's user that sends wrong master passwords back to back keeps the limit taken, so the person's own password check gets `presence_busy` (or `conflict`) for as long as it keeps sending. It denies availability only, and the same program can already send `lock` or `shutdown`. **Accepted by Omar as a residual (2026-11-19),** with choice 18 as built. He declined (b), a queue, each check waiting for the Argon2id before it, which the same program fills instead, and (c), no limit, so each wrong password costs an Argon2id run of its own.

   **Owed, outside layers 2–6** (Omar's decision of 2026-11-19):
   - **iOS's password checks.** Two `KlavCore` methods, iOS only (`crates/klav-ffi/src/lib.rs`), still check a password that stands in for presence against the account files on disk, not the unlocked session: `cancel_account_deletion_with_password` and `resume_agents_with_password`. They switch to the session's check (`Unlocked::password_check()`, §2.3) in a separate PR, after the presence layers, with no urgency. It isn't part of layers 2–6, and nothing of them waits for it. The change is for one rule everywhere. He declined leaving them, the option that rested on iOS keeping other programs out of the app's container.

   The tests run Touch ID through a fake behind a trait (`touchid::Biometric`) and give each connection a fixed key, so what they assert doesn't depend on what runs them. `hold` stays `not_supported`; a switch that only tests can set turns it on to test the held-connection rules.

   Tested with a fake verifier behind `#[cfg(test)]`:
   - one case per gated operation;
   - window expiry with a mock clock, and lock dropping windows and held connections;
   - a held connection: until-lock with 5 minutes, per value with Always, dropped when the setting moves to Always, never shared with another connection;
   - a declared connection that `confirm_presence`, `passkey_get` or an `EveryTime` presence verified: not held;
   - a declaration dropped on Always, and not back after a move to 5 minutes;
   - two keys not sharing one window, Always, and the busy rule;
   - a second `unlock` while an unlock prompt is open: `presence_busy`; an `unlock` without the password after another key's: `already_unlocked`, and no window for the caller; with the password: `already_unlocked`, and the caller's window;
   - a window opened under 5 minutes that stays 5 minutes after a move to While unlocked;
   - a loosening of either setting that opens no window: the next value, or passkey use, asks once more;
   - both settings answering `locked` while locked, and `status` without the passkey setting then;
   - an existing `passkeys.json`, whatever it says: the warning at the first unlock, the file deleted, and no warning at the next;
   - a renamed socket stopping `klavd`;
   - no prompt waiting behind a dialog that holds the session's lock, whether the dialog was open first or opened while the request waited, a waiting `unlock` busy once the running unlock's dialog opens, and a value whose window is open served once the dialog closes (the third review, A);
   - a full backlog at the staging name not failing the start (the third review, C).
3. **`presence/cli` (`nix`'s `term` feature in `klav-cli` only if needed, §9):** `presence_required` handled (the master password on the terminal; without one, an error with an exit code from `cli.md`'s table), the name of the CLI's controlling terminal printed before asking, with layer 2's conversion (§2.4), `already_unlocked` and `presence_busy` said on `klav unlock`, `klav presence window [always|5m|unlocked]`, and `cli.md`. An end-to-end test on Linux CI with the password path.

   **What layer 3 built (2026-11-19).** Run on macOS 27.2 (Apple silicon) against a test `klavd --presence-gate --no-touch-id`; Linux only through the PR's CI. Code in `crates/klav-cli/src/presence.rs` and `crates/klav-cli/src/commands/presence.rs`, the end-to-end tests in `crates/klav-cli/tests/presence.rs`.
   - **The value commands.** Every CLI command that sends an operation of §3's «window» row goes through one helper: `klav item get --reveal` (`view`), `klav item history --reveal` (`previous_password`), `klav totp`, `klav generated show` (`generated_value`), `klav run` and `klav inject` (`resolve`). The CLI sends no `autofill` and no `extension_attach`. On `presence_required` it asks for the master password on its controlling terminal, and sends the request again with `password`; if `klavd` then asks something else, it asks once more (own choice 33). With no terminal it exits with a new code, 9 (own choice 25, kept by Omar). No value-giving command for agents reaches this path: `klav agent …` and `klav mcp` ask `klavd` for no value. The agent commands that already ask (`klav agent resume`, `approve`, widening grant changes) ask for Touch ID or the master password as before, `--password-stdin` included (`cli.md` corrected in the review round).
   - **The terminal's name.** The CLI reads its own controlling terminal's device number with layer 1's readers (`klav_daemon::peer::own_terminal`: the shim's `process_info` on macOS, `/proc/self/stat` on Linux; `klavd` never calls it) and names it with layer 2's `terminal_name`, with the same fallback, "a terminal". `ttyname` isn't used, so §2.4's question about `ttyname` on `/dev/tty` didn't need an answer. `nix`'s `term` feature was added in the review round, for the question's own terminal handling (finding 8); it adds no crate. The name is written on the terminal before every password question the gate asks (a value's, a loosening's, an unlock's and an already-asking operation's), before `klav unlock`'s Touch ID with the gate on, and before a value's Touch ID on `klavd`'s notice (own choice 28, changed by finding 1 and Omar's decision 2).
   - **`presence_busy`** is said by what the CLI sent: without a password, a Touch ID dialog; with one, another password check; for a setting change, either or another change. With the gate off, the second password check's `conflict` keeps `klavd`'s own message, which says the same.
   - **`klav unlock`.** It learns whether the gate is on from `status`'s `presence` (own choice 39, which replaced 27 in the review round), sends no `unlock` to an already unlocked `klavd`, and says `already_unlocked` with Omar's text (Q-N1, and his decision 5 of 2026-11-19). It shows an unlock answer's warnings: §2.4's "to be confirmed in layers 3–5" is confirmed for the CLI (the old `passkeys.json` warning, in the end-to-end test).
   - **`klav presence window [always|5m|unlocked]`** shows the setting only from an unlocked `klavd` and never unlocks it itself (Q-N2). Locked, the gate off (`not_supported`) and an older `klavd` (`bad_request`) each get their own message. Tightening asks for nothing; loosening asks for Touch ID, or the master password on the terminal, names the change, and opens no window.
   - **Tests.** Unit tests for the texts, the gate's reading and the busy words. Two end-to-end tests with a `klav-server`, a test `klavd` in its own home stopped by pid, and `script` for a pseudo-terminal (required, also on Linux: a missing `script` fails the test). One with the gate on, covering: no terminal (exit 9, also with `--password-stdin`); a right password with stdin and stdout redirected inside the terminal, where the printed name equals `tty`'s; a wrong one; two checks at once (one `presence_busy`); and the setting shown, loosened (its own prompt, then the next value asks and opens the session's window) and tightened. One with the gate off, pinning what the CLI did before. Removing the `/dev/tty` check, the name before the question, the busy words, or the gate check before `unlock` each made the gate-on test fail (run on macOS).
   - **Not checked:** the Touch ID paths (the tests run with Touch ID off), and anything on Linux, which only CI runs.

   **Layer 3's review, and the fix round (2026-11-19).** An independent review of the PR found eight problems. Each is fixed as follows, with Omar's five decisions of the same day (The owner's decisions, above).
   1. **The unlock's question named neither the terminal nor what it opens** (and the operations that already ask had the same shape). With the gate on, every master-password question the CLI sends to `klavd` (a value's, an unlock's, a setting's loosening, an operation that already asks) now names the terminal and says what the answer opens; the prompts whose password never goes to `klavd` (signup, login, `set-server`, the emergency kit, logout, account deletion, and the direct mode, `--no-daemon`) keep the plain prompt: an unlock's from `status`'s `presence`, which `klavd` matches with `shown` (own choice 34); an operation that already asks says "It confirms this one action, and opens no window." Own choice 28 is now true for those questions.
   2. **What a password granted was decided by `klavd`'s state at the resend, and a rename could change the item.** `klavd` binds the password to the ask it answers (own choice 32): it checks it only if it would ask exactly the same, request and item included, and re-reads the item under the session's lock before handing it out (`conflict` otherwise, own choice 36). The wire addition is the ask's `lasts` and `value` in place of the unreleased `what`.
   3. **`klav unlock` raced a lock between `status` and `unlock`.** It sends no `unlock` to an unlocked `klavd` (Omar's decision 5).
   4. **An every-time ask was worded as a window.** The CLI words the grant from `lasts`, which `klavd` sets only when the password opens a window.
   5. **A Touch ID unlock answered `already_unlocked` also printed "Unlocked with …".** It prints only Omar's text.
   6. **The value's text came in the Mac's language inside an English sentence.** `klavd` sends the kind and the title (cleaned), and the CLI words it, cleaning the title again (own choice 40).
   7. **The gate's probe read an unexpected answer as "off".** There is no probe: `status`'s `presence` says the gate is on, and only a `klavd` with the gate on sends it (own choice 39).
   8. **Ctrl-C at the question could leave the terminal without echo, and a background job asked.** Confirmed against `rpassword` 7.5.4 in `Cargo.lock`: it turns `ISIG` off and, on a Ctrl-C byte, raises `SIGINT` before it restores the terminal. The gate's questions now read the terminal themselves (`nix`'s `term` feature, no new crate, no `unsafe`): `ISIG` off so Ctrl-C is a byte that ends the question, the terminal restored by a guard on Enter, Ctrl-C, Ctrl-D, an error or a panic (a signal from outside during the question, such as `SIGTERM` or `SIGHUP`, still skips it), and a process that isn't the terminal's foreground job treated as having no terminal (own choices 37 and 38).

   **Layer 3's second review, and the second fix round (2026-11-19).** A second independent review, after the fix round above, found these; each is fixed in the same PR, with Omar's decisions A–E of the same day (The owner's decisions, above). Own choices 43–50 are the round's own.
   - **Finding 2. A value whose query named no single item was asked about with "a value from your vault", and its hand-out was bound to no item:** a program could rename its target to the query while the person confirmed. `view`, `previous_password`, `totp` and `autofill` now resolve the query to exactly one item before anything is asked (`not_found` or `invalid` otherwise), an ask for one value names it (an ask that opens a window names who and for how long, and no item), and the hand-out re-reads it under the session's lock, also when the answer opens a window (own choices 43 and 44). `resolve` and `generated_value` are not bound to an item (own choice 51, added by the third round).
   - **Finding 3.** The first password unlock opened the setting's window (Omar's decision A).
   - **Finding 4.** A stdin unlock still counted as a passkey verification (Omar's decision B; the envelope's `untyped`).
   - **Finding 5. What a connection remembered of the request was the request itself**, up to the 100 MiB line limit, and a request that couldn't be serialized compared equal to another. It is now a SHA-256 through `klav-core`, and such a request is refused (own choice 48).
   - **Finding 6.** With Always, the value's Touch ID dialog named no one (Omar's decision C).
   - **Finding 7. The gate's two passes both kept asks**, the first without the item: a setting changed between them left an ask no resend matched. Only the second pass keeps and compares asks now.
   - **Finding 8. The question's reader dropped Tab and Ctrl-W, let an arrow key's escape sequence into the password, and read what was typed before the question.** It now flushes pending input before writing the question; Tab and printable characters go in; Backspace, Ctrl-U and Ctrl-W erase; escape sequences never go in, with one exception that fails closed: a lone ESC also takes the printable ASCII byte after it (as Alt and that key would), so a password typed with ESC in it loses a character and fails, and never gains one. The line lives in a fixed buffer, and every erased byte is zeroed at once (own choice 47).
   - **Raw warnings.** The operations that already ask and the setting's tightening printed `klavd`'s warnings uncleaned with the gate on. They go through the same cleaning now; with the gate off they print byte for byte as before (own choice 41).
   - **The gate-off envelope.** A layer-3 `klavd` reads `notify`, `shown` and `untyped` with the gate off too, and ignores them, where an older one answers `bad_request`. Clients send them only to a `klavd` whose `status` has `presence`, so nothing a client of this repository sees changes; `docs/klavd.md` §3 says it.

   Tests: daemon tests for each finding and decision (a setting changed between the passes, a query that names no single item, a rename during the dialog, the first-unlock and later-unlock windows, an untyped unlock with the gate on and off, the Always dialog's words, the digest); a real-`klavd` end-to-end test that types the unlock password on the terminal and reads a value inside the window its question named, at the first unlock and a later one; the reader's keys through a pseudo-terminal (typed ahead, Ctrl-W, an arrow key, SS3, Backspace).

   `klavd`'s own messages (warnings, refusals) go through the CLI's cleaning in the gate's paths. Tests: unit tests for every text and for the line reader; the gate-on end-to-end test gained the whole question line, the stdin unlock that opens no window followed by a value that asks, a password offered on stdin from a terminal, Ctrl-C with `stty` checked after, a background job (exit 9), `klav agent list` with the gate on and no terminal, and "this program"; a new end-to-end test against a scripted `klavd` on the socket pins the requests the CLI sends (exactly one resend of the same request, no password on the first; a second ask; the every-time words; an older `klavd`'s `status` with no gate fields sent; no `unlock` to an unlocked `klavd`, with the gate off too; the notice, and a notice nobody asked for refused; `already_unlocked` after a Touch ID unlock; `shown` for typed and stdin passwords; the busy words). The 5-tries overlap of two real password checks was replaced: the CLI's words come from the scripted `klavd`, deterministically, and `klavd`'s one-check rule already has a deterministic unit test.

   **Layer 3's third review, and the third fix round (2026-11-19).** A third independent review found these; each is fixed in the same PR, with Omar's decisions F–J of the same day (The owner's decisions, above). Own choices 51–53 are the round's own; Omar answered them the same day (decisions K–M).
   - **An edit between the ask and the hand-out handed out the edited item** (Omar's decision F). `klavd` keeps the item's version with the ask (`Bound` stays the request digest and the item; the version is kept beside it, so a resend still matches its ask) and compares item and version under the session's lock in the hold that hands it out. The version is the item's `version` from the vault (`ItemSummary::version`): every write to its content raises it (moving it to the trash and restoring it raise the server's `revision`, not `version`, and change no content), and a sync refuses one lower than a version already seen.
   - **A `conflict` left the window open** (Omar's decision G): `require` granted the window before `handle` found the mismatch. `require` now returns the window the answer stated, and `handle` opens it only after the item check passes, still under the session's lock. A refusal before that check opens none either (own choice 52).
   - **The reader past 1024 bytes** gave up mid-line, and the bytes still queued, and those that arrived after, went to the shell with echo on. The line is now refused whole: what was kept is zeroed, the rest is read and dropped up to Enter (or Ctrl-C, or the terminal closing), and what is queued after it is flushed before the terminal's modes are restored (own choice 53).
   - **Reader details.** `ESC O` followed by a parameter (`ESC O 5 D`) let the `D` in; the whole sequence is dropped now. A lone ESC still takes the next printable byte (it fails closed; said in `cli.md` and above). `Typed::text` borrows the buffer, so the buffer never moves once a byte is in it, as its doc says.
   - **Sentences that said the ask always names the item**, or that what is handed out is the item the question was about, now say which requests are bound to an item and which aren't (own choice 51). The claim that the CLI cleans all of `klavd`'s text is scoped to what the presence module prints; own choice 41 lists the four paths that still print it raw.
   - **Tests the review named:** the digest test keeps only what can fail; the no-single-item test fails if its setting change fails; the rename test covers `view`, `totp`, `previous_password` and `autofill` (by title), the password path, and checks that the rerun after a `conflict` asks again; the untyped-unlock test also signs in with a passkey after each unlock; the daemon's `unlock_shown` helper says it re-implements the CLI's mapping and names the end-to-end test that drives the CLI's own (it pins both unlocks); the pseudo-terminal test waits for the output it expects instead of fixed sleeps.

   Tests added: an edit during a held Touch ID dialog and between `presence_required` and the resend, for `view` and `previous_password`, with an unedited item still handed out by both paths; a new version synced from a second device during the dialog; a `conflict` that opens no window, by Touch ID and by the password; a unit test that a passed answer opens its window only through `open_window`; the reader's `ESC O 5 D`, a lone ESC, and lines past the bound; a 1500-byte paste through a pseudo-terminal after which the shell reads nothing. Each of these was broken on purpose once in this round, and its test failed: the version left out of the comparison (`an_item_edited_while_its_dialog_is_open_is_not_handed_out`, `a_new_version_synced_during_the_dialog_is_not_handed_out`); the window opened before the item check (`a_conflict_opens_no_window`, `an_item_renamed_while_its_dialog_is_open_is_not_handed_out`) and inside `require` (`a_passed_answer_opens_its_window_only_when_handed_out`); `ESC O` without its parameters (`the_line_reader_edits_and_stops_like_a_terminal`); the over-long line without the drain and the flush (`with_the_gate_on_values_ask_for_the_master_password_on_the_terminal`: 476 bytes reached the shell); `untyped` ignored (`an_untyped_unlock_is_no_passkey_verification_with_the_gate_on`: the passkey sign-in went through without a verification).
4. **`presence/extension`:** the master-password frame for `presence_required`, the presence of `extension_attach` per connection or per fill on Always, with §3.1's prompt texts in `klavd`'s dialog and in the frame: agents may fill until Klav locks (Omar's decision of 2026-11-18), naming the event that caused it, with a text per event, a fill, the fill step of an assisted password change and an agent's passkey sign-in, in English and Spanish, for macOS and for Linux (Omar's decision of 2026-11-19). The layer gives the last two their final wording, written natively in each language, and gets the event, and for a passkey the site `klavd` armed, to the dialog and the frame; `browser_ambiguous` (in `klavd`'s `BrowserHub`: with more than one connection, exactly one reporting focus, at `browser_tab` and again before each value-carrying event; §3.1, Omar's decision on Q-N5), and Playwright tests in `apps/extension`, including two connections where neither, one or both report focus. The frame sends its master password on the connection that got `presence_required` (own choice 32: an ask is kept per connection), and a password `unlock` sends `shown` with what its own question said (own choice 34: without it, the unlock opens no window with the gate on).

   **Built (2026-11-24).**
5. **`presence/mac`:**
   - `DaemonEngine` (`klav-ffi`) resends a request with the master password on the connection that got `presence_required`, not a new one per request as today (own choice 32), and a password `unlock` sends `shown` with what the app's question said (own choice 34);
   - the held connection and `hold` in `DaemonEngine` (`klav-ffi`), with the app's password window for `presence_required`, and a new long connection with `hold` when the app's Settings moves the setting off Always;
   - `presence_busy` in the app, and its text for a password check that answers `conflict` because another one is running (gate off): today `klav-ffi` maps it to "The item changed on another device. Sync and try again." (found by the third layer-2 review);
   - the Release build's home from the account record (`getpwuid(getuid())->pw_dir`), ignoring every environment variable; `KLAV_HOME` only behind `#if DEBUG` in `KlavHome.directory()` (§1.2);
   - `scripts/macos/build-app.sh` checking, on every build, the hardened runtime flag and the three entitlements, and failing if any is wrong (§1.2);
   - the window in Settings, with Touch ID to loosen it;
   - `macos.md`, including the Debug build's limit and the home rule.

   On the signed build, once, by hand (Omar), with a checklist (§1.2):
   - unlocking from the app, then using it, asks nothing new;
   - unlocking from the terminal, then using the app, asks once;
   - with Always, each value asks;
   - the build script's check ran and passed on this build;
   - a debugger of the same user can't attach;
   - started with `HOME`, `CFFIXED_USER_HOME` and `KLAV_HOME` pointing at a directory with a socket of its own, the app connects to the default socket (`lsof -U -p <pid>`).

   **Stop rule:** if the build script's check can't be put in place, or either of the last two fails, `hold` stays `not_supported` until Omar decides.

   **Built (2026-11-24),** after layer 4, on top of layer 4's `BrowserAmbiguous` mapping in `klav-ffi`. The build script's check is in place (`scripts/macos/build-app.sh`). The by-hand checklist on a signed Developer ID build is Omar's, and it hasn't run yet, so `hold` stays `not_supported` (layer 6, below).
6. **`presence/on`:** only after `resolve` and `generated_value` are bound to what they were asked about (decision K), the over-long line's gap with a paste of several lines is closed with its test (decision M), a window's time counts from the verification and not from the hand-out (third layer-3 re-review: today a request that holds the session's lock with its own dialog delays the start), and `open_window`'s guards have tests that can fail; and only after layers 4 and 5 resend on the asking connection and send `shown` (own choices 32 and 34): until then, with the gate on, their password resends would never be checked and their password unlocks would open no window. The gate on by default, `hold` on (only if layer 5's by-hand checks passed and the build script's check is in place), the end-to-end tests giving the master password, `klavd.md`, `cli.md`, the public pages, and the threat model's T195–T198, T203 and T204 marked built.

   **Built (2026-11-24), except `hold` and the public pages.** In order:
   - **Decision K.** Before asking, `klavd` resolves each of a `resolve`'s references to its item, checks the field, and keeps every item with its version; `generated_value` keeps a digest of its history entry, the instant and the value (own choice 56). Under the session's lock at the hand-out it checks the same again, and a change is `conflict`, with no window opened. A reference that names nothing is refused before the ask, with the error it gave before (own choice 57).
   - **Decision M.** After any answer at the terminal's question, good or refused, the CLI reads on with echo off until the terminal is quiet for 0.2 s (2 s at most) and drops it, then flushes the input queue (own choice 55). A pseudo-terminal test pastes the password and two shell lines, then a fourth 60 ms later, also after an over-long line; without the drain, 51 bytes reached the shell.
   - **The window's start** is the instant the verification ended, taken before the session's lock, not the hand-out's (`Opening::at`).
   - **`open_window`'s guards** each have a test, and each was broken once and its test failed: the generation check after a lock, the stated window, a tightening while it asked (`min`), the declaration still in place, Always opening nothing, the start taken at the hand-out, and decision K's binding.
   - **The gate is on,** with no flag: `--presence-gate` is removed, not kept as a no-op (own choice 54). The gate-off paths are deleted, among them own choice 19's check of the password against the files on disk while locked, the gate-off `passkeys.json`, and the `conflict` answer to a second password in flight. `browser_fill` now needs the unlocked session (§3.1), so an agent's fill while Klav is locked answers `locked`, after a pause's `agents_paused`. The tests that pinned gate-off behavior are gone; an older `klavd` (no `presence` in `status`) is still covered by the scripted-`klavd` tests in `klav-ffi` (own choice 58).
   - **`hold` stays off,** by layer 5's stop rule: Omar hasn't run its by-hand checks on a signed build. Turning it on is one constant, `HOLD_SUPPORTED` in `crates/klav-daemon/src/server.rs`, which only takes effect on macOS. Until then the app's long connection is keyed like any other peer's (§1.2) and asks again when its window lapses.
   - **The end-to-end tests** give the master password where they read values: the CLI's on a pseudo-terminal (`crates/klav-cli/tests/common/terminal.rs`; Playwright's `Stack.klavInTerminal`), the fake extensions on their connection (`extension_presence`), and the browser in Klav's frame (`confirmPresence`). Linux CI keys the test process by its connection; the macOS runs key it by its parent.
   - **Not done here:** the public pages (`apps/docs`, `docs/features.md`'s public section) still don't list ADR 0041, until Omar says so (ADR 0039's amendment of 2026-11-13).
7. **`card/format` (`klav-core`):** blob `0x24` with its three forms (command, file, this program), the digest, the two labels in spec §2.3, spec §3 and a new §13.13, and `docs/vectores/inject-command.json` with Rust tests that read it.
8. **`card/server` (`klav-proto`, `klav-server`):**
   - `claims.command`, the upload route and its nullable column, the deletions, `target_key`;
   - the `inject_card` switch, turned on in one request with every re-signed grant (all or nothing), with its `400`, its precondition `409` and `inject_rule_missing`; the account lock on every grant write;
   - the lease refused on an `inject` approval without a command while the switch is on;
   - the blobs of expired approvals deleted by the periodic purge;
   - tasks not covering `inject` with the switch on;
   - hidden approvals until their blob arrives, and the push moved to the upload;
   - `inject_card` in `/v1/agent/me` only while the switch is on;
   - `api.md`.

   Tested in SQLite and Postgres, including old-format requests and keys, the precondition with an agent approved during the sheet, a blob that never arrives, and every answer with the switch off compared byte for byte with today's. It needs the "safe with older clients" review before merge (§5.6), because `main` deploys the server.
9. **`card/agent` (`klav-sdk` with `nix`'s `fs` feature, approved; `klav-cli`):** the runtime describes the command or the file (the resolved `argv[0]`, the variables, the output mode, and the write through the directory descriptor), seals and uploads it, checks the limits, and checks that an approval names its digest; `klav agent run|inject`, MCP and the SDK. Tested against a local server, with the switch on and off.
10. **`card/person` (`klav-client`, `klavd`, CLI, extension popup, Mac app, `klav-ffi` and iOS):** opening and checking the blob, the card, the "for a while" text, the Touch ID text, and the new cross-check in `klav log verify`. Tested with a server that swaps the blob, and one that sends another agent's.
11. **`card/tasks`:** `inject` out of new task cards (P15).
12. **`card/migration`:** `inject_card_prepare` and `inject_card_apply`, the sheet in the Mac app and `klav agent inject-card` (§6) with F3's differences and the check that nothing widens, ADR 0032's default rule for `inject`, the `409` paths in the clients, the new issuer warnings, `features.md`, the public docs pages, and the threat model's entries marked as built. An end-to-end test:
    - three agents, one kept, one with a scoped `allow` (tags) and one an issuer;
    - an older server, which stops the sheet before anything is signed;
    - an agent approved from another client while the sheet is open, so the switch is refused;
    - then the switch on;
    - a re-approve from an older client refused.

## Still open
Each piece keeps its first-round number.

**Confirmed by Omar on condition that the independent review passes:**

| # | What | Where |
|---|---|---|
| P5 | Lock and sleep drop every window and held connection, and so does the screen lock on macOS (on Linux it doesn't: risk 79, Omar's decision); a window also ends with its session leader or parent | §2.3 |
| P9 | ADR 0032's "every time" is the same gate, with `EveryTime` | §4 |
| P18 | Presence first; the gate ships off and is turned on once the clients answer `presence_required` | §7 |
| P20 | The threat entries T195–T204 and residual risks 73–79 | Threats |

**Accepted by Omar on 2026-11-18, with the fourth round's changes** (after the third independent review):

| # | What | Where | Findings |
|---|---|---|---|
| P4 | The presence setting, and the passkey setting, sealed in `klavd`'s local data and read at unlock; missing means the default, unreadable means Always; the old `passkeys.json` ignored and the person told once; loosening not retroactive; the password change re-seals both | §2.4 | R4, N8 |
| P21 | The held connection for the Mac app, `hold` as a declaration that only an `unlock` or the gate's window verification turns into a held connection, dropped on Always; the signed build's home from the account record; the build script's check on every build; layer 5's by-hand checks and stop rule | §1.2 | K1, R1, N1, N2, N6, N10 |
| P24 | The terminal's name in the prompt (from the device number, layer 2) and on the CLI (its controlling terminal), the prompt's duration from the window key, `presence_busy` instead of a queue where `klavd` shows the prompt, the `unlock` rule, and the `unlock` prompt with the window | §2.4 | N2, N7, N9 |
| P25 | With more than one extension connection attached, a fill only to the one connection that reports focus, else `browser_ambiguous`; the connection count in the prompt, as a hint | §3.1 | N5, N11 |

**Not built** (Omar's decision of 2026-11-18):

| # | What | Where |
|---|---|---|
| P26 | Watching `klavd`'s directory. The 2-second poll stays, and §8 says what it doesn't cover | §8 |

**New in the third round, or revised in it, for an independent review and then Omar** (the third review didn't cover them):

| # | Proposal | Where |
|---|---|---|
| P22 | The grants and the switch in one request, all or nothing, compared against every active agent's grant version under the account's lock (revised after R6 and R7) | §6, steps 0 and 6 |
| P23 | `inject_card_prepare` and `inject_card_apply`: a batch grant change under ADR 0033's F3 that keeps scopes exactly and refuses anything that widens (rewritten after K2) | §6, step 5 |

**Answered by Omar on 2026-11-18 (the fourth round's questions).** Writing the 2026-11-18 decisions down needed these choices, which his words didn't settle. He chose from short descriptions of each, and took the recommended option each time. The options stay as they were put to him; the answer is under each, and the body reads accordingly. None of them is open.

1. **Q-N1. An `unlock` that finds `klavd` already unlocked by another key: what does its caller see, and what may it do?**
   - (a) `ok` with `already_unlocked: true`. Without the master password it grants the caller's key nothing, no window and no held connection, and the CLI and the app say "Klav was already unlocked elsewhere; this unlock gave this terminal (or app) nothing. If you didn't unlock it, lock Klav". With the master password, the checked password is the caller's own verification and opens its window. **Recommended:** an older client keeps working, and the person learns what happened.
   - (b) A new error, `already_unlocked`. An older client shows it as an error.
   - (c) As (a), but `klavd` also shows a Touch ID for the caller's own key, with the window's text, so the person's unlock still gives them their window.

   **Owner's decision (2026-11-18): (a).** He declined (b) and (c). §2.4.
2. **Q-N2. A change to the presence or passkey setting while `klavd` is locked** (there is no local key to seal it with):
   - (a) Reading and changing both answer `locked`, and Settings shows the value after the next unlock. **Recommended:** nothing unsealed is kept, and a locked `klavd` has no copy of the setting. The cost: `status` can't report the passkey setting while locked, and today that is a required field.
   - (b) Tightening is kept in memory and applied at the next unlock; loosening answers `locked`.
   - (c) A change while locked asks the person to unlock first, and then applies it.

   **Owner's decision (2026-11-18): (a),** with its cost: `status` stops reporting the passkey setting while locked, and the clients accept that. §2.4, which also corrects "a required field": `klavd` always sends it today, and the clients read it with a default.
3. **Q-N3. How Klav "tells them once" that the old passkey setting is ignored:**
   - (a) At the first unlock after the upgrade, `klavd` checks only whether `passkeys.json` exists, never its contents. If it does, the unlock's answer carries a warning that the client shows, and `klavd` deletes the file. **Recommended:** the file stays unread, and someone whose file said Always reads one needless sentence.
   - (b) `klavd` reads the file's value only to decide whether to warn (only someone who had loosened it), never to apply it, then deletes it.
   - (c) Every person is told once after the upgrade, with or without the file, through a flag in `klavd`'s sealed local data.

   **Owner's decision (2026-11-18): (a).** §2.4.
4. **Q-N4. What a prompt says for a peer keyed by its connection** (an unknown peer, an orphan, and on Linux every peer with no terminal, the browser's hosts included). The review proposed "this request", but some of these connections are long: `klav-native-host` relays a browser port over one `klavd` connection, and the app without `hold` keeps one.
   - (a) "let this connection use your vault for 5 minutes", and the window stays on the connection. **Recommended:** it is true of both short and long connections, and it changes no behavior.
   - (b) "this request": a connection key's verification covers only the request that asked. The app without `hold`, and on Linux the browser, then ask for every value.

   **Owner's decision (2026-11-18): (a).** He was told that on Linux the browser then asks once every 5 minutes, and declined (b). §2.4.
5. **Q-N5. Where `klavd` applies P25's rule** (the choice of connection is made at `browser_tab`, and the fill routes by the tab string it returned):
   - (a) At `browser_tab`, and again just before each value-carrying event (`browser_fill`, the fill step of `agent_rotate_begin`, `passkey_arm`): with more than one connection attached, every connection is asked for focus again. **Recommended:** "a fill goes out only if exactly one reports focus" is then true as written. The cost is one more round to the extensions per fill, with more than one connection.
   - (b) At `browser_tab` only, and at the fill a refusal if the set of attached connections changed since.
   - (c) At `browser_tab` only.

   **Owner's decision (2026-11-18): (a),** with its cost. §3.1.

The two other points Omar answered that day, the loosening's own verification and an extension connection's prompt, weren't among these questions. They are with his decisions at the top.

**The ADR's own choices, not Omar's** (fourth round, and the record of its answers). Nobody asked him about these when they were made. He can overturn any of them, and the text says where each one is. On 2026-11-19 he was asked about rows 3 to 22, and his answers are in the last column (the fifth-round answers, at the top): he overturned row 5 and kept or accepted the rest. Rows 6–12, 15, 16 and 20–22 he accepted together, from a one-line summary of each. Rows 1 and 2 weren't asked, and stay the ADR's own choices, open to him.

| # | Choice | Where | What overturning it would mean | Omar's answer |
|---|---|---|---|---|
| 1 | After the setting leaves Always, the app opens a new long connection and declares `hold` again, at its next unlock or when its own Settings moves the setting off Always. Until then its long connection is an ordinary one | §1.2 | Another moment to declare again, or none: the app would stay on per-window prompts until Klav locks | Not asked: still open |
| 2 | A terminal whose device number layer 2 can't name is shown as "a terminal" / «una terminal» | §2.4 | Another text, such as the raw device number, or failing closed with no window for that peer | Not asked: still open |
| 3 | The extension connection's prompt says "a browser" on macOS and "this browser connection" on Linux, as §3.2's texts do. Both systems key this presence by its connection | §3.1 | "This browser connection" on both systems | Kept (2026-11-19) |
| 4 | The same prompt says "until Klav locks", and not "or until the browser closes", though a closed connection ends the grant first | §3.1 | Adding "or the browser closes" / «o se cierre el navegador» | Kept (2026-11-19) |
| 5 | The same prompt calls every value-carrying event a fill, also the fill step of an assisted change and an agent's passkey use (`passkey_arm`) | §3.1 | A text per event | **Overturned (2026-11-19):** a text per event, a fill, an assisted password change's fill step and a passkey sign-in (§3.1). The Always text stays one |
| 6 | One flag, `klavd --presence-gate`, turns on everything a person or an older client would see: the gate, the sealed passkey setting, deleting `passkeys.json`, `locked` settings, `status` without `passkey_uv`, and the `unlock` rule. With it off, an older client sees no change | Plan in layers, item 2; `docs/klavd.md` §3 | Some of them on before layer 6 | Accepted, in the block (2026-11-19) |
| 7 | The socket watchdog's inode check is on without the flag | §8 | Behind the flag until layer 6 | Accepted, in the block (2026-11-19) |
| 8 | `presence_window` answers `not_supported` with the gate off | §2.4 | It reads and changes a setting that nothing uses yet | Accepted, in the block (2026-11-19) |
| 9 | The passkey setting's purpose and file are `passkey-window` and `passkey-window.bin`; the presence setting's are `presence` and `presence.bin` | §2.4, spec §12.2 | Other names | Accepted, in the block (2026-11-19) |
| 10 | The master password travels as `password?` on each of the six window operations, as `passkey_get` does, and comes out before the operation runs | §3.2 | A separate `presence` request that opens the window first | Accepted, in the block (2026-11-19) |
| 11 | The busy rule holds for the same key too: one open presence dialog, whatever asks next | §2.4 | A second request of the same key waits for the open dialog | Accepted, in the block (2026-11-19) |
| 12 | `already_unlocked` is decided by the caller's key: the key that unlocked doesn't get it. A password unlock that finds `klavd` locked opens what the setting gives for the caller's key, with no dialog in `klavd` | §2.4 | Another rule | Accepted, in the block (2026-11-19) |
| 13 | While locked `klavd` can't read the setting, so the unlock dialog states the setting it read at its last unlock. At the first unlock since `klavd` started it states no window and opens none: the next value asks once more | §2.4 | Open the default 5 minutes at that unlock, or keep the setting outside the sealed data | Kept (2026-11-19) |
| 14 | The prompt texts that this ADR doesn't give: each value's own text, the unlock that opens a window, a declared connection ("the program that asked"), a program with no terminal, and the setting change ("ask for your presence every 5 minutes instead of for every value") | §2.4, `docs/klavd.md` §6.1 | Other words | Approved as written, in English and Spanish (2026-11-19) |
| 15 | `hold` answers `{declared, held}` once it is supported | §1.2 | Another shape | Accepted, in the block (2026-11-19) |
| 16 | `extension_attach` is classified but asks nothing yet: its presence comes with layer 4, which builds the frame | §3.1 | The presence in layer 2, with Touch ID only | Accepted, in the block (2026-11-19) |

Rows 17 to 22 were added after the second layer-2 review, with its fixes (Plan in layers, item 2). Nobody asked Omar about them when they were made; he answered them on 2026-11-19.

| # | Choice | Where | What overturning it would mean | Omar's answer |
|---|---|---|---|---|
| 17 | With the gate on, every Touch ID dialog `klavd` shows takes part in the one-prompt rule: a value's, an unlock's, `confirm_presence`, a passkey use, an operation that already asks, and a setting's loosening. With it off, nothing waits | §2.4; `docs/klavd.md` §3 | Only the gate's own dialogs wait; the others may show alongside one | Confirmed (2026-11-19) |
| 18 | One master-password check at a time: another that arrives meanwhile gets `presence_busy` with the gate on, `conflict` with it off, at once. A program that sends wrong passwords back to back keeps the person's own check refused while it sends (the third layer-2 review; Plan in layers, item 2) | §2.3 | A queue, each waiting for the Argon2id before it, or no limit | Kept, with its residual accepted (2026-11-19) |
| 19 | With the gate off, a loosening of the passkey setting while `klavd` is locked still checks the password against the files on disk: there is no session to check against. It gains a program nothing, because with the gate off the setting is the plain `passkeys.json`, which the program can write | §2.3 | Answer `locked` while locked, which an older client would see as a new error | Kept until layer 6 (2026-11-19) |
| 20 | A change of either setting while another change runs gets `presence_busy` | §2.4 | It waits for the one running, and then shows its own prompt | Accepted, in the block (2026-11-19) |
| 21 | The socket's staging name is `klavd.new`, in the same directory, so it fits wherever `klavd.sock` does | §8 | Another name | Accepted, in the block (2026-11-19) |
| 22 | At the staging name, a connection from another process accepted before `klavd`'s own is closed unanswered and `klavd` keeps waiting for its own, up to 10 s; then it doesn't start | §8 | Fail the start at the first connection that isn't `klavd`'s | Accepted, in the block (2026-11-19) |

Rows 23 and 24 were added after the third layer-2 review, with its fixes (Plan in layers, item 2). Omar was asked about both on 2026-11-19 and kept each as built (Decisions).

| # | Choice | Where | What overturning it would mean |
|---|---|---|---|
| 23 | With the gate on, whether a request will show a prompt is judged from the request before it waits for the session's lock: an operation that already asks, sent without a password, and a passkey use the caller's window doesn't cover then. Those get `presence_busy` while a dialog is open or as soon as one opens, also when they would have failed before their prompt. Any other request waits as before, and if it then needs a prompt, gets `presence_busy` if any dialog opened while it waited, whoever held it | §2.4; `docs/klavd.md` §3 | It waits, and its prompt shows right after the open one |
| 24 | A connection queued at the staging name after `klavd`'s own is left in the backlog, and the main loop serves it like any client's once the socket is `klavd.sock` | §8 | Close every connection queued at `klavd.new` before the rename |

Rows 25 to 31 were added by layer 3 (Plan in layers, item 3). After layer 3's review, Omar answered 25, 26, 28 and 31 on 2026-11-19 (last column); 27 and 29 changed in the fix round, and 30 was not asked. Rows 32 to 42 were added by the fix round. Omar answered them on 2026-11-19, after layer 3's second review (his decisions A, B and E): 35 and 42 overturned, the rest accepted as a block. Rows 43 to 50 were added by the second fix round; Omar answered them, and row 30, after layer 3's third review (his decisions G–J). Rows 51 to 53 were added by the third fix round, and nobody has asked him about them yet: they are listed for him in layer 3's PR, with options.

| # | Choice | Where | What overturning it would mean | Now |
|---|---|---|---|---|
| 25 | With no terminal to ask on, the CLI exits with a new code, 9, added to `cli.md`'s table | §3.2; `docs/cli.md` §1 and §8 | Reuse 1 (any error) or 4 (waits for the person) | **Kept by Omar (2026-11-19)** |
| 26 | The master password for presence is read only from the controlling terminal (`/dev/tty`), for a value and for a loosening: `--password-stdin` doesn't count. An `unlock` with `--password-stdin` is unchanged | §3.2 | Accept the `--password-stdin` line as presence too | **First half decided by Omar (2026-11-19):** stdin never counts for a value, also with a terminal. **Second half overturned** with the gate on: a stdin unlock opens no window (his decision 4) |
| 27 | The CLI learns whether the gate is on by reading `presence_window` (the setting or `locked`: on; `not_supported`: off; `bad_request`: older). It reads it before sending `unlock` to an unlocked `klavd`, which it then does only with the gate on, and before an unlock's Touch ID, to name the terminal | §2.4 | Send `unlock` always (a `klavd` without the gate would then sync and count it as use, which it doesn't today), or a field in `status` (a layer 2 change) | Replaced by 39 (finding 7) |
| 28 | The CLI prints its terminal's name where it starts the ask itself: before every master-password question and before an unlock's Touch ID. Before a value whose Touch ID dialog `klavd` shows, it prints nothing: it can't know a dialog will open | §2.4 (N9) | A line before every value command while the gate is on and Touch ID available, or a notice from `klavd` just before it shows a dialog (a protocol addition) | **Overturned by Omar for values (2026-11-19):** `klavd`'s notice (his decision 2). Every master-password question the CLI sends to `klavd` with the gate on also says what it opens (finding 1) |
| 29 | One try: a wrong password ends the command with `wrong_credentials` (exit 1), as the direct mode does | §3.2 | Ask again, up to a few times | Kept per question; a second question only when `klavd` didn't check the first (33) |
| 30 | Omar's `already_unlocked` text says "this program" instead of "this terminal" when the CLI has no terminal | §2.4 (Q-N1) | His words as they are | **Accepted by Omar (2026-11-19),** in the block of his decision J |
| 31 | A `klav unlock` told `already_unlocked` asks for nothing more: the next value asks | §2.4 (Q-N1) | Ask for the master password right away, so that this `unlock` opens this terminal's window | **Kept and extended by Omar (2026-11-19):** no password asked, nothing sent, on an unlocked Klav (his decision 5) |
| 32 | `klavd` checks a password only as the answer to the last ask it sent that connection, and only if it would ask exactly the same now (the `presence` object, the request without `password`, the item). Otherwise, and for a password with no ask before it, it answers a new `presence_required` and leaves the password unchecked. The ask is kept per connection: a client that sends the password on a new connection (today's `klav-ffi` `DaemonEngine`, one connection per request) is never checked, so layer 5 must resend on the connection that got the ask | §2.4; `docs/klavd.md` §3 | Check it anyway and grant the narrower of the two asks; or key the ask by the window key, not the connection | Accepted, in the block (2026-11-19) |
| 33 | When the resend gets a new ask, the CLI says the password wasn't used and asks once more with the new words; a third ask ends the command (exit 1) | §3.2; `docs/cli.md` §8 | End the command at the first changed ask, or ask without a limit | Accepted, in the block (2026-11-19) |
| 34 | A password `unlock` opens what the client's question said (`shown`) only if that is what `klavd` would open now; otherwise, and without `shown`, none. With the gate on, an older client's password unlock (the current Mac app and extension) then opens no window, where own choice 12 opened the setting's; the gate stays off until layer 6, after layers 4 and 5 teach both clients `shown` | §2.4; `docs/klavd.md` §3 | Open the setting's window when `shown` is missing, as before | Accepted, in the block (2026-11-19) |
| 35 | Before the first unlock since `klavd` started, when the setting isn't read yet, `status` says `lasts: setting`, the CLI's question says "for as long as your presence setting says, at most until Klav locks", and the unlock opens the setting's window, at most `shown`. This keeps own choice 12 for that unlock | §2.4 | No window at that unlock, as for its Touch ID dialog (own choice 13) | **Overturned by Omar (2026-11-19):** the first unlock opens no window (his decision A); `lasts: setting` is gone |
| 36 | An item renamed or replaced between the ask and the answer: the gate re-reads it under the session's lock and answers `conflict` ("the item changed while you confirmed: nothing was handed out"), exit 1. The CLI doesn't retry | §2.4 | Hand out the item the query finds now | Accepted, in the block (2026-11-19) |
| 37 | Ctrl-C or Ctrl-D at the question cancels it: exit 1, "canceled: no master password was sent", the terminal restored | §3.2; `docs/cli.md` §8 | Exit 130, as a shell does for `SIGINT` | Accepted, in the block (2026-11-19) |
| 38 | Only the gate's questions read the terminal themselves; every other master-password prompt keeps `rpassword`, whose Ctrl-C leaves echo off, because the brief kept the gate-off CLI unchanged | §3.2 | Move every prompt to the same reader (a change with the gate off) | Accepted, in the block (2026-11-19) |
| 39 | Whether the gate is on comes from `status`'s `presence` (replaces 27). A `klavd` that sends none is read as before the gate: an older one has no gate, and a gate-on one always sends it. If one didn't, the value path still answers `presence_required` and an `unlock` sends no `shown`, which opens no window | §2.4 | Keep a probe, with `bad_request` read as an error | Accepted, in the block (2026-11-19) |
| 40 | The value's words are the CLI's, in English, from `value`'s kind and title; the title is cleaned by `klavd` and again by the CLI (40 characters, quotes replaced) | §2.4; `docs/klavd.md` §3 | `klavd` sends the sentence in the client's language | Accepted, in the block (2026-11-19) |
| 41 | `klavd`'s own messages are cleaned by the CLI in the value commands and the setting's change, with the gate off too. Text with no hidden character and at most 1000 characters is printed unchanged, so the real `klavd`'s messages print byte for byte, and in `klav unlock` and the operations that already ask only with the gate on, so their gate-off output stays byte for byte. Six paths still print `klavd`'s text raw, with the gate on too: the note `klav generate` prints when the history can't keep a password (`crates/klav-cli/src/commands/generate.rs`), an import's refusal (`crates/klav-cli/src/backend.rs`), every call's warnings (`crates/klav-cli/src/backend.rs`, `call`), every `klavd` error message (`crates/klav-cli/src/error.rs`, `CliError::Daemon`), `klav log reset`'s warnings (`crates/klav-cli/src/commands/log.rs`) and the refusal `klav proxy use` reads from `status` (`crates/klav-cli/src/commands/proxy.rs`; the warnings printed a few lines further on, in the no-`klavd` path, are `klav-client`'s own) | `docs/cli.md` §8 | Clean them everywhere | Accepted, in the block (2026-11-19) |
| 42 | A password `unlock` that opens no window (`shown` missing or different, a password from stdin) still counts as the passkey verification of ADR 0020 §8 for the caller's key, as every password unlock did before the gate: `klavd` can't tell a typed `shown: always` from a stdin one without another wire value | §2.5 | A stdin unlock grants no passkey verification either, with a new `shown` value or field for it | **Overturned by Omar (2026-11-19):** an `untyped` unlock grants no passkey verification (his decision B) |
| 43 | A value request resolves its query to one item before anything is asked, also when the answer would open a window; the item then binds the hand-out under every grant, so a rename during a window's dialog also gets `conflict`. Before, a window's verification hand-out read the query afresh | §2.4; `docs/klavd.md` §3 | Bind only one-value grants, and let a window's first value be whatever the query names after the dialog | **Accepted by Omar (2026-11-19)** with his decision G: a `conflict` opens no window |
| 44 | The remembered ask includes the item for window asks too, so a rename between the ask and the resend gets a new ask with the same words, the title included | §2.4 | Leave the item out of window asks: the window, not the item, is what the person approves | **Accepted by Omar (2026-11-19)** with his decision G |
| 45 | Decision C's wording ends the value's text with "(for …)" / «(para …)». A fill for the browser's own window keeps "fill “GitHub” in a browser" | §2.4; `docs/klavd.md` §6.1 | "let the terminal ttys003 show the code of “GitHub”" / «dejar que la terminal ttys003 muestre el código de «GitHub»» | **Approved by Omar as built (2026-11-19)** (his decision H) |
| 46 | Decision B's wire value is an envelope boolean, `untyped`, missing for typed. It also applies when `klavd` is already unlocked, and doesn't touch a Touch ID unlock. The Mac app and the extension send none: the person types into their own window | §2.5; `docs/klavd.md` §3 | A new `shown` value (`untyped`) instead; or a field of the `unlock` request | **Kept by Omar (2026-11-19)** (his decision I): the client's own word, not checked by `klavd`; nothing sent counts as typed |
| 47 | The question's reader: ESC followed by a non-ASCII byte counts as that byte; a bracketed paste's text goes in (its markers don't); no cursor movement, so arrow keys do nothing | §3.2; `docs/cli.md` §8 | Drop the byte after ESC whatever it is; refuse a bracketed paste; support moving the cursor | **Accepted by Omar (2026-11-19),** in the block of his decision J, with two fixes: a line past 1024 bytes is refused whole and none of it reaches the shell, and `ESC O` with a parameter is dropped whole |
| 48 | The remembered request is its SHA-256 through `klav_core::crypto::agent::body_digest`, the digest agents' requests already use; a request `klavd` can't serialize again is refused as `internal` | §2.4 | A new label for this digest; or compare such a request as unequal and ask again | **Accepted by Omar (2026-11-19),** in the block of his decision J |
| 49 | `lasts: setting` is removed from the wire, not kept and never sent: it existed only for own choice 35 and was never released | `docs/klavd.md` §5 | Keep it as a value the client still reads | **Accepted by Omar (2026-11-19),** in the block of his decision J |
| 50 | `autofill` with a title as its item is still asked about, and refused by the fill only after presence, as before: its ask now names the item the title resolves to | §3.1 | Refuse a title before asking, as for a query that names no item | **Accepted by Omar (2026-11-19),** in the block of his decision J |
| 51 | ~~`resolve` and `generated_value` are bound to no item.~~ Built bound in layer 6 (own choices 56 and 57). As first built: `resolve` resolves each reference only at the hand-out (`klav_client::ops::resolve_all`): a reference that names nothing fails after presence, and the item behind a reference can be renamed, replaced or edited between the ask and the hand-out with no `conflict`. Their ask says "use N values from your vault in a command" or "show a password you generated", which stays literally true (risk 95) | §2.2; `docs/klavd.md` §3 | Bind them: resolve every reference to an item before asking, keep each item and version with the ask, and answer `conflict` at the hand-out if any changed; and bind `generated_value` to its history entry | Overturned by Omar (2026-11-19, decision K): bind them in a later round, before the gate is turned on. Built in layer 6 (2026-11-24) |
| 52 | Decision G's window opens only once the hand-out has found the item and the version asked about, under the session's lock. A refusal before that check opens no window either: a lock, a failed revalidation of the cache. A refusal after it (the fill refusing a title, an item with no code) still opens it, as before | §2.4; `docs/klavd.md` §3 | Open the window on every outcome but `conflict` | Accepted by Omar (2026-11-19, decision L) |
| 53 | A line past 1024 bytes at the gate's question is refused only at its end: the reader keeps reading, with echo off and nothing shown, until Enter, Ctrl-C or the terminal closing, then flushes what is queued and says the password was too long. Only that refusal flushes: after a normal Enter, the rest of a multi-line paste still reaches the shell, as before this round | §3.2; `docs/cli.md` §8 | Refuse at byte 1025 at once and flush what is queued then (bytes still arriving afterwards reach the shell) | Accepted by Omar (2026-11-19, decision M), with the several-line paste's gap closed before the gate is turned on. Closed in layer 6 (own choice 55) |
| 54 | `klavd --presence-gate` is removed in layer 6, not kept as an accepted no-op: no released `klavd` had it (layers 2–5 never shipped it on), and a hidden flag that does nothing would mislead whoever reads a launch command | Plan in layers, item 6; `docs/klavd.md` §3 | Keep accepting it and ignore it | Not asked: open |
| 55 | Decision M's fix accepts the paste: the first line is the password and is checked; what follows it is read and dropped until the terminal is quiet for 0.2 s, 2 s at most, then the input queue is flushed. The same drain runs after an over-long line and after Ctrl-C | §3.2; `docs/cli.md` §8 | Refuse a password that arrives with more lines behind it; or wait longer than 0.2 s (slower terminals over ssh may split a paste wider) | Not asked: open |
| 56 | `generated_value` is bound to a SHA-256 of its entry, the instant (big-endian) and then the value, through `body_digest`, kept in memory with the ask; not to the instant alone, which a delete and a new entry at the same millisecond would reuse | §2.4; `docs/klavd.md` §3 | Bind to the instant only | Not asked: open |
| 57 | A `resolve` whose reference names nothing, or a field the item lacks, is refused before the ask with the error it gave before (now `invalid` or `not_found` at once), so a program learns that without presence, as `view` without `reveal` already tells it | §2.4; `docs/klavd.md` §3 | Ask first, and refuse after presence | Not asked: open |
| 58 | The tests that pinned gate-off behavior are deleted with the gate-off code, not kept against a hidden switch; an older `klavd` is still covered by `klav-ffi`'s scripted-`klavd` tests | Plan in layers, item 6 | Keep a test-only switch to turn the gate off | Not asked: open |

## Rewritten at Omar's direction after the first review
Not open proposals: Omar directed each change through the review's findings, and the independent review checks them.

| # | What | Where | Findings |
|---|---|---|---|
| P1 | What the kernel gives and what it doesn't; on macOS, `last_pid`, the fd-ownership check and the unique-ID re-check, with Q2's stop rule; on Linux, the pidfd, re-checked after reading `/proc`, and no window before 6.5 | §1.1 | B1, S3, R3, R8 |
| P6 | The table of §3, by variant and argument, kept exhaustive in code (the writes are Omar's decision) | §3 | M1, M2 |
| P8 | `klavd` shows Touch ID itself; without it, `presence_required` and the master password in Klav's frame or the terminal; the prompt texts | §3.2 | S6 |
| P10 | What the agent describes: `argv`, the resolved `argv[0]`, the working directory, the receiving variables and the output mode; or the destination path, written through its directory; or the calling program | §5.1 | S7, M7, R5 |
| P11 | Blob `0x24` with HPKE to the account's identity, its labels under `klav/v1/inject/`, its three forms and the lowered limits | §5.2 | S8, M5, R5 |
| P13 | `claims.command` in the signed body and `target_key`; the blob uploaded apart, not logged, hidden until it arrives, deleted on decision, on expiry or by the purge | §5.3 | S8 |
| P14 | The card's text, the escaping, the "for a while" text, and a Touch ID prompt without the command | §5.4 | S7, M6, R10 |
| P16 | The `inject_card` account switch, off until the migration, in `/v1/agent/me` only while on, with no path to turn it off | §5.6 | B2, S9 |
| P19 | `PR_SET_DUMPABLE` on Linux, and the socket-inode watchdog, with what it doesn't detect | §8 | S1, R1 |

## Stop rules
- **Layer 1, macOS** (Omar's decision on Q2): if `klavd` can't be shown to check that the reported process holds the socket, and is the same process from the first read to the last, layer 1 stops and reports. No other presence layer starts until Omar chooses between a window per connection and the session key with the residual named (§1.1).
- **Layer 5, the held connection (R2, N10):** `klavd` keeps answering `hold` with `not_supported` until Omar decides (§1.2) in any of these cases:
  - the build script's check of the hardened runtime and the three entitlements can't be put in place;
  - a same-user debugger attaches to the signed build;
  - the signed build, started with `HOME`, `CFFIXED_USER_HOME` and `KLAV_HOME` set, connects to any socket but the default one.

  On a later build, the script's check fails the build itself.
- **Not a stop rule (Omar's decision of 2026-11-18):** whether a debugger's attach reparents a process on macOS. Layer 2 checks it if it can and records the result (Plan in layers, item 1).
