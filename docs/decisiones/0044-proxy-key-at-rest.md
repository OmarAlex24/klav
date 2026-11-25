# 0044 · The credential proxy's key at rest: an alarm for a new address, an egress address signed by the person, and the proxy's memory kept out of swap and core dumps

- Status: Accepted (2026-11-18), not built. Omar approved the direction on 2026-11-18, before launch, as an amendment to ADR 0036: the alarm, the optional signed egress address and the memory measures («si, vamos con tus recomendados»). The same day he answered Q1–Q10 (the owner's decisions, below). His answer to Q2 adds two network profiles per proxy, an alert profile (the default) and a strict one (§2.5); his answer to Q10 makes a strict network lapse after 90 days unseen, as an alert one does (§2.6). §11 lists what this ADR chose on its own so he can overturn it
- Date: 2026-11-18
- Amends: [ADR 0036](0036-sandboxes-de-agentes.md) §2 and §11 (dated notes there). Nothing in ADR 0036 is reversed: the proxy is still an agent with a key that lives where it runs
- Leaves to the second ADR (deployed services): what [ADR 0038](0038-deployed-services.md) keeps in the proxy's memory and lets through during a pause (§12)

## Context

### What Omar asked for
In his words: "I wanted my proxy to be as secure as possible, and that I'm not the leak point now", and "that my proxy is dumb: it never has anything stored in plain text".

The coordinator proposed three measures, and Omar approved them before launch:
- **The alarm:** the server notifies the person's phone when a proxy's key is used from a new address.
- **The pin (optional):** the person's devices sign the proxy's egress address, and the server refuses the key from anywhere else.
- **The memory:** the proxy locks its memory against swap and turns off core dumps.

The stated limit: none of this stops someone who is already inside the proxy's host.

**What this ADR does not give Omar, said first:** the proxy's key still sits in plain text at rest, in a 0600 file by default, or in the macOS keychain when the proxy was set up with `--store keychain` (`crates/klav-proxy/src/main.rs:55`, `:99-100`). §10 explains why each way to encrypt it was rejected. What the three measures do is make a copy of the key **visible** (the alarm) and **useless from elsewhere** (the pin), and keep the values the proxy decrypts out of swap and core dumps (the memory).

### The problem, checked in the code at `main` (`fee28baa`)
A read-only review reported the points below. I checked each one in the code and say where it was wrong.

- **Where the key lives.** The proxy's agent key (`kag1_`, spec §13.2, [`especificacion-cripto.md`](../especificacion-cripto.md):629) is not encrypted. The proxy keeps it in a 0600 file it checks at start (`crates/klav-proxy/src/app.rs:93-142`: a regular file of its own user, mode 0600, in a directory only its owner can write) or, when chosen with `--store keychain`, in the macOS keychain. The file is the default (`crates/klav-proxy/src/main.rs:55`, `:99-100`).
  - **Correction to the review:** the proxy refuses to start with `KLAV_AGENT_KEY` set (`app.rs:78-84`, `app.rs:221-222`). That variable is a key source for other agents through the SDK (`crates/klav-sdk/src/keystore.rs:7`, `:113`), not for the proxy.
  - The same key is the proxy's identity in the sandbox channel. `serve` takes the channel's TLS signer from it (`app.rs:577-578`), and the forwarder pins its SPKI (spec §13.10, lines 870 and 882).
- **What a copy is worth.** With a copy of `agents/<name>.key` and `agents/<name>.json` (the json holds no secret, `crates/klav-sdk/src/config.rs:1-11`), someone on any machine can read every provider key granted to the proxy:
  1. Sign `GET /v1/agent/me` and get the grant with `items[].shared_key`.
  2. Open each item key with the proxy's X25519 key (`crates/klav-sdk/src/grant.rs:60-70`).
  3. Send `POST /v1/agent/access` with `permission: proxy` and a host, method and path the policy allows (`crates/klav-sdk/src/proxy.rs:125-144`).
  4. Decrypt the sealed item from the answer.

  The server checks only the signature, the timestamp, the nonce, the agent's status, a pending deletion and a pause (`crates/klav-server/src/agentauth.rs:161-280`). Nothing in it looks at where the request comes from. Only revoking the proxy, or changing the item key (spec §13.4, "Cambio de llave de un elemento"), stops it. This part of the review is right.
  - **One detail the review didn't state:** the value itself comes only from a **logged** call. `GET /v1/agent/items` lists only the grant's projects (`crates/klav-server/src/routes/agent_access.rs:945-949`), and a proxy's grant has none (spec §13.4, version 2). So a thief's reads of values appear in the audit log as the proxy's own `agent.access` events. They are indistinguishable from the real proxy's.
- **Alarms.** T23 of the threat model promises "alertas de uso anómalo" ([`modelo-de-amenazas.md`](../modelo-de-amenazas.md):106).
  - **Correction to the review:** some alerts exist, so "no alarm exists" is too strong. The server tags logged events with `denied`, `first_use` and `burst` (`crates/klav-server/src/audit.rs:30-77`; the field is `crates/klav-proto/src/audit.rs:134-137`). The apps show them in the activity view (`apps/ios/Shared/App/ActivityWords.swift:115-121`).
  - **What is missing:** none of these is pushed, none looks at an address, and `first_use` and `burst` skip the `proxy` permission entirely (`uses_secret`, `audit.rs:33-38`). For a proxy, only `denied` can fire. Nothing in ADR 0036 or 0038 adds an alarm. The server uses the client's address only for rate limiting (`crates/klav-server/src/ratelimit.rs:186-250`) and for the registration and login limits (`routes/agents.rs:124-136`, `routes/auth.rs:47-70`).
- **Memory.** `mlock` is postponed (T33, `modelo-de-amenazas.md`:122; ADR [0013](0013-touch-id-secure-enclave.md) §9). `klav-proxy`'s source has no `mlock`, core-dump limit, `prctl` or `madvise`; nor do `klav-daemon`, `klav-cli`, `klav-core` or `klav-sdk` (grep at `fee28baa`). `klav-proxy` enables only `nix`'s `user` feature (`crates/klav-proxy/Cargo.toml:29`). Copies of a value outside a `SecretBox`:
  - **The header itself:** `HeaderValue::from_bytes` copies prefix and value into a buffer that is not zeroed when dropped (`crates/klav-proxy/src/profiles.rs:183-193`). The intermediate `bytes` and the copy returned for the redactor are `Zeroizing` (`profiles.rs:183-185`, `:194`), so they are wiped, but they are plain heap copies.
  - **The redactor:** it holds the value (`Zeroizing`, `crates/klav-sdk/src/actions.rs:160`, `:194`) until the answer ends (`crates/klav-proxy/src/proxy.rs:39-50`, `:1137-1138`), so up to the request timeout of 120 s. With a stream (`text/event-stream`, the MCP gate, ADR 0036 §7, note of 2026-11-19), up to the longest life of a stream, 15 minutes, and never past its sandbox (note of 2026-11-25: corrected when step M3 was built).
  - **Not checked:** what `hyper`'s write buffer and `rustls`'s plaintext buffer keep of the outgoing request after it is sent.

### The five things checked before designing

**1. Which address the server really sees in production.**
- **The code.** The middleware `limit_by_ip` (`ratelimit.rs:231-250`) picks the source from `Config` (`crates/klav-server/src/config.rs:233-238`) and stores the result as `ClientIp` for the routes:
  - by default, the TCP peer;
  - with `trust_forwarded_for` (`KLAV_TRUST_FORWARDED_FOR`), the rightmost `X-Forwarded-For` entry;
  - with `trusted_ip_header` (`KLAV_TRUSTED_IP_HEADER`), the last value of that header.

  The two settings exclude each other (`config.rs:394-406`). A header that is missing or isn't a single address falls back to the peer (`ratelimit.rs:197-228`).
- **The repository's Railway image sets neither** (`deploy/railway/Dockerfile:67-71`). The docs say to leave `KLAV_TRUST_FORWARDED_FOR=false` always, and to set `KLAV_TRUSTED_IP_HEADER=x-real-ip` only after a test shows Railway replaces the header ([`self-hosting.md`](../self-hosting.md) §8.1, "La IP del cliente"; §3.2).
- **So, with the image's defaults behind Railway's edge,** the server sees the edge's address for every client. An alarm or a pin on that value is worthless: every proxy and every thief would arrive from the same few edge addresses.
- **Not checked:** what production sets. I didn't query Railway, as the brief forbids it. Whether Railway's edge replaces a client's `X-Real-IP` is also unverified: Railway's docs don't say, as `self-hosting.md` §8.1 records.
- **Who could forge the value:**
  - with a header source, anyone whose request reaches the server without passing the edge that rewrites it, or through an edge that appends instead of replacing;
  - with the peer source behind a proxy, nobody needs to forge anything, because the value says nothing.

  §1.1 builds on this: the alarm and the pin work only on a server whose operator turned them on, and the default is off.

**2. Whether a push to the person's devices for a security event exists.**
- **The iPhone.** APNs exists for approvals, agent registrations, tasks and the account's deletion (`crates/klav-server/src/push.rs:59-77`). The payload carries no text: localisation keys, a type and an ID (`push.rs:119-137`). Each kind has an hourly budget per account (`push.rs:43-55`, `:368-382`). Without an APNs key, `notify` returns and nothing is sent (`push.rs:320-324`); the APNs settings are optional ([`self-hosting.md`](../self-hosting.md) §2.4).
  - **The iOS app** routes only `approval`, `agent` and `task` (`apps/ios/Klav/Push.swift:12-23`). The localisation keys come from the app's own strings, so an older app that got an unknown key would show the bare key.
  - **The server can't tell which kinds a phone understands.** A phone registers a token and an environment, nothing else (`crates/klav-proto/src/auth.rs:352-360`, `deny_unknown_fields`; `crates/klav-server/src/routes/devices.rs:27-79`).
- **The Mac** has no APNs. It reads its requests through `klavd` every 10 s while unlocked and shows a local notification for each new one ([`macos.md`](../macos.md) §1, lines 67-68).
- **The push for a second claim that ADR 0036 promises** (§5, line 297, and E5: `sandbox_theft`) **is not built.** The table `sandbox_pushes` exists (`crates/klav-server/migrations/sqlite/0019_sandboxes_de_la_persona.sql:66-76`), but nothing sends it ([`roadmap.md`](../roadmap.md):341, "nadie los manda"). `GET /v1/events` sends only `change` and `resync` (`crates/klav-server/src/routes/sync.rs:237-242`).
- **So the alarm needs a new push kind, a way for the phone to say it understands it, and a list the Mac and the CLI can read** (§1.4). Nothing that exists today delivers it.

**3. Where the person's choice of proxy is signed, and what its bytes are.**
- **The setting** `preferences.proxy = {mode, agent_id?}` lives in the encrypted `preferences` item (spec lines 358 and 414-415; `crates/klav-core/src/model/preferences.rs:32-55`). It is sealed, not signed, and the server never reads it.
- **The signed part** is the grant:
  - the proxy's grant is `GrantPayload` `v: 2`, or `v: 3` with `issuers`;
  - it is signed with `klav/v1/sig/agent-grant` (`crates/klav-core/src/crypto/agent.rs:39`; spec §13.4);
  - the issuer's grant (`v: 3`) carries `sandbox.proxy.url`, the address the forwarder dials (`crates/klav-proto/src/agent.rs:232-240`).
- **No signed structure carries an egress address,** so the pin needs either a new grant field or a new signed record:
  - **A grant field means `v: 4`,** and an un-updated proxy rejects its own grant ("the grant is not readable", spec §13.4, last bullet), so it stops working until it updates. Old apps, `klavd` and verifiers reject it too.
  - **A new signed record, as the pause (§13.9) and the person's sandbox revocation (§13.11) did, leaves the grant alone.** The proxy never needs to read it, because the server enforces it.

  §2 chooses the record.

**4. Why T33 postponed `mlock`, and what `nix` covers.**
- **Why it was postponed.** ADR 0013 §9 gave four reasons:
  - whoever can read swap or a dump is root or the same user, who can already read `klavd`'s live memory;
  - macOS encrypts swap;
  - doing it well needs `unsafe` or `memsec`/`region` on every secret type;
  - it would come back "with the desktop app or if the model changes".

  The proxy is such a change. It runs unattended on hosts that may not encrypt swap, and its operator (ADR 0036 §11) is a third party that can collect core dumps.
- **What `nix` 0.31.3 covers** (the version in `Cargo.lock`), with no new crate. Read in its source:
  - `mman` gives a safe `mlockall` and `MCL_CURRENT`/`MCL_FUTURE` (`src/sys/mman.rs:404`, built everywhere but Haiku, Cygwin and Redox). Its `mlock` is `unsafe` (`mman.rs:381`), which `CLAUDE.md` forbids outside `klav-ffi` and the Touch ID shim, so per-buffer locking is out.
  - `resource` gives `setrlimit` with `RLIMIT_CORE` and `RLIMIT_MEMLOCK` (`src/sys/resource.rs:65`, `:90`, `:230`).
  - `process` gives `prctl::set_dumpable` on Linux only (`src/sys/mod.rs:66-70`; `src/sys/prctl.rs:63`). ADR 0041 §8 and §9 already plan it for `klavd`.

  In `nix`'s own `Cargo.toml`, `mman = []`, `resource = []` and `process = []`: none brings in a crate. So the memory measures need no new dependency and no approval beyond this ADR (§3.5).

**5. How the server could tell "this proxy key, from a new address".**
- **Today** the server stores per agent its identity, status, dates, grant and `last_seen_at`, but no address (`crates/klav-server/migrations/sqlite/0005_agentes.sql:9-26`). It writes `last_seen_at` at most once a minute, after the signature checks out (`agentauth.rs:59-60`, `:241-248`). No migration stores an address (`grep` over `migrations/`: only `push_tokens`, which holds an APNs token, not an address).
- **What it would need:** a table of the networks each agent was seen from, written at the same point and with the same granularity, plus a table for the signed pin. Both go in new migration files (`0020`, and `0021` if the pin ships separately). No existing migration is edited.

## The owner's decisions (2026-11-18)

Omar answered Q1–Q10 on 2026-11-18. The ADR records them as given; where he chose an offered option, it was the recommended one. The questions as they were asked are at the end.

1. **Owner's decision (2026-11-18). The pin is off by default** (Q1 (a)). The app suggests it for a proxy seen from one network for 7 days, or on a VPS with a fixed address (§2.4).
2. **Owner's decision (2026-11-18). Two network profiles per proxy** (Q2). In his words: «podriamos tener un perfil estricto que rechace estos cambios, y otro default que solo avise» ("we could have a strict profile that refuses these changes, and a default one that only alerts"):
   - **the alert profile, the default:** a new network raises the alarm and the request goes on (option (a));
   - **the strict profile:** the server refuses the proxy from a new network until the person confirms it (option (b)).

   *The coordinator's reading, not Omar's words:* the strict profile and the signed pin of §2 are one thing. Turning on "strict" is turning on the pin, and confirming a new network is signing it into the pin with Touch ID or Face ID. That agrees with decision 1: strict is off by default and suggested. §2.5 designs it that way and says exactly where the pin as first written differs from "refuses these changes until the person confirms". The one difference that needed a choice was Q10, settled by decision 10.
3. **Owner's decision (2026-11-18). A network stays known for 90 days since it was last seen** (Q3 (a)).
4. **Owner's decision (2026-11-18). The alarm covers proxies only, for now** (Q4 (a)). Other agents may come later, one by one, by a switch in the agent's sheet.
5. **Owner's decision (2026-11-18). The phone's words are neutral, with no name in the payload** (Q5 (a)).
6. **Owner's decision (2026-11-18). When the host refuses to lock memory, the proxy starts, warns and reports `locked: false` in `status`,** with `--require-memory-lock` for whoever wants it fatal (Q6 (a)).
   - **Amended by decision 17 (2026-11-19), for macOS only:** a Mac, which can't lock at all, starts without the warning; `status` says why. On Linux it still warns.
7. **Owner's decision (2026-11-18). The server keeps agents' addresses in clear,** deleted after decision 3's 90 days and with the agent (Q7 (a)).

   Before choosing, Omar asked: «pero si se guarda esto, un hacker no podria modificar la red para "pasarse" a la lista blanca?» ("if this is stored, couldn't a hacker change the network to get onto the allow list?"). He was told, and the ADR keeps it as plainly:
   - **The pin's list (the strict profile) is signed by his devices,** so the server can't add to it. A malicious server can only ignore it (§8).
   - **The alarm's list of known networks lives in the server's database.** Whoever controls the server can add their network and silence the alarm, whether the addresses are stored in clear or hashed. Hashing would not change that.
   - **A thief without the server** can't edit that list or fake a source address, and gets past the alarm only by leaving through the proxy's own network. "Can't fake a source address" holds on a server whose address source the operator checked (§1.1, T212); on one that trusts a header its edge doesn't replace, the address is worth nothing.

   He was also offered a variant where every confirmed network is signed by a device, also under the alert profile, and did not choose it. It is not rejected; it is not in this design.
8. **Owner's decision (2026-11-18). Omar turns it on in production himself** (Q8 (a)). After layer 2 deploys, he runs the `self-hosting.md` §8.1 test against production and, if it passes, sets `KLAV_TRUSTED_IP_HEADER` and `KLAV_AGENT_ADDRESSES`.
9. **Owner's decision (2026-11-18). A pin entry is `/32` for IPv4 and `/64` for IPv6 by default** (Q9 (a)). Wider ranges only through the CLI.
10. **Owner's decision (2026-11-18). Under the strict profile, a network also lapses after 90 days unseen** (Q10 (a)). The server stops admitting a pinned network it hasn't seen for 90 days; the person lets it in again with Face ID or Touch ID; the apps sign a narrower list without it. The cost he accepted with it: the server admits fewer networks than the signed list names, and the audit log shows the signed list, not the shorter one in force. §2.6 designs it.

### The owner's decisions on layer 1 (2026-11-19)
An independent review of layer 1's pull request (#466) found that the lock turned itself on with no way to turn it off and had never run past start-up, and that `status` showed an unauthenticated record as the proxy's state. Omar decided the following on 2026-11-19, after reading the review and the layer's questions L1–L8 (§11). Where a decision changes the text above or below, a dated amendment sits at that place.

11. **Owner's decision (2026-11-19). The lock is on fault.** `mlockall` adds `MCL_ONFAULT`: a page is locked once the proxy touches it, so the key and the values never reach swap, but pages nobody touched (thread stacks above all) are not made resident. A kernel that refuses the flag is a lock that could not be taken: an unlocked start with the reason, fatal with the requirement, never a silent fall back to locking every page at once. Amends §3.2.
12. **Owner's decision (2026-11-19). An off switch.** `KLAV_PROXY_MEMORY_LOCK=off`, or `--no-memory-lock`, starts without trying to lock, and `status` shows the lock as turned off on purpose. Core dumps stay off always: the switch touches only the lock. With `--require-memory-lock` or its variable it is a start-up error. Omar decided that the switch exists, shows in `status` and is an error together with the requirement; which values it accepts is the layer's own choice (§11, L9). *Corrected on 2026-11-19, third round: this sentence used to end "Its values are strict, as in decision 16", which Omar did not decide.*
13. **Owner's decision (2026-11-19). Only the limit decides (L3 confirmed).** `CAP_IPC_LOCK` with a finite limit does not count: the proxy locks only when the `memlock` limit is unlimited or it can raise it. §3.2's gloss names the capability; this is Omar's choice of the simpler rule, not the rule "as written" (note in §3.2).
14. **Owner's decision (2026-11-19). Refuse always (L2 and L4 confirmed).** If core dumps can't be turned off, or on Linux the process stays dumpable, `init`, `serve` and `status` all stop, with a message that says what failed. What L4 confirmed is that `status` hardens itself and refuses when core dumps can't be turned off; that `status` also locks its own memory is the layer's choice (§11, L20).
15. **Owner's decision (2026-11-19). `status` shows the last `serve`'s memory, from its record (L1 confirmed),** read with the sandbox store's checks, and worded as what the `serve` that last wrote this record recorded, saying that `status` can't tell whether that proxy still runs. *Amended by decision 24 (2026-11-19): this read "the `serve` that last started" until L15 made the record the one of the `serve` that last started listening.* *Amended again by decision 27 (2026-11-19): it read "the `serve` that last started listening" until then.*
16. **Owner's decision (2026-11-19). Strict values (L5 confirmed)** for `KLAV_PROXY_REQUIRE_MEMORY_LOCK`: only `1`, `true`, `0` and `false`.
17. **Owner's decision (2026-11-19). No warning on macOS (L8 confirmed).** This amends decision 6's "warns" for macOS only.
18. **Owner's decision (2026-11-19). L6 and L7 accepted:** `dumpable` is `null` on macOS; the record carries `since`, and `why` is left out when locked.

Everything below that isn't one of these sentences is design.

### The owner's decisions on layer 1, third batch (2026-11-19)
After a second independent re-review of #466, Omar decided the following on 2026-11-19. Decisions 19–25 answer the questions on L9–L20 (§11) and two of the re-review's points on the wording of decisions 11 and 15.

19. **Owner's decision (2026-11-19). L18 is overturned: a lock that took, doesn't read back and can't be undone starts, and says so.** When `mlockall` succeeded, `VmLck` reads 0 or can't be read, and `munlockall` then fails, the proxy does not refuse:
    - the memory stays marked to lock, and a limit the proxy raised **stays raised**: putting it back while the lock is on would make a later allocation fail under a finite limit, the defect the third round fixed;
    - the start's log and `status` say that the lock could not be confirmed and could not be undone; they never say "locked", and never say plainly "unlocked";
    - `--require-memory-lock` / `KLAV_PROXY_REQUIRE_MEMORY_LOCK` treats this state as not locked, so with the requirement the start is fatal, as for any unconfirmed lock;
    - `init`, `serve` and `status` all follow this, and `status` has no refusal for the lock left.

    His reason is his rule that an update must not stop a proxy that runs today. That nobody has checked on which hosts this state can occur is the layer's own observation, not part of his reason. *Reworded on 2026-11-19 (fifth round): this read "His reason: an update must not stop a proxy that runs today, and nobody has checked on which hosts this state can occur."* The shape and the words are the layer's (§11, L21, L22 and L24), accepted by Omar in decisions 28 and 29; L23 he overturned (decision 26). This path has run only against the scripted calls of the layer's tests, never on a kernel.
20. **Owner's decision (2026-11-19). L19 accepted as built:** root with `CAP_SYS_RESOURCE` raises a finite `memlock` limit (§3.2's rule, "unlimited or raisable to unlimited"), and the update guide warns about memory caps (`self-hosting.md` §9.2, "Antes de actualizar un proxy que ya corre").
21. **Owner's decision (2026-11-19). L9 accepted as built:** `KLAV_PROXY_MEMORY_LOCK` takes only `on` and `off`; anything else stops the start. `KLAV_PROXY_REQUIRE_MEMORY_LOCK` keeps `1`, `true`, `0` and `false` (decision 16).
22. **Owner's decision (2026-11-19). L20 accepted as built:** `status` locks its own memory when the limit allows, and never fails for the lock.
23. **Owner's decision (2026-11-19). Accepted as a block, as built:** L10, L11 (with decision 19 for the case where the undo fails), L12, L14, L15, L16 and L17; L13's withdrawal, with only the source-order test in `main.rs` guarding the order; and the core-file test staying by hand, out of CI.
24. **Owner's decision (2026-11-19). Decision 15's words follow L15:** `status` attributes the record to the `serve` that last **started listening**, not the one that last started. He approved the change of words. *Superseded by decision 27 (2026-11-19): "that last wrote this record".*
25. **Owner's decision (2026-11-19). Two sentences of decision 11 are his:** on a kernel that refuses `MCL_ONFAULT` the proxy does not lock (it never falls back to locking every page at once), and with the requirement that is fatal.

For the record, the three sentences of decision 12 the re-review questioned (the switch shows in `status`; core dumps stay off always; the switch together with the requirement is a start-up error) were in the option Omar picked on 2026-11-19, and stay recorded as his.

### The owner's decisions on layer 1, fourth batch (2026-11-19)
After a read-only re-review of #466 at `d6debff4`, which found no defect in the lock sequence, Omar decided the following on 2026-11-19. Decisions 26–29 answer the questions on L21–L24 (§11).

26. **Owner's decision (2026-11-19). `status` says what its own process got (L23 overturned).** `klav-proxy status` writes on stderr one line about its own process's memory, labeled as this process's and not the `serve`'s, in each state: locked on fault (with `VmLck`), not locked with the reason, the lock turned off by the switch, and decision 19's words. Stdout, in text and in `--json`, stays as it is. The reason, as the question he answered put it: the update guide's dry run is `status` under the unit's or the container's own settings, and without this line it can't show whether the updated proxy will lock, which is what matters under a memory cap. That macOS prints nothing is the layer's choice (§11, L25), and so is printing it before `status` reads the registration (L26); he accepted both in decision 30.
27. **Owner's decision (2026-11-19). `status` attributes the record to "the `klav-proxy serve` that last wrote this record"** (decisions 15 and 24's words change again). It is true by construction in every case, including a `serve` that starts listening, fails to write its record (a full disk) and exits, leaving an earlier `serve`'s record. The guide says a `serve` writes its record once it is listening.
28. **Owner's decision (2026-11-19). L21 accepted as built** (`locked: false`, `why`, optional `lock_not_undone: true`, the record stays `v: 1`), with one addition: a record that says both `locked: true` and `lock_not_undone: true` is treated as decision 19's state. How it is read is the layer's, not part of his decision: `locked: false` in the text and in `status --json`, so the two agree and a reader that knows only `locked` never reads `true` for it. No `serve` writes such a record.
29. **Owner's decision (2026-11-19). L22 and L24 accepted as built:** the long words of decision 19's state in `status`, the warning and the requirement's error; and the line for a record that can't be read.
30. **Owner's decision (2026-11-19). L25 and L26 accepted as built:** on macOS `status` prints no line about its own process, and on Linux the line comes before `status` reads the registration or calls the server.

## Decision

### 1. The alarm: a proxy's key used from a new network

#### 1.1 Where the address comes from, and when the server has none
- **The value used** is the `ClientIp` the rate limiter already computed for the request (`ratelimit.rs:249-250`), from the same configured source. It is never read again from a header in another place.
- **Its network:**
  - an IPv4 address is its own network (`/32`);
  - an IPv6 address counts as its `/64`, as the rate limiter already does (`ratelimit.rs:170-183`), so privacy addresses that rotate inside one prefix don't count as new;
  - an IPv4-mapped IPv6 address counts as the IPv4 address.
- **A new setting, `agent_addresses` (`KLAV_AGENT_ADDRESSES`), off by default.** The server records, alarms and enforces pins only when it is on. Reasons:
  - the server can't tell whether its peer is the real client or an edge (point 1), so only the operator can say;
  - turning it on implicitly would make every self-hosted server behind nginx or Railway alarm on, or pin to, its own edge.
- **The operator's side.** `self-hosting.md` §3.2 and §8.1 gain the rule: turn it on only with a client-IP source you checked (`KLAV_TRUSTED_IP_HEADER` after the §8.1 test), or with the server reached directly. At start, the server logs a warning when `agent_addresses` is on and the source is the TCP peer. It still starts, because a server listening directly is a valid case.
- **With the setting off,** the address endpoints of §1.4 answer `{"source": "off"}`, and a pin is refused with `409 agent_addresses_off` (§2.3). The apps say "this server doesn't record where agents connect from, so the alarm and the pin are off", never just nothing.
- **On `api.klav.dev`:** turning it on is Omar's step, after running the `self-hosting.md` §8.1 test against production (decision 8).

#### 1.2 What the server stores
A new table, `agent_networks`, in migration `0020`, for SQLite and Postgres:

| Column | Meaning |
|---|---|
| `agent_id` | references `agents (id) ON DELETE CASCADE` |
| `account_id` | references `accounts (id) ON DELETE CASCADE` |
| `network` | text: `203.0.113.7` or `2001:db8:1:2::/64`, normalised as in §1.1 |
| `first_seen_at`, `last_seen_at` | Unix ms |
| `state` | `baseline`, `new`, `known` or `refused` (§2.3) |
| `confirmed_at`, `confirmed_by_device` | when the person said "it's mine", and from which device |
| `notified_at` | when a push or a notice went out for this row |

The primary key is `(agent_id, network)`.

- **Plain addresses, kept for a while** (decision 7). The person needs to see the address to judge it and to pin it (§2). The server already sees it on every request; what is new is keeping it.
  - A row not seen for 90 days (decision 3) is deleted by the existing purge (`crates/klav-server/src/purge.rs`).
  - Revoking or deleting the agent, or deleting the account, deletes its rows.
  - [`privacidad.md`](../privacidad.md) gains the paragraph in the server layer.
- **Writes are throttled.** The server updates `last_seen_at` at most once a minute per row, as it does `agents.last_seen_at` (`agentauth.rs:59-60`). The current network per agent is cached in memory, so a request from a known network costs no write.
- **The limit of this table, said plainly (decision 7).** It is the server's own data, unsigned. Whoever controls the server, or its database, can add a network as `known` and the alarm stays silent for it. Storing a keyed hash instead of the address would not change that. A thief who holds only the key can't write here, and on a server with a checked address source (§1.1) can't choose the address the server sees, so they get past the alarm only by leaving through a network the proxy already uses. Only the strict profile's list (§2.5) is signed by the person's devices.

#### 1.3 When a network counts as new
- **Only after the signature verifies** and the request passed the timestamp, nonce and status checks (`agentauth.rs:161-261`). A request with a bad signature never writes a row or raises an alarm. Otherwise anyone who knows an agent ID could flood the person's phone.
- **Only for proxies (decision 4).** An agent counts as a proxy when its current stored grant (`agents.grant_payload`, `0005_agentes.sql:23`) has at least one profile. How the layer caches that is its choice.
- **The first network is the baseline.** The first signed request after the server layer deploys, or after the proxy's approval, records its network as `baseline`, with no push. The apps show it ("seen from 203.0.113.7 since …"). There is one baseline per agent, ever (the server keeps that the agent had one): when a row expires after 90 days unseen, its network comes back as `new`, not as a baseline, so an emptied table never gives a thief a silent start. A key stolen before the baseline would make the thief's network the baseline. The person sees which network it is, and the pin of §2 is the answer if that matters.
- **Every later network not in the table, or past its retention, is `new`:**
  - the server records the row and raises one notice (§1.4);
  - it tags the agent's next logged event from that network with the alert `new_address`, in the same `alerts` list as `first_use` (`audit.rs:132-133`; `agent_access.rs:515-516`);
  - reads (`/v1/agent/me`, `/v1/agent/items`) are not logged, so the tag lands on the first logged call. As point 5 says, that is the first call that can read a value.
- **What the request does next depends on the proxy's network profile (decision 2, §2.5).**
  - **Alert profile, the default:** it goes on. The alarm alerts and doesn't block.
  - **Strict profile:** a network outside the signed pin is refused before anything is done (§2.3), and the person is told at once. A network inside the pin is admitted, and §2.5 says what the alarm records for it.
- **A burst of new networks.** At most 5 notices per agent per hour. After that, one notice of kind `many_networks` covers the rest of the hour, and further rows are recorded without a push. A thief rotating addresses to bury the alarm produces that notice, which is a stronger signal than any one row.

#### 1.4 What the person sees, and where
- **On the iPhone, a push of a new kind, `agent_network`:**
  - no text in the payload, as today: localisation keys, `type` and the agent's ID (the T173 rule);
  - its own budget of 6 per account per hour, apart from approvals;
  - the app fetches the details when the person opens it and shows them in the agent's sheet.
  - The words are neutral, with no name (decision 5). Alert profile: "New network for a proxy" / "One of your proxies was used from a network it hadn't used before. Open Klav to check it." Strict profile, when a call was refused: "A proxy was kept out of a new network" / "One of your proxies tried to connect from a network outside its strict profile. Open Klav to let it in or keep it out." Both are the same push kind with different localisation keys. The Spanish is written natively in the iOS layer.
- **Only to phones that said they understand it.** `PushRegistration` gains an optional `kinds: ["agent_network"]` (migration `0020` adds a nullable column to `push_tokens`). The server sends the new kind only to tokens registered with it. This is what keeps an older app from showing a bare localisation key (§9).
  - A new app talking to an older self-hosted server gets `400` for the unknown field (`deny_unknown_fields`, `auth.rs:354`). It registers again without it, and that server sends no such push anyway.
- **On the Mac,** `klavd` reads the notices with the requests it already polls. The app shows a local notification and a row in the proxy's section ("Development › Sandboxes"), so no APNs is needed.
- **In the CLI:**
  - `klav proxy networks` lists the proxy's networks with their state;
  - `klav proxy networks confirm <network>` says "it's mine";
  - `klav agent list` marks an agent with an unconfirmed new network.
- **The endpoints, with the person's session:**
  - `GET /v1/agents/{agent_id}/networks` → `{source: "off"|"on", networks: [{network, state, first_seen_at, last_seen_at, confirmed_at}]}`;
  - `POST /v1/agents/{agent_id}/networks/confirm` with `{network}` → `204`;
  - `GET /v1/agents` gains `new_networks: n` per agent. `AgentInfo` has no `deny_unknown_fields` (`crates/klav-proto/src/agent.rs:630-632`), so older clients ignore it.
- **What the person can do from the notice:**
  - "It's mine": the row becomes `known`, and confirming needs only the session (§11). **Under the strict profile this changes only what the alarm says and never lets a refused network in;** the action there is "Let it in", which signs the network into the pin with Touch ID or Face ID (§2.5);
  - "Pause this proxy": the signed pause of one agent that exists (ADR 0033 §7, spec §13.9), with presence, as today;
  - "Revoke this proxy": the existing revocation, which changes the item keys (ADR 0036 §18) and tells the person to rotate the provider's tokens;
  - "Make this proxy strict" (§2.5), with the network as the first entry.
- **Without APNs on the server,** the Mac's local notification, the iPhone app on opening and the CLI still show it. E-mail is not proposed. The roadmap lists ADR 0010's e-mail verification as unbuilt ([`roadmap.md`](../roadmap.md), Hito C), and whether `klav-server` can send mail is not checked in code.
- **The proxy itself learns what the server sees.** `GET /v1/agent/me` gains `seen_from: {network, source}`, and `klav-proxy status` prints "the Klav server sees this proxy at 203.0.113.7 (from x-real-ip)". The operator can then check it and pin it. `AgentMe` has no `deny_unknown_fields` (`agent.rs:759-761`), so older proxies ignore the field. It is informational: a lying server can print anything.

#### 1.5 Hosts whose address changes, and how noisy that is

| Host | What happens | Noise |
|---|---|---|
| Mac behind a home router (IPv4) | One alarm each time the ISP changes the public address. On IPv6, one each time the delegated prefix changes, never for privacy addresses inside the `/64` | Low: an ISP change is days to months (not checked per ISP) |
| Laptop that moves (home, office, café) | One alarm per new network, once; confirmed networks stay known for 90 days unseen (decision 3) | High the first weeks, then low. The alarm can't tell a new café from a thief |
| Dual stack | The proxy may alternate between IPv4 and IPv6: two networks, both confirmed once | One extra alarm |
| VPS rebuilt or moved | One alarm after the rebuild, which the person just did | One per rebuild |
| PaaS (Railway, Fly) egress | Egress is shared with other tenants and may change on each deploy or region (not checked per platform) | One alarm per change, and blind to anyone on the same egress (§8) |
| Behind a corporate or carrier NAT shared with others | Stable, but shared | Quiet, and blind to anyone behind the same NAT |

The alarm is a tripwire, not a guard. It catches a copy of the key used from somewhere else, which is the case the review describes. Its noise is one confirmation per new network, not per request.

### 2. The pin, which is the strict profile: the person signs where the proxy may connect from

#### 2.1 A new signed record, not a grant field
Point 3 left two ways. A grant `v: 4` would make every un-updated proxy reject its own grant and stop. A record the server enforces changes nothing for a proxy that is inside its pin. So the pin is **a new signed record, like the pause (§13.9) and the person's sandbox revocation (§13.11)**:

```
networks = sorted list of entries, each:
             0x04 ‖ address(4)  ‖ prefix(1)          (IPv4, prefix 16–32)
           | 0x06 ‖ address(16) ‖ prefix(1)          (IPv6, prefix 32–128)
message  = tuple("klav/v1/sig/agent-egress", account_id(16), agent_id(16), u64_be(at_ms), networks)
```

- **The version is the label's `v1`, as in every signed tuple of §13.** The family byte of each entry says its length.
- **Canonical, so the same set always signs the same bytes:**
  - host bits are zero;
  - entries are sorted by their bytes, with no duplicates;
  - at most 16 entries.
  - An empty list removes the pin.

  A reader rejects anything else; it never normalises.
- **Freshness, as in the pause:**
  - `at_ms` is when the person decided;
  - the server rejects `|now − at_ms| > 5 min`, and an `at_ms` not greater than the agent's last pin, with `409` and `last_at`;
  - so an old, wider pin can't be replayed.
- **Signed by the account identity,** with `sign_egress`/`verify_egress` in `klav-core::crypto::agent`. No new primitive and no new dependency: it is the Ed25519 signature the pause already uses.
- **The spec entry is §13.13**, with vectors in `docs/vectores/agent-egress.json` (layer 4). Both are written with the code, as the ADR 0043 layers do.

#### 2.2 Setting it, widening it, removing it
- **Narrowing needs no presence.** Setting the first pin, or removing a network from it, only takes access away, like revoking (ADR 0033, amendment of 2026-11-10).
- **Widening asks for Touch ID or Face ID** (on Linux, the master password, as in ADR 0041). Adding a network, keeping an entry that lapsed (§2.6) or removing the pin gives access back, and a program of the person's user must not do it through an unlocked `klavd`.
- **What the person picks from.** The app offers the networks the server saw (§1.2) and the one the proxy reports (§1.4). The default entry is the network as §1.1 computes it: `/32` for IPv4, `/64` for IPv6 (decision 9).
  - The CLI also takes ranges: `klav proxy egress pin <network>…`, `add`, `remove`, `clear`, `show`.
  - A server that lies about the address can make the person pin the wrong network. That server could ignore the pin anyway (§8).
- **The first pin of an account asks for every device to be updated** (`--every-device-is-updated` in the CLI, a confirmation sheet in the apps), as the first `klav proxy issuer add` does (spec §13.4, last bullet). The record goes into the audit log as `agent.egress_pinned`, and a `klav log verify` older than layer 4 fails on any action it doesn't know (`crates/klav-client/src/audit.rs:419-430`).
- **`PUT /v1/agents/{agent_id}/egress`** takes `{at_ms, base_at_ms, networks: ["203.0.113.7/32", …], signature}`. The server:
  1. refuses with `409` and `last_at` when `base_at_ms` is not the `at_ms` of the agent's current record (absent for the first pin), so a device never replaces a record it didn't build on (§2.6);
  2. rebuilds the bytes and verifies the signature;
  3. stores the record in `agent_egress_pins` (migration `0021`), one row per agent, deleted with it, and sets each entry's 90-day clock (§2.6);
  4. appends `agent.egress_pinned` with the signature and the fields the message is rebuilt from.

  `base_at_ms` is not signed: it is the server's compare-and-set, and a server that ignores it can only lose a change, which the device sees when it fetches the record again.

  The verifier checks the signature and that `at_ms` grows per agent, and lists the agent's current pin in its report.

#### 2.3 What the server enforces, and the errors
- **Where:** in `AgentAuth`, after the signature, the nonce and the status (`agentauth.rs:222-261`), and before the deletion and pause checks (`agentauth.rs:263-270`). It covers **every** signed agent route, including `GET /v1/agent/me`, because `me` is the route that hands out the grant and its item keys (point 5).
- **A request from outside the pin, or from an entry that lapsed (§2.6),** gets `403` with the code `agent_egress_refused` and the message "the account allows this agent only from the networks it signed; this request came from elsewhere". The message never lists the pinned networks, and doesn't say whether the network was never pinned or lapsed.
  - The request is not logged as an action: like a pause, it is refused before anything is done.
  - It writes a `refused` row and raises a notice of kind `agent_egress_refused`, under the alarm's budget. A proxy that moved outside its pin is the case the person must see at once.
- **Other errors:**
  - `409 agent_addresses_off`: the server has `agent_addresses` off, so it can't enforce a pin and refuses to store one;
  - `409` with `last_at`: an `at_ms` not newer than the last pin;
  - `400`: a network list that isn't canonical, or more than 16 entries.
- **If the operator turns `agent_addresses` off while pins exist,** the server refuses every request of a pinned agent, with `403 agent_egress_refused`, until it is turned back on or the person clears the pin. The pin fails closed, never open. The server logs that at start.

#### 2.4 The default, and what the pin means where addresses move
- **Off by default (decision 1).** Every proxy starts in the alert profile.
  - Omar's words make it optional.
  - Most of the hosts in §1.5 (a Mac at home, a laptop, a PaaS) have an egress that changes or is shared.
  - A pin on by default would cut the proxy off at the first change, through a server that may not even see addresses (§1.1).
- **The app suggests the strict profile:**
  - for a proxy seen from one network for 7 days;
  - for a VPS with a fixed address.
  - The app explains what happens when the address changes: the proxy stops, the person gets a notice, and letting the new network in asks for Touch ID or Face ID.
- **Behind a NAT shared with others,** the pin admits everyone behind that NAT. The app says so in general words when the person pins a network. It never says whether other accounts use that network: that would let anyone probe where other people's proxies run.
- **On a PaaS** the pin is usable only with a static egress address, if the platform sells one (not checked per platform). Otherwise the app recommends a VPS for the proxy.

#### 2.5 The two network profiles (decision 2)
Each proxy has one **network profile**. It is not the provider profile of ADR 0036 §2 (`--profile`), and the apps and the CLI always say "network profile" or name it ("alert", "strict").

| | Alert profile (the default) | Strict profile |
|---|---|---|
| What it is | No pin. The alarm of §1 | The signed pin of §2.1, plus the alarm |
| A call from a new network | Goes on; one notice (§1.3) | Refused with `403 agent_egress_refused` before anything is done; one notice at once (§2.3) |
| What lets a network in | Nothing needs to | Only a record signed by a device, with presence (§2.2) |
| A network unseen for 90 days (decisions 3 and 10) | Its row is deleted; the next call from it is `new` again and alarms | Its entry lapses: the next call from it is refused until the person lets it in again; a device then signs a narrower list without it (§2.6) |
| "It's mine" with the session (§1.4) | The row becomes `known` | The row becomes `known`; the network stays refused |
| Who can add to the list | Whoever controls the server (§1.2, decision 7) | Only the person's devices; the server can ignore the list but not widen it (§8) |
| Needs | `agent_addresses` on | `agent_addresses` on; layers 4–6; every device updated (§2.2) |

**How each step maps to the pin:**
- **Turning strict on is the first pin** (§2.2). It needs no presence, because it only takes access away. It carries the "every device updated" confirmation and is refused with `409 agent_addresses_off` on a server that doesn't record addresses. The app offers the networks the server saw and the one the proxy reports, the current one selected.
- **Letting a refused network in is adding it to the pin,** from the notice ("Let it in") or the proxy's sheet, with Touch ID or Face ID (on Linux, the master password). The entry is the `/32` or `/64` of decision 9. A network whose entry lapsed (§2.6) is let in the same way.
- **The device builds on the record it verified.** Before signing a wider list, it fetches the agent's current record, checks the account's signature and that its `at_ms` is not older than the last one it saw, and signs that list plus the new entry. A server that handed it a different list could otherwise get a wider one signed (T213). The person sees the full list in the confirmation sheet, not only the new entry.
- **Turning strict off is clearing the pin.** That gives access back, so it is widening and asks for presence (§2.2). The proxy returns to the alert profile, and the networks it was seen from stay in the alarm's table.
- **Removing one network** needs no presence (narrowing), unless it is the last one: an empty list clears the pin, which is widening.
- **The CLI:** `klav proxy networks strict [<network>…]` and `klav proxy networks alert` are the same records as `klav proxy egress pin` and `klav proxy egress clear`.

**What the alarm does under the strict profile:**
- **A call from inside an entry that hasn't lapsed** is admitted. Its row is recorded as `known`, with no notice and no `new_address` alert, because the person signed that network. That holds also for an address inside a wider range pinned through the CLI whose own alarm row is new.
- **A call from outside, or from a lapsed entry,** writes a `refused` row and one notice, under the alarm's budgets (§1.3, §2.3).

**Where the pin as first written differs from "refuses these changes until the person confirms":**
- **Confirming is signing, not tapping.** Under the strict profile, the session-only "It's mine" can't admit a network. Only a device with presence can. This is the coordinator's reading of decision 2, and it is what makes the strict list one the server can't widen.
- **Entries lapse after 90 days unseen, as alert networks do** (decision 10). The signed record has no per-entry date, so the lapse is the server's, and §2.6 says how it works.
- **No other difference was found.** Both refuse before anything is done, on every signed route, `me` included (§2.3); both tell the person at once.

#### 2.6 A strict network lapses after 90 days unseen (decision 10)
The record of §2.1 is unchanged: no per-entry date, so no format change (Q10 (c) was not chosen). The lapse is enforced by the server and cleaned up by the person's devices.

**The clock, on the server:**
- **Each entry of the current record has a `last_seen_at`,** in migration `0021` next to the record (one row per agent and entry). A call admitted by an entry sets it, at most once a minute, as `agents.last_seen_at` is written.
- **For a range wider than the alarm's network** (a `/24` through the CLI), the entry's clock is the latest call from any address inside it, not any one alarm row.
- **When a record is stored, an entry that was in the previous record and hadn't lapsed keeps its clock.** Every other entry, one that is new or one that had lapsed and the person let in again, starts its clock at the time the server stores the record. A network just let in has its full 90 days before its first call, and a narrowing never extends the life of the entries it keeps.
- **An entry whose clock is older than 90 days has lapsed.** The server treats a call from it as from outside the pin (§2.3), and counts as lapsed only entries of the current record.

**What the person sees:**
- **Before the lapse:** nothing is pushed. A proxy that keeps running is seen all the time, so its entries never lapse; an entry used once (a café) lapses quietly. The proxy's sheet shows "not seen for N days" for an entry unseen for 80 days or more.
- **At the lapse:** nothing either. The sheet marks the entry "Lapsed after 90 days unseen".
- **At the next call from it:** the strict profile's refusal and notice (§1.4, §2.3), with "Let it in". If the entry was the proxy's only network, the proxy is cut off until then, as at any network change under the strict profile (risk 85).

**How the list shrinks:**
- **The apps sign a narrower list without the lapsed entries,** with no presence because it only takes access away (§2.2). The first device that has the account unlocked and sees a lapsed entry does it: the Mac's `klavd` with its polling, the iOS app when opened, the CLI on `klav proxy egress show`. It is never a prompt.
- **It builds on the record it verified** (§2.5): it fetches the current record, checks the account's signature and `at_ms`, removes the entries the server reports lapsed, and sends `base_at_ms` with the record it built on (§2.2).
- **Never the empty list.** When every entry has lapsed, the device signs nothing: an empty list would clear the pin, which is widening (§2.1, §2.5). The pin stays, every call is refused, and the sheet says "every network of this proxy lapsed; let one in".
- **Two devices at once:** the second gets `409` with `last_at`, fetches the record again, and signs only if the new record still has a lapsed entry. A narrowing that would drop an entry the person just let in can't happen: that entry's record is newer, so the stale `base_at_ms` is refused.
- **Every widening drops lapsed entries too.** When the person lets a network in, the device signs the current entries that haven't lapsed plus the new one. A lapsed entry goes back in only when the person picks it; the confirmation sheet shows the full list.
- **Keeping a lapsed entry is widening,** even though the list doesn't grow. A record that still names an entry the server reports lapsed restarts its clock, so it gives access back: the device asks for Touch ID or Face ID (on Linux, the master password) before signing it, as for adding a network (§2.2). Otherwise a program behind an unlocked `klavd` could revive every lapsed entry by re-signing the same list. The unattended narrowing never keeps a lapsed entry, so it never needs presence.

**What the lapse is worth against a malicious server** (§8, T213):
- The lapse information is the server's and unsigned. A server that hides a lapse keeps admitting an entry the person signed, which is no wider than the signed list. A server that invents one makes a device narrow the list, which fails closed. Either way it can only do what it could already do by ignoring the pin.
- **The cost decision 10 accepts:** the server admits fewer networks than the signed list names, until a device narrows it, and the audit log (`agent.egress_pinned`) shows the signed list, not the shorter one in force. The narrowing that follows is its own `agent.egress_pinned`, so the log catches up.

### 3. The proxy's memory

#### 3.1 At start, before the key is loaded
`klav-proxy init` and `klav-proxy serve` call `harden_process()` first. Calling it any later would be too late: the key would already be in memory.
- **Core dumps off on every Unix:** `setrlimit(RLIMIT_CORE, 0, 0)`. Both limits go to 0, so the process can't raise them back.
- **Not dumpable on Linux:** `prctl(PR_SET_DUMPABLE, 0)` through `nix::sys::prctl::set_dumpable(false)`, as ADR 0041 §8 does for `klavd`. A process of the same user then can't `ptrace` it or read `/proc/<pid>/mem`.
  - **Two points to confirm in layer 1:**
    - whether a piped `core_pattern` (systemd-coredump, apport) still collects a dump when the limit is 0 or the flag is off. I didn't check core(5) and prctl(2) here, and the layer tests it on a Linux host;
    - whether anything the proxy reads under `/proc/self` breaks once the flag makes those files root's.
  - **Implementation note (2026-11-19, layer 1): both points checked, neither false.**
    - **The piped `core_pattern`.** The limit alone does not stop it; the flag does.
      - core(5) says `RLIMIT_CORE` "is not enforced for core dumps that are piped to a program". So for a piped pattern, `(0, 0)` alone would not stop the kernel from running the handler.
      - The kernel checks the flag first. The versions read were Linux 6.1 (a long-term release) and `master` on 2026-11-19; a container runs its host's kernel, whatever its image. In 6.1, `do_coredump` in `fs/coredump.c` returns at `if (!__get_dumpable(cprm.mm_flags)) goto fail;` before `format_corename` decides whether the pattern is a pipe, and before the pipe branch (where the source says "core limits are irrelevant to pipes"). `master` does the same in `vfs_coredump` → `coredump_skip`. So a process that is not dumpable gets no core, piped or not.
      - systemd-coredump also stores nothing for a process whose core limit is under one page (`save_external_coredump` in `src/coredump/coredump-submit.c`, "Resource limits disable core dumping"). The limit is passed to it as `%c`.
      - apport was not checked. On Linux it is covered by the flag, as above.
      - Consequence in the code: on Linux, a failed `PR_SET_DUMPABLE` is fatal, because `core_dumps: "off"` rests on it for a piped pattern. A failed `RLIMIT_CORE` is fatal on every Unix (§11).
      - "The process can't raise them back" (§3.1) holds for an unprivileged process. One running as root (`CAP_SYS_RESOURCE`) can raise any limit, and so could code that runs inside it. The flag stays off either way: only the process itself can turn it back on.
      - Checked in the kernel's and systemd's public source and in the manual page. Running it on a Linux host is the plan's test: the file case and the systemd-coredump case are ignored tests with their steps, run by hand (CI's runner pipes its cores to apport).
      - **Note (2026-11-19, second round, after the review of #466): what settled this point, said exactly.** This section said the layer would test the piped pattern on a Linux host. It was settled by reading the kernel's and systemd's source instead, as above. No piped pattern was run:
        - CI's runner pipes its cores to apport. apport was not read or run; on Linux it is covered only by the kernel's own check of the flag, read in source.
        - In CI the file-case test returns early, because the runner's pattern is a pipe, so it checked nothing there. It now prints `NOT CHECKED` when that happens. When it does run, the unhardened control must leave a core, or the test fails.
        - *Third round (2026-11-19):* a passing test's output never shows in CI, so that `NOT CHECKED` line couldn't be seen either. The file-case test is now `#[ignore]`d and fails on its precondition (a pattern that writes a file, a hard core limit above 0) when run without it; CI doesn't run it, and it stays by hand. It ran and passed in a Linux container (Linux 7.0, pattern `core`, uid 1000), which is not a host.
        - The systemd-coredump test is still by hand and was not run. The roadmap lists both as not run.
    - **`/proc/self`.** Nothing the proxy reads breaks.
      - proc_pid(5): a non-dumpable process's `/proc/<pid>` files become `root:root`.
      - Linux 6.1 `fs/proc/base.c`: `status`, `maps`, `cgroup` and `mountinfo` are `S_IRUGO`, so they stay readable. `exe`, `fd` and `maps` allow the process itself (`same_thread_group` in `kernel/ptrace.c` and `fs/proc/fd.c`). `environ`, `auxv` and `mem` are `S_IRUSR` and stop being readable by the process itself.
      - Nothing in `klav-proxy`'s Linux dependency tree reads them. A grep of every crate's Rust source in `cargo tree -p klav-proxy --target x86_64-unknown-linux-gnu` found no `/proc/` path. `aws-lc-sys` reads `/proc/self/auxv` only when the libc lacks `getauxval`, and glibc has had it since 2.16.
      - Rust's standard library was not grepped: its source wasn't installed on the machine that wrote this. What it is known to read (`/proc/self/cgroup` and `mountinfo` for `available_parallelism`, the `exe` link, and glibc's `/proc/self/maps` for the main thread's stack) is in the readable list. The layer's Linux test reads those, lists `fd` and starts a thread after hardening, in CI.
- **Memory locked:** see §3.2.
- **On macOS,** only the core limit. macOS encrypts swap (ADR 0013 §9), and whether `mlockall` works there is not checked. On a Mac, `--store keychain` keeps the key out of a file.
  - **Implementation note (2026-11-19, layer 1): checked, `mlockall` does not work on macOS, which is what this design assumed.**
    - In Apple's open-source XNU, `mlockall` and `munlockall` in `bsd/kern/kern_mman.c` only `return ENOSYS`. The layer's test confirmed it on this Mac: a child process calls `mlockall(MCL_CURRENT | MCL_FUTURE)` and gets `ENOSYS`.
    - `nix` 0.31.3 doesn't even define `RLIMIT_MEMLOCK` on macOS, only on Linux and the BSDs (`src/sys/resource.rs:87-90`).
    - So the proxy doesn't try to lock outside Linux. `status` says `locked: false` with that reason, and `--require-memory-lock` always refuses to start on a Mac.
- **What `klav-proxy status` reports:** `memory: {core_dumps: "off", dumpable: false, locked: true|false, why}`, so the operator sees what took effect. Older `status --json` readers are only the CLI and tests (not checked beyond `klav-proxy`).
  - **Amendment (2026-11-19, decisions 11, 12 and 15):** `memory` also carries `vm_lck_kib` (the `VmLck` read back after the lock) and `lock_turned_off: true` when the switch turned the lock off. `locked` is `true` only when `mlockall` succeeded **and** `VmLck` read back more than 0 (§11, L11). The record is read with the sandbox store's checks and shown as what the `serve` that last wrote it recorded (§11, L15–L16; decisions 24 and 27). *Amended on 2026-11-19 (decision 19):* the report and the record also carry `lock_not_undone: true` when a lock could be neither read back nor undone (§11, L21). *Amended on 2026-11-19 (decisions 26 and 28):* a record that says both `locked: true` and `lock_not_undone: true` is read with `locked: false`; and `status` also writes one stderr line about its own process's memory (Linux only, §11 L25), which stdout never carries.
  - **Implementation note (2026-11-19, layer 1):**
    - `memory` is what the `serve` that last wrote the record turned on; a `serve` writes it to `<home>/agents/<name>.memory` (0600, `v: 1`) once bound, with `since`. It is not the `status` process's own (§11). *Reworded on 2026-11-19 (decision 27): this said "what the last `serve` turned on".*
    - `memory` is absent until a `serve` has written a record, and `memory_error` says why a record can't be read. *Reworded on 2026-11-19 (decision 27): this said "until a `serve` has started".*
    - `dumpable` is `null` where the system has no such flag (macOS), and `why` is present only when `locked` is `false`.
    - Readers checked: no program in the repository reads `klav-proxy status --json`. `klav proxy status` is the person's CLI command, not this one, and the Mac app doesn't run `klav-proxy`. The tests call `app::status` in their process, and the field is new and optional.

#### 3.2 Locking memory, and what happens when the host refuses
- **`mlockall(MCL_CURRENT | MCL_FUTURE)` keeps every page the proxy has, and will have, out of swap,** including the heap where values, header copies and the redactor live. Per-buffer `mlock` would need `unsafe` (point 4).
  - **Amendment (2026-11-19, decision 11): `mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)`.** The two flags above make every mapping resident when it is created, so the lock populated the binary, its libraries and each thread's whole stack. That is one runtime worker per CPU, plus tokio's blocking pool (up to 512 threads, used by every DNS lookup). Under a cgroup or container memory cap, the kernel kills such a process.
    - **mlockall(2) (man7.org, read on 2026-11-19).** `MCL_ONFAULT` exists "since Linux 4.4" and "must be used with either `MCL_CURRENT` or `MCL_FUTURE` or both":
      - with `MCL_CURRENT`, "all present pages are locked, but `mlockall()` will not fault in non-present pages";
      - with `MCL_FUTURE`, future mappings "will be marked to lock pages when they are faulted in, but they will not be populated by the lock when the mapping is created";
      - unknown flags get `EINVAL`, so an older kernel refuses the call. The proxy then starts unlocked with that reason (fatal with the requirement) and never retries without the flag.
    - **`nix` 0.31.3** names only `MCL_CURRENT` and `MCL_FUTURE` (`src/sys/mman.rs:362-368`). Its safe `mlockall` passes `flags.bits()` to libc unchanged (`:404-406`). The proxy adds the third flag with `MlockAllFlags::from_bits_retain(nix::libc::MCL_ONFAULT)`: no `unsafe` and no new crate. `libc` 0.2.191 defines the constant for each Linux target, and it isn't always 4 (`0x8000` on PowerPC).
    - **Measured on Linux 7.0 (Docker Desktop's VM; a probe with `nix` and the same flags; not a CI run):**
      - 64 threads with 2 MiB stacks made 140 MiB resident under the old flags and under 1 MiB under the new ones.
      - With the new flags, the locked resident pages (`Locked` in `/proc/self/smaps_rollup`) followed `VmRSS`.
      - `VmLck` counted the full size of the marked mappings (4.3 GB with those threads alive), not what is resident.
      - A 64 KiB limit still got `ENOMEM`: the limit counts the marked size.
    - So the finite-limit rule below stands unchanged, and "locked" at start means "every mapping marked to lock on fault, and the pages touched so far locked". It is read back as `VmLck` more than 0 (§11, L11).
    - **Note (2026-11-19, third round): a locked proxy under requests, measured.** This is the one place that lists the readings; `self-hosting.md` §9.2, the tests and the pull request point here. Two tests, both with 64 runtime workers and the pinned toolchain's **debug** build:
      - the real binary, locked, after one request its access step refused (`tests/memory.rs`). The bound it enforces: under 64 MiB resident;
      - the library's test binary as a locked proxy, after 200 requests through a profile to a local fake upstream (16 at a time, each one building the header, resolving through the system resolver on tokio's blocking pool, opening a TLS connection and redacting the echoed value; `locked_e2e_tests.rs`). The bounds it enforces, fixed before the first run: under 64 MiB resident after the burst, and under 32 MiB of growth during it. Without `MCL_ONFAULT` the same test read 200,212 kB and failed.

      The readings vary by host and build: from about 5 MB to about 21 MB after one request, and about 27 to 34 MB after the burst. The readings recorded, in `VmRSS`; the rows marked CI are CI's `test` task on the runner, and the others are local runs in a Linux container (Linux 7.0, Docker Desktop's VM, arm64):

      | Where | One request | Burst, before → after |
      |---|---|---|
      | Local container, second-round run | 5,028 kB | 20,692 → 29,448 kB |
      | Local container, on `53cb1061` | 5,080 kB | 20,720 → 29,012 kB |
      | CI, on `53cb1061` | 20,780 kB | 24,976 → 33,592 kB |
      | Local container, fourth round's final crate tree | 5,112 kB | 20,820 → 28,580 kB |
      | CI, run 44594791391, on `731e2d6f` | 20,752 kB | 24,980 → 33,984 kB |
      | CI, run 44597426157, on `d6debff4` | 20,736 kB | 25,152 → 33,636 kB |
      | Local container, fifth round, on `af069cd6` | 5,096 kB | 20,760 → 27,384 kB |

      Not measured: the release binary's resident memory under requests or under a memory cap, real providers, real name resolution of a provider's name (the test resolves `localhost` for the fixture's `upstream.test`), and a host under real load over time. CI's `test` task runs both tests with a raised limit. CI's `docker` task starts the release image locked under `--memory 64m` with `TOKIO_WORKER_THREADS=64`: it gets past the lock and stops because it has no registration there (it isn't paired), so it shows that a locked start fit under the cap, not that the image answers under it. *Corrected on 2026-11-19 (fifth round): this said "with 64 workers". The log shows only the variable passed, and `VmLck` reads the same with or without it, so the case doesn't show how many workers the runtime started.*
- **The catch: `MCL_FUTURE` counts every later allocation against `RLIMIT_MEMLOCK`.** With a finite limit, a later allocation can fail with `ENOMEM` and crash the proxy mid-request. Containers often run with a small limit (not checked per platform). So the rule:
  - **Limit unlimited, or raisable to unlimited** (root or `CAP_IPC_LOCK`): lock both and report `locked: true`.
    - **Implementation note (2026-11-19, layer 1):** the layer locks when `getrlimit(RLIMIT_MEMLOCK)` is unlimited, or when `setrlimit` to unlimited (soft and hard) succeeds.
      - The gloss is not exact. Raising a finite hard limit takes root or `CAP_SYS_RESOURCE`. `CAP_IPC_LOCK` does not raise the limit; it makes the kernel ignore it for `mlock`.
      - So a process with `CAP_IPC_LOCK` and a finite limit starts unlocked under this rule (§11, question L3).
      - A soft limit under an unlimited hard one is raised without privilege.
      - **Correction (2026-11-19, decision 13):** this note used to say the layer applies the rule "as written", which is wrong. The gloss names `CAP_IPC_LOCK`, so the rule as written would lock with it. Leaving it out was the layer's choice, L3, and Omar confirmed it on 2026-11-19: only the limit decides.
      - **What root does (2026-11-19):** a proxy running as root with `CAP_SYS_RESOURCE` raises a finite limit, including one an operator set on purpose. That follows from this section's accepted rule, "limit unlimited, or raisable to unlimited"; decision 13 is about `CAP_IPC_LOCK` and doesn't decide it. Keeping it is the layer's choice (§11, L19). The answer for such an operator is the off switch (decision 12) and the docs. Root in a default container has no `CAP_SYS_RESOURCE` and doesn't raise it. CI's `docker` task runs this case (root with `CAP_SYS_RESOURCE` and a 64 KiB limit: raised and locked) since the third round.
      - **A limit the proxy raised is put back if the lock then fails** (§11, L12), and read again: the reason says what it reads.
      - **A lock that took but doesn't read back is undone first** (§11, L11): `munlockall`, then the limit goes back. Putting a finite limit back under `MCL_FUTURE` is the state this section rules out. If `munlockall` fails, the proxy starts with the lock unconfirmed and not undone, a raised limit stays raised, and it says so (decision 19, which overturned L18).
      - **Note (2026-11-19, third round): the raise, run.** Until this round every locked run started with a limit already unlimited. CI's `docker` task now starts the real image with a 64 KiB soft limit under an unlimited hard one, with every capability dropped: it locks, and `VmLck` reads back more than 64 KiB, which the kernel allows `mlockall(MCL_CURRENT)` only after the raise. The reverse runs too: a seccomp profile answers `mlockall` with `EPERM` after the raise, and the reason reads the limit back at 64 KiB, hard unlimited. Rehearsed on a local image of the debug binary on Linux 7.0 (Docker Desktop's VM); CI's run of the release image is the first on a runner's kernel.
  - **Otherwise: don't lock (decision 6).** The proxy starts, logs a warning naming the limit and how to raise it, and reports `locked: false` with the reason. `--require-memory-lock` (and `KLAV_PROXY_REQUIRE_MEMORY_LOCK=1`) makes this fatal for an operator who wants it. Refusing to start by default would break proxies that run today on hosts that don't allow it.
  - **Amendment (2026-11-19, decision 12): the off switch.** `--no-memory-lock` or `KLAV_PROXY_MEMORY_LOCK=off` skips the lock and the raise of the limit, logs no warning, and `status` says the lock is turned off. Core dumps stay off and the process stays not dumpable. With the requirement it is a start-up error.
- **Deploy files and docs** gain the settings (layer 1):
  - the systemd unit with `LimitMEMLOCK=infinity` and `LimitCORE=0`;
  - Docker Compose with `ulimits: {memlock: -1, core: 0}`;
  - in `deploy/proxy/Dockerfile`, a comment saying the image can't set them and the runtime must.
  - Railway: not checked whether a service can raise its memlock limit. The docs say what `status` will show there.
  - **Note (2026-11-19, second round):**
    - The documented `init` commands now run with the same limits as the service: `--ulimit memlock=-1:-1` with `docker run`, the service's `ulimits` with `docker compose run`, and `systemd-run -p LimitMEMLOCK=infinity` instead of `sudo -u`.
    - On a rootless engine, `--ulimit memlock=-1:-1` may not be granted and the container doesn't start. `self-hosting.md` §9.2 says what that looks like and that the proxy still starts, unlocked, without the ulimit.
    - The unit's empty `CapabilityBoundingSet` keeps a `--channel` port under 1024 from binding; the unit says so.

#### 3.3 Fewer copies of a value
- **The header value:** build it from a buffer that zeroes itself when the last reference drops, through `Bytes::from_owner` (`bytes` 1.12.1 is in `Cargo.lock`) and `HeaderValue::from_maybe_shared`, in place of `from_bytes`'s plain copy (`profiles.rs:187`).
  - **To confirm in layer 1:** that `http` 1.5.0 keeps the shared buffer instead of copying it.
  - **Implementation note (2026-11-19, layer 1): checked, true.**
    - In `http` 1.5.0's source, `HeaderValue::from_maybe_shared` downcasts a `Bytes` (`if_downcast_into!`, `src/convert.rs`) and hands it to `from_shared`. That validates the bytes and stores the same `Bytes` as the value's `inner`, with no copy (`src/header/value.rs:159-166`, `:208-231`).
    - `bytes` 1.12.1's `Bytes::from_owner` keeps the owner behind a reference count and drops it with the last clone (`owned_drop_impl`, `src/bytes.rs`).
    - The layer's test checks it in the build: the header's bytes are at the owner's address, a clone shares them, and the owner drops only with the last clone. The owner is a plain `Vec<u8>`, sized once (its capacity is its length), in a type of its own, `HeaderBytes`, whose `Drop` zeroes every byte in place with `zeroize`'s volatile writes before the buffer is freed. It has no `Debug` or `Display`.
    - *Corrected on 2026-11-19, third round:* this note said the owner "is a `Zeroizing<Vec<u8>>`". It was until commit `f5d1157d` of the second round, which made the zeroing the buffer's own `Drop`: inside `Zeroizing`, the wipe ran after the owner's `Drop`, so the test couldn't see it, and `Zeroizing<Vec>` also empties the vector. Now the test goes through `Profile::credential` and sees the buffer drop with every byte zero, at the length and capacity it was built with.
    - What stays is as this section says: `hyper`'s write buffer and `rustls`'s plaintext buffer.
  - **What stays and is said plainly:** copies inside `hyper`'s write buffer and `rustls`'s plaintext buffer, which the proxy doesn't own. With §3.2 they stay out of swap, and with §3.1 out of dumps; they are not zeroed.
- **The redactor's copy** stays `Zeroizing` and lives until the answer ends: at most `DEFAULT_REQUEST_TIMEOUT`, 120 s, or for a stream (`text/event-stream`) at most `STREAM_MAX`, 15 minutes, and never past its sandbox (`proxy.rs`; ADR 0036 §7, note of 2026-11-19; corrected on 2026-11-25 when step M3 was built). Shortening that is the redactor's design (ADR 0036 E9), not this ADR's.

#### 3.4 The key file
- **Unchanged:** 0600 and checked at start (`app.rs:93-142`). On a Mac, `--store keychain` is the alternative to the file.
- **Recommended in the deploy docs, not enforced:** the data volume on an encrypted disk. Most VPS providers and PaaS volumes don't let the proxy check it (not checked).
- §10 says why the file isn't encrypted by Klav.

#### 3.5 Dependencies

| Layer | Crate | `nix` features today | Adds | For | Approval |
|---|---|---|---|---|---|
| 1 | `klav-proxy` | `user` | `resource`, `mman`, `process` (none brings in a crate) | `setrlimit`, `mlockall`, `set_dumpable` | No new crate; accepted with this ADR, as ADR 0041 §9 listed `process` for `klavd` |

No new cryptographic dependency. The pin's signature is Ed25519 in `klav-core`, as the pause's.

### 4. Audit events

| Event | Who writes it | Older verifiers |
|---|---|---|
| Alert `new_address` in `alerts` of the agent's next logged event from a new network | Server | Unaffected: alerts are server-written tags, not in the action table. An older iOS app shows the tag's raw name (`ActivityWords.swift:120`) |
| Alert `outside_egress` | Never: a refused request isn't logged (§2.3) | — |
| `agent.egress_pinned` with the account's signature, `decided_at` = `at_ms` and the networks | Server, from a device's signed record | An older `klav log verify` fails on it ("unknown action"); hence §2.2's "every device updated" |
| Confirming a network | Not logged: it changes only what the alarm says, not what an agent can do (§11) | — |

### 5. Proxies whose address changes: summary
- **The alert profile (the default):** one notice per new network, never per request. Baseline without a push. Networks known for 90 days unseen.
- **The strict profile (the pin):** off by default and suggested. A new address cuts the proxy until the person lets it in with presence, and the person is told at once. A pinned network unseen for 90 days lapses, and the devices drop it from the list.
- **IPv6 privacy addresses** never trigger either, because the network is the `/64`.

### 6. Safe with older clients
Every layer touches `crates/`, so every merge redeploys the production `klav-server`. Layers 2 and 5 are the ones that change what the server does and add migrations, and each needs the "safe with older clients" review before merging. Layer 4 changes `klav-core` and the verifier, which the server links but doesn't call for this, so its review asks only that the server's behaviour is unchanged. What each un-updated program sees:

| Program | After layer 2 (alarm) | After layer 5 (pin) |
|---|---|---|
| iOS app | No new push: the kind goes only to tokens registered with `kinds`. `GET /v1/agents` has a field it ignores. Activity may show a raw `new_address` tag | Nothing until the person pins a proxy. Then its verifier fails on `agent.egress_pinned` until it updates, which is why the first pin asks for every device to be updated |
| Mac app and `klavd` | Nothing new, and nothing fails | Same as iOS |
| CLI | Nothing new; `klav log verify` passes, because alerts aren't checked | Same as iOS for `klav log verify` |
| `klav-proxy` | `GET /v1/agent/me` has a field it ignores (`AgentMe` without `deny_unknown_fields`) | Nothing while it connects from inside its pin. From outside: a `403` whose code it doesn't know reads as a plain refusal (`crates/klav-client/src/api.rs:291-292`; `crates/klav-sdk/src/session.rs:1367-1380`). The grant refresh logs a warning and keeps the grant it has (`crates/klav-proxy/src/app.rs:405-415`), the issuer list keeps its last value (`proxy.rs:691-693`), and each call answers `server_denied` (`proxy.rs:1007-1009`). It ends no sandbox for it. Not checked: the sweep's handling of every refused route |
| `klav-forward` | Untouched | Sees the proxy's existing refusal codes |
| Self-hosted server not updated, with a new app | The app's `kinds` gets `400`; the app registers again without it (§1.4) | Pinning gets `404`; the app says the server is too old |
| A server rolled back after the migration | The new tables and the nullable column are ignored | Pins are not enforced: fails open, like any server that doesn't enforce (§8) |

With `agent_addresses` off, the default, layer 2 changes no answer except the new fields. Nothing any program does today starts failing.

### 7. Order
1. **The memory first (layer 1).** It needs no server, protects every proxy at once and can ship alone.
2. **Then the alarm (layers 2–3).**
3. **Then the pin (layers 4–6).** It reuses the alarm's address source and tables.

### 8. What this does not stop
- **An attacker inside the proxy's host.** They use the key from the proxy's own address: no alarm, and the pin admits them. With root, they read the proxy's memory despite §3, and the key file in any case. This is ADR 0036 §11 and residual risk 53, unchanged.
- **A malicious Klav server.** The alarm and the pin are both decided by the server: it can hide a new address, invent one, or ignore the pin.
  - ADR 0036 treats the server as the second barrier, and so does this ADR.
  - A malicious server with a copy of the key needs no new network, because it already holds every sealed item. It still can't open them without the key.
  - The pin's signature protects only against a server that **changes** the pin it shows the person; the audit log keeps the signed record.
  - **Under the alert profile, whoever controls the server can add a network to the alarm's list** and silence the alarm for it, in clear or hashed (decision 7, §1.2). Only the strict profile's list is the person's.
  - **Under the strict profile, the 90-day lapse is the server's** (§2.6). A server can hide a lapse and keep admitting a network the person signed, or invent one and make a device narrow the list. Neither admits a network outside the signed list.
- **An attacker who shares the proxy's egress address:** another tenant of the same PaaS egress, the same carrier NAT or the same office. They get no alarm, and the pin admits them.
- **A forged client address.** On a server whose address source can be forged (point 1), both measures are worth what that source is worth. The operator is told so when turning them on.
- **The agent key in `KLAV_AGENT_KEY` on a PaaS.**
  - The proxy refuses it (`app.rs:78-84`).
  - Other agents, through the SDK, accept it (`keystore.rs:113`). For them, only the alarm could help, and decision 4 leaves them out for now.
  - On a PaaS whose staff and API can read environment variables (ADR 0038's October 2026 incidents), the variable is a copy of the key, and the PaaS's shared egress makes the pin mostly unusable there.
- **A theft that is used once, fast.** The alarm tells the person after the first call from the new network. By then that call has read a value, and the person must still revoke the proxy, which changes the item keys, and rotate the provider's token. Only the strict profile prevents the first call.
- **The key at rest is still plaintext** (§10).

### 9. Threats
New rows go in the threat model's new §5.21 and new residual risks, marked "aceptado, pendiente de implementar (ADR 0044)":
- **T210:** a copy of the proxy's key used from another network;
- **T211:** an alarm flood from a thief rotating addresses;
- **T212:** a forged client address defeats the alarm or the pin;
- **T213:** a pin silently dropped or widened by the server, including by handing a device a different list to extend;
- **T214:** the proxy's memory in swap or in a core dump;
- **T215:** the server stores agents' addresses (privacy);
- **T216:** under the strict profile, a network let in without the person's device (the session's "It's mine", or the server);
- **risks 81–86:** 85 is the strict profile's cost (the proxy stops at every network change until someone with a device answers); 86 is the alarm's list, which the server controls (decision 7).

T23 and T33 gain dated notes, and risks 52 and 53 gain one each.

**Numbering.** `main` ends at T204 and risk 79 (ADR 0041). Open PR #445 (ADR 0043) uses T205–T209 and risks 79–80, and its 79 collides with `main`'s. This ADR starts at T210 and risk 81 to stay clear of both.

### 10. Rejected alternatives
- **Encrypting the key file under a passphrase.** The proxy runs unattended and restarts on its own (systemd, the PaaS, a reboot), and nobody is there to type it.
  - A passphrase stored next to the file, or in a platform variable, protects nothing.
  - One typed at each start turns every restart into an outage until the person is back.
- **A hardware-bound key: TPM 2.0 or a cloud KMS.**
  - It needs a new dependency (TSS or a KMS SDK) and an ADR.
  - Most hosts where the proxy runs offer neither: a Mac (the Secure Enclave holds P-256 only), a Railway or Fly service, most small VPS plans.
  - The proxy's key is Ed25519 and X25519. Whether a given TPM or KMS can sign Ed25519 and open X25519 is not checked. Where one can't, the identity, the pin in the forwarder and the item-key wrapping would all have to change.
- **Splitting the key with a second host** (threshold signing, or a second host that releases the key). It needs either a threshold protocol, which is home-made cryptography or a new dependency, or a second always-on host that releases the key to whoever asks with the first half, and a thief with the first half asks the same way. It doubles the hosts that must be up for the proxy to work.
- **The server keeps the key encrypted and releases it per session.** The proxy needs a credential to get it, which is a key at rest again.
- **A new audit action for each new network.** Every un-updated `klav log verify` would fail on accounts whose proxy simply moved (`audit.rs:419-430`). The alert tag and the notice table carry the same information without that.
- **The pin as a grant field (`v: 4`).** It would stop every un-updated proxy and reject its grant in older apps and `klavd` (point 3).
- **Pin on by default.** See §2.4.
- **Geolocating addresses ("used from another country").** It needs an outside service or a database, and sends agents' addresses to it.

### 11. What this ADR chose on its own (Omar can overturn each)
Omar answered Q1–Q10, not these.
- **The first network is a baseline without a push** (§1.3). Pushing it would alarm on every proxy the day the layer deploys.
- **Confirming a network needs only the session, unsigned and unlogged.** It changes what the alarm says, not what the proxy can do. A malicious server could hide alarms anyway.
- **The pin's refusals are not logged as audit actions** (§2.3), like a pause's refusals. The notice table carries them.
- **`agent_addresses` is off by default, and a pin on a server that turned it off fails closed** (§1.1, §2.3).
- **The proxy is shown what the server sees** (`seen_from`, §1.4).
- **Budgets:** 5 notices per agent per hour, then one `many_networks`; 6 pushes per account per hour.
- **The pin's limits:** at most 16 networks; IPv4 prefixes from `/16` to `/32`, IPv6 from `/32` to `/128` (§2.1).
- **No hint about other accounts:** the pin's shared-network warning is general, never "other accounts use this network" (§2.4).
- **`first_use` and `burst` stay off for the `proxy` permission.** At 60 calls a minute per sandbox (`proxy.rs:52`), `burst` (20 a minute, `audit.rs:30`) would fire all day.
- **The strict profile's details** (§2.5): a call from inside an entry that hasn't lapsed is silent, also for a range pinned through the CLI; the refusal uses the alarm's push kind with its own words; turning strict off returns the proxy to the alert profile with its alarm rows kept.
- **Layer 1's own choices** (2026-11-19, the implementation; questions L1–L8 in the layer's pull request). **Answered by Omar on 2026-11-19:** L1, L2, L3, L4, L5, L6, L7 and L8 confirmed (decisions 13–18). Of L4, Omar confirmed that `status` hardens itself and refuses when core dumps can't be turned off; "the lock when allowed" in `status` was not his, and is L20 now. It also follows the off switch (L10).
  - **L1. `status.memory` is the last `serve`'s,** read from the record it writes when bound (§3.1 note). Neither the `status` process's own, which another process's limits could make different, nor a question to the running `serve`.
  - **L2. Failing to turn core dumps off, or on Linux to make the process not dumpable, stops the start,** for `init`, `serve` and `status`, with or without `--require-memory-lock`. `core_dumps: "off"` would be false otherwise (§3.1 note on the piped `core_pattern`).
    - *Note (2026-11-19, fourth round):* the stop comes "with a message that says what failed" (decision 14) only when the call fails with an error. Under a systemd `SystemCallFilter=` without `SystemCallErrorNumber=`, or a seccomp profile whose action kills, a call outside the filter ends the process with `SIGSYS` before it logs anything, and a service with a restart policy loops. `self-hosting.md` §9.2 says so and gives a dry run under the unit's or the container's own settings. Decision 14's text is unchanged.
  - **L3. The lock rule leaves `CAP_IPC_LOCK` out: only the limit decides** (§3.2 note). This is not §3.2's gloss as written, which names the capability (decision 13). A host gives the proxy an unlimited limit with `LimitMEMLOCK=infinity` or `--ulimit memlock=-1:-1`. *Corrected on 2026-11-19 (fourth round): this used to say "applied as written", which decision 13 contradicts.*
  - **L4. `status` hardens itself too** (core dumps off, not dumpable), because it loads the key to sign its request, and refuses when that fails. It never fails for the lock (decisions 19 and 22), and `--require-memory-lock` is an option of `init` and `serve` only.
  - **L5. `KLAV_PROXY_REQUIRE_MEMORY_LOCK` takes `1` or `true`, and `0` or `false`.** Any other value stops `init` and `serve` instead of being guessed.
  - **L6. `dumpable` is `null` where the system has no such flag** (macOS), not `false`.
  - **L7. `memory` also carries `since`,** when that `serve` wrote the record, once listening, and `why` is left out when `locked` is `true`. *Reworded on 2026-11-19 (decision 27): this said "when that `serve` started"; the code has always written the instant it writes the record.*
  - **L8. No warning on macOS,** where nothing can be locked: `status` says why, and `--require-memory-lock` still refuses. A warning on every start of every Mac proxy would teach operators to ignore the one that matters on Linux.
- **Layer 1's own choices of its second round** (2026-11-19, after the review of #466 and decisions 11–18). **Answered by Omar on 2026-11-19 (third batch):** L9 accepted (decision 21); L10, L11, L12, L14, L15, L16, L17 and L13's withdrawal accepted (decision 23).
  - **L9. `KLAV_PROXY_MEMORY_LOCK` takes only `on` and `off`.** Anything else, `0`, `false` and `OFF` included, stops the start instead of being guessed. Omar decided that the switch exists, shows in `status` and is an error with the requirement (decision 12); its values are this choice, by analogy with decision 16.
  - **L10. The switch reaches `status`; the requirement doesn't.** `status` also loads the key and locks its own memory (L20), so `KLAV_PROXY_MEMORY_LOCK=off` turns that lock off too, and a value it doesn't take stops `status` as well. `status` never reads `KLAV_PROXY_REQUIRE_MEMORY_LOCK`, so the two together aren't an error there. `--no-memory-lock` and `--require-memory-lock` are options of `init` and `serve` only; before the subcommand or on `status`, the parser refuses them (exit 2), and together it refuses them too.
  - **L11. `locked` is read back.** It is `true` only when `mlockall` succeeded and `VmLck` in `/proc/self/status` reads more than 0 right after. A success that reads back 0, or can't be read, is undone with `munlockall` before a raised limit is put back, and reported as `locked: false` with that reason, which stops a start that requires the lock. When `munlockall` fails, decision 19 applies (L21). *Amended on 2026-11-19, third round:* this used to say "the memory may still be locked then; the report fails closed". It was worse: the lock stayed on under the finite limit put back, the state §3.2 rules out, or on while `status` warned that values may reach swap. Under lock on fault, `VmLck` is the size of the marked mappings, not the resident pages (§3.2 amendment).
  - **L12. A limit the proxy raised to unlimited is put back** when `mlockall` then fails, or once a lock that doesn't read back is undone (L11), never before; the limit is then read again, and the reason says what it reads. A failed lock leaves the limit as the host set it.
  - ~~**L13. The hardening refuses to run once a second thread exists**~~ **Withdrawn on 2026-11-19 (third round, after the re-review of #466).** It refused every subcommand when a second thread ran before the hardening: a preloaded library's thread, or the helper thread of a user-mode emulator running the image on a foreign architecture, would stop a working proxy. The hardening is fully effective there: the core limit, the dumpable flag and `mlockall` apply to the whole process. The order is now guarded by a test (`main.rs`'s `main_hardens_before_the_runtime_and_the_key`, run in CI), and no build refuses to start for threads.
  - **L14. No warning when the lock is turned off.** The memory line logs `lock_turned_off`, and `status` says it.
  - **L15. The record lives only while its `serve` does.** *Amended on 2026-11-19, third round:* a `serve` replaces the record only once it listens (an atomic rename); one that fails before it listens leaves an existing record as it is, since it may be a running `serve`'s. Until this round `serve` removed any record before it started, so a second `serve` on the same home that failed on a taken port erased the running proxy's record. When `serve` stops on a signal or an error, it removes the record only if it is still its own, byte for byte. With no record, `status` says only that there is no record from a `serve` on this home, never that none runs. The honest limits stay:
    - a `serve` killed with `SIGKILL` leaves its record, which is why `status` says it can't tell whether that proxy still runs;
    - two `serve`s on one home (different ports) both run, and the record is the one written last (decision 27); when its writer stops, its record goes, and the other runs with none.
  - **L16. `status` reads the record as the sandbox store is read:**
    - a regular file of its own user, mode 0600, in a directory only its owner can write;
    - opened without following a link and without blocking, then checked again once open;
    - at most 4096 bytes.
    
    Every string from it is filtered of hidden characters before it reaches the terminal, and a `since` that isn't a sane past instant is said as such, without overflow.
  - **L17. `vm_lck_kib` and `lock_turned_off` are new optional fields** of the report and the record. The record stays `v: 1`, and a first-round record still reads.
- **Layer 1's own choices of its third round** (2026-11-19, after the re-review of #466). **Answered by Omar on 2026-11-19 (third batch):** L18 overturned (decision 19), L19 accepted (decision 20), L20 accepted (decision 22).
  - ~~**L18. A lock that took, doesn't read back and can't be undone stops the start.**~~ **Overturned by Omar on 2026-11-19 (decision 19).** It stopped `init`, `serve` and `status` when `munlockall` failed after a lock that didn't read back. Omar's reason is his rule that an update must not stop a proxy that runs today; that nobody checked on which hosts that state can occur is the layer's own observation. Since decision 19 the proxy starts and says so (L21, L22, L24).
  - **L19. Root with `CAP_SYS_RESOURCE` raises a finite limit, including one an operator set on purpose** (§3.2, "What root does"), as §3.2's accepted rule reads. The off switch is the answer for such an operator.
  - **L20. `status` locks its own memory when the limit allows,** as `init` and `serve` do, because it loads the key; it never fails for the lock (decision 19), and the off switch reaches it (L10). As root on a host, it may raise the limit to do so (L19).
- **Layer 1's own choices of its fourth round** (2026-11-19, building decisions 19 and 24). **Answered by Omar on 2026-11-19 (fourth batch):** L21 accepted with one addition (decision 28), L22 and L24 accepted (decision 29), L23 overturned (decision 26).
  - **L21. The shape of decision 19's state:** `locked: false`, `why` and one new optional field, `lock_not_undone: true`, in the report and the record. Left out when `false`, so by L17 the record stays `v: 1`, and a record without it still reads. `vm_lck_kib` carries what `VmLck` read, if anything. `locked` stays `false` so that every reader that knows only `locked` treats the state as not locked, as the requirement does; `why` alone is true without the new field: "mlockall returned success but VmLck … reads 0 kB (or could not be read back), and munlockall then failed (…): the lock could not be confirmed and could not be undone, so the memory stays marked to lock, unconfirmed", plus, when the proxy raised the limit, "and the memlock limit it raised to unlimited stays raised, since a finite limit under the lock could make a later allocation fail", and what to check.
  - **L22. Decision 19's words:**
    - `status`: `… core dumps off, not dumpable, lock could not be confirmed and could not be undone: <why>.`;
    - the start's warning (stderr for `init`, a `WARN` for `serve`): `klav-proxy could not confirm its memory lock and could not undo it, so it can't say whether the values it handles stay out of swap: <why>`;
    - with the requirement: `the memory lock could not be confirmed, nor undone, and the lock is required (--require-memory-lock or KLAV_PROXY_REQUIRE_MEMORY_LOCK=1): <why>`;
    - the `klav-proxy memory` log line carries `lock_not_undone`, after `vm_lck_kib`, on every start.

    None of them says "locked", "not locked" or "unlocked".
  - ~~**L23. `status` says nothing about its own process's lock,**~~ **Overturned by Omar on 2026-11-19 (decision 26).** It printed only the `serve`'s record (decision 15), and its own lock only kept the key it loads out of swap (L20). The update guide's dry run is `status` under the service's own settings, and without a line about its own process it couldn't show whether the updated proxy will lock.
  - **L24. The words when the record can't be read:** `Memory: the record a klav-proxy serve writes on this home once it listens cannot be read: <error>`. It used to say "the record the last klav-proxy serve wrote", which decision 24 makes inexact: the file may not be any `serve`'s.
- **Layer 1's own choices of its fifth round** (2026-11-19, building decisions 26–29). **Answered by Omar on 2026-11-19 (fifth batch):** L25 and L26 accepted as built (decision 30).
  - **L25. On macOS, `status` prints no line about its own process,** with the switch on or off: nothing can lock there, decision 17 keeps macOS free of an unlocked warning, and `status`'s `memory` already says why. The line's code is `memory::status_own_line`, which returns nothing where the system can't lock.
  - **L26. The line comes before `status` reads the registration or calls the server,** from the report `main` got from `harden_process`, with no second lock attempt. So a dry run under the service's settings shows it even when the registration or the network fails, and a `status` that then fails still printed it. One failure comes before the line: a home that can't be resolved at all (no `--home`, `KLAV_HOME` unset or empty, and `HOME` unset) stops `status` first. Its words: `klav-proxy: memory of this status process, not of any serve: core dumps off, not dumpable, ` followed by the same lock words as the record's line (`locked on fault (VmLck N kB at start).`, `not locked: <why>.`, `not locked: the lock is turned off (KLAV_PROXY_MEMORY_LOCK=off).`, or decision 19's). Only `KLAV_PROXY_MEMORY_LOCK` reaches `status` (L10), so the turned-off words name only it.

- **How decision 10's lapse works** (§2.6):
  - the clock is per entry, on the server, and a range's clock is its latest call from any address inside it;
  - an entry kept by a new record keeps its clock, and only a new or let-in entry starts a fresh one;
  - no push before or at the lapse, only "not seen for N days" in the sheet from day 80;
  - the narrowing is unattended, by the first unlocked device that sees a lapse, and never signs the empty list;
  - a record that keeps a lapsed entry is widening and asks for presence, even when the list doesn't grow;
  - `PUT …/egress` gains `base_at_ms` as the server's compare-and-set;
  - the refusal doesn't say whether a network lapsed or was never pinned.

### 12. Left to other ADRs
- **Deployed services (the second ADR):**
  - ADR 0038 keeps a decrypted item in the proxy's memory for as long as leases renew (0038:410). §3 here protects that memory; it doesn't shorten its life;
  - 0038 lets `POST /v1/agent/access` for a service through during a global pause (0038:610);
  - whether the alarm and the pin cover a service principal, whose PaaS egress is shared.

  This ADR doesn't redesign 0038.
- **Keyless access through workload identity federation.**
- **The proxy hosted by Klav** (ADR 0036 §12).
- **Detecting a copied sandbox** (ADR 0036 §5's second claim and its unbuilt `sandbox_theft` push).
- **Changing the proxy's key without a redeploy.** Until then, revoking and pairing a new proxy is how a stolen key ends.
- **Mode (b) of the sandboxes** (ADR 0043, PR #445).

## Plan in layers
One branch per layer, stacked with `gh stack` on this ADR's branch. Every layer touches `crates/`, so every merge redeploys `klav-server`. The last column says which ones change what it does; those need the "safe with older clients" review before merging (§6).

| Layer | Branch | What | Tests | Changes the server's behaviour |
|---|---|---|---|---|
| 1 | `proxy-key/memory` | `harden_process()` in `klav-proxy` (§3.1, §3.2), `--require-memory-lock`, `status.memory`, the self-zeroing header buffer (§3.3), the `nix` features (§3.5), the systemd unit, Compose and docs for `deploy/proxy` | Unit: after `harden_process()`, `getrlimit(RLIMIT_CORE) == (0, 0)`; on Linux, `get_dumpable() == false` in a child process; the lock decision for an unlimited, raisable and finite limit with an injected `getrlimit`. On a Linux host: no core file after `SIGABRT`, with the default `core_pattern` and with systemd-coredump. `status --json` shows `memory`. *Where each ran (2026-11-19):* the unit tests, the scripted lock sequence and `status --json` on macOS and in Linux containers (Docker Desktop's VM), and in CI's `test` task; the locked tests in those containers and in CI with a raised limit; the release image's cases in CI's `docker` task; the core-file test with a file `core_pattern` only in a Linux container, by hand. Neither host test has run on a host, and no run of the systemd-coredump one is recorded (decision 23) | No |
| 2 | `proxy-key/networks-server` | Migration `0020` (`agent_networks`, `push_tokens.kinds`); `agent_addresses`; recording after the signature; baseline, `new`, budgets and `many_networks`; the `new_address` alert; `GET`/`POST …/networks`; `new_networks` in `GET /v1/agents`; `seen_from` in `me`; the `agent_network` push, only to tokens with `kinds`; the purge after 90 days unseen; `self-hosting.md` §3.2 and §8.1; `privacidad.md` | Server tests on SQLite and Postgres: a bad signature writes nothing; the first network is a baseline without a push; a second one is `new` with one notice and the alert on the next logged event; IPv6 in one `/64` is one network; budgets; tokens without `kinds` get no push; `source: "off"` with the setting off; rows deleted with the agent and after retention; an older client's `PushRegistration` without `kinds` still works | **Yes.** Then Omar runs the §8.1 test on production and sets `KLAV_TRUSTED_IP_HEADER` and `KLAV_AGENT_ADDRESSES` (decision 8) |
| 3 | `proxy-key/networks-clients` | `klav-client` and `klav-ffi`; `klav proxy networks [confirm]` and the mark in `klav agent list`; a `klavd` operation and the Mac's local notification and rows; iOS registers `kinds`, the push route and the sheet; strings in `Localizable.xcstrings` (en, es); `klav-proxy status` prints `seen_from`; `apps/docs` page on the proxy | Client tests against a test server; the iOS route parses `agent_network`; the Mac sample app shows a notice; the CLI's `--json` | No |
| 4 | `proxy-key/egress-format` | `sign_egress`/`verify_egress` in `klav-core`, spec §13.13, `docs/vectores/agent-egress.json`; the verifier's `agent.egress_pinned` | Vectors (IPv4, IPv6, empty list, 16 entries); the reader rejects unsorted, duplicated, host bits set, prefix out of range, 17 entries; the verifier rejects a bad signature and an `at_ms` that doesn't grow | No |
| 5 | `proxy-key/egress-server` | Migration `0021` (`agent_egress_pins` and each entry's `last_seen_at`); `PUT /v1/agents/{id}/egress` with `base_at_ms`, its `409`s and `400`; enforcement in `AgentAuth` with `403 agent_egress_refused` on every signed route, `me` included; the 90-day lapse per entry (§2.6); `refused` rows and the notice; inside the pin, `known` rows with no notice (§2.5); `GET /v1/agents/{id}/egress` returning the signed record with each entry's `last_seen_at` and `lapsed`; fail-closed with the setting off | A pinned agent outside its pin gets `403` on `me`, `items` and `access`, and nothing is logged; inside, everything works; a replayed or stale `at_ms` gets `409`, and so does a `base_at_ms` that isn't the current record; with the setting off, a pinned agent is refused and a new pin is `409`; an un-updated proxy (current `klav-sdk`) outside its pin keeps its sandboxes and answers `server_denied`; under a pin, `POST …/networks/confirm` turns a `refused` row `known` and the next call from it is still refused; a call inside the pin raises no notice. With an injected clock: an entry unseen for 90 days is refused, with the same `403` as outside; a call inside a `/24` range keeps the range's entry alive; a new record keeps the clock of an entry it carries over and starts a fresh one for a new or let-in entry; a lapsed entry of an older record doesn't count once a newer record dropped it | **Yes** |
| 6 | `proxy-key/egress-clients` | The two network profiles (§2.5): `klav proxy networks strict\|alert` and `klav proxy egress pin\|add\|remove\|clear\|show`, presence for widening (letting a network in, turning strict off), `--every-device-is-updated` on the first pin, the device extending only a record it verified, the shared-network warning; the unattended narrowing of lapsed entries in `klavd`, the iOS app and the CLI, and the sheets' "not seen for N days" and "Lapsed" (§2.6); the Mac and iOS sheets, the strict notice's "Let it in" and the strict push words (en, es); the suggestion to turn strict on after 7 days on one network or on a VPS (decision 1); `apps/docs`; T210–T216 and risks 81–86 marked built; `features.md` | CLI tests with presence mocked; the first pin without the flag is refused; turning strict off without presence is refused; a device handed a list whose signature or `at_ms` doesn't verify refuses to extend it; a device that sees a lapsed entry signs the narrower list with no prompt, and signs nothing when every entry lapsed; a record that keeps a lapsed entry, even with the same list, is refused without presence; two devices narrowing at once: the second gets `409`, fetches again and signs nothing more; a widening leaves out lapsed entries the person didn't pick; the end-to-end test from §6's table with a proxy that moves outside its pin and back after "Let it in", and with a pinned network that lapses and is let in again | No |

## Consequences
- **What the review's chain becomes.**
  - **With the strict profile,** a copied key can't be used from anywhere but the pinned networks.
  - **With the alert profile, on a server that records addresses,** using it from another network tells the person within one call.
  - **Neither changes anything for a thief on the proxy's own host,** nor on a server that doesn't see real addresses.
- **The server keeps agents' addresses** for 90 days unseen (risk 84).
- **Production needs an operator step** before the alarm works there (decision 8).
- **One more thing to configure for whoever self-hosts:** `KLAV_AGENT_ADDRESSES`, and the client-IP source before it.
- **The proxy may start with memory unlocked on hosts that don't allow it,** and says so in `status`.
- **T23's promise of anomaly alerts** becomes true for proxies once layers 2–3 ship, for a new network only.

## The questions as asked (answered 2026-11-18)
Each listed its options; the first one was the recommendation. Omar's answer is under each, and the owner's decisions at the top record them.

- **Q1. The pin's default.**
  - (a) **Off,** with the app suggesting it for a proxy seen from one network for 7 days or on a VPS with a fixed address. *Recommended:* your words make it optional, and most proxy hosts have a changing or shared egress.
  - (b) On at pairing, with the network the proxy first connects from.
  - (c) Off and never suggested.
  - **Answered: (a).**
- **Q2. What a new network does.**
  - (a) **Alarm only;** the request goes on. *Recommended:* nothing breaks when a Mac changes networks, and the pin is there for whoever wants to block.
  - (b) Alarm and hold. The server refuses that proxy from the new network until the person taps "it's mine" on a device. The first call of a thief is blocked, but so is the proxy every time its address changes, until someone answers. It is an automatic pin made by the server, unsigned.
  - (c) Alarm and pause. Not possible automatically: a pause is signed by the account (§13.9) and the server can't sign it. It would only be a button on the notice, which (a) already has.
  - **Answered: two profiles: (a) as the default, (b) as a strict profile (decision 2, §2.5).**
- **Q3. How long a confirmed network stays known.**
  - (a) **90 days since it was last seen.** *Recommended:* it covers a laptop's usual places without keeping old addresses for ever.
  - (b) 30 days.
  - (c) Until the person removes it.
  - **Answered: (a).**
- **Q4. Which agents the alarm covers.**
  - (a) **Proxies only now;** other agents later, one by one, by a switch in the agent's sheet. *Recommended:* agents on a laptop change networks all day, and an alarm that rings all day gets ignored.
  - (b) Every agent from the start.
  - (c) Proxies, plus every agent the person marks as running on a server.
  - **Answered: (a).**
- **Q5. What the phone says.**
  - (a) **Neutral, with no name in the payload.** "New network for a proxy" / "One of your proxies was used from a network it hadn't used before. Open Klav to check it." The Spanish is written natively in the iOS layer, along the lines of «Un proxy se conectó desde una red nueva». *Recommended:* it keeps the rule that pushes carry no text, and it doesn't cry theft for a router change.
  - (b) Alarming: "Your proxy's key may have been copied".
  - (c) With the proxy's name, through `loc-args`. That puts the name in the payload, which T173 rules out today.
  - **Answered: (a).**
- **Q6. When the host refuses to lock the proxy's memory.**
  - (a) **Start, warn, and report `locked: false` in `status`,** with `--require-memory-lock` for whoever wants it fatal. *Recommended:* refusing would break proxies that start today on containers with a small memlock limit.
  - (b) Refuse to start.
  - **Answered: (a).**
- **Q7. How the server keeps agents' addresses.**
  - (a) **In clear, deleted after Q3's period and with the agent.** *Recommended:* you need to see the address to judge it and pin it, and the server already sees it on every request.
  - (b) Only a keyed hash. The notice says "a new network" without the address, and the pin can't be built from it.
  - **Answered: (a), after asking whether a stored list could be edited to get onto it (decision 7).**
- **Q8. Turning it on in production.**
  - (a) **You run the `self-hosting.md` §8.1 test against `api.klav.dev` after layer 2 deploys,** and set `KLAV_TRUSTED_IP_HEADER=x-real-ip` and `KLAV_AGENT_ADDRESSES=true` if it passes. *Recommended:* only the operator can say the address is real.
  - (b) Leave it off in production until launch.
  - (c) An agent runs the test with your OK. It sends 15 requests with made-up `X-Real-IP` values to production's login.
  - **Answered: (a).**
- **Q9. What a pin entry covers by default.**
  - (a) **The network as the alarm counts it:** `/32` for IPv4, `/64` for IPv6, with wider ranges only through the CLI. *Recommended:* it is the narrowest entry that doesn't break on IPv6 privacy addresses.
  - (b) `/24` for IPv4 too, which survives some ISP reassignments but admits the neighbours.
  - **Answered: (a).**
- **Q10. Under the strict profile, does a network expire after 90 days unseen, as under the alert profile?** Asked after Q1–Q9, because decision 3 set 90 days for the alarm and a signed pin entry, as first written, stayed until the person removed it, with at most 16 entries.
  - (a) **Yes.** The server stops admitting a pinned entry it hasn't seen for 90 days; the next call from it is refused and the person lets it in again with Face ID or Touch ID. The apps then sign a narrower list without that entry, which needs no presence, so the list doesn't fill. *Recommended:* it carries your answer of 90 days into the strict profile, and a café a laptop used once doesn't stay open for good. The cost: the server admits fewer networks than the signed list names (it fails closed, never open), and the audit log shows the signed list, not the shorter one in force.
  - (b) No. A signed entry stays until the person removes it. The app marks entries not seen for 90 days and offers removing them. The server enforces exactly what was signed, and a laptop in the strict profile can fill its 16 entries.
  - (c) An expiry inside the signed record. Each entry carries its own date, and the server ignores expired ones. It is exact, but it changes the format of §2.1 before it ships and needs a device to renew entries that are still in use.
  - **Answered: (a) (decision 10, §2.6).**

## Stop rules
- **A layer that finds a point marked "not checked" or "to confirm" false stops** and comes back to this ADR before going on. The list: the piped `core_pattern`, `/proc/self` after the dumpable flag, `http` keeping the shared buffer, `mlockall` on macOS, the sweep's handling of every refused route, and (2026-11-19) what `MCL_ONFAULT` does. That last one was checked in mlockall(2) and on Linux 7.0, and is as decision 11 assumed (§3.2 amendment).
- **Layer 2 doesn't merge without the "safe with older clients" review,** and layer 5 doesn't merge before layer 4's verifier is in a published release.
