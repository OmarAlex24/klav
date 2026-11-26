# Testing sandboxes by hand

This guide walks through the whole sandbox flow of [ADR 0036](decisiones/0036-sandboxes-de-agentes.md) with the real binaries, mode (a) only:
- the person grants a provider token to their own `klav-proxy`;
- an issuer starts a sandbox;
- `klav-forward` in the sandbox claims it;
- a tool in the sandbox calls the provider through it;
- the person sees the sandbox and revokes it.

It also covers the failure paths a person meets first: a second claim (the theft signal), paused agents, a proxy that doesn't answer, and calls outside the profile.

- **Time:** about 45 minutes, most of it setting up the three machines.
- **Isolated:** use a test server and a test account. Before the first command on each machine, check that it names the test server (`klav status` prints `server:`), and stop if it says `klav.dev` or `api.klav.dev`.
- **Rehearsed:** every step was run once on 2026-11-17, against a local test server, with debug builds of commit `633554a1`. All three roles ran on one Mac, over loopback. "Not run" marks what that rehearsal could not do. "Rehearsal output" quotes what it printed, with IDs shortened and made-up values. Some messages were reworded after the rehearsal; the guide quotes those as the code has them now.
- **Run for real:** the same day, the flow ran once end to end with a real Boat sandbox, a real Northflank token and the proxy and issuer on a Linux host reached over Tailscale. "Ran on 2026-11-17" marks what that run covered that the rehearsal did not. [What the real run taught](#what-the-real-run-of-2026-11-17-taught) is at the end, and [ADR 0042](decisiones/0042-sandboxes-for-daily-use.md) designs what it showed is missing.
- **Daily use:** [§14](#14-a-daily-sandbox) starts a sandbox the way ADR 0042 does it, with one command on the proxy's host, once the proxy, the issuer, Tailscale and Boat are set up. It ran once, end to end, on 2026-11-18. [What that run taught](#what-the-real-run-of-2026-11-18-taught) is at the end.

Check each box as it passes. When something fails, write down the step, the command and what it printed, and stop that section.

## 0. Requirements

**Three roles, three places:**

| Role | Where | Runs |
|---|---|---|
| The person | Their own device (a Mac or Linux computer) | `klav`, signed in to the test account |
| The proxy and the issuer | One host the person controls: a server, or their Mac | `klav-proxy serve`, and `klav` with the issuer's own home |
| The sandbox | A Linux VM or container (Boat, or any other) | `klav-forward`; for the Northflank line, also the Northflank CLI on its `PATH` |

- **The issuer runs on the proxy's host.** `klav sandbox start` talks to `klav-proxy serve` on `127.0.0.1` of the same machine: port 8790, or `--proxy-port`. From another machine it fails with "Klav's credential proxy did not answer on this machine".
- **What reaches what:**
  - the person's device and the proxy host reach the test server;
  - the proxy host also reaches the provider (`api.northflank.com`);
  - the sandbox only needs TCP to the proxy's channel, `HOST:PORT`. It never talks to the Klav server.
- **Builds of the commit under test:**
  - `klav` and `klavd` on the person's device and on the proxy host;
  - `klav-proxy` on the proxy host;
  - `klav-forward` in the sandbox image.

  `cargo build --release -p klav-cli -p klav-daemon -p klav-proxy -p klav-forward` builds them. `deploy/proxy/Dockerfile` builds an image of `klav-proxy`. The Linux tarball of a release doesn't carry `klav-proxy` or `klav-forward` ([releasing.md](releasing.md) §1).
- **Same commit everywhere:** `klav --version`, `klav-proxy --version` and `klav-forward --version` each name the commit, as in `klav-proxy 0.0.0 (633554a18784 2026-11-17T05:05:44Z)`. Check that all three name the same one. The setup lines need a `klav-forward` at least as new as the `klav` that prints them.
- **A provider token in the vault.** This guide uses a Northflank API token. For a dry run, a made-up value works: Northflank answers `401` with `Invalid API token`, which still shows the call went out through the proxy.

**Placeholders:**

| Placeholder | What it is |
|---|---|
| `SERVER` | The test server's URL (`https://…`; `http://` only for `127.0.0.1`) |
| `EMAIL` | The test account's e-mail |
| `ITEM` | The provider token's item, by title or `vault/project/item` |
| `PROXY_HOME`, `ISSUER_HOME` | Two directories on the proxy host, one for the proxy and one for the issuer, never the default Klav home |
| `HOST:PORT` | The address on the proxy host where sandboxes reach the channel |
| `PROXY_ID`, `SANDBOX_ID` | IDs the commands print |

## 1. The person: the token (person's device)

1. Check the server: `klav status` prints `server: SERVER` and the test account.
2. Add the token. The command asks for the value without echo:

   ```sh
   klav item add api-key --title ITEM -s api_key
   ```

   It prints `Added klav://Personal/General/ITEM`.

## 2. The proxy: register (proxy host)

```sh
klav-proxy --home PROXY_HOME init --email EMAIL --server SERVER
```

Rehearsal output:

```
Registered klav-proxy (8cd8ed5e-…).
Key: file PROXY_HOME/agents/klav-proxy.key (0600)

Pairing code: come unaligned life sublease trapeze moocher

Next, on a device of yours: `klav proxy use own 8cd8ed5e-…`, then `klav proxy grant <item> …` within 59 minutes, before this request lapses. The first grant shows these 6 words: check they match before you confirm.
Never approve it with `klav agent approve` or from the Requests list of the Klav app: that gives it whole projects, and a proxy must only get credentials one by one. Run `klav proxy use` first: from then on Klav refuses that approval.
```

- [ ] Keep the ID and the six words.
- [ ] **The request lapses one hour after `init`** (the server's `PENDING_TTL_MS`); `init` says how many minutes are left. If step 4.2 comes later than that, run `init` again with a new `PROXY_HOME`.
- [ ] `klav-proxy --home PROXY_HOME status` prints `pending`, the pairing code, `Memory: no record from a klav-proxy serve on this home.`, `No profiles yet.` and `No live sandboxes.` (The `Memory` line came with ADR 0044, after the 2026-11-17 runs.)

## 3. The issuer: register (proxy host)

```sh
KLAV_HOME=ISSUER_HOME klav agent register --name sandbox-issuer --server SERVER --email EMAIL --key-store file
```

It prints the agent's ID and its key file, says to approve it "within 59 minutes with the command for what it does", and gives the six words. Then it gives a command for each kind of agent: `klav agent approve sandbox-issuer --project <vault/project>` "if it reads projects", and `klav proxy issuer add sandbox-issuer --profile … --url …` "if it starts sandboxes (never give it projects)".

- [ ] Keep the six words. Its request also lapses in one hour.
- [ ] **Do not run the `klav agent approve` line it prints.** That gives the issuer whole projects. Step 4.3 runs the other one, `klav proxy issuer add`, which approves it as an issuer with no projects.

## 4. The person: three commands (person's device)

Each of these signs a change to an agent's grant. Through `klavd` they ask for Touch ID; without it, or with `--password-stdin`, the master password. The rehearsal used the master password: its Mac's screen was locked, and the test `klavd` locks when the screen does.

1. **Make it the account's proxy:**

   ```sh
   klav proxy use own PROXY_ID
   ```

   It prints a warning about devices with an older Klav, then `Credential proxy: "klav-proxy" (PROXY_ID), pending`, its pairing words, `No credentials yet.` and the next command.

2. **Grant the token.** The short way is the `northflank` preset:

   ```sh
   klav proxy grant ITEM --preset northflank
   ```

   It prints a note first: GET, POST and PATCH go through, each DELETE asks you, PUT and every other method are refused, and nothing in the preset guards role or token changes by path. Then it shows the whole profile before it asks anything:

   ```
   Grant to the credential proxy "klav-proxy" (PROXY_ID):
     item 696f160d-… in "Personal/General"
     "ITEM" → profile northflank
         upstream  https://api.northflank.com
         header    authorization: Bearer <value>
         rate      60 calls/min
         allow     GET,PATCH,POST api.northflank.com /
         ask       DELETE api.northflank.com /
   ```

   The long way types every part, and makes the same profile:

   ```sh
   klav proxy grant ITEM --profile northflank --upstream https://api.northflank.com \
       --header authorization --prefix "Bearer " --method GET,POST,PATCH \
       --ask-method DELETE --path-prefix /
   ```

   Either way, any flag you add to the preset replaces that part of it (`--path-prefix /v1`, say). When the flags change what gets signed, the note becomes one line saying so: the profile below it is what you sign, and the sentence about role and token changes stays while that profile lets a POST or PATCH through or asks for one. The 2026-11-17 runs came before the preset: they typed `--method GET,POST --path-prefix /v1`, so their profile showed `allow     GET,POST api.northflank.com /v1` and no `ask` line.

   - **The account's first per-item grant stops here** with "update every device first … then run it again with --every-device-is-updated". Update every device of the account, then add that flag. Without a terminal, the same message also asks for `--words "…"`, so the second run can carry both.
   - **The proxy's first credential** asks you to compare its six words (`[y/N]` in a terminal; without one, pass `--words "…"`). Compare them with step 2's. If they differ, answer no and revoke that agent.
   - **The `api.northflank.com` warning** says the token could reach the proxy if the proxy runs on Northflank (ADR 0036 §11). Run the proxy elsewhere.
   - It ends with `"ITEM" granted to the proxy "klav-proxy" (grant version 1).`
   - `/v1` lets through `GET /v1/login`, which the Northflank line of step 7 needs without an approval. Don't add `--ask` to this profile.

3. **Make the issuer:**

   ```sh
   klav proxy issuer add sandbox-issuer --profile northflank --url tls://HOST:PORT --inject-ask
   ```

   - It shows the proxy address, the profiles and the limits ("up to 3 at once, each for at most 8h"), says `It is pending: this approves it, with no projects`, and shows the issuer's six words. Compare them with step 3's.
   - `--inject-ask` makes each `inject` of the issuer ask you first. Without it, the command warns that the issuer could hand a token to the command that creates the sandbox.
   - The approval card shows the agent, the item and the reason, not the command the token goes to. [ADR 0041](decisiones/0041-presence-for-values-and-the-inject-card.md) (accepted, not built) adds the command.
   - **The account's first issuer stops** like the first grant: add `--every-device-is-updated` after updating every device and `klav-proxy`.
   - It ends with `"sandbox-issuer" may start sandboxes through the proxy "klav-proxy" (`klav sandbox start`).`
   - `tls://HOST:PORT` must be the address step 5 serves the channel on, reachable from the sandbox.

- [ ] `klav proxy status` lists the credential, then the issuer under `Sandbox issuers:`, as `"sandbox-issuer" (ID): profiles northflank; up to 3 at once, each for at most 8h`, and ends with `Sandboxes: 0 active, 0 waiting for claim`.
- [ ] `klav-proxy --home PROXY_HOME status` prints `active` and the profile: `northflank  https://api.northflank.com (header authorization, 60 calls/min)`.

## 5. The proxy: serve (proxy host)

```sh
klav-proxy --home PROXY_HOME serve --channel HOST:PORT
```

- It logs `klav-proxy listening listen=127.0.0.1:8790 …` and `klav-proxy channel listening (TLS 1.3, pinned keys) channel=HOST:PORT`.
- Before them, `klav-proxy memory core_dumps="off" dumpable=… locked=…` (ADR 0044 §3, after the 2026-11-17 runs). On a Mac, `locked=false` with no warning: macOS has no `mlockall`, and `status` says why. On Linux, `locked=true` only with an unlimited memlock limit; otherwise a warning names the limit and how to raise it ([self-hosting.md](self-hosting.md) §9.2). `KLAV_PROXY_MEMORY_LOCK=off` starts it without locking. From then on, `klav-proxy status` has a `Memory, as recorded by the klav-proxy serve that last started …` line with the same, until that `serve` stops.
- Keep it running for the rest of the guide.
- `--no-local-calls` may be added: it refuses every profile call on `127.0.0.1` of the proxy host with `403 klav_not_allowed`, and keeps the issuer's signed API and the channel ([self-hosting.md](self-hosting.md) §9.2). This guide makes no local calls, so every step works the same with it. The start log then has the field `local_calls` set to `false`: `local_calls=false` in the `pretty` format, `"local_calls":false` in JSON, the Docker image's format. (Not part of the 2026-11-17 runs: the option came after them.)
- The rehearsal started it after step 4 and gave it `--port` with a free port, because it ran on the same machine as the forwarder, which also takes 8790. On a separate host, the default is fine. With another `--port`, pass the same number to `klav sandbox start --proxy-port`. If the two collide, the error of whichever starts second names the other (`klav-proxy listens there` or `another klav-forward listens there`) and the flag that moves it. The 2026-11-17 runs came before that message.
- On a terminal, its log has colors; written to a file or a pipe, it has none.

## 6. The issuer: start a sandbox (proxy host)

Two ways to hand over the package:

```sh
# the command that creates the sandbox gets the package in KLAV_SANDBOX
KLAV_HOME=ISSUER_HOME klav sandbox start --label LABEL --profile northflank -- COMMAND

# or a new 0600 file, for a program that passes it on and deletes the file
KLAV_HOME=ISSUER_HOME klav sandbox start --label LABEL --profile northflank --package-file PATH
```

Rehearsal output:

```
Started sandbox d93432d5-… (rehearsal-1), with northflank; it expires in 7h 59m (2026-11-17 13:38 UTC).
Its package is in PATH (mode 0600): put it in the sandbox's environment as KLAV_SANDBOX and delete the file.
Setup lines for the sandbox (no secrets):
  klav-forward down --if-other-package
  klav-forward up --daemon
  eval "$(klav-forward env)"
  northflank login -n klav -t klav-placeholder --override --host "$KLAV_FORWARD_NORTHFLANK_URL"
Next: Put the setup lines in the sandbox's setup script as they are. When the work is done, run `klav sandbox stop d93432d5-…` and delete the sandbox at the provider. Unclaimed, it ends 1 hour after it starts, or at its expiry if that comes first. The `northflank login` line needs the `northflank` profile to allow `GET /v1/login` without an approval step.
```

- [ ] **The sandbox needs the package in its environment as `KLAV_SANDBOX`**, the value that starts with `ksb1_`. The `--package-file` output says so. It is a one-time secret: it never goes in a log, a repository or a chat.
- [ ] The fourth line appears only for a sandbox with the `northflank` profile.
- [ ] `KLAV_HOME=ISSUER_HOME klav sandbox ls` lists it as waiting (`claimed` once step 7 runs).

## 7. The sandbox: the setup lines (sandbox)

With `KLAV_SANDBOX` set, run the lines exactly as printed:

```sh
klav-forward down --if-other-package
klav-forward up --daemon
eval "$(klav-forward env)"
northflank login -n klav -t klav-placeholder --override --host "$KLAV_FORWARD_NORTHFLANK_URL"
klav-forward status
```

Rehearsal output, in a clean environment without root:

```
klav-forward is not running here: nothing to stop.
Claimed sandbox «rehearsal-1» (d93432d5-…). Profiles: northflank.
Calls go to http://127.0.0.1:8790/<profile>/… and Klav's proxy adds the credential.
Could not write /etc/profile.d/klav-forward.sh (not root?): the shell lines are in ~/.klav-forward/env.sh instead: . ~/.klav-forward/env.sh
installed the Klav skill in ~/.claude/skills/klav/SKILL.md
installed the Klav skill in ~/.agents/skills/klav/SKILL.md
Running in the background; its log is ~/.klav-forward/forward.log.
Sandbox «rehearsal-1» (d93432d5-…) is live. Profiles: northflank. Calls go to http://127.0.0.1:8790/<profile>/…
```

- [ ] `klav-forward status` exits `0`.
- [ ] `env | grep KLAV_FORWARD` shows `KLAV_FORWARD_URL=http://127.0.0.1:8790` and `KLAV_FORWARD_NORTHFLANK_URL=http://127.0.0.1:8790/northflank`, and no values.
- [ ] **`KLAV_SANDBOX` is still set** in the shell that ran the lines: `up` can't remove it from its parent, and the lines don't unset it. The package is spent once claimed. A second claim with it ends this sandbox as theft (step 10.1).
- [ ] The proxy's log says `sandbox claimed sandbox=SANDBOX_ID`.
- **The Northflank line** (not run in the rehearsal. Ran on 2026-11-17: in a real Boat sandbox, `northflank login` succeeded against the forwarder) needs the Northflank CLI on the sandbox's `PATH`.
  - Without it, the line exits `127`, and under `set -e` the script stops after `up` already claimed the sandbox. Install the CLI in the image before running the lines.
  - Its `login` checks `GET /v1/login` through the forwarder, with a 3 s timeout and 3 attempts (ADR 0036 §5, decision of 2026-11-16).
  - Commands of that CLI that use WebSockets probably fail through the proxy.

## 8. One call (sandbox)

```sh
curl -sS -D - -H "Authorization: Bearer klav-placeholder" "$KLAV_FORWARD_NORTHFLANK_URL/v1/login"
```

- [ ] The answer is Northflank's. With the rehearsal's made-up token it was `HTTP/1.1 401 Unauthorized` and `{"error":{"status":401,"message":"Invalid API token"}}`. The proxy drops the placeholder `Authorization` and sends the real one. With a real token, Northflank's answer to a logged-in call. Ran on 2026-11-17: `GET /v1/login` answered `200`.
- [ ] The proxy's log says `proxied call method=GET status=401 error="" sandbox="SANDBOX_ID"`.
- [ ] On the person's device, `klav log --limit 5` shows `klav-proxy  agent.access proxy → allow  klav://…/ITEM  credential proxy call from a sandbox`, after `sandbox.claimed` and `sandbox.issued`.

## 9. The person: see and revoke (person's device)

1. `klav proxy sandboxes`:

   ```
   Proxy: "klav-proxy" (8cd8…): heartbeat just now

   ID        LABEL (per the issuer)  PROFILES    ISSUER                  EXPIRES    LAST SEEN  STATE
   d93432d5  "rehearsal-1"           northflank  sandbox-issuer (2dfc…)  in 7h 58m  just now   active

   Verified up to event #11.
   ```

2. `klav proxy status` ends with `Sandboxes: 1 active, 0 waiting for claim`.
3. `klav log verify` prints `The audit log is intact: …` and `This device's signed head is at event N.`
4. **Revoke it:**

   ```sh
   klav proxy sandboxes revoke d93432d5 --wait
   ```

   - It says the revocation is signed and stored, then `Waiting for the proxy to log their end (at most 2 minutes)…` and `The proxy logged their end.` That took 11 s in the rehearsal.
   - `--all` instead of an ID revokes every sandbox of the proxy (21 s in the rehearsal).
   - Neither asks for Touch ID: revoking only takes access away.
5. In the sandbox, the same `curl` now gets `HTTP/1.1 401 Unauthorized`, `klav-error: klav_sandbox_revoked` and the JSON `error`, `message` and `next`. The call stops at the proxy. `klav-forward status` exits `5`. The real run of 2026-11-17 saw the same, and the proxy logged the end with reason `person`. The `message` now says why: `This sandbox's access to Klav's credential proxy has ended: the person revoked it.` The 2026-11-17 runs saw the generic text.
6. Within 5 minutes, at its next status check, the forwarder stops by itself and frees its port. `forward.log` says `the sandbox ended (klav_sandbox_revoked)`, and `klav-forward status` keeps exiting `5` with the proxy's message, which the forwarder keeps in `ended.json` in its state directory. `klav-forward down` then says there is nothing to stop. From then on, a tool that calls the forwarder's port gets "connection refused", with no `Klav-Error` header: run `klav-forward status`, which says why. The 2026-11-17 runs came before this: there the forwarder kept running and held its port until `klav-forward down`, which said `http://127.0.0.1:8790 is free` and `The proxy had already ended the sandbox`. An expired sandbox's forwarder still keeps running, so each tool keeps getting `klav_sandbox_expired` with its `next`.
7. **The other two ways to end a sandbox:**
   - the issuer: `KLAV_HOME=ISSUER_HOME klav sandbox stop SANDBOX_ID` (or `--all`);
   - the sandbox itself: `klav-forward down`, which releases it at the proxy.
8. `klav proxy sandboxes --ended` shows each ended sandbox and why: `revoked by you`, `stopped by the issuer`, `released by its forwarder`, `theft signal`.

## 10. Failure paths

1. **A second claim (theft signal).** Run `klav-forward up` with the same package in another sandbox, or in another state directory: `--state-dir`, or another `HOME`.
   - **The second claim** gets exit `5` with the `klav_sandbox_revoked` message, which says it was a second claim from another forwarder.
   - **The first sandbox** is ended: `klav-forward status` exits `5`, and calls get `klav_sandbox_revoked` with the same message. Neither forwarder learns which claim came first. Within 5 minutes the first forwarder stops by itself (§9, step 6).
   - **The proxy** logs `a second claim with the right secret: the sandbox ends with theft`.
   - **The issuer's** `klav sandbox ls` says `No live sandboxes.`
   - **The person** sees it as a security warning above the table of `klav proxy sandboxes`, with or without `--ended`: `Sandbox d93432d5: security warning: theft signal at …`, with the label and the issuer and what to do. The row stays in the plain list with the state `theft signal`, and `--json` names it in `theft_signals`. `klav proxy status` prints the same line above its counts. Both still exit `0`. `klav log` shows the end as `sandbox.revoked → theft`; `klav log verify` says nothing of it, since a theft is a valid event, not tampering. The push to the phone doesn't exist yet.
2. **Paused agents.** `klav agent pause --all` on the person's device ("Every agent paused until you resume").
   - A call in a live sandbox gets `HTTP/1.1 423 Locked` with `klav_agents_paused`.
   - `klav sandbox start` exits `7`.
   - `klav-forward status` exits `7` with the `klav_agents_paused` message, up to 30 s after the pause, when the proxy next refreshes its grant. The forwarder keeps running. The 2026-11-17 runs, before this, saw `live` and exit `0`. Pausing only the issuer (`klav agent pause <issuer>`) doesn't change `status`: it still says `live`, while that sandbox's calls get `423`.
   - Running the setup lines again while paused stops at `klav-forward up`, with exit `7`, before `eval "$(klav-forward env)"`. Nothing breaks: after the resume the same lines work again.
   - `klav agent resume --all` asks for Touch ID or the master password; afterwards the sandbox works again.
3. **The proxy doesn't answer.** With `klav-proxy serve` stopped:
   - a call gets `HTTP/1.1 503 Service Unavailable` with `klav_proxy_unreachable`;
   - `klav-forward status` exits `1` with the same message;
   - once `serve` runs again with the same home, the sandbox is live again.
4. **Outside the profile.** All of these get `HTTP/1.1 403 Forbidden` with `klav_not_allowed`:
   - a path outside `/v1` (`/v2/projects`) or a method not granted (`DELETE`). The message says whether the path, the method, or the method on that path was outside what the person allowed, and never names the rules. The 2026-11-17 runs saw the server's wide message, which named three possible causes;
   - a profile the proxy doesn't have (`/railway/…`), with `Klav's credential proxy has no profile with that name.`

   - [ ] For a path or a method outside the profile, the proxy's log has a `WARN` line before that call's `proxied call` line: `a call outside its profile was refused method=DELETE sandbox="SANDBOX_ID" profile="northflank" error="denied" outside="method"`. `outside` is `path`, `method` or `method_on_path`, and `error` is the kind of refusal the server gave. The line never has the path, the query, a header, the body or anything of the credential. A refusal for another reason says `the server refused the call` with its `reason` instead. A profile whose credential is no longer in the proxy's grant is refused by the proxy itself, before the server is asked: `the proxy's grant does not have this profile's credential` with `reason="not_in_grant"`. An answer the proxy could not verify is an `ERROR` line, `the server's answer could not be verified`. One honest case reaches it: for up to 30 s after the person changes a rule from ask to allow, the proxy's copy of the grant still asks, and the proxy refuses the server's "allowed".

## 11. Errors the person is likely to meet

Every error from the forwarder or the proxy is HTTP with a `Klav-Error` header and a JSON body with `error`, `message` and `next`. The skill tells an agent to repeat the `message` to the person and stop. One exception: once the proxy revokes a sandbox, its forwarder exits, so a call to its port gets "connection refused" with no header. That means: run `klav-forward status`, which says why.

| `error` | HTTP | What it means | What to do |
|---|---|---|---|
| `klav_sandbox_revoked` | 401 | The sandbox ended: revoked by the person, stopped by the issuer, released, a second claim (theft), or ended by the proxy's sweep after an hour without calls. Its `message` says which, unless the proxy restarted since | `klav proxy sandboxes --ended` says which. A new sandbox needs a new `klav sandbox start` |
| `klav_sandbox_expired` | 401 | Its expiry passed, before or after the proxy's sweep ended it (not run). After a restart of the proxy, an ended one gets `klav_sandbox_revoked` | Start a new one |
| `klav_agents_paused` | 423 | The person paused agents | `klav agent resume --all` when it's safe |
| `klav_not_allowed` | 403 | Outside the profile's host, methods or paths; a profile the proxy doesn't have; or the proxy was revoked | Check the profile in `klav proxy status`; change it with a new `klav proxy grant` |
| `klav_proxy_unreachable` | 503 | The forwarder doesn't reach the proxy's channel | Check that `klav-proxy serve --channel HOST:PORT` runs and that the sandbox reaches `HOST:PORT` |
| `klav_server_unreachable` | 503 | The proxy doesn't reach the Klav server (not run) | Check the proxy host's network to `SERVER` |
| `klav_rate_limited` | 429 | Over the sandbox's or the profile's calls per minute (not run) | Wait `retry_after` seconds |
| `klav_upstream_blocked` | 502 | Private address, redirect, or a body the proxy can't check (not run) | Check the profile's upstream |
| `klav_approval_pending` / `klav_approval_denied` | 409 / 403 | A profile with `--ask` or `--ask-method` (not run) | Decide on the person's device. The sandbox has no way to wait for it yet (§12) |
| `klav_proxy_backlog` | 503 | On `klav sandbox start`: too many ended sandboxes waiting for the server (not run). On Klav Cloud's hosted proxy, also on a call: the account already has as many calls or as much request data in flight as it may (ADR 0051 §3.3) | For a start, fix the proxy's connection to the server; for a call, wait `retry_after` seconds |
| `klav_forward_not_running` | — | `klav-forward status` with no forwarder in this state directory | A new sandbox needs a new package |
| `klav_forward_already_claimed`, `klav_forward_port_in_use` | — | `up` with a package already spent here, or with the port taken. The second message says who holds the port: another `klav-forward`, `klav-proxy` or another program (not run) | Run the setup lines as printed: the first one stops another package's forwarder. For `klav-proxy` or another program, its `next` says this run spent nothing and which `--port` moves what |

On the proxy host, `klav sandbox start` with the proxy down, or on another port, exits `1` with "Klav's credential proxy did not answer on this machine". It then says to check `klav-proxy serve` and `--proxy-port`.

## 12. What does not exist yet

- **Mode (b):** `HTTPS_PROXY` with a CA of the sandbox, for tools that can't take a base URL (Railway's CLI).
- **Mode (c), tried for real:** the MCP gate (Maple) is built, but has not run in a real sandbox yet: [§15](#15-the-mcp-gate-maple-step-m5) is that test.
- **Approvals inside the sandbox:** `klav-forward approval wait`, and the proxy holding a call while the person decides. A profile with `--ask` answers `klav_approval_pending` at once.
- **The apps' panes:** the Mac app has "Active sandboxes" (Development › Sandboxes). Still missing: the iPhone app's pane, the `sandbox_theft` and `sandbox_expiring` pushes, the Mac's local notifications (E5) and its Issuers block.
- **Presets:** `northflank` and `maple` exist (`klav proxy grant ITEM --preset northflank|maple`). `railway` needs mode (b). The `northflank` preset hasn't been tried in a Boat sandbox yet, which layer 10 asks for; `maple` is §15.
- **Packaging:** a Railway template for the proxy, and the proxy on the Mac (LaunchAgent and Tailscale).

## 13. Clean up

1. On the person's device: `klav proxy sandboxes revoke --all --wait`.
2. In each sandbox: `klav-forward down`, then delete the sandbox at the provider.
3. On the proxy host: stop `klav-proxy serve`, and delete `PROXY_HOME` and `ISSUER_HOME` if they were only for this test.

## 14. A daily sandbox

For daily use, one command on the proxy's host makes the whole sandbox ([ADR 0042](decisiones/0042-sandboxes-for-daily-use.md)). `klav sandbox start` runs `new-sandbox`, which makes a Tailscale key for this sandbox and creates the Boat machine from the template, in the daily environment. The daily environment's setup script then joins the tailnet and runs the setup lines, so the sandbox claims itself. Nobody types anything inside it.

This section is for a person whose setup is already done. It doesn't repeat it:
- the proxy and the issuer: steps 1 to 5, with `klav-proxy serve` running;
- Tailscale's OAuth client, `tag:klav-sandbox`, its `tagOwners` and the rule: ADR 0042 §2, §4 and layer 4;
- `new-sandbox`, its `config` and its two 0600 files on the proxy's host: [deploy/sandbox/README.md](../deploy/sandbox/README.md);
- the build environment and the saved template: [deploy/sandbox-template/README.md](../deploy/sandbox-template/README.md);
- the daily environment and the Boat key: ADR 0042 §5 and §7.

**The setup the 2026-11-18 run used,** to compare against yours:
- **`config`** held four keys. The machine lasts as long as the sandbox, 8 hours:
  ```
  BOAT_TEMPLATE=klav-sandbox-<version>
  BOAT_ENVIRONMENT=<the daily environment>
  TAILNET=on
  BOAT_TTL_SECONDS=28800
  ```
- **The daily environment:** third parties off, GitHub on, agents' credentials on, Secrets off, sandbox (Boat) credentials off. No variables and no secret files. One repository, with this setup script:
  ```sh
  { printenv KLAV_TAILNET_KEY || true; } | sudo -n /usr/local/sbin/klav-tailnet-up "${KLAV_TAILNET_HOSTNAME:-}"
  klav-forward down --if-other-package
  klav-forward up --daemon
  eval "$(klav-forward env)"
  northflank login -n klav -t klav-placeholder --override --host "$KLAV_FORWARD_NORTHFLANK_URL"
  ```
  The first line is `klav-tailnet-up`'s. The other four are exactly the setup lines `klav sandbox start --profile northflank` prints. The per-sandbox values of `new-sandbox` (`KLAV_SANDBOX`, `KLAV_TAILNET_KEY`, `KLAV_TAILNET_HOSTNAME`) arrived with Secrets off. "Blocking" is now ticked on the setup script; in the run it was still off.
- **The proxy** ran `klav-proxy serve --no-local-calls --channel HOST:PORT` (step 5).
- **The build environment** has every toggle off. The template was built there on 2026-11-17 with `build-template`, which exited 0 with `nothing forbidden found` ([its README](../deploy/sandbox-template/README.md#building-a-template-once-per-release)).
- **The Boat key** has the `ci` preset, is limited to the daily and the build environments, and lasts 30 days. It deployed the saved template.

### 14.1 Start it (proxy's host)

As the issuer's system user, with the issuer's Klav home (add `KLAV_HOME=ISSUER_HOME` if it isn't that user's default). `NEW_SANDBOX` is where `new-sandbox` is installed on the host; the run used `/usr/local/lib/klav-sandbox/new-sandbox`.

```sh
klav sandbox start --label LABEL --profile northflank -- NEW_SANDBOX
```

Output of the run (19 s, exit `0`):

```
Started sandbox SANDBOX_ID (daily-1), with northflank; it expires in 7h 59m (…).
(the four setup lines, as in step 6)
Next: …
bx_XXXXXXXX
```

- [ ] It exits `0`, and its last line is Boat's sandbox ID, `bx_` and 8 characters. Keep it and `SANDBOX_ID`: ending the sandbox needs both.
- [ ] Without `--ttl`, the sandbox lasts 8 hours. Unclaimed, it ends 1 hour after it starts.
- **When it fails,** `new-sandbox` prints one line that says whether a Boat machine may exist ([its README](../deploy/sandbox/README.md#when-it-fails)). `klav sandbox start` leaves the Klav sandbox live either way: run `klav sandbox stop SANDBOX_ID` at once, and check Boat when the line says a machine may exist.

### 14.2 Know it's ready

- The Boat machine is `provisioning` for about 3 minutes, then `idle` with health `ok`.
- [ ] **Ready is the claim, not `idle`:** the proxy's log says `sandbox claimed sandbox=SANDBOX_ID`, and `klav sandbox ls`, as the issuer, shows it `claimed`. In the run, that came 3 min 11 s after `sandbox started`, when the setup script ran.
- In the run, the setup script had already run by the time the machine was `idle`, but "Blocking" was off then. It has been ticked since and not run again.

### 14.3 Check it (sandbox)

Run these in the sandbox, with `boat exec` or its terminal. The 2026-11-18 run checked each of these things with `boat exec`, printing only shapes, but not with these exact commands. **Boat stores every command and its output, so print only what you check:**

```sh
klav-forward status
tailscale status --json | jq '{BackendState, Tags: .Self.Tags, Online: .Self.Online, HostName: .Self.HostName}'
systemctl is-active klav-tailscaled
systemctl is-enabled tailscaled.service
eval "$(klav-forward env)"
curl -sS -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer klav-placeholder" "$KLAV_FORWARD_NORTHFLANK_URL/v1/login"   # the proxy replaces the placeholder (step 8)
northflank list projects >/dev/null; echo "$?"
```

- [ ] `klav-forward status` exits `0`: `Sandbox «LABEL» (SANDBOX_ID) is live. Profiles: northflank. Calls go to http://127.0.0.1:8790/<profile>/…`
- [ ] Tailscale: `BackendState` is `Running`, `Tags` is `["tag:klav-sandbox"]`, the node is online, and its hostname is `klav-` plus the first 8 characters of `SANDBOX_ID`.
- [ ] `klav-tailscaled` is `active`, and `tailscaled.service` is `masked`.
- [ ] The call answers `200`, and `northflank list projects` exits `0` with the placeholder token. The run's call sent no `Authorization` header at all and also got `200`: the proxy adds the real one. The proxy's log has a `proxied call` line for each.
- [ ] No Northflank token or model API key is in the environment. Test each name you care about with `[ -n "${NAME:+x}" ] && echo "NAME is set"`, never by printing it.

### 14.4 Use it

- **Tools call through the forwarder:** `$KLAV_FORWARD_NORTHFLANK_URL`, and the Northflank CLI, logged in with the placeholder. The proxy adds the real token. Errors are in §11.
- **The repository** of the daily environment is cloned. In the run, at `main`'s commit.
- **An agent** gets its model login from the daily environment. Not run yet: no agent ran in the 2026-11-18 run.

**Cautions:**
- **The GitHub token is wider than the environment's repository.** Boat puts a token of its GitHub App in `GITHUB_TOKEN`, a user token (`ghu_…`) that expires with the machine. It reaches every repository the app's installation covers, with the installation's permissions. The environment's repository setting decides what is cloned, not what the token reaches. Any agent in the sandbox can read it. Omar accepted this on 2026-11-18, because the sandboxes sometimes work on several repositories (ADR 0042 §7). To narrow it, limit the app's installation to selected repositories in GitHub's settings. It is the one secret that lives inside the sandbox; Klav's credentials stay on the proxy.
- **The sandbox's user is root in effect:** `sudo -n` works without a password. An agent can read the forwarder's state and `tailscaled`'s socket. The sandbox is disposable and the credential stays on the proxy, as ADR 0036 and ADR 0042 already assume.
- **`KLAV_SANDBOX` and `KLAV_TAILNET_KEY` stay in the machine's environment,** and Boat stores every command and its output. Never print the environment there: no `env`, no bare `printenv`, no reading `/proc/*/environ`. Test a variable with `[ -n "${VAR:+x}" ]`. The key is single-use and already spent, and the package is already claimed, but neither belongs in a log.
- **A daily sandbox has one life.** Don't stop and resume the machine. On a resume the setup script runs again, `tailscaled` kept its state in memory, and the single-use key is spent, so by design the node can't rejoin the tailnet. Not tried in the run. Within the same life, running the first setup line again is harmless: two hours after the start it printed `klav-tailnet-up: already on the tailnet with tag:klav-sandbox: nothing to do` and exited `0`.

### 14.5 End it

- **The issuer:** `klav sandbox stop SANDBOX_ID` on the proxy's host, then delete `bx_XXXXXXXX` at Boat.
- **Or the person,** from their device: `klav proxy sandboxes revoke SANDBOX_ID --wait` (§9, step 4), then delete the machine at Boat.

Ending was not exercised in the 2026-11-18 run. Step 9 and the 2026-11-17 run cover what a revoked sandbox answers.

## 15. The MCP gate (Maple), step M5

The last step of the MCP gate (ADR 0036 §7, note of 2026-11-19): an MCP client in a real sandbox reaches Maple's MCP server through the proxy, with the proxy's key and never its own. It measures what the note leaves unchecked. **Not run yet:** steps M2 to M4 were tested only against a fake provider. Run it after [§14](#14-a-daily-sandbox) works, with the same proxy, issuer and template.

**Before:**
- [ ] **A restricted Maple key:** read-only permissions, expiring within 90 days, in an `api-key` item (decision 2). Not your full key: every MCP call is the same `POST /mcp`, so the key's permissions are the only limit (T226).
- [ ] **The grant:** `klav proxy grant ITEM --preset maple` (add `--upstream https://api.eu.maple.dev` for the EU host). The note before the profile says the key is the limit; the profile shows `allow DELETE,GET,POST api.maple.dev /mcp` and no `ask` line.
- [ ] **The issuer** may use it: `klav proxy issuer add ISSUER --profile maple` (with `northflank` too if it already had it).
- [ ] **The template** has Claude Code or Codex (or both) on the `PATH`, and the daily environment's setup script has the two `maple` lines that `klav sandbox start --profile maple` prints, after the `eval` line.

**In the sandbox:**
- [ ] `klav sandbox start --profile maple …` printed the two lines, and the setup script ran them: `claude mcp get maple` shows `http://127.0.0.1:8790/maple/mcp` with `Authorization: Bearer klav-placeholder`; `codex mcp get maple` (or `~/.codex/config.toml`) shows the same URL, without a header.
- [ ] Ask the agent for something read-only ("list my Maple services"): the call works, and `klav log` on the person's device shows `proxy` accesses with `POST api.maple.dev /mcp` and the sandbox.
- [ ] **No sign-in.** Neither client opened or offered an OAuth sign-in with Maple, and no token of Maple's own landed in the sandbox (`grep -ri maple_ ~/.claude* ~/.codex` finds only the placeholder).
- [ ] **Codex without the placeholder:** if a `401` or `403` from the proxy (a revoked sandbox, say) makes Codex start a sign-in, write it down: it is the gap the note of 2026-11-25 names.

**What to measure and write down** (the note's "not checked" list):
- [ ] Whether Maple answers a `POST` with a stream (`text/event-stream`) or with JSON, how long it keeps a stream open, and whether it uses `Mcp-Session-Id` (`klav-proxy` logs each call's status and duration, never its body).
- [ ] The largest event line Maple sends: under 1 MiB, or the stream is cut.
- [ ] Whether 60 calls a minute per sandbox and the 4 slots per sandbox are enough for a real session (a `429 klav_rate_limited` in the agent's output says no).
- [ ] **Cuts:** with a stream open, `klav proxy sandboxes revoke ID` on the person's device cuts it within about 30 s (the proxy's sweep), and `klav agent pause --all` within about 30 s (the grant's refresh). Both show as a broken stream in the client, never a clean end.

Then, and only then, check the mode (c) box in [roadmap.md](roadmap.md).

## What the 2026-11-17 rehearsal changed

- All three roles ran on one Mac against a local server on `127.0.0.1`: the channel was on loopback, and each sandbox was a clean environment (`env -i`) with its own `HOME`.
- The Mac's screen was locked, so the test `klavd` locked itself. The person's commands ran on the CLI's direct path with the master password, and Touch ID was not exercised.
- The Northflank line was not run, to keep to one request to an outside host. The one request was the `curl` of step 8, with a made-up token.
- The second claim of step 10.1 used `--port 8791`, because the first forwarder held 8790 on the same machine.

## What the real run of 2026-11-17 taught

The run used a Boat machine created from a saved snapshot prepared once: `klav-forward` checked against its SHA-256, Tailscale installed but not connected, and the Northflank CLI. The proxy's channel listened on its tailnet address, port 8443, and a Tailscale rule let `tag:klav-sandbox` reach only that port.

- **Tailscale needs root and `/dev/net/tun`.** A Boat machine has both, so `tailscaled --state=mem:` and `tailscale up --auth-key=file:PATH` worked, with the key in a file removed right after, never on a command line. `klav-forward` has no support for a SOCKS or HTTP proxy, so Tailscale's userspace mode is not an option.
- **`/etc/profile.d` was not writable** without root, so the shell lines went to `~/.klav-forward/env.sh`. The four setup lines still exited `0`.
- **A template saved from a `--no-env` machine can never run an agent.** The run's template was built with `boat new --no-env`, and Boat keeps that flag on every sandbox made from its snapshot, whatever `--environment` says, so the sandbox had none of the agent's own logins. ADR 0042 replaces that template with one saved from a normal machine of an empty build environment, and adds a minimal daily environment.
- **The template is now built by a script.** `deploy/sandbox-template/` holds `build-template`, its "never in it" checks, the manifest and `klav-tailnet-up`, which joins the tailnet with the key on standard input ([its README](../deploy/sandbox-template/README.md)). Building and saving a template stays the person's step, and the daily-use guide comes with layer 6 of ADR 0042. (2026-11-18: it is [§14](#14-a-daily-sandbox).)
- **The package took a detour.** `--package-file` wrote it to a tmpfs, and it went to `boat new -e KLAV_SANDBOX=…` on another machine where the Boat CLI was logged in. In ADR 0042, a script on the proxy's host creates the machine through Boat's API, with the package in the request body on standard input, never on a command line. That script is now `deploy/sandbox/new-sandbox` ([its README](../deploy/sandbox/README.md)): `klav sandbox start … -- deploy/sandbox/new-sandbox`, with its configuration and two 0600 files on the proxy's host. It has run only against a fake `curl` so far. (2026-11-18: it ran for real, [below](#what-the-real-run-of-2026-11-18-taught).)
- **The Tailscale key was made by hand,** single-use, ephemeral and tagged. ADR 0042 is about making it per sandbox.
- **The sandbox's node saw other devices of the tailnet** but reached none of them, and only port 8443 of the proxy answered. A node sees every device that may connect to it ([Tailscale: device visibility](https://tailscale.com/docs/concepts/device-visibility)), so the tailnet's policy let those devices connect to `tag:klav-sandbox`. The person's own rules decide that.
- **After the person revoked it,** calls got `401 klav_sandbox_revoked`, `klav-forward status` exited `5`, and the proxy logged the end with reason `person` 37 seconds after the sandbox's last call.

## What the real run of 2026-11-18 taught

The first daily sandbox of ADR 0042, run as [§14](#14-a-daily-sandbox) says: the proxy and the issuer on the proxy's host, reached over Tailscale, a real Northflank token, and a Boat machine from the template saved in the build environment, started in the daily environment. Everything inside the sandbox was checked with `boat exec`, printing only shapes.

- **The template was built and saved the day before,** on 2026-11-17, with `build-template` on a normal machine of the build environment: exit `0`, `nothing forbidden found` ([its README](../deploy/sandbox-template/README.md) lists what that build proved).
- **The first start failed before any call to Boat:** `new-sandbox: Tailscale's token answer held no token it could read; no Boat machine was created`. Tailscale's OAuth access token was 442 characters, and the script refused more than 255. PR #454 lets the token and the key have up to 4096. As documented, the failed start left the Klav sandbox live, and `klav sandbox stop SANDBOX_ID` ended it at once.
- **The second start took 19 seconds** and exited `0`, with Boat's sandbox ID on its last line. The machine was `provisioning` for about 3 minutes, then `idle` with health `ok`. The proxy logged `sandbox claimed` 3 min 11 s after `sandbox started`.
- **The script's two calls to Tailscale and its call to Boat worked for real.** The key was made per sandbox, and the script read the ID from Boat's answer at `.sandbox.id`.
- **A scoped Boat key deploys the saved template.** The key had the `ci` preset and was limited to the daily and the build environments. This run doesn't show whether a key limited to the daily environment alone could.
- **`env` values reach the sandbox with Secrets off.** `KLAV_SANDBOX`, `KLAV_TAILNET_KEY` and `KLAV_TAILNET_HOSTNAME` all arrived.
- **The template held up on a real tailnet:**
  - `tailscaled.service` was still masked in the deployed sandbox;
  - `klav-tailscaled`, the unit `klav-tailnet-up` starts, outlived the setup script and was still active two hours later;
  - `sudo -n` worked without a password;
  - `tailscale status --json` showed `BackendState` `Running`, `Self.Tags` `["tag:klav-sandbox"]`, the node online, and the hostname `klav-` plus 8 characters of the sandbox ID;
  - two hours in, the first setup line run again by hand, with the key already spent, said `already on the tailnet with tag:klav-sandbox: nothing to do` and exited `0`. The forwarder still answered.
- **Boat's GitHub token reaches more than the environment's repository** (§14.4). Omar accepted that the same day. The repository was cloned at `main`'s commit.
- **Not proven yet:**
  - where Boat's `409` puts its error code: no `409` came;
  - whether Tailscale and Boat accept a 4096-character value: 442 worked;
  - an agent's model login inside the sandbox: no agent ran;
  - stopping and resuming the machine, and ending the sandbox (§14.5);
  - the setup script with "Blocking" ticked;
  - `main`'s binaries: the template and the proxy's host ran those of the template's commit, older than `main`, so later forwarder and proxy changes were not in this run.
