# 0042 · Sandboxes for daily use: one command from the proxy's host, a Tailscale key per sandbox, and a minimal Boat environment

- Status: Accepted (2026-11-17). Omar answered P1–P7, P9 and P10 the same day; P8 is open. The route decided now (layers 2 to 6) is built, and the first daily sandbox ran on 2026-11-18 ([try-sandboxes.md](../try-sandboxes.md#14-a-daily-sandbox) §14). The later proxy route (§10) is not built
- Date: 2026-11-17
- Builds on: [ADR 0036](0036-sandboxes-de-agentes.md) §4, §5, §6 and §11, and its amendment of 2026-11-09 (E6.1). Nothing in ADR 0036 is reversed; where this ADR narrows it, ADR 0036 carries a dated note pointing here

> **Read this first.** Omar's decision 1 asked that the Tailscale credential live in the Klav vault and be used through the credential proxy, so that the issuer never holds it. Today's `klav-proxy` can't do that.
> - **Why the OAuth client doesn't fit:** it is the Tailscale credential that can be limited to tagged keys. It trades its secret for a one-hour access token, and the trade sends the secret in the request body. The proxy only puts a secret in a header.
> - **Why the API access token is rejected:** it fits the proxy unchanged, but it has "the same permissions as the owning user".
>
> **Omar chose a route that works now and accepted its costs knowingly (§2).** The issuer's system user on the proxy's host keeps an OAuth client limited to `auth_keys` and `tag:klav-sandbox`, next to the Boat API key. A helper script under `deploy/sandbox/` trades it, creates the key and creates the Boat machine. This needs no grant format change, no server change and no device update.
> - **The cost:** the issuer, which is an agent, holds that credential. That departs from the letter of decision 1.
> - **Later work, not scheduled:** the proxy making the trade itself (§2, "Later").

**Who decided what.**
- Sentences marked **Omar's decision** are Omar's, from 2026-11-17.
- Sentences marked **Proposal** are mine and still wait for Omar. Only P8 is left.
- Everything else is fact, from one of three sources:
  - what the run on 2026-11-17 showed;
  - what the code at `main` does;
  - what the public documentation says, with its URL.

## Context

### The first real sandbox (2026-11-17)
On 2026-11-17 the first real sandbox ran end to end, by hand. No hostname, address, account or ID is written here.

- **The proxy and the issuer** ran on a small Linux host that Omar controls, reachable only over Omar's tailnet (Tailscale). The proxy's node carries `tag:klav-proxy`, and the channel listens on port 8443 of its tailnet address. The proxy's loopback listener stays on `127.0.0.1:8790`.
- **The sandbox** was a Boat machine created from a saved snapshot (a "template") prepared once. The template held:
  - `klav-forward`, copied in and checked against its SHA-256;
  - Tailscale, installed from its signed apt repository but not connected (service disabled, no state);
  - the Northflank CLI.
- **How the template was built:** in a machine created with `boat new --no-env`.
  - A saved snapshot of such a machine stays `--no-env` forever. Every sandbox made from this template can never receive a login, so §7 replaces it.
  - Boat machines have root and `/dev/net/tun`, so Tailscale's normal mode works.
  - `klav-forward` has no support for a SOCKS or HTTP proxy, so Tailscale's userspace mode with a SOCKS5 proxy would not have done.
- **Tailscale.** Omar created a tag `tag:klav-sandbox`, a rule letting it reach only `tag:klav-proxy` on `tcp:8443`, and one single-use, ephemeral, tagged auth key, typed by hand.
- **The package.** `klav sandbox start --package-file` wrote the package to a 0600 file on a tmpfs. It was read once, deleted, and handed to `boat new -e KLAV_SANDBOX=…` on another machine, where the Boat CLI was logged in. The Tailscale key went along as a file.
- **In the sandbox:**
  - `tailscaled --state=mem:` started first;
  - then `tailscale up --auth-key=file:PATH`, so the key was never on a command line. The node was named `klav-` plus the first 8 characters of the sandbox ID, and refused the tailnet's DNS and routes. The key file was removed;
  - the node's tags were read back from `tailscale status --json`, and it had the tag;
  - only port 8443 of the proxy answered: six other ports on the proxy did not, nor did six on each other visible device.
- **The flow:**
  - the four setup lines exited 0. `/etc/profile.d` was not writable without root, so the shell lines went to `~/.klav-forward/env.sh`;
  - `northflank login` succeeded against the forwarder;
  - `GET /v1/login` through the proxy answered 200 with the real token, and a `DELETE` got `403 klav_not_allowed`;
  - Omar revoked with `klav proxy sandboxes revoke`. After that:
    - calls got `401 klav_sandbox_revoked`;
    - `klav-forward status` exited 5;
    - the proxy logged the end with reason `person`, 37 seconds after the last call.

### What the run showed is missing
1. **The Tailscale key per sandbox is manual.** ADR 0036 §6 says the issuer creates it by the API; nothing does yet.
2. **The package has no direct path** from the issuer's host to the provider. It went through a file and a second machine.
3. **The sandbox could not run an agent,** because it had none of the agent's own logins. Its template was saved from a `--no-env` machine, and Boat keeps that flag on every sandbox made from it.
4. **Other devices of the tailnet are visible to the sandbox's node,** though it can't reach them. That is Tailscale's documented rule: a device sees "All devices that can connect to your device". So the tailnet's policy lets those devices connect to `tag:klav-sandbox` (§1, §9).

### Omar's decisions (2026-11-17)
1. **The issuer creates the Tailscale key for each sandbox by Tailscale's API** (ADR 0036 §6 already says so). Omar asked for the credential for that API to live in the vault and be used through the credential proxy, so that the issuer never holds it. That doesn't work with today's proxy, and Omar chose the route of §2.
2. **In daily use the issuer, on the proxy's host, creates the provider's machine,** with a Boat API key that belongs to the issuer's system user. One command does it: `klav sandbox start -- <helper>`, with the package in the command's environment and no file. §5 says how the package then reaches Boat.
3. **Daily sandboxes start from a minimal Boat environment made for this:** the agent's model login and git access, nothing else. Provider tokens stay out and arrive through Klav. The template is rebuilt for it.
4. **That the sandbox's node can see other devices of the tailnet is fine for Omar,** who sometimes wants a sandbox to reach another device (by SSH, for example). Omar's idea is that Klav asks the person what a sandbox may reach on their network. This ADR records it as an open product question (§9) and doesn't decide it.

Omar's answers to the proposals, the same day, are in §13 and in each section as **Omar's decision**.

## 1. What I read, and when

All reads on **2026-11-17**, from public pages, without calling any API. Quotes are short and exact; "not documented" means I didn't find it in these pages.

### Tailscale

| Source | What it says |
|---|---|
| API reference, served as OpenAPI at <https://api.tailscale.com/api/v2?outputOpenapiSchema=true> (the page <https://tailscale.com/api> renders it; [`api.md`](https://raw.githubusercontent.com/tailscale/tailscale/main/api.md) in the Tailscale repository says "The Tailscale API documentation has moved to https://tailscale.com/api") | **Auth:** "Access tokens can be supplied as the username portion of HTTP Basic authentication (leave the password blank) or as an OAuth Bearer token".<br>**API access tokens:** "These tokens will have the same permissions as the owning user, and can be set to expire in 1 to 90 days."<br>**Trust credentials:** "Trust credentials don't expire" and "are not tied to an individual Tailscale user".<br>**`POST /tailnet/{tailnet}/keys`**, "Create an auth key or trust credential": "Returns a JSON object with the generated key"; "The full key can no longer be retrieved after the initial response"; "OAuth Scope: `auth_keys` grants access to create machine auth keys"; `keyType` is `auth`, `client` or `federated`; `expirySeconds` "Defaults to 90 days".<br>**`capabilities.devices.create`** has `reusable`, `ephemeral`, `preauthorized` and `tags`. For a key owned by the tailnet (created through OAuth), "it must have tags", which "must exactly match the tags that are on the OAuth client … (or they must be tags that are owned by the tags that are on the OAuth client …)". For a key owned by a user, "tags are optional".<br>`POST` exists only on `/keys`; `/keys/{keyId}` has `GET`, `DELETE` and `PUT` |
| OAuth clients, <https://tailscale.com/kb/1215/oauth-clients> | "The Tailscale OAuth token endpoint is `https://api.tailscale.com/api/v2/oauth/token`", which "accepts requests that conform to the OAuth 2.0 client credentials grant request format".<br>Its one example sends the secret as form fields in the body: `curl -d "client_id=…" -d "client_secret=…"`. **Whether it also takes HTTP Basic is not documented.**<br>"An OAuth access token expires after 1 hour. This time cannot be modified." "All auth keys created from an OAuth client must use tags." |
| Trust credentials, <https://tailscale.com/docs/reference/trust-credentials> | "When you revoke a trust credential, any active API access tokens that the credential created are also revoked." "Revoking a trust credential does not revoke auth keys or child trust credentials that it created." A federated identity needs a system "capable of generating OIDC-compliant JWT identity tokens" |
| Tags, <https://tailscale.com/docs/features/tags> | "Tag owners can be users, groups, or even other tags". "If tag:a owns tag:b, you can apply tag:b to a device authenticated with an auth key that applied tag:a", and "Doing so replaces the device's existing tags". Ownership doesn't chain. "You cannot remove tags using the --advertise-tags flag if the device uses an auth key." |
| Device visibility, <https://tailscale.com/docs/concepts/device-visibility> | A device sees "Devices that your device can connect to as permitted by the tailnet policy file", "All devices authenticated with the same user identity", and "All devices that can connect to your device, even if you aren't permitted to connect to them". "You can restrict which devices know about each other by implementing more prescriptive access control policies." |
| Auth keys, <https://tailscale.com/kb/1085/auth-keys> | "Tailscale automatically revokes one-off keys after they are used." "Revoking a key does not deauthorize nodes using the key." "To deauthorize a node, delete it from the Machines page." |
| Ephemeral nodes, <https://tailscale.com/kb/1111/ephemeral-nodes> | They "are auto-removed anywhere normally from 30 to 60 minutes after the last activity", and "immediately removed from your network if you run `tailscale logout`". With `--state=mem:` "the daemon stores state in memory", and since v1.30 "when the device exits, the `tailscaled` daemon itself performs `tailscale logout`" |
| `tailscale up`, <https://tailscale.com/kb/1241/tailscale-up> | `--auth-key` reads the key from a file when its value starts with `file:`.<br>`--timeout` "Defaults to `0s`, which blocks forever."<br>`--accept-dns` defaults to accepting.<br>`--accept-routes` "The default depends on the host operating system."<br>`--hostname` replaces the OS's. **What `up` does on a node that is already up, given a spent key, is not documented** |

I also read Tailscale's own key tool, [`cmd/get-authkey/main.go`](https://raw.githubusercontent.com/tailscale/tailscale/main/cmd/get-authkey/main.go). That is source code, not documentation. It leaves the way the secret is sent to Go's `clientcredentials` library.

### Boat

| Source | What it says |
|---|---|
| CLI reference, <https://docs.boat.dev/cli-reference.md> | **`boat new --env`:** only `KEY=VALUE` is documented (`boat new --help` shows only `-e, --env <KEY=VALUE>`).<br>**`--no-env`:** "creates a sandbox that gets none of the secrets of your account". "A saved snapshot of a `--no-env` sandbox stays `--no-env`": "every sandbox from it gets none of your environment secrets, even with `--environment`". "To make a template that gets secrets, save it from a sandbox created without `--no-env`."<br>**Other flags:** `--from` starts from a saved snapshot, and `--environment <name>` picks the environment.<br>**Global flags:** `--api-url <URL>` "Use a different API endpoint (env: `BOAT_API_URL`)". `BOAT_API_BASE` is not on this page.<br>**Login:** `boat login --key-stdin` "reads the token from standard input, not from the command line" |
| Environments and access, <https://docs.boat.dev/environments.md> and <https://docs.boat.dev/environments/access.md> | **With *Safe for third parties* on, or `--no-env`:** "The sandbox gets no environment variables, no secret files, no GitHub access", "no boat credentials, no agent logins and no repository setup scripts". "boat keeps this flag forever." `boat new --no-env` "works exactly like a start in an environment that is safe for third parties".<br>**With it off,** four toggles decide what a sandbox gets:<ul><li>GitHub (`passGithub`);</li><li>Secrets (`passSecrets`);</li><li>boat credentials (`passSandboxCredentials`): "A boat API key, so the sandbox can snapshot, stop and resume itself";</li><li>Agents credentials (`passAgentsCredentials`).</li></ul>Every sandbox also gets `BOAT_ID` and `ASCII_TOKEN`, and "`ASCII_TOKEN` can act only on this one sandbox". **The toggles' defaults are not documented** |
| Saved snapshots, <https://docs.boat.dev/snapshots/templates.md> and <https://docs.boat.dev/snapshots/whats-saved.md> | **Saving:** `boat snapshot <id> <name>` saves the disk; the same name replaces it.<br>**What a deploy gets:** a deploy from it "does **not** get the **environment** of the source sandbox", but "Each `--env KEY=VALUE` that you gave the source is set on every deploy". Boat's advice: "Do not put a secret in `--env` on a sandbox that you will save".<br>**What isn't saved:** memory and running programs. Enabled systemd services start again |
| API keys and scopes, <https://docs.boat.dev/api-keys.md>, <https://docs.boat.dev/api-keys/create-and-list.md>, <https://docs.boat.dev/api-keys/scopes.md> | **Scope and expiry:** "Every new key has a scope." "Every new key expires. The maximum is 365 days." A key can be limited with `--env` (API `environmentIds`).<br>**The `ci` preset:** "Everything in `full-sandbox`, plus create, resume, fork, and delete the sandboxes this key created. No account admin".<br>**From a saved snapshot,** a key needs "`sandbox.create` for the destination, and `snapshot.read` access to the source", and "A destination environment does not give access to snapshots from other environments". **How to give a key `snapshot.read` on one saved snapshot is not documented:** the scoped-key API takes only `preset`, `actions`, `sandboxIds` and `environmentIds`.<br>**The in-sandbox key:** Boat writes one into each sandbox at `~/.config/ascii/boat/config.json`; it "works on **that sandbox** only" |
| Create sandbox, <https://docs.boat.dev/api/reference/sandboxes/create-sandbox.md> | `POST https://boat.dev/api/v1/sandboxes`, with `Authorization: Bearer boat_…`. The body takes `env` ("Per-sandbox environment variables"), `environment`, `from` (a saved snapshot), `ttlSeconds` and `noEnv`. An `Idempotency-Key` header makes retries safe |

### The code at `main`

- **The loopback listener** (`crates/klav-proxy/src/app.rs`, `bind`) binds `127.0.0.1` only. Every path except the issuer API goes to `proxy::handle`, which serves the call through `forward` as `Caller::Local` (`crates/klav-proxy/src/proxy.rs`). `forward` serves **any** profile in the proxy's map, to a local caller or to a sandbox that has that profile.
  - **What a local call is checked for:** only the browser headers and the `Host` (`not_local`). It carries no identity.
  - **Its limits:** the profile's `rate_per_minute`, and the 16 requests in flight that all callers share. The per-sandbox limits (60 calls a minute, 4 slots) apply only to `Caller::Sandbox`.
  - **Its audit entry:** the proxy's own signed `POST /v1/agent/access`, with no `sandbox` and the reason `"credential proxy call"` (`profiles.rs`, `Profile::call`).
  - **So every process on the host can use every profile,** and the log only says the proxy made the call. On a host with several users, that is every user. [self-hosting.md](../self-hosting.md) §9.2 says it for the container.
- **The issuer API** (`/_klav/sandboxes`, `crates/klav-proxy/src/sandboxes.rs`) is on the same listener, but it checks the issuer's signature against the proxy's grant, which the account signs.
- **`klav sandbox start -- COMMAND`** runs the command directly, without a shell, with the package in `KLAV_SANDBOX` and standard input closed (`crates/klav-cli/src/commands/sandbox.rs`). It redacts only the package from the command's output.
- **A profile in a grant** is `klav_proto::agent::ProxyProfile`, with `deny_unknown_fields`. The server parses the grant payload when the person signs one (`crates/klav-server/src/routes/agents.rs`, `check_format`). A new kind of profile is therefore a grant format change and a server change.
- **The server and `klav log verify`** accept an access that names a sandbox that was issued but not yet claimed:
  - the server's `barrier` (`crates/klav-server/src/routes/sandboxes.rs`) refuses a sandbox that was never issued, ended, revoked or expired;
  - `klav log verify` (`crates/klav-client/src/audit.rs`) only requires that such an access be a `proxy` one.

  I read this in the code; I didn't test it.
- **The package** `ksb1_` (spec §13.10) has no field for a Tailscale key.
- **`klav agent register`** prints, for an issuer, "If it starts sandboxes (never give it projects)" (`crates/klav-cli/src/commands/agent.rs`).

### What the code and the docs contradict
- **ADR 0036 §6 puts the Tailscale key "in the same boot package".** The package format has no field for it. §4 decides how it travels.
- **Decision 2 says "in the command's environment and no file".** That holds from `klav` to the command, but Boat's CLI documents only `-e KEY=VALUE`. So `boat new` would hold the package on its own command line, readable with `ps` by every user of the host. §5 sends it to Boat's API instead.
- **ADR 0036 E6.1 lets the issuer's command be `klav agent run …`.** That needs `inject` on a project, which an issuer must never have. §6 reconciles them.
- **The run's template can't serve daily use.** It was saved from a `--no-env` machine, and Boat keeps that flag on every sandbox made from it, whatever `--environment` says. §7 replaces it.

## 2. The Tailscale credential (decision 1)

### What fits the proxy, and what doesn't
`klav-proxy` puts one secret into one header (`prefix` + value) of a request to one upstream, for the methods and path prefixes the profile allows. It never looks at the body (ADR 0036 §7; spec §13.4).

| Credential | How it authenticates | Lifetime | Through today's proxy | What its holder can do |
|---|---|---|---|---|
| **User API access token** (`tskey-api-…`) | `Authorization: Bearer`, or Basic with the token as the user name | 1 to 90 days | **Yes**, as a plain profile | "The same permissions as the owning user". Untagged, reusable keys valid for 90 days, since "tags are optional" for a key owned by a user. By inference, not tested: OAuth clients with any scopes through the same `POST …/keys`, which never expire |
| **OAuth client**, scope `auth_keys`, tag `tag:klav-sandbox` (`tskey-client-…`) | Trade `client_id` and `client_secret` at `/api/v2/oauth/token` for an access token, then `Authorization: Bearer` with it. The documented trade sends the secret **in the form body** | The secret never expires; the access token lasts 1 hour, fixed | **No:** the trade needs the secret in the body. HTTP Basic at the token endpoint is not documented, and the caller would get the one-hour token back | Auth keys that must carry the client's tags or tags those tags own. The holder still chooses reusable, ephemeral, pre-approved, and up to 90 days |
| **Federated identity** | An OIDC JWT from the caller's own identity provider | Short | **No:** Klav is not an OIDC issuer | — |
| **The OAuth client secret as an auth key** (`tailscale up --auth-key=tskey-client-…`) | Given to the node itself | Never expires | Not a proxy call | Puts the long-lived secret inside the sandbox. **Never** |

### Omar's decision: the scoped OAuth client on the proxy's host, now
**Omar's decision (2026-11-17).**
- **The credential:** an OAuth client with only the `auth_keys` scope and only `tag:klav-sandbox`. The issuer's system user on the proxy's host keeps it in a 0600 file, next to the Boat API key (§5).
- **The helper** `deploy/sandbox/new-sandbox` (§5) runs as the command of `klav sandbox start --`. It does three things:
  1. trades the client for a one-hour access token, with the secret never on a command line;
  2. creates the key with a fixed body (§4);
  3. creates the Boat machine.
- **What it doesn't need:** a grant format change, a server change or a device update.
- **The user API access token stays rejected.**

**The costs, accepted knowingly by Omar:**
- **The issuer holds the credential.** That departs from the letter of decision 1. The issuer is an agent, so its own commands can read that file.
- **The "fixed body" is a convention of the script.** Whoever holds the secret can ask Tailscale for other bodies.
- **A thief gets unlimited keys** carrying `tag:klav-sandbox`, reusable and non-ephemeral, valid for up to 90 days, until Omar revokes the client in Tailscale.
- **Klav's log records nothing about these keys.** Tailscale's configuration audit log names the client that made each one.
- **The bound** is that such nodes reach only the proxy's channel port, and claim nothing without a package. It holds only under three assumptions, which Omar keeps true in the tailnet's policy:
  1. **the tag's rule** lets `tag:klav-sandbox` reach only `tag:klav-proxy` on `tcp:8443`;
  2. **`tag:klav-sandbox` owns no tag** (in `tagOwners`), and neither does any other tag a sandbox's key can carry. A sandbox has root. A node joined with a key that applied `tag:a` can give itself any tag `tag:a` owns, so ownership would let a sandbox promote itself. The person owns `tag:klav-sandbox`, not `tag:klav-proxy`;
  3. **the keys are pre-approved.** Device approval, if the tailnet has it on, is not a check here: a thief's node joins exactly as a sandbox's does.

### Later: the proxy makes the trade itself
**Not scheduled.** This was my P1 (a). It is what decision 1 asked for, and it stays here so it isn't lost. It moves the OAuth client from the issuer's file into the vault, granted to the proxy.

- **A profile of a new kind, `oauth2-client-credentials`:**
  - the proxy sends the trade from its own process;
  - it keeps the one-hour token in memory only (never a file, a log or an answer) and drops it at expiry or on a `401`.
- **The profile is never served by `forward`,** on the loopback listener or on the channel. It is not a mode (a) profile. It isn't in the map `forward` reads; only the sandbox start flow (P2 below) uses it.
- **Who refuses it in an issuer grant:**
  - `klav proxy issuer add` refuses it;
  - the server refuses an issuer grant that lists it.

  So no sandbox and no local caller ever has it.
- **The item's `proxy` rules** allow only `POST` to `api.tailscale.com` on two paths: `/api/v2/oauth/token` and `/api/v2/tailnet/-/keys`.
- **Two accesses, each logged:**
  - the trade is a use of the item, so it gets its own `POST /v1/agent/access`. A refreshed token is a new trade and a new access;
  - each key it creates gets another, naming the sandbox.

  A single access can't cover both, because the server's access names one method and one path.
- **What it costs:** the new profile kind is a grant format change. The spec §13.4 gets it, with vectors. The server must accept it while still accepting every grant older clients send, and it deploys when merged to `main`. Every device and `klav-proxy` must be updated first, behind the same `--every-device-is-updated` gate the first per-item grant used.

### What happens when a key or a node goes
- **A one-off key** is revoked by Tailscale as soon as it is used. A copy after that gives nothing.
- **Revoking a key "does not deauthorize nodes using the key".** Neither does revoking the OAuth client.
- **The sandbox's node leaves the tailnet:**
  - when `tailscaled --state=mem:` exits (it logs itself out since v1.30);
  - on `tailscale logout`;
  - 30 to 60 minutes after its last activity, since it is ephemeral.

  A Boat machine that is deleted, or stopped without a clean shutdown, takes the 30 to 60 minutes.
- **None of this is what cuts the sandbox off: revoking the sandbox is** (ADR 0036 §6). A node that stays on the tailnet after its sandbox ended reaches port 8443, where its channel key no longer works.

## 3. Who may call the proxy's loopback listener
**Today, anyone on the host.** A call to `http://127.0.0.1:8790/<profile>/…` has:

- **no identity:** the listener can't tell the issuer from any other process, or from any other user's process;
- **only the profile's rate and the shared slots,** not the per-sandbox limits;
- **an audit entry that only names the proxy:** an `agent.access` by the proxy, permission `proxy`, with the item, method, host and path, the reason `"credential proxy call"` and no sandbox. Nothing says which process asked.

The issuer runs on that host (decision 2), so the issuer, which is an agent, can use every profile directly, without a sandbox.

**Omar's decision (P9 (a)):** `klav-proxy serve --no-local-calls` on Omar's proxy.
- **What it does:** it refuses every profile call on `127.0.0.1` with `403 klav_not_allowed`, and keeps the issuer API, which is signed.
- **The default stays as it is for now.** The hand-test guide and the end-to-end tests use local calls, and changing the default changes what existing proxies do.

**Omar's decision (P10 (a)):** the proxy's host is single-purpose. It has two system users, one for `klav-proxy` and one for the issuer, and nothing else, as ADR 0036 §11 already recommends. `--no-local-calls` limits what a second process can use; it doesn't make a shared host safe.

## 4. The Tailscale key: what it is and how it travels

### The key
Every key is created with the same body:

```json
{"keyType":"auth","description":"klav sandbox","expirySeconds":3600,
 "capabilities":{"devices":{"create":{"reusable":false,"ephemeral":true,"preauthorized":true,"tags":["tag:klav-sandbox"]}}}}
```

- **One hour,** because an unclaimed sandbox already ends one hour after it starts (ADR 0036 §4). The key is spent within minutes or not at all.
- **Who creates it:**
  - in the route decided now, the helper (§2), so the body is the script's convention;
  - in the later route, the proxy, inside `klav sandbox start` (**Omar's decision, P2 (a)**), with a body it builds and the issuer can't change. The issuer asks for it with a signed request, and the server logs the access by its sandbox. From the code, that access needs no server or verifier change (§1).

### How it travels: `KLAV_TAILNET_KEY`
**Omar's decision (P3 (a)):** a second variable, `KLAV_TAILNET_KEY`, never a `ksb2_` package. Spec §13.10 gets one line saying the Tailscale key never goes in the package.

- **Who sets it now:** the helper, in the `env` of its Boat request (§5).
  - `klav` never sees the key, so it can't redact it: the helper never prints it, and never prints a Tailscale or Boat response.
  - The helper also sets `KLAV_TAILNET_HOSTNAME`. It is not secret: `klav-` plus the first 8 characters of the sandbox ID, which the helper reads from the package's ID bytes (spec §13.10) and never prints with the rest.
- **Who sets it later:** `klav sandbox start --tailnet`, in the command's environment. It is redacted from the command's output like the package, and `--package-file` gets a sibling file for it.
- **Without Tailscale,** neither route sets it, and the template's script does nothing (§4, "Who runs Tailscale").

### Who runs `tailscaled` and `tailscale up`
**A root-owned script in the template,** `/usr/local/sbin/klav-tailnet-up` (layer 3).
- **Who calls it:** the daily environment's setup script, before the lines `klav sandbox start` prints:
  ```sh
  printenv KLAV_TAILNET_KEY | sudo -n /usr/local/sbin/klav-tailnet-up "$KLAV_TAILNET_HOSTNAME"
  ```
- **Why in the template, not printed by `klav`:**
  - in the route decided now, `klav sandbox start` has no `--tailnet` and doesn't know whether a key exists;
  - the script needs root and the template's pinned `tailscale`, and it is built and versioned with the template under `deploy/`;
  - Klav's CLI stays unchanged.
- **Why `printenv` into a pipe:** `sudo` resets the environment, so the key can't reach the script as a variable. A trace shows only the variable's name, and the key goes through a pipe, never an argument.
- **What the script does,** in this order:
  1. **No tracing:** `set -eu` and `set +x`. Never run the setup lines with `-x`.
  2. **The key file:** `umask 077`, then a new directory made with `mktemp -d /run/klav-tailnet.XXXXXX`. An explicit path, because `mktemp` follows `TMPDIR`; `/run` is a tmpfs a snapshot doesn't keep. A `trap` removes the directory on every exit, also when `tailscale up` fails under `set -e`. The key from standard input goes to a 0600 file there. With an empty input, it says "no Tailscale key: skipped" and exits 0.
  3. **Already up:** if `tailscale status --json` says the node is already running with `tag:klav-sandbox` in `Self.Tags`, it exits 0 without calling `up`. A rerun with a spent key, on a node already up, isn't documented, so the layer that builds this must test that case.
  4. **The daemon:** it starts `tailscaled --state=mem:` in the background if its socket isn't there, then waits for the socket, at most 30 s.
  5. **Joining:** `tailscale up --auth-key="file:$dir/key" --hostname="$1" --accept-dns=false --accept-routes=false --timeout=60s`. Without `--timeout`, `up` "blocks forever".
  6. **The tag:** it reads `Self.Tags` from `tailscale status --json` with the template's pinned `jq`. Without `tag:klav-sandbox`, it runs `tailscale logout` and exits 1. In the route decided now, nothing else enforces the tag on the node.
- **The key never sits in the setup script.** The script names only the variable, never the value, so the provider's stored setup script and command history hold no key. `unset KLAV_TAILNET_KEY` would only clear it in one shell, so the script doesn't rely on it.
- **Boat stores the key, as it stores `KLAV_SANDBOX`.** It is single-use and lasts one hour; once spent, it gives nothing. If someone else takes it first, `klav-tailnet-up` fails, and under `set -e` the sandbox never claims its package. The node made with the stolen key reaches only the channel port, where it needs a package.

> **Note (2026-11-17), layer 3 review.** Two corrections to this section, made when the script was built:
> - **The setup line.** As quoted above, it breaks when the tailnet is off (§8): neither variable is set, so `set -u` stops on the hostname and `pipefail` fails on `printenv`. The line is:
>   ```sh
>   { printenv KLAV_TAILNET_KEY || true; } | sudo -n /usr/local/sbin/klav-tailnet-up "${KLAV_TAILNET_HOSTNAME:-}"
>   ```
>   With an empty input and an empty hostname, the script says "no Tailscale key: skipped" and exits 0.
> - **Step 4, the daemon.** It is not started "in the background" as a child of the script. A child shares the setup script's session and control group, so a hangup from `sudo` or the session's end could stop it, and with `--state=mem:` a stopped daemon is a logged-out node. It starts as a transient systemd unit, `systemd-run --unit=klav-tailscaled --collect`, and the script still waits at most 30 s for the socket. The template masks `tailscaled.service` (§7), so the two units never share a name.

> **Note (2026-11-18), layer 6.** The first daily sandbox answered step 3's open case. Two hours after the start, the setup line run again on a node already up, with the key spent, printed `klav-tailnet-up: already on the tailnet with tag:klav-sandbox: nothing to do` and exited 0. `klav-tailscaled` was still active then, and `tailscaled.service` was still masked after the snapshot ([try-sandboxes.md](../try-sandboxes.md#what-the-real-run-of-2026-11-18-taught)).

## 5. Creating the machine from the proxy's host (decision 2)
**Omar's decision (P4):** the helper calls Boat's API directly, with the body on standard input. There is no test of `boat new -e NAME` and no Boat start spent on one. The package is never on a command line.

**The command:**
```sh
klav sandbox start --label L --profile northflank -- deploy/sandbox/new-sandbox
```

**What `new-sandbox` does,** as the issuer's system user:
1. **Reads two 0600 files** of that user, and refuses a file that is more open or someone else's:
   - the Tailscale OAuth client's ID and secret;
   - the Boat API key.
2. **Trades the client** (§2), then creates the key (§4).
3. **Calls `POST https://boat.dev/api/v1/sandboxes`** with an `Idempotency-Key`.
   - **The body:** `from` (the template, §7), `environment` (the daily one) and `env`. The `env` holds:
     - `KLAV_SANDBOX`, from its own environment;
     - `KLAV_TAILNET_KEY` and `KLAV_TAILNET_HOSTNAME`, only when it created a key.
   - **The credentials:** curl reads every secret header and every body from standard input or a file descriptor (`-K`, `--data-binary @-`), never from its arguments. The body is built with shell builtins, which never run as a separate process.
4. **Prints only Boat's sandbox ID.**
   - Never the package, the key, the access token or a response: `klav` redacts only the package from the command's output.
   - The command's standard input is closed (`klav sandbox start` closes it), so the script never prompts.

**The Boat key. Omar's decision (P5 (a)):**
- **Its scope:** the `ci` preset (create, resume, fork and delete "the sandboxes this key created", no account admin), limited to the daily environment, with the shortest TTL that works (at most 365 days). It is kept by the issuer's system user.
- **It may not be able to deploy the template as scoped.** Creating from a saved snapshot needs `snapshot.read` on the source, and "A destination environment does not give access to snapshots from other environments". The template is built in another environment (§7).
  - Boat's docs don't say how to give a key `snapshot.read` on one saved snapshot. The scoped-key API has no snapshot field.
  - Layer 4 settles it with Omar. The candidates are:
    - adding the build environment to the key's `environmentIds`, if that grants `snapshot.read` on snapshots saved from it (not documented);
    - an `actions` list instead of the preset (`--actions` and `--preset` exclude each other);
    - whatever Boat says.
- **It sits next to the issuer's Klav key,** in the same trust zone, as ADR 0036 §4 already says ("quien roba una, roba la otra").

> **Note (2026-11-17), layer 4 review.** What Boat's create-sandbox reference says, and what `new-sandbox` does with it ([`deploy/sandbox/README.md`](../../deploy/sandbox/README.md)):
> - **The answer:** success is `202` with `{ok, type: "sandbox.created", status, ttlSeconds, sandbox: {id, name, state, …}}`. The ID is `.sandbox.id` (`bx_…`), never a top-level `id`.
> - **Retries:** the same account, `Idempotency-Key` and body give back the same sandbox for 24 hours; timeouts and `5xx` are safe to retry with the same key. A `409` `idempotency_in_progress` means "retry shortly, same key", and `idempotency_key_reused` means another body. The script makes at most 3 attempts with the same key and body, only after a lost answer, a `5xx` or that first `409`.
> - **No `4xx` proves that nothing was created.** Only curl failing to resolve or connect on the first attempt does. After the call may have been sent, the script says the machine may exist and that the Tailscale key goes to it. It never deletes the key.
> - **`ttlSeconds`:** Boat's default is 3600, so it archives the machine one hour after it was created. This ADR doesn't choose it: `BOAT_TTL_SECONDS` in the helper's `config` is the person's choice at setup, and without it the script sends nothing.
> - **The inherited environment:** the helper runs with the issuer's environment, so it fixes its own `PATH` and drops proxy and certificate variables. Its `config`, which decides where the secrets go, must be writable only by the issuer's user.

> **Note (2026-11-18), layer 6.** The first daily sandbox settled the Boat key's open question: a key with the `ci` preset, limited to the daily and the build environments, deployed the saved template. The run doesn't show whether a key limited to the daily environment alone could. The script read the ID at `.sandbox.id` from Boat's `2xx` answer. Where Boat's `409` puts its error code is still unseen ([try-sandboxes.md](../try-sandboxes.md#what-the-real-run-of-2026-11-18-taught)).

## 6. The Boat key and Klav: now and later
ADR 0036 E6.1 said the command could be `klav agent run …`, so that the Boat key also arrives through Klav. That doesn't fit an issuer as Klav makes them today:

- `klav agent run` needs `inject` on a project, and `klav agent register` tells the person never to give an issuer projects;
- the owner's issuer has `--inject-ask`, so each start would wait for an approval;
- an issuer with `inject` can hand a token to the command that creates the sandbox (T171, residual risk 63).

**For now (Omar's decision 2):** the Boat key belongs to the issuer's system user on the proxy's host, and doesn't come from Klav. ADR 0036 E6.1 now carries a note pointing here.

**What it would take later,** each with its own decision:
- **(a) A `boat` profile on the proxy, used through the signed issuer API,** never the loopback listener. The helper calls Boat's HTTP API, and Boat's CLI also takes `--api-url` (env `BOAT_API_URL`), so neither needs a change on Boat's side.
- **(b) The proxy creates the Boat machine itself,** the way the later route creates the Tailscale key. That moves the provider's whole API into Klav's proxy.
- **(c) A second agent, not the issuer,** with `inject` on the Boat key only and `ask`. It is still a Klav key on the same host, so it gains little.

## 7. The template and the environments (decision 3)
**Omar's decision (P6 (a)):** a script and a manifest under `deploy/sandbox-template/`, rebuilt and renamed for each Klav release.

- **Where it is built: a normal machine, never `--no-env`,** in a **build environment** made only for this. A snapshot of a `--no-env` machine stays `--no-env` forever, so it could never receive the daily environment's logins.
  - **The build environment has everything off:** *Safe for third parties* off (it would be as permanent as `--no-env`), and each toggle off. That means no variables, no secret files, no GitHub, no boat credentials (the in-sandbox Boat key) and no agent logins. It has no AI profile and no setup script. Boat's docs don't give the toggles' defaults, so Omar sets each one.
  - **The build machine gets no `-e` at all:** a saved snapshot replays the source's `--env` values on every deploy.
- **What goes in:**
  - **`klav-forward` from the release commit:**
    - where from: until a release carries it, the Linux artifact of the release's CI run ([releasing.md](../releasing.md) §1 and §6);
    - checked: its SHA-256 is written in the manifest and checked in the machine before the binary is installed;
    - which commit: `klav-forward --version` must name the same commit as the `klav` that prints the setup lines (ADR 0036, note of 2026-11-15).
  - **Tailscale** from its signed apt repository, with the service disabled. (Note, 2026-11-17: disabled is not enough, since §1 quotes Boat: enabled systemd services start again after a snapshot, and a package update can enable one again. The unit is **masked**, and `check-template` refuses anything but `masked`.)
  - **`klav-tailnet-up`** (§4), owned by root.
  - **Pinned versions** of `jq`, the Northflank CLI and the agent CLIs.
- **What must never be in it.** The script checks each item before `boat snapshot`, and refuses to save otherwise:
  - **Tailscale state:** `/var/lib/tailscale` must be empty, and no `tailscaled` running;
  - **forwarder state:** no `~/.klav-forward`, no claim marker, no skill copy from a run;
  - **agent logins:** for example `~/.claude/.credentials.json` and `~/.codex/auth.json`, and any other login file of the pinned agent CLIs;
  - **git and GitHub credentials:** no `~/.git-credentials` and no `~/.config/gh/hosts.yml`;
  - **SSH keys:** no private key under `~/.ssh` or `/root/.ssh`;
  - **Boat's keys:** no in-sandbox Boat key or other Boat login (`~/.config/ascii`);
  - **secret strings:** no `ksb1_`, `tskey-` or `boat_` string under `/home`, `/root`, `/etc` or `/var`. (Note, 2026-11-17: a snapshot saves the whole disk, so the check scans all of it except `/proc`, `/sys`, `/dev` and `/run`. It excuses only the two Klav files that match the build record, Debian packages' unchanged files, and the files on the manifest's allow list, each by its path and SHA-256: [`deploy/sandbox-template/README.md`](../../deploy/sandbox-template/README.md). The first real build showed files of Boat's base image that name `boat_` and hold no key.)
  - **variables:** none set with `-e`.
- **Naming:** `klav-sandbox-<version>`, a new name for each release, so a running sandbox's template never changes under it. The previous one is removed once nothing deploys it.
- **Reproducible enough:** pinned versions and recorded hashes, not a bit-for-bit image. Boat's snapshot is a disk, not a build.
- **The template of the 2026-11-17 run is replaced.** It was saved from a `--no-env` machine.

**Omar's decision (P7 (a)): the daily environment.**
- **What it holds:** a Boat environment named for this, with *Safe for third parties* off and two things on:
  - the agent's model login (Agents credentials, and its AI profile);
  - a GitHub token limited to the repositories the sandboxes work on, with the setup script that runs `klav-tailnet-up` and the `klav sandbox start` lines.
- **What it doesn't hold:** no secrets, no boat credentials and no provider token.
- **How sandboxes use it:** they start with `from: klav-sandbox-<version>` and `environment: <daily>`.
- **What stays exposed:** the model login and the git token are in the sandbox and can be copied, as anything in it can (ADR 0036 §18). Klav keeps only provider tokens and Klav keys out.

> **Note (2026-11-18), the GitHub token.** The first daily sandbox showed that the token Boat puts in a sandbox reaches every repository its GitHub App's installation covers, with the installation's permissions, whatever repositories the environment lists: those decide what is cloned. So "limited to the repositories the sandboxes work on", here and in P7, holds only as far as that installation is limited. Omar accepted this the same day, because the sandboxes sometimes work on several repositories. To narrow it, limit the app's installation to selected repositories in GitHub ([try-sandboxes.md](../try-sandboxes.md#14-a-daily-sandbox) §14.4).

## 8. Networks other than Tailscale
They stay as ADR 0036 has them. The channel is TLS 1.3 with pinned keys, on any address the sandbox reaches: Railway's TCP Proxy, a public VPS port, or a blind relay later.

Without Tailscale:
- the helper creates no key, and `KLAV_TAILNET_KEY` is unset;
- `klav-tailnet-up` skips;
- nothing in this ADR is needed.

ADR 0036's warning about a channel port open to the internet still applies ([self-hosting.md](../self-hosting.md) §9.2).

## 9. Open product question: what a sandbox may reach on the person's network (decision 4)
**Omar's decision:** that other devices are visible to the sandbox's node is fine, and sometimes Omar wants a sandbox to reach one (by SSH, for example). **Omar's idea:** Klav asks the person what a sandbox may reach. **Nothing is decided here; Omar was not asked about P8.**

**What visibility means.** Tailscale documents it: a node sees the devices it may connect to, and "All devices that can connect to your device". The run's node saw other devices it couldn't reach. So the tailnet's policy lets those devices connect to `tag:klav-sandbox`.
- **The person can change that** with their own rules: a rule set that lets nothing connect to `tag:klav-sandbox` also hides those devices from it.
- **Klav doesn't change it,** because it never edits the policy.

**My recommendation (P8), not a decision:**
- **The tailnet's policy stays the person's.** Klav never edits it, because that needs a credential with the policy scope, much wider than `auth_keys`.
- **The person makes one tag per kind of reach,** for example `tag:klav-sandbox` (the proxy only) and `tag:klav-sandbox-ssh` (the proxy, plus port 22 of named devices). Each rule says what the tag reaches, and which devices may connect to it, which decides what it sees.
- **Reach tags own nothing.** A sandbox with root could otherwise switch to a tag its own tag owns. One OAuth client that makes keys for several reach tags carries a tag-owner tag, for example `tag:klav-sandbox-owner`, which owns them and which no node ever carries.
- **`klav proxy issuer add` asks once which of those tags this issuer may request,** shows what each reaches according to the person, and signs the list into the issuer's grant.
- **`klav sandbox start --reach ssh`** picks one, and the proxy refuses a tag outside the issuer's list.
- **It needs the later route of §2:** with the helper, the tag is only the script's convention.

## 10. Layers
Each is one PR with its test and its roadmap box.

### The route decided now (no server change)

| # | What changes | How it is tested | Omar's hands |
|---|---|---|---|
| 1 | This ADR, and the run recorded in the roadmap, the hand-test guide and ADR 0036 | Docs only | — |
| 2 | `klav-proxy serve --no-local-calls` (§3), with its line in self-hosting | An end-to-end test in `klav-proxy`: a local profile call gets `403`, and the signed issuer API still works | Adds the flag to the proxy's `serve` command |
| 3 | `deploy/sandbox-template/`: the build script, the "never in it" checks, the manifest and `klav-tailnet-up` (§4, §7) | `shellcheck`.<br>The checks run against a directory seeded with each forbidden file and string.<br>`klav-tailnet-up` runs against fake `tailscale` and `tailscaled` that record their arguments and environment. The cases: the key is never an argument; the key file is removed when `up` fails under `set -e`; the socket wait and the `up` timeout; a missing tag leads to `logout` and exit 1; an empty input skips; a node already up is a rerun | Creates the build environment with everything off. Builds and saves the template for each release |
| 4 | `deploy/sandbox/new-sandbox` (§5): the token trade, the key with the fixed body, and Boat's API with the body on standard input | `shellcheck`.<br>A fake `curl` that records its arguments: no secret ever in them, and the body of each call checked.<br>`KLAV_TAILNET_KEY` only when a key was made.<br>Nothing printed but Boat's sandbox ID | Creates the OAuth client (`auth_keys`, `tag:klav-sandbox`), with `tagOwners` (the person owns the tag, and it owns nothing) and the rule. Writes the two 0600 files on the host. Settles the Boat key's `snapshot.read` (§5) |
| 5 | The Boat side, no code: the daily environment (§7) and the Boat key (§5) | One sandbox from the template, in the daily environment, logs in its agent | All of it |
| 6 | One daily sandbox end to end, and a daily-use section in [try-sandboxes.md](../try-sandboxes.md) | The guide, run once | Runs it |

**Order:** layers 2 and 3 can start at once. Layer 4 follows 3, so the variable names match. Layer 5 runs alongside, and layer 6 comes last.

### The later proxy route (not scheduled)

| # | What changes | Server change? |
|---|---|---|
| L1 | The `oauth2-client-credentials` profile kind (§2, "Later"): never served by `forward`, refused in issuer grants, rules only for the token path and `POST …/keys`; spec §13.4 with vectors | **Yes**, and a device round with `--every-device-is-updated` |
| L2 | The proxy makes the trade and creates the key in `start` (P2 (a)); `"tailnet"` in the issuer API ([api.md](../api.md) §8.9); `klav sandbox start --tailnet` sets `KLAV_TAILNET_KEY` and redacts it (P3 (a)); the helper stops holding the OAuth client | No beyond L1 (§1) |
| L3 | P8, once Omar answers | If it changes the issuer grant |

## 11. Threats
New credentials on the proxy's host, and what a thief gets.

| Credential | Where it lives | Stolen, it gives | Stops it |
|---|---|---|---|
| Tailscale OAuth client (now) | A 0600 file of the issuer's system user. The issuer is an agent and its commands can read it | Unlimited auth keys carrying `tag:klav-sandbox`: reusable, non-ephemeral, up to 90 days. The bound in §2 holds only under its three assumptions (the rule reaches only `tag:klav-proxy` on `tcp:8443`; `tag:klav-sandbox` owns no tag; keys are pre-approved). Under them, the thief's nodes can do two things. They see the devices the policy lets connect to the tag (§9). They can tie up the channel's handshakes, as any client reaching the port can ([self-hosting.md](../self-hosting.md) §9.2). Klav's log records none of it | Revoke the client in Tailscale ("Trust credentials don't expire"). Keys and nodes it made stay until deleted |
| The one-hour access token | The helper's memory, for one run | The same as the client, for at most one hour | Expiry |
| One sandbox's auth key | Boat's stored `env`, then a 0600 file in `/run` for a moment | One node with the tag, within the hour, if not used yet; nothing once used | Single use; the claim still needs the package |
| User API access token (rejected) | — | Everything Omar can do in the tailnet | Not used |
| Boat API key (§5) | A 0600 file of the issuer's system user | Within its scope: create sandboxes from the template, in the daily environment. Those receive its model login and git token. It can also delete "the sandboxes this key created", and spend money | Revoke it at Boat; a short TTL and the environment limit |
| The loopback listener (§3) | — | Today, every process on the host uses every profile, with no identity | `--no-local-calls` and a single-purpose host |

**Residual:**
- **The proxy's host holds four secrets together:** the proxy key, the issuer key, the Boat key and the Tailscale client. Whoever owns that host owns all four. ADR 0036 §4 and §11 already say so for the first two.
- **A sandbox's node can stay on the tailnet for up to an hour** after its sandbox ends (ephemeral removal). It reaches only the channel port, where its channel key no longer works.
- **The daily environment's model login and git token are inside every sandbox.** Klav doesn't protect them; §7 keeps them narrow.
- **Boat keeps every `env` value,** the package and the Tailscale key included. Both are spent or useless within minutes, but someone who reads Boat's copy first wins the race. With the package, Klav notices (the theft signal). With the key, the sandbox just can't claim.

The threat model ([modelo-de-amenazas.md](../modelo-de-amenazas.md) §5.17) gains rows for these with layer 4, when the helper exists. This ADR doesn't add IDs.

> **Note (2026-11-17).** The helper exists (layer 4), but its rows are not in the threat model yet. They come in their own docs PR, numbered on `main` once the two open ADR PRs that also add rows have landed, so their IDs don't collide.

## 12. Rejected alternatives
- **A user API access token through a plain profile:** it works with today's proxy, but it gives every local caller Omar's rights over `POST …/keys`: untagged, reusable keys and, by inference, trust credentials that never expire (§2).
- **The OAuth client secret as the auth key in the sandbox** (`tailscale up --auth-key=tskey-client-…`): a credential that never expires, inside a machine others can copy.
- **The Tailscale key inside the `ksb1_` package:** a format version for a value Klav doesn't own (P3).
- **`klav-forward` running `tailscaled`:** root in a binary that is meant to need none.
- **`boat new -e KLAV_SANDBOX=…` from the helper:** the package on a command line every user of the host can read (§5).
- **A template saved from a `--no-env` machine, or in an environment safe for third parties:** Boat keeps that flag forever, so its sandboxes never receive a login (§7).

## 13. Omar's answers (2026-11-17) and what is still open

| # | Answer |
|---|---|
| P1 | **A new option:** the scoped OAuth client lives on the proxy's host now, and the helper uses it (§2). The proxy doing the trade itself stays as later work, not scheduled. The user API token stays rejected. Omar accepted the costs listed in §2 |
| P2 | **(a)**, for the later route: the proxy creates the key inside `klav sandbox start`, with a body it builds |
| P3 | **(a):** a second variable, `KLAV_TAILNET_KEY`, never a `ksb2_` package (§4) |
| P4 | **The helper calls Boat's API directly, with the body on standard input.** No test of `boat new -e NAME`, and never the package on a command line (§5) |
| P5 | **(a):** the narrow Boat key, plus whatever it needs to read the template (§5) |
| P6 | **(a):** a script and a manifest under `deploy/sandbox-template/`, rebuilt and renamed for each release, built in a normal machine of an empty build environment (§7) |
| P7 | **(a):** the model login and a GitHub token limited to the repositories the sandboxes work on (§7) |
| P9 | **(a):** `--no-local-calls` on Omar's proxy, with the default unchanged for now (§3) |
| P10 | **(a):** the proxy's host is single-purpose (§3) |

**Still open: P8,** what a sandbox may reach on the person's network (§9). Omar was not asked. The text in §9 is my recommendation, and nothing there is decided.

## Consequences
- **No format, protocol or server change** in the route decided now. The later route adds a profile kind (spec §13.4, with vectors), a server that accepts it, and `"tailnet"` in the issuer API.
- **CLI:** `klav-proxy serve --no-local-calls`. `klav sandbox start` is unchanged until the later route.
- **New files:** `deploy/sandbox-template/` (the build script, the checks, the manifest and `klav-tailnet-up`) and `deploy/sandbox/new-sandbox`.
- **Dependencies:** none in the Rust workspace. The template pins `jq`, Tailscale and the CLIs it carries.
- **Omar's hands:**
  - in Tailscale: the OAuth client, the tag, `tagOwners` and the rule;
  - at Boat: the build environment, the daily environment and the Boat key;
  - on the proxy's host: the two 0600 files;
  - for each release: building the template.
- **Docs:** the roadmap's sandbox section, [try-sandboxes.md](../try-sandboxes.md), [self-hosting.md](../self-hosting.md) §9, and the threat model with layer 4.
