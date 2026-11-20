# 0032 · Environments per repository

- Status: accepted
- Date: 2026-11-05

> Omar answered the core decisions and the three questions of PR #176, and added that references inherit the protection (§"Omar's answer", answers 6–9). Accepted on 2026-11-05.

## Context
Today a repository connects to Klav through its `klav.toml` (`cli.md` §5): an `[env]` table that gives each variable a `klav://…` reference, plus `[files]`. `klav run` confirms it the first time and every time it changes (`trusted-projects.json`, by path and exact text) and puts the values in the child process's environment (`cli.md` §6). It works, but it falls short:

- **There are no environments.** The same repository needs `development`, `staging` and `production`, with the same variable names and different values. Today that means three `klav.toml` files or three sets of names by hand.
- **A variable is an item.** The `staging` `DATABASE_URL` has to live in a separate login or API key, with a made-up title. A 30-line `.env` is 30 items, and there is no natural way to import it.
- **The repository and the project don't know each other.** The person writes `project = "Trabajo/acme-api"`, and nothing warns if a `klav.toml` asks for secrets from another project.
- **Production can't be told apart.** A production variable is injected the same way as a development one, and an agent gets it with the same `inject` in `allow` (design §5.2) as everything else in the project.

Omar asked to manage variables **per project and per environment**: link a repository to a Klav project, store one set of variables per environment and run `klav run --env production -- …`. Omar also asked whether Klav should be split into "Klav dev" and "Klav user".

### What was researched
Only what applies to Klav:

- **1Password Environments** ([docs](https://www.1password.dev/environments), [local `.env`](https://www.1password.dev/environments/local-env-file)). An "Environment" is a set of variables imported from a `.env` and delivered in three ways: `op run --environment <ID>`, an SDK, or a "mounted" `.env` that is really a named pipe (FIFO) and never touches the disk. Each read of the mount asks for authorization. It is exactly the `--fifo` of `klav inject` (`cli.md` §7). It all lives behind the switch **Settings › Developer › "Show 1Password Developer Experience"**, which adds the *Developer* section (SSH agent, CLI, Environments) to the sidebar ([community](https://www.1password.community/developers-69/enabling-environments-on-linux-23883)).
- **`op run`** ([docs](https://developer.1password.com/docs/cli/reference/commands/run/)). It looks for `op://bóveda/elemento/campo` references in the environment or in an `--env-file`, resolves them and launches the child. It masks literal values in the output (`<concealed by 1Password>`), like Klav's `Redactor`, with the same limit: an encoded value gets through.
- **Doppler** ([CLI](https://docs.doppler.com/docs/install-cli), [configuration](https://docs.doppler.com/docs/environment-based-configuration)). A *project* has *configs* (`dev`, `stg`, `prd`). `doppler setup` binds a directory to a project and a config, and stores it **outside the repository** (`~/.doppler/.doppler.yaml`, by path). An optional `doppler.yaml` in the repository only proposes the project and the config. Klav does the same: the pin lives in `$KLAV_HOME`, by path, and the repository's file only proposes.
- **Infisical** ([projects](https://infisical.mintlify.app/documentation/platform/secrets-mgmt/project)). Environments per project, references between secrets, and personal values that override the shared one. Personal values exist **only for people, never for machine identities**. Klav doesn't adopt them in this ADR (§"Later"), but takes the idea that an agent's things and a person's things don't mix.
- **dotenv-vault** ([notice](https://dotenvx.com/docs/env-vault-file/)). It has been deprecated since May 2024. Its replacement, **dotenvx**, encrypts each `.env` in the repository, with one private key per environment (`DOTENV_PRIVATE_KEY_PRODUCTION`). One key per environment is what Klav achieves with per-environment permissions without handing out loose keys. Encrypted secrets living in the repository doesn't apply to Klav: the repository only carries references.

## Omar's answer (2026-11-05)

Core decisions, in the brief:

1. **Production asks for Touch ID.** It holds for the whole environment, not variable by variable: one confirmation per `klav run --env production` (or `inject`), and one each time a production value is copied or revealed in an app. Where there is no Touch ID, the master password. An agent never gets production without an approval. "Production" is defined by a per-environment flag, `protected`, which is on by default in an environment named `production` or `prod` (§3).
2. **Accepts a new item kind, "Environment"** (not a tag): one item per project and environment with N variables, each with its own value or a `klav://` reference to a field that already exists (§1).
3. **Accepts the repository–project link that only suggests.** The project stores, encrypted, the identifiers of its repositories. The link never grants anything or skips the `klav run` confirmation (§2).
4. **Accepts per-environment agent permissions** on the grant and policy model of ADRs 0006 and 0014, without a parallel one (§4).
5. **Personal use and development use** (§7): a single product, not split. The "Development" switch is **on by default in every account**, created from an app or from the CLI, because Klav is made for agents first. It stays in Settings, so that someone who only wants passwords can hide projects, environments, agents and the SSH key and API key kinds. **There is no question at sign-up** ("What will you use Klav for?").

Answers to the questions of PR #176:

6. **Production is protected with the policy and the agent runtime**, without separately encrypting protected environments with the vault key (§4.4, residual risk 44).
7. **An agent can write to a protected environment**, with an approval each time (`update` in `ask once`). The person's next `klav run` shows which variables it changed (§3).
8. **`klav run` without `--env` doesn't pick `development` on its own.** It uses `default_env` or the only environment there is; if there are several, it asks for `--env` (§5).
9. **New decision: references inherit the protection.** It replaces the proposal's "just warn". An item a `klav://` reference points to from a protected environment becomes protected too for agents: any access by an agent asks for the same `ask once` approval, with Touch ID, as production, even if the agent has a direct `allow` on that item. In the person's apps, copying or showing that item follows the production rule. It has to be impossible to bypass (§3.1).

## Decision

### 1. The "Environment" item
A new item kind, `environment`, in the usual format: two sections `0x10`/`0x11` sealed with its item key (spec §7). No new blob type is needed, and the AAD isn't touched.

- **One item per (project, environment).** The environment's name is the item's `title`, so the rule of unique titles per project (roadmap, phase 4.1) also prevents two `production` in a project. For the `environment` kind, the title also matches `[a-z0-9][a-z0-9_-]{0,63}`, so that `--env` and `klav://` write it without quotes.
- **Variables aren't `fields`.** A field name is `[a-z0-9][a-z0-9_-]{0,63}` (spec §7.1) and a variable is called `STRIPE_KEY`. They go in their own list, `variables`, with names `[A-Za-z_][A-Za-z0-9_]{0,127}`, unique and **case-sensitive**.
- **Each variable carries a value or a reference, never both:**
  - **Value:** secret, kept as `SecretValue` in memory, like a `concealed` field. It never goes in the *overview*.
  - **Reference:** `klav://` to a field of **another item that isn't an environment**, in any project or vault of the account. That way the Stripe key isn't duplicated, and rotating it in its login changes it in every environment that uses it. Pointing from one environment to another isn't allowed: there are no chains or cycles to resolve. `klav env set` stores the reference by ID (`klav://<bóveda>/<proyecto>/<elemento>/<campo>` with UUIDs, design §3), so that it doesn't break on rename, and shows it by name.
  - **Reference to an attachment** (a `file` field): the variable receives the attachment's content if it is UTF-8 of up to 64 KiB (a `.pem`); if not, `run` fails before running anything. For a `.p8` or a binary, `[files]` in `klav.toml` is still the way.
  - **A reference resolves with the permissions of the item it points to.** If the environment is protected, that item becomes protected too (§3.1).

**Schema** (added to spec §7.1 with the code; `v` stays at 1):

*Overview*, for the `environment` kind (it carries no secrets):

| Key | Type | Required | Notes |
|---|---|---|---|
| `title` | text | yes | the environment's name, with the rule above |
| `environment` | object | yes | `{protected: bool, variables: [nombre…]}`; only with `kind = environment` |
| `tags` | list | no | as in any item |

*Details*:

| Key | Type | Required | Notes |
|---|---|---|---|
| `variables` | list | yes | `{name, value}` or `{name, ref}`; only with `kind = environment` |
| `notes` | text | no | as in any item |

- When rebuilding the item, the client checks that the *overview*'s `environment.variables` is exactly the list of names in *details*, in the same order. If not, `SectionMismatch`, as today with `username`.
- An environment carries no `urls`, `fields`, `attachments`, `passkey` or `password_record`. The `[files]` stay in `klav.toml` (§5).
- **What the server sees:** the same as for any item: its ID, the project, the version, the size of the blobs and who wrote it (ADR 0030 §7). It doesn't see the kind, the environment's name, the `protected` flag, the variable names or the references, which go inside the encrypted sections. The size lets one guess roughly how many variables there are, like that of any note.
- **References to a variable:** `klav://Trabajo/acme-api/production/STRIPE_KEY`. If the item is an environment, the fourth segment is the name of a variable and is case-sensitive; in the other kinds it is still the name of a field. It works for `klav inject` with a template and for `-e`.
- **Vectors:** `docs/vectores/entorno.json`, with a sample *overview* and *details* (one with a value and one with a reference), negative cases (repeated variable name, value and reference at once, reference to another environment and lists that don't match) and cases of the protected set of §3.1 (entries of the person's and an agent's versions, and the resulting set).

**Compatibility.** An old client that finds `kind = environment` can't read it: `ItemKind` rejects it, the item shows as "does not decrypt" and is skipped (`klav-client`, `session.rs`). It breaks nothing else: it can't edit or overwrite it. The first code layer makes that warning say "unknown item kind; update Klav" instead of "does not decrypt", so it doesn't look like tampering.

### 2. Repository–project link

**Where it lives.** The project metadata (`0x13`, spec §7.2) gains an optional `repos` key, a list of normalized identifiers, sealed with the project key like the name. The person sees it and, with a grant for the project, so does their agent, which works in that repository anyway.

**Normalization.** From the git `remote` comes `host/dueño/repo`:

- lowercase, without `.git`, without a trailing `/`;
- without user, password, scheme or port;
- `git@github.com:omar/acme-api.git`, `ssh://git@github.com:22/omar/acme-api` and `https://github.com/Omar/acme-api` give `github.com/omar/acme-api`;
- paths with groups (`gitlab.com/grupo/sub/repo`) are stored whole.

`origin` is used. If it doesn't exist and there are several remotes, or if `origin` and `upstream` differ (a *fork*), `klav env link` asks once which one, and remembers it in that directory's local pin (§5).

**Commands:** `klav env link [Bóveda/Proyecto] [--remote NOMBRE]` adds the current repository's identifier to the project and offers to write `project = …` in the `klav.toml`. `klav env unlink` removes it.

**Compatibility: readers first.** `ProjectMeta` rejects unknown keys (`deny_unknown_fields`), and a project whose metadata doesn't open is skipped **entirely**, with all its items ("in an unknown project"). So the order matters:

1. The first layer teaches `klav-core` to accept `repos` (and the `environment` kind) in every reader: CLI, `klavd`, extension, `KlavFFI`/iOS and the agents' runtime.
2. `klav env link` arrives in a later layer, after the previous one is published on TestFlight and in the extension Omar uses.

Remaining risk: an installation that hasn't updated stops seeing the linked project until it updates. When this was decided (2026-11-05), Klav had no users besides Omar, so it was cheap. The alternative, storing the link in a system item of the project that old clients skip, and only that item, is in "Rejected alternatives".

**Security: the link only suggests.** Whoever made the repository controls the URL of a `remote`. A malicious cloned repository can set `origin` to `github.com/omar/acme-api`. That is why:

- The link **never grants anything**: it doesn't widen what a `klav.toml` asks for, it doesn't give permissions to any agent, and it doesn't skip the `klav run` confirmation.
- **It only serves to:**
  - propose the project when there is no `klav.toml` or it doesn't say `project` ("This repository looks like Trabajo/acme-api, by `origin` = `github.com/omar/acme-api`. Use it?"), and that answer goes through the same confirmation;
  - **warn**, in the `klav run` confirmation, when the `klav.toml` asks for a `project` that doesn't have this repository linked, or references outside the linked project: "This `klav.toml` asks for secrets from Personal/banco, which isn't linked to `github.com/omar/acme-api`".
- **The trust pin stays the same:** by path and by exact text in `trusted-projects.json` (`cli.md` §5). The link doesn't change the pin's key or count as an approval.

### 3. Production: the `protected` flag
- **What it is.** A per-environment flag, in the *overview* (`environment.protected`). When an environment is created, it turns on by itself if it is called `production` or `prod` (case-insensitive); in the others it is off. The person can change it: turning it on asks for nothing, turning it off asks for Touch ID (or the password), because it lowers the protection.
- **Who decides it.** An agent with `update` could rewrite the *overview* and turn it off. That is why the flag that counts is the one of the **latest version written by the person**, with the per-version authorship of ADR 0030 §7, the same one that decides the confirmed sites. If no version is the person's (an agent created it), the environment is protected if its flag is on **or** if it is called `production`/`prod`: it fails closed.
- **For the person:**
  - **CLI:** one confirmation per `klav run --env production` or `klav inject --env production`, covering all its variables and references. It is the presence check that already exists for approving (ADR 0014 §5.4): Touch ID with `LAContext` through `klavd`, or the master password with `--no-daemon` or without Touch ID. `--trust` doesn't skip it. Without Touch ID and without a terminal (a script on Linux), it fails: production doesn't run without someone in front of it.
  - **If an agent changed values since the person's latest version** (answer 7), the confirmation says so before asking for Touch ID: "`DATABASE_URL` and `REDIS_URL` were changed by *mi-agente* on Nov 5". That way a `DATABASE_URL` changed to someone else's host doesn't get through unseen.
  - **Apps** (*popup*, iOS, Mac): one confirmation per copy or per "Show" of a value from a protected environment. The other environments are copied and shown like any item with the vault open.
- **For agents**, in §4.

### 3.1 References inherit the protection (answer 9)
An item a reference from a protected environment points to becomes **protected**: the whole item, with all its fields and attachments, not only the field it points to. What is protected is the value, not a particular path to it.

**The protected set.**

- **Only the person's versions count.** For each environment, its latest version written by the person is taken (ADR 0030 §7). If the environment is protected in that version (§3), the target item of each `ref` of its `variables` goes into the set.
- **An agent doesn't shrink it.** If an agent removes a reference, moves it to another environment or turns off `protected`, it writes an agent version, which doesn't count. The item stays protected until the person writes a version without that reference.
- **An environment an agent created** (with no version by the person) adds nothing to the set: its references don't protect other items. Its own values are protected if it is called `production` or `prod` (§3).
- **Other projects and other vaults.** A reference counts the same wherever it points. The protected item is the target, even if it is in a project the agent has and the environment doesn't.
- **Attachments.** A reference to a `file` field protects the whole item, with its attachments. Delivering attachments to agents (ADR 0016) goes through the same approval.
- **A single function.** `klav-core` computes the set (`protected_set`), a pure function over the person's versions of the environments, with vectors in `entorno.json`. `klav-client` (CLI and `klavd`), `KlavFFI`/iOS and the grant issuer use it.

**What changes for an agent.** On a protected item, `fill`, `inject`, `reveal`, `totp`, `update` and `delete` become `ask once`, even if the grant says `allow`; `list` doesn't change. Since an `ask once` target doesn't go into tasks (§4.2), and `passkey` and `rotate` only exist inside a task (ADR 0021), a protected item doesn't allow those two either.

**How it reaches agents: inside the signed grant.** The server can't read references, and an agent's runtime may not see the environment (it is in another project). That is why the person's client writes the set into the grant of every agent that has the project of a protected item:

- They are `ask once` rules with `items: [IDs]` for those permissions, with the mark `origin: "protected"`.
- The most restrictive wins (ADR 0006 §3), so a direct `allow` on the item doesn't open it.
- If that permission had no rules in the grant, the client first writes its default value as an explicit project rule. Without it, the inherited rule would leave everything else in `deny` (ADR 0006 §2).
- **The server and the agent runtime apply them.** The runtime verifies the grant's signature with the account's pinned identity and evaluates that policy, as today. Both barriers come from the same signed document.
- `Policy`, `Rule` and `Scope` reject unknown fields (`deny_unknown_fields`). A runtime or a server without this version rejects a grant with `items` or `once`, instead of reading it without them: it fails closed.

**When writing, the grant first.** When the person saves a version of an environment that makes the set **grow** (a new reference in a protected environment, or turning on `protected`), the client:

1. computes the new set;
2. reissues and uploads the affected grants (version + 1);
3. and only then uploads the environment's version.

If step 2 fails, the version isn't saved and the error says so ("couldn't protect Stripe for *mi-agente*: without a network the reference isn't saved"). To **shrink** the set (removing the reference, or turning off `protected`, which already asks for Touch ID) the order is the reverse: first the version, then the grants. If the grants fail, the item stays over-protected until the next `sync`, which retries it: it fails closed.

**When reissuing, the set only shrinks with proof.** A device can reissue a grant for other reasons: a rotation, a change of permissions, a new environment. So that one with an old cache doesn't erase a protection another one added:

- it keeps every `origin: "protected"` rule of the current grant the account signed;
- it only removes an item if it has the person's version of the environment that left it out, and then names it in the grant's `released: [IDs]`;
- before signing a grant it syncs, and if the sync fails or gives a *rollback* warning, it doesn't sign;
- **the server answers `409`** to a new grant that loses an `origin: "protected"` rule from the previous one without naming the item in `released`. It is a second barrier against an old client or one with an old cache; a malicious server gains nothing by skipping it, because the agent runtime still applies the grant the account signed.

**Where `klavd` evaluates it, also with an old cache.** `klavd` keeps the set in its encrypted cache (`0x41`), along with the person's latest version of each environment, with its *details* (it extends the cache of ADR 0030 §7, which today only keeps the URLs). It uses it in four places:

- **Copy and Show** in the *popup* and the Mac app, and `klav item get --reveal`/`klav env show --reveal` in the CLI: Touch ID every time, like production.
- **The person's `klav run` and `inject`:** if any reference it resolves is in the set, one confirmation with Touch ID for the whole command, even if the requested environment isn't production ("uses Stripe, protected by *production*").
- **Approval and task cards:** a target in the set appears without "Approve 15 min" and can't be checked in a task, even if the request the server sent doesn't say so. That way, an old grant isn't enough to open it from the person's surfaces.
- **When issuing grants**, with the rules above.

With an old cache, it fails closed:

- the cached set **only grows** when syncing; an item leaves it only when `klavd` has the person's version of the environment that left it out;
- the `origin: "protected"` rules of the current grants, which `klavd` reads and verifies, also feed it, so a protection another device added arrives even if `klavd` doesn't have that environment yet;
- if the person's version of a protected environment isn't in the cache and can't be downloaded, or doesn't open, `klavd` doesn't know what it protects. Meanwhile, Copy, Show, `run` and `inject` of **any** item in that vault ask for Touch ID, and `klavd` doesn't issue grants. It is rare (a network or server failure) and the next good sync fixes it.

iOS (`KlavFFI`) applies the same rules with Face ID.

**What doesn't change for the person.** Browser autofill and the iOS Credential Provider for a protected login stay as today: they only fill on their confirmed sites (T61). Omar asked for the rule for copying and showing, not for every sign-in (residual risk 45).

**One approval per agent `run`.** `run_with_secrets` with an environment asks for **one** approval for the environment and the protected items its references point to:

- The approval's `request` lists their IDs in `items`. The signed bytes of §13.5 already carry the whole `request`, so no new format is needed.
- The person's card checks that those IDs are references of the person's version of that environment, and warns if the agent asked for something the environment doesn't use.
- The approval is good for one access to each item in the list, within that call. The server spends it when those accesses are done or when it expires.

### 4. Per-environment agent permissions
The usual model is used (ADRs 0006 and 0014). Two additions to the policy are needed.

**4.1 Per-item scope.** `Scope` today has vaults, projects, tags, domains and hours. It gains `items: [ItemId]`, by ID only (like vaults and projects in a grant: the server doesn't see names). Tags are ruled out because the agent declares them in the request (ADR 0014 §4.2), so a tag rule on production doesn't stop whoever stole the agent's key. The item ID, on the other hand, goes in every signed request and the server checks it. It meets rule 6 of ADR 0006: it is one more dimension, AND across dimensions and OR within the list.

**4.2 "Ask every time".** An `ask` rule gains the optional flag `once`. An approval given under that rule:

- can't carry a lease: the server rejects a decision with `lease_until_ms > 0` for that target, and the apps don't offer "Approve 15 min";
- is spent in a single use, like a one-time approval today (ADR 0015 §2). Reuse within the next 10 minutes still holds for the retry that spends it, but not for a second use;
- doesn't go into tasks: `propose` leaves that target unchecked ("Always asks for approval") and `TaskDecision` rejects a decision that includes it, as ADR 0030 §6 does with site permissions on an item without a site: the row isn't checked and can't be checked;
- is decided with presence, like any approval (ADR 0014 §5.4): Touch ID on the Mac, Face ID on iOS, or the master password where there is no biometry.

A `once` only makes sense with `ask`: in `allow` or `deny` the client doesn't sign it and the server answers `400`.

**4.3 How it translates.** `klav agent approve` and `klav agent grant` gain `--env NOMBRE=allow|ask|deny`, and the apps one row per environment. The person's client builds `inject` rules with each environment's ID. Two rules of ADR 0006 have to be respected:

- **§2:** as soon as a permission has rules, its default value stops applying.
- **§3:** among the rules that apply, the most restrictive wins.

Example: `development` in `allow`, `staging` in `ask`, and the rest of the project as it was, with `inject` in `allow` by default. `production` points to the Stripe API key, which is in another project the agent also has:

```
inject  allow        { projects: [acme-api] }                       ← el valor por defecto, ahora explícito
inject  ask          { projects: [acme-api], items: [staging] }
inject  ask  once    { projects: [acme-api], items: [production] }  ← lo pone Klav solo, por estar protegido
inject  ask  once    { items: [stripe] }   origin: protected        ← heredada por la referencia (§3.1)
```

`development` only matches the first rule, so it goes in `allow`. `staging` matches two, and `ask` wins. `production` and the Stripe API key go in `ask once`. A login in the project stays in `allow`, as before.

- **Production can't be opened.** For a protected environment and for each item in the set of §3.1, the client always adds `ask once` to the permissions of §3.1 and refuses to sign a grant that leaves them in `allow`. By rule 3, no other rule can open them.
- **Agents that write to production** (answer 7): `update` on a protected environment goes in `ask once`. The person's next run shows which variables the agent changed (§3).
- **Limit of the translation.** An environment can't end up **more open** than a general rule that also covers it. For example, `inject: ask` for the whole project and `allow` only in `development` can't be expressed without excluding items, because `ask` wins. Klav says so when building the grant and proposes narrowing the general rule by items. If it is really needed, a later ADR adds an exclusion.
- **Environments created after the grant.** A new environment falls under the project's general rule. If it is created protected, or marked protected later, in a project shared with agents, the person's client reissues those agents' grants **before** saving the version, the same as with references (§3.1).

**4.4 Double barrier, without new cryptography** (answer 6). The server can't read `protected` or the references. The guarantee against an agent is the usual one for `ask` (T22):

- **The server** applies the `ask once` rules of the signed grant.
- **The agent runtime** (`klav-sdk`, `klav mcp`) applies the same grant. Besides, when it can read the environment, it computes its effective flag (§3) and requires a verified approval (ADR 0030 §3) even if the server says `allow`. If the server says `allow` without backing, it is a `Security` error.

What it doesn't cover: a malicious server **that also** has the stolen key of an agent with that project can deliver production, because the project key opens the environment and the protected items. Omar chose not to seal protected environments with the vault key (residual risk 44, "Rejected alternatives").

**4.5 Agents in practice.**

- `run_with_secrets` in `klav mcp` gains `environment` (next to `project`), and `klav agent run` gains `--env`.
- One approval covers the environment and its protected items in that call (§3.1).
- References to **non**-protected items are each evaluated with their own rules, in the same decision, like the attachments of ADR 0016.
- `klav agent approve --env development=allow` warns if `development` points to items the grant leaves in `deny` or that are protected: that `run` would fail or ask for approval.

### 5. `klav.toml`
Compatible with today's:

```toml
project     = "Trabajo/acme-api"
default_env = "development"            # opcional

[env.development]                      # se suma al entorno «development» de la bóveda
EXTRA_FLAG = "klav://Trabajo/acme-api/Flags/dev"

[env.production]
SENTRY_DSN = "klav://Trabajo/acme-api/Sentry/dsn"

[files]
"secrets/AuthKey.p8" = "klav://Trabajo/app-ios/APNs/key"
```

- **How `[env]` is read.** Inside `[env]`, a text value is a variable and a table is a named environment (`[env.production]`). Today's `klav.toml`, with only text in `[env]`, is read the same as today.
- **The unnamed environment.** The text variables of `[env]` form the unnamed environment: today's. If there is `default_env` and also text variables in `[env]`, it is an error that says "move them to `[env.<default_env>]`": there aren't two default environments.
- **`klav run` without `--env`** (answer 8), in this order:
  1. `default_env`, if set;
  2. if there are text variables in `[env]`, the unnamed environment, and `klav run` does **exactly** what it does today, without reading any "Environment" item;
  3. if among the `project`'s "Environment" items and the `[env.<nombre>]` tables there is **only one** environment, that one;
  4. if not, it fails before running anything and lists the environments: "there are development, staging and production: use `--env`".

  It never picks `development` by its name. If the only environment is a protected one, it asks for Touch ID as always (§3).
- **What `klav run --env NOMBRE` injects.** If a name repeats, the later source wins:
  1. the process environment's variables whose value is `klav://…`;
  2. the `project`'s "Environment" item `NOMBRE`, if it exists;
  3. `[env.NOMBRE]` in the `klav.toml`;
  4. `-e NOMBRE=REF`.

  With `--env`, the environment has to exist in the item or in the `klav.toml`; if not, it fails before running anything. The `[files]` hold for every environment. The references of `[env.NOMBRE]` in the `klav.toml` protect nothing: the set of §3.1 comes only from the vault.
- **Confirmation.** The pin is still by path and exact text. The path's entry in `trusted-projects.json` gains the list of environments already confirmed with that text. The first time the file is used with an environment, the confirmation shows what it is going to inject: the project, the environment, the **names** of its variables and where each comes from (the vault or the `klav.toml`), plus the link's warnings (§2). A protected environment, or a `run` that resolves a protected item, also asks for Touch ID **every time** (§3 and §3.1).
- **Agents.** As today (ADR 0014 §10): `klav mcp` and the SDK stay in the `klav.toml`'s `project`. Without `environment`, `run_with_secrets` picks the environment with the same rules as `klav run` without `--env`.

### 6. Commands and apps

**CLI** (secrets never in argv, `cli.md` §1):

```sh
klav env ls [--project P]                          # entornos, n.º de variables, protegido, última edición
klav env show NOMBRE [--reveal] [--json]           # nombres y origen; valores enmascarados
klav env create NOMBRE [--protected | --no-protected]
klav env set NOMBRE -s VAR                         # valor por prompt sin eco
klav env set NOMBRE --secret-stdin VAR
klav env set NOMBRE --ref VAR=klav://Trabajo/acme-api/Stripe/api_key
klav env rm NOMBRE [VAR…]                          # sin VAR: el entorno entero a la papelera, con confirmación
klav env import .env --env NOMBRE [--project P] [--dry-run]
klav env link [Bóveda/Proyecto] [--remote NOMBRE] | klav env unlink
klav run --env NOMBRE -- npm run dev
klav inject --env NOMBRE --dotenv -o .env [--fifo] # el entorno como .env 0600, o por una tubería
```

- **`klav env show --reveal`** and **`klav inject --env`** of a protected environment ask for Touch ID every time.
- **`klav env set --ref`** in a protected environment says which item becomes protected and for which agents ("Stripe is now protected for *mi-agente* and *ci-bot*"), and reissues their grants before saving (§3.1).
- **`klav item get`** and `klav item ls` mark protected items and by which environment.
- **`klav env import`:**
  - reads `KEY=VALUE`, `export KEY=…`, single and double quotes, multi-line values in quotes, and comments;
  - **never prints a value**, not even in errors (`línea 12: falta =`);
  - shows the review by name: new, changes or same;
  - if a value matches a field of an item that already exists (compared in memory), it proposes storing it as a reference to that field instead of duplicating it. In a protected environment, the review says that item will become protected;
  - when done, **offers to delete the `.env`**, with `[s/N]`. If git tracks it, it warns that deleting it doesn't take it out of the history and that those values must be rotated. Deleting is `unlink`, not a secure erase, and the message says so;
  - with `--secret-stdin`/`-` it reads from stdin with the same wiped buffer `klav import` uses (residual risk 38).
- **`klav inject --env --dotenv`** is the answer to 1Password's mounted `.env`: with `--fifo`, the tool reads the `.env` once and the secret doesn't touch the disk (`cli.md` §7).

**Apps** (*popup*, iOS and the Mac app of ADR 0027), with the "Development" switch on (§7):

- On a project's page, an **"Environments"** section with one row per environment: the name, the number of variables and a padlock if it is protected.
- When an environment is opened, the list of variables with hidden values (`••••`), "Show" and "Copy" on each, and where a reference comes from ("from Stripe › api_key").
- In a protected environment, and on the item page of any item protected by a reference, "Show" and "Copy" ask for Touch ID or Face ID every time. The item page carries the padlock and the notice "Protected by acme-api's *production*". The copied value is cleared from the clipboard like any password.
- Editing variables and the `protected` flag can be done from the apps, with the same rules of §3.1. Importing a `.env` belongs to the CLI in this ADR; in the Mac app, dragging a `.env` may come later.

### 7. Personal use and development use
**Answer: a single product**, with the same account, the same vaults and the same price (USD 20 a year, roadmap). Splitting it would break what sets Klav apart: the same agent fills a login and uses an API key, and the person approves both from the same phone.

- **Two front doors:**
  - Someone who only wants passwords starts in the Mac or iOS app, with the extension. They don't need the CLI or `klav.toml`.
  - Someone who develops starts in the terminal: `klav signup`, `klav env import .env --env development`, `klav run`.
- **The "Development" switch**, in Settings of the *popup*, of iOS and of the Mac app. **On by default in every account** (answer 5):
  - Off, it hides projects (items are seen in a single list, ungrouped), environments, the agents section and the SSH key and API key kinds in the tabs and in "New item".
  - Those items stay in "All" and in search: hiding a kind doesn't make it look deleted.
  - **It is interface only.** It changes no data, permission, grant or policy. An agent with a grant keeps working, and a protected item still asks for Touch ID to copy or show it.
  - **What asks for a decision is never hidden.** Agent registration requests, approvals, tasks and security warnings are shown the same with the switch off. Turning it off can't serve to let something happen without the person seeing it.
  - The CLI doesn't look at it.
- **Where it lives.** In a new system item, `kind = preferences`, in the system project of the personal vault (spec §7.3). That project has a derived ID every client recognizes and that **no grant includes**, so an agent can't read or change the setting.
  - It syncs encrypted like any item, with its history. There is no change on the server.
  - `ItemKind::Preferences` is a system kind (`is_system`): it is never listed or created by hand.
  - Its *details* carry `preferences: {developer: bool}`. Keys that come later are added with their own ADR.
  - **Without the item, it counts as on.** That way no existing account, starting with Omar's, loses sight of its projects or its agents. The item is only written when someone changes the setting.
  - An old client skips that item with the same warning as an environment (§1); the setting isn't applied to it, and since it is on by default, nothing changes.
- **What was done elsewhere:** 1Password has the same switch, "Show 1Password Developer Experience", in Settings › Developer (§"What was researched"). There it is off by default. Klav turns it on by default because its starting audience uses agents.

### 8. Migration
- **Nothing breaks.** A `klav.toml` with a flat `[env]` keeps doing the same, without reading any environment. Loose items (logins and API keys) are still the targets of references, of `[env]` and of reference variables.
- **Moving to environments is optional.** `klav env import klav.toml --env development` reads the flat `[env]` and creates the `development` environment with **references** to the same fields, without copying any value. Then it offers to change the `klav.toml` to `default_env = "development"`. If it is imported into a protected environment, the review says which items will become protected.
- **Agents.** Today's grant has no per-item rules: a new environment falls under its project rules. A protected environment and the items it points to are added on their own with `ask once` (§3.1 and §4.3), and the agent notices on its next access.

### Later
Outside this ADR, in case they are needed:

- a person's personal values that override the environment's (as in Infisical);
- inheriting variables from a base environment;
- importing or showing a `.env` by dragging it to the Mac app;
- syncing with Railway, Vercel or GitHub Actions.

## Consequences
- **Format:** a new item kind (`environment`) and a system one (`preferences`) in the schema of §7.1, and optional `repos` in `0x13` (§7.2). No new blob, no new label, and no AAD changes. The spec and `docs/vectores/entorno.json` arrive with the first code layer, as in ADR 0030. This ADR doesn't touch the spec.
- **Policy and grants:**
  - `Scope.items`, `Rule.once` and the mark `origin: "protected"` in `klav-core::policy`, with *proptests*: adding `items`, `once` or an inherited rule never makes a decision more permissive;
  - `released` in the `GrantPayload`;
  - the server rejects `once` without `ask`, leases on a `once` target, tasks that include it, and a new grant that loses an inherited rule without naming it in `released` (`409`);
  - the `items` of the approval request (§3.1).
- **Grants that are reissued:** when creating or marking a protected environment, and when adding or removing references in one. When the protection grows, the reissue goes **before** saving the version, and without a network the version isn't saved.
- **`klavd` and `KlavFFI` cache:** they keep the person's latest version of each environment, with its *details*, and the protected set, which only shrinks with proof (§3.1).
- **Compatibility:** readers go first (§2). An installation that hasn't updated skips environments and stops seeing a linked project. An agent runtime or a server that hasn't updated rejects grants with `items` or `once`: the agent stops working until it updates, instead of skipping the protection.
- **References inherit the protection** (answer 9). An item a protected environment uses starts asking for Touch ID to copy or show it, and for approval every time for agents. It is more friction if the same API key is used in `development` and in `production`: Klav shows it when saving the reference, so that the person can separate the keys if they don't want it that way.
- **`inject` is still not a sealed channel** (ADR 0030 §2, residual risk 31): an approved production `run` gives the process the values, and the process can get them out. The approval decides **whether** it runs, not what the process does afterwards.
- **Threat model:**
  - §5.14 with T125–T130 and residual risks 44 and 45;
  - it starts after what the open PRs reserve: the Mac app (§5.11, T120–T124 and risk 43) and ADR 0029 (§5.13, T113–T117).
- **Roadmap:** section "Entornos por repositorio (aceptado, ADR 0032)" at the end of the work order, with one box per layer. "Estado actual" doesn't change.

## Rejected alternatives
- **Environments as tags** on loose items. They don't give an atomic version (changing three variables is three versions), there is no natural target for `klav env import`, and the server doesn't check a tag rule (§4.1).
- **Environments as projects** (`acme-api-production`). It would be the only cryptographic barrier, because each project has its key. But it multiplies projects, breaks "one repository, one project" and forces repeating shared logins or crossing projects with references. It remains as a way of working for whoever wants it: a `klav.toml` can point `[env.production]` to another project.
- **Variables as `fields`.** A field name doesn't allow uppercase (§1).
- **The link in a system item of the project**, instead of in `0x13`. An old client would skip only that item and not the whole project. It is ruled out because it puts an invisible item in every linked project, with its key, its version and its authorship, for something that is project metadata, and because the advantage only lasts until every client reads `repos`.
- **A `klav.toml` that grants through the link** (if `origin` matches, don't ask). The repository controls the `remote` (T125).
- **Production with leases** ("Approve 15 min"). Omar asked for an approval every time.
- **Sealing protected environments with the vault key** (a `0x17` blob, like `0x15`/`0x16`, delivered to the agent by HPKE on each approval). It would close the "malicious server + an agent's stolen key" case, but every use would need one of the person's devices awake to reseal, and it wouldn't protect the referenced items without sealing them too. Omar chose policy and runtime (answer 6).
- **Just warning** when a protected environment points to an item a grant leaves in `allow`. It was the proposal; it let the production value out by asking for the item directly. Omar chose inheritance (answer 9).
- **Computing the protected set on the server**, or letting the agent declare which references it uses. The server can't read references, and what the agent declares isn't a barrier. That is why it goes in the grant the account signs.
- **`klav run` without `--env` with `development` by default.** Omar ruled it out (answer 8): a name isn't enough to choose which secrets go to a process.
- **Splitting the product** into "Klav dev" and "Klav user" (§7), or the switch off by default in accounts created from an app. Omar chose one product and the switch on for everyone.
- **Asking at sign-up** "What will you use Klav for?". It is one more step for a setting that is already on by default and is changed in Settings. Omar removed it.

## Questions for Omar

None: Omar answered the three questions on 2026-11-05 (answers 6–8) and added the inheritance of the protection (answer 9).
