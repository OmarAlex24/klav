# 0048 · Invite-only free beta on `api.klav.dev`, per-account quotas, the waitlist as the invite queue, and installing Klav without Docker

- Status: accepted (2026-11-25). Omar answered (a), the recommended option, to all seven questions (Q1–Q7) on 2026-11-25; see "Open questions for Omar".
- Date: 2026-11-24
- Amends: ADR [0028](0028-servidor-por-defecto-klav-dev.md) §3 and its answer H4 (when registration opens on `api.klav.dev`); brings forward part of phase 8 (ADR [0010](0010-decisiones-fase-3-y-plan-alojado.md) §2 and the roadmap); and, if Omar answers Q1 with (a), replaces his launch decision of 2026-11-18 ("self-hosted only from day 0, with a waiting list for the paid plan") and the note of 2026-11-13 that `api.klav.dev` "does not open for free".

## Context

### The wall a new person hits today

- **The default server is closed.** `api.klav.dev` runs with `KLAV_ALLOW_REGISTRATION=false` (ADR 0028 §3, H4). Someone who watches a demo video and installs `Klav.dmg` reaches "Set up this Mac", types an email, and is told: "Registration on klav.dev is not open yet. You can host your own server". The check reads `registration_open` from `GET /v1/health` (`crates/klav-client/src/server.rs`, `crates/klav-cli/src/commands/account.rs:85`), so it happens before the password.
- **The only way in is to self-host**, which today means:
  - cloning the repository and running `KLAV_ALLOW_REGISTRATION=true docker compose up -d --build`, which compiles Rust from source, even though `release-docker.yml` already publishes `ghcr.io/omaralex24/klav-server` (amd64 only, started by hand);
  - putting TLS in front (`self-hosting.md` §3);
  - then **restarting the server without the variable** so that strangers can't register (§1). If they forget, the server stays open, and finished attachments have no quota (§6).
- **iPhone push approvals don't reach the TestFlight app from a self-hosted server.** APNs only accepts pushes signed with the key of whoever signed the app (`self-hosting.md` §2.4 and §8.4), and the relay for self-hosted servers is phase 8. So the strongest part of the demo (approve an agent from the phone) only works on `api.klav.dev`, which is closed.
- **The waitlist has one person** (2026-11-24). The landing page asks people to join "the paid plan waitlist", and nothing happens after they sign up.

### What already exists and this ADR builds on

- **Registration.** `register/start` and `register/finish` (`crates/klav-server/src/routes/auth.rs`) refuse with `403` when `allow_registration` is false. `register/finish` is a single `INSERT … ON CONFLICT DO NOTHING` with no transaction, and it returns `409` when the email exists, which reveals which emails have accounts (`self-hosting.md` §6; ADR 0010 §2 defers the fix to email verification).
- **The request types refuse unknown fields.** `RegisterStartRequest` and `RegisterFinishRequest` are `#[serde(deny_unknown_fields)]` (`crates/klav-proto/src/auth.rs`): an older server answers `400` to any new field. `HealthResponse` doesn't refuse unknown fields, so new fields there are safe for older clients.
- **Older clients can't read a new error code.** `ErrorCode` is an enum without a catch-all. `klav-client` reads the error body with `serde_json::from_slice(..).ok()` (`crates/klav-client/src/api.rs:275`), so an unknown code drops the whole body and the client falls back to a generic error for that HTTP status, without the message.
- **Order of a sign-up in the clients** (`crates/klav-client/src/auth.rs:95`): read `registration_open`, then deliver the emergency kit, then derive Argon2id (256 MiB), then `register/start` and `register/finish`. Any rejection after the kit leaves the person with a kit for an account that doesn't exist.
- **Quotas.** The only per-account quota is `max_pending_upload_bytes` (1 GiB of unfinished uploads). The attachment route checks it in one transaction, under the owner's account-row lock (`routes/attachments.rs:139`). Item writes take the same account lock (`VaultWrite::begin_for` → `deletion::lock_account`, `vaultdb.rs:100`). `create_vault` opens a transaction but doesn't lock the account (`routes/vaults.rs:112`). Per-object limits: 64 KiB overview, 1 MiB details, 50 versions per item, 100 MiB per attachment (`config.rs`, `api.md` §7).
- **Configuration** is TOML plus `KLAV_*` overrides (`config.rs`). Production on Railway is configured only by environment variables, and today `[limits]` has no environment variables at all.
- **Tokens.** `klav_core::crypto::token` generates 32-byte bearer tokens and stores only `SHA-256(tuple("klav/v1/server/token", token))`. `klav-server` takes all its hashing from `klav-core`, and doesn't depend on `sha2` itself.
- **The binary's commands.** `klav-server` parses its own arguments (no `clap`): `serve`, `healthcheck`, `--version` (`main.rs`).
- **The site** (`apps/web/server.mjs`) has no dependencies and a CSP built from hashes. The `waitlist` table has `id, email UNIQUE COLLATE NOCASE, lang, created_at`, with `PRAGMA user_version = 1`, and the server refuses a database with a newer schema. `GET /api/waitlist/export` hands out a CSV to whoever holds `KLAV_WEB_ADMIN_TOKEN`. Emails are stored as `trim().toLowerCase()`, the same normalization as the server's `validate::email` (`trim().to_lowercase()`).
- **Releases** (`docs/releasing.md`): the asset names in `scripts/release/kit.mjs` (`ASSETS`) are a contract with `apps/web/server.mjs`. `seal` refuses files it doesn't know. `release-linux.yml` builds `klav`, `klavd` and `klav-native-host` (x86_64, glibc 2.36) in `deploy/linux/Dockerfile`, plus `klav-forward` and `klav-proxy` as a separate artifact. There is no macOS CLI on its own, because unsigned binaries downloaded from a browser are quarantined (§1).
- **Production deploys from `main`.** A merge that touches `crates/` or `Cargo.*` redeploys `klav-server` on Railway, so every server layer must be safe with today's production variables and with the clients already shipped.

## Goal

1. **One mechanism, two uses:** invites let Omar run a free, controlled beta on `api.klav.dev`. They also let a self-hoster add a person without restarting with `KLAV_ALLOW_REGISTRATION=true` and then `false`.
2. **Bound abuse of a free server** with per-account quotas that a self-hoster can also use.
3. **Make the waitlist the queue of invites,** with Omar's manual loop written down. There is no email infrastructure.
4. **Install Klav and its server without Docker or a Rust toolchain:** Homebrew, prebuilt `klav-server` binaries, the published image in the quick start, and one-command TLS with Tailscale Serve or Caddy.

Out of scope: billing, email verification (§3.5 says when it becomes mandatory), the push relay for self-hosted servers (phase 8), S3, and account recovery.

## Decision

### 1. `registration_mode` in `klav-server`

#### 1.1 The setting

- **`registration_mode = "open" | "invite" | "closed"`** in the TOML, and `KLAV_REGISTRATION_MODE` in the environment.
  - `open`: as `allow_registration = true` today.
  - `closed`: as `allow_registration = false` today.
  - `invite`: `register/start` and `register/finish` need a valid invite (§1.3).
- **The old key is still read.** `allow_registration` / `KLAV_ALLOW_REGISTRATION` = `true` means `open`, and `false` means `closed`.
- **Both keys set:** after the file and the environment are merged (the environment wins, as today), the two must agree. `true` agrees only with `open`. `false` agrees with `closed` **and with `invite`**: it means "not open to everyone". Any other pair stops the server at start-up, with an error that names both keys.
  - **`false` is the floor that keeps a rollback closed.** A binary from before this ADR ignores `KLAV_REGISTRATION_MODE` (unknown `KLAV_*` variables are skipped) and defaults to open. Without `KLAV_ALLOW_REGISTRATION=false` next to it, a Railway rollback, or an older image pinned under the new `docker-compose.yml`, would run fully open (T253). So production and every shipped configuration that uses the environment keep `KLAV_ALLOW_REGISTRATION=false` and add `KLAV_REGISTRATION_MODE=invite`. Going to `open` means removing `false` on purpose.
- **The default of the bare binary stays `open`**, the same as today's `allow_registration = true`, so no existing configuration changes meaning.
  - The shipped configurations change instead (layer 4): `docker-compose.yml`, the Railway template, the Homebrew `server.toml` and the systemd unit all start in `invite`, each with `allow_registration = false` / `KLAV_ALLOW_REGISTRATION=false` next to it (above). A self-hoster then creates their own invite (§1.4), and never has to reopen or restart anything.
- **Production is untouched when layer 1 deploys:** today's `KLAV_ALLOW_REGISTRATION=false` maps to `closed`.

#### 1.2 What `GET /v1/health` says

- **New optional field `registration_mode`:** `"open" | "invite" | "closed"`.
- **`registration_open` stays, and in `invite` mode it is `false`.**
  - Clients already shipped then stop cleanly before the kit and before Argon2id, with today's "not open yet" message. They never write a kit for an account they can't create.
  - If it were `true`, an older client would deliver the kit, derive the keys and then hit a `403` it can't explain.
  - The cost is that an older client tells an invited person registration isn't open. The answer is to update (the Mac app updates itself with Sparkle; the CLI ships with it).
- **New clients read `registration_mode` first.** Without it (an older server), they fall back to `registration_open`, exactly as today.

#### 1.3 Invites: table, code, check and consumption

**Table** `registration_invites` (new migration `0021_registration_invites.sql`, in SQLite and Postgres; existing migrations are never edited):

| Column | Type | Meaning |
|---|---|---|
| `id` | TEXT, primary key | A random UUID. This is what `ls` and `revoke` use; never the code |
| `code_hash` | BLOB, unique, 32 bytes | `SHA-256(tuple("klav/v1/server/invite", canonical code))`. The code itself is never stored |
| `bound_email` | TEXT, nullable | Normalized with the server's `validate::email`. If set, only that email can use the invite |
| `max_uses` | INTEGER, default 1 | More than 1 only for a batch code (Q3) |
| `used_count` | INTEGER, default 0 | |
| `expires_at` | INTEGER (Unix ms), nullable | |
| `note` | TEXT, nullable, ≤ 200 characters | For Omar ("waitlist", "launch video"); never shown to the person |
| `created_at` | INTEGER (Unix ms) | |
| `revoked_at` | INTEGER (Unix ms), nullable | |

Plus `registration_invite_uses (invite_id, account_id, used_at)`, so that `ls` can say which accounts came from a batch code. Its row goes with the account in the deletion cascade (ADR 0037). The seat is **not** given back: `used_count` stays, and Omar can create another invite.

**The code** (format pending Q2; recommended):

- **16 random bytes (128 bits)** from `klav_core::crypto::random`, written in Crockford base32 (26 characters) after a `KLAV-` prefix, in groups so that it can be read aloud: `KLAV-XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX`.
- **Canonical form:** remove the prefix, dashes and spaces; turn it to uppercase; map `I`/`L` to `1` and `O` to `0`; decode to the 16 bytes. 26 characters carry 130 bits, so the 2 bits left over must be zero; otherwise two spellings would decode to the same bytes. The digest is over those bytes. A code that doesn't decode to exactly 16 bytes with those bits at zero is invalid, and is rejected before touching the database.
- **Generation, canonical form and digest live in `klav-core`** (`crypto::invite`, following the `crypto::token` pattern with its own label). `klav-server` and the CLI only call it. The code is a `SecretString` everywhere, and is never in a `Debug`, a log or an error.
- **Why 128 bits, with the arithmetic:**
  - *Online:* with N live codes and G guesses, the chance of a hit is about G·N/2^b. With 60 bits (`KLAV-XXXX-XXXX-XXXX`, the format first suggested), 1,000 live codes and the per-IP limit below from 10,000 IPs for a year (about 5.3·10^9 guesses), that is about 4.6·10^-6. That's small, but it depends on the rate limit holding. With 128 bits it is about 1.5·10^-26, whatever the rate limit.
  - *Offline, against a stolen database:* the hash has no salt (it has to be looked up). At about 10^10 SHA-256 per second on one GPU, 60 bits take about 3.7 GPU-years for the whole space, and divided among 1,000 live codes, about 1.3 GPU-days for one of them. With 128 bits it is out of reach.
  - Someone with the database can already do more harm than register, so the offline case only matters for not leaving seats up for grabs. 128 bits closes both cases, and the cost is a code that gets pasted rather than typed, which is fine, because it arrives by email.

**The check, before any work (`POST /v1/auth/invite/check`):**

- **Body:** `{ "email", "invite" }`. Answers `204` if the invite can be used by that email now (it exists, isn't revoked or expired, has uses left, and isn't bound to another email). Otherwise it answers `403 invite_invalid`, the same code and message in every case ("This invite code isn't valid for this email").
- **It doesn't read `accounts`.** It answers the same whether the email has an account or not, so it adds no way to find out which emails exist.
- **It isn't a reservation.** Two people with the last seat of a batch code can both pass the check; only one finishes (below).
- **The clients call it before asking for the password and before delivering the kit** (§2). That is the fast failure: the 256 MiB Argon2id derivation and the kit only happen with an invite that worked a moment ago.
- **In `open` and `closed`** it answers `404` (the route doesn't apply).

**`register/start`** gains an optional `invite` field (`#[serde(default)]`). In `invite` mode, it runs the same check and gives the same `403 invite_invalid` before the OPAQUE work. **Clients send `invite` only when health said `invite`**, because an older server refuses unknown fields (`deny_unknown_fields`).

**`register/finish`** gains the same optional `invite`. In `invite` mode, everything goes in **one transaction**, with the write first (so SQLite never has to upgrade a read lock):

1. `UPDATE registration_invites SET used_count = used_count + 1 WHERE code_hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $now) AND used_count < max_uses AND (bound_email IS NULL OR bound_email = $email)`. If no row changes: `403 invite_invalid`.
2. The current `INSERT INTO accounts … ON CONFLICT DO NOTHING`. If no row is inserted, the transaction **rolls back** (the seat isn't spent) and the answer is today's `409`.
3. `INSERT INTO registration_invite_uses`, then commit.

The conditional `UPDATE` is atomic in SQLite and in Postgres. Two finishes for the last seat can't both commit.

**Limits on attempts:**

- **A new per-IP bucket** for `invite/check` and every invite failure in `start` and `finish`: `rate_limit.invite_ip_per_minute = 1` and `invite_ip_burst = 10` (60 per hour sustained). This is on top of today's `auth_ip_*` and `auth_email_*`.
- **One `warn` log line per failure,** with the client IP key and no code and no email, so that an alert can be set on it (Maple).
- **Behind a proxy without a trusted IP header,** all clients share one bucket (`self-hosting.md` §3.2). For a personal server that's fine; the docs say so.

**New error code:** `ErrorCode::InviteInvalid` (`invite_invalid`, `403`). Older clients never get it, because health tells them `registration_open: false` and they stop first. An older client that skips health and calls `register/*` would see a generic `403`, as today.

#### 1.4 Managing invites: `klav-server invite`

Subcommands of the same binary. They work against the configured database (`--config` / `KLAV_CONFIG` / `KLAV_DATABASE_URL`), and there is **no HTTP admin API**:

```text
klav-server invite create [--email EMAIL] [--uses N] [--expires 30d] [--note TEXT]
klav-server invite ls [--all]
klav-server invite revoke <ID>
```

- **`create`** prints the code once, on stdout, and its `id`. The code isn't stored or logged anywhere.
  - `--email` normalizes the address with the same `validate::email`, so the comparison in `register/finish` is byte for byte.
  - `--expires` defaults to 30 days. `--uses` above 1 needs `--expires` (Q3).
- **`ls`** shows `id`, the bound email, uses, expiry, the note, creation and revocation. It never shows codes. Without `--all`, only usable invites.
- **`revoke`** sets `revoked_at`. It doesn't touch accounts already created.
- **They never migrate the database.** If the schema is older than the binary's, the subcommand stops and says to upgrade and start the server first. A CLI run from a newer image against a running older server must never change its schema.
- **They run alongside the running server:** SQLite in WAL with `busy_timeout`, or Postgres.
- **Where Omar runs them:**
  - on Railway, inside the service with `railway ssh` (the binary is already in the image). The Railway image starts as root and drops to `klav` (`self-hosting.md` §8), so layer 1 tests which user and environment that session has: run as root against SQLite, the subcommand could leave a WAL file owned by root that the server can't write. If needed, the subcommand refuses to run as root on a database it doesn't own, or the docs say to switch to `klav` first;
  - with Compose, `docker compose exec klav klav-server invite create`;
  - with Homebrew or systemd, directly.
- **Who can run them:** whoever can read and write the database, who already controls the server. There is no new privilege.

### 2. Signing up with an invite in the clients

- **`klav-client`:**
  - `server::registration_mode(url)` returns `Open | Invite | Closed | Unknown`; `Unknown` (an older server) falls back to `registration_open`.
  - `SignupRequest` gains `invite: Option<SecretString>`.
  - `signup` calls `invite/check` before `deliver(&kit)` and before Argon2id, and sends `invite` in `register/start` and `register/finish`.
  - The `invite_invalid` error maps to `ClientError::InviteInvalid`.
- **CLI:** `klav signup` with an invite server:
  - asks "Invite code:" after the email and before the password. The code is visible as it is typed: it is single-use and bound, not a long-lived secret;
  - also takes `--invite CODE` or `KLAV_INVITE`, for scripts. The docs say `--invite` stays in the shell history and in `ps`, and that this only matters until the code is used;
  - on `invite_invalid`: "This invite code isn't valid for <email>. Check the code, or request one at https://klav.dev." The kit isn't written and nothing is derived;
  - in `closed`: today's message.
- **`klav-ffi`:**
  - `sign_up` gains `invite: Option<String>`;
  - two new functions, `registration_mode(server)` and `check_invite(server, email, invite)`;
  - `InviteInvalid` in the error enum.
- **Mac app** ("Set up this Mac", `AccountSheet`):
  - With `invite` mode, an "Invite code" field appears under the email.
  - "Continue" runs `check_invite`, and only then asks for the master password.
  - Errors appear under the field, in English and Spanish, written natively (`Localizable.xcstrings`): "This invite code isn't valid for this email." / «Este código no sirve para este correo.» Each comes with a "Request an invite" link to `https://klav.dev/#beta`.
  - With "Use my own server", the same field follows that server's mode.
- **iOS:** no change. The iPhone signs in to accounts created on the Mac or with the CLI (`ios.md`).
- **The extension:** no change; it doesn't sign up (ADR 0017 §2).

### 3. Per-account quotas

#### 3.1 The limits

New keys in `[limits]`, each with a `KLAV_*` variable, because production is configured only from the environment. **`0` means unlimited.** The owner of the vault pays: today only the owner is a member, as `max_pending_upload_bytes` already assumes.

| Key / variable | What it counts | Default (self-hosting) | `api.klav.dev` beta (Q4) |
|---|---|---|---|
| `max_account_attachment_bytes` / `KLAV_MAX_ACCOUNT_ATTACHMENT_BYTES` | Declared size of every attachment in the owner's vaults that isn't purged: finished, pending, and those of trashed items | 10 GiB | 250 MiB |
| `max_account_vault_bytes` / `KLAV_MAX_ACCOUNT_VAULT_BYTES` | Everything encrypted in the owner's vaults except attachments: `overview` + `details` + `wrapped_key` of every item that isn't purged **plus their kept versions**, and the `meta` of every vault and project | 1 GiB | 64 MiB |
| `max_items_per_account` / `KLAV_MAX_ITEMS_PER_ACCOUNT` | Items that aren't purged (trashed ones count until they are purged) | 100,000 | 5,000 |
| `max_vaults_per_account` / `KLAV_MAX_VAULTS_PER_ACCOUNT` | Owned vaults that aren't deleted, and deleted ones until they are purged | 1,000 | 20 |

- **Why there is a byte limit on vault data:** counting items isn't enough. Details may be 1 MiB with 50 kept versions, so 5,000 items could weigh about 250 GiB. Projects have no count limit either, and carry up to 64 KiB of `meta` each, so their `meta` counts here too. Real items weigh a few KiB, so 64 MiB covers tens of thousands of versions.
- **The self-hosting defaults are generous but finite.** A server someone leaves open by mistake gets a ceiling, and nobody with a normal vault ever sees it. `self-hosting.md` §6 stops saying finished attachments have no quota.
- **`validate()`** accepts `0` or a positive value. For attachments, a non-zero quota must be at least `max_attachment_bytes`, so that a single allowed attachment always fits. `max_pending_upload_bytes` keeps its own meaning.

#### 3.2 Where and how they are enforced

- **One helper, `quota::check(tx, owner, delta)`,** called inside the transaction that already holds the owner's account lock:
  - **attachments:** at `create`, the upload's declaration. Its size is fixed there, and chunks can't exceed it, so `complete` needs no check. The pending bytes count from the moment they are declared;
  - **items:** in `insert_item` and in the item update path (people and agents: `Writer::Person` and `Writer::Agent`, rotation, accepted secret requests). Restoring a version is an update, with its own delta. Restoring from the trash adds nothing, because trashed items already count;
    - *As built (layer 1):* a new version of an item doesn't replace the bytes of the old one, it moves them to the kept versions (`max_item_versions`), which count too. So the vault-data delta of an update is measured, not predicted: the account's vault bytes under the lock before the write, again after the write and its prune, and the write is refused only if the account grew past the limit (`quota::check_growth`). An edit to the same size, once the history is full, grows nothing and is never refused. Counting only "new − old current" would let the history grow `max_item_versions` times past the quota, against the bound in §3.3;
  - **vaults and projects:** in `create_vault`, which **starts taking the account lock** before inserting, the same lock as the other writes, and in `create_project` and every change to a vault's or project's `meta`, under the same lock.
- **Atomic against concurrency:** every write that adds bytes or rows for an account goes through that account's lock. So two uploads or two items declared at the same time can't both fit in the last free space.
- **Measured inside the transaction:** `SUM`/`COUNT` under the lock, as the pending uploads are today (with `CAST(… AS BIGINT)` for `sqlx::Any` on Postgres). Writes to a password manager are rare, so this is cheap. If it ever shows up in the traces, a counter column comes later, in its own ADR.
- **What is never refused:**
  - a write that doesn't grow the account (`delta ≤ 0`: an edit to the same size or smaller);
  - deleting anything, or moving it to the trash;
  - reading.
  An account above a quota that is lowered later keeps everything, and can still clean up.
- **Error: `403 quota_exceeded`** (`ErrorCode::QuotaExceeded`), with a message that says which limit, how much is used and the maximum: "Attachments for this account are limited to 250 MiB (248.3 MiB used). Delete some, or empty the trash."
  - Not `413`: in this API, `413` means a request body that is too large.
  - An older client can't read the new code (§Context) and shows a generic `403`. The Mac app updates itself, so that window is short.
- **The clients show the message as it comes.** `klav-client` maps it to `ClientError::QuotaExceeded(String)`. Nothing else in the clients changes.

#### 3.3 The volume behind the beta

The quota is per account. There is no global ceiling: the risk is that the sum of seats times quotas exceeds the volume. **The rule that Omar applies when sizing each wave of invites:**

> used today + (live seats × (`max_account_attachment_bytes` + `max_account_vault_bytes`)) ≤ 80% of the Railway volume

- With the recommended numbers (250 MiB + 64 MiB ≈ 314 MiB per account), **50 seats are at most about 15.3 GiB**. Omar checks the real size of the `/data` volume before the first wave, and grows it, or lowers quotas, before the next one.
- **The formula covers only attachments and vault data.** Other per-account rows grow outside any quota: the audit log (`audit_events`, one row per logged action), devices, sessions, agents, approvals, tasks, rotations, sandboxes and secret requests. Most have their own pending limits (`api.md` §7, ADR 0046) and the request rate limits, but the audit log grows for as long as the account is used. That is why the rule leaves 20% free.
- **An alarm** on the volume's usage (Railway metrics, Maple) at 70%. Setting it up is Omar's step.
- A server-side "minimum free disk" check is left out: it needs `statvfs` through a new dependency or `unsafe`, and both are outside this ADR.

#### 3.4 Abuse that quotas don't cover

- **Requests:** today's limits per IP and per account (`api.md` §7) still apply.
- **Many accounts from one person:** each needs its own invite. With bound invites, each also needs a mailbox Omar wrote to.

#### 3.5 Email verification: why it waits, and until when

- **ADR 0010 §2** puts email verification in phase 8, so that registration stops revealing which emails exist.
- **A bound invite is the verification, done by hand.** Omar writes to the address on the waitlist with a code that only works for that address. Whoever registers it has read that mailbox.
- **The `409` that reveals existing emails** is now reachable only by someone with a valid invite for that same email (bound), or with a batch code (Q3), and within the auth limits.
- **What it doesn't cover:** with a batch code, or with someone else's invite email in hand (T246), someone can register an address that isn't theirs and keep its real owner out (squatting). They can read nothing, because the vault is end-to-end encrypted. That is residual risk 98.
- **Email verification becomes mandatory** before `api.klav.dev` runs in `open` mode, and before the paid plan, whichever comes first (Q7). It needs transactional email, which is outside this ADR.

### 4. The waitlist becomes the invite queue (`apps/web`)

- **Still zero dependencies, the same CSP built from hashes,** and no IP addresses stored.
- **Schema v2:** `ALTER TABLE waitlist ADD COLUMN invited_at TEXT` and `ADD COLUMN note TEXT`, then `PRAGMA user_version = 2`, in one transaction. `SCHEMA_VERSION = 2`.
  - **Rollback consequence:** an older `klav-web` refuses a schema-2 database. The columns are additive, so rolling back means setting `PRAGMA user_version = 1` by hand, inside the container. `sitio-web.md` writes that down.
- **`GET /api/waitlist/export`** gains the `invited_at` and `note` columns (the header changes, and Omar is the only reader), and `?pending=1` keeps only rows without `invited_at`. The token is the same.
- **`POST /api/waitlist/mark-invited`** with `Authorization: Bearer $KLAV_WEB_ADMIN_TOKEN`:
  - body `{ "emails": [...], "note": "…" }`, at most 200 emails and 16 KB;
  - answers `{ "marked": n, "unknown": m }`;
  - it is `404` without a token configured, as export is, and `401` with a wrong one;
  - JSON only. It doesn't need `Origin` (it is called with `curl`), and the token is the only authentication.
- **Omar's loop, by hand** (there is no email infrastructure; `sitio-web.md` gets it as a recipe):
  1. `curl … /api/waitlist/export?pending=1` → the pending emails.
  2. For each one, inside the server: `klav-server invite create --email <email> --expires 30d --note waitlist` → the code.
  3. Omar sends the code from his own mailbox, with the template in `sitio-web.md` (English and Spanish), which links to the download and the docs.
  4. `curl -X POST … /api/waitlist/mark-invited -d '{"emails":[…]}'`.

  The codes pass through Omar's mail provider. A code is single-use, bound and expires in 30 days, so this is acceptable (T246).
- **The landing page** (English and Spanish, written natively, not translated):
  - The call to action becomes "Request a free beta invite" / «Pide una invitación a la beta gratuita».
  - Under it, plainly: the hosted server is free during the beta, it will be a 20 USD a year plan after it (with the notice of Q5), and self-hosting is free forever.
  - The form stays email-only.
  - **This copy couldn't ship while this ADR was `proposed`.** ADR 0039 §3 only lets the site name what is in `main` or accepted. Layer 3 changes, in the same PR: the page, `features.md` (the hosted plan moves from "decided, not built" to the beta), `sitio-web.md` §6, "On the way" in `apps/docs`, and the privacy page (`privacidad.md` and `public/privacy`), which gains "whether and when we sent you an invite, and a note".

### 5. Installing without Docker or a Rust toolchain

#### 5.1 What already exists, and the difference

- **`ghcr.io/omaralex24/klav-server` already exists** (`release-docker.yml`), for `linux/amd64` only, published by hand with `:<version>` and `:latest`. The quick start (README and `self-hosting.md` §1) still builds with `--build`.
- **Change:** the root `docker-compose.yml` uses `image: ghcr.io/omaralex24/klav-server:<version>`, pinned to the release (the release PR bumps it), with no `build:`. Building from source goes in `docker-compose.build.yml` (`docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build`).
  - The quick start no longer needs `git clone`: you download the `docker-compose.yml` of the tag (`raw.githubusercontent.com/OmarAlex24/klav/vX.Y.Z/docker-compose.yml`).
  - It starts with `KLAV_REGISTRATION_MODE=invite` and keeps `KLAV_ALLOW_REGISTRATION=false` (§1.1), and the first step after `up` is `docker compose exec klav klav-server invite create --email you@…`.
- **`linux/arm64` image and binary** (Raspberry Pi 5, Ampere VPSes): only with a native arm64 runner. QEMU emulation would multiply the time of each paid Boat run (ADR 0034). Without that runner, they stay out of this ADR.

#### 5.2 `klav-server` release binaries

- **`klav-server-linux-x86_64.tar.gz`,** a folder `klav-server-linux-x86_64/` with `klav-server`, `klav-server.service` and `server.toml.example`. glibc 2.36 or later, from the same `deploy/linux/Dockerfile` (one more `-p klav-server --bin klav-server`).
  - `release-linux.yml` checks that `klav-server --version` carries the commit's SHA, as it does for `klav`. Layer 4 adds the build identity to `klav-server --version` if it doesn't have it. *As built:* layer 1 added it (`klav-server 0.9.2 (<sha> <date>)`, from the same `build.rs` as `klavd`), so layer 4 only checks it.
  - Its `.sha256` goes in the run summary.
- **The kit:** `ASSETS.server_linux`, the `--server-linux` option in `assemble` (it checks the tarball holds those three files, with the binary executable), and the file in `SHA256SUMS`.
  - No `/download/…` route on `klav.dev`. Homebrew and the docs use the tag's GitHub URL, so the contract of names with `apps/web/server.mjs` doesn't change.
- **No `klav-server` binary for macOS on the release.** `releasing.md` §1 explains why: it would be unsigned and quarantined. On a Mac, Homebrew builds it from the tag's source (§5.3), and there's no notarization involved.
- **`deploy/server/klav-server.service`,** a hardened systemd unit:
  - `DynamicUser=yes`, `StateDirectory=klav`, `ProtectSystem=strict`, `ProtectHome=yes`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, `CapabilityBoundingSet=`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`;
  - `listen = 127.0.0.1:8080` and `registration_mode = "invite"` in the example configuration.

#### 5.3 Homebrew

- **A tap,** with the repository name pending Q6 (recommended: `OmarAlex24/homebrew-tap`, `brew install omaralex24/tap/…`).
  - **Cask `klav`** (macOS, Apple silicon, macOS 15): the `Klav.dmg` of the tag, `version` and `sha256` pinned. `auto_updates true`, because Sparkle updates it.
  - **Formula `klav-cli`** (**Linux only**): the `klav-linux-x86_64.tar.gz` of the tag, with its `sha256`. It isn't called `klav`, so that `brew install klav` is never ambiguous with the cask. On macOS the CLI comes from the app ("Set up this Mac"), as today.
  - **Formula `klav-server`** (Linux and macOS):
    - on Linux, the prebuilt tarball;
    - on macOS, from the tag's source archive with `depends_on "rust" => :build` (`cargo install --locked --path crates/klav-server`);
    - a `service do` block (`run [opt_bin/"klav-server", "--config", etc/"klav/server.toml"]`, `keep_alive true`, logs under `var/log`). `brew services` uses launchd on macOS and systemd on Linux;
    - `post_install` writes `etc/klav/server.toml` only if it doesn't exist: `listen = 127.0.0.1:8080`, SQLite under `var/"klav"`, `registration_mode = "invite"`;
    - `caveats` give the next two steps: TLS (§5.4) and `klav-server invite create`.
- **The Homebrew details above** (`service do`, `post_install`, `auto_updates`, `depends_on "rust" => :build`) are the design; layer 4 checks each against Homebrew's current Formula and Cask Cookbooks before writing them.
- **Every URL names the tag** (`releases/download/vX.Y.Z/…`), never `releases/latest`, so that a `sha256` always matches what it names.
- **Who updates the tap: Omar, as a release step** (`releasing.md` §2 gains it), with a PR to the tap that bumps the versions and the `sha256` values copied from `SHA256SUMS`.
  - There is no token with write access to the tap in Klav's CI in this version. An automated bump is a credential that can publish code onto people's machines, and it would need its own ADR.
  - The tap repository gets the ADR 0040 ruleset (PR required, no force push, no deletion).

#### 5.4 TLS in one command, without a reverse proxy configuration

`self-hosting.md` §3 and the `tls-and-reverse-proxy` page put these two first, before the Caddyfile and nginx:

- **Private (home Mac mini, a VPS with no open ports): Tailscale Serve.**

  ```sh
  tailscale serve --bg 8080
  ```

  - Serves `http://127.0.0.1:8080` as `https://<machine>.<tailnet>.ts.net`, with a certificate Tailscale issues. Only devices in the tailnet reach it: nothing is open to the internet. It survives reboots (`--bg`), and `tailscale serve reset` removes it.
  - Every device (Mac, iPhone) needs Tailscale connected to sync.
  - Layer 4 checks against Tailscale's docs whether HTTPS certificates must be turned on for the tailnet first, and which client-IP header Serve sets. Until then, the docs leave `trust_forwarded_for` off: every client shares one per-IP bucket, which a personal server can live with (§3.2).
  - **`tailscale funnel` is not recommended:** it publishes the server to the internet.
  - It **doesn't bring iPhone push approvals.** That still needs your own APNs key with an app you signed, or the phase-8 relay (`self-hosting.md` §2.4).
- **Public (a VPS with a domain): Caddy.**

  ```sh
  caddy reverse-proxy --from klav.example.com --to 127.0.0.1:8080
  ```

  - Gets and renews the certificate itself, with the domain's `A`/`AAAA` record pointing at the machine and ports 80 and 443 open.
  - To keep it running across reboots, the docs give the equivalent Caddyfile (§3.1) with the distribution's `caddy` service. Layer 4 checks whether `caddy reverse-proxy` stays in the foreground.
  - Caddy adds `X-Forwarded-For`, so `KLAV_TRUST_FORWARDED_FOR=true`, as §3.2 explains. Layer 4 checks it against Caddy's `reverse_proxy` docs.
- **Both keep the server on `127.0.0.1`,** and both pass paths and query strings unchanged, as agents' signatures need (§3).
- **The `apps/docs` pages change in the same PR** (ADR 0039): `quick-start.mdx`, `tls-and-reverse-proxy.mdx`, `configuration.mdx` (the new keys) and `index.mdx` (§6, limitations).

### 6. Security

**No new cryptographic dependency.** The invite digest is SHA-256 with a label, from `klav-core`, which already depends on `sha2`; the randomness is the same `crypto::random`. Crockford base32 is an encoding (`data-encoding`, already in `klav-core` and `klav-server`). No dependency is added to any crate.

**New threats.** In a new §5.25 of the [threat model](../modelo-de-amenazas.md), added when this ADR is accepted (it isn't edited now). Before writing them, check that no other open branch has taken these numbers.

| ID | Threat | Mitigation |
|---|---|---|
| T242 | Guessing invite codes online, to take a seat | 128-bit codes (Q2); a per-IP bucket for invite failures, on top of the auth limits; a log line per failure for an alert. The chance of a hit doesn't depend on the bucket (§1.3) |
| T243 | Someone with a copy of the database recovers usable codes | Only the labelled digest is stored; 128 bits can't be searched offline. Whoever has the database already controls the server |
| T244 | Invite errors reveal which emails have accounts | `invite/check` and the invite failures don't read `accounts`, and answer one `403 invite_invalid` for every reason. The `409` of `register/finish` (ADR 0010 §2) is now reachable only with a valid invite for that email, or a batch code |
| T245 | A batch code leaks (a public video, a forum): strangers take its seats, or squat other people's emails | Batch codes need an expiry and a maximum of uses (Q3); `invite ls` shows how many were used and by which accounts; `invite revoke`. Squatting is residual risk 98 |
| T246 | An invite sent by email is read by someone else before its owner uses it | Bound to the email, so it only creates that email's account; expires in 30 days. If the intruder uses it first, the account is theirs, with their password: the owner gets `409` with a new invite, and Omar can't remove that account today. It ends in the same squatting as residual risk 98 |
| T247 | Two registrations spend the last seat at once, or a failed registration spends it | Conditional `UPDATE` and account `INSERT` in one transaction; a `409` rolls back the seat (§1.3) |
| T248 | Concurrent uploads or writes get past a quota | Every write that adds to an account checks its quota under that account's lock, including vault creation, which starts taking it; pending uploads count from their declaration (§3.2) |
| T249 | The beta fills the server's volume (seats × quota) and the server stops for everyone | The sizing rule of §3.3 before each wave, and an alarm at 70%. Residual risk 99 |
| T250 | Someone with write access to the Homebrew tap, or with Omar's GitHub account, publishes a formula or cask that installs other code | URLs pinned to the tag and `sha256` from `SHA256SUMS`; the tap updated only by Omar's PR, with the ADR 0040 ruleset and 2FA; no token for the tap in CI. Residual risk 100 |
| T251 | An invite code ends up in a log, in a crash report or in shell history | `SecretString` with no `Debug` from the request to the digest; `create` prints it only to stdout; the CLI prompts for it by default and the docs warn about `--invite`. A used or expired code is worthless |
| T252 | A self-hoster exposes the server without TLS, or to the internet through Tailscale Funnel, while following the new instructions | The docs keep `127.0.0.1` in every example, say Serve is tailnet-only, and advise against Funnel; the clients refuse `http://` outside loopback (ADR 0011) |
| T253 | A server from before this ADR (a rollback, an older pinned image, an old template) ignores `KLAV_REGISTRATION_MODE=invite` and runs open to anyone | `KLAV_ALLOW_REGISTRATION=false` stays next to it in production and in every shipped configuration, and agrees with `invite` (§1.1); an older binary reads it and stays closed. Removing it is only for `open` |

**New residual risks** (numbered after 97, in §7 of the threat model):

- **98. Squatting an email.** Whoever holds a batch code can register an email that isn't theirs, and whoever reads someone else's invite email can register that address before its owner (T246). Either way the real owner is kept out until email verification exists (§3.5). The squatter reads nothing. Omar can't delete that account from the server today; that needs an admin command, which this ADR doesn't add.
- **99. The quota is per account, not global, and doesn't cover everything.** If Omar invites more seats than the sizing rule allows, the volume can fill up. The audit log and the other per-account rows outside the quotas (§3.3) also keep growing. The alarm is the only safeguard.
- **100. Homebrew trusts the tap.** Whoever controls the tap repository, or Omar's GitHub account, controls what `brew install` runs. It is the same trust as GitHub Releases and the image on `ghcr.io`, and it doesn't touch the vaults, which stay end-to-end encrypted.

### 7. Rejected alternatives

- **An HTTP admin API for invites** (`POST /v1/admin/invites` with a token): a new secret in production and a new surface on the internet, for a command Omar runs a few times a week. The database is already the privilege.
- **Opening `api.klav.dev` with a global cap on accounts:** the first ones to find it take the seats, and nobody can be left out on purpose or prioritized from the waitlist.
- **Codes stored in plaintext, or encrypted:** the server only needs to compare them, so a digest is enough, as with session tokens.
- **Emailing invites from `klav-web`:** it needs transactional email (domain, SPF/DKIM, a provider, a secret). That arrives with email verification (§3.5).
- **`registration_open: true` in `invite` mode:** older clients would write the kit and derive keys before a `403` they can't explain (§1.2).
- **Formula `klav` together with cask `klav`:** `brew install klav` would be ambiguous on macOS (§5.3).
- **Unsigned macOS `klav-server` on the release:** it gets quarantined (`releasing.md` §1). Homebrew builds it from source instead.

## Consequences

- **`klav-core`:** `crypto::invite` (generate, canonical form, digest), with its label and vectors in `docs/vectores/invite.json`. The code isn't a binary format with a version byte, but its canonical form and digest are fixed by the vectors.
- **`klav-proto`:**
  - `HealthResponse.registration_mode`;
  - `invite` (optional) in `RegisterStartRequest` and `RegisterFinishRequest`;
  - `InviteCheckRequest`;
  - `ErrorCode::InviteInvalid` and `ErrorCode::QuotaExceeded`.
- **`klav-server`:**
  - `registration_mode` and its mapping;
  - migration `0021`;
  - `invite/check`, and the invite in `register/*`;
  - `klav-server invite …`;
  - the four quotas with their variables, the invite rate limit, and the account lock in `create_vault`.
- **`klav-client`, CLI, `klav-ffi`, Mac app:** §2.
- **`apps/web`:** schema v2, export with `pending`, `mark-invited`, and the copy (layer 3, after acceptance).
- **Release:**
  - `klav-server` in `deploy/linux/Dockerfile`, `release-linux.yml` and the kit;
  - `docker-compose.yml` with the pinned image, plus `docker-compose.build.yml`;
  - `deploy/server/klav-server.service`;
  - the tap repository (created by Omar);
  - a new owner step in `releasing.md` §2 (bump the tap).
- **Docs:**
  - `api.md` §1.1, §1.3, §2.2 and §7;
  - `self-hosting.md` §1, §2.1, §3, §6 and §8.5;
  - `sitio-web.md` §2, §3 and §6;
  - `releasing.md`, `cli.md` §3, `macos.md`, `features.md` and `roadmap.md` (phase 8: the beta and quotas come first; email verification stays);
  - the `apps/docs` pages listed in §5.4;
  - README, quick start.
- **Glossary** (`docs/glossary.md` and `glossary.mdx`), in the first PR that uses each term: invite code (código de invitación), registration mode (modo de registro), quota (cuota), batch code (código de grupo), beta.
- **Threat model:** §5.25 with T242–T253, and residual risks 98–100, when accepted.
- **What Omar does, and nobody does for him:**
  - answer Q1–Q7;
  - after layers 1 and 2 ship in a release, change the production variables (§8);
  - check the volume size and set the alarm;
  - create the tap repository and its ruleset;
  - send the invites.

## 8. Plan in layers

A `gh stack` stack, one branch per layer. **Layers 1 and 2 can merge before Omar flips anything,** because with today's production variables they change nothing.

| Layer | What | Notes |
|---|---|---|
| 1 · server | `klav-core::crypto::invite` and its vectors; `klav-proto` types; `registration_mode`; migration 0021; `invite/check` and the invite in `register/*`; `klav-server invite`; the four quotas; the lock in `create_vault`; the invite rate limit; tests in SQLite and Postgres (the last seat raced, rollback on `409`, a quota under concurrency, both keys set, older clients against `invite` mode) | It deploys production on merge: it needs the "safe with older clients" review. With `KLAV_ALLOW_REGISTRATION=false`, nothing changes |
| 2 · clients | `klav-client` (mode, check, `InviteInvalid`, `QuotaExceeded`); `klav signup` (prompt, `--invite`, `KLAV_INVITE`); `klav-ffi`; Mac app ("Invite code", es/en strings) | Ships in a release (Sparkle) before the flip |
| — · flip (Omar) | On Railway: keep `KLAV_ALLOW_REGISTRATION=false`, add `KLAV_REGISTRATION_MODE=invite` and the beta `KLAV_MAX_*`, deploy the staged changes; check `GET /v1/health`; create his first invite and sign up with it from a clean Mac | Only after the layer 2 release is out |
| 3 · site | Waitlist schema v2, `?pending=1`, `mark-invited`; beta copy en/es; `features.md`, `sitio-web.md` §6, "On the way", privacy | After acceptance (ADR 0039 §3) and after the flip: the page doesn't promise invites before they work |
| 4 · distribution | `klav-server` in the Linux build and the kit; the systemd unit; `docker-compose.yml` with the pinned image, plus `docker-compose.build.yml`; README and `self-hosting.md`/`apps/docs` (quick start, Tailscale Serve, Caddy, the new keys); the Homebrew formulae and cask, written in `deploy/homebrew/` and copied by Omar to the tap | Independent of 1–3 except the config examples (`registration_mode`), so it goes on top of 1. The tap and its first publication are Omar's |

When each layer is finished, its box in `docs/roadmap.md` is ticked in the same PR.

## Open questions for Omar

**Answered on 2026-11-25:** Omar chose **(a)**, the recommended option, for every question, Q1 to Q7. The "Answer" column records it.

| # | Question | Options | Answer (2026-11-25) |
|---|---|---|---|
| Q1 | Do we open `api.klav.dev` as a free, invite-only beta now? It reverses your launch decision of 2026-11-18 ("self-hosted only from day 0, with a waiting list for the paid plan") and ADR 0028 H4 | **(a) Yes: invite-only beta now; open registration and the 20 USD plan later, with email verification (Recommended)** · (b) No: build `invite` mode only for self-hosters, and `api.klav.dev` stays closed until the paid plan · (c) Only people you pick by hand, with no public invite button on the site | (a) |
| Q2 | Invite code format | **(a) 128 bits: `KLAV-` + 26 Crockford base32 characters (Recommended)** · (b) 80 bits: `KLAV-XXXX-XXXX-XXXX-XXXX` · (c) 60 bits: `KLAV-XXXX-XXXX-XXXX` (as first proposed; secure online only while the rate limit holds, §1.3) | (a) |
| Q3 | Batch codes (no bound email, more than one use) in the first version? | **(a) Yes, but with a mandatory expiry of at most 14 days and at most 50 uses (Recommended)** · (b) No: only codes bound to one email, until email verification · (c) Yes, without limits | (a) |
| Q4 | Beta quotas on `api.klav.dev` | **(a) 250 MiB attachments, 64 MiB vault data, 5,000 items, 20 vaults, and at most 50 seats in the first wave (Recommended)** · (b) 500 MiB attachments, 128 MiB vault data, 10,000 items, 50 vaults · (c) 100 MiB attachments, 32 MiB vault data, 2,000 items, 10 vaults | (a) |
| Q5 | What happens to beta accounts when the beta ends | **(a) At least 60 days' notice in the apps and by email, then the 20 USD a year plan or moving to your own server with `klav account set-server`; nothing is deleted without that notice (Recommended)** · (b) Beta accounts stay free for good · (c) The first year of the plan free for beta accounts | (a) |
| Q6 | When `klav-server` binaries and Homebrew ship, and the tap's name | **(a) In v0.10.0, tap `OmarAlex24/homebrew-tap` (`brew install omaralex24/tap/klav-server`), cask `klav` and Linux formula `klav-cli` (Recommended)** · (b) In a v0.9.x patch, same tap · (c) Binaries only, no Homebrew yet | (a) |
| Q7 | Email verification | **(a) Stays deferred until `api.klav.dev` opens without invites or the paid plan starts, whichever is first; bound invites cover the beta (Recommended)** · (b) Required before the beta opens (it delays the beta until transactional email exists) | (a) |
