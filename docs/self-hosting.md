# Self-hosting `klav-server`

> The introduction for people who use Klav is on the public page [`index.mdx`](../apps/docs/src/content/docs/self-hosting/index.mdx) (in `apps/docs/src/content/docs/self-hosting/`); a change to it goes there first.

`klav-server` stores and syncs encrypted vaults. **It never sees your secrets**:
it receives OPAQUE messages and blobs encrypted on the client with `klav-core`.
If someone steals the server or the database, they get ciphertext, emails,
sizes and dates (see [threat model](modelo-de-amenazas.md), T1–T14), not
passwords or keys.

This guide covers installing with Docker and SQLite, configuration options,
TLS, backups, Postgres, where to host it (§7) and Railway (§8). The API is in
[`api.md`](api.md).

**Using your own server in the clients** (ADR
[0028](decisiones/0028-servidor-por-defecto-klav-dev.md)): by default, the CLI
and the apps use `https://api.klav.dev`. For yours:

- CLI: `klav signup --server https://<your domain> …` and `klav login --server …`,
  or `KLAV_SERVER` ([`cli.md`](cli.md) §3). An existing account moves with
  `klav account set-server https://<your domain>`.
- iOS: on "Sign in on this iPhone", tap "Use my own server" and type the URL.
  An existing account moves in Settings › Account › "Use another server"
  ([`ios.md`](ios.md) §2).
- The URL is kept in the emergency kit: `klav account kit` prints it again with
  today's server.

## 1. Quick start with Docker Compose

> The steps for people who use Klav are on the public page [`quick-start.mdx`](../apps/docs/src/content/docs/self-hosting/quick-start.mdx) (in `apps/docs/src/content/docs/self-hosting/`); a change to those steps goes there first.

Requirements: Docker with the `compose` plugin, on Linux x86_64 (the image is
`linux/amd64` only; other machines below). No `git clone` and no Rust build:
the release's [`docker-compose.yml`](../docker-compose.yml) runs the published
image (ADR [0048](decisiones/0048-invite-beta-and-distribution.md) §5.1).

```sh
mkdir klav && cd klav
curl -fsSLO https://raw.githubusercontent.com/OmarAlex24/klav/v0.10.0/docker-compose.yml
docker compose up -d
curl http://127.0.0.1:8080/v1/health
# {"status":"ok",…,"registration_open":false,…,"registration_mode":"invite"}
# Then TLS in front (§3), and the invite you sign up with:
docker compose exec klav klav-server invite create --email you@example.com
```

`invite create` prints the code once, on stdout, with its ID. Create your
account with it (`klav signup --server https://<your domain> --email …`, which
asks for the code before the master password; [`cli.md`](cli.md) §3), and one
invite per person after that. Managing invites (`ls`, `revoke`, batch codes) is
in §2.5.

The root [`docker-compose.yml`](../docker-compose.yml):

- runs `ghcr.io/omaralex24/klav-server:<version>`, pinned to the release: the
  version-bump PR raises it ([`releasing.md`](releasing.md) §2, step 1), so the
  file at tag `vX.Y.Z` names image `X.Y.Z`. There is no `build:`;
  [`docker-compose.build.yml`](../docker-compose.build.yml) adds it
  (`docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build`,
  from a checkout);
- publishes the port only on `127.0.0.1:8080`: put TLS in front of it (§3);
- stores everything in the `klav-data` volume (`/data` in the container): the
  SQLite database, its WAL and attachments;
- runs as an unprivileged user (`klav`, UID 10001), with a read-only
  filesystem, no capabilities and `no-new-privileges`;
- has a health check (`klav-server healthcheck`), so `docker ps` shows
  `healthy` when it responds;
- starts in **invite mode** (`KLAV_REGISTRATION_MODE=invite`), with
  `KLAV_ALLOW_REGISTRATION=false` next to it (§2.5): an image from before
  invite mode ignores the first and reads the second, so pinning an older
  image under this file leaves the server closed, not open (T253). Checked
  with the `0.9.2` image: it starts healthy with `registration_open: false`.

**Other machines.** On Apple silicon, Docker Desktop runs the `amd64` image
through emulation with `DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose up -d`
(without it: `no matching manifest for linux/arm64/v8`); Homebrew is simpler
there (below). On Linux ARM, build from a checkout of the tag with
`docker-compose.build.yml`. A `linux/arm64` image waits for a native arm64
runner (ADR 0048 §5.1).

The base images (`rust` and `debian`) are pinned by digest in the
[`Dockerfile`](../Dockerfile) and in Railway's (§8). To bump them, take the
`Digest:` line from `docker buildx imagetools inspect rust:<version>-slim-bookworm`
(the version from `rust-toolchain.toml`, so the server is built with the same
`rustc` it is tested with) and from
`docker buildx imagetools inspect debian:bookworm-slim`, and change it in both
files at once. The image includes `ca-certificates`: the server validates TLS
to Apple with the system roots (§2.4).

### Without Docker

**Linux, the release binary and systemd.** Each release carries
`klav-server-linux-x86_64.tar.gz` (glibc 2.36 or later), a folder with
`klav-server`, [`klav-server.service`](../deploy/server/klav-server.service)
and [`server.toml.example`](../deploy/server/server.toml.example)
([`releasing.md`](releasing.md) §1):

```sh
tag=v0.10.0
curl -fsSLO "https://github.com/OmarAlex24/klav/releases/download/$tag/klav-server-linux-x86_64.tar.gz"
curl -fsSLO "https://github.com/OmarAlex24/klav/releases/download/$tag/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf klav-server-linux-x86_64.tar.gz && cd klav-server-linux-x86_64
sudo install -m 0755 klav-server /usr/local/bin/klav-server
sudo install -d -m 0755 /etc/klav
sudo install -m 0644 server.toml.example /etc/klav/server.toml
sudo install -m 0644 klav-server.service /etc/systemd/system/klav-server.service
sudo systemctl daemon-reload && sudo systemctl enable --now klav-server
```

- The unit runs the server as a dynamic user named `klav` (`DynamicUser=yes`)
  that can write only to `StateDirectory=klav` (`/var/lib/klav`, really
  `/var/lib/private/klav`), with `ProtectSystem=strict`, `ProtectHome=yes`,
  `PrivateTmp=yes`, `NoNewPrivileges=yes`, no capabilities,
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` and a `@system-service`
  system call filter.
- `/etc/klav/server.toml` must be readable by that user (0644), so it holds no
  secrets. Secrets go in `/etc/klav/server.env` (`KLAV_*` lines, 0600, owned by
  root): systemd reads `EnvironmentFile=` before it drops to the user.
- **Invites run as the same user.** Run as root, `klav-server invite` could
  leave SQLite files in `/var/lib/klav` owned by root that the service can't
  write (ADR 0048 §1.4). A second unit with `DynamicUser=yes` and the same
  `User=klav` shares the running service's user:

  ```sh
  sudo systemd-run --pipe --wait --quiet \
    -p DynamicUser=yes -p User=klav -p StateDirectory=klav -p StateDirectoryMode=0700 \
    -p EnvironmentFile=-/etc/klav/server.env -E KLAV_CONFIG=/etc/klav/server.toml \
    /usr/local/bin/klav-server invite create --email you@example.com
  ```

  `StateDirectoryMode=0700` matters: without it the second unit sets
  `/var/lib/private/klav` back to systemd's default 0755.
- Checked on 2026-11-25 in a Debian 12 container running systemd 252, with an
  arm64 build of `deploy/linux/Dockerfile` (`registration_mode` removed from
  the example, since that binary predated it): `systemd-analyze verify` clean,
  `systemd-analyze security` 1.2 ("OK"), the service as `klav`, the
  `systemd-run` unit with the same UID writing to `/var/lib/klav`, a root-only
  0600 `server.env` read by both, and no denied system call in the journal.

**Homebrew (Linux or macOS):** `brew install omaralex24/tap/klav-server`, then
`brew services start klav-server`. On Linux it installs the release tarball; on
macOS it builds from the tag's source with Homebrew's Rust (there is no macOS
`klav-server` on the release, [`releasing.md`](releasing.md) §1). Its first
install writes `$(brew --prefix)/etc/klav/server.toml` (127.0.0.1:8080, invite
mode, SQLite under `$(brew --prefix)/var/klav`) and never overwrites it. Invites:
`KLAV_CONFIG="$(brew --prefix)/etc/klav/server.toml" klav-server invite create --email you@example.com`.
The formula is in [`deploy/homebrew/`](../deploy/homebrew/README.md).

**From source:**

```sh
cargo build --release -p klav-server
./target/release/klav-server --config /etc/klav/server.toml
```

The binary needs nothing else (SQLite is bundled). Without a configuration it
is **open to everyone** (`registration_mode` defaults to `open`, §2.5).
`klav-server --version` prints the version and `klav-server healthcheck` exits
with code 0 if the configured server responds on `/v1/health`.

## 2. Configuration

> The steps for people who use Klav are on the public page [`configuration.mdx`](../apps/docs/src/content/docs/self-hosting/configuration.mdx) (in `apps/docs/src/content/docs/self-hosting/`); a change to those steps goes there first.

Everything has a safe default. There are two sources, in this order:

1. an optional TOML file, with `--config <path>` (or `-c`) or with the
   `KLAV_CONFIG` variable;
2. `KLAV_*` environment variables, which win over the file.

Unknown keys in the TOML are an error: a typo does not pass silently.

### 2.1 Environment variables

| Variable | TOML key | Default | What it does |
|---|---|---|---|
| `KLAV_CONFIG` | — | — | Path to the TOML file |
| `KLAV_LISTEN` | `listen` | `127.0.0.1:8080` (`0.0.0.0:8080` in the image) | Address and port |
| `KLAV_DATABASE_URL` | `database_url` | `sqlite://data/klav.db` (`sqlite:///data/klav.db` in the image) | `sqlite://…` or `postgres://…` |
| `KLAV_DATA_DIR` | `data_dir` | `data` (`/data` in the image) | Attachments directory |
| `KLAV_TRUST_FORWARDED_FOR` | `trust_forwarded_for` | `false` | Use `X-Forwarded-For` as the client IP (§3.2) |
| `KLAV_TRUSTED_IP_HEADER` | `trusted_ip_header` | — (none) | Header your proxy sets to the client IP, e.g. `x-real-ip` (§3.2); mutually exclusive with the above |
| `KLAV_REGISTRATION_MODE` | `registration_mode` | `open` (`invite` in `docker-compose.yml`, Homebrew and `deploy/server/`, §1) | `open`, `invite` or `closed` (§2.5) |
| `KLAV_ALLOW_REGISTRATION` | `allow_registration` | `true` (`false` in `docker-compose.yml`, Homebrew and `deploy/server/`, §1) | The older switch: `true` = `open`, `false` = `closed`; with `invite` it must be `false` (§2.5) |
| `KLAV_LOG_FORMAT` | `log.format` | `json` | `json` or `pretty` |
| `KLAV_LOG` | `log.filter` | `info` | `tracing` filter, e.g. `info,klav_server=debug` |
| `KLAV_APNS_KEY_PATH` | `push.apns.key_path` | — | APNs `.p8` file (§2.4) |
| `KLAV_APNS_KEY` | `push.apns.key` | — | PEM content of the `.p8`, instead of the path (§2.4) |
| `KLAV_APNS_KEY_ID` | `push.apns.key_id` | — | That key's ID |
| `KLAV_APNS_TEAM_ID` | `push.apns.team_id` | — | Apple team ID |
| `KLAV_APNS_TOPIC` | `push.apns.topic` | — | Bundle ID of the iOS app |
| `KLAV_MAX_ACCOUNT_ATTACHMENT_BYTES` | `limits.max_account_attachment_bytes` | 10 GiB | Attachments per account; `0` is no limit (§2.6) |
| `KLAV_MAX_ACCOUNT_VAULT_BYTES` | `limits.max_account_vault_bytes` | 1 GiB | Vault data per account, without attachments (§2.6) |
| `KLAV_MAX_ITEMS_PER_ACCOUNT` | `limits.max_items_per_account` | 100,000 | Items per account (§2.6) |
| `KLAV_MAX_VAULTS_PER_ACCOUNT` | `limits.max_vaults_per_account` | 1,000 | Vaults per account (§2.6) |

Booleans accept `true`/`false`, `1`/`0` and `yes`/`no`.

### 2.2 Complete TOML file

```toml
listen = "127.0.0.1:8080"
database_url = "sqlite://data/klav.db"
data_dir = "data"
trust_forwarded_for = false
# trusted_ip_header = "x-real-ip"   # or this one, never both (§3.2)
allow_registration = true
registration_mode = "open"     # or "invite" or "closed" (§2.5)

[sessions]
access_ttl_secs = 900          # access token: 15 min
refresh_ttl_secs = 2592000     # refresh token: 30 days, sliding

[retention]
trash_days = 30                # trash and deleted vaults before purging
purge_interval_secs = 3600     # how often the purge runs

[log]
format = "json"
filter = "info"

[limits]
max_json_body_bytes = 4194304        # 4 MiB per JSON request
max_meta_bytes = 65536               # vault or project metadata
max_overview_bytes = 65536           # overview section of an item
max_details_bytes = 1048576          # details section of an item
max_item_versions = 50               # previous versions per item
max_attachment_bytes = 104857600     # 100 MiB per attachment (encrypted)
max_attachment_chunk_bytes = 8388608 # 8 MiB per upload chunk
max_pending_upload_bytes = 1073741824 # 1 GiB of unfinished uploads per account
max_account_attachment_bytes = 10737418240 # 10 GiB per account (§2.6); 0: no limit
max_account_vault_bytes = 1073741824 # 1 GiB of vault data per account; 0: no limit
max_items_per_account = 100000       # 0: no limit
max_vaults_per_account = 1000        # 0: no limit

[rate_limit]                   # token buckets: refill per minute and burst
ip_per_minute = 600            # every request, per IP
ip_burst = 120
auth_ip_per_minute = 30        # prelogin, registration, login and refresh, per IP
auth_ip_burst = 10
auth_email_per_minute = 10     # attempts per email and per IP
auth_email_burst = 5
account_per_minute = 1200      # authenticated requests per account
account_burst = 300
invite_ip_per_minute = 1       # invite checks and invite failures, per IP (§2.5)
invite_ip_burst = 10

[push.apns]                    # optional: approval notifications to the iPhone (§2.4)
key_path = "/run/secrets/AuthKey_ABC123DEFG.p8"
# key = """-----BEGIN PRIVATE KEY-----…"""  # or the content, never both
key_id = "ABC123DEFG"
team_id = "SZ3F58F8LX"
topic = "dev.klav.ios"
```

When a limit is exceeded, the server responds `429` with `Retry-After`.

Limits per IP address group IPv6 addresses by their `/64` (what a single
client typically receives). The authentication limit per email counts by email
**and** IP: someone who knows your email cannot lock you out from another
network. Trying passwords from many IPs helps nobody: key derivation also
needs the 128-bit Secret Key. The server keeps at most 100,000 buckets; if it
fills up, it evicts the least recently used ones.

### 2.3 Logs

Logs are JSON, one line per event, on standard output. For each request, the
server logs the method, the **route as a template**
(`/v1/vaults/{vault_id}/items/{item_id}`), the status code and the duration.
It never logs bodies, blobs, headers (`Authorization` included) or the query
string. A test checks this with `TRACE` level enabled.

When an account is deleted (ADR [0037](decisiones/0037-borrar-la-cuenta.md)),
an `account deleted` line is written with its `account_id`, never its email.
Keep it with your backups (§4.3). If deleting an account fails (a database
error), the purge writes `account deletion failed; the next purge tries again`
with the `account_id` and the error, and continues with the other accounts,
the trash and the sessions. The account keeps its pending deletion and the
next purge retries it.

### 2.4 Approval notifications to the iPhone (APNs)

Without `[push.apns]` the server sends no notifications: the iOS app sees
approvals when you open it. To notify the phone when an agent asks for
something (ADR 0018 §5):

1. On [developer.apple.com](https://developer.apple.com/account/resources/authkeys/list),
   create a key with **Apple Push Notifications service (APNs)**. Download the
   `.p8` (you can only do it once) and note its Key ID and your Team ID.
2. Give it to the server in one of two ways:
   - **as a file**, readable only by the server's user (in Docker, a secret or
     a read-only volume), in `KLAV_APNS_KEY_PATH` or `key_path`;
   - **as content**, pasting the whole PEM (with the
     `-----BEGIN/END PRIVATE KEY-----` lines) in `KLAV_APNS_KEY` or `key`.
     Useful on platforms without secret files, such as Railway (§8). If the
     platform does not accept line breaks, writing them as literal `\n` works.

   Path and content at the same time are an error. Also set `KLAV_APNS_KEY_ID`,
   `KLAV_APNS_TEAM_ID` and `KLAV_APNS_TOPIC` (or their keys under `[push.apns]`).
   All four go together (path or content, Key ID, Team ID and topic): if one is
   missing, the server does not start.
3. `topic` is the app's bundle ID (`dev.klav.ios` by default, or the one you
   use when signing it).

The server reads the key on startup (if it is not a valid PKCS#8 P-256 key,
it does not start, and the error does not repeat its content) and then removes
it from its configuration: it keeps only the loaded key. If it arrived via
`KLAV_APNS_KEY`, the process's environment still holds it (visible to anyone
who can read `/proc/<pid>/environ` or the service's variables), so a file is
preferable wherever possible. It signs an ES256 JWT every 40 minutes and
speaks HTTP/2 with `api.push.apple.com` or `api.sandbox.push.apple.com`
depending on the environment each phone registered. It **never** logs the key,
the JWT or device tokens (only the device ID and the reason for a rejection).

What Apple sees: that your server notifies a device, when, and a payload with
the notification type and a random ID (`api.md` §3). Not the agent's name,
nor the reason, nor the item.

An app signed by someone else (for example, the one published on the App Store)
accepts only notifications signed with that person's key: if you self-host the
server and use an app you didn't sign yourself, notifications will arrive
through the hosted plan's relay (phase 8).

### 2.5 Registration and invites

`registration_mode` (ADR [0048](decisiones/0048-invite-beta-and-distribution.md) §1):

- `open`: anyone can register; the bare binary's default, as
  `allow_registration = true` was.
- `invite`: `register/start` and `register/finish` need a valid invite.
- `closed`: nobody can.

`allow_registration` is still read: `true` means `open`, `false` means
`closed`. After the file and the environment are merged, the two must agree,
or the server stops at start-up naming both keys: `true` agrees only with
`open`, and `false` agrees with `closed` **and** `invite`. Every shipped
configuration (`docker-compose.yml`, `deploy/server/server.toml.example`,
Homebrew's) keeps `false` next to `invite`, so that a binary from before
`registration_mode`, which ignores `KLAV_REGISTRATION_MODE`, stays closed
instead of open (T253). Remove it only to choose `open`.

`GET /v1/health` gains `registration_mode`. `registration_open` stays, and is
`false` in `invite` mode, so clients from before invites stop with their "not
open yet" message before the emergency kit and Argon2id.

**Invites** are managed with subcommands of the same binary, against the
configured database (`--config`, `KLAV_CONFIG` or `KLAV_DATABASE_URL`), while
the server runs. There is no HTTP admin API:

```text
klav-server invite create [--email EMAIL] [--uses N] [--expires 30d] [--note TEXT]
klav-server invite ls [--all]
klav-server invite revoke <ID>
```

- `create` prints the code once, on stdout, and its ID; only a labelled
  SHA-256 of the code is stored. `--email` binds it to that address, normalized
  as registration does. `--expires` defaults to 30 days.
- Without `--email` and with `--uses` above 1, it is a batch code: it needs
  `--expires`, at most 14 days, and at most 50 uses (Q3).
- `ls` never shows codes; without `--all`, only usable invites. `revoke`
  doesn't touch accounts already created.
- They never migrate the database: against a schema older than the binary's,
  they stop and say to upgrade and start the server first.
- How to run them: `docker compose exec klav klav-server invite …` (§1), the
  `systemd-run` command of §1 for the systemd unit, or directly with Homebrew.

A failed invite (`POST /v1/auth/invite/check`, or an invite refused in
`register/*`) costs a token from a per-IP bucket, `invite_ip_per_minute` and
`invite_ip_burst` (60 per hour sustained), on top of the `auth_*` limits, and
writes one `warn` log line with the client's IP key, never the code or the
email. Behind a proxy without a trusted IP header (§3.2), every client shares
that bucket; for a personal server that is fine.

### 2.6 Quotas per account

`0` turns a quota off. The owner of the vault is counted.

| Key | What it counts | Default |
|---|---|---|
| `max_account_attachment_bytes` | Declared size of every attachment not purged in the owner's vaults: finished, pending, and those of trashed items | 10 GiB |
| `max_account_vault_bytes` | `overview` + `details` + `wrapped_key` of every item not purged, with their kept versions, plus the `meta` of every vault and project | 1 GiB |
| `max_items_per_account` | Items not purged (trashed ones count until purged) | 100,000 |
| `max_vaults_per_account` | Owned vaults not deleted, and deleted ones until purged | 1,000 |

- Checked inside the transaction that holds the owner's account lock, so two
  concurrent writes can't both take the last free space (T248). Attachments
  count from their declaration (`create`), not from `complete`.
- A write that doesn't grow the account, deleting, moving to the trash and
  reading are never refused. Over a quota, a growing write gets
  `403 quota_exceeded` with the limit, the usage and the maximum.
- A non-zero attachment quota must be at least `max_attachment_bytes`.
  `max_pending_upload_bytes` keeps its own meaning.
- There is no global ceiling: the disk must fit the accounts times their
  quotas (ADR 0048 §3.3).

## 3. TLS and reverse proxy

> The steps for people who use Klav are on the public page [`tls-and-reverse-proxy.mdx`](../apps/docs/src/content/docs/self-hosting/tls-and-reverse-proxy.mdx) (in `apps/docs/src/content/docs/self-hosting/`); a change to those steps goes there first.

`klav-server` speaks plain HTTP and **must not be exposed to the internet like
that**. Session tokens travel in `Authorization` and without TLS anyone on the
network can copy them. The server already sends `Strict-Transport-Security`.

Agents' requests are signed over the path and the query string exactly as the
agent sends them ([`api.md`](api.md) §8.2). A proxy that rewrites `/v1/agent/…`
paths (prefixes, trailing slashes, encoding) breaks the signature and the agent
gets `401`. The same applies to the query string: `klav approval wait` waits
with `GET /v1/agent/approvals/{id}?wait=N`, so a proxy that strips or reorders
the query string also breaks the signature. In addition, that request stays
open for up to 30 s: the proxy's read timeout must be longer. Pass paths
unchanged, as in the examples below.

### 3.0 One command: Tailscale Serve or Caddy

Both keep the server on `127.0.0.1:8080` and pass paths and query strings
unchanged (ADR [0048](decisiones/0048-invite-beta-and-distribution.md) §5.4).
Checked on 2026-11-25 against Tailscale's and Caddy's docs, and Tailscale's
source where its docs say nothing.

**Private (a home Mac mini, a VPS with no open ports): Tailscale Serve.**

```sh
tailscale serve --bg 8080
```

- Serves `http://127.0.0.1:8080` as `https://<machine>.<tailnet>.ts.net`
  (`tailscale serve status` shows it), with a certificate Tailscale issues.
  Only devices in the tailnet reach it; every device that syncs needs
  Tailscale connected.
- "Tailscale Serve requires you to enable HTTPS certificates in your tailnet"
  ([Serve](https://tailscale.com/kb/1312/serve)); if they are off, the CLI
  offers to turn them on. That needs MagicDNS, and publishes the machine's and
  the tailnet's names in Certificate Transparency logs
  ([Enabling HTTPS](https://tailscale.com/kb/1153/enabling-https)): don't use
  a machine name with anything private in it.
- With `--bg` it "runs persistently in the background until you disable it",
  and resumes after a reboot ([CLI](https://tailscale.com/kb/1242/tailscale-serve)).
  `tailscale serve reset` removes it.
- **Paths, query strings and events.** With the default mount `/`, Serve's
  reverse proxy (`httputil.ReverseProxy` with `SetURL` to the target) keeps
  the path and the query string and passes the `Host`, and Go's reverse
  proxy flushes `text/event-stream` immediately (Tailscale's source, as
  below; its docs don't say).
- **Client IP.** Serve's documentation names only its `Tailscale-User-*`
  identity headers. Its source (`ipn/ipnlocal/serve.go`,
  `addProxyForwardedHeaders`) sets `X-Forwarded-For` to the tailnet address
  of the device, replacing any the device sent. The docs leave
  `KLAV_TRUST_FORWARDED_FOR` off anyway: all devices share one bucket per IP,
  which a personal server can live with (§3.2), and a later Tailscale could
  change undocumented behavior.
- **`tailscale funnel` is not recommended:** it publishes the server to the
  internet (T252).
- It doesn't bring iPhone push approvals: that still needs your own APNs key
  with an app you signed, or the phase-8 relay (§2.4).

**Public (a VPS with a domain): Caddy.**

```sh
caddy reverse-proxy --from klav.example.com --to 127.0.0.1:8080
```

- "If the `--from` address has a host or IP, Caddy will attempt to serve the
  proxy over HTTPS with a certificate" ([command line](https://caddyserver.com/docs/command-line#caddy-reverse-proxy)):
  the domain's `A`/`AAAA` record must point at the machine, with ports 80 and
  443 open.
- It is a command, not a service: it serves while it runs, and its docs call it
  "useful for quick deployments, demos, and development". To keep it across
  reboots, use the Caddyfile of §3.1 with the distribution's `caddy` service.
- `reverse_proxy` "sets or augments the `X-Forwarded-For` header field", and
  from clients that aren't `trusted_proxies` "the proxy will ignore their
  values from incoming requests, to prevent spoofing"
  ([reverse_proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)):
  the last address is the client's, so set `KLAV_TRUST_FORWARDED_FOR=true`
  (§3.2). It flushes `text/event-stream` responses immediately, so
  `/v1/events` needs nothing.

### 3.1 Caddy

Caddy obtains and renews the certificate on its own (the same proxy as
`caddy reverse-proxy` in §3.0, as a service; set
`KLAV_TRUST_FORWARDED_FOR=true`):

```caddyfile
klav.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

Caddy forwards SSE events (`/v1/events`) without buffering them.

### 3.2 The client's IP address (`trust_forwarded_for`)

Limits per IP address need the client's real IP. Behind a proxy, the server
sees only the proxy's IP, and all clients would share one bucket.

By default the server trusts no header. There are two ways to tell it where to
get the IP from, and only one can be used:

- With `KLAV_TRUST_FORWARDED_FOR=true` it takes the **last** address in
  `X-Forwarded-For`, the one your proxy (nginx, Caddy) added.
- With `KLAV_TRUSTED_IP_HEADER=<header>` it takes the value of that header,
  which your proxy **replaces** with the client's IP (for example `x-real-ip`
  on Railway, §8.1). If it arrives several times the last one counts; if it is
  missing or is not a single address, the server uses the connection's IP.

Enable either one **only** if there is a proxy in front that always sets that
header and does not pass through the client's. Otherwise, a client could make
up an IP on every request and bypass the limits.

Without either one, behind a proxy all clients share the proxy's IP: limits per
IP (`ip_*`, `auth_ip_*`) become global and the authentication limit per email
becomes per email only, so someone who knows your email could exhaust it.

### 3.3 nginx

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    client_max_body_size 9m;   # larger than max_attachment_chunk_bytes
}
location /v1/events {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_buffering off;       # SSE
    proxy_read_timeout 1h;
}
```

## 4. Data and backups

> The steps for people who use Klav are on the public page [`data-and-backups.mdx`](../apps/docs/src/content/docs/self-hosting/data-and-backups.mdx) (in `apps/docs/src/content/docs/self-hosting/`); a change to those steps goes there first.

### 4.1 What is in `/data`

| Path | Contents |
|---|---|
| `klav.db`, `klav.db-wal`, `klav.db-shm` | SQLite database in WAL mode |
| `attachments/<vault>/<attachment>` | Encrypted attachments (`.part` while uploading) |

The database includes the `server_state` table with the **server's OPAQUE
setup**. If it is lost, nobody can sign in again (the encrypted data is still
safe, but that value has to be restored). Always back up the entire database.

### 4.2 Backing up

The simplest and most consistent way is to stop the server for a moment:

```sh
docker compose stop klav
docker run --rm -v klav_klav-data:/data:ro -v "$PWD":/backup debian:bookworm-slim \
  tar czf /backup/klav-$(date +%F).tar.gz -C /data .
docker compose start klav
```

The volume name is prefixed with the Compose project name (by default, the
directory name: `klav_klav-data`). Check it with `docker volume ls`.

Do not copy the database files while the server is running: SQLite in WAL mode
splits changes between `klav.db` and `klav.db-wal`, and a copy of half-written
files may fail to open. If you cannot stop it, back up the database with
SQLite's backup API, which is consistent even while writes happen, from a
machine with `sqlite3` that can see the volume (the image does not include it),
and copy the attachments separately:

```sh
sqlite3 /path/to/volume/klav.db ".backup '/backups/klav-$(date +%F).db'"
sqlite3 /backups/klav-$(date +%F).db 'PRAGMA integrity_check'   # ok
```

To restore, stop the server, empty the volume, extract the `.tar.gz` into it
and start it again. Starting in phase 3, clients will save the latest revision
of each vault they saw. If you restore an older backup, they will reject the
regression (rollback protection, T7) and you will have to re-sync them on
purpose.

What gets backed up is already encrypted end to end. Even so, guard your
backups with the same care as the server: they contain emails and the metadata
from T13.

**Rolling back to an earlier version.** Migrations run automatically on
startup. A server older than its database still starts: it skips migrations it
does not know, and what they added (tables, columns) stays unused. This holds
as long as they only add tables, or columns that accept NULL or have a default
value. A `NOT NULL` column with no default in a table the older version inserts
into, a new `CHECK` or trigger, or a new table whose foreign key to `accounts`
lacks `ON DELETE CASCADE` breaks the older version while it runs; and if a
migration changes or drops something the older version reads, rolling back
requires restoring a backup. While the older version runs, the new tables do
not track what it does (for example, the `sandboxes` rows of a proxy it revokes
stay live), and the newer version, when it comes back, picks them up as they
were left.

### 4.3 Deleted accounts and backups

Anyone with an account can delete it from the iPhone app, the Mac app or with
`klav account delete` (ADR [0037](decisiones/0037-borrar-la-cuenta.md),
[api.md](api.md) §2.4). There is no setting to turn it off: the person has the
right to delete their data, and you can already delete it by hand. It is
deleted 7 days after requesting it, in the hourly purge
(`retention.purge_interval_secs`), along with everything belonging to the
account and its vaults' files at the same time. The email becomes free for
another account.

What is not deleted:

- **Your backups** keep the account until you delete them or they expire. If
  you restore one taken before the deletion, the account comes back (residual
  risk 60). To delete it again, look in the log for `account deleted` lines
  after the backup and delete those accounts:

  ```sh
  # With the server stopped, for each account_id from the log:
  sqlite3 /path/to/volume/klav.db \
    "PRAGMA foreign_keys = ON; \
     DELETE FROM vault_members WHERE member_type = 'account' AND member_id = '<account_id>'; \
     DELETE FROM accounts WHERE id = '<account_id>';"
  ```

  `PRAGMA foreign_keys = ON` is needed in SQLite so the deletion cascades (the
  server sets it on every connection; the `sqlite3` command line does not). On
  Postgres it always cascades. Those vaults' files are removed by the server's
  next purge, once their vault no longer exists.
- **The log** keeps those lines for as long as you keep it. They carry only the
  `account_id`.
- **The two deletion limits** (5 reauthentications per account per hour, 3
  deletion requests every 7 days) live in memory, like the others (§6): a
  restart clears them.

## 5. Postgres

> The steps for people who use Klav are on the public page [`postgres.mdx`](../apps/docs/src/content/docs/self-hosting/postgres.mdx) (in `apps/docs/src/content/docs/self-hosting/`); a change to those steps goes there first.

SQLite is enough for one person or a family. To use Postgres (CI tests with
version 17):

```sh
KLAV_DATABASE_URL=postgres://klav:<password>@127.0.0.1:5432/klav
```

Migrations run automatically on startup. Attachments stay in `KLAV_DATA_DIR`,
on disk.

> **No TLS to Postgres.** The server does not include TLS for the database
> connection (ADR [0008](decisiones/0008-pila-del-servidor.md)). Run Postgres
> on the same machine, over a socket or `127.0.0.1`, or on a private network.
> What travels is encrypted blobs, but also token digests and OPAQUE records.
> TLS to Postgres arrives with the hosted plan (phase 8, ADR
> [0010](decisiones/0010-decisiones-fase-3-y-plan-alojado.md)).

## 6. Known limitations

> The steps for people who use Klav are on the public page [`index.mdx`](../apps/docs/src/content/docs/self-hosting/index.mdx) (in `apps/docs/src/content/docs/self-hosting/`); a change to those steps goes there first.

- **Single instance.** Rate limits, half-finished logins (2 min) and SSE
  notifications live in memory. Do not run multiple replicas behind a load
  balancer. On restart, half-finished logins are lost and clients reconnect
  their SSE streams.
- **No S3.** Attachments are stored on local disk only.
- **Quotas are per account, not global.** Each account has quotas on
  attachments, vault data, items and vaults (§2.6), and half-finished uploads
  cannot exceed `max_pending_upload_bytes` (1 GiB; any idle for a day are
  deleted). Nothing caps the sum across accounts, and the audit log and other
  per-account rows grow outside the quotas: keep registration in `invite` mode
  on personal instances, and watch the disk.
- **Registration reveals whether an email exists** (`409` on registration).
  In `invite` mode only someone with a valid invite for that email, or a batch
  code, gets that far (ADR 0048 §3.5). Prelogin does not: it returns decoy
  parameters for unknown emails, which is why the server accepts new accounts
  only with the default Argon2id parameters, the same as the decoy.
- **No password change or account recovery** yet. If you lose your master
  password and your emergency kit, the account is unrecoverable by design.

## 7. Where to host it

> The steps for people who use Klav are on the public page [`index.mdx`](../apps/docs/src/content/docs/self-hosting/index.mdx) (in `apps/docs/src/content/docs/self-hosting/`); a change to those steps goes there first.

`klav-server` is a single process with SQLite and fits on the smallest machine
of any provider. What changes between options is how much you maintain yourself
and what happens when it goes down.

| Option | Approximate cost | Maintenance | Availability |
|---|---|---|---|
| **VPS with Docker Compose** (§1, recommended) | A small VPS, around 5 USD/month | You: operating system, Docker, proxy with TLS (§3), backups (§4) | The provider's, high |
| **Railway** (§8) | 5 USD/month for the Hobby plan, which already includes that usage | Little: Railway provides TLS, restarts and volume backups | High; a brief outage on each deploy |
| **Mac mini at home**, private with Tailscale Serve (§3.0) or public with a tunnel (Cloudflare Tunnel) | Electricity; you already own the machine | You, plus Tailscale or the tunnel and your home connection | Your home's: power outages, internet outages, reboots for updates |
| **Hosted plan** (phase 8, does not exist yet) | ~5 USD/month | None | Ours; includes the iPhone notification relay (§2.4) |

We recommend a **VPS with Docker Compose**: it is the option with the fewest
third-party pieces, the image runs with a read-only filesystem and no
capabilities, and backups are a `tar` (§4.2). **Railway** is the easiest if you
do not want to administer a server. A **Mac mini** works for testing or if you
already have one always on: Homebrew's `klav-server` (§1) with Tailscale Serve
(§3.0) keeps it on your tailnet only. With a public tunnel, pass paths and the
query string unchanged (§3) and leave `KLAV_TRUST_FORWARDED_FOR=false` until
you verify how the tunnel sets `X-Forwarded-For` (§3.2). Not Tailscale Funnel,
which publishes the server to the internet.

**If the server goes down, you do not lose access to your passwords**: every
client keeps reading its local copy (the CLI warns you, [`cli.md`](cli.md) §3).
While it is down, however, nothing syncs between devices, changes cannot be
written, and agents get no service: their approval requests and tasks do not
arrive, nor do phone notifications. If you rely on agents working on their own,
availability matters more than price.

## 8. Railway

> The steps for people who use Klav are on the public page [`railway.mdx`](../apps/docs/src/content/docs/self-hosting/railway.mdx) (in `apps/docs/src/content/docs/self-hosting/`); a change to those steps goes there first.

[Railway](https://railway.com) deploys the server from the repo, provides TLS
and a domain, and stores `/data` on a volume. The cheapest option is **a single
service with a volume and SQLite**, without a separate Postgres: that is what
this section describes.

The service uses its own image,
[`deploy/railway/Dockerfile`](../deploy/railway/Dockerfile), because the root
one does not work on Railway:

- it uses BuildKit cache mounts, which Railway accepts only with an `id` that
  contains the service ID
  ([docs](https://docs.railway.com/builds/dockerfiles#cache-mounts)), and a
  template cannot know that;
- it runs as `klav` (UID 10001), and Railway mounts volumes as root, so the
  server would not be able to write to `/data`
  ([docs](https://docs.railway.com/volumes/reference)).

The Railway image builds the same way and starts as root only for a moment: its
entrypoint gives `/data` to `klav` and launches the server as that user, with no
capabilities and with `no_new_privs`. It only touches `/data` (or a directory
inside it, if you change `KLAV_DATA_DIR`), without following symbolic links;
with any other path it refuses to start. That is why you **do not need**
`RAILWAY_RUN_UID=0`, the variable Railway suggests for non-root images: with it
the whole server would run as root. The entrypoint also listens on the `PORT`
Railway provides (8080 if none is set).

### 8.1 Deploy

1. **Project.** In the [dashboard](https://railway.com/dashboard), *New
   Project* → *Deploy from GitHub repo* and choose your copy of `klav`. Railway
   creates a service with the first deploy (it will fail until step 3; that is
   fine).
2. **Volume.** Right-click the service → *Attach Volume*, with mount path
   `/data`. The Hobby plan allows up to 5 GB per volume.
3. **Variables** (*Variables* on the service):

   | Variable | Value | Why |
   |---|---|---|
   | `RAILWAY_DOCKERFILE_PATH` | `deploy/railway/Dockerfile` | The Railway image, not the root one ([docs](https://docs.railway.com/builds/dockerfiles#custom-dockerfile-path)) |
   | `KLAV_ALLOW_REGISTRATION` | `false`; `true` only while creating your accounts (step 6) | §2.1: without it, the server accepts new accounts |
   | `KLAV_TRUST_FORWARDED_FOR` | `false` | See below |
   | `KLAV_TRUSTED_IP_HEADER` | do not create it; `x-real-ip` only after checking | See below |
   | `KLAV_APNS_KEY`, `KLAV_APNS_KEY_ID`, `KLAV_APNS_TEAM_ID`, `KLAV_APNS_TOPIC` | Optional: the `.p8` PEM and its details | Notifications to the iPhone (§2.4) |

   For `KLAV_APNS_KEY`, paste the entire `.p8`, including its `BEGIN` and `END`
   lines. Anyone with access to the Railway project can view the variables:
   grant access only to people who should have the key.
   **Do not create empty variables**: an empty `KLAV_APNS_*` counts as
   configured and the server will not start. **Do not set `RAILWAY_RUN_UID`.**

   Railway's documentation does not say whether `RAILWAY_DOCKERFILE_PATH` is
   relative to the repo root or starts with `/`. If the build uses the root
   `Dockerfile` (it fails on the cache mounts), try `/deploy/railway/Dockerfile`.
4. **Deploy** (*Settings* → *Deploy*): *Healthcheck Path* `/v1/health` and
   *Restart Policy* `On Failure`. Do not set *Custom Start Command*: Railway
   would use it instead of the image's entrypoint.
5. **Domain** (*Settings* → *Networking*): *Generate Domain* for a
   `*.up.railway.app`, or *Custom Domain* for your own. Railway provides TLS.
6. Deploy and check `https://<your domain>/v1/health`. To create your accounts,
   change `KLAV_ALLOW_REGISTRATION` to `true` and deploy, create the accounts
   with `klav signup --server https://<your domain> …` ([`cli.md`](cli.md) §3),
   and set it back to `false` (another deploy). While it is `true`, anyone who
   finds the URL can open an account.

Do not turn on *Serverless*: it puts the service to sleep with no traffic, and
the first request on wake can return `502`
([docs](https://docs.railway.com/deployments/serverless)). An agent asking for
an approval at that moment fails, and the savings are minimal.

**The client's IP address.** Railway's proxy documents that it sets `X-Real-IP`
"to identify the remote client IP", in addition to `X-Forwarded-Proto` and
`X-Forwarded-Host`, but says nothing about `X-Forwarded-For` or whether
`X-Real-IP` replaces one sent by the client
([docs](https://docs.railway.com/networking/public-networking/specs-and-limits#technical-specifications),
checked on 2026-11-05). Always keep `KLAV_TRUST_FORWARDED_FOR=false`. Without
`KLAV_TRUSTED_IP_HEADER`, the server sees the proxy's IP: limits per IP (`ip_*`
and `auth_ip_*`, §2.2) are shared by all clients and the authentication limit
per email is by email only (§3.2). To enable `KLAV_TRUSTED_IP_HEADER=x-real-ip`,
first verify that Railway replaces the header:

1. With the variable set (`x-real-ip`), send more requests than `auth_ip_burst`
   (10) with a different made-up `X-Real-IP` on each one, and different emails:

   ```sh
   for i in $(seq 1 15); do
     curl -s -o /dev/null -w '%{http_code}\n' -H "X-Real-IP: 192.0.2.$i" \
       -H 'content-type: application/json' \
       -d "{\"email\":\"test$i@example.com\"}" \
       https://<your domain>/v1/auth/prelogin
   done
   ```

2. If `429` starts at request 11, Railway replaced the header with your real IP
   and it is safe to keep it. If all 15 return `200`, the server believed the
   made-up IPs: remove the variable.

**Proxy limits** (same page): a request is cut off after 5 minutes without data
and after 15 minutes total, even if data arrives. `klav approval wait` waits
(30 s) and attachment chunks fit easily. SSE events (`/v1/events`) are cut off
every 15 minutes and clients reconnect on their own.

**Deploys.** With a volume, each deploy has a brief outage: the old container
stops before the new one starts, even with a health check
([docs](https://docs.railway.com/volumes/reference)). You also cannot run
replicas with a volume, which matches §6: a single instance.

### 8.2 Backups

Railway backs up the entire volume, including the SQLite database
([docs](https://docs.railway.com/volumes/backups)). In the service's *Backups*
tab, choose one or more schedules:

- daily, kept for 6 days;
- weekly, kept for 27 days;
- monthly, kept for 89 days.

You can also take a manual one before doing something delicate. They are
incremental and billed like the volume. On restore, Railway mounts a new volume
with the backup and leaves the old one unmounted; confirm with *Deploy*. Watch
out: **deleting the volume (*wipe*) also deletes its backups**, and they can
only be restored in the same project and environment.

Those backups are the real safety net. To also keep a copy outside Railway,
connect with [`railway ssh`](https://docs.railway.com/cli/ssh) and pack `/data`
with `tar`, with one caveat: you cannot follow §4.2 there. `railway ssh` needs
the container running, so you cannot stop the server, and the image does not
include `sqlite3` to use `.backup`. A `tar` of the database while the server is
writing **may not be consistent**: copy `klav.db`, `klav.db-wal` and
`klav.db-shm` together during a quiet moment, and **verify the copy** on your
machine before relying on it:

```sh
mkdir copy && tar xzf klav-YYYY-MM-DD.tar.gz -C copy
sqlite3 copy/klav.db 'PRAGMA integrity_check'   # must say ok
```

If it does not say `ok`, redo it or stick with Railway's backup. What §4.2 says
about restoring an older backup (T7) applies here as well.

### 8.3 Cost

According to the [pricing page](https://docs.railway.com/pricing/plans)
(checked on 2026-11-04), the **Hobby** plan costs **5 USD per month and
includes 5 USD of usage**; you pay extra only for what goes beyond that. Usage
is billed per minute:

| Resource | Price |
|---|---|
| CPU | 20 USD per vCPU per month |
| Memory | 10 USD per GB per month |
| Volume | 0.15 USD per GB per month |
| Outbound traffic | 0.05 USD per GB |
| Builds | Free |

A personal server at rest uses almost nothing: in a local test, the image used
about 5 MiB of memory and 0% CPU with no requests. Even counting 50 MB of
memory under real use (0.50 USD), a few minutes of CPU per day and a 1 GB
volume (0.15 USD), it stays well below the included 5 USD: **the expected cost
is the plan's fixed 5 USD**. Watch it under *Usage*; it is an estimate, not a
guarantee.

The Free plan (1 USD credit per month, 0.5 GB volume) can work for trying it
out, but not for storing your passwords: when the plan ends, Railway deletes
volumes after 30 days.

### 8.4 Notifications to the iPhone

What §2.4 says still holds: the App Store app only accepts notifications signed
with the key of whoever signed it. With your own APNs key, notifications only
reach an app you signed yourself (with the same bundle ID in `KLAV_APNS_TOPIC`).
With the App Store app, they will arrive through the hosted plan's relay (phase
8); meanwhile, the app sees approvals when you open it.

### 8.5 Template

A Railway template is a "Deploy on Railway" button that creates the project
already configured. It is published **when the repo goes public**: Railway
supports private repos, but each person would need access to the repo
([docs](https://docs.railway.com/templates/create)).

What it contains:

- **One service**, `klav-server`, with GitHub source `OmarAlex24/klav` (branch
  `main`), public HTTP networking and no start command.
- **One volume** mounted at `/data`.
- ***Healthcheck Path*** `/v1/health` and ***Restart Policy*** `On Failure`.
- **Variables with default values**, which the person can change:

  | Variable | Default |
  |---|---|
  | `RAILWAY_DOCKERFILE_PATH` | `deploy/railway/Dockerfile` |
  | `KLAV_ALLOW_REGISTRATION` | `false` (the description explains to set it to `true` only while creating accounts, §8.1 step 6) |
  | `KLAV_TRUST_FORWARDED_FOR` | `false` |
  | `KLAV_LOG` | `info` |

  `KLAV_TRUSTED_IP_HEADER` does **not** go in the template: left unset, the
  server trusts no header. The description explains how to test `x-real-ip` and
  add it (§8.1).

- **Nothing to ask the person for**: the server starts with no secrets, because
  it generates the OPAQUE setup on first start and stores it in the database.
  The four `KLAV_APNS_*` variables do **not** go in the template: they are
  optional, and an empty variable prevents startup. The description explains
  how to add them (§8.1, step 3).

Configuration lives in the template and on the service, not in the repo:
Railway stopped accepting `railway.json`/`railway.toml` in new services and
stops reading them on 2026-12-01
([docs](https://docs.railway.com/config-as-code)). Its replacement,
`.railway/railway.ts`, is not read on deploy: it is applied by the CLI
(`railway config apply`) against your own project, so it does not work for a
template either ([docs](https://docs.railway.com/infrastructure-as-code)).

To create it:

1. Deploy a project as in §8.1 and verify that it works.
2. In the project, *Settings* → *Generate Template from Project* → *Create
   Template* (or `railway templates create` from the CLI, which does the same,
   [docs](https://docs.railway.com/cli/templates)). You can also start from
   scratch on the workspace's *Templates* page with *New Template*.
3. In the editor, review the service: source, variables and their values, the
   volume at `/data`, the health check and that there is no start command.
   Remove `KLAV_APNS_*`, `KLAV_TRUSTED_IP_HEADER` (which your service may have
   enabled after testing it) and any custom domain, and leave
   `KLAV_ALLOW_REGISTRATION` as `false`.
4. *Create Template* creates a draft with its URL. For the marketplace, publish
   it from the dashboard or with
   `railway templates publish <id> --category Storage --description "…" --readme-file <file>`;
   the first publication requires a long description (`--readme-file`).
5. Add the button to the README with the template's URL.

## 9. Credential proxy (`klav-proxy`)

`klav-proxy` inserts into each HTTP request a provider credential (Northflank,
Railway, Maple…) that the person granted to it, without returning the credential
to the caller (ADR [0036](decisiones/0036-sandboxes-de-agentes.md)), and
redacts it if the provider echoes it back in full. Redaction is a safety net
for accidental echoes, not a barrier: it replaces only the whole value, never a
piece, and an echo in a form it does not recognize gets through (threat model,
T149).
It is another Klav agent, with a **per-item** grant: its key opens only the
items granted one by one. It is a separate service from `klav-server`, with its
own volume. This is layer 3 of the ADR; what it does not do yet is at the end
of the section.

### 9.1 Pairing it

```sh
docker build -f deploy/proxy/Dockerfile -t klav-proxy .
docker volume create klav-proxy-data
docker run --rm -it -v klav-proxy-data:/data \
    --ulimit memlock=-1:-1 --ulimit core=0 klav-proxy \
    init --email ana@example.com --server https://klav.example.com
# With rootless Docker or Podman, remove `--ulimit memlock=-1:-1`: the
# container will not start with that option there (§9.2).
```

`init` creates the proxy's key: with the same limits as `serve` it creates it
in locked memory (§9.2). Without `--ulimit memlock=-1:-1` it still works, but
creates the key unlocked and warns about it.

`init` generates the proxy's identity, registers it and shows the **six
words**. Then, on one of your devices ([cli.md](cli.md) §10.1):

```sh
klav proxy use own klav-proxy      # this agent is the account's proxy
klav proxy grant Northflank --profile northflank \
    --upstream https://api.northflank.com --header authorization \
    --prefix "Bearer " --method GET,POST --path-prefix /v1
```

The first credential adds `--every-device-is-updated` and asks for Touch ID:
the dialog shows those words, derived from the key being signed, the item with
its vault and project, and the rules being granted (host, methods, paths, and
the port, header and field when they are not the defaults; not the profile
name, prefix or rate, [cli.md](cli.md) §10.1). Each credential has its own
profile: which field, in which header, to which host, with which methods and
paths and at what rate.

**Update Klav on all your devices first** (apps, CLI and `klavd`). With the
account's first per-item grant, an older device: with an older CLI or `klavd`,
can no longer list agents; on the iPhone stops loading requests, and on the Mac
stops loading requests and tasks, even behind a new `klavd`; when revoking
another agent with `--rotate`, stops at the proxy's grant and agents after it
lose access. Nothing can check this for you: devices do not report their
version ([cli.md](cli.md) §10.1). And it is permanent, not just until the proxy
is revoked: the server keeps a revoked agent's grant and those versions open
every agent's grant; only updating the device fixes it.
**Issuers.** To let an agent (T3 Code, an orchestrator) create sandboxes with
this proxy: `klav proxy issuer add t3-code --profile northflank --url
tls://proxy.example.com:8443` ([cli.md](cli.md) §10.1). `--url` is where a
sandbox will reach the proxy. This only signs the grants: creating sandboxes
(`klav sandbox start`) arrives in the next layer. Update this `klav-proxy` and
all your devices first: an older `klav-proxy` stops serving any credential once
the first issuer is added, and removing the issuer does not undo that.
**Never approve it with `klav agent approve` or from the app's requests list:**
that grants entire projects, whereas a proxy receives only one credential at a
time. After `klav proxy use`, Klav refuses to do so; before that, it cannot
know that the agent is a proxy.

**The key** (`kag1_…`) is stored in `/data/agents/klav-proxy.key`, created with
mode 0600 from the first byte. The proxy refuses to start:

- with `KLAV_AGENT_KEY` set: a platform stores environment variables where its
  staff and its API can read them (ADR 0036 §11, T150);
- with `SSL_CERT_FILE` or `SSL_CERT_DIR` set: on Linux they replace the system
  TLS roots, and anyone who changes the environment could read every credential
  the proxy sends. Some images have them set by default (Nix-built images,
  often, and some CI images): there you must unset them for the proxy process
  (`env -u SSL_CERT_FILE -u SSL_CERT_DIR klav-proxy serve`);
- with a key file more open than 0600, owned by another user, that is not a
  regular file (a symlink, for example) or in a directory others can write to.

On a Mac, `--key-store keychain` stores it in the Keychain.

### 9.2 Serving it

```sh
docker run -d --name klav-proxy -v klav-proxy-data:/data \
    --ulimit memlock=-1:-1 --ulimit core=0 klav-proxy
# With rootless Docker or Podman, remove `--ulimit memlock=-1:-1` (below).
# equivalent to: klav-proxy serve [--port 8790] [--max-body BYTES] [--timeout SECONDS] \
#     [--channel HOST:PORT] [--no-local-calls] [--require-memory-lock] \
#     [--control-socket PATH | --no-control-socket]
```

With Docker Compose, [`deploy/proxy/compose.yaml`](../deploy/proxy/compose.yaml)
has the same setup (`init` with `docker compose -f deploy/proxy/compose.yaml
run --rm klav-proxy init …`, which inherits the service's `ulimits`, then
`up -d`). Without Docker, on a Linux host with systemd,
[`deploy/proxy/klav-proxy.service`](../deploy/proxy/klav-proxy.service) states
at the top how to create the user and directory and run `init` as that user
with `systemd-run` and the same limits as the service (with `sudo -u` it would
get a session's limits, almost always a finite `memlock`). Neither was tested
on a host: the systemd unit was not started on any host.

- **The proxy's memory** (ADR [0044](decisiones/0044-proxy-key-at-rest.md) §3,
  with Omar's decisions of 2026-11-19). On startup, before reading or creating
  its key, `klav-proxy` (`init`, `serve` and `status`):
  - **turns off core dumps** (`RLIMIT_CORE` to 0). An unprivileged process can
    no longer raise it; one running as root with `CAP_SYS_RESOURCE` could.
  - **on Linux, makes itself not dumpable** (`PR_SET_DUMPABLE` to 0): the
    kernel will not write a core dump even for a piped `core_pattern`
    (systemd-coredump, apport), and another process of the same user can no
    longer debug it with `ptrace` or read `/proc/<pid>/mem`.
  - **If either one fails, it does not start**, neither `init` nor `serve` nor
    `status`, and no option skips it. The message names the step
    (`setrlimit(RLIMIT_CORE, 0, 0)` or `prctl(PR_SET_DUMPABLE, 0)`), the error
    (`EPERM: Operation not permitted`, for example) and what to check: almost
    always a seccomp profile, or a container or service manager setting, that
    blocks that call.
  - **on Linux, locks its memory against swap on fault** (`mlockall` with
    `MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT`). Each page is locked as soon as
    the proxy uses it, and none is made resident solely to lock it (thread
    stacks, especially). What the tests require, with 64 runtime threads: under
    64 MiB resident after one request and after 200 requests through a profile,
    and under 32 MiB growth during those 200. Measured values vary with the
    host and build (always debug): from about 5 MB to about 21 MB after one
    request, and from about 27 to about 34 MB after the 200; without
    `MCL_ONFAULT`, about 200 MB. Every measurement is in ADR 0044 §3.2 ("a
    locked proxy under requests, measured"). The resident memory of the release
    binary under real requests, or under a memory cap, was not measured. It
    requires Linux 4.4 or later; an older kernel rejects it (`EINVAL`), and the
    proxy starts unlocked and reports it, without trying to lock everything up
    front.
  - **It locks only if the `memlock` limit is unlimited or the process can lift
    it.** Under a finite limit, the kernel counts the full size of every marked
    mapping against it, and a later memory allocation could fail and crash the
    proxy mid-request. So it does not lock: it starts anyway, logs a warning
    (`WARN`) with the limit and how to raise it **on every start**, and
    `status` reports `locked: false` with the reason. Having `CAP_IPC_LOCK`
    changes nothing: only the limit decides.
    - To lift the cap: `--ulimit memlock=-1:-1` with `docker run` (also for
      `init`), `ulimits: memlock: -1` in Compose, `LimitMEMLOCK=infinity` in
      systemd.
    - **With a rootless engine** (rootless Docker or Podman), the engine cannot
      grant a hard limit above its own. Then `docker run --ulimit
      memlock=-1:-1 …` fails before starting the container, with a runtime
      error like `error setting rlimit type 8: operation not permitted`, and
      `docker compose up` with `memlock: -1` does the same. There are two ways
      out: remove that option (the proxy starts unlocked and warns about it),
      or raise the limit of the user running the engine
      (`LimitMEMLOCK=infinity` in its systemd user service, or `memlock` in
      `/etc/security/limits.conf`) and restart the engine.
    - **As root:** on a host, with `CAP_SYS_RESOURCE`, the proxy lifts the cap
      itself, even one the operator set on purpose; to prevent locking, use the
      switch below. Inside a default container, root does not have
      `CAP_SYS_RESOURCE`: with the limit the engine gives, it does not lock and
      warns about it.
  - **`--require-memory-lock`** (or `KLAV_PROXY_REQUIRE_MEMORY_LOCK=1`; accepts
    only `1`, `true`, `0` or `false`) makes `init` and `serve` refuse to start
    without the lock. `status` never fails for this.
  - **The memory lock switch:** `--no-memory-lock` on `init` and `serve`, or
    `KLAV_PROXY_MEMORY_LOCK=off` (accepts only `on` or `off`, and also applies
    to `status`), starts without trying to lock or raise the limit, and without
    warning. `status` reports that the lock is turned off. Core dumps stay off
    and the process stays not dumpable. Combined with `--require-memory-lock`
    or its variable, it does not start.
  - **On macOS** there is no `mlockall` (the kernel returns `ENOSYS`) and swap
    is encrypted: there only core dumps are turned off, with no startup
    warning. `status` reports `locked: false` with the reason, and
    `--require-memory-lock` never lets it start.
  - **If the lock took effect but cannot be read back** (`VmLck` is 0 or
    unreadable), the proxy undoes it with `munlockall` before restoring any
    limit it raised, and starts unlocked and reports it.
  - **If `munlockall` also fails** (Omar's decision 19, 2026-11-19), the proxy
    starts anyway, including `status`: memory stays marked for locking,
    unconfirmed, and any limit it raised stays raised (lowering it while the
    lock is on could cause a later allocation to fail). The startup warning and
    `status` say that the lock could not be confirmed or undone, never "locked"
    or "not locked", and `--json` includes `"lock_not_undone": true` with
    `locked: false`. With `--require-memory-lock` it counts as unlocked: it
    does not start. This case has been tested only with mocked calls in tests,
    never on a real kernel, and nobody has checked on which hosts it can occur.
  - **What `klav-proxy status` shows** is what the `klav-proxy serve` that last
    wrote this record recorded, not the proxy's live state (Omar's decisions
    15, 24 and 27). A `serve` writes `<name>.memory` in `<home>/agents/` as
    soon as it is listening, replacing any existing one, and removes it on
    shutdown if it is still its own. A `serve` that fails before listening (an
    occupied port, for example) leaves the record as it was: it may belong to a
    running proxy. One that starts listening and fails to write its own (a full
    disk) exits with an error and also leaves the previous one: that is why
    `status` attributes it to the `serve` that wrote it, not to the last one
    that started listening. `status` cannot tell whether that `serve` is still
    running: one killed with `SIGKILL` leaves its record behind. With two
    `serve` processes in the same home on different ports, both run, the record
    belongs to the last one that wrote it, and when that one stops the other is
    left with no record. It reads the file the same way as the sandbox store (a
    regular file owned by its user, 0600, in a directory only its owner can
    write to, without following symlinks, without blocking and at most 4096
    bytes) and strips hidden characters from what it prints. On a host that
    does not allow locking memory:

    ```
    Memory, as recorded by the klav-proxy serve that last wrote this record, 3 min ago; status can't tell whether that proxy still runs: core dumps off, not dumpable, not locked: the memlock limit is 8 MiB (hard limit 8 MiB) and this process may not raise it (EPERM: Operation not permitted); locking under a finite limit could end the proxy mid-request. To lock, raise it to unlimited for klav-proxy: `LimitMEMLOCK=infinity` in its systemd unit, `ulimits: memlock: -1` in Docker Compose, or `--ulimit memlock=-1:-1` with `docker run`; or turn the lock off with KLAV_PROXY_MEMORY_LOCK=off.
    ```

    With locked memory: `… core dumps off, not dumpable, locked on fault (VmLck
    20196 kB at start).` `VmLck` is the size of the mappings marked for
    locking, not resident memory. In `--json`: `"memory": {"core_dumps": "off",
    "dumpable": false, "locked": true, "vm_lck_kib": 20196, "since": …}`.
    `locked` is `true` only if `mlockall` succeeded and `VmLck`, read right
    after, is greater than 0. With the switch, `"lock_turned_off": true`
    appears; when unlocked, `why`; with a lock that could not be confirmed or
    undone, `"lock_not_undone": true` and `… lock could not be confirmed and
    could not be undone: …`; `since` is in Unix ms, and `dumpable` is `null` on
    macOS. Without a record: `Memory: no record from a klav-proxy serve on this
    home.`, and no `memory` in `--json`; that does not say whether a proxy is
    running. A record that claims both `locked: true` and `lock_not_undone:
    true` (no `serve` writes it that way) is read as the decision 19 state,
    with `locked: false`, in both text and `--json` (Omar's decision 28).
  - **The line `status` writes about its own process** (Omar's decision 26,
    2026-11-19). On Linux, `status` also writes a line to stderr about its own
    process's memory, stating that it is for that process and not for any
    `serve`. It comes from what that same process's hardening achieved on
    startup, with no second lock attempt, and is printed before reading the
    agent or calling the server, so it appears even if that fails (printing it
    first is the layer's own choice L26, which Omar accepted in decision 30):

    ```
    klav-proxy: memory of this status process, not of any serve: core dumps off, not dumpable, locked on fault (VmLck 20440 kB at start).
    ```

    When unlocked, the ending is `not locked: <reason>.`; with the switch, `not
    locked: the lock is turned off (KLAV_PROXY_MEMORY_LOCK=off).`; in the
    decision 19 state, `lock could not be confirmed and could not be undone:
    <reason>.`. Standard output, in both text and `--json`, does not change. On
    macOS, where nothing can be locked, it does not write that line (the
    layer's own choice L25, which Omar accepted in decision 30).
  - **On Railway** it was not checked whether a service can lift the `memlock`
    cap. If it cannot, the proxy starts anyway and `status` reports `locked:
    false` with the limit it found; core dumps stay off and the process stays
    not dumpable regardless.
  - **What remains:**
    - copies of the value in `hyper` and `rustls` buffers, which are not wiped
      (with locked memory, they do not go to swap either);
    - whoever operates the machine as root, who can read memory and the key
      file anyway (residual risk 53);
    - **a process of the same user.** Making the proxy not dumpable prevents
      debugging it or reading its memory, but not reading the key file (0600
      owned by that same user) or the rest of the data directory. Run the proxy
      as a user dedicated to it (the systemd unit creates `klav-proxy`), or on
      a Mac with `--key-store keychain`.

    Better yet, put the data volume on an encrypted disk; the proxy cannot
    check for that.

#### Before upgrading a running proxy

Starting with layer 1 of ADR 0044, an upgraded proxy behaves as follows
depending on where it runs:

| Where it runs | What it sees on upgrade |
|---|---|
| Linux with unlimited `memlock` (`LimitMEMLOCK=infinity`, `ulimits: memlock: -1`, `--ulimit memlock=-1:-1`), or with a finite soft limit under an unlimited hard limit, which it raises without privileges. The systemd unit and Compose file in `deploy/proxy` include this, but arrive with this version: a proxy already running uses them only if you adopt them | Locks its memory on fault and `status` changes to `locked: true`. With a memory cap, see below. Its resident memory was measured in tests, not under real load (above) |
| Linux with the default limit, finite soft and hard, without `CAP_SYS_RESOURCE` | Does not lock: a `WARN` on every start with the limit and how to raise it, and keeps serving |
| Root on a host (with `CAP_SYS_RESOURCE`) | Lifts the `memlock` cap itself and locks, even if the cap was set on purpose; `klav-proxy status` run as root does too. To prevent this, set `KLAV_PROXY_MEMORY_LOCK=off` |
| Root in a default container (without `CAP_SYS_RESOURCE`) | Cannot lift the cap: does not lock and warns, as with a finite limit |
| The `deploy/proxy` image without `--ulimit memlock=-1:-1` | Same as with a finite limit |
| A rootless engine with `--ulimit memlock=-1:-1` or `memlock: -1` | The container does not start (above): remove the option or raise the engine's limit |
| macOS | Only core dumps are turned off, with no warning |

In all of them:

- **No core dumps or debugger from the same user.** If you diagnosed the proxy
  with a core file, `gdb -p` or `strace -p` as its user, you can no longer do
  so; as root, you still can.
- **The proxy's `/proc/<pid>` becomes owned by root.** Once not dumpable, the
  kernel gives root (in a container with its own user namespace, that
  namespace's root) ownership of `/proc/<pid>` files: a monitoring tool running
  as the same user as the proxy can still read world-readable files (`status`,
  `cgroup`), but no longer `environ`, `fd` or `mem`.
- **New reasons not to start:**
  - `setrlimit(RLIMIT_CORE)` or, on Linux, `prctl(PR_SET_DUMPABLE)` failing (a
    strict seccomp profile, for example); this applies to `status` too, and the
    switch does not skip them;
  - a value rejected by `KLAV_PROXY_REQUIRE_MEMORY_LOCK` or
    `KLAV_PROXY_MEMORY_LOCK`;
  - the switch and the requirement set at the same time;
  - a `serve` that, once listening, cannot write its memory record.

  A lock that cannot be confirmed or undone is no longer one of them (above):
  without the requirement, it starts and reports it.
- **A syscall filter that kills.** `init`, `serve` and `status` now call,
  before anything else, `setrlimit(RLIMIT_CORE)` and, on Linux,
  `prctl(PR_SET_DUMPABLE)`; with the lock on, they then call `getrlimit` and
  possibly `setrlimit` for `RLIMIT_MEMLOCK`, `mlockall` and possibly
  `munlockall`. The switch removes only the locking calls. With glibc (the
  image is Debian), `getrlimit` and `setrlimit` are wrappers around a single
  syscall, `prlimit64` (getrlimit(2)), and that is what a filter sees: the core
  dump limit call and the `memlock` limit calls are the same syscall. With
  systemd's `SystemCallFilter=` without `SystemCallErrorNumber=`, the default
  action for a disallowed syscall is to kill the process with `SIGSYS`
  (systemd.exec(5)); a seccomp profile with a killing action (`SCMP_ACT_KILL`,
  `SCMP_ACT_KILL_PROCESS`) does the same. The proxy dies before writing
  anything, and with `Restart=` or `restart:` the service enters a restart
  loop. With `SystemCallErrorNumber=` (an errno) or Docker's default profile
  (`SCMP_ACT_ERRNO`), the call fails with an error:
  - if it is `prctl` or `prlimit64`, the proxy refuses to start, naming the
    failed call by its wrapper name: the error says `setrlimit`, not
    `prlimit64`, which is what to look for in the filter. Because `prlimit64`
    is also used for the core dump limit, which runs first, a filter rejecting
    it stops startup right there: it never reaches "starts unlocked";
  - if it is `mlockall`, it starts unlocked and reports it;
  - if it is `munlockall` after an unconfirmed lock, it lands in the decision
    19 state (above).

  Which syscalls each systemd group contains is shown by `systemd-analyze
  syscall-filter`. What was run to verify this is at the end of this section.
- **A memory cap becomes a wall.** With the lock enabled, every page the proxy
  touches is off limits for the kernel to reclaim or swap out, including
  file-backed pages (the binary and its libraries). Under a cap (`MemoryMax=`
  in systemd, `--memory` or `mem_limit` in Docker), the kernel can no longer
  reclaim those pages: when it hits the cap, it kills the process. A proxy
  running as root on the host, or with unlimited `memlock`, starts locking on
  upgrade **with no configuration change**. Before upgrading, check whether it
  has a cap and what it is, using the commands below. If the cap is tight, or
  you do not want to find out, `KLAV_PROXY_MEMORY_LOCK=off` leaves it as
  before. What was measured: in CI's `docker` task, the release image starts
  locked under `--memory 64m`, with `TOKIO_WORKER_THREADS=64`, and exits
  because it is not paired there (it does not find its agent), so it serves no
  requests. That case shows that a locked startup fit under that cap, not how
  many threads the runtime spawned: the log shows only the variable that was
  passed, and `VmLck` reads the same with or without it. The resident memory of
  the release binary under real requests, and under a cap, has not been
  measured.
- **The switch** `KLAV_PROXY_MEMORY_LOCK=off` leaves memory behavior as before
  the upgrade, without warning, and keeps core dumps off.
- **`klav-proxy status` also hardens itself** before reading the key: under
  whatever limit it has, it locks its own memory, and as root on a host it can
  lift the cap to do so. The switch applies to it as well. What it achieved is
  reported in its stderr line (above).
- **Never run two `serve` processes in the same home.** If the second uses the
  same port, it fails and leaves the first one's record. If it uses another
  port, both serve with the same key, and when the one that last wrote the
  record stops, `status` no longer shows a record even though the other is
  still running.
- **Before swapping the binary, run a dry run with the service's settings:**
  the new binary runs `status` with the service's user, limits, capabilities,
  filter and cap. Running `klav-proxy status` in a terminal does not test this:
  the terminal does not run under the unit's or container's filter, cap or
  limits.

  **What it does.** It opens no port, but it is a real `status`: it loads the
  key, sends a signed request to the Klav server and may rewrite the agent's
  config file in the home, just as `status` does today. Run it with the same
  user and the same home as the service.

  **What it shows.**
  - That no hardening call kills or stops the process under those settings: if
    the line `klav-proxy: memory of this status process, …` appears on stderr,
    it passed all of them. If the process dies with `SIGSYS` without printing
    anything, or fails to start with `cannot turn core dumps off` or `cannot
    make the process not dumpable`, the upgraded service would do the same.
  - In that line, whether a process with those settings locks its memory:
    `locked on fault (VmLck …)` means the upgraded `serve` will lock with those
    same settings, so the memory cap matters (above); `not locked: <reason>`
    means it will not lock, and why.
  - It does not show the memory of a `serve` handling requests under the cap.

  With a binary older than this version, the dry run shows nothing about
  locking: that line is new.

  The commands, replacing `<…>` with your values:
  - **systemd.** Read the unit along with its drop-ins: `systemctl cat <unit>`.
    `systemd-run` creates a new transient unit that inherits nothing from
    yours: copy by hand `User=`, `LimitMEMLOCK=`, `LimitCORE=`, `MemoryMax=`,
    each `SystemCallFilter=` line, `SystemCallErrorNumber=`,
    `CapabilityBoundingSet=`, `AmbientCapabilities=`, `Environment=`,
    `EnvironmentFile=` and `Slice=`, plus whatever `--home` or `--name`
    `ExecStart=` passes, and any other `[Service]` option that restricts
    syscalls, capabilities or memory. Systemd's "Transient settings" page marks
    every option in this list as accepted in a transient unit.

    ```sh
    sudo systemd-run --wait --pipe --collect \
        -p User=<user> -p LimitMEMLOCK=<as in the unit> -p LimitCORE=0 \
        -p MemoryMax=<as in the unit> \
        -p 'SystemCallFilter=<one line from the unit>' \
        -p SystemCallErrorNumber=<as in the unit> \
        -p 'CapabilityBoundingSet=<as in the unit>' \
        -p 'AmbientCapabilities=<as in the unit>' \
        -p EnvironmentFile=<as in the unit> \
        -E KLAV_HOME=<its home> --slice=<as in Slice=> \
        /path/to/new-klav-proxy [--home <as in ExecStart=>] [--name <as in ExecStart=>] status
    ```

    Drop each line for an option the unit does not set. Repeat `-p
    'SystemCallFilter=…'` for each line in the unit: as in the unit, they
    combine. An empty `CapabilityBoundingSet=`, like the one in the
    `deploy/proxy` unit, is not "unset": it leaves the process with no
    capabilities (systemd.exec(5)), so copy it empty (`-p
    CapabilityBoundingSet=`). Without `--slice`, the transient unit lands in
    `system.slice`, which may have a different cap than your service's. With
    `--wait`, `systemd-run` exits with the process's status and summarizes it
    at the end: if the filter kills it, you see it there, not when restarting
    the service. **This command has not been run:** no Linux host with systemd
    was used. Its options and properties were checked in the `systemd-run`,
    systemd.exec(5) and "Transient settings" pages.
  - **Docker.** Inspect the running container:

    ```sh
    docker inspect --format '{{.Config.User}} {{.HostConfig.Memory}} {{json .HostConfig.Ulimits}} {{json .HostConfig.CapAdd}} {{json .HostConfig.CapDrop}} {{.HostConfig.Privileged}} {{json .HostConfig.SecurityOpt}}' <container>
    docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' <container> \
        | grep -E '^KLAV_(HOME|PROXY_MEMORY_LOCK|PROXY_REQUIRE_MEMORY_LOCK)='
    ```

    The first prints the user, the cap in bytes (0 for no cap), the `ulimits`,
    added and dropped capabilities, whether it is privileged and the security
    options; the second prints only the Klav variables that matter here. Do not
    print its whole environment or all `KLAV_` variables: `KLAV_AGENT_KEY` is
    the agent's key. A custom seccomp profile appears as `seccomp={…}`, with
    the profile's content rather than the file path: the CLI reads the file and
    sends its content to the Docker daemon (Docker's "Seccomp security
    profiles" page). `null` in `SecurityOpt` means the default profile, and
    `seccomp=unconfined` means none. To get the profile back as a file:

    ```sh
    docker inspect --format '{{range .HostConfig.SecurityOpt}}{{println .}}{{end}}' <container> \
        | sed -n 's/^seccomp=//p' > profile.json
    ```

    If `SecurityOpt` has `seccomp=unconfined`, that file ends up containing
    only the word `unconfined` and is not a profile: do not use it, and pass
    `--security-opt seccomp=unconfined` directly. If the file is empty, the
    container uses the default profile: drop the option.

    Then run the new image with the same settings, dropping each option whose
    value came out empty (`null`, `[]`, 0 or `false`):

    ```sh
    docker run --rm --user <user> --memory <cap> \
        --ulimit memlock=<as in the container> --ulimit core=0 \
        --cap-drop <each from CapDrop> --cap-add <each from CapAdd> --privileged \
        --security-opt seccomp=profile.json --security-opt <each other from SecurityOpt> \
        -e <each of those variables> \
        -v <volume>:/data <new-image> status
    ```

    With Compose, `docker compose -f <compose.yaml> config <service>` shows
    the service's settings (`user`, `mem_limit`, `ulimits`, `cap_add`,
    `cap_drop`, `privileged`, `security_opt`, `environment`). `config` resolves
    variables and environment files and prints their values: if the service
    shares an env file with other secrets, do not paste or save that output
    where others can read it. `docker compose -f <compose.yaml> run --rm
    --no-deps <service> status` runs with the service's configuration (its
    documentation does not spell out which settings carry over to the `run`
    container), so the `docker run` above is the dry run you can verify.

  - **What the running process actually has.** A unit without `User=` or
    `LimitMEMLOCK=`, or a container without `--ulimit`, shows nothing in the
    checks above, and that is precisely the root or inherited-limit case. Read
    the process: get its pid with `systemctl show -p MainPID --value <unit>` or
    `docker inspect --format '{{.State.Pid}}' <container>`, and then

    ```sh
    grep -E '^Max (locked memory|core file size)' /proc/<pid>/limits
    grep -E '^(Uid|CapEff|VmLck|VmRSS)' /proc/<pid>/status
    echo $(( 0x$(awk '/^CapEff/ {print $2}' /proc/<pid>/status) >> 24 & 1 ))   # 1: has CAP_SYS_RESOURCE
    ```

    Whether the upgraded proxy will lock is answered by the dry-run line; this
    is how to check an already-running process. It locks if the **hard** limit
    of `Max locked memory` (the second column) is `unlimited` (a finite soft
    limit under an unlimited hard limit is raised without privileges), or if it
    has `CAP_SYS_RESOURCE` in `CapEff`, which lets it raise a finite hard
    limit. `Uid` 0 does not decide it: root in a default container does not
    have `CAP_SYS_RESOURCE` and does not lock (the table above), nor does a
    root unit whose `CapabilityBoundingSet=` drops it; an unprivileged user
    with that capability does lock. The capability works to raise the limit
    only in the initial user namespace (getrlimit(2)): in a rootless container,
    `CapEff` may show it without it working. And a filter rejecting `mlockall`
    prevents locking anyway: that is why the real answer is the dry-run line.

  - **The memory cap.** On cgroup v2 (`stat -fc %T /sys/fs/cgroup` prints
    `cgroup2fs`), caps are hierarchical: a slice above the service can cap it
    even if its own `memory.max` says `max`. On the host, read the process's
    and its ancestors':

    ```sh
    p=$(sed -n 's/^0:://p' /proc/<pid>/cgroup)
    while [ -n "$p" ]; do
      printf '%s %s\n' "$p" "$(cat "/sys/fs/cgroup$p/memory.max" 2>/dev/null || echo -)"
      [ "$p" = / ] && break
      p=$(dirname "$p")
    done
    ```

    The cap that applies is the smallest; `max` means uncapped, and the root
    has no `memory.max` (`-`). Inside a container with its own cgroup namespace
    the path is `/` and ancestors are not visible: run it on the host. On
    cgroup v1 or a hybrid setup, `/proc/<pid>/cgroup` has one line per
    hierarchy and this command does not work: take the path from the `memory`
    line (`N:memory:/path`) and read
    `/sys/fs/cgroup/memory/<path>/memory.limit_in_bytes` and that of each
    parent directory above it, which also apply; a huge number (close to 2^63)
    means uncapped. The v1 form comes from the kernel documentation (cgroup-v1,
    `memory`) and was not run.

  **What of this was run** (Linux 7.0 in the Docker Desktop VM, arm64, the
  debug binary of this version in `debian:bookworm-slim`, as uid 1000, with
  `--ulimit memlock=-1:-1`; no Linux host):
  - the `docker run … status` above, with `--entrypoint` pointing to the binary
    and an empty home, without a custom profile, with
    `KLAV_PROXY_MEMORY_LOCK=off`, with `--ulimit memlock=65536:65536` and with
    seccomp profiles that allow everything except one syscall. Without a custom
    profile, the line says `locked on fault`; with the switch or the finite
    limit, `not locked` and the reason. A profile that kills `mlockall`, or
    `prctl` with `PR_SET_DUMPABLE`, terminates `status` with `SIGSYS` (exit
    code 159) without printing anything, while `--version`, which exits before
    hardening, works. With an errno, `mlockall` gives `not locked: mlockall(…)
    failed (EPERM…)`, and `prctl` (`PR_SET_DUMPABLE`) or `prlimit64` give the
    startup error naming the call: `prlimit64` stops at the core dump limit. A
    profile that kills the `getrlimit` and `setrlimit` syscalls changes
    nothing, which matches glibc using `prlimit64`; `strace` was not in the
    local images and was not used. A profile that kills `prlimit64` does not
    let even `/bin/true` start on the engine used (Docker Engine 29.9.2, runc
    1.5.2): no container runs with such a profile there;
  - the `docker inspect` templates (including `.State.Pid` and the variables
    one, which did not print a `KLAV_AGENT_KEY` set on purpose) against test
    containers, and the profile recovered with `sed`, reused as a file;
  - the three `/proc/<pid>/status` reads, inside a container on its own PID 1:
    with `--cap-add SYS_RESOURCE` the `CapEff` calculation gave 1, and as root
    in a default container, 0;
  - the cgroup v2 walk inside a container with `--cgroupns host` and `--memory
    64m`: its cgroup read 67108864, its parent `max`, the root `-`.

  Not run: `systemd-run`, `systemctl cat`, `systemctl show`, `systemd-analyze
  syscall-filter`, `docker compose config`, `docker compose run`, the v1 cap
  form or any `/proc` read from a host.

- **Listens only on `127.0.0.1`**, and no option, variable or file changes
  that. Publishing the container port does not expose it. Sandboxes reach it
  over the authenticated channel (`--channel`, below), through
  `klav-forward up` inside each one (api.md §8.11). The local listener does not
  authenticate the caller: any process on the same machine (in the same
  container) can use its profiles. On a multi-user host, any user's processes
  can too, and the audit log says only that the proxy called, not who did. With
  the issuer on the same host, as in daily use under ADR
  [0042](decisiones/0042-sandboxes-for-daily-use.md), the issuer can use them
  too. For that use, Omar decided on 2026-11-17 on a host that does nothing
  else and the `--no-local-calls` option.
  A request carrying a browser's `Origin` or `Sec-Fetch-Site`, or whose `Host`
  is not exactly `127.0.0.1:<port>` or `localhost:<port>`, receives a `403`
  without reaching the server or the provider, and responses have
  `Access-Control-*` headers stripped. `Sec-Fetch-Mode` alone is not enough to
  reject it: Node's `fetch` sends it on every request. A browser older than
  Fetch Metadata (Chrome before 76, Firefox before 90, Safari before 16.4) can
  still make a blind `GET` without either header (T149).
- **`--no-local-calls`** (ADR 0042 §3): the local listener rejects every call
  to a profile with `403 klav_not_allowed`, regardless of path, method or
  headers, before asking the server or reading any credential. The signed
  issuer API (`/_klav/sandboxes`, [api.md](api.md) §8.9) and the sandbox
  channel stay unchanged: only sandboxes reach the profiles. Without the
  option, nothing changes; it is not the default because the manual test guide
  and the tests use local calls. The startup log (`klav-proxy listening`)
  reports it with `local_calls` set to `false` (`local_calls=false` in `pretty`
  format, `"local_calls":false` in JSON, the Docker image's format). It limits
  what another process on the host can use, but does not make a shared host
  safe.
- **The local socket** (ADR 0036 E3.5, layer 11): `serve` also opens
  `<home>/agents/<name>.sock` (0600, same uid only; `/data/agents/klav-proxy.sock`
  in the Docker image), where the person on that machine lists its live
  sandboxes and revokes them with no signature (`klav proxy local status|revoke`,
  [api.md](api.md) §8.14). It shows metadata only and only takes access away.
  `--control-socket PATH` moves it and `--no-control-socket` turns it off; a
  failure to open it at the default path is a warning, not a failed start.
- **Creating Boat machines from this host** (ADR 0042 §5): `klav sandbox start
  … -- deploy/sandbox/new-sandbox`, as the issuer's OS user, creates the
  sandbox's Tailscale key and the machine via the Boat API, with no secret in
  any argument ([deploy/sandbox/README.md](../deploy/sandbox/README.md)). It
  reads `~/.config/klav-sandbox/config`, which decides which servers receive
  the secrets and therefore must be writable only by that user, and two 0600
  files owned by that user: the Boat key and the Tailscale OAuth client. It
  does not use the inherited `PATH` or proxies. With them, the host holds four
  secrets together (the proxy's key, the issuer's key, the Boat key and the
  Tailscale client): whoever controls the host has all four (ADR 0042 §11).
- **The sandbox channel** (`--channel HOST:PORT`, layer 6): with this option
  the proxy also listens on that address, for example the Mac's Tailscale
  address or `0.0.0.0:8791` behind Railway's TCP Proxy, using TLS 1.3 only and
  its own key, which each sandbox package pins. Whoever connects must prove a
  channel key, and can only use the sandbox that key claimed ([api.md](api.md)
  §8.10). The URL the person signs for the issuer (`klav proxy issuer add --url
  tls://HOST:PORT`) must reach this address. Without `--channel`, no sandbox
  reaches the proxy. Next to the store sits `<name>.sandbox-channels`: always
  move it together with `<name>.sandbox-store`.
  Calls over the channel go through the same browser check as local calls
  (`Origin`, `Sec-Fetch-Site` and a `Host` of `127.0.0.1` or `localhost`, with
  any port): the proxy enforces it, not `klav-forward`, which only forwards
  bytes ([api.md](api.md) §8.10). So do `GET /_klav/status` and
  `POST /_klav/release`, which also accept `Host: klav-proxy`, the forwarder's
  host: that way a web page inside the sandbox cannot end it with a form or
  read its status.
  `klav-forward down` uses `POST /_klav/release` to release its sandbox
  (reason `released`) before stopping, freeing its `--max-live` slot; a
  forwarder stopped with a signal does not release it ([api.md](api.md) §8.11).
- **The limits of `klav-forward`** inside the sandbox ([api.md](api.md) §8.11),
  to see why a call gets `klav_forward_busy`: `FIRST_BYTE` 20 s for the first
  byte of a local connection, which holds no slot until then; `MAX_RELAYED` 12
  concurrent calls and `STATUS_LANE` 2 for `klav-forward status`; `TURN_WAIT`
  10 s waiting for a turn and `MAX_WAITING` 64 waiting connections, and beyond
  that `503 klav_forward_busy`; `RELAY_IDLE` 240 s with no byte in either
  direction; `DRAIN` 1 s reading whatever the caller keeps sending on close, so
  closing does not discard the response.
  If you raise `--timeout` above 3 minutes, a call silent for more than 240 s
  is cut off by the forwarder.
- **A channel port open to the internet can be tied up by anyone.** Nobody gets
  in without a sandbox's key, but anyone who can reach the port can consume
  handshakes and non-sandbox connections, delaying or blocking claims and new
  forwarder connections. The limits ([api.md](api.md) §8.10) make that more
  expensive, not impossible: behind a TCP Proxy every connection arrives from
  the same address, so there is no per-source-address limit. **Tailscale is the
  first choice** (ADR 0036 §6): the port is visible only to nodes on your
  network. Use `0.0.0.0` behind Railway's TCP Proxy only if you accept that.
- **Pieces of the value in responses:** `klav-proxy status` reports, per
  profile, how many pieces of the value (12 characters or more) came back in
  responses since the proxy started, and the log writes one line per response.
  The proxy lets them through, and a sandbox cannot tell they were counted; a
  program on this machine running as the same user as the proxy can read those
  counts. Several in a row may indicate a sandbox getting the service to echo
  its guesses: check who uses that profile and, if needed, stop the sandbox and
  rotate the value.
- **Unconfirmed thefts:** if `klav-proxy status` shows any, someone else had
  that sandbox's package, and the proxy could not confirm that the audit log
  recorded it, because the server already considered the sandbox ended. Check
  the audit log and review who could have seen the sandbox's environment.
- **A persistent volume is required** (heartbeat, ADR 0036 E3.3). The data
  directory (`/data` in the image) holds the proxy's record and key, its
  sandbox store (`<name>.sandbox-store`), the channels
  (`<name>.sandbox-channels`), what the running `serve` enabled on its memory
  (`<name>.memory`) and the heartbeat (`<name>.sandbox-heartbeat`: the store
  epoch and the last `seq`; decided by Omar on 2026-11-13, even though the ADR
  places `seq` in the store). Without a volume, every restart starts a fresh
  store: the proxy logs a `sandbox.store_reset` in the audit log and forgets
  live sandboxes, which it can no longer end or revoke; the server cuts off
  their access when they expire, and until then the audit log shows them as
  live. Always move these files together.
- **The heartbeat** (`PUT /v1/agent/sandboxes/state`, [api.md](api.md) §8.8):
  before the first one, the proxy logs its store's epoch (`sandbox.store_reset`).
  After that it sends one every 5 minutes with live sandboxes and every 30 with
  none, and earlier—at most once per minute—when a sandbox connects or
  disconnects or the previous heartbeat did not get through. The server accepts
  it only from a proxy whose grant has profiles or issuers (`403 forbidden` in
  the log otherwise; decided by Omar on 2026-11-13). What the apps will show
  once they display the sandbox list (arriving in a later layer):
  - **Age comes from the proxy's clock** (`sent_at_ms`), not the server's.
  - **A slow clock** makes the heartbeat look older than it is. **A clock fast
    by more than 5 minutes** causes the server to reject the heartbeat (`400`,
    in the proxy's log) and devices to ignore it: the app will show no signs
    from the proxy even though it is alive. Keep the host's clock synced (NTP).
  - **A sleeping Mac** sends no heartbeats: with live sandboxes, the app will
    show no signs from the proxy after 10 minutes, and with none, after 40.
    While paused the server rejects it: the proxy keeps the last one and, on
    resume, sends it as is within 75 s at most (one minute since the last
    attempt plus the 15 s between checks), and a new one a minute later.
  - **Restoring an old copy of the volume** causes the server to reject its
    `seq` with a `409`: the proxy starts a new epoch, logs it in the audit log
    and never repeats a `seq` (accepted by Omar on 2026-11-15).
  - **One process per proxy.** Two with the same key (two replicas, or a deploy
    that overlaps old and new) steal the epoch from each other: each logs a
    `sandbox.store_reset` on every attempt, at most once per minute, until only
    one remains.
- **Fixed limits:** 64 open connections (the next waits), 16 concurrent
  requests (the next receives `429`), and a 60 s timeout per response chunk,
  from the provider or from the caller; after that the proxy drops the value
  and the response ends in an error (the transfer is broken, never appearing
  complete), just as when the provider cuts it off mid-stream. `--timeout`
  (120 s by default) covers the whole response, body included.
- **Streams** (`Content-Type: text/event-stream`, the MCP gate of ADR 0036
  §7): `--timeout` covers only the headers; the stream may then stay open
  for up to 15 minutes from when the proxy took the value, and is cut after
  2 minutes without a chunk. Each event goes out with the chunk that ends
  its line, redacted; a line over 1 MiB cuts the response. An open stream
  holds its request slot, and is cut with an error when its sandbox ends for
  any reason or the person pauses the agents ([api.md](api.md) §8.7 and
  §8.10). The redactor's copy of the value lives as long as the stream.
- **Mode (a), base URL:** a tool calls
  `http://127.0.0.1:8790/<profile>/<path>` and the proxy sends
  `https://<profile's upstream>/<path>` with the credential in the profile's
  header.
- **For each request**, the proxy asks the Klav server for the item
  (`POST /v1/agent/access` with method, host and path), which evaluates the
  policy and logs it; it never caches authorization. Revoking the proxy or
  pausing agents cuts off the next request.
- **HTTP proxies:** the client talking to the Klav server honors `HTTPS_PROXY`
  (TLS is still verified and responses are signed; that proxy sees the server's
  host and when it is called, and can block calls), while the client talking to
  providers ignores proxy variables.
- **TLS roots:** verifies each provider's certificate against the system roots.
  The image installs `ca-certificates` and the proxy refuses to start if it
  finds none.
- **Logs:** JSON on stderr, with the method, status and error code, and the
  listening port (including with `--port 0`). A response where the proxy
  redacted the value also writes a line with the profile and how many matches
  there were: many in a row may be a sandbox probing for the token piece by
  piece. Never the path, query string, any header, body or value.

### 9.3 What it does with each request

- **Rejects** anything the policy cannot judge as is: a method that is not 1 to
  16 uppercase letters, `CONNECT`, `TRACE`, a path not in its single canonical
  form (spec §13.4) or containing `"`, an absolute URI, and a path the URL
  parser would rewrite differently. What is checked is, byte for byte, what is
  sent. For a non-canonical path, the message says which escape or character it
  rejected and how to send it (`%2C` escapes `,`, which goes as is), without
  repeating the rest of the path: Go's `PathEscape` and JavaScript's
  `encodeURIComponent` escape those characters by default.
- **The query string** (`?…`) goes as is, byte for byte, and is not part of the
  policy or the approval. One that names the method is rejected (`_method`,
  `x-http-method-override` and similar, unescaped up to three times, as an
  array base, `_method[]`, or as the final bracketed key, `a[_method]`; a name
  still escaped after three decodings too). A `_method` in a form body
  (`application/x-www-form-urlencoded`, read by Rails and Laravel) is not
  checked.
- **The value:** the profile's `field` or, without it, `password` on a login
  and `api_key` on an API key. Never a TOTP seed.
- **Strips** from the request `Authorization`, `Cookie`, `Proxy-Authorization`,
  the profile's header, method-override headers (`X-HTTP-Method-Override`,
  `X-HTTP-Method`, `X-Method-Override`), `Host`, hop-by-hop headers,
  `Forwarded`, `X-Forwarded` and all `X-Forwarded-*`, `X-Original-URL`,
  `X-Original-URI`, `X-Original-Host`, `X-Host`, `X-Rewrite-URL`, `Via`,
  client-IP headers (`X-Real-IP`, `Client-IP`, `X-Client-IP`, `True-Client-IP`,
  `CF-Connecting-IP`, `Fastly-Client-IP`, `X-Cluster-Client-IP`), all
  `X-Envoy-*` and `Klav-*`.
  Sends `Accept-Encoding: identity`.
- **SSRF:** resolves DNS itself and rejects the whole lookup if any address is
  not public (private, loopback, link-local, CGNAT, cloud metadata, IPv4 inside
  IPv6). Connects only to the addresses it checked, with no second lookup in
  between. Never uses `HTTPS_PROXY` and speaks HTTPS only.
- **Response:** does not follow redirects (`502 klav_upstream_blocked`); a
  `304 Not Modified` passes through, with no body and with redacted headers.
  Blocks a compressed response (any `Content-Encoding` other than `identity`,
  or a `Transfer-Encoding` other than just `chunked`), strips any `Klav-Error`
  from the provider and `Access-Control-*`, and replaces the injected value,
  and its encodings, in headers and body, even when split across two chunks.
- **Rate:** each profile's `rate_per_minute`, counted before asking the server
  (`429 klav_rate_limited` with `retry_after`).
- **`ask`:** replies immediately with `409 klav_approval_pending` and the
  `approval_id`; retrying the same request uses the decision once the person
  makes it. The server stores the approval by method, host and path, without
  the query string: a request with a different query string can spend a
  one-time approval (the proxy remembers its own only with the exact query
  string).

Errors carry the `Klav-Error` header and JSON with `error`, `message` and
`next` (ADR 0036 §10). The list is in
[api.md](api.md#87-proxy-de-credenciales-klav-proxy).

### 9.4 What it does not do yet

- **No Railway template.** With the proxy listening only on loopback it would
  be useless outside its container. This arrives once the layer 6 channel
  exists.
- **Does not decompress** `gzip`, `br` or `deflate` to redact (ADR 0036 §8): it
  requests `identity` and blocks compressed responses.
- **Does not hold the request** for up to 2 minutes waiting for approval (ADR
  0036 §9, layer 7): it returns `klav_approval_pending` immediately.
- **Per-sandbox rate:** 60 calls per minute across all its profiles, in
  addition to each profile's rate, and 4 of the 16 concurrent requests. A
  response for a sandbox has `Set-Cookie` and `WWW-Authenticate` stripped
  ([api.md](api.md) §8.10): a sign-in challenge would let an MCP client start
  an OAuth flow with the provider and get a token that works without the
  proxy.
  Sandbox limits are also in place: `max_live` per issuer, 30 starts per minute
  per issuer and no starts while 256 ends are waiting for the server
  ([api.md](api.md) §8.9).
- **Upgrade the server before the proxy.** A layer 5a proxy drops the end of a
  sandbox the server never had only when the server replies `404
  sandbox_not_found`. With an older server, that end stays queued in the store,
  without blocking the others, until the server is upgraded.
- **The request body is read in full** before sending it (10 MiB by default,
  `--max-body`). The response body is streamed.
- **An API that puts the credential in the path** is not supported: the path is
  stored unredacted in the audit log and in approvals.
- **Redaction replaces only the whole value** (ADR 0036 E9): that way an
  endpoint echoing what the sandbox sends cannot let it ask "is this a piece of
  the token?". A real piece returned by a service by accident passes through,
  and an echo in a form the proxy does not recognize passes through in full
  (threat model, T149).
- **The proxy is for high-entropy values.** A short or guessable value can be
  confirmed by guessing the whole thing: the whole value is replaced. An API
  token qualifies; a PIN does not.
- **Per-item version memory** (against server rollback) lives in memory and
  starts fresh when the proxy restarts; the grant's is persisted.

### 9.5 Where not to host it

Never on a service reachable by one of its tokens. For example, with a Railway
account token in the proxy, do not host it in that Railway account: the agent
could read the proxy's volume through the API and extract its key (T151).
