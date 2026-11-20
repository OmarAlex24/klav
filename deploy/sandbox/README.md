# `new-sandbox`: a daily sandbox from the proxy's host

`new-sandbox` creates the Boat machine of one sandbox ([ADR 0042](../../docs/decisiones/0042-sandboxes-for-daily-use.md) §5, layer 4). It runs on the proxy's host as the issuer's system user, as the command of `klav sandbox start`:

```sh
klav sandbox start --label L --profile northflank -- deploy/sandbox/new-sandbox
```

`klav` puts the package in `KLAV_SANDBOX` and closes standard input. `new-sandbox` prints only Boat's sandbox ID.

**What the host needs:** `curl`, `jq`, `od`, `ls` and `sleep` in `/usr/bin` or `/bin`. The script looks for them only there, whatever `PATH` it inherits. What bash itself takes from the environment before the script's first line still applies: `BASH_ENV`, `SHELLOPTS`, and exported functions, which can stand in for any of those commands. The script turns off an inherited trace and an inherited `allexport`; beyond that, the issuer's environment is trusted.

## What it does

1. **It clears part of what it inherits.** `klav sandbox start` passes the issuer's environment through. So the script sets its own `PATH` (`/usr/bin:/bin`) and drops these variables before it runs anything:
   - the proxy variables, upper and lower case (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY`);
   - `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `SSLKEYLOGFILE` and `CURL_HOME`.
2. **It reads the package** from `KLAV_SANDBOX` and takes it out of the environment of every program it runs. The sandbox's hostname is `klav-` plus the first 8 characters of the sandbox ID. It comes from the package's own bytes (spec §13.10), decoded with shell builtins, so the package never reaches an argument or a file.
3. **It reads its configuration and the two secret files.** `config` and its directory decide which hosts receive the secrets. So the script refuses either one when it is a link, belongs to another user, or is writable by anyone else. It refuses a secret file that is a link, another user's, or readable by anyone else.
4. **With `TAILNET=on`, it makes the Tailscale key:**
   - it trades the OAuth client for a one-hour access token: `client_id` and `client_secret` in the form body of `POST {TAILSCALE_API}/oauth/token`;
   - it creates the key with the fixed body of ADR 0042 §4 at `POST {TAILSCALE_API}/tailnet/{TAILNET_NAME}/keys`. The key is single-use, ephemeral, pre-approved, `tag:klav-sandbox`, and valid one hour.
5. **It creates the machine:** `POST {BOAT_API}/sandboxes` with an `Idempotency-Key`.
   - **The body** is `from` (the template), `environment`, `ttlSeconds` only when `BOAT_TTL_SECONDS` is set, and `env`. `env` holds `KLAV_SANDBOX`, plus `KLAV_TAILNET_KEY` and `KLAV_TAILNET_HOSTNAME` only when it made a key.
   - **Success** is a `2xx` answer (Boat documents `202`) with the sandbox ID at `.sandbox.id`, shaped `bx_` and 8 lowercase letters or digits. The script prints that ID and nothing else.
6. **It retries the Boat call, at most 3 attempts in all,** 3 s apart, with the same `Idempotency-Key` and the same body. Boat documents that the same account, key and body give back the same sandbox for 24 hours, and that timeouts and `5xx` are safe to retry with the same key. It retries only:
   - when curl lost the answer: exit 28 (timeout; a create waits for the machine to be built, so a slow success can pass `--max-time 60`), 52 (no answer) or 56 (cut off);
   - on a `5xx`;
   - on a `409` whose error code is `idempotency_in_progress` ("retry shortly, same key"). The code is read from `error.code`, or from `error` or `code` when the answer has no object there. Any other `409`, such as `idempotency_key_reused`, isn't retried.

**How the secrets travel.** No secret is ever an argument of a process, in an exported variable or in a file:
- curl reads each body from standard input (`--data-binary @-`);
- it reads the one secret header from its own file descriptor (`-K /dev/fd/3`);
- shell builtins write both.

`-q` comes first, so no `~/.curlrc` applies, and only `https` is allowed. Every secret, and every value from an answer, has its characters checked before it goes into JSON or a curl configuration. Each secret is blanked as soon as the script is done with it, and all of them on every exit. Never run it with `-x`.

## Its files

All of them live in `~/.config/klav-sandbox/`, or in `KLAV_SANDBOX_CONFIG_DIR`. That directory must be the issuer's user's, and writable by no one else.

| File | Mode | What it holds |
|---|---|---|
| `config` | Not secret, but it decides where the secrets go: the issuer's user's, and writable only by that user (for example `0644` or `0600`) | `KEY=VALUE` lines, below |
| `boat-api-key` | `0600`, the issuer's user | The Boat API key, on one line |
| `tailscale-oauth` | `0600`, the issuer's user | `client_id=…` and `client_secret=…` on two lines. Read only with `TAILNET=on` |

**`config`:**

| Key | Required | Default | What it is |
|---|---|---|---|
| `BOAT_TEMPLATE` | Yes | — | The template to start from, `klav-sandbox-<version>` |
| `BOAT_ENVIRONMENT` | Yes | — | The daily environment's name |
| `TAILNET` | Yes | — | `on` to make a Tailscale key for each sandbox, `off` for a sandbox that reaches the proxy another way (ADR 0042 §8) |
| `BOAT_TTL_SECONDS` | No | Not sent | The machine's lifetime in seconds, a whole number from 1 to 2592000 (30 days). Without it, Boat applies its default of 3600: it archives the machine one hour after it was created. Choosing it is the person's step at setup |
| `TAILNET_NAME` | No | `-` | The tailnet in the key's URL; `-` is the OAuth client's own |
| `BOAT_API` | No | `https://boat.dev/api/v1` | Boat's API base URL. A test seam: another value is refused without `ALLOW_OTHER_API=yes` |
| `TAILSCALE_API` | No | `https://api.tailscale.com/api/v2` | Tailscale's API base URL. A test seam, like `BOAT_API` |
| `ALLOW_OTHER_API` | No | `no` | `yes` lets `BOAT_API` or `TAILSCALE_API` differ from the default. It exists for tests against other servers. Leave it out on the proxy's host |

Names allow letters, digits, `.`, `_` and `-`; a tailnet named `.` or `..` is refused. URLs must be `https`, with no `.` or `..` path segment. A key the script doesn't know is refused.

## When it fails

It exits non-zero with one line on standard error and nothing on standard output. **It never prints an answer's body.**

| What failed | Exit | The line ends with |
|---|---|---|
| The package, the configuration or a file | 2 | `no Boat machine was created` |
| The token trade, or creating the key | 1 | `no Boat machine was created`. When a key may have been made, the line also says it expires unused within an hour |
| The call to Boat, when no attempt can have reached it: curl's 6 (no name) or 7 (no connection) on the first attempt | 1 | `no Boat machine was created`, and with the tailnet on, that its key expires unused within an hour |
| The call to Boat, any other way: unreachable after an earlier attempt, every attempt timed out, any status that isn't `2xx` (a `4xx` included), or no sandbox ID it could read | 1 | `a Boat machine may exist: check Boat`, and with the tailnet on, `(the Tailscale key goes to that machine if it exists)` |
| A `HUP`, `INT` or `TERM` | 128 + the signal | What may exist at that moment, as above. It says so at once, without waiting for curl |

**No `4xx` from Boat proves that nothing was created.** So every failure on Boat's side says the machine may exist, except the one case where nothing was sent.

**`klav sandbox start` leaves the Klav sandbox live** when its command fails. It prints `klav sandbox stop <id>` for that.

**Two things it doesn't do:**
- it never retries anything but the Boat call, and that call only as above;
- it never deletes a Tailscale key it made before a failed Boat call. Outside the one case above, a machine may exist, and deleting the key would stop that machine from joining the tailnet. The key is single-use and expires in an hour either way.

## Tests

```sh
deploy/sandbox/test/run-tests
KLAV_TEST_BASH=/bin/bash deploy/sandbox/test/run-tests   # another bash
```

They need only `jq` and plain tools.

**The shipped `new-sandbox` never runs in the tests.** It fixes its own `PATH`, so the tests run a copy whose two marked "test seam" lines change only that:
- `bin_path`, the fakes' directory;
- `retry_wait`, set to 0.

The tests check that the copy equals the shipped file outside the seam, and that the shipped seam holds `/usr/bin:/bin` and 3. The fakes are:
- a `curl` that records its arguments, standard input, environment and the file it read with `-K`. It answers from files, attempt by attempt, and can hang until it is let go;
- logging wrappers around `ls`, `jq`, `od` and `sleep`.

A guard fails a case when anything else ran. The package comes from [`docs/vectores/sandbox.json`](../../docs/vectores/sandbox.json).

**What the tests check:**
- no secret in any argument or environment of any process, on standard output or on standard error, in every case;
- the exact body of each of the three calls, with and without `ttlSeconds`;
- `KLAV_TAILNET_*` only when a key was made;
- Tailscale's access token and key go through whole up to 4096 characters, past the 255 the other values may have, and one more character is refused;
- only the sandbox ID on standard output, read from Boat's documented `202` answer, `provisioning` or `ready`. A top-level `id` isn't accepted;
- the retries: the same key, body and header each time, at most 3, and only on curl's 28, 52 and 56, a `5xx` or a `409` in progress. curl's 28 and 7 lead to different messages;
- one line and no response body on each failure, and the right "no machine" or "may exist";
- a `TERM` while a call is out: the line at once, exit 143;
- an inherited environment: the proxy and certificate variables reach no child, and a hostile `PATH` runs nothing;
- the refusals:
  - a secret file open to others, another user's, or a link;
  - a `config` or its directory writable by others, another user's, or a link;
  - another API without `ALLOW_OTHER_API=yes`;
  - a `.` or `..` segment;
  - a `BOAT_TTL_SECONDS` out of range.

**What the fakes don't prove,** for layer 6. The first daily sandbox, on 2026-11-18, ran the script for real ([try-sandboxes.md](../../docs/try-sandboxes.md#what-the-real-run-of-2026-11-18-taught)).
- **Proved by that run:**
  - the real token trade and key creation at Tailscale. Its first try failed before any call to Boat: Tailscale's access token was 442 characters, past the 255 the script then allowed. The limit is now 4096;
  - the real shape of Boat's answer: a `2xx` with the ID at `.sandbox.id`, which the script read and printed;
  - that a scoped Boat key can deploy the template: the `ci` preset, limited to the daily and the build environments. The run doesn't show whether a key limited to the daily environment alone could.
- **Still not proven:**
  - where Boat's `409` puts its error code: no `409` came;
  - whether Tailscale and Boat accept a token or key of 4096 characters: 442 worked.
