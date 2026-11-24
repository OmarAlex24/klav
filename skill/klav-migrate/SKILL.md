---
name: klav-migrate
description: Move all of a repository's secrets into Klav, eliminate loose `.env` and key files, split credentials cleanly by environment (development, staging, production), wire `klav.toml` and `klav run`, and set up `klav-proxy` for anything that runs in a sandbox. Use whenever the person asks to migrate a project to Klav, move secrets into Klav, get rid of `.env` or loose key files, or organize a repo's credentials by environment.
metadata:
  klav-skill-version: "0.2.0"
---

# Migrate a project to Klav (no loose files, split by environment)

The person wants every secret for this repository to live in Klav — nothing left in loose `.env` files, key files, `/tmp` scripts or provider dotfiles — and organized cleanly by environment (`development`, `staging`, `production`).

## Non-negotiable rules

1. **Never read, print or ask for secret values.**
   - Do **not** `cat`, `head`, `tail`, `grep` or open `.env`, `.env.*`, `.pem`, `.p8`, `.key`, `.p12`, service-account JSONs or any file that holds real credentials.
   - To inspect a `.env` file, extract **variable names only** (never values), e.g.:
     ```sh
     awk -F= '/^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=/{gsub(/^[[:space:]]+/, "", $1); print $1}' .env
     ```
   - Never ask the person to paste a secret into the chat, and never put a secret in command arguments (`argv`).
2. **Only the person runs vault-writing and proxy commands** (`klav project create`, `klav item add`, `klav item attach`, `klav proxy grant`, `klav proxy issuer add`). You prepare the exact commands and let the person run them in their own terminal.
3. **Never delete a loose file until Klav is verified working** for that command/environment.

## Step 1 · Inventory the repository (names and paths only)

Scan the repo (without reading secret values) to find:

- **Env files:** `.env`, `.env.local`, `.env.development`, `.env.staging`, `.env.production`, `.env.*`, `.env.example`.
- **Key/cert/credential files:** `*.p8`, `*.pem`, `*.key`, `*.p12`, `*.jks`, service-account JSONs, `.npmrc` tokens, `~/.northflank` or similar CLI config files.
- **Secret consumers in code and scripts:** references to `process.env.*` / `std::env` / `os.environ`, scripts that read key files or write `/tmp/...` files, `klav agent inject` + `rm` workarounds, CI workflows, and sandbox setup scripts.
- **Git history exposure:** run `git ls-files` on any discovered secret file. If a real secret file is tracked by git, flag it immediately so the person knows to **rotate** those credentials, not just delete the file.

If you are already connected to Klav (`search_items`), search first so existing items are reused instead of duplicated.

Present a concise plan table to the person before making changes, classifying every variable/file into one of four buckets:

| Bucket | Examples | Where it goes |
|---|---|---|
| **Non-secret config** | `PORT`, `NODE_ENV`, public URLs, feature flags | Stays in `.env.example` / app config (not in Klav) |
| **Local / runtime secret** | `DATABASE_URL`, `JWT_SECRET`, API keys used locally | Klav item → `klav.toml` `[env]` → `klav run` / `klav agent run` |
| **Binary / key file** | APNs `.p8`, TLS `.pem`, signing keys | Klav attachment (`klav item attach`) → `klav.toml` `[files]` (auto-deleted when `klav run` exits) |
| **Sandbox / remote-agent API key** | Provider or AI gateway keys called from a sandbox | **Same Klav vault item**, granted to `klav-proxy` (`klav proxy grant`), never injected into the sandbox |

Confirm the vault name, project naming and environment list (`dev`, `staging`, `prod`) with the person if anything is ambiguous.

## Step 2 · Split by environment

Organize credentials so environments never mix and agents never touch production:

- **One Klav project per environment** inside the person's chosen vault (for example `<Vault>/<app>-dev`, `<Vault>/<app>-staging`, `<Vault>/<app>-prod`):
  - Agent grants in Klav are scoped per project, so keeping `dev`, `staging` and `prod` in separate projects lets the person grant an agent `allow` on `<app>-dev`, `ask` on `<app>-staging`, and **no access at all** to `<app>-prod`.
  - If an API key is genuinely shared across environments, store it once in a shared project (or reuse the existing item found via `search_items`) and point to it by full `klav://…` reference rather than duplicating it.
- **One committed reference manifest per environment** (references only, zero secrets):
  - `klav.toml` for the default (`development`) environment:
    ```toml
    project = "<Vault>/<app>-dev"

    [env]
    DATABASE_URL = "Postgres/api_key"
    API_KEY      = "klav://<Vault>/<app>-dev/Service/api_key"

    [files]
    "secrets/AuthKey.p8" = "klav://<Vault>/<app>-dev/APNs/key"
    ```
  - `klav.staging.toml` and `klav.prod.toml` for the other environments, run with:
    ```sh
    klav run --config klav.prod.toml -- <command>
    ```

## Step 3 · Move secrets into Klav (person runs these in their terminal)

Give the person copy-pasteable commands tailored to the inventory from Step 1:

1. **Create the environment projects** (skip any that already exist):
   ```sh
   klav project create --vault "<Vault>" "<app>-dev"
   klav project create --vault "<Vault>" "<app>-staging"
   klav project create --vault "<Vault>" "<app>-prod"
   ```
2. **Add individual API keys / secrets** — either send a native secret request card with `request_secret` (including `proxy_proposal` for sandbox keys) so the person enters the value in a hidden field on their device without pasting in chat, or give them the terminal command (interactive hidden prompt with `-s`, never in `argv`):
   ```sh
   klav item add api-key --vault "<Vault>" --project "<app>-dev" --title "<Service>" -s api_key
   ```
3. **Import a loose `.env.<env>` file without pasting values into chat:** give the person a small command they run in their own terminal that reads only the agreed secret variable names from the `.env.<env>` file and pipes each value straight into `--secret-stdin api_key` (never echoing values and never placing them in `argv`):
   ```sh
   for var in VAR_ONE VAR_TWO; do
     val="$(awk -F= -v k="$var" '$1 == k {sub(/^[^=]*=/, ""); gsub(/^["'\'']|["'\'']$/, ""); print; exit}' .env.development)"
     [ -n "$val" ] && printf '%s\n' "$val" | klav item add api-key --vault "<Vault>" --project "<app>-dev" --title "$var" --secret-stdin api_key
     unset val
   done
   ```
   *(Skip any item that already exists in Klav; use `klav item edit` if updating an existing one.)*
4. **Upload key/certificate files as encrypted attachments:**
   ```sh
   klav item add note --vault "<Vault>" --project "<app>-dev" --title "APNs"
   klav item attach "klav://<Vault>/<app>-dev/APNs" key ./secrets/AuthKey.p8
   ```
5. **For credentials used from sandboxes** (same vault item, granted to `klav-proxy` instead of injected into the sandbox):
   ```sh
   klav proxy grant "klav://<Vault>/<app>-dev/<Service>" \
     --profile <profile> \
     --upstream https://<provider-host> \
     --header authorization --prefix "Bearer " \
     --method GET,POST --path-prefix /v1
   klav proxy issuer add <issuer> --profile <profile> --url tls://<proxy-host>:<port>
   ```
   *(If a preset exists, e.g. `--preset northflank`, prefer it.)*

Wait for the person to confirm the items (and any proxy profiles) are saved before moving to verification.

## Step 4 · Wire the repository to Klav (zero loose files)

1. **Write `klav.toml`** (and `klav.staging.toml` / `klav.prod.toml` as needed) with exact `klav://…` references only. Verify that every `[files]` path is relative to the `klav.toml` directory and stays inside it.
2. **Keep `.env.example`** with variable names and placeholder comments only (never real values).
3. **Update scripts and code:**
   - Replace manual `.env` loading dependencies or `/tmp/...` key-file hacks with standard environment variables (delivered via `klav run` / `klav agent run`) or `[files]` in `klav.toml` (which Klav creates as `0600` before starting and deletes automatically when the command exits).
   - For tools that will run inside a **sandbox**, make the API base URL configurable (e.g. an env var like `*_BASE_URL`) so the tool points at `klav-forward` without ever needing the real API key inside the sandbox.
   - Update `package.json`, `Makefile` or docs commands to launch through `klav run -- …` (and `klav run --config klav.<env>.toml -- …` for non-default environments).
4. **Harden `.gitignore`:** ensure it ignores `.env`, `.env.*` (with `!.env.example`), any key/cert paths used by `[files]`, and `*.klav-tmp` (temporary files left only on a crash/`SIGKILL`).

## Step 5 · Verify, then remove loose files

1. Ask the person to verify each environment works through Klav:
   ```sh
   klav run -- <dev command>
   klav run --config klav.staging.toml -- <staging check>
   ```
   (Remember: the first time `klav run` sees a new or changed `klav.toml`, it shows the references and asks the person to confirm.)
2. Only **after** the person confirms it works, give them the exact `rm` commands to delete the old `.env*` and loose key files (plus any leftovers in `/tmp`), and remind them to rotate any credential that was ever committed to git.
3. **Final check on agent access:** remind the person to grant local agents only `<app>-dev` (never `<app>-prod`), keep `reveal` denied, and let sandboxes talk only through `klav-proxy`.
