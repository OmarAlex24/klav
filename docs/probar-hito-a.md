# Testing milestone A on your Mac

This guide goes by hand through everything milestone A delivers, "Klav for my
agent", from scratch: building, bringing up your own server, creating the
account, unlocking with Touch ID, saving secrets, using them with `klav run`
and `inject`, registering Claude Code as an agent, approving it and letting it
sign in to a site without seeing the password. At the end you review the
audit log, revoke the agent and delete everything.

- **Time:** about 45 minutes (the first build takes several).
- **Isolated:** everything lives in `~/klav-prueba`. It doesn't touch any other
  Klav installation you have.
- The steps marked **[Touch ID]** ask for your finger. If you cancel, Klav
  asks for the master password.
- You will use three terminals: **T1** for the server, **T2** for the test
  site and **T3** for everything else.

## 0. Requirements

- A Mac with Touch ID and macOS 14 or newer.
- Xcode's Command Line Tools (`xcode-select --install`). Without them,
  `klavd` is built without Touch ID.
- Rust with `rustup` (<https://rustup.rs>). The repository pins the version
  in `rust-toolchain.toml`; `cargo` installs it on its own.
- Node 20 or newer, for the test site and the Playwright example.
- Google Chrome or, if you don't have it, Playwright's Chromium
  (`npx playwright install chromium`; step 9 finds it on its own).
- Claude Code (`claude`), for the MCP part.
- Optional: Docker, if you'd rather bring up the server with `docker compose`.

## 1. Preparing the test environment

In **T3**, from the root of the repository (here `~/dev/klav`):

```sh
cd ~/dev/klav
mkdir -p ~/klav-prueba
cat > ~/klav-prueba/env.sh <<EOF
export KLAV_REPO="$PWD"
export KLAV_HOME="\$HOME/klav-prueba/persona"
export KLAV_SERVER="http://127.0.0.1:8080"
export PATH="\$KLAV_REPO/target/release:\$PATH"
EOF
source ~/klav-prueba/env.sh
```

- `KLAV_HOME` is the local state of this "device". Outside this
  test, Klav uses `~/Library/Application Support/klav`.
- `KLAV_SERVER` saves repeating `--server`. Without it, `signup` and `login` would use
  the default server, `https://api.klav.dev` ([`cli.md`](cli.md) §3).
- **In each new terminal**, run `source ~/klav-prueba/env.sh` before
  anything else.

## 2. Building

```sh
cargo build --release -p klav-cli -p klav-daemon -p klav-server
klav --version
```

It leaves `klav`, `klavd` and `klav-server` in `target/release`, which is already in
your `PATH`. `klav` starts the `klavd` next to it.

**Signed alternative:** `scripts/macos/build-sign.sh` builds and signs
`klav` and `klavd` with your Developer ID in `dist/macos` (it needs the
certificate in the keychain). If you use it, change the `PATH` in `env.sh` to
`$KLAV_REPO/dist/macos` and keep `target/release` for `klav-server`.
Touch ID works the same with unsigned binaries (ADR 0013).

## 3. Bringing up the server

Pick one option. Both listen on `127.0.0.1:8080`.

**Option A, `klav-server` directly.** In **T1**:

```sh
source ~/klav-prueba/env.sh
mkdir -p ~/klav-prueba/servidor
KLAV_DATABASE_URL="sqlite://$HOME/klav-prueba/servidor/klav.db" \
KLAV_DATA_DIR="$HOME/klav-prueba/servidor/data" \
KLAV_LOG_FORMAT=pretty \
  klav-server
```

(or `cargo run --release -p klav-server` with the same variables).

**Option B, Docker.** In **T1**, from the repository, building this checkout
(`docker-compose.yml` alone would pull the published image instead):

```sh
docker compose -p klav-prueba -f docker-compose.yml -f docker-compose.build.yml up --build
```

It starts in invite mode: before `klav signup`, create the invite it asks for
with `docker compose -p klav-prueba exec klav klav-server invite create --email tu@correo.com`
([self-hosting.md](self-hosting.md) §2.5).

Check it in **T3**:

```sh
curl -s http://127.0.0.1:8080/v1/health
```

It should answer with a JSON that says `ok`. The server speaks plain HTTP:
`klav` only accepts that on `127.0.0.1` or `localhost`.

## 4. Creating the account

```sh
klav signup --email tu@correo.com --emergency-kit ~/klav-prueba/kit.txt
klav status
```

- `signup` asks for the master password twice. Pick a test one.
- `kit.txt` is the emergency kit: it contains the Secret Key. In real use it is
  printed and the file deleted.
- `klav status` shows the account, the device and the **account's 6
  words** (`words:`). You will compare them with the agent's.

## 5. Unlocking with Touch ID

```sh
klav unlock          # la primera vez pide la contraseña y da de alta Touch ID
klav status          # daemon: unlocked
klav lock
klav unlock          # [Touch ID]
```

- The first `unlock` starts `klavd` and creates, without a dialog, a key in the
  Secure Enclave. It is kept in `$KLAV_HOME/touchid.json`.
- **[Touch ID]** The second `unlock` shows the Touch ID dialog. If you
  cancel it, it asks for the password.
- With `klavd` unlocked, the other commands don't ask for anything.
- `klavd` locks on its own after 15 minutes without use or when the
  screen locks; the next command asks for Touch ID again.

## 6. Saving secrets

First the test site. In **T2**:

```sh
source ~/klav-prueba/env.sh
node "$KLAV_REPO/examples/login-site/server.mjs"
```

It is a login page at <http://127.0.0.1:8765> that accepts any
username and password. It saves nothing: it only says how many characters it received.

In **T3**, a login with TOTP, an API key and a `.p8` file:

```sh
klav item add login --title Sitio --username ana --url http://127.0.0.1:8765 -g password -s totp
#   totp: pega JBSWY3DPEHPK3PXP (una semilla de prueba)
klav item add api-key --title Stripe -s api_key
#   api_key: escribe, por ejemplo, sk_test_prueba_123
printf -- '-----BEGIN PRIVATE KEY-----\nPRUEBA\n-----END PRIVATE KEY-----\n' > ~/klav-prueba/AuthKey_PRUEBA.p8
klav item add note --title APNs
klav item attach APNs key ~/klav-prueba/AuthKey_PRUEBA.p8
rm ~/klav-prueba/AuthKey_PRUEBA.p8

klav item ls
klav item get Sitio                 # la contraseña sale enmascarada
klav totp Sitio                     # código actual
```

- `-g password` generates the password: not even you know it yet. To see it:
  `klav item get klav://Personal/General/Sitio/password --reveal`.
- `-s` asks for the value without echo. Secrets never go on the command
  line.

## 7. `klav run` and `inject` with `klav.toml`

A demo project:

```sh
mkdir -p ~/klav-prueba/demo && cd ~/klav-prueba/demo
cat > klav.toml <<'EOF'
project = "Personal/General"

[env]
STRIPE_KEY = "Stripe/api_key"
EOF
cat > .env.tpl <<'EOF'
STRIPE_KEY={{ klav://Personal/General/Stripe/api_key }}
EOF

klav run -- sh -c 'echo "STRIPE_KEY tiene ${#STRIPE_KEY} caracteres"'
klav inject -i .env.tpl -o .env     # archivo 0600
cat .env && rm .env
klav inject -r APNs/key -o AuthKey.p8 --ttl 20s   # el .p8; se borra a los 20 s
ls AuthKey.p8                        # ya no existe
```

- The first time, `run` shows what the `klav.toml` asks for and asks
  (again if the file changes). Answer `y`.
- `run` puts `STRIPE_KEY` only in the command's environment: neither in argv nor in
  the output.
- `inject -r` writes the value as is, also a binary attachment like the
  `.p8`, to a 0600 file. With `--ttl` it stays in the foreground and deletes it
  when it runs out.
- `klav.toml` also accepts `[files]` (`"secrets/AuthKey.p8" =
  "APNs/key"`): `run` writes them while the command runs and deletes them when it
  finishes. Step 10 uses it with the agent.
- Inside a git repository, `inject` warns if the file isn't in a
  `.gitignore`.

## 8. Registering Claude Code as an agent

Still in `~/klav-prueba/demo`, in **T3**:

```sh
klav agent register --name claude-code
```

- It prints **6 words**. It uses the account and the server of this `KLAV_HOME`.
- The agent's private key is kept in the login keychain
  (service `dev.klav.agent`). If you'd rather have a file:
  `--key-store file` (it is kept in `$KLAV_HOME/agents/claude-code.key`, 0600).
- If you rebuild `klav` unsigned, macOS may ask whether `klav` can
  use that keychain key: choose "Always Allow".

Now approve it, as the person:

```sh
klav agent list                                  # claude-code: pending
klav agent approve claude-code --project Personal/General --fill-domain 127.0.0.1
#   compara las 6 palabras con las de register y responde "y"
#   [Touch ID]
klav agent status --agent claude-code            # active
```

- **[Touch ID]** Approving asks for Touch ID even if `klavd` is unlocked.
- With no more options, the policy is the default one: `list`, `fill`,
  `inject` and `create` are allowed; `totp` and `update` ask (`ask`);
  `reveal` and `delete` are denied. `--fill-domain` also limits `fill` to that
  host.

## 9. A browser for the agent

The agent types into a Chrome tab over CDP. Use a separate profile, not
your everyday browser:

```sh
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
[ -x "$CHROME" ] || CHROME="$(ls -d ~/Library/Caches/ms-playwright/chromium-*/chrome-mac*/"Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing" | tail -1)"
"$CHROME" --remote-debugging-port=9333 --user-data-dir="$HOME/klav-prueba/chrome" \
  --no-first-run http://127.0.0.1:8765 >/dev/null 2>&1 &
klav agent browser register navegador --cdp http://127.0.0.1:9333
```

Try it from the terminal, as the agent would:

```sh
klav agent fill klav://Personal/General/Sitio --session navegador --reason "probar fill"
```

- The tab shows the username and password filled in. Press **Sign
  in**: the page says how many characters it received, and so does **T2**. The
  terminal only prints `Filled username, password on http://127.0.0.1:8765/.`
- Press **Sign out** to go back to the form: `fill` only writes on a
  page with login fields.
- Klav first checks that the tab's host is that of one of the
  item's URLs. On any other page, it refuses.
- Use a port other than 9222: another browser of yours might have it
  open, and an agent must not write into it.

**Optional, Playwright with `@klav/sdk`:**

```sh
cd "$KLAV_REPO/examples/playwright"
npm install && npx playwright install chromium
LOGIN_URL=http://127.0.0.1:8765 ITEM=klav://Personal/General/Sitio KLAV_AGENT=claude-code npm start
#   logged in: Welcome
cd ~/klav-prueba/demo
```

The script opens its own headless Chromium (`HEADLESS=0` to see it)
with a CDP port the system picks, and only passes `klav` the
reference and the reason. With `CHROME=/ruta/al/chrome` it uses another browser.

## 10. Connecting `klav mcp` to Claude Code

In `~/klav-prueba/demo`:

```sh
claude mcp add klav -e KLAV_HOME="$KLAV_HOME" -e KLAV_AGENT=claude-code -- "$(command -v klav)" mcp
claude mcp list                       # klav: …/klav mcp - ✔ Connected
mkdir -p .claude/skills/klav && cp "$KLAV_REPO/skill/SKILL.md" .claude/skills/klav/
claude
```

- `claude mcp add` without `-s` saves the server only for this directory
  (`local` scope). Claude Code starts it here, so `klav mcp` uses
  this `klav.toml`: short references and only the
  `Personal/General` project.
- The skill teaches Claude to use the tools without asking for values.
- Inside Claude, `/mcp` should show `klav` connected with 12
  tools.

**Other clients** (Claude Desktop, Cursor…) use this JSON, with your absolute
paths:

```json
{
  "mcpServers": {
    "klav": {
      "command": "/Users/TU_USUARIO/dev/klav/target/release/klav",
      "args": ["mcp"],
      "env": {
        "KLAV_HOME": "/Users/TU_USUARIO/klav-prueba/persona",
        "KLAV_AGENT": "claude-code"
      }
    }
  }
}
```

Those clients usually start the server outside your project: without
`klav.toml`, the agent sees every project in its grant and needs
full references.

### What to ask Claude

Type each one into Claude and watch which tool it uses:

1. *"What secrets do I have in Klav for this project?"* → `search_items`:
   titles and references, without values.
2. *"Run `sh -c 'echo key=$STRIPE_KEY'` with the project's secrets."*
   → `run_with_secrets`: the output says `key=[redacted by klav]`.
3. *"Sign in to http://127.0.0.1:8765 in the sdk:navegador browser."*
   → `fill_login`: it fills the tab and returns only the names of the
   fields. The tab must be on the form (**Sign out** if not).
   Press **Sign in** yourself. If you ask it *"…and submit the form"*, Claude
   passes `submit: true`: the page says how many characters it received, and the
   response carries `"navigated": true` and the new address
   (`…/session`), never the password.
4. *"Write the Stripe API key into a `.env` with a template, and have it
   deleted in a minute."* → `inject_file` with `template` and `ttl_seconds`:
   the file appears in `~/klav-prueba/demo` (0600) and disappears after a
   minute. Claude doesn't receive the content.
5. *"Give me the TOTP code for Sitio."* → `get_totp` waits up to 60 s and,
   if you don't approve in that time, returns `"status": "pending"`. Claude
   should, without you telling it anything else:
   - tell you what it is asking for, what for, and the exact command to approve it;
   - leave the `wait_command` it received running **in the background**
     (`KLAV_HOME=… …/klav approval wait <id> --agent claude-code …`): in
     Claude Code it shows up as a background Bash task.

   In **T3**, approve the ID it gave you (or the only one in the list):

   ```sh
   klav approval list                # una sola solicitud, aunque Claude repita la llamada
   klav approval approve <id>        # [Touch ID]
   ```

   The background task ends with `"status":"approved"`, Claude
   wakes up on its own and repeats `get_totp` with `approval_id`: it receives the code.
   **Don't type "I approved it"**; if Claude asks you to, the skill isn't being
   used. If you approve while the call is still waiting (the first
   60 s), the code arrives in that same call.

   Variants:
   - `klav approval deny <id>`: the wait exits with 5 and Claude tells you that
     you denied it, without looking for another way.
   - If Claude repeats `get_totp` without `approval_id` after you
     approved, it also works: the server uses your approval instead of
     creating another request.
6. *"Show me the password for Sitio."* → `reveal` is **denied**. Claude
   should explain it and, at most, use `request_access`, which tells it what
   you would have to change; it shouldn't look for another way.

7. *"Write the APNs `key` attachment to `AuthKey.p8` for the push
   tool, and have it deleted in a minute."* (`search_items` shows
   `attachments: 1` on APNs, but you chose the field's name in
   step 6, which is why it goes in the request) → `inject_file` with `ref:
   "APNs/key"` and `ttl_seconds` (ADR 0016): the `.p8` appears in
   `~/klav-prueba/demo` (0600), identical to the original, and is deleted after a minute.
   Claude receives the path, not the content.
8. Add the attachment to `klav.toml` the way a tool would read it:

   ```sh
   mkdir -p secrets
   printf '\n[files]\n"secrets/AuthKey.p8" = "APNs/key"\n' >> klav.toml
   ```

   and ask it *"Run `sh -c 'wc -c < secrets/AuthKey.p8'` with the project's
   secrets."* → `run_with_secrets`: the output says how many bytes
   it has, and the file no longer exists when it finishes. If the command prints the
   file (`cat`), its content comes out as `[redacted by klav]`.

The password for Sitio, the API key and the content of the `.p8` don't appear
in any tool response.

## 11. The audit log

In **T3**:

```sh
klav log                              # lo más nuevo primero, con el motivo de cada acción
klav log --agent claude-code --alerts # first_use, burst, denied
klav log --item Sitio
klav log --csv > ~/klav-prueba/bitacora.csv
klav log verify
```

- Each of the agent's actions appears with its reason and its result (`allow`,
  `ask`, `deny`, `approve`).
- `log verify` recomputes the hash chain, checks the agent's and your
  account's signatures, and signs the log's last event as this device's head,
  unless it already signed that one (a device never signs the same head twice).
  It says "This device's signed head is at event N." If something was altered,
  it exits with code 3.

## 12. Revoking the agent

```sh
klav agent show claude-code           # el reporte "qué vio"
klav agent revoke claude-code         # pregunta y revoca; no pide Touch ID
```

- `show` and `revoke` list the projects whose keys it received, each
  item it used (Sitio appears with `fill` and `SECRET` at `yes`; APNs
  with `inject` and `yes (file)`, because it received the attachment) and the denied
  attempts. An item only shows `yes` if it really received a value.
- The `ID` column tells apart two items with the same title, and an
  item you already sent to the trash shows `(in trash)`. Klav no longer
  lets you create two items with the same title in a project
  (`item add --allow-duplicate` if you really want to).
- Ask Claude for anything from Klav: the tool answers with an
  error, because the server already rejects the agent.
- `klav agent revoke claude-code --rotate` also rotates the project's
  key. Change at the source the secrets the report flags: rotating doesn't
  erase what the agent already saw.
- `klav log verify` still checks out after revoking.

## 13. Cleaning up

```sh
cd ~/klav-prueba/demo
claude mcp remove klav                # quita el servidor de Claude Code
klav agent list                       # copia el ID de claude-code
security delete-generic-password -s dev.klav.agent -a <ID>   # su llave, si usaste el llavero
klav lock --stop                      # detiene klavd
```

With `-a <ID>` you delete only this agent's key, not those of others you
have.

- Close Claude, the test Chrome and the site (**T2**, `Ctrl-C`).
- Stop the server: `Ctrl-C` in **T1**; with Docker, also
  `docker compose -p klav-prueba down -v` from the repository (it deletes the
  volume with the database).
- Delete everything else:

  ```sh
  rm -rf ~/klav-prueba
  ```

  That includes the account, the kit, `touchid.json` (the Secure Enclave key
  only worked through that file), the Chrome profile and the
  database.

## If something fails

| Symptom | What to do |
|---|---|
| `connection refused` | The server isn't running in **T1**, or you're missing `source ~/klav-prueba/env.sh` |
| Code 3 | Security check: different words, account identity changed or audit log altered. Read the message; don't ignore it |
| Code 4 | The agent is waiting for your approval: `klav approval list` |
| Code 5 | The policy denied it: check `klav agent show claude-code` |
| `fill` refuses because of the host | The tab isn't on the item's URL (`http://127.0.0.1:8765`) |
| The Touch ID dialog doesn't appear | The Command Line Tools weren't there at build time, or `KLAV_NO_TOUCH_ID` is set |
| Chrome doesn't open port 9333 | It needs its own `--user-data-dir`; close other Chrome instances using that profile |
| `klav mcp` doesn't connect in Claude | `claude mcp list`; check the path to `klav` and that `KLAV_HOME` is absolute |
