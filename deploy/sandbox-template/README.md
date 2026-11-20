# The sandbox template

The scripts that prepare a Boat machine to be saved as the sandbox template, `klav-sandbox-<version>`, for daily sandboxes ([ADR 0042](../../docs/decisiones/0042-sandboxes-for-daily-use.md) §4 and §7, layer 3). The template carries `klav-forward`, Tailscale with no state, `klav-tailnet-up`, `jq`, and the Northflank and agent CLIs, all at pinned versions. It holds no state, login or secret.

| File | What it is |
|---|---|
| `build-template` | Checks the manifest and the `klav-forward` binary, installs everything, records it, then runs `check-template` |
| `check-template` | The "never in it" checks, and the installed Klav files against the build record. Exits 1 and names each finding's path, never its content. With `--hashes`, it also prints the allow-list line of each finding the allow list can take |
| `klav-tailnet-up` | Installed as `/usr/local/sbin/klav-tailnet-up`, owned by root: joins the sandbox to the tailnet with the key on standard input |
| `manifest` | The inputs for one release, all empty here: fill in a copy. Every key is required except `ALLOW`, the allow list |
| `test/run-tests` | Tests against fakes only (below) |

All four scripts need bash 3.2 or later. They run on Linux; `build-template` needs Debian or Ubuntu with apt and systemd.

## Building a template, once per release

Each step is the person's. Nothing here calls Boat or Tailscale for them.

1. **The build environment.** At Boat, create an environment only for this, with *Safe for third parties* off and every toggle off: no variables, no secret files, no GitHub, no boat credentials and no agent logins. Give it no AI profile and no setup script. Boat's docs don't give the toggles' defaults, so set each one.
2. **The build machine.** Create a normal machine in that environment: never `--no-env`, and no `-e` at all. A saved snapshot of a `--no-env` machine stays `--no-env` forever, and a snapshot replays the source's `-e` values on every deploy. `check-template` can't see either of these.
3. **The manifest.** Fill in a copy of `manifest` for the release:
   - the `klav-forward` SHA-256 and the release's full commit, from the release's CI run ([releasing.md](../../docs/releasing.md) §1 and §6);
   - the SHA-256 of Tailscale's apt keyring for the build machine's Debian or Ubuntu release (the manifest says which URL). It changes only when Tailscale rotates its key;
   - the exact Tailscale and `jq` apt versions;
   - each npm CLI as `name@version`;
   - the login files of those CLIs other than `.claude/.credentials.json` and `.codex/auth.json`, or `none`. The manifest's comment says where Northflank's CLI keeps its login;
   - the allow list, in step 5.

   Nothing in this repository picks a value for you.
4. **Copy in.** Boat mounts `/run` with `noexec`, so nothing under it runs. Give the folder a tmpfs of its own under `/run`, mounted with `exec`. It's still under `/run`, so the scan skips it and the template doesn't save it. Your copy tool can't write to a folder owned by root, so copy in two steps:

   ```sh
   # 1. A folder you own, for your copy tool:
   sudo install -d -o "$(id -u)" -g "$(id -g)" -m 0700 /run/klav-in
   #    copy this folder's files, the filled manifest and the klav-forward binary into /run/klav-in
   # 2. The exec tmpfs, owned by root, with the files copied in by root:
   sudo install -d -m 0755 /run/klav-template
   sudo mount -t tmpfs -o exec,nosuid,nodev,mode=0755,size=64m tmpfs /run/klav-template
   sudo cp -R /run/klav-in/. /run/klav-template/
   sudo chown -R root:root /run/klav-template
   sudo chmod 0755 /run/klav-template/build-template /run/klav-template/check-template /run/klav-template/klav-forward
   sudo rm -rf /run/klav-in
   ```

   A copy left under `/home`, `/root`, `/etc` or `/var` fails the checks, because the scripts and the binary contain the strings they look for. `build-template` refuses, before it installs anything, when it can't execute `check-template` or the binary from where they are.
5. **The allow list.** Before the build, list what the scan flags on this machine, with each file's SHA-256:

   ```sh
   sudo /run/klav-template/check-template --manifest /run/klav-template/manifest.0.9.0 --hashes
   ```

   It changes nothing. On standard error it names each finding; on standard output it prints an `ALLOW=<SHA-256>  <path>` line for each file the allow list can take, and a `# no entry for …` line for each one it can't. On a fresh build machine, expect these findings: no build record, no `klav-forward` or `klav-tailnet-up`, the `tailscaled` unit not masked, and whatever is under `/var/log` or in apt's lists. The build takes care of all of them. The rest are files of the base image. On a normal Boat machine these are Boat's CLI and pip's emoji names, which name `boat_`, and the two files in `~/.config/ascii`. **Look at each file.** Copy into the manifest only the lines of the files you accept. Then run the same command again: only the expected findings should be left.

   An npm CLI may add a flagged file that only the build shows. Then the build fails and names it. Run `sudo /run/klav-template/check-template --hashes` on that machine, without `--manifest`: after a build it uses the record's lists. Look at the file, add its line to the manifest, and build again on a new build machine.

   Don't search for the strings by hand on the build machine. `sudo` and the journal record every command line, so the logs would name the string. The build empties the logs, but `--hashes` never needs that search. Shell history isn't a log: a command that named a string stays in `~/.bash_history`, and that file is a finding.
6. **Build:**

   ```sh
   sudo /run/klav-template/build-template --manifest /run/klav-template/manifest.0.9.0 --forward /run/klav-template/klav-forward
   ```

   It refuses, before installing anything, when:
   - a manifest value is missing or malformed, or an `ALLOW` line is (below);
   - it can't execute `check-template` or the binary: their folder is mounted `noexec` (step 4), or a file lost its execute bit;
   - the binary's SHA-256 isn't the manifest's;
   - `klav-forward --version` doesn't name the manifest's commit;
   - it doesn't run as root.

   Then it installs, in this order:
   - Tailscale's keyring, refused and removed unless its SHA-256 is the manifest's, and the apt list for Tailscale's repository, which the script writes itself;
   - Tailscale and `jq` at the exact versions, held. The `tailscaled` unit is stopped and **masked**, and `/var/lib/tailscale` left empty;
   - `klav-forward` and `klav-tailnet-up`, owned by root with mode 0755;
   - the npm CLIs.

   It records all of it in `/etc/klav-sandbox-template/manifest`: the SHA-256 of both Klav files, the allow list, and `NPM_GLOBAL_PREFIX`, the prefix `npm` installed the CLIs under. For root, `npm` may be a user's install (nvm), and then the CLIs are under that user's home. Then it cleans up what the template must not carry:
   - **apt's package lists**, which name a package with `boat_` in its file name. A sandbox runs `apt-get update` itself before it installs anything;
   - **the logs.** `journalctl --rotate`, then the journal's archived files are removed, and every other file under `/var/log` is emptied in place. Any failure stops the build.

   Last, it runs `check-template` with the record, which checks those files against it.
7. **Save,** only if `build-template` exited 0 and printed `klav-sandbox-<version> is ready. Save this machine as …`. It prints that line only when every check passed. Use the name it printed: a new name for each release, so a running sandbox's template never changes under it. Remove the previous template once nothing deploys it. **Keep the template private:** don't share it with a share code until Boat's per-machine token is known to die with the build machine (below).

**Nothing stops a save after a failed check.** The build machine has no Boat credentials, so the save is a command on the person's own machine, and these scripts can't refuse it. `build-template` exits 1, says "do not save it", and never prints the line to save. Run `check-template` again after any change by hand, without `--manifest`: `sudo /run/klav-template/check-template`. It repeats every check, the installed files included, with the logins and the allow list of the build record.

**What the build trusts:**
- **Tailscale's keyring** comes over HTTPS. It must match the manifest's hash, which the person took from that same URL once: trust on first use, pinned after that. The script writes the apt list itself, with `signed-by` set to that keyring, so apt checks every Tailscale package's signature with it. A downloaded list could leave `signed-by` out.
- **The npm CLIs** run as root with their install scripts. Each has an exact version, but nothing pins its tarball's hash, so the build trusts the npm registry for those bytes.

## What `check-template` refuses

| Finding | Where |
|---|---|
| Tailscale state, or `tailscaled` running | `/var/lib/tailscale` not empty, or a `tailscaled` process |
| The `tailscaled` unit not masked | `systemctl is-enabled tailscaled.service` answers anything but `masked`, `masked-runtime` included, or there is no `systemctl`. An enabled unit starts again after a snapshot, with its state on disk and on the socket `klav-tailnet-up` uses |
| The Klav files changed | `/usr/local/bin/klav-forward` and `/usr/local/sbin/klav-tailnet-up` not matching the SHA-256 in the build record; `klav-tailnet-up` not a file owned by root with mode 0755; no record, or a record without those hashes |
| Forwarder state from a run | `~/.klav-forward` (its claim markers and `env.sh`), and the skill `klav-forward` installs in `~/.claude/skills/klav` and `~/.agents/skills/klav` |
| Agent logins | `~/.claude/.credentials.json`, `~/.codex/auth.json`, and every path in the manifest's `AGENT_LOGIN_FILES` |
| git and GitHub credentials | `~/.git-credentials`, `~/.config/gh/hosts.yml` |
| SSH private keys | `~/.ssh/id_*` other than `.pub`, and any file under `~/.ssh` with a private key header |
| Boat's keys | Each entry under `~/.config/ascii` that isn't a folder (a file, a link, anything else), unless it's a regular file on the allow list. A normal Boat machine has two files there with no key in them, `boat/config.json` and `computer-mcp.py` |
| Secret strings | `ksb1_`, `tskey-` or `boat_` in any file, text or binary, on the whole disk a snapshot saves |
| A name with a newline | Any file or folder on that disk whose name holds a newline, shown with `\n`. The checks read paths one line at a time, so such a name could make a file pass for an excused one |

`~` is `/root` and every directory under `/home`.

**The string scan** covers every file on the root's filesystem, and on those of `/home`, `/root`, `/etc` and `/var` if they are mounted on their own. It skips:
- `/proc`, `/sys`, `/dev` and `/run`: they aren't on the disk, and `/run` holds this folder and the binary while they run;
- `klav-forward` and `klav-tailnet-up` while they match the build record. Both name these strings on purpose: `klav-forward` reads packages, and `klav-tailnet-up` refuses OAuth secrets;
- a Debian package's file while its MD5 is the one in that package's list in `/var/lib/dpkg/info`. Tailscale's own binaries name `tskey-`;
- a file on the allow list, while it has the listed SHA-256.

Any other file that holds one of the strings is a finding, also when it's harmless. It takes 24 s on a real build machine: about 350 000 files, 21 GB.

### The allow list

`ALLOW=<SHA-256>  <absolute path>` lines in the manifest, two spaces between, one per file, as `check-template --hashes` prints them. `build-template` copies them into the record.
- **What it excuses:** a file at that path that is a regular file, not a link, with that SHA-256, and only from the string scan and from `~/.config/ascii`. Any other file, or a listed file whose bytes changed, is still a finding.
- **What it never excuses:** agent logins, SSH keys, git and GitHub credentials, forwarder state, Tailscale state, and the two Klav files. `--hashes` prints no line for those.
- **An entry whose file is missing, or whose file has other bytes, excuses nothing.** `check-template` prints a note for it, never a finding: an entry only ever takes a finding away.
- **Where the lists come from:** the manifest's (`--manifest`) before a build, for `--hashes` and `--validate`. Once the build record exists, its `ALLOW` and `AGENT_LOGIN_FILES` lines are always the ones used, with or without `--manifest`, so a run by hand never checks fewer logins or excuses more files than the build recorded. A `--manifest` whose lists aren't the record's (any order) exits 2. `build-template` passes the record itself.
- **Refused, exit 2, before anything is installed:** a line that isn't that shape, a hash that isn't 64 lowercase hex, a relative path, an empty, `.` or `..` part, a character other than letters, digits and `._+@~:,=/-`, a path listed twice, a path under `/proc`, `/sys`, `/dev` or `/run` (never scanned), under `/var/log` or apt's lists (the build empties them), and the two Klav files and the record. `check-template` checks these lines, for itself and, with `--validate`, for `build-template`.

### What `check-template` can't see

- **Variables given to the build machine with `-e`,** which a saved snapshot replays on every deploy, and whether the machine was made with `--no-env`.
- **Boat's per-machine token.** Every Boat machine has `~/.ascii/host-token`, mode 0600, a JWT, and the variable `ASCII_TOKEN`. Boat rewrites the file at each machine start. It holds none of the three strings and isn't in any category, so the checks pass with it, and a saved template carries the build machine's copy. Nobody has yet shown that the token dies with the build machine. Until someone does, keep the template private: never share it with a share code. The scripts don't read the file.
- **A CLI's login moved elsewhere,** for example Northflank's with `NF_CONFIG_DIR`. Only the paths in `AGENT_LOGIN_FILES` are checked.

## `klav-tailnet-up`

The daily environment's setup script runs it before the lines `klav sandbox start` prints:

```sh
{ printenv KLAV_TAILNET_KEY || true; } | sudo -n /usr/local/sbin/klav-tailnet-up "${KLAV_TAILNET_HOSTNAME:-}"
```

With the tailnet off (`TAILNET=off` in `new-sandbox`), neither variable is set. Then the input and the hostname are empty, and it skips. The line works under `set -euo pipefail`.

It follows ADR 0042 §4, in order:
1. no tracing;
2. the key from standard input into a 0600 file, in a new directory under `/run` that is removed on every exit. With an empty input and an empty hostname it says `no Tailscale key: skipped` and exits 0;
3. if the node already runs with `tag:klav-sandbox`, it exits 0 without calling `up` (a rerun with a spent key);
4. `tailscaled --state=mem:` if its socket isn't there, as a transient systemd unit (`systemd-run --unit=klav-tailscaled --collect`), waiting at most 30 s for the socket. A child of the script would share the setup script's session and control group. Then a hangup from `sudo` or the session's end could stop it, and with its state in memory a stopped daemon is a logged-out node. The unit's name isn't the masked `tailscaled.service`;
5. `tailscale up --auth-key=file:… --hostname=… --accept-dns=false --accept-routes=false --timeout=60s`;
6. without the tag on the node it runs `tailscale logout` and exits 1.

**It refuses with exit 2:**
- a hostname with an empty input: `new-sandbox` made a key for this sandbox, and it didn't arrive;
- a hostname that isn't lowercase letters, digits and dashes;
- a key with characters a key never has;
- an OAuth client secret (`tskey-client-…`).

The key is never an argument of any process, and never in a trace. Never run the setup lines with `-x`.

**`sudo -n` must work for the sandbox's user without a password.** The script doesn't set that up.

## Tests

```sh
deploy/sandbox-template/test/run-tests
KLAV_TEST_BASH=/bin/bash deploy/sandbox-template/test/run-tests   # another bash
```

They need `jq`, `sha256sum` and `python3` or `node`, and install nothing.

**Every script under test runs with a `PATH` of fakes only.** The fakes stand in for `tailscale`, `tailscaled`, `systemd-run`, `systemctl`, `sudo`, `pgrep`, `id`, `ls`, `apt-get`, `apt-mark`, `curl`, `npm`, `install`, `journalctl` and `truncate`, and each records its arguments and environment. A few plain tools are reached only through logging wrappers. The ones that write (`rm`, `mkdir`, `chmod`, and the fake `install`, `curl` and `truncate`) refuse any path outside the case's directory. A guard fails a case when anything else ran. A `noexec` mount is stood in for by a file without its execute bit, and by an exec that exits 126.

**The shipped `klav-tailnet-up` and `build-template` never run in the tests.** Both fix their own `PATH`, and they write under `/run` and `/`. So the tests run copies whose marked "test seam" lines point at the fakes and at a temporary directory:
- `klav-tailnet-up`: three lines (`bin_path`, `run_dir`, `socket_wait`);
- `build-template`: two lines (`bin_path`, and `root`, which prefixes every system path it reads or writes).

The tests check three things about each copy:
- it equals the shipped file outside the seam;
- the shipped seam holds the real values;
- the rewrite applied, before anything runs.

For `build-template`, a test also checks that no system path outside the seam skips `root`. The seams are constants, so the caller's environment can't change what the installed script runs or where it writes. A test passes `klav-tailnet-up`, the script `sudo` runs, a hostile `PATH` and hostile seam variables to prove it.

The documented setup line is tested as written in this README: under `set -euo pipefail`, with and without the two variables, through a fake `sudo` that accepts only those arguments.

**What the fakes don't prove.** It's for layer 6, against the real services. The real template build of 2026-11-17 and the first daily sandbox, on 2026-11-18, which deployed that template on a real tailnet ([try-sandboxes.md](../../docs/try-sandboxes.md#what-the-real-run-of-2026-11-18-taught)), proved most of it.
- **Proved by the build of 2026-11-17,** on a normal Boat machine of the build environment, with the scripts at that day's `main`:
  - the real install of `build-template`: it exited 0 in 54 s with `is ready` and `nothing forbidden found`. The Tailscale package and `jq` were pinned and held, and `@northflank/cli` was pinned and installed by root's `npm` into the user's nvm prefix. On the saved machine afterwards, `check-template` by hand again found nothing; the unit was masked, no `tailscaled` ran and `/var/lib/tailscale` was empty; `klav-tailnet-up` with no key said `no Tailscale key: skipped` and exited 0; and `apt-get update` worked after the lists had been deleted;
  - that the exec tmpfs of step 4 lets both run: `build-template` and `check-template` ran from a root-owned tmpfs mounted with `exec` under `/run`;
  - that `journalctl --rotate` and emptying the logs let the scan pass, the user's journal included. A trial run before the fix had failed on exactly `/var/log/auth.log` and the user's journal, because `sudo` and journald keep command lines;
  - the string scan against the real base image with its allow list, and with the pinned CLIs installed. The allow list was what `check-template --hashes` printed, the same paths and hashes as a trial run hours earlier on another machine with a different base image version, and the manifest's `AGENT_LOGIN_FILES` was `.northflank/config.json`.
- **Proved by the daily sandbox of 2026-11-18:**
  - a rerun of `klav-tailnet-up` with a spent key on a node already up: two hours in, it said `already on the tailnet with tag:klav-sandbox: nothing to do` and exited 0;
  - that systemd is reachable from the setup script, and `tailscaled` is still up after the setup script ends: `klav-tailscaled` was still active two hours later;
  - that `sudo -n` works without a password for the sandbox's user;
  - that `systemctl mask` survives Boat's snapshot: `tailscaled.service` was still masked in the deployed sandbox;
  - what `tailscale status --json` really prints for a tagged node: `BackendState` `Running`, `Self.Tags` `["tag:klav-sandbox"]`, and the node online.
- **Still not proven:** that `build-template` names the cause when it is started from a real `noexec` mount. The fixed scripts were never run from one.
