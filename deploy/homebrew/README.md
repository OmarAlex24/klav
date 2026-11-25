# Homebrew tap templates

These files are the contents of Klav's Homebrew tap, `OmarAlex24/homebrew-tap`
([ADR 0048](../../docs/decisiones/0048-invite-beta-and-distribution.md) §5.3,
Q6). They live here so that a change to them is reviewed with the release that
needs it; Omar copies them to the tap. Nothing in Klav's CI writes to the tap:
a token that can push there could publish code onto people's machines (T250).

| File in the tap | What it installs | Where |
|---|---|---|
| `Casks/klav.rb` | The Mac app, `Klav.dmg` of the tag. Sparkle updates it (`auto_updates true`), so `brew upgrade` skips it unless `--greedy` | macOS 15 or later, Apple silicon |
| `Formula/klav-cli.rb` | `klav`, `klavd` and `klav-native-host` from `klav-linux-x86_64.tar.gz` | Linux x86_64, glibc 2.36 or later |
| `Formula/klav-server.rb` | `klav-server`: the prebuilt `klav-server-linux-x86_64.tar.gz` on Linux; built from the tag's source with Homebrew's Rust on macOS. A `brew services` service, and a first `etc/klav/server.toml` in invite mode | Linux x86_64; macOS |

What people run (a fully qualified name also trusts that item: Homebrew
refuses formulae and casks from a third-party tap nobody trusted):

```sh
brew install --cask omaralex24/tap/klav       # macOS: the app
brew install omaralex24/tap/klav-cli          # Linux: the CLI
brew install omaralex24/tap/klav-server       # Linux or macOS: the server
brew services start klav-server
```

`klav-cli` isn't called `klav`, so that `brew install klav` never has to choose
between it and the cask. On a Mac the CLI comes with the app ("Set up this
Mac").

Every URL names the tag (`releases/download/vX.Y.Z/…` or
`archive/refs/tags/vX.Y.Z.tar.gz`), never `releases/latest`, so a `sha256`
always matches the file it names. Every `sha256` here is a placeholder of
zeros: Homebrew refuses the download until it is replaced.

## Creating the tap (once, Omar)

After the first release that carries `klav-server-linux-x86_64.tar.gz`
(`v0.10.0`) is published:

1. **The repository**, public, so Homebrew can clone it without credentials:

   ```sh
   gh repo create OmarAlex24/homebrew-tap --public \
     --description "Homebrew tap for Klav (https://klav.dev)"
   git clone https://github.com/OmarAlex24/homebrew-tap
   mkdir -p homebrew-tap/Formula homebrew-tap/Casks
   cp deploy/homebrew/Formula/*.rb homebrew-tap/Formula/
   cp deploy/homebrew/Casks/klav.rb homebrew-tap/Casks/
   ```

2. **The hashes,** as in "Each release" below, step 2. Then commit and push
   this first version straight to `main`: the ruleset doesn't exist yet.

3. **The ruleset of ADR 0040 §2 (a),** on the default branch: a pull request
   required with 0 approvals, squash only, no force push, no deletion, and an
   empty bypass list. The tap has no CI, so it requires no checks:

   ```sh
   gh api -X POST repos/OmarAlex24/homebrew-tap/rulesets --input - <<'JSON'
   {
     "name": "main",
     "target": "branch",
     "enforcement": "active",
     "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
     "bypass_actors": [],
     "rules": [
       { "type": "deletion" },
       { "type": "non_fast_forward" },
       { "type": "pull_request", "parameters": {
           "required_approving_review_count": 0,
           "dismiss_stale_reviews_on_push": false,
           "require_code_owner_review": false,
           "require_last_push_approval": false,
           "required_review_thread_resolution": false,
           "allowed_merge_methods": ["squash"] } }
     ]
   }
   JSON
   ```

   In *Settings › General*, allow only squash merging. The account that owns
   the tap keeps two-factor authentication on: whoever controls it controls
   what `brew install` runs (residual risk 100).

4. **Check it from a clean shell** on each platform you have, as in "Each
   release", step 4.

## Each release (Omar)

A step of [`docs/releasing.md`](../../docs/releasing.md) §2, after the GitHub
Release is published (the source archive and the assets must exist).

1. **Copy the templates** from the release commit's `deploy/homebrew/`, if
   they changed, and bump the tag in every URL (`v0.10.0` → `vX.Y.Z`).
2. **The hashes.** Three come from the release's own `SHA256SUMS`, which `seal`
   wrote; the fourth is GitHub's source archive of the tag, which isn't in it:

   ```sh
   tag=vX.Y.Z
   gh release download "$tag" --repo OmarAlex24/klav --pattern SHA256SUMS --output -
   # Klav.dmg                         → Casks/klav.rb
   # klav-linux-x86_64.tar.gz         → Formula/klav-cli.rb
   # klav-server-linux-x86_64.tar.gz  → Formula/klav-server.rb, resource "prebuilt"
   curl -fsSL "https://github.com/OmarAlex24/klav/archive/refs/tags/$tag.tar.gz" | shasum -a 256
   #                                  → Formula/klav-server.rb, the top-level sha256
   ```

3. **A pull request** to the tap with those changes, and run on the branch:

   ```sh
   brew style omaralex24/tap
   brew audit --strict --online omaralex24/tap/klav-cli omaralex24/tap/klav-server
   brew audit --strict --online --cask omaralex24/tap/klav
   ```

   (`brew tap omaralex24/tap`, then check out the branch in
   `$(brew --repository omaralex24/tap)`; `brew trust omaralex24/tap` once,
   so Homebrew loads the tap's files by name.) Squash-merge it.
4. **Check the published versions:**

   ```sh
   brew update
   brew upgrade omaralex24/tap/klav-server && brew test omaralex24/tap/klav-server   # macOS builds with Rust: minutes
   brew upgrade --cask --greedy omaralex24/tap/klav                                  # macOS
   brew upgrade omaralex24/tap/klav-cli && brew test omaralex24/tap/klav-cli         # Linux
   ```

   On a Mac the app's own Sparkle update usually gets there first, so the cask
   upgrade may find nothing to do.

## How the files are written

Checked against the installed Homebrew 7.0 and its Formula and Cask Cookbooks
(2026-11-25), with `brew style` and `brew audit --strict` clean on a local copy
of the tap:

- **No `url` inside `on_linux`/`on_macos`:** `brew style` refuses it. So
  `klav-server`'s main `url` is the tag's source archive, which macOS builds
  (`depends_on "rust" => :build`, `cargo install` through
  `std_cargo_args(path: "crates/klav-server")`), and Linux installs the
  prebuilt tarball from a `resource "prebuilt"` declared only `on_linux`.
  Linux downloads the source archive too, and doesn't build it.
- **`post_install_steps`, not `post_install`:** Homebrew deprecated the
  `post_install` method for formulae. `unless_path_exists` writes
  `etc/klav/server.toml` only when it doesn't exist, so an upgrade never
  overwrites it; `{{var}}` in its text becomes Homebrew's `var` (for example
  `/opt/homebrew/var`). A throwaway formula with the same block was installed,
  run twice and removed to check both.
- **The `service do` block** runs `klav-server --config etc/klav/server.toml`,
  logs to `var/log/klav-server.log`, and gives `brew services` a launchd agent
  on macOS and a systemd user unit on Linux.
- **`depends_on macos: :sequoia`** is the cask's minimum (macOS 15), and
  `depends_on arch: :arm64` keeps it off Intel Macs, which the DMG doesn't
  support.
- **The cask's `zap`** removes only what the app can rebuild. It leaves
  `~/Library/Application Support/klav`, where the account and the Secret Key
  live: without the emergency kit, that may be the only copy.
- **`klav-cli` after an upgrade:** the browsers' host manifest names
  `klav-native-host` by its real path, which is versioned under Homebrew's
  Cellar, so `klav extension install-host` must run again after
  `brew upgrade klav-cli`. Its caveats say so.
