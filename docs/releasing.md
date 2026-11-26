# Releasing Klav's downloads

This page says what one release of Klav's downloads contains, the file names the site's links rely on, the order of the steps, and which steps only Omar can do. The iPhone app ships through TestFlight and the App Store instead ([publicar-ios.md](publicar-ios.md)), and the extension stores have their own guide ([publicar-extension.md](publicar-extension.md)).

Releases are GitHub Releases of `OmarAlex24/klav`, which only work once the repository is public. None of `klav.dev`'s download URLs leads to GitHub before that: the site serves its own `/download/…` URLs and redirects them only for what is switched on ([sitio-web.md](sitio-web.md) §2).

## 1. What a release contains

`scripts/release/kit.mjs` puts these files in `target/release-kit/<tag>/`. Their names never carry a version, so `https://github.com/OmarAlex24/klav/releases/latest/download/<name>` always gives the newest one.

| File | What it is | Made by | Site URL |
|---|---|---|---|
| `Klav.dmg` | The Mac app: Apple silicon, macOS 15 or later, Developer ID signed, notarized and stapled. It carries `klav`, `klavd` and `klav-native-host` | `scripts/macos/build-app.sh release` ([macos.md](macos.md) §5) | `/download/mac` |
| `appcast.xml` | The Sparkle feed, with one item for this `Klav.dmg`, signed with the EdDSA key | `scripts/macos/appcast.sh make` ([macos.md](macos.md) §6) | `/releases/mac/appcast.xml`, which every Mac app build has baked in |
| `klav-extension-chromium.zip` | The extension for Chrome, Brave, Edge, Arc and Dia, loaded unpacked (§3) | `scripts/extension/package.sh` | `/download/extension/chromium` |
| `klav-extension-firefox.xpi` | The extension for Firefox, ID `klav@klav.dev`, signed by Mozilla as an unlisted add-on (§3). Optional: until Mozilla signs it, the release has no Firefox file, and the unsigned zip is never published | `scripts/extension/package.sh`, then addons.mozilla.org | `/download/extension/firefox` |
| `klav-linux-x86_64.tar.gz` | `klav`, `klavd` and `klav-native-host` for Linux, x86_64, glibc 2.36 or later (Debian 12), in a folder `klav-linux-x86_64/`. Optional until the CI build of §6 has run | CI (§6) | `/download/linux` |
| `klav-server-linux-x86_64.tar.gz` | `klav-server`, its hardened systemd unit (`klav-server.service`) and `server.toml.example` (invite mode, `127.0.0.1:8080`), from [`deploy/server/`](../deploy/server/), in a folder `klav-server-linux-x86_64/`; x86_64, glibc 2.36 or later. Optional until the CI build of §6 has run (ADR [0048](decisiones/0048-invite-beta-and-distribution.md) §5.2) | CI (§6) | — (the docs and Homebrew use the tag's GitHub URL) |
| `RELEASE.txt` | The tag, the commit, and where each file came from, including which Chromium build it is | the kit | — |
| `SHA256SUMS` | SHA-256 of every file above | the kit | `/download/checksums` |

`/download/iphone` redirects to the public TestFlight link, which is not a file ([publicar-ios.md](publicar-ios.md)).

The same CI run also leaves the Linux `klav-forward` and `klav-proxy` as a separate artifact, for testing agent sandboxes; it is not part of a release, and once the repository is public anyone signed in to GitHub can download it for the day it is kept (§6).

**The names are a contract.** `ASSETS` in `scripts/release/kit.mjs` and the redirects in `apps/web/server.mjs` use the same names. Renaming one breaks every link already published: change both in one PR. `klav-server-linux-x86_64.tar.gz` has no site route: the self-hosting docs and the Homebrew formula name it by `releases/download/vX.Y.Z/…`, so renaming it breaks those instead.

**No macOS CLI on its own.** On a Mac, the CLI comes from the app ("Set up this Mac" links `/usr/local/bin/klav` to the app's copy, which updates with it). The binaries in `target/release` are not signed or notarized: downloaded from a browser, macOS quarantines them and refuses to run them, and a bare `klavd` shows Touch ID without Klav's name and icon ([macos.md](macos.md) §3, "klavd va en su propio *bundle*"). An Intel Mac builds from source. For the same reason there is no macOS `klav-server`: Homebrew's formula builds it from the tag's source (§2, step 11).

## 2. The steps, in order

"Owner" marks what only Omar can do: it needs Omar's signing identity, keys or accounts. Nothing in the kit does any of it, and an agent never does it in Omar's place.

1. **The version.** One version for the Mac app, the extension and the CLI, and a tag `vX.Y.Z` for it; the first release is `v0.9.0` (§8). Raising it is a separate PR, merged before the tag: the workspace version in `Cargo.toml` (and `Cargo.lock`), `MARKETING_VERSION` and `CURRENT_PROJECT_VERSION` in `apps/ios/project.yml` (the build always goes up: Sparkle compares it), the `version` in `apps/extension/package.json` and `packages/sdk/package.json`, and the image tag in the root `docker-compose.yml` (`ghcr.io/omaralex24/klav-server:X.Y.Z`, the image `release-docker.yml` publishes for that version, so the file at the tag names its own image). It touches `crates/`, `Cargo.*` and the Mac app, so it isn't part of the release kit's PRs.

   **The release commit** is that merge on `main`, and every step below uses its full SHA: the Mac app and the extension are built from a clean checkout of it, the Linux workflow builds it (§6), and the tag names it. `assemble` refuses a checkout with changes and writes its commit in `RELEASE.txt`; `seal` prints `gh release create --target <that commit>`, because without `--target` GitHub cuts a new tag from the newest commit on `main` when the draft is published.
2. **The Mac app (owner),** from a clean checkout of the release commit. `nice -n 19 env CARGO_BUILD_JOBS=2 scripts/macos/build-app.sh release`. The version and the build come from `apps/ios/project.yml` (step 1), and the DMG takes its name from the app's `Info.plist`; `build-app.sh`'s `KLAV_MAC_VERSION` and `KLAV_MAC_BUILD` overrides are for the update test ([probar-mac.md](probar-mac.md)), not for a release. It signs with the Developer ID in the owner's keychain and notarizes with the owner's App Store Connect key, and leaves `target/macos/dist/Klav-X.Y.Z.dmg`. The key's path, key ID and issuer ID come from the environment or the owner's local build config ([ios.md](ios.md) §5), which lives outside the checkout, so the checkout stays clean; without them the script stops before building. Its DerivedData goes in `target/xcode/mac-release-derived` unless that config says otherwise.
3. **The extension.** `pnpm install && scripts/extension/package.sh`, from the same clean checkout. It leaves the three zips (store, keyed and Firefox), the source archive and their `SHA256SUMS` in `target/extension/`.
   - **Firefox (owner):** upload the Firefox zip and the source archive to addons.mozilla.org for signing (§3, "Signing the Firefox build"). When the signed `.xpi` is back, install it in release Firefox (`about:addons` › gear › *Install Add-on From File…*) and check that Klav loads: the kit doesn't verify Mozilla's signature. If that's done before step 5, pass it with `--firefox-xpi`; otherwise the release goes out without Firefox, and step 10 adds it.
4. **Linux (owner):** run the workflow of §6 from `main` on the release commit (the same full SHA), which must contain the build identity (§6, "When it can run"), then download its two tarballs with `gh run download` (`klav-linux-x86_64` and `klav-server-linux-x86_64`).
5. **Assemble:**

   ```sh
   node scripts/release/kit.mjs assemble --tag vX.Y.Z --chromium dev [--firefox-xpi klav-signed.xpi] \
     [--linux klav-linux-x86_64.tar.gz] [--server-linux klav-server-linux-x86_64.tar.gz]
   ```

   It checks each input before it copies or removes anything:
   - the checkout has no changes, and its commit goes in `RELEASE.txt`;
   - the DMG ends in a disk image trailer and, when found by default, is named `Klav-<version>.dmg`; `seal` then checks the appcast's version and length;
   - every zip matches `package.sh`'s `SHA256SUMS`;
   - the Firefox ID is `klav@klav.dev`;
   - a `.xpi` holds exactly the files of `package.sh`'s Firefox zip, plus `META-INF/` signature files. The kit doesn't verify the signature (Firefox does when it installs), so install the `.xpi` in release Firefox before publishing;
   - the Chromium zip carries exactly the development key (`--chromium dev`) or no key (`--chromium store`);
   - the Linux tarball holds the three binaries, as regular files, executable;
   - the server tarball (`--server-linux`) holds `klav-server-linux-x86_64/klav-server`, executable, and `klav-server.service` and `server.toml.example`, all as regular files. `RELEASE.txt` gets a `server-linux:` line, and `seal` lists it in `SHA256SUMS`.

   `--chromium` has no default: which build people get is a decision (§3). Each command takes only its own flags, each once: a misspelled `--xpi` fails instead of leaving Firefox out.

   `--out` (default `target/release-kit/<tag>`) must be a new folder, or one holding only a kit's files: `assemble` deletes only those, and refuses a folder with anything else in it or an input inside it.
6. **Sign the appcast (owner).** `assemble` prints the command: the one in [macos.md](macos.md) §6, whose `appcast.sh` takes Sparkle's `sign_update` from step 2's DerivedData, with `--url-base https://github.com/OmarAlex24/klav/releases/download/vX.Y.Z` and the kit's `Klav.dmg`. The feed is signed whole, so the enclosure URL is fixed at this step: it must name this tag's release, never `releases/latest`, or an old feed would point at a newer DMG.
7. **Seal:**

   ```sh
   node scripts/release/kit.mjs seal --tag vX.Y.Z
   ```

   It refuses if:
   - a file is missing, or `RELEASE.txt` names no commit;
   - the directory holds anything else;
   - the appcast is not signed, has more than one item, or doesn't name this tag's `Klav.dmg` with its exact length and version;
   - the appcast's signature block has two `edSignature:` or two `length:` lines (`appcast.sh` signs the feed once, and which line Sparkle would keep isn't checked);
   - a signature or the key isn't canonical base64 of the right length, whitespace around it included: whether Sparkle would trim it isn't checked, so the kit doesn't;
   - either EdDSA signature doesn't verify with `KLAV_SPARKLE_PUBLIC_KEY` (`apps/ios/Config/Base.xcconfig`, the key every Mac app build checks updates with): the enclosure's over `Klav.dmg`, and the feed's own over the bytes before its signature block, as Sparkle 2.10.0 reads it. A feed signed with `appcast.sh test-key`'s key fails here; installed apps would refuse the update.

   It verifies with Node's built-in `node:crypto` and never signs anything. Then it writes `SHA256SUMS` and prints the `gh release create --target <commit>` command, with `--notes-file NOTES.md`: write the notes in that file first.
8. **Publish (owner).**
   - `gh release create vX.Y.Z --target <release commit> --draft …` with the files `seal` listed, as `seal` prints it. The tag is created on that commit when the draft is published.
   - Open the draft, check the files and the notes, and publish it.
   - **Not as a pre-release:** `releases/latest` skips pre-releases, so every link and the update feed would keep pointing at the previous release (or at nothing, the first time).
9. **The first time only (owner),** in this order, as [sitio-web.md](sitio-web.md) §2 lists them:
   1. the release from step 8 is published, not as a pre-release;
   2. make the repository public;
   3. `curl -sIL https://github.com/OmarAlex24/klav/releases/latest/download/appcast.xml` ends in `200`;
   4. attach the custom domain `docs.klav.dev` to the docs site ([sitio-web.md](sitio-web.md) §7, "Poner `docs.klav.dev`"), and check that it answers `200`: with `docs` on, the downloads section and the install steps link to it;
   5. only then set `KLAV_WEB_OPEN` on Railway's `klav-web` service, and deploy the staged change;
   6. check what §5 lists;
   7. `iphone` comes after all of this, never before: the iPhone app only signs in, so someone who joins the TestFlight beta needs the downloads and the self-hosting docs to create an account ([publicar-ios.md](publicar-ios.md) §9.5, step 7).

   **Before 9.2 (making the repository public):** `ci.yml` uses the ci-cache setup action from `OmarAlex24/ci-cache`, a private repository, and a workflow in a public repository can't use an action from a private one. PR #395 copies that action into this repository. Merge it, and check that `ci` is green on `main` with it, before making the repository public.

   With `mac` on before step 3 passes, every `/download/…` link and every installed Mac app's update check follows a `302` into a GitHub `404`. Later releases change nothing on the site: `releases/latest` follows them.
10. **Firefox, when Mozilla's signature is back (owner):**

    ```sh
    node scripts/release/kit.mjs firefox --tag vX.Y.Z --xpi klav-signed.xpi
    ```

    First check that the kit is the published one: `gh release download vX.Y.Z --repo OmarAlex24/klav --pattern SHA256SUMS --output - | diff - target/release-kit/vX.Y.Z/SHA256SUMS` prints nothing. Before running `firefox`, install the `.xpi` in release Firefox and check that Klav loads (step 3): the kit doesn't verify Mozilla's signature. `firefox` refuses a kit where anything changed since `seal`, or that holds a file `SHA256SUMS` doesn't list (`.DS_Store` included): assemble and seal again then. It checks the `.xpi` as `assemble` does (its files, not the signature), adds it as `klav-extension-firefox.xpi`, rewrites `RELEASE.txt` and `SHA256SUMS`, and prints the `gh release upload --clobber` command for the three files. Then switch `firefox` on ([sitio-web.md](sitio-web.md) §2).

11. **The Homebrew tap (owner),** after step 8, once the release and its source archive exist: a PR to `OmarAlex24/homebrew-tap` that bumps the tag in every URL of `Casks/klav.rb`, `Formula/klav-cli.rb` and `Formula/klav-server.rb`, with the `sha256` values copied from this release's `SHA256SUMS` (and, for `klav-server`'s source archive, `curl -fsSL https://github.com/OmarAlex24/klav/archive/refs/tags/vX.Y.Z.tar.gz | shasum -a 256`). The templates and the exact commands are in [`deploy/homebrew/README.md`](../deploy/homebrew/README.md). No token in Klav's CI can write to the tap (ADR 0048 §5.3, T250); creating the tap and its ruleset is a one-time step there.

## 3. The browser extension

A zip loaded with "Load unpacked" is an unpacked extension, and its ID decides whether `klav-native-host` lets it reach `klavd` ([extension.md](extension.md) §3, "Who can call"). There are two builds, and neither is as safe as the store's:

- **`--chromium dev`: the keyed build** (`klav-<v>-chromium-dev.zip`). Its manifest carries the development key, so its ID is always `niiplppgdljgimbnmokojdkofdcjkgao`. It connects with `klav extension install-host --dev`, or with "Development extension" in the Mac app. **The risk:** that key's public half is in the repository, so any unpacked extension that carries it gets the same ID and could talk to `klavd` (ADR 0030, layer 09; threats T64 and T122). The Mac app says this before the switch turns on, and the public install page says it too.
- **`--chromium store`: the store build** (`klav-<v>-chromium.zip`), without a key. Chromium gives an unpacked extension without a key an ID made from the folder it was loaded from, so each person gets their own. It connects with `klav extension install-host --extension-id <that ID>`. The Mac app can't do that: "Connect the browsers" rewrites the host without `--extension-id`, and from then on the host refuses the extension.
- **`--chromium none`:** Chromium browsers wait for the Chrome Web Store, and Firefox is the only browser offered.

Which one a release offers is Omar's decision. Until the Chrome Web Store lists Klav, even as *Unlisted*, there is no build without one of these trade-offs.

**Firefox** has its own limit. Release Firefox installs only add-ons Mozilla signed. A zip loaded with "Load Temporary Add-on…" stays installed only until Firefox restarts (Mozilla's [temporary installation](https://extensionworkshop.com/documentation/develop/temporary-installation-in-firefox/) page). So a release offers only a self-distributed build: AMO signs it without listing it, and the person installs the `.xpi` for good ([signing and distribution](https://extensionworkshop.com/documentation/publish/signing-and-distribution-overview/)). It doesn't update itself: the manifest has no `update_url`, so a new version is installed by hand from the downloads.

### Signing the Firefox build (owner)

What Mozilla's pages say, read on 2026-11-13 ([Submitting an add-on](https://extensionworkshop.com/documentation/publish/submitting-an-add-on/), [Source code submission](https://extensionworkshop.com/documentation/publish/source-code-submission/)):

- **Source code is required.** *You must upload your extension's source code when its code was created using* bundlers or *any other custom tool that takes files, applies pre-processing, and generates file(s)*. Klav's is bundled with esbuild and carries a WebAssembly build. *Matching source code must be attached to every extension version*, up to 200 MB. A reviewer *uses a diff tool to compare the generated sources to those in the extension. There must be no differences.*
- **No notes field** appears in the self-distribution steps, so the build steps travel inside the source archive: `package.sh` puts `apps/extension/BUILDING.md` and `BUILD-INFO.txt` (the exact tool versions) at its root.
- **The signed file** comes back by email. *You receive an email when your extension has been signed.* Then it is under My Add-ons, in the version's page. *Further review may still happen afterwards.*

The clicks, with the two files from `target/extension/` of the release commit:

1. addons.mozilla.org › Developer Hub › *Submit a New Add-on* (for later versions, the add-on's own page › *Upload New Version*, so AMO treats it as an update).
2. *On your own*, then *Continue*.
3. *Select a file*: `klav-<version>-firefox.zip`. Validation runs the same `addons-linter` as `package.sh`; only the Firefox for Android warning should show (no native messaging there). Platforms: Firefox only.
4. *Do you need to provide your source code?* **Yes**, and upload `klav-<version>-source.zip`.
5. Wait for the email, download the signed `.xpi` from the version's page, and pass it to the kit (§2, step 5 or step 10).

The first submission creates the add-on under Omar's AMO account, which doesn't exist yet ([publicar-extension.md](publicar-extension.md) §1).

**A note for Omar on the source archive.** It is `git archive` of the whole tracked repository at the release commit, not only the extension: every document in `docs/`, the other apps and the server included. Uploaded before the repository is public, it gives Mozilla's reviewers the full repository. Check that this is fine with you before the first upload; if not, wait until the repository is public.

## 4. What only Omar can do

- Make the repository public.
- Sign and notarize the Mac app, and sign the appcast (Omar's Developer ID, App Store Connect key, and the Sparkle key in Omar's vault).
- Create the tag and the GitHub Release, and publish it. The tag names the release commit, the one in `RELEASE.txt` (`--target`, §2 step 1), and the Mac app and the Linux workflow are built from that same full SHA.
- Set `KLAV_WEB_OPEN` and `KLAV_WEB_TESTFLIGHT_URL` on Railway.
- Upload the Firefox build and its source to addons.mozilla.org for signing (§3), install the signed `.xpi` in release Firefox before it ships, and anything else in App Store Connect, the Chrome Web Store or addons.mozilla.org.
- Merge the version bump (§2, step 1) and run the Linux workflow (§6).
- Create `OmarAlex24/homebrew-tap` with its ruleset, and bump it each release (§2, step 11).

## 5. After the first release

From a computer that isn't signed in to anything (plain `curl`, no cookies):

- `curl -sI https://klav.dev/download/mac` answers `302` with `Location: https://github.com/OmarAlex24/klav/releases/latest/download/Klav.dmg`, and following it ends at the DMG. The same for every switched-on URL in §1.
- `curl -sL https://klav.dev/releases/mac/appcast.xml` gives the signed feed.
- `shasum -a 256 -c SHA256SUMS` passes on the downloaded files.
- **The update path:** install the previous build, choose "Check for Updates…" and watch it install this one. Sparkle reads the feed through two redirects (`klav.dev` → `github.com` → GitHub's file host) and the DMG through one.

What is known about that path, from Sparkle 2.10.0's source (the version the Mac app pins), read for the review of the site's redirects:

- The feed is signed whole (`SURequireSignedFeed` in `apps/ios/Mac/Info.plist`; `appcast.sh make` signs it), so no host along the redirects can change it without Sparkle refusing it.
- Sparkle fetches the feed with `NSURLSession`'s defaults, which follow cross-host HTTPS redirects; its delegate doesn't implement `willPerformHTTPRedirection`. It checks the status only on the final response and doesn't check the content type.
- A background check that meets a `404` shows no dialog: a broken link fails silently on every installed Mac app, which is why step 9 checks the GitHub URL before switching `mac` on.

What only the first release can test, and what to do if it fails:

1. **What GitHub answers for this repository's `appcast.xml` asset** (`curl -sIL …/releases/latest/download/appcast.xml`, step 9). If it isn't a `200` at the end of the redirects, leave `mac` off and find why (a draft or pre-release, a private repository, a wrong asset name) before anything else.
2. **How GitHub's file host treats Sparkle's User-Agent.** If "Check for Updates…" reports an error or finds nothing while `curl` gets the feed, the fallback is for the site to serve a copy of `appcast.xml` itself (an `apps/web` PR; the feed is signed, so serving it from another host changes nothing about trusting it).
3. **Whether `UpdateGuard`'s Team ID check finds the downloaded DMG** where it expects it (`apps/ios/Mac/Updates.swift`, Sparkle's `PersistentDownloads` folder). If the app shows "Klav X.Y.Z wasn’t installed" and the log has `rejected: no download` (`log stream --predicate 'subsystem == "dev.klav.mac"'`), the guard is looking in the wrong place: no update installs until a fixed build ships, and people with the broken build download the next one from `/download/mac` by hand. That fix belongs to the Mac app's owner.

## 6. Linux binaries in CI

`.github/workflows/release-linux.yml` builds them; `deploy/linux/Dockerfile` is its build. Omar decided on 2026-11-13 that the Linux binaries are built in CI (§8).

- **Run only by hand** (`workflow_dispatch`), with the full SHA of the commit to build. It runs on no push or PR, so the `ci` job and its cost don't change. Its job is called `linux release build`, a name no check of `ci.yml` uses.
- **Only a commit on `main`.** It checks out the full history and stops before building unless `git merge-base --is-ancestor <sha> origin/main` passes, so a commit from another branch or a fork's never reaches the kit as release binaries.
- **One job on `boat-large`.** Under ADR 0034 that is one machine start per run, plus the build time. A release build of `klav`, `klavd` and `klav-native-host` with the Mac app's settings (fat LTO, one codegen unit, stripped: `scripts/macos/build-app.sh`), plus `klav-forward` and `klav-proxy`, took 2 min 46 s for the whole job on its first run (2026-11-16), about 145 s of it the build step; `klav-server` (ADR 0048 §5.2) makes it a sixth binary. Expect a cold build every time: there is no compile cache. Boat's pages don't publish the price per second per size (ADR 0034, "Tamaño"), so the cost is a start plus a few minutes of `boat-large`, once per release. The job stops at 60 minutes, which only bounds a hung run.
- **Inside the pinned builder image** that the root `Dockerfile` already uses (`rust:1.98.1-slim-bookworm@sha256:ff52…`), so no new image enters the supply chain. Its glibc is 2.36: the binaries run on Debian 12, Ubuntu 23.04 and newer, and not on Ubuntu 22.04 (§8). The job summary lists the newest glibc symbol each binary needs.
- **No compile cache.** With fat LTO and one codegen unit, sccache would hit almost nothing, the ci-cache session is read-only from `main`, and it would put a token in the environment of every build script. Paths are the image's (`/src`, `/usr/local/cargo`), so nothing from the runner ends up in the binaries and no `--remap-path-prefix` (no `RUSTFLAGS`) is needed. `deploy/linux/Dockerfile.dockerignore` replaces the root `.dockerignore` for this build, which would leave out `skill/SKILL.md`.
- **Its output is three workflow artifacts.** `klav-linux-x86_64`, kept 7 days, holds `klav-linux-x86_64.tar.gz` and its `.sha256`, also printed in the job summary; Omar downloads it and passes it to `kit.mjs assemble --linux`. `klav-server-linux-x86_64`, kept 7 days, holds `klav-server-linux-x86_64.tar.gz` (the server, its systemd unit and example configuration from `deploy/server/`) and its `.sha256`, also in the summary, for `kit.mjs assemble --server-linux`. `klav-sandbox-linux-x86_64`, kept 1 day, holds `klav-forward` and `klav-proxy`, for testing agent sandboxes; it is not part of a release. Workflow artifacts are not private to Omar: once the repository is public, anyone signed in to GitHub can download a run's artifacts while they are kept.
- **A test pre-release may carry the Linux tarballs** before the first release: a tag without the `v` prefix, marked pre-release, so `releases/latest` never points at it. It is not a release of Klav's downloads, and it becomes public with the repository unless it is deleted first.
- **The job's only permission is `contents: read`,** for the checkout: it can't create a release, upload to one or get an OIDC token.

**When it can run.** GitHub offers a `workflow_dispatch` workflow only once its file is on the default branch, so the first run waits until this stack is merged. It builds the commit in `sha` with that commit's own `deploy/linux/Dockerfile`, so that commit must already contain it: the release commit, after the version bump (§2, step 1). Dispatch it only on a commit that contains the build identity (PR #385: `klav --version` names the commit and its date): the workflow passes the commit to the build and stops unless the tarball's `klav --version` names it, so on an older commit it fails after the build. It also stops unless `klav-forward --version`, `klav-proxy --version` and `klav-server --version` name it, so the commit must also be one where those three carry the build identity (`klav-forward` and `klav-proxy` print only `0.0.0` before it; `klav-server` printed only its version until it gained the identity, ADR 0048 §5.2). Then it stops unless every binary's newest glibc symbol is `GLIBC_2.36` or older (the floor, §8).

Run it from a checkout signed in to `gh`, and dispatch it from `main` (the default: no `--ref`), so the workflow file that runs is `main`'s:

```sh
gh workflow run release-linux.yml -f sha=<full SHA of the release commit>
gh run list --workflow release-linux.yml --limit 1        # the run's ID
gh run download <run ID> -n klav-linux-x86_64              # once it has finished
gh run download <run ID> -n klav-server-linux-x86_64
```

## 7. Tests

`node --test scripts/release/test/*.test.mjs`, in the CI task `extension` next to the site's tests. The tests use made-up files (a DMG trailer, small zips, a tar, an appcast in `appcast.sh`'s format) and an Ed25519 key pair they generate, so they need no build and never the real key. They pass their own repository, key and commit, so `KLAV_RELEASE_REPO` or the state of the checkout doesn't change them. One test reads this checkout's commit with `git`, so they run in a Git checkout.

## 8. Decisions (Omar, 2026-11-13)

Omar took the recommended option on each.

- **Chromium:** the keyed build (`--chromium dev`), published as a preview with its risk explained (§3).
- **Firefox:** an `.xpi` Mozilla signs as an unlisted add-on; Omar uploads it (§3). Until a signed file exists, the release has no Firefox file and the site shows Firefox as not out yet; the unsigned zip is never published.
- **Version:** `v0.9.0` for the Mac app, the extension and the CLI. The bump is its own PR, merged before the tag (§2, step 1).
- **Linux tarball:** `klav`, `klavd` and `klav-native-host`.
- **Linux floor:** Debian 12 (glibc 2.36). Ubuntu 22.04 is out for the first release.
- **Linux in CI:** the workflow of §6, run by hand; it publishes nothing.
