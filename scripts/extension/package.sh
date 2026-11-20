#!/bin/sh
# Builds what goes to the extension stores (docs/publicar-extension.md §2):
#
#   target/extension/klav-<version>-chromium.zip  Chrome Web Store and Edge Add-ons (no dev `key`)
#   target/extension/klav-<version>-chromium-dev.zip  the same build with the dev `key`, for a
#                                                 release people load unpacked (docs/releasing.md)
#   target/extension/klav-<version>-firefox.zip   addons.mozilla.org
#   target/extension/klav-<version>-source.zip    the source AMO asks for (git archive of HEAD,
#                                                 plus BUILDING.md and BUILD-INFO.txt at its root)
#   target/extension/SHA256SUMS
#
# It builds klav-wasm, compiles both targets into target/extension/build
# (apps/extension/dist stays the development build), checks the manifests
# and runs addons-linter. From a clean checkout, so the source archive is
# exactly what was built; KLAV_ALLOW_DIRTY=1 skips that check (never for an
# upload). From the source archive (no .git), as AMO's reviewers run it, it
# builds the same two packages and skips the source archive.
#
# Usage: scripts/extension/package.sh
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
app="$root/apps/extension"
out="$root/target/extension"

cd "$root"
if [ ! -x "$app/node_modules/.bin/addons-linter" ]; then
  echo "package.sh: run \`pnpm install\` first" >&2
  exit 1
fi
PATH="$app/node_modules/.bin:$PATH"
export PATH
git=0
git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1 && git=1
if [ "$git" = 1 ] && [ "${KLAV_ALLOW_DIRTY:-}" != "1" ] && [ -n "$(git status --porcelain)" ]; then
  echo "package.sh: the checkout has changes; commit them first (or KLAV_ALLOW_DIRTY=1 for a trial run)" >&2
  exit 1
fi

# The paths of this machine (home, checkout) out of the WASM's panic
# messages: the same bytes from any checkout. Only klav-wasm's build sees it.
# rustc applies the last prefix that matches, and the checkout and Cargo's
# home are usually inside the home folder: the most specific goes last, or
# a checkout under $HOME would come out as /home/<its path>.
remap="--remap-path-prefix=$HOME=/home --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$root=/klav"
rustflags="${RUSTFLAGS:-}${RUSTFLAGS:+ }$remap"

rm -rf "$out"
mkdir -p "$out/build"

(cd "$app" && RUSTFLAGS="$rustflags" node scripts/build-wasm.mjs)
(cd "$app" && KLAV_STORE=1 KLAV_DIST="$out/build" node scripts/build.mjs --zip)
# The same code with the development `key`, so its ID is fixed: what a
# release offers to load unpacked until the store has Klav. Same WASM.
(cd "$app" && KLAV_DIST="$out/build-dev" node scripts/build.mjs --zip)

version=$(node -p 'require(process.argv[1]).version' "$out/build/chromium/manifest.json")

# What a store would reject, or what would break the native host.
node - "$out/build" "$out/build-dev" "$app/static/dev-key.txt" <<'EOF'
const { readFileSync } = require("node:fs");
const [dir, devDir, devKeyFile] = process.argv.slice(2);
const chromium = JSON.parse(readFileSync(`${dir}/chromium/manifest.json`, "utf8"));
const firefox = JSON.parse(readFileSync(`${dir}/firefox/manifest.json`, "utf8"));
const dev = JSON.parse(readFileSync(`${devDir}/chromium/manifest.json`, "utf8"));
const fail = (why) => { console.error(`package.sh: ${why}`); process.exit(1); };
if ("key" in chromium) fail("the Chromium package still has the development `key`");
if (dev.key !== readFileSync(devKeyFile, "utf8").trim()) fail("the keyed Chromium package doesn't carry the development `key`");
if (dev.version !== chromium.version) fail("the keyed Chromium package has another version");
if (chromium.version !== firefox.version) fail("the two packages have different versions");
if (firefox.browser_specific_settings?.gecko?.id !== "klav@klav.dev") fail("the Firefox ID is not klav@klav.dev");
EOF

(cd "$app" && node scripts/lint-firefox.mjs "$out/build/firefox")

cp "$out/build/klav-chromium.zip" "$out/klav-$version-chromium.zip"
cp "$out/build/klav-firefox.zip" "$out/klav-$version-firefox.zip"
cp "$out/build-dev/klav-chromium.zip" "$out/klav-$version-chromium-dev.zip"
files="klav-$version-chromium.zip klav-$version-chromium-dev.zip klav-$version-firefox.zip"
if [ "$git" = 1 ]; then
  commit=$(git -C "$root" rev-parse --short HEAD)
else
  commit="source archive"
fi

# rust-toolchain.toml pins the release, but an override (`rustup override`,
# RUSTUP_TOOLCHAIN) can change it: write down which one built this, so a
# reviewer can build the same bytes.
{
  echo "klav $version ($commit)"
  rustc --version
  cargo --version
  wasm-bindgen --version
  echo "node $(node --version)"
  echo "pnpm $(pnpm --version 2>/dev/null || echo '?')"
  echo "RUSTFLAGS for klav-wasm: $remap" | sed "s|$root|<checkout>|; s|${CARGO_HOME:-$HOME/.cargo}|<cargo home>|; s|$HOME|<home>|"
} > "$out/BUILD-INFO.txt"

# AMO's reviewers rebuild from this archive, and the self-distributed upload
# has no notes field: the build steps and the versions go at its root.
# (`--add-file` needs git 2.35 or later.)
if [ "$git" = 1 ]; then
  git archive --format=zip --prefix="klav-$version-source/" \
    --add-file="$app/BUILDING.md" --add-file="$out/BUILD-INFO.txt" \
    -o "$out/klav-$version-source.zip" HEAD
  files="$files klav-$version-source.zip"
fi

cd "$out"
# shellcheck disable=SC2086 # plain file names
shasum -a 256 $files > SHA256SUMS
echo "Klav $version ($commit):"
sed 's/^/  /' SHA256SUMS
echo "in $out"
