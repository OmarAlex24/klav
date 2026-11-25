#!/usr/bin/env bash
# Builds the Mac app for distribution (ADR 0027 §4, §5): Klav.app with its
# helpers, signed with the Developer ID from the inside out, notarized and
# stapled, inside a DMG that is signed, notarized and stapled too.
#
#   scripts/macos/build-app.sh adhoc     build, sign ad hoc, make the DMG
#                                        (no Apple account; Gatekeeper rejects it)
#   scripts/macos/build-app.sh release   Developer ID, notarization, stapling
#
# Out: $CARGO_TARGET_DIR/macos/dist (default target/macos/dist): Klav.app
# and Klav-<version>.dmg.
#
# Environment:
#   KLAV_MAC_IDENTITY     signing identity (default: the "Developer ID
#                          Application" of team SZ3F58F8LX in the keychain)
#   KLAV_NOTARY_KEY       App Store Connect API key, a path; only its path is
#                          ever passed, never its contents
#   KLAV_NOTARY_KEY_ID    its key ID
#   KLAV_NOTARY_ISSUER    its issuer ID (the three have no default: release stops without them)
#   KLAV_MAC_RELEASE_DERIVED  DerivedData (default target/xcode/mac-release-derived)
#   KLAV_SPM_CACHE        Swift package cache (default target/xcode/spm-cache)
#   (all of these can also go in the local build config, scripts/dev/local-config.sh)
#   KLAV_IOS_SKIP_FFI=1   reuse target/ios/KlavFFI.xcframework (a release build)
#   KLAV_SKIP_CARGO=1     reuse the release helpers already built
#   KLAV_SPARKLE_PUBLIC_KEY  Sparkle's public EdDSA key, instead of the one in
#                          Config/Base.xcconfig (the update test uses a test key)
#   KLAV_ALLOW_NO_UPDATES=1  release without a Sparkle key (the app never updates)
#   KLAV_SPARKLE_FEED_URL  the appcast, instead of https://klav.dev/releases/mac/appcast.xml
#                          (the update test, docs/probar-mac.md §1; never for a real release)
#   KLAV_MAC_VERSION, KLAV_MAC_BUILD  CFBundleShortVersionString and
#                          CFBundleVersion, instead of project.yml's
#
# Cargo runs as the environment says: on the shared Mac, call it as
#   nice -n 19 env CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=... scripts/macos/build-app.sh release
set -euo pipefail

team=SZ3F58F8LX
mode="${1:-}"
case "$mode" in
  adhoc | release) ;;
  *) echo "usage: $0 adhoc|release" >&2; exit 2 ;;
esac

root="$(cd "$(dirname "$0")/../.." && pwd)"
target="${CARGO_TARGET_DIR:-$root/target}"
helpers_src="$target/release"
# shellcheck source=scripts/dev/local-config.sh
. "$root/scripts/dev/local-config.sh"
klav_dev_config_load
derived="${KLAV_MAC_RELEASE_DERIVED:-$(klav_dev_default_dir "$root" mac-release-derived)}"
# Swift packages (Sparkle, apps/ios/Package.resolved) are cached there too,
# not in ~/Library/Caches.
spm_cache="${KLAV_SPM_CACHE:-$(klav_dev_default_dir "$root" spm-cache)}"
if [[ "$mode" == release ]]; then
  klav_dev_config_require release KLAV_NOTARY_KEY KLAV_NOTARY_KEY_ID KLAV_NOTARY_ISSUER
  notary_key="$KLAV_NOTARY_KEY"
  notary_key_id="$KLAV_NOTARY_KEY_ID"
  notary_issuer="$KLAV_NOTARY_ISSUER"
fi
klav_dev_config_print derived spm_cache notary_key notary_key_id notary_issuer
dist="$target/macos/dist"
helpers=(klav klavd klav-native-host)
head=""

# Budget (ADR 0027 §5), in bytes.
max_dmg=$((25 * 1000 * 1000))
max_app=$((60 * 1000 * 1000))

if [[ "$mode" == release ]]; then
  # A release names its commit (docs/macos.md §3): HEAD, with nothing
  # uncommitted that the helpers could carry without saying so.
  head="$(git -C "$root" rev-parse HEAD)"
  [[ -z "$(git -C "$root" status --porcelain)" ]] || { echo "release from a clean checkout" >&2; exit 1; }
  identity="${KLAV_MAC_IDENTITY:-$(security find-identity -p codesigning -v \
    | sed -n "s/.*\"\(Developer ID Application: .*($team)\)\"$/\1/p" | head -1)}"
  if [[ -z "$identity" ]]; then
    echo "no \"Developer ID Application\" identity of team $team in the keychain." >&2
    echo "Create it in developer.apple.com › Certificates (Developer ID Application)" >&2
    echo "and import it, or run '$0 adhoc'." >&2
    exit 1
  fi
  [[ -r "$notary_key" ]] || { echo "the notarization key is not readable: $notary_key" >&2; exit 1; }
  timestamp=(--timestamp)
else
  identity=-
  timestamp=()
fi

step() { printf '\n== %s\n' "$*"; }
size() { du -sk "$1" | awk '{print $1 * 1024}'; }
mb() { awk -v b="$1" 'BEGIN { printf "%.1f MB", b / 1000000 }'; }

work="$dist/.work"
rm -rf "$work"
mkdir -p "$work"
trap 'rm -rf "$work"' EXIT

# 1. The helpers, release, optimized for size (`opt-level="s"`, keeping
# Argon2id/BLAKE2 at 3), without symbols and with link-time optimization
# across crates, so Klav.app and the DMG stay within ADR 0027 §5's budget.
if [[ "${KLAV_SKIP_CARGO:-0}" != 1 ]]; then
  step "helpers (cargo build --release)"
  cargo build --release --locked -p klav-cli -p klav-daemon \
    --bin klav --bin klavd --bin klav-native-host \
    --config 'profile.release.opt-level="s"' \
    --config 'profile.release.package.argon2.opt-level=3' \
    --config 'profile.release.package.blake2.opt-level=3' \
    --config 'profile.release.strip="symbols"' \
    --config 'profile.release.lto="fat"' \
    --config 'profile.release.codegen-units=1'
fi
for name in "${helpers[@]}"; do
  [[ -x "$helpers_src/$name" ]] || { echo "missing $helpers_src/$name" >&2; exit 1; }
done
# The app tells its klav and klavd from older ones by the commit they were
# built from (docs/macos.md §3): a release's helpers must name HEAD. They
# take it from git, or from KLAV_BUILD_COMMIT and KLAV_BUILD_COMMIT_TIME;
# helpers left from another commit (KLAV_SKIP_CARGO=1) are refused.
for name in klav klavd; do
  said="$("$helpers_src/$name" --version)"
  echo "$said"
  if [[ "$mode" == release && "$said" != "$name "*" (${head:0:12} "* ]]; then
    echo "$name says '$said', not HEAD ${head:0:12}: cargo clean -p klav-daemon -p klav-cli" >&2
    exit 1
  fi
done

# 2. KlavFFI (release) and the app.
if [[ "${KLAV_IOS_SKIP_FFI:-0}" != 1 ]]; then
  step "KlavFFI.xcframework (release)"
  "$root/scripts/ios/build-xcframework.sh" --release
fi

step "Klav.app (Release)"
command -v xcodegen >/dev/null || { echo "xcodegen is missing: brew install xcodegen" >&2; exit 1; }
(cd "$root/apps/ios" && xcodegen generate --quiet)
overrides=()
[[ -n "${KLAV_SPARKLE_PUBLIC_KEY:-}" ]] && overrides+=("KLAV_SPARKLE_PUBLIC_KEY=$KLAV_SPARKLE_PUBLIC_KEY")
[[ -n "${KLAV_SPARKLE_FEED_URL:-}" ]] && overrides+=("KLAV_SPARKLE_FEED_URL=$KLAV_SPARKLE_FEED_URL")
[[ -n "${KLAV_MAC_VERSION:-}" ]] && overrides+=("MARKETING_VERSION=$KLAV_MAC_VERSION")
[[ -n "${KLAV_MAC_BUILD:-}" ]] && overrides+=("CURRENT_PROJECT_VERSION=$KLAV_MAC_BUILD")
KLAV_HELPERS_SOURCE="$helpers_src" KLAV_SKIP_HELPER_SIGNING=1 xcodebuild \
  -project "$root/apps/ios/Klav.xcodeproj" \
  -scheme KlavMac \
  -configuration Release \
  -destination "platform=macOS,arch=arm64" \
  -derivedDataPath "$derived" \
  -packageCachePath "$spm_cache" \
  -onlyUsePackageVersionsFromResolvedFile \
  -quiet \
  build ${overrides[@]+"${overrides[@]}"}

app="$dist/Klav.app"
rm -rf "$app"
ditto "$derived/Build/Products/Release/Klav.app" "$app"
# The app's binary without its symbol table, like the helpers (its dSYM stays
# in DerivedData): about 8 MB of the budget.
strip -x "$app/Contents/MacOS/Klav"
version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Info.plist")"
sparkle_key="$(/usr/libexec/PlistBuddy -c 'Print :SUPublicEDKey' "$app/Contents/Info.plist" 2>/dev/null || true)"
if [[ -z "$sparkle_key" ]]; then
  if [[ "$mode" == release && "${KLAV_ALLOW_NO_UPDATES:-0}" != 1 ]]; then
    echo "no Sparkle key: set KLAV_SPARKLE_PUBLIC_KEY in apps/ios/Config/Base.xcconfig" >&2
    echo "(docs/macos.md §6), or KLAV_ALLOW_NO_UPDATES=1 for an app that never updates." >&2
    exit 1
  fi
  echo "warning: no Sparkle key; this Klav.app does not look for updates"
fi

# 3. Signing, from the inside out: Sparkle's helpers and framework (as its
# documentation says), each helper with its identifier, then the app
# (which seals all of them and the LaunchAgent's plist).
step "signing ($([[ "$mode" == release ]] && echo "$identity" || echo ad hoc))"
sparkle="$app/Contents/Frameworks/Sparkle.framework"
if [[ -d "$sparkle" ]]; then
  for part in Versions/B/XPCServices/Installer.xpc Versions/B/Autoupdate Versions/B/Updater.app; do
    codesign --force ${timestamp[@]+"${timestamp[@]}"} --options runtime --sign "$identity" "$sparkle/$part"
  done
  codesign --force ${timestamp[@]+"${timestamp[@]}"} --options runtime --preserve-metadata=entitlements \
    --sign "$identity" "$sparkle/Versions/B/XPCServices/Downloader.xpc"
  codesign --force ${timestamp[@]+"${timestamp[@]}"} --options runtime --sign "$identity" "$sparkle"
fi
# klavd is signed as its bundle, Helpers/klavd.app (ADR 0027, note of
# 2026-11-05); Helpers/klavd is a link to its binary, sealed by the app.
for name in klav klav-native-host klavd.app; do
  codesign --force ${timestamp[@]+"${timestamp[@]}"} --options runtime --identifier "dev.klav.${name%.app}" \
    --sign "$identity" "$app/Contents/Helpers/$name"
done
[[ "$(readlink "$app/Contents/Helpers/klavd")" == klavd.app/Contents/MacOS/klavd ]] || {
  echo "Helpers/klavd is not the link to klavd.app (scripts/macos/embed-helpers.sh)" >&2
  exit 1
}
codesign --force ${timestamp[@]+"${timestamp[@]}"} --options runtime \
  --entitlements "$root/apps/ios/Mac/KlavMac.entitlements" \
  --sign "$identity" "$app"
codesign --verify --deep --strict --verbose=1 "$app"

if [[ "$mode" == release ]]; then
  # What the app checks at launch (T120): every helper is the team's, with
  # its own identifier. klavd through its bundle: through the link, a static
  # check of the binary fails.
  for name in klav klav-native-host klavd.app; do
    codesign --verify --strict \
      -R="identifier \"dev.klav.${name%.app}\" and anchor apple generic and certificate leaf[subject.OU] = \"$team\"" \
      "$app/Contents/Helpers/$name"
  done
  echo "helpers: signed by $team"
  # What keeps a program of the same user from attaching a debugger to the
  # app or loading a library into it, and so from using its held connection
  # to klavd (ADR 0041 §1.2, N10): on every Developer ID build.
  "$root/scripts/macos/check-signature.sh" "$app" \
    "$app/Contents/Helpers/klav" "$app/Contents/Helpers/klav-native-host" "$app/Contents/Helpers/klavd.app"
fi

app_bytes=$(size "$app")
echo "Klav.app: $(mb "$app_bytes") (budget $(mb $max_app))"
((app_bytes <= max_app)) || { echo "Klav.app is over budget" >&2; exit 1; }

# notarize <file>: submits it and waits; prints Apple's log if it is not
# accepted. The key goes by path only.
notarize() {
  local file="$1" result status id
  result="$(xcrun notarytool submit "$file" \
    --key "$notary_key" --key-id "$notary_key_id" --issuer "$notary_issuer" \
    --wait --output-format json)"
  status="$(plutil -extract status raw -o - - <<<"$result" 2>/dev/null || true)"
  id="$(plutil -extract id raw -o - - <<<"$result" 2>/dev/null || true)"
  echo "notarization $id: $status"
  if [[ "$status" != Accepted ]]; then
    [[ -n "$id" ]] && xcrun notarytool log "$id" \
      --key "$notary_key" --key-id "$notary_key_id" --issuer "$notary_issuer" >&2 || true
    return 1
  fi
}

# 4. The app notarized and stapled, so it opens offline once copied.
if [[ "$mode" == release ]]; then
  step "notarizing Klav.app"
  ditto -c -k --keepParent "$app" "$work/Klav.zip"
  notarize "$work/Klav.zip"
  xcrun stapler staple "$app"
  xcrun stapler validate "$app"
fi

# 5. The DMG: the app and an alias to /Applications.
step "Klav-$version.dmg"
dmg="$dist/Klav-$version.dmg"
rm -f "$dmg"
mkdir -p "$work/dmg"
ditto "$app" "$work/dmg/Klav.app"
ln -s /Applications "$work/dmg/Applications"
hdiutil create -quiet -volname Klav -srcfolder "$work/dmg" -fs APFS -format ULFO "$dmg"
codesign --force ${timestamp[@]+"${timestamp[@]}"} --sign "$identity" "$dmg"

if [[ "$mode" == release ]]; then
  step "notarizing the DMG"
  notarize "$dmg"
  xcrun stapler staple "$dmg"
  xcrun stapler validate "$dmg"
  spctl --assess --type open --context context:primary-signature --verbose=2 "$dmg"
  spctl --assess --type execute --verbose=2 "$app"
fi

# The DMG by its file size (ADR 0027 §5), not by du's allocated blocks,
# which counted 26.0 MB for a 24.99 MB DMG.
dmg_bytes=$(stat -f %z "$dmg")
echo
echo "Klav.app       $(mb "$app_bytes")   $app"
echo "Klav-$version.dmg  $(mb "$dmg_bytes")   $dmg (budget $(mb $max_dmg))"
((dmg_bytes <= max_dmg)) || { echo "the DMG is over budget" >&2; exit 1; }
