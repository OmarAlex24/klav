#!/usr/bin/env bash
# Xcode build phase of KlavMac (ADR 0027 §4): puts klav, klavd and
# klav-native-host in Klav.app/Contents/Helpers, and the LaunchAgents of
# klavd and of the credential proxy in Contents/Library/LaunchAgents,
# before Xcode signs the app. The proxy has no helper of its own: its
# LaunchAgent runs Helpers/klav as `klav-proxy` (ADR 0036, layer 11).
#
# klavd goes inside its own bundle, Helpers/klavd.app (ADR 0027, note of
# 2026-11-05): macOS names the process asking for Touch ID after the bundle
# that holds its executable, so the dialog says "Klav", with the app's icon.
# Helpers/klavd stays, as a link to klavd.app/Contents/MacOS/klavd, for
# whatever runs it by that path: klav and klav-native-host start the klavd
# next to them, the app asks it for --version, and a LaunchAgent loaded by
# an older Klav.app still points there.
#
# The helpers come from KLAV_HELPERS_SOURCE (scripts/macos/build-app.sh
# points it at the release build); by default, from the debug build of
# CARGO_TARGET_DIR or target/. Without them the app still builds and says
# so in «Set up this Mac». Debug builds sign them ad hoc; build-app.sh signs
# everything again with the Developer ID, from the inside out.
set -euo pipefail

: "${SRCROOT:?run from Xcode}"
: "${TARGET_BUILD_DIR:?run from Xcode}"
: "${WRAPPER_NAME:?run from Xcode}"

root="$(cd "$SRCROOT/../.." && pwd)"
app="$TARGET_BUILD_DIR/$WRAPPER_NAME"
source_dir="${KLAV_HELPERS_SOURCE:-${CARGO_TARGET_DIR:-$root/target}/debug}"
helpers=(klav klavd klav-native-host)

mkdir -p "$app/Contents/Library/LaunchAgents"
cp -f "$SRCROOT/Mac/LaunchAgents/dev.klav.klavd.plist" "$app/Contents/Library/LaunchAgents/"
cp -f "$SRCROOT/Mac/LaunchAgents/dev.klav.proxy.plist" "$app/Contents/Library/LaunchAgents/"

missing=()
for name in "${helpers[@]}"; do
  [[ -x "$source_dir/$name" ]] || missing+=("$name")
done
if ((${#missing[@]})); then
  echo "warning: no ${missing[*]} in $source_dir: Klav.app is built without its helpers (cargo build -p klav-cli -p klav-daemon)"
  rm -rf "$app/Contents/Helpers"
  exit 0
fi

sign() { # <path> <identifier>
  if [[ "${KLAV_SKIP_HELPER_SIGNING:-0}" != 1 ]]; then
    codesign --force --sign "${EXPANDED_CODE_SIGN_IDENTITY:--}" --options runtime --identifier "$2" "$1"
  fi
}

mkdir -p "$app/Contents/Helpers"
for name in klav klav-native-host; do
  cp -f "$source_dir/$name" "$app/Contents/Helpers/$name"
  sign "$app/Contents/Helpers/$name" "dev.klav.$name"
done

# klavd.app: the binary, its Info.plist with the app's versions, and the
# app's icon (actool already wrote it into Resources).
daemon_app="$app/Contents/Helpers/klavd.app"
rm -rf "$daemon_app" "$app/Contents/Helpers/klavd"
mkdir -p "$daemon_app/Contents/MacOS" "$daemon_app/Contents/Resources"
cp -f "$source_dir/klavd" "$daemon_app/Contents/MacOS/klavd"
info="$daemon_app/Contents/Info.plist"
cp -f "$root/scripts/macos/klavd-Info.plist" "$info"
plutil -replace CFBundleShortVersionString -string "${MARKETING_VERSION:-0}" "$info"
plutil -replace CFBundleVersion -string "${CURRENT_PROJECT_VERSION:-0}" "$info"
plutil -replace LSMinimumSystemVersion -string "${MACOSX_DEPLOYMENT_TARGET:-15.0}" "$info"
if [[ -f "$app/Contents/Resources/AppIcon.icns" ]]; then
  cp -f "$app/Contents/Resources/AppIcon.icns" "$daemon_app/Contents/Resources/AppIcon.icns"
else
  echo "warning: no AppIcon.icns in $app/Contents/Resources: klavd.app has no icon"
  plutil -remove CFBundleIconFile "$info"
fi
sign "$daemon_app" dev.klav.klavd
# Relative, so it survives copying the app (ditto, the DMG, Sparkle).
ln -s klavd.app/Contents/MacOS/klavd "$app/Contents/Helpers/klavd"
