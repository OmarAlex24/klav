#!/usr/bin/env bash
# Release build of the iOS app for TestFlight (ADR 0018 §7).
#
#   scripts/ios/archive.sh check    compile Release for devices, unsigned
#                                   (no Apple account needed)
#   scripts/ios/archive.sh export   archive and export an .ipa to
#                                   target/ios/export (upload it with
#                                   Transporter or Xcode's Organizer)
#   scripts/ios/archive.sh upload   archive and upload to App Store Connect
#
# `export` and `upload` sign with the team in apps/ios/Config/Local.xcconfig
# (copy Local.xcconfig.example) and need that team signed in to Xcode
# (Settings › Accounts); Xcode creates the profiles
# (-allowProvisioningUpdates).
#
# Environment:
#   KLAV_IOS_DERIVED   DerivedData directory (default target/xcode/ios-derived)
#   KLAV_SPM_CACHE     Swift package cache (default target/xcode/spm-cache)
#   KLAV_IOS_SKIP_FFI=1  reuse target/ios/KlavFFI.xcframework as is (it must
#                       be a release build with the device slice)
# The first two can also go in the local build config (scripts/dev/local-config.sh).
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
action="${1:-}"
# shellcheck source=scripts/dev/local-config.sh
. "$root/scripts/dev/local-config.sh"
klav_dev_config_load
derived="${KLAV_IOS_DERIVED:-$(klav_dev_default_dir "$root" ios-derived)}"
# Swift packages (Sparkle, apps/ios/Package.resolved) are cached there too,
# not in ~/Library/Caches.
spm_cache="${KLAV_SPM_CACHE:-$(klav_dev_default_dir "$root" spm-cache)}"
out="$root/target/ios"
klav_dev_config_print derived spm_cache

case "$action" in
  check | export | upload) ;;
  *) echo "usage: $0 check|export|upload" >&2; exit 2 ;;
esac

command -v xcodegen >/dev/null || { echo "xcodegen is missing: brew install xcodegen" >&2; exit 1; }

if [[ "$action" != check ]]; then
  local_config="$root/apps/ios/Config/Local.xcconfig"
  if ! grep -Eq '^[[:space:]]*DEVELOPMENT_TEAM[[:space:]]*=[[:space:]]*[A-Z0-9]{10}' "$local_config" 2>/dev/null; then
    echo "set DEVELOPMENT_TEAM in apps/ios/Config/Local.xcconfig (see Local.xcconfig.example)" >&2
    exit 1
  fi
fi

if [[ "${KLAV_IOS_SKIP_FFI:-0}" != 1 || ! -d "$out/KlavFFI.xcframework" ]]; then
  KLAV_IOS_TARGETS="aarch64-apple-ios" "$root/scripts/ios/build-xcframework.sh" --release
fi

cd "$root/apps/ios"
xcodegen generate --quiet

if [[ "$action" == check ]]; then
  xcodebuild \
    -project Klav.xcodeproj \
    -scheme Klav \
    -configuration Release \
    -destination "generic/platform=iOS" \
    -derivedDataPath "$derived" \
    -packageCachePath "$spm_cache" \
    -onlyUsePackageVersionsFromResolvedFile \
    -quiet \
    CODE_SIGNING_ALLOWED=NO \
    build
  echo "app: $derived/Build/Products/Release-iphoneos/Klav.app (unsigned)"
  exit 0
fi

archive="$out/Klav.xcarchive"
rm -rf "$archive"
xcodebuild \
  -project Klav.xcodeproj \
  -scheme Klav \
  -configuration Release \
  -destination "generic/platform=iOS" \
  -derivedDataPath "$derived" \
  -packageCachePath "$spm_cache" \
  -onlyUsePackageVersionsFromResolvedFile \
  -archivePath "$archive" \
  -allowProvisioningUpdates \
  -quiet \
  archive

options="$(mktemp "$out/export-options.XXXXXX")"
trap 'rm -f "$options"' EXIT
destination="export"
[[ "$action" == upload ]] && destination=upload
sed "s/__DESTINATION__/$destination/" Config/ExportOptions.plist > "$options"

rm -rf "$out/export"
xcodebuild \
  -exportArchive \
  -archivePath "$archive" \
  -exportOptionsPlist "$options" \
  -exportPath "$out/export" \
  -allowProvisioningUpdates
echo "archive: $archive"
if [[ "$action" == export ]]; then
  echo "ipa: $out/export"
fi
