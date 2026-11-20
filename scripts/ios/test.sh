#!/usr/bin/env bash
# Builds and tests the iOS app on a simulator (ADR 0018 §7). Local gate for
# the iOS layers; CI (Linux) only checks that the Swift bindings generate.
#
#   scripts/ios/test.sh [build|test]     (default: test)
#
# Environment:
#   KLAV_IOS_DERIVED     DerivedData directory (default target/xcode/ios-derived)
#   KLAV_SPM_CACHE       Swift package cache (default target/xcode/spm-cache)
#   KLAV_IOS_SIMULATOR   simulator UDID or name (default "iPhone 17")
#   KLAV_IOS_SKIP_FFI=1  reuse target/ios/KlavFFI.xcframework as is
# The first two can also go in the local build config (scripts/dev/local-config.sh).
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
action="${1:-test}"
# shellcheck source=scripts/dev/local-config.sh
. "$root/scripts/dev/local-config.sh"
klav_dev_config_load
derived="${KLAV_IOS_DERIVED:-$(klav_dev_default_dir "$root" ios-derived)}"
# Swift packages (Sparkle, apps/ios/Package.resolved) are cached there too,
# not in ~/Library/Caches.
spm_cache="${KLAV_SPM_CACHE:-$(klav_dev_default_dir "$root" spm-cache)}"
simulator="${KLAV_IOS_SIMULATOR:-iPhone 17}"
klav_dev_config_print derived spm_cache

command -v xcodegen >/dev/null || { echo "xcodegen is missing: brew install xcodegen" >&2; exit 1; }

if [[ "${KLAV_IOS_SKIP_FFI:-0}" != 1 || ! -d "$root/target/ios/KlavFFI.xcframework" ]]; then
  "$root/scripts/ios/build-xcframework.sh"
fi

cd "$root/apps/ios"
xcodegen generate --quiet

if [[ "$simulator" =~ ^[0-9A-Fa-f-]{36}$ ]]; then
  destination="platform=iOS Simulator,id=$simulator"
else
  destination="platform=iOS Simulator,name=$simulator"
fi

case "$action" in
  build) xcode_action=(build) ;;
  test) xcode_action=(build test) ;;
  *) echo "usage: $0 [build|test]" >&2; exit 2 ;;
esac

if [[ "$action" == test ]]; then
  # The VoiceOver tests read accessibility labels, which come back empty while
  # the simulator has app accessibility off (agent-device sessions can leave
  # it that way). simctl takes the same name or UDID as -destination; booting
  # an already booted simulator fails, so that error is ignored.
  xcrun simctl boot "$simulator" 2>/dev/null || true
  xcrun simctl spawn "$simulator" defaults write com.apple.Accessibility \
    ApplicationAccessibilityEnabled -bool true
fi

# No test may reach the real server by forgetting one (ADR 0028 §2). The
# scheme sets it too; xcodebuild passes TEST_RUNNER_* to the test host.
export TEST_RUNNER_KLAV_NO_DEFAULT_SERVER=1

xcodebuild \
  -project Klav.xcodeproj \
  -scheme Klav \
  -configuration Debug \
  -destination "$destination" \
  -derivedDataPath "$derived" \
  -packageCachePath "$spm_cache" \
  -onlyUsePackageVersionsFromResolvedFile \
  -quiet \
  "${xcode_action[@]}"

echo "app: $derived/Build/Products/Debug-iphonesimulator/Klav.app"
