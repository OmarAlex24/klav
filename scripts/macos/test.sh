#!/usr/bin/env bash
# Builds and tests the Mac app (ADR 0027): the KlavMac scheme of
# apps/ios/project.yml. The tests run the app on the sample vault, with a
# temporary home and KLAV_HOME made here: no klavd and no real home are
# touched.
#
#   scripts/macos/test.sh [build|test]     (default: test)
#
# Environment:
#   KLAV_MAC_DERIVED     DerivedData directory (default target/xcode/mac-derived)
#   KLAV_SPM_CACHE       Swift package cache (default target/xcode/spm-cache)
#   KLAV_IOS_SKIP_FFI=1  reuse target/ios/KlavFFI.xcframework as is
#   KLAV_MAC_TEST_TMPDIR where the installer tests make their temporary
#                         homes (default: the system's temporary directory)
# The first two can also go in the local build config (scripts/dev/local-config.sh).
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
action="${1:-test}"
# shellcheck source=scripts/dev/local-config.sh
. "$root/scripts/dev/local-config.sh"
klav_dev_config_load
derived="${KLAV_MAC_DERIVED:-$(klav_dev_default_dir "$root" mac-derived)}"
# Swift packages (Sparkle, apps/ios/Package.resolved) are cached there too,
# not in ~/Library/Caches.
spm_cache="${KLAV_SPM_CACHE:-$(klav_dev_default_dir "$root" spm-cache)}"
klav_dev_config_print derived spm_cache

command -v xcodegen >/dev/null || { echo "xcodegen is missing: brew install xcodegen" >&2; exit 1; }

if [[ "${KLAV_IOS_SKIP_FFI:-0}" != 1 || ! -d "$root/target/ios/KlavFFI.xcframework/macos-arm64" ]]; then
  "$root/scripts/ios/build-xcframework.sh"
fi

cd "$root/apps/ios"
xcodegen generate --quiet

if [[ -n "${KLAV_MAC_TEST_TMPDIR:-}" ]]; then
  mkdir -p "$KLAV_MAC_TEST_TMPDIR"
  export TEST_RUNNER_KLAV_TEST_TMPDIR="$KLAV_MAC_TEST_TMPDIR"
fi

case "$action" in
  build) xcode_action=(build) ;;
  test) xcode_action=(build test) ;;
  *) echo "usage: $0 [build|test]" >&2; exit 2 ;;
esac

# The host app runs on the sample vault, and at launch it runs its own
# klav (the skill, the browsers' hosts). It gets a fresh home, KLAV_HOME and
# link folder, outside the home folder and deleted afterwards, so nothing
# lands in the person's (review of PR #230). Without them the sample
# refuses to run klav at all (SampleSafety), which is what protects a run
# started from Xcode. TEST_RUNNER_* reaches the host's environment; a
# scheme variable could not make a new folder per run nor delete it.
if [[ "$action" == test ]]; then
  test_home="$(mktemp -d "${KLAV_MAC_TEST_TMPDIR:-${TMPDIR:-/tmp}}/kmh.XXXXXX")"
  trap 'rm -rf "$test_home"' EXIT
  mkdir -p "$test_home/user" "$test_home/home" "$test_home/bin"
  export TEST_RUNNER_KLAV_BROWSER_HOME="$test_home/user"
  export TEST_RUNNER_KLAV_HOME="$test_home/home"
  export TEST_RUNNER_KLAV_CLI_LINK_DIR="$test_home/bin"
fi

xcodebuild \
  -project Klav.xcodeproj \
  -scheme KlavMac \
  -configuration Debug \
  -destination "platform=macOS,arch=arm64" \
  -derivedDataPath "$derived" \
  -packageCachePath "$spm_cache" \
  -onlyUsePackageVersionsFromResolvedFile \
  -quiet \
  "${xcode_action[@]}"
