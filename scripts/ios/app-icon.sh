#!/usr/bin/env bash
# Regenerates the app icons in apps/ios/Klav/Assets.xcassets/AppIcon.appiconset
# (light, dark and tinted, 1024 × 1024) from the pixel key and the dither.
# Builds under target/ios.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="$root/target/ios/app-icon"
icons="$root/apps/ios/Klav/Assets.xcassets/AppIcon.appiconset"
mkdir -p "$out"
swiftc -O -parse-as-library \
  "$root/scripts/ios/app-icon.swift" \
  "$root/apps/ios/Shared/Dither.swift" \
  "$root/apps/ios/Shared/Glyph.swift" \
  -o "$out/app-icon"
"$out/app-icon" "$icons"
ls "$icons"
