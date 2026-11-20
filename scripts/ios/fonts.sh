#!/usr/bin/env bash
# Copies the browser extension's fonts into the iOS app as TrueType (iOS
# registers .ttf from UIAppFonts; the extension ships .woff2). The glyphs
# are the same files, only unpacked: Geist (variable, 100–900), Geist Mono
# 400 and Departure Mono 400, with their OFL licenses.
#
#   scripts/ios/fonts.sh
#
# Needs fontTools with Brotli. It makes a venv next to the real target/
# (never in /tmp) the first time.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
src="$root/apps/extension/static/fonts"
out="$root/apps/ios/Shared/Fonts"
venv="$(cd "$root/target" && pwd -P)/fonttools-venv"

if [[ ! -x "$venv/bin/fonttools" ]]; then
  python3 -m venv "$venv"
  "$venv/bin/pip" install --quiet fonttools brotli
fi

mkdir -p "$out"
for name in geist geist-mono-400 departure-mono-400; do
  "$venv/bin/fonttools" ttLib.woff2 decompress -o "$out/$name.ttf" "$src/$name.woff2"
done
cp "$src/LICENSE-geist.txt" "$src/LICENSE-departure-mono.txt" "$out/"
ls "$out"
