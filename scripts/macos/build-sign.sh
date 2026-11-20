#!/usr/bin/env bash
# Builds `klav` and `klavd` in release mode, signs them with the
# Developer ID certificate (hardened runtime, secure timestamp) and packs
# them in a zip ready for `notarize.sh`.
#
#   scripts/macos/build-sign.sh            # native architecture
#   KLAV_TARGET=x86_64-apple-darwin scripts/macos/build-sign.sh
#
# Environment:
#   KLAV_SIGN_IDENTITY  codesign identity (default: Developer ID Application of KLAV_SIGN_TEAM)
#   KLAV_SIGN_TEAM      Apple Team ID used to look up the certificate (default: SZ3F58F8LX)
#   KLAV_TARGET         Rust target triple (default: the host)
#   KLAV_DIST           output directory (default: dist/macos)
#
# No secret is read or stored here: the private key stays in the login
# keychain. If codesign asks for the keychain password, the script stops
# after a timeout instead of waiting forever.
set -euo pipefail

TEAM="${KLAV_SIGN_TEAM:-SZ3F58F8LX}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DIST="${KLAV_DIST:-$ROOT/dist/macos}"
TARGET="${KLAV_TARGET:-}"
SIGN_TIMEOUT=120

[[ "$(uname -s)" == "Darwin" ]] || { echo "build-sign.sh: macOS only" >&2; exit 1; }

# `timeout` is not part of macOS; perl's alarm is.
with_timeout() {
  local seconds="$1"; shift
  perl -e 'alarm shift; exec @ARGV or die "exec: $!"' "$seconds" "$@"
}

IDENTITY="${KLAV_SIGN_IDENTITY:-$(security find-identity -v -p codesigning \
  | sed -n "s/.*\"\(Developer ID Application: .*($TEAM)\)\"$/\1/p" | head -1)}"

if [[ -z "$IDENTITY" ]] || ! security find-identity -v -p codesigning | grep -Fq "\"$IDENTITY\""; then
  echo "build-sign.sh: signing identity not found in the keychain (team $TEAM): ${IDENTITY:-none}" >&2
  echo "Install the Developer ID Application certificate (Xcode > Settings > Accounts," >&2
  echo "or developer.apple.com > Certificates) and run again." >&2
  exit 1
fi

cd "$ROOT"
cargo_args=(build --release --locked -p klav-cli -p klav-daemon)
out_dir="$ROOT/target/release"
if [[ -n "$TARGET" ]]; then
  cargo_args+=(--target "$TARGET")
  out_dir="$ROOT/target/$TARGET/release"
fi
cargo "${cargo_args[@]}"

arch="$(lipo -archs "$out_dir/klav")"
mkdir -p "$DIST"
for bin in klav klavd; do
  cp "$out_dir/$bin" "$DIST/$bin"
  if ! with_timeout "$SIGN_TIMEOUT" codesign --force --options runtime --timestamp \
      --identifier "dev.klav.$bin" --sign "$IDENTITY" "$DIST/$bin"; then
    echo "build-sign.sh: codesign failed or timed out for $bin" >&2
    echo "(if a keychain dialog appeared, allow codesign to use the key and run again)" >&2
    exit 1
  fi
  codesign --verify --strict --verbose=2 "$DIST/$bin"
done

zip="$DIST/klav-macos-${arch// /-}.zip"
rm -f "$zip"
(cd "$DIST" && ditto -c -k --sequesterRsrc klav klavd "$zip" 2>/dev/null) || \
  (cd "$DIST" && zip -q "$zip" klav klavd)
echo "Signed: $DIST/klav, $DIST/klavd"
echo "Archive for notarization: $zip"
