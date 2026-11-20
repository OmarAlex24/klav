#!/usr/bin/env bash
# The Sparkle appcast of the Mac app (ADR 0027 §7, docs/macos.md §6). It
# writes target/macos/dist/appcast.xml and publishes nothing: uploading it
# and the DMG to https://klav.dev/releases/mac/ is Omar's step.
#
#   scripts/macos/appcast.sh make --key-file FILE [options] DMG
#       one <item> for DMG, its enclosure signed with the EdDSA key, then
#       the whole feed signed too (the app requires SURequireSignedFeed).
#       FILE '-' reads the key from standard input (never from argv), so
#       the production key can come straight from the vault:
#         klav item get "klav://Personal/Release/Sparkle EdDSA/api_key" --reveal \
#           | scripts/macos/appcast.sh make --key-file - target/macos/dist/Klav-0.2.0.dmg
#   scripts/macos/appcast.sh test-key FILE
#       a throwaway EdDSA key for tests, written to FILE (0600, never
#       overwritten); prints its public key. Never the production key.
#
# Options of make:
#   --app PATH        the Klav.app whose versions go in the item
#                     (default target/macos/dist/Klav.app)
#   --url-base URL    where the DMG will be (default https://klav.dev/releases/mac)
#   --notes-url URL   release notes, if any
#   --out FILE        (default target/macos/dist/appcast.xml)
#
# Sparkle's sign_update comes from the Swift package Xcode resolved, in the
# DerivedData of build-app.sh (KLAV_MAC_RELEASE_DERIVED), then of test.sh
# (KLAV_MAC_DERIVED), then their defaults in target/xcode/ (both can go in the
# local build config, scripts/dev/local-config.sh); KLAV_SPARKLE_BIN to point
# elsewhere.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
target="${CARGO_TARGET_DIR:-$root/target}"
dist="$target/macos/dist"
# shellcheck source=scripts/dev/local-config.sh
. "$root/scripts/dev/local-config.sh"
klav_dev_config_load
sparkle_dirs=("${KLAV_MAC_RELEASE_DERIVED:-}" "${KLAV_MAC_DERIVED:-}"
  "$(klav_dev_default_dir "$root" mac-release-derived)" "$(klav_dev_default_dir "$root" mac-derived)")
if [[ "${KLAV_DEV_CONFIG_PRINT:-0}" == 1 ]]; then printf 'sparkle_dir=%s\n' "${sparkle_dirs[@]}"; exit 0; fi

usage() { sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

sparkle_bin() {
  if [[ -n "${KLAV_SPARKLE_BIN:-}" ]]; then echo "$KLAV_SPARKLE_BIN"; return; fi
  local d
  for d in "${sparkle_dirs[@]}"; do
    [[ -n "$d" && -x "$d/SourcePackages/artifacts/sparkle/Sparkle/bin/sign_update" ]] \
      && { echo "$d/SourcePackages/artifacts/sparkle/Sparkle/bin"; return; }
  done
  echo "Sparkle's tools are missing: build the app first (scripts/macos/build-app.sh)" >&2
  exit 1
}

test_key() {
  local file="${1:?test-key FILE}"
  [[ ! -e "$file" ]] || { echo "$file already exists" >&2; exit 1; }
  local tools="$target/macos/tools"
  mkdir -p "$tools/module-cache"
  cat > "$tools/sparkle-test-key.swift" <<'SWIFT'
// A throwaway Sparkle EdDSA key (Ed25519, CryptoKit): the private seed in
// base64, as `generate_keys -x` exports it, and the public key on stdout.
import CryptoKit
import Foundation

let path = CommandLine.arguments[1]
let key = Curve25519.Signing.PrivateKey()
let text = Data(key.rawRepresentation.base64EncodedString().utf8)
guard FileManager.default.createFile(atPath: path, contents: text, attributes: [.posixPermissions: 0o600]) else {
    FileHandle.standardError.write(Data("cannot write \(path)\n".utf8))
    exit(1)
}
print(key.publicKey.rawRepresentation.base64EncodedString())
SWIFT
  swiftc -O -module-cache-path "$tools/module-cache" "$tools/sparkle-test-key.swift" -o "$tools/sparkle-test-key"
  (umask 077 && "$tools/sparkle-test-key" "$file")
}

xml_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' <<<"$1"; }

make_feed() {
  local key_file="" app="$dist/Klav.app" url_base="https://klav.dev/releases/mac" notes="" out="$dist/appcast.xml" dmg=""
  while (($#)); do
    case "$1" in
      --key-file) key_file="$2"; shift 2 ;;
      --app) app="$2"; shift 2 ;;
      --url-base) url_base="${2%/}"; shift 2 ;;
      --notes-url) notes="$2"; shift 2 ;;
      --out) out="$2"; shift 2 ;;
      -*) usage ;;
      *) dmg="$1"; shift ;;
    esac
  done
  [[ -n "$key_file" && -n "$dmg" ]] || usage
  [[ -f "$dmg" ]] || { echo "no DMG at $dmg" >&2; exit 1; }
  local info="$app/Contents/Info.plist"
  [[ -f "$info" ]] || { echo "no Klav.app at $app (--app)" >&2; exit 1; }

  local bin version build minimum key=""
  bin="$(sparkle_bin)"
  version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$info")"
  build="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$info")"
  minimum="$(/usr/libexec/PlistBuddy -c 'Print :LSMinimumSystemVersion' "$info")"

  # The key is read once and handed to sign_update on its standard input
  # (the shell's printf is a builtin: it never shows up in a process list).
  if [[ "$key_file" == - ]]; then
    IFS= read -r key || true
    [[ -n "$key" ]] || { echo "no key on standard input" >&2; exit 1; }
  else
    [[ -r "$key_file" ]] || { echo "cannot read $key_file" >&2; exit 1; }
    IFS= read -r key < "$key_file" || true
  fi
  sign() { printf '%s\n' "$key" | "$bin/sign_update" --ed-key-file - "$@"; }

  local enclosure
  enclosure="$(sign "$dmg")"
  [[ "$enclosure" == *'sparkle:edSignature="'* ]] || { echo "sign_update failed" >&2; exit 1; }

  local name url notes_line=""
  name="$(basename "$dmg")"
  url="$url_base/$name"
  [[ -n "$notes" ]] && notes_line="
      <sparkle:releaseNotesLink>$(xml_escape "$notes")</sparkle:releaseNotesLink>"
  mkdir -p "$(dirname "$out")"
  cat > "$out" <<XML
<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
  <channel>
    <title>Klav</title>
    <link>https://klav.dev/releases/mac/appcast.xml</link>
    <language>en</language>
    <item>
      <title>Klav $(xml_escape "$version")</title>
      <pubDate>$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S +0000')</pubDate>
      <sparkle:version>$(xml_escape "$build")</sparkle:version>
      <sparkle:shortVersionString>$(xml_escape "$version")</sparkle:shortVersionString>
      <sparkle:minimumSystemVersion>$(xml_escape "$minimum")</sparkle:minimumSystemVersion>$notes_line
      <enclosure url="$(xml_escape "$url")" type="application/octet-stream" $enclosure/>
    </item>
  </channel>
</rss>
XML
  # The feed itself, signed (its signature goes inside the file).
  sign "$out" >/dev/null
  printf '%s\n' "$key" | "$bin/sign_update" --verify --ed-key-file - "$out" >/dev/null
  key=""
  echo "appcast: $out (Klav $version, build $build, $(basename "$dmg"))"
  echo "Upload $name and appcast.xml to $url_base/ — the DMG first."
}

case "${1:-}" in
  test-key) shift; test_key "$@" ;;
  make) shift; make_feed "$@" ;;
  *) usage ;;
esac
