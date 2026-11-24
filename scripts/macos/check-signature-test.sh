#!/usr/bin/env bash
# Tests scripts/macos/check-signature.sh on small ad hoc signed binaries:
# the app's own entitlements file with the hardened runtime passes; no
# runtime flag, each forbidden entitlement, an unsigned binary and a
# missing path fail. Works under target/ and deletes what it made, also
# on failure.
#
#   scripts/macos/check-signature-test.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
check="$root/scripts/macos/check-signature.sh"
work="$(mktemp -d "$root/target/check-signature.XXXXXX")"
trap 'rm -rf "$work"' EXIT

printf 'int main(void) { return 0; }\n' | cc -x c - -o "$work/base"

# entitlements <file> <key>...: a plist with each key set to true.
entitlements() {
  local file="$1"
  shift
  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    echo '<plist version="1.0"><dict>'
    for key in "$@"; do echo "<key>$key</key><true/>"; done
    echo '</dict></plist>'
  } >"$file"
}

# signed <name> [codesign options...]: an ad hoc signed copy of base.
signed() {
  local name="$1"
  shift
  cp "$work/base" "$work/$name"
  codesign --force --sign - "$@" "$work/$name" 2>/dev/null
  echo "$work/$name"
}

pass=0
fail=0
expect() {
  local want="$1" label="$2"
  shift 2
  local got=0
  "$check" "$@" >/dev/null 2>&1 || got=$?
  if { [[ "$want" == pass ]] && ((got == 0)); } || { [[ "$want" == fail ]] && ((got != 0)); }; then
    echo "ok   $label"
    pass=$((pass + 1))
  else
    echo "FAIL $label: expected $want, exit $got" >&2
    "$check" "$@" || true
    fail=$((fail + 1))
  fi
}

# The app's own entitlements, as build-app.sh signs it.
app_entitlements="$root/apps/ios/Mac/KlavMac.entitlements"
expect pass "the app's entitlements with the hardened runtime" \
  "$(signed good --options runtime --entitlements "$app_entitlements")"
expect pass "no entitlements with the hardened runtime" "$(signed bare --options runtime)"
expect pass "a harmless entitlement" \
  "$(entitlements "$work/fine.plist" com.apple.security.network.client
     signed fine --options runtime --entitlements "$work/fine.plist")"
expect fail "no hardened runtime" \
  "$(signed noruntime --entitlements "$app_entitlements")"
for key in com.apple.security.get-task-allow get-task-allow \
  com.apple.security.cs.disable-library-validation \
  com.apple.security.cs.allow-dyld-environment-variables; do
  entitlements "$work/$key.plist" com.apple.security.network.client "$key"
  expect fail "the entitlement $key" "$(signed "e-$key" --options runtime --entitlements "$work/$key.plist")"
done
cp "$work/base" "$work/unsigned"
codesign --remove-signature "$work/unsigned"
expect fail "an unsigned binary" "$work/unsigned"
expect fail "a missing path" "$work/missing"
expect fail "one bad path among good ones" "$work/good" "$work/noruntime"

echo "$pass passed, $fail failed"
((fail == 0))
