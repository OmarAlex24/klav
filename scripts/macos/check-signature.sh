#!/usr/bin/env bash
# Checks what keeps another program of the same user out of a signed
# Klav.app (ADR 0041 §1.2, N10): each given bundle or binary carries the
# hardened runtime flag, and its entitlements include none of the three
# that let a debugger attach or a library load into it.
#
#   scripts/macos/check-signature.sh <path>...
#
# build-app.sh runs it on every Developer ID build, on the app and its
# helpers, and fails the build if any check fails. It fails closed: a path
# codesign can't read, or a signature with no flags line, is a failure.
# scripts/macos/check-signature-test.sh tests it.
set -euo pipefail

forbidden=(
  com.apple.security.get-task-allow
  get-task-allow
  com.apple.security.cs.disable-library-validation
  com.apple.security.cs.allow-dyld-environment-variables
)

(($# > 0)) || { echo "usage: $0 <path>..." >&2; exit 2; }

failed=0
for path in "$@"; do
  bad=0
  # codesign -dv writes to stderr.
  if ! details="$(codesign -dv "$path" 2>&1)"; then
    echo "$path: codesign can't read its signature: $details" >&2
    failed=1
    continue
  fi
  flags_line="$(grep -E '^CodeDirectory .*flags=0x[0-9a-fA-F]+\(' <<<"$details" || true)"
  if [[ -z "$flags_line" ]]; then
    echo "$path: no CodeDirectory flags in its signature" >&2
    failed=1
    continue
  fi
  # flags=0x10000(runtime) or flags=0x10002(adhoc,runtime)
  flags="$(sed -E 's/.*flags=0x[0-9a-fA-F]+\(([^)]*)\).*/\1/' <<<"$flags_line")"
  if [[ ",$flags," != *",runtime,"* ]]; then
    echo "$path: signed without the hardened runtime (flags: ${flags:-none})" >&2
    bad=1
  fi

  if ! entitlements="$(codesign -d --entitlements - --xml "$path" 2>/dev/null)"; then
    echo "$path: codesign can't read its entitlements" >&2
    failed=1
    continue
  fi
  # Every key, wherever the XML breaks its lines. No entitlements at all,
  # or an empty dict, has none.
  keys="$(grep -oE '<key>[^<]*</key>' <<<"$entitlements" | sed -E 's#</?key>##g' || true)"
  for key in "${forbidden[@]}"; do
    if grep -qxF -- "$key" <<<"$keys"; then
      echo "$path: has the entitlement $key" >&2
      bad=1
    fi
  done
  if ((bad)); then
    failed=1
  else
    echo "$path: hardened runtime, no debugging or library entitlements"
  fi
done

exit "$failed"
