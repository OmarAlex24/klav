#!/usr/bin/env bash
# Sends the zip produced by build-sign.sh to Apple's notary service and
# waits for the verdict.
#
#   KLAV_NOTARY_PROFILE=klav-notary scripts/macos/notarize.sh [zip]
#
# Credentials are never passed on the command line or stored in the repo:
# they live in a keychain profile created once with `notarytool
# store-credentials` (see below). Bare command-line binaries cannot be
# stapled; Gatekeeper checks the notarization ticket online.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROFILE="${KLAV_NOTARY_PROFILE:-}"
ZIP="${1:-}"

if [[ -z "$PROFILE" ]]; then
  cat >&2 <<'MSG'
notarize.sh: set KLAV_NOTARY_PROFILE to a notarytool keychain profile.

Create it once (it asks for the app-specific password and stores it in the
keychain; nothing is written to the repository):

  xcrun notarytool store-credentials klav-notary \
    --apple-id "<your Apple ID e-mail>" --team-id SZ3F58F8LX

(app-specific password: appleid.apple.com > Sign-In and Security >
App-Specific Passwords). Or with an App Store Connect API key:

  xcrun notarytool store-credentials klav-notary \
    --key AuthKey_<KEYID>.p8 --key-id <KEYID> --issuer <ISSUER-UUID>

Then: KLAV_NOTARY_PROFILE=klav-notary scripts/macos/notarize.sh
MSG
  exit 1
fi

if [[ -z "$ZIP" ]]; then
  ZIP="$(ls -t "$ROOT"/dist/macos/klav-macos-*.zip 2>/dev/null | head -1 || true)"
fi
[[ -n "$ZIP" && -f "$ZIP" ]] || { echo "notarize.sh: no zip found; run build-sign.sh first" >&2; exit 1; }

echo "Submitting $ZIP (profile $PROFILE)…"
if ! xcrun notarytool submit "$ZIP" --keychain-profile "$PROFILE" --wait --output-format json \
    | tee /dev/stderr | grep -q '"status" *: *"Accepted"'; then
  echo "notarize.sh: not accepted. Inspect with:" >&2
  echo "  xcrun notarytool history --keychain-profile $PROFILE" >&2
  echo "  xcrun notarytool log <submission-id> --keychain-profile $PROFILE" >&2
  exit 1
fi
echo "Notarized: $ZIP"
