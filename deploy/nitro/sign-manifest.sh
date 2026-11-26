#!/usr/bin/env bash
# Signs a Klav Enclave Transparency Manifest with the release authority's
# Ed25519 key (ADR 0051 §2.4, §11.5), on the release authority's own Mac,
# never in CI. The signature is over
# tuple("klav/v1/sig/enclave-manifest", SHA-256(manifest bytes)), as
# klav-core verifies it, and the script checks it against the public key the
# image pins before writing anything.
#
#   deploy/nitro/sign-manifest.sh --manifest N.json --key PATH --release-key HEX
#
# --key is a PEM private key file read once. Pass the named pipe that
# `klav inject --pipe` serves, so the key never touches the disk (runbook §2):
#
#   klav inject -r 'klav://Personal/General/klav-release-authority-active/key' \
#     --pipe -o "$TMPDIR/klav-release.pem" --ttl 2m &
#   deploy/nitro/sign-manifest.sh --manifest deploy/nitro/manifests/drafts/1.json \
#     --key "$TMPDIR/klav-release.pem" --release-key <active public key hex>
#
# It writes N.json.sig next to the manifest (128 lowercase hex characters and
# a newline), and prints the manifest's SHA-256. Needs OpenSSL 3.0 or later
# (Homebrew's `openssl`; macOS's /usr/bin/openssl is LibreSSL, which can't
# sign raw Ed25519 messages), jq and xxd.
set -euo pipefail

die() {
    echo "sign-manifest.sh: $*" >&2
    exit 1
}

LABEL="klav/v1/sig/enclave-manifest"

manifest=
key=
pub=
while [[ $# -gt 0 ]]; do
    [[ $1 == -h || $1 == --help ]] && {
        sed -n '2,23p' "$0"
        exit 0
    }
    [[ $# -ge 2 ]] || die "$1 needs a value"
    case "$1" in
        --manifest) manifest=$2 ;;
        --key) key=$2 ;;
        --release-key) pub=$2 ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
    shift 2
done

[[ -f $manifest ]] || die "--manifest N.json is required"
[[ -n $key && -e $key ]] || die "--key PATH is required (a PEM file or the pipe klav inject serves)"
[[ $pub =~ ^[0-9a-f]{64}$ ]] || die "--release-key must be the expected public key, 64 lowercase hex characters"
for tool in openssl jq xxd; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed"
done
openssl version | grep -q '^OpenSSL [3-9]' || die "OpenSSL 3.0 or later is needed ($(openssl version)); on macOS: brew install openssl and put it first in PATH"
jq -e '.v == 1 and (.seq | type) == "number"' "$manifest" >/dev/null || die "$manifest is not a version 1 manifest"
seq=$(jq -r .seq "$manifest")
[[ "$(basename "$manifest")" == "$seq.json" ]] || die "the file must be named $seq.json (its seq)"
now_ms=$(($(date +%s) * 1000))
jq -e --argjson now "$now_ms" '.expires_at_ms > $now and .issued_at_ms <= $now + 300000' "$manifest" >/dev/null \
    || die "$manifest is expired or issued in the future: draft it again"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if command -v sha256sum >/dev/null 2>&1; then
    digest=$(sha256sum "$manifest" | cut -d' ' -f1)
else
    digest=$(shasum -a 256 "$manifest" | cut -d' ' -f1)
fi
{
    printf '%08x' "${#LABEL}" | xxd -r -p
    printf '%s' "$LABEL"
    printf '%08x' 32 | xxd -r -p
    printf '%s' "$digest" | xxd -r -p
} >"$work/message.bin"

# The private key is read once, from --key, straight into openssl.
openssl pkeyutl -sign -rawin -inkey "$key" -in "$work/message.bin" -out "$work/sig.bin" \
    || die "openssl could not sign with $key"

printf '302a300506032b6570032100%s' "$pub" | xxd -r -p >"$work/pub.der"
openssl pkeyutl -verify -pubin -inkey "$work/pub.der" -keyform DER -rawin \
    -in "$work/message.bin" -sigfile "$work/sig.bin" >/dev/null 2>&1 \
    || die "the key given is not the release key $pub: nothing written"

sig="${manifest%.json}.json.sig"
xxd -p -c 64 "$work/sig.bin" >"$sig"
[[ $(tr -d '\n' <"$sig") =~ ^[0-9a-f]{128}$ ]] || die "unexpected signature length"
echo "sign-manifest.sh: wrote $sig for manifest $seq (SHA-256 $digest), verified with ${pub:0:16}…" >&2
