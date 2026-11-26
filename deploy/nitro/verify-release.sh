#!/usr/bin/env bash
# Checks a published Klav Enclave Transparency Manifest independently
# (ADR 0051 §2.4, §7.3): anyone can run it, with nothing from Klav but the
# public repository.
#
#   deploy/nitro/verify-release.sh --seq N --release-key HEX [--release-key HEX]
#                                  [--commit SHA] [--manifests URL|DIR] [--keep]
#                                  [--no-rebuild]
#
# 1. Fetches manifest N and its signature (<N>.json, <N>.json.sig) from the
#    public repository (default: the default branch's deploy/nitro/manifests/
#    on raw.githubusercontent.com), or reads them from a local DIR.
# 2. Verifies the Ed25519 signature over
#    tuple("klav/v1/sig/enclave-manifest", SHA-256(manifest bytes)) with one
#    of the release-authority keys given (64 hex characters each; the ones
#    klav-core pins in RELEASE_AUTHORITY_KEYS). Prints its seq, dates,
#    seed_epoch and images.
# 3. For each commit the manifest lists (or only --commit), checks the commit
#    out in a fresh git worktree, rebuilds both enclave images with
#    deploy/nitro/build-eif.sh, and compares PCR0, PCR1 and PCR2 with the
#    manifest's entries for that commit: every image rebuilt must be listed,
#    and every image listed for that commit must be rebuilt. --no-rebuild
#    stops after step 2 (a quick check of the signature and contents).
#
# Exit status 0 only if the signature verifies and every compared PCR is
# byte-identical. Needs what build-eif.sh needs, plus openssl (3.0 or later,
# for Ed25519), curl for remote manifests, and xxd.
#
# Where it builds: target/nitro/verify-<commit>/ (a worktree and its output),
# removed at the end unless --keep. Run it from a clone of the repository
# that has the commits (`git fetch --tags origin` first).
set -euo pipefail

die() {
    echo "verify-release.sh: $*" >&2
    exit 1
}

LABEL="klav/v1/sig/enclave-manifest"
DEFAULT_MANIFESTS="https://raw.githubusercontent.com/OmarAlex24/klav/main/deploy/nitro/manifests/"

seq=
keys=()
only_commit=
manifests=$DEFAULT_MANIFESTS
keep=0
rebuild=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --seq)
            [[ $# -ge 2 ]] || die "--seq needs a number"
            seq=$2
            shift 2
            ;;
        --release-key)
            [[ $# -ge 2 ]] || die "--release-key needs 64 hex characters"
            keys+=("$2")
            shift 2
            ;;
        --commit)
            [[ $# -ge 2 ]] || die "--commit needs a SHA"
            only_commit=$2
            shift 2
            ;;
        --manifests)
            [[ $# -ge 2 ]] || die "--manifests needs a URL or a directory"
            manifests=$2
            shift 2
            ;;
        --keep)
            keep=1
            shift
            ;;
        --no-rebuild)
            rebuild=0
            shift
            ;;
        -h | --help)
            sed -n '2,32p' "$0"
            exit 0
            ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
done

[[ $seq =~ ^[0-9]+$ ]] || die "--seq N is required (the manifest's sequence number)"
[[ ${#keys[@]} -gt 0 ]] || die "at least one --release-key is required (the release authority's Ed25519 public key, 64 hex)"
for k in "${keys[@]}"; do
    [[ $k =~ ^[0-9a-fA-F]{64}$ ]] || die "--release-key $k is not 64 hex characters"
done
for tool in git jq openssl xxd; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed"
done
if command -v sha256sum >/dev/null 2>&1; then
    sha256_hex() { sha256sum "$1" | cut -d' ' -f1; }
else
    sha256_hex() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi

root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel) || die "run from a git clone of Klav"
cd "$root"
work="$root/target/nitro/verify-$seq"
rm -rf "$work"
mkdir -p "$work"
worktrees=()
cleanup() {
    for wt in "${worktrees[@]:-}"; do
        [[ -n "$wt" ]] && git -C "$root" worktree remove --force "$wt" >/dev/null 2>&1 || true
    done
    if [[ $keep -eq 0 ]]; then
        rm -rf "$work"
    else
        echo "verify-release.sh: kept $work" >&2
    fi
}
trap cleanup EXIT

# 1. The manifest and its signature, as published.
manifest="$work/$seq.json"
sigfile="$work/$seq.json.sig"
if [[ -d $manifests ]]; then
    cp "$manifests/$seq.json" "$manifest" || die "no $seq.json in $manifests"
    cp "$manifests/$seq.json.sig" "$sigfile" || die "no $seq.json.sig in $manifests"
else
    command -v curl >/dev/null 2>&1 || die "curl is not installed"
    base=${manifests%/}/
    curl -fsSL --proto '=https' --max-filesize 65536 -o "$manifest" "$base$seq.json" \
        || die "could not fetch $base$seq.json"
    curl -fsSL --proto '=https' --max-filesize 256 -o "$sigfile" "$base$seq.json.sig" \
        || die "could not fetch $base$seq.json.sig"
fi

# 2. The signature: 128 lowercase hex characters, an optional final newline.
sig_hex=$(tr -d '\n' <"$sigfile")
[[ $sig_hex =~ ^[0-9a-f]{128}$ ]] || die "$seq.json.sig is not 128 lowercase hex characters"
printf '%s' "$sig_hex" | xxd -r -p >"$work/sig.bin"
digest=$(sha256_hex "$manifest")
{
    printf '%08x' "${#LABEL}" | xxd -r -p
    printf '%s' "$LABEL"
    printf '%08x' 32 | xxd -r -p
    printf '%s' "$digest" | xxd -r -p
} >"$work/message.bin"

verified_by=
for k in "${keys[@]}"; do
    # An Ed25519 SubjectPublicKeyInfo is this 12-byte DER prefix and the key.
    printf '302a300506032b6570032100%s' "$(tr 'A-F' 'a-f' <<<"$k")" | xxd -r -p >"$work/key.der"
    if openssl pkeyutl -verify -pubin -inkey "$work/key.der" -keyform DER -rawin \
        -in "$work/message.bin" -sigfile "$work/sig.bin" >/dev/null 2>&1; then
        verified_by=$k
        break
    fi
done
[[ -n "$verified_by" ]] || die "manifest $seq's signature verifies with none of the keys given: do not trust it"
echo "signature: OK (release key ${verified_by:0:16}…)"

jq -e '.v == 1' "$manifest" >/dev/null || die "manifest $seq is not version 1"
jq -e --argjson seq "$seq" '.seq == $seq' "$manifest" >/dev/null || die "the file $seq.json says another seq"
now_ms=$(($(date +%s) * 1000))
jq -r --argjson now "$now_ms" '
  "seq \(.seq), seed_epoch \(.seed_epoch), endpoint \(.endpoint), server \(.server)",
  "issued  \(.issued_at_ms / 1000 | floor | todate)",
  "expires \(.expires_at_ms / 1000 | floor | todate)\(if .expires_at_ms < $now then "  (EXPIRED: devices refuse it)" else "" end)",
  "egress  \(.egress | join(", "))",
  "parent_roles (PCR3) \(.parent_roles | join(", "))",
  (.images[] | "image \(.version) \(.commit[0:12]) \(.arch) \(.status)")' "$manifest"

if [[ $rebuild -eq 0 ]]; then
    echo "verify-release.sh: signature verified; images not rebuilt (--no-rebuild)"
    exit 0
fi

# 3. Rebuild and compare.
if [[ -n "$only_commit" ]]; then
    commits=$(git rev-parse --verify "$only_commit^{commit}") || die "unknown commit $only_commit"
    jq -e --arg c "$commits" 'any(.images[]; .commit == $c)' "$manifest" >/dev/null \
        || die "manifest $seq lists no image of commit $commits"
else
    commits=$(jq -r '[.images[].commit] | unique | .[]' "$manifest")
fi

failed=0
for commit in $commits; do
    git cat-file -e "$commit^{commit}" 2>/dev/null \
        || die "commit $commit is not in this clone (git fetch --tags origin)"
    wt="$work/src-$commit"
    git worktree add --detach "$wt" "$commit" >/dev/null
    worktrees+=("$wt")
    [[ -x "$wt/deploy/nitro/build-eif.sh" ]] || die "commit $commit has no deploy/nitro/build-eif.sh"
    echo "rebuilding $commit (this takes a while)…"
    "$wt/deploy/nitro/build-eif.sh" --variant all --no-cache --out "$work/out-$commit" >/dev/null
    built="$work/out-$commit/images.json"
    # Each rebuilt image must be listed with this commit, and each listed
    # image of this commit must be one rebuilt.
    if jq -e --slurpfile built "$built" --arg c "$commit" '
        def key: [.pcr0, .pcr1, .pcr2];
        ([.images[] | select(.commit == $c) | key] | sort) == ($built[0] | map(key) | sort)
      ' "$manifest" >/dev/null; then
        echo "commit ${commit:0:12}: PCR0, PCR1 and PCR2 match the manifest for every image"
    else
        echo "commit ${commit:0:12}: MISMATCH" >&2
        echo "  rebuilt:" >&2
        jq -r '.[] | "    \(.pcr0) \(.pcr1) \(.pcr2)"' "$built" >&2
        echo "  manifest:" >&2
        jq -r --arg c "$commit" '.images[] | select(.commit == $c) | "    \(.pcr0) \(.pcr1) \(.pcr2) \(.status)"' "$manifest" >&2
        failed=1
    fi
done

[[ $failed -eq 0 ]] || die "manifest $seq does not match what its commits build"
echo "verify-release.sh: manifest $seq verified: signed by a release key, and every listed image rebuilds to its PCRs"
