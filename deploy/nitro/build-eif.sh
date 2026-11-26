#!/usr/bin/env bash
# Builds Klav Cloud's hosted proxy enclave images (ADR 0051 §7.1) from the
# commit checked out here, reproducibly, and prints their PCR0, PCR1 and PCR2.
#
#   deploy/nitro/build-eif.sh [--variant join|genesis|all] [--out DIR]
#                             [--no-cache] [--allow-dirty]
#
# Writes to DIR (default: target/nitro/<commit>):
#   klav-enclave-<variant>.eif                 the enclave image file
#   klav-enclave-<variant>.measurements.json   nitro-cli's output (PCR0/1/2)
#   images.json      the manifest's `images` entries for this commit
#                    (status "current"), ready for draft-manifest.sh
#   build-info.json  commit, version, nitro-cli version, the SHA-256 of its
#                    blobs (PCR1 measures them) and the base image digests
#   SHA256SUMS       of every file above
#
# Needs: git, docker with buildx (a daemon reachable at /var/run/docker.sock,
# which nitro-cli reads the image from), jq, and sha256sum or shasum.
# Builds for linux/arm64 (Graviton, c7g.large); on an x86_64 host Docker
# needs QEMU emulation and the build takes far longer.
#
# The only inputs are the commit's tree, its hash and its committer time:
# two runs on one commit must print the same PCRs (eif.yml checks it on two
# runners; verify-release.sh lets anyone check it). Nothing here signs
# anything: the release authority signs the manifest offline (runbook §2).
set -euo pipefail

die() {
    echo "build-eif.sh: $*" >&2
    exit 1
}

variant=all
out=
no_cache=()
allow_dirty=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --variant)
            [[ $# -ge 2 ]] || die "--variant needs a value"
            variant=$2
            shift 2
            ;;
        --out)
            [[ $# -ge 2 ]] || die "--out needs a directory"
            out=$2
            shift 2
            ;;
        --no-cache)
            no_cache=(--no-cache)
            shift
            ;;
        --allow-dirty)
            allow_dirty=1
            shift
            ;;
        -h | --help)
            sed -n '2,25p' "$0"
            exit 0
            ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
done

case "$variant" in
    join | genesis) variants=("$variant") ;;
    all) variants=(join genesis) ;;
    *) die "--variant must be join, genesis or all" ;;
esac

for tool in git docker jq; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed"
done
docker buildx version >/dev/null 2>&1 || die "docker buildx is not available"
docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable"
if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$@"; }
elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$@"; }
else
    die "neither sha256sum nor shasum is installed"
fi

root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel) || die "not inside a git checkout of Klav"
cd "$root"
[[ -f deploy/nitro/Dockerfile.enclave ]] || die "deploy/nitro/Dockerfile.enclave is missing in $root"

commit=$(git rev-parse HEAD)
commit_time=$(git show -s --format=%ct HEAD)
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
[[ -n "$version" ]] || die "could not read the workspace version from Cargo.toml"
dirty=false
if [[ -n "$(git status --porcelain)" ]]; then
    dirty=true
    [[ $allow_dirty -eq 1 ]] || die "the working tree has uncommitted changes: the image would not be the commit's (commit them, or --allow-dirty for a throwaway build)"
    echo "build-eif.sh: WARNING: uncommitted changes; these PCRs belong to no commit and must never be listed in a manifest" >&2
fi

out=${out:-target/nitro/$commit}
mkdir -p "$out"
out=$(cd "$out" && pwd)
short=${commit:0:12}
platform=linux/arm64

echo "build-eif.sh: commit $commit ($version), committed at $commit_time, variants: ${variants[*]}" >&2

nitro_tag="klav-nitro-cli:$(sha256 deploy/nitro/Dockerfile.nitro-cli | cut -c1-12)"
echo "build-eif.sh: building $nitro_tag" >&2
docker buildx build --platform "$platform" --load ${no_cache[@]+"${no_cache[@]}"} \
    -t "$nitro_tag" - <deploy/nitro/Dockerfile.nitro-cli >&2

nitro_version=$(docker run --rm --platform "$platform" "$nitro_tag" --version | tr -d '\r')
blobs=$(docker run --rm --platform "$platform" --entrypoint sh "$nitro_tag" \
    -c 'cd /usr/share/nitro_enclaves/blobs && sha256sum *' | sort -k2)

images='[]'
for v in "${variants[@]}"; do
    tag="klav-enclave:$v-$short"
    echo "build-eif.sh: building the $v image ($tag)" >&2
    docker buildx build --platform "$platform" --load ${no_cache[@]+"${no_cache[@]}"} \
        --build-arg "VARIANT=$v" \
        --build-arg "KLAV_BUILD_COMMIT=$commit" \
        --build-arg "KLAV_BUILD_COMMIT_TIME=$commit_time" \
        --build-arg "SOURCE_DATE_EPOCH=$commit_time" \
        -t "$tag" -f deploy/nitro/Dockerfile.enclave . >&2

    eif="klav-enclave-$v.eif"
    echo "build-eif.sh: nitro-cli build-enclave -> $out/$eif" >&2
    raw=$(docker run --rm --platform "$platform" \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$out:/out" \
        "$nitro_tag" build-enclave --docker-uri "$tag" --output-file "/out/$eif") \
        || die "nitro-cli build-enclave failed for $v"
    # nitro-cli prints progress lines, then the JSON object.
    measurements=$(printf '%s\n' "$raw" | sed -n '/^{/,$p' | jq -e '.Measurements') \
        || die "no measurements in nitro-cli's output for $v: $raw"
    printf '%s\n' "$measurements" >"$out/klav-enclave-$v.measurements.json"
    for pcr in PCR0 PCR1 PCR2; do
        value=$(jq -r ".$pcr" <<<"$measurements")
        [[ $value =~ ^[0-9a-f]{96}$ ]] || die "$v: $pcr is not 96 hex characters: $value"
    done
    images=$(jq -c --arg version "$version" --arg commit "$commit" --argjson m "$measurements" \
        '. + [{version: $version, commit: $commit, arch: "aarch64",
               pcr0: $m.PCR0, pcr1: $m.PCR1, pcr2: $m.PCR2, status: "current"}]' <<<"$images")
    docker image rm "$tag" >/dev/null 2>&1 || true
done

jq . <<<"$images" >"$out/images.json"
jq -n \
    --arg commit "$commit" \
    --arg commit_time "$commit_time" \
    --arg version "$version" \
    --argjson dirty "$dirty" \
    --arg nitro_cli "$nitro_version" \
    --arg blobs "$blobs" \
    --arg rust_image "$(sed -n 's/^FROM \(rust:[^ ]*\) AS build$/\1/p' deploy/nitro/Dockerfile.enclave)" \
    --arg busybox_image "$(sed -n 's/^FROM \(busybox:[^ ]*\) AS busybox$/\1/p' deploy/nitro/Dockerfile.enclave)" \
    --arg nitro_image "$(sed -n 's/^FROM \(public.ecr.aws[^ ]*\)$/\1/p' deploy/nitro/Dockerfile.nitro-cli)" \
    '{commit: $commit, commit_time: ($commit_time | tonumber), version: $version, dirty: $dirty,
      nitro_cli: $nitro_cli,
      nitro_cli_blobs: ($blobs | split("\n") | map(select(length > 0) | split("  ") | {(.[1]): .[0]}) | add),
      base_images: {rust: $rust_image, busybox: $busybox_image, nitro_cli: $nitro_image}}' \
    >"$out/build-info.json"

(cd "$out" && sha256 -- *.eif *.json >SHA256SUMS)

echo "build-eif.sh: done, in $out" >&2
for v in "${variants[@]}"; do
    printf '%s\n' "$v"
    jq -r '"  PCR0 \(.PCR0)\n  PCR1 \(.PCR1)\n  PCR2 \(.PCR2)"' "$out/klav-enclave-$v.measurements.json"
done
