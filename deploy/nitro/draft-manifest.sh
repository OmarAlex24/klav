#!/usr/bin/env bash
# Drafts the next Klav Enclave Transparency Manifest (ADR 0051 §2.4), UNSIGNED.
# The release authority reviews it and signs it offline (runbook §2); nothing
# here touches a key.
#
#   deploy/nitro/draft-manifest.sh --seq N --images images.json
#       [--previous PREV.json] [--seed-epoch N]
#       [--parent-role-arn ARN ...] [--parent-role HEX ...] [--egress CIDR ...]
#       [--endpoint proxy.klav.dev] [--server api.klav.dev] [--days 30]
#       [--out FILE]
#
# - images.json: build-eif.sh's output (the new images, status "current").
# - --previous: the last published manifest. Its images stay listed: the
#   ones that were "current" become "draining" (devices still accept them,
#   and a live enclave of that image can still hand the seed to the new one),
#   "draining" and "revoked" stay as they are. Its seed_epoch, parent_roles,
#   egress, endpoint and server are kept unless given here.
# - --parent-role-arn: the parent instances' IAM role ARN (terraform output
#   `parent_role_arn`); its PCR3 is SHA-384(48 zero bytes || ARN), as AWS
#   documents. --parent-role takes a PCR3 already computed (96 hex).
# - --egress: the parents' Elastic IPs as /32 (terraform output
#   `egress_cidrs`), for ADR 0044's strict network profile.
# - --seed-epoch: bump it by one after a total loss (ADR 0051 §4.4).
#
# Writes deploy/nitro/manifests/drafts/<N>.json unless --out. The file's
# exact bytes are what gets signed: don't reformat it after signing.
set -euo pipefail

die() {
    echo "draft-manifest.sh: $*" >&2
    exit 1
}

seq=
images=
previous=
seed_epoch=
roles=()
role_arns=()
egress=()
endpoint=
server=
days=30
out=
while [[ $# -gt 0 ]]; do
    [[ $1 == -h || $1 == --help ]] && {
        sed -n '2,28p' "$0"
        exit 0
    }
    [[ $# -ge 2 ]] || die "$1 needs a value"
    case "$1" in
        --seq) seq=$2 ;;
        --images) images=$2 ;;
        --previous) previous=$2 ;;
        --seed-epoch) seed_epoch=$2 ;;
        --parent-role) roles+=("$2") ;;
        --parent-role-arn) role_arns+=("$2") ;;
        --egress) egress+=("$2") ;;
        --endpoint) endpoint=$2 ;;
        --server) server=$2 ;;
        --days) days=$2 ;;
        --out) out=$2 ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
    shift 2
done

command -v jq >/dev/null 2>&1 || die "jq is not installed"
[[ $seq =~ ^[0-9]+$ ]] || die "--seq N is required"
[[ -f $images ]] || die "--images images.json is required (build-eif.sh's output)"
[[ $days =~ ^[0-9]+$ && $days -ge 1 && $days -le 30 ]] || die "--days must be 1 to 30 (devices refuse a longer validity)"
if [[ -n $previous ]]; then
    [[ -f $previous ]] || die "no file $previous"
    prev_seq=$(jq -r .seq "$previous")
    [[ $seq -gt $prev_seq ]] || die "--seq $seq must be greater than the previous manifest's $prev_seq"
fi

for arn in "${role_arns[@]:-}"; do
    [[ -z $arn ]] && continue
    [[ $arn =~ ^arn:aws:iam::[0-9]{12}:role/ ]] || die "--parent-role-arn $arn is not an IAM role ARN"
    command -v openssl >/dev/null 2>&1 || die "openssl is needed for --parent-role-arn"
    roles+=("$({
        head -c 48 /dev/zero
        printf '%s' "$arn"
    } | openssl dgst -sha384 -r | cut -d' ' -f1)")
done
for r in "${roles[@]:-}"; do
    [[ -z $r || $r =~ ^[0-9a-f]{96}$ ]] || die "parent role $r is not 96 lowercase hex characters"
done
for c in "${egress[@]:-}"; do
    [[ -z $c || $c =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/32$ ]] || die "--egress $c must be an IPv4 /32"
done

issued=$(($(date +%s) * 1000))
expires=$((issued + days * 86400000))

prev_json='null'
[[ -n $previous ]] && prev_json=$(jq -c . "$previous")
roles_json=$(printf '%s\n' "${roles[@]:-}" | jq -R . | jq -sc 'map(select(length > 0))')
egress_json=$(printf '%s\n' "${egress[@]:-}" | jq -R . | jq -sc 'map(select(length > 0))')

draft=$(jq -n \
    --argjson seq "$seq" \
    --argjson issued "$issued" \
    --argjson expires "$expires" \
    --argjson prev "$prev_json" \
    --slurpfile new "$images" \
    --argjson roles "$roles_json" \
    --argjson egress "$egress_json" \
    --arg seed_epoch "$seed_epoch" \
    --arg endpoint "$endpoint" \
    --arg server "$server" '
  def pick($given; $old; $default): if ($given | length) > 0 then $given elif $old != null then $old else $default end;
  ($new[0]) as $new
  | ($new | map([.pcr0, .pcr1, .pcr2])) as $newkeys
  | {
      v: 1,
      seq: $seq,
      seed_epoch: (if $seed_epoch != "" then ($seed_epoch | tonumber) else ($prev.seed_epoch // 0) end),
      issued_at_ms: $issued,
      expires_at_ms: $expires,
      endpoint: pick($endpoint; $prev.endpoint; "proxy.klav.dev"),
      server: pick($server; $prev.server; "api.klav.dev"),
      images: (
        (($prev.images // [])
          | map(select(([.pcr0, .pcr1, .pcr2]) as $k | $newkeys | index([$k]) | not))
          | map(if .status == "current" then .status = "draining" else . end))
        + $new),
      parent_roles: pick($roles; $prev.parent_roles; []),
      egress: pick($egress; $prev.egress; [])
    }')

jq -e '(.parent_roles | length) > 0' <<<"$draft" >/dev/null \
    || die "no parent role: give --parent-role-arn (or --previous). Without PCR3, no enclave hands the seed to another"
jq -e '(.egress | length) > 0' <<<"$draft" >/dev/null \
    || echo "draft-manifest.sh: WARNING: no egress addresses; devices can't offer the strict network profile" >&2

out=${out:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)/deploy/nitro/manifests/drafts/$seq.json}
mkdir -p "$(dirname "$out")"
jq . <<<"$draft" >"$out"
echo "draft-manifest.sh: wrote $out (UNSIGNED; review, then sign it offline: runbook §2)" >&2
cat "$out"
