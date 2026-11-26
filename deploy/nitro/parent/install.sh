#!/usr/bin/env bash
# Installs or upgrades Klav Cloud's hosted proxy on one parent instance
# (ADR 0051 §7.4). Runs as root on Amazon Linux 2023 (aarch64), through SSM
# Session Manager or Run Command: the instances have no SSH (runbook §3).
#
#   install.sh --bundle DIR [--start]
#
# DIR is an unpacked bundle from eif.yml's `klav-nitro-bundle` artifact:
#   bin/klav-nitro-parent, parent/*, eif/klav-enclave-join.eif,
#   eif/klav-enclave-genesis.eif, eif/images.json, SHA256SUMS
#
# It checks the bundle against SHA256SUMS, installs nitro-cli at the version
# the EIFs were built with, writes the allocator configuration, installs the
# two units, enables them (so a reboot or an instance recovery joins again)
# and restarts the parent relay. It starts the enclave only with --start,
# and then only the JOIN image: a holder must be in service behind
# proxy.klav.dev. It never starts a genesis enclave (runbook §4).
#
# Upgrading a host whose enclave runs: install, then follow runbook §6; the
# running enclave keeps the old image until klav-enclave.service restarts.
set -euo pipefail

die() {
    echo "install.sh: $*" >&2
    exit 1
}

# The nitro-cli the EIFs were built with (deploy/nitro/Dockerfile.nitro-cli).
NITRO_CLI_VERSION=1.5.3-0.amzn2023

bundle=
start=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --bundle)
            [[ $# -ge 2 ]] || die "--bundle needs a directory"
            bundle=$2
            shift 2
            ;;
        --start)
            start=1
            shift
            ;;
        -h | --help)
            sed -n '2,20p' "$0"
            exit 0
            ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "run as root"
[[ -n "$bundle" && -d "$bundle" ]] || die "--bundle DIR is required and must exist"
[[ $(uname -m) == aarch64 ]] || die "this host is $(uname -m); the EIFs are for aarch64 (c7g)"
grep -q '^ID="amzn"' /etc/os-release || die "expected Amazon Linux 2023"

cd "$bundle"
for f in bin/klav-nitro-parent parent/klav-nitro-parent.service parent/klav-enclave.service \
    parent/allocator.yaml eif/klav-enclave-join.eif eif/klav-enclave-genesis.eif eif/images.json SHA256SUMS; do
    [[ -f $f ]] || die "the bundle has no $f"
done
sha256sum --check --strict --quiet SHA256SUMS || die "the bundle does not match its SHA256SUMS"

echo "install.sh: nitro-cli $NITRO_CLI_VERSION"
dnf install -y "aws-nitro-enclaves-cli-$NITRO_CLI_VERSION" >/dev/null
nitro-cli --version

id klav-parent >/dev/null 2>&1 || useradd --system --no-create-home --shell /sbin/nologin klav-parent
install -d -m 0755 /opt/klav /opt/klav/bin /opt/klav/eif
# Replaced by rename, so a running service never reads a half-written file.
install -m 0755 bin/klav-nitro-parent /opt/klav/bin/klav-nitro-parent.new
mv -f /opt/klav/bin/klav-nitro-parent.new /opt/klav/bin/klav-nitro-parent
for f in klav-enclave-join.eif klav-enclave-genesis.eif images.json; do
    install -m 0644 "eif/$f" "/opt/klav/eif/$f.new"
    mv -f "/opt/klav/eif/$f.new" "/opt/klav/eif/$f"
done
install -m 0644 SHA256SUMS /opt/klav/SHA256SUMS

install -d -m 0755 /etc/nitro_enclaves
install -m 0644 parent/allocator.yaml /etc/nitro_enclaves/allocator.yaml
install -m 0644 parent/klav-nitro-parent.service /etc/systemd/system/klav-nitro-parent.service
install -m 0644 parent/klav-enclave.service /etc/systemd/system/klav-enclave.service

systemctl daemon-reload
systemctl enable --now nitro-enclaves-allocator.service
systemctl enable klav-nitro-parent.service klav-enclave.service
systemctl restart klav-nitro-parent.service
/opt/klav/bin/klav-nitro-parent --version

if [[ $start -eq 1 ]]; then
    systemctl start klav-enclave.service
    echo "install.sh: join enclave started. It is ready when this answers 200 (runbook §3):"
    printf '  %s\n' "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8443/v1/manifest"
else
    echo "install.sh: installed; the enclave was not (re)started (runbook §4–§6 say when)"
fi
