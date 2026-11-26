#!/bin/sh
# The enclave image's command (deploy/nitro/Dockerfile.enclave), run by
# busybox's sh inside the enclave. It does only what klav-proxy can't do
# itself, then execs it: an enclave boots with `lo` down, and klav-proxy's
# egress bridge and each account's issuer API listen on 127.0.0.1
# (ADR 0051 §16). Bringing `lo` up gives it 127.0.0.1/8.
set -eu

bb=/bin/busybox

if [ -z "${KLAV_ENCLAVE_RELEASE_KEYS:-}" ]; then
    echo "klav-enclave-start: this image pins no release-authority key (KLAV_ENCLAVE_RELEASE_KEYS is empty); no manifest can verify (ADR 0051 §14)" >&2
    exit 78
fi

$bb ip link set dev lo up
if ! $bb ip -4 addr show dev lo | $bb grep -q 'inet 127\.0\.0\.1/'; then
    $bb ip addr add 127.0.0.1/8 dev lo
fi

exec /usr/local/bin/klav-proxy enclave
