#!/usr/bin/env bash
# Imprime todo lo que entra en las llaves de caché (ruta, usuario, toolchains,
# banderas). Córrelo en un sandbox de Boat y en un paso de la CI, guarda las dos
# salidas y compáralas con `diff`: cada línea distinta es una razón para que la
# caché no acierte.
#
#   Sandbox:  boat exec <id> 'cd /home/user/<repo> && bash cache-fingerprint.sh' > sandbox.txt
#   CI:       - run: bash cache-fingerprint.sh   (y copia la salida del log a ci.txt)
#   diff sandbox.txt ci.txt
set -u
v() { command -v "$1" >/dev/null 2>&1 && "$@" 2>&1 | head -1 || echo "(no instalado)"; }

echo "== máquina"
echo "usuario:      $(id -un) uid=$(id -u)"
echo "HOME:         $HOME"
echo "checkout:     $(pwd -P)"
echo "os:           $(. /etc/os-release && echo "$PRETTY_NAME")"
echo "kernel:       $(uname -r) $(uname -m)"
echo "vCPU / RAM:   $(nproc) / $(awk '/MemTotal/ {printf "%.1f GB", $2/1048576}' /proc/meminfo)"

echo "== rust"
echo "rustc:        $(v rustc -V)"
echo "host:         $(rustc -vV 2>/dev/null | awk '/host/ {print $2}')"
echo "cargo:        $(v cargo -V)"
echo "sccache:      $(v sccache --version)"
echo "toolchain:    $(cat rust-toolchain.toml 2>/dev/null | tr '\n' ' ' || echo '(sin rust-toolchain.toml)')"
echo "RUSTFLAGS:    ${RUSTFLAGS-}"
echo "CARGO_INCREMENTAL: ${CARGO_INCREMENTAL-}"
echo "CARGO_HOME:   ${CARGO_HOME:-$HOME/.cargo}"

echo "== node"
echo "node:         $(v node -v)"
echo "pnpm:         $(v pnpm -v)"
echo "turbo:        $(v npx --no-install turbo --version)"
echo "pnpm store:   $(pnpm store path 2>/dev/null || echo '-')"

echo "== go"
echo "go:           $(v go version)"
echo "GOFLAGS:      ${GOFLAGS-}"
echo "GOCACHE:      $(go env GOCACHE 2>/dev/null || echo '-')"

echo "== python"
echo "python:       $(v python3 -V)"
echo "uv:           $(v uv --version)"

echo "== docker"
echo "docker:       $(v docker version --format '{{.Server.Version}}')"
echo "buildx:       $(v docker buildx version)"

echo "== variables que entran en las llaves"
env | grep -E '^(CARGO_|RUST|SCCACHE_|TURBO_|GO|CC=|CXX=|CFLAGS|LDFLAGS|NODE_OPTIONS)' | grep -viE 'token|key|secret' | sort
