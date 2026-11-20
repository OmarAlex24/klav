#!/usr/bin/env bash
# Paso principal de setup/action.yml. Lee los inputs de INPUT_* (ver action.yml).
# Nunca imprime tokens: se enmascaran con ::add-mask:: antes de cualquier salida.
set -euo pipefail

# SHA-256 de los tarballs oficiales de sccache para la versión por defecto
# (https://github.com/mozilla/sccache/releases/tag/v0.19.0, verificados contra los .sha256).
DEFAULT_SCCACHE_VERSION=0.19.0
DEFAULT_SCCACHE_SHA256_X86_64=aa73c7270c997894038c0d8f0d297865f57569e1687883322bc431713d4bb9dd
DEFAULT_SCCACHE_SHA256_AARCH64=3e47fc4a71b1ddd1b4294a0de9d34498922fdf41e3cd0bda5df3954e3d6deb9d

fail() {
  echo "::error title=ci-cache::$*"
  exit 1
}

# Lee un campo de texto de un JSON plano (jq si existe; si no, python3).
json_field() {
  local field=$1 file=$2
  if command -v jq >/dev/null 2>&1; then
    jq -r --arg f "$field" '.[$f] // empty' "$file"
  else
    python3 -c 'import json,sys; v=json.load(open(sys.argv[2])).get(sys.argv[1]); print("" if v is None else v)' "$field" "$file"
  fi
}

url=${INPUT_URL%/}
audience=${INPUT_AUDIENCE:-ci-cache}
[[ $url =~ ^https?://[^[:space:]]+$ ]] || fail "input url inválido: '$url'"
[[ -n ${GITHUB_ENV:-} && -n ${GITHUB_OUTPUT:-} && -n ${GITHUB_REPOSITORY:-} ]] || fail "esto debe correr dentro de GitHub Actions"
if [[ -z ${ACTIONS_ID_TOKEN_REQUEST_URL:-} || -z ${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-} ]]; then
  fail "no hay token OIDC: añade 'permissions: id-token: write' al job"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# 1. Token OIDC de GitHub con la audiencia del Worker.
curl -fsS --retry 3 -G \
  -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  --data-urlencode "audience=$audience" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL" -o "$tmp/oidc.json" || fail "no se pudo pedir el token OIDC a GitHub"
oidc=$(json_field value "$tmp/oidc.json")
[[ -n $oidc ]] || fail "GitHub no devolvió un token OIDC"
echo "::add-mask::$oidc"

# 2. Sesión en el Worker. El nivel lo decide el Worker a partir del OIDC.
status=$(curl -sS --retry 3 -X POST -H "Authorization: Bearer $oidc" \
  -o "$tmp/session.json" -w '%{http_code}' "$url/v1/session") || fail "no se pudo contactar a $url"
if [[ $status != 200 ]]; then
  fail "POST /v1/session respondió $status: $(json_field message "$tmp/session.json" 2>/dev/null || true)"
fi
token=$(json_field token "$tmp/session.json")
[[ -n $token ]] || fail "respuesta de sesión sin token"
echo "::add-mask::$token"
tier=$(json_field tier "$tmp/session.json")
branch=$(json_field branch "$tmp/session.json")
expires=$(json_field expiresAt "$tmp/session.json")

repo_name=${GITHUB_REPOSITORY#*/}
{
  echo "TURBO_API=$url"
  echo "TURBO_TOKEN=$token"
  # turbo exige un team; el Worker lo ignora (el prefijo sale del token).
  echo "TURBO_TEAM=$repo_name"
  # Ante un 403 turbo apaga la caché remota del run entero: main-ro la usa de solo lectura.
  if [[ $tier == main-ro ]]; then echo "TURBO_CACHE=local:rw,remote:r"; fi
} >>"$GITHUB_ENV"
echo "ci-cache: sesión $tier (rama $branch) hasta $expires"

# 3. Directorio de trabajo: opcionalmente la misma ruta que los sandboxes de Boat.
workdir=$GITHUB_WORKSPACE
if [[ ${INPUT_MOUNT_WORKDIR:-false} == true ]]; then
  workdir=/home/user/$repo_name
  if mountpoint -q "$workdir" 2>/dev/null; then
    echo "ci-cache: $workdir ya está montado"
  else
    sudo mkdir -p "$workdir"
    if [[ -n $(sudo ls -A "$workdir") ]]; then fail "$workdir existe y no está vacío"; fi
    sudo mount --bind "$GITHUB_WORKSPACE" "$workdir"
    echo "ci-cache: checkout montado en $workdir"
  fi
fi

# 4. sccache si hay Rust.
want_sccache=${INPUT_SCCACHE:-auto}
if [[ $want_sccache == auto ]]; then
  # -print -quit en vez de `| grep -q`: con pipefail, el SIGPIPE de find daría falso negativo.
  if [[ -n $(find "$GITHUB_WORKSPACE" -maxdepth 3 -name Cargo.toml -not -path '*/node_modules/*' -not -path '*/target/*' -print -quit) ]]; then
    want_sccache=true
  else
    want_sccache=false
  fi
fi
if [[ $want_sccache == true ]]; then
  version=${INPUT_SCCACHE_VERSION:-$DEFAULT_SCCACHE_VERSION}
  [[ $(uname -s) == Linux ]] || fail "la instalación de sccache solo soporta Linux"
  case $(uname -m) in
    x86_64 | amd64) arch=x86_64 default_sha=$DEFAULT_SCCACHE_SHA256_X86_64 ;;
    aarch64 | arm64) arch=aarch64 default_sha=$DEFAULT_SCCACHE_SHA256_AARCH64 ;;
    *) fail "arquitectura no soportada: $(uname -m)" ;;
  esac
  sha=${INPUT_SCCACHE_SHA256:-}
  if [[ -z $sha ]]; then
    [[ $version == "$DEFAULT_SCCACHE_VERSION" ]] || fail "sccache-version $version requiere sccache-sha256"
    sha=$default_sha
  fi
  [[ $sha =~ ^[0-9a-f]{64}$ ]] || fail "sccache-sha256 inválido"

  dest=${RUNNER_TOOL_CACHE:-$HOME/.local/share}/sccache/$version/$arch
  if [[ -x $dest/sccache ]]; then
    echo "ci-cache: sccache $version ya instalado en $dest"
  else
    name=sccache-v$version-$arch-unknown-linux-musl
    curl -fsSL --retry 3 -o "$tmp/$name.tar.gz" \
      "https://github.com/mozilla/sccache/releases/download/v$version/$name.tar.gz" || fail "no se pudo descargar sccache $version"
    echo "$sha  $tmp/$name.tar.gz" | sha256sum -c --quiet - || fail "el SHA-256 de sccache no coincide"
    tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
    mkdir -p "$dest"
    install -m 0755 "$tmp/$name/sccache" "$dest/sccache"
  fi
  echo "$dest" >>"$GITHUB_PATH"
  # Si la caché remota falla en la comprobación con la que arranca el servidor de
  # sccache, el servidor no arranca y cada rustc sale con error: la corrida quedaría
  # roja en vez de solo más lenta. Se arranca aquí y, si falla, no se activa.
  if SCCACHE_WEBDAV_ENDPOINT="$url/dav" SCCACHE_WEBDAV_TOKEN="$token" SCCACHE_WEBDAV_DISABLE_CREATE_DIR=true \
    "$dest/sccache" --start-server >/dev/null 2>&1; then
    {
      echo "RUSTC_WRAPPER=sccache"
      echo "SCCACHE_WEBDAV_ENDPOINT=$url/dav"
      echo "SCCACHE_WEBDAV_TOKEN=$token"
      # R2 no tiene directorios: sin esto sccache manda un PROPFIND antes de cada PUT.
      echo "SCCACHE_WEBDAV_DISABLE_CREATE_DIR=true"
      # sccache no cachea compilaciones incrementales.
      echo "CARGO_INCREMENTAL=0"
    } >>"$GITHUB_ENV"
    echo "ci-cache: sccache $version listo"
  else
    echo "::warning::ci-cache: sccache no arrancó contra la caché remota; esta corrida compila sin sccache"
  fi
fi

{
  echo "tier=$tier"
  echo "branch=$branch"
  echo "expires-at=$expires"
  echo "workdir=$workdir"
} >>"$GITHUB_OUTPUT"
