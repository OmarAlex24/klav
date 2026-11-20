# shellcheck shell=bash
# The build scripts' settings that belong to one machine or one Apple
# account (docs/ios.md §5): where Xcode puts DerivedData and the Swift
# package cache, and the App Store Connect key that notarizes the Mac app.
# Sourced by scripts/ios/{test,archive}.sh and scripts/macos/{test,build-app,appcast}.sh.
#
# They live in one file per user, outside every checkout:
#
#   ${KLAV_DEV_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/klav-dev/config.env}
#
# The file is read, never run: one NAME=value per line, plus blank lines
# and lines starting with '#'. Everything after the first '=' is the value,
# taken literally: no quotes, no $VAR, no ~, so paths are absolute, and a
# value with quotes or spaces around it is refused. Only
# the names in klav_dev_config_names are accepted, each once. A variable
# already set (and not empty) in the environment wins over the file.
# Example: scripts/dev/config.env.example.
#
# KLAV_DEV_CONFIG_PRINT=1 makes a script print what it resolved and exit
# before it builds anything.

klav_dev_config_names=(
  KLAV_IOS_DERIVED
  KLAV_MAC_DERIVED
  KLAV_MAC_RELEASE_DERIVED
  KLAV_SPM_CACHE
  KLAV_NOTARY_KEY
  KLAV_NOTARY_KEY_ID
  KLAV_NOTARY_ISSUER
)
# The ones that hold a path, which must be absolute.
klav_dev_config_paths=" KLAV_IOS_DERIVED KLAV_MAC_DERIVED KLAV_MAC_RELEASE_DERIVED KLAV_SPM_CACHE KLAV_NOTARY_KEY "

klav_dev_config_die() {
  echo "${0##*/}: $*" >&2
  exit 1
}

# The config file's path (it may not exist).
klav_dev_config_file() {
  printf '%s\n' "${KLAV_DEV_CONFIG:-${XDG_CONFIG_HOME:-${HOME:?is unset, so set KLAV_DEV_CONFIG}/.config}/klav-dev/config.env}"
}

# Sets, from the config file, each accepted name the environment leaves
# unset or empty. No file is fine, unless KLAV_DEV_CONFIG names it.
klav_dev_config_load() {
  local file line n=0 name value known k seen=" "
  file="$(klav_dev_config_file)"
  if [[ ! -e "$file" ]]; then
    [[ -z "${KLAV_DEV_CONFIG:-}" ]] || klav_dev_config_die "KLAV_DEV_CONFIG names a file that doesn't exist: $file"
    return 0
  fi
  [[ -f "$file" && -r "$file" ]] || klav_dev_config_die "can't read $file"
  while IFS= read -r line || [[ -n "$line" ]]; do
    n=$((n + 1))
    line="${line%$'\r'}"
    [[ "$line" =~ ^[[:space:]]*(#.*)?$ ]] && continue
    [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] \
      || klav_dev_config_die "$file:$n: not a NAME=value line"
    name="${BASH_REMATCH[1]}"
    value="${BASH_REMATCH[2]}"
    known=0
    for k in "${klav_dev_config_names[@]}"; do [[ "$k" == "$name" ]] && known=1; done
    [[ "$known" == 1 ]] \
      || klav_dev_config_die "$file:$n: unknown name $name (accepted: ${klav_dev_config_names[*]})"
    [[ "$seen" != *" $name "* ]] || klav_dev_config_die "$file:$n: $name is set twice"
    seen="$seen$name "
    [[ -n "$value" ]] || klav_dev_config_die "$file:$n: $name is empty"
    case "$value" in
      [[:space:]\"\']* | *[[:space:]\"\'])
        klav_dev_config_die "$file:$n: $name has quotes or spaces around its value, which is taken as written"
        ;;
    esac
    if [[ "$klav_dev_config_paths" == *" $name "* && "$value" != /* ]]; then
      klav_dev_config_die "$file:$n: $name must be an absolute path (the file doesn't expand ~ or \$HOME)"
    fi
    [[ -n "${!name:-}" ]] || printf -v "$name" '%s' "$value"
  done < "$file"
}

# The default build directory NAME: target/xcode/NAME in this repository,
# with target/ resolved, since it may be a link to another disk.
klav_dev_default_dir() {
  local target="$1/target"
  if [[ -L "$target" && ! -e "$target" ]]; then
    klav_dev_config_die "target/ is a link to something that isn't there: $(readlink "$target")"
  fi
  if [[ -d "$target" ]]; then target="$(cd -P "$target" && pwd)"; fi
  printf '%s/xcode/%s\n' "$target" "$2"
}

# Stops with every missing name of "$@" (after the first argument, what
# needs them) and where to set them.
klav_dev_config_require() {
  local what="$1" name missing=""
  shift
  for name in "$@"; do
    [[ -n "${!name:-}" ]] || missing="$missing${missing:+, }$name"
  done
  [[ -z "$missing" ]] && return 0
  echo "${0##*/}: $what needs $missing, which have no default." >&2
  echo "Set them in the environment or in $(klav_dev_config_file)" >&2
  echo "(one NAME=value per line; example: scripts/dev/config.env.example)." >&2
  exit 1
}

# With KLAV_DEV_CONFIG_PRINT=1: prints each shell variable of "$@" as
# name=value and exits.
klav_dev_config_print() {
  [[ "${KLAV_DEV_CONFIG_PRINT:-0}" == 1 ]] || return 0
  local name
  for name in "$@"; do printf '%s=%s\n' "$name" "${!name-}"; done
  exit 0
}
