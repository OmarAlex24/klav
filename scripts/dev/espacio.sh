#!/bin/sh
# Disk-space guard for local work: run it at the start of each phase or
# layer and after long test runs.
#
# Prints the free space of the internal disk and of the volume that holds
# `target/` (which may be a symlink to an external disk), and the size of
# `target/`. If `target/` is too big it sweeps old build artifacts. Exits
# non-zero when there is too little room to keep working safely.
#
# Limits (in GB) can be changed with environment variables:
#   KLAV_MIN_FREE_GB         free space the internal disk needs (20)
#   KLAV_MIN_TARGET_FREE_GB  free space the volume of target/ needs, when
#                             it is a different volume (50)
#   KLAV_TARGET_MAX_GB       size of target/ that triggers a sweep (25)
set -eu

min_free=${KLAV_MIN_FREE_GB:-20}
min_target_free=${KLAV_MIN_TARGET_FREE_GB:-50}
target_max=${KLAV_TARGET_MAX_GB:-25}

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

# Free space, in whole GB, of the volume holding $1. Empty when `df`
# cannot tell (e.g. an external disk that is not answering).
free_gb() {
	df -Pk "$1" 2>/dev/null | awk 'NR == 2 && $4 ~ /^[0-9]+$/ { printf "%d", $4 / 1048576 }' || true
}

# Device (filesystem) holding $1, to tell whether two paths share a volume.
volume_of() {
	df -Pk "$1" 2>/dev/null | awk 'NR == 2 { print $1 }' || true
}

# Size of $1 in whole GB (follows a symlinked directory). Empty when `du`
# gives no number (a disk that hiccups answers nothing or an I/O error).
size_gb() {
	du -sk "$1/" 2>/dev/null | awk '$1 ~ /^[0-9]+$/ { printf "%d", $1 / 1048576 }' || true
}

# True when $1 is a whole number (an empty answer is "unknown").
known() {
	case "$1" in
	'' | *[!0-9]*) return 1 ;;
	*) return 0 ;;
	esac
}

internal=${HOME:-/}
internal_free=$(free_gb "$internal")
status=0
if known "$internal_free"; then
	echo "Disco interno ($internal): ${internal_free} GB libres"
else
	echo "AVISO: no pude medir el espacio libre del disco interno ($internal)." >&2
fi

if [ -e target ]; then
	target_dir=$(cd target 2>/dev/null && pwd -P || true)
	if [ -z "$target_dir" ]; then
		target_dir=target
		echo "AVISO: no pude entrar en target/ (¿el disco externo no responde?)." >&2
	fi
	if [ -L target ]; then
		echo "target/ -> $target_dir"
	fi
	target_size=$(size_gb "$target_dir")
	if known "$target_size"; then
		echo "target/: ${target_size} GB"
	else
		echo "AVISO: no pude medir target/ (du no respondió); no lo limpio." >&2
	fi
	target_volume=$(volume_of "$target_dir")
	if [ -n "$target_volume" ] && [ "$target_volume" != "$(volume_of "$internal")" ]; then
		target_free=$(free_gb "$target_dir")
		if known "$target_free"; then
			echo "Volumen de target/: ${target_free} GB libres"
			if [ "$target_free" -lt "$min_target_free" ]; then
				echo "ALTO: el volumen de target/ tiene menos de ${min_target_free} GB libres." >&2
				status=1
			fi
		else
			echo "AVISO: no pude medir el espacio libre del volumen de target/." >&2
		fi
	fi
	if known "$target_size" && [ "$target_size" -gt "$target_max" ]; then
		if command -v cargo-sweep >/dev/null 2>&1; then
			echo "target/ pasa de ${target_max} GB: borro lo que no se usa desde hace 2 días (cargo sweep --time 2)."
			cargo sweep --time 2
		else
			echo "target/ pasa de ${target_max} GB y cargo-sweep no está instalado (cargo install cargo-sweep): uso cargo clean."
			cargo clean
		fi
		echo "target/ ahora: $(size_gb "$target_dir") GB"
	fi
else
	echo "target/: no existe todavía"
fi

if known "$internal_free" && [ "$internal_free" -lt "$min_free" ]; then
	echo "ALTO: el disco interno tiene menos de ${min_free} GB libres. Libera espacio antes de seguir." >&2
	status=1
fi

exit "$status"
