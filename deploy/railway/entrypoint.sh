#!/bin/sh
# Entrypoint of the Railway image (deploy/railway/Dockerfile).
#
# Railway mounts the volume at /data owned by root. Running as root, this
# script gives /data to `klav` (UID 10001) and starts klav-server as that
# user, with no capabilities and no_new_privs: the server never runs as
# root. Run as any other user, it just starts the server.
set -eu

# Listen on Railway's PORT (8080 if unset) unless KLAV_LISTEN is set.
: "${KLAV_LISTEN:=0.0.0.0:${PORT:-8080}}"
export KLAV_LISTEN

if [ "$(id -u)" = 0 ]; then
	data=${KLAV_DATA_DIR:-/data}
	# Root only hands over the volume: /data or a directory inside it,
	# reached without symlinks. Anything else (`/`, `/etc`, `/data/../usr`,
	# a symlink out of the volume) would give that tree to UID 10001.
	resolved=$(realpath -m -- "$data")
	case "$resolved" in
	/data | /data/*) ;;
	*)
		echo "klav-entrypoint: KLAV_DATA_DIR must be /data or a directory inside it, not '$data'" >&2
		exit 1
		;;
	esac
	if [ "$resolved" != "$(realpath -s -m -- "$data")" ]; then
		echo "klav-entrypoint: KLAV_DATA_DIR must not go through a symlink: '$data'" >&2
		exit 1
	fi
	mkdir -p -- "$resolved"
	if [ "$(realpath -e -- "$resolved")" != "$resolved" ] || [ ! -d "$resolved" ]; then
		echo "klav-entrypoint: KLAV_DATA_DIR is not a plain directory: '$data'" >&2
		exit 1
	fi
	# Only what is not klav's yet: cheap on every start after the first.
	# Never follow a symlink: `chown -h` changes the link, not its target.
	find "$resolved" -xdev ! -user 10001 -exec chown -h 10001:10001 {} +
	chmod 700 -- "$resolved"
	exec setpriv --reuid=10001 --regid=10001 --clear-groups \
		--inh-caps=-all --bounding-set=-all --no-new-privs \
		-- /usr/local/bin/klav-server "$@"
fi
exec /usr/local/bin/klav-server "$@"
