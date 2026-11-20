#!/bin/sh
# Entrypoint of the klav-web image (docs/sitio-web.md), the same pattern as
# deploy/railway/entrypoint.sh: Railway mounts the volume at /data owned by
# root, so as root this gives /data to `node` (UID 1000) and starts the
# server as that user, with no capabilities and no_new_privs. Run as any
# other user, it just starts the server.
set -eu

if [ "$(id -u)" = 0 ]; then
	data=$(dirname "${KLAV_WEB_DB:-/data/waitlist.db}")
	mkdir -p "$data"
	find "$data" -xdev ! -user 1000 -exec chown 1000:1000 {} +
	chmod 700 "$data"
	exec setpriv --reuid=1000 --regid=1000 --clear-groups \
		--inh-caps=-all --bounding-set=-all --no-new-privs \
		-- node --disable-warning=ExperimentalWarning /app/server.mjs "$@"
fi
exec node --disable-warning=ExperimentalWarning /app/server.mjs "$@"
