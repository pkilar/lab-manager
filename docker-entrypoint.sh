#!/bin/sh
# Start as root only long enough to hand /app/instance to the unprivileged
# runtime user, then exec the app as that user via su-exec.
#
# Volumes written by older images (which ran everything as root) hold a
# root-owned servers.db and a 0600 root-owned .encryption_key. Re-owning them on
# every start migrates those in place, so no manual chown is needed on upgrade.
#
# PUID/PGID override the image's default 10001:10001. The host-networked
# docker-compose deploy sets them to the host user so a bind-mounted ./instance
# stays readable outside the container.
set -eu

if [ "$(id -u)" != 0 ]; then
	# Already unprivileged (e.g. `user:` set in compose): nothing to do.
	exec "$@"
fi

uid="${PUID:-10001}"
gid="${PGID:-10001}"
case "$uid$gid" in
*[!0-9]*)
	echo "docker-entrypoint: PUID/PGID must be numeric (got PUID=$uid PGID=$gid)" >&2
	exit 1
	;;
esac
if [ "$uid" = 0 ]; then
	echo "docker-entrypoint: refusing PUID=0; the app must not run as root" >&2
	exit 1
fi

mkdir -p /app/instance
chown -R "$uid:$gid" /app/instance
chmod 0700 /app/instance

exec su-exec "$uid:$gid" "$@"
