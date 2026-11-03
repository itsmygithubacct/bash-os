#!/bin/sh
# Signed Debian archives; the snapshot's Release expiry is intentionally ignored.
set -eu
snapshot=${1:?usage: apt-snapshot.sh YYYYMMDDTHHMMSSZ}
case "$snapshot" in
    ????????T??????Z) ;;
    *) echo 'invalid Debian snapshot timestamp' >&2; exit 2 ;;
esac
case "$snapshot" in
    *[!0-9TZ]*) echo 'invalid Debian snapshot timestamp' >&2; exit 2 ;;
esac
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources
cat > /etc/apt/sources.list.d/parity.sources <<EOF
Types: deb
URIs: http://snapshot.debian.org/archive/debian/$snapshot/
Suites: trixie trixie-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
Check-Valid-Until: no

Types: deb
URIs: http://snapshot.debian.org/archive/debian-security/$snapshot/
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
Check-Valid-Until: no
EOF
printf '%s\n' "$snapshot" > /etc/bash-os-parity-snapshot
printf 'Acquire::Retries "3";\n' > /etc/apt/apt.conf.d/80parity-retries
