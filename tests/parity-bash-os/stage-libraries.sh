#!/bin/sh
set -eu
mkdir -p /image/bin /image/etc /image/usr /image/root /image/tmp /image/work \
    /image/dev /image/proc /image/sys /image/run
chmod 0700 /image/root
chmod 1777 /image/tmp /image/work
for path in /usr/lib /usr/lib64 /usr/share/zoneinfo /usr/share/terminfo \
    /usr/share/fonts /usr/share/fontconfig /usr/share/glvnd /usr/share/drirc.d \
    /usr/share/egl /usr/share/ca-certificates /usr/share/doc /etc/ssl /etc/fonts \
    /etc/terminfo /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/nsswitch.conf \
    /etc/ld.so.cache /etc/ld.so.conf /etc/ld.so.conf.d /etc/localtime; do
    if [ -e "$path" ] || [ -L "$path" ]; then
        mkdir -p "/image$(dirname "$path")"
        cp -a "$path" "/image$path"
    fi
done
for path in /lib /lib64; do
    if [ -L "$path" ]; then cp -a "$path" "/image$path"; fi
done
mkdir -p /image/usr/share/bash-os
cp /etc/bash-os-parity-snapshot /image/usr/share/bash-os/debian-snapshot
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Status}\n' \
    > /image/usr/share/bash-os/runtime-packages.tsv
