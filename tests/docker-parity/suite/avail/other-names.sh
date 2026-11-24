# avail/other-names: non-coreutils commands reachable by their own names
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
for c in egrep fgrep gunzip xz unxz xzcat bzip2 cpio xxd sdiff diff3 gawk; do printf '%s ' "$c"; command -v "$c" >/dev/null && echo found || echo missing; done
