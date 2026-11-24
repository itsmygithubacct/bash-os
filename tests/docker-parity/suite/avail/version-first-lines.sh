# avail/version-first-lines: --version first lines of common tools
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
for c in sort ls cat tar gzip sed grep find diff patch date od cksum iconv bc; do $c --version </dev/null 2>&1 | head -n 1; done
