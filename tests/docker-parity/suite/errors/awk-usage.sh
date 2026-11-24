# errors/awk-usage: awk: usage text for an unknown option and a missing program
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
e() { printf '$ awk %s\n' "$*"; awk "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e
