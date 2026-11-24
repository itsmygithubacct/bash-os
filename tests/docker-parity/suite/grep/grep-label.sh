# grep/grep-label: --label names standard input
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'x\ny\n' | grep -H --label=IN x; printf 'x\n' | grep -c --label=IN -H x
