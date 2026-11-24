# grep/grep-stdin-labels: stdin with --label, -Z, -z, -c on several files
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'x\n' > a; printf 'y\n' > b; grep -cZ x a b | od -An -c
printf 'one\0two\0' | grep -z tw | od -An -c; printf 'x\n' | grep -c x - a
