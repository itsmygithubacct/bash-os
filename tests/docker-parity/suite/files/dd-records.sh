# files/dd-records: dd record counts on stderr with partial blocks
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '%025d' 0 > f
dd if=f of=o bs=10 2>&1 | head -n 2; wc -c < o
dd if=f of=o2 ibs=7 obs=3 2>&1 | head -n 2
