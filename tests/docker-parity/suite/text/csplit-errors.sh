# text/csplit-errors: csplit error for a missing pattern, with and without -k
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
seq 1 5 > f
csplit f '/9/'; echo "rc=$?"; ls xx* 2>/dev/null | wc -l
csplit -k f 2 '/9/'; echo "rc=$?"; ls xx*; rm -f xx*
