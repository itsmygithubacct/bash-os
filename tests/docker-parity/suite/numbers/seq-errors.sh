# numbers/seq-errors: seq invalid arguments
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
seq; echo "rc=$?"; seq a; echo "rc=$?"; seq 1 0 3; echo "rc=$?"; seq -f '%d' 1; echo "rc=$?"
