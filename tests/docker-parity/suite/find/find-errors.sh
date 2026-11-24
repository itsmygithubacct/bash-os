# find/find-errors: missing start point and unknown predicate
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir x; touch x/f
find x nosuch -name f; echo "rc=$?"; find x -bogus; echo "rc=$?"; find x -name; echo "rc=$?"; find x -maxdepth z; echo "rc=$?"
