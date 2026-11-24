# awk/awk-errors: syntax errors and missing input files
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
awk 'BEGIN{print 1' ; echo "rc=$?"; awk '{print}' nosuch; echo "rc=$?"; printf 'x\n' > f; awk '{print}' f nosuch; echo "rc=$?"
