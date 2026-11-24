# sed/sed-errors: parse errors and missing files
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'x\n' > f
sed 's/a/b' f; echo "rc=$?"; sed 'k' f; echo "rc=$?"; sed 'y/ab/c/' f; echo "rc=$?"; sed -n p nosuch; echo "rc=$?"
sed 'b nolabel' f; echo "rc=$?"; sed '}' f; echo "rc=$?"; sed -e p -e 's/x' f; echo "rc=$?"
