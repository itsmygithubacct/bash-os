# diff/cmp-gnu-options: cmp -b, -i SKIP, -i SKIP1:SKIP2 and --verbose
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'abcdef' > a; printf 'abXdeY' > b
cmp -b a b; echo "rc=$?"; cmp -i 3 a b; echo "rc=$?"; cmp --verbose a b; echo "rc=$?"; cmp -i 1:1 a b; echo "rc=$?"
