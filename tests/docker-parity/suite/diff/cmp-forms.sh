# diff/cmp-forms: cmp default, -l, -s, -b, -n, -i and EOF reports
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'abcdef' > a; printf 'abXdeY' > b; printf 'abc' > c
cmp a b; echo "rc=$?"; cmp -l a b; cmp -s a b; echo "rc=$?"; cmp a c; echo "rc=$?"; cmp -n 2 a b; echo "rc=$?"
cmp a a; echo "rc=$?"; cmp a nosuch; echo "rc=$?"
