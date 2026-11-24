# diff/diff-whitespace: -b -w -B -i -E -Z ignore options
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'a  b\nc\n\nD\nx\t\n' > l; printf 'a b\nc\nd\nx\n' > r
diff l r; echo "rc=$?"; diff -b l r; echo "rc=$?"; diff -w -B -i l r; echo "rc=$?"; diff -Z -B -i -b l r; echo "rc=$?"; diff -i l r | head -n 3
