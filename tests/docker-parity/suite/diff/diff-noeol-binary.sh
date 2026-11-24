# diff/diff-noeol-binary: missing final newline and binary files
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'a\nb' > l; printf 'a\nc' > r; diff l r; diff -u --label l --label r l r
printf 'x\0y' > b1; printf 'x\0z' > b2; diff b1 b2; echo "rc=$?"; diff -a b1 b2 | od -An -c | head -n 2
