# sed/sed-wide-files: sed over a generated file and line counts
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
seq 1 5000 > f; sed -n '/7$/p' f | wc -l; sed '1~2d' f | md5sum; sed -n '4990,$p' f | tr '\n' ' '; echo
