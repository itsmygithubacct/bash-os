# files/basename-dirname: basename and dirname edge cases
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
basename /a/b/c.txt; basename /a/b/c.txt .txt; basename -s .txt x.txt y.txt; basename -a a/b c/d; basename /; basename ''; basename a//
dirname /a/b/c; dirname a; dirname /; dirname a/b/; dirname //x; dirname a b/c; dirname ''; basename -z a | od -An -c
