# numbers/expr-utf8: expr length/substr/index count characters in C.UTF-8 (G97 seed)
export LC_ALL=C.UTF-8 TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
expr length $'\303\251a'; expr substr $'\303\251ab' 2 1; expr index $'\303\251a' a; expr $'\303\251' : '.'
