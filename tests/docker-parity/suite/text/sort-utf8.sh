# text/sort-utf8: sort in C.UTF-8 orders by code point
export LC_ALL=C.UTF-8 TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '%s\n' 'b' 'é' 'a' 'z' 'É' 'ä' | sort | od -An -c
printf '%s\n' 'b' 'é' 'a' | sort -r | od -An -c
