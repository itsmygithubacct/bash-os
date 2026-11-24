# text/rev-utf8: rev reverses characters in C.UTF-8
export LC_ALL=C.UTF-8 TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'h\303\251llo\n' | rev | od -An -c
