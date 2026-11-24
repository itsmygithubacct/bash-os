# text/cut-utf8: cut -c and -b on UTF-8 input in C.UTF-8
export LC_ALL=C.UTF-8 TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'h\303\251llo w\303\266rld\n' > f
cut -c1-3 f | od -An -c
cut -b1-3 f | od -An -c
