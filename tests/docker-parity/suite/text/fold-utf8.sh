# text/fold-utf8: fold -w counts columns on UTF-8 text
export LC_ALL=C.UTF-8 TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '\303\251\303\251\303\251\303\251\n' | fold -w 2 | od -An -c
printf '\303\251\303\251\303\251\303\251\n' | fold -b -w 2 | od -An -c
