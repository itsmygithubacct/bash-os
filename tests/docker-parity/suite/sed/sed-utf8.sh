# sed/sed-utf8: sed y and case conversion on UTF-8 in C.UTF-8 (G49 seed)
export LC_ALL=C.UTF-8 TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '\303\251\303\240\n' | sed $'y/\303\251\303\240/ea/'
printf '\303\251cole\n' | sed 's/.*/\U&/' | od -An -c; printf '\303\251\n' | sed -n '/^.$/p' | od -An -c
