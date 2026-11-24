# grep/grep-utf8: -i and . on UTF-8 in C.UTF-8
export LC_ALL=C.UTF-8 TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '\303\251t\303\251\nETE\n\303\211T\303\211\n' > f
grep -i $'\303\251t\303\251' f | od -An -c; grep -c '^...$' f; grep -o '.' f | head -n 2 | od -An -c
