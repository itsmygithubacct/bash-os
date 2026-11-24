# files/cat-e-crlf: cat -E and -A show a CR before the newline as ^M
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'a\r\nb\rc\n' > f; cat -E f | od -An -c; cat -A f; cat -vE f | od -An -c
