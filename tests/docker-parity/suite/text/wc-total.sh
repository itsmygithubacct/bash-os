# text/wc-total: wc --total=never/only/always
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'one two\nthree\n' > a; printf 'no newline' > b
wc --total=never a b; echo --; wc --total=only a b; echo --; wc --total=always a
