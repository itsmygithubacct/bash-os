# text/join-unpaired-fmt: join -o with explicit fields and -t tab
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '1\tA\tx\n2\tB\ty\n' > l; printf '1\tp\n3\tq\n' > r
join -t "$(printf '\t')" -a1 -o 1.1,1.3,2.2 -e '?' l r | od -An -c
