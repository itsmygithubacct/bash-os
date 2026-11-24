# text/sort-misc: -o in place, -z, -k with -n and blanks, --field-separator
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'c\nb\na\n' > f; sort -o f f; cat f
printf 'b\0a\0c\0' | sort -z | od -An -c
printf '  10 x\n9 y\n 100 z\n' | sort -n -k1
printf 'a,10\nb,9\nc,100\n' | sort --field-separator=, --key=2n
printf '%s\n' 'b 2' 'a 2' 'c 1' | sort -k2n -k1r
