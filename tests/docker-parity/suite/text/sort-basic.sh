# text/sort-basic: default, -r, -f, -d, -b ordering
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '%s\n' b B a A _x ' c' 10 9 '' z | sort
echo --; printf '%s\n' b B a A _x ' c' | sort -r
echo --; printf '%s\n' b B a A _x | sort -f
echo --; printf '%s\n' 'a-b' 'ab' 'a b' 'a.c' | sort -d
echo --; printf '%s\n' '  b' ' a' 'c' | sort -b
