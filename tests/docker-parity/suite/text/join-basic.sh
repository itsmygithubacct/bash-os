# text/join-basic: join on default and chosen fields
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '1 a\n2 b\n3 c\n5 e\n' > l; printf '1 x\n3 y\n4 z\n5 w\n' > r
join l r; echo --; join -a1 l r; echo --; join -v2 l r; echo --; join -a1 -a2 -e NA -o 0,1.2,2.2 l r
printf 'a:1\nb:2\n' > l2; printf '1:p\n2:q\n' > r2
echo --; join -t: -1 2 -2 1 l2 r2
