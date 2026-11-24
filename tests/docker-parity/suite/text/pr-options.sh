# text/pr-options: pr -m, -n, -w, -o, -d
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'a\nb\nc\n' > x; printf '1\n2\n' > y; touch -d @1700000000 x y
pr -t -m x y; echo --; pr -t -n x; echo --; pr -t -o 4 x; echo --; pr -t -d x; echo --; pr -t -w 20 -2 x
echo --; pr -T -m -s, x y
