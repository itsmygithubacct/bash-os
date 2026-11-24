# text/join-header-case: join --header, -i, -o auto, --check-order
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'id name\n1 Alice\n2 bob\n' > l; printf 'id age\n1 30\n2 25\n' > r
join --header l r
printf 'A 1\nb 2\n' > l3; printf 'a x\nB y\n' > r3
echo --; join -i l3 r3
printf '1 a b\n2 c\n' > l4; printf '1 x\n2 y z\n' > r4
echo --; join -o auto -e - l4 r4
printf '2 a\n1 b\n' > bad; printf '1 x\n2 y\n' > ok
echo --; join --check-order bad ok; echo "rc=$?"
echo --; join --nocheck-order bad ok; echo "rc=$?"
