# text/sort-unique-stable: -u, -s and their interaction with keys
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
cat > people <<'EOF'
carol 35 7.5K berlin
alice 30 2M paris
bob 25 512 rome
dave 30 1.5G oslo
eve 22 900 paris
alice 28 3K lima
EOF
sort -u -k1,1 people
echo --; sort -s -k2,2n people
echo --; printf '%s\n' b a b c a | sort -u
echo --; printf '%s\n' 'x 2' 'y 1' 'x 1' 'y 2' | sort -s -k1,1
echo --; printf '%s\n' A a B b | sort -fu
