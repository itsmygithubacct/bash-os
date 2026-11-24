# text/sort-keys: -k with field and character positions, -t
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
sort -k2,2n -k1,1 people
echo --; sort -k4 -k1,1r people
echo --; sort -t ' ' -k1.2,1.3 people
echo --; printf 'a:3:x\nb:1:y\nc:2:x\n' | sort -t: -k3,3 -k2,2n
echo --; printf 'x 1b\nx 1a\ny 0c\n' | sort -k2.2
