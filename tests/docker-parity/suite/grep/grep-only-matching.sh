# grep/grep-only-matching: -o, -b, --color=never, -m
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
cat > f <<'EOF'
apple pie
Banana split
cherry tart
apple
pineapple
grape-fruit
123 numbers
EOF
grep -o 'p[a-z]*' f; echo --; grep -ob apple f; echo --; grep -m 2 a f; echo --; grep -o -i 'A' f | wc -l; echo --; grep -on '[0-9]' f
