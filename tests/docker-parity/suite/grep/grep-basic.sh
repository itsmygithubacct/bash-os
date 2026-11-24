# grep/grep-basic: plain match, -i -v -n -c -x -w
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
grep apple f; echo --; grep -i banana f; echo --; grep -v a f; echo --; grep -n apple f; echo --; grep -c apple f
echo --; grep -x apple f; echo --; grep -w apple f; echo --; grep -w grape f; echo --; grep -vc apple f
# --- grep over a generated file: counts and -m with -c
mkdir part-grep-large && (cd part-grep-large || exit
seq 1 20000 > f; grep -c 7 f; grep -m 5 -c 7 f; grep -E '^(1|2)0{3}$' f; grep -x -c '[0-9]\{3\}' f
)
