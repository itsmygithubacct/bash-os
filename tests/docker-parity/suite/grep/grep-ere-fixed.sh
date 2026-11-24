# grep/grep-ere-fixed: -E alternation, -F literals, -e multiple patterns, -f
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
grep -E 'pie|tart' f; echo --; grep -F 'e-f' f; echo --; grep -e cherry -e grape f; echo --; printf 'pie\n123\n' > pats; grep -f pats f
echo --; grep -F -x -f pats f; echo "rc=$?"; echo --; grep 'p\{2\}' f; echo --; grep -E 'p{2}' f; echo --; grep -F '.' f; echo "rc=$?"
# --- -e with leading dash, -- and empty pattern
mkdir part-grep-perl-free && (cd part-grep-perl-free || exit
printf -- '-x\nx\n\n' > f
grep -e -x f; grep -- -x f; grep -c '' f; grep -c -e '' f; grep -v -c '' f; echo "rc=$?"
)
