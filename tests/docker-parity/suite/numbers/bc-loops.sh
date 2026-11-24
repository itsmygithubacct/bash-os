# numbers/bc-loops: bc while/for, arrays, strings and last
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
bc <<'EOF'
for (i = 1; i <= 5; i++) { s += i^2 }
s
i = 0; while (i < 3) { a[i] = i * 10; i++ }
a[2]
"text\n"
scale = 3; 1/7; last * 7
EOF
