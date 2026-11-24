# sed/sed-scripts: multi-command scripts, -f, labels and branches
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
cat > s.sed <<'EOF'
:a
s/^\([0-9]\+\)\([0-9]\{3\}\)/\1,\2/
ta
EOF
printf '1234567\n12\n1000\n' | sed -f s.sed
printf 'a b c\n' | sed -e 's/a/A/' -e 's/b/B/'; printf 'x\n' | sed '{s/x/y/;s/y/z/}'
printf 'one\\\ntwo\nthree\n' | sed -e ':j' -e '/\\$/{N;s/\\\n//;bj' -e '}'
printf 'aXb\n' | sed 's/X/\n/' | od -An -c; printf 'k\n' | sed 'T;s/k/K/'; printf 'k\n' | sed 's/q/Q/;T;s/k/K/'
