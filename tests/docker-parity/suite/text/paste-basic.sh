# text/paste-basic: paste columns, -d lists, -s serial
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '1\n2\n3\n' > a; printf 'x\ny\n' > b
paste a b; echo --; paste -d, a b; echo --; paste -d':;' a b a
echo --; paste -s a; echo --; paste -s -d'+' a; echo --; paste - - < a
echo --; paste -d '\n' a b; echo --; printf 'p\0q\0' | paste -z -s -d, | od -An -c
# --- paste with uneven and empty inputs
mkdir part-paste-uneven && (cd part-paste-uneven || exit
printf '1\n2\n3\n4\n' > a; printf 'x\n' > b; : > e
paste a b e | od -An -c | head -n 4; paste -d '' a b; paste -s a b e
)
