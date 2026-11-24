# text/wc-basic: wc counts, multiple files, totals
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'one two\nthree\n' > a; printf 'no newline' > b; : > e
wc a; wc -l a; wc -w a; wc -c a; wc -m a; wc -L a; echo --
wc a b e; echo --; wc -lw a b; echo --; wc < a; 
echo --; printf 'a\0b\0' > list0; printf 'a\nb\n' > list; wc --files0-from=list0
# --- wc on stdin with -c and words separated by odd whitespace
mkdir part-wc-pipe-mixed && (cd part-wc-pipe-mixed || exit
printf 'a\tb\vc\fd\re  f\n' | wc -w
printf 'x\n' | wc -c -
printf '' | wc
)
