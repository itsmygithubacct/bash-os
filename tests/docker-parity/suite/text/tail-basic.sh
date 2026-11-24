# text/tail-basic: tail -n -c with +N and multiple files
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
seq 1 20 > f; printf 'x\ny' > g
tail -n 3 f; echo --; tail -n +18 f; echo --; tail -c 6 f; echo --; tail -c +48 f; echo --
tail -n 1 f g; echo; echo --; tail -q -n1 f g; echo; echo --; tail -n 2 g; echo; echo --; seq 5 | tail -2
# --- tail/head with -z and zero counts
mkdir part-tail-zero && (cd part-tail-zero || exit
printf 'a\0b\0c\0' | tail -z -n 2 | od -An -c
printf 'a\0b\0c\0' | head -z -n 1 | od -An -c
seq 3 | tail -n 0; echo "rc=$?"; seq 3 | head -n 0; echo "rc=$?"
)
# --- tail on a regular file with -n and -c combinations
mkdir part-tail-follow-noop && (cd part-tail-follow-noop || exit
printf '1\n2\n3\n4\n5\n' > f
tail -n +0 f | wc -l; tail -c +0 f | wc -c; tail -n -2 f; tail -2 f
)
