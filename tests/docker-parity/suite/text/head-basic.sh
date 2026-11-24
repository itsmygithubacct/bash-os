# text/head-basic: head -n -c with negatives and multiple files
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
seq 1 20 > f; printf 'x\ny\n' > g
head -n 3 f; echo --; head -n -17 f; echo --; head -c 5 f; echo; echo --; head -c -40 f | tail -n 2
echo --; head -n 2 f g; echo --; head -q -n1 f g; echo --; head -v -n1 g; echo --; head -n 1K f | wc -l
echo --; seq 3 | head -n 2 -
# --- head and tail on pipes and large counts
mkdir part-head-tail-pipe && (cd part-head-tail-pipe || exit
seq 1 100000 | tail -n 2
seq 1 100000 | head -c 20; echo
seq 1 100000 | tail -c 12
yes_lines() { local i; for ((i=0;i<5000;i++)); do echo y; done; }
yes_lines | head -n 3
)
# --- head -c and -n with unit suffixes
mkdir part-head-bytes-units && (cd part-head-bytes-units || exit
seq 1 1000 > f
head -c 1k f | wc -c; head -c 1KB f | wc -c; head -n 1k f | wc -l; head -c 2b f | wc -c
)
