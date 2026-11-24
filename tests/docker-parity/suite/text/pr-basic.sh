# text/pr-basic: pr headers with fixed dates and columns
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
seq 1 12 > f; touch -d @1700000000 f
pr -l 20 f; echo --; pr -t -3 f; echo --; pr -t -2 -a f; echo --; pr -h TITLE -l 15 f
