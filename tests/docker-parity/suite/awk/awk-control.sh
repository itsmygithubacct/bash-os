# awk/awk-control: if/else, while, do, for, break, continue, next, exit code
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
seq 1 10 | awk '$1%2{next} {s+=$1} $1==8{exit 3} END{print s}'; echo "rc=$?"
awk 'BEGIN{i=0; do {i++} while (i<5); print i; for (;;) {if (++j>3) break}; print j; for (k=0;k<5;k++) {if (k==2) continue; printf "%d", k}; print ""}'
awk 'BEGIN{x = 3 > 2 ? "yes" : "no"; print x; exit} END{print "end after exit"}'; echo 'a' | awk '{exit} END{print "end"}'
