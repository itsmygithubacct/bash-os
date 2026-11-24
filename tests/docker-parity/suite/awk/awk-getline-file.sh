# awk/awk-getline-file: plain getline and getline var advance a file operand
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'l1\nl2\nl3\n' > f
awk 'NR==1{getline; print "after getline:", $0, NR}' f; awk 'NR==1{getline v; print v, NR, $0}' f; awk '{getline; print}' f
