# awk/awk-getline: getline forms: plain, var, < file, cmd |
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'l1\nl2\nl3\n' > f; printf 'o1\no2\n' > g
awk 'NR==1{getline; print "after getline:", $0, NR} NR==3{print "end", NR}' < f
awk '{getline line < "g"; print $0, line}' f; awk 'BEGIN{while ((getline l < "f") > 0) n++; print n; print (getline x < "nosuch")}'
awk 'BEGIN{"echo cmd-out" | getline v; print v; cmd="printf \"a\\nb\\n\""; while ((cmd | getline w) > 0) print "got", w; close(cmd)}'
awk 'NR==1{getline v; print v, NR, $0}' < f
