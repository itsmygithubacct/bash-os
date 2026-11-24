# awk/awk-arrays: associative arrays, in, delete, split, for-in order sorted
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'b 2\na 1\nb 3\nc 5\na 4\n' | awk '{s[$1]+=$2; n[$1]++} END{for (k in s) print k, s[k], n[k] | "sort"; close("sort"); if ("a" in s) print "has a"; delete s["a"]; print ("a" in s); print length(n)}'
awk 'BEGIN{n=split("x:y:z", a, ":"); print n, a[1], a[3]; n=split("a1b22c", b, /[0-9]+/); print n, b[2], b[3]; split("", c); print length(c)}'
awk 'BEGIN{a[1,2]=3; for (k in a) {split(k, p, SUBSEP); print p[1], p[2]}; delete a; print length(a)}'
