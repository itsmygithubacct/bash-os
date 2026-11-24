# awk/awk-output: print > file, >>, | command, close, fflush, printf to stderr
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
awk 'BEGIN{print "one" > "o"; print "two" > "o"; close("o"); print "three" >> "o"; print "x" | "cat 1>&2"; print "to-sort-b" | "sort"; print "to-sort-a" | "sort"}' 2>err
cat o err; awk 'BEGIN{printf "e\n" > "/dev/stderr"; print "out" > "/dev/stdout"}' 2>&1
