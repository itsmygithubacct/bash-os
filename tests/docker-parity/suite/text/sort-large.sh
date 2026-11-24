# text/sort-large: sort of a generated 20000-line file, numeric and plain
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
awk 'BEGIN { for (i = 0; i < 20000; i++) print (i * 7919) % 20011, "k" (i % 97) }' > f
sort -n f | md5sum; sort f | md5sum; sort -k2,2 -k1,1n f | md5sum; sort -u -k2,2 f | wc -l
