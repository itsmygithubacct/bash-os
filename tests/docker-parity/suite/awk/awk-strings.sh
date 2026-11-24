# awk/awk-strings: length substr index match sub gsub toupper sprintf
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
awk 'BEGIN{s="Hello, World"; print length(s), substr(s,8), substr(s,2,3), substr(s,11,5), index(s,"World"), toupper(s), tolower(s)
print match(s, /o, W/), RSTART, RLENGTH; t=s; n=gsub(/o/, "0", t); print n, t; u=s; sub(/l+/, "[&]", u); print u
v="a.b.c"; gsub(/\./, "\\&", v); print v; w="aaa"; print gsub(/x*/, "-", w), w; print sprintf("%03d", 7) substr("xyz", 2)}'
