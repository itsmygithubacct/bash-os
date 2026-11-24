# archive/gzip-trailing: trailing garbage after a member (G67 seed)
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'H4sIAAAAAAAAA8tIzcnJBwCGphA2BQAAAA==' | base64 -d > h.gz; printf 'garbage' >> h.gz
zcat h.gz; echo; echo "rc=$?"; gzip -t h.gz; echo "rc=$?"
