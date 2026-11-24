# archive/gzip-fixed-stream: decompress a fixed gzip member and a concatenation
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'H4sIAAAAAAAAA8tIzcnJBwCGphA2BQAAAA==' | base64 -d > h.gz
zcat h.gz; echo; cat h.gz h.gz | gzip -dc; echo; gzip -l h.gz | tail -n 1 | awk '{print $1, $2}'
printf 'not gzip' > bad.gz; gzip -t bad.gz; echo "rc=$?"
