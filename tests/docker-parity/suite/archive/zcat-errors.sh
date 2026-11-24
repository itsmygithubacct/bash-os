# archive/zcat-errors: zcat diagnostics on bad input are gzip's
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'not gzip' > bad.gz; zcat bad.gz; echo "rc=$?"; zcat nosuch.gz; echo "rc=$?"
