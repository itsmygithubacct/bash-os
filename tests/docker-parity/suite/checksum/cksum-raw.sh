# checksum/cksum-raw: cksum --raw output bytes
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'abc' > f; cksum --raw -a sha256 f | od -An -tx1; cksum --raw f | od -An -tx1
