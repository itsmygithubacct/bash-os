# checksum/sum-large: checksums of a generated 1 MiB stream
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
awk 'BEGIN{for (i=0;i<65536;i++) printf "%015d\n", i}' > big; wc -c < big; md5sum < big; sha256sum < big; cksum < big; cksum -a sha512 < big
