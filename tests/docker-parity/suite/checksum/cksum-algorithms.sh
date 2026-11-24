# checksum/cksum-algorithms: cksum default CRC and -a for each digest
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'The quick brown fox\n' > f; : > e
cksum f e; for a in crc md5 sha1 sha224 sha256 sha384 sha512 blake2b; do cksum -a "$a" f; done
cksum -a sha256 --untagged f; cksum -a blake2b -l 256 f; cksum -a sha512 --base64 f; printf 'x' | cksum
