# checksum/cksum-check: cksum -c on tagged lines of several algorithms
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'abc' > a; printf 'def' > b; { cksum -a md5 a; cksum -a sha1 b; cksum -a sha512 a; cksum -a blake2b -l 128 b; } > S; cksum -c S; echo "rc=$?"
