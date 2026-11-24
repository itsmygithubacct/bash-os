# checksum/cksum-sysv-bsd: cksum -a sysv and -a bsd
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'The quick brown fox\n' > f; cksum -a sysv f; echo "rc=$?"; cksum -a bsd f; echo "rc=$?"; printf '' | cksum -a sysv
