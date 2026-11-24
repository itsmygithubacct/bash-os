# checksum/check-missing: -c with missing files and --ignore-missing, stdin lists (G122 seed)
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'abc' > a; md5sum a > S; printf '%s  gone\n' 0123456789abcdef0123456789abcdef >> S
md5sum -c S; echo "rc=$?"; md5sum -c --ignore-missing S; echo "rc=$?"; md5sum -c < S; echo "rc=$?"; printf 'junk\n' | md5sum -c; echo "rc=$?"
