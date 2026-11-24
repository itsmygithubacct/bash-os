# archive/tar-errors: missing members and bad archives
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
tar -cf /tmp/x.tar nosuch; echo "rc=$?"; printf 'junk' > bad.tar; tar -tf bad.tar; echo "rc=$?"; tar -xf nosuch.tar; echo "rc=$?"
