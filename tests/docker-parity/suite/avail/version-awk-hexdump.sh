# avail/version-awk-hexdump: awk and hexdump accept --version
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
awk --version </dev/null >/dev/null 2>&1; echo "awk rc=$?"; hexdump --version </dev/null >/dev/null 2>&1; echo "hexdump rc=$?"; awk -W version </dev/null >/dev/null 2>&1; echo "awk -W rc=$?"
