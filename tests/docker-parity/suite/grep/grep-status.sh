# grep/grep-status: exit statuses: match, none, error, -q, -s
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'a\n' > f
grep a f >/dev/null; echo "rc=$?"; grep z f; echo "rc=$?"; grep a nosuch; echo "rc=$?"; grep -s a nosuch; echo "rc=$?"
grep -q a f nosuch; echo "rc=$?"; grep -q z f nosuch; echo "rc=$?"; grep -E '(' f; echo "rc=$?"; grep '\(' f; echo "rc=$?"
