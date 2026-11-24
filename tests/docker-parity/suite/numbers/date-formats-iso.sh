# numbers/date-formats-iso: date -I, -R, --rfc-3339 with fixed input
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
date -u -d @1700000000 -I; date -u -d @1700000000 -Iseconds; date -u -d @1700000000 -Ihours; date -u -d @1700000000 -R
date -u -d @1700000000 --rfc-3339=seconds; date -u -d @1700000000 --rfc-3339=date; date -u -d @1700000000.5 -Ins
