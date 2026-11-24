# numbers/date-tz: TZ rules applied by date (POSIX TZ strings, no zoneinfo)
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
TZ=UTC0 date -d @1700000000 '+%F %T %Z %z'; TZ=EST5EDT,M3.2.0,M11.1.0 date -d @1700000000 '+%F %T %Z %z'; TZ=EST5EDT,M3.2.0,M11.1.0 date -d @1690000000 '+%F %T %Z %z'
TZ=JST-9 date -d @1700000000 '+%F %T %Z %z'; TZ='<+0530>-5:30' date -d @1700000000 '+%F %T %z'; date -u -d @1700000000 '+%Z'
