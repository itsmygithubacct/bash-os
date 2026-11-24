# numbers/date-hash-flag: date %#b and %#Z swap case
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
date -u -d @1700000000 '+%#b %#a %#Z %#p'
