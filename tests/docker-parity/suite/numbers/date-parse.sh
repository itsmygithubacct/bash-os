# numbers/date-parse: date -d with absolute and relative strings
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
for s in '2024-02-29' '2024-02-29 13:14:15' '2024-02-29T13:14:15Z' '@1700000000 + 1 day' '2024-01-31 + 1 month' '2024-03-10 2 hours ago' '2020-01-01 next monday' 'Mar 5 2024' '5 March 2024' '03/05/2024' '2024-12-31 + 1 day'; do printf '%-34s %s\n' "$s" "$(date -u -d "$s" '+%F %T' 2>&1)"; done
date -u -d 'not a date'; echo "rc=$?"
