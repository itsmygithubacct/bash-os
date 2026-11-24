# numbers/date-epoch: date -d @N with many formats
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
for n in 0 86399 951782400 1700000000 2147483648 -86400; do date -u -d "@$n" '+%F %T %a %b %j %u %w %U %V %G %s %Z %z'; done
date -u -d @1700000000; date -u -d @1700000000 '+%c|%x|%X|%D|%r|%R|%e|%k|%l|%p|%P|%C|%y|%h|%n%t|%%'
date -u -d @1700000000 '+%-d %-m %_H %03j %^a %^b %10s %:z %::z'
