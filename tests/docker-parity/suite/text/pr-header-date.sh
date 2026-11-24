# text/pr-header-date: pr page header uses the file time; -D format
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'l1\nl2\n' > f; touch -d @86400 f
pr -l 12 f | head -n 4; pr -D '%Y/%m/%d' -l 12 f | head -n 4
