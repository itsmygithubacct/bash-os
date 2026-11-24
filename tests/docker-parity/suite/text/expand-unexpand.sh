# text/expand-unexpand: expand/unexpand tab stops
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'a\tb\tc\n\tx\n12345678\ty\n' > f
expand f | od -An -c; echo --; expand -t 4 f; echo --; expand -t 2,6,10 f; echo --; expand -i f | od -An -c
printf '        a       b\n    c\n' > s
echo --; unexpand s | od -An -c; echo --; unexpand -a s | od -An -c; echo --; unexpand -t 4 -a s | od -An -c
echo --; expand --tabs=3 f
# --- expand with backspace and long lines
mkdir part-expand-backspace && (cd part-expand-backspace || exit
printf 'ab\bc\td\n' | expand | od -An -c
printf '%s\tz\n' 0123456789 | expand -t 8 | od -An -c
)
