# files/touch-forms: touch -d @N, -r, -m, -a, -c, date strings
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch -d @1700000000 a; stat -c '%X %Y' a; touch -r a b; stat -c '%Y' b
touch -m -d @1600000000 a; stat -c '%X %Y' a; touch -a -d @1500000000 a; stat -c '%X %Y' a
touch -c nosuch; ls nosuch 2>/dev/null; echo "rc=$?"
touch -d '2024-02-29 12:34:56' c; stat -c %Y c; touch -t 202001020304.05 e; stat -c %Y e
touch -d '2001-09-09 01:46:40 UTC' f; stat -c %Y f
# --- touch -d with assorted date strings
mkdir part-touch-dates && (cd part-touch-dates || exit
for s in '2020-01-01' '2020-01-01 00:00:01' '@0' '1970-01-02' '2038-01-19 03:14:08' '2024-03-01T10:00:00Z' '20200101'; do touch -d "$s" f; printf '%s -> %s\n' "$s" "$(stat -c %Y f)"; done
)
