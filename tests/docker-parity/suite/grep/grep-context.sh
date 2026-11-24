# grep/grep-context: -A -B -C and group separators
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
seq 1 20 > f
grep -A1 '^5$' f; echo --; grep -B2 '^5$' f; echo --; grep -C1 -e '^5$' -e '^9$' f; echo --; grep -C1 -e '^5$' -e '^7$' f
echo --; grep -n -C1 '^20$' f
