# grep/grep-group-separator: --group-separator and --no-group-separator
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
seq 1 20 > f; grep -A1 --group-separator=XX -e '^2$' -e '^8$' f; echo --; grep -A1 --no-group-separator -e '^2$' -e '^8$' f
