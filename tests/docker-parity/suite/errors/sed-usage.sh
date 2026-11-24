# errors/sed-usage: sed: usage text for an unknown option and a missing program
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
e() { printf '$ sed %s\n' "$*"; sed "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e
