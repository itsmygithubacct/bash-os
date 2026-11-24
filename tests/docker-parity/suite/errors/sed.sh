# errors/sed: sed: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ sed %s\n' "$*"; sed "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e -@
e -e
e -f nosuch
e -n p nosuch
e -f
