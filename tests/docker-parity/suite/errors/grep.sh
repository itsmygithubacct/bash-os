# errors/grep: grep: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ grep %s\n' "$*"; grep "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e
e -e
e -m x
e -A x
e -E '('
