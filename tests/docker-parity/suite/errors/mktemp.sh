# errors/mktemp: mktemp: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ mktemp %s\n' "$*"; mktemp "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e bad
e aXX
e -p
e a b
