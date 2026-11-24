# errors/seq: seq: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ seq %s\n' "$*"; seq "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e
e x
e 1 x
e -f
e 1 2 3 4
