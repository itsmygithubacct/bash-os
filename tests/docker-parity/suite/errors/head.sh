# errors/head: head: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ head %s\n' "$*"; head "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e -n
e -n x
e -c x
e nosuch
