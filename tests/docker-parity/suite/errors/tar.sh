# errors/tar: tar: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ tar %s\n' "$*"; tar "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e
e -f
e -c
e -tf nosuch
e -x -t
