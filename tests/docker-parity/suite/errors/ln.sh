# errors/ln: ln: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ ln %s\n' "$*"; ln "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e
e -t
e --backup=bad a b
