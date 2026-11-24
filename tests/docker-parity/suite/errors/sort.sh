# errors/sort: sort: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ sort %s\n' "$*"; sort "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e -k
e -t
e -k 0
e -k 1.0
e -t ab x
e -S
e nosuch
