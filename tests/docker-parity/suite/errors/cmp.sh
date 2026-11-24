# errors/cmp: cmp: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ cmp %s\n' "$*"; cmp "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e
e -n
e -n x a b
e -i x a b
e nosuch a
