# errors/split: split: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ split %s\n' "$*"; split "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e -l
e -l 0
e -b x
e -a 0
e -n x
e -C x
e nosuch
