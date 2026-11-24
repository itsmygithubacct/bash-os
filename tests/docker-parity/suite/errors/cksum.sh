# errors/cksum: cksum: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ cksum %s\n' "$*"; cksum "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e -a
e -a bad
e -l 7 -a blake2b
e nosuch
