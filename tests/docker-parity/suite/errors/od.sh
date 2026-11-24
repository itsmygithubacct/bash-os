# errors/od: od: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ od %s\n' "$*"; od "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e -j
e -t q
e -N x
e nosuch
