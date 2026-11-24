# errors/join: join: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ join %s\n' "$*"; join "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e
e a
e -t
e -j x a b
e a b c
