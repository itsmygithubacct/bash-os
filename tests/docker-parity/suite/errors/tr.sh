# errors/tr: tr: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ tr %s\n' "$*"; tr "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e
e a
e -d
e a b c
e -d a b
