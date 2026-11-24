# errors/cut: cut: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ cut %s\n' "$*"; cut "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e
e -d
e -f
e -f 0
e -b 1 -f 1
e -c x
