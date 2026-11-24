# errors/timeout: timeout: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ timeout %s\n' "$*"; timeout "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e
e x true
e 1
e -s BAD 1 true
e -k x 1 true
