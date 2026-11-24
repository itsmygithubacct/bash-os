# errors/wc: wc: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ wc %s\n' "$*"; wc "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e nosuch
e --files0-from=nosuch
