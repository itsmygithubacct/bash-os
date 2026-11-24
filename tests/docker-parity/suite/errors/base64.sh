# errors/base64: base64: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ base64 %s\n' "$*"; base64 "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e -w
e -w x
e nosuch
e a b
