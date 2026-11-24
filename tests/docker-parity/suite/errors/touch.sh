# errors/touch: touch: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ touch %s\n' "$*"; touch "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e
e -d
e -d bad x
e -t bad x
e -r nosuch x
