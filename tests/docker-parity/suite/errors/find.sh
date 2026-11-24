# errors/find: find: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ find %s\n' "$*"; find "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e -name
e -maxdepth x
e -type q
e nosuch
e -newer nosuch
