# errors/dd: dd: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ dd %s\n' "$*"; dd "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e bs=x
e foo
e if=nosuch
e count=-1
