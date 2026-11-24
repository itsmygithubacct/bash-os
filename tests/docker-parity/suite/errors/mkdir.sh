# errors/mkdir: mkdir: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ mkdir %s\n' "$*"; mkdir "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e
e -m
e -m bad x
