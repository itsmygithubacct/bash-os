# errors/xargs: xargs: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ xargs %s\n' "$*"; xargs "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e -n
e -n x
e -P x
e -s 0
