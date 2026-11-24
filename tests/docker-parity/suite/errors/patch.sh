# errors/patch: patch: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ patch %s\n' "$*"; patch "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e -p
e -p x
e -i nosuch
