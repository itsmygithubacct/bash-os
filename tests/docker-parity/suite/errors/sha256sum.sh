# errors/sha256sum: sha256sum: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ sha256sum %s\n' "$*"; sha256sum "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e nosuch
e -c nosuch
e --status x
