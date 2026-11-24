# errors/diff: diff: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ diff %s\n' "$*"; diff "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e
e a
e -U
e -U x a b
e nosuch nosuch2
