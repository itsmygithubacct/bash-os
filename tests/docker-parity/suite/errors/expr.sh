# errors/expr: expr: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ expr %s\n' "$*"; expr "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e
e 1 +
e '(' 1
e 1 + + 2
e 1 '*'
