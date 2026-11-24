# errors/uniq: uniq: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ uniq %s\n' "$*"; uniq "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e -f
e -f x
e a b c
